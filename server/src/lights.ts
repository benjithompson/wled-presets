import { effectObjects, effectsLook, type EffectSettings } from '../../shared/effects.ts';
import { sequenceEffects, sequenceObjects, type Sequence } from '../../shared/sequence.ts';
import { playlistSteps, playlistTransition } from '../../shared/playlist.ts';
import type { ApplyResult, Device, DeviceInfo, DeviceWithStatus, LightControls, LogLevel, PublicState, Scene } from '../../shared/types.ts';
import { readLayout } from './layoutStore.ts';
import type { Db } from './db.ts';
import type { Bus } from './events.ts';
import { KEY, readHiddenGames, readLightControls, readSettings, sceneTransitionOf, writeLightControls } from './settings.ts';
import type { SceneTransition } from '../../shared/transitions.ts';
import { parseHex } from '../../shared/color.ts';
import { baseUrl, lastWrite, wled, type FetchResult, type PowerState } from './wled.ts';
import { mergeLooks, type PresetLook } from './presetLook.ts';
import type { Peek } from './roofView.ts';
import { WledPeek } from './wledPeek.ts';
import { visitorLabel } from './visitor.ts';
import type { HomeAssistant } from './homeAssistant.ts';
import { entityOf, haId, isHaId, type HaEntity } from '../../shared/homeAssistant.ts';

/**
 * A change a device reports this soon after this app told it something may be that request
 * taking effect, so it is not taken as a change made somewhere else. WLED applies a preset a
 * moment after the request, and tells its WebSocket at most about once a second.
 */
const SETTLE_MS = 2500;
/** A status check that took longer than this: the device is busy, and sits the next check or two out. */
const SLOW_CHECK_MS = 2000;

/** WLED's brightness (1 to 255) in percent, as the switches count it. */
const percent = (bri: number) => Math.max(1, Math.round((bri / 255) * 100));

/** Adds what one batch of commands did to another's result. */
function merge(into: ApplyResult, more: ApplyResult) {
  into.applied.push(...more.applied);
  into.skipped.push(...more.skipped);
  into.failed.push(...more.failed);
}

export type PresetImport = { deviceId: string; ok: true; count: number } | { deviceId: string; ok: false; error: string };

/**
 * Plays a scene's effects on the layout objects, or a sequence (null: stops them). Returns the
 * devices that get the frames and the number of objects that are lit.
 */
export type EffectPlayer = (
  show: { effects?: Record<string, EffectSettings> | null; sequence?: Sequence | null } | null,
  /** How the show that plays now gives way to this one (none: at once). */
  transition?: SceneTransition | null
) => { devices: string[]; objects: number };

export interface Actor {
  ip?: string | null;
  userAgent?: string | null;
  /** A visitor who is not an admin (their tag, see visitorTag): what they do is logged as visitor activity. */
  visitor?: string;
}

interface Status {
  online: boolean;
  /** Checks in a row that got no answer. One miss is not enough to call a device offline. */
  misses?: number;
  info: DeviceInfo | null;
  lastSeen: string | null;
}

/**
 * Owns everything that talks to the lights: applying scenes and colors, the auto-revert
 * timer, and the device status monitor. One instance per process.
 */
export class Lights {
  private status = new Map<string, Status>();
  private revertTimer: NodeJS.Timeout | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private pollMs = 10_000;
  private db: Db;
  private bus: Bus;
  private effectPlayer: EffectPlayer | null = null;

  /** devicesWithStatus() for the frame loops, which ask 60 times a second (see liveDevices). */
  private live: (DeviceWithStatus & { switchedOff?: boolean })[] | null = null;
  /** The admin's power and brightness switches, read once and kept up to date. */
  private controlsCache: LightControls | null = null;

  /** One WebSocket per enabled device: WLED says every change of its power and brightness on it. */
  private watchers = new Map<string, { url: string; peek: WledPeek }>();
  /** Per device, the borrowed peeks (see peek) that want its live colors now. */
  private liveWanted = new Map<string, Set<object>>();
  /** What each device last reported (see observe), and when. */
  private seen = new Map<string, PowerState & { at: number }>();
  /** Devices that missed an admin's power or brightness switch: they get it when they answer again. */
  private missed = new Set<string>();
  private refreshing: Promise<void> | null = null;
  private refreshAgain = false;

  /**
   * Called when every light is off after a change made outside this app (WLED's own app, a
   * button, a timer on the device), as when an admin switches them off here: the game ends.
   */
  onAllOff: (() => void) | null = null;
  /** See SETTLE_MS (shorter in tests). */
  settleMs = SETTLE_MS;
  /** A second of a playlist, in milliseconds (shorter in tests). */
  playlistSecondMs = 1000;
  /**
   * True while something else has the lights (a game): a playlist waits on the scene it is on,
   * and moves on once the lights are free again.
   */
  holdPlaylist: () => boolean = () => false;
  /**
   * Home Assistant, when it is used: plugs that power WLED controllers, and other lights that
   * switch with these (see HaSettings).
   */
  private home: HomeAssistant | null = null;
  get ha(): HomeAssistant | null {
    return this.home;
  }
  set ha(h: HomeAssistant | null) {
    if (this.home) this.home.onChange = null;
    this.home = h;
    if (h) h.onChange = (e) => this.haChanged(e);
  }
  /** How long a device has to fade out before its plug cuts the power (shorter in tests). */
  plugDelayMs = 1500;
  /**
   * A Home Assistant light's power switch that failed is sent again this long after (ms), once
   * each, while its switch stays as it was. Only a failed command: one Home Assistant answers
   * late, and did, is not sent again; and a light switched in Home Assistant meanwhile is
   * someone's choice, and followed (see followHa).
   */
  haRetryMs = [2000, 6000];
  private stopped = false;
  /** Devices whose plug was switched on: when they answer, they get the switches and what plays. */
  private booting = new Set<string>();
  /**
   * Switches seen in Home Assistant, by entity, and when: followed once they have held for a
   * while (see followHa), as a Zigbee light can say off for a moment and on again.
   */
  private haSeen = new Map<string, { state: 'on' | 'off'; at: number; check: number }>();
  /** followHa's checks, counted: one seen in a check is followed at a later one. */
  private haCheck = 0;
  /** When the schedule switches the lights on next (ISO), or null: told to visitors while they are off. */
  lightsOnAt: () => string | null = () => null;
  /** The schedule's night: whether a visitor's pick wakes the lights, and woken, their idle minutes (see LightScheduler). */
  nightWake: () => { wake: boolean; idleMinutes: number | null } = () => ({ wake: false, idleMinutes: null });

  /** The playlist that plays now: its scene, the step it is on, and the timer to the next one. */
  private playlist: { id: string; step: number; showing: string | null; timer: NodeJS.Timeout | null } | null = null;

  constructor(db: Db, bus: Bus) {
    this.db = db;
    this.bus = bus;
    // Every change to the device list is announced on the bus.
    this.bus.on('devices', () => (this.live = null));
  }

  /** Connects the game host, which draws effects and sends them to the lights. */
  setEffectPlayer(player: EffectPlayer) {
    this.effectPlayer = player;
  }

  /** What a scene plays on the lights: its sequence (when it still exists), or its effects. */
  private showOf(scene: Scene | null) {
    if (!scene) return null;
    const sequence = scene.sequenceId ? this.db.getSequence(scene.sequenceId) : null;
    return sequence ? { sequence } : scene.effects ? { effects: scene.effects } : null;
  }

  /** After a restart: the scene that was playing plays again, if it has effects or a sequence; a playlist starts again. */
  resumeEffects() {
    const id = this.db.getSetting(KEY.currentScene);
    const scene = id ? this.db.getScene(id) : null;
    if (scene?.playlist) return void this.startPlaylist(scene, null);
    const show = this.showOf(scene);
    if (show) this.effectPlayer?.(show);
  }

  /** The scene whose show plays now: the current scene, or the one its playlist is on. */
  private showingScene() {
    const id = this.playlist ? this.playlist.showing : this.db.getSetting(KEY.currentScene);
    return id ? this.db.getScene(id) : null;
  }

  /** A scene was changed: if it is playing, play its new effects at once. A playlist that was changed starts again. */
  sceneChanged(sceneId: string) {
    if (this.playlist?.id === sceneId) {
      const scene = this.db.getScene(sceneId);
      if (scene?.playlist) return void this.startPlaylist(scene, playlistTransition(scene.playlist));
      // No longer a playlist: it plays as a scene of its own.
      this.stopPlaylist();
      return void this.effectPlayer?.(this.showOf(scene));
    }
    const showing = this.showingScene();
    if (showing?.id === sceneId) this.effectPlayer?.(this.showOf(showing));
    else if (!this.playlist && this.db.getSetting(KEY.currentScene) === sceneId) {
      // A scene that became a playlist.
      const scene = this.db.getScene(sceneId);
      if (scene?.playlist) void this.startPlaylist(scene, null);
    }
  }

  /** A sequence was saved or deleted: a playing scene that uses it plays the new version. */
  sequenceChanged(sequenceId: string) {
    const scene = this.showingScene();
    if (scene && (scene.sequenceId === sequenceId || !scene.sequenceId)) this.effectPlayer?.(this.showOf(scene));
  }

  /** A scene was deleted: if it was playing, its effects stop. A playlist on it moves on at its next step. */
  sceneDeleted(sceneId: string) {
    if (this.db.getSetting(KEY.currentScene) === sceneId) {
      this.stopPlaylist();
      this.effectPlayer?.(null);
      this.db.setSetting(KEY.currentScene, '');
    }
  }

  // ---------- Playlists ----------

  /** The scene a playlist is on now (null when none plays). */
  playlistScene(): string | null {
    return this.playlist?.showing ?? null;
  }

  private stopPlaylist() {
    if (this.playlist?.timer) clearTimeout(this.playlist.timer);
    this.playlist = null;
  }

  /**
   * Starts a playlist from its first scene (`transition`: how the show before gives way to it).
   * Returns what its first scene did, or null when it has no scene to play.
   */
  private async startPlaylist(scene: Scene, transition: SceneTransition | null): Promise<ApplyResult | null> {
    this.stopPlaylist();
    const run = { id: scene.id, step: -1, showing: null as string | null, timer: null as NodeJS.Timeout | null };
    this.playlist = run;
    return this.stepPlaylist(run, transition);
  }

  /** The playlist plays its next scene, and sets the timer for the one after. */
  private async stepPlaylist(run: NonNullable<Lights['playlist']>, transition: SceneTransition | null): Promise<ApplyResult | null> {
    run.timer = null;
    const scene = this.db.getScene(run.id);
    const steps = scene?.playlist ? playlistSteps(scene.playlist, this.db.listScenes()) : [];
    if (!scene?.playlist || !steps.length) {
      if (this.playlist === run) this.playlist = null;
      return null;
    }
    const wait = (seconds: number) => {
      if (this.playlist === run) run.timer = setTimeout(() => void this.stepPlaylist(run, playlistTransition(scene.playlist!)), seconds * this.playlistSecondMs);
      run.timer?.unref?.();
    };
    // A game has the lights, or they are switched off: try again in a moment.
    if (run.step >= 0 && (this.holdPlaylist() || this.allOff())) {
      wait(2);
      return null;
    }
    // The next scene, or the first again (scenes may have come and gone since the last step).
    const at = steps.findIndex((s) => s.scene.id === run.showing);
    const step = run.step < 0 ? 0 : at >= 0 ? (at + 1) % steps.length : Math.min(run.step, steps.length - 1) % steps.length;
    const next = steps[step];
    run.step = step;
    run.showing = next.scene.id;
    const result = await this.play(next.scene, transition);
    if (this.playlist !== run) return result;
    wait(next.seconds);
    this.bus.emit('state');
    return result;
  }

  log(level: LogLevel, action: string, message: string, details?: unknown, actor?: Actor) {
    const line = `[${level.toUpperCase()}] ${action}: ${message}`;
    (level === 'error' ? console.error : console.log)(line);
    try {
      this.db.addLog({ level, action, message, details, clientIp: actor?.ip ?? 'server', userAgent: actor?.userAgent ?? 'system' });
      this.bus.emit('log', null);
    } catch (e) {
      console.error('Could not write log:', (e as Error).message);
    }
  }

  // ---------- Status monitor ----------

  start(intervalMs: number) {
    this.stopped = false;
    this.pollMs = intervalMs;
    void this.refreshStatus();
    this.pollTimer = setInterval(() => void this.refreshStatus(), intervalMs);
    this.restoreRevertTimer();
  }

  stop() {
    this.stopped = true;
    this.stopPlaylist();
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.revertTimer) clearTimeout(this.revertTimer);
    for (const w of this.watchers.values()) w.peek.close();
    this.watchers.clear();
  }

  /**
   * A device's info, with its LED outputs (see DeviceInfo.outputs). The outputs are read once,
   * and again when the LED count changes: they live in the device's settings.
   */
  private async readInfo(d: Device): Promise<FetchResult<{ info: DeviceInfo; power: PowerState | null }>> {
    const r = await wled.infoAndPower(d, 3000);
    if (!r.ok) return r;
    const { info, power } = r.data;
    const prev = this.status.get(d.id)?.info;
    if (prev?.outputs && prev.leds?.count === info.leds?.count) return { ...r, data: { power, info: { ...info, outputs: prev.outputs } } };
    const o = await wled.outputs(d);
    return o.ok ? { ...r, data: { power, info: { ...info, outputs: o.data } } } : r;
  }

  /**
   * A device's own settings changed here (its LED outputs may have): its outputs are read again
   * with its info, now.
   */
  settingsChanged(deviceId: string): Promise<void> {
    const s = this.status.get(deviceId);
    if (s?.info?.outputs) this.status.set(deviceId, { ...s, info: { ...s.info, outputs: undefined } });
    this.live = null;
    return this.refreshStatus();
  }

  /** Checks every enabled device. A check asked for while one runs runs once more after it. */
  refreshStatus(): Promise<void> {
    if (this.refreshing) {
      this.refreshAgain = true;
      return this.refreshing;
    }
    this.refreshing = (async () => {
      try {
        do {
          this.refreshAgain = false;
          await this.checkDevices();
        } while (this.refreshAgain);
      } finally {
        this.refreshing = null;
      }
    })();
    return this.refreshing;
  }

  /**
   * Devices that answered slowly (or not in time), and how many checks each sits out: a device
   * that has fallen behind gets room to catch up instead of another request at every check.
   * 1, then 2, then 3 checks in a row (about 10, 20, 30 s) while it stays slow.
   */
  private slowChecks = new Map<string, { wait: number; skip: number }>();
  /** Told of each status check of a device (see LightSender.checked, which holds a device that falls behind to fewer frames). */
  onChecked: ((d: Device, c: { ok: boolean; ms: number; fps?: number }) => void) | null = null;

  private async checkDevices(): Promise<void> {
    const all = this.enabledDevices();
    this.syncWatchers(all);
    // A slow one sits a check or two out (see slowChecks); its status stays as it was.
    const devices = all.filter((d) => {
      const s = this.slowChecks.get(d.id);
      if (!s || s.skip <= 0) return true;
      s.skip--;
      return false;
    });
    // A device busy with real-time frames over Wi-Fi can answer slowly; allow 3 s.
    const timed = (d: Device) => {
      const t0 = Date.now();
      return this.readInfo(d).then((r) => ({ r, ms: Date.now() - t0 }));
    };
    const [checks] = await Promise.all([Promise.all(devices.map(timed)), this.followHa().catch(() => {})]);
    const results = checks.map((c) => c.r);
    let changed = false;
    const seen = new Set(all.map((d) => d.id));
    devices.forEach((d, i) => {
      const r = results[i];
      const { ms } = checks[i];
      if (ms > SLOW_CHECK_MS) {
        const wait = Math.min(3, (this.slowChecks.get(d.id)?.wait ?? 0) + 1);
        this.slowChecks.set(d.id, { wait, skip: wait });
      } else this.slowChecks.delete(d.id);
      this.onChecked?.(d, { ok: r.ok, ms, ...(r.ok && typeof r.data.info.leds?.fps === 'number' ? { fps: r.data.info.leds.fps } : {}) });
      const prev = this.status.get(d.id);
      const misses = r.ok ? 0 : (prev?.misses ?? 0) + 1;
      const next: Status = r.ok
        ? { online: true, misses, info: r.data.info, lastSeen: new Date().toISOString() }
        : // Offline only after two missed checks in a row, so one slow answer does not flash "offline".
          { online: prev?.online === true && misses < 2, misses, info: prev?.info ?? null, lastSeen: prev?.lastSeen ?? null };
      if (!prev || prev.online !== next.online) changed = true;
      this.status.set(d.id, next);
      this.live = null;
      if (!next.online) this.seen.delete(d.id);
      // The state in the answer, for a device whose WebSocket does not work.
      else if (r.ok && r.data.power) this.observe(d, r.data.power, true);
    });
    for (const id of this.slowChecks.keys()) if (!seen.has(id)) this.slowChecks.delete(id);
    for (const id of this.status.keys()) {
      if (!seen.has(id)) {
        this.status.delete(id);
        this.seen.delete(id);
        this.live = null;
        changed = true;
      }
    }
    if (changed) {
      this.bus.emit('state');
      this.bus.emit('devices');
    }
  }

  /**
   * The same as devicesWithStatus(), kept between changes, for the loops that send frames to the
   * lights: they ask on every frame, and a database query each time would cost frame time. It is
   * rebuilt after a device changes and after each status check (an LED count changed in WLED).
   */
  liveDevices(): (DeviceWithStatus & { switchedOff?: boolean })[] {
    // A device switched off counts as disabled here: no frames reach it, and one that was
    // getting them is given back (it shows its own state, which is off). An editor's preview
    // still lights it, while the admin looks (see LightFrame.wakes).
    return (this.live ??= this.devicesWithStatus().map((d) => (d.enabled && this.isOff(d.id) ? { ...d, enabled: false, switchedOff: true } : d)));
  }

  /** The frames a second the sender sends a device now (see LightSender.sending): set by the server. */
  sendingTo: ((d: Device & { info: DeviceInfo | null }) => { fps: number; held: boolean } | null) | null = null;

  devicesWithStatus(): DeviceWithStatus[] {
    return this.db.listDevices().map((d) => {
      const s = this.status.get(d.id);
      const sending = d.enabled ? (this.sendingTo?.({ ...d, info: s?.info ?? null }) ?? null) : null;
      const p = d.enabled && s?.online ? this.seen.get(d.id) : undefined;
      const plug = this.plugOf(d.id);
      const e = plug ? this.ha?.entity(plug) : undefined;
      return {
        ...d,
        online: d.enabled ? (s?.online ?? null) : null,
        info: s?.info ?? null,
        lastSeen: s?.lastSeen ?? null,
        power: p ? { on: p.on, bri: p.bri } : null,
        ...(plug ? { plug: { entity: plug, name: e?.name ?? plug, on: e?.state === 'on' ? true : e?.state === 'off' ? false : null } } : {}),
        ...(sending ? { sending } : {})
      };
    });
  }

  // ---------- What the devices report ----------

  /** Keeps one WebSocket open to each enabled device, and none to the rest. */
  private syncWatchers(enabled: Device[]) {
    const ids = new Set(enabled.map((d) => d.id));
    for (const [id, w] of this.watchers) {
      if (ids.has(id)) continue;
      w.peek.close();
      this.watchers.delete(id);
      this.seen.delete(id);
      this.missed.delete(id);
    }
    for (const d of enabled) this.watch(d);
  }

  /** The device's WebSocket, opened if need be (again, after its address changed). */
  private watch(d: Device): WledPeek {
    const url = baseUrl(d);
    const w = this.watchers.get(d.id);
    if (w?.url === url) return w.peek;
    w?.peek.close();
    this.seen.delete(d.id);
    const peek = new WledPeek(d, () => this.status.get(d.id)?.info?.leds?.count ?? 0, {
      live: false,
      onPower: (p) => {
        const device = this.db.getDevice(d.id);
        if (device?.enabled) this.observe(device, p);
      }
    });
    this.watchers.set(d.id, { url, peek });
    return peek;
  }

  /**
   * What the device shows by itself, for the roof view, over the same WebSocket as its state
   * (WLED takes only a few at once). Closing it only stops the colors.
   */
  peek(d: Device): Peek {
    const cur = () => this.watchers.get(d.id)?.peek;
    // Several views borrow the same WebSocket (the roofline, the admin's yard view): the colors
    // keep coming while any of them wants them.
    const me = {};
    const wanting = () => {
      let set = this.liveWanted.get(d.id);
      if (!set) this.liveWanted.set(d.id, (set = new Set()));
      return set;
    };
    const want = (live: boolean) => {
      const set = wanting();
      if (live) set.add(me);
      else set.delete(me);
      return set.size > 0;
    };
    return {
      get leds() {
        return cur()?.leds ?? null;
      },
      get step() {
        return cur()?.step ?? 1;
      },
      get at() {
        return cur()?.at ?? 0;
      },
      get on() {
        return cur()?.on ?? null;
      },
      get bri() {
        return cur()?.bri ?? null;
      },
      // The current one: after an address change, `d` has the old address.
      setLive: (live: boolean) => (cur() ?? this.watch(d)).setLive(want(live)),
      close: () => cur()?.setLive(want(false))
    };
  }

  /**
   * A device reported its power and brightness (null: its WebSocket closed). The app follows
   * the device: a light switched on or off, or dimmed, somewhere else (WLED's own app, a
   * button, a timer on the device) is switched that way here too, so the switches show what
   * the lights do, and scenes keep to it. A change that comes right after this app told the
   * device something is that request (see SETTLE_MS). A device that missed an admin's switch
   * while it was offline gets it now instead.
   */
  private observe(d: Device, power: PowerState | null, fromPoll = false) {
    const watcher = this.watchers.get(d.id)?.peek;
    // The WebSocket says each change as it happens: an answer to a check that was on its way
    // meanwhile may be older. A device that missed a switch gets it now, though: its WebSocket
    // says nothing until something changes, and then it would never get it.
    if (fromPoll && watcher?.connected) {
      if (power && this.missed.delete(d.id)) void this.sendSwitches(d);
      return;
    }
    if (!power) {
      // Gone, or only the connection: a check tells.
      void this.refreshStatus();
      return;
    }
    if (!fromPoll && this.status.get(d.id)?.online !== true) void this.refreshStatus();
    const now = Date.now();
    const prev = this.seen.get(d.id);
    this.seen.set(d.id, { ...power, at: now });
    const booted = this.booting.delete(d.id);
    if (this.missed.delete(d.id) || booted) {
      void this.sendSwitches(d).then(() => (booted ? this.restoreLook(d) : undefined));
    } else {
      // Before the first report: what the switches say.
      const before = prev ?? { on: !this.isOff(d.id), bri: this.levelOf(d.id), at: now - this.settleMs };
      // This app's own request if it went since the last report, and the change came soon
      // after it (a check can come up to one interval later than the WebSocket).
      const wrote = lastWrite(d);
      const ours = wrote > before.at - this.settleMs && now - wrote < this.settleMs + (fromPoll ? this.pollMs : 0);
      if (!ours) this.follow(d, power, before);
    }
    if (!prev || prev.on !== power.on || prev.bri !== power.bri) this.bus.emit('devices');
  }

  /** Sets the switches to a change made on the device (see observe). */
  private follow(d: Device, now: PowerState, before: { on: boolean; bri: number | null }) {
    const c = this.controls();
    let next = c;
    const what: string[] = [];
    if (now.on !== before.on && now.on === this.isOff(d.id)) {
      next = { ...next, off: now.on ? next.off.filter((id) => id !== d.id) : [...next.off, d.id] };
      what.push(`switched ${now.on ? 'on' : 'off'}`);
    }
    // A level set here follows the device; with none, each scene's presets set it anyway.
    const level = this.levelOf(d.id);
    if (now.bri !== before.bri && level != null && now.bri !== level) {
      next = { ...next, brightness: { ...next.brightness, devices: { ...next.brightness.devices, [d.id]: percent(now.bri) } } };
      what.push(`brightness ${percent(now.bri)}%`);
    }
    if (next === c) return;
    this.saveControls(next);
    this.log('info', 'power', `"${d.name}" ${what.join(', ')} outside this app`, { deviceId: d.id, on: now.on, bri: now.bri });
    this.bus.emit('state');
    if (!now.on && this.allOff()) {
      this.cancelRevert();
      this.onAllOff?.();
    }
  }

  /** Sends the device what the switches say: off, or on at its level. */
  private sendSwitches(d: Device) {
    return this.switchWled(d, !this.isOff(d.id));
  }

  /** Devices that did not get a switch get it when they answer again (see observe). */
  private noteMissed(result: ApplyResult) {
    for (const id of result.applied) this.missed.delete(id);
    for (const f of result.failed) this.missed.add(f.deviceId);
  }

  /**
   * What a scene plays: its looks, and the devices it reaches. `reach` works it out for any
   * scene, with the layout, sequences and presets read once.
   */
  private sceneReach() {
    const enabledIds = new Set(this.enabledDevices().map((d) => d.id));
    const presets = this.db.listDevicePresets();
    const layout = readLayout(this.db);
    const sequences = new Map(this.db.listSequences().map((q) => [q.id, q]));
    return (s: Scene): { looks: PresetLook[]; devices: string[] } => {
      // Effects (or a sequence) on objects that are in the layout, and the devices they are on.
      const seq = s.sequenceId ? sequences.get(s.sequenceId) : undefined;
      const objects = new Set(seq ? sequenceObjects(seq, layout) : effectObjects(layout, Object.keys(s.effects ?? {})));
      const fxDevices = new Set(layout.fixtures.filter((f) => objects.has(f.id)).map((f) => f.deviceId).filter((id): id is string => !!id && enabledIds.has(id)));
      const mapped = Object.keys(s.devicePresets).filter((id) => enabledIds.has(id) && !fxDevices.has(id));
      const looks: PresetLook[] = effectsLook(objects.size ? (seq ? sequenceEffects(seq) : Object.values(s.effects ?? {})) : []);
      for (const deviceId of mapped) {
        const p = presets[deviceId]?.find((x) => x.id === s.devicePresets[deviceId]);
        if (p?.colors?.length) looks.push({ colors: p.colors, energy: p.energy ?? 0.3 });
      }
      return { looks, devices: [...mapped, ...fxDevices] };
    };
  }

  publicState(): PublicState {
    const settings = readSettings(this.db);
    const enabled = this.enabledDevices();
    const night = this.nightState();
    // Online, or on its way: starting up, or off at its plug for the night (a visitor's pick switches it on).
    const isOnline = (id: string) => this.status.get(id)?.online === true || this.booting.has(id) || (night.lightsWake && this.plugOf(id) != null);
    const list = this.db.listScenes();
    const reach = this.sceneReach();
    const scenes = list.map((s) => {
      // A playlist looks like the scenes it plays, and is online when one of them is.
      const parts = s.playlist ? playlistSteps(s.playlist, list).map((p) => reach(p.scene)) : [reach(s)];
      const look = mergeLooks(parts.flatMap((p) => p.looks));
      const all = parts.flatMap((p) => p.devices);
      return { id: s.id, name: s.name, online: all.length === 0 ? false : all.some(isOnline), palette: look.colors, energy: look.energy, ...(s.playlist ? { playlist: true } : {}) };
    });
    const onlineDevices = enabled.filter((d) => isOnline(d.id)).length;
    return {
      title: settings.siteTitle,
      subtitle: settings.siteSubtitle,
      showColors: settings.showColors,
      scenes,
      currentSceneId: this.db.getSetting(KEY.currentScene) || null,
      currentColor: this.db.getSetting(KEY.currentColor) || null,
      playlistSceneId: this.playlistScene(),
      anyOnline: onlineDevices > 0,
      onlineDevices,
      totalDevices: enabled.length,
      revertAt: this.db.getSetting(KEY.revertAt) || null,
      lightsOff: this.allOff(),
      lightsOnAt: this.allOff() ? this.lightsOnAt() : null,
      ...night,
      hiddenGames: readHiddenGames(this.db)
    };
  }

  private nightState() {
    const n = this.nightWake();
    const off = this.allOff();
    return { lightsWake: off && n.wake, idleOffMinutes: off ? null : n.idleMinutes };
  }

  // ---------- Commands ----------

  private async fanOut(work: { device: Device; run: () => Promise<FetchResult<unknown>> }[]): Promise<ApplyResult> {
    const results = await Promise.all(work.map((w) => w.run()));
    const out: ApplyResult = { applied: [], skipped: [], failed: [] };
    results.forEach((r, i) => {
      const id = work[i].device.id;
      if (r.ok) out.applied.push(id);
      else out.failed.push({ deviceId: id, error: r.error });
      // A command result is fresh evidence of the device status.
      const prev = this.status.get(id);
      if (prev && prev.online !== r.ok) {
        this.status.set(id, { ...prev, online: r.ok });
        if (!r.ok) this.seen.delete(id);
        this.live = null;
      }
    });
    return out;
  }

  async applyScene(sceneId: string, actor?: Actor, reason: 'user' | 'revert' = 'user'): Promise<ApplyResult | null> {
    const scene = this.db.getScene(sceneId);
    if (!scene) return null;
    // A scene someone picks comes in with the scene transition; the auto-revert changes at once.
    const transition = reason === 'user' ? sceneTransitionOf(readSettings(this.db)) : null;
    let result: ApplyResult;
    if (scene.playlist) result = (await this.startPlaylist(scene, transition)) ?? { applied: [], skipped: [], failed: [], effects: 0 };
    else {
      this.stopPlaylist();
      result = await this.play(scene, transition);
    }
    const played = { objects: result.effects ?? 0 };
    const sent = result.applied.length + result.failed.length;

    if (result.applied.length > 0 || played.objects > 0 || result.starting?.length) {
      this.db.setSetting(KEY.currentScene, scene.id);
      this.db.setSetting(KEY.currentColor, '');
      const { defaultSceneId } = readSettings(this.db);
      if (scene.id === defaultSceneId) this.cancelRevert();
      else this.scheduleRevert();
    } else if (scene.playlist) this.stopPlaylist();
    const first = scene.playlist && this.playlist ? this.db.getScene(this.playlist.showing ?? '')?.name : null;
    this.log(
      result.applied.length || played.objects ? (result.failed.length ? 'warn' : 'info') : 'error',
      reason === 'revert' ? 'auto_revert' : actor?.visitor ? 'visitor' : 'applied',
      (actor?.visitor ? `${visitorLabel(actor.visitor, actor.ip)}: ` : '') +
      scene.playlist
        ? `Playlist "${scene.name}" started${first ? ` with "${first}"` : ' with no scene to play'}: ${result.applied.length}/${sent} device(s)${played.objects ? `, effects on ${played.objects} object(s)` : ''}`
        : `Scene "${scene.name}" applied to ${result.applied.length}/${sent} device(s)${played.objects ? `, effects on ${played.objects} object(s)` : ''}`,
      { sceneId: scene.id, sceneName: scene.name, ...(actor?.visitor ? { visitor: actor.visitor, ip: actor.ip } : {}), ...result },
      actor
    );
    this.bus.emit('state');
    return result;
  }

  /** Puts a scene on the lights: its effects or sequence, and its presets on the other devices. */
  private async play(scene: Scene, transition: SceneTransition | null): Promise<ApplyResult> {
    const devices = this.onDevices();
    // Effects first: a device with an object that plays an effect gets the effect, not a preset.
    const played = this.effectPlayer?.(this.showOf(scene), transition) ?? { devices: [], objects: 0 };
    const streamed = new Set(played.devices.filter((id) => !this.isOff(id)));
    const work = [];
    const skipped: string[] = [];
    // A device starting up gets the scene when it answers (see restoreLook).
    const starting: string[] = [];
    for (const device of devices) {
      const presetId = scene.devicePresets[device.id];
      if (streamed.has(device.id)) continue;
      if (!presetId) skipped.push(device.id);
      else if (this.booting.has(device.id)) starting.push(device.id);
      else work.push({ device, run: () => wled.applyPreset(device, presetId) });
    }
    const result = await this.fanOut(work);
    result.skipped = skipped;
    for (const id of streamed) {
      if (this.booting.has(id)) starting.push(id);
      else if (this.status.get(id)?.online === false) result.failed.push({ deviceId: id, error: 'Not responding' });
      else result.applied.push(id);
    }
    if (starting.length) result.starting = starting;
    result.effects = played.objects;
    if (this.ha) merge(result, await this.haShow(mergeLooks(this.sceneReach()(scene).looks).colors, streamed));
    // A preset brings its own brightness: the admin's level goes on after it (WLED applies a
    // preset a moment after the request), and on the devices that play effects.
    const leveled = devices.filter((d) => result.applied.includes(d.id) && this.levelOf(d.id) != null);
    if (leveled.length) {
      setTimeout(() => void Promise.all(leveled.map((d) => wled.brightness(d, this.levelOf(d.id)!))), 150).unref?.();
    }
    return result;
  }

  async applyColor(hex: string, actor?: Actor): Promise<ApplyResult | null> {
    const rgb = parseHex(hex);
    if (!rgb) return null;
    const color = `#${hex.replace('#', '').toLowerCase()}`;
    this.stopPlaylist();
    this.effectPlayer?.(null);
    const devices = this.onDevices();
    // A device starting up gets the color when it answers (see restoreLook).
    const starting = devices.filter((d) => this.booting.has(d.id)).map((d) => d.id);
    const result = await this.fanOut(devices.filter((d) => !this.booting.has(d.id)).map((device) => ({ device, run: () => wled.applyColor(device, rgb, this.levelOf(device.id)) })));
    if (starting.length) result.starting = starting;
    merge(result, await this.haShow([color]));
    if (result.applied.length > 0 || starting.length) {
      this.db.setSetting(KEY.currentScene, '');
      this.db.setSetting(KEY.currentColor, color);
      this.scheduleRevert();
    }
    this.log(
      result.applied.length ? (result.failed.length ? 'warn' : 'info') : 'error',
      actor?.visitor ? 'visitor' : 'applied',
      `${actor?.visitor ? `${visitorLabel(actor.visitor, actor.ip)}: c` : 'C'}olor ${color} applied to ${result.applied.length}/${devices.length} device(s)`,
      { color, ...(actor?.visitor ? { visitor: actor.visitor, ip: actor.ip } : {}), ...result },
      actor
    );
    this.bus.emit('state');
    return result;
  }

  // ---------- Power and brightness ----------

  controls(): LightControls {
    return (this.controlsCache ??= readLightControls(this.db));
  }

  private saveControls(c: LightControls) {
    writeLightControls(this.db, c);
    this.controlsCache = c;
    this.live = null;
  }

  isOff(deviceId: string): boolean {
    return this.controls().off.includes(deviceId);
  }

  /** True when there are lights and an admin switched every one of them off. */
  allOff(): boolean {
    const ids = [...this.enabledDevices().map((d) => d.id), ...this.haLights()];
    return ids.length > 0 && ids.every((id) => this.isOff(id));
  }

  /** The Home Assistant lights the site switches, as "ha:" ids (none without Home Assistant): the ones added and not disabled. */
  haLights(): string[] {
    if (!this.ha?.connected()) return [];
    const { lights, disabled } = this.ha.settings();
    return lights.filter((id) => !disabled.includes(id)).map(haId);
  }

  /** True when the site switches this Home Assistant light ("ha:" id): added, and not disabled. */
  haEnabled(id: string): boolean {
    return this.haLights().includes(id);
  }

  /** The Home Assistant plug that powers a device, or null. */
  plugOf(deviceId: string): string | null {
    return this.ha?.connected() ? (this.ha.settings().plugs[deviceId] ?? null) : null;
  }

  /** A device's name, or a Home Assistant light's. */
  private nameOf(id: string): string {
    if (isHaId(id)) return this.ha?.entity(entityOf(id))?.name ?? entityOf(id);
    return this.db.getDevice(id)?.name ?? id;
  }

  /** The devices in use (an admin can disable one in the device list). */
  private enabledDevices(): Device[] {
    return this.db.listDevices().filter((d) => d.enabled);
  }

  /** The devices in use that an admin has not switched off: the ones scenes and colors go to. */
  private onDevices(): Device[] {
    return this.enabledDevices().filter((d) => !this.isOff(d.id));
  }

  /** A device's brightness from the admin's switches, as WLED counts it (1 to 255), or null: the scene's. */
  levelOf(deviceId: string): number | null {
    const { brightness } = this.controls();
    const pct = brightness.devices[deviceId] ?? brightness.all;
    return pct == null ? null : Math.max(1, Math.round((pct / 100) * 255));
  }

  /**
   * Switches one device, or every device, on or off. Off holds: scenes, colors, effects and
   * games leave the device dark until an admin switches it on again.
   */
  async setPower(on: boolean, deviceId: string | readonly string[] | null, actor?: Actor, why?: string): Promise<ApplyResult> {
    const all = this.db.listDevices();
    const ha = this.haLights();
    const picked = deviceId == null ? null : new Set(typeof deviceId === 'string' ? [deviceId] : deviceId);
    const target = picked ? all.filter((d) => picked.has(d.id)) : all;
    const haTarget = picked ? ha.filter((id) => picked.has(id)) : ha;
    // A disabled light keeps its switch for when it is enabled again, as a disabled device does,
    // and all lights switch it too (nothing is sent to it): enabled again, it is as the rest.
    const haAll = this.ha?.connected() ? this.ha.settings().lights.map(haId) : [];
    const ids = new Set([...target.map((d) => d.id), ...(picked ? haTarget : haAll)]);
    const known = new Set([...all.map((d) => d.id), ...haAll]);
    const c = this.controls();
    const off = on ? c.off.filter((id) => !ids.has(id)) : [...new Set([...c.off, ...ids])];
    this.saveControls({ ...c, off: off.filter((id) => known.has(id)) });
    if (!on && this.allOff()) this.cancelRevert();
    const devices = target.filter((d) => d.enabled);
    const result = await this.fanOut(devices.map((device) => ({ device, run: () => this.powerDevice(device, on) })));
    // A device that was getting frames is given back on the next frame, switched off (after any
    // frame still on its way: see LightSender.giveBack).
    this.noteMissed(result);
    merge(result, await this.haSwitch(haTarget, on));
    const what = !picked ? 'All lights' : ids.size === 1 ? `"${this.nameOf([...ids][0])}"` : `${ids.size} lights`;
    this.log(result.failed.length ? 'warn' : 'info', 'power', `${what} switched ${on ? 'on' : 'off'}${why ? ` ${why}` : ''}${this.failedText(result)}`, result, actor);
    this.bus.emit('devices');
    this.bus.emit('state');
    return result;
  }

  /** The lights a command did not reach, and why, for the log's line (the console's log shows only that). */
  private failedText(r: ApplyResult): string {
    return r.failed.length ? `; not taken by ${r.failed.map((f) => `"${this.nameOf(f.deviceId)}" (${f.error})`).join(', ')}` : '';
  }

  /**
   * Switches a device on or off, and its plug when it has one: the plug first when on (the
   * controller then boots, and gets the switches and what plays when it answers), and last when
   * off, once the lights have faded out.
   */
  private async powerDevice(d: Device, on: boolean): Promise<FetchResult<unknown>> {
    const plug = this.plugOf(d.id);
    if (!plug || !this.ha) return this.switchWled(d, on);
    const done = { ok: true as const, status: 200, data: null };
    const failed = (r: { status: number; error: string }) => ({ ok: false as const, status: r.status, error: `Power plug: ${r.error}` });
    if (on) {
      if (this.ha.entity(plug)?.state === 'on' && this.status.get(d.id)?.online) return this.switchWled(d, true);
      const p = await this.ha.set(plug, true);
      if (!p.ok) return failed(p);
      this.booting.add(d.id);
      // A controller that has its own power as well answers at once.
      if (this.status.get(d.id)?.online) void this.switchWled(d, true).then((r) => r.ok && this.booting.delete(d.id));
      return done;
    }
    this.booting.delete(d.id);
    const r = await this.switchWled(d, false);
    if (r.ok) await new Promise((res) => setTimeout(res, this.plugDelayMs));
    // Switched on again meanwhile: the power stays.
    if (!this.isOff(d.id)) return r;
    const p = await this.ha.set(plug, false);
    return p.ok ? done : failed(p);
  }

  /**
   * Switches a WLED device on (at its level) or off, and keeps what it took: the device shows
   * its new state as soon as it answers, not once its WebSocket or the next check says so.
   * The report that follows is this request's (see observe).
   */
  private async switchWled(d: Device, on: boolean): Promise<FetchResult<unknown>> {
    const bri = on ? this.levelOf(d.id) : null;
    const r = await wled.power(d, on, bri);
    const seen = this.seen.get(d.id);
    if (r.ok && seen) this.seen.set(d.id, { on, bri: bri || seen.bri, at: Date.now() });
    return r;
  }

  /**
   * Switches Home Assistant lights on (at their level) or off; `what` says which, for the log
   * (a brightness is sent as an on). Each light takes its commands in turn (see
   * HomeAssistant.set): an off goes after any effects color still on its way, which would
   * otherwise come on again after it. A command that failed goes again (see haRetryMs), once
   * Home Assistant's late answer, if one comes, says it did fail.
   */
  private async haSwitch(ids: string[], on: boolean, what: 'switch' | 'brightness' = 'switch', attempt = 0): Promise<ApplyResult> {
    const out: ApplyResult = { applied: [], skipped: [], failed: [] };
    const ha = this.ha;
    if (!ha || !ids.length) return out;
    const results = await Promise.all(ids.map((id) => ha.set(entityOf(id), on, { bri: this.levelOf(id) })));
    const failed: { id: string; answer: Promise<{ ok: boolean }> }[] = [];
    results.forEach((r, i) => {
      if (r.ok) return void out.applied.push(ids[i]);
      out.failed.push({ deviceId: ids[i], error: r.error });
      failed.push({ id: ids[i], answer: r.late ?? Promise.resolve(r) });
    });
    if (failed.length && this.haRetryMs[attempt] != null) void this.haRetry(failed, on, what, attempt);
    return out;
  }

  /** Sends the commands that failed again (see haSwitch), haRetryMs[attempt] after. */
  private async haRetry(failed: { id: string; answer: Promise<{ ok: boolean }> }[], on: boolean, what: 'switch' | 'brightness', attempt: number) {
    const answers = await Promise.all(failed.map((f) => f.answer));
    const still = failed.filter((_, i) => !answers[i].ok).map((f) => f.id);
    if (!still.length || this.stopped) return;
    await new Promise((resolve) => setTimeout(resolve, this.haRetryMs[attempt]).unref?.());
    if (this.stopped) return;
    // Only the lights whose switch is still as it was, and that the site still switches.
    const again = still.filter((id) => this.isOff(id) === !on && this.haEnabled(id));
    if (!again.length) return;
    const r = await this.haSwitch(again, on, what, attempt + 1);
    const names = again.map((id) => `"${this.nameOf(id)}"`).join(', ');
    this.log(r.failed.length ? 'warn' : 'info', 'power', `${names}${what === 'brightness' ? ': brightness sent again' : ` switched ${on ? 'on' : 'off'} again`}, as it failed before${this.failedText(r)}`, r);
  }

  /**
   * The Home Assistant lights that are on show colors: a scene's (one each, in turn) or one
   * color. With none, they come on as they are.
   */
  private async haShow(colors: string[], streamed: ReadonlySet<string> = new Set(), only?: ReadonlySet<string>): Promise<ApplyResult> {
    const out: ApplyResult = { applied: [], skipped: [], failed: [] };
    const ha = this.ha;
    // A light in the layout that plays the scene's effects gets them as frames instead (see HaFrames).
    const ids = this.haLights().filter((id) => !this.isOff(id) && !streamed.has(id) && (!only || only.has(id)));
    if (!ha || !ids.length) return out;
    const rgbs = colors.map(parseHex).filter((c): c is NonNullable<typeof c> => !!c);
    const results = await Promise.all(
      ids.map((id, i) => ha.set(entityOf(id), true, { bri: this.levelOf(id), rgb: rgbs.length ? (rgbs[i % rgbs.length] as [number, number, number]) : null, transition: 1 }))
    );
    results.forEach((r, i) => (r.ok ? out.applied.push(ids[i]) : out.failed.push({ deviceId: ids[i], error: r.error })));
    return out;
  }

  /**
   * Home Assistant lights enabled again ("ha:" ids): each one's switch is as the other lights'
   * (on when any of them is on, so one held off while it was disabled does not stay dark), and
   * one that is on shows what plays now: the color, or the scene's colors (effects reach it as
   * frames by themselves).
   */
  async haEnabledAgain(ids: string[]): Promise<void> {
    if (!ids.length) return;
    const back = new Set(ids);
    const others = [...this.enabledDevices().map((d) => d.id), ...this.haLights().filter((id) => !back.has(id))];
    const c = this.controls();
    if (others.some((id) => !c.off.includes(id)) && c.off.some((id) => back.has(id))) this.saveControls({ ...c, off: c.off.filter((id) => !back.has(id)) });
    const on = ids.filter((id) => !this.isOff(id));
    if (!on.length) return;
    const color = this.db.getSetting(KEY.currentColor) || '';
    const scene = this.showingScene();
    const colors = color ? [color] : scene ? mergeLooks(this.sceneReach()(scene).looks).colors : [];
    await this.haShow(colors, new Set(), new Set(on));
    this.bus.emit('devices');
    this.bus.emit('state');
  }

  /** A device that booted (its plug came on) shows what plays now: the color, or its preset. */
  private async restoreLook(d: Device) {
    if (this.isOff(d.id)) return;
    const color = parseHex(this.db.getSetting(KEY.currentColor) || '');
    if (color) return void (await wled.applyColor(d, color as [number, number, number], this.levelOf(d.id)));
    const presetId = this.showingScene()?.devicePresets[d.id];
    if (!presetId) return;
    await wled.applyPreset(d, presetId);
    const bri = this.levelOf(d.id);
    if (bri != null) setTimeout(() => void wled.brightness(d, bri), 150).unref?.();
  }

  /**
   * A light or switch changed in Home Assistant (its event, or a refresh): the console shows it
   * at once. Switched on or off by someone else, it waits in haSeen for followHa.
   */
  private haChanged(e: HaEntity & { from: string }) {
    this.bus.emit('devices');
    // Only on to off and back: a light coming back from unavailable (a Zigbee light that missed
    // a few checks) says what it is, which is no one switching it.
    if ((e.state !== 'on' && e.state !== 'off') || (e.from !== 'on' && e.from !== 'off')) return void this.haSeen.delete(e.id);
    // This app's own switch, coming back.
    if (Date.now() - (this.ha?.lastWrite(e.id) ?? 0) < this.settleMs + this.pollMs) return;
    this.haSeen.set(e.id, { state: e.state, at: Date.now(), check: this.haCheck });
  }

  /**
   * Home Assistant's lights and plugs, read with each status check (and told by its events in
   * between). A light or plug switched in Home Assistant (or by its own button) is switched that
   * way here too, as for WLED's own app, once it has held until the next check, and for most of
   * a check's interval: a Zigbee light that says off for a moment, then on again, is not taken
   * as switched off.
   */
  private async followHa() {
    const ha = this.ha;
    if (!ha?.connected()) return;
    const check = ++this.haCheck;
    const start = Date.now();
    const { ok } = await ha.refresh();
    if (!ok) return;
    const hold = Math.min(this.pollMs, 10_000) * 0.8;
    const confirmed: [string, 'on' | 'off'][] = [];
    for (const [id, seen] of this.haSeen) {
      if (seen.check >= check || start - seen.at < hold) continue;
      this.haSeen.delete(id);
      if (ha.entity(id)?.state === seen.state && Date.now() - ha.lastWrite(id) >= this.settleMs + this.pollMs) confirmed.push([id, seen.state]);
    }
    if (!confirmed.length) return;
    const { plugs } = ha.settings();
    const lights = new Set(this.haLights());
    let c = this.controls();
    const switched: string[] = [];
    for (const [entity, state] of confirmed) {
      const e = { id: entity };
      const on = state === 'on';
      const ids = [...Object.entries(plugs).filter(([, p]) => p === e.id).map(([id]) => id), ...(lights.has(haId(e.id)) ? [haId(e.id)] : [])];
      for (const id of ids) {
        if (on !== c.off.includes(id)) continue;
        c = { ...c, off: on ? c.off.filter((x) => x !== id) : [...c.off, id] };
        if (on && !isHaId(id)) this.booting.add(id);
        switched.push(`"${this.nameOf(id)}" switched ${on ? 'on' : 'off'}`);
      }
    }
    if (!switched.length) return;
    this.saveControls(c);
    this.log('info', 'power', `${switched.join(', ')} in Home Assistant`);
    this.bus.emit('state');
    if (this.allOff()) {
      this.cancelRevert();
      this.onAllOff?.();
    }
  }

  /**
   * Sets the brightness (percent, 1 to 100) of one device, or of every device. Null: one device
   * follows "all" again; for all, each scene's presets set it again.
   */
  async setBrightness(pct: number | null, deviceId: string | null, actor?: Actor): Promise<ApplyResult> {
    const c = this.controls();
    const devicesLevels = { ...c.brightness.devices };
    if (deviceId) {
      if (pct == null) delete devicesLevels[deviceId];
      else devicesLevels[deviceId] = pct;
    }
    this.saveControls({ ...c, brightness: deviceId ? { ...c.brightness, devices: devicesLevels } : { all: pct, devices: devicesLevels } });
    const devices = this.onDevices().filter((d) => !deviceId || d.id === deviceId);
    const work = devices.flatMap((device) => {
      const bri = this.levelOf(device.id);
      return bri == null ? [] : [{ device, run: () => wled.brightness(device, bri) }];
    });
    const result = await this.fanOut(work);
    this.noteMissed(result);
    const haIds = this.haLights().filter((id) => !this.isOff(id) && (!deviceId || id === deviceId) && this.levelOf(id) != null);
    merge(result, await this.haSwitch(haIds, true, 'brightness'));
    const what = deviceId ? `"${this.nameOf(deviceId)}"` : 'All lights';
    this.log(result.failed.length ? 'warn' : 'info', 'power', `${what}: brightness ${pct == null ? (deviceId ? 'follows all lights' : 'set by each scene') : `${pct}%`}`, result, actor);
    this.bus.emit('devices');
    return result;
  }

  // ---------- Device presets ----------

  /** Reads presets.json from a device and stores the list. Never throws. */
  async importPresets(deviceId: string): Promise<PresetImport> {
    const device = this.db.getDevice(deviceId);
    if (!device) return { deviceId, ok: false, error: 'Unknown device' };
    const r = await wled.presets(device);
    if (!r.ok) return { deviceId, ok: false, error: r.error };
    this.db.replaceDevicePresets(device.id, r.data);
    this.bus.emit('devices');
    return { deviceId, ok: true, count: r.data.length };
  }

  /** Imports presets for newly added devices and logs one line with the outcome. */
  async importPresetsForNew(deviceIds: string[], actor?: Actor): Promise<PresetImport[]> {
    if (!deviceIds.length) return [];
    const results = await Promise.all(deviceIds.map((id) => this.importPresets(id)));
    const ok = results.filter((r) => r.ok);
    const total = ok.reduce((n, r) => n + (r.ok ? r.count : 0), 0);
    this.log(
      ok.length === results.length ? 'info' : 'warn',
      'import',
      `Imported ${total} preset(s) from ${ok.length}/${results.length} new device(s)`,
      results,
      actor
    );
    return results;
  }

  // ---------- Auto-revert ----------
  // The revert time is stored, so a restart does not lose a pending revert.

  scheduleRevert() {
    const { revertMinutes, defaultSceneId } = readSettings(this.db);
    if (revertMinutes <= 0 || !defaultSceneId || this.allOff()) return this.cancelRevert();
    const at = new Date(Date.now() + revertMinutes * 60_000);
    this.db.setSetting(KEY.revertAt, at.toISOString());
    this.armRevert(at);
    this.log('info', 'auto_revert', `Scheduled in ${revertMinutes} minute(s)`);
  }

  cancelRevert() {
    if (this.revertTimer) clearTimeout(this.revertTimer);
    this.revertTimer = null;
    if (this.db.getSetting(KEY.revertAt)) this.db.setSetting(KEY.revertAt, '');
  }

  /** Call after settings change. A pending revert restarts with the new values. */
  /** Told when the settings change (the frame rate limit goes to the sender). */
  settingsHook: (() => void) | null = null;

  onSettingsChanged() {
    this.settingsHook?.();
    if (this.db.getSetting(KEY.revertAt)) this.scheduleRevert();
    this.bus.emit('state');
  }

  private armRevert(at: Date) {
    if (this.revertTimer) clearTimeout(this.revertTimer);
    const ms = Math.max(0, at.getTime() - Date.now());
    this.revertTimer = setTimeout(() => void this.revertNow(), Math.min(ms, 2 ** 31 - 1));
  }

  private restoreRevertTimer() {
    const at = this.db.getSetting(KEY.revertAt);
    if (at && !Number.isNaN(Date.parse(at))) this.armRevert(new Date(at));
  }

  private async revertNow() {
    this.revertTimer = null;
    this.db.setSetting(KEY.revertAt, '');
    const { defaultSceneId } = readSettings(this.db);
    // Lights switched off stay off.
    if (this.allOff()) {
      this.bus.emit('state');
      return;
    }
    if (!defaultSceneId || !this.db.getScene(defaultSceneId)) {
      this.log('warn', 'auto_revert', 'Default scene is not set or no longer exists');
      this.bus.emit('state');
      return;
    }
    await this.applyScene(defaultSceneId, undefined, 'revert');
  }
}
