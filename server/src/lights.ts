import { effectObjects, effectsLook, type EffectSettings } from '../../shared/effects.ts';
import { sequenceEffects, sequenceObjects, type Sequence } from '../../shared/sequence.ts';
import type { ApplyResult, Device, DeviceInfo, DeviceWithStatus, LightControls, LogLevel, PublicState, Scene } from '../../shared/types.ts';
import { readLayout } from './layoutStore.ts';
import type { Db } from './db.ts';
import type { Bus } from './events.ts';
import { KEY, readLightControls, readSettings, writeLightControls } from './settings.ts';
import { hexToRgb, wled, type FetchResult } from './wled.ts';
import { mergeLooks, type PresetLook } from './presetLook.ts';

export type PresetImport = { deviceId: string; ok: true; count: number } | { deviceId: string; ok: false; error: string };

/**
 * Plays a scene's effects on the layout objects, or a sequence (null: stops them). Returns the
 * devices that get the frames and the number of objects that are lit.
 */
export type EffectPlayer = (show: { effects?: Record<string, EffectSettings> | null; sequence?: Sequence | null } | null) => { devices: string[]; objects: number };

export interface Actor {
  ip?: string | null;
  userAgent?: string | null;
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
  private db: Db;
  private bus: Bus;
  private effectPlayer: EffectPlayer | null = null;

  /** devicesWithStatus() for the frame loops, which ask 60 times a second (see liveDevices). */
  private live: (DeviceWithStatus & { switchedOff?: boolean })[] | null = null;
  /** The admin's power and brightness switches, read once and kept up to date. */
  private controlsCache: LightControls | null = null;

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

  /** After a restart: the scene that was playing plays again, if it has effects or a sequence. */
  resumeEffects() {
    const id = this.db.getSetting(KEY.currentScene);
    const show = this.showOf(id ? this.db.getScene(id) : null);
    if (show) this.effectPlayer?.(show);
  }

  /** A scene was changed: if it is playing, play its new effects at once. */
  sceneChanged(sceneId: string) {
    if (this.db.getSetting(KEY.currentScene) !== sceneId) return;
    this.effectPlayer?.(this.showOf(this.db.getScene(sceneId)));
  }

  /** A sequence was saved or deleted: a playing scene that uses it plays the new version. */
  sequenceChanged(sequenceId: string) {
    const id = this.db.getSetting(KEY.currentScene);
    const scene = id ? this.db.getScene(id) : null;
    if (scene && (scene.sequenceId === sequenceId || !scene.sequenceId)) this.effectPlayer?.(this.showOf(scene));
  }

  /** A scene was deleted: if it was playing, its effects stop. */
  sceneDeleted(sceneId: string) {
    if (this.db.getSetting(KEY.currentScene) === sceneId) {
      this.effectPlayer?.(null);
      this.db.setSetting(KEY.currentScene, '');
    }
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
    void this.refreshStatus();
    this.pollTimer = setInterval(() => void this.refreshStatus(), intervalMs);
    this.restoreRevertTimer();
  }

  stop() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.revertTimer) clearTimeout(this.revertTimer);
  }

  /**
   * A device's info, with its LED outputs (see DeviceInfo.outputs). The outputs are read once,
   * and again when the LED count changes: they live in the device's settings.
   */
  private async readInfo(d: Device): Promise<FetchResult<DeviceInfo>> {
    const r = await wled.info(d, 3000);
    if (!r.ok) return r;
    const prev = this.status.get(d.id)?.info;
    if (prev?.outputs && prev.leds?.count === r.data.leds?.count) return { ...r, data: { ...r.data, outputs: prev.outputs } };
    const o = await wled.outputs(d);
    return o.ok ? { ...r, data: { ...r.data, outputs: o.data } } : r;
  }

  async refreshStatus(): Promise<void> {
    const devices = this.db.listDevices().filter((d) => d.enabled);
    // A device busy with real-time frames over Wi-Fi can answer slowly; allow 3 s.
    const results = await Promise.all(devices.map((d) => this.readInfo(d)));
    let changed = false;
    const seen = new Set<string>();
    devices.forEach((d, i) => {
      seen.add(d.id);
      const r = results[i];
      const prev = this.status.get(d.id);
      const misses = r.ok ? 0 : (prev?.misses ?? 0) + 1;
      const next: Status = r.ok
        ? { online: true, misses, info: r.data, lastSeen: new Date().toISOString() }
        : // Offline only after two missed checks in a row, so one slow answer does not flash "offline".
          { online: prev?.online === true && misses < 2, misses, info: prev?.info ?? null, lastSeen: prev?.lastSeen ?? null };
      if (!prev || prev.online !== next.online) changed = true;
      this.status.set(d.id, next);
      this.live = null;
    });
    for (const id of this.status.keys()) {
      if (!seen.has(id)) {
        this.status.delete(id);
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

  devicesWithStatus(): DeviceWithStatus[] {
    return this.db.listDevices().map((d) => {
      const s = this.status.get(d.id);
      return { ...d, online: d.enabled ? (s?.online ?? null) : null, info: s?.info ?? null, lastSeen: s?.lastSeen ?? null };
    });
  }

  publicState(): PublicState {
    const settings = readSettings(this.db);
    const enabled = this.db.listDevices().filter((d) => d.enabled);
    const isOnline = (id: string) => this.status.get(id)?.online === true;
    const enabledIds = new Set(enabled.map((d) => d.id));
    const presets = this.db.listDevicePresets();
    const layout = readLayout(this.db);
    const sequences = new Map(this.db.listSequences().map((q) => [q.id, q]));
    const scenes = this.db.listScenes().map((s) => {
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
      const look = mergeLooks(looks);
      const all = [...mapped, ...fxDevices];
      return { id: s.id, name: s.name, online: all.length === 0 ? false : all.some(isOnline), palette: look.colors, energy: look.energy };
    });
    const onlineDevices = enabled.filter((d) => isOnline(d.id)).length;
    return {
      title: settings.siteTitle,
      subtitle: settings.siteSubtitle,
      showColors: settings.showColors,
      scenes,
      currentSceneId: this.db.getSetting(KEY.currentScene) || null,
      currentColor: this.db.getSetting(KEY.currentColor) || null,
      anyOnline: onlineDevices > 0,
      onlineDevices,
      totalDevices: enabled.length,
      revertAt: this.db.getSetting(KEY.revertAt) || null,
      lightsOff: this.allOff()
    };
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
        this.live = null;
      }
    });
    return out;
  }

  async applyScene(sceneId: string, actor?: Actor, reason: 'user' | 'revert' = 'user'): Promise<ApplyResult | null> {
    const scene = this.db.getScene(sceneId);
    if (!scene) return null;
    const devices = this.db.listDevices().filter((d) => d.enabled && !this.isOff(d.id));
    // Effects first: a device with an object that plays an effect gets the effect, not a preset.
    const played = this.effectPlayer?.(this.showOf(scene)) ?? { devices: [], objects: 0 };
    const streamed = new Set(played.devices.filter((id) => !this.isOff(id)));
    const work = [];
    const skipped: string[] = [];
    for (const device of devices) {
      const presetId = scene.devicePresets[device.id];
      if (streamed.has(device.id)) continue;
      if (!presetId) skipped.push(device.id);
      else work.push({ device, run: () => wled.applyPreset(device, presetId) });
    }
    const result = await this.fanOut(work);
    result.skipped = skipped;
    for (const id of streamed) {
      if (this.status.get(id)?.online === false) result.failed.push({ deviceId: id, error: 'Not responding' });
      else result.applied.push(id);
    }
    result.effects = played.objects;
    // A preset brings its own brightness: the admin's level goes on after it (WLED applies a
    // preset a moment after the request), and on the devices that play effects.
    const leveled = devices.filter((d) => result.applied.includes(d.id) && this.levelOf(d.id) != null);
    if (leveled.length) {
      setTimeout(() => void Promise.all(leveled.map((d) => wled.brightness(d, this.levelOf(d.id)!))), 150).unref?.();
    }

    if (result.applied.length > 0 || played.objects > 0) {
      this.db.setSetting(KEY.currentScene, scene.id);
      this.db.setSetting(KEY.currentColor, '');
      const { defaultSceneId } = readSettings(this.db);
      if (scene.id === defaultSceneId) this.cancelRevert();
      else this.scheduleRevert();
    }
    this.log(
      result.applied.length || played.objects ? (result.failed.length ? 'warn' : 'info') : 'error',
      reason === 'revert' ? 'auto_revert' : 'applied',
      `Scene "${scene.name}" applied to ${result.applied.length}/${work.length + streamed.size} device(s)${played.objects ? `, effects on ${played.objects} object(s)` : ''}`,
      { sceneId: scene.id, sceneName: scene.name, ...result },
      actor
    );
    this.bus.emit('state');
    return result;
  }

  async applyColor(hex: string, actor?: Actor): Promise<ApplyResult | null> {
    const rgb = hexToRgb(hex);
    if (!rgb) return null;
    const color = `#${hex.replace('#', '').toLowerCase()}`;
    this.effectPlayer?.(null);
    const devices = this.db.listDevices().filter((d) => d.enabled && !this.isOff(d.id));
    const result = await this.fanOut(devices.map((device) => ({ device, run: () => wled.applyColor(device, rgb, this.levelOf(device.id)) })));
    if (result.applied.length > 0) {
      this.db.setSetting(KEY.currentScene, '');
      this.db.setSetting(KEY.currentColor, color);
      this.scheduleRevert();
    }
    this.log(
      result.applied.length ? (result.failed.length ? 'warn' : 'info') : 'error',
      'applied',
      `Color ${color} applied to ${result.applied.length}/${devices.length} device(s)`,
      { color, ...result },
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
    const enabled = this.db.listDevices().filter((d) => d.enabled);
    return enabled.length > 0 && enabled.every((d) => this.isOff(d.id));
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
  async setPower(on: boolean, deviceId: string | null, actor?: Actor): Promise<ApplyResult> {
    const all = this.db.listDevices();
    const target = deviceId ? all.filter((d) => d.id === deviceId) : all;
    const ids = new Set(target.map((d) => d.id));
    const c = this.controls();
    const off = on ? c.off.filter((id) => !ids.has(id)) : [...new Set([...c.off, ...ids])];
    this.saveControls({ ...c, off: off.filter((id) => all.some((d) => d.id === id)) });
    if (!on && this.allOff()) this.cancelRevert();
    const devices = target.filter((d) => d.enabled);
    const result = await this.fanOut(devices.map((device) => ({ device, run: () => wled.power(device, on, this.levelOf(device.id)) })));
    // A device that was getting frames is given back on the next frame, and over HTTP that
    // switches it on again: say off once more after that.
    if (!on) setTimeout(() => void Promise.all(devices.filter((d) => this.isOff(d.id)).map((d) => wled.power(d, false))), 600).unref?.();
    const what = deviceId ? `"${target[0]?.name ?? deviceId}"` : 'All lights';
    this.log(result.failed.length ? 'warn' : 'info', 'power', `${what} switched ${on ? 'on' : 'off'}`, result, actor);
    this.bus.emit('devices');
    this.bus.emit('state');
    return result;
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
    const devices = this.db.listDevices().filter((d) => d.enabled && !this.isOff(d.id) && (!deviceId || d.id === deviceId));
    const work = devices.flatMap((device) => {
      const bri = this.levelOf(device.id);
      return bri == null ? [] : [{ device, run: () => wled.brightness(device, bri) }];
    });
    const result = await this.fanOut(work);
    const what = deviceId ? `"${devices[0]?.name ?? deviceId}"` : 'All lights';
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
  onSettingsChanged() {
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
