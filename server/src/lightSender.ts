import type { Device, DeviceInfo } from '../../shared/types.ts';
import { MAX_FPS, sendFps } from './ledTiming.ts';
import { DDP_PORT, RealtimeOut } from './realtime.ts';
import { FrameRateHold, type DeviceCheck } from './frameRateHold.ts';
import { wled } from './wled.ts';

/** A pixel whose brightest channel is below this is sent as off. */
export const MIN_PIXEL = 16;
/** In a pixel that stays on, a channel below this is sent as 0. */
const MIN_CHANNEL = 4;

/**
 * Real LEDs cannot show very dim colors. At values of a few steps (less still after the
 * device's own brightness), each LED lights a different channel or flickers, so a "faint
 * glow" shows as scattered red, green and blue dots. Such pixels go out as off, and a tiny
 * channel in a brighter pixel goes out as 0, so it does not tint the color.
 */
export function blackLevel(rgb: Uint8Array, out: Uint8Array = new Uint8Array(rgb.length)): Uint8Array {
  for (let i = 0; i + 2 < rgb.length; i += 3) {
    const r = rgb[i], g = rgb[i + 1], b = rgb[i + 2];
    if (r < MIN_PIXEL && g < MIN_PIXEL && b < MIN_PIXEL) {
      out[i] = out[i + 1] = out[i + 2] = 0;
      continue;
    }
    out[i] = r < MIN_CHANNEL ? 0 : r;
    out[i + 1] = g < MIN_CHANNEL ? 0 : g;
    out[i + 2] = b < MIN_CHANNEL ? 0 : b;
  }
  return out;
}

export type DeviceTarget = Device & {
  info: DeviceInfo | null;
  /** Switched off by an admin (enabled is then false): only an editor's preview lights it (see LightFrame.wakes). */
  switchedOff?: boolean;
};

/**
 * Whether a device shows frames: one that is enabled and on, or, for a frame that `wakes` it
 * (an editor's preview, which the admin turned on to see it on the lights), one an admin
 * switched off. The one place that decides it, for the pipeline, the editors and the roof view.
 */
export const takesFrames = (d: DeviceTarget, wakes = false) => d.enabled || (wakes && !!d.switchedOff);

/** How frames reach one device. */
export type LinkMode = 'checking' | 'udp' | 'http';

export interface LinkStatus {
  mode: LinkMode;
  /** Plain-language reason, for the debug panel. */
  note: string;
}

/** After this long, the device must report that it shows real-time data, or we switch to HTTP. */
const PROBE_AFTER_MS = 700;
/** HTTP is much slower than UDP: at most this many frames per second. */
const HTTP_FPS = 12;
/** A stream with no frames for this long has ended; HTTP streams then give the device back. */
const IDLE_MS = 2500;
/**
 * A frame the device already shows is not sent again, but at least this often, well within
 * WLED's real-time timeout (2.5 s), so the device keeps showing the stream.
 */
const RESEND_MS = 1000;

const HTTP_NOTE = (d: DeviceTarget) =>
  `Real-time UDP (DDP, port ${d.info?.ddpport ?? DDP_PORT}) did not reach the device, so frames go over HTTP: slower, about ${HTTP_FPS} per second.`;

interface Link {
  mode: LinkMode;
  startedAt: number;
  lastFrame: number;
  probing: boolean;
  inflight: boolean;
  lastHttp: number;
  /** Done once a device that was off has been told to switch on (see wake). */
  woke: Promise<void>;
  /** Done once the last HTTP frame has reached the device (or failed to). */
  flight: Promise<void>;
  /** The device as it was at its last frame (an admin may switch it on or off meanwhile). */
  device: DeviceTarget;
  idleTimer: NodeJS.Timeout | null;
  note: string;
  /** Smoothed time for one HTTP frame to reach the device, in ms. */
  httpMs: number;
  /** When the device last got a frame from this link (0: not yet, or it must get the next one). */
  sentAt: number;
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

/**
 * Sends LED colors to WLED devices. It uses DDP over UDP (fast; the device returns to normal
 * by itself). It checks that the device really received the frames; if not (for example, a
 * router between two networks drops UDP), it falls back to the JSON API over HTTP, which
 * works wherever the web app can reach the device, at about 12 frames per second.
 */
export class LightSender {
  private udp = new RealtimeOut();
  private links = new Map<string, Link>();
  /**
   * For each device: the frame it shows (after blackLevel) and the next one. The two swap, so
   * no frame needs a new buffer; a frame is copied into packets as it is sent.
   */
  private frames = new Map<string, { shown: Uint8Array; next: Uint8Array }>();
  /** Devices that UDP did not reach, and until when to go straight to HTTP for them. */
  private httpUntil = new Map<string, number>();
  /** When we last told a device to show its own state over a real-time stream (lor: 1). */
  private overrideAt = new Map<string, number>();
  /**
   * Devices given back a moment ago, whether each was on before, and when: a stream that
   * starts again soon after must not read the state before the device has gone back to it.
   */
  private gaveBack = new Map<string, { on: boolean; at: number }>();
  private log: (level: 'info' | 'warn', msg: string) => void;
  /** The most frames a second any device is sent (the admin's limit, see Settings.maxFps). */
  maxFps: number = MAX_FPS;
  /** The pipeline's clock (see frameClock): a device gets every frame of it, or an even share. */
  clockHz: number = MAX_FPS;
  /** Devices that fell behind, held to fewer frames (see FrameRateHold). */
  readonly hold = new FrameRateHold();

  constructor(log: (level: 'info' | 'warn', msg: string) => void = () => {}) {
    this.log = log;
  }

  /** `rgb`: one byte triple per LED, from device LED 0. */
  send(d: DeviceTarget, input: Uint8Array) {
    let f = this.frames.get(d.id);
    if (!f || f.next.length !== input.length) this.frames.set(d.id, (f = { shown: new Uint8Array(input.length), next: new Uint8Array(input.length) }));
    const rgb = blackLevel(input, f.next);
    const now = Date.now();
    let link = this.links.get(d.id);
    if (!link) {
      link = { mode: 'checking', startedAt: now, lastFrame: now, probing: false, inflight: false, lastHttp: 0, woke: Promise.resolve(), flight: Promise.resolve(), device: d, idleTimer: null, httpMs: 80, sentAt: 0, note: 'Checking that real-time UDP (DDP) reaches the device.' };
      link.woke = this.wake(d, link);
      // We may have told the device to ignore real-time data a moment ago (see end()); a new
      // stream must undo that, or the device would keep ignoring it.
      if (now - (this.overrideAt.get(d.id) ?? 0) < 10_000) {
        this.overrideAt.delete(d.id);
        void wled.setState(d, { lor: 0 }, 1500);
      }
      if ((this.httpUntil.get(d.id) ?? 0) > now) {
        link.mode = 'http';
        link.note = HTTP_NOTE(d);
      }
      this.links.set(d.id, link);
    }
    link.lastFrame = now;
    link.device = d;
    this.armIdle(d, link);
    if (link.mode === 'checking' && !link.probing && now - link.startedAt > PROBE_AFTER_MS) void this.probe(d, link);

    if (link.sentAt) {
      // The device already shows this frame (an editor view between blinks, a still scene).
      if (now - link.sentAt < RESEND_MS && sameBytes(rgb, f.shown)) return;
      // It is still drawing the last one: a long strip cannot show every frame. It gets every
      // second or third frame of the clock (see sendFps); the clock's ticks jitter by a few ms,
      // hence the margin.
      const fps = this.rate(d);
      if (fps < this.clockHz && now - link.sentAt < 1000 / fps - 4) return;
    }
    const sent = link.mode === 'http' ? this.sendHttp(d, link, rgb) : (this.udp.sendDdp(d.host, d.info?.ddpport ?? DDP_PORT, rgb), true);
    if (!sent) return;
    link.sentAt = now;
    f.next = f.shown;
    f.shown = rgb;
  }

  /**
   * The most frames a second this device gets now (null: no frames lately), and whether its
   * hold makes that fewer than it would get. A still picture is sent less often (see RESEND_MS).
   */
  sending(d: DeviceTarget): { fps: number; held: boolean } | null {
    const link = this.links.get(d.id);
    if (!link || Date.now() - link.lastFrame >= IDLE_MS) return null;
    if (link.mode === 'http') return { fps: HTTP_FPS, held: false };
    const fps = this.rate(d);
    return { fps: Math.round(fps * 10) / 10, held: fps < sendFps(d.info, this.maxFps, this.clockHz) };
  }

  /** The frames a second this device is sent while it gets frames: its strip's, the admin's limit, or its hold. */
  rate(d: DeviceTarget): number {
    return sendFps(d.info, Math.min(this.maxFps, this.hold.limit(d.id)), this.clockHz);
  }

  /**
   * A status check of a device (see FrameRateHold): one that falls behind while it gets frames
   * over UDP gets fewer.
   */
  checked(d: DeviceTarget, c: DeviceCheck) {
    const link = this.links.get(d.id);
    const sending = link && link.mode === 'udp' && Date.now() - link.lastFrame < IDLE_MS ? this.rate(d) : 0;
    const change = this.hold.checked(d.id, d.name, c, sending, this.maxFps, this.clockHz);
    if (change) this.log(change.includes('behind') ? 'warn' : 'info', change);
  }

  /**
   * About how long until a frame sent now shows on the device, in ms. Callers that keep an
   * animation in step with a clock (the editor's pulse) draw that far ahead.
   */
  delay(deviceId: string): number {
    const l = this.links.get(deviceId);
    // HTTP: the request time, plus on average half a frame of waiting for the frame limit.
    return l?.mode === 'http' ? l.httpMs + 1000 / HTTP_FPS / 2 : 5;
  }

  status(deviceId: string): LinkStatus | null {
    const l = this.links.get(deviceId);
    if (!l) return null;
    const held = this.hold.all()[deviceId];
    return { mode: l.mode, note: held ? `${l.note} It fell behind, so it gets ${Math.round(held * 10) / 10} frames a second until it keeps up.` : l.note };
  }

  /**
   * Ends the stream to one device now, and puts its own state back at once (its color, scene
   * or preset, or off), instead of after its real-time timeout (see giveBack).
   */
  end(d: DeviceTarget) {
    const link = this.links.get(d.id);
    if (!link) return;
    if (link.idleTimer) clearTimeout(link.idleTimer);
    this.links.delete(d.id);
    this.giveBack(d, link);
  }

  /**
   * Gives back every device that gets frames over HTTP now (unfreezes its effect), and
   * switches off again a device an admin switched off (an editor's preview lit it). Call it
   * before the server stops; otherwise such a device would stay frozen on the last frame, or on.
   */
  async release(devices: DeviceTarget[]) {
    await Promise.all(
      devices.map((d) => {
        const link = this.links.get(d.id);
        const off = link && !this.onAfter(link);
        if (!link || (link.mode !== 'http' && !off)) return null;
        const body = { ...(off ? { on: false } : {}), ...(link.mode === 'http' ? { seg: { id: 0, frz: false } } : {}) };
        return Promise.all([link.woke, link.flight]).then(() => wled.setState(d, body, 800));
      })
    );
  }

  close() {
    for (const l of this.links.values()) if (l.idleTimer) clearTimeout(l.idleTimer);
    this.udp.close();
  }

  /** Asks the device whether it is showing real-time data now. */
  private async probe(d: DeviceTarget, link: Link) {
    link.probing = true;
    const r = await wled.live(d);
    link.probing = false;
    if (this.links.get(d.id) !== link) return;
    if (r.ok && r.data) {
      link.mode = 'udp';
      link.note = 'Real-time UDP (DDP): fast and smooth, whole frames at once.';
      return;
    }
    if (!r.ok) {
      // The device did not answer; try again on a later frame.
      link.startedAt = Date.now();
      return;
    }
    link.mode = 'http';
    link.note = HTTP_NOTE(d);
    // The frames sent over UDP did not arrive: send the next one, even if it is the same.
    link.sentAt = 0;
    // Check UDP again after a while, in case the network changes.
    this.httpUntil.set(d.id, Date.now() + 10 * 60_000);
    this.log('warn', `Real-time UDP did not reach "${d.name}" (${d.host}). Sending frames over HTTP instead, about ${HTTP_FPS} per second. A router or firewall between the networks can drop UDP.`);
  }

  /** Returns false when the frame is skipped (one is on its way, or the frame limit). */
  private sendHttp(d: DeviceTarget, link: Link, rgb: Uint8Array): boolean {
    const now = Date.now();
    if (link.inflight || now - link.lastHttp < 1000 / HTTP_FPS) return false;
    link.inflight = true;
    link.lastHttp = now;
    const hex: string[] = [];
    for (let i = 0; i + 2 < rgb.length; i += 3) hex.push(((rgb[i] << 16) | (rgb[i + 1] << 8) | rgb[i + 2]).toString(16).padStart(6, '0'));
    link.flight = (async () => {
      await link.woke;
      // Given back while it waited: the frame would switch the device on again.
      if (this.links.get(d.id) !== link) return;
      // "i" sets the LEDs of segment 0 from its first LED, and freezes its effect.
      const t0 = Date.now();
      const r = await wled.setState(d, { on: true, seg: { id: 0, i: hex } }, 1500);
      if (r.ok) link.httpMs = link.httpMs * 0.8 + (Date.now() - t0) * 0.2;
    })().finally(() => (link.inflight = false));
    return true;
  }

  private armIdle(d: DeviceTarget, link: Link) {
    if (link.idleTimer) return;
    const wait = Math.max(50, IDLE_MS - (Date.now() - link.lastFrame));
    link.idleTimer = setTimeout(() => {
      link.idleTimer = null;
      if (Date.now() - link.lastFrame < IDLE_MS) return this.armIdle(d, link);
      this.links.delete(d.id);
      // UDP streams end by themselves, but a device an admin switched off goes off again. An
      // HTTP stream gives the device back: unfreeze the effect.
      if (link.mode === 'http') this.giveBack(link.device, link);
      else if (!this.onAfter(link)) this.giveBack(link.device, link, false);
    }, wait);
    link.idleTimer.unref?.();
  }

  /**
   * A device that is off (switched off by an admin here, for an editor's preview, or a moment
   * before the app hears that it was switched on) would not show the frames: it is switched on
   * for them.
   */
  private async wake(d: DeviceTarget, link: Link) {
    const recent = this.gaveBack.get(d.id);
    let on: boolean;
    if (recent && Date.now() - recent.at < 10_000) on = recent.on;
    else {
      const s = await wled.state(d);
      on = s.ok ? s.data.on !== false : true;
    }
    if (!on && this.links.get(d.id) === link) await wled.setState(d, { on: true }, 1500);
  }

  /**
   * Whether the device is on once the stream ends: as the admin's switch says now (see
   * DeviceTarget.switchedOff), not as the device was when the stream started. A device switched
   * off in WLED is switched off here too (see Lights.observe), so the switch knows. What the
   * stream found could be stale (a switch-on still on its way, a device given back off a moment
   * ago), and switching the device off by it left a device dark that the switch says is on: at
   * the next start the app took that for a change made outside it, and switched it off for good.
   */
  private onAfter(link: Link): boolean {
    return !link.device.switchedOff;
  }

  /**
   * Puts the device's own state back: on, or off when an admin has switched it off (see onAfter). UDP: "lor: 1"
   * tells WLED to show its own state until the real-time data has ended (it resets by
   * itself). HTTP: unfreeze the effect. `override: false`: the real-time data has ended already.
   *
   * It goes after anything the stream still has on its way (switching the device on, an HTTP
   * frame, which switches it on too), so the device ends as this says: an admin's "off" holds.
   */
  private giveBack(d: DeviceTarget, link: Link, override = true) {
    link.device = d;
    const on = this.onAfter(link);
    this.gaveBack.set(d.id, { on, at: Date.now() });
    const power = on ? {} : { on: false };
    let body: Record<string, unknown> | null = null;
    if (link.mode === 'http') body = { on, seg: { id: 0, frz: false } };
    else if (override) {
      this.overrideAt.set(d.id, Date.now());
      body = { lor: 1, ...power };
    } else if (!on) body = power;
    if (body) void Promise.all([link.woke, link.flight]).then(() => wled.setState(d, body));
  }
}
