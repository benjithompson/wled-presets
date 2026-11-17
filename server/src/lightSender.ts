import type { Device, DeviceInfo } from '../../shared/types.ts';
import { DDP_PORT, RealtimeOut } from './realtime.ts';
import { baseUrl, requestJson } from './wled.ts';

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
export function blackLevel(rgb: Uint8Array): Uint8Array {
  const out = new Uint8Array(rgb.length);
  for (let i = 0; i + 2 < rgb.length; i += 3) {
    const r = rgb[i], g = rgb[i + 1], b = rgb[i + 2];
    if (Math.max(r, g, b) < MIN_PIXEL) continue;
    out[i] = r < MIN_CHANNEL ? 0 : r;
    out[i + 1] = g < MIN_CHANNEL ? 0 : g;
    out[i + 2] = b < MIN_CHANNEL ? 0 : b;
  }
  return out;
}

export type DeviceTarget = Device & { info: DeviceInfo | null };

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

const HTTP_NOTE = (d: DeviceTarget) =>
  `Real-time UDP (DDP, port ${d.info?.ddpport ?? DDP_PORT}) did not reach the device, so frames go over HTTP: slower, about ${HTTP_FPS} per second.`;

interface Link {
  mode: LinkMode;
  startedAt: number;
  lastFrame: number;
  probing: boolean;
  inflight: boolean;
  lastHttp: number;
  /** HTTP only: whether the device was on before we took over. */
  wasOn: boolean | null;
  idleTimer: NodeJS.Timeout | null;
  note: string;
  /** Smoothed time for one HTTP frame to reach the device, in ms. */
  httpMs: number;
}

/**
 * Sends LED colors to WLED devices. It uses DDP over UDP (fast; the device returns to normal
 * by itself). It checks that the device really received the frames; if not (for example, a
 * router between two networks drops UDP), it falls back to the JSON API over HTTP, which
 * works wherever the web app can reach the device, at about 12 frames per second.
 */
export class LightSender {
  private udp = new RealtimeOut();
  private links = new Map<string, Link>();
  /** Devices that UDP did not reach, and until when to go straight to HTTP for them. */
  private httpUntil = new Map<string, number>();
  /** When we last told a device to show its own state over a real-time stream (lor: 1). */
  private overrideAt = new Map<string, number>();
  private log: (level: 'info' | 'warn', msg: string) => void;

  constructor(log: (level: 'info' | 'warn', msg: string) => void = () => {}) {
    this.log = log;
  }

  /** `rgb`: one byte triple per LED, from device LED 0. */
  send(d: DeviceTarget, input: Uint8Array) {
    const rgb = blackLevel(input);
    const now = Date.now();
    let link = this.links.get(d.id);
    if (!link) {
      link = { mode: 'checking', startedAt: now, lastFrame: now, probing: false, inflight: false, lastHttp: 0, wasOn: null, idleTimer: null, httpMs: 80, note: 'Checking that real-time UDP (DDP) reaches the device.' };
      // We may have told the device to ignore real-time data a moment ago (see end()); a new
      // stream must undo that, or the device would keep ignoring it.
      if (now - (this.overrideAt.get(d.id) ?? 0) < 10_000) {
        this.overrideAt.delete(d.id);
        void requestJson(`${baseUrl(d)}/json/state`, { method: 'POST', body: { lor: 0 }, timeoutMs: 1500 });
      }
      if ((this.httpUntil.get(d.id) ?? 0) > now) {
        link.mode = 'http';
        link.note = HTTP_NOTE(d);
      }
      this.links.set(d.id, link);
    }
    link.lastFrame = now;
    this.armIdle(d, link);

    if (link.mode === 'http') return this.sendHttp(d, link, rgb);
    this.udp.sendDdp(d.host, d.info?.ddpport ?? DDP_PORT, rgb);
    if (link.mode === 'checking' && !link.probing && now - link.startedAt > PROBE_AFTER_MS) void this.probe(d, link);
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
    return l ? { mode: l.mode, note: l.note } : null;
  }

  /**
   * Ends the stream to one device now, and puts its own state back at once (its color, scene
   * or preset), instead of after its real-time timeout. UDP: "lor: 1" tells WLED to show its
   * own state until the real-time data has ended; it resets by itself. HTTP: unfreeze.
   */
  end(d: DeviceTarget) {
    const link = this.links.get(d.id);
    if (!link) return;
    if (link.idleTimer) clearTimeout(link.idleTimer);
    this.links.delete(d.id);
    if (link.mode === 'http') {
      void requestJson(`${baseUrl(d)}/json/state`, { method: 'POST', body: { on: link.wasOn ?? true, seg: { id: 0, frz: false } }, timeoutMs: 2000 });
    } else {
      this.overrideAt.set(d.id, Date.now());
      void requestJson(`${baseUrl(d)}/json/state`, { method: 'POST', body: { lor: 1 }, timeoutMs: 2000 });
    }
  }

  /**
   * Gives back every device that gets frames over HTTP now (unfreezes its effect). Call it
   * before the server stops; otherwise such a device would stay frozen on the last frame.
   */
  async release(devices: DeviceTarget[]) {
    const http = devices.filter((d) => this.links.get(d.id)?.mode === 'http');
    await Promise.all(http.map((d) => requestJson(`${baseUrl(d)}/json/state`, { method: 'POST', body: { seg: { id: 0, frz: false } }, timeoutMs: 800 })));
  }

  close() {
    for (const l of this.links.values()) if (l.idleTimer) clearTimeout(l.idleTimer);
    this.udp.close();
  }

  /** Asks the device whether it is showing real-time data now. */
  private async probe(d: DeviceTarget, link: Link) {
    link.probing = true;
    const r = await requestJson<{ live?: boolean; lip?: string }>(`${baseUrl(d)}/json/info`, { timeoutMs: 1500 });
    link.probing = false;
    if (this.links.get(d.id) !== link) return;
    if (r.ok && r.data.live) {
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
    // Check UDP again after a while, in case the network changes.
    this.httpUntil.set(d.id, Date.now() + 10 * 60_000);
    this.log('warn', `Real-time UDP did not reach "${d.name}" (${d.host}). Sending frames over HTTP instead, about ${HTTP_FPS} per second. A router or firewall between the networks can drop UDP.`);
  }

  private sendHttp(d: DeviceTarget, link: Link, rgb: Uint8Array) {
    const now = Date.now();
    if (link.inflight || now - link.lastHttp < 1000 / HTTP_FPS) return;
    link.inflight = true;
    link.lastHttp = now;
    const hex: string[] = [];
    for (let i = 0; i + 2 < rgb.length; i += 3) hex.push(((rgb[i] << 16) | (rgb[i + 1] << 8) | rgb[i + 2]).toString(16).padStart(6, '0'));
    void (async () => {
      if (link.wasOn === null) {
        const s = await requestJson<{ on?: boolean }>(`${baseUrl(d)}/json/state`, { timeoutMs: 1500 });
        link.wasOn = s.ok ? s.data.on !== false : true;
      }
      // "i" sets the LEDs of segment 0 from its first LED, and freezes its effect.
      const t0 = Date.now();
      const r = await requestJson(`${baseUrl(d)}/json/state`, { method: 'POST', body: { on: true, seg: { id: 0, i: hex } }, timeoutMs: 1500 });
      if (r.ok) link.httpMs = link.httpMs * 0.8 + (Date.now() - t0) * 0.2;
      link.inflight = false;
    })();
  }

  private armIdle(d: DeviceTarget, link: Link) {
    if (link.idleTimer) return;
    const wait = Math.max(50, IDLE_MS - (Date.now() - link.lastFrame));
    link.idleTimer = setTimeout(() => {
      link.idleTimer = null;
      if (Date.now() - link.lastFrame < IDLE_MS) return this.armIdle(d, link);
      this.links.delete(d.id);
      // UDP streams end by themselves. An HTTP stream gives the device back: unfreeze the effect.
      if (link.mode === 'http') {
        void requestJson(`${baseUrl(d)}/json/state`, { method: 'POST', body: { on: link.wasOn ?? true, seg: { id: 0, frz: false } }, timeoutMs: 2000 });
      }
    }, wait);
    link.idleTimer.unref?.();
  }
}
