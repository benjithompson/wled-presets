import { entityOf } from '../../shared/homeAssistant.ts';
import type { HomeAssistant } from './homeAssistant.ts';

type Rgb = [number, number, number];

/** A switch (a relay) takes a new state at most this often, whatever the lights' rate. */
const SWITCH_MS = 5000;
/** A color this close to the last one sent (sum of the channels' differences) is not sent again. */
const SAME = 12;
/** Darker than this (the brightest channel, 0 to 255) is off. */
const DARK = 8;
/** A brightness this close to the last one sent is not sent again (it is a second Zigbee command). */
const SAME_BRI = 6;

/** What the colors of one light did: for the console, to see how fast it goes. */
export interface HaFrameStats {
  sent: number;
  failed: number;
  /** Frames that came while a command was still on its way (the light was not ready). */
  waited: number;
  /** How long the last commands took, in ms (a running mean). */
  latency: number;
}

/**
 * Home Assistant lights in the layout show what the effects and games draw on their objects,
 * as fast as they can take it: one color (the mix of the object's LEDs), up to `fps` a second
 * (HomeAssistant.fps) with a fade as long as the gap between two (unless fade is off), and
 * only so many commands on their way to a light at once (HomeAssistant.inflight, 1 unless a
 * speed test found more is faster), so a slow light gets the newest color and never a queue of
 * old ones. The brightness goes only when it changed (on Zigbee it is a command of
 * its own). A light that only goes on and off (a switch) is on while its objects are lit,
 * checked every few seconds.
 */
export class HaFrames {
  private ha: HomeAssistant;
  private latest = new Map<string, Rgb>();
  private sent = new Map<string, { rgb: Rgb; bri: number; on: boolean; at: number }>();
  /** Commands on their way, per light. */
  private busy = new Map<string, number>();
  private stats = new Map<string, HaFrameStats>();
  /** May this light show frames now (not switched off, or an editor wakes it)? */
  private allowed: (id: string, wakes: boolean) => boolean;
  /** The admin's brightness for the light, as WLED counts it (1 to 255), or null. */
  private level: (id: string) => number | null;
  private wakes = new Map<string, boolean>();
  /** The clock (a test sets its own). */
  now = () => Date.now();

  constructor(ha: HomeAssistant, allowed: (id: string, wakes: boolean) => boolean, level: (id: string) => number | null) {
    this.ha = ha;
    this.allowed = allowed;
    this.level = level;
  }

  /** A frame's color for a light (see HaSink); null: it no longer gets frames. */
  frame = (id: string, rgb: Rgb | null, wakes: boolean) => {
    if (!rgb) {
      this.latest.delete(id);
      this.sent.delete(id);
      this.wakes.delete(id);
      return;
    }
    this.latest.set(id, rgb);
    this.wakes.set(id, wakes);
    this.flush(id);
  };

  /** How each light's colors went (see HaFrameStats), by "ha:" id. */
  report(): Record<string, HaFrameStats> {
    return Object.fromEntries(this.stats);
  }

  private stat(id: string) {
    let s = this.stats.get(id);
    if (!s) this.stats.set(id, (s = { sent: 0, failed: 0, waited: 0, latency: 0 }));
    return s;
  }

  /** Sends the light its newest color, when it is due and ready. */
  flush(id: string) {
    const rgb = this.latest.get(id);
    if (!rgb || !this.allowed(id, this.wakes.get(id) ?? false)) return;
    const now = this.now();
    const entity = entityOf(id);
    const every = entity.startsWith('switch.') ? SWITCH_MS : 1000 / this.ha.fps();
    const last = this.sent.get(id);
    if (last && now - last.at < every) return;
    const top = Math.max(...rgb);
    const on = top >= DARK;
    const bri = Math.max(1, Math.round((top * (this.level(id) ?? 255)) / 255));
    // The color at full strength: the brightness says how bright.
    const color = on ? (rgb.map((c) => Math.round((c * 255) / top)) as Rgb) : rgb;
    if (last && last.on === on && (!on || (Math.abs(last.rgb[0] - color[0]) + Math.abs(last.rgb[1] - color[1]) + Math.abs(last.rgb[2] - color[2]) < SAME && Math.abs(last.bri - bri) < SAME_BRI))) return;
    if ((this.busy.get(id) ?? 0) >= this.ha.inflight()) {
      this.stat(id).waited++;
      return;
    }
    const sendBri = !last || !last.on || Math.abs(last.bri - bri) >= SAME_BRI;
    this.sent.set(id, { rgb: color, bri: sendBri || !last ? bri : last.bri, on, at: now });
    this.busy.set(id, (this.busy.get(id) ?? 0) + 1);
    const transition = this.ha.fade() ? Math.round(every / 100) / 10 : 0;
    const started = performance.now();
    void this.ha
      .set(entity, on, on ? { rgb: color, bri: sendBri ? bri : null, transition } : { transition })
      .then((r) => {
        const s = this.stat(id);
        const ms = performance.now() - started;
        s.latency = s.sent ? s.latency * 0.8 + ms * 0.2 : ms;
        s.sent++;
        if (!r.ok) s.failed++;
      })
      .finally(() => {
        const n = (this.busy.get(id) ?? 1) - 1;
        if (n > 0) this.busy.set(id, n);
        else this.busy.delete(id);
        // A newer color may have come meanwhile: it goes now, if it is due.
        this.flush(id);
      });
  }

  close() {
    this.latest.clear();
  }
}
