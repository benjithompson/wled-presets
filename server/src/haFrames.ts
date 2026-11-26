import { entityOf } from '../../shared/homeAssistant.ts';
import type { HomeAssistant } from './homeAssistant.ts';

type Rgb = [number, number, number];

/** How often a Home Assistant light takes a new color: lights and bulbs, and switches (relays). */
export const HA_FRAME_MS = { light: 1000, switch: 5000 } as const;
/** A color this close to the last one sent (sum of the channels' differences) is not sent again. */
const SAME = 24;
/** Darker than this (the brightest channel, 0 to 255) is off. */
const DARK = 8;

/**
 * Home Assistant lights in the layout show what the effects and games draw on their objects,
 * as far as they can: one color (the mix of the object's LEDs), a new one about once a second
 * with a fade to it, as Home Assistant and the lights behind it can't take 60 frames a second.
 * A light that only goes on and off (a switch) is on while its objects are lit, checked every
 * few seconds.
 */
export class HaFrames {
  private ha: HomeAssistant;
  private latest = new Map<string, Rgb>();
  private sent = new Map<string, { rgb: Rgb; at: number }>();
  private busy = new Set<string>();
  private timer: NodeJS.Timeout | null = null;
  /** May this light show frames now (not switched off, or an editor wakes it)? */
  private allowed: (id: string, wakes: boolean) => boolean;
  /** The admin's brightness for the light, as WLED counts it (1 to 255), or null. */
  private level: (id: string) => number | null;
  private wakes = new Map<string, boolean>();
  /** How often the colors are looked at (shorter in tests). */
  tickMs = 250;
  frameMs: { light: number; switch: number } = { ...HA_FRAME_MS };

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
    if (!this.timer) {
      this.timer = setInterval(() => this.flush(), this.tickMs);
      this.timer.unref?.();
    }
  };

  /** Sends each light its newest color when it is due. */
  flush(now = Date.now()) {
    if (!this.latest.size && this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      return;
    }
    for (const [id, rgb] of this.latest) {
      if (this.busy.has(id) || !this.allowed(id, this.wakes.get(id) ?? false)) continue;
      const entity = entityOf(id);
      const every = entity.startsWith('switch.') ? this.frameMs.switch : this.frameMs.light;
      const last = this.sent.get(id);
      if (last && now - last.at < every) continue;
      if (last && Math.abs(last.rgb[0] - rgb[0]) + Math.abs(last.rgb[1] - rgb[1]) + Math.abs(last.rgb[2] - rgb[2]) < SAME) continue;
      this.sent.set(id, { rgb, at: now });
      this.busy.add(id);
      void this.send(entity, id, rgb, every).finally(() => this.busy.delete(id));
    }
  }

  private send(entity: string, id: string, rgb: Rgb, every: number) {
    const top = Math.max(...rgb);
    if (top < DARK) return this.ha.set(entity, false, { transition: every / 1000 });
    // The color at full strength, and how bright it is: the admin's level scales it.
    const color = rgb.map((c) => Math.round((c * 255) / top)) as Rgb;
    const level = this.level(id) ?? 255;
    return this.ha.set(entity, true, { rgb: color, bri: Math.max(1, Math.round((top * level) / 255)), transition: every / 1000 });
  }

  close() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.latest.clear();
  }
}
