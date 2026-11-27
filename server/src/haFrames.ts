import { entityOf } from '../../shared/homeAssistant.ts';
import type { HomeAssistant } from './homeAssistant.ts';

type Rgb = [number, number, number];

/** A switch (a relay) takes a new state at most this often, whatever the lights' rate. */
const SWITCH_MS = 5000;
/** A color this close to the last one sent (sum of the channels' differences) is not sent again. */
const SAME = 12;
/** Darker than this (the brightest channel, 0 to 255) is dark: a light dims right down, a switch goes off. */
const DARK = 8;
/** A brightness this close to the last one sent is not sent again (it is a second Zigbee command). */
const SAME_BRI = 6;
/** The level a light shows a dark part of an effect at (1 to 255): as dark as it goes, still on. */
export const DIM_LEVEL = 1;

/**
 * Home Assistant lights in the layout show what the effects and games draw on their objects,
 * as fast as they can take it: one color (the mix of the object's LEDs), up to `fps` a second
 * (HomeAssistant.fps) with a fade as long as the gap between two (unless fade is off). A slow
 * light gets the newest color and never a queue of old ones: HomeAssistant.set gives each
 * light its commands in turn, the newest waiting. The brightness is the light's own level (its slider on the Devices page), sent
 * when it comes on and when the level changes, never with each color (on Zigbee it is a
 * command of its own): a dim part of an effect shows at that level. A dark one dims the light
 * right down (DIM_LEVEL) with its last color, and never switches it off: switching a Zigbee
 * light off and on is slow, drops commands, and leaves Home Assistant unsure what it is. The
 * first color goes through light.turn_on, so Home Assistant knows the light is on; the ones
 * after may go as Zigbee commands (HomeAssistant.direct), which never switch it. A light that
 * only goes on and off (a switch) is on while its objects are lit, checked every few seconds.
 */
export class HaFrames {
  private ha: HomeAssistant;
  private latest = new Map<string, Rgb>();
  private sent = new Map<string, { rgb: Rgb; bri: number; on: boolean; at: number }>();
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

  /** Sends the light its newest color, when it is due. */
  flush(id: string) {
    const rgb = this.latest.get(id);
    if (!rgb || !this.allowed(id, this.wakes.get(id) ?? false)) return;
    const now = this.now();
    const entity = entityOf(id);
    const every = entity.startsWith('switch.') ? SWITCH_MS : 1000 / this.ha.fps();
    const last = this.sent.get(id);
    if (last && now - last.at < every) return;
    const top = Math.max(...rgb);
    const dark = top < DARK;
    const isSwitch = entity.startsWith('switch.');
    // A switch: on while lit. A light: always on, its last color right down when dark.
    const on = !isSwitch || !dark;
    // The color at full strength: how bright it is, is the level's.
    const color: Rgb = dark ? (last?.rgb ?? [255, 255, 255]) : (rgb.map((c) => Math.round((c * 255) / top)) as Rgb);
    // The light's own level (its slider on the Devices page), not the mix's: frames carry only
    // the color, so each one is a single command.
    const bri = dark ? DIM_LEVEL : (this.level(id) ?? 255);
    const sendColor = !last || Math.abs(last.rgb[0] - color[0]) + Math.abs(last.rgb[1] - color[1]) + Math.abs(last.rgb[2] - color[2]) >= SAME;
    const sendBri = !last || !last.on || Math.abs(last.bri - bri) >= SAME_BRI;
    if (last && last.on === on && (isSwitch || (!sendColor && !sendBri))) return;
    this.sent.set(id, { rgb: sendColor || !last ? color : last.rgb, bri: sendBri || !last ? bri : last.bri, on, at: now });
    const transition = this.ha.fade() ? Math.round(every / 100) / 10 : 0;
    // Coming on: through light.turn_on, so Home Assistant knows it is on (a Zigbee color command does not tell it).
    void this.ha.set(entity, on, on ? { rgb: sendColor || !last?.on ? color : null, bri: sendBri ? bri : null, transition, direct: this.ha.direct() && !!last?.on } : { transition });
  }

  close() {
    this.latest.clear();
  }
}
