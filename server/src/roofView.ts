import { buildStage, type Layout } from '../../shared/layout.ts';
import type { RoofGeometry } from '../../shared/types.ts';
import { deviceMaps } from './framePipeline.ts';
import type { DeviceTarget } from './lightSender.ts';
import { WledPeek } from './wledPeek.ts';

/** Frames a second to the home page. Enough for a strip along the edge of the window. */
export const ROOF_HZ = 20;
/** At most this many cells along the roof. */
export const MAX_CELLS = 160;
/** At most this many browsers watch at once: each one costs a stream. */
export const MAX_ROOF_VIEWERS = 500;
/** With nobody watching for this long, the connections to the devices close. */
const LINGER_MS = 15_000;

/** What the roof view needs to know about the lights. */
export interface RoofSources {
  /** The yard as it is now. */
  layout(): Layout;
  /** The devices (one switched off counts as disabled). */
  devices(): DeviceTarget[];
  /** What the server sends a device now (see FramePipeline.deviceFrame), or null. */
  deviceFrame(deviceId: string): Uint8Array | null;
  /** The simulated yard's frame in stage order, for objects with no device, or null. */
  simFrame(): Uint8Array | null;
}

/** What a device shows by itself (see WledPeek). */
export type Peek = Pick<WledPeek, 'leds' | 'step' | 'at' | 'on' | 'bri' | 'setLive' | 'close'>;

export type RoofEvent = { event: 'geometry'; data: string } | { event: 'frame'; data: string };

interface Cell {
  /** Stage indexes of its LEDs. */
  leds: number[];
}

/**
 * The roofline for the home page: what the roof's lights show now, gathered into cells along
 * the front of the house. A device that gets frames from the server shows those (exactly what
 * was sent); one that plays its own preset or color is watched over its WebSocket (WledPeek);
 * a switched-off device is dark; roof objects with no device show the simulator.
 */
export class RoofView {
  private src: RoofSources;
  private makePeek: (d: DeviceTarget) => Peek;
  private viewers = new Set<(e: RoofEvent) => void>();
  private peeks = new Map<string, Peek>();
  private timer: NodeJS.Timeout | null = null;
  private lingerTimer: NodeJS.Timeout | null = null;

  private layout: Layout | null = null;
  private cells: Cell[] = [];
  private geometry: RoofGeometry = { x: [], y: [] };
  /** Per stage LED: its device and the device LED number (-1: none). */
  private deviceOf: (string | null)[] = [];
  private ledOf = new Int32Array(0);
  private roofDevices: string[] = [];
  private bytes = new Uint8Array(0);
  private last = '';

  constructor(src: RoofSources, makePeek: (d: DeviceTarget) => Peek = (d) => new WledPeek(d, () => d.info?.leds?.count ?? 0)) {
    this.src = src;
    this.makePeek = makePeek;
  }

  /**
   * Adds a browser. It gets the geometry and the last frame at once, then each new frame.
   * Returns the function that removes it, or null when too many watch already.
   */
  watch(send: (e: RoofEvent) => void): (() => void) | null {
    if (this.viewers.size >= MAX_ROOF_VIEWERS) return null;
    this.rebuildIfMoved();
    this.viewers.add(send);
    send({ event: 'geometry', data: JSON.stringify(this.geometry) });
    if (this.last) send({ event: 'frame', data: this.last });
    if (this.lingerTimer) clearTimeout(this.lingerTimer);
    this.lingerTimer = null;
    if (!this.timer) {
      this.timer = setInterval(() => this.tick(), 1000 / ROOF_HZ);
      this.timer.unref?.();
    }
    return () => {
      this.viewers.delete(send);
      if (this.viewers.size) return;
      if (this.timer) clearInterval(this.timer);
      this.timer = null;
      this.last = '';
      this.lingerTimer = setTimeout(() => this.closePeeks(), LINGER_MS);
      this.lingerTimer.unref?.();
    };
  }

  /** The roof's colors now, one RGB triple per cell (also what tick() sends). */
  frame(): Uint8Array {
    this.rebuildIfMoved();
    const devices = new Map(this.src.devices().map((d) => [d.id, d]));
    const now = Date.now();
    // Keep a connection to each roof device that plays by itself; quiet ones that get frames.
    for (const id of this.roofDevices) {
      const d = devices.get(id);
      let peek = this.peeks.get(id);
      if (!d?.enabled) {
        peek?.close();
        this.peeks.delete(id);
        continue;
      }
      if (!peek) this.peeks.set(id, (peek = this.makePeek(d)));
      peek.setLive(!this.src.deviceFrame(id));
    }
    const sim = this.src.simFrame();
    const out = this.bytes;
    out.fill(0);
    this.cells.forEach((cell, c) => {
      let r = 0;
      let g = 0;
      let b = 0;
      for (const i of cell.leds) {
        const id = this.deviceOf[i];
        let src: ArrayLike<number> | null = null;
        let at = 0;
        let k = 1;
        if (id == null) {
          src = sim;
          at = i * 3;
        } else if (devices.get(id)?.enabled) {
          const led = this.ledOf[i];
          const sent = this.src.deviceFrame(id);
          const peek = this.peeks.get(id);
          if (sent) {
            src = sent;
            at = led * 3;
            // The device scales what it is sent by its own brightness.
            if (peek?.on === false) k = 0;
            else if (peek?.bri != null) k = peek.bri / 255;
          } else if (peek?.leds && now - peek.at < 3000) {
            src = peek.leds;
            at = Math.floor(led / peek.step) * 3;
          }
        }
        if (!src || at + 2 >= src.length) continue;
        r = Math.max(r, src[at] * k);
        g = Math.max(g, src[at + 1] * k);
        b = Math.max(b, src[at + 2] * k);
      }
      out[c * 3] = r;
      out[c * 3 + 1] = g;
      out[c * 3 + 2] = b;
    });
    return out;
  }

  close() {
    if (this.timer) clearInterval(this.timer);
    if (this.lingerTimer) clearTimeout(this.lingerTimer);
    this.timer = this.lingerTimer = null;
    this.viewers.clear();
    this.closePeeks();
  }

  private tick() {
    const moved = this.rebuildIfMoved();
    if (moved) for (const send of this.viewers) send({ event: 'geometry', data: JSON.stringify(this.geometry) });
    const data = Buffer.from(this.frame()).toString('base64');
    if (data === this.last && !moved) return;
    this.last = data;
    for (const send of this.viewers) send({ event: 'frame', data });
  }

  private closePeeks() {
    for (const p of this.peeks.values()) p.close();
    this.peeks.clear();
  }

  /** Builds the cells again when the layout changed. True if it did. */
  private rebuildIfMoved(): boolean {
    const layout = this.src.layout();
    if (layout === this.layout) return false;
    this.layout = layout;
    const stage = buildStage(layout);
    this.deviceOf = new Array(stage.pixelCount).fill(null);
    this.ledOf = new Int32Array(stage.pixelCount).fill(-1);
    for (const m of deviceMaps(layout, stage)) {
      for (let p = 0; p < m.pairs.length; p += 2) {
        this.deviceOf[m.pairs[p]] = m.deviceId;
        this.ledOf[m.pairs[p]] = m.pairs[p + 1];
      }
    }
    const roof = Array.from(stage.roofPath);
    const xs = roof.map((i) => stage.positions[i * 2]);
    const ys = roof.map((i) => stage.positions[i * 2 + 1]);
    const minX = Math.min(...xs);
    const span = Math.max(...xs) - minX;
    const count = Math.max(1, Math.min(MAX_CELLS, roof.length));
    const byCell: number[][] = Array.from({ length: count }, () => []);
    roof.forEach((i, k) => byCell[span > 0 ? Math.min(count - 1, Math.floor(((xs[k] - minX) / span) * count)) : 0].push(k));
    // Cells with no LED (a gap between two roofs) are left out.
    const used = byCell.map((ks, c) => ({ ks, c })).filter((x) => x.ks.length);
    // Layout y grows downward: the highest point of the roof has the smallest y.
    const top = Math.min(...ys);
    const height = Math.max(...ys) - top;
    this.cells = used.map(({ ks }) => ({ leds: ks.map((k) => roof[k]) }));
    this.geometry = {
      x: used.map(({ c }) => round3((c + 0.5) / count)),
      y: used.map(({ ks }) => round3(height > 0 ? 1 - (ks.reduce((a, k) => a + ys[k], 0) / ks.length - top) / height : 0.5))
    };
    this.roofDevices = [...new Set(this.cells.flatMap((c) => c.leds.map((i) => this.deviceOf[i]).filter((id): id is string => id != null)))];
    for (const [id, p] of this.peeks) {
      if (this.roofDevices.includes(id)) continue;
      p.close();
      this.peeks.delete(id);
    }
    this.bytes = new Uint8Array(this.cells.length * 3);
    this.last = '';
    return true;
  }
}

const round3 = (v: number) => Math.round(v * 1000) / 1000;
