// A frame of light for every LED on the stage, in linear 0..1 RGB. Games draw into it
// additively; the host converts it to bytes for the simulator and, later, the real lights.

export type Rgb = [number, number, number];

export class Frame {
  readonly data: Float32Array;
  readonly count: number;

  constructor(count: number) {
    this.count = count;
    this.data = new Float32Array(count * 3);
  }

  clear() {
    this.data.fill(0);
  }

  /** Multiplies every LED, for trails that fade over time. */
  fade(keep: number) {
    for (let i = 0; i < this.data.length; i++) this.data[i] *= keep;
  }

  add(i: number, [r, g, b]: Rgb, amount = 1) {
    if (i < 0 || i >= this.count) return;
    const k = Math.floor(i) * 3;
    this.data[k] += r * amount;
    this.data[k + 1] += g * amount;
    this.data[k + 2] += b * amount;
  }

  set(i: number, [r, g, b]: Rgb) {
    if (i < 0 || i >= this.count) return;
    const k = Math.floor(i) * 3;
    this.data[k] = r;
    this.data[k + 1] = g;
    this.data[k + 2] = b;
  }

  /** A soft dot at a fractional position along a run of LEDs, spread over neighbours. */
  splat(start: number, length: number, pos: number, color: Rgb, width = 1.5, amount = 1) {
    const lo = Math.max(0, Math.floor(pos - width * 2));
    const hi = Math.min(length - 1, Math.ceil(pos + width * 2));
    for (let p = lo; p <= hi; p++) {
      const d = (p - pos) / width;
      this.add(start + p, color, Math.exp(-d * d) * amount);
    }
  }

  /** Bytes for output, with a gentle tone curve so bright additive colors do not clip harshly. */
  toBytes<T extends Uint8Array>(out: T): T {
    for (let i = 0; i < this.data.length; i++) {
      const v = this.data[i];
      out[i] = Math.round(255 * (v <= 0 ? 0 : v >= 1.5 ? 1 : v < 0.8 ? v : 0.8 + (v - 0.8) * 0.2857));
    }
    return out;
  }
}

export function hsv(h: number, s = 1, v = 1): Rgb {
  const f = (n: number) => {
    const k = (n + h * 6) % 6;
    return v - v * s * Math.max(0, Math.min(k, 4 - k, 1));
  };
  return [f(5), f(3), f(1)];
}

export const mix = (a: Rgb, b: Rgb, t: number): Rgb => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

export const WHITE: Rgb = [1, 1, 1];
export const WARM: Rgb = [1, 0.62, 0.28];
