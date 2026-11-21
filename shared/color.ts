// Colors, and the small maths the effects, the games and the editor draw with.
//
// One convention: a color is `Rgb`, three numbers from 0 to 1 (more is brighter still: the
// games add light up). Bytes (0..255) are made at the edges: `bytes` for a color, `toBytes` for
// a whole frame, `hex` for the phone and the page.

/** A color, 0..1 per channel. */
export type Rgb = [number, number, number];
/** A color as bytes, 0..255 per channel. */
export type Rgb8 = [number, number, number];

export const BLACK: Rgb = [0, 0, 0];
export const WHITE: Rgb = [1, 1, 1];

const hsvChannel = (n: number, h6: number, v: number, vs: number) => {
  const k = (n + h6) % 6;
  return v - vs * Math.max(0, Math.min(k, 4 - k, 1));
};

/** A color from hue (0..1, and any number: it wraps around, so -0.25 is 0.75), saturation and value. */
export function hsv(h: number, s = 1, v = 1): Rgb {
  const h6 = (h - Math.floor(h)) * 6;
  const vs = v * s;
  return [hsvChannel(5, h6, v, vs), hsvChannel(3, h6, v, vs), hsvChannel(1, h6, v, vs)];
}

/** From `a` (t = 0) to `b` (t = 1). */
export const mix = (a: Rgb, b: Rgb, t: number): Rgb => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

/** `c`, `k` times as bright. */
export const scale = (c: Rgb, k: number): Rgb => [c[0] * k, c[1] * k, c[2] * k];

/** Bytes for a color (clamped to 0..1 first). */
export const bytes = (c: Rgb): Rgb8 => [byte(c[0]), byte(c[1]), byte(c[2])];
const byte = (v: number) => Math.round(255 * clamp01(v));

const rounded = (c: Rgb): Rgb8 => [Math.round(c[0]), Math.round(c[1]), Math.round(c[2])];
/** A byte color `k` times as bright, rounded. */
export const scale8 = (c: Rgb8, k: number): Rgb8 => rounded(scale(c, k));
/** From byte color `a` (t = 0) to `b` (t = 1), rounded. */
export const mix8 = (a: Rgb8, b: Rgb8, t: number): Rgb8 => rounded(mix(a, b, t));

/** Bytes for a fully saturated hue (0..1) at value `v`. */
export const hsvBytes = (h: number, v = 1): Rgb8 => bytes(hsv(h, 1, v));

/** `#rrggbb` for a color (clamped to 0..1 first). */
export const hex = (c: Rgb) => '#' + bytes(c).map((v) => v.toString(16).padStart(2, '0')).join('');

/** The color of `#rrggbb` (a bad one is black). */
export function fromHex(s: string): Rgb {
  const n = parseInt(s.replace('#', '').slice(0, 6), 16) || 0;
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/** The bytes of `#rrggbb` (the `#` may be left out), or null if it is not one. */
export function parseHex(s: string): Rgb8 | null {
  const m = /^#?([0-9a-f]{6})$/i.exec(s.trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/**
 * A frame of colors (three per LED, 0..1 and may go above) as bytes for the lights, with a soft
 * shoulder so bright, added-up colors roll off instead of clipping flat.
 */
export function toBytes<T extends Uint8Array>(data: Float32Array, out: T): T {
  for (let i = 0; i < data.length; i++) {
    const v = data[i];
    out[i] = Math.round(255 * (v <= 0 ? 0 : v >= 1.5 ? 1 : v < 0.8 ? v : 0.8 + (v - 0.8) * 0.2857));
  }
  return out;
}

// ---------- Small maths ----------

export const clamp = (x: number, lo: number, hi: number) => (x < lo ? lo : x > hi ? hi : x);
export const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);
export const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
export const fract = (x: number) => x - Math.floor(x);
/** Smoothstep on 0..1: slow at both ends. */
export const ease = (t: number) => t * t * (3 - 2 * t);
/** 0 below `a`, 1 above `b`, and eased in between. */
export const smooth = (a: number, b: number, x: number) => ease(clamp01((x - a) / (b - a)));

/** A small, fast random number generator (mulberry32): the same numbers for the same seed. */
export function seededRandom(seed: number): () => number {
  let a = seed >>> 0 || 1;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
