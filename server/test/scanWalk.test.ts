import { describe, expect, it } from 'vitest';
import { codeColor, codeFrames, type Pixels } from '../../shared/photoTrace.ts';
import type { PosedCam, Pt3 } from '../../shared/scan3d.ts';
import { Walk, type WalkResult } from '../../shared/scanWalk.ts';

// A walk round a tree of lights, drawn: the lights blink the code over and over while the phone
// goes round, ten-ish pictures a second, its AR tracking a little off.

const N = 120;
const W = 480;
const H = 640;
const FOCAL = 0.8 * H;
/** Seconds each code frame shows; the lights take a moment to change, the page waits for them. */
const SLOT = 0.6;
const LAG = 0.12;
const SETTLE = 0.25;

/** A spiral up a cone, in meters (y up). */
const tree: Pt3[] = Array.from({ length: N }, (_, i) => {
  const u = i / (N - 1);
  const a = u * 5 * Math.PI * 2;
  const r = 0.3 * (1 - u * 0.85);
  return { x: Math.sin(a) * r, y: 0.05 + u * 0.8, z: Math.cos(a) * r };
});

function noise(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296 - 0.5;
  };
}

/** A camera at C looking at `aim`, as world to camera (looking down −z, y up). */
function lookAt(C: number[], aim: number[], roll = 0): PosedCam {
  const norm = (v: number[]) => {
    const l = Math.hypot(...v);
    return v.map((x) => x / l);
  };
  const cross = (p: number[], q: number[]) => [p[1] * q[2] - p[2] * q[1], p[2] * q[0] - p[0] * q[2], p[0] * q[1] - p[1] * q[0]];
  const fw = norm(aim.map((v, i) => v - C[i]));
  let right = norm(cross(fw, [0, 1, 0]));
  let up = cross(right, fw);
  const cr = Math.cos(roll);
  const sr = Math.sin(roll);
  [right, up] = [right.map((v, i) => v * cr + up[i] * sr), up.map((v, i) => -right[i] * sr + v * cr)];
  const R = [...right, ...up, ...fw.map((v) => -v)];
  const t: [number, number, number] = [0, 1, 2].map((i) => -(R[i * 3] * C[0] + R[i * 3 + 1] * C[1] + R[i * 3 + 2] * C[2])) as [number, number, number];
  return { R, t, f: FOCAL, cu: W / 2, cv: H / 2 };
}

function draw(cam: PosedCam, slot: number, phase: number, rnd: () => number): Pixels {
  const data = new Uint8ClampedArray(W * H * 4);
  // A dim room, lighter at the top left, and a lamp.
  for (let y = 0; y < H; y++)
    for (let x = 0; x < W; x++) {
      const i = (y * W + x) * 4;
      const base = 70 - (x + y) * 0.03 + rnd() * 8;
      data[i] = base + 8;
      data[i + 1] = base;
      data[i + 2] = base - 6;
      data[i + 3] = 255;
    }
  const F = codeFrames(N);
  // Which code the lights show: the slot's, once they have caught up.
  const shown = phase < LAG ? slot - 1 : slot;
  const code = ((shown % F) + F) % F;
  const C = [0, 1, 2].map((i) => -(cam.R[i] * cam.t[0] + cam.R[3 + i] * cam.t[1] + cam.R[6 + i] * cam.t[2]));
  const spots: { u: number; v: number; rgb: number[]; s: number }[] = [{ u: 60, v: 90, rgb: [255, 200, 120], s: 9 }];
  tree.forEach((p, i) => {
    // Round the back of the tree: hidden.
    const out = [p.x, 0, p.z];
    const to = [C[0] - p.x, 0, C[2] - p.z];
    const lo = Math.hypot(...out) || 1;
    const lt = Math.hypot(...to) || 1;
    if ((out[0] * to[0] + out[2] * to[2]) / (lo * lt) < -0.3) return;
    const R = cam.R;
    const X = [p.x, p.y, p.z];
    const px = R[0] * X[0] + R[1] * X[1] + R[2] * X[2] + cam.t[0];
    const py = R[3] * X[0] + R[4] * X[1] + R[5] * X[2] + cam.t[1];
    const d = -(R[6] * X[0] + R[7] * X[1] + R[8] * X[2] + cam.t[2]);
    const rgb = codeColor(i, code, N);
    const k = 255 / Math.max(...rgb);
    spots.push({ u: cam.cu + (cam.f * px) / d, v: cam.cv - (cam.f * py) / d, rgb: rgb.map((v) => v * k), s: 1.7 });
  });
  for (const sp of spots) {
    const r = Math.ceil(sp.s * 3);
    for (let y = Math.max(0, Math.floor(sp.v) - r); y <= Math.min(H - 1, Math.floor(sp.v) + r); y++)
      for (let x = Math.max(0, Math.floor(sp.u) - r); x <= Math.min(W - 1, Math.floor(sp.u) + r); x++) {
        const e = Math.exp(-((x - sp.u) ** 2 + (y - sp.v) ** 2) / (2 * sp.s * sp.s));
        const core = Math.exp(-((x - sp.u) ** 2 + (y - sp.v) ** 2) / (2 * 0.6 * 0.6));
        const i = (y * W + x) * 4;
        for (let c = 0; c < 3; c++) data[i + c] = data[i + c] + sp.rgb[c] * e + 200 * core;
      }
  }
  return { width: W, height: H, data: data as unknown as Uint8ClampedArray };
}

function walk(opts: { degrees?: number; flipped?: boolean; seconds?: number; fps?: number; drift?: number } = {}): WalkResult {
  const { degrees = 360, flipped = false, seconds = 40, fps = 7, drift = 0.002 } = opts;
  const rnd = noise(7);
  const F = codeFrames(N);
  const w = new Walk(N);
  const frames = Math.round(seconds * fps);
  for (let k = 0; k < frames; k++) {
    const t = k / fps;
    const a = ((20 + (degrees * t) / seconds) * Math.PI) / 180;
    const r = 1.4 + 0.1 * Math.sin(t * 0.7);
    // The hand: a little up and down, side to side, and tipped.
    const C = [Math.sin(a) * r + 0.01 * Math.sin(t * 3), 1.15 + 0.05 * Math.sin(t * 1.3), Math.cos(a) * r];
    const truth = lookAt(C, [0.02 * Math.sin(t * 2), 0.45, 0], 0.05 * Math.sin(t * 1.1));
    const slot = Math.floor(t / SLOT);
    const phase = t - slot * SLOT;
    let px = draw(truth, slot, phase, rnd);
    if (flipped) {
      const out = new Uint8ClampedArray(px.data.length);
      for (let y = 0; y < H; y++) out.set(px.data.subarray((H - 1 - y) * W * 4, (H - y) * W * 4), y * W * 4);
      px = { ...px, data: out };
    }
    // What the phone's tracking says: a little off.
    const told = lookAt(
      C.map((v) => v + rnd() * drift),
      [0.02 * Math.sin(t * 2) + rnd() * drift, 0.45 + rnd() * drift, rnd() * drift],
      0.05 * Math.sin(t * 1.1) + rnd() * 0.002
    );
    w.add({ pixels: px, cam: told, code: phase >= SETTLE ? slot % F : null, cycle: Math.floor(slot / F) });
  }
  return w.finish();
}

/** How far apart pairs of placed LEDs are, against the tree itself (meters, on average). */
function shapeError(points: (Pt3 | null)[]): number {
  const idx = points.map((p, i) => (p ? i : -1)).filter((i) => i >= 0);
  let sum = 0;
  let count = 0;
  for (let a = 0; a < idx.length; a += 3)
    for (let b = a + 1; b < idx.length; b += 5) {
      const p = points[idx[a]]!;
      const q = points[idx[b]]!;
      const s = tree[idx[a]];
      const t = tree[idx[b]];
      sum += Math.abs(Math.hypot(p.x - q.x, p.y - q.y, p.z - q.z) - Math.hypot(s.x - t.x, s.y - t.y, s.z - t.z));
      count++;
    }
  return sum / count;
}

/** The way round (not mirrored): the sign of the volume of four spread-out LEDs. */
function handed(points: (Pt3 | null)[]): number {
  const pick = [0, 30, 60, 90].map((i) => points.slice(i).find(Boolean)!);
  const at = (p: Pt3) => [p.x - pick[0].x, p.y - pick[0].y, p.z - pick[0].z];
  const [a, b, c] = pick.slice(1).map(at);
  return Math.sign(a[0] * (b[1] * c[2] - b[2] * c[1]) - a[1] * (b[0] * c[2] - b[2] * c[0]) + a[2] * (b[0] * c[1] - b[1] * c[0]));
}

describe('walking round in AR', () => {
  it('places the LEDs all round, at their real size', () => {
    const got = walk();
    expect(got.flipped).toBe(false);
    expect(got.solved.placed).toBeGreaterThanOrEqual(N * 0.85);
    expect(shapeError(got.solved.points)).toBeLessThan(0.01);
    expect(handed(got.solved.points)).toBe(handed(tree));
    expect(got.solved.rms).toBeLessThan(2.5);
    // Upright, the first picture's side the front: the bottom of the tree low, the first camera at +z.
    const ys = got.solved.points.filter(Boolean).map((p) => p!.y);
    expect(got.solved.points[0]!.y).toBeLessThan(Math.min(...ys) + 0.08);
    expect(got.solved.cameras[0].z).toBeGreaterThan(1);
    expect(Math.abs(got.solved.cameras[0].x)).toBeLessThan(0.05);
    // The first picture's dots, most with their numbers.
    expect(got.front.filter((d) => d.num != null).length).toBeGreaterThan(N * 0.3);
  }, 60_000);

  it('keeps up with a quick walk, a few pictures a second, the tracking further off', () => {
    const got = walk({ seconds: 18, fps: 5, drift: 0.006 });
    expect(got.solved.placed).toBeGreaterThanOrEqual(N * 0.85);
    expect(shapeError(got.solved.points)).toBeLessThan(0.01);
  }, 60_000);

  it('works out pictures that come upside down', () => {
    const got = walk({ flipped: true, degrees: 200, seconds: 26 });
    expect(got.flipped).toBe(true);
    expect(got.solved.placed).toBeGreaterThanOrEqual(N * 0.6);
    expect(shapeError(got.solved.points)).toBeLessThan(0.01);
    expect(handed(got.solved.points)).toBe(handed(tree));
  }, 60_000);
});
