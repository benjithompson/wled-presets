import { describe, expect, it } from 'vitest';
import { design3d, solveViews, step3d, wire3d, type Pt3, type ScanView } from '../../shared/scan3d.ts';
import { designLeds, designTransform } from '../../shared/layout.ts';

const DEG = Math.PI / 180;

/** A tree of lights: a spiral up a cone, in meters (y up). */
function tree(n: number, turns = 5, r = 0.3, h = 0.8): Pt3[] {
  return Array.from({ length: n }, (_, i) => {
    const u = i / (n - 1);
    const a = u * turns * Math.PI * 2;
    return { x: Math.sin(a) * r * (1 - u * 0.9), y: u * h, z: Math.cos(a) * r * (1 - u * 0.9) };
  });
}

let seed = 11;
const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
const gauss = () => Math.sqrt(-2 * Math.log(rand() + 1e-12)) * Math.cos(2 * Math.PI * rand());

/**
 * A phone's picture of the LEDs from `angle` degrees round (to the right of the front), from
 * `distance` meters and `height` above the middle, rolled a little: where each LED it can see is.
 */
function shoot(pts: Pt3[], { angle, distance = 1.5, height = 0.3, roll = 0, w = 1400, h = 788, f = 0.8 * 1400, noise = 0.6, aim = { x: 0, y: 0.4, z: 0 }, hidden = true }: { angle: number; distance?: number; height?: number; roll?: number; w?: number; h?: number; f?: number; noise?: number; aim?: Pt3; hidden?: boolean }): ScanView {
  const a = angle * DEG;
  const C = { x: aim.x + Math.sin(a) * distance, y: aim.y + height, z: aim.z + Math.cos(a) * distance };
  const fw = norm({ x: aim.x - C.x, y: aim.y - C.y, z: aim.z - C.z });
  const right = norm(cross(fw, { x: 0, y: 1, z: 0 }));
  const up = cross(right, fw);
  const leds: ScanView['leds'] = [];
  pts.forEach((p, num) => {
    const d = { x: p.x - C.x, y: p.y - C.y, z: p.z - C.z };
    // The far side of the tree is hidden behind it.
    const out = norm({ x: p.x, y: 0, z: p.z });
    const toCam = norm({ x: C.x - p.x, y: 0, z: C.z - p.z });
    if (hidden && out.x * toCam.x + out.z * toCam.z < -0.25) return;
    const depth = dot(d, fw);
    let X = (f * dot(d, right)) / depth;
    let Y = (-f * dot(d, up)) / depth;
    const cr = Math.cos(roll * DEG);
    const sr = Math.sin(roll * DEG);
    [X, Y] = [X * cr - Y * sr, X * sr + Y * cr];
    leds.push({ num, x: w / 2 + X + gauss() * noise, y: h / 2 + Y + gauss() * noise });
  });
  return { leds, width: w, height: h };
}
const dot = (a: Pt3, b: Pt3) => a.x * b.x + a.y * b.y + a.z * b.z;
const cross = (a: Pt3, b: Pt3) => ({ x: a.y * b.z - a.z * b.y, y: a.z * b.x - a.x * b.z, z: a.x * b.y - a.y * b.x });
const norm = (a: Pt3) => {
  const l = Math.hypot(a.x, a.y, a.z);
  return { x: a.x / l, y: a.y / l, z: a.z / l };
};
const sub = (a: Pt3, b: Pt3) => ({ x: a.x - b.x, y: a.y - b.y, z: a.z - b.z });

/**
 * How far the solved shape is from the real one, as a share of its size, once sized alike
 * (distances between LEDs do not care where it is or how it is turned), and whether it came
 * out mirrored.
 */
function compare(truth: Pt3[], got: (Pt3 | null)[]) {
  const idx = got.map((p, i) => (p ? i : -1)).filter((i) => i >= 0);
  const pairs: [number, number][] = [];
  for (let k = 0; k < 400; k++) pairs.push([idx[Math.floor(rand() * idx.length)], idx[Math.floor(rand() * idx.length)]]);
  const d = (p: Pt3, q: Pt3) => Math.hypot(p.x - q.x, p.y - q.y, p.z - q.z);
  const ratios = pairs.filter(([i, j]) => i !== j).map(([i, j]) => d(truth[i], truth[j]) / d(got[i]!, got[j]!));
  const s = ratios.sort((a, b) => a - b)[Math.floor(ratios.length / 2)];
  const size = Math.max(...truth.map((p) => d(p, truth[0])));
  const err = pairs.filter(([i, j]) => i !== j).reduce((a, [i, j]) => a + Math.abs(d(truth[i], truth[j]) - s * d(got[i]!, got[j]!)), 0) / pairs.length / size;
  // Handedness: the same turn for most sets of four.
  let same = 0;
  let total = 0;
  for (let k = 0; k < 200; k++) {
    const q = [0, 1, 2, 3].map(() => idx[Math.floor(rand() * idx.length)]);
    const det = (P: Pt3[]) => dot(sub(P[1], P[0]), cross(sub(P[2], P[0]), sub(P[3], P[0])));
    const t = det(q.map((i) => truth[i]));
    const g = det(q.map((i) => got[i]!));
    if (Math.abs(t) < 1e-4) continue;
    total++;
    if (Math.sign(t) === Math.sign(g)) same++;
  }
  return { err, mirrored: same < total / 2, scale: s };
}

describe('a custom object in 3D from scans from several sides', () => {
  it('places the LEDs of a tree from scans all the way round, at uneven steps', () => {
    const truth = tree(150);
    const angles = [0, 40, 95, 130, 180, 230, 270, 320];
    const views = angles.map((angle, k) => shoot(truth, { angle, roll: k % 2 ? 2 : -1.5, distance: 1.4 + k * 0.05 }));
    const t0 = Date.now();
    const s = solveViews(views, truth.length);
    const ms = Date.now() - t0;
    expect(s.placed).toBeGreaterThan(130);
    const { err, mirrored } = compare(truth, s.points);
    expect(mirrored).toBe(false);
    expect(err).toBeLessThan(0.02);
    expect(s.rms).toBeLessThan(1.5);
    // The cameras' angles come out as they were.
    s.cameras.forEach((c, k) => expect(Math.abs(((c.angle - angles[k] + 540) % 360) - 180)).toBeLessThan(3));
    expect(ms).toBeLessThan(8000);
  });

  it('works from three scans an eighth of the way round each', () => {
    const truth = tree(100);
    const views = [0, 45, 90].map((angle) => shoot(truth, { angle }));
    const s = solveViews(views, truth.length);
    const { err, mirrored } = compare(truth, s.points);
    expect(mirrored).toBe(false);
    expect(err).toBeLessThan(0.03);
  });

  it('works from two scans, a step apart as asked', () => {
    const truth = tree(80);
    const views = [0, 45].map((angle) => shoot(truth, { angle }));
    const s = solveViews(views, truth.length);
    const { err, mirrored } = compare(truth, s.points);
    expect(mirrored).toBe(false);
    expect(err).toBeLessThan(0.05);
  });

  it('finds the way round, the step and a wide-angle camera', () => {
    const truth = tree(120);
    for (const [angles, f] of [
      [[0, -45, -90, -135], 0.8],
      [[0, -45], 0.8],
      [[0, 90, 180, 270], 0.8],
      [[0, 90], 0.8],
      [[0, 45, 90, 135], 0.45],
      [[0, 45, 90, 135], 1.6]
    ] as const) {
      const views = angles.map((angle) => shoot(truth, { angle, f: f * 1400, distance: f < 0.6 ? 0.9 : f > 1.2 ? 3 : 1.5 }));
      const s = solveViews(views, truth.length);
      const { err, mirrored } = compare(truth, s.points);
      expect(mirrored, `${angles}`).toBe(false);
      expect(err, `${angles} ${f}`).toBeLessThan(0.012);
    }
  });

  it('leaves out misread numbers', () => {
    const truth = tree(120);
    const views = [0, 45, 90, 135].map((angle) => shoot(truth, { angle }));
    // A few LEDs read as others in one scan.
    const bad = views[2].leds.slice(10, 16);
    bad.forEach((l, k) => (l.num = (l.num + 37 + k) % truth.length));
    const s = solveViews(views, truth.length);
    const { err } = compare(truth, s.points);
    expect(err).toBeLessThan(0.03);
  });

  it('becomes a design in meters, one LED at each point, facing the front', () => {
    const truth = tree(90);
    const views = [0, 45, 90, 135, 180, 225, 270, 315].map((angle) => shoot(truth, { angle }));
    const s = solveViews(views, truth.length);
    const runs = wire3d(s.points);
    expect(runs.reduce((a, r) => a + r.length, 0)).toBe(90);
    // Sized by the string's spacing, as the photo is.
    const realStep = step3d(truth);
    const design = design3d(s.points, realStep / step3d(s.points));
    const leds = designLeds(design, 90);
    expect(leds).toHaveLength(90);
    // About the real size: as tall as the tree.
    const ys = leds.map((p) => p.y);
    expect(Math.max(...ys) - Math.min(...ys)).toBeGreaterThan(0.7);
    expect(Math.max(...ys) - Math.min(...ys)).toBeLessThan(0.9);
    // LED 0, at the bottom front of the tree, is toward the front.
    expect(leds[0].z!).toBeGreaterThan(0.2);
    // Placed facing right, its front points right.
    const at = designTransform({ points: [{ x: 0, y: 0 }], facing: 90 }, 100);
    expect(at(leds[0]).x).toBeGreaterThan(20);
  });
});
