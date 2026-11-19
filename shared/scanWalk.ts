// A custom object in 3D from walking round it with the phone in AR.
//
// The phone's AR tracking (its camera and motion sensors together, as AR apps do: on Android,
// ARCore through WebXR) says where the phone is and which way it faces for every picture, in
// meters. Meanwhile the lights blink the scan's color code over and over (see codeColor in
// photoTrace.ts), and the pictures come about ten times a second. So:
//
// - Each LED is followed from picture to picture: where it shows next follows from how the phone
//   moved (and, once its place is known, from where it is), so the right dot is close by.
// - Followed through every frame of the code, an LED's colors tell its number, as in a scan. The
//   code repeats, so the number is read again each time round: an LED followed into its
//   neighbor's dot by mistake reads as the neighbor from then on.
// - Each LED is where its lines of sight from all the pictures meet (see placeSeen). The size is
//   real: the tracking is in meters.
//
// The pictures may come upside down (how the phone's camera image is stored is up to the
// browser): both ways are tried, and the one where the lines of sight meet wins.

import { autoDots, brightMaps, codeFrames, findDots, readColors, typicalGap, type Pixels, type Pt } from './photoTrace.ts';
import { placeSeen, type PosedCam, type Pt3, type Sighting, type Solved3D } from './scan3d.ts';

/** One picture of the walk. */
export interface WalkFrame {
  pixels: Pixels;
  /** Where the phone's camera was (from its AR tracking), for this picture's pixels. */
  cam: PosedCam;
  /** The code frame the lights showed, settled, when it was taken; null while they change. */
  code: number | null;
  /** How many times round the code the lights have been. */
  cycle: number;
}

/** How the walk is going, after each picture. */
export interface WalkStatus {
  frames: number;
  /** LEDs (or other lights) seen in this picture, and the numbers of those that were read. */
  dots: { x: number; y: number; num: number | null }[];
  /** How many LEDs have had their number read so far. */
  numbered: number;
  /** How many of those have a place in 3D so far (seen from far enough apart). */
  placed: number;
  /** The pictures come upside down (null: not clear yet). */
  flipped: boolean | null;
}

/** What the walk found. */
export interface WalkResult {
  /** In meters: x to the right and z toward the phone as seen from where the walk started, y up. */
  solved: Solved3D;
  /** The first picture's dots, with their numbers where read (for the photo view). */
  front: { x: number; y: number; num: number | null }[];
  /** The pictures came upside down (the first one must be turned to match the dots). */
  flipped: boolean;
  frames: number;
}

interface Seen {
  k: number;
  x: number;
  y: number;
}

interface Track {
  seen: Seen[];
  /** Colors over the LED's glow, by time round the code and code frame: summed, and how many. */
  colors: Map<number, { sum: number[][]; count: number[] }>;
  /** The number read each time round the code (null: it did not add up). */
  nums: Map<number, number | null>;
  /** Pictures in a row it was not found in. */
  missed: number;
  /** Where it is, once seen from far enough apart (for following it). */
  X: number[] | null;
}

/** A track not found for this many pictures in a row is left (it went behind something). */
const LOST_AFTER = 12;

function centerOf(c: PosedCam): number[] {
  const R = c.R;
  const [tx, ty, tz] = c.t;
  return [-(R[0] * tx + R[3] * ty + R[6] * tz), -(R[1] * tx + R[4] * ty + R[7] * tz), -(R[2] * tx + R[5] * ty + R[8] * tz)];
}

/** Where a point shows in a picture, and how far in front it is. */
function projectTo(c: PosedCam, X: number[]): [number, number, number] {
  const R = c.R;
  const px = R[0] * X[0] + R[1] * X[1] + R[2] * X[2] + c.t[0];
  const py = R[3] * X[0] + R[4] * X[1] + R[5] * X[2] + c.t[1];
  const pz = R[6] * X[0] + R[7] * X[1] + R[8] * X[2] + c.t[2];
  const d = -pz;
  return [c.cu + (c.f * px) / d, c.cv - ((c.fy ?? c.f) * py) / d, d];
}

/** A point `depth` in front of a camera, through a pixel. */
function along(c: PosedCam, u: number, v: number, depth: number): number[] {
  const R = c.R;
  const d = [(u - c.cu) / c.f, -(v - c.cv) / (c.fy ?? c.f), -1];
  const C = centerOf(c);
  return [0, 1, 2].map((i) => C[i] + depth * (R[i] * d[0] + R[3 + i] * d[1] + R[6 + i] * d[2]));
}

/** An LED's colors summed over its glow (nearer the middle counts more: the edge may catch a neighbor's). */
function glowAt(img: Pixels, p: Pt, rr: number): number[] {
  const out = [0, 0, 0];
  const r = Math.ceil(rr);
  const cx = Math.round(p.x);
  const cy = Math.round(p.y);
  for (let y = Math.max(0, cy - r); y <= Math.min(img.height - 1, cy + r); y++)
    for (let x = Math.max(0, cx - r); x <= Math.min(img.width - 1, cx + r); x++) {
      const d = Math.hypot(x - cx, y - cy);
      if (d > rr) continue;
      const wt = 1 - d / (rr + 1);
      const i = (y * img.width + x) * 4;
      for (let c = 0; c < 3; c++) out[c] += img.data[i + c] * wt;
    }
  return out;
}

export class Walk {
  private readonly n: number;
  private readonly F: number;
  private cams: PosedCam[] = [];
  private cycles: number[] = [];
  private heights: number[] = [];
  private tracks: Track[] = [];
  private threshold: number | null = null;
  /** Times round the code whose numbers were read. */
  private readUpTo = -1;
  /** How far the object is, for following LEDs not yet placed (meters). */
  private depth = 1.5;
  /** The pictures come upside down (null: not known yet). */
  private flip: boolean | null = null;
  private numbered = new Set<number>();
  private placedCount = 0;

  constructor(n: number) {
    this.n = n;
    this.F = codeFrames(n);
  }

  /** The pixel as the camera has it (the pictures may be upside down). */
  private real(k: number, v: number) {
    return this.flip ? this.heights[k] - 1 - v : v;
  }

  add(frame: WalkFrame): WalkStatus {
    const k = this.cams.length;
    const img = frame.pixels;
    this.cams.push(frame.cam);
    this.cycles.push(frame.cycle);
    this.heights.push(img.height);
    const cam = frame.cam;

    const maps = brightMaps(img);
    if (this.threshold == null || k % 20 === 0) this.threshold = autoDots(maps, Math.max(4, this.n * 0.6)).threshold;
    const dots = findDots(maps, this.threshold);
    const gap = typicalGap(dots) || 12;
    const near = dots.map((p) => {
      let best = Infinity;
      for (const q of dots) if (q !== p) best = Math.min(best, Math.hypot(p.x - q.x, p.y - q.y));
      return best;
    });

    // Where each LED being followed should show now.
    const live = this.tracks.filter((t) => t.missed < LOST_AFTER);
    const guesses = live.map((t) => {
      const last = t.seen[t.seen.length - 1];
      let X = t.X;
      if (!X) X = along(this.cams[last.k], last.x, this.real(last.k, last.y), this.depth);
      const [u, v, d] = projectTo(cam, X);
      return d > 0.05 ? { x: u, y: this.real(k, v) } : null;
    });
    // Each dot to the LED it is closest to where it should be, closest first.
    const gate = Math.max(3, Math.min(22, gap * 0.5));
    const pairs: { t: number; d: number; dist: number }[] = [];
    const cell = gate * 2;
    const grid = new Map<string, number[]>();
    dots.forEach((p, i) => {
      const key = `${Math.floor(p.x / cell)},${Math.floor(p.y / cell)}`;
      (grid.get(key) ?? grid.set(key, []).get(key)!).push(i);
    });
    guesses.forEach((g, t) => {
      if (!g) return;
      const reach = gate * (1 + 0.25 * Math.min(4, live[t].missed));
      const gx = Math.floor(g.x / cell);
      const gy = Math.floor(g.y / cell);
      for (let i = gx - 1; i <= gx + 1; i++)
        for (let j = gy - 1; j <= gy + 1; j++)
          for (const d of grid.get(`${i},${j}`) ?? []) {
            const dist = Math.hypot(dots[d].x - g.x, dots[d].y - g.y);
            if (dist <= reach) pairs.push({ t, d, dist });
          }
    });
    pairs.sort((a, b) => a.dist - b.dist);
    const trackOf = new Map<number, Track>();
    const taken = new Set<Track>();
    for (const p of pairs) {
      const t = live[p.t];
      if (taken.has(t) || trackOf.has(p.d)) continue;
      taken.add(t);
      trackOf.set(p.d, t);
    }
    // A dot no LED was expected at: a new one to follow.
    dots.forEach((_, d) => {
      if (trackOf.has(d)) return;
      const t: Track = { seen: [], colors: new Map(), nums: new Map(), missed: 0, X: null };
      this.tracks.push(t);
      trackOf.set(d, t);
    });

    const sample = (t: Track, p: Pt, rr: number) => {
      if (frame.code == null || frame.code < 0 || frame.code >= this.F) return;
      let c = t.colors.get(frame.cycle);
      if (!c) t.colors.set(frame.cycle, (c = { sum: Array.from({ length: this.F }, () => [0, 0, 0]), count: new Array(this.F).fill(0) }));
      const g = glowAt(img, p, rr);
      for (let i = 0; i < 3; i++) c.sum[frame.code][i] += g[i];
      c.count[frame.code]++;
    };
    for (const [d, t] of trackOf) {
      const p = dots[d];
      t.seen.push({ k, x: p.x, y: p.y });
      t.missed = 0;
      sample(t, p, Math.max(1.5, Math.min(gap * 0.6, near[d] * 0.42)));
    }
    // Not found (too dim in the white frame, say), but surely there: its colors where it should be.
    live.forEach((t, i) => {
      if (taken.has(t)) return;
      t.missed++;
      const g = guesses[i];
      if (g && t.missed <= 6 && g.x >= 0 && g.y >= 0 && g.x < img.width && g.y < img.height) sample(t, g, Math.max(1.5, gap * 0.3));
    });

    // Once round the code and one more: read the numbers from the time before (the time after
    // fills in frames a track missed).
    if (frame.cycle - 1 > this.readUpTo + 1) {
      for (let c = this.readUpTo + 1; c < frame.cycle - 1; c++) this.read(c);
      this.readUpTo = frame.cycle - 2;
    }
    if (k % 10 === 9) this.follow();

    return {
      frames: k + 1,
      dots: [...trackOf].map(([d, t]) => ({ x: dots[d].x, y: dots[d].y, num: this.numOf(t, frame.cycle) })),
      numbered: this.numbered.size,
      placed: this.placedCount,
      flipped: this.flip
    };
  }

  /** Reads the numbers of the LEDs followed through one time round the code. */
  private read(cycle: number) {
    const F = this.F;
    const list: { t: Track; sums: number[][] }[] = [];
    for (const t of this.tracks) {
      if (!t.colors.has(cycle) || t.nums.has(cycle)) continue;
      // Each code frame from this time round, else the time before or after.
      const sums: number[][] = [];
      for (let f = 0; f < F; f++) {
        const from = [cycle, cycle - 1, cycle + 1].map((c) => t.colors.get(c)).find((c) => c && c.count[f] > 0);
        if (!from) break;
        sums.push(from.sum[f].map((v) => v / from.count[f]));
      }
      if (sums.length === F) list.push({ t, sums });
      else t.nums.set(cycle, null);
    }
    if (!list.length) return;
    const { ids, strength } = readColors(
      list.map((x) => x.sums),
      this.n
    );
    // Two lights with one number at once: the brighter keeps it when clearly brighter (the
    // other is its reflection), else neither.
    const frames = list.map((x) => new Set(x.t.seen.filter((s) => this.cycles[s.k] === cycle).map((s) => s.k)));
    const out = [...ids];
    for (let a = 0; a < list.length; a++)
      for (let b = a + 1; b < list.length; b++) {
        if (ids[a] == null || ids[a] !== ids[b] || ![...frames[a]].some((k) => frames[b].has(k))) continue;
        if (strength[a] >= strength[b] * 1.6) out[b] = null;
        else if (strength[b] >= strength[a] * 1.6) out[a] = null;
        else out[a] = out[b] = null;
      }
    list.forEach((x, i) => {
      x.t.nums.set(cycle, out[i]);
      if (out[i] != null) this.numbered.add(out[i]!);
    });
  }

  /** A track's number in a time round the code: as read, else as read before and after. */
  private numOf(t: Track, cycle: number): number | null {
    const here = t.nums.get(cycle);
    if (here != null) return here;
    const before = [...t.nums].filter(([c, v]) => c < cycle && v != null).sort((a, b) => b[0] - a[0])[0];
    const after = [...t.nums].filter(([c, v]) => c > cycle && v != null).sort((a, b) => a[0] - b[0])[0];
    if (before && after) return before[1] === after[1] ? before[1] : null;
    return (before ?? after)?.[1] ?? null;
  }

  /** The sightings of each LED, by number, in the camera's own pixels (see flip). */
  private sightings(flip: boolean): Sighting[][] {
    const out: Sighting[][] = Array.from({ length: this.n }, () => []);
    for (const t of this.tracks) {
      const by = new Map<number, number | null>();
      for (const s of t.seen) {
        const c = this.cycles[s.k];
        if (!by.has(c)) by.set(c, this.numOf(t, c));
        const num = by.get(c);
        if (num != null) out[num].push({ cam: s.k, u: s.x, v: flip ? this.heights[s.k] - 1 - s.y : s.y });
      }
    }
    return out;
  }

  /** Every so often: where the followed LEDs are, to follow them better, and how far the object is. */
  private follow() {
    if (this.flip == null) this.pickFlip(false);
    const flip = !!this.flip;
    const live = this.tracks.filter((t) => t.missed < LOST_AFTER && t.seen.length >= 4);
    const seen = live.map((t) => t.seen.slice(-40).map((s) => ({ cam: s.k, u: s.x, v: flip ? this.heights[s.k] - 1 - s.y : s.y })));
    const got = placeSeen(this.cams, seen);
    live.forEach((t, i) => {
      const p = got.points[i];
      t.X = p ? [p.x, p.y, p.z] : null;
    });
    const cam = this.cams[this.cams.length - 1];
    const depths = live.flatMap((t) => (t.X ? [projectTo(cam, t.X)[2]] : [])).filter((d) => d > 0.05);
    if (depths.length >= 3) this.depth = depths.sort((a, b) => a - b)[Math.floor(depths.length / 2)];
    this.placedCount = placeSeen(this.cams, this.sightings(flip)).placed;
  }

  /**
   * Which way up the pictures are: the way the lines of sight meet. While walking, from the
   * lights followed so far (numbers or not), settled once it is clear; at the end, from the LEDs.
   */
  private pickFlip(final: boolean) {
    const ways = [false, true].map((flip) => placeSeen(this.cams, this.sightings(flip)));
    const score = (w: { placed: number; rms: number }) => w.placed / (1 + w.rms);
    if (final) {
      this.flip = score(ways[1]) > score(ways[0]);
      return ways;
    }
    const followed = this.tracks.filter((t) => t.seen.length >= 6);
    const [up, down] = [false, true].map((flip) => placeSeen(this.cams, followed.map((t) => t.seen.map((s) => ({ cam: s.k, u: s.x, v: flip ? this.heights[s.k] - 1 - s.y : s.y })))));
    if (up.placed + down.placed >= 12) {
      if (score(up) > score(down) * 1.5) this.flip = false;
      else if (score(down) > score(up) * 1.5) this.flip = true;
    }
    return ways;
  }

  /** The LEDs in 3D, from the whole walk. */
  finish(): WalkResult {
    for (let c = this.readUpTo + 1; c <= (this.cycles.at(-1) ?? -1); c++) this.read(c);
    this.readUpTo = this.cycles.at(-1) ?? -1;
    const empty = { solved: { points: Array.from({ length: this.n }, () => null), cameras: [], rms: 0, placed: 0 }, front: [], flipped: false, frames: this.cams.length };
    if (this.cams.length < 2) return empty;
    const was = this.flip;
    const ways = this.pickFlip(true);
    // Once settled while walking, it stays (unless the whole walk clearly says otherwise).
    if (was != null && was !== this.flip && ways[was ? 1 : 0].placed >= ways[this.flip ? 1 : 0].placed * 0.9) this.flip = was;
    const got = ways[this.flip ? 1 : 0];
    const pts = got.points.slice();

    // An LED far from both of its neighbors on the string was misread.
    const steps: number[] = [];
    for (let i = 1; i < pts.length; i++) {
      const a = pts[i - 1];
      const b = pts[i];
      if (a && b) steps.push(Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z));
    }
    steps.sort((a, b) => a - b);
    const step = steps[Math.floor(steps.length / 2)] ?? 0;
    if (step > 0) {
      const far = (i: number, j: number) => {
        const a = pts[i];
        const b = pts[j];
        return !a || !b ? null : Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z) > step * 5;
      };
      const drop = pts.map((_, i) => {
        const near = [i - 1, i + 1].filter((j) => j >= 0 && j < pts.length).map((j) => far(i, j)).filter((x): x is boolean => x != null);
        return near.length > 0 && near.every(Boolean);
      });
      drop.forEach((d, i) => d && (pts[i] = null));
    }

    // To the design's frame: the middle of the LEDs at 0, the first picture's side the front.
    const placed = pts.filter((p): p is Pt3 => !!p);
    if (!placed.length) return { ...empty, flipped: !!this.flip };
    const mid = (key: 'x' | 'y' | 'z') => (Math.min(...placed.map((p) => p[key])) + Math.max(...placed.map((p) => p[key]))) / 2;
    const m = { x: mid('x'), y: mid('y'), z: mid('z') };
    const c0 = centerOf(this.cams[0]);
    let fz = [c0[0] - m.x, 0, c0[2] - m.z];
    const lz = Math.hypot(...fz);
    fz = lz > 1e-6 ? fz.map((v) => v / lz) : [0, 0, 1];
    // x = up × z.
    const fx = [fz[2], 0, -fz[0]];
    const to = (p: { x: number; y: number; z: number }): Pt3 => {
      const d = [p.x - m.x, p.y - m.y, p.z - m.z];
      return { x: d[0] * fx[0] + d[2] * fx[2], y: d[1], z: d[0] * fz[0] + d[2] * fz[2] };
    };
    const points = pts.map((p) => (p ? to(p) : null));
    const cameras = this.cams.map((c) => {
      const C = centerOf(c);
      const q = to({ x: C[0], y: C[1], z: C[2] });
      return { ...q, angle: (Math.atan2(q.x, q.z) * 180) / Math.PI };
    });
    // The first picture's dots. One whose LED was not followed long enough to read its number
    // takes the number of the LED that shows there, of those seen near the start.
    const raw = this.tracks.flatMap((t) => {
      const s = t.seen.find((x) => x.k === 0);
      return s ? [{ x: s.x, y: s.y, num: this.numOf(t, this.cycles[0]) }] : [];
    });
    const flip = !!this.flip;
    const early = new Set<number>();
    this.sightings(flip).forEach((list, i) => list.some((o) => o.cam < 15) && early.add(i));
    const claimed = new Set(raw.flatMap((d) => (d.num != null ? [d.num] : [])));
    const gap0 = typicalGap(raw) || 10;
    const shows = pts.flatMap((p, i) => {
      if (!p || !early.has(i) || claimed.has(i)) return [];
      const [u, v, d] = projectTo(this.cams[0], [p.x, p.y, p.z]);
      return d > 0 ? [{ i, x: u, y: flip ? this.heights[0] - 1 - v : v }] : [];
    });
    for (const dot of raw) {
      if (dot.num != null) continue;
      let best: (typeof shows)[number] | null = null;
      let bd = Math.max(3, gap0 * 0.5);
      for (const q of shows) {
        const dd = Math.hypot(q.x - dot.x, q.y - dot.y);
        if (dd < bd && !claimed.has(q.i)) ((bd = dd), (best = q));
      }
      if (best) {
        dot.num = best.i;
        claimed.add(best.i);
      }
    }
    const front = raw.map((d) => ({ x: d.x, y: flip ? this.heights[0] - 1 - d.y : d.y, num: d.num }));
    return { solved: { points, cameras, rms: got.rms, placed: points.filter(Boolean).length }, front, flipped: !!this.flip, frames: this.cams.length };
  }
}
