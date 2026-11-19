// A custom object from a photo: the object's LEDs are lit in one color that stands out (its
// first LED in another), someone takes a picture, and this finds the lit LEDs in it (a cloud of
// dots), puts them in the order the wire runs, and turns them into a design (see DesignStroke).
// When the dots are wrong or missing, the editor lets you trace the wire over the photo by hand.
//
// Everything here works on plain RGBA pixels (as from a canvas), so it runs in the browser and
// in tests alike. The photo never leaves the browser.

import type { DesignStroke } from './layout.ts';

export type RGB = [number, number, number];
export interface Pt {
  x: number;
  y: number;
}

/** RGBA pixels, row by row (as ImageData has them). */
export interface Pixels {
  width: number;
  height: number;
  data: Uint8ClampedArray | Uint8Array;
}

/** The colors to light an object in for its photo: most LEDs in `rgb`, the first one in `start`. */
export interface PhotoColor {
  id: string;
  name: string;
  rgb: RGB;
  start: RGB;
  startName: string;
}

// The LEDs at half power: at full power they glow into each other in a photo.
export const PHOTO_COLORS: PhotoColor[] = [
  { id: 'green', name: 'Green', rgb: [0, 140, 0], start: [255, 0, 0], startName: 'red' },
  { id: 'blue', name: 'Blue', rgb: [0, 0, 160], start: [255, 0, 0], startName: 'red' },
  { id: 'magenta', name: 'Magenta', rgb: [140, 0, 140], start: [0, 255, 0], startName: 'green' }
];

/** One lit LED found in the photo, in photo pixels. */
export interface Dot extends Pt {
  /** How many pixels it covers. */
  area: number;
  /** True when it has the first LED's color. */
  start?: boolean;
}

// ---------- Finding the LEDs ----------

/** A color's hue direction (the color minus its gray), as a unit vector. */
function hueOf(c: RGB): RGB {
  const m = (c[0] + c[1] + c[2]) / 3;
  const d: RGB = [c[0] - m, c[1] - m, c[2] - m];
  const l = Math.hypot(...d) || 1;
  return [d[0] / l, d[1] / l, d[2] / l];
}

/**
 * How much a pixel looks like a lit LED of a color (0..255): strongly of that hue (not merely
 * near it: yellow is not green), and bright. Grass by day is green too, but much darker.
 */
function glow(r: number, g: number, b: number, h: RGB): number {
  const m = (r + g + b) / 3;
  const dr = r - m;
  const dg = g - m;
  const db = b - m;
  const along = dr * h[0] + dg * h[1] + db * h[2];
  if (along <= 0) return 0;
  const off = Math.sqrt(Math.max(0, dr * dr + dg * dg + db * db - along * along));
  const s = (along - 0.6 * off) * (Math.max(r, g, b) / 255);
  return s > 0 ? Math.min(255, s * 1.2) : 0;
}

/** The two glow maps of a photo (the LEDs' color and the first LED's), and its blown-out white. */
export interface GlowMaps {
  width: number;
  height: number;
  main: Uint8Array;
  start: Uint8Array;
  /** The camera's white: the middle of a bright LED often comes out white, with its color around it. */
  white: Uint8Array;
}

export function glowMaps(img: Pixels, color: Pick<PhotoColor, 'rgb' | 'start'>): GlowMaps {
  const n = img.width * img.height;
  const main = new Uint8Array(n);
  const start = new Uint8Array(n);
  const white = new Uint8Array(n);
  const hm = hueOf(color.rgb);
  const hs = hueOf(color.start);
  const d = img.data;
  for (let i = 0; i < n; i++) {
    const r = d[i * 4];
    const g = d[i * 4 + 1];
    const b = d[i * 4 + 2];
    main[i] = glow(r, g, b, hm);
    start[i] = glow(r, g, b, hs);
    white[i] = r >= 225 && g >= 225 && b >= 225 ? 1 : 0;
  }
  return { width: img.width, height: img.height, main, start, white };
}

/**
 * The lit LEDs at one threshold: patches of glowing pixels (white ones count only next to
 * color, so a lit window or a street light is not an LED). Patches much bigger than the rest
 * (a lit wall, a reflection) are left out.
 */
export function findDots(maps: GlowMaps, threshold: number): Dot[] {
  const { width: w, height: h, main, start, white } = maps;
  const n = w * h;
  const seen = new Uint8Array(n);
  const stack = new Int32Array(n);
  const found: (Dot & { colored: number; sMain: number; sStart: number })[] = [];
  const lit = (i: number) => main[i] >= threshold || start[i] >= threshold || white[i] === 1;
  for (let i0 = 0; i0 < n; i0++) {
    if (seen[i0] || !lit(i0)) continue;
    let top = 0;
    stack[top++] = i0;
    seen[i0] = 1;
    let area = 0;
    let colored = 0;
    let sx = 0;
    let sy = 0;
    let sw = 0;
    let sMain = 0;
    let sStart = 0;
    while (top) {
      const i = stack[--top];
      const x = i % w;
      const y = (i - x) / w;
      area++;
      const m = main[i];
      const s = start[i];
      if (m >= threshold || s >= threshold) colored++;
      sMain += m;
      sStart += s;
      // Weighted by how much it glows; the white middle counts fully.
      const wt = white[i] ? 255 : Math.max(m, s);
      sx += x * wt;
      sy += y * wt;
      sw += wt;
      if (x > 0 && !seen[i - 1] && lit(i - 1)) ((seen[i - 1] = 1), (stack[top++] = i - 1));
      if (x < w - 1 && !seen[i + 1] && lit(i + 1)) ((seen[i + 1] = 1), (stack[top++] = i + 1));
      if (y > 0 && !seen[i - w] && lit(i - w)) ((seen[i - w] = 1), (stack[top++] = i - w));
      if (y < h - 1 && !seen[i + w] && lit(i + w)) ((seen[i + w] = 1), (stack[top++] = i + w));
    }
    // A patch with (almost) no color is a white light, not one of ours.
    if (colored < 2 || colored < area * 0.08 || !sw) continue;
    found.push({ x: sx / sw, y: sy / sw, area, colored, sMain, sStart });
  }
  if (!found.length) return [];
  const areas = found.map((f) => f.area).sort((a, b) => a - b);
  const typical = areas[Math.floor(areas.length / 2)];
  const kept = found.filter((f) => f.area <= Math.max(60, typical * 25));
  const dots = mergeClose(kept);
  // The first LED: the one dot that is clearly the start color.
  let best = -1;
  let bestShare = 0.6;
  dots.forEach((d, i) => {
    const share = d.sStart / Math.max(1, d.sStart + d.sMain);
    if (share > bestShare) {
      bestShare = share;
      best = i;
    }
  });
  return dots.map((d, i) => ({ x: d.x, y: d.y, area: d.area, ...(i === best ? { start: true } : {}) }));
}

/** One LED can come out as two patches (a bright middle, a ring of color): they become one. */
function mergeClose<T extends Dot & { sMain: number; sStart: number }>(dots: T[]): T[] {
  if (dots.length < 3) return dots;
  const gap = typicalGap(dots);
  const out: T[] = [];
  const gone = new Set<number>();
  for (let i = 0; i < dots.length; i++) {
    if (gone.has(i)) continue;
    let d = dots[i];
    for (let j = i + 1; j < dots.length; j++) {
      if (gone.has(j)) continue;
      const e = dots[j];
      if (Math.hypot(d.x - e.x, d.y - e.y) < gap * 0.4) {
        const a = d.area + e.area;
        d = { ...d, x: (d.x * d.area + e.x * e.area) / a, y: (d.y * d.area + e.y * e.area) / a, area: a, sMain: d.sMain + e.sMain, sStart: d.sStart + e.sStart };
        gone.add(j);
      }
    }
    out.push(d);
  }
  return out;
}

/** The usual distance from a dot to its nearest neighbor. */
export function typicalGap(pts: Pt[]): number {
  if (pts.length < 2) return 0;
  const near = pts.map((p, i) => {
    let best = Infinity;
    for (let j = 0; j < pts.length; j++) if (j !== i) best = Math.min(best, Math.hypot(p.x - pts[j].x, p.y - pts[j].y));
    return best;
  });
  near.sort((a, b) => a - b);
  return near[Math.floor(near.length / 2)];
}

/** Thresholds to try, from catching faint LEDs to only the brightest. */
export const THRESHOLDS = [16, 24, 32, 40, 50, 60, 72, 86, 100, 116, 134, 154, 176, 200];

/**
 * Finds the LEDs at the threshold that works best: the one closest to `expected` LEDs when the
 * count is known, else the middle of the steadiest stretch (where the count changes least).
 */
export function autoDots(maps: GlowMaps, expected?: number | null): { dots: Dot[]; threshold: number } {
  const tries = THRESHOLDS.map((t) => ({ threshold: t, dots: findDots(maps, t) }));
  if (expected && expected > 0) {
    let best = tries[0];
    for (const t of tries) {
      const d = Math.abs(t.dots.length - expected) - Math.abs(best.dots.length - expected);
      // Ties: the higher threshold, with less noise.
      if (d <= 0) best = t;
    }
    return best;
  }
  let best = { from: 0, len: 0 };
  for (let i = 0; i < tries.length; i++) {
    const c = tries[i].dots.length;
    if (c < 3) continue;
    let j = i;
    while (j + 1 < tries.length && Math.abs(tries[j + 1].dots.length - c) <= Math.max(1, c * 0.05)) j++;
    if (j - i + 1 > best.len) best = { from: i, len: j - i + 1 };
  }
  return best.len ? tries[best.from + Math.floor((best.len - 1) / 2)] : tries[0];
}

// ---------- Putting them in order ----------

const dist = (a: Pt, b: Pt) => Math.hypot(a.x - b.x, a.y - b.y);

/**
 * The order the wire runs through the dots, as strokes of dot indexes: from the first LED (or
 * an end of the string when it is not known), always on to a near dot, then straightened out
 * (no crossings where none are needed). Where the next LED is much farther than usual, the wire
 * jumps: a new stroke starts.
 */
export function orderDots(dots: Pt[], start?: number | null): number[][] {
  const n = dots.length;
  if (!n) return [];
  if (n === 1) return [[0]];
  const gap = typicalGap(dots);
  const first = start != null && start >= 0 && start < n ? start : endOf(dots, gap);
  // Nearest neighbor, from the first LED.
  const left = new Set(dots.keys());
  left.delete(first);
  const path = [first];
  while (left.size) {
    const at = dots[path.at(-1)!];
    let best = -1;
    let bd = Infinity;
    for (const j of left) {
      const d = dist(at, dots[j]);
      if (d < bd) {
        bd = d;
        best = j;
      }
    }
    path.push(best);
    left.delete(best);
  }
  untangle(dots, path);
  // A long jump: the wire leaves the LEDs there.
  const strokes: number[][] = [[path[0]]];
  for (let i = 1; i < n; i++) {
    if (dist(dots[path[i - 1]], dots[path[i]]) > gap * 2.6) strokes.push([]);
    strokes.at(-1)!.push(path[i]);
  }
  return strokes;
}

/** An end of the string: a dot with at most one near neighbor, as far out as can be. */
function endOf(dots: Pt[], gap: number): number {
  const cx = dots.reduce((a, p) => a + p.x, 0) / dots.length;
  const cy = dots.reduce((a, p) => a + p.y, 0) / dots.length;
  let best = -1;
  let bd = -1;
  let low = 0;
  dots.forEach((p, i) => {
    if (p.y > dots[low].y) low = i;
    let near = 0;
    for (const q of dots) if (q !== p && dist(p, q) < gap * 1.6) near++;
    const d = Math.hypot(p.x - cx, p.y - cy);
    if (near <= 1 && d > bd) {
      bd = d;
      best = i;
    }
  });
  // A loop has no ends: start at the bottom.
  return best >= 0 ? best : low;
}

/**
 * Shortens a path that starts at path[0] (it stays first): parts of it are turned around (2-opt),
 * and short runs of one to three dots move to where they fit better (or-opt), so the wire does
 * not cross itself or leave a few LEDs behind for later. Stops after a while on big strings.
 */
function untangle(dots: Pt[], path: number[], budgetMs = 400) {
  const n = path.length;
  const d = (i: number, j: number) => dist(dots[path[i]], dots[path[j]]);
  const until = Date.now() + budgetMs;
  for (let pass = 0, better = true; better && pass < 60; pass++) {
    better = false;
    for (let i = 1; i < n - 1; i++) {
      if (Date.now() > until) return;
      for (let j = i + 1; j < n; j++) {
        // Turn path[i..j] around: edges (i-1, i) and (j, j+1) become (i-1, j) and (i, j+1).
        const before = d(i - 1, i) + (j + 1 < n ? d(j, j + 1) : 0);
        const after = d(i - 1, j) + (j + 1 < n ? d(i, j + 1) : 0);
        if (after < before - 1e-9) {
          for (let a = i, b = j; a < b; a++, b--) [path[a], path[b]] = [path[b], path[a]];
          better = true;
        }
      }
    }
    for (let len = 1; len <= 3; len++) {
      for (let i = 1; i + len <= n; i++) {
        if (Date.now() > until) return;
        const e = i + len - 1;
        // Taking path[i..e] out joins i-1 to e+1.
        const gain = d(i - 1, i) + (e + 1 < n ? d(e, e + 1) - d(i - 1, e + 1) : 0);
        let best: { j: number; flip: boolean; cost: number } | null = null;
        for (let j = 0; j < n; j++) {
          if (j >= i - 1 && j <= e) continue;
          // Between j and j + 1 (or after the last dot), either way round.
          const next = j + 1 < n ? j + 1 : -1;
          const base = next >= 0 ? d(j, next) : 0;
          const keep = d(j, i) + (next >= 0 ? d(e, next) : 0) - base;
          const flip = d(j, e) + (next >= 0 ? d(i, next) : 0) - base;
          const cost = Math.min(keep, flip);
          if (cost < gain - 1e-9 && (!best || cost < best.cost)) best = { j, flip: flip < keep, cost };
        }
        if (!best) continue;
        const part = path.slice(i, e + 1);
        if (best.flip) part.reverse();
        const id = path[best.j];
        path.splice(i, len);
        path.splice(path.indexOf(id) + 1, 0, ...part);
        better = true;
      }
    }
  }
}

/**
 * The dots a finger or the mouse passed over, in the order it passed them: each dot within
 * `radius` of the path, at most once, leaving out the dots in `used` (already on the wire).
 */
export function traceDots(dots: Pt[], path: Pt[], radius: number, used: ReadonlySet<number> = new Set()): number[] {
  const out: number[] = [];
  const taken = new Set(used);
  const segs = path.length === 1 ? [[path[0], path[0]]] : path.slice(1).map((p, i) => [path[i], p]);
  for (const [a, b] of segs) {
    const vx = b.x - a.x;
    const vy = b.y - a.y;
    const l2 = vx * vx + vy * vy;
    const hits: { i: number; t: number }[] = [];
    dots.forEach((p, i) => {
      if (taken.has(i)) return;
      const t = l2 ? Math.max(0, Math.min(1, ((p.x - a.x) * vx + (p.y - a.y) * vy) / l2)) : 0;
      if (Math.hypot(a.x + vx * t - p.x, a.y + vy * t - p.y) <= radius) hits.push({ i, t });
    });
    hits.sort((p, q) => p.t - q.t);
    for (const h of hits) {
      out.push(h.i);
      taken.add(h.i);
    }
  }
  return out;
}

/** Fewer points on a line (Ramer–Douglas–Peucker): those within `tolerance` of the line go. */
export function simplify(pts: Pt[], tolerance: number): Pt[] {
  if (pts.length < 3) return pts;
  const keep = new Uint8Array(pts.length);
  keep[0] = keep[pts.length - 1] = 1;
  const stack: [number, number][] = [[0, pts.length - 1]];
  while (stack.length) {
    const [a, b] = stack.pop()!;
    let far = -1;
    let fd = tolerance;
    for (let i = a + 1; i < b; i++) {
      const d = toSegment(pts[i], pts[a], pts[b]);
      if (d > fd) {
        fd = d;
        far = i;
      }
    }
    if (far >= 0) {
      keep[far] = 1;
      stack.push([a, far], [far, b]);
    }
  }
  return pts.filter((_, i) => keep[i]);
}

function toSegment(p: Pt, a: Pt, b: Pt) {
  const vx = b.x - a.x;
  const vy = b.y - a.y;
  const l2 = vx * vx + vy * vy;
  const t = l2 ? Math.max(0, Math.min(1, ((p.x - a.x) * vx + (p.y - a.y) * vy) / l2)) : 0;
  return Math.hypot(a.x + vx * t - p.x, a.y + vy * t - p.y);
}

// ---------- To a design ----------

/** A run of the wire traced on the photo, in photo pixels. `dots`: its points are lit LEDs. */
export interface PhotoStroke {
  points: Pt[];
  dots: boolean;
  closed?: boolean;
  /** One point per LED, in order (from a scan: see numberedStrokes). */
  exact?: boolean;
}

/** The strokes of dots in wire order (see orderDots); a stroke that ends next to its start goes all round. */
export function strokesFromOrder(dots: Pt[], order: number[][]): PhotoStroke[] {
  const gap = typicalGap(dots);
  return order
    .filter((o) => o.length)
    .map((o) => {
      const points = o.map((i) => ({ x: dots[i].x, y: dots[i].y }));
      return { points, dots: true, ...(isLoop(points, gap) ? { closed: true } : {}) };
    });
}

/** True for a run of LEDs whose last LED is next to its first. */
export function isLoop(points: Pt[], gap: number): boolean {
  return points.length >= 6 && gap > 0 && dist(points[0], points.at(-1)!) <= gap * 1.8;
}

/**
 * The wire's length between two LEDs is the most they can be apart; where it is slack (or runs
 * toward the camera) they look closer. So the string's spacing shows in the longer steps, not
 * the usual ones: this is a high one (the 80th percentile, `at`), leaving out the few longest
 * (an LED missed between two, or misread).
 */
export function tautStep(steps: number[], at = 0.8): number {
  const v = steps.filter((x) => x > 0).sort((a, b) => a - b);
  return v.length ? v[Math.min(v.length - 1, Math.floor(v.length * at))] : 0;
}

/** The string's spacing in photo pixels, from the traced wire through the dots (0: none). */
export function ledStep(strokes: PhotoStroke[]): number {
  const steps: number[] = [];
  for (const s of strokes) {
    if (!s.dots) continue;
    for (let i = 1; i < s.points.length; i++) steps.push(dist(s.points[i - 1], s.points[i]));
  }
  return tautStep(steps);
}

/** The string's spacing in photo pixels from a scan: between LEDs whose numbers follow on. */
export function numberedStep(dots: Pt[], ids: (number | null)[]): number {
  const at = new Map<number, Pt>();
  ids.forEach((id, k) => id != null && at.set(id, dots[k]));
  const steps: number[] = [];
  for (const [id, p] of at) {
    const q = at.get(id + 1);
    if (q) steps.push(dist(p, q));
  }
  return tautStep(steps, 0.85);
}

/**
 * A scan's wire as strokes with one point per LED, all n of them, in number order (see orderByNumber):
 * an LED that was not read sits on the straight line between the ones read before and after it
 * (the wire runs there: LEDs are never farther apart than the wire between them), or, before the
 * first or after the last one read, on it.
 */
export function numberedStrokes(dots: Pt[], ids: (number | null)[], order: number[][], n: number): PhotoStroke[] {
  const runs = order.filter((o) => o.length);
  if (!runs.length) return [];
  const out: PhotoStroke[] = runs.map(() => ({ points: [], dots: true, exact: true }));
  const first = ids[runs[0][0]]!;
  for (let i = 0; i < first; i++) out[0].points.push({ ...dots[runs[0][0]] });
  let prev: { id: number; p: Pt } | null = null;
  runs.forEach((run, r) => {
    for (const k of run) {
      const id = ids[k]!;
      const p = dots[k];
      if (prev && id - prev.id > 1) {
        // The ones between: on the way from the one before (in the stroke the wire came from).
        const into = out[run[0] === k && r > 0 ? r - 1 : r].points;
        for (let m = 1; m < id - prev.id; m++) {
          const t = m / (id - prev.id);
          into.push({ x: prev.p.x + (p.x - prev.p.x) * t, y: prev.p.y + (p.y - prev.p.y) * t });
        }
      }
      out[r].points.push({ x: p.x, y: p.y });
      prev = { id, p };
    }
  });
  const last = prev as { id: number; p: Pt } | null;
  if (last) for (let i = last.id + 1; i < n; i++) out.at(-1)!.points.push({ ...last.p });
  return out;
}

/** How wide the traced wire is, in photo pixels. */
export function photoWidth(strokes: PhotoStroke[]): number {
  const xs = strokes.flatMap((s) => s.points.map((p) => p.x));
  return xs.length ? Math.max(...xs) - Math.min(...xs) : 0;
}

/**
 * The traced wire as a design, in meters (y up), with the anchor in the middle. `metersPerPixel`
 * sizes it. Straight runs keep only their ends: the LEDs spread along the wire evenly anyway.
 */
export function photoDesign(strokes: PhotoStroke[], metersPerPixel: number): DesignStroke[] {
  const live = strokes.filter((s) => s.points.length);
  const all = live.flatMap((s) => s.points);
  if (!all.length) return [];
  const cx = (Math.min(...all.map((p) => p.x)) + Math.max(...all.map((p) => p.x))) / 2;
  const cy = (Math.min(...all.map((p) => p.y)) + Math.max(...all.map((p) => p.y))) / 2;
  const step = ledStep(live);
  const r3 = (v: number) => Math.round(v * 1000) / 1000 + 0;
  const at = (p: Pt) => ({ x: r3((p.x - cx) * metersPerPixel), y: r3(-(p.y - cy) * metersPerPixel) });
  return live.map((s) => {
    // A scanned run keeps every LED where it is.
    if (s.exact) return { points: s.points.map(at), exact: true, ...(s.closed ? { closed: true } : {}) };
    const pts = s.closed ? [...s.points, s.points[0]] : s.points;
    let simple = simplify(pts, Math.max(1, (step || 8) * 0.2));
    if (s.closed) simple = simple.slice(0, -1);
    return {
      points: simple.map((p) => ({ x: r3((p.x - cx) * metersPerPixel), y: r3(-(p.y - cy) * metersPerPixel) })),
      ...(s.closed && simple.length > 2 ? { closed: true } : {})
    };
  });
}

// ---------- Scanning with the camera: every LED tells its number ----------
//
// For an exact order, the LEDs blink their own numbers, as active markers do in motion capture.
// The first frame lights every LED a dim white: a reference for how each one comes out on camera.
// In each frame after it, every LED is red, green or blue for one base-3 digit of its number (its
// place from the start of the wire), and a last frame holds a check digit. The colors turn by one
// each frame (a digit 0 is red in one frame, green in the next), so every LED changes color during
// the scan, even LED 0.
//
// What changes from frame to frame is an LED; a lamp, the wall or a colorful toy does not. So the
// LEDs are found where the frames differ, and each is read against its own white and its own
// darkest: a warm lamp, the camera's color balance or a tinted bulb do not shift the colors.

/** The three colors of the code, a little dimmed so the middle of an LED is not all white. */
export const CODE_RGB: RGB[] = [
  [150, 0, 0],
  [0, 120, 0],
  [0, 0, 170]
];
/** The first frame: every LED a dim white. */
export const CODE_WHITE: RGB = [70, 60, 80];

/** How many digits the numbers of n LEDs need. */
export const codeDigits = (n: number) => Math.max(1, Math.ceil(Math.log(Math.max(2, n)) / Math.log(3) - 1e-9));

/** How many frames a scan of n LEDs takes: the white one, the digits and the check digit. */
export const codeFrames = (n: number) => codeDigits(n) + 2;

/** Digit k of LED i's code (k = codeDigits(n): the check digit, the digits' sum). */
export function codeDigit(i: number, k: number, n: number): number {
  const d = codeDigits(n);
  if (k < d) return Math.floor(i / 3 ** k) % 3;
  let sum = 0;
  for (let j = 0; j < d; j++) sum += Math.floor(i / 3 ** j) % 3;
  return sum % 3;
}

/** The color of LED i (counted from the start of the wire) in a frame of a scan of n LEDs. */
export function codeColor(i: number, frame: number, n: number): RGB {
  if (frame <= 0) return CODE_WHITE;
  const k = frame - 1;
  return CODE_RGB[(codeDigit(i, k, n) + k) % 3];
}

/** The LED number from its digits, or null when they do not add up. */
export function decodeDigits(digits: number[], n: number): number | null {
  const d = codeDigits(n);
  if (digits.length !== d + 1 || digits.some((x) => x < 0 || x > 2)) return null;
  let i = 0;
  let sum = 0;
  for (let k = 0; k < d; k++) {
    i += digits[k] * 3 ** k;
    sum += digits[k];
  }
  return sum % 3 === digits[d] && i < n ? i : null;
}

/** A glow map for lights of any color: strongly colored and bright (the code has three colors). */
export function colorfulMaps(img: Pixels): GlowMaps {
  const n = img.width * img.height;
  const main = new Uint8Array(n);
  const white = new Uint8Array(n);
  const d = img.data;
  for (let i = 0; i < n; i++) {
    const r = d[i * 4];
    const g = d[i * 4 + 1];
    const b = d[i * 4 + 2];
    const hi = Math.max(r, g, b);
    const lo = Math.min(r, g, b);
    main[i] = Math.min(255, ((hi - lo) * hi) / 200);
    white[i] = lo >= 225 ? 1 : 0;
  }
  return { width: img.width, height: img.height, main, start: new Uint8Array(n), white };
}

/**
 * How far the dots in a frame moved from where they were (a hand holding the phone moves a
 * little): the move that lines up the most dots, tried every two pixels up to `reach`, then
 * made exact on the dots it lines up.
 */
export function frameShift(ref: Pt[], seen: Pt[], reach = 40): Pt {
  if (!ref.length || !seen.length) return { x: 0, y: 0 };
  const cell = 4;
  const grid = new Map<string, Pt[]>();
  for (const q of seen) {
    const key = `${Math.floor(q.x / cell)},${Math.floor(q.y / cell)}`;
    (grid.get(key) ?? grid.set(key, []).get(key)!).push(q);
  }
  const near = (x: number, y: number, tol: number): Pt | null => {
    const gx = Math.floor(x / cell);
    const gy = Math.floor(y / cell);
    let best: Pt | null = null;
    let bd = tol;
    for (let i = gx - 1; i <= gx + 1; i++)
      for (let j = gy - 1; j <= gy + 1; j++)
        for (const q of grid.get(`${i},${j}`) ?? []) {
          const d = Math.hypot(q.x - x, q.y - y);
          if (d <= bd) {
            bd = d;
            best = q;
          }
        }
    return best;
  };
  let best = { x: 0, y: 0, hits: -1 };
  for (let dy = -reach; dy <= reach; dy += 2)
    for (let dx = -reach; dx <= reach; dx += 2) {
      let hits = 0;
      for (const p of ref) if (near(p.x + dx, p.y + dy, 2)) hits++;
      if (hits > best.hits || (hits === best.hits && Math.hypot(dx, dy) < Math.hypot(best.x, best.y))) best = { x: dx, y: dy, hits };
    }
  const ox: number[] = [];
  const oy: number[] = [];
  for (const p of ref) {
    const q = near(p.x + best.x, p.y + best.y, 2.5);
    if (q) (ox.push(q.x - p.x), oy.push(q.y - p.y));
  }
  const mid = (v: number[]) => v.sort((a, b) => a - b)[Math.floor(v.length / 2)];
  return ox.length ? { x: mid(ox), y: mid(oy) } : { x: best.x, y: best.y };
}

/**
 * A glow map of small bright spots of any color (white too), brighter than what is around them:
 * to follow the dots from frame to frame. A lit wall is bright too, but not brighter than itself.
 */
function brightMaps(img: Pixels): GlowMaps {
  const { width: w, height: h, data: d } = img;
  const n = w * h;
  const v = new Float64Array(n);
  for (let i = 0; i < n; i++) v[i] = Math.max(d[i * 4], d[i * 4 + 1], d[i * 4 + 2]);
  // Sums from the top left corner, for the mean of any box at once.
  const sum = new Float64Array((w + 1) * (h + 1));
  for (let y = 0; y < h; y++) {
    let row = 0;
    for (let x = 0; x < w; x++) {
      row += v[y * w + x];
      sum[(y + 1) * (w + 1) + x + 1] = sum[y * (w + 1) + x + 1] + row;
    }
  }
  const r = 10;
  const main = new Uint8Array(n);
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++) {
      const x0 = Math.max(0, x - r);
      const y0 = Math.max(0, y - r);
      const x1 = Math.min(w, x + r + 1);
      const y1 = Math.min(h, y + r + 1);
      const mean = (sum[y1 * (w + 1) + x1] - sum[y0 * (w + 1) + x1] - sum[y1 * (w + 1) + x0] + sum[y0 * (w + 1) + x0]) / ((x1 - x0) * (y1 - y0));
      main[y * w + x] = Math.max(0, Math.min(255, (v[y * w + x] - mean) * 2));
    }
  return { width: w, height: h, main, start: new Uint8Array(n), white: new Uint8Array(n) };
}

/** A scan's frames lined up: where each frame moved (from frame 1), and its colors evened out. */
export interface ScanFrames {
  frames: Pixels[];
  /** Whole pixels to add to a position in frame 1 to find it in each frame. */
  shifts: Pt[];
  /** Per frame and color: what to multiply by so the room looks the same in every frame. */
  levels: number[][];
}

/**
 * Lines the frames up: the hand moves a little (followed through the colored dots), and the
 * camera may change its exposure or color balance from frame to frame (evened out on the room,
 * which does not change).
 */
export function lineUp(frames: Pixels[], n: number): ScanFrames {
  const ref = frames[Math.min(1, frames.length - 1)];
  // The threshold that suits frame 1 suits the others (looking for the best one is slow).
  const first = autoDots(brightMaps(ref), n);
  const spots = frames.map((img, f) => (f === 1 ? first.dots : findDots(brightMaps(img), first.threshold)));
  const shifts = spots.map((list, f) => {
    if (f === 1) return { x: 0, y: 0 };
    const sh = frameShift(spots[1], list);
    return { x: Math.round(sh.x), y: Math.round(sh.y) };
  });
  // The room's middle level of each color, from a sample of pixels.
  const median = (img: Pixels, c: number) => {
    const hist = new Uint32Array(256);
    let count = 0;
    for (let i = c; i < img.data.length; i += 4 * 7) (hist[img.data[i]]++, count++);
    for (let v = 0, acc = 0; v < 256; v++) if ((acc += hist[v]) * 2 >= count) return Math.max(4, v);
    return 128;
  };
  const base = [0, 1, 2].map((c) => median(ref, c));
  const levels = frames.map((img) => [0, 1, 2].map((c) => Math.min(2, Math.max(0.5, base[c] / median(img, c)))));
  return { frames, shifts, levels };
}

/** One frame's color at a place in frame 1's terms, evened out (see lineUp). */
function at(s: ScanFrames, f: number, x: number, y: number, c: number): number {
  const img = s.frames[f];
  const fx = Math.min(img.width - 1, Math.max(0, x + s.shifts[f].x));
  const fy = Math.min(img.height - 1, Math.max(0, y + s.shifts[f].y));
  return img.data[(fy * img.width + fx) * 4 + c] * s.levels[f][c];
}

/**
 * Finds the LEDs of a scan: where the color changes from frame to frame. A lamp, the wall and
 * anything else that stays the same drop out. Dots are in frame 1's pixels.
 */
export function scanDots(s: ScanFrames, n: number): { dots: Dot[]; threshold: number } {
  const { width: w, height: h } = s.frames[0];
  const main = new Uint8Array(w * h);
  const F = s.frames.length;
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++) {
      let most = 0;
      for (let c = 0; c < 3; c++) {
        let lo = 255 * 2;
        let hi = 0;
        for (let f = 0; f < F; f++) {
          const v = at(s, f, x, y, c);
          if (v < lo) lo = v;
          if (v > hi) hi = v;
        }
        most = Math.max(most, hi - lo);
      }
      main[y * w + x] = Math.min(255, most);
    }
  // Glows of neighbors run together where they change: the white frame's small bright spots
  // keep them apart (and only what changes counts).
  const white = brightMaps(s.frames[0]);
  const s0 = s.shifts[0];
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++) {
      const fx = Math.min(w - 1, Math.max(0, x + s0.x));
      const fy = Math.min(h - 1, Math.max(0, y + s0.y));
      main[y * w + x] = Math.min(main[y * w + x], white.main[fy * w + fx]);
    }
  return autoDots({ width: w, height: h, main, start: new Uint8Array(w * h), white: new Uint8Array(w * h) }, n);
}

/**
 * Reads a scan: each dot gets its LED number, or null when its colors do not add up. Each dot is
 * read against itself: its darkest in each color (the room) and its white (how bright each color
 * comes out). A dot whose check digit fails gets one more try, with its least sure digit as its
 * second choice. Then the string itself checks the numbers: LEDs that follow on are never
 * farther apart than the wire between them, so of two dots with one number the one next to its
 * neighbors keeps it, a dot far from both neighbors loses its number, and a dot without one may
 * take a number its colors nearly said that has a neighbor next to it.
 */
export function decodeScan(s: ScanFrames, dots: Pt[], n: number): (number | null)[] {
  const F = s.frames.length;
  const gap = typicalGap(dots) || 10;
  const sums = dots.map((p) => {
    let near = Infinity;
    for (const q of dots) if (q !== p) near = Math.min(near, dist(p, q));
    const rr = Math.max(1.5, Math.min(gap * 0.6, near * 0.42));
    const r = Math.ceil(rr);
    const cx = Math.round(p.x);
    const cy = Math.round(p.y);
    return Array.from({ length: F }, (_, f) => {
      const out = [0, 0, 0];
      for (let y = cy - r; y <= cy + r; y++)
        for (let x = cx - r; x <= cx + r; x++) {
          const d = Math.hypot(x - cx, y - cy);
          if (d > rr) continue;
          // Nearer the middle counts more: the edge may catch a neighbor's glow.
          const wt = 1 - d / (rr + 1);
          for (let c = 0; c < 3; c++) out[c] += at(s, f, x, y, c) * wt;
        }
      return out;
    });
  });
  // Each dot's white over its darkest, per color; a dot too faint in one takes the usual.
  const spans = sums.map((fs) => [0, 1, 2].map((c) => fs[0][c] - Math.min(...fs.slice(1).map((v) => v[c]))));
  const usual = [0, 1, 2].map((c) => {
    const v = spans.map((x) => x[c]).sort((a, b) => a - b);
    return Math.max(1, v[Math.floor(v.length / 2)] ?? 1);
  });
  const reads = sums.map((fs, k) => {
    const lo = [0, 1, 2].map((c) => Math.min(...fs.slice(1).map((v) => v[c])));
    const span = spans[k].map((x, c) => (x > usual[c] * 0.15 ? x : usual[c]));
    return fs.slice(1).map((v, j) => {
      const score = v.map((x, c) => (x - lo[c]) / span[c]);
      const order = [0, 1, 2].sort((a, b) => score[b] - score[a]);
      // Back from the frame's color to the digit (the colors turn by one each frame).
      const digit = (c: number) => (c - j + 300) % 3;
      return { best: digit(order[0]), second: digit(order[1]), margin: score[order[0]] - score[order[1]] };
    });
  });
  let ids = reads.map((r) => decodeDigits(r.map((x) => x.best), n));
  const count = (list: (number | null)[]) => {
    const m = new Map<number, number>();
    for (const id of list) if (id != null) m.set(id, (m.get(id) ?? 0) + 1);
    return m;
  };
  const sure = count(ids);
  // One more try for a dot that does not add up: its least sure digit, the other way.
  ids = ids.map((id, k) => {
    if (id != null) return id;
    const r = reads[k];
    let weak = 0;
    r.forEach((x, j) => x.margin < r[weak].margin && (weak = j));
    const fixed = decodeDigits(r.map((x, j) => (j === weak ? x.second : x.best)), n);
    return fixed != null && !sure.has(fixed) ? fixed : null;
  });
  const many = count(ids);
  const unique = ids.map((id) => (id != null && many.get(id) === 1 ? id : null));

  // LEDs next to each other on the string are never farther apart than the wire between them.
  const limit = numberedStep(dots, unique) * 1.35;
  if (!(limit > 0)) return unique;
  const where = new Map<number, number>();
  unique.forEach((id, k) => id != null && where.set(id, k));
  const neighbors = (k: number, id: number) => [id - 1, id + 1].map((j) => where.get(j)).filter((j): j is number => j != null && j !== k);
  const fits = (k: number, id: number) => neighbors(k, id).some((j) => dist(dots[j], dots[k]) <= limit);
  const lonely = (k: number, id: number) => {
    const near = neighbors(k, id);
    return near.length > 0 && near.every((j) => dist(dots[j], dots[k]) > limit * 1.5);
  };
  // Two dots with one number: the one next to its neighbors keeps it.
  const out = [...unique];
  for (const [id, times] of many) {
    if (times < 2) continue;
    const claim = ids.map((x, k) => (x === id ? k : -1)).filter((k) => k >= 0);
    const good = claim.filter((k) => fits(k, id));
    if (good.length === 1) {
      out[good[0]] = id;
      where.set(id, good[0]);
    }
  }
  // A dot far from both of its neighbors (when they were read) was misread.
  out.forEach((id, k) => {
    if (id == null || !lonely(k, id)) return;
    where.delete(id);
    out[k] = null;
  });
  // A dot without a number gets one its colors allow (one or two of its least sure digits the
  // other way) that has a neighbor close by, or none.
  out.forEach((id, k) => {
    if (id != null) return;
    const r = reads[k];
    const weak = r.map((x, j) => [x.margin, j] as const).sort((a, b) => a[0] - b[0]).map(([, j]) => j);
    const tries = [[weak[0]], [weak[1]], [weak[0], weak[1]], [weak[2]]].filter((t) => t.every((j) => j != null));
    for (const t of tries) {
      const alt = decodeDigits(r.map((x, j) => (t.includes(j) ? x.second : x.best)), n);
      if (alt != null && !where.has(alt) && fits(k, alt)) {
        out[k] = alt;
        where.set(alt, k);
        return;
      }
    }
  });
  return out;
}

/** The dots in LED order, as strokes of dot indexes: a new stroke where the wire jumps. */
export function orderByNumber(dots: Pt[], ids: (number | null)[]): number[][] {
  const known = ids.map((id, k) => ({ id, k })).filter((x): x is { id: number; k: number } => x.id != null).sort((a, b) => a.id - b.id);
  if (!known.length) return [];
  // The most one LED can be from the next: the string's spacing (see numberedStep).
  const step = numberedStep(dots, ids);
  const out: number[][] = [[known[0].k]];
  for (let j = 1; j < known.length; j++) {
    const a = known[j - 1];
    const b = known[j];
    // Farther than the wire between them reaches: a longer wire (between strands, say) or a jump.
    if (step && dist(dots[a.k], dots[b.k]) > step * (b.id - a.id) * 1.5 + step * 0.5) out.push([]);
    out.at(-1)!.push(b.k);
  }
  return out;
}
