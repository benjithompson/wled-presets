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

/** The usual distance from one LED to the next along the traced wire, in photo pixels (0: none). */
export function ledStep(strokes: PhotoStroke[]): number {
  const steps: number[] = [];
  for (const s of strokes) {
    if (!s.dots) continue;
    for (let i = 1; i < s.points.length; i++) steps.push(dist(s.points[i - 1], s.points[i]));
  }
  steps.sort((a, b) => a - b);
  return steps.length ? steps[Math.floor(steps.length / 2)] : 0;
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
  return live.map((s) => {
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
// For an exact order, the LEDs blink their own numbers: in each of a few frames every LED is
// red, green or blue, one base-3 digit of its number (the LED's place from the start of the
// wire), and a last frame holds a check digit. A camera that watches the frames reads each dot's
// colors and so its number: no guessing at the order, even where the wire crosses itself. Every
// LED is lit in every frame, so the camera's exposure stays steady and every frame shows every
// dot (a shaky hand is followed from frame to frame).

/** The three colors of the code, a little dimmed so the middle of an LED is not all white. */
export const CODE_RGB: RGB[] = [
  [150, 0, 0],
  [0, 120, 0],
  [0, 0, 170]
];

/** How many digits the numbers of n LEDs need. */
export const codeDigits = (n: number) => Math.max(1, Math.ceil(Math.log(Math.max(2, n)) / Math.log(3) - 1e-9));

/** How many frames a scan of n LEDs takes: its digits and the check digit. */
export const codeFrames = (n: number) => codeDigits(n) + 1;

/** The color (0 red, 1 green, 2 blue) of LED i (counted from the start of the wire) in a frame of a scan of n LEDs. */
export function codeDigit(i: number, frame: number, n: number): number {
  const d = codeDigits(n);
  if (frame < d) return Math.floor(i / 3 ** frame) % 3;
  // The check digit: the digits' sum, so one misread digit shows.
  let sum = 0;
  for (let k = 0; k < d; k++) sum += Math.floor(i / 3 ** k) % 3;
  return sum % 3;
}

/** The LED number from the colors read in each frame, or null when they do not add up. */
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

/** How far the dots in a frame moved from where they were (a hand holding the phone moves a little). */
export function frameShift(ref: Pt[], seen: Pt[], gap: number): Pt {
  let shift = { x: 0, y: 0 };
  if (!ref.length || !seen.length) return shift;
  for (let round = 0, reach = gap * 3; round < 4; round++, reach = gap * 0.5) {
    const dx: number[] = [];
    const dy: number[] = [];
    for (const p of ref) {
      let best: Pt | null = null;
      let bd = reach;
      for (const q of seen) {
        const d = Math.hypot(q.x - p.x - shift.x, q.y - p.y - shift.y);
        if (d < bd) {
          bd = d;
          best = q;
        }
      }
      if (best) {
        dx.push(best.x - p.x);
        dy.push(best.y - p.y);
      }
    }
    if (!dx.length) return shift;
    const mid = (v: number[]) => v.sort((a, b) => a - b)[Math.floor(v.length / 2)];
    shift = { x: mid(dx), y: mid(dy) };
  }
  return shift;
}

/**
 * How much red, green and blue each dot shows in a frame, around its middle (which is often
 * white). Nearer the middle counts more: the edge may catch a neighbor's glow.
 */
export function colorSums(img: Pixels, dots: Pt[], shift: Pt, radius: number | number[]): number[][] {
  const { width: w, height: h, data } = img;
  return dots.map((p, k) => {
    const s = [0, 0, 0];
    const rr = Math.max(1, typeof radius === 'number' ? radius : radius[k]);
    const r = Math.ceil(rr);
    const cx = Math.round(p.x + shift.x);
    const cy = Math.round(p.y + shift.y);
    for (let y = Math.max(0, cy - r); y <= Math.min(h - 1, cy + r); y++)
      for (let x = Math.max(0, cx - r); x <= Math.min(w - 1, cx + r); x++) {
        const d = Math.hypot(x - cx, y - cy);
        if (d > rr) continue;
        const i = (y * w + x) * 4;
        const lo = Math.min(data[i], data[i + 1], data[i + 2]);
        if (lo >= 225) continue;
        const wt = 1 - d / (rr + 1);
        for (let c = 0; c < 3; c++) s[c] += Math.max(0, data[i + c] - lo) * wt;
      }
    return s;
  });
}

/**
 * How bright each color comes out (cameras see green brighter, for one): its high end over all
 * the readings. Taken over the whole scan, since a frame may not show every color (the top
 * digit of a few LEDs is never 2).
 */
export function colorGains(sums: number[][]): number[] {
  return [0, 1, 2].map((c) => {
    const v = sums.map((s) => s[c]).sort((a, b) => a - b);
    return Math.max(1, v[Math.floor(v.length * 0.85)] ?? 1);
  });
}

/** The color of each reading: 0 red, 1 green, 2 blue. */
export const pickColors = (sums: number[][], gains: number[]) =>
  sums.map((s) => {
    const v = s.map((x, c) => x / gains[c]);
    return v.indexOf(Math.max(...v));
  });

/**
 * Reads a scan: the frames in order (see codeDigit), the dots found in the first one. Each dot
 * gets its LED number, or null when its colors do not add up. Two dots with the same number
 * both get null (one of them was misread).
 */
export function decodeScan(frames: Pixels[], dots: Pt[], n: number, threshold: number): (number | null)[] {
  const gap = typicalGap(dots) || 10;
  // Each dot is read within less than half the way to its nearest neighbor.
  const radius = dots.map((p) => {
    let near = Infinity;
    for (const q of dots) if (q !== p) near = Math.min(near, dist(p, q));
    return Math.max(1.5, Math.min(gap * 0.6, near * 0.42));
  });
  const sums = frames.map((img, f) => {
    const shift = f === 0 ? { x: 0, y: 0 } : frameShift(dots, findDots(colorfulMaps(img), threshold), gap);
    return colorSums(img, dots, shift, radius);
  });
  const gains = colorGains(sums.flat());
  const colors = sums.map((s) => pickColors(s, gains));
  const digits = dots.map((_, k) => colors.map((c) => c[k]));
  const ids = digits.map((d) => decodeDigits(d, n));
  const count = new Map<number, number>();
  for (const id of ids) if (id != null) count.set(id, (count.get(id) ?? 0) + 1);
  return ids.map((id) => (id != null && count.get(id) === 1 ? id : null));
}

/** The dots in LED order, as strokes of dot indexes: a new stroke where the wire jumps. */
export function orderByNumber(dots: Pt[], ids: (number | null)[]): number[][] {
  const known = ids.map((id, k) => ({ id, k })).filter((x): x is { id: number; k: number } => x.id != null).sort((a, b) => a.id - b.id);
  if (!known.length) return [];
  // The usual distance from one LED to the next, per LED number (some may be missing).
  const steps: number[] = [];
  for (let j = 1; j < known.length; j++) steps.push(dist(dots[known[j].k], dots[known[j - 1].k]) / (known[j].id - known[j - 1].id));
  steps.sort((a, b) => a - b);
  const step = steps[Math.floor(steps.length / 2)] ?? 0;
  const out: number[][] = [[known[0].k]];
  for (let j = 1; j < known.length; j++) {
    const a = known[j - 1];
    const b = known[j];
    if (step && dist(dots[a.k], dots[b.k]) > step * (b.id - a.id) * 2.2 + step) out.push([]);
    out.at(-1)!.push(b.k);
  }
  return out;
}
