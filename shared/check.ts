// Checks for the layout editor: test pictures that show, on the real lights, whether the
// drawing matches the yard. The editor's simulator paints the same picture at the same moment
// (both follow the wall clock), so you compare the house with the screen:
//   - a slice: a thin plane of white light across the whole yard, along one axis, that you move
//     (or that sweeps by itself). Where the drawing puts an LED in the plane, the real LED lights
//     white: on the house, the white should line up (straight across, or level) on every object.
//   - a ruler: the yard in bands of color, a band every so many feet or meters along one axis.
//     Every real object should sit in the same bands as in the drawing.
//   - a color test of one object: its LEDs colored by where the drawing puts them, in two
//     halves (left and right, top and bottom, or the street side and the house side), or in up
//     to eight blocks, all three at once. On the house, the object shows the same clean halves
//     or blocks (from the street, and from above) when its shape and wiring are right, and
//     swapped or scrambled colors when they are not.
//   - a chase: one light runs along the object's wire from LED 0, so you can follow where the
//     real string starts and which way it goes.
//   - strings: each string (strand) of one object, or of every object, in a color of its own,
//     its first LED blinking white and its last LED white, so you see where each one starts and
//     ends on the house.

import { mix8, scale8, type Rgb8 } from './color.ts';
import { lightsOf, stringRanges } from './lights.ts';
import { DEFAULT_SCALE, fixturePixels, isLine, layoutGround, wavePasses, type Fixture, type Layout, type Stage } from './layout.ts';

/** x: across (left to right), y: height, z: depth (from the house toward the street). */
export type CheckAxis = 'x' | 'y' | 'z';

export type LayoutCheck =
  /** A slice across the yard. `at`: where, in layout units along the axis (y down from the top, as in Point); null: it sweeps. */
  | { kind: 'slice'; axis: CheckAxis; at: number | null }
  /** Bands of color along the axis, `step` layout units wide, from the left edge, the ground or the front wall. */
  | { kind: 'bands'; axis: CheckAxis; step: number }
  /** The color test of one object, in two halves along one axis, or (all, or none given) in up to eight blocks. */
  | { kind: 'picture'; id: string; split?: PictureSplit }
  /** A light running along one object's wire. */
  | { kind: 'chase'; id: string }
  /** The strings of one object, or of every object (id null), each in a color of its own. */
  | { kind: 'strings'; id: string | null };

/** How the color test cuts an object: in two halves along one axis, or along all three at once. */
export type PictureSplit = CheckAxis | 'all';

/** Half the thickness of the slice, in meters. */
export const SLICE_HALF_M = 0.15;
/** How fast the slice sweeps, in meters a second. */
const SWEEP_MPS = 1.5;
/** The slice never takes less than this to cross the yard (ms). */
const SWEEP_MIN_MS = 4000;
export const SLICE_RGB: Rgb8 = [255, 255, 255];
/** LEDs on the low side of the slice (left of it, above it, behind it) and on the high side. */
export const SLICE_LOW_RGB: Rgb8 = [0, 45, 110];
export const SLICE_HIGH_RGB: Rgb8 = [110, 40, 0];
/** The ruler's bands, in turn. */
export const BAND_RGB: Rgb8[] = [
  [220, 0, 0],
  [0, 190, 0],
  [0, 70, 255],
  [230, 160, 0]
];
/** The color test's four blocks on one side, as seen from the street. */
export interface PictureSide {
  topLeft: Rgb8;
  topRight: Rgb8;
  bottomLeft: Rgb8;
  bottomRight: Rgb8;
}
/**
 * The color test's eight blocks: the half toward the street (front) and the half toward the
 * house (back), each in four as seen from the street. An object with no depth to speak of is
 * all front.
 */
export const PICTURE_RGB: { front: PictureSide; back: PictureSide } = {
  front: { topLeft: [255, 0, 0], topRight: [0, 70, 255], bottomLeft: [255, 170, 0], bottomRight: [0, 210, 0] },
  back: { topLeft: [255, 0, 170], topRight: [0, 210, 210], bottomLeft: [255, 255, 255], bottomRight: [255, 70, 0] }
};
/**
 * The color test's two halves: the left, the top or the street side in the first color, the
 * right, the bottom or the house side in the second.
 */
export const HALF_RGB: [Rgb8, Rgb8] = [
  [255, 0, 0],
  [0, 70, 255]
];
/** The two halves of each axis, in words, in the order of HALF_RGB. */
export const HALF_NAMES: Record<CheckAxis, [string, string]> = { x: ['left', 'right'], y: ['top', 'bottom'], z: ['front (street side)', 'back (house side)'] };
/** The strings' colors, in turn along the wire (and from one object to the next). */
export const STRING_RGB: Rgb8[] = [
  [255, 0, 0],
  [0, 200, 0],
  [0, 70, 255],
  [255, 170, 0],
  [190, 0, 255],
  [0, 210, 210]
];
const CHASE_BASE: Rgb8 = [0, 10, 26];
const CHASE_TAIL: Rgb8 = [0, 160, 255];

/** True for checks that move by themselves, so their picture changes on every frame. */
export const checkMoves = (c: LayoutCheck | null | undefined) => !!c && ((c.kind === 'slice' && c.at == null) || c.kind === 'chase');

const AXIS_INDEX: Record<CheckAxis, number> = { x: 0, y: 1, z: 2 };

/** The lowest and highest coordinate of the yard's LEDs in use along the axis. */
export function axisRange(stage: Pick<Stage, 'positions3' | 'active' | 'pixelCount'>, axis: CheckAxis): [number, number] {
  const a = AXIS_INDEX[axis];
  let lo = Infinity;
  let hi = -Infinity;
  for (let i = 0; i < stage.pixelCount; i++) {
    if (!stage.active[i]) continue;
    const v = stage.positions3[i * 3 + a];
    if (v < lo) lo = v;
    if (v > hi) hi = v;
  }
  return lo <= hi ? [lo, hi] : [0, 0];
}

/** Where the slice is at `nowMs`: where it was put, or, sweeping, back and forth across the yard's LEDs. */
export function slicePosition(stage: Pick<Stage, 'positions3' | 'active' | 'pixelCount' | 'scale'>, check: { axis: CheckAxis; at: number | null }, nowMs: number): number {
  if (check.at != null) return check.at;
  const scale = stage.scale || 1;
  const [a, b] = axisRange(stage, check.axis);
  const lo = a - scale * 0.5;
  const span = b + scale * 0.5 - lo;
  const pass = Math.max(SWEEP_MIN_MS, (span / (SWEEP_MPS * scale)) * 1000);
  const t = (((nowMs % (2 * pass)) + 2 * pass) % (2 * pass)) / pass;
  return lo + span * (t < 1 ? t : 2 - t);
}

/** Where the ruler's bands start along the axis: the left edge, the ground, the front wall. */
export const bandOrigin = (layout: Pick<Layout, 'groundY' | 'height'>, axis: CheckAxis) => (axis === 'y' ? layoutGround(layout) : 0);

/** The band (0, 1, 2…, or below the origin -1, -2…) of a coordinate along the axis. Heights count up from the ground. */
export function bandOf(layout: Pick<Layout, 'groundY' | 'height'>, axis: CheckAxis, step: number, v: number): number {
  const d = axis === 'y' ? bandOrigin(layout, axis) - v : v - bandOrigin(layout, axis);
  return Math.floor(d / Math.max(1e-6, step));
}


/**
 * Paints the check into `out` (RGB bytes, one triple per stage LED). `nowMs`: the wall clock
 * when the frame shows, so the simulator and the house move together. LEDs in skipped segments
 * stay dark, and an object check leaves the other objects dark.
 */
export function paintCheck(layout: Layout, stage: Stage, check: LayoutCheck, nowMs: number, pulse: boolean, out: Uint8Array) {
  out.fill(0);
  const P = stage.positions3;
  const n = stage.pixelCount;
  if (check.kind === 'slice') {
    const a = AXIS_INDEX[check.axis];
    const at = slicePosition(stage, check, nowMs);
    const half = SLICE_HALF_M * (stage.scale || 1);
    for (let i = 0; i < n; i++) {
      if (!stage.active[i]) continue;
      const d = P[i * 3 + a] - at;
      const side = d < 0 ? SLICE_LOW_RGB : SLICE_HIGH_RGB;
      const ad = Math.abs(d);
      // In the slice: white. Just beside it: a glow that fades into the side's color.
      const c = ad <= half ? SLICE_RGB : ad <= half * 3 ? mix8(scale8(SLICE_RGB, 0.35), side, (ad - half) / (half * 2)) : side;
      out.set(c, i * 3);
    }
    return;
  }
  if (check.kind === 'bands') {
    const a = AXIS_INDEX[check.axis];
    for (let i = 0; i < n; i++) {
      if (!stage.active[i]) continue;
      const b = bandOf(layout, check.axis, check.step, P[i * 3 + a]);
      out.set(BAND_RGB[((b % BAND_RGB.length) + BAND_RGB.length) % BAND_RGB.length], i * 3);
    }
    return;
  }
  if (check.kind === 'strings') {
    let color = 0;
    for (const f of layout.fixtures) {
      if (check.id != null && f.id !== check.id) continue;
      const sf = stage.fixtures.find((x) => x.id === f.id);
      if (!sf?.count) continue;
      for (const r of stringRanges(sf.count, lightsOf(layout, f.lights)?.perStrand ?? null, f.stringBreaks)) {
        const c = STRING_RGB[color++ % STRING_RGB.length];
        // Strings run in the order of the device's LEDs: from the object's last point when it counts down.
        for (let d = r.lo; d <= r.hi; d++) {
          const i = sf.offset + (f.reversed ? sf.count - 1 - d : d);
          if (!stage.active[i]) continue;
          out.set(d === r.lo ? (pulse ? SLICE_RGB : [0, 0, 0]) : d === r.hi ? SLICE_RGB : c, i * 3);
        }
      }
    }
    return;
  }
  const fi = layout.fixtures.findIndex((f) => f.id === check.id);
  const sf = stage.fixtures.find((f) => f.id === check.id);
  if (fi < 0 || !sf || !sf.count) return;
  const on = (j: number) => !!stage.active[sf.offset + j];
  if (check.kind === 'chase') {
    const count = sf.count;
    const speed = Math.max(15, count / 12);
    const tail = Math.max(4, Math.round(count / 10));
    const head = Math.floor(((nowMs / 1000) * speed) % (count + tail));
    for (let j = 0; j < count; j++) {
      if (!on(j)) continue;
      const d = head - j;
      out.set(d === 0 ? SLICE_RGB : d > 0 && d <= tail ? scale8(CHASE_TAIL, 1 - (d - 1) / tail) : CHASE_BASE, (sf.offset + j) * 3);
    }
    return;
  }
  const split = pictureSplit(stage, sf.offset, sf.count);
  const cut = pictureCut(split, check.split);
  for (let j = 0; j < sf.count; j++) {
    if (!on(j)) continue;
    const i = sf.offset + j;
    out.set(pictureColor(split, cut, P[i * 3], P[i * 3 + 1], P[i * 3 + 2]), i * 3);
  }
  // Where the wire starts: blinking white.
  if (on(0)) out.set(pulse ? SLICE_RGB : scale8(SLICE_RGB, 0.15), sf.offset * 3);
}

/**
 * How the color test cuts an object in blocks: at its middle, across, up and in depth, along
 * each way it is big enough for that (a quarter of its biggest size).
 */
interface Split {
  cx: number;
  cy: number;
  cz: number;
  across: boolean;
  up: boolean;
  deep: boolean;
}

function pictureSplit(stage: Stage, offset: number, count: number): Split {
  const lo = [Infinity, Infinity, Infinity];
  const hi = [-Infinity, -Infinity, -Infinity];
  for (let i = offset; i < offset + count; i++) {
    for (let a = 0; a < 3; a++) {
      const v = stage.positions3[i * 3 + a];
      lo[a] = Math.min(lo[a], v);
      hi[a] = Math.max(hi[a], v);
    }
  }
  const size = hi.map((h, a) => h - lo[a]);
  const big = Math.max(...size);
  // A long low line is cut only across; a tall thin one only up; a flat one not in depth.
  const cut = (a: number) => big > 0 && size[a] >= big * 0.25;
  return { cx: (lo[0] + hi[0]) / 2, cy: (lo[1] + hi[1]) / 2, cz: (lo[2] + hi[2]) / 2, across: cut(0), up: cut(1), deep: cut(2) };
}

const SPLIT_FLAG: Record<CheckAxis, 'across' | 'up' | 'deep'> = { x: 'across', y: 'up', z: 'deep' };

/**
 * The cut the color test of an object makes: the one asked for, or, when the object is too thin
 * along that axis to have two halves there, the first it has (top and bottom, then left and
 * right, then front and back). All: every way it can be cut.
 */
export function pictureCut(blocks: { across: boolean; up: boolean; deep: boolean }, split: PictureSplit | undefined): PictureSplit {
  if (split == null || split === 'all') return 'all';
  if (blocks[SPLIT_FLAG[split]]) return split;
  return (['y', 'x', 'z'] as const).find((a) => blocks[SPLIT_FLAG[a]]) ?? split;
}

function pictureColor(s: Split, cut: PictureSplit, x: number, y: number, z: number): Rgb8 {
  // One half (pictureCut picks one the object has; with none it is all the first half).
  if (cut === 'x') return HALF_RGB[s.across && x > s.cx ? 1 : 0];
  if (cut === 'y') return HALF_RGB[s.up && y > s.cy ? 1 : 0];
  if (cut === 'z') return HALF_RGB[s.deep && z < s.cz ? 1 : 0];
  const side = s.deep && z < s.cz ? PICTURE_RGB.back : PICTURE_RGB.front;
  const right = s.across && x > s.cx;
  const bottom = s.up && y > s.cy;
  return bottom ? (right ? side.bottomRight : side.bottomLeft) : right ? side.topRight : side.topLeft;
}

/** Which blocks the color test of this object shows (see pictureSplit). */
export function pictureBlocks(stage: Stage, id: string): { across: boolean; up: boolean; deep: boolean } | null {
  const sf = stage.fixtures.find((f) => f.id === id);
  if (!sf?.count) return null;
  const { across, up, deep } = pictureSplit(stage, sf.offset, sf.count);
  return { across, up, deep };
}

// ---------- The ways an object's string can run ----------

/** One way the real string of an object might run: a name, and the settings that draw it so. */
export interface WiringGuess {
  label: string;
  patch: Partial<Fixture>;
}

const ENDS = [
  { reversed: false, text: '' },
  { reversed: true, text: ' · other end' }
];

/**
 * Where the object's LEDs are, in the order of the device's LED numbers: two settings that
 * give the same key light the house the same way (a zigzag with an even number of rows run
 * from the other end is the zigzag the other way up).
 */
function wireKey(f: Fixture, scale: number): string {
  const pts = fixturePixels(f, scale);
  if (f.reversed) pts.reverse();
  return pts.map((p) => `${Math.round(p.x)},${Math.round(p.y)},${Math.round(p.z)}`).join(';');
}

/**
 * The ways the real string of this object can run, for its kind: which end it starts at, which
 * way it winds or zigzags. Ways that light the house the same are listed once. The editor steps
 * through them while the color test or the chase shows on the house, until the house matches
 * the drawing.
 */
export function wiringGuesses(f: Fixture, scale = DEFAULT_SCALE): WiringGuess[] {
  const seen = new Set<string>();
  return guessesFor(f).filter((g) => {
    const key = wireKey({ ...f, ...g.patch }, scale);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function guessesFor(f: Fixture): WiringGuess[] {
  if (isLine(f)) {
    return [
      { label: 'LED 0 at the first point', patch: { reversed: false } },
      { label: 'LED 0 at the last point', patch: { reversed: true } }
    ];
  }
  if (f.kind === 'tree' && f.pattern === 'strands') {
    return ENDS.flatMap((e) => [
      { label: `Round counterclockwise${e.text}`, patch: { spin: undefined, reversed: e.reversed } },
      { label: `Round clockwise${e.text}`, patch: { spin: 'cw' as const, reversed: e.reversed } }
    ]);
  }
  if (f.kind === 'tree' && f.pattern === 'wave') {
    // The same passes: the end side flips with the start side.
    const { startSide, endSide } = wavePasses(f);
    const flip = (x: 'left' | 'right') => (x === 'left' ? 'right' : 'left');
    return (['base', 'top'] as const).flatMap((start) =>
      [false, true].map((other) => {
        const from = other ? flip(startSide) : startSide;
        return {
          label: `${start === 'base' ? 'Base up' : 'Top down'}, from the ${from}`,
          patch: { start: start === 'base' ? undefined : start, startSide: from === 'left' ? undefined : from, endSide: other ? flip(endSide) : endSide }
        };
      })
    );
  }
  if (f.kind === 'tree') {
    return [
      { label: 'Base up, counterclockwise', patch: { start: undefined, spin: undefined } },
      { label: 'Base up, clockwise', patch: { start: undefined, spin: 'cw' } },
      { label: 'Top down, counterclockwise', patch: { start: 'top', spin: undefined } },
      { label: 'Top down, clockwise', patch: { start: 'top', spin: 'cw' } }
    ];
  }
  if (f.kind === 'semicircle') {
    const ways = [
      ['down', 'Rows, from the top'],
      ['up', 'Rows, from the bottom'],
      ['right', 'Columns, from the left'],
      ['left', 'Columns, from the right']
    ] as const;
    return ENDS.flatMap((e) => ways.map(([zigzag, text]) => ({ label: `${text}${e.text}`, patch: { zigzag: zigzag === 'down' ? undefined : zigzag, reversed: e.reversed } })));
  }
  if (f.kind === 'bush') {
    const ways = [
      ['fill', 'A net over the bush'],
      ['ring', 'A ring around the edge'],
      ['spiral', 'A spiral from the middle']
    ] as const;
    return ENDS.flatMap((e) => ways.map(([pattern, text]) => ({ label: `${text}${e.text}`, patch: { pattern, reversed: e.reversed } })));
  }
  return [
    { label: 'LED 0 where the design starts', patch: { reversed: false } },
    { label: 'LED 0 where the design ends', patch: { reversed: true } }
  ];
}

/** The guess that lights the house as the object does now, or -1 (set some other way). */
export function currentGuess(f: Fixture, guesses: WiringGuess[], scale = DEFAULT_SCALE): number {
  const key = wireKey(f, scale);
  return guesses.findIndex((g) => wireKey({ ...f, ...g.patch }, scale) === key);
}

/** The check, if it can be shown on this layout (an object check needs its object). */
export const validCheck = (c: LayoutCheck | null | undefined, layout: Layout): LayoutCheck | null =>
  !c ? null : c.kind === 'slice' || c.kind === 'bands' || (c.kind === 'strings' && c.id == null) || layout.fixtures.some((f) => f.id === c.id) ? c : null;
