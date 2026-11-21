// Checks for the layout editor: test pictures that show, on the real lights, whether the
// drawing matches the yard. The editor's simulator paints the same picture at the same moment
// (both follow the wall clock), so you compare the house with the screen:
//   - a slice: a thin plane of white light across the whole yard, along one axis, that you move
//     (or that sweeps by itself). Where the drawing puts an LED in the plane, the real LED lights
//     white: on the house, the white should line up (straight across, or level) on every object.
//   - a ruler: the yard in bands of color, a band every so many feet or meters along one axis.
//     Every real object should sit in the same bands as in the drawing.
//   - a color test of one object: its LEDs colored by where the drawing puts them (four blocks:
//     top left, top right, bottom left, bottom right). On the house, the object shows the same
//     four clean blocks when its shape and wiring are right, and swapped or scrambled colors
//     when they are not.
//   - a chase: one light runs along the object's wire from LED 0, so you can follow where the
//     real string starts and which way it goes.

import { DEFAULT_SCALE, fixturePixels, isLine, layoutGround, wavePasses, type Fixture, type Layout, type Stage } from './layout.ts';

/** x: across (left to right), y: height, z: depth (from the house toward the street). */
export type CheckAxis = 'x' | 'y' | 'z';

export type LayoutCheck =
  /** A slice across the yard. `at`: where, in layout units along the axis (y down from the top, as in Point); null: it sweeps. */
  | { kind: 'slice'; axis: CheckAxis; at: number | null }
  /** Bands of color along the axis, `step` layout units wide, from the left edge, the ground or the front wall. */
  | { kind: 'bands'; axis: CheckAxis; step: number }
  /** The color test of one object. */
  | { kind: 'picture'; id: string }
  /** A light running along one object's wire. */
  | { kind: 'chase'; id: string };

type RGB = [number, number, number];

/** Half the thickness of the slice, in meters. */
export const SLICE_HALF_M = 0.15;
/** How fast the slice sweeps, in meters a second. */
const SWEEP_MPS = 1.5;
/** The slice never takes less than this to cross the yard (ms). */
const SWEEP_MIN_MS = 4000;
export const SLICE_RGB: RGB = [255, 255, 255];
/** LEDs on the low side of the slice (left of it, above it, behind it) and on the high side. */
export const SLICE_LOW_RGB: RGB = [0, 45, 110];
export const SLICE_HIGH_RGB: RGB = [110, 40, 0];
/** The ruler's bands, in turn. */
export const BAND_RGB: RGB[] = [
  [220, 0, 0],
  [0, 190, 0],
  [0, 70, 255],
  [230, 160, 0]
];
/** The color test's four blocks, as seen from the street. */
export const PICTURE_RGB = { topLeft: [255, 0, 0] as RGB, topRight: [0, 70, 255] as RGB, bottomLeft: [255, 170, 0] as RGB, bottomRight: [0, 210, 0] as RGB };
const CHASE_BASE: RGB = [0, 10, 26];
const CHASE_TAIL: RGB = [0, 160, 255];

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

const mix = (a: RGB, b: RGB, t: number): RGB => [Math.round(a[0] + (b[0] - a[0]) * t), Math.round(a[1] + (b[1] - a[1]) * t), Math.round(a[2] + (b[2] - a[2]) * t)];
const times = (c: RGB, k: number): RGB => [Math.round(c[0] * k), Math.round(c[1] * k), Math.round(c[2] * k)];

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
      const c = ad <= half ? SLICE_RGB : ad <= half * 3 ? mix(times(SLICE_RGB, 0.35), side, (ad - half) / (half * 2)) : side;
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
      out.set(d === 0 ? SLICE_RGB : d > 0 && d <= tail ? times(CHASE_TAIL, 1 - (d - 1) / tail) : CHASE_BASE, (sf.offset + j) * 3);
    }
    return;
  }
  const split = pictureSplit(stage, sf.offset, sf.count);
  for (let j = 0; j < sf.count; j++) {
    if (!on(j)) continue;
    const i = sf.offset + j;
    out.set(pictureColor(split, P[i * 3], P[i * 3 + 1]), i * 3);
  }
  // Where the wire starts: blinking white.
  if (on(0)) out.set(pulse ? SLICE_RGB : times(SLICE_RGB, 0.15), sf.offset * 3);
}

/** How the color test cuts an object in blocks: at its middle, across and up, when it is wide (or tall) enough for that. */
interface Split {
  cx: number;
  cy: number;
  across: boolean;
  up: boolean;
}

function pictureSplit(stage: Stage, offset: number, count: number): Split {
  let x0 = Infinity;
  let x1 = -Infinity;
  let y0 = Infinity;
  let y1 = -Infinity;
  for (let i = offset; i < offset + count; i++) {
    const x = stage.positions3[i * 3];
    const y = stage.positions3[i * 3 + 1];
    x0 = Math.min(x0, x);
    x1 = Math.max(x1, x);
    y0 = Math.min(y0, y);
    y1 = Math.max(y1, y);
  }
  const w = x1 - x0;
  const h = y1 - y0;
  const big = Math.max(w, h);
  // A long low line is cut only across; a tall thin one only up.
  return { cx: (x0 + x1) / 2, cy: (y0 + y1) / 2, across: w >= big * 0.25, up: h >= big * 0.25 };
}

function pictureColor(s: Split, x: number, y: number): RGB {
  const right = s.across && x > s.cx;
  const bottom = s.up && y > s.cy;
  return bottom ? (right ? PICTURE_RGB.bottomRight : PICTURE_RGB.bottomLeft) : right ? PICTURE_RGB.topRight : PICTURE_RGB.topLeft;
}

/** Which blocks the color test of this object shows (see pictureSplit). */
export function pictureBlocks(stage: Stage, id: string): { across: boolean; up: boolean } | null {
  const sf = stage.fixtures.find((f) => f.id === id);
  if (!sf?.count) return null;
  const { across, up } = pictureSplit(stage, sf.offset, sf.count);
  return { across, up };
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
  !c ? null : c.kind === 'slice' || c.kind === 'bands' || layout.fixtures.some((f) => f.id === c.id) ? c : null;
