// The yard's scale (layout units per meter) from its roofline. The roof is traced over the
// picture of the house, and its LEDs sit a known distance apart on their strings: from one
// corner's LED to the next is so many LEDs (where the corners are pinned, or spread evenly), so
// that stretch of roofline is that much string long. The roofline as drawn, over the length of
// string along it, is the scale: everything else (the top view, the picture from above, real
// distances) follows from it.
//
// Objects keep the size they are drawn at when the scale changes: they were placed over the
// pictures already. What the strings work out (a tree's turns, see stringFit) is worked out
// again.

import { layoutScale, lineLengths, pointOffsets, type Fixture, type Layout } from './layout.ts';
import { lightsOf } from './lights.ts';

type Lit = Pick<Layout, 'lightTypes'>;

/** One roof's part of the scale: its lit roofline as drawn (layout units) and the string along it (meters). */
export interface RoofRun {
  drawn: number;
  meters: number;
  /** LEDs from the first lit corner's LED to the last, gaps counted. */
  gaps: number;
}

/**
 * A roof's lit segments: how long they are drawn, and how much string runs along them. Skipped
 * segments (see Fixture.skip) leave out: their wire need not follow the drawing. Null: not a
 * roof, no light type, or nothing to measure.
 */
export function roofRun(f: Fixture, layout: Lit): RoofRun | null {
  if (f.kind !== 'roof' || f.points.length < 2 || Math.floor(f.pixels) < 2) return null;
  const lt = lightsOf(layout, f.lights);
  if (!lt || !(lt.spacing > 0)) return null;
  const seg = lineLengths(f);
  const offs = pointOffsets(f);
  let drawn = 0;
  let gaps = 0;
  seg.forEach((len, k) => {
    if (f.skip?.includes(k)) return;
    drawn += len;
    gaps += Math.max(0, offs[k + 1] - offs[k]);
  });
  return drawn > 0 && gaps > 0 ? { drawn, meters: gaps * lt.spacing, gaps } : null;
}

export interface RoofScale {
  /** Layout units per meter. */
  scale: number;
  /** The lit roofline as drawn, in layout units, and the string along it, in meters. */
  drawn: number;
  meters: number;
  /** The roofs it comes from, by id. */
  roofs: string[];
}

const SCALE_MIN = 1;
const SCALE_MAX = 10_000;
const round3 = (n: number) => Math.round(n * 1000) / 1000;

/** The scale every roof with a light type gives, together (their lengths added up), or null. */
export function roofScale(layout: Pick<Layout, 'fixtures' | 'lightTypes'>): RoofScale | null {
  let drawn = 0;
  let meters = 0;
  const roofs: string[] = [];
  for (const f of layout.fixtures) {
    const r = roofRun(f, layout);
    if (!r) continue;
    drawn += r.drawn;
    meters += r.meters;
    roofs.push(f.id);
  }
  if (!roofs.length) return null;
  return { scale: Math.min(SCALE_MAX, Math.max(SCALE_MIN, round3(drawn / meters))), drawn, meters, roofs };
}

/** The roofline's scale when it sets the yard's (not set by hand, see Layout.scaleBy), or null. */
export const autoScale = (layout: Pick<Layout, 'fixtures' | 'lightTypes' | 'scaleBy'>): RoofScale | null => (layout.scaleBy === 'hand' ? null : roofScale(layout));

/** True when this object's LEDs set the yard's scale: its string is as long as it is drawn, by definition. */
export const setsScale = (f: Fixture, layout: Pick<Layout, 'fixtures' | 'lightTypes' | 'scaleBy'>): boolean => layout.scaleBy !== 'hand' && roofRun(f, layout) != null;

/** Custom objects (designed in meters) at `scale` but the size they are drawn at now. */
function sameSize(l: Layout, scale: number): Fixture[] {
  const k = layoutScale(l) / scale;
  if (k === 1) return l.fixtures;
  return l.fixtures.map((f) => (f.kind === 'custom' ? { ...f, size: Math.min(100, Math.max(0.01, Math.round((f.size && f.size > 0 ? f.size : 1) * k * 1e6) / 1e6)) } : f));
}

/**
 * Keeps the yard's scale at the roofline's (see autoScale) across an edit from `prev` to
 * `next`. Objects keep the size they are drawn at: a custom object's size (a factor of its
 * design, which is in meters) goes the other way. `prev` comes back with its custom objects
 * sized the same way (its scale as it was), so the edit's other checks (strings, locks) do not
 * take that for a change.
 */
export function keepScale(prev: Layout, next: Layout): { layout: Layout; prev: Layout } {
  const r = autoScale(next);
  if (!r || r.scale === layoutScale(next)) return { layout: next, prev };
  return {
    layout: { ...next, scale: r.scale, fixtures: sameSize(next, r.scale) },
    prev: { ...prev, fixtures: sameSize(prev, r.scale) }
  };
}
