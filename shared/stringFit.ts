// How the light string limits the drawing. The LEDs of a string sit a fixed distance apart along
// its wire (the light type's spacing), so an object's wire cannot be drawn longer than its
// string, and the bulbs on the drawing sit as far apart as on the real string:
//   - a shape with a setting that is only there to say how the wire winds (a tree's turns, its
//     strands or the passes of a wave, a semicircle's rows, a bush's spiral) has it worked out
//     from the string, so the wire is as long as the string;
//   - a bush with a ring round its edge is as big as its string goes round;
//   - a line, a custom object, and any shape the string cannot cover even so, cannot be
//     stretched (a point dragged, a size made bigger) past the length of their string;
//   - a roof that sets the yard's scale (see yardScale.ts) is as long as its string by
//     definition: dragging it changes the scale instead.
// Objects without a light type are not limited.

import { BUSH_TURNS, capFloor, ledGap, layoutScale, treeSize, type Fixture, type Layout, type Point } from './layout.ts';
import { lightsOf } from './lights.ts';
import { setsScale } from './yardScale.ts';

/** How much longer than the string a wire may be drawn (rounding, and how a curve is measured). */
const SLACK = 0.03;

/** The setting worked out from the string, for the kinds that have one. */
export type FreeSetting = 'turns' | 'strands' | 'passes' | 'rows' | 'radius';

export function freeSetting(f: Pick<Fixture, 'kind' | 'pattern'>): FreeSetting | null {
  if (f.kind === 'tree') return f.pattern === 'strands' ? 'strands' : f.pattern === 'wave' ? 'passes' : 'turns';
  if (f.kind === 'semicircle') return 'rows';
  if (f.kind === 'bush') return f.pattern === 'ring' ? 'radius' : f.pattern === 'spiral' ? 'turns' : null;
  return null;
}

/** How far apart the object's LEDs are on its string, in layout units, or null (no light type set). */
export function stringGap(f: Pick<Fixture, 'lights'>, layout: Pick<Layout, 'lightTypes' | 'scale'>): number | null {
  const lt = lightsOf(layout, f.lights);
  return lt && lt.spacing > 0 ? lt.spacing * layoutScale(layout) : null;
}

/** True when the object's wire is no longer than its string (or nothing limits it). */
export function fitsString(f: Fixture, layout: Pick<Layout, 'lightTypes' | 'scale'>): boolean {
  const want = stringGap(f, layout);
  const gap = want == null ? null : ledGap(f, layoutScale(layout));
  return want == null || gap == null || gap <= want * (1 + SLACK);
}

/** The largest whole number from lo to hi whose gap fits `want` (gap grows with it), or lo. */
function largestFitting(lo: number, hi: number, gapAt: (k: number) => number | null, want: number): number {
  const fits = (k: number) => (gapAt(k) ?? 0) <= want * (1 + SLACK);
  if (!fits(lo)) return lo;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (fits(mid)) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** The value from lo to hi whose gap is `want` (gap grows with it), or the end it stops at. */
function solve(lo: number, hi: number, gapAt: (v: number) => number | null, want: number): number {
  if ((gapAt(lo) ?? 0) >= want) return lo;
  if ((gapAt(hi) ?? 0) <= want) return hi;
  for (let i = 0; i < 24; i++) {
    const mid = (lo + hi) / 2;
    if ((gapAt(mid) ?? 0) < want) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}

/**
 * The object with its free setting (see freeSetting) worked out from its string: its LEDs as
 * far apart as on the string, or as near as the setting goes. Others, and objects without a
 * light type, come back as they are.
 */
export function fitString(f: Fixture, layout: Pick<Layout, 'lightTypes' | 'scale'>): Fixture {
  const want = stringGap(f, layout);
  const free = freeSetting(f);
  if (want == null || !free || Math.floor(f.pixels) < 2) return f;
  const scale = layoutScale(layout);
  const gap = (g: Fixture) => ledGap(g, scale);
  let patch: Partial<Fixture>;
  if (free === 'turns') {
    const turns = solve(0.5, f.kind === 'bush' ? 50 : 100, (t) => gap({ ...f, turns: t }), want);
    const t = Math.round(turns * 100) / 100;
    patch = { turns: f.kind === 'bush' && t === BUSH_TURNS ? undefined : t };
  } else if (free === 'strands' || free === 'rows') {
    patch = { strands: largestFitting(1, 64, (k) => gap({ ...f, strands: k }), want) };
  } else if (free === 'passes') {
    // The passes are set by how far apart they are (see wavePasses).
    const climb = treeSize(f).h * (1 - capFloor(f));
    const spacingFor = (p: number) => Math.max(1, Math.round((climb / Math.max(1, p - 1)) * 10) / 10);
    const p = largestFitting(2, 200, (k) => gap({ ...f, spacing: spacingFor(k) }), want);
    patch = { spacing: spacingFor(p) };
  } else {
    // A ring is as long as its edge: its size goes with it.
    const now = gap(f);
    const r = f.radius ?? 60;
    patch = { radius: now ? Math.max(5, Math.min(4000, Math.round((r * want) / now))) : r };
  }
  const out = { ...f, ...patch };
  for (const k of Object.keys(patch) as (keyof Fixture)[]) if (out[k] === undefined) delete out[k];
  return (Object.keys(patch) as (keyof Fixture)[]).every((k) => out[k] === f[k]) ? f : out;
}

/** Settings that change how long the wire is, or how far apart its LEDs are. */
const WIRE_KEYS = ['kind', 'pixels', 'lights', 'radius', 'height', 'pattern', 'shape', 'cover', 'bias', 'sweep', 'startSide', 'endSide', 'zigzag', 'start', 'size', 'design'] as const;

const same = (a: unknown, b: unknown) => a === b || JSON.stringify(a) === JSON.stringify(b);

/** `from` moved t (0 to 1) of the way to `to`: its points and its size. The rest is `to`'s. */
function partWay(from: Fixture, to: Fixture, t: number): Fixture {
  const mix = (a: number | undefined, b: number | undefined, round: (n: number) => number) => (a != null && b != null ? round(a + (b - a) * t) : b);
  const r2 = (n: number) => Math.round(n * 100) / 100;
  const points: Point[] =
    from.points.length === to.points.length
      ? to.points.map((q, i) => {
          const p = from.points[i];
          const z = mix(p.z ?? 0, q.z ?? 0, r2);
          return { ...q, x: r2(p.x + (q.x - p.x) * t), y: r2(p.y + (q.y - p.y) * t), ...(q.z != null || p.z != null ? { z } : {}) };
        })
      : to.points;
  return { ...to, points, radius: mix(from.radius, to.radius, Math.round), height: mix(from.height, to.height, Math.round), size: mix(from.size, to.size, r2) };
}

/**
 * Keeps every object's wire within its string across an edit from `prev` to `next`. An object
 * whose wire changed gets its free setting worked out again (see fitString). One then drawn
 * longer than its string (a point dragged too far, a size made too big) goes only as far as
 * the string reaches, or no farther than it was when it was too long already. An object that
 * is too long for another reason (fewer LEDs, a shorter string) stays as it is: the editor says
 * so. `limited`: the names of the objects held back.
 */
export function keepStrings(prev: Layout, next: Layout): { layout: Layout; limited: string[] } {
  const before = new Map(prev.fixtures.map((f) => [f.id, f]));
  const limited: string[] = [];
  const fixtures = next.fixtures.map((g) => {
    const f = before.get(g.id);
    const want = stringGap(g, next);
    // A roof that sets the yard's scale is as long as its string, however it is drawn.
    if (want == null || setsScale(g, next)) return g;
    const rewired = !f || WIRE_KEYS.some((k) => !same(f[k], g[k])) || stringGap(f, prev) !== want;
    if (!rewired && (f === g || same(f.points, g.points))) return g;
    // A locked object keeps its size (see keepLocked): a ring then stays as big as it is.
    const fit = (x: Fixture) => (freeSetting(x) && !(x.locked && freeSetting(x) === 'radius') ? fitString(x, next) : x);
    const out = rewired ? fit(g) : g;
    if (!f || fitsString(out, next)) return out;
    // Drawn too long: the edit goes only part of the way, as far as the string reaches (or,
    // for one too long before, no farther than it was).
    const scale = layoutScale(next);
    const was = ledGap(fit(f), scale) ?? 0;
    const limit = Math.max(want * (1 + SLACK), was);
    const ok = (x: Fixture) => (ledGap(x, scale) ?? 0) <= limit + 1e-9;
    if (ok(out)) return out;
    const at = (t: number) => fit(partWay(f, g, t));
    if (!ok(at(0))) return out;
    let lo = 0;
    let hi = 1;
    for (let i = 0; i < 12; i++) {
      const mid = (lo + hi) / 2;
      if (ok(at(mid))) lo = mid;
      else hi = mid;
    }
    limited.push(g.name);
    return at(lo);
  });
  const changed = fixtures.some((x, i) => x !== next.fixtures[i]);
  return { layout: changed ? { ...next, fixtures } : next, limited };
}
