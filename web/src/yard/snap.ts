// Snapping for the layout editor, as in CAD programs: the pointer jumps to points, midpoints,
// lines and alignments with other points, and an angle step (Shift: 45°; Ortho: 90°) keeps a
// line at a multiple of that angle. With a grid, the pointer also jumps to grid crossings where
// nothing else is near.
// Everything works in view coordinates (u to the right, v down), in layout units.

export type UV = { u: number; v: number };

/** What the pointer snapped to. */
export type SnapKind = 'point' | 'center' | 'mid' | 'on' | 'align' | 'grid' | 'angle' | 'free';

export interface SnapTargets {
  /** Points of lines (and points of the line being drawn). */
  points: UV[];
  /** Straight segments of lines. */
  segments: [UV, UV][];
  /** Middles of bushes and bases of trees. */
  centers: UV[];
}

export interface Snapped {
  at: UV;
  kind: SnapKind;
  /** Lines to draw as dashed guides (alignments, the 45° direction). */
  guides: [UV, UV][];
}

/** A snapping grid: lines every `step` layout units, counted from `origin`. */
export interface SnapGrid {
  step: number;
  origin: UV;
}

export const emptyTargets = (): SnapTargets => ({ points: [], segments: [], centers: [] });

const dist = (a: UV, b: UV) => Math.hypot(a.u - b.u, a.v - b.v);
const round = (p: UV): UV => ({ u: Math.round(p.u), v: Math.round(p.v) });
/** Grid steps are rarely whole layout units: keep grid positions to 1/100 of a unit. */
const fine = (x: number) => Math.round(x * 100) / 100;
const roundFine = (p: UV): UV => ({ u: fine(p.u), v: fine(p.v) });

/** The grid line nearest to x along one axis. */
export const onGrid = (x: number, grid: SnapGrid, axis: 'u' | 'v') => fine(grid.origin[axis] + Math.round((x - grid.origin[axis]) / grid.step) * grid.step);

/** The point on a ray from `from`, at a multiple of `stepDeg`, closest to `to`. */
export function constrainAngle(from: UV, to: UV, stepDeg = 45): UV {
  const du = to.u - from.u;
  const dv = to.v - from.v;
  const len = Math.hypot(du, dv);
  if (!len) return { ...from };
  const step = (stepDeg * Math.PI) / 180;
  const a = Math.round(Math.atan2(dv, du) / step) * step;
  const cu = Math.cos(a);
  const cv = Math.sin(a);
  const t = du * cu + dv * cv;
  return { u: from.u + cu * t, v: from.v + cv * t };
}

/** The closest point on segment a–b to p. */
export function closestOnSegment(p: UV, a: UV, b: UV): { at: UV; t: number } {
  const l2 = (b.u - a.u) ** 2 + (b.v - a.v) ** 2;
  const t = l2 ? Math.max(0, Math.min(1, ((p.u - a.u) * (b.u - a.u) + (p.v - a.v) * (b.v - a.v)) / l2)) : 0;
  return { at: { u: a.u + t * (b.u - a.u), v: a.v + t * (b.v - a.v) }, t };
}

function nearest(p: UV, list: UV[], tol: number): UV | null {
  let best: UV | null = null;
  let bestD = tol;
  for (const q of list) {
    const d = dist(p, q);
    if (d <= bestD) {
      best = q;
      bestD = d;
    }
  }
  return best;
}

/** The point whose u (or v) is closest to p's, within tol. */
function alignOn(p: UV, list: UV[], tol: number, axis: 'u' | 'v'): UV | null {
  let best: UV | null = null;
  let bestD = tol;
  for (const q of list) {
    const d = Math.abs(q[axis] - p[axis]);
    // Prefer the nearer point when two points line up equally well.
    if (d < bestD || (best && d === bestD && dist(p, q) < dist(p, best))) {
      best = q;
      bestD = d;
    }
  }
  return best;
}

/**
 * Snaps a pointer position. `tol` is the snap distance in layout units (a few screen pixels).
 * `angle`: keep the direction from `from` at a multiple of this many degrees (true: 45°).
 * `snap` false: no snapping to objects. `grid`: snap to this grid where no object is near.
 * Order: points, centers, midpoints, lines, alignment with other points, then the grid.
 */
export function snapPoint(raw: UV, targets: SnapTargets, tol: number, opts: { from?: UV | null; angle?: boolean | number; snap?: boolean; grid?: SnapGrid | null }): Snapped {
  const snapOn = opts.snap !== false;
  const grid = opts.grid && opts.grid.step > 0 ? opts.grid : null;
  const step = opts.angle === true ? 45 : opts.angle || 0;
  if (step && opts.from) {
    const from = opts.from;
    const at = constrainAngle(from, raw, step);
    // Along a level or upright line, still line up with other points, or else with the grid.
    const level = Math.abs(at.v - from.v) < 1e-6;
    const upright = Math.abs(at.u - from.u) < 1e-6;
    if (level || upright) {
      const axis = level ? 'u' : 'v';
      // The other coordinate stays exactly that of `from`, so the line (or the move) is truly level or upright.
      const keep = (x: number): UV => (axis === 'u' ? { u: x, v: from.v } : { u: from.u, v: x });
      if (snapOn) {
        const q = alignOn(
          at,
          targets.points.filter((p) => dist(p, from) > 1e-6),
          tol,
          axis
        );
        if (q) {
          const a = keep(q[axis]);
          return { at: a, kind: 'align', guides: [[from, a], [q, a]] };
        }
      }
      if (grid) {
        const g = keep(onGrid(at[axis], grid, axis));
        return { at: g, kind: 'grid', guides: [[from, g]] };
      }
      const a = keep(Math.round(at[axis]));
      return { at: a, kind: 'angle', guides: [[from, a]] };
    }
    return { at: round(at), kind: 'angle', guides: [[from, at]] };
  }
  const onTheGrid = (): Snapped | null => (grid ? { at: { u: onGrid(raw.u, grid, 'u'), v: onGrid(raw.v, grid, 'v') }, kind: 'grid', guides: [] } : null);
  if (!snapOn) return onTheGrid() ?? { at: round(raw), kind: 'free', guides: [] };

  const point = nearest(raw, targets.points, tol);
  if (point) return { at: round(point), kind: 'point', guides: [] };
  const center = nearest(raw, targets.centers, tol);
  if (center) return { at: round(center), kind: 'center', guides: [] };
  const mids = targets.segments.map(([a, b]) => ({ u: (a.u + b.u) / 2, v: (a.v + b.v) / 2 }));
  const mid = nearest(raw, mids, tol);
  if (mid) return { at: round(mid), kind: 'mid', guides: [] };

  // Alignment with other points: both directions at once gives their crossing.
  const all = [...targets.points, ...targets.centers];
  const au = alignOn(raw, all, tol, 'u');
  const av = alignOn(raw, all, tol, 'v');
  if (au && av) {
    const at = { u: au.u, v: av.v };
    return {
      at: round(at),
      kind: 'align',
      guides: [
        [au, at],
        [av, at]
      ]
    };
  }

  let on: UV | null = null;
  let onD = tol;
  for (const [a, b] of targets.segments) {
    const c = closestOnSegment(raw, a, b).at;
    const d = dist(raw, c);
    if (d <= onD) {
      on = c;
      onD = d;
    }
  }
  if (on) return { at: round(on), kind: 'on', guides: [] };

  if (au || av) {
    // Lined up one way; the other way goes to the grid, when there is one.
    const at = { u: au ? au.u : grid ? onGrid(raw.u, grid, 'u') : raw.u, v: av ? av.v : grid ? onGrid(raw.v, grid, 'v') : raw.v };
    return { at: grid ? roundFine(at) : round(at), kind: 'align', guides: [[(au ?? av)!, at]] };
  }
  return onTheGrid() ?? { at: round(raw), kind: 'free', guides: [] };
}
