// The 2D views of the yard: front, top and side, and the boxes they show. A view's coordinates
// are u to the right and v down, in layout units.
import { buildStage, BUSH_TALL, drawnByPaths, isLine, layoutScale, objectPaths, pointOnSegment, radiusOf, treeOutline, type Fixture, type Layout, type Point } from '../../../shared/layout.ts';
import type { Box } from './camera.ts';
import { closestOnSegment, emptyTargets, type SnapTargets, type UV } from './snap.ts';

/**
 * Which side the yard is seen from. Front: the picture. Top: from above, the street at the
 * bottom. Side: from the left, the street on the right (u is the depth, v the height as in front).
 */
export type ViewSide = 'front' | 'top' | 'side';

/** The size of a view, in layout units. The top view shows depths zMin (back) to zMax (street); the side view shows them across. */
export function viewSize(layout: Layout, side: ViewSide, zRange: [number, number]) {
  return side === 'front' ? { w: layout.width, h: layout.height } : side === 'top' ? { w: layout.width, h: zRange[1] - zRange[0] } : { w: zRange[1] - zRange[0], h: layout.height };
}

/** Where a view's yard starts across (u): the left edge, or in the side view the back (zMin). */
const viewLeft = (side: ViewSide, zRange: [number, number]) => (side === 'side' ? zRange[0] : 0);

/**
 * What a view shows when nothing else is asked for: the yard, grown to take in every LED (a
 * roof peak above the picture, a line past its edge) with room for the glow of the outer bulbs.
 */
export function fitBox(layout: Layout, side: ViewSide, zRange: [number, number]): Box {
  const size = viewSize(layout, side, zRange);
  const left = viewLeft(side, zRange);
  const b = ledBounds(layout, side, zRange);
  if (!b) return { x: left, y: 0, w: size.w, h: size.h };
  const { x0, y0, x1, y1 } = b;
  // Room for the glow of the outermost bulbs.
  const pad = 0.025 * Math.max(size.w, size.h);
  const bx0 = Math.min(left, x0 - pad);
  const by0 = Math.min(0, y0 - pad);
  const bx1 = Math.max(left + size.w, x1 + pad);
  const by1 = Math.max(size.h, y1 + pad);
  return { x: bx0, y: by0, w: bx1 - bx0, h: by1 - by0 };
}

/** Just the LEDs, with room for their glow (a game zooms in on them). */
export function ledBox(layout: Layout, side: ViewSide, zRange: [number, number]): Box {
  const b = ledBounds(layout, side, zRange);
  if (!b) return fitBox(layout, side, zRange);
  const size = viewSize(layout, side, zRange);
  const pad = Math.max(0.06 * Math.max(b.x1 - b.x0, b.y1 - b.y0), 0.02 * Math.max(size.w, size.h));
  return {
    x: b.x0 - pad,
    y: b.y0 - pad,
    w: b.x1 - b.x0 + 2 * pad,
    h: b.y1 - b.y0 + 2 * pad
  };
}

/** A box grown about its middle to a shape (width over height), so it fills a view of that shape. */
export function coverBox(b: Box, aspect: number): Box {
  if (!(aspect > 0)) return b;
  if (b.w / b.h < aspect) {
    const w = b.h * aspect;
    return { x: b.x - (w - b.w) / 2, y: b.y, w, h: b.h };
  }
  const h = b.w / aspect;
  return { x: b.x, y: b.y - (h - b.h) / 2, w: b.w, h };
}

/** Where the LEDs are, in view units (null: none placed). */
function ledBounds(layout: Layout, side: ViewSide, zRange: [number, number]) {
  const p = viewPositions(buildStage(layout).positions3, side, zRange[0]);
  let x0 = Infinity;
  let y0 = Infinity;
  let x1 = -Infinity;
  let y1 = -Infinity;
  for (let i = 0; i < p.length; i += 2) {
    const u = p[i];
    const v = p[i + 1];
    if (!Number.isFinite(u) || !Number.isFinite(v)) continue;
    x0 = Math.min(x0, u);
    x1 = Math.max(x1, u);
    y0 = Math.min(y0, v);
    y1 = Math.max(y1, v);
  }
  return x0 > x1 ? null : { x0, y0, x1, y1 };
}

/** A point in view coordinates (u to the right, v down). */
export function toView(p: Point, side: ViewSide, zMin: number): { u: number; v: number } {
  return side === 'front' ? { u: p.x, v: p.y } : side === 'top' ? { u: p.x, v: (p.z ?? 0) - zMin } : { u: p.z ?? 0, v: p.y };
}

/** A point from a position in a view. The coordinate the view does not show comes from `base`. */
export function fromView(at: { u: number; v: number }, side: ViewSide, zMin: number, base: Point): Point {
  return side === 'front' ? { ...base, x: at.u, y: at.v } : side === 'top' ? { ...base, x: at.u, z: Math.round(at.v + zMin) } : { ...base, z: Math.round(at.u), y: at.v };
}

/** LED positions (x, y, z for each, as in Stage.positions3) in a view: u, v for each. */
export function viewPositions(positions3: Float32Array, side: ViewSide, zMin: number): Float32Array {
  const n = positions3.length / 3;
  const out = new Float32Array(n * 2);
  for (let i = 0; i < n; i++) {
    out[i * 2] = side === 'side' ? positions3[i * 3 + 2] : positions3[i * 3];
    out[i * 2 + 1] = side === 'top' ? positions3[i * 3 + 2] - zMin : positions3[i * 3 + 1];
  }
  return out;
}

/** A point of a line that is left out (it is being dragged), with its two segments. */
export type PointRef = { id: string; index: number };

/**
 * A layout as one view shows it: where its objects are in that view, and what is at a spot in
 * it (for snapping, picking and dragging).
 */
export class LayoutInView {
  readonly layout: Layout | null;
  readonly side: ViewSide;
  readonly zMin: number;

  constructor(layout: Layout | null, side: ViewSide, zMin: number) {
    this.layout = layout;
    this.side = side;
    this.zMin = zMin;
  }

  private get fixtures() {
    return this.layout?.fixtures ?? [];
  }

  /** Where a point is in this view. */
  at(p: Point) {
    return toView(p, this.side, this.zMin);
  }

  /** What can be snapped to: the points and segments of lines, and the middles of the other objects (`linesOnly`: not those). */
  targets(exclude?: PointRef, linesOnly = false): SnapTargets {
    const t = emptyTargets();
    for (const f of this.fixtures) {
      const pts = f.points.map((p) => this.at(p));
      if (!isLine(f)) {
        if (!linesOnly) t.centers.push(pts[0]);
        continue;
      }
      pts.forEach((p, i) => !(exclude?.id === f.id && exclude.index === i) && t.points.push(p));
      for (let k = 0; k < pts.length - 1; k++) if (!(exclude?.id === f.id && (exclude.index === k || exclude.index === k + 1))) t.segments.push([pts[k], pts[k + 1]]);
    }
    return t;
  }

  /** The 3D point of a line that sits at this spot, if any. */
  pointAt(at: UV, exclude?: PointRef): Point | undefined {
    for (const f of this.fixtures) {
      if (!isLine(f)) continue;
      for (let i = 0; i < f.points.length; i++) {
        if (exclude?.id === f.id && exclude.index === i) continue;
        const q = this.at(f.points[i]);
        if (Math.abs(q.u - at.u) < 1 && Math.abs(q.v - at.v) < 1) return f.points[i];
      }
    }
    return undefined;
  }

  /** The end of a line within `tol` of this spot (the nearest), for continuing that line. */
  lineEndAt(at: UV, tol: number): { f: Fixture; at: 'first' | 'last' } | null {
    let best: { f: Fixture; at: 'first' | 'last' } | null = null;
    let bestD = tol;
    for (const f of this.fixtures) {
      if (!isLine(f)) continue;
      for (const end of ['first', 'last'] as const) {
        const q = this.at(f.points[end === 'first' ? 0 : f.points.length - 1]);
        const d = Math.hypot(q.u - at.u, q.v - at.v);
        if (d <= bestD) {
          best = { f, at: end };
          bestD = d;
        }
      }
    }
    return best;
  }

  /** The 3D point on segment k of a line nearest to a spot. */
  pointOnLine(f: Fixture, k: number, raw: UV): Point {
    const { at, t } = closestOnSegment(raw, this.at(f.points[k]), this.at(f.points[k + 1]));
    return fromView({ u: Math.round(at.u), v: Math.round(at.v) }, this.side, this.zMin, pointOnSegment(f, k, t));
  }

  /** Points moved by (du, dv) in this view; the coordinate the view does not show stays. */
  moved(points: Point[], du: number, dv: number): Point[] {
    const side = this.side;
    return points.map((q) => (side === 'front' ? { ...q, x: q.x + du, y: q.y + dv } : side === 'top' ? { ...q, x: q.x + du, z: (q.z ?? 0) + dv } : { ...q, z: (q.z ?? 0) + du, y: q.y + dv }));
  }

  /** The box around an object. */
  box(f: Fixture): Box {
    const span = (pts: UV[]): Box => {
      const us = pts.map((p) => p.u);
      const vs = pts.map((p) => p.v);
      return { x: Math.min(...us), y: Math.min(...vs), w: Math.max(...us) - Math.min(...us), h: Math.max(...vs) - Math.min(...vs) };
    };
    if (drawnByPaths(f)) {
      const pts: Point[] = objectPaths(f, this.layout ? layoutScale(this.layout) : undefined).flat();
      if (!pts.length) pts.push(f.points[0]);
      return span(pts.map((p) => this.at(p)));
    }
    const c = this.at(f.points[0]);
    const r = radiusOf(f);
    if (this.side === 'top') return { x: c.u - r, y: c.v - r, w: 2 * r, h: 2 * r };
    // A tree: its outline from that side (tilted, as it is), with the whole ball for a cap.
    if (f.kind === 'tree') return span(treeOutline({ ...f, cover: undefined }, this.side === 'side' ? 'side' : 'front').map((p) => this.at(p)));
    const h = r * BUSH_TALL;
    return { x: c.u - r, y: c.v - h, w: 2 * r, h: 2 * h };
  }
}
