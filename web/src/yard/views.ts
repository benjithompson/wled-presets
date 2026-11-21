// The 2D views of the yard: front, top and side, and the boxes they show. A view's coordinates
// are u to the right and v down, in layout units.
import { buildStage, type Layout, type Point } from '../../../shared/layout.ts';
import type { Box } from './camera.ts';

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
