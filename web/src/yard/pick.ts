// What a click or a tap in a 2D view picks: the object nearest the pointer, not the one whose
// hit area happens to be drawn on top. Near an object's wire or one of its LEDs beats being inside
// another object's outline, so a bush in front of a tree, a line through an arch or a small
// object in a big one's box can all be picked; inside outlines only, the smallest one wins.
import type { UV } from './snap.ts';

/** One object as a view shows it, in view units. */
export interface PickShape {
  id: string;
  /** Its wire: polylines. For a line, one polyline of its points (segment k from point k to point k + 1). */
  wire: UV[][];
  /** Its LEDs: u, v for each. */
  leds?: ArrayLike<number>;
  /** The outline it covers, as a polygon, when it has one (a bush, a tree, the box of an arch). */
  area?: UV[];
  /** A line: the pick says which segment. */
  line?: boolean;
}

export interface Picked {
  id: string;
  /** The segment of a line nearest the pointer; null for other objects. */
  seg: number | null;
}

/** The distance from p to the segment a–b. */
export function segmentDistance(p: UV, a: UV, b: UV): number {
  const du = b.u - a.u;
  const dv = b.v - a.v;
  const len2 = du * du + dv * dv;
  const t = len2 ? Math.max(0, Math.min(1, ((p.u - a.u) * du + (p.v - a.v) * dv) / len2)) : 0;
  return Math.hypot(p.u - (a.u + t * du), p.v - (a.v + t * dv));
}

/** Whether p is inside a polygon (even-odd). */
export function insidePolygon(p: UV, poly: UV[]): boolean {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const a = poly[i];
    const b = poly[j];
    if (a.v > p.v !== b.v > p.v && p.u < ((b.u - a.u) * (p.v - a.v)) / (b.v - a.v) + a.u) inside = !inside;
  }
  return inside;
}

/** The area of a polygon (shoelace), always positive. */
export function polygonArea(poly: UV[]): number {
  let s = 0;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) s += (poly[j].u + poly[i].u) * (poly[j].v - poly[i].v);
  return Math.abs(s) / 2;
}

/** An ellipse as a polygon. */
export const ellipsePolygon = (c: UV, rx: number, ry: number, n = 32): UV[] =>
  Array.from({ length: n }, (_, i) => ({ u: c.u + Math.cos((2 * Math.PI * i) / n) * rx, v: c.v + Math.sin((2 * Math.PI * i) / n) * ry }));

/**
 * The object at `at`: the one whose wire or LEDs pass nearest, within `tol` (view units);
 * failing that, the smallest one whose outline it is inside. Ties go to the later shape (drawn
 * on top). Null: nothing there.
 */
export function pickAt(shapes: PickShape[], at: UV, tol: number): Picked | null {
  let near: { d: number; hit: Picked } | null = null;
  let inside: { area: number; hit: Picked } | null = null;
  for (const s of shapes) {
    let d = Infinity;
    let seg: number | null = null;
    s.wire.forEach((path, j) => {
      if (path.length === 1) {
        const e = Math.hypot(at.u - path[0].u, at.v - path[0].v);
        if (e <= d) [d, seg] = [e, s.line ? 0 : null];
      }
      for (let k = 0; k < path.length - 1; k++) {
        const e = segmentDistance(at, path[k], path[k + 1]);
        if (e <= d) [d, seg] = [e, s.line && j === 0 ? k : null];
      }
    });
    if (s.leds) for (let i = 0; i + 1 < s.leds.length; i += 2) d = Math.min(d, Math.hypot(at.u - s.leds[i], at.v - s.leds[i + 1]));
    const hit = { id: s.id, seg: s.line ? seg ?? 0 : null };
    if (d <= tol && (!near || d <= near.d)) near = { d, hit };
    if (s.area && s.area.length > 2 && insidePolygon(at, s.area)) {
      const area = polygonArea(s.area);
      if (!inside || area <= inside.area) inside = { area, hit };
    }
  }
  return near?.hit ?? inside?.hit ?? null;
}
