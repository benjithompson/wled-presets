// Drawing a new bush, tree or semicircle in the layout editor: press where it goes, drag to
// size it, let go. What it looks like while it is drawn, and the object it makes.
import { unproject, type FrontCam } from '../../yard/frontCamera.ts';
import { lightsOf } from '../../../../shared/lights.ts';
import { BUSH_TALL, layoutGround, layoutScale, type Fixture, type Layout, type Point, type ShapeKind } from '../../../../shared/layout.ts';
import type { UV } from '../../yard/snap.ts';
import type { ViewSide } from '../../yard/views.ts';

/**
 * A shape being drawn: where it was pressed (a bush's middle, a tree's or a semicircle's base)
 * and how far it has been dragged (a bush's or a semicircle's radius; a tree's height from the
 * front, its base's radius from above). 0: not dragged yet.
 */
export interface ShapeDraft {
  shape: ShapeKind;
  side: ViewSide;
  at: UV;
  size: number;
}

/** A tree drawn from the front: its radius as a share of its height. */
const TREE_WIDTH = 0.33;

/** The draft's size with the pointer at `p`. */
export function draftSize(d: ShapeDraft, p: UV): number {
  const front = d.side === 'front';
  if (d.shape === 'bush') return Math.round(Math.hypot(p.u - d.at.u, (p.v - d.at.v) / (front ? BUSH_TALL : 1)));
  if (d.shape === 'tree') return Math.round(front ? Math.max(0, d.at.v - p.v) : Math.hypot(p.u - d.at.u, p.v - d.at.v));
  return Math.round(Math.hypot(p.u - d.at.u, p.v - d.at.v));
}

/** The draft's outline in its view, as an SVG path. */
export function draftOutline(d: ShapeDraft): string {
  const { u, v } = d.at;
  const s = d.size;
  const front = d.side === 'front';
  const ellipse = (rx: number, ry: number) => `M ${u - rx} ${v} A ${rx} ${ry} 0 1 0 ${u + rx} ${v} A ${rx} ${ry} 0 1 0 ${u - rx} ${v} Z`;
  if (d.shape === 'bush') return ellipse(s, s * (front ? BUSH_TALL : 1));
  if (d.shape === 'tree') return front ? `M ${u - s * TREE_WIDTH} ${v} L ${u} ${v - s} L ${u + s * TREE_WIDTH} ${v} Z` : ellipse(s, s);
  // A semicircle from the front: the round side up. From above: a flat object is a line.
  return front ? `M ${u - s} ${v} A ${s} ${s} 0 0 1 ${u + s} ${v} Z` : `M ${u - s} ${v} L ${u + s} ${v}`;
}

/**
 * The object a draft makes, with `id`. From the front, a bush touches the front wall and a tree
 * or a semicircle stands a little in front of it; from above, each stands on the ground. A
 * click without a drag makes one of a usual size. With the yard's light string set, a bush and
 * a semicircle get one strand of LEDs and a tree four.
 */
export function shapeFrom(d: ShapeDraft, layout: Layout, zMin: number, id: string, cam?: FrontCam | null): Fixture {
  const s = layoutScale(layout);
  const ground = layoutGround(layout);
  const front = d.side === 'front';
  const { u, v } = d.at;
  const lt = lightsOf(layout, layout.lights);
  const count = layout.fixtures.filter((f) => f.kind === d.shape).length;
  const common = { id, ...(lt ? { lights: lt.id } : {}), deviceId: null, startPixel: 0, reversed: false };
  /** At depth z under the spot, seen from the front (turned: where the line of sight meets that depth). */
  const atDepth = (z: number): Point => {
    const p = cam ? unproject(cam, u, v, z) : { x: u, y: v };
    return { x: Math.round(p.x), y: Math.round(p.y), z: Math.round(z) };
  };
  /** On the ground, seen from above. */
  const onGround = (y: number): Point => ({ x: u, y: Math.round(y), z: Math.round(v + zMin) });
  if (d.shape === 'bush') {
    const r = Math.max(30, d.size || 70);
    const center = front ? atDepth(r) : onGround(ground - r * BUSH_TALL);
    return { ...common, name: `Bush ${count + 1}`, kind: 'bush', points: [center], radius: r, pattern: 'fill', pixels: lt?.perStrand ?? 60 };
  }
  if (d.shape === 'tree') {
    // From the front you drag the height; from above, the radius of the base.
    const height = front ? Math.max(40, d.size || 2.5 * s) : Math.max(40, (d.size || 0.6 * s) * 3);
    const r = Math.round(front ? height * TREE_WIDTH : Math.max(15, d.size || 0.6 * s));
    const base = front ? atDepth(r + 0.5 * s) : onGround(ground);
    return { ...common, name: `Tree ${count + 1}`, kind: 'tree', points: [base], radius: r, height: Math.round(height), pattern: 'spiral', turns: 8, pixels: lt?.perStrand ? lt.perStrand * 4 : 200 };
  }
  const r = Math.max(15, d.size || Math.round(0.6 * s));
  const base = front ? atDepth(0.5 * s) : onGround(ground);
  return { ...common, name: `Semicircle ${count + 1}`, kind: 'semicircle', points: [base], radius: r, strands: 8, zigzag: 'down', pixels: lt?.perStrand ?? 100 };
}

/**
 * A bulb placed with a click: a single light (see FixtureKind). From the front it hangs on the
 * spot, just in front of the wall; from above it stands on the ground (a path light, say).
 */
export function bulbFrom(side: ViewSide, at: UV, layout: Layout, zMin: number, id: string, cam?: FrontCam | null): Fixture {
  const s = layoutScale(layout);
  const r = Math.max(6, Math.round(0.12 * s));
  const count = layout.fixtures.filter((f) => f.kind === 'bulb').length;
  let point: Point;
  if (side === 'front') {
    const p = cam ? unproject(cam, at.u, at.v, r) : { x: at.u, y: at.v };
    point = { x: Math.round(p.x), y: Math.round(p.y), z: r };
  } else point = { x: at.u, y: Math.round(layoutGround(layout) - r), z: Math.round(at.v + zMin) };
  return { id, name: `Bulb ${count + 1}`, kind: 'bulb', points: [point], radius: r, pixels: 1, deviceId: null, startPixel: 0, reversed: false };
}
