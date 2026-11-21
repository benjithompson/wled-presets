// The yard layout: the physical light objects (roofline, bushes) drawn over a picture of
// the house, and where each LED of each object sits. Shared by the server (games) and the
// web client (editor and simulator), so both agree on every pixel's position.

import type { PaintPad } from './paint.ts';
import type { LineView } from './line.ts';
import type { EffectSettings } from './effects.ts';
import type { LightType } from './lights.ts';

/**
 * roof: the roofline, a line of LEDs that games use as "the roof".
 * line: any other line of LEDs (windows, doors, a fence, a path); edited like a roof line.
 * bush: LEDs spread over a dome.
 * tree: a cone (or a cylinder, or a ball: see TreeShape), with LEDs in a spiral or in strands
 *   from the base to the top.
 * semicircle: a flat half-disc standing on its straight edge (a sunrise, a fan), with the LEDs
 *   in a zigzag across it (see Zigzag).
 * custom: your own shape (a star, a wreath, an arch…), drawn in the object designer. Its
 *   design can be saved to the library and placed many times.
 */
export const FIXTURE_KINDS = ['roof', 'line', 'bush', 'tree', 'semicircle', 'custom'] as const;
export type FixtureKind = (typeof FIXTURE_KINDS)[number];
/** Bush: fill, ring, spiral. Tree: spiral, strands, wave (back and forth over its front, see wavePasses). */
export const FIXTURE_PATTERNS = ['fill', 'ring', 'spiral', 'strands', 'wave'] as const;
export type FixturePattern = (typeof FIXTURE_PATTERNS)[number];
/** A side of an object, as seen from the street. */
export const SIDES = ['left', 'right'] as const;
export type Side = (typeof SIDES)[number];
/** A tree's sides: a cone (a tree), a cylinder (a wrapped post or column), or a sphere (a ball of lights) on its base. */
export const TREE_SHAPES = ['cone', 'cylinder', 'sphere'] as const;
export type TreeShape = (typeof TREE_SHAPES)[number];
/** Which way a spiral winds, as seen from above, following the wire from LED 0: counterclockwise or clockwise. */
export const SPINS = ['ccw', 'cw'] as const;
export type Spin = (typeof SPINS)[number];
/**
 * How a semicircle's zigzag runs, from LED 0: down (rows across, from the top down), up (rows
 * across, from the bottom up), right (columns, from the left to the right) or left (columns,
 * from the right to the left). Up mirrors down, left mirrors right. Rows start at the left and
 * columns at the ground.
 */
export const ZIGZAGS = ['down', 'up', 'right', 'left'] as const;
export type Zigzag = (typeof ZIGZAGS)[number];
export const UNITS = ['ft', 'm'] as const;
export type Units = (typeof UNITS)[number];

/**
 * A position in the yard, in layout units. x: from the left edge of the front view. y: down
 * from the top edge of the front view (as in the picture). z: depth, from the front wall of the
 * house (0) toward the street (positive) or to the back (negative). A point without z is on
 * the front wall.
 */
export interface Point {
  x: number;
  y: number;
  z?: number;
}

export interface Point3 {
  x: number;
  y: number;
  z: number;
}

/** True for objects that are a line of LEDs with points and segments (roof and line). */
export const isLine = (f: { kind: FixtureKind }) => f.kind === 'roof' || f.kind === 'line';

/**
 * One run of LEDs in a custom object's design, in meters, as seen from the front: x to the
 * right, y up, z toward the front (toward whoever looks at the object; none: 0, a flat object),
 * (0, 0, 0) is the object's anchor (the point you place). The LEDs run from the first point to
 * the last; a closed stroke goes back to its first point. Between strokes, the wire jumps
 * without LEDs.
 */
export interface DesignStroke {
  points: DesignPoint[];
  closed?: boolean;
  /**
   * One LED at each point, in order (a scanned string: the wire between LEDs is flexible, so
   * they are not evenly spaced). Other strokes spread their LEDs evenly along the wire.
   */
  exact?: boolean;
}

/** A point of a design, in meters: x to the right, y up, z toward the front (see DesignStroke). */
export type DesignPoint = { x: number; y: number; z?: number };

/** A custom object in the library, to place as many times as you like. */
export interface Design {
  id: string;
  name: string;
  strokes: DesignStroke[];
  pixels: number;
  /** The light string it is made of (a LightType id). */
  lights?: string;
}

export interface Fixture {
  id: string;
  name: string;
  kind: FixtureKind;
  /** Roof and line: the polyline from the first LED to the last; inner points are corners. Bush: [center]. Tree: [center of the base]. */
  points: Point[];
  /** Bush, tree and semicircle: radius in layout units (tree: at the base, or the widest; semicircle: half its width). */
  radius?: number;
  /** Tree: height from the base to the top, in layout units. Semicircle: from its straight edge to the top of the round (default: the radius). */
  height?: number;
  /** Bush and tree: how the LEDs are spread over the object. */
  pattern?: FixturePattern;
  /** Tree with a spiral: how many times the LEDs go around from the base to the top. */
  turns?: number;
  /**
   * Tree with a spiral: where its loops sit closer together, from -1 (toward the base, or the
   * outside edge of a ball's cap) through 0 (evenly apart, measured over its surface) to 1
   * (toward the top, the middle of a ball's cap). Not set: evenly.
   */
  bias?: number;
  /**
   * Tree with strands: the number of strands. They zigzag: up the first, down the second, and so on.
   * Semicircle: the number of rows (or columns) of its zigzag.
   */
  strands?: number;
  /** Tree: the shape of its sides. Not set: a cone. */
  shape?: TreeShape;
  /**
   * Tree shaped as a ball: how much of it has LEDs, in degrees from the top down. 180 (not set):
   * all of it; 90: its top half, an upside-down bowl (the crown of a Japanese maple, say). The
   * ball keeps its width and height; the LEDs stop at the edge of that cap.
   */
  cover?: number;
  /** Tree: which way its spiral winds (or its strands go round), seen from above (see Spin). Not set: counterclockwise. */
  spin?: Spin;
  /** Tree with a spiral or a wave: where LED 0 is, at the base or at the top. Not set: the base. */
  start?: 'base' | 'top';
  /**
   * Tree with a wave: how far around the tree it winds back and forth, in degrees, centered on
   * its front (see facing). Not set: 180 (its front half).
   */
  sweep?: number;
  /** Tree with a wave: the height between one pass and the next, in layout units. Not set: 8 passes. */
  spacing?: number;
  /** Tree with a wave: the side its first pass starts on, as seen from its front. Not set: left. */
  startSide?: Side;
  /** Tree with a wave: the side its last pass ends on. Not set: wherever the passes end. */
  endSide?: Side;
  /** Semicircle: how its zigzag runs (see Zigzag). Not set: down. */
  zigzag?: Zigzag;
  /** Number of LEDs. */
  pixels: number;
  /** What the LEDs are: a LightType id (see shared/lights.ts). Not set: unknown. */
  lights?: string;
  /** Custom: its design, a copy of the library's (designId) so the object draws on its own. */
  design?: DesignStroke[];
  /** Custom: the library design it was placed from. Editing that design changes this object too. */
  designId?: string;
  /** Custom: size as a factor of the design (1: as designed). */
  size?: number;
  /**
   * Custom and semicircle: turned clockwise, in degrees, as seen from the front. Tree: tilted
   * that way about its base (to the left or right).
   */
  rotation?: number;
  /**
   * Tree, semicircle and custom: tilted about its point, clockwise as seen from the side view
   * (from the left, the street on the right), in degrees: more leans its top toward the street,
   * less toward the house. Not set: upright.
   */
  tilt?: number;
  /**
   * Custom, semicircle and tree: turned about the upright axis, as seen from above, in degrees.
   * Which way its front faces: 0 the street, 90 right (as seen from the street), -90 left, 180
   * the house. A tree's front is where its spiral (or first strand) starts.
   */
  facing?: number;
  /** The WLED device that drives these LEDs. Null: simulation only. */
  deviceId: string | null;
  /** Index of the first LED of this object on that device. */
  startPixel: number;
  /** True when the LED numbers count down along the drawn line (the first point has the highest number). */
  reversed: boolean;
  /**
   * Roof only, one entry per point: the LED (counted from the first point, 0-based) that sits
   * at that point. Null: spread evenly. Pinned corners make the placement exact when the
   * LEDs are not evenly spaced along the roof.
   */
  pointLeds?: (number | null)[];
  /**
   * Roof only: segments that are off (skipped), by index (segment k runs from point k to
   * point k + 1). Use it for a stretch of wire or LEDs that only links two lit segments.
   * Their LEDs stay dark, and games skip them.
   */
  skip?: number[];
  /**
   * The effect this object plays in the layout editor: the working copy of a scene. A scene
   * saved from the editor keeps its own copy of every object's effect.
   */
  effect?: EffectSettings;
  /**
   * Roof and line: effects of single segments, by segment index (segment k runs from point k
   * to point k + 1). Such a segment plays its own effect; the object's effect fills the rest.
   */
  segmentEffects?: Record<string, EffectSettings>;
  /**
   * Locked in place: the editor does not move, reshape or delete it (see keepLocked). Its LEDs,
   * wiring and effects can still change.
   */
  locked?: boolean;
}

export interface Layout {
  /** Layout units. The width is always 1600; the height follows the picture's aspect. */
  width: number;
  height: number;
  /** URL of the background picture, or null. */
  background: string | null;
  fixtures: Fixture[];
  /** Layout units per meter, for real distances. Default: DEFAULT_SCALE. */
  scale?: number;
  /** Units for distances in the editor. Default: feet. */
  units?: Units;
  /** The ground in the front view: the y of the bottom of the front wall. Default: the bottom edge. */
  groundY?: number;
  /**
   * The effect the whole yard plays in the layout editor (the working copy of a scene's "*"
   * effect). Objects and segments with their own effect play theirs instead.
   */
  effect?: EffectSettings;
  /** Your own light types (the built-in ones are in shared/lights.ts). */
  lightTypes?: LightType[];
  /** The light type new objects are made of. */
  lights?: string;
  /** The library of custom objects. */
  designs?: Design[];
  /** A picture of the yard from above, under the top view. */
  aerial?: AerialPicture | null;
}

/**
 * A picture of the yard from above: a satellite or drone photo, or a screenshot of a map. It
 * lies under the top view, so trees and bushes can be placed where they really are. It is placed
 * by its middle, its width and how far it is turned.
 */
export interface AerialPicture {
  /** Where to load it. Only signed-in users can: it shows where the house is. */
  url: string;
  /** The middle of the picture: x as in the front view, z the depth (toward the street). */
  x: number;
  z: number;
  /** Width in layout units. */
  width: number;
  /** The picture's height divided by its width. */
  aspect: number;
  /** Turned clockwise as seen from above, in degrees. */
  rotation: number;
  /** 0 (hidden) to 1. Default: AERIAL_OPACITY. */
  opacity?: number;
}

/** A point seen from above: x across, z the depth. */
export type XZ = { x: number; z: number };

export const AERIAL_OPACITY = 0.6;

const round2 = (n: number) => Math.round(n * 100) / 100;
/** Degrees in (-180, 180]. */
const wrapDegrees = (d: number) => {
  const w = ((((d + 180) % 360) + 360) % 360) - 180;
  return round2(w === -180 ? 180 : w);
};

/**
 * A new picture from above. `prev`: the picture it replaces, whose place it takes. A first
 * picture is twice as wide as the front view, with its middle on the front wall.
 */
export function placeAerial(layout: Pick<Layout, 'width'>, url: string, aspect: number, prev?: AerialPicture | null): AerialPicture {
  if (prev) return { ...prev, url, aspect };
  return { url, aspect, x: layout.width / 2, z: 0, width: layout.width * 2, rotation: 0, opacity: AERIAL_OPACITY };
}

/** The corners of the picture from above: top left, top right, bottom right, bottom left. */
export function aerialCorners(a: AerialPicture): XZ[] {
  const t = (a.rotation * Math.PI) / 180;
  const c = Math.cos(t);
  const s = Math.sin(t);
  const hw = a.width / 2;
  const hh = (a.width * a.aspect) / 2;
  return [
    [-hw, -hh],
    [hw, -hh],
    [hw, hh],
    [-hw, hh]
  ].map(([u, v]) => ({ x: a.x + u * c - v * s, z: a.z + u * s + v * c }));
}

/**
 * Moves, turns and sizes the picture so that the spot `from1` on it lands on `to1`, and `from2`
 * on `to2` (as the Align command of CAD programs). Without the second pair it only moves.
 */
export function alignAerial(a: AerialPicture, from1: XZ, to1: XZ, from2?: XZ, to2?: XZ): AerialPicture {
  const dx = from2 ? from2.x - from1.x : 0;
  const dz = from2 ? from2.z - from1.z : 0;
  const d2 = dx * dx + dz * dz;
  if (!from2 || !to2 || d2 < 1e-6) return { ...a, x: round2(a.x + to1.x - from1.x), z: round2(a.z + to1.z - from1.z) };
  // As complex numbers: k = (to2 - to1) / (from2 - from1) turns and scales about from1.
  const tx = to2.x - to1.x;
  const tz = to2.z - to1.z;
  const kr = (tx * dx + tz * dz) / d2;
  const ki = (tz * dx - tx * dz) / d2;
  const cx = a.x - from1.x;
  const cz = a.z - from1.z;
  return {
    ...a,
    x: round2(to1.x + kr * cx - ki * cz),
    z: round2(to1.z + ki * cx + kr * cz),
    width: round2(a.width * Math.hypot(kr, ki)),
    rotation: wrapDegrees(a.rotation + (Math.atan2(ki, kr) * 180) / Math.PI)
  };
}

/** Scales the picture by `factor` about the spot `about`, which stays where it is. */
export function scaleAerial(a: AerialPicture, about: XZ, factor: number): AerialPicture {
  return { ...a, x: round2(about.x + (a.x - about.x) * factor), z: round2(about.z + (a.z - about.z) * factor), width: round2(a.width * factor) };
}

export const LAYOUT_WIDTH = 1600;
/** 80 units per meter: the front view is 20 m (about 66 ft) wide. */
export const DEFAULT_SCALE = 80;
export const FEET_PER_METER = 3.28084;

export const layoutScale = (l: Pick<Layout, 'scale'>) => (l.scale && l.scale > 0 ? l.scale : DEFAULT_SCALE);
export const layoutGround = (l: Pick<Layout, 'groundY' | 'height'>) => l.groundY ?? l.height;
const pz = (p: Point) => p.z ?? 0;
export const MAX_FIXTURE_PIXELS = 2000;

/** A first layout so the simulator shows something: a gabled roof and three bushes. */
export function sampleLayout(): Layout {
  return {
    width: LAYOUT_WIDTH,
    height: 900,
    background: null,
    fixtures: [
      {
        id: 'roof',
        name: 'Roofline',
        kind: 'roof',
        points: [
          { x: 220, y: 470 },
          { x: 560, y: 470 },
          { x: 800, y: 250 },
          { x: 1040, y: 470 },
          { x: 1380, y: 470 }
        ],
        pixels: 450,
        deviceId: null,
        startPixel: 0,
        reversed: false
      },
      bush('bush-1', 'Left bush', 360, 760, 80),
      bush('bush-2', 'Middle bush', 800, 790, 95),
      bush('bush-3', 'Right bush', 1240, 760, 80)
    ]
  };
}

function bush(id: string, name: string, x: number, y: number, radius: number): Fixture {
  // In front of the house: the back of the bush touches the front wall.
  return { id, name, kind: 'bush', points: [{ x, y, z: radius }], radius, pattern: 'fill', pixels: 60, deviceId: null, startPixel: 0, reversed: false };
}

/** Hues for objects in the editor, in list order. */
export const FIXTURE_HUES = [0.08, 0.55, 0.33, 0.85, 0.15, 0.7, 0.0, 0.45];

/** RGB bytes for an HSV color. */
export function hsvBytes(h: number, v = 1): [number, number, number] {
  const f = (n: number) => {
    const k = (n + h * 6) % 6;
    return Math.round(255 * (v - v * Math.max(0, Math.min(k, 4 - k, 1))));
  };
  return [f(5), f(3), f(1)];
}

/** The editor color of the object at this list position. */
export const fixtureColor = (index: number, v = 1) => hsvBytes(FIXTURE_HUES[index % FIXTURE_HUES.length], v);

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/**
 * Positions of the LEDs of one object, in LED order (LED 0 first), in 3D. `scale` (layout units
 * per meter) sizes custom objects, which are designed in meters.
 */
export function fixturePixels(f: Fixture, scale = DEFAULT_SCALE): Point3[] {
  const n = Math.max(0, Math.floor(f.pixels));
  if (n === 0) return [];
  if (f.kind === 'tree') return treePixels(f, n).map(tiltOf(f));
  if (f.kind === 'semicircle') return semicirclePixels(f, n).map(tiltOf(f));
  if (f.kind === 'custom') {
    const at = designTransform(f, scale);
    const tilt = tiltOf(f);
    return designLeds(f.design ?? [], n).map((p) => tilt(at(p)));
  }
  if (f.kind === 'bush') {
    const c = f.points[0] ?? { x: 0, y: 0 };
    const cz = pz(c);
    const r = radiusOf(f);
    const out: Point3[] = [];
    for (let i = 0; i < n; i++) {
      let a: number;
      let d: number;
      if (f.pattern === 'ring') {
        a = (i / n) * Math.PI * 2;
        d = r;
      } else if (f.pattern === 'spiral') {
        const t = n === 1 ? 0 : i / (n - 1);
        a = t * Math.PI * 2 * 3;
        d = r * (0.15 + 0.85 * t);
      } else {
        // Sunflower spread: even coverage, like a net of lights over the bush.
        a = i * GOLDEN_ANGLE;
        d = r * Math.sqrt((i + 0.5) / n);
      }
      // Bushes are wider than tall. The LEDs lie on the front of a dome: the middle bulges
      // toward the street, the edge is at the bush's center depth.
      const k = Math.min(1, d / r);
      out.push({ x: c.x + Math.cos(a) * d, y: c.y + Math.sin(a) * d * BUSH_TALL, z: cz + Math.sqrt(1 - k * k) * r * 0.75 });
    }
    return out;
  }
  // Roof and line: spread the LEDs by length between anchors (the ends and any pinned corners).
  const pts = f.points;
  if (pts.length < 2) return Array.from({ length: n }, () => p3(pts[0] ?? { x: 0, y: 0 }));
  const offsets = pointOffsets(f);
  const out: Point3[] = [];
  const anchors = anchorIndexes(f);
  for (let k = 0; k < anchors.length - 1; k++) {
    const pa = anchors[k];
    const pb = anchors[k + 1];
    const la = offsets[pa];
    const lb = offsets[pb];
    const sub = pts.slice(pa, pb + 1);
    const last = k === anchors.length - 2;
    for (let led = la; led < lb || (last && led === lb); led++) {
      out.push(along(sub, lb === la ? 0 : (led - la) / (lb - la)));
    }
  }
  return out.slice(0, n);
}

const p3 = (p: Point): Point3 => ({ x: p.x, y: p.y, z: pz(p) });

/**
 * Tilts a point of an object about the object's point: first as seen from the side view (`tilt`,
 * clockwise with the street on the right), then, for a tree, as seen from the front (`rotation`,
 * clockwise). Semicircles and custom objects take their `rotation` in their own design instead.
 */
export function tiltOf(f: Pick<Fixture, 'kind' | 'points' | 'rotation' | 'tilt'>): (p: Point3) => Point3 {
  const t = ((f.kind === 'tree' || f.kind === 'semicircle' || f.kind === 'custom' ? (f.tilt ?? 0) : 0) * Math.PI) / 180;
  const r = ((f.kind === 'tree' ? (f.rotation ?? 0) : 0) * Math.PI) / 180;
  if (!t && !r) return (p) => p;
  const c = f.points[0] ?? { x: 0, y: 0 };
  const cz = pz(c);
  const ct = Math.cos(t);
  const st = Math.sin(t);
  const cr = Math.cos(r);
  const sr = Math.sin(r);
  return (p) => {
    // In the side view (u: z, v: y down), clockwise on the screen.
    let dz = p.z - cz;
    let dy = p.y - c.y;
    let dx = p.x - c.x;
    [dz, dy] = [dz * ct - dy * st, dz * st + dy * ct];
    // In the front view (u: x, v: y down), clockwise on the screen.
    [dx, dy] = [dx * cr - dy * sr, dx * sr + dy * cr];
    return { x: c.x + dx, y: c.y + dy, z: cz + dz };
  };
}

/** The settings that place an object and give it its size: a locked object keeps them. */
export const PLACE_KEYS = ['points', 'radius', 'height', 'size', 'rotation', 'facing', 'tilt'] as const;

/**
 * Keeps locked objects in place across an edit from `prev` to `next`: an object locked in both
 * whose place or size changed goes back as it was (all of it, so its points and their LED pins
 * stay together), and a locked object that was removed comes back where it was in the list.
 * Unlocking is an edit like any other, so an object unlocked in `next` can change. `blocked`:
 * the names of the objects kept.
 */
export function keepLocked(prev: Layout, next: Layout): { layout: Layout; blocked: string[] } {
  const blocked: string[] = [];
  let fixtures = next.fixtures;
  prev.fixtures.forEach((f, i) => {
    if (!f.locked) return;
    const j = fixtures.findIndex((g) => g.id === f.id);
    if (j < 0) {
      blocked.push(f.name);
      fixtures = [...fixtures.slice(0, i), f, ...fixtures.slice(i)];
      return;
    }
    const g = fixtures[j];
    if (g === f || !g.locked) return;
    if (PLACE_KEYS.some((k) => JSON.stringify(g[k]) !== JSON.stringify(f[k]))) {
      blocked.push(f.name);
      fixtures = fixtures.map((x, k) => (k === j ? f : x));
    }
  });
  return { layout: fixtures === next.fixtures ? next : { ...next, fixtures }, blocked };
}

/** Kinds that are one shape on a point (see changeKind): their kind can change. */
export const SHAPE_KINDS = ['bush', 'tree', 'semicircle'] as const;
export type ShapeKind = (typeof SHAPE_KINDS)[number];
export const isShapeKind = (k: FixtureKind): k is ShapeKind => (SHAPE_KINDS as readonly string[]).includes(k);

/** How tall a bush looks from the front, as a share of its radius (its LEDs spread 0.72 r up and down). */
export const BUSH_TALL = 0.72;

// A shape's size when its layout does not say (objects saved before the setting came).
/** A tree's radius at its base. */
const TREE_RADIUS = 80;
/** A tree's height. */
const TREE_HEIGHT = 240;
/** A bush's or a semicircle's radius. */
const SHAPE_RADIUS = 60;

/** A tree's radius at its base, and its height. */
export const treeSize = (f: Pick<Fixture, 'radius' | 'height'>) => ({ r: f.radius ?? TREE_RADIUS, h: f.height ?? TREE_HEIGHT });

/** A semicircle's radius, and its height (its radius unless set). */
export function semicircleSize(f: Pick<Fixture, 'radius' | 'height'>) {
  const r = f.radius ?? SHAPE_RADIUS;
  return { r, h: f.height ?? r };
}

/** A shape's radius: a bush's, a tree's at its base, a semicircle's. */
export const radiusOf = (f: Pick<Fixture, 'kind' | 'radius'>) => f.radius ?? (f.kind === 'tree' ? TREE_RADIUS : SHAPE_RADIUS);

/** A shape's height: a tree's, a semicircle's (its radius unless set), a bush's as it looks from the front. */
export function heightOf(f: Pick<Fixture, 'kind' | 'radius' | 'height'>) {
  if (f.kind === 'bush') return 2 * BUSH_TALL * radiusOf(f);
  return f.kind === 'tree' ? treeSize(f).h : semicircleSize(f).h;
}

/**
 * The object made into another kind of shape (a bush into a tree, say), keeping what it is
 * besides its shape: its name, LEDs (count, device, numbers, direction), light string, effect,
 * lock, and where it stands and how big it is. It covers the same part of the front view: the
 * same width, the same ground line and the same height. Settings of the old kind that the new
 * one does not have go; the new kind's own start at their defaults (a bush becomes a ball of
 * lights, the tree shape closest to a bush). A tree and a semicircle keep which way they face.
 */
export function changeKind(f: Fixture, kind: ShapeKind): Fixture {
  if (f.kind === kind || !isShapeKind(f.kind)) return f;
  const p = f.points[0] ?? { x: 0, y: 0 };
  const r = radiusOf(f);
  // The front view's bottom and height of the old shape.
  const height = heightOf(f);
  const bottom = f.kind === 'bush' ? p.y + BUSH_TALL * r : p.y;
  const { id, name, pixels, lights, deviceId, startPixel, reversed, effect, locked } = f;
  const keep: Fixture = { id, name, kind, points: [], radius: r, pixels, lights, deviceId, startPixel, reversed, effect, locked };
  const at = (y: number): Point[] => [{ ...p, y: Math.round(y) }];
  // A tree and a semicircle keep which way they face, and how they are tilted.
  const facing = f.kind === 'bush' ? undefined : f.facing;
  const turned = kind === 'bush' || f.kind === 'bush' ? {} : { rotation: f.rotation, tilt: f.tilt };
  let out: Fixture;
  if (kind === 'bush') out = { ...keep, points: at(bottom - height / 2), pattern: 'fill' };
  else if (kind === 'tree') out = { ...keep, points: at(bottom), height: Math.round(height), pattern: 'spiral', shape: f.kind === 'bush' ? 'sphere' : undefined, facing, ...turned };
  else out = { ...keep, points: at(bottom), height: Math.round(height), facing, ...turned };
  // Not set stays not set (as a saved layout has it).
  for (const k of Object.keys(out) as (keyof Fixture)[]) if (out[k] === undefined) delete out[k];
  return out;
}

/**
 * A tree's radius at height u (0 at the base, 1 at the top), as a share of its radius: a cone
 * narrows to a point (almost: the LEDs at the top sit just off the axis), a cylinder keeps its
 * width, a sphere (an ellipsoid when its height is not its width) is widest halfway up.
 */
export function treeWidthAt(shape: TreeShape | undefined, u: number): number {
  if (shape === 'cylinder') return 1;
  if (shape === 'sphere') return 2 * Math.sqrt(Math.max(0, u * (1 - u)));
  return 1 - u * 0.96;
}

/** The share of a ball's height (0 at its bottom) where the LEDs of its cap stop (see Fixture.cover). */
export const capFloor = (f: Pick<Fixture, 'shape' | 'cover'>) => (f.shape === 'sphere' && f.cover != null && f.cover < 180 ? (1 + Math.cos((Math.max(1, f.cover) * Math.PI) / 180)) / 2 : 0);

/**
 * The outline of a tree from the front, at its base: a triangle, a rectangle or an ellipse (for
 * a ball with LEDs on its top part only, that cap of it).
 */
export function treeOutline(f: Pick<Fixture, 'kind' | 'points' | 'radius' | 'height' | 'shape' | 'cover' | 'rotation' | 'tilt'>, plane: 'front' | 'side' = 'front'): Point3[] {
  const b = f.points[0] ?? { x: 0, y: 0 };
  const bz = pz(b);
  const { r, h } = treeSize(f);
  // Across: x in the front view, z (the depth) in the side view.
  const pt = (d: number, y: number): Point3 => (plane === 'side' ? { x: b.x, y, z: bz + d } : { x: b.x + d, y, z: bz });
  let flat: Point3[];
  if (f.shape === 'sphere') {
    // Round from the top: the cap's edge, over the top, to its other edge.
    const c = f.cover != null && f.cover < 180 ? (Math.max(1, f.cover) * Math.PI) / 180 : Math.PI;
    flat = Array.from({ length: 37 }, (_, i) => {
      const a = -c + (2 * c * i) / 36;
      return pt(Math.sin(a) * r, b.y - h / 2 - (Math.cos(a) * h) / 2);
    });
  } else {
    const top = f.shape === 'cylinder' ? [-r, r] : [0];
    flat = [pt(-r, b.y), ...top.map((d) => pt(d, b.y - h)), pt(r, b.y)];
  }
  return flat.map(tiltOf({ ...f, kind: 'tree' }));
}

/**
 * The LEDs of a tree, from the base point up. Angles start at its front (the street, unless it
 * is turned: `facing`) and grow counterclockwise as seen from above (`spin`: or clockwise).
 */
function treePixels(f: Fixture, n: number): Point3[] {
  const b = f.points[0] ?? { x: 0, y: 0 };
  const bz = pz(b);
  const { r, h } = treeSize(f);
  const face = ((f.facing ?? 0) * Math.PI) / 180;
  const sign = f.spin === 'cw' ? -1 : 1;
  const out: Point3[] = [];
  // u: 0 at the base, 1 at the top. Angle 0 is the front; going round counterclockwise as
  // seen from above (the street at the bottom), the LEDs move to the right as seen from the street.
  // A ball with LEDs on its top only: u runs over that cap (u0 to 1 of the ball's height).
  const u0 = capFloor(f);
  const span = 1 - u0;
  const at = (u: number, a: number): Point3 => {
    const ub = u0 + span * u;
    const rad = r * treeWidthAt(f.shape, ub);
    return { x: b.x + Math.sin(face + sign * a) * rad, y: b.y - ub * h, z: bz + Math.cos(face + sign * a) * rad };
  };
  const widthAt = (u: number) => treeWidthAt(f.shape, u0 + span * u);
  if (f.pattern === 'strands') {
    const s = Math.max(1, Math.min(n, Math.round(f.strands ?? 12)));
    const per = Math.floor(n / s);
    for (let i = 0; i < n; i++) {
      const k = Math.min(s - 1, Math.floor(i / Math.max(1, per)));
      const count = k === s - 1 ? n - per * (s - 1) : per;
      const j = i - k * per;
      const u = count > 1 ? j / (count - 1) : 0;
      // Zigzag: up the first strand, down the next.
      out.push(at(k % 2 === 0 ? u : 1 - u, (k / s) * Math.PI * 2));
    }
    return out;
  }
  // A wave goes left and right by its own sides: the way a spiral winds does not turn it round.
  if (f.pattern === 'wave') return wavePixels(f, n, (u, a) => at(u, sign * a), widthAt, h * span);
  const turns = f.turns ?? 8;
  const fromTop = f.start === 'top';
  // The loops sit evenly apart over the surface (up the side of a cone, over the curve of a
  // ball), or closer toward one end (bias): t (0 at the base, 1 at the top) is how far along the
  // loops, m how far up the surface, u the height.
  const up = surfaceToHeight(widthAt, r, h * span);
  const bend = biasCurve(f.bias ?? 0);
  // s: how far along the wire from LED 0. The angle grows along the wire from the front, so a
  // spiral from the top starts at the front too, and winds the way it is set as it comes down.
  const point = (s: number) => at(up(bend(fromTop ? 1 - s : s)), s * turns * Math.PI * 2);
  // A plain cone or cylinder: the wire's length is about proportional to its width there, and
  // these LEDs stay exactly where they always were.
  const plain = !u0 && !f.bias && (!f.shape || f.shape === 'cone' || f.shape === 'cylinder');
  if (plain) {
    const H = f.shape === 'cylinder' ? (x: number) => x : (x: number) => 1 - Math.sqrt(1 - x);
    return Array.from({ length: n }, (_, i) => {
      const s = n > 1 ? i / (n - 1) : 0;
      return point(fromTop ? 1 - H(1 - s) : H(s));
    });
  }
  return spreadAlong(point, n, Math.max(1024, Math.ceil(turns * 256)));
}

/** n points spread evenly by length along a curve point(s), s from 0 to 1, measured in K steps. */
function spreadAlong(point: (s: number) => Point3, n: number, K: number): Point3[] {
  const len = new Float64Array(K + 1);
  let prev = point(0);
  for (let k = 1; k <= K; k++) {
    const q = point(k / K);
    len[k] = len[k - 1] + Math.hypot(q.x - prev.x, q.y - prev.y, q.z - prev.z);
    prev = q;
  }
  const total = len[K];
  const out: Point3[] = [];
  let k = 0;
  for (let i = 0; i < n; i++) {
    const want = n > 1 ? (i / (n - 1)) * total : 0;
    while (k < K - 1 && len[k + 1] < want) k++;
    const span = len[k + 1] - len[k];
    out.push(point((k + (span > 0 ? Math.max(0, Math.min(1, (want - len[k]) / span)) : 0)) / K));
  }
  return out;
}

/** Bends 0..1 so steps bunch toward 1 (bias 1), toward 0 (bias -1), or stay even (0). */
function biasCurve(bias: number): (t: number) => number {
  const b = Math.max(-1, Math.min(1, bias));
  const q = 1 + 2 * Math.abs(b);
  if (Math.abs(b) < 1e-3) return (t) => t;
  return b > 0 ? (t) => 1 - Math.pow(1 - t, q) : (t) => Math.pow(t, q);
}

/**
 * For a tree's side (`widthAt`: its radius at height u as a share of `r`; `h`: its height): the
 * height u (0..1) at the share m (0..1) of the way up its surface, from the base to the top.
 */
function surfaceToHeight(widthAt: (u: number) => number, r: number, h: number): (m: number) => number {
  const K = 256;
  const len = new Float64Array(K + 1);
  for (let k = 1; k <= K; k++) len[k] = len[k - 1] + Math.hypot(r * (widthAt(k / K) - widthAt((k - 1) / K)), h / K);
  const total = len[K];
  return (m) => {
    if (!(total > 0)) return m;
    const want = Math.max(0, Math.min(1, m)) * total;
    let lo = 0;
    let hi = K;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      if (len[mid] < want) lo = mid;
      else hi = mid;
    }
    const span = len[hi] - len[lo];
    return (lo + (span > 0 ? (want - len[lo]) / span : 0)) / K;
  };
}

/** How far it is up a tree's side, over its surface from the base to the top (the LEDs' part of a ball), in layout units. */
export function treeSurfaceLength(f: Pick<Fixture, 'radius' | 'height' | 'shape' | 'cover'>): number {
  const { r, h } = treeSize(f);
  const u0 = capFloor(f);
  const span = 1 - u0;
  const K = 256;
  let len = 0;
  for (let k = 1; k <= K; k++) len += Math.hypot(r * (treeWidthAt(f.shape, u0 + (span * k) / K) - treeWidthAt(f.shape, u0 + (span * (k - 1)) / K)), (h * span) / K);
  return len;
}

/** n points spread evenly by length along a path given as many close points. */
function spreadEvenly(pts: Point3[], n: number): Point3[] {
  const len = new Float64Array(pts.length);
  for (let k = 1; k < pts.length; k++) len[k] = len[k - 1] + Math.hypot(pts[k].x - pts[k - 1].x, pts[k].y - pts[k - 1].y, pts[k].z - pts[k - 1].z);
  const total = len[pts.length - 1] ?? 0;
  const out: Point3[] = [];
  let k = 0;
  for (let i = 0; i < n; i++) {
    if (pts.length < 2) {
      out.push({ ...(pts[0] ?? { x: 0, y: 0, z: 0 }) });
      continue;
    }
    const want = n > 1 ? (i / (n - 1)) * total : 0;
    while (k < pts.length - 2 && len[k + 1] < want) k++;
    const span = len[k + 1] - len[k];
    const t = span > 0 ? Math.max(0, Math.min(1, (want - len[k]) / span)) : 0;
    const p = pts[k];
    const q = pts[k + 1];
    out.push({ x: p.x + (q.x - p.x) * t, y: p.y + (q.y - p.y) * t, z: p.z + (q.z - p.z) * t });
  }
  return out;
}

export const WAVE_SWEEP = 180;
const WAVE_PASSES = 8;

/**
 * A wave's passes: how many times it crosses the tree (from one side of its sweep to the other,
 * level), and the sides it starts and ends on. The passes are `spacing` apart, as near as can
 * be, from the base to the top: when the end side is set, one pass more or less ends it there.
 */
export function wavePasses(f: Pick<Fixture, 'height' | 'spacing' | 'startSide' | 'endSide' | 'shape' | 'cover'>): { passes: number; startSide: Side; endSide: Side } {
  // The height the passes share: a ball's cap when only its top has LEDs.
  const h = treeSize(f).h * (1 - capFloor(f));
  const startSide = f.startSide ?? 'left';
  const want = f.spacing && f.spacing > 0 ? h / f.spacing + 1 : WAVE_PASSES;
  let passes = Math.max(2, Math.min(200, Math.round(want)));
  // An even number of passes ends on the side it started on.
  const endsAt = (p: number): Side => (p % 2 === 0 ? startSide : startSide === 'left' ? 'right' : 'left');
  if (f.endSide && endsAt(passes) !== f.endSide) passes = passes === 2 || want > passes ? passes + 1 : passes - 1;
  return { passes, startSide, endSide: endsAt(passes) };
}

/**
 * The LEDs of a tree with a wave: the wire runs level across the tree's front (`sweep` degrees
 * of it), turns up in a round bend (a half circle, as wide as the passes are apart) and runs back,
 * like the bends of a river, from the base to the top (or the top down). The LEDs are spread
 * evenly along it. `at(u, a)`: the point at height u (0 to 1) and angle a from the front.
 */
function wavePixels(f: Fixture, n: number, at: (u: number, a: number) => Point3, widthAt: (u: number) => number, h: number): Point3[] {
  const { passes, startSide } = wavePasses(f);
  const { r } = treeSize(f);
  const half = ((Math.max(10, Math.min(360, f.sweep ?? WAVE_SWEEP)) / 2) * Math.PI) / 180;
  const sigma = startSide === 'right' ? 1 : -1;
  const du = 1 / (passes - 1);
  // The path in (angle, height): each pass level, each bend a half circle (in real lengths).
  const path: [number, number][] = [];
  const bend = (k: number) => {
    // The bend from pass k up to pass k + 1, on the side pass k ends on.
    const side = k % 2 === 0 ? -sigma : sigma;
    const uMid = (k + 0.5) * du;
    const width = Math.max(1e-3, r * widthAt(uMid));
    const ra = Math.min(half * 0.9, (h * du) / 2 / width);
    return { side, uMid, ra, center: side * (half - ra) };
  };
  const bends = Array.from({ length: passes - 1 }, (_, k) => bend(k));
  for (let k = 0; k < passes; k++) {
    const u = k * du;
    const from = k === 0 ? sigma * (k % 2 === 0 ? 1 : -1) * half : bends[k - 1].center;
    const to = k === passes - 1 ? (k % 2 === 0 ? -sigma : sigma) * half : bends[k].center;
    const steps = 32;
    for (let i = k === 0 ? 0 : 1; i <= steps; i++) path.push([from + ((to - from) * i) / steps, u]);
    if (k < passes - 1) {
      const b = bends[k];
      for (let i = 1; i < 24; i++) {
        const phi = -Math.PI / 2 + (Math.PI * i) / 24;
        path.push([b.center + b.side * b.ra * Math.cos(phi), b.uMid + (du / 2) * Math.sin(phi)]);
      }
    }
  }
  const fromTop = f.start === 'top';
  const pts = (fromTop ? [...path].reverse() : path).map(([a, u]) => at(u, a));
  return spreadEvenly(pts, n);
}


// ---------- Semicircles ----------

/**
 * The wire of a semicircle's zigzag, in layout units: x to the right, y up, (0, 0) the middle
 * of its straight edge, the round side up (before it is turned). One point at each end of each
 * row (or column).
 */
export function zigzagPath(f: Pick<Fixture, 'radius' | 'height' | 'strands' | 'zigzag'>): DesignPoint[] {
  const { r, h } = semicircleSize(f);
  const rows = Math.max(1, Math.min(64, Math.round(f.strands ?? 8)));
  const way = f.zigzag ?? 'down';
  const out: DesignPoint[] = [];
  for (let i = 0; i < rows; i++) {
    const t = (i + 0.5) / rows;
    // Every other row (or column) runs back the other way.
    const back = i % 2 === 1;
    if (way === 'down' || way === 'up') {
      const y = way === 'down' ? h * (1 - t) : h * t;
      const w = r * Math.sqrt(Math.max(0, 1 - (y / h) ** 2));
      out.push({ x: back ? w : -w, y }, { x: back ? -w : w, y });
    } else {
      const x = way === 'right' ? r * (2 * t - 1) : r * (1 - 2 * t);
      const top = h * Math.sqrt(Math.max(0, 1 - (x / r) ** 2));
      out.push({ x, y: back ? top : 0 }, { x, y: back ? 0 : top });
    }
  }
  return out;
}

/** From a semicircle's own layout units to the yard: turned and facing as the object is, at its point. */
const semicircleTransform = (f: Pick<Fixture, 'points' | 'rotation' | 'facing'>) => designTransform({ points: f.points, rotation: f.rotation, facing: f.facing }, 1);

/** The LEDs of a semicircle: spread evenly along its zigzag. */
function semicirclePixels(f: Fixture, n: number): Point3[] {
  return designLeds([{ points: zigzagPath(f) }], n).map(semicircleTransform(f));
}

/** The outline of a semicircle in the yard: over the round side, then back along the straight edge. */
export function semicircleOutline(f: Pick<Fixture, 'points' | 'radius' | 'height' | 'rotation' | 'facing' | 'tilt'>): Point3[] {
  const { r, h } = semicircleSize(f);
  const at = semicircleTransform(f);
  const tilt = tiltOf({ ...f, kind: 'semicircle' });
  const arc = Array.from({ length: 33 }, (_, i) => (i / 32) * Math.PI).map((a) => tilt(at({ x: -Math.cos(a) * r, y: Math.sin(a) * h })));
  return [...arc, arc[0]];
}

/** True for objects drawn by their wire (lines, custom objects and semicircles; see objectPaths), not as a circle or a tree. */
export const drawnByPaths = (f: { kind: FixtureKind }) => isLine(f) || f.kind === 'custom' || f.kind === 'semicircle';

/** The wire of an object drawn by its paths (see drawnByPaths), one path per stroke. Others: none. */
export function objectPaths(f: Fixture, scale = DEFAULT_SCALE): Point3[][] {
  if (isLine(f)) return [f.points.map(p3)];
  if (f.kind === 'custom') return designPaths(f, scale);
  if (f.kind === 'semicircle') return [semicircleOutline(f)];
  return [];
}

// ---------- Custom objects ----------

const strokePath = (s: DesignStroke) => (s.closed && s.points.length > 2 ? [...s.points, s.points[0]] : s.points);
const pathLength = (pts: DesignPoint[]) => pts.slice(1).reduce((a, p, i) => a + Math.hypot(p.x - pts[i].x, p.y - pts[i].y, (p.z ?? 0) - (pts[i].z ?? 0)), 0);

/** The length of wire with LEDs in a design, in meters. */
export const designLength = (strokes: DesignStroke[]) => strokes.reduce((a, s) => a + pathLength(strokePath(s)), 0);

/**
 * Where the n LEDs of a design sit (in meters, LED order). An exact stroke has one at each of
 * its points; the others are spread evenly along the other strokes, at one spacing: an open
 * stroke has an LED at each end, a closed one goes all round.
 */
export function designLeds(strokes: DesignStroke[], n: number): DesignPoint[] {
  const live = strokes.filter((s) => s.points.length > 0);
  if (n <= 0) return [];
  if (!live.length) return Array.from({ length: n }, () => ({ x: 0, y: 0 }));
  const closed = live.map((s) => !!s.closed && s.points.length > 2);
  const counts = designCounts(live, n);
  const out: DesignPoint[] = [];
  live.forEach((s, j) => {
    const c = counts[j];
    if (s.exact) {
      for (let i = 0; i < c; i++) out.push({ ...s.points[i] });
      return;
    }
    const path = strokePath(s);
    const deep = path.some((p) => p.z);
    for (let i = 0; i < c; i++) {
      const t = closed[j] ? i / c : c > 1 ? i / (c - 1) : 0.5;
      const p = along(path, t);
      out.push(deep ? { x: p.x, y: p.y, z: p.z } : { x: p.x, y: p.y });
    }
  });
  // An exact design with fewer points than LEDs: the rest wait at its last point.
  while (out.length < n) out.push({ ...(out.at(-1) ?? { x: 0, y: 0 }) });
  return out;
}

/**
 * How many of the n LEDs each stroke (with points) of a design gets: an exact stroke one per
 * point (in order, while there are LEDs left), the others share the rest by length.
 */
export function designCounts(strokes: DesignStroke[], n: number): number[] {
  const live = strokes.filter((s) => s.points.length > 0);
  if (!live.length || n <= 0) return live.map(() => 0);
  const counts = live.map(() => 0);
  let left = n;
  live.forEach((s, j) => {
    if (!s.exact) return;
    counts[j] = Math.min(left, s.points.length);
    left -= counts[j];
  });
  const even = live.map((s, j) => (s.exact ? -1 : j)).filter((j) => j >= 0);
  if (!even.length || left <= 0) return counts;
  const closed = even.map((j) => !!live[j].closed && live[j].points.length > 2);
  const lens = even.map((j) => pathLength(strokePath(live[j])));
  const total = lens.reduce((a, b) => a + b, 0);
  // One spacing for the whole design: open strokes have one more LED than gaps.
  const gaps = left - closed.filter((c) => !c).length;
  const ideal = gaps > 0 && total > 0 ? lens.map((l, k) => (l * gaps) / total + (closed[k] ? 0 : 1)) : lens.map((l) => (total > 0 ? (l * left) / total : left / even.length));
  // Whole numbers that add up: round down, then give the rest to the biggest remainders.
  const share = ideal.map(Math.floor);
  let more = left - share.reduce((a, b) => a + b, 0);
  const order = ideal.map((v, k) => [v - Math.floor(v), k] as const).sort((a, b) => b[0] - a[0]);
  for (let k = 0; more > 0; k = (k + 1) % order.length, more--) share[order[k][1]]++;
  even.forEach((j, k) => (counts[j] = share[k]));
  return counts;
}

/** From a design's meters to the yard: sized, turned and facing as the object is, at its point. */
export function designTransform(f: Pick<Fixture, 'points' | 'size' | 'rotation' | 'facing'>, scale = DEFAULT_SCALE): (p: DesignPoint) => Point3 {
  const c = f.points[0] ?? { x: 0, y: 0 };
  const cz = pz(c);
  const k = scale * (f.size && f.size > 0 ? f.size : 1);
  const r = ((f.rotation ?? 0) * Math.PI) / 180;
  const fa = ((f.facing ?? 0) * Math.PI) / 180;
  const cr = Math.cos(r);
  const sr = Math.sin(r);
  const cf = Math.cos(fa);
  const sf = Math.sin(fa);
  return (p) => {
    // Turned clockwise as seen from the front; y is up in the design, down in the yard.
    const u = (p.x * cr + p.y * sr) * k;
    const v = (-p.x * sr + p.y * cr) * k;
    // Its front faces the way it faces: toward the street at 0, to the right at 90.
    const w = (p.z ?? 0) * k;
    return { x: c.x + u * cf + w * sf, y: c.y - v, z: cz - u * sf + w * cf };
  };
}

/** The wire of a custom object in the yard, one path per stroke, for drawing its shape. */
export function designPaths(f: Fixture, scale = DEFAULT_SCALE): Point3[][] {
  const at = designTransform(f, scale);
  const tilt = tiltOf(f);
  return (f.design ?? []).filter((s) => s.points.length).map((s) => strokePath(s).map((p) => tilt(at(p))));
}

/** How far the design reaches from its anchor, in layout units. */
export function designReach(f: Fixture, scale = DEFAULT_SCALE): number {
  const k = scale * (f.size && f.size > 0 ? f.size : 1);
  let r = 0;
  for (const s of f.design ?? []) for (const p of s.points) r = Math.max(r, Math.hypot(p.x, p.y, p.z ?? 0));
  return r * k;
}

function segLengths(pts: Point[]) {
  return pts.slice(1).map((p, i) => Math.hypot(p.x - pts[i].x, p.y - pts[i].y, pz(p) - pz(pts[i])));
}

/** The point at fraction t (0..1) of the length of a polyline. */
function along(pts: Point[], t: number): Point3 {
  const seg = segLengths(pts);
  const total = seg.reduce((a, b) => a + b, 0);
  if (!total) return p3(pts[0]);
  let want = t * total;
  for (let i = 0; i < seg.length; i++) {
    if (want <= seg[i] || i === seg.length - 1) {
      const u = seg[i] ? Math.min(1, want / seg[i]) : 0;
      const a = pts[i];
      const b = pts[i + 1];
      return { x: a.x + (b.x - a.x) * u, y: a.y + (b.y - a.y) * u, z: pz(a) + (pz(b) - pz(a)) * u };
    }
    want -= seg[i];
  }
  return p3(pts.at(-1)!);
}

/** Points whose LED is fixed: the two ends and every valid pinned corner, in order. */
function anchorIndexes(f: Fixture): number[] {
  const last = f.points.length - 1;
  const n = Math.max(1, Math.floor(f.pixels));
  const out = [0];
  let prev = 0;
  for (let i = 1; i < last; i++) {
    const pin = f.pointLeds?.[i];
    // A pin must sit after the previous anchor and before the last LED; others are ignored.
    if (pin != null && Number.isInteger(pin) && pin > prev && pin < n - 1) {
      out.push(i);
      prev = pin;
    }
  }
  out.push(last);
  return out;
}

/**
 * The LEDs (offsets from the first point, inclusive) of segment k of a roof line. Segments do
 * not share LEDs: the LED at a corner is the first LED of the segment after it, and the segment
 * before it ends on the LED just before. Example: segment 1 is 0–49, segment 2 starts at 50.
 */
export function segmentLeds(f: Fixture, k: number): { lo: number; hi: number } {
  const offs = pointOffsets(f);
  const n = Math.max(1, Math.floor(f.pixels));
  const last = f.points.length - 2;
  return { lo: offs[k], hi: k >= last ? n - 1 : Math.max(offs[k], offs[k + 1] - 1) };
}

/** The length of each segment of a line, in layout units. */
export const lineLengths = (f: Pick<Fixture, 'points'>) => segLengths(f.points);

/**
 * Gives segment k of a line `count` LEDs, as when that stretch of the real string has more or
 * fewer LEDs than the drawing guessed. The LEDs after it move along (the line gets longer or
 * shorter); every corner keeps the LEDs it has now, so the other segments do not change.
 */
export function resizeSegment(f: Fixture, k: number, count: number): Pick<Fixture, 'pixels' | 'pointLeds'> {
  const last = f.points.length - 1;
  const { lo, hi } = segmentLeds(f, k);
  const delta = Math.max(1, Math.round(count)) - (hi - lo + 1);
  const pixels = Math.max(f.points.length - 1, Math.min(MAX_FIXTURE_PIXELS, f.pixels + delta));
  const d = pixels - f.pixels;
  const offs = pointOffsets(f);
  const pins = f.points.map((_, i) => (i === 0 || i === last ? null : i > k ? offs[i] + d : offs[i]));
  return { pixels, pointLeds: pins.some((p) => p != null) ? pins : undefined };
}

/**
 * For each LED of the object (from the first point): 1 when it is in use, 0 when it lies in a
 * skipped segment.
 */
export function activeLeds(f: Fixture): Uint8Array {
  const n = Math.max(0, Math.floor(f.pixels));
  if (!isLine(f) || !f.skip?.length || f.points.length < 2) return new Uint8Array(n).fill(1);
  const out = new Uint8Array(n);
  for (let k = 0; k < f.points.length - 1; k++) {
    if (f.skip.includes(k)) continue;
    const { lo, hi } = segmentLeds(f, k);
    for (let i = lo; i <= hi && i < n; i++) out[i] = 1;
  }
  return out;
}

/**
 * The part of the yard that games play on, set by an admin (Games page). Effects and scenes
 * still use every LED: this only keeps games off lights that are hidden, for example around a
 * corner of the house. Ids of objects that are not in the layout are ignored.
 */
export interface GameArea {
  /** Objects that games leave out (they stay dark during a game). */
  exclude?: string[];
  /** Lines and roofs: segments that games leave out, by object id (segment k: point k to k + 1). */
  skip?: Record<string, number[]>;
  /** Lines and roofs: how many LEDs games leave out at the first point's end and at the last point's end. */
  trim?: Record<string, [number, number]>;
}

/** For each LED of the object (from the first point): 1 when games use it. */
export function gameLeds(f: Fixture, area: GameArea | null | undefined): Uint8Array {
  const on = activeLeds(f);
  if (!area) return on;
  if (area.exclude?.includes(f.id)) return on.fill(0);
  if (!isLine(f)) return on;
  const skip = area.skip?.[f.id];
  if (skip?.length && f.points.length > 1) {
    for (const k of skip) {
      if (k < 0 || k >= f.points.length - 1) continue;
      const { lo, hi } = segmentLeds(f, k);
      for (let i = lo; i <= hi && i < on.length; i++) on[i] = 0;
    }
  }
  const [a, b] = area.trim?.[f.id] ?? [0, 0];
  for (let i = 0; i < Math.min(a, on.length); i++) on[i] = 0;
  for (let i = Math.max(0, on.length - b); i < on.length; i++) on[i] = 0;
  return on;
}

/** True when the area leaves something out. */
export const gameAreaSet = (a: GameArea | null | undefined) =>
  !!a && (!!a.exclude?.length || Object.values(a.skip ?? {}).some((x) => x.length) || Object.values(a.trim ?? {}).some(([x, y]) => x > 0 || y > 0));

/**
 * Moves segment effects to new segment indexes after the points changed. `to(k)` gives the
 * new index (or indexes) of old segment k; none drops it. When two land on one segment, the
 * first one wins.
 */
export function mapSegmentEffects(fx: Fixture['segmentEffects'], to: (k: number) => number[]): Fixture['segmentEffects'] {
  if (!fx) return fx;
  const out: Record<string, EffectSettings> = {};
  const keys = Object.keys(fx)
    .map(Number)
    .sort((a, b) => a - b);
  for (const k of keys) for (const j of to(k)) if (j >= 0 && !(j in out)) out[j] = fx[k];
  return Object.keys(out).length ? out : undefined;
}

/** Where the segments go when a point is inserted inside segment k: k becomes two (both keep its effect). */
export const segmentsAfterInsert = (k: number) => (s: number) => (s < k ? [s] : s === k ? [k, k + 1] : [s + 1]);
/** Where the segments go when inner point i is removed: segments i - 1 and i become one. */
export const segmentsAfterRemove = (i: number) => (s: number) => (s < i ? [s] : s === i ? [i - 1] : [s - 1]);

/** Segment indexes after inserting a point inside segment k: k becomes two segments. */
export function skipAfterInsert(skip: number[] | undefined, k: number): number[] | undefined {
  if (!skip?.length) return skip;
  const out = skip.flatMap((s) => (s < k ? [s] : s === k ? [k, k + 1] : [s + 1]));
  return out.length ? out : undefined;
}

/** Segment indexes after removing inner point i: segments i - 1 and i become one (off only if both were off). */
export function skipAfterRemove(skip: number[] | undefined, i: number): number[] | undefined {
  if (!skip?.length) return skip;
  const out: number[] = [];
  for (const s of skip) {
    if (s < i - 1) out.push(s);
    else if (s === i - 1 && skip.includes(i)) out.push(i - 1);
    else if (s > i) out.push(s - 1);
  }
  return out.length ? out : undefined;
}

/** The LED offset (within the object, from the first point) at each point of a roof line. */
export function pointOffsets(f: Fixture): number[] {
  const pts = f.points;
  const n = Math.max(1, Math.floor(f.pixels));
  const out = new Array<number>(pts.length).fill(0);
  if (pts.length < 2) return out;
  const anchors = anchorIndexes(f);
  const seg = segLengths(pts);
  for (let k = 0; k < anchors.length - 1; k++) {
    const pa = anchors[k];
    const pb = anchors[k + 1];
    const la = k === 0 ? 0 : (f.pointLeds![pa] as number);
    const lb = k === anchors.length - 2 ? n - 1 : (f.pointLeds![pb] as number);
    out[pa] = la;
    out[pb] = lb;
    const total = seg.slice(pa, pb).reduce((a, b) => a + b, 0) || 1;
    let acc = 0;
    for (let i = pa + 1; i < pb; i++) {
      acc += seg[i - 1];
      out[i] = Math.round(la + (acc / total) * (lb - la));
    }
  }
  return out;
}

/** True when the point's LED is pinned (and valid), not spread evenly. */
export function isPinned(f: Fixture, index: number): boolean {
  return index > 0 && index < f.points.length - 1 && anchorIndexes(f).includes(index);
}

/** LED offsets (within the object) at the corners of a roof line. */
export function cornerPixels(f: Fixture): number[] {
  if (!isLine(f) || f.points.length < 3) return [];
  return pointOffsets(f).slice(1, -1);
}

// ---------- LED numbers on the device ----------

/** The device's LED number for LED i of the object (i counts from the first point). */
export function deviceLed(f: Fixture, i: number): number {
  return f.reversed ? f.startPixel + f.pixels - 1 - i : f.startPixel + i;
}

/** Device LED numbers at the first and the last point of the object. */
export function ledRange(f: Fixture): { first: number; last: number } {
  return { first: deviceLed(f, 0), last: deviceLed(f, f.pixels - 1) };
}

/** The stored fields for an object that runs from device LED `first` to device LED `last`. */
export function fromLedRange(first: number, last: number): Pick<Fixture, 'startPixel' | 'pixels' | 'reversed'> {
  return { startPixel: Math.min(first, last), pixels: Math.abs(last - first) + 1, reversed: last < first };
}

/**
 * Sets the device LED number at one point of a roof line, for editing one segment at a time.
 * Point 0 and the last point change the object's first and last LED; an inner point is pinned.
 * Pinned points, and the points in `lock` (pinned at their current numbers first), keep their
 * device LED numbers, so the other segments stay where they are on the lights.
 */
export function setPointLed(f: Fixture, index: number, led: number, lock: number[] = []): Pick<Fixture, 'startPixel' | 'pixels' | 'reversed' | 'pointLeds'> {
  const lastPoint = f.points.length - 1;
  const offs = pointOffsets(f);
  const pinned: (number | null)[] = f.points.map((_, i) => (i > 0 && i < lastPoint && (isPinned(f, i) || lock.includes(i)) ? deviceLed(f, offs[i]) : null));
  let first = deviceLed(f, 0);
  let last = deviceLed(f, f.pixels - 1);
  if (index <= 0) first = led;
  else if (index >= lastPoint) last = led;
  else pinned[index] = led;
  const range = fromLedRange(first, last);
  const g = { ...f, ...range };
  const toOffset = (d: number) => (g.reversed ? g.startPixel + g.pixels - 1 - d : d - g.startPixel);
  const pointLeds = pinned.map((d) => (d == null ? null : toOffset(d)));
  return { ...range, pixels: Math.min(MAX_FIXTURE_PIXELS, range.pixels), pointLeds: pointLeds.some((p) => p != null && p > 0) ? pointLeds.map((p) => (p != null && p > 0 ? p : null)) : undefined };
}

// ---------- Matching a drawn line to the real lights ----------

/**
 * The "match to the lights" wizard: one LED blinks red on the house, you move it to the real
 * start, corner or end of the line, and that point takes its LED. Offsets count from the first
 * point of the object as it is now, and can lie outside it: the start or the end can move out.
 */
export interface MatchProbe {
  /** The point being matched (0: the start, the last point: the end). */
  point: number;
  /** The LED that blinks, as an offset from the first point. */
  offset: number;
}

/**
 * The offsets the blinking LED can take for one point, so the points stay in order with at
 * least one LED in each segment. The start stays before the next pinned corner; a corner stays
 * after the point before it (later corners give way, see matchPoint); the end stays after the
 * last pinned corner. Device LED numbers never go below 0, nor past the last LED the device
 * has (`ledCount`, as set in WLED, when known), and the line stays within MAX_FIXTURE_PIXELS.
 */
export function matchRange(f: Fixture, point: number, ledCount?: number | null): { lo: number; hi: number } {
  const L = f.points.length - 1;
  const n = Math.max(1, Math.floor(f.pixels));
  const offs = pointOffsets(f);
  const anchors = anchorIndexes(f);
  const before = [...anchors].reverse().find((a) => a < point) ?? 0;
  const after = anchors.find((a) => a > point) ?? L;
  let lo: number;
  let hi: number;
  if (point <= 0) {
    lo = n - MAX_FIXTURE_PIXELS;
    hi = offs[after] - after;
  } else if (point >= L) {
    lo = offs[before] + (L - before);
    hi = MAX_FIXTURE_PIXELS - 1;
  } else {
    lo = offs[before] + (point - before);
    hi = n - 1 - (L - point);
  }
  // Device LED 0 is as far as it goes one way, the device's last LED the other way.
  if (f.reversed) hi = Math.min(hi, f.startPixel + n - 1);
  else lo = Math.max(lo, -f.startPixel);
  if (ledCount && ledCount > 0) {
    if (f.reversed) lo = Math.max(lo, f.startPixel + n - ledCount);
    else hi = Math.min(hi, ledCount - 1 - f.startPixel);
  }
  return { lo, hi: Math.max(lo, hi) };
}

/**
 * Gives a point of a line the LED at `offset` (see MatchProbe): the start or the end moves
 * there, a corner is pinned there. Every other pinned corner keeps its device LED number,
 * except later corners the new pin passes: they are unpinned, to be matched next.
 */
export function matchPoint(f: Fixture, point: number, offset: number, ledCount?: number | null): Pick<Fixture, 'startPixel' | 'pixels' | 'reversed' | 'pointLeds'> {
  const L = f.points.length - 1;
  const { lo, hi } = matchRange(f, point, ledCount);
  const o = Math.min(hi, Math.max(lo, Math.round(offset)));
  let g = f;
  if (point > 0 && point < L && f.pointLeds) {
    const pins = f.pointLeds.map((p, i) => (i > point && p != null && p <= o + (i - point) - 1 ? null : p));
    g = { ...f, pointLeds: pins };
  }
  return setPointLed(g, point, deviceLed(g, o));
}

/**
 * Paints the wizard's view: the matched line dim blue, the stretch from the point before up to
 * the blinking LED brighter (so you can follow it along the roof), and the blinking LED red.
 * Other objects stay dark. `put` can get LEDs outside the object (see MatchProbe).
 */
export function paintMatch(
  layout: Layout,
  selected: string,
  probe: MatchProbe,
  pulse: boolean,
  put: (fixtureIndex: number, led: number, rgb: [number, number, number]) => void
) {
  const scale = (c: [number, number, number], k: number): [number, number, number] => [Math.round(c[0] * k), Math.round(c[1] * k), Math.round(c[2] * k)];
  layout.fixtures.forEach((f, fi) => {
    const n = Math.max(0, Math.floor(f.pixels));
    if (f.id !== selected) {
      for (let i = 0; i < n; i++) put(fi, i, [0, 0, 0]);
      return;
    }
    const from = probe.point > 0 ? pointOffsets(f)[probe.point - 1] : probe.offset;
    const a = Math.min(from, probe.offset);
    const b = Math.max(from, probe.offset);
    for (let i = Math.min(0, a); i < Math.max(n, b + 1); i++) put(fi, i, i >= a && i <= b ? scale(SELECTED_RGB, 0.45) : i >= 0 && i < n ? scale(SELECTED_RGB, 0.08) : [0, 0, 0]);
    put(fi, probe.offset, pulse ? LAST_LED_RGB : [0, 0, 0]);
  });
}

/**
 * Limits a new LED number for one point of a roof line, so the points stay in order: every
 * segment keeps at least one LED, no segment can cross the one before or after it, and the
 * line keeps its direction. Point 0 and the last point move only away from their neighbour.
 */
export function clampPointLed(f: Fixture, index: number, led: number): number {
  const lastPoint = f.points.length - 1;
  const n = Math.max(1, Math.floor(f.pixels));
  const offs = pointOffsets(f);
  // Work in offsets from the first point, where the order is always ascending.
  const toOffset = (d: number) => (f.reversed ? f.startPixel + n - 1 - d : d - f.startPixel);
  let lo = index <= 0 ? -Infinity : offs[index - 1] + 1;
  let hi = index >= lastPoint ? Infinity : offs[index + 1] - 1;
  // The last point sits after the last corner, with at least one LED between them.
  if (index >= lastPoint && lastPoint > 0) lo = offs[lastPoint - 1] + 1;
  // Device LED numbers cannot go below 0.
  if (f.reversed) hi = Math.min(hi, toOffset(0));
  else lo = Math.max(lo, toOffset(0));
  const o = Math.min(hi, Math.max(lo, toOffset(led)));
  return deviceLed(f, o);
}

/**
 * Adds points to one end of a line, as when you continue drawing from that end. The new
 * segments get LEDs at the same spacing as the line has now, and the LEDs already placed keep
 * their device LED numbers: the point where the new part joins is pinned. The device numbers
 * grow away from the old end. `shifted` is true when that would go below LED 0, so the numbers
 * start at 0 instead.
 */
export function extendLine(f: Fixture, at: 'first' | 'last', added: Point[]): { patch: Pick<Fixture, 'points' | 'pixels' | 'startPixel' | 'pointLeds' | 'skip' | 'segmentEffects'>; shifted: boolean } {
  const n = Math.max(1, Math.floor(f.pixels));
  const oldLen = segLengths(f.points).reduce((a, b) => a + b, 0);
  // LED steps per layout unit. A line with no length yet: one LED per 10 units.
  const density = oldLen > 0 && n > 1 ? (n - 1) / oldLen : 0.1;
  const join = at === 'last' ? f.points[f.points.length - 1] : f.points[0];
  const chain = [join, ...added];
  const steps = segLengths(chain).map((len) => Math.max(1, Math.round(len * density)));
  const add = steps.reduce((a, b) => a + b, 0);
  const offs = pointOffsets(f);
  const oldPins = f.points.map((_, i) => (isPinned(f, i) ? offs[i] : null));
  let points: Point[];
  let pins: (number | null)[];
  let skip = f.skip;
  let segmentEffects = f.segmentEffects;
  if (at === 'last') {
    points = [...f.points, ...added];
    pins = [...oldPins, ...added.map(() => null)];
    pins[f.points.length - 1] = n - 1;
  } else {
    points = [...[...added].reverse(), ...f.points];
    pins = [...added.map(() => null), ...oldPins.map((p) => (p == null ? null : p + add))];
    pins[added.length] = add;
    skip = f.skip?.map((k) => k + added.length);
    segmentEffects = mapSegmentEffects(f.segmentEffects, (k) => [k + added.length]);
  }
  const pixels = Math.min(MAX_FIXTURE_PIXELS, n + add);
  // Keep the old LEDs' device numbers: the start moves down when the numbers grow toward it.
  const growsDown = (at === 'last') === f.reversed;
  let startPixel = growsDown ? f.startPixel - (pixels - n) : f.startPixel;
  const shifted = startPixel < 0;
  if (shifted) startPixel = 0;
  const last = points.length - 1;
  const pointLeds = pins.map((p, i) => (i === 0 || i === last || p == null ? null : p));
  return { patch: { points, pixels, startPixel, pointLeds: pointLeds.some((p) => p != null) ? pointLeds : undefined, skip, segmentEffects }, shifted };
}

/** The point on a line at a fraction t (0..1) of segment k, with depth. */
export function pointOnSegment(f: Fixture, k: number, t: number): Point {
  const a = f.points[k];
  const b = f.points[k + 1] ?? a;
  return { x: Math.round(a.x + (b.x - a.x) * t), y: Math.round(a.y + (b.y - a.y) * t), z: Math.round(pz(a) + (pz(b) - pz(a)) * t) };
}

/** Inserts a point inside segment k. Pins and skipped segments stay with their points. */
export function insertPoint(f: Fixture, k: number, p: Point): Pick<Fixture, 'points' | 'pointLeds' | 'skip' | 'segmentEffects'> {
  const points = [...f.points];
  points.splice(k + 1, 0, p);
  const pins = f.pointLeds ? [...f.pointLeds] : undefined;
  pins?.splice(k + 1, 0, null);
  return { points, pointLeds: pins, skip: skipAfterInsert(f.skip, k), segmentEffects: mapSegmentEffects(f.segmentEffects, segmentsAfterInsert(k)) };
}

export interface DeviceRun {
  fixtureId: string;
  /** Lowest and highest device LED numbers the object uses. */
  lo: number;
  hi: number;
}

/** For each device: the LED runs the objects use, in LED order, and the runs that overlap. */
export function deviceRuns(layout: Layout): Map<string, { runs: DeviceRun[]; overlaps: [DeviceRun, DeviceRun][] }> {
  const out = new Map<string, { runs: DeviceRun[]; overlaps: [DeviceRun, DeviceRun][] }>();
  for (const f of layout.fixtures) {
    if (!f.deviceId) continue;
    const e = out.get(f.deviceId) ?? { runs: [], overlaps: [] };
    e.runs.push({ fixtureId: f.id, lo: f.startPixel, hi: f.startPixel + f.pixels - 1 });
    out.set(f.deviceId, e);
  }
  for (const e of out.values()) {
    e.runs.sort((a, b) => a.lo - b.lo);
    for (let i = 0; i < e.runs.length; i++) {
      for (let j = i + 1; j < e.runs.length && e.runs[j].lo <= e.runs[i].hi; j++) e.overlaps.push([e.runs[i], e.runs[j]]);
    }
  }
  return out;
}

export interface StageFixture {
  id: string;
  name: string;
  kind: FixtureKind;
  /** Index of this object's first LED in the stage frame. */
  offset: number;
  count: number;
  /** Roof and line: LED offsets (within the object) at the corners. */
  corners: number[];
  center: Point3;
}

/** Everything a game needs to know about the yard. Frames list every LED of every object, in order. */
export interface Stage {
  width: number;
  height: number;
  pixelCount: number;
  /** x, y of each LED: the front view. */
  positions: Float32Array;
  /** x, y, z of each LED (see Point), in layout units. */
  positions3: Float32Array;
  /** Layout units per meter. */
  scale: number;
  /** The y of the ground. */
  groundY: number;
  fixtures: StageFixture[];
  /**
   * Every roof LED, as stage indexes, in the order of the strip: all roof objects joined
   * end to end. Objects on the same device follow its LED numbers, so the gaps between
   * runs are skipped. Games that run along "the roof" use this.
   */
  roofPath: Int32Array;
  /** Positions in roofPath at the corners and where one roof object joins the next. */
  roofCorners: number[];
  /** 1 for each stage LED in use, 0 for LEDs in skipped segments (they stay dark). */
  active: Uint8Array;
}

/**
 * The LEDs of the layout, in one list. With a game area: the stage that games play on. It has
 * the same LEDs at the same places (so frames go to the lights the same way), but the LEDs left
 * out are not active, the roof path skips them, and objects left out are not in `fixtures`.
 */
export function buildStage(layout: Layout, area?: GameArea | null): Stage {
  const fixtures: StageFixture[] = [];
  const pos: number[] = [];
  const pos3: number[] = [];
  const active: number[] = [];
  const scale = layoutScale(layout);
  for (const f of layout.fixtures) {
    const pts = fixturePixels(f, scale);
    const offset = pos.length / 2;
    for (const p of pts) {
      pos.push(p.x, p.y);
      pos3.push(p.x, p.y, p.z);
    }
    const on = gameLeds(f, area);
    for (let i = 0; i < pts.length; i++) active.push(on[i] ?? 1);
    const mean = (k: 'x' | 'y' | 'z') => pts.reduce((a, p) => a + p[k], 0) / (pts.length || 1);
    fixtures.push({ id: f.id, name: f.name, kind: f.kind, offset, count: pts.length, corners: cornerPixels(f), center: { x: mean('x'), y: mean('y'), z: mean('z') } });
  }
  const activeMask = Uint8Array.from(active);
  const { path, corners } = roofPath(layout, fixtures, activeMask);
  return {
    width: layout.width,
    height: layout.height,
    pixelCount: pos.length / 2,
    positions: new Float32Array(pos),
    positions3: new Float32Array(pos3),
    scale: layoutScale(layout),
    groundY: layoutGround(layout),
    fixtures: area?.exclude?.length ? fixtures.filter((f) => !area.exclude!.includes(f.id)) : fixtures,
    roofPath: path,
    roofCorners: corners,
    active: activeMask
  };
}

function roofPath(layout: Layout, stageFixtures: StageFixture[], active: Uint8Array) {
  const roofs = layout.fixtures.map((f, i) => ({ f, s: stageFixtures[i] })).filter((r) => r.f.kind === 'roof');
  // Group by device, in the order each device first appears; sort each group by LED number.
  const groups = new Map<string, typeof roofs>();
  for (const r of roofs) {
    const key = r.f.deviceId ?? `sim:${r.f.id}`;
    groups.set(key, [...(groups.get(key) ?? []), r]);
  }
  const path: number[] = [];
  const corners: number[] = [];
  for (const g of groups.values()) {
    g.sort((a, b) => a.f.startPixel - b.f.startPixel);
    for (const { f, s } of g) {
      if (path.length) corners.push(path.length);
      // Strip order is ascending LED number; a reversed object runs against its drawn order.
      // LEDs in skipped segments are left out; where they were, the path has a join (a corner).
      const at = new Map<number, number>();
      let skipped = false;
      for (let j = 0; j < s.count; j++) {
        const i = f.reversed ? s.count - 1 - j : j;
        if (!active[s.offset + i]) {
          skipped = true;
          continue;
        }
        if (skipped && path.length) corners.push(path.length);
        skipped = false;
        at.set(i, path.length);
        path.push(s.offset + i);
      }
      for (const c of s.corners) if (at.has(c)) corners.push(at.get(c)!);
    }
  }
  return { path: Int32Array.from(path), corners: [...new Set(corners)].sort((a, b) => a - b) };
}

/**
 * The roof as games play on it: a track measured in the front view (as the house looks from the
 * street), not in LEDs. Something that moves along it at a steady speed moves evenly across the
 * front of the house, whatever the LEDs do behind it:
 *   - a stretch at an angle to the street is shorter on the track, as it looks shorter;
 *   - where the roof line runs away from the street (back along the side of the house), or runs
 *     behind other roof LEDs (at the same spot of the front view, further back), it cannot be
 *     seen from the street: the track still runs through it, lit as usual, but very quickly, so
 *     from the street the motion does not stop at the corner. It is never faster than
 *     MAX_SPEEDUP times the LEDs a second of a stretch that faces the street, so it shows as a
 *     quick streak, not one flash.
 * So hidden stretches need no leaving out on the Games page.
 */
export interface RoofTrack {
  /** The track's length, in steps. A step is about one LED of a stretch that faces the street. */
  n: number;
  /** Layout units of the front view per step. */
  step: number;
  /** Stage index of each roof LED, in strip order (the stage's roofPath). */
  leds: Int32Array;
  /** Per roof LED: its place on the track, in steps (0 to n - 1, never decreasing). */
  at: Float32Array;
  /** Per roof LED: 1 when it cannot be seen from the street (the track hurries through it). */
  hidden: Uint8Array;
  /** Per step: the point of the front view. */
  x: Float32Array;
  y: Float32Array;
  /** Steps at the corners, and where one roof object (or a left-out stretch) joins the next. */
  corners: number[];
}

/** Front-view length per real length below which a stretch counts as edge-on (hidden). */
const EDGE_ON = 0.35;
/** How many times faster (in LEDs a second) the track runs through a hidden stretch, at most. */
export const MAX_SPEEDUP = 6;

const median = (a: number[]) => {
  if (!a.length) return 0;
  const s = [...a].sort((p, q) => p - q);
  return s[Math.floor(s.length / 2)];
};

export function roofTrack(stage: Pick<Stage, 'roofPath' | 'roofCorners' | 'positions3' | 'scale'>): RoofTrack {
  const leds = stage.roofPath;
  const m = leds.length;
  const P = stage.positions3;
  const X = (k: number) => P[leds[k] * 3];
  const Y = (k: number) => P[leds[k] * 3 + 1];
  const Z = (k: number) => P[leds[k] * 3 + 2];
  // Between each LED and the next: the front-view distance and the real one.
  const front = new Float32Array(Math.max(0, m - 1));
  const real = new Float32Array(Math.max(0, m - 1));
  for (let k = 0; k < m - 1; k++) {
    front[k] = Math.hypot(X(k + 1) - X(k), Y(k + 1) - Y(k));
    real[k] = Math.hypot(front[k], Z(k + 1) - Z(k));
  }
  const spacing = median(Array.from(real).filter((d) => d > 1e-6)) || 1;
  // A jump much longer than an LED's spacing is a join (between objects, or over a left-out stretch).
  const joined = (k: number) => real[k] > spacing * 3 || real[k] <= 1e-6;
  // Edge-on: both stretches beside the LED run nearly straight away from the street, so a
  // corner between a front stretch and a side stretch still shows.
  const hidden = new Uint8Array(m);
  for (let k = 0; k < m; k++) {
    let facing = -1;
    for (const p of [k - 1, k]) if (p >= 0 && p < m - 1 && !joined(p)) facing = Math.max(facing, front[p] / real[p]);
    if (facing >= 0 && facing < EDGE_ON) hidden[k] = 1;
  }
  // The step: the front-view spacing of LEDs on stretches that face the street.
  const faced: number[] = [];
  for (let k = 0; k < m - 1; k++) if (!joined(k) && front[k] >= real[k] * 0.7) faced.push(front[k]);
  const step = median(faced) || median(Array.from(front).filter((d) => d > 1e-6)) || spacing;
  // Behind: another LED that shows sits at the same spot of the front view, nearer the street.
  const near = step * 0.9;
  const depth = (stage.scale || 1) * 0.3;
  const grid = new Map<string, number[]>();
  const cell = (x: number, y: number) => `${Math.floor(x / near)},${Math.floor(y / near)}`;
  for (let k = 0; k < m; k++) {
    if (hidden[k]) continue;
    const key = cell(X(k), Y(k));
    const list = grid.get(key);
    if (list) list.push(k);
    else grid.set(key, [k]);
  }
  const behind = new Uint8Array(m);
  for (let k = 0; k < m; k++) {
    const cx = Math.floor(X(k) / near);
    const cy = Math.floor(Y(k) / near);
    search: for (let i = cx - 1; i <= cx + 1; i++) {
      for (let j = cy - 1; j <= cy + 1; j++) {
        for (const o of grid.get(`${i},${j}`) ?? []) {
          if (Z(o) > Z(k) + depth && (X(o) - X(k)) ** 2 + (Y(o) - Y(k)) ** 2 < near * near) {
            behind[k] = 1;
            break search;
          }
        }
      }
    }
  }
  for (let k = 0; k < m; k++) if (behind[k]) hidden[k] = 1;
  // Places on the track: front-view length, but at least 1 / MAX_SPEEDUP of a step per LED, and
  // exactly that where the roof cannot be seen. Joins take none.
  const least = step / MAX_SPEEDUP;
  const at = new Float32Array(m);
  for (let k = 1; k < m; k++) at[k] = at[k - 1] + (joined(k - 1) ? 0 : hidden[k - 1] || hidden[k] ? least : Math.max(least, front[k - 1]));
  const length = m ? at[m - 1] : 0;
  const n = !m ? 0 : length > 0 ? Math.max(2, Math.round(length / step) + 1) : 1;
  for (let k = 0; k < m; k++) at[k] = length > 0 ? (at[k] / length) * (n - 1) : 0;
  // The front-view point at each step: between the LEDs on either side of it.
  const x = new Float32Array(n);
  const y = new Float32Array(n);
  let k = 0;
  for (let i = 0; i < n; i++) {
    while (k < m - 2 && at[k + 1] <= i) k++;
    const j = Math.min(m - 1, k + 1);
    const t = at[j] > at[k] ? Math.max(0, Math.min(1, (i - at[k]) / (at[j] - at[k]))) : 1;
    x[i] = X(k) + (X(j) - X(k)) * t;
    y[i] = Y(k) + (Y(j) - Y(k)) * t;
  }
  const corners = [...new Set(stage.roofCorners.filter((c) => c < m).map((c) => Math.round(at[c])))].sort((a, b) => a - b);
  return { n, step: n > 1 ? length / (n - 1) : step, leds, at, hidden, x, y, corners };
}

/** Game sessions shown on the play page. */
export interface GameInfo {
  id: string;
  name: string;
  description: string;
  /** For the game picker, for example "1 player" or "1–2 players". */
  players?: string;
}

/** The big button's color on the play screen. */
export type ButtonTone = 'go' | 'good' | 'bad' | 'calm' | 'wait';

/**
 * One of a row of buttons on the phone, for games with more than one (see GameStatus.controls).
 * Its press and release reach the game with this id.
 */
export interface GameControl {
  /** Sent with the input: 'main' is the big button's job (start, fire); games name the others. */
  id: string;
  label: string;
  /** A CSS color: the button's fill (for example the color it picks). Not set: the tone's colors. */
  color?: string;
  /** Keyboard keys (KeyboardEvent.code) that work as this button. */
  keys?: string[];
  /** Larger than the others (the middle button of a row). */
  big?: boolean;
}

/**
 * A choice the player makes before a game (difficulty, number of colors), shown on the phone as
 * a row of choices on the start and game-over screens. A tap sends the setting's id and the value.
 */
export interface GameSetting {
  id: string;
  label: string;
  value: string;
  choices: { value: string; label: string }[];
}

/** A button id (or a setting's id or value) the server accepts: short, lowercase letters and digits. */
export const CONTROL_ID = /^[a-z0-9]{1,16}$/;

export interface GameStatus {
  game: string | null;
  /**
   * False: someone else has the turn, so this phone watches (see LineView). Not set: it plays.
   */
  canPlay?: boolean;
  /** This phone's view of the line for the lights (who plays now, its place, its turn). */
  line?: LineView;
  phase: string;
  /** Short text for the play screen, for example "Tap to start!". */
  message: string;
  score: number;
  lives: number | null;
  goal: number | null;
  players: number;
  /** Debug mode: names of the real WLED devices that show the game too. Empty: simulator only. */
  realLights?: string[];
  /** The big button's label. Not set: GO! or STOP!, by phase. */
  button?: string;
  /** The big button's color. Not set: by phase. */
  tone?: ButtonTone;
  /** How far along the player is (for example orbs popped of the target). Shown instead of score of goal. */
  progress?: { value: number; max: number };
  /** Short facts under the message, for example Level 3 or Best 120. */
  stats?: { label: string; value: string | number }[];
  /** Team scores, for games with sides. Colors are CSS colors. */
  scores?: { name: string; color: string; value: number }[];
  /** This player's side in a game with sides (each phone gets its own). */
  you?: { name: string; color: string } | null;
  /**
   * A row of buttons in place of the one big button, left to right (for example: change color
   * left, fire, change color right). Not set: the big button (id 'main').
   */
  controls?: GameControl[];
  /** Under the buttons on a computer: which keys to use, for example "← → to change, space to fire". */
  keysHint?: string;
  /** Choices for the next game (on the start and game-over screens). */
  settings?: GameSetting[];
  /** The game's high scores (on the start and game-over screens). */
  scoreboard?: Scoreboard;
  /** An arcade score display while playing (Beat Drop): it takes the place of score and stats. */
  arcade?: ArcadeHud;
  /** Light Painter: the phone shows the paint box and the yard to paint on (see paint.ts). */
  paint?: PaintPad;
  /** Whack-a-Mole: the phone shows the holes to whack, and the arcade's marquee (see MoleBoard). */
  moles?: MoleBoard;
  /** The last game's score made the board: the phone asks for initials. */
  enterInitials?: { id: number; rank: number; score: number; refused?: boolean };
}

/** A game's arcade score display: the score, the multiplier and how close the next one is. */
export interface ArcadeHud {
  score: number;
  best: number;
  mult: number;
  maxMult: number;
  /** Hits toward the next step of the multiplier, of perStep (all of them at the top). */
  charge: number;
  perStep: number;
  /** Hits in a row. */
  streak: number;
  /** The latest judgment, numbered so the phone can pop each new one. */
  judged: { n: number; text: string; kind: 'perfect' | 'good' | 'held' | 'miss' | 'stray' } | null;
  /** Times the multiplier climbed, and was lost, this game: a new count is a celebration (or a crash). */
  ups: number;
  drops: number;
  /** Small facts in the corner, for example the speed and the stage. */
  info: { label: string; value: string | number }[];
}

/**
 * Whack-a-Mole on the phone: one hole per bush or tree of the yard (or stretch of roof), left to
 * right as seen from the street. A tap on a hole sends a press with the hole's id as the button.
 */
export interface MoleBoard {
  holes: MoleHole[];
  /** Whole seconds left in the round, and how long a round is. */
  timeLeft: number;
  duration: number;
  /** Big over the holes before a round: "3", "2", "1", "GO!". */
  countdown?: string | null;
  /** The points multiplier now (1 to 4), and whacks in a row. */
  mult: number;
  streak: number;
  best: number;
  /** Moles whacked this round, and moles that got away. */
  hits: number;
  missed: number;
}

export interface MoleHole {
  /** The button id its press sends: h0, h1… */
  id: string;
  /** The hole's own color (CSS), the color it glows in the yard. */
  color: string;
  kind: 'bush' | 'tree' | 'roof';
  /** What is in it now: nothing, a mole (a golden one is worth more), a whacked one, one that got away. */
  state: 'empty' | 'up' | 'gold' | 'hit' | 'miss';
  /** Counts the moles that came up in this hole, so the phone animates each new one. */
  n: number;
  /** The last whack's points, for the "+20" that pops off the hole. */
  points: number;
}

/** An arcade high-score table: the best scores of one game (and its settings), with initials. */
export interface Scoreboard {
  title: string;
  entries: { id: number; rank: number; initials: string; score: number }[];
  /** The line just named, to light up. */
  fresh?: number;
}

/** Debug mode state: games sent to the real lights. */
export interface OutputInfo {
  enabled: boolean;
  /** 0.05..1, applied to every frame sent to the lights. */
  brightness: number;
  /** True while the layout editor shows its preview; game frames wait. */
  paused: boolean;
  framesSent: number;
  devices: { id: string; name: string; host: string; ddpPort: number; online: boolean; mappedLeds: number; objects: string[]; link: { mode: 'checking' | 'udp' | 'http'; note: string } | null }[];
  /** Objects with no device: they show in the simulator only. */
  simulationOnly: string[];
}

// ---------- Editor colors (the same on the simulator and the real lights) ----------

/** The selected object glows this color, so it stands out from everything else. */
export const SELECTED_RGB: [number, number, number] = [40, 170, 255];
export const FIRST_LED_RGB: [number, number, number] = [0, 255, 0];
export const LAST_LED_RGB: [number, number, number] = [255, 0, 0];
export const CORNER_RGB: [number, number, number] = [255, 150, 0];

/**
 * Whether the selected ends are bright now. It follows the wall clock (on for 0.5 s, off for
 * 0.5 s), so the editor's drawing and the real lights pulse together.
 */
export const editorPulse = (nowMs: number) => Math.floor(nowMs / 500) % 2 === 0;

/** The Games page's colors: what each part of the yard is in a game (see server/src/game/kit.ts). */
export const GAME_ROLE_RGB: Record<FixtureKind, [number, number, number]> = {
  roof: [255, 196, 110],
  bush: [40, 220, 110],
  tree: [30, 200, 180],
  line: [150, 110, 255],
  semicircle: [150, 110, 255],
  custom: [150, 110, 255]
};
/** LEDs that games leave out. */
export const GAME_OUT_RGB: [number, number, number] = [70, 0, 0];
/** Roof LEDs that cannot be seen from the street, which games hurry through (see roofTrack). */
export const GAME_UNSEEN_RGB: [number, number, number] = [40, 48, 70];

let hiddenCache: { layout: Layout; area: string; key: string; hidden: Map<string, Uint8Array> } | null = null;

/**
 * A text that changes when the yard's shape or its LEDs change (where they are, how many, which
 * device and LED numbers), and not when only effects or names do. Caches of things built from a
 * layout (a Stage, its device maps) key on it, as editors send a new layout object each time.
 */
export function layoutShapeKey(layout: Layout): string {
  return JSON.stringify([layout.width, layout.height, layout.scale, layout.groundY, layout.fixtures.map(({ effect: _e, segmentEffects: _s, name: _n, locked: _l, ...f }) => f)]);
}

/**
 * For each roof object: 1 for each LED (from the first point) that cannot be seen from the
 * street, as games see it (see roofTrack).
 */
export function roofHidden(layout: Layout, area: GameArea | null | undefined): Map<string, Uint8Array> {
  // The Games page sends its layout with every change (a new object each time): a new object
  // with the same shape does not build the stage again.
  const areaKey = JSON.stringify(area ?? null);
  if (hiddenCache?.layout === layout && hiddenCache.area === areaKey) return hiddenCache.hidden;
  const key = areaKey + layoutShapeKey(layout);
  if (hiddenCache?.key === key) {
    hiddenCache.layout = layout;
    hiddenCache.area = areaKey;
    return hiddenCache.hidden;
  }
  const stage = buildStage(layout, area);
  const track = roofTrack(stage);
  const byLed = new Uint8Array(stage.pixelCount);
  for (let k = 0; k < track.leds.length; k++) byLed[track.leds[k]] = track.hidden[k];
  const hidden = new Map<string, Uint8Array>();
  for (const f of stage.fixtures) if (f.kind === 'roof') hidden.set(f.id, byLed.slice(f.offset, f.offset + f.count));
  hiddenCache = { layout, area: areaKey, key, hidden };
  return hidden;
}

/**
 * The Games page's view of the yard: the LEDs games use in the color of their part (roof, bush,
 * tree, the rest), roof LEDs that cannot be seen from the street gray-blue, the ones left out
 * faint red, skipped ones dark. `focus` (an object, or one of its segments) is brighter, and
 * blinks with `pulse`, so it can be found on the house.
 */
export function paintGameArea(
  layout: Layout,
  area: GameArea | null,
  focus: { id: string; segment: number | null } | null,
  pulse: boolean,
  put: (fixtureIndex: number, led: number, rgb: [number, number, number]) => void
) {
  const k = (c: [number, number, number], m: number): [number, number, number] => [Math.round(c[0] * m), Math.round(c[1] * m), Math.round(c[2] * m)];
  const unseen = roofHidden(layout, area);
  layout.fixtures.forEach((f, fi) => {
    const n = Math.max(0, Math.floor(f.pixels));
    if (!n) return;
    const lit = activeLeds(f);
    const game = gameLeds(f, area);
    const hid = unseen.get(f.id);
    const seg = focus?.id === f.id && focus.segment != null && isLine(f) ? segmentLeds(f, focus.segment) : null;
    const dim = focus && focus.id !== f.id ? 0.35 : 1;
    for (let i = 0; i < n; i++) {
      if (!lit[i]) {
        put(fi, i, [0, 0, 0]);
        continue;
      }
      const focused = focus?.id === f.id && (!seg || (i >= seg.lo && i <= seg.hi));
      const base = !game[i] ? GAME_OUT_RGB : hid?.[i] ? GAME_UNSEEN_RGB : GAME_ROLE_RGB[f.kind];
      put(fi, i, focused ? (pulse ? k(base, game[i] ? 1 : 3) : k(base, game[i] ? 0.45 : 1.5)) : k(base, (game[i] ? 0.55 : 1) * dim));
    }
  });
}

/**
 * Paints the layout editor's view: the selected object in bright blue with its first LED green,
 * its last LED red and its corners amber (the ends pulse, so they are easy to spot), and the
 * other objects dim in their own colors. With nothing selected, every object shows its color.
 * `put(fixtureIndex, ledIndex, rgb)` receives each LED; ledIndex counts from the first point.
 */
export function paintEditor(
  layout: Layout,
  selected: string | null,
  corner: number | null,
  segment: number | null,
  pulse: boolean,
  put: (fixtureIndex: number, led: number, rgb: [number, number, number]) => void
) {
  const anySelected = layout.fixtures.some((f) => f.id === selected);
  const scale = (c: [number, number, number], k: number): [number, number, number] => [Math.round(c[0] * k), Math.round(c[1] * k), Math.round(c[2] * k)];
  layout.fixtures.forEach((f, fi) => {
    const n = Math.max(0, Math.floor(f.pixels));
    if (!n) return;
    const on = activeLeds(f);
    if (f.id !== selected) {
      const c = fixtureColor(fi, anySelected ? 0.07 : 0.35);
      for (let i = 0; i < n; i++) put(fi, i, on[i] ? c : [0, 0, 0]);
      return;
    }
    // One segment of a roof line selected: only that segment glows; its ends are green and red.
    if (isLine(f) && segment != null && segment >= 0 && segment < f.points.length - 1) {
      const offs = pointOffsets(f);
      const { lo: a, hi: b } = segmentLeds(f, segment);
      // A skipped segment still shows while selected (dimmer), so you can find it.
      const segOn = !f.skip?.includes(segment);
      for (let i = 0; i < n; i++) put(fi, i, i >= a && i <= b ? (segOn ? SELECTED_RGB : scale(SELECTED_RGB, 0.3)) : on[i] ? scale(SELECTED_RGB, 0.1) : [0, 0, 0]);
      for (let k = 1; k < f.points.length - 1; k++) if (k !== segment && k !== segment + 1 && on[offs[k]]) put(fi, offs[k], scale(CORNER_RGB, 0.4));
      put(fi, a, pulse ? FIRST_LED_RGB : scale(FIRST_LED_RGB, 0.35));
      put(fi, b, pulse ? LAST_LED_RGB : scale(LAST_LED_RGB, 0.35));
      return;
    }
    for (let i = 0; i < n; i++) put(fi, i, on[i] ? SELECTED_RGB : [0, 0, 0]);
    if (isLine(f)) {
      const offs = pointOffsets(f);
      for (let k = 1; k < f.points.length - 1; k++) put(fi, offs[k], k === corner && !pulse ? scale(CORNER_RGB, 0.3) : CORNER_RGB);
    }
    // Ends never go dark, so you can always see where they are; they pulse to catch the eye.
    put(fi, 0, pulse ? FIRST_LED_RGB : scale(FIRST_LED_RGB, 0.35));
    if (n > 1) put(fi, n - 1, pulse ? LAST_LED_RGB : scale(LAST_LED_RGB, 0.35));
  });
}
