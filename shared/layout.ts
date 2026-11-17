// The yard layout: the physical light objects (roofline, bushes) drawn over a picture of
// the house, and where each LED of each object sits. Shared by the server (games) and the
// web client (editor and simulator), so both agree on every pixel's position.

/**
 * roof: the roofline, a line of LEDs that games use as "the roof".
 * line: any other line of LEDs (windows, doors, a fence, a path); edited like a roof line.
 * bush: LEDs spread over a dome.
 * tree: a cone, with LEDs in a spiral or in strands from the base to the top.
 */
export type FixtureKind = 'roof' | 'line' | 'bush' | 'tree';
/** Bush: fill, ring, spiral. Tree: spiral, strands. */
export type FixturePattern = 'fill' | 'ring' | 'spiral' | 'strands';
export type Units = 'ft' | 'm';

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

export interface Fixture {
  id: string;
  name: string;
  kind: FixtureKind;
  /** Roof and line: the polyline from the first LED to the last; inner points are corners. Bush: [center]. Tree: [center of the base]. */
  points: Point[];
  /** Bush and tree: radius in layout units (tree: at the base). */
  radius?: number;
  /** Tree only: height from the base to the top, in layout units. */
  height?: number;
  /** Bush and tree: how the LEDs are spread over the object. */
  pattern?: FixturePattern;
  /** Tree with a spiral: how many times the LEDs go around from the base to the top. */
  turns?: number;
  /** Tree with strands: the number of strands. They zigzag: up the first, down the second, and so on. */
  strands?: number;
  /** Number of LEDs. */
  pixels: number;
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

/** Positions of the LEDs of one object, in LED order (LED 0 first), in 3D. */
export function fixturePixels(f: Fixture): Point3[] {
  const n = Math.max(0, Math.floor(f.pixels));
  if (n === 0) return [];
  if (f.kind === 'tree') return treePixels(f, n);
  if (f.kind === 'bush') {
    const c = f.points[0] ?? { x: 0, y: 0 };
    const cz = pz(c);
    const r = f.radius ?? 60;
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
      out.push({ x: c.x + Math.cos(a) * d, y: c.y + Math.sin(a) * d * 0.72, z: cz + Math.sqrt(1 - k * k) * r * 0.75 });
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

/** The LEDs of a tree: a cone from the base point up. */
function treePixels(f: Fixture, n: number): Point3[] {
  const b = f.points[0] ?? { x: 0, y: 0 };
  const bz = pz(b);
  const r = f.radius ?? 80;
  const h = f.height ?? 240;
  const out: Point3[] = [];
  // u: 0 at the base, 1 at the top. The angle starts at the front (toward the street).
  const at = (u: number, a: number): Point3 => {
    const rad = r * (1 - u * 0.96);
    return { x: b.x + Math.sin(a) * rad, y: b.y - u * h, z: bz + Math.cos(a) * rad };
  };
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
  const turns = f.turns ?? 8;
  for (let i = 0; i < n; i++) {
    const s = n > 1 ? i / (n - 1) : 0;
    // The wire is longer near the base, where the cone is wide: spread the LEDs by length.
    const u = 1 - Math.sqrt(1 - s);
    out.push(at(u, u * turns * Math.PI * 2));
  }
  return out;
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

export function buildStage(layout: Layout): Stage {
  const fixtures: StageFixture[] = [];
  const pos: number[] = [];
  const pos3: number[] = [];
  const active: number[] = [];
  for (const f of layout.fixtures) {
    const pts = fixturePixels(f);
    const offset = pos.length / 2;
    for (const p of pts) {
      pos.push(p.x, p.y);
      pos3.push(p.x, p.y, p.z);
    }
    const on = activeLeds(f);
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
    fixtures,
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

/** Game sessions shown on the play page. */
export interface GameInfo {
  id: string;
  name: string;
  description: string;
}

export interface GameStatus {
  game: string | null;
  phase: string;
  /** Short text for the play screen, for example "Tap to start!". */
  message: string;
  score: number;
  lives: number | null;
  goal: number | null;
  players: number;
  /** Debug mode: names of the real WLED devices that show the game too. Empty: simulator only. */
  realLights?: string[];
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
