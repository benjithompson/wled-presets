// Shared pieces for the games: the parts of the yard and what each one is for, colors that mean
// the same thing in every game, and light that travels through the whole yard: sparks that slide
// along the roof under gravity, drops and rockets that pass the windows on their way, and
// shockwaves that sweep over every LED.
//
// Every game gives the parts of the yard the same jobs, so a player who knows one game can read
// the next one:
//   roof:  where the game is played.
//   bushes: containers: what you have won (or, in Overflow, what you fill).
//   trees: meters that fill from the base up (progress, a rally's heat).
//   decor (other lines and custom objects: windows, doors, a fence, a star): the house reacting.
//     They catch the color of every explosion, like windows lit by fireworks, and glow warmer
//     with a combo.
// Any of them can be missing; a game still plays on a roof alone.

import { roofTrack, type RoofTrack, type Stage, type StageFixture } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';

/** Colors with the same meaning in every game. */
export const COLORS = {
  /** Points and success. */
  gold: [1, 0.68, 0.12] as Rgb,
  /** A mistake, a lost life. */
  bad: [1, 0.04, 0.02] as Rgb,
  /** "Your turn": a soft blue-white. */
  hint: [0.55, 0.7, 1] as Rgb,
  fire: [1, 0.28, 0.02] as Rgb,
  ice: [0.05, 0.55, 1] as Rgb
};

/** A CSS hex color for the phone. */
export const css = (c: Rgb) => '#' + c.map((v) => Math.round(Math.min(1, Math.max(0, v)) * 255).toString(16).padStart(2, '0')).join('');

export const scale = (c: Rgb, k: number): Rgb => [c[0] * k, c[1] * k, c[2] * k];

/** A temperature scale for meters: dark red, orange, yellow, white hot, at 0..1. */
export function heat(t: number): Rgb {
  const k = Math.max(0, Math.min(1, t));
  if (k < 0.33) return mix([0.5, 0.02, 0], [1, 0.3, 0], k / 0.33);
  if (k < 0.66) return mix([1, 0.3, 0], [1, 0.8, 0.1], (k - 0.33) / 0.33);
  return mix([1, 0.8, 0.1], WHITE, (k - 0.66) / 0.34);
}

/** One light object, with each LED's place within it. */
export interface Part {
  fixture: StageFixture;
  offset: number;
  count: number;
  /** Front view, in layout units. */
  x: number;
  top: number;
  bottom: number;
  left: number;
  right: number;
  /** Per LED: 0 at the lowest LED, 1 at the highest (as seen from the street). */
  up: Float32Array;
  /** Per LED: -1 at the left edge, 1 at the right. */
  across: Float32Array;
  /** LED indexes (within the part) from the lowest to the highest. */
  bottomUp: number[];
}

function makePart(stage: Stage, f: StageFixture): Part {
  const up = new Float32Array(f.count);
  const across = new Float32Array(f.count);
  let top = Infinity;
  let bottom = -Infinity;
  let left = Infinity;
  let right = -Infinity;
  for (let i = 0; i < f.count; i++) {
    const x = stage.positions[(f.offset + i) * 2];
    const y = stage.positions[(f.offset + i) * 2 + 1];
    top = Math.min(top, y);
    bottom = Math.max(bottom, y);
    left = Math.min(left, x);
    right = Math.max(right, x);
  }
  const h = Math.max(1e-6, bottom - top);
  const w = Math.max(1e-6, right - left);
  for (let i = 0; i < f.count; i++) {
    up[i] = (bottom - stage.positions[(f.offset + i) * 2 + 1]) / h;
    across[i] = ((stage.positions[(f.offset + i) * 2] - left) / w) * 2 - 1;
  }
  const bottomUp = Array.from({ length: f.count }, (_, i) => i).sort((a, b) => up[a] - up[b]);
  return { fixture: f, offset: f.offset, count: f.count, x: (left + right) / 2, top, bottom, left, right, up, across, bottomUp };
}

/** Where light goes: one stage LED, a color and an amount. */
export type Sink = (i: number, color: Rgb, amount: number) => void;

/**
 * "The roof": every roof object joined in strip order, as a track measured in the front view
 * (see roofTrack). Positions are steps along the track, from 0 to n - 1: something that moves
 * at a steady speed moves evenly across the front of the house, and runs very quickly through
 * stretches that cannot be seen from the street (back along the side, behind another part).
 */
export class Roof {
  /** The track's length, in steps (about one LED of a stretch that faces the street). */
  readonly n: number;
  readonly track: RoofTrack;
  /** Per step: the front-view point. */
  readonly x: Float32Array;
  readonly y: Float32Array;
  /**
   * Per step: the sine of the roof's slope toward higher positions, as seen from the street.
   * Positive: the roof climbs as the position grows; negative: it falls. Gravity pulls a ball
   * along the roof by -g * slope.
   */
  readonly slope: Float32Array;
  readonly corners: number[];
  /** True when position 0 is at the left of the house (as seen from the street). */
  readonly startsLeft: boolean;
  /** Per step: 1 where every roof LED near it cannot be seen from the street. */
  readonly hidden: Uint8Array;
  /** The roof LEDs (indexes into track.leds) nearest each step: bucket i is first[i] to first[i + 1]. */
  private first: Int32Array;
  private bucket: Int32Array;

  constructor(stage: Stage) {
    const track = roofTrack(stage);
    this.track = track;
    const n = (this.n = track.n);
    this.x = track.x;
    this.y = track.y;
    this.corners = track.corners;
    this.slope = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      const a = Math.max(0, i - 2);
      const b = Math.min(n - 1, i + 2);
      const d = Math.hypot(this.x[b] - this.x[a], this.y[b] - this.y[a]);
      // y grows downward, so a climb has a smaller y ahead. Where the track hurries through a
      // hidden stretch, the front view hardly moves: flat.
      this.slope[i] = d > track.step * 0.2 ? Math.max(-1, Math.min(1, (this.y[a] - this.y[b]) / d)) : 0;
    }
    this.startsLeft = n < 2 || this.x[0] <= this.x[n - 1];
    // The LEDs by the step they are nearest.
    const m = track.leds.length;
    this.first = new Int32Array(n + 1);
    const step = (k: number) => Math.max(0, Math.min(n - 1, Math.round(track.at[k])));
    for (let k = 0; k < m; k++) this.first[step(k) + 1]++;
    for (let i = 0; i < n; i++) this.first[i + 1] += this.first[i];
    this.bucket = new Int32Array(m);
    const fill = this.first.slice(0, n);
    for (let k = 0; k < m; k++) this.bucket[fill[step(k)]++] = k;
    this.hidden = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      let all = this.first[i + 1] > this.first[i];
      for (let b = this.first[i]; b < this.first[i + 1] && all; b++) all = !!track.hidden[this.bucket[b]];
      this.hidden[i] = all ? 1 : 0;
    }
  }

  /** True where the roof cannot be seen from the street: no place for a target. */
  hiddenAt(pos: number) {
    return !!this.hidden[Math.max(0, Math.min(this.n - 1, Math.round(pos)))];
  }

  /** The slope at a fractional position. */
  slopeAt(pos: number) {
    const i = Math.max(0, Math.min(this.n - 1, Math.round(pos)));
    return this.slope[i] ?? 0;
  }

  /** The front-view point at a fractional position. */
  point(pos: number): { x: number; y: number } {
    if (!this.n) return { x: 0, y: 0 };
    const p = Math.max(0, Math.min(this.n - 1, pos));
    const i = Math.floor(p);
    const j = Math.min(this.n - 1, i + 1);
    const t = p - i;
    return { x: this.x[i] + (this.x[j] - this.x[i]) * t, y: this.y[i] + (this.y[j] - this.y[i]) * t };
  }

  /**
   * The roof position right above a front-view x (the highest one where the roof doubles back),
   * where it can be seen from the street.
   */
  above(x: number): number {
    let best = 0;
    let score = Infinity;
    for (let i = 0; i < this.n; i++) {
      const s = Math.abs(this.x[i] - x) + this.y[i] * 1e-3 + (this.hidden[i] ? 1e6 : 0);
      if (s < score) {
        score = s;
        best = i;
      }
    }
    return best;
  }

  /** Lights the LEDs of one step of the track. */
  at(put: Sink, pos: number, color: Rgb, amount = 1) {
    const i = Math.round(pos);
    if (amount <= 0 || i < 0 || i >= this.n) return;
    const { leds } = this.track;
    for (let b = this.first[i]; b < this.first[i + 1]; b++) put(leds[this.bucket[b]], color, amount);
  }

  /** A soft dot at a fractional position: each LED near it by its own place on the track. */
  splat(put: Sink, pos: number, color: Rgb, width = 1.5, amount = 1, reach = 2.5) {
    if (amount <= 0 || !this.n) return;
    const lo = Math.max(0, Math.floor(pos - width * reach));
    const hi = Math.min(this.n - 1, Math.ceil(pos + width * reach));
    const { leds, at } = this.track;
    for (let b = this.first[lo]; b < this.first[hi + 1]; b++) {
      const k = this.bucket[b];
      const d = (at[k] - pos) / width;
      put(leds[k], color, Math.exp(-d * d) * amount);
    }
  }
}

/** The yard as the games see it: the roof, and each other object by what it is for. */
export class Yard {
  readonly stage: Stage;
  readonly roof: Roof;
  /** Left to right. */
  readonly bushes: Part[];
  readonly trees: Part[];
  /** Other lines (windows, doors, a fence, a path) and custom objects (stars, wreaths…). */
  readonly decor: Part[];
  /** The middle of the house, as seen from the street. */
  readonly middle: number;
  readonly ground: number;
  /** The LEDs that are in use (not in a skipped segment). */
  readonly lit: Int32Array;
  private grid = new Map<number, number[]>();
  private out: Frame | null = null;
  private static CELL = 48;

  constructor(stage: Stage) {
    this.stage = stage;
    this.roof = new Roof(stage);
    const parts = stage.fixtures.filter((f) => f.count > 0).map((f) => makePart(stage, f));
    const byX = (a: Part, b: Part) => a.x - b.x;
    this.bushes = parts.filter((p) => p.fixture.kind === 'bush').sort(byX);
    this.trees = parts.filter((p) => p.fixture.kind === 'tree').sort(byX);
    this.decor = parts.filter((p) => p.fixture.kind === 'line' || p.fixture.kind === 'custom').sort(byX);
    const roofXs = Array.from(this.roof.x);
    this.middle = roofXs.length ? (Math.min(...roofXs) + Math.max(...roofXs)) / 2 : stage.width / 2;
    this.ground = stage.groundY;
    const lit: number[] = [];
    for (let i = 0; i < stage.pixelCount; i++) {
      if (!stage.active[i]) continue;
      lit.push(i);
      const key = this.cell(stage.positions[i * 2], stage.positions[i * 2 + 1]);
      const list = this.grid.get(key);
      if (list) list.push(i);
      else this.grid.set(key, [i]);
    }
    this.lit = Int32Array.from(lit);
  }

  private cell(x: number, y: number) {
    return (Math.floor(x / Yard.CELL) + 1000) * 4096 + Math.floor(y / Yard.CELL) + 1000;
  }

  /** Starts a frame: clears it; everything below draws into it. */
  begin(frame: Frame) {
    this.out = frame;
    frame.clear();
  }

  /** Adds light to one stage LED (skipped LEDs stay dark). */
  add(i: number, color: Rgb, amount = 1) {
    if (amount <= 0 || !this.stage.active[i]) return;
    this.out?.add(i, color, amount);
  }

  /** Straight into the frame: for the roof track, whose LEDs are all in use. */
  private put: Sink = (i, color, amount) => this.out?.add(i, color, amount);

  /** A soft light at a point of the front view: every LED within `radius` catches some of it. */
  glow(x: number, y: number, radius: number, color: Rgb, amount = 1) {
    if (amount <= 0) return;
    const c = Yard.CELL;
    const pos = this.stage.positions;
    for (let cx = Math.floor((x - radius) / c); cx <= Math.floor((x + radius) / c); cx++) {
      for (let cy = Math.floor((y - radius) / c); cy <= Math.floor((y + radius) / c); cy++) {
        const list = this.grid.get((cx + 1000) * 4096 + cy + 1000);
        if (!list) continue;
        for (const i of list) {
          const d2 = ((pos[i * 2] - x) ** 2 + (pos[i * 2 + 1] - y) ** 2) / (radius * radius);
          if (d2 < 1) this.out?.add(i, color, amount * (1 - d2) * (1 - d2));
        }
      }
    }
  }

  /** A ring of light at distance r from a point: one frame of a shockwave through the yard. */
  ring(x: number, y: number, r: number, width: number, color: Rgb, amount = 1) {
    const pos = this.stage.positions;
    // Only LEDs within 2.5 widths of the ring light up: test the squared distance first.
    const inner = r - 2.5 * width;
    const in2 = inner > 0 ? inner * inner : -1;
    const out2 = (r + 2.5 * width) ** 2;
    for (const i of this.lit) {
      const dx = pos[i * 2] - x;
      const dy = pos[i * 2 + 1] - y;
      const d2 = dx * dx + dy * dy;
      if (d2 <= in2 || d2 >= out2) continue;
      const d = (Math.sqrt(d2) - r) / width;
      if (d > -2.5 && d < 2.5) this.out?.add(i, color, amount * Math.exp(-d * d));
    }
  }

  /** The same light on every LED of the yard. */
  wash(color: Rgb, amount = 1) {
    for (const i of this.lit) this.out?.add(i, color, amount);
  }

  fill(part: Part, color: Rgb, amount = 1) {
    for (let i = 0; i < part.count; i++) this.add(part.offset + i, color, amount);
  }

  /** One step of the roof track, by position along the roof. */
  roofAt(pos: number, color: Rgb, amount = 1) {
    this.roof.at(this.put, pos, color, amount);
  }

  /** A soft dot on the roof at a fractional position. */
  roofSplat(pos: number, color: Rgb, width = 1.5, amount = 1) {
    this.roof.splat(this.put, pos, color, width, amount);
  }

  /** The point of the front view at the top of a part, where a rocket leaves from. */
  topOf(p: Part) {
    return { x: p.x, y: p.top };
  }

  /** The part whose middle is nearest to a front-view x. */
  nearest(parts: Part[], x: number): Part | null {
    let best: Part | null = null;
    for (const p of parts) if (!best || Math.abs(p.x - x) < Math.abs(best.x - x)) best = p;
    return best;
  }
}

// ---------- Motion and timing on the roof ----------

/** Moves a position `step` along the roof in direction `dir` (1 or -1), bouncing off both ends. */
export function bounce(pos: number, dir: number, step: number, n: number): { pos: number; dir: number } {
  const end = n - 1;
  const p = pos + dir * step;
  if (p >= end) return { pos: 2 * end - p, dir: -1 };
  if (p <= 0) return { pos: -p, dir: 1 };
  return { pos: p, dir };
}

/**
 * What happened over the last moments, by time (where the comet was). A press arrives late,
 * after Wi-Fi, so games judge it by what the player saw then, not by where things are now.
 */
export class Recent<T> {
  private list: { t: number; v: T }[] = [];
  private keep: number;

  /** Keeps `keep` seconds. */
  constructor(keep: number) {
    this.keep = keep;
  }

  push(t: number, v: T) {
    this.list.push({ t, v });
    let old = 0;
    while (old < this.list.length && t - this.list[old].t > this.keep) old++;
    if (old) this.list.splice(0, old);
  }

  /** The values from time t on, oldest first. */
  since(t: number): T[] {
    return this.list.filter((e) => e.t >= t).map((e) => e.v);
  }

  /** The value at time t: the last one at or before it. */
  at(t: number): T | undefined {
    for (let i = this.list.length - 1; i >= 0; i--) if (this.list[i].t <= t) return this.list[i].v;
    return undefined;
  }

  get latest(): T | undefined {
    return this.list.at(-1)?.v;
  }

  clear() {
    this.list.length = 0;
  }
}

/** The light a fast thing leaves on the roof: a soft head, fading behind it. */
export class Trail {
  /** Per roof step: how bright, 0..1. */
  readonly level: Float32Array;
  /** Per roof step: whose light it is (a team, for its color). */
  readonly tag: Uint8Array;

  constructor(n: number) {
    this.level = new Float32Array(n);
    this.tag = new Uint8Array(n);
  }

  /** Fades by `rate` per second. */
  fade(dt: number, rate: number) {
    const k = Math.exp(-dt * rate);
    for (let i = 0; i < this.level.length; i++) this.level[i] *= k;
  }

  /** The head, at a position between steps: it lights the two steps on each side. */
  mark(pos: number, tag = 0) {
    const n = this.level.length;
    const lo = Math.max(0, Math.floor(pos - 2));
    const hi = Math.min(n - 1, Math.ceil(pos + 2));
    for (let i = lo; i <= hi; i++) {
      const v = Math.exp(-((i - pos) ** 2) / 1.5);
      if (v > this.level[i]) {
        this.level[i] = v;
        this.tag[i] = tag;
      }
    }
  }

  /** Draws every step brighter than `min`, at `gain` times its level. */
  draw(yard: Yard, color: (level: number, tag: number) => Rgb, gain = 1, min = 0.01) {
    for (let i = 0; i < this.level.length; i++) {
      const v = this.level[i];
      if (v > min) yard.roofAt(i, color(v, this.tag[i]), v * gain);
    }
  }

  clear() {
    this.level.fill(0);
  }
}

// ---------- Sparks on the roof ----------

interface Spark {
  pos: number;
  vel: number;
  color: Rgb;
  life: number;
  max: number;
}

/** Sparks that fly along the roof, slide down its slopes and burn out. */
export class Sparks {
  private list: Spark[] = [];
  private roof: Roof;
  private gravity: number;
  private drag: number;

  /** Gravity, in LEDs per second²; drag, per second. */
  constructor(roof: Roof, gravity = 0, drag = 1.8) {
    this.roof = roof;
    this.gravity = gravity;
    this.drag = drag;
  }

  burst(pos: number, colors: Rgb[], count: number, power: number, life = 1) {
    for (let i = 0; i < count; i++) {
      const max = life * (0.5 + Math.random() * 0.9);
      this.list.push({ pos, vel: (Math.random() - 0.5) * 2 * power * (0.25 + Math.random()), color: colors[i % colors.length], life: max, max });
    }
  }

  get count() {
    return this.list.length;
  }

  update(dt: number) {
    const k = Math.exp(-dt * this.drag);
    for (let i = this.list.length - 1; i >= 0; i--) {
      const s = this.list[i];
      s.life -= dt;
      s.vel = s.vel * k - this.gravity * this.roof.slopeAt(s.pos) * dt;
      s.pos += s.vel * dt;
      if (s.life <= 0 || s.pos < 0 || s.pos > this.roof.n - 1) this.list.splice(i, 1);
    }
  }

  draw(yard: Yard) {
    for (const s of this.list) {
      const age = 1 - s.life / s.max;
      // White hot at first, then the spark's own color, then a flicker as it burns out.
      const c = age < 0.15 ? mix(WHITE, s.color, age / 0.15) : s.color;
      const flicker = age > 0.6 ? 0.6 + 0.4 * Math.random() : 1;
      yard.roofSplat(s.pos, c, 0.9, (s.life / s.max) ** 0.8 * flicker);
    }
  }

  clear() {
    this.list.length = 0;
  }
}

// ---------- Light that travels through the yard ----------

interface Mote {
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: Rgb;
  size: number;
  life: number;
  /** Stops when it falls below this y (front view); then calls land. */
  floor: number;
  land?: () => void;
}

interface Flight {
  ax: number;
  ay: number;
  cx: number;
  cy: number;
  bx: number;
  by: number;
  t: number;
  duration: number;
  color: Rgb;
  size: number;
  arrive?: () => void;
}

/**
 * Points of light that move through the front view of the yard: falling drops (with gravity) and
 * flights along an arc from one place to another. They light whatever LEDs they pass: a drop
 * from the gutter to a bush lights the window it falls past.
 */
export class Motes {
  private motes: Mote[] = [];
  private flights: Flight[] = [];
  /** Gravity, in layout units per second² (about 9.8 m/s² at the layout's scale). */
  readonly gravity: number;

  private yard: Yard;

  constructor(yard: Yard) {
    this.yard = yard;
    this.gravity = yard.stage.scale * 9.8;
  }

  drop(x: number, y: number, color: Rgb, opts: { vx?: number; vy?: number; size?: number; floor?: number; life?: number; land?: () => void } = {}) {
    this.motes.push({ x, y, vx: opts.vx ?? 0, vy: opts.vy ?? 0, color, size: opts.size ?? 28, life: opts.life ?? 4, floor: opts.floor ?? this.yard.ground, land: opts.land });
  }

  /**
   * Drops a light from (x, y) so that it lands on (tx, ty): it is thrown up a little (by `lift`,
   * layout units per second) and falls the rest of the way.
   */
  dropTo(x: number, y: number, tx: number, ty: number, color: Rgb, opts: { lift?: number; size?: number; land?: () => void } = {}) {
    const vy = -(opts.lift ?? 0);
    const fall = Math.max(0, ty - y);
    const t = (-vy + Math.sqrt(vy * vy + 2 * this.gravity * fall)) / this.gravity || 0.3;
    this.drop(x, y, color, { vx: (tx - x) / Math.max(0.05, t), vy, size: opts.size, floor: Math.max(y, ty), land: opts.land });
  }

  /** Flies from a to b along an arc that bulges by `arc` (layout units, up is positive). */
  fly(a: { x: number; y: number }, b: { x: number; y: number }, color: Rgb, duration: number, opts: { arc?: number; size?: number; arrive?: () => void } = {}) {
    const arc = opts.arc ?? 0;
    this.flights.push({ ax: a.x, ay: a.y, bx: b.x, by: b.y, cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2 - arc, t: 0, duration, color, size: opts.size ?? 34, arrive: opts.arrive });
  }

  get busy() {
    return this.motes.length + this.flights.length > 0;
  }

  update(dt: number) {
    for (let i = this.motes.length - 1; i >= 0; i--) {
      const m = this.motes[i];
      m.vy += this.gravity * dt;
      m.x += m.vx * dt;
      m.y += m.vy * dt;
      m.life -= dt;
      if (m.y >= m.floor || m.life <= 0) {
        this.motes.splice(i, 1);
        m.land?.();
      }
    }
    for (let i = this.flights.length - 1; i >= 0; i--) {
      const f = this.flights[i];
      f.t += dt / f.duration;
      if (f.t >= 1) {
        this.flights.splice(i, 1);
        f.arrive?.();
      }
    }
  }

  draw() {
    for (const m of this.motes) this.yard.glow(m.x, m.y, m.size, m.color, 0.9);
    for (const f of this.flights) {
      // The head and a short tail behind it.
      for (let k = 0; k < 5; k++) {
        const t = f.t - k * 0.035;
        if (t < 0) break;
        // Ease in and out, so it leaves and lands gently.
        const e = t * t * (3 - 2 * t);
        const u = 1 - e;
        const x = u * u * f.ax + 2 * u * e * f.cx + e * e * f.bx;
        const y = u * u * f.ay + 2 * u * e * f.cy + e * e * f.by;
        this.yard.glow(x, y, f.size * (1 - k * 0.12), k === 0 ? mix(f.color, WHITE, 0.3) : f.color, 1 - k * 0.2);
      }
    }
  }

  clear() {
    this.motes.length = 0;
    this.flights.length = 0;
  }
}

interface Wave {
  x: number;
  y: number;
  r: number;
  speed: number;
  width: number;
  color: Rgb;
  amount: number;
  reach: number;
}

/** Shockwaves: rings of light that sweep out over every LED of the yard and fade. */
export class Waves {
  private list: Wave[] = [];
  private yard: Yard;

  constructor(yard: Yard) {
    this.yard = yard;
  }

  add(x: number, y: number, color: Rgb, opts: { speed?: number; width?: number; amount?: number; reach?: number } = {}) {
    const s = this.yard.stage;
    this.list.push({ x, y, r: 0, speed: opts.speed ?? s.scale * 14, width: opts.width ?? s.scale * 0.5, color, amount: opts.amount ?? 0.8, reach: opts.reach ?? Math.hypot(s.width, s.height) });
  }

  update(dt: number) {
    for (let i = this.list.length - 1; i >= 0; i--) {
      const w = this.list[i];
      w.r += w.speed * dt;
      if (w.r > w.reach) this.list.splice(i, 1);
    }
  }

  draw() {
    for (const w of this.list) this.yard.ring(w.x, w.y, w.r, w.width, w.color, w.amount * (1 - w.r / w.reach) ** 1.5);
  }

  clear() {
    this.list.length = 0;
  }
}

/** A color that flares up and fades: the house's windows catching the light of an explosion. */
export class Flare {
  color: Rgb = [0, 0, 0];
  private fade: number;

  constructor(fade = 4) {
    this.fade = fade;
  }

  add(c: Rgb, amount = 1) {
    this.color = [this.color[0] + c[0] * amount, this.color[1] + c[1] * amount, this.color[2] + c[2] * amount];
  }
  update(dt: number) {
    this.color = scale(this.color, Math.exp(-dt * this.fade));
  }
}

/** A rainbow hue per index that keeps neighbours apart (golden ratio steps). */
export const spreadHue = (i: number) => (i * 0.618034) % 1;
export const rainbow = (i: number, s = 1) => hsv(spreadHue(i), s);

// ---------- Best scores ----------

const best = new Map<string, number>();

/** Keeps the best score of each game while the server runs. Returns the best and whether this is a new one. */
export function record(game: string, score: number): { best: number; isNew: boolean } {
  const old = best.get(game) ?? 0;
  if (score > old) best.set(game, score);
  return { best: Math.max(old, score), isNew: score > old && score > 0 };
}

export const bestScore = (game: string) => best.get(game) ?? 0;
