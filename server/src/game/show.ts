// The light show around a game: what the whole yard does while the game is played on it.
//
// A game draws its pieces (the comet, the gates, the meters) into the frame as before. The show
// draws into a layer of its own, and that layer goes under the pieces: where a piece is lit, the
// show steps back, so the pieces stay clean (no white where two colors meet) and the show fills
// everything around them. Nothing in the yard is ever off while a game runs.
//
//   backdrop: every LED glows dim in the game's mood: two colors that drift slowly across the
//     house. The game changes the mood with its state: calm, a streak heating up, danger. A new
//     mood can wipe across the yard (a stage change), or ease in.
//   pulse: the whole yard kicks in one color and settles (a hit, a beat).
//   firework: a rocket from the ground that bursts into sparks that fall through the yard, lighting
//     the windows, the trees and the roof as they pass.
//   explode: a flash where something happened, a shockwave and debris.
//   sweep: a band of color that crosses the whole yard.
//   ripple: a ring through the backdrop, like a shock through a grid.
//
// Big moments (game over, a stage cleared) can go over the pieces instead (`over: true`).

import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import type { Yard } from './kit.ts';

/** Which way a sweep (or a mood's wipe) crosses the yard, as seen from the street. */
export type Direction = 'left' | 'right' | 'up' | 'down' | 'out' | 'in';

export interface Mood {
  /** The two colors that drift across the backdrop. */
  a: Rgb;
  b: Rgb;
  /** How bright the backdrop is (default 1: dim, but plainly on). */
  level?: number;
  /** How fast the colors drift (default 1). */
  drift?: number;
  /** Throbs this many times a second (danger), 0: steady. */
  throb?: number;
  /**
   * Two sides instead of drifting colors: `a` on the left of the yard and `b` on the right,
   * meeting at this share of the way across (0..1), with a wavy edge. Not set: they drift.
   */
  split?: number;
}

/** After a game over: a dark red that sinks, `seconds` after it, but never goes out. */
export const overMood = (seconds: number): Mood => ({ a: [0.6, 0.02, 0.02], b: [0.3, 0, 0.1], level: Math.max(0.4, 0.8 - seconds * 0.08), drift: 0.4 });

/** Waiting for a player: every hue going slowly round the house. */
export const attractMood = (clock: number): Mood => ({ a: hsv(clock * 0.05), b: hsv(clock * 0.05 + 0.33), level: 1.1, drift: 0.8 });

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: Rgb;
  life: number;
  max: number;
  size: number;
  /** Twinkles as it burns out. */
  crackle: boolean;
  /** Falls this much more slowly (a willow hangs). */
  float: number;
  /** Trail points (the last few positions). */
  tx: number[];
  ty: number[];
  over: boolean;
}

interface Rocket {
  x: number;
  y: number;
  vy: number;
  /** Its own gravity, so every rocket takes about as long to climb. */
  g: number;
  burstY: number;
  colors: Rgb[];
  kind: FireworkKind;
  size: number;
  over: boolean;
}

interface Sweep {
  dir: Direction;
  color: Rgb;
  /** 0..1 across the yard (and a little past). */
  t: number;
  speed: number;
  width: number;
  amount: number;
  over: boolean;
}

interface Flash {
  x: number;
  y: number;
  color: Rgb;
  t: number;
  duration: number;
  size: number;
  over: boolean;
}

interface Ring {
  x: number;
  y: number;
  r: number;
  speed: number;
  width: number;
  color: Rgb;
  amount: number;
  reach: number;
  over: boolean;
}

export type FireworkKind = 'peony' | 'ring' | 'willow' | 'crackle';


/** The color a mood's backdrop starts from: deep blue and violet. */
export const NIGHT_MOOD: Mood = { a: [0.1, 0.12, 0.55], b: [0.4, 0.06, 0.6] };

/** Seconds a rocket takes to climb. */
const ROCKET = 0.75;

const ease = (t: number) => t * t * (3 - 2 * t);

export class Show {
  readonly yard: Yard;
  /** The show's layer, under the pieces. */
  private under: Float32Array;
  /** Over the pieces: for the big moments. */
  private overLayer: Float32Array;
  /** Per LED: across the yard (0 left, 1 right) and down it (0 top, 1 bottom), and from the middle (0..1). */
  private u: Float32Array;
  private v: Float32Array;
  private r: Float32Array;
  /** Per LED: how strongly pieces push the show back (the roof more, it is the playfield). */
  private hold: Float32Array;
  /** Per LED: how bright the backdrop is there (see dim). */
  private level: Float32Array;
  private x0: number;
  private y0: number;
  private w: number;
  private h: number;
  /** One meter in layout units. */
  readonly m: number;

  private mood: Required<Mood> = { a: NIGHT_MOOD.a, b: NIGHT_MOOD.b, level: 1, drift: 1, throb: 0, split: -1 };
  private from: Required<Mood> = { ...this.mood };
  private change = 1;
  private changeSpeed = 2;
  private changeDir: Direction | null = null;
  private clock = 0;
  private kick: Rgb = [0, 0, 0];
  private kickOver: Rgb = [0, 0, 0];
  private particles: Particle[] = [];
  private rockets: Rocket[] = [];
  private sweeps: Sweep[] = [];
  private flashes: Flash[] = [];
  private rings: Ring[] = [];
  /** Backdrop brightness on the roof, as a share of the rest (the roof is the playfield). */
  roofLevel = 0.7;
  /**
   * How much of the show (under the pieces) reaches the roof at all: 0 for a game that draws the
   * whole roof itself and needs it clear around its pieces. Big moments (`over`) still reach it.
   */
  roofShare = 1;
  /** Turns the whole show down (0..1), e.g. while a game is not running. */
  master = 1;
  /**
   * Where fireworks burst, from the top of the yard (0) to the bottom (1). The roof is usually
   * the top: a game that wants the bursts off it sets a lower band (see belowRoof).
   */
  burstBand: [number, number] = [0.15, 0.5];
  /**
   * The most the show adds to a roof LED (under the pieces), and never white: on the roof it
   * keeps only its color, so only a game's own pieces are ever white there.
   */
  roofCap = 0.25;

  constructor(yard: Yard) {
    this.yard = yard;
    const stage = yard.stage;
    const count = stage.pixelCount;
    this.under = new Float32Array(count * 3);
    this.overLayer = new Float32Array(count * 3);
    this.u = new Float32Array(count);
    this.v = new Float32Array(count);
    this.r = new Float32Array(count);
    this.hold = new Float32Array(count);
    this.level = new Float32Array(count).fill(1);
    this.m = stage.scale || 50;
    const pos = stage.positions;
    let x0 = Infinity;
    let x1 = -Infinity;
    let y0 = Infinity;
    let y1 = -Infinity;
    for (const i of yard.lit) {
      x0 = Math.min(x0, pos[i * 2]);
      x1 = Math.max(x1, pos[i * 2]);
      y0 = Math.min(y0, pos[i * 2 + 1]);
      y1 = Math.max(y1, pos[i * 2 + 1]);
    }
    if (!(x1 >= x0)) {
      x0 = y0 = 0;
      x1 = stage.width;
      y1 = stage.height;
    }
    this.x0 = x0;
    this.y0 = y0;
    this.w = Math.max(1, x1 - x0);
    this.h = Math.max(1, y1 - y0);
    const roof = new Set<number>(yard.roof.track.leds);
    this.onRoof = new Uint8Array(count);
    const cx = x0 + this.w / 2;
    const cy = y0 + this.h / 2;
    const far = Math.hypot(this.w / 2, this.h / 2);
    for (const i of yard.lit) {
      this.u[i] = (pos[i * 2] - x0) / this.w;
      this.v[i] = (pos[i * 2 + 1] - y0) / this.h;
      this.r[i] = Math.hypot(pos[i * 2] - cx, pos[i * 2 + 1] - cy) / far;
      const onRoof = roof.has(i);
      this.onRoof[i] = onRoof ? 1 : 0;
      this.hold[i] = onRoof ? 5 : 2.2;
    }
  }

  private onRoof: Uint8Array;

  /** The backdrop on these LEDs at `k` times its brightness (e.g. dimmer on a meter, so its lit part reads clearly). */
  dim(part: { offset: number; count: number }, k: number) {
    this.level.fill(k, part.offset, part.offset + part.count);
  }

  /** The middle of the yard, and its size, in the front view. */
  get box() {
    return { x: this.x0, y: this.y0, w: this.w, h: this.h };
  }

  // ---------- The backdrop ----------

  /**
   * Sets the game's mood. It eases in over `fade` seconds, or wipes across the yard from one side
   * when `wipe` is given. Setting the same mood again does nothing, so a game can set it on every
   * frame from its state.
   */
  setMood(m: Mood, opts: { fade?: number; wipe?: Direction } = {}) {
    const next: Required<Mood> = { level: 1, drift: 1, throb: 0, split: -1, ...m };
    const same = (a: Rgb, b: Rgb) => Math.abs(a[0] - b[0]) + Math.abs(a[1] - b[1]) + Math.abs(a[2] - b[2]) < 0.02;
    const cur = this.mood;
    if (same(cur.a, next.a) && same(cur.b, next.b) && Math.abs(cur.level - next.level) < 0.02 && cur.drift === next.drift && cur.throb === next.throb && Math.abs(cur.split - next.split) < 0.02) return;
    // Mid-change: start from what shows now.
    this.from = this.change >= 1 ? { ...cur } : this.blend(this.from, cur, this.change);
    this.mood = next;
    this.change = 0;
    this.changeDir = opts.wipe ?? null;
    this.changeSpeed = 1 / Math.max(0.05, opts.fade ?? (opts.wipe ? 0.9 : 0.6));
  }

  /** Eases toward a mood every frame without restarting the change: for moods that follow a number (heat, health). */
  followMood(m: Mood, rate = 3, dt = 1 / 60) {
    const next: Required<Mood> = { level: 1, drift: 1, throb: 0, split: -1, ...m };
    const k = 1 - Math.exp(-rate * dt);
    // Mid-change (a wipe crossing the yard): the change goes on, toward a target that follows.
    const cur = this.mood;
    this.mood = { a: mix(cur.a, next.a, k), b: mix(cur.b, next.b, k), level: cur.level + (next.level - cur.level) * k, drift: next.drift, throb: next.throb, split: next.split };
  }

  private blend(a: Required<Mood>, b: Required<Mood>, t: number): Required<Mood> {
    return { a: mix(a.a, b.a, t), b: mix(a.b, b.b, t), level: a.level + (b.level - a.level) * t, drift: b.drift, throb: t < 0.5 ? a.throb : b.throb, split: t < 0.5 ? a.split : b.split };
  }

  /** The whole yard kicks in a color and settles over a few tenths of a second. */
  pulse(color: Rgb, amount = 0.5, opts: { over?: boolean } = {}) {
    const k = opts.over ? this.kickOver : this.kick;
    k[0] += color[0] * amount;
    k[1] += color[1] * amount;
    k[2] += color[2] * amount;
  }

  // ---------- Events ----------

  /**
   * A firework: a rocket from the ground at x (default: anywhere across the yard) that bursts
   * somewhere over the house and falls through it. Colors: one or a few.
   */
  firework(opts: { x?: number; y?: number; colors?: Rgb[]; kind?: FireworkKind; size?: number; over?: boolean; delay?: number } = {}) {
    const x = opts.x ?? this.x0 + this.w * (0.1 + Math.random() * 0.8);
    const [lo, hi] = this.burstBand;
    const burstY = opts.y ?? this.y0 + this.h * (lo + Math.random() * (hi - lo));
    const ground = Math.max(this.yard.ground, this.y0 + this.h);
    const colors = opts.colors ?? [hsv(Math.random()), hsv(Math.random())];
    const kind = opts.kind ?? (['peony', 'ring', 'willow', 'crackle'] as const)[Math.floor(Math.random() * 4)];
    // Up in ROCKET seconds, slowing to a stop where it bursts (a delay starts it below the ground).
    const rise = Math.max(this.m * 2, ground - burstY);
    const vy = (2 * rise) / ROCKET;
    const rocket: Rocket = { x, y: ground + (opts.delay ?? 0) * vy, vy: -vy, g: vy / ROCKET, burstY, colors, kind, size: opts.size ?? 1, over: !!opts.over };
    this.rockets.push(rocket);
  }

  /** A burst of sparks right here (a firework without the rocket). */
  burst(x: number, y: number, colors: Rgb[], opts: { kind?: FireworkKind; size?: number; over?: boolean } = {}) {
    const kind = opts.kind ?? 'peony';
    const size = opts.size ?? 1;
    const count = Math.round((kind === 'ring' ? 36 : 48) * Math.sqrt(size));
    const speed = this.m * 8 * Math.sqrt(size);
    for (let k = 0; k < count; k++) {
      const a = (k / count) * Math.PI * 2 + Math.random() * 0.2;
      const s = kind === 'ring' ? speed : speed * (0.35 + 0.65 * Math.sqrt(Math.random()));
      const max = (kind === 'willow' ? 2.4 : 1.3) * (0.75 + Math.random() * 0.5);
      this.particles.push({
        x,
        y,
        vx: Math.cos(a) * s,
        vy: Math.sin(a) * s * (kind === 'ring' ? 0.55 : 1),
        color: colors[k % colors.length],
        life: max,
        max,
        size: this.m * 0.75 * Math.sqrt(size),
        crackle: kind === 'crackle',
        float: kind === 'willow' ? 0.25 : 0.5,
        tx: [],
        ty: [],
        over: !!opts.over
      });
    }
    this.flash(x, y, mix(colors[0], WHITE, 0.4), { size: 1.4 * size, duration: 0.25, over: opts.over });
  }

  /** Several fireworks across the yard, one after another: a finale. */
  finale(count = 6, opts: { colors?: Rgb[][]; over?: boolean } = {}) {
    for (let k = 0; k < count; k++) {
      const x = this.x0 + this.w * ((k + 0.5) / count + (Math.random() - 0.5) * 0.08);
      this.firework({ x, colors: opts.colors?.[k % opts.colors.length], delay: k * 0.18, over: opts.over });
    }
  }

  /**
   * A firework from one side of the yard and then the other, in turn: for the hits and catches of
   * a game, which can come quickly (no more than `max` go up at once; the rest are skipped).
   */
  rocket(colors: Rgb[], opts: { size?: number; kind?: FireworkKind; side?: 0 | 1; max?: number } = {}) {
    if (this.rockets.length >= (opts.max ?? 3)) return;
    this.side = opts.side ?? ((1 - this.side) as 0 | 1);
    const x = this.x0 + this.w * (this.side === 0 ? 0.08 + Math.random() * 0.32 : 0.6 + Math.random() * 0.32);
    this.firework({ x, colors, size: opts.size, kind: opts.kind ?? (Math.random() < 0.25 ? 'ring' : Math.random() < 0.5 ? 'crackle' : 'peony') });
  }

  private side: 0 | 1 = 0;

  /**
   * Game over: the house blows from (x, y), red sweeps down over everything and the yard wipes to
   * a dark red (follow overMood from here). A new best: gold fireworks all over once the dust settles.
   */
  gameOver(x: number, y: number, opts: { newBest?: boolean; color?: Rgb } = {}) {
    const color = opts.color ?? [1, 0.04, 0.02];
    this.explode(x, y, color, { size: 2.5, over: true });
    this.sweep(color, { dir: 'down', amount: 0.9, duration: 1, over: true });
    this.setMood(overMood(0), { wipe: 'down' });
    if (opts.newBest) this.finale(7, { colors: [[[1, 0.68, 0.12], WHITE], [[1, 0.68, 0.12]]] });
  }

  /** The band from just under the roof to the ground, for fireworks that should not burst on the roof. */
  belowRoof() {
    const roof = this.yard.roof;
    if (!roof.n) return;
    let eaves = -Infinity;
    for (let i = 0; i < roof.n; i++) eaves = Math.max(eaves, roof.y[i]);
    const ground = Math.max(this.yard.ground, this.y0 + this.h);
    const lo = (eaves + (ground - eaves) * 0.15 - this.y0) / this.h;
    const hi = (eaves + (ground - eaves) * 0.5 - this.y0) / this.h;
    // Only where there is something under the roof to light.
    if (hi > lo && lo < 1) this.burstBand = [Math.max(0, lo), Math.min(1, hi)];
  }

  /** The backdrop back to full on every LED (see dim). */
  undim() {
    this.level.fill(1);
  }

  /** An explosion: a flash, a shockwave through the whole yard, and debris. */
  explode(x: number, y: number, color: Rgb, opts: { size?: number; over?: boolean; debris?: number } = {}) {
    const size = opts.size ?? 1;
    this.flash(x, y, mix(color, WHITE, 0.25), { size: 2.2 * size, duration: 0.45, over: opts.over });
    this.ripple(x, y, color, { amount: 0.7, over: opts.over });
    const count = opts.debris ?? Math.round(22 * size);
    for (let k = 0; k < count; k++) {
      const a = Math.random() * Math.PI * 2;
      const s = this.m * (3 + Math.random() * 8) * Math.sqrt(size);
      const max = 0.6 + Math.random() * 0.9;
      this.particles.push({ x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s - this.m * 3, color: k % 3 ? color : mix(color, WHITE, 0.5), life: max, max, size: this.m * 0.35, crackle: false, float: 1, tx: [], ty: [], over: !!opts.over });
    }
    this.pulse(color, 0.18 * size, { over: opts.over });
  }

  /** A quick soft light at a point that swells and fades. */
  flash(x: number, y: number, color: Rgb, opts: { size?: number; duration?: number; over?: boolean } = {}) {
    this.flashes.push({ x, y, color, t: 0, duration: opts.duration ?? 0.35, size: opts.size ?? 1, over: !!opts.over });
  }

  /** A band of color that crosses the whole yard. */
  sweep(color: Rgb, opts: { dir?: Direction; duration?: number; width?: number; amount?: number; over?: boolean } = {}) {
    this.sweeps.push({ dir: opts.dir ?? 'right', color, t: -0.15, speed: 1 / (opts.duration ?? 0.8), width: opts.width ?? 0.12, amount: opts.amount ?? 0.8, over: !!opts.over });
  }

  /** A ring that runs out from a point over every LED. */
  ripple(x: number, y: number, color: Rgb, opts: { amount?: number; speed?: number; width?: number; over?: boolean } = {}) {
    this.rings.push({ x, y, r: 0, speed: opts.speed ?? this.m * 16, width: opts.width ?? this.m * 0.45, color, amount: opts.amount ?? 0.5, reach: Math.hypot(this.w, this.h) * 1.05, over: !!opts.over });
  }

  /** Everything in the air is gone (a new game). The mood stays. */
  clear() {
    this.particles.length = 0;
    this.rockets.length = 0;
    this.sweeps.length = 0;
    this.flashes.length = 0;
    this.rings.length = 0;
    this.kick = [0, 0, 0];
    this.kickOver = [0, 0, 0];
  }

  /** Rockets on their way up. */
  get rocketsUp() {
    return this.rockets.length;
  }

  /** True while fireworks, sweeps or flashes are going on. */
  get busy() {
    return this.particles.length + this.rockets.length + this.sweeps.length + this.flashes.length + this.rings.length > 0;
  }

  // ---------- Time ----------

  update(dt: number) {
    this.clock += dt;
    if (this.change < 1) this.change = Math.min(1, this.change + dt * this.changeSpeed);
    const kk = Math.exp(-dt * 5);
    this.kick = [this.kick[0] * kk, this.kick[1] * kk, this.kick[2] * kk];
    this.kickOver = [this.kickOver[0] * kk, this.kickOver[1] * kk, this.kickOver[2] * kk];
    const g = this.m * 9.8;
    for (let i = this.rockets.length - 1; i >= 0; i--) {
      const r = this.rockets[i];
      r.vy += r.g * dt;
      r.y += r.vy * dt;
      if (r.vy >= 0 || r.y <= r.burstY) {
        this.rockets.splice(i, 1);
        this.burst(r.x, r.y, r.colors, { kind: r.kind, size: r.size, over: r.over });
      }
    }
    const drag = Math.exp(-dt * 1.6);
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.tx.unshift(p.x);
      p.ty.unshift(p.y);
      if (p.tx.length > 4) {
        p.tx.pop();
        p.ty.pop();
      }
      p.vx *= drag;
      p.vy = p.vy * drag + g * p.float * dt;
      p.x += p.vx * dt;
      p.y += p.vy * dt;
      p.life -= dt;
      if (p.life <= 0) this.particles.splice(i, 1);
    }
    for (let i = this.sweeps.length - 1; i >= 0; i--) {
      const s = this.sweeps[i];
      s.t += dt * s.speed;
      if (s.t > 1.2) this.sweeps.splice(i, 1);
    }
    for (let i = this.flashes.length - 1; i >= 0; i--) {
      const f = this.flashes[i];
      f.t += dt;
      if (f.t >= f.duration) this.flashes.splice(i, 1);
    }
    for (let i = this.rings.length - 1; i >= 0; i--) {
      const w = this.rings[i];
      w.r += w.speed * dt;
      if (w.r > w.reach) this.rings.splice(i, 1);
    }
  }

  // ---------- Drawing ----------

  /** Where a LED is along a direction: 0 where a sweep starts, 1 where it ends. */
  private along(i: number, dir: Direction) {
    switch (dir) {
      case 'right':
        return this.u[i];
      case 'left':
        return 1 - this.u[i];
      case 'down':
        return this.v[i];
      case 'up':
        return 1 - this.v[i];
      case 'out':
        return this.r[i];
      case 'in':
        return 1 - this.r[i];
    }
  }

  private moodAt(m: Required<Mood>, i: number, out: Rgb) {
    const t = this.clock * 0.45 * m.drift;
    const u = this.u[i];
    const v = this.v[i];
    // Two slow waves across the house, at an angle to each other: the colors drift and swirl.
    const f = m.split >= 0 ? Math.max(0, Math.min(1, (u - m.split + 0.04 * Math.sin(v * 7 + t * 3)) * 6 + 0.5)) : 0.5 + 0.5 * Math.sin(u * 5.2 + t + 1.3 * Math.sin(v * 3.1 - t * 0.7));
    const shimmer = 0.78 + 0.22 * Math.sin(u * 17 - v * 9 + t * 2.3);
    const throb = m.throb ? 0.55 + 0.45 * Math.sin(this.clock * Math.PI * 2 * m.throb) : 1;
    const k = 0.2 * m.level * shimmer * throb * this.level[i] * (this.onRoof[i] ? this.roofLevel : 1);
    out[0] = (m.a[0] + (m.b[0] - m.a[0]) * f) * k;
    out[1] = (m.a[1] + (m.b[1] - m.a[1]) * f) * k;
    out[2] = (m.a[2] + (m.b[2] - m.a[2]) * f) * k;
  }

  private addTo(layer: Float32Array, i: number, c: Rgb, amount: number) {
    if (amount <= 0 || !this.yard.stage.active[i]) return;
    const k = i * 3;
    layer[k] += c[0] * amount;
    layer[k + 1] += c[1] * amount;
    layer[k + 2] += c[2] * amount;
  }

  private glowInto(layer: Float32Array, x: number, y: number, radius: number, c: Rgb, amount: number) {
    if (amount <= 0) return;
    this.yard.within(x, y, radius, (i, d2) => this.addTo(layer, i, c, amount * (1 - d2) * (1 - d2)));
  }

  /**
   * Puts the show into the frame, under the pieces the game drew (and the big moments over them).
   * Call it after the game has drawn.
   */
  draw(frame: Frame) {
    const under = this.under;
    const over = this.overLayer;
    under.fill(0);
    over.fill(0);
    const c: Rgb = [0, 0, 0];
    const d: Rgb = [0, 0, 0];
    const master = this.master;
    // The backdrop, and a mood that is changing.
    if (master > 0) {
      const changing = this.change < 1;
      const e = ease(this.change);
      for (const i of this.yard.lit) {
        this.moodAt(this.mood, i, c);
        if (changing) {
          this.moodAt(this.from, i, d);
          let t = e;
          if (this.changeDir) {
            // The new mood behind a soft front that crosses the yard, with a bright edge.
            const front = this.change * 1.25 - 0.1;
            const a = this.along(i, this.changeDir);
            t = Math.max(0, Math.min(1, (front - a) / 0.1));
            const edge = Math.exp(-(((a - front) / 0.06) ** 2)) * (1 - this.change);
            const k = i * 3;
            under[k] += (this.mood.a[0] * 0.6 + 0.2) * edge * 0.6;
            under[k + 1] += (this.mood.a[1] * 0.6 + 0.2) * edge * 0.6;
            under[k + 2] += (this.mood.a[2] * 0.6 + 0.2) * edge * 0.6;
          }
          c[0] = d[0] + (c[0] - d[0]) * t;
          c[1] = d[1] + (c[1] - d[1]) * t;
          c[2] = d[2] + (c[2] - d[2]) * t;
        }
        const k = i * 3;
        under[k] += c[0] * master + this.kick[0];
        under[k + 1] += c[1] * master + this.kick[1];
        under[k + 2] += c[2] * master + this.kick[2];
        if (this.kickOver[0] + this.kickOver[1] + this.kickOver[2] > 0.003) {
          over[k] += this.kickOver[0];
          over[k + 1] += this.kickOver[1];
          over[k + 2] += this.kickOver[2];
        }
      }
    }
    for (const s of this.sweeps) {
      const layer = s.over ? over : under;
      for (const i of this.yard.lit) {
        const a = (this.along(i, s.dir) - s.t) / s.width;
        if (a > -2.5 && a < 2.5) this.addTo(layer, i, s.color, s.amount * Math.exp(-a * a) * (a > 0 ? 1 : 0.7));
      }
    }
    const pos = this.yard.stage.positions;
    for (const w of this.rings) {
      const layer = w.over ? over : under;
      const amount = w.amount * (1 - w.r / w.reach) ** 1.3;
      const in2 = Math.max(0, w.r - 2.5 * w.width) ** 2;
      const out2 = (w.r + 2.5 * w.width) ** 2;
      for (const i of this.yard.lit) {
        const dx = pos[i * 2] - w.x;
        const dy = pos[i * 2 + 1] - w.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < in2 || d2 > out2) continue;
        const q = (Math.sqrt(d2) - w.r) / w.width;
        this.addTo(layer, i, w.color, amount * Math.exp(-q * q));
      }
    }
    for (const f of this.flashes) {
      const t = f.t / f.duration;
      this.glowInto(f.over ? over : under, f.x, f.y, this.m * f.size * (0.6 + 1.6 * t), f.color, (1 - t) ** 2 * 1.2);
    }
    for (const r of this.rockets) {
      if (r.y > this.y0 + this.h + this.m) continue;
      const layer = r.over ? over : under;
      this.glowInto(layer, r.x, r.y, this.m * 0.45, [1, 0.85, 0.6], 1);
      this.glowInto(layer, r.x + (Math.random() - 0.5) * this.m * 0.2, r.y + this.m * 0.6, this.m * 0.4, [1, 0.5, 0.15], 0.5);
    }
    for (const p of this.particles) {
      const layer = p.over ? over : under;
      const life = p.life / p.max;
      const age = 1 - life;
      let amount = life ** 0.7;
      if (p.crackle && age > 0.45) amount *= Math.random() < 0.5 ? 1.6 : 0.1;
      // White hot as it leaves, then its own color.
      const color = age < 0.12 ? mix(WHITE, p.color, age / 0.12) : p.color;
      this.glowInto(layer, p.x, p.y, p.size, color, amount);
      for (let k = 0; k < p.tx.length; k++) this.glowInto(layer, p.tx[k], p.ty[k], p.size * (0.85 - k * 0.12), p.color, amount * (0.45 - k * 0.1));
    }
    // Under the pieces: where the game lit a LED, the show steps back.
    const data = frame.data;
    for (const i of this.yard.lit) {
      const k = i * 3;
      const lum = Math.max(data[k], data[k + 1], data[k + 2]);
      let keep = Math.max(0, 1 - lum * this.hold[i]);
      if (this.onRoof[i]) {
        // On the roof: only the show's color (none of its white), and not much of it.
        const white = Math.min(under[k], under[k + 1], under[k + 2]);
        under[k] -= white;
        under[k + 1] -= white;
        under[k + 2] -= white;
        const most = Math.max(under[k], under[k + 1], under[k + 2]);
        keep *= this.roofShare * (most > this.roofCap ? this.roofCap / most : 1);
      }
      data[k] += under[k] * keep + over[k];
      data[k + 1] += under[k + 1] * keep + over[k + 1];
      data[k + 2] += under[k + 2] * keep + over[k + 2];
    }
  }
}

/** A color with its hue turned by `turn` (0..1 of the way round): a partner for a mood. */
export function turnHue([r, g, b]: Rgb, turn: number): Rgb {
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max <= 0) return [0, 0, 0];
  const d = max - min;
  let h = 0;
  if (d > 1e-6) {
    if (max === r) h = ((g - b) / d + 6) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
  }
  return hsv(h / 6 + turn, d / max, max);
}
