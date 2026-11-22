// Transitions: how one show of the lights gives way to the next. The sequence editor uses them
// between clips, and the server between scenes that someone picks (see Settings.sceneTransition).
// Both draw the same transitions with the code here. Keep this file free of Node and DOM APIs.

import type { Stage } from './layout.ts';

export type TransitionId =
  | 'fade'
  | 'dip'
  | 'flash'
  | 'wipeRight'
  | 'wipeLeft'
  | 'wipeUp'
  | 'wipeDown'
  | 'diagonal'
  | 'splitOut'
  | 'splitIn'
  | 'iris'
  | 'irisClose'
  | 'clock'
  | 'blinds'
  | 'strings'
  | 'dissolve';

/** A transition, or "random": a different one picked each time. */
export type TransitionChoice = TransitionId | 'random';

export const TRANSITIONS: { id: TransitionId; name: string; description: string }[] = [
  { id: 'fade', name: 'Crossfade', description: 'One effect fades into the other.' },
  { id: 'dip', name: 'Dip to black', description: 'Fades out to dark, then the next fades in.' },
  { id: 'flash', name: 'Flash', description: 'Flares up to white, then the next comes out of the flash.' },
  { id: 'wipeRight', name: 'Wipe →', description: 'A soft edge sweeps from left to right across the yard.' },
  { id: 'wipeLeft', name: 'Wipe ←', description: 'A soft edge sweeps from right to left.' },
  { id: 'wipeUp', name: 'Wipe ↑', description: 'A soft edge rises from the ground up.' },
  { id: 'wipeDown', name: 'Wipe ↓', description: 'A soft edge comes down from the top.' },
  { id: 'diagonal', name: 'Diagonal wipe', description: 'A soft edge sweeps from the bottom left corner to the top right.' },
  { id: 'splitOut', name: 'Split open', description: 'Opens from the middle out to both sides, like curtains.' },
  { id: 'splitIn', name: 'Split close', description: 'Closes in from both sides to the middle.' },
  { id: 'iris', name: 'Iris open', description: 'A circle opens from the middle out.' },
  { id: 'irisClose', name: 'Iris close', description: 'A circle closes in from the edges to the middle.' },
  { id: 'clock', name: 'Clock wipe', description: 'A hand sweeps round the middle like a clock, from twelve o’clock.' },
  { id: 'blinds', name: 'Blinds', description: 'Six slats across the yard wipe over at once, like opening blinds.' },
  { id: 'strings', name: 'Along the strings', description: 'Runs along each light string from its first LED to its last.' },
  { id: 'dissolve', name: 'Sparkle dissolve', description: 'LEDs switch over one by one, in random order.' }
];

export const RANDOM_TRANSITION = { id: 'random' as const, name: 'Random', description: 'A different transition each time, picked at random.' };

/** Every choice, the transitions and then "random". */
export const TRANSITION_CHOICES: { id: TransitionChoice; name: string; description: string }[] = [...TRANSITIONS, RANDOM_TRANSITION];

export const TRANSITION_IDS = TRANSITIONS.map((t) => t.id);

export const transitionInfo = (id: TransitionChoice | undefined) => (id === 'random' ? RANDOM_TRANSITION : (TRANSITIONS.find((t) => t.id === id) ?? TRANSITIONS[0]));

/** A transition for a choice: "random" picks one by `r` (0..1, e.g. Math.random()). */
export function pickTransition(choice: TransitionChoice | undefined, r: number): TransitionId {
  if (choice !== 'random') return choice ?? 'fade';
  const i = Math.floor((((r % 1) + 1) % 1) * TRANSITIONS.length);
  return TRANSITIONS[Math.min(TRANSITIONS.length - 1, i)].id;
}

/** A number in 0..1 from a string (FNV-1a), the same everywhere: a "random" pick that stays put. */
export function hashUnit(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  // Mix the last characters into every bit (MurmurHash3's finish): "x|0" and "x|1" land far apart.
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return (h >>> 0) / 2 ** 32;
}

/** How scenes give way to each other when someone picks one (see Settings.sceneTransition). */
export interface SceneTransition {
  type: TransitionChoice;
  seconds: number;
}

/** "none": a new scene shows at once. */
export type SceneTransitionChoice = TransitionChoice | 'none';

export const SCENE_TRANSITION_SECONDS = { min: 0.1, max: 10, default: 1 } as const;

/** A box in the yard: [x0, x1, y0, y1], in 0..1 across the whole yard (y up). */
export type Box = [number, number, number, number];

export const WHOLE_YARD: Box = [0, 1, 0, 1];

export const unionBox = (a: Box, b: Box): Box => [Math.min(a[0], b[0]), Math.max(a[1], b[1]), Math.min(a[2], b[2]), Math.max(a[3], b[3])];

/**
 * Where each LED of a stage is, for transitions: across the whole yard (0..1, x right, y up),
 * along its own string (0 at its first LED, 1 at its last), and a random number of its own.
 */
export class LedPlaces {
  readonly ux: Float32Array;
  readonly uy: Float32Array;
  readonly along: Float32Array;
  readonly rnd: Float32Array;

  constructor(stage: Stage) {
    const n = stage.pixelCount;
    this.ux = new Float32Array(n);
    this.uy = new Float32Array(n);
    this.along = new Float32Array(n);
    this.rnd = new Float32Array(n);
    let x0 = Infinity;
    let x1 = -Infinity;
    let y0 = Infinity;
    let y1 = -Infinity;
    const P = stage.positions3;
    for (let i = 0; i < n; i++) {
      if (!stage.active[i]) continue;
      x0 = Math.min(x0, P[i * 3]);
      x1 = Math.max(x1, P[i * 3]);
      y0 = Math.min(y0, -P[i * 3 + 1]);
      y1 = Math.max(y1, -P[i * 3 + 1]);
    }
    const W = x1 - x0 || 1;
    const H = y1 - y0 || 1;
    for (let i = 0; i < n; i++) {
      this.ux[i] = (P[i * 3] - x0) / W;
      this.uy[i] = (-P[i * 3 + 1] - y0) / H;
      this.rnd[i] = (Math.sin(i * 12.9898 + 4.1) * 43758.5453) % 1;
      if (this.rnd[i] < 0) this.rnd[i] += 1;
    }
    for (const f of stage.fixtures) for (let i = 0; i < f.count && f.offset + i < n; i++) this.along[f.offset + i] = f.count > 1 ? i / (f.count - 1) : 0;
  }
}

/** Where LED `i` is for a transition (0..1: when the edge crosses it), inside a box of the yard. */
export function transitionCoord(type: TransitionId, places: LedPlaces, i: number, box: Box): number {
  const ux = places.ux[i];
  const uy = places.uy[i];
  const w = box[1] - box[0];
  const h = box[3] - box[2];
  const fx = w > 1e-6 ? (ux - box[0]) / w : 0.5;
  const fy = h > 1e-6 ? (uy - box[2]) / h : 0.5;
  switch (type) {
    case 'wipeRight':
      return fx;
    case 'wipeLeft':
      return 1 - fx;
    case 'wipeUp':
      return fy;
    case 'wipeDown':
      return 1 - fy;
    case 'diagonal':
      return (fx + fy) / 2;
    case 'splitOut':
      return Math.min(1, Math.abs(fx - 0.5) * 2);
    case 'splitIn':
      return 1 - Math.min(1, Math.abs(fx - 0.5) * 2);
    case 'iris':
    case 'irisClose': {
      // A circle in the front view, from the middle of the box.
      const cx = (box[0] + box[1]) / 2;
      const cy = (box[2] + box[3]) / 2;
      const R = Math.hypot(w, h) / 2 || 1;
      const r = Math.min(1, Math.hypot(ux - cx, uy - cy) / R);
      return type === 'iris' ? r : 1 - r;
    }
    case 'clock': {
      // Clockwise from straight up, round the middle of the box.
      const a = Math.atan2(fx - 0.5, fy - 0.5) / (2 * Math.PI);
      return a < 0 ? a + 1 : a;
    }
    case 'blinds':
      return (fx * BLINDS) % 1;
    case 'strings':
      return places.along[i];
    case 'dissolve':
      return places.rnd[i];
    default:
      return 0;
  }
}

const BLINDS = 6;

/** How wide a transition's soft edge is (in its 0..1 coordinate). */
const EDGE: Partial<Record<TransitionId, number>> = { dissolve: 0.06, strings: 0.12, blinds: 0.3, clock: 0.08 };

/**
 * How much of an outgoing and an incoming show lights one LED, `p` (0..1) of the way through a
 * transition, into `out`: [color out, cover out, color in, cover in, white]. Color weights mix
 * the colors; cover weights say how much each covers what is below it (in a sequence, the
 * layers below: a fade to nothing shows them); white is light added on top (a flash). `s` is
 * where the LED is (see transitionCoord).
 */
export function transitionWeights(type: TransitionId, p: number, s: number, out: Float32Array) {
  out[4] = 0;
  if (type === 'dip' || type === 'flash') {
    out[0] = Math.max(0, 1 - 2 * p);
    out[1] = Math.min(1, 2 - 2 * p);
    out[2] = Math.max(0, 2 * p - 1);
    out[3] = Math.min(1, 2 * p);
    if (type === 'flash') out[4] = 1 - Math.abs(2 * p - 1);
    return;
  }
  let m: number;
  if (type === 'fade') m = p;
  else {
    // A soft edge that crosses every LED between p = 0 and p = 1.
    const W = EDGE[type] ?? 0.18;
    const x = (p * (1 + W) - s) / W;
    m = x <= 0 ? 0 : x >= 1 ? 1 : x * x * (3 - 2 * x);
  }
  out[0] = out[1] = 1 - m;
  out[2] = out[3] = m;
}

/**
 * Mixes two whole frames (3 floats per stage LED) `p` (0..1) of the way through a transition
 * from `from` to `to`, into `out` (it may be `to`).
 */
export function crossFrames(type: TransitionId, p: number, from: Float32Array, to: Float32Array, out: Float32Array, places: LedPlaces, box: Box = WHOLE_YARD) {
  const w = new Float32Array(5);
  const q = Math.max(0, Math.min(1, p));
  const n = Math.min(places.ux.length, out.length / 3);
  for (let i = 0; i < n; i++) {
    transitionWeights(type, q, transitionCoord(type, places, i, box), w);
    const k = i * 3;
    for (let j = 0; j < 3; j++) out[k + j] = from[k + j] * w[0] + to[k + j] * w[2] + w[4];
  }
}

/** Something drawn frame by frame (a scene's effects, a sequence). */
export interface Drawn<S> {
  setStage(stage: Stage, layout: S): void;
  update(dt: number, out: Float32Array): void;
  objects(): string[];
}

/**
 * One show giving way to the next over `seconds`. Both keep running while it lasts; after, it
 * draws only the next one (`done`). It lights the objects of the next one.
 */
export class Crossover<S, P extends Drawn<S> = Drawn<S>> implements Drawn<S> {
  readonly from: P;
  readonly to: P;
  readonly type: TransitionId;
  private seconds: number;
  private t = 0;
  private places: LedPlaces;
  private buf: Float32Array;

  constructor(stage: Stage, from: P, to: P, type: TransitionId, seconds: number) {
    this.from = from;
    this.to = to;
    this.type = type;
    this.seconds = Math.max(0, seconds);
    this.places = new LedPlaces(stage);
    this.buf = new Float32Array(stage.pixelCount * 3);
  }

  get done() {
    return this.t >= this.seconds;
  }

  /** 0..1: how far it has come. */
  get progress() {
    return this.seconds > 0 ? Math.min(1, this.t / this.seconds) : 1;
  }

  setStage(stage: Stage, layout: S) {
    this.from.setStage(stage, layout);
    this.to.setStage(stage, layout);
    this.places = new LedPlaces(stage);
    if (this.buf.length !== stage.pixelCount * 3) this.buf = new Float32Array(stage.pixelCount * 3);
  }

  update(dt: number, out: Float32Array) {
    this.t += Math.max(0, dt);
    this.to.update(dt, out);
    if (this.done) return;
    this.from.update(dt, this.buf);
    crossFrames(this.type, this.progress, this.buf, out, out, this.places);
  }

  objects() {
    return this.to.objects();
  }
}
