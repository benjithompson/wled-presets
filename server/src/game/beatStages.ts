import { hsv, mix, type Rgb } from '../../../shared/color.ts';

// Beat Drop's stages: every STAGE_BARS bars the whole roofline changes its look, like the skins of
// a puzzle game that change as the music does. Each stage paints a backdrop along the full roof,
// behind the notes and timed to the music, and each one is busier than the one before: a calm
// night first, then waves, curtains of light, twinkling stars, ripples on every beat and at last a
// rainbow that turns on the beat. The busier the backdrop, the harder it is to pick out the notes:
// that is part of the difficulty. The notes always stay readable: the game dims the backdrop
// under and around every note (see beat.ts), and the backdrop stays far dimmer than a note head.
//
// The backdrops keep away from white (in the one-color game, the notes are white) and from red
// (a miss), and use the note colors only dimly and late, when the stages are meant to be hard.

/** Bars in a stage. The eighth bar of each stage is a breather; the next stage starts right after. */
export const STAGE_BARS = 8;

/** One LED step of the roof, as a backdrop paints it. The caller reuses one object for every step. */
export interface Scene {
  /** The step along the roof (0 to n - 1). */
  i: number;
  /** Steps from the hit zone toward the far end of the roof (where the notes come from); negative past it. */
  x: number;
  /** x over the length from the zone to the far end: 0 at the zone, 1 at the far end. */
  u: number;
  /** Steps from the zone to the far end. */
  span: number;
  /** Seconds, always running. */
  clock: number;
  /** Where in the beat: 0 on the beat, rising to 1 just before the next. */
  beat: number;
  /** Where in the bar, the same way. */
  bar: number;
  /** Whole beats since the song began. */
  beats: number;
  /** How strong: 1 on Normal's first round of stages, less on Easy, more on Hard and later rounds. */
  k: number;
}

export interface Look {
  name: string;
  /** The stage's color, for the sweep that brings it in and the house as it plays. */
  accent: Rgb;
  /** Adds this step's backdrop light to `out`. */
  paint(s: Scene, out: Rgb): void;
}

const add = (out: Rgb, c: Rgb, a: number) => {
  out[0] += c[0] * a;
  out[1] += c[1] * a;
  out[2] += c[2] * a;
};

/** A flash on the beat that dies away. */
const onBeat = (beat: number, sharp = 5) => Math.exp(-beat * sharp);

/** A number 0..1 for each whole number, the same every time. */
export function hash(i: number) {
  let h = Math.imul((i | 0) ^ 0x9e3779b9, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return (h >>> 0) / 4294967296;
}

const ROSE: Rgb = [0.6, 0.02, 0.15];
const AMBER: Rgb = [1, 0.4, 0.03];
const TEAL: Rgb = [0, 0.7, 0.45];
const VIOLET: Rgb = [0.45, 0.05, 0.8];
const PINK: Rgb = [1, 0.05, 0.45];
const ORANGE: Rgb = [1, 0.35, 0];
const LAVENDER: Rgb = [0.6, 0.35, 1];

/** A band that sweeps from the zone to the far end once a bar: the stage's own timeline. */
function timeline(s: Scene, out: Rgb, color: Rgb, amount: number) {
  const d = (s.x - s.bar * (s.span + 24)) / 3;
  if (d > -3 && d < 3) add(out, color, Math.exp(-d * d) * amount);
}

export const LOOKS: Look[] = [
  {
    // A calm night: deep indigo, breathing on the beat.
    name: 'Midnight',
    accent: [0.35, 0.15, 1],
    paint(s, out) {
      const shimmer = 0.5 + 0.5 * Math.sin(s.u * 14 - s.clock * 0.8);
      add(out, [0.03, 0.012, 0.07], 1);
      add(out, [0.12, 0.04, 0.4], s.k * (0.06 * shimmer + 0.12 * onBeat(s.beat)));
    }
  },
  {
    // Warm waves rolling out from the zone along the roof.
    name: 'Ember Tide',
    accent: AMBER,
    paint(s, out) {
      const w = 0.5 + 0.5 * Math.sin(s.x * 0.16 - s.clock * 2.6);
      add(out, [0.03, 0.005, 0.01], 1);
      add(out, mix(ROSE, AMBER, w), s.k * (0.04 + 0.16 * w * w) * (0.75 + 0.25 * onBeat(s.beat)));
    }
  },
  {
    // Curtains of teal and violet drifting both ways, shimmering.
    name: 'Aurora',
    accent: TEAL,
    paint(s, out) {
      const a = 0.5 + 0.5 * Math.sin(s.x * 0.06 + s.clock * 0.7);
      const b = 0.5 + 0.5 * Math.sin(s.x * 0.11 - s.clock * 1.2 + 2);
      const shimmer = 0.8 + 0.2 * Math.sin(s.clock * 6 + s.i * 1.7);
      add(out, [0.005, 0.015, 0.03], 1);
      add(out, mix(TEAL, VIOLET, b), s.k * (0.03 + 0.24 * a * a) * shimmer * (0.8 + 0.2 * onBeat(s.beat)));
    }
  },
  {
    // A deep blue sky full of stars that twinkle in and out.
    name: 'Starfall',
    accent: [1, 0.75, 0.4],
    paint(s, out) {
      add(out, [0.008, 0.012, 0.05], 1 + 0.6 * onBeat(s.beat, 4));
      const h = hash(s.i);
      add(out, [0.1, 0.06, 0.3], s.k * 0.05 * (0.5 + 0.5 * Math.sin(s.u * 6 + s.clock * 0.4)));
      if (hash(s.i + 7777) < Math.min(0.6, 0.4 * s.k)) {
        const p = (s.clock * (0.35 + 0.5 * h) + h * 13) % 1;
        if (p < 0.22) add(out, mix([1, 0.75, 0.35], [0.7, 0.5, 1], h), (1 - p / 0.22) ** 2 * 0.42 * s.k);
      }
    }
  },
  {
    // Ripples running out from the zone on every beat, pink and orange in turn, and a timeline.
    name: 'Pulse',
    accent: PINK,
    paint(s, out) {
      add(out, [0.04, 0, 0.03], 1);
      const ax = Math.abs(s.x);
      for (let j = 0; j < 3; j++) {
        const d = (ax - (s.beat + j) * s.span * 0.5) / 5;
        if (d > -3 && d < 3) add(out, (s.beats - j) % 2 ? ORANGE : PINK, Math.exp(-d * d) * (1 - j / 3) * 0.22 * s.k);
      }
      timeline(s, out, LAVENDER, 0.2 * s.k);
    }
  },
  {
    // A rainbow in blocks that turns on every beat, with a timeline: every color, everywhere.
    name: 'Prism',
    accent: [0.9, 0.3, 1],
    paint(s, out) {
      const block = Math.floor((s.x + 1000) / 10);
      add(out, hsv((block * 0.13 + s.beats * 0.17) % 1, 0.9), s.k * (0.05 + 0.14 * onBeat(s.beat, 4)));
      timeline(s, out, LAVENDER, 0.24 * s.k);
    }
  }
];

/** The look of a stage (0: the first): the looks in turn, round and round. */
export const lookOf = (stage: number) => LOOKS[((stage % LOOKS.length) + LOOKS.length) % LOOKS.length];
