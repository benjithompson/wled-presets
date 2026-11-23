// The showcase: a 60-second show to a beat, built for whatever yard the layout has. The objects
// are its band. The trees are the kick drum, the bushes the hi-hats and the bass, the roof's
// segments the keys the melody plays on (low notes on the left, high ones on the right), and an
// arpeggio hops from object to object like notes on a staff.
//
// The show is mostly motion on dark: every quarter note moves somewhere (a light that walks
// along the roof, each object wiping side to side or up and down, a laser scanning across the
// bushes or up the trees, a wave across the yard), and what moves grows with the music: one
// roof key in the intro, the bushes in the build, every object in the drops, everything with a
// 3-D picture behind it at the end of the second drop. The dark between the beats (negative
// space) is part of it: the yard's 3-D pictures play only where the music swells.
//
// One score drives both the lights (a sequence) and the music (the editor synthesizes it into
// an audio track, web/src/pages/admin/sequence/showcaseAudio.ts), so every flash lands on its
// note. Keep this file free of Node and DOM APIs.

import { hex, hsv, mix, fromHex } from './color.ts';
import { defaultSettings, effectInfo, effectKey, YARD, type EffectId, type EffectSettings } from './effects.ts';
import { activeLeds, buildStage, isLine, segmentLeds, type Layout } from './layout.ts';
import { newId, type SeqClip, type SeqTrack, type Sequence } from './sequence.ts';
import type { TransitionChoice } from './transitions.ts';

export const SHOWCASE_BPM = 128;
/** 32 bars of 4/4 at 128 beats a minute. */
export const SHOWCASE_SECONDS = 60;

const BEAT = 60 / SHOWCASE_BPM;
const BAR = 4 * BEAT;
const S16 = BEAT / 4;
/** The time of a bar, beat and sixteenth (all from 0). */
const at = (bar: number, beat = 0, six = 0) => bar * BAR + beat * BEAT + six * S16;

export type Instrument = 'kick' | 'clap' | 'snare' | 'hat' | 'bass' | 'lead' | 'arp' | 'pad' | 'stab' | 'impact' | 'riser';

/** One note of the score. */
export interface ScoreNote {
  inst: Instrument;
  /** Seconds from the start, and how long it sounds. */
  t: number;
  dur: number;
  /** MIDI note numbers (a chord has several; drums have none). */
  notes: number[];
  /** 0..1 */
  vel: number;
  /** Where it sounds, -1 (left) to 1 (right): where its light is in the yard. */
  pan: number;
}

export interface Showcase {
  sequence: Sequence;
  score: ScoreNote[];
}

// ---------- The music ----------

/** The sections, by bar. */
const SECTIONS = [
  { bar: 0, label: 'Intro' },
  { bar: 4, label: 'Build' },
  { bar: 8, label: 'Rise' },
  { bar: 12, label: 'Drop' },
  { bar: 20, label: 'Breakdown' },
  { bar: 24, label: 'Drop 2' },
  { bar: 30, label: 'Finale' }
];

/** A minor: Am, F, C, G, one chord a bar. Each has its color and an accent that answers it. */
const CHORDS = [
  { name: 'Am', bass: 33, tones: [57, 60, 64, 69], color: '#b000ff', accent: '#ff2a8a' },
  { name: 'F', bass: 29, tones: [53, 57, 60, 65], color: '#0050ff', accent: '#00e5ff' },
  { name: 'C', bass: 36, tones: [60, 64, 67, 72], color: '#00e0b0', accent: '#ffe000' },
  { name: 'G', bass: 31, tones: [55, 59, 62, 67], color: '#ff6000', accent: '#ff0050' }
];
const chordOf = (bar: number) => CHORDS[bar % 4];

/** The hook, four bars of [sixteenth, note, length in sixteenths]. */
const HOOK: [number, number, number][][] = [
  [[0, 69, 2], [3, 72, 1], [4, 76, 2], [6, 81, 2], [8, 79, 3], [11, 76, 1], [12, 74, 2], [14, 72, 2]],
  [[0, 72, 2], [3, 69, 1], [4, 72, 2], [6, 77, 2], [8, 76, 4], [12, 72, 2], [14, 69, 2]],
  [[0, 67, 2], [3, 72, 1], [4, 76, 2], [6, 79, 2], [8, 81, 3], [11, 79, 1], [12, 76, 2], [14, 72, 2]],
  [[0, 71, 2], [3, 74, 1], [4, 79, 2], [6, 83, 2], [8, 81, 2], [10, 79, 2], [12, 74, 4]]
];

/** The breakdown's slow tune, one bar per chord. */
const AIR: [number, number, number][][] = [
  [[0, 76, 6], [6, 74, 2], [8, 72, 8]],
  [[0, 69, 6], [6, 72, 2], [8, 77, 8]],
  [[0, 79, 6], [6, 76, 2], [8, 72, 8]],
  [[0, 74, 4], [4, 71, 4], [8, 79, 8]]
];

/** Arpeggios: which of a chord's six tones (its four, then the first two an octave up) each step plays. */
const ARP8 = [0, 1, 2, 3, 2, 1, 2, 3];
const ARP16 = [0, 1, 2, 3, 4, 5, 4, 3, 2, 3, 4, 5, 4, 3, 2, 1];
const arpTone = (bar: number, k: number) => {
  const t = chordOf(bar).tones;
  return k < 4 ? t[k] : t[k - 4] + 12;
};

/** The score's notes, before they are placed in the yard (pan 0). */
function compose(): ScoreNote[] {
  const out: ScoreNote[] = [];
  const add = (inst: Instrument, t: number, dur: number, notes: number[], vel: number) => out.push({ inst, t, dur, notes, vel, pan: 0 });
  const drop = (bar: number) => (bar >= 12 && bar < 20) || (bar >= 24 && bar < 31);
  for (let bar = 0; bar < 32; bar++) {
    const chord = chordOf(bar);
    // Drums.
    for (let b = 0; b < 4; b++) {
      const kick = (bar >= 4 && bar < 11) || drop(bar) || (bar === 11 && b === 0) || (bar === 31 && b === 0);
      if (kick) add('kick', at(bar, b), BEAT, [], bar >= 12 ? 1 : 0.85);
      if (drop(bar) && (b === 1 || b === 3)) add('clap', at(bar, b), BEAT, [], 0.9);
    }
    if (bar >= 4 && bar < 11) for (let b = 0; b < 4; b++) add('hat', at(bar, b, 2), S16, [], 0.5);
    if (drop(bar)) for (let s = 0; s < 16; s++) add('hat', at(bar, 0, s), S16, [], s % 4 === 2 ? 0.55 : 0.22);
    // The rise: the snare comes faster and louder, and stops for a beat before the drop.
    const roll = bar === 8 ? 4 : bar === 9 ? 8 : bar === 10 || bar === 11 || bar === 23 ? 16 : 0;
    const rollEnd = bar === 11 ? 12 : bar === 23 ? 14 : 16;
    for (let s = 0; s < 16 && roll; s += 16 / roll) {
      if (s >= rollEnd) break;
      const from = bar === 23 ? at(23) : at(8);
      const span = bar === 23 ? BAR : at(12) - at(8);
      add('snare', at(bar, 0, s), (16 / roll) * S16, [], 0.3 + 0.7 * ((at(bar, 0, s) - from) / span));
    }
    if (bar === 8) add('riser', at(8), at(11, 3) - at(8), [], 0.8);
    if (bar === 23) add('riser', at(23), at(23, 3, 2) - at(23), [], 0.7);
    if (bar === 12 || bar === 24 || bar === 30 || bar === 31) add('impact', at(bar), bar === 31 ? 3.5 : 2.5, [], 1);
    // Bass: on the off-beats as it builds, rolling eighths in the drops.
    if (bar >= 6 && bar < 11) for (let b = 0; b < 4; b++) add('bass', at(bar, b, 2), S16 * 1.6, [chord.bass + 12], 0.7);
    if (drop(bar) && bar < 30) for (let e = 0; e < 8; e++) add('bass', at(bar, 0, e * 2), S16 * 1.7, [chord.bass + (e % 4 === 3 ? 24 : 12)], e % 2 ? 0.7 : 0.9);
    // Pads under the quiet parts.
    if (bar < 12 || (bar >= 20 && bar < 24)) add('pad', at(bar), BAR, chord.tones, bar < 4 || bar >= 20 ? 0.5 : 0.3);
    // Melodies.
    if (bar < 12) for (let e = 0; e < 8; e++) add('arp', at(bar, 0, e * 2), S16 * 1.7, [arpTone(bar, ARP8[e]) + (bar >= 8 && e % 2 ? 12 : 0)], bar < 4 ? 0.45 : 0.6);
    if (bar >= 12 && bar < 20) for (const [s, n, len] of HOOK[bar % 4]) add('lead', at(bar, 0, s), len * S16, [n], 0.85);
    if (bar >= 20 && bar < 24) for (const [s, n, len] of AIR[bar % 4]) add('lead', at(bar, 0, s), len * S16, [n], 0.6);
    if (bar >= 24 && bar < 30) for (let s = 0; s < 16; s++) add('arp', at(bar, 0, s), S16 * 0.9, [arpTone(bar, ARP16[s]) + 12], s % 4 === 0 ? 0.75 : 0.5);
    if (bar === 30) for (let b = 0; b < 4; b++) add('stab', at(30, b), BEAT * 0.6, chordOf(b).tones, 0.9);
    if (bar === 31) add('stab', at(31), BAR * 0.95, CHORDS[0].tones.concat([45]), 1);
  }
  return out.sort((a, b) => a.t - b.t);
}

// ---------- The band: who plays what ----------

interface Player {
  /** The effect target: an object, or a segment of a roof or line. */
  key: string;
  /** Across the yard, 0 (left) to 1 (right). */
  x: number;
}

interface Band {
  /** Roof segments, left to right: the keys. */
  keys: Player[];
  /** Every object on the ground, left to right. */
  ground: Player[];
  /** Trees: the kick. */
  trees: Player[];
  /** Bushes: hi-hats and bass, played in turn left and right. */
  bushes: Player[];
  /** Whole roofs and lines: the claps and pads. */
  roof: Player[];
  /** Everything, left to right. */
  all: Player[];
}

function band(layout: Layout): Band {
  const stage = buildStage(layout);
  const w = layout.width || 1600;
  const byX = (a: Player, b: Player) => a.x - b.x;
  const keys: Player[] = [];
  const ground: Player[] = [];
  const trees: Player[] = [];
  const bushes: Player[] = [];
  const others: Player[] = [];
  const roof: Player[] = [];
  layout.fixtures.forEach((f, i) => {
    const sf = stage.fixtures[i];
    if (!sf || sf.count < 1) return;
    const me = { key: f.id, x: sf.center.x / w };
    if (isLine(f)) {
      if (!activeLeds(f).some(Boolean)) return;
      roof.push(me);
      for (let k = 0; k < f.points.length - 1; k++) {
        if (f.skip?.includes(k)) continue;
        const { lo, hi } = segmentLeds(f, k);
        if (hi - lo + 1 < 6) continue;
        const mid = Math.min(sf.count - 1, Math.round((lo + hi) / 2));
        keys.push({ key: effectKey(f.id, k), x: stage.positions[(sf.offset + mid) * 2] / w });
      }
      return;
    }
    ground.push(me);
    (f.kind === 'tree' ? trees : f.kind === 'bush' ? bushes : others).push(me);
  });
  for (const l of [keys, ground, trees, bushes, others, roof]) l.sort(byX);
  const yard = [{ key: YARD, x: 0.5 }];
  const all = [...keys, ...ground].sort(byX);
  return {
    keys: keys.length >= 3 ? keys : all.length ? all : yard,
    ground: ground.length ? ground : all.length ? all : yard,
    trees: trees.length ? trees : others.length ? others : bushes.length ? bushes : roof.length ? roof : yard,
    bushes: bushes.length ? bushes : ground.length ? ground : all.length ? all : yard,
    roof: roof.length ? roof : ground.length ? ground : yard,
    all: all.length ? all : yard
  };
}

/** The player for a note: low notes on the left, high ones on the right. */
const byPitch = (players: Player[], note: number, lo: number, hi: number) => players[Math.round(((Math.max(lo, Math.min(hi, note)) - lo) / (hi - lo)) * (players.length - 1))];

/** Left or right half of a group, in turn. */
const half = (players: Player[], k: number) => {
  if (players.length < 2) return players;
  const m = Math.ceil(players.length / 2);
  return k % 2 ? players.slice(m) : players.slice(0, m);
};

const panOf = (players: Player[]) => Math.max(-0.8, Math.min(0.8, (players.reduce((a, p) => a + p.x, 0) / players.length) * 2 - 1));

// ---------- The lights ----------

/** A note's color: around the circle of fifths, so notes that sound well together look close. */
const noteColor = (note: number, s = 1) => hex(hsv((((note % 12) * 7) % 12) / 12 + 0.6, s, 1));
const whiter = (color: string, k: number) => hex(mix(fromHex(color), [1, 1, 1], k));

const solid = (color: string, brightness = 1): EffectSettings => ({ ...defaultSettings('solid'), palette: 'custom', colors: [color], brightness: Math.max(0, Math.min(1, brightness)) });

function fx(effect: EffectId, s: Partial<EffectSettings>): EffectSettings {
  return { ...defaultSettings(effect), ...s };
}

const effectName = (id: EffectId) => effectInfo(id).name;

const r4 = (x: number) => Math.round(x * 10000) / 10000;

const keysOf = (players: Player[]) => [...new Set(players.map((p) => p.key))];

/** The laser scan's speed for one pass across its objects every `beats` beats (a pass is 1.5625 of its seconds at speed 0.5). */
const scanSpeed = (beats: number) => Math.max(0, Math.min(1, 0.5 + Math.log2(1.5625 / (beats * BEAT)) / 4));

class Layer {
  clips: SeqClip[] = [];
  readonly name: string;
  readonly blend: SeqTrack['blend'];
  readonly opacity: number;

  constructor(name: string, blend: SeqTrack['blend'], opacity = 1) {
    this.name = name;
    this.blend = blend;
    this.opacity = opacity;
  }

  /** A clip from `t` for `dur` seconds (rounded so that clips back to back never overlap). */
  add(targets: string[], t: number, dur: number, effect: EffectSettings, more: Partial<SeqClip> = {}) {
    const start = r4(t);
    const duration = r4(t + dur) - start;
    if (duration < 0.05) return;
    this.clips.push({ id: newId('clip'), start, duration, targets, effect, ...more });
  }

  /** A hit: lit at once, then fading away (or draining, with `out`) over most of its length. */
  hit(players: Player[], t: number, dur: number, color: string, brightness = 1, out: TransitionChoice = 'fade', inT?: TransitionChoice) {
    const d = Math.max(0.05, dur);
    this.add(keysOf(players), t, d, solid(color, brightness), {
      fadeOut: r4(d * 0.85),
      transitionOut: out,
      ...(inT ? { fadeIn: r4(Math.min(0.06, d * 0.3)), transitionIn: inT } : {})
    });
  }

  /**
   * A band of light that crosses each player on its own in `dur` seconds, the way `dir` goes:
   * it wipes in from one side and out the other, so every bush (say) shows the motion at once.
   */
  cross(players: Player[], t: number, dur: number, color: string, brightness: number, dir: TransitionChoice, name?: string) {
    // The way out starts while the way in is a third across: a band with dark either side.
    this.add(keysOf(players), t, dur, solid(color, brightness), {
      fadeIn: r4(dur * 0.6),
      transitionIn: dir,
      fadeOut: r4(dur * 0.75),
      transitionOut: dir,
      eachObject: true,
      ...(name ? { name } : {})
    });
  }

  /** Each player fills the way `inT` goes, then empties the way `out` goes. */
  fill(players: Player[], t: number, dur: number, color: string, brightness: number, inT: TransitionChoice, out: TransitionChoice) {
    this.add(keysOf(players), t, dur, solid(color, brightness), { fadeIn: r4(dur * 0.3), transitionIn: inT, fadeOut: r4(dur * 0.6), transitionOut: out, eachObject: true });
  }

  /** A band of light that sweeps across the whole yard in `dur` seconds: it wipes in from one side and out after it. */
  sweep(t: number, dur: number, color: string, brightness: number, dir: TransitionChoice = 'wipeRight') {
    const start = r4(t);
    const half = Math.floor(((r4(t + dur) - start) / 2) * 10000) / 10000;
    this.add([YARD], t, dur, solid(color, brightness), { fadeIn: half, transitionIn: dir, fadeOut: half, transitionOut: dir });
  }

  /**
   * A laser that scans across the players (as one) and back, a pass every `beats` beats from
   * `t`: it starts at the left (or the bottom) on the beat and reaches the other side on the
   * next. A new color on every pass.
   */
  laser(players: Player[], t: number, dur: number, beats: number, colors: string[], brightness: number, direction: 'right' | 'up') {
    this.add(keysOf(players), t, dur, fx('scanner', { palette: 'custom', colors, brightness, speed: scanSpeed(beats), intensity: 0.45, size: 0.55, direction }), {
      name: direction === 'up' ? 'Laser, up and down' : 'Laser, side to side',
      fadeOut: r4(Math.min(BEAT / 2, dur / 4))
    });
  }

  track(): SeqTrack {
    return { id: newId('layer'), name: this.name, clips: this.clips, opacity: this.opacity, blend: this.blend };
  }
}

/**
 * The yard's 3-D pictures. They are few and far between: most of the show is the band on dark
 * (negative space), with a picture behind it where the music swells (the rise, the end of each
 * drop) and in the quiet of the breakdown.
 */
const BED: { from: number; to: number; effect: EffectSettings; in?: TransitionChoice; fadeIn?: number; fadeOut?: number; name: string; tint?: boolean }[] = [
  // The end of the rise: stars stream out, faster and faster, until the beat of silence.
  { name: 'Hyperspace', from: at(10), to: at(11, 3), effect: fx('hyperspace', { brightness: 0.7, intensity: 1, speed: 0.85, size: 0.8, direction: 'out' }), fadeIn: BAR },
  // The end of the first drop: bars of light bounce to the beat.
  { name: 'Equalizer', from: at(18), to: at(20), effect: fx('equalizer', { brightness: 0.55, intensity: 0.8 }), fadeIn: BEAT },
  // Breakdown: snow, a few flakes on dark.
  { name: 'Snowfall', from: at(22), to: at(24), effect: fx('snowfall', { brightness: 0.45, intensity: 0.45, speed: 0.55 }), fadeIn: BAR, fadeOut: BEAT },
  // Drop 2 fills up: mirrors, then a hologram, then fireworks, brighter each time.
  { name: 'Kaleidoscope', tint: true, from: at(24), to: at(26), effect: fx('kaleidoscope', { brightness: 0.35, speed: 0.6, intensity: 0.6 }) },
  { name: 'Hologram', from: at(26), to: at(28), effect: fx('hologram', { palette: 'neon', brightness: 0.6, intensity: 0.5, size: 0.7, speed: 0.6 }), in: 'wipeUp' },
  { name: 'Starburst', from: at(28), to: at(30), effect: fx('starburst', { brightness: 0.85, intensity: 0.9 }), in: 'irisClose' },
  { name: 'Supernova', from: at(30), to: SHOWCASE_SECONDS, effect: fx('supernova', { brightness: 1, size: 0.7 }), in: 'flash', fadeOut: at(1) }
];
/** Pictures that follow on from the one before cross over it for this long. */
const BED_OVERLAP = BEAT;

/** The roof's own picture in a bar, where it has one: rising in the rise, rolling color in the second drop. */
function roofEffect(bar: number): EffectSettings | null {
  const c = chordOf(bar);
  const two = { palette: 'custom' as const, colors: [c.color, c.accent] };
  if (bar === 10) return fx('wipe', { ...two, speed: 0.55 + 0.12 * (bar - 8), intensity: 0.1, size: 0.3, brightness: 0.45 + 0.1 * (bar - 8) });
  if (bar >= 24 && bar < 30) return fx('rainbow', { palette: 'custom', colors: [c.color, c.accent, chordOf(bar + 1).color], speed: 0.8, size: 0.4, brightness: 0.25 + 0.04 * (bar - 24) });
  return null;
}

/** Side to side, beat by beat: right on the strong beats, left on the others. */
const sideOf = (beat: number): TransitionChoice => (beat % 2 ? 'wipeLeft' : 'wipeRight');
/** Up on the strong beats, down on the others. */
const upDownOf = (beat: number): TransitionChoice => (beat % 2 ? 'wipeDown' : 'wipeUp');

/**
 * How the quarter notes show, two bars (a phrase) at a time. Each phrase moves (side to side, up
 * and down, a laser, a light that walks) and lights a bit more of the yard than the quiet ones
 * before it, so the lit part grows as the song gets bigger: one roof key in the intro, the
 * bushes in the build, every object in the drops, and everything plus the roof in the second.
 */
type BeatLook =
  /** One player a beat, walking across a group and back, each crossed the way it walks. */
  | { kind: 'walk'; group: keyof Band; back?: boolean; brightness: number }
  /** Every player of a group crossed on its own, side to side or up and down. */
  | { kind: 'cross'; group: keyof Band; way: 'side' | 'upDown'; brightness: number }
  /** A laser across a group (as one), a pass a beat. */
  | { kind: 'laser'; group: keyof Band; direction: 'right' | 'up'; brightness: number; white?: boolean }
  /** A wave of color across the whole yard on every beat, there and back. */
  | { kind: 'wave'; brightness: number };

const BEAT_LOOKS: { bar: number; bars: number; looks: BeatLook[] }[] = [
  { bar: 0, bars: 4, looks: [{ kind: 'walk', group: 'keys', brightness: 0.5 }] },
  { bar: 4, bars: 2, looks: [{ kind: 'walk', group: 'keys', brightness: 0.9 }, { kind: 'cross', group: 'bushes', way: 'side', brightness: 0.7 }] },
  { bar: 6, bars: 2, looks: [{ kind: 'walk', group: 'keys', brightness: 0.9 }, { kind: 'laser', group: 'bushes', direction: 'right', brightness: 0.9 }] },
  { bar: 8, bars: 2, looks: [{ kind: 'cross', group: 'bushes', way: 'upDown', brightness: 0.85 }] },
  { bar: 10, bars: 2, looks: [{ kind: 'laser', group: 'ground', direction: 'up', brightness: 1 }] },
  { bar: 12, bars: 2, looks: [{ kind: 'laser', group: 'ground', direction: 'right', brightness: 1, white: true }] },
  { bar: 14, bars: 2, looks: [{ kind: 'cross', group: 'ground', way: 'side', brightness: 1 }] },
  { bar: 16, bars: 2, looks: [{ kind: 'wave', brightness: 0.7 }, { kind: 'cross', group: 'bushes', way: 'upDown', brightness: 0.8 }] },
  { bar: 18, bars: 2, looks: [{ kind: 'cross', group: 'ground', way: 'upDown', brightness: 1 }] },
  { bar: 20, bars: 4, looks: [{ kind: 'walk', group: 'ground', back: true, brightness: 0.45 }] },
  { bar: 24, bars: 2, looks: [{ kind: 'cross', group: 'all', way: 'side', brightness: 1 }] },
  { bar: 26, bars: 2, looks: [{ kind: 'laser', group: 'ground', direction: 'right', brightness: 1, white: true }, { kind: 'laser', group: 'trees', direction: 'up', brightness: 1 }] },
  { bar: 28, bars: 2, looks: [{ kind: 'laser', group: 'all', direction: 'right', brightness: 1, white: true }, { kind: 'cross', group: 'ground', way: 'upDown', brightness: 1 }] }
];

/** The color of a beat: the chord's on the strong beats, its accent on the others, whiter in the drops. */
function beatColor(bar: number, beat: number) {
  const c = chordOf(bar);
  const base = beat % 2 ? c.accent : c.color;
  return (bar >= 12 && bar < 20) || bar >= 24 ? whiter(base, 0.3) : base;
}

/**
 * The showcase for a layout: a 60-second sequence at 128 beats a minute, and its score (for the
 * music). The same layout always gets the same show.
 */
export function showcase(layout: Layout, name = 'Showcase'): Showcase {
  const b = band(layout);
  const score = compose();

  const blackout = new Layer('Blackout', 'normal');
  const flash = new Layer('Flash', 'add');
  const stabs = new Layer('Chord stabs', 'normal');
  const kick = new Layer('Kick (trees)', 'normal');
  const clap = new Layer('Clap (roof)', 'add');
  const roll = new Layer('Roof keys (snare roll)', 'normal');
  const lead = new Layer('Melody (roof keys)', 'normal');
  const arp = new Layer('Arpeggio (note to note)', 'normal');
  const walk = new Layer('Beat: a light that walks', 'lighten');
  const sides = new Layer('Beat: each object side to side', 'lighten');
  const upDown = new Layer('Beat: each object up and down', 'lighten');
  const lasers = new Layer('Beat: laser side to side', 'add');
  const lasersUp = new Layer('Beat: laser up and down', 'add');
  const waves = new Layer('Beat: waves across the yard', 'add');
  const bass = new Layer('Bass (bushes)', 'lighten');
  const hats = new Layer('Hi-hats (bushes)', 'add');
  const sweep = new Layer('Roof (beat sweeps)', 'lighten');
  const roof = new Layer('Roof (color)', 'lighten');
  const pump = new Layer('Pump: the yard ducks on the kick', 'multiply');
  const bed = new Layer('Yard 3-D', 'normal');

  let rolls = 0;
  let basses = 0;
  let hatN = 0;
  /** Bars where the yard's 3-D picture plays under a drop, to duck on the kick. */
  const bedUnder = (bar: number) => (bar >= 18 && bar < 20) || (bar >= 24 && bar < 30);
  for (const n of score) {
    const bar = Math.floor(n.t / BAR + 1e-6);
    const chord = chordOf(bar);
    const note = n.notes[0] ?? 0;
    switch (n.inst) {
      case 'kick': {
        const beat = Math.round((n.t - at(bar)) / BEAT);
        const color = beatColor(bar, beat);
        // The trees: filling from the ground in the build, up and back down in the rise, a
        // flash that drains away in the first drop, side to side in the second.
        if (bar < 8) kick.fill(b.trees, n.t, BEAT * 0.55, color, n.vel, 'wipeUp', 'fade');
        else if (bar < 12) kick.fill(b.trees, n.t, BEAT * 0.65, color, n.vel, 'wipeUp', 'wipeDown');
        else if (bar < 24 || bar >= 31) kick.hit(b.trees, n.t, BEAT * 0.45, color, n.vel, 'wipeDown');
        else kick.cross(b.trees, n.t, BEAT * 0.9, color, n.vel, sideOf(beat));
        // A band of a new color runs along the roof on every beat of the drops, with dark
        // either side of it: side to side in the first, out from the middle and back in the second.
        if (bar >= 12 && bar < 30) {
          const colors = [chord.color, chord.accent, whiter(chord.color, 0.35), chordOf(bar + 2).color];
          const dir: TransitionChoice = bar >= 24 ? (beat % 2 ? 'splitIn' : 'splitOut') : sideOf(beat);
          sweep.add(keysOf(b.roof), n.t, BEAT, solid(colors[beat], bar >= 24 ? 0.8 : 0.95), { fadeIn: r4(BEAT * 0.6), transitionIn: dir, fadeOut: r4(BEAT * 0.75), transitionOut: dir });
        }
        if (bedUnder(bar)) pump.hit([{ key: YARD, x: 0.5 }], n.t, BEAT * 0.8, '#4d4d4d', 1, bar >= 24 ? 'splitOut' : 'iris');
        n.pan = panOf(b.trees);
        break;
      }
      case 'clap':
        clap.hit(b.roof, n.t, BEAT * 0.5, whiter(Math.round((n.t - at(bar)) / BEAT) === 1 ? chord.accent : chord.color, 0.5), 0.8, 'fade', 'splitOut');
        n.pan = 0;
        break;
      case 'snare': {
        const p = [b.keys[rolls % b.keys.length]];
        roll.hit(p, n.t, Math.min(BEAT * 0.8, n.dur * 0.9), whiter('#ff2a8a', n.vel * 0.6), 0.4 + 0.6 * n.vel);
        n.pan = panOf(p);
        rolls++;
        break;
      }
      case 'hat': {
        if (bar >= 12) break;
        const p = half(b.bushes, hatN++);
        hats.hit(p, n.t, S16 * 0.95, whiter(hatN % 2 ? chord.accent : chord.color, 0.45), 0.35);
        n.pan = panOf(p);
        break;
      }
      case 'bass': {
        // Left and right in turn, dim, under the lasers; where each bush moves on its own, the
        // bass leaves them to it.
        const p = half(b.bushes, basses++);
        const shown = bar < 12 || (bar >= 12 && bar < 14) || (bar >= 26 && bar < 28);
        if (shown) bass.hit(p, n.t, Math.min(n.dur, S16 * 1.9), basses % 4 === 0 ? chord.accent : chord.color, bar >= 12 ? 0.4 : 0.5);
        n.pan = panOf(p);
        break;
      }
      case 'lead': {
        const p = [byPitch(b.keys, note, 67, 83)];
        lead.hit(p, n.t, n.dur * 0.94, noteColor(note), n.vel + 0.15, 'fade', n.dur >= BEAT / 2 ? 'splitOut' : undefined);
        n.pan = panOf(p);
        break;
      }
      case 'arp': {
        // In the second drop it runs up and down the roof, and along the ground with it.
        const p = bar >= 24 ? [byPitch(b.keys, note, 69, 88), byPitch(b.ground, note, 69, 88)] : [byPitch(b.ground, note, 53, 84)];
        arp.hit(p, n.t, n.dur * 0.94, noteColor(note, bar >= 24 ? 0.85 : 1), Math.min(1, n.vel + (bar < 4 ? 0.1 : 0.3)));
        n.pan = panOf(p);
        break;
      }
      case 'pad':
        n.pan = 0;
        break;
      case 'stab': {
        // The finale: left, right, left, everything; then one last chord that closes in to the middle.
        const last = bar === 31;
        const k = Math.round((n.t - at(30)) / BEAT);
        const p = last || k === 3 ? b.all : half(b.all, k);
        stabs.hit(p, n.t, last ? BAR : n.dur, last ? '#ffe6b0' : whiter(CHORDS[k % 4].color, 0.2), 1, last ? 'irisClose' : 'fade');
        n.pan = last || k === 3 ? 0 : panOf(p);
        break;
      }
      case 'impact':
        flash.hit([{ key: YARD, x: 0.5 }], n.t, 0.9, '#ffffff', 0.9, 'fade');
        break;
    }
  }

  // The quarter notes, phrase by phrase (see BEAT_LOOKS). The beat before each drop stays dark.
  const silent = (bar: number, beat: number) => (bar === 11 && beat === 3) || (bar === 23 && beat === 3);
  for (const phrase of BEAT_LOOKS) {
    for (const look of phrase.looks) {
      const group = 'group' in look ? b[look.group] : b.all;
      if (look.kind === 'laser') {
        // A clip a bar, so every bar starts again from the left (or the bottom) on its downbeat.
        const layer = look.direction === 'up' ? lasersUp : lasers;
        for (let bar = phrase.bar; bar < phrase.bar + phrase.bars; bar++) {
          const c = chordOf(bar);
          const colors = look.white ? [whiter(c.color, 0.25), whiter(c.accent, 0.25)] : [c.color, c.accent];
          const beats = bar === 11 ? 3 : 4;
          layer.laser(group, at(bar), beats * BEAT, 1, colors, look.brightness, look.direction);
        }
        continue;
      }
      for (let k = 0; k < phrase.bars * 4; k++) {
        const bar = phrase.bar + Math.floor(k / 4);
        const beat = k % 4;
        if (silent(bar, beat)) continue;
        const t = at(bar, beat);
        const color = beatColor(bar, beat);
        if (look.kind === 'walk') {
          // There and back, one a beat; in a group of one, it crosses it side to side.
          const n = group.length;
          const step = n > 1 ? k % (2 * n - 2) : 0;
          const i = step < n ? step : 2 * n - 2 - step;
          const forward = n > 1 ? step < n - 1 || step === 0 : beat % 2 === 0;
          const goingRight = look.back ? !forward : forward;
          const p = look.back ? group[n - 1 - i] : group[i];
          walk.cross([p], t, BEAT * 0.95, color, look.brightness, goingRight ? 'wipeRight' : 'wipeLeft');
        } else if (look.kind === 'cross') {
          const layer = look.way === 'side' ? sides : upDown;
          layer.cross(group, t, BEAT * 0.9, color, look.brightness, look.way === 'side' ? sideOf(beat) : upDownOf(beat));
        } else {
          waves.sweep(t, BEAT, color, look.brightness, sideOf(beat));
        }
      }
    }
  }
  // Waves once a bar in the breakdown, slow and dim.
  for (const bar of [22, 23]) waves.sweep(at(bar), bar === 23 ? 3 * BEAT : BAR, whiter(chordOf(bar).accent, 0.3), 0.4);

  // The roof's own color, where it has one, wiping in from one side and then the other.
  for (let bar = 0; bar < 30; bar++) {
    const effect = roofEffect(bar);
    if (!effect) continue;
    const first = !roofEffect(bar - 1);
    const overlap = first ? 0 : BEAT / 2;
    const end = bar === 10 ? at(11, 3) : at(bar + 1);
    roof.add(keysOf(b.roof), at(bar) - overlap, end - at(bar) + overlap, effect, {
      name: `${chordOf(bar).name}: ${effectName(effect.effect)}`,
      ...(first ? { fadeIn: r4(BEAT) } : { transitionIn: bar % 2 ? 'wipeRight' : 'wipeLeft' })
    });
  }

  // The beat of silence before each drop.
  blackout.add([YARD], at(11, 3), BEAT, solid('#000000', 1));
  blackout.add([YARD], at(23, 3, 2), BEAT / 2, solid('#000000', 1));

  // A picture that follows straight on from the one before crosses over it, so the new one is
  // in on the downbeat. A tinted picture takes the chord's colors, a new set every bar.
  let prevEnd = -1;
  for (const s of BED) {
    const ov = Math.abs(prevEnd - s.from) < 1e-6 ? BED_OVERLAP : 0;
    prevEnd = s.to;
    const more = { ...(s.fadeIn && !ov ? { fadeIn: r4(s.fadeIn) } : {}), ...(s.fadeOut ? { fadeOut: r4(s.fadeOut) } : {}) };
    if (!s.tint) {
      bed.add([YARD], s.from - ov, s.to - s.from + ov, s.effect, { name: s.name, ...(s.in && ov ? { transitionIn: s.in } : {}), ...more });
      continue;
    }
    for (let bar = Math.round(s.from / BAR); bar < Math.round(s.to / BAR); bar++) {
      const first = at(bar) === s.from;
      const o = first ? ov : BEAT / 2;
      const c = chordOf(bar);
      bed.add([YARD], at(bar) - o, BAR + o, { ...s.effect, palette: 'custom', colors: [c.color, c.accent, chordOf(bar + 1).color] }, {
        name: `${s.name} (${c.name})`,
        ...(first ? (s.in && ov ? { transitionIn: s.in } : {}) : { transitionIn: bar % 2 ? 'wipeUp' : 'diagonal' }),
        ...(first ? more : {})
      });
    }
  }

  const layers = [blackout, flash, stabs, kick, clap, roll, lead, arp, walk, sides, upDown, lasers, lasersUp, waves, sweep, roof, bass, hats, pump, bed];
  const sequence: Sequence = {
    id: '',
    name,
    duration: SHOWCASE_SECONDS,
    loop: true,
    bpm: SHOWCASE_BPM,
    tracks: layers.filter((l) => l.clips.length).map((l) => l.track()),
    audio: [{ id: newId('audio'), name: 'Audio 1', clips: [], volume: 1 }],
    markers: SECTIONS.map((s) => ({ id: newId('marker'), t: r4(at(s.bar)), label: s.label }))
  };
  return { sequence, score };
}
