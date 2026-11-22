// The showcase: a 60-second show to a beat, built for whatever yard the layout has. The objects
// are its band. The trees are the kick drum, the bushes the hi-hats and the bass, the roof's
// segments the keys the melody plays on (low notes on the left, high ones on the right), and
// the whole yard plays 3-D effects behind them, ducking on every kick in the drops. An
// arpeggio hops from object to object like notes on a staff. The roof is the lead: its own
// moving color all through, a new color swept across it on every beat of the drops. Every
// chord has a color and an accent, so the colors change every bar and every beat.
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
  kick: Player[];
  /** Bushes: hi-hats and bass, played in turn left and right. */
  hats: Player[];
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
  const kick = trees.length ? trees : others.length ? others : bushes.length ? bushes : roof.length ? roof : yard;
  return {
    keys: keys.length >= 3 ? keys : all.length ? all : yard,
    ground: ground.length ? ground : all.length ? all : yard,
    kick,
    hats: bushes.length ? bushes : ground.length ? ground : all.length ? all : yard,
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
    this.add(
      players.map((p) => p.key),
      t,
      d,
      solid(color, brightness),
      { fadeOut: r4(d * 0.85), transitionOut: out, ...(inT ? { fadeIn: r4(Math.min(0.06, d * 0.3)), transitionIn: inT } : {}) }
    );
  }

  /** A band of light that sweeps across the whole yard in `dur` seconds: it wipes in from one side and out after it. */
  sweep(t: number, dur: number, color: string, brightness: number, dir: 'wipeRight' | 'wipeLeft' = 'wipeRight') {
    const start = r4(t);
    const half = Math.floor(((r4(t + dur) - start) / 2) * 10000) / 10000;
    this.add([YARD], t, dur, solid(color, brightness), { fadeIn: half, transitionIn: dir, fadeOut: half, transitionOut: dir });
  }

  track(): SeqTrack {
    return { id: newId('layer'), name: this.name, clips: this.clips, opacity: this.opacity, blend: this.blend };
  }
}

/** The yard's 3-D picture behind the band, section by section. */
const BED: { from: number; to: number; effect: EffectSettings; in?: TransitionChoice; overlap?: number; fadeIn?: number; fadeOut?: number; name: string; tint?: boolean }[] = [
  // Intro: night sky, then fireflies wake up.
  { name: 'Nebula', from: 0, to: at(2), effect: fx('nebula', { brightness: 0.5, speed: 0.35, size: 0.65 }), fadeIn: at(1, 2) },
  { name: 'Fireflies', from: at(2), to: at(4), effect: fx('fireflies', { brightness: 0.9, intensity: 0.95, size: 0.75 }), in: 'dissolve', overlap: BAR },
  // Build: things start to turn.
  { name: 'Double helix', tint: true, from: at(4), to: at(6), effect: fx('helix', { brightness: 0.6, speed: 0.55 }), in: 'diagonal', overlap: BAR },
  { name: 'Orbits', from: at(6), to: at(8), effect: fx('orbits', { brightness: 0.75, intensity: 0.7, speed: 0.6 }), in: 'iris', overlap: 2 * BEAT },
  // Rise: the jump to hyperspace, faster and faster.
  { name: 'Hyperspace', from: at(8), to: at(10), effect: fx('hyperspace', { brightness: 0.8, intensity: 0.95, speed: 0.55, size: 0.6, direction: 'out' }), in: 'iris', overlap: 2 * BEAT },
  { name: 'Hyperspace, faster', from: at(10), to: at(12), effect: fx('hyperspace', { brightness: 1, intensity: 1, speed: 0.9, size: 0.8, direction: 'out' }), in: 'fade', overlap: BEAT },
  // Drop: a new big picture every two bars.
  { name: 'Kaleidoscope', tint: true, from: at(12), to: at(14), effect: fx('kaleidoscope', { brightness: 1, speed: 0.6, intensity: 0.6 }) },
  { name: 'Plasma globe', from: at(14), to: at(16), effect: fx('tesla', { brightness: 1, intensity: 1, size: 0.7, speed: 0.65 }), in: 'clock', overlap: 2 * BEAT },
  { name: 'Vortex', tint: true, from: at(16), to: at(18), effect: fx('vortex', { palette: 'party', brightness: 1, intensity: 0.6, speed: 0.6 }), in: 'blinds', overlap: 2 * BEAT },
  { name: 'Equalizer', from: at(18), to: at(20), effect: fx('equalizer', { brightness: 1, intensity: 0.8 }), in: 'splitOut', overlap: 2 * BEAT },
  // Breakdown: falling into a black hole, then snow.
  { name: 'Black hole', from: at(20), to: at(22), effect: fx('blackhole', { palette: 'galaxy', brightness: 1, intensity: 0.7, size: 0.7, speed: 0.5 }), in: 'dissolve', overlap: BAR },
  { name: 'Snowfall', from: at(22), to: at(24), effect: fx('snowfall', { brightness: 0.75, intensity: 0.7, speed: 0.55 }), in: 'wipeDown', overlap: 2 * BEAT },
  // Drop 2: rings of color, a hologram in the air, fireworks.
  { name: 'Color rings', from: at(24), to: at(26), effect: fx('wash', { palette: 'rainbow', brightness: 0.75, intensity: 0.7, size: 0.3, speed: 0.75, direction: 'out' }) },
  { name: 'Hologram', from: at(26), to: at(28), effect: fx('hologram', { palette: 'neon', brightness: 1, intensity: 0.5, size: 0.7, speed: 0.6 }), in: 'wipeUp', overlap: 2 * BEAT },
  { name: 'Starburst', from: at(28), to: at(30), effect: fx('starburst', { brightness: 1, intensity: 0.9 }), in: 'irisClose', overlap: 2 * BEAT },
  { name: 'Supernova', from: at(30), to: SHOWCASE_SECONDS, effect: fx('supernova', { brightness: 1, size: 0.7 }), in: 'flash', overlap: BEAT, fadeOut: at(1) }
];

/** The laser scan's speed for one pass across the yard every `beats` beats (a pass is 1.5625 of its seconds at speed 0.5). */
const scanSpeed = (beats: number) => Math.max(0, Math.min(1, 0.5 + Math.log2(1.5625 / (beats * BEAT)) / 4));

/** How a tinted picture changes color at a bar line inside its section. */
const BAR_TURNS: TransitionChoice[] = ['fade', 'wipeUp', 'diagonal', 'wipeDown'];

/** The roof's own picture in a bar: moving color in the chord's two colors, busier as the song goes (in the drops, under the beat sweeps). */
function roofEffect(bar: number): EffectSettings | null {
  const c = chordOf(bar);
  const two = { palette: 'custom' as const, colors: [c.color, c.accent] };
  if (bar < 4) return fx('rainbow', { ...two, speed: 0.35, size: 0.7, brightness: 0.45 + 0.1 * bar });
  if (bar < 8) return fx('chase', { ...two, speed: 0.55, intensity: 0.5, size: 0.4, brightness: 0.75 });
  if (bar < 12) return fx('wipe', { ...two, speed: 0.55 + 0.12 * (bar - 8), intensity: 0.1, size: 0.3, brightness: 0.6 + 0.1 * (bar - 8) });
  if (bar < 20) {
    const k = Math.floor((bar - 12) / 2);
    const effect = (['chase', 'candy', 'sparkle', 'wipe'] as EffectId[])[k];
    return fx(effect, { ...two, speed: 0.75, intensity: 0.55, size: 0.4, brightness: 0.4 });
  }
  if (bar < 24) return fx('breathe', { ...two, speed: 0.6, intensity: 0.35, brightness: 0.7 });
  if (bar < 30) return fx('rainbow', { palette: 'custom', colors: [c.color, c.accent, chordOf(bar + 1).color], speed: 0.8, size: 0.4, brightness: 0.45 });
  return null;
}

/**
 * The showcase for a layout: a 60-second sequence at 128 beats a minute, and its score (for the
 * music). The same layout always gets the same show.
 */
export function showcase(layout: Layout, name = 'Showcase'): Showcase {
  const b = band(layout);
  const score = compose();

  const blackout = new Layer('Blackout', 'normal');
  const sweeps = new Layer('Yard sweeps (beat)', 'add');
  const flash = new Layer('Flash', 'add');
  const stabs = new Layer('Chord stabs', 'normal');
  const kick = new Layer('Kick (trees)', 'normal');
  const clap = new Layer('Clap (roof)', 'add');
  const roll = new Layer('Roof keys (beats, snare roll)', 'normal');
  const lead = new Layer('Melody (roof keys)', 'normal');
  const arp = new Layer('Arpeggio (note to note)', 'normal');
  const bass = new Layer('Bass (bushes)', 'lighten');
  const hats = new Layer('Hi-hats (bushes)', 'add');
  const sweep = new Layer('Roof (beat sweeps)', 'lighten');
  const roof = new Layer('Roof (color)', 'lighten');
  const pump = new Layer('Pump: the yard ducks on the kick', 'multiply');
  const bed = new Layer('Yard 3-D', 'normal');

  let kicks = 0;
  let rolls = 0;
  let basses = 0;
  let hatN = 0;
  for (const n of score) {
    const bar = Math.floor(n.t / BAR + 1e-6);
    const chord = chordOf(bar);
    const note = n.notes[0] ?? 0;
    switch (n.inst) {
      case 'kick': {
        // Short, so the yard's picture shows on the trees between the beats.
        const dur = BEAT * (bar >= 12 ? 0.6 : 0.75);
        // The chord's color on the strong beats, its accent on the others.
        const beat = Math.round((n.t - at(bar)) / BEAT);
        const base = beat % 2 ? chord.accent : chord.color;
        const color = bar >= 12 ? whiter(base, 0.45) : base;
        kick.hit(b.kick, n.t, dur, color, n.vel, bar >= 12 ? 'wipeDown' : 'fade');
        // The roof sweeps a new color across on every beat of the drops: side to side in the
        // first, opening from the middle and closing in the second.
        if (bar >= 12 && bar < 30) {
          const colors = [chord.color, chord.accent, whiter(chord.color, 0.35), chordOf(bar + 2).color];
          const dir: TransitionChoice = bar >= 24 ? (beat % 2 ? 'splitIn' : 'splitOut') : beat % 2 ? 'wipeLeft' : 'wipeRight';
          sweep.add(b.roof.map((p) => p.key), n.t, BEAT, solid(colors[beat], bar >= 24 ? 0.7 : 0.95), { fadeIn: r4(BEAT * 0.22), transitionIn: dir, fadeOut: r4(BEAT * 0.7) });
        }
        if (bar >= 12) pump.hit([{ key: YARD, x: 0.5 }], n.t, BEAT * 0.8, '#4d4d4d', 1, bar >= 24 ? 'splitOut' : kicks % 8 < 4 ? 'fade' : 'iris');
        n.pan = panOf(b.kick);
        kicks++;
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
        const p = half(b.hats, hatN++);
        hats.hit(p, n.t, S16 * 0.95, whiter(hatN % 2 ? chord.accent : chord.color, 0.45), 0.6);
        n.pan = panOf(p);
        break;
      }
      case 'bass': {
        const p = half(b.hats, basses++);
        bass.hit(p, n.t, Math.min(n.dur, S16 * 1.9), basses % 4 === 0 ? chord.accent : chord.color, bar >= 12 ? 1 : 0.7);
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
        arp.hit([...new Map(p.map((x) => [x.key, x])).values()], n.t, n.dur * 0.94, noteColor(note, bar >= 24 ? 0.85 : 1), n.vel + 0.3);
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
  // The build: the roof counts the beats, one key a beat, there and back.
  if (b.keys.length > 1)
    for (let k = 0; k < 16; k++) {
      const n = b.keys.length;
      const i = k % (2 * n - 2) < n ? k % (2 * n - 2) : 2 * n - 2 - (k % (2 * n - 2));
      const chord = chordOf(4 + Math.floor(k / 4));
      roll.hit([b.keys[i]], at(4, k), BEAT * 0.9, whiter(k % 2 ? chord.accent : chord.color, 0.3), 1);
    }

  // The roof's own color, a new one every bar, wiping in from one side and then the other.
  for (let bar = 0; bar < 30; bar++) {
    const effect = roofEffect(bar);
    if (!effect) continue;
    const section = SECTIONS.some((x) => x.bar === bar);
    const overlap = bar === 0 || bar === 12 || bar === 24 ? 0 : section ? BEAT : BEAT / 2;
    roof.add(b.roof.map((p) => p.key), at(bar) - overlap, BAR + overlap, effect, {
      name: `${chordOf(bar).name}: ${effectName(effect.effect)}`,
      ...(bar === 0 ? { fadeIn: r4(BAR / 2) } : overlap ? { transitionIn: bar === 20 ? 'dissolve' : bar % 2 ? 'wipeRight' : 'wipeLeft' } : {})
    });
  }

  // Sweeps across the whole yard to the beat. A laser scans left to right and back, one pass
  // every two beats late in the build and one a beat at the end of the second drop; a wave of
  // color rolls left to right on every beat of the first drop's second half, and once a bar in
  // the breakdown.
  const laser = (bar: number, bars: number, beats: number, colors: string[], brightness: number) =>
    sweeps.add([YARD], at(bar), bars * BAR, fx('scanner', { palette: 'custom', colors, brightness, speed: scanSpeed(beats), intensity: 0.55, size: 0.6, direction: 'right' }), { name: 'Laser sweeps' });
  laser(6, 2, 2, [whiter(chordOf(6).color, 0.4), whiter(chordOf(6).accent, 0.4)], 0.7);
  for (let bar = 16; bar < 20; bar++) for (let k = 0; k < 4; k++) sweeps.sweep(at(bar, k), BEAT, k % 2 ? chordOf(bar).accent : chordOf(bar).color, 0.75);
  for (const bar of [22, 23]) sweeps.sweep(at(bar), BAR, whiter(chordOf(bar).accent, 0.3), 0.5);
  laser(28, 2, 1, [chordOf(28).color, chordOf(28).accent, '#ffffff', chordOf(29).color, chordOf(29).accent, '#ffffff'], 1);

  // The beat of silence before each drop.
  blackout.add([YARD], at(11, 3), BEAT, solid('#000000', 1));
  blackout.add([YARD], at(23, 3, 2), BEAT / 2, solid('#000000', 1));

  // Each picture crosses over the one before it (overlap) so the new one is in on the downbeat.
  // A tinted picture takes the chord's colors, a new set every bar, sweeping in over half a beat.
  for (const s of BED) {
    const ov = s.overlap ?? 0;
    const more = { ...(s.fadeIn ? { fadeIn: r4(s.fadeIn) } : {}), ...(s.fadeOut ? { fadeOut: r4(s.fadeOut) } : {}) };
    if (!s.tint) {
      bed.add([YARD], s.from - ov, s.to - s.from + ov, s.effect, { name: s.name, ...(s.in ? { transitionIn: s.in } : {}), ...more });
      continue;
    }
    for (let bar = Math.round(s.from / BAR); bar < Math.round(s.to / BAR); bar++) {
      const first = at(bar) === s.from;
      const o = first ? ov : BEAT / 2;
      const c = chordOf(bar);
      const turn = BAR_TURNS[bar % BAR_TURNS.length];
      bed.add([YARD], at(bar) - o, BAR + o, { ...s.effect, palette: 'custom', colors: [c.color, c.accent, chordOf(bar + 1).color] }, {
        name: `${s.name} (${c.name})`,
        ...(first ? (s.in ? { transitionIn: s.in } : {}) : { transitionIn: turn }),
        ...(first ? more : {})
      });
    }
  }

  const layers = [blackout, sweeps, flash, stabs, kick, clap, roll, lead, arp, sweep, roof, bass, hats, pump, bed];
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
