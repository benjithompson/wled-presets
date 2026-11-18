import type { GameControl, GameSetting, Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { ORB_COLORS } from './cascade.ts';
import { bestScore, COLORS, css, Flare, heat, Motes, record, scale, Sparks, Waves, Yard, type Part } from './kit.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Beat Drop: a rhythm game on the roofline, with four colors. Notes in green, cyan, blue and
// magenta slide along the roof toward two dim posts near its start; the phone has a button in
// each color (on a keyboard: the arrow keys, ← ↓ ↑ →, or D F J K). Press the button in a note's
// color as its head reaches the posts. Long notes are holds: press as the head arrives, keep that
// button down while the body slides through, and let go as the bright end cap reaches the posts.
// The chart never ends: the tempo creeps up bar by bar (90 to 170 beats a minute), the patterns
// get busier and the colors change more often, so a perfect player can go on forever.
//
// Notes never come two at once: on a single line of lights they would land on the same LEDs and
// their colors would add up into a mess. The colors come in gently: the first bars use only the
// two outside buttons (green and magenta), one color per bar or two in turn; then all four, in
// pairs and alternations; then runs up and down the colors (← ↓ ↑ →); then jumps anywhere. A color
// never changes between two notes closer than CHANGE_GAP, so even at top speed every change
// leaves time to move a finger.
//
// Presses are judged by time (each note has its moment), as the player saw it: a press counts
// where the notes were a moment ago, since the phone and Wi-Fi are a little late. A press is
// judged against the notes of its own color only: the wrong color is a stray (the streak breaks,
// a little health goes) and the note can still be hit with the right one. PERFECT is worth 2,
// GOOD 1, a hold that is held to its end a bonus by its length; everything times the multiplier,
// which climbs every 8 hits in a row up to ×4. A miss breaks the streak and drains the health
// meter; hits fill it back a little; empty is game over.
//
// Settings, chosen on the phone before a game (kept from one game to the next):
//   Colors: 4 (a button per color, as above); 2 (only the two outside colors, green and magenta,
//     with two buttons, ← and →, or F and J: the same notes and patterns, the colors in turns,
//     pairs and jumps between the two); or 1 (the original one-button game: every note
//     white-headed with a cyan tail, the big button plays any note, Space or Enter on a keyboard).
//   Difficulty (see LEVELS):
//     Easy: 75 → 130 BPM, a longer look at each note, only the two simpler pattern sets and holds of
//       at most 2 beats, colors that change gently (no runs, no jumps), wider timing windows
//       (PERFECT ±0.06 s, GOOD ±0.14 s), and misses cost less health.
//     Normal: 90 → 170 BPM, everything as described above, PERFECT ±0.05 s, GOOD ±0.12 s.
//     Hard: 100 → 176 BPM (eighths at the top stay 0.17 s apart), the notes come quicker, the
//       busy patterns and color jumps come sooner, PERFECT ±0.045 s, GOOD ±0.11 s, misses cost more.
//   Each combination keeps its own best score.
//
// Colors mean one thing each: the four note colors say which button (the heads at full brightness,
// tails and hold bodies dimmer, hold end caps bright), the posts are a dim warm white that tints
// toward the next note's color, gold is points, red a miss.
//
// The yard: the bushes are the multiplier, one more lit gold for each step (×2, ×3, ×4), pulsing
// on the beat, with a flash in the color of every note hit. The trees are the health meter,
// filling from the base up (green when healthy, red and blinking when low). Windows and doors
// bounce on every beat and flare in the colors of the hits.

type Phase = 'ready' | 'play' | 'over';

export interface BeatNote {
  /** The moment the head reaches the posts (song time, seconds). */
  time: number;
  /** A hold's end (the same as time for a tap). */
  end: number;
  hold: boolean;
  /** A hold's length in beats. */
  beats: number;
  /** Which color, and so which button (an index into ORB_COLORS). */
  tone: number;
  state: 'coming' | 'held' | 'done' | 'missed' | 'broken';
  /** Seconds since it was judged, for its fade. */
  age: number;
}

/** The game, with a peek at the chart (for tests and the curious). */
export interface BeatGame extends Game {
  chart(): { song: number; notes: readonly Readonly<BeatNote>[] };
}

/** A press counts where the notes were this long ago: the phone and Wi-Fi are a little late. */
export const LAG = 0.08;
/** Timing windows on Normal, in seconds either side of a note's moment (see LEVELS). */
export const PERFECT = 0.05;
export const GOOD = 0.12;

export type Level = 'easy' | 'normal' | 'hard';
export type ColorCount = '1' | '2' | '4';

/** How each difficulty plays. Tiers: when the busier pattern sets (and color changes) come in, by bar. */
export const LEVELS: Record<
  Level,
  {
    bpmStart: number;
    bpmMax: number;
    /** BPM added each bar. */
    bpmStep: number;
    /** Seconds from the far end of the roof to the posts, at the start and at top speed. */
    travelSlow: number;
    travelFast: number;
    /** The first bar of tiers 0, 1, 2 and 3; the last tier used. */
    tiers: [number, number, number, number];
    maxTier: number;
    /** The longest hold, in beats. */
    maxHold: number;
    perfect: number;
    good: number;
    /** Health lost for a miss, a stray press, a hold let go too soon; gained for a hit. */
    miss: number;
    stray: number;
    broken: number;
    heal: number;
  }
> = {
  easy: { bpmStart: 75, bpmMax: 130, bpmStep: 1, travelSlow: 2.9, travelFast: 2, tiers: [1, 6, 99999, 99999], maxTier: 1, maxHold: 2, perfect: 0.06, good: 0.14, miss: 0.08, stray: 0.02, broken: 0.04, heal: 1.25 },
  normal: { bpmStart: 90, bpmMax: 170, bpmStep: 1.5, travelSlow: 2.4, travelFast: 1.4, tiers: [1, 4, 10, 20], maxTier: 3, maxHold: 4, perfect: PERFECT, good: GOOD, miss: 0.12, stray: 0.04, broken: 0.06, heal: 1 },
  hard: { bpmStart: 100, bpmMax: 176, bpmStep: 2, travelSlow: 2, travelFast: 1.2, tiers: [1, 2, 6, 12], maxTier: 3, maxHold: 4, perfect: 0.045, good: 0.11, miss: 0.16, stray: 0.05, broken: 0.08, heal: 0.9 }
};
const LEVEL_NAMES: Record<Level, string> = { easy: 'Easy', normal: 'Normal', hard: 'Hard' };
/** A hold let go this close to its end (or later) counts as held to the end. */
const RELEASE = 0.15;
/** Notes are never closer than this; after a hold, never closer than HOLD_GAP. */
const MIN_GAP = 0.17;
const HOLD_GAP = 0.3;
const BPM_DEMO = 100;
/** A note's color only changes from the note before when they are at least this far apart. */
export const CHANGE_GAP = 0.2;
/** The four buttons, left to right, in the order of the note colors. */
export const BUTTONS = ['c0', 'c1', 'c2', 'c3'];
const LABELS = ['←', '↓', '↑', '→'];
const KEYS = [
  ['ArrowLeft', 'KeyD'],
  ['ArrowDown', 'KeyF'],
  ['ArrowUp', 'KeyJ'],
  ['ArrowRight', 'KeyK']
];
const CONTROLS: GameControl[] = ORB_COLORS.map((c, i) => ({ id: BUTTONS[i], label: LABELS[i], color: css(c), keys: KEYS[i] }));
/** The two-color game: the two outside colors, green (←) and magenta (→), with keys for both hands. */
const TWO_TONES = [0, 3];
const TWO_CONTROLS: GameControl[] = [
  { ...CONTROLS[0], keys: ['ArrowLeft', 'KeyF', 'KeyD'] },
  { ...CONTROLS[3], keys: ['ArrowRight', 'KeyJ', 'KeyK'] }
];
const COLOR_NAMES: Record<ColorCount, string> = { '1': '1 color', '2': '2 colors', '4': '4 colors' };
/** The posts: a dim, warm white. */
const POST: Rgb = [1, 0.78, 0.5];
/** How a bar picks its notes' colors. */
type ColorMode = 'same' | 'alternate' | 'pairs' | 'stairs' | 'random';
/** Hits in a row for each step of the multiplier. */
const STEP = 8;
const MAX_MULT = 4;
const HEALTH_START = 0.6;

const NIGHT: Rgb = [0.02, 0.008, 0.045];
const MISSED: Rgb = [0.12, 0.1, 0.16];
/** The one-color game's look: white heads and end caps, cyan tails, blue bodies, blue-white posts. */
const TAIL: Rgb = [0, 0.75, 1];
const BODY_FAR: Rgb = [0.1, 0.1, 1];
const toneColor = (tone: number): Rgb => ORB_COLORS[tone] ?? ORB_COLORS[0];

/** Patterns of one bar of 4 beats: [beat, hold length in beats (0: a tap)]. Busier ones come later. */
const PATTERNS: [number, number][][][] = [
  // Quarters, halves, a first hold.
  [
    [[0, 0], [2, 0]],
    [[0, 0], [1, 0], [2, 0], [3, 0]],
    [[0, 0], [1, 0], [2, 0]],
    [[0, 2], [3, 0]]
  ],
  // Eighth pairs and holds.
  [
    [[0, 0], [1, 0], [2, 0], [2.5, 0], [3, 0]],
    [[0, 0], [1, 2]],
    [[0, 1], [2, 1]],
    [[0, 0], [0.5, 0], [1, 0], [2, 0], [3, 0]],
    [[0, 3]]
  ],
  // Syncopation.
  [
    [[0, 0], [1.5, 0], [2, 0], [3.5, 0]],
    [[0.5, 0], [1.5, 0], [2.5, 0], [3, 0]],
    [[0, 0], [0.5, 0], [1, 0], [2, 1.5]],
    [[0, 0], [1.5, 1.5], [3.5, 0]],
    [[0, 4]]
  ],
  // Busy: runs of eighths, holds between them.
  [
    [[0, 0], [0.5, 0], [1, 0], [1.5, 0], [2, 0], [3, 0], [3.5, 0]],
    [[0, 1], [1.5, 0], [2, 0], [2.5, 1]],
    [[0, 0], [0.5, 0], [1.5, 0], [2, 0], [2.5, 0], [3.5, 0]],
    [[0.5, 0], [1, 0], [1.5, 2]],
    [[0, 0], [0.5, 0], [1, 0], [1.5, 0], [2, 0], [2.5, 0], [3, 0], [3.5, 0]]
  ]
];

interface Bar {
  start: number;
  bpm: number;
}

export function beatGame(stage: Stage): BeatGame {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= 30;
  const sparks = new Sparks(roof, n * 0.1, 1.8);
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const decorFlare = new Flare(3);

  // The posts: about 5% in from the start of the roof, where it can be seen from the street.
  let line = Math.round(n * 0.05);
  for (let i = line; i < n * 0.3; i++) {
    if (!roof.hiddenAt(i) && !roof.hiddenAt(i - 2) && !roof.hiddenAt(i + 2)) {
      line = i;
      break;
    }
  }
  line = Math.max(3, line);
  const span = Math.max(1, n - 1 - line);

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
  /** Song time: the chart's clock. */
  let song = 0;
  let notes: BeatNote[] = [];
  let bars: Bar[] = [];
  let barIndex = 0;
  let nextBar = 0;
  /** When the last note ends, and whether it was a hold: the next one keeps its distance. */
  let lastEnd = -Infinity;
  let lastHold = false;
  /** The color of the last note added. */
  let lastTone = 0;
  let level: Level = 'normal';
  let colors: ColorCount = '4';
  const cfg = () => LEVELS[level];
  const single = () => colors === '1';
  const two = () => colors === '2';
  const bestKey = () => `beat:${colors}:${level}`;
  let travel = cfg().travelSlow;
  let demo = true;

  let score = 0;
  let streak = 0;
  let longest = 0;
  let health = HEALTH_START;
  let newBest = false;
  /** The hold being held: by which player, with which color's button. */
  let holder: { player: string; tone: number } | null = null;
  let judged: { text: string; t: number } | null = null;
  /** Flashes at the posts: gold for a hit, red for a miss (seconds since); the last hit's color. */
  let hitFlash = 9;
  let hitColor: Rgb = COLORS.gold;
  let missFlash = 9;
  /** The bushes lit (smoothed), and when the multiplier was lost. */
  let bushLevel = 0;
  let dropFlash = 9;
  let dropFrom = 0;

  const mult = () => Math.min(MAX_MULT, 1 + Math.floor(streak / STEP));
  const travelFor = (bpm: number) => {
    const c = cfg();
    const f = Math.max(0, Math.min(1, (Math.min(c.bpmMax, bpm) - c.bpmStart) / (c.bpmMax - c.bpmStart)));
    return c.travelSlow - f * (c.travelSlow - c.travelFast);
  };
  const speed = () => span / travel;
  const posAt = (t: number) => line + (t - song) * speed();

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

  /** The bar playing now (the last one started). */
  function barNow(): Bar {
    let b = bars[0] ?? { start: 0, bpm: demo ? BPM_DEMO : cfg().bpmStart };
    for (const x of bars) if (x.start <= song) b = x;
    return b;
  }

  /** Where in the beat the song is: 0 on the beat, rising to 1 just before the next. */
  function beatPhase() {
    const b = barNow();
    const k = ((song - b.start) * b.bpm) / 60;
    return k < 0 ? 0 : k - Math.floor(k);
  }

  const pickFrom = <T,>(list: T[]) => list[Math.floor(Math.random() * list.length)];

  /**
   * The colors a bar can use and how it picks them, by tier: first the two outside buttons, one
   * color per bar or two in turn; then all four in pairs and alternations; then runs up and down
   * the colors; then jumps anywhere.
   */
  function colorsFor(tier: number): { palette: number[]; modes: ColorMode[] } {
    if (single()) return { palette: [0], modes: ['same'] };
    // Two colors: the same patterns, the two colors in turns, pairs and (later) jumps.
    if (two()) {
      if (tier < 0) return { palette: TWO_TONES, modes: ['same'] };
      if (level === 'easy' || tier === 0) return { palette: TWO_TONES, modes: ['same', 'same', 'alternate', 'pairs'] };
      if (demo || tier <= 2) return { palette: TWO_TONES, modes: ['same', 'alternate', 'pairs'] };
      return { palette: TWO_TONES, modes: ['alternate', 'pairs', 'random', 'random'] };
    }
    // Easy: all four colors after the first bars, but only gentle changes.
    if (level === 'easy' && tier >= 1) return { palette: [0, 1, 2, 3], modes: ['same', 'same', 'alternate', 'pairs'] };
    if (demo) return { palette: [0, 1, 2, 3], modes: ['alternate', 'stairs', 'pairs'] };
    if (tier <= 0) return { palette: [0, 3], modes: tier < 0 ? ['same'] : ['same', 'same', 'alternate', 'pairs'] };
    if (tier === 1) return { palette: [0, 1, 2, 3], modes: ['same', 'alternate', 'pairs'] };
    if (tier === 2) return { palette: [0, 1, 2, 3], modes: ['same', 'alternate', 'pairs', 'stairs', 'stairs'] };
    return { palette: [0, 1, 2, 3], modes: ['alternate', 'pairs', 'stairs', 'stairs', 'random', 'random'] };
  }

  function addBar() {
    const c = cfg();
    const bpm = demo ? BPM_DEMO : Math.min(c.bpmMax, c.bpmStart + barIndex * c.bpmStep);
    const tier = demo ? 1 : barIndex < c.tiers[0] ? -1 : Math.min(c.maxTier, barIndex < c.tiers[1] ? 0 : barIndex < c.tiers[2] ? 1 : barIndex < c.tiers[3] ? 2 : 3);
    // The first bar is gentle; every eighth bar is a breather.
    const library = tier < 0 || (!demo && barIndex % 8 === 7) ? [[[0, 0], [2, 0]] as [number, number][]] : PATTERNS[Math.min(tier, PATTERNS.length - 1)].concat(tier > 0 ? PATTERNS[tier - 1] : []);
    const pattern = library[Math.floor(Math.random() * library.length)];
    const beat = 60 / bpm;
    bars.push({ start: nextBar, bpm });
    // The bar's colors: a first color (a change from the last bar where it can), and a second.
    const { palette, modes } = colorsFor(tier);
    const mode = pickFrom(modes);
    const fresh = palette.filter((t) => t !== lastTone);
    const a = mode === 'stairs' ? lastTone : pickFrom(fresh.length ? fresh : palette);
    const others = palette.filter((t) => t !== a);
    const b = pickFrom(others.length ? others : palette);
    const dir = Math.random() < 0.5 ? 1 : -1;
    let j = 0;
    for (const [at, full] of pattern) {
      const len = Math.min(full, c.maxHold);
      const time = nextBar + at * beat;
      if (time - lastEnd < (lastHold ? HOLD_GAP : MIN_GAP)) continue;
      const hold = len > 0;
      const end = hold ? time + len * beat : time;
      let tone: number;
      if (mode === 'same') tone = a;
      else if (mode === 'alternate') tone = j % 2 ? b : a;
      else if (mode === 'pairs') tone = Math.floor(j / 2) % 2 ? b : a;
      else if (mode === 'stairs') tone = (lastTone + dir + 4) % 4;
      else tone = pickFrom(palette);
      // Too close to the note before for a finger to move: the same color again.
      if (time - lastEnd < CHANGE_GAP) tone = lastTone;
      notes.push({ time, end, hold, beats: len, tone, state: 'coming', age: 0 });
      lastEnd = end;
      lastHold = hold;
      lastTone = tone;
      j++;
    }
    nextBar += 4 * beat;
    barIndex++;
  }

  function restart(asDemo: boolean) {
    demo = asDemo;
    song = 0;
    notes = [];
    bars = [];
    barIndex = 0;
    travel = travelFor(demo ? BPM_DEMO : cfg().bpmStart);
    // A lead-in: the first note comes all the way along the roof.
    nextBar = travel + 1.2;
    lastEnd = -Infinity;
    lastHold = false;
    lastTone = single() ? 0 : Math.random() < 0.5 ? 0 : 3;
    holder = null;
    judged = null;
  }

  function newGame() {
    restart(false);
    score = 0;
    streak = 0;
    longest = 0;
    health = HEALTH_START;
    newBest = false;
    bushLevel = 0;
    sparks.clear();
    motes.clear();
    waves.clear();
    setPhase('play');
  }

  const linePoint = () => roof.point(line);

  function gain(points: number) {
    score += points * mult();
  }

  /** A hit: points, a streak, a burst of gold at the posts. */
  function hit(note: BeatNote, perfect: boolean) {
    const before = mult();
    streak++;
    longest = Math.max(longest, streak);
    if (!demo) {
      gain(perfect ? 2 : 1);
      health = Math.min(1, health + (perfect ? 0.04 : 0.025) * cfg().heal);
    }
    judged = { text: perfect ? 'PERFECT!' : 'GOOD', t: clock };
    hitFlash = 0;
    hitColor = single() ? COLORS.gold : toneColor(note.tone);
    sparks.burst(line, [COLORS.gold, mix(COLORS.gold, WHITE, 0.5)], perfect ? 26 : 12, n * (perfect ? 0.3 : 0.18), perfect ? 0.9 : 0.6);
    decorFlare.add(hitColor, perfect ? 0.45 : 0.25);
    decorFlare.add(COLORS.gold, perfect ? 0.2 : 0.1);
    if (!note.hold) note.state = 'done';
    if (mult() > before) stepUp();
  }

  /** The multiplier climbs: a shockwave of gold, and a light flies down to the next bush. */
  function stepUp() {
    const p = linePoint();
    waves.add(p.x, p.y, COLORS.gold, { amount: 0.9 });
    decorFlare.add(COLORS.gold, 1);
    const b = yard.bushes.length;
    if (b) {
      const lit = Math.max(1, Math.round((b * (mult() - 1)) / (MAX_MULT - 1)));
      const bush = yard.bushes[Math.min(b - 1, lit - 1)];
      motes.fly(p, yard.topOf(bush), mix(COLORS.gold, WHITE, 0.3), 0.5, { arc: 40, size: 28 });
    }
  }

  function breakStreak() {
    if (mult() > 1) {
      dropFlash = 0;
      dropFrom = bushLevel;
    }
    streak = 0;
  }

  function miss(note: BeatNote) {
    note.state = 'missed';
    note.age = 0;
    if (demo) return;
    breakStreak();
    health -= cfg().miss;
    judged = { text: 'MISS', t: clock };
    missFlash = 0;
    sparks.burst(line, [COLORS.bad, [1, 0.25, 0]], 10, n * 0.1, 0.5);
    if (health <= 0) gameOver();
  }

  /** A press with no note of its color near it: the streak breaks, a little health goes. */
  function stray(wrongColor: boolean) {
    breakStreak();
    health -= cfg().stray;
    judged = { text: wrongColor ? 'Wrong color!' : 'Too early!', t: clock };
    missFlash = 0;
    if (health <= 0) gameOver();
  }

  function finishHold(note: BeatNote, full: boolean, t: number) {
    holder = null;
    note.age = 0;
    const bonus = Math.max(2, Math.round(note.beats * 2));
    if (full) {
      note.state = 'done';
      if (!demo) {
        gain(bonus);
        health = Math.min(1, health + 0.03 * cfg().heal);
      }
      judged = { text: 'HELD!', t: clock };
      hitFlash = 0;
      hitColor = single() ? COLORS.gold : toneColor(note.tone);
      sparks.burst(line, [COLORS.gold, mix(COLORS.gold, WHITE, 0.5), single() ? TAIL : hitColor], 24, n * 0.28, 0.9);
      decorFlare.add(hitColor, 0.4);
      decorFlare.add(COLORS.gold, 0.3);
    } else {
      note.state = 'broken';
      if (!demo) {
        const part = Math.max(0, Math.min(1, (t - note.time) / Math.max(0.01, note.end - note.time)));
        gain(Math.floor(bonus * part));
        breakStreak();
        health -= cfg().broken;
        judged = { text: 'Let go too soon', t: clock };
        missFlash = 0;
        if (health <= 0) gameOver();
      }
    }
  }

  function gameOver() {
    health = 0;
    holder = null;
    newBest = record(bestKey(), score).isNew;
    // Everything still on the roof falls off the gutter.
    for (const note of notes) {
      if (note.state !== 'coming' && note.state !== 'held') continue;
      const pos = posAt(note.time);
      if (pos > n - 1) continue;
      const p = roof.point(Math.max(line, pos));
      motes.drop(p.x, p.y, mix(single() ? TAIL : toneColor(note.tone), COLORS.bad, 0.5), { vx: (Math.random() - 0.5) * 60, size: 20 });
    }
    notes = [];
    setPhase('over');
  }

  const holding = () => notes.find((x) => x.state === 'held');

  /** Which color a button is (-1: not a color button, such as the big button). */
  const toneOf = (button: string | undefined) => (button ? BUTTONS.indexOf(button) : -1);

  function press(player: string, button: string | undefined) {
    if (!playable) return;
    // Any button starts a game.
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    // With one color, any button plays any note; with four, the big button does nothing while
    // playing. No button does anything during a hold (no note ever comes during one).
    const tone = single() ? 0 : toneOf(button);
    if (phase !== 'play' || holder || tone < 0) return;
    const { good, perfect } = cfg();
    const t = song - LAG;
    let best: BeatNote | null = null;
    let other = false;
    for (const x of notes) {
      if (x.state !== 'coming' || Math.abs(x.time - t) > good) continue;
      if (x.tone !== tone) {
        other = true;
        continue;
      }
      if (!best || Math.abs(x.time - t) < Math.abs(best.time - t)) best = x;
    }
    if (!best) return stray(other);
    if (best.hold) {
      best.state = 'held';
      holder = { player, tone };
    }
    hit(best, Math.abs(best.time - t) <= perfect);
  }

  function release(player: string, button: string | undefined) {
    if (phase !== 'play' || !holder || player !== holder.player) return;
    // Only the button that holds the note lets go of it (undefined: every button of a phone that left).
    if (button !== undefined && !single() && toneOf(button) !== holder.tone) return;
    const note = holding();
    if (!note) return void (holder = null);
    const t = song - LAG;
    finishHold(note, t >= note.end - RELEASE, t);
  }

  function step(dt: number) {
    song += dt;
    travel += (travelFor(barNow().bpm) - travel) * Math.min(1, dt * 1.5);
    while (nextBar < song + travel + 1.5) addBar();
    const t = song - LAG;
    for (const x of notes) {
      if (x.state !== 'coming' && x.state !== 'held') x.age += dt;
      if (demo) {
        // The attract mode plays itself, perfectly.
        if (x.state === 'coming' && song >= x.time) {
          if (x.hold) x.state = 'held';
          hit(x, true);
        } else if (x.state === 'held' && song >= x.end) finishHold(x, true, song);
        continue;
      }
      if (x.state === 'coming' && t > x.time + cfg().good) miss(x);
      else if (x.state === 'held' && t >= x.end) finishHold(x, true, t);
      if (phase !== 'play') return;
    }
    // Notes that have gone past the start of the roof are gone, once judged (a note nobody
    // pressed stays until it counts as a miss, even past the end of the roof).
    notes = notes.filter((x) => (x.state === 'coming' || x.state === 'held' || posAt(x.end) > -6) && !(x.state === 'done' && x.age > 0.5));
    bars = bars.filter((b, i) => i + 1 >= bars.length || bars[i + 1].start > song - 1);
  }

  // ---------- Drawing ----------

  function drawRoof() {
    const beat = Math.exp(-beatPhase() * 5);
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT, 1 + 0.5 * beat);
    const sp = speed();
    let due: BeatNote | null = null;
    for (const x of notes) if (x.state === 'coming' && (!due || x.time < due.time)) due = x;
    for (const x of notes) {
      const head = posAt(x.time);
      if (head > n + 4) continue;
      if (x.state === 'done') continue;
      const alive = x.state === 'coming' || x.state === 'held';
      // A missed note goes on past the posts, gray, and fades.
      const fade = alive ? 1 : Math.max(0, 1 - x.age / 0.8);
      if (fade <= 0) continue;
      if (single()) {
        drawClassic(x, head, alive, fade, sp);
        continue;
      }
      const color = alive ? toneColor(x.tone) : MISSED;
      if (x.hold) {
        const held = x.state === 'held';
        // Held: the body is eaten up at the posts as it slides in. A dark step behind the head
        // keeps it apart from the body.
        const from = held ? line : Math.max(head + 2, -6);
        const end = posAt(x.end);
        const to = Math.min(n - 1, end - 1.5);
        const pulse = held ? 0.45 + 0.15 * Math.sin(clock * 24) : 0.3;
        for (let i = Math.max(0, Math.ceil(from)); i <= to; i++) yard.roofAt(i, color, pulse * fade);
        // The end cap: bright, in the note's color.
        if (end >= 0 && end <= n - 1) yard.roofSplat(end, color, 0.9, 0.95 * fade);
        if (!held && head <= n - 1) {
          yard.roofSplat(head, color, 1.1, fade);
          yard.roofSplat(head, color, 0.5, 0.4 * fade);
        }
        if (held) yard.roofSplat(line, color, 2.5, 0.6);
      } else {
        if (head > n - 1) continue;
        // A short, dim tail behind the head (toward the far end, where it came from), with a dark
        // step between them.
        const tail = Math.max(2, Math.min(6, sp * 0.06));
        for (let k = 2; k <= tail + 1; k++) yard.roofSplat(head + k, color, 0.7, (1 - (k - 1) / (tail + 1)) * 0.35 * fade);
        yard.roofSplat(head, color, 1.1, fade);
        // A brighter core, in the same color.
        yard.roofSplat(head, color, 0.5, 0.4 * fade);
      }
    }
    // The posts: a dim warm white, breathing on the beat, tinted toward the color of the next
    // note as it comes near; a flash in the hit note's color and gold on a hit, red on a miss.
    const hitK = Math.max(0, 1 - hitFlash / 0.25);
    const missK = Math.max(0, 1 - missFlash / 0.35);
    const near = due && phase !== 'over' ? Math.max(0, 1 - (due.time - song) / Math.max(0.3, travel * 0.4)) : 0;
    const post = single() ? COLORS.hint : near > 0 && due ? mix(POST, toneColor(due.tone), 0.5 * near) : POST;
    for (const at of [line - 2.2, line + 2.2]) {
      yard.roofSplat(at, post, 0.8, 0.22 + 0.2 * beat);
      if (hitK) yard.roofSplat(at, COLORS.gold, 1, hitK * 0.8);
      if (missK) yard.roofSplat(at, COLORS.bad, 1.2, missK);
    }
    if (hitK && !single()) yard.roofSplat(line, hitColor, 2.5, hitK * 0.7);
    if (missK) yard.roofSplat(line, COLORS.bad, 3, missK * 0.6);
    sparks.draw(yard);
  }

  /** The one-color game: white heads and end caps (what you time against), cyan tails, blue bodies. */
  function drawClassic(x: BeatNote, head: number, alive: boolean, fade: number, sp: number) {
    if (x.hold) {
      const held = x.state === 'held';
      const from = held ? line : Math.max(head, -6);
      const end = posAt(x.end);
      const to = Math.min(n - 1, end);
      const pulse = held ? 0.75 + 0.25 * Math.sin(clock * 24) : 0.5;
      for (let i = Math.max(0, Math.ceil(from)); i <= to; i++) {
        const f = (i - from) / Math.max(1, end - from);
        yard.roofAt(i, alive ? mix(TAIL, BODY_FAR, f) : MISSED, pulse * fade);
      }
      if (end >= 0 && end <= n - 1) yard.roofSplat(end, alive ? WHITE : MISSED, 0.9, 0.85 * fade);
      if (!held && head <= n - 1) yard.roofSplat(head, alive ? WHITE : MISSED, 1.1, fade);
      if (held) yard.roofSplat(line, TAIL, 2.5, 0.5);
    } else {
      if (head > n - 1) return;
      const tail = Math.max(2, Math.min(6, sp * 0.06));
      for (let k = 1; k <= tail; k++) yard.roofSplat(head + k, alive ? TAIL : MISSED, 0.7, (1 - k / (tail + 1)) * 0.6 * fade);
      yard.roofSplat(head, alive ? WHITE : MISSED, 1.1, fade);
    }
  }

  function drawBushes() {
    const b = yard.bushes.length;
    const lit = phase === 'over' ? 0 : (b * (mult() - 1)) / (MAX_MULT - 1);
    const beat = Math.exp(-beatPhase() * 4);
    const drop = Math.max(0, 1 - dropFlash / 0.6);
    // A flash in the color of the note just hit.
    const flash = phase === 'play' && !single() ? Math.max(0, 1 - hitFlash / 0.2) : 0;
    yard.bushes.forEach((bush, bi) => {
      const on = Math.max(0, Math.min(1, bushLevel - bi));
      const color = mult() >= MAX_MULT ? mix(COLORS.gold, WHITE, 0.25 * beat) : COLORS.gold;
      for (let i = 0; i < bush.count; i++) {
        yard.add(bush.offset + i, [0.02, 0.02, 0.05]);
        if (on > 0) yard.add(bush.offset + i, color, on * (0.4 + 0.45 * beat + 0.1 * Math.sin(clock * 6 + i * 2.1)));
        // The multiplier lost: the bushes that were lit flash red as they go out.
        if (drop && bi < Math.ceil(dropFrom - 0.05)) yard.add(bush.offset + i, COLORS.bad, drop * 0.4);
        if (flash) yard.add(bush.offset + i, hitColor, flash * 0.35);
      }
    });
    bushLevel += (lit - bushLevel) * 0.2;
  }

  function drawTree(part: Part) {
    // The health meter, from the base up: green when healthy, yellow, then red and blinking.
    const low = health < 0.25 && phase === 'play';
    const blink = low ? (Math.sin(clock * 14) > 0 ? 1 : 0.25) : 1;
    const color = health < 0.25 ? COLORS.bad : hsv(0.33 * Math.min(1, (health - 0.15) / 0.75));
    for (let i = 0; i < part.count; i++) {
      if (part.up[i] <= health) yard.add(part.offset + i, color, 0.6 * blink);
      else yard.add(part.offset + i, [0.02, 0.015, 0.04]);
    }
  }

  function drawDecor(part: Part) {
    // The house bounces to the music: a soft pulse on every beat, warmer with the multiplier.
    const beat = Math.exp(-beatPhase() * 6);
    const tint = mix([0.35, 0.15, 1], heat(0.4), (mult() - 1) / (MAX_MULT - 1));
    for (let i = 0; i < part.count; i++) {
      yard.add(part.offset + i, NIGHT, 1.2);
      if (phase !== 'over') yard.add(part.offset + i, tint, 0.08 + 0.22 * beat);
      yard.add(part.offset + i, decorFlare.color, 1);
    }
  }

  restart(true);

  return {
    id: 'beat',

    scoreBoard: () => ({ key: bestKey(), title: `Beat Drop: ${LEVEL_NAMES[level]}, ${COLOR_NAMES[colors]}` }),

    input(e: GameInput) {
      if (e.action === 'press') press(e.playerId, e.button);
      else release(e.playerId, e.button);
    },

    leave(playerId: string) {
      release(playerId, undefined);
    },

    setting(id: string, value: string) {
      if (phase === 'play') return;
      if (id === 'colors' && (value === '1' || value === '2' || value === '4')) colors = value;
      else if (id === 'level' && (value === 'easy' || value === 'normal' || value === 'hard')) level = value;
      else return;
      // The attract demo shows the new choice.
      if (phase === 'ready') restart(true);
    },

    chart() {
      return { song, notes };
    },

    update(dt: number, frame: Frame) {
      clock += dt;
      phaseTime += dt;
      hitFlash += dt;
      missFlash += dt;
      dropFlash += dt;
      yard.begin(frame);
      if (!playable) return;
      if (phase === 'ready' || phase === 'play') step(dt);
      if (phase === 'over' && phaseTime > 10) {
        restart(true);
        setPhase('ready');
      }
      sparks.update(dt);
      motes.update(dt);
      waves.update(dt);
      decorFlare.update(dt);

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      for (const d of yard.decor) drawDecor(d);
      if (phase === 'over') yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(phaseTime * 3)), 0.05);
      motes.draw();
      waves.draw();
    },

    status(): GameStatusFields {
      const best = bestScore(bestKey());
      const settings: GameSetting[] = [
        { id: 'colors', label: 'Colors', value: colors, choices: (['1', '2', '4'] as ColorCount[]).map((c) => ({ value: c, label: COLOR_NAMES[c] })) },
        {
          id: 'level',
          label: 'Difficulty',
          value: level,
          choices: (['easy', 'normal', 'hard'] as Level[]).map((l) => ({ value: l, label: LEVEL_NAMES[l] }))
        }
      ];
      const choice = `${LEVEL_NAMES[level]}, ${COLOR_NAMES[colors]}.`;
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score: 0, lives: null, goal: null };
      const stats = [
        { label: 'Score', value: score },
        { label: 'Best', value: Math.max(best, score) },
        { label: 'Multiplier', value: `×${mult()}` },
        { label: 'BPM', value: Math.round(barNow().bpm) }
      ];
      const common = { score, lives: null, goal: null };
      switch (phase) {
        case 'ready':
          return {
            ...common,
            score: 0,
            phase,
            message: single()
              ? `${choice} Tap GO! Then tap as each white note reaches the blue posts. Hold the long ones until their end goes by.`
              : `${choice} Tap GO! Then press the button in each note’s color as it reaches the posts. Hold the long ones until their end goes by.`,
            button: 'GO!',
            tone: 'go',
            stats: [{ label: 'Best', value: best }],
            settings
          };
        case 'play': {
          const held = !!holder;
          const recent = judged && clock - judged.t < 1.2 ? judged.text : null;
          const run = streak >= 2 ? ` ${streak} in a row` : '';
          const message = held
            ? single()
              ? 'Hold… let go when the white end reaches the posts.'
              : `Hold ${LABELS[holder!.tone]}… let go when the bright end reaches the posts.`
            : recent
              ? `${recent}${recent === 'MISS' || recent.startsWith('Too') || recent.startsWith('Let') || recent.startsWith('Wrong') ? '' : run}`
              : streak >= STEP
                ? `×${mult()}!${run}`
                : single()
                  ? 'Tap when a white note reaches the blue posts.'
                  : 'Press the button in the note’s color as it reaches the posts.';
          return {
            ...common,
            phase,
            message,
            button: held ? 'HOLD' : 'TAP',
            tone: 'go',
            progress: { value: Math.round(Math.max(0, health) * 100), max: 100 },
            stats,
            ...(single() ? {} : two() ? { controls: TWO_CONTROLS, keysHint: '← → (or F J) for the two colors' } : { controls: CONTROLS, keysHint: 'Arrow keys (or D F J K) for the four colors' })
          };
        }
        case 'over':
          return {
            ...common,
            phase,
            message: newBest ? `New best: ${score}! (${choice})` : `Game over: ${score} points. Longest streak ${longest}. (${choice})`,
            button: 'GO!',
            tone: 'go',
            stats,
            settings
          };
      }
    }
  };
}
