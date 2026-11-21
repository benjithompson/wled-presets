import type { ArcadeHud, GameControl, GameSetting, Stage } from '../../../shared/layout.ts';
import { hex, hsv, mix, WHITE, type Rgb } from '../../../shared/color.ts';
import { type Frame } from './frame.ts';
import { hash, lookOf, STAGE_BARS, type Scene } from './beatStages.ts';
import { COLORS, Flare, FOUR_TONES, Sparks, Yard, type Part } from './kit.ts';
import { endGlow, Fx, MIN_ROOF, Round } from './round.ts';
import { overMood, turnHue, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Beat Drop: a rhythm game on the roofline, with four colors. Notes in green, cyan, blue and
// magenta slide along the roof toward the hit zone near its start: a lit band between two bright
// posts, drawn over everything so they show through every explosion. The phone has a button in
// each color (on a keyboard: the arrow keys, ← ↓ ↑ →, or D F J K). Press the button in a note's color as its head passes through the zone. Long notes are
// holds: press as the head arrives, keep that button down while the body slides through, and let
// go as the bright end cap reaches the zone.
//
// The zone: its band is the PERFECT window (a note pressed while its head is inside the band is a
// PERFECT), so it widens as the notes speed up. It stands a little way in from the start of the
// roof (RUNWAY, about two feet past the band on real lights): past the band the roof is a faint
// red, the late side, and a note that slides on into it shows the player they are late. GOOD hits
// say whether they were early or late.
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
// Stages (see beatStages.ts): every 8 bars the whole roofline changes its look, sweeping in from
// the zone to the far end: a calm night, then waves, curtains of light, stars, ripples on every
// beat, a rainbow, and round again, stronger each round (and stronger on Hard, gentler on Easy).
// The backdrops are timed to the music and get busier stage by stage, so the notes get harder to
// pick out: part of the difficulty. They stay readable: the backdrop is dimmed under and around
// every note and in the zone, and is always far dimmer than a note.
//
// The whole roof reacts to the play: a miss sends red ripples out along the full roofline and
// makes the backdrop stutter red; losing a multiplier scatters red sparks along the roof; a
// PERFECT sends a soft gold ripple; low health beats red through the whole roof like a heart.
// A new multiplier is celebrated off the roof (bushes, trees, the house), with only a soft glow
// along the roof, so the next notes stay easy to see.
//
// Colors mean one thing each: the four note colors say which button (the heads at full brightness,
// tails and hold bodies dimmer, hold end caps bright), the zone is a warm white that tints toward
// the next note's color, gold is points, red a miss (and the late side of the zone).
//
// The yard: the bushes are the multiplier, one more lit gold for each step (×2, ×3, ×4), pulsing
// on the beat, with a flash in the color of every note hit. The trees are the health meter,
// filling from the base up (green when healthy, red and blinking when low). Windows and doors
// bounce on every beat and flare in the colors of the hits.

type Phase = 'ready' | 'play' | 'over';

export interface BeatNote {
  /** The moment the head reaches the middle of the zone (song time, seconds). */
  time: number;
  /** A hold's end (the same as time for a tap). */
  end: number;
  hold: boolean;
  /** A hold's length in beats. */
  beats: number;
  /** Which color, and so which button (an index into FOUR_TONES). */
  tone: number;
  state: 'coming' | 'held' | 'done' | 'missed' | 'broken';
  /** Seconds since it was judged, for its fade. */
  age: number;
}

/** The game, with a peek at the chart (for tests and the curious). */
export interface BeatGame extends Game {
  chart(): { song: number; notes: readonly Readonly<BeatNote>[] };
  /** The hit zone (roof steps: its middle and half its width) and the stage (0: the first). */
  look(): { line: number; zone: number; stage: number; name: string };
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
    /** Seconds from the far end of the roof to the zone, at the start and at top speed. */
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
const CONTROLS: GameControl[] = FOUR_TONES.map((c, i) => ({ id: BUTTONS[i], label: LABELS[i], color: hex(c), keys: KEYS[i] }));
/** The two-color game: the two outside colors, green (←) and magenta (→), with keys for both hands. */
const TWO_TONES = [0, 3];
const TWO_CONTROLS: GameControl[] = [
  { ...CONTROLS[0], keys: ['ArrowLeft', 'KeyF', 'KeyD'] },
  { ...CONTROLS[3], keys: ['ArrowRight', 'KeyJ', 'KeyK'] }
];
const COLOR_NAMES: Record<ColorCount, string> = { '1': '1 color', '2': '2 colors', '4': '4 colors' };
/** The zone: a warm white. */
const POST: Rgb = [1, 0.78, 0.5];
/** How a bar picks its notes' colors. */
type ColorMode = 'same' | 'alternate' | 'pairs' | 'stairs' | 'random';
type Judged = NonNullable<ArcadeHud['judged']>['kind'];
/** Hits in a row for each step of the multiplier. */
const STEP = 8;
const MAX_MULT = 4;
const HEALTH_START = 0.6;
/** Seconds the roof glows for a new multiplier. */
const POWER = 0.8;
/** Meters of roof between the late edge of the zone's band (at top speed) and the start of the roof. */
export const RUNWAY = 0.6;
/** How strong the stage backdrops are on each difficulty. */
const LOOK_K: Record<Level, number> = { easy: 0.7, normal: 1, hard: 1.25 };
/** Seconds for a new stage to sweep along the roof. */
const WIPE = 0.8;
/** Roof steps around a note where the backdrop is dimmed, and how much of it is left on the note. */
const CLEAR = 6;
const CLEAR_KEEP = 0.12;
/** Light that runs out along the roof from the zone, both ways. */
interface Ripple {
  age: number;
  life: number;
  /** Steps a second. */
  speed: number;
  width: number;
  color: Rgb;
  amount: number;
}

const MISSED: Rgb = [0.12, 0.1, 0.16];
const DARK: Rgb = [0, 0, 0];
/** The one-color game's look: white heads and end caps, cyan tails, blue bodies, a blue-white zone. */
const TAIL: Rgb = [0, 0.75, 1];
const BODY_FAR: Rgb = [0.1, 0.1, 1];
const toneColor = (tone: number): Rgb => FOUR_TONES[tone] ?? FOUR_TONES[0];

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
  /** Bars since the song began. */
  index: number;
}

export function beatGame(stage: Stage): BeatGame {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= MIN_ROOF;
  const sparks = new Sparks(roof, n * 0.1, 1.8);
  const decorFlare = new Flare(3);
  // The whole yard plays along: its mood follows the stage, it pumps on every beat, and
  // fireworks go up for PERFECTs, holds and every new multiplier.
  const fx = new Fx(yard, { sparks, flare: decorFlare });
  const { motes, waves, show } = fx;
  for (const t of yard.trees) show.dim(t, 0.45);
  // The roof has its own backdrop (the stage's look), kept clear around the notes.
  show.roofShare = 0;
  /** The beat the yard last pumped on. */
  let lastBeat = -1;

  // The zone: RUNWAY meters past the late edge of its band at its widest (the fastest notes of
  // any difficulty), counted from the first step of the roof that can be seen from the street;
  // never more than a quarter of the way along.
  const perMeter = stage.scale / Math.max(1e-6, roof.track.step);
  let first = 0;
  while (first < n * 0.3 && roof.hiddenAt(first)) first++;
  const widest = Math.max(...Object.values(LEVELS).map((c) => c.perfect / c.travelFast));
  let line = Math.max(3, Math.min(Math.round(n * 0.25), Math.round(first + RUNWAY * perMeter + widest * n)));
  for (let i = line; i < n * 0.35; i++) {
    if (!roof.hiddenAt(i) && !roof.hiddenAt(i - 2) && !roof.hiddenAt(i + 2)) {
      line = i;
      break;
    }
  }
  const span = Math.max(1, n - 1 - line);
  /** The backdrop along the roof (RGB per step), and how much of it shows at each step. */
  const bg = new Float32Array(n * 3);
  const keep = new Float32Array(n);
  const px: Rgb = [0, 0, 0];

  // The board is one per choice of colors and difficulty.
  const round = new Round<Phase>('beat', 'ready', { board: () => `beat:${colors}:${level}`, title: (name) => `${name}: ${LEVEL_NAMES[level]}, ${COLOR_NAMES[colors]}` });
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
  let travel = cfg().travelSlow;
  let demo = true;

  let score = 0;
  let streak = 0;
  let longest = 0;
  let health = HEALTH_START;
  let newBest = false;
  /** The hold being held: by which player, with which color's button. */
  let holder: { player: string; tone: number } | null = null;
  let judged: { text: string; t: number; kind: Judged; n: number } | null = null;
  /** Judgments so far, so the phone can pop each new one. */
  let judgedCount = 0;
  /** Times the multiplier climbed, and was lost, this game: the phone celebrates each. */
  let ups = 0;
  let drops = 0;
  /** The multiplier just climbed: seconds since, and to what (the lights' power-up). */
  let powerAge = 9;
  let powerTo = 1;
  /** Flashes at the zone: gold for a hit, red for a miss (seconds since); the last hit's color. */
  let hitFlash = 9;
  let hitColor: Rgb = COLORS.gold;
  let missFlash = 9;
  /** The bushes lit (smoothed), and when the multiplier was lost. */
  let bushLevel = 0;
  let dropFlash = 9;
  let dropFrom = 0;
  /** The stage showing, the one before (while the new one sweeps in), and since when. */
  let stageNow = 0;
  let stagePrev = 0;
  let stageAge = 9;
  let ripples: Ripple[] = [];
  /** When the phone last announced a new stage. */
  let announced = -9;

  const mult = () => Math.min(MAX_MULT, 1 + Math.floor(streak / STEP));
  const travelFor = (bpm: number) => {
    const c = cfg();
    const f = Math.max(0, Math.min(1, (Math.min(c.bpmMax, bpm) - c.bpmStart) / (c.bpmMax - c.bpmStart)));
    return c.travelSlow - f * (c.travelSlow - c.travelFast);
  };
  const speed = () => span / travel;
  const posAt = (t: number) => line + (t - song) * speed();

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

  /** Where in the bar (0..1) and whole beats since the song began. */
  function barPhase() {
    const b = barNow();
    const k = Math.max(0, ((song - b.start) * b.bpm) / 60);
    return { bar: Math.min(1, k / 4), beats: b.index * 4 + Math.floor(k) };
  }

  /** How strong the backdrop is: by difficulty, and stronger each time round the stages. */
  const lookK = () => (demo ? 1 : LOOK_K[level] * (1 + 0.2 * Math.min(3, Math.floor(stageNow / 6))));

  /** The yard's mood in a stage: its color and a neighbour, brighter with the multiplier. */
  function moodOf(st: number): Mood {
    const accent = lookOf(st).accent;
    return { a: accent, b: turnHue(accent, 0.12), level: 0.9 + 0.25 * (mult() - 1), drift: 1 + 0.3 * (mult() - 1) };
  }

  const ripple = (color: Rgb, amount: number, opts: Partial<Ripple> = {}) => ripples.push({ age: 0, life: 0.9, speed: span / 0.7, width: 5, color, amount, ...opts });

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
    bars.push({ start: nextBar, bpm, index: barIndex });
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
    stageNow = 0;
    stagePrev = 0;
    stageAge = 9;
    ripples = [];
  }

  function newGame() {
    restart(false);
    score = 0;
    streak = 0;
    longest = 0;
    health = HEALTH_START;
    newBest = false;
    bushLevel = 0;
    ups = 0;
    drops = 0;
    fx.clear();
    show.setMood(moodOf(0), { wipe: roof.startsLeft ? 'right' : 'left' });
    round.to('play');
  }

  const linePoint = () => roof.point(line);

  function judge(text: string, kind: Judged) {
    judged = { text, t: round.clock, kind, n: ++judgedCount };
  }

  function gain(points: number) {
    score += points * mult();
  }

  /** A hit: points, a streak, a burst of gold at the zone. `late`: after the note's moment. */
  function hit(note: BeatNote, perfect: boolean, late = false) {
    const before = mult();
    streak++;
    longest = Math.max(longest, streak);
    if (!demo) {
      gain(perfect ? 2 : 1);
      health = Math.min(1, health + (perfect ? 0.04 : 0.025) * cfg().heal);
    }
    judge(perfect ? 'PERFECT!' : late ? 'GOOD · late' : 'GOOD · early', perfect ? 'perfect' : 'good');
    hitFlash = 0;
    hitColor = single() ? COLORS.gold : toneColor(note.tone);
    if (perfect) ripple(COLORS.gold, 0.14, { life: 0.6, width: 3 });
    show.pulse(hitColor, perfect ? 0.12 : 0.06);
    if (perfect && !demo) show.rocket([hitColor, COLORS.gold], { size: 0.6 + 0.1 * mult() });
    sparks.burst(line, [COLORS.gold, mix(COLORS.gold, WHITE, 0.5)], perfect ? 26 : 12, n * (perfect ? 0.18 : 0.11), perfect ? 0.9 : 0.6);
    decorFlare.add(hitColor, perfect ? 0.45 : 0.25);
    decorFlare.add(COLORS.gold, perfect ? 0.2 : 0.1);
    if (!note.hold) note.state = 'done';
    if (mult() > before) stepUp();
  }

  /**
   * The multiplier climbs. The yard celebrates, more at every step: the bushes flash, a gold band
   * runs up the trees, the house flashes and a light flies down to the next bush. The roof, where
   * the next notes come, gets only a soft glow from the zone and a small burst in it.
   */
  function stepUp() {
    const m = mult();
    ups++;
    powerAge = 0;
    powerTo = m;
    const p = linePoint();
    const shine = mix(COLORS.gold, WHITE, 0.35);
    ripple(m >= MAX_MULT ? hsv(round.clock * 0.3) : COLORS.gold, 0.25, { life: 0.8, width: 4 });
    sparks.burst(line, [COLORS.gold, shine], 10 + 3 * m, n * 0.06, 0.6);
    decorFlare.add(COLORS.gold, 0.5 + 0.1 * m);
    // Up goes a volley, one firework more at every step, and gold sweeps up the yard.
    show.sweep(COLORS.gold, { dir: 'up', amount: 0.6 });
    show.finale(1 + m, { colors: m >= MAX_MULT ? [[hsv(0)], [hsv(0.2)], [hsv(0.45)], [hsv(0.6)], [hsv(0.8)]] : [[COLORS.gold, hitColor]] });
    const b = yard.bushes.length;
    if (b) {
      const lit = Math.max(1, Math.round((b * (mult() - 1)) / (MAX_MULT - 1)));
      const bush = yard.bushes[Math.min(b - 1, lit - 1)];
      motes.fly(p, yard.topOf(bush), mix(COLORS.gold, WHITE, 0.3), 0.5, { arc: 40, size: 28 });
    }
  }

  function breakStreak() {
    if (mult() > 1) {
      drops++;
      dropFlash = 0;
      dropFrom = bushLevel;
      // The multiplier shatters: red sparks all along the roof.
      for (let k = 0; k < 6; k++) sparks.burst(line + span * (0.12 + 0.15 * k + 0.05 * Math.random()), [COLORS.bad, [1, 0.25, 0]], 6, n * 0.05, 0.6);
      // And the yard: red debris falls off every bush that was lit, and red runs away along the house.
      yard.bushes.forEach((bush, bi) => bi < Math.ceil(bushLevel - 0.05) && show.explode(bush.x, bush.top, COLORS.bad, { size: 0.7 }));
      show.sweep(COLORS.bad, { dir: roof.startsLeft ? 'right' : 'left', amount: 0.5, duration: 0.6 });
    }
    streak = 0;
  }

  function miss(note: BeatNote) {
    note.state = 'missed';
    note.age = 0;
    if (demo) return;
    breakStreak();
    health -= cfg().miss;
    judge('MISS', 'miss');
    missFlash = 0;
    sparks.burst(line, [COLORS.bad, [1, 0.25, 0]], 10, n * 0.1, 0.5);
    const lp = linePoint();
    show.ripple(lp.x, lp.y, COLORS.bad, { amount: 0.6 });
    show.pulse(COLORS.bad, 0.15);
    // Red runs out along the whole roof, twice.
    ripple(COLORS.bad, 0.55, { width: 7 });
    ripple(COLORS.bad, 0.35, { width: 4, speed: span / 1.1, life: 1.2 });
    if (health <= 0) gameOver();
  }

  /** A press with no note of its color near it: the streak breaks, a little health goes. */
  function stray(wrongColor: boolean) {
    breakStreak();
    health -= cfg().stray;
    judge(wrongColor ? 'Wrong color!' : 'Too early!', 'stray');
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
      judge('HELD!', 'held');
      hitFlash = 0;
      hitColor = single() ? COLORS.gold : toneColor(note.tone);
      sparks.burst(line, [COLORS.gold, mix(COLORS.gold, WHITE, 0.5), single() ? TAIL : hitColor], 24, n * 0.17, 0.9);
      decorFlare.add(hitColor, 0.4);
      decorFlare.add(COLORS.gold, 0.3);
      if (!demo) show.rocket([hitColor, COLORS.gold], { size: 1, kind: 'ring' });
    } else {
      note.state = 'broken';
      if (!demo) {
        const part = Math.max(0, Math.min(1, (t - note.time) / Math.max(0.01, note.end - note.time)));
        gain(Math.floor(bonus * part));
        breakStreak();
        health -= cfg().broken;
        judge('Let go too soon', 'stray');
        missFlash = 0;
        if (health <= 0) gameOver();
      }
    }
  }

  function gameOver() {
    health = 0;
    holder = null;
    newBest = round.record(score);
    // Everything still on the roof falls off the gutter.
    for (const note of notes) {
      if (note.state !== 'coming' && note.state !== 'held') continue;
      const pos = posAt(note.time);
      if (pos > n - 1) continue;
      const p = roof.point(Math.max(line, pos));
      motes.drop(p.x, p.y, mix(single() ? TAIL : toneColor(note.tone), COLORS.bad, 0.5), { vx: (Math.random() - 0.5) * 60, size: 20 });
    }
    notes = [];
    // The house blows, and the yard goes dark red (gold fireworks for a new best).
    const lp = linePoint();
    show.gameOver(lp.x, lp.y, { newBest });
    round.to('over');
  }

  const holding = () => notes.find((x) => x.state === 'held');

  /** Which color a button is (-1: not a color button, such as the big button). */
  const toneOf = (button: string | undefined) => (button ? BUTTONS.indexOf(button) : -1);

  function press(player: string, button: string | undefined) {
    if (!playable) return;
    // Any button starts a game.
    if (round.canStart) return newGame();
    // With one color, any button plays any note; with four, the big button does nothing while
    // playing. No button does anything during a hold (no note ever comes during one).
    const tone = single() ? 0 : toneOf(button);
    if (round.phase !== 'play' || holder || tone < 0) return;
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
    hit(best, Math.abs(best.time - t) <= perfect, t > best.time);
  }

  function release(player: string, button: string | undefined) {
    if (round.phase !== 'play' || !holder || player !== holder.player) return;
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
    // A new stage every STAGE_BARS bars: it sweeps in along the roof, and the house flares in its color.
    const st = Math.floor(barNow().index / STAGE_BARS);
    if (st !== stageNow) {
      stagePrev = stageNow;
      stageNow = st;
      stageAge = 0;
      const look = lookOf(st);
      const p = linePoint();
      waves.add(p.x, p.y, look.accent, { amount: 0.6 });
      decorFlare.add(look.accent, 0.8);
      // The new stage wipes across the whole yard, with fireworks in its colors.
      show.setMood(moodOf(st), { wipe: roof.startsLeft ? 'right' : 'left' });
      if (!demo) show.finale(4, { colors: [[look.accent, turnHue(look.accent, 0.15)]] });
      if (!demo) announced = round.clock;
    }
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
      if (round.phase !== 'play') return;
    }
    // Notes that have gone past the start of the roof are gone, once judged (a note nobody
    // pressed stays until it counts as a miss, even past the end of the roof).
    notes = notes.filter((x) => (x.state === 'coming' || x.state === 'held' || posAt(x.end) > -6) && !(x.state === 'done' && x.age > 0.5));
    bars = bars.filter((b, i) => i + 1 >= bars.length || bars[i + 1].start > song - 1);
  }

  // ---------- Drawing ----------

  /** The zone's color: a warm white (blue-white with one color), tinting toward the next note's color as it comes near. */
  function zoneTint(due: BeatNote | null): Rgb {
    const near = due && round.phase !== 'over' ? Math.max(0, 1 - (due.time - song) / Math.max(0.3, travel * 0.4)) : 0;
    const base = single() ? COLORS.hint : POST;
    return near > 0 && due && !single() ? mix(base, toneColor(due.tone), 0.5 * near) : base;
  }

  /**
   * The zone's two posts, two steps thick with a dark step either side, drawn last and over
   * everything else (sparks, flashes, ripples), so the zone stays easy to see through every explosion. A hit flashes them in the
   * note's color, a miss red. A note's head passing over a post shows through it.
   */
  function drawPosts(frame: Frame) {
    let due: BeatNote | null = null;
    for (const x of notes) if (x.state === 'coming' && (!due || x.time < due.time)) due = x;
    const half = zoneHalf();
    const hitK = Math.max(0, 1 - hitFlash / 0.25);
    const missK = Math.max(0, 1 - missFlash / 0.35);
    let color = zoneTint(due);
    if (hitK) color = mix(color, hitColor, 0.6 * hitK);
    if (missK) color = mix(color, COLORS.bad, missK);
    // Full brightness always: the glow around them (in the backdrop) breathes on the beat.
    const amount = 1;
    const set = (led: number, c: Rgb, a: number) => frame.set(led, [c[0] * a, c[1] * a, c[2] * a]);
    const heads = notes.filter((x) => x.state === 'coming' || (x.hold && x.state !== 'done')).flatMap((x) => (x.hold ? [posAt(x.time), posAt(x.end)] : [posAt(x.time)]));
    for (const [at, out] of [
      [Math.round(line - half - 1), -1],
      [Math.round(line + half + 1), 1]
    ]) {
      // A dark step either side of each post keeps it crisp inside the sparks.
      for (const [pos, c] of [
        [at - out, DARK],
        [at, color],
        [at + out, color],
        [at + 2 * out, DARK]
      ] as const) {
        if (pos < 0 || pos >= n || heads.some((h) => Math.abs(h - pos) < 2.5)) continue;
        roof.at(set, pos, c, amount);
      }
    }
  }

  /** The half width of the zone's band, in steps: the PERFECT window at the notes' speed now. */
  const zoneHalf = () => Math.max(2.5, cfg().perfect * speed());

  /** Light into the backdrop: a soft dot at a step. */
  function bgDot(pos: number, color: Rgb, width: number, amount: number) {
    const lo = Math.max(0, Math.floor(pos - width * 2.5));
    const hi = Math.min(n - 1, Math.ceil(pos + width * 2.5));
    for (let i = lo; i <= hi; i++) {
      const d = (i - pos) / width;
      const a = Math.exp(-d * d) * amount;
      bg[i * 3] += color[0] * a;
      bg[i * 3 + 1] += color[1] * a;
      bg[i * 3 + 2] += color[2] * a;
    }
  }

  /** Dims the backdrop over a stretch (lo to hi) to `floor`, fading back over CLEAR steps either side. */
  function clearOver(lo: number, hi: number, floor: number) {
    const from = Math.max(0, Math.floor(lo - CLEAR));
    const to = Math.min(n - 1, Math.ceil(hi + CLEAR));
    for (let i = from; i <= to; i++) {
      const out = i < lo ? lo - i : i > hi ? i - hi : 0;
      keep[i] = Math.min(keep[i], floor + (1 - floor) * Math.min(1, out / CLEAR));
    }
  }

  /**
   * The backdrop along the whole roof: the stage's look (the new one sweeping in over the old),
   * the ripples, a stutter after a miss, a heartbeat when health is low, and the zone. Dimmed
   * under and around every note, so the notes, drawn on top, always stand out.
   */
  function drawBackdrop(due: BeatNote | null, beat: number) {
    const { bar, beats } = barPhase();
    const scene: Scene = { i: 0, x: 0, u: 0, span, clock: round.clock, beat: beatPhase(), bar, beats, k: lookK() };
    const look = lookOf(stageNow);
    const old = lookOf(stagePrev);
    const front = stageAge < WIPE ? line + (stageAge / WIPE) * (span + 12) : Infinity;
    const missK = Math.max(0, 1 - missFlash / 0.45);
    const fadeOut = round.phase === 'over' ? Math.max(0.1, 1 - round.time / 1.5) : 1;
    const low = round.phase === 'play' && !demo && health < 0.3 ? ((0.3 - health) / 0.3) * Math.exp(-scene.beat * 6) : 0;
    const glitch = Math.floor(round.clock * 30);
    for (let i = 0; i < n; i++) {
      px[0] = px[1] = px[2] = 0;
      scene.i = i;
      scene.x = i - line;
      scene.u = scene.x / span;
      (i > front ? old : look).paint(scene, px);
      if (front < Infinity) {
        const d = (i - front) / 3;
        if (d > -3 && d < 3) {
          const a = Math.exp(-d * d) * 0.7;
          px[0] += look.accent[0] * a;
          px[1] += look.accent[1] * a;
          px[2] += look.accent[2] * a;
        }
      }
      // A miss: the backdrop stutters and turns red for a moment.
      if (missK) {
        const lum = (px[0] + px[1] + px[2]) / 3 + 0.04;
        const flicker = hash(i * 31 + glitch) < 0.5 ? 1 - 0.7 * missK : 1;
        px[0] = (px[0] + (lum * 2 - px[0]) * 0.7 * missK + 0.12 * missK * missK) * flicker;
        px[1] = px[1] * (1 - 0.7 * missK) * flicker;
        px[2] = px[2] * (1 - 0.7 * missK) * flicker;
      }
      bg[i * 3] = px[0] * fadeOut + COLORS.bad[0] * 0.12 * low;
      bg[i * 3 + 1] = px[1] * fadeOut;
      bg[i * 3 + 2] = px[2] * fadeOut;
      keep[i] = 1;
    }
    for (const r of ripples) {
      if (r.age < 0) continue;
      const a = r.amount * (1 - r.age / r.life) * fadeOut;
      bgDot(line + r.age * r.speed, r.color, r.width, a);
      bgDot(line - r.age * r.speed, r.color, r.width, a);
    }
    // A new multiplier: a soft glow sweeps out along the roof from the zone and fades (see stepUp).
    if (powerAge < POWER) {
      const front = (powerAge / 0.45) * (span + 10);
      const fade = (1 - powerAge / POWER) * fadeOut;
      const amount = 0.05 + 0.02 * (powerTo - 2);
      const top = powerTo >= MAX_MULT;
      for (let i = 0; i < n; i++) {
        const d = Math.abs(i - line);
        if (d > front + 8) continue;
        const edge = Math.exp(-(((d - front) / 3) ** 2));
        const c = top ? mix(hsv((i / n) * 2 + round.clock * 0.8), WHITE, 0.2) : mix(COLORS.gold, WHITE, 0.3 * edge);
        const a = ((d <= front ? amount : 0) + 0.2 * edge) * fade;
        bg[i * 3] += c[0] * a;
        bg[i * 3 + 1] += c[1] * a;
        bg[i * 3 + 2] += c[2] * a;
      }
    }

    // The zone: the backdrop dimmed around it, a soft band between two bright posts, and the late
    // side, past the band, a faint red.
    const half = zoneHalf();
    const hitK = Math.max(0, 1 - hitFlash / 0.25);
    const zoneMissK = Math.max(0, 1 - missFlash / 0.35);
    clearOver(line - half - 1, line + half + 1, 0.15);
    for (let i = 0; i < Math.floor(line - half - CLEAR - 1); i++) keep[i] = Math.min(keep[i], 0.25);
    for (let i = 0; i < n; i++) for (let c = 0; c < 3; c++) bg[i * 3 + c] *= keep[i];
    const zoneColor = zoneTint(due);
    const add = (i: number, c: Rgb, a: number) => {
      bg[i * 3] += c[0] * a;
      bg[i * 3 + 1] += c[1] * a;
      bg[i * 3 + 2] += c[2] * a;
    };
    for (let i = Math.max(0, Math.ceil(line - half)); i <= Math.min(n - 1, Math.floor(line + half)); i++) {
      add(i, zoneColor, 0.12 + 0.06 * beat);
      if (hitK) add(i, hitColor, 0.25 * hitK);
      if (zoneMissK) add(i, COLORS.bad, 0.3 * zoneMissK);
    }
    for (let i = 0; i < Math.ceil(line - half - 1); i++) add(i, COLORS.bad, 0.045);
    // A glow around the posts (the posts themselves are drawn last, over everything: see drawPosts).
    for (const at of [line - half - 1.5, line + half + 1.5]) bgDot(at, zoneColor, 1.6, 0.25 + 0.15 * beat);

    // Under and around every note: the backdrop (and the zone) give way, so the note stands alone.
    keep.fill(1);
    const floor = Math.min(0.3, CLEAR_KEEP + 0.03 * Math.min(6, stageNow));
    for (const x of notes) {
      if (x.state === 'done') continue;
      const head = posAt(x.time);
      if (head > n + CLEAR) continue;
      const held = x.state === 'held';
      const tail = x.hold ? posAt(x.end) : head + Math.max(2, Math.min(6, speed() * 0.06)) + 1;
      const alive = x.state === 'coming' || held;
      const fade = alive ? 1 : Math.max(0, 1 - x.age / 0.8);
      if (fade <= 0) continue;
      clearOver(held ? line : head - 1, tail + 1, 1 - (1 - floor) * fade);
    }
    for (let i = 0; i < n; i++) {
      const k = keep[i];
      px[0] = bg[i * 3] * k;
      px[1] = bg[i * 3 + 1] * k;
      px[2] = bg[i * 3 + 2] * k;
      if (px[0] + px[1] + px[2] > 0.002) yard.roofAt(i, px, 1);
    }
  }

  function drawRoof() {
    const beat = Math.exp(-beatPhase() * 5);
    const sp = speed();
    let due: BeatNote | null = null;
    for (const x of notes) if (x.state === 'coming' && (!due || x.time < due.time)) due = x;
    drawBackdrop(due, beat);
    for (const x of notes) {
      const head = posAt(x.time);
      if (head > n + 4) continue;
      if (x.state === 'done') continue;
      const alive = x.state === 'coming' || x.state === 'held';
      // A missed note goes on past the zone, gray, and fades.
      const fade = alive ? 1 : Math.max(0, 1 - x.age / 0.8);
      if (fade <= 0) continue;
      if (single()) {
        drawClassic(x, head, alive, fade, sp);
        continue;
      }
      const color = alive ? toneColor(x.tone) : MISSED;
      if (x.hold) {
        const held = x.state === 'held';
        // Held: the body is eaten up at the zone as it slides in. A dark step behind the head
        // keeps it apart from the body.
        const from = held ? line : Math.max(head + 2, -6);
        const end = posAt(x.end);
        const to = Math.min(n - 1, end - 1.5);
        const pulse = held ? 0.45 + 0.15 * Math.sin(round.clock * 24) : 0.3;
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
    // A hit: a flash in the note's color at the middle of the zone; a miss: red.
    const hitK = Math.max(0, 1 - hitFlash / 0.25);
    const missK = Math.max(0, 1 - missFlash / 0.35);
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
      const pulse = held ? 0.75 + 0.25 * Math.sin(round.clock * 24) : 0.5;
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
    const lit = round.phase === 'over' ? 0 : (b * (mult() - 1)) / (MAX_MULT - 1);
    const beat = Math.exp(-beatPhase() * 4);
    const drop = Math.max(0, 1 - dropFlash / 0.6);
    // A flash in the color of the note just hit.
    const flash = round.phase === 'play' && !single() ? Math.max(0, 1 - hitFlash / 0.2) : 0;
    // A new multiplier: every bush flashes and fades, brighter at every step.
    const power = powerAge < 0.8 ? (0.3 + 0.08 * powerTo) * (1 - powerAge / 0.8) : 0;
    yard.bushes.forEach((bush, bi) => {
      const on = Math.max(0, Math.min(1, bushLevel - bi));
      const color = mult() >= MAX_MULT ? mix(COLORS.gold, WHITE, 0.25 * beat) : COLORS.gold;
      for (let i = 0; i < bush.count; i++) {
        if (on > 0) yard.add(bush.offset + i, color, on * (0.4 + 0.45 * beat + 0.1 * Math.sin(round.clock * 6 + i * 2.1)));
        // The multiplier lost: the bushes that were lit flash red as they go out.
        if (drop && bi < Math.ceil(dropFrom - 0.05)) yard.add(bush.offset + i, COLORS.bad, drop * 0.4);
        if (flash) yard.add(bush.offset + i, hitColor, flash * 0.35);
        if (power) yard.add(bush.offset + i, powerTo >= MAX_MULT ? hsv(bi / b + round.clock * 1.5) : mix(COLORS.gold, WHITE, 0.4), power);
      }
    });
    bushLevel += (lit - bushLevel) * 0.2;
  }

  function drawTree(part: Part) {
    // The health meter, from the base up: green when healthy, yellow, then red and blinking.
    const low = health < 0.25 && round.phase === 'play';
    const blink = low ? (Math.sin(round.clock * 14) > 0 ? 1 : 0.25) : 1;
    const color = health < 0.25 ? COLORS.bad : hsv(0.33 * Math.min(1, (health - 0.15) / 0.75));
    for (let i = 0; i < part.count; i++) {
      if (part.up[i] <= health) yard.add(part.offset + i, color, 0.6 * blink);
      // A new multiplier: a gold band runs up the tree.
      if (powerAge < 0.8) yard.add(part.offset + i, COLORS.gold, 0.7 * Math.exp(-(((part.up[i] - powerAge / 0.6) / 0.12) ** 2)));
    }
  }

  /** The house: the show's backdrop pumping to the music, and the flare of every hit. */
  function drawDecor(part: Part) {
    for (let i = 0; i < part.count; i++) yard.add(part.offset + i, decorFlare.color, 0.5);
  }

  /** The yard's mood from the game's state: the stage, the multiplier, and red when health runs low. */
  function moodNow(): Mood {
    if (round.phase === 'over') return overMood(round.time);
    const m = moodOf(stageNow);
    if (round.phase === 'play' && !demo && health < 0.3) return { a: COLORS.bad, b: mix(m.a, COLORS.bad, 0.6), level: 1.1, throb: barNow().bpm / 60 };
    return m;
  }

  restart(true);

  return {
    id: 'beat',

    scoreBoard: () => round.scoreBoard(),

    input(e: GameInput) {
      if (e.action === 'press') press(e.playerId, e.button);
      else release(e.playerId, e.button);
    },

    leave(playerId: string) {
      release(playerId, undefined);
    },

    setting(id: string, value: string) {
      if (round.phase === 'play') return;
      if (id === 'colors' && (value === '1' || value === '2' || value === '4')) colors = value;
      else if (id === 'level' && (value === 'easy' || value === 'normal' || value === 'hard')) level = value;
      else return;
      // The attract demo shows the new choice.
      if (round.phase === 'ready') restart(true);
    },

    chart() {
      return { song, notes };
    },

    look() {
      return { line, zone: zoneHalf(), stage: stageNow, name: lookOf(stageNow).name };
    },

    update(dt: number, frame: Frame) {
      round.tick(dt);
      hitFlash += dt;
      missFlash += dt;
      dropFlash += dt;
      powerAge += dt;
      stageAge += dt;
      for (const r of ripples) r.age += dt;
      ripples = ripples.filter((r) => r.age < r.life);
      yard.begin(frame);
      if (!playable) return;
      if (round.phase === 'ready' || round.phase === 'play') step(dt);
      if (round.timedOut) {
        restart(true);
        round.to('ready');
      }
      fx.update(dt);
      if (round.settled) show.followMood(moodNow(), 2, dt);
      // The yard pumps on every beat, harder with the multiplier.
      const { beats } = barPhase();
      if (beats !== lastBeat && round.phase !== 'over') {
        lastBeat = beats;
        show.pulse(lookOf(stageNow).accent, demo ? 0.04 : 0.05 + 0.025 * mult());
      }

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      for (const d of yard.decor) drawDecor(d);
      if (round.phase === 'over') endGlow(yard, round.time, 0.05);
      fx.draw(frame);
      drawPosts(frame);
    },

    status(): GameStatusFields {
      const best = round.best();
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
      if (!playable) return round.setup();
      const stats = [
        { label: 'Score', value: score },
        { label: 'Best', value: Math.max(best, score) },
        { label: 'Multiplier', value: `×${mult()}` },
        { label: 'BPM', value: Math.round(barNow().bpm) },
        { label: 'Stage', value: stageNow + 1 }
      ];
      const common = { score, lives: null, goal: null };
      // The arcade cabinet around the yard on the phone, from GO! to game over.
      const arcade = (play: boolean): ArcadeHud => {
        const m = play ? mult() : 1;
        return {
          score: round.phase === 'ready' ? 0 : score,
          best,
          mult: m,
          maxMult: MAX_MULT,
          charge: !play ? 0 : m >= MAX_MULT ? STEP : streak % STEP,
          perStep: STEP,
          streak: play ? streak : 0,
          judged: play && judged ? { n: judged.n, text: judged.text, kind: judged.kind } : null,
          ups,
          drops,
          info: [
            { label: 'Stage', value: stageNow + 1 },
            { label: 'BPM', value: Math.round(barNow().bpm) }
          ]
        };
      };
      switch (round.phase) {
        case 'ready':
          return {
            ...common,
            score: 0,
            phase: round.phase,
            message: single()
              ? `${choice} Tap GO! Then tap as each white note passes through the blue zone. Hold the long ones until their end goes by.`
              : `${choice} Tap GO! Then press the button in each note’s color as it passes through the lit zone. Hold the long ones until their end goes by.`,
            button: 'GO!',
            tone: 'go',
            stats: [{ label: 'Best', value: best }],
            arcade: arcade(false),
            settings
          };
        case 'play': {
          const held = !!holder;
          // The arcade display shows each judgment, the streak and the multiplier; the message
          // is for what to do: hold, a new stage, and how to play until the first judgment.
          const message = held
            ? single()
              ? 'Hold… let go when the white end reaches the zone.'
              : `Hold ${LABELS[holder!.tone]}… let go when the bright end reaches the zone.`
            : round.clock - announced < 2
              ? `Stage ${stageNow + 1}: ${lookOf(stageNow).name}!`
              : judged
                ? ''
                : single()
                  ? 'Tap when a white note passes through the blue zone.'
                  : 'Press the button in the note’s color as it passes through the zone.';
          return {
            ...common,
            phase: round.phase,
            message,
            arcade: arcade(true),
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
            phase: round.phase,
            message: newBest ? `New best: ${score}! (${choice})` : `Game over: ${score} points. Longest streak ${longest}. (${choice})`,
            button: 'GO!',
            tone: 'go',
            stats,
            arcade: arcade(false),
            settings
          };
      }
    }
  };
}
