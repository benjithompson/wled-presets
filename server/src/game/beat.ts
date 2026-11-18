import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, COLORS, Flare, heat, Motes, record, scale, Sparks, Waves, Yard, type Part } from './kit.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Beat Drop: a rhythm game on the roofline. Notes slide along the roof toward two soft blue posts
// near its start: tap as a note's white head reaches the posts. Long notes are holds: press as
// the head arrives, keep holding while the body slides through, and let go as the white end cap
// reaches the posts. The chart never ends: the tempo creeps up bar by bar (90 to 170 beats a
// minute) and the patterns get busier, so a perfect player can go on forever.
//
// Presses are judged by time (each note has its moment), as the player saw it: a press counts
// where the notes were a moment ago, since the phone and Wi-Fi are a little late. PERFECT is
// worth 2, GOOD 1, a hold that is held to its end a bonus by its length; everything times the
// multiplier, which climbs every 8 hits in a row up to ×4. A miss breaks the streak and drains
// the health meter; hits fill it back a little; empty is game over.
//
// Colors mean one thing each: white is only the notes' heads and hold end caps (what you time
// against), cyan and blue their tails and bodies, soft blue-white the posts, gold points, red a
// miss.
//
// The yard: the bushes are the multiplier, one more lit gold for each step (×2, ×3, ×4), pulsing
// on the beat. The trees are the health meter, filling from the base up (green when healthy,
// red and blinking when low). Windows and doors bounce on every beat and flare gold with hits.

type Phase = 'ready' | 'play' | 'over';

export interface BeatNote {
  /** The moment the head reaches the posts (song time, seconds). */
  time: number;
  /** A hold's end (the same as time for a tap). */
  end: number;
  hold: boolean;
  /** A hold's length in beats. */
  beats: number;
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
/** Timing windows, in seconds either side of a note's moment. */
export const PERFECT = 0.05;
export const GOOD = 0.12;
/** A hold let go this close to its end (or later) counts as held to the end. */
const RELEASE = 0.15;
/** Notes are never closer than this; after a hold, never closer than HOLD_GAP. */
const MIN_GAP = 0.17;
const HOLD_GAP = 0.3;
const BPM_START = 90;
const BPM_MAX = 170;
const BPM_DEMO = 100;
/** Seconds from the far end of the roof to the posts: slow at the start, quicker at top speed. */
const TRAVEL_SLOW = 2.4;
const TRAVEL_FAST = 1.4;
/** Hits in a row for each step of the multiplier. */
const STEP = 8;
const MAX_MULT = 4;
const HEALTH_START = 0.6;

const NIGHT: Rgb = [0.02, 0.008, 0.045];
const TAIL: Rgb = [0, 0.75, 1];
const BODY_FAR: Rgb = [0.1, 0.1, 1];
const MISSED: Rgb = [0.12, 0.1, 0.16];

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
  let travel = TRAVEL_SLOW;
  let demo = true;

  let score = 0;
  let streak = 0;
  let longest = 0;
  let health = HEALTH_START;
  let newBest = false;
  let holder: string | null = null;
  let judged: { text: string; t: number } | null = null;
  /** Flashes at the posts: gold for a hit, red for a miss (seconds since). */
  let hitFlash = 9;
  let missFlash = 9;
  /** The bushes lit (smoothed), and when the multiplier was lost. */
  let bushLevel = 0;
  let dropFlash = 9;
  let dropFrom = 0;

  const mult = () => Math.min(MAX_MULT, 1 + Math.floor(streak / STEP));
  const travelFor = (bpm: number) => TRAVEL_SLOW - ((Math.min(BPM_MAX, bpm) - BPM_START) / (BPM_MAX - BPM_START)) * (TRAVEL_SLOW - TRAVEL_FAST);
  const speed = () => span / travel;
  const posAt = (t: number) => line + (t - song) * speed();

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

  /** The bar playing now (the last one started). */
  function barNow(): Bar {
    let b = bars[0] ?? { start: 0, bpm: demo ? BPM_DEMO : BPM_START };
    for (const x of bars) if (x.start <= song) b = x;
    return b;
  }

  /** Where in the beat the song is: 0 on the beat, rising to 1 just before the next. */
  function beatPhase() {
    const b = barNow();
    const k = ((song - b.start) * b.bpm) / 60;
    return k < 0 ? 0 : k - Math.floor(k);
  }

  function addBar() {
    const bpm = demo ? BPM_DEMO : Math.min(BPM_MAX, BPM_START + barIndex * 1.5);
    const tier = demo ? 1 : barIndex === 0 ? -1 : Math.min(PATTERNS.length - 1, barIndex < 4 ? 0 : barIndex < 10 ? 1 : barIndex < 20 ? 2 : 3);
    // The first bar is gentle; every eighth bar is a breather.
    const library = tier < 0 || (!demo && barIndex % 8 === 7) ? [[[0, 0], [2, 0]] as [number, number][]] : PATTERNS[Math.min(tier, PATTERNS.length - 1)].concat(tier > 0 ? PATTERNS[tier - 1] : []);
    const pattern = library[Math.floor(Math.random() * library.length)];
    const beat = 60 / bpm;
    bars.push({ start: nextBar, bpm });
    for (const [at, len] of pattern) {
      const time = nextBar + at * beat;
      if (time - lastEnd < (lastHold ? HOLD_GAP : MIN_GAP)) continue;
      const hold = len > 0;
      const end = hold ? time + len * beat : time;
      notes.push({ time, end, hold, beats: len, state: 'coming', age: 0 });
      lastEnd = end;
      lastHold = hold;
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
    travel = travelFor(demo ? BPM_DEMO : BPM_START);
    // A lead-in: the first note comes all the way along the roof.
    nextBar = travel + 1.2;
    lastEnd = -Infinity;
    lastHold = false;
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
      health = Math.min(1, health + (perfect ? 0.04 : 0.025));
    }
    judged = { text: perfect ? 'PERFECT!' : 'GOOD', t: clock };
    hitFlash = 0;
    sparks.burst(line, [COLORS.gold, mix(COLORS.gold, WHITE, 0.5)], perfect ? 26 : 12, n * (perfect ? 0.3 : 0.18), perfect ? 0.9 : 0.6);
    decorFlare.add(COLORS.gold, perfect ? 0.5 : 0.25);
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
    health -= 0.12;
    judged = { text: 'MISS', t: clock };
    missFlash = 0;
    sparks.burst(line, [COLORS.bad, [1, 0.25, 0]], 10, n * 0.1, 0.5);
    if (health <= 0) gameOver();
  }

  /** A press with no note near it: the streak breaks, a little health goes. */
  function stray() {
    breakStreak();
    health -= 0.04;
    judged = { text: 'Too early!', t: clock };
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
        health = Math.min(1, health + 0.03);
      }
      judged = { text: 'HELD!', t: clock };
      hitFlash = 0;
      sparks.burst(line, [COLORS.gold, WHITE, TAIL], 24, n * 0.28, 0.9);
      decorFlare.add(COLORS.gold, 0.6);
    } else {
      note.state = 'broken';
      if (!demo) {
        const part = Math.max(0, Math.min(1, (t - note.time) / Math.max(0.01, note.end - note.time)));
        gain(Math.floor(bonus * part));
        breakStreak();
        health -= 0.06;
        judged = { text: 'Let go too soon', t: clock };
        missFlash = 0;
        if (health <= 0) gameOver();
      }
    }
  }

  function gameOver() {
    health = 0;
    holder = null;
    newBest = record('beat', score).isNew;
    // Everything still on the roof falls off the gutter.
    for (const note of notes) {
      if (note.state !== 'coming' && note.state !== 'held') continue;
      const pos = posAt(note.time);
      if (pos > n - 1) continue;
      const p = roof.point(Math.max(line, pos));
      motes.drop(p.x, p.y, mix(note.hold ? BODY_FAR : TAIL, COLORS.bad, 0.5), { vx: (Math.random() - 0.5) * 60, size: 20 });
    }
    notes = [];
    setPhase('over');
  }

  const holding = () => notes.find((x) => x.state === 'held');

  function press(id: string) {
    if (!playable) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    if (phase !== 'play' || holder) return;
    const t = song - LAG;
    let best: BeatNote | null = null;
    for (const x of notes) if (x.state === 'coming' && Math.abs(x.time - t) <= GOOD && (!best || Math.abs(x.time - t) < Math.abs(best.time - t))) best = x;
    if (!best) return stray();
    if (best.hold) {
      best.state = 'held';
      holder = id;
    }
    hit(best, Math.abs(best.time - t) <= PERFECT);
  }

  function release(id: string) {
    if (phase !== 'play' || !holder || id !== holder) return;
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
      if (x.state === 'coming' && t > x.time + GOOD) miss(x);
      else if (x.state === 'held' && t >= x.end) finishHold(x, true, t);
      if (phase !== 'play') return;
    }
    // Notes that have gone past the start of the roof are gone.
    notes = notes.filter((x) => posAt(x.end) > -6 && !(x.state === 'done' && x.age > 0.5));
    bars = bars.filter((b, i) => i + 1 >= bars.length || bars[i + 1].start > song - 1);
  }

  // ---------- Drawing ----------

  function drawRoof() {
    const beat = Math.exp(-beatPhase() * 5);
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT, 1 + 0.5 * beat);
    const sp = speed();
    for (const x of notes) {
      const head = posAt(x.time);
      if (head > n + 4) continue;
      if (x.state === 'done') continue;
      const alive = x.state === 'coming' || x.state === 'held';
      // A missed note goes on past the posts, gray, and fades.
      const fade = alive ? 1 : Math.max(0, 1 - x.age / 0.8);
      if (fade <= 0) continue;
      if (x.hold) {
        const held = x.state === 'held';
        // Held: the body is eaten up at the posts as it slides in.
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
        if (head > n - 1) continue;
        // A short cyan tail behind the head (toward the far end, where it came from).
        const tail = Math.max(2, Math.min(6, sp * 0.06));
        for (let k = 1; k <= tail; k++) yard.roofSplat(head + k, alive ? TAIL : MISSED, 0.7, (1 - k / (tail + 1)) * 0.6 * fade);
        yard.roofSplat(head, alive ? WHITE : MISSED, 1.1, fade);
      }
    }
    // The posts: soft blue-white, breathing on the beat; gold on a hit, red on a miss.
    const hitK = Math.max(0, 1 - hitFlash / 0.25);
    const missK = Math.max(0, 1 - missFlash / 0.35);
    for (const at of [line - 2.2, line + 2.2]) {
      yard.roofSplat(at, COLORS.hint, 0.8, 0.3 + 0.3 * beat);
      if (hitK) yard.roofSplat(at, COLORS.gold, 1, hitK);
      if (missK) yard.roofSplat(at, COLORS.bad, 1.2, missK);
    }
    if (missK) yard.roofSplat(line, COLORS.bad, 3, missK * 0.6);
    sparks.draw(yard);
  }

  function drawBushes() {
    const b = yard.bushes.length;
    const lit = phase === 'over' ? 0 : (b * (mult() - 1)) / (MAX_MULT - 1);
    const beat = Math.exp(-beatPhase() * 4);
    const drop = Math.max(0, 1 - dropFlash / 0.6);
    yard.bushes.forEach((bush, bi) => {
      const on = Math.max(0, Math.min(1, bushLevel - bi));
      const color = mult() >= MAX_MULT ? mix(COLORS.gold, WHITE, 0.25 * beat) : COLORS.gold;
      for (let i = 0; i < bush.count; i++) {
        yard.add(bush.offset + i, [0.02, 0.02, 0.05]);
        if (on > 0) yard.add(bush.offset + i, color, on * (0.4 + 0.45 * beat + 0.1 * Math.sin(clock * 6 + i * 2.1)));
        // The multiplier lost: the bushes that were lit flash red as they go out.
        if (drop && bi < Math.ceil(dropFrom - 0.05)) yard.add(bush.offset + i, COLORS.bad, drop * 0.4);
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

    input(e: GameInput) {
      if (e.action === 'press') press(e.playerId);
      else release(e.playerId);
    },

    leave(playerId: string) {
      release(playerId);
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
      const best = bestScore('beat');
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
          return { ...common, score: 0, phase, message: 'Tap to start! Tap as each white note reaches the blue posts. Hold the long ones until their end goes by.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'play': {
          const held = !!holder;
          const recent = judged && clock - judged.t < 1.2 ? judged.text : null;
          const run = streak >= 2 ? ` ${streak} in a row` : '';
          const message = held
            ? 'Hold… let go when the white end reaches the posts.'
            : recent
              ? `${recent}${recent === 'MISS' || recent.startsWith('Too') || recent.startsWith('Let') ? '' : run}`
              : streak >= STEP
                ? `×${mult()}!${run}`
                : 'Tap when a white note reaches the blue posts.';
          return { ...common, phase, message, button: held ? 'HOLD' : 'TAP', tone: 'go', progress: { value: Math.round(Math.max(0, health) * 100), max: 100 }, stats };
        }
        case 'over':
          return { ...common, phase, message: newBest ? `New best: ${score}!` : `Game over: ${score} points. Longest streak ${longest}.`, button: 'GO!', tone: 'go', stats };
      }
    }
  };
}
