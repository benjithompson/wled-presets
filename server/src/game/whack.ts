import type { GameSetting, MoleBoard, MoleHole, Stage } from '../../../shared/layout.ts';
import { ease, hex, hsv, lerp, mix, WHITE, type Rgb } from '../../../shared/color.ts';
import { type Frame } from './frame.ts';
import { COLORS, Flare, Sparks, Yard, type Part } from './kit.ts';
import { Fx, Round } from './round.ts';
import { attractMood, NIGHT_MOOD, turnHue as turn, type FireworkKind, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Whack-a-Mole, the arcade game, played on the whole yard. Every bush and tree is a hole: a mole
// pops up in one (the bush fills with the hole's color from the ground up, a bright head on top),
// and the phone shows the same hole lit as a circle to whack. A whack blows the mole up in a
// burst of color: the bush swirls through the rainbow, a firework bursts over it, a shockwave runs
// through the house and sparks fly along the roof. A mole that gets away flashes red three times
// and is gone. A round lasts 45 seconds and speeds up as it goes; whacks in a row raise the
// multiplier, and now and then a golden mole is worth five times as much. As the round speeds up,
// moles come up two, three or four at once (more, and sooner, on harder levels). A whack at an empty hole
// (a slip: mashing, or a finger off target) costs seconds off the clock, and the hole and the
// roof's clock flash red, so it pays to aim.
//
//   bushes and trees: the holes, each in its own color (never red: red means one got away).
//   roof: the round's clock, a rainbow marquee that shrinks toward the middle as time runs out
//     (orange and ticking in the last ten seconds), with sparks from every whack.
//   windows, doors and other lines: the house reacting, catching the color of every whack.
// A yard with fewer than three bushes and trees plays on stretches of the roof instead, and the
// bushes and trees it has keep the time.

type Phase = 'ready' | 'countdown' | 'running' | 'over';
type Level = 'easy' | 'normal' | 'hard';

const LEVELS: Level[] = ['easy', 'normal', 'hard'];
const LEVEL_NAMES: Record<Level, string> = { easy: 'Easy', normal: 'Normal', hard: 'Hard' };

/** Seconds in a round, and of the 3-2-1 before it. */
export const ROUND = 45;
const COUNTDOWN = 3;
/** Seconds a mole takes to pop up. */
const RISE = 0.16;
/**
 * Seconds a mole takes to sink once its time is up. A whack while it sinks still counts: the
 * phone sees the mole a little late (Wi-Fi), and so does a kid's hand.
 */
const SINK = 0.28;
/** Seconds of a whacked mole's explosion, and of a missed one's three red flashes. */
const HIT_TIME = 1;
const MISS_TIME = 0.75;
/** A hole stays empty at least this long before the next mole. */
const REST = 0.35;
/** The last seconds of a round, when the clock turns orange and ticks. */
const HURRY = 10;
/** Before a new round can start after the last one, so a frantic last whack does not start one. */
const OVER_LOCK = 2;
/** At most this many holes (the biggest objects, if there are more). */
const MAX_HOLES = 20;
/** Seconds off the clock for a whack at an empty hole, on each level. */
export const SLIP_COST: Record<Level, number> = { easy: 1, normal: 2, hard: 3 };
/** Seconds of a slip's red flashes on the hole and the clock, and of its "−2 s" on the phone. */
const SLIP_TIME = 0.5;
const SLIP_NEWS = 1.2;

/**
 * How the round goes on each level, from its start to its end (it speeds up): how long a mole
 * stays up, the seconds between moles, the most up at once, the most that pop up together, and
 * the chance of a golden one.
 */
const PACE: Record<Level, { stay: [number, number]; gap: [number, number]; up: [number, number]; pack: [number, number]; gold: number }> = {
  easy: { stay: [2.4, 1.5], gap: [1.25, 0.75], up: [1, 2], pack: [1, 2], gold: 0.08 },
  normal: { stay: [1.7, 0.95], gap: [0.95, 0.45], up: [2, 3], pack: [1, 3], gold: 0.08 },
  hard: { stay: [1.15, 0.62], gap: [0.65, 0.3], up: [2, 4], pack: [2, 4], gold: 0.1 }
};
/** Each extra mole in a pack stays up this much longer (a share of its time), so there is time to whack them all. */
const PACK_STAY = 0.35;
/** Seconds a pack waits, at most, for enough holes to be free (the last whacks still bursting). */
const PACK_WAIT = 0.7;

const POINTS = 10;
const GOLD_POINTS = 50;
/** Whacks in a row for each step of the multiplier (×2, ×3, ×4). */
const MULT_AT = [5, 10, 20];

/** The holes' colors, far apart for neighbours: green, magenta, yellow, blue, orange, cyan, violet. No red. */
const HOLE_HUES = [0.33, 0.83, 0.14, 0.6, 0.08, 0.5, 0.73];
const RED: Rgb = [1, 0.03, 0.01];

type HoleState = 'empty' | 'up' | 'hit' | 'miss';

interface Hole {
  id: string;
  kind: MoleHole['kind'];
  color: Rgb;
  /** Front view: where effects for this hole go off. */
  x: number;
  y: number;
  top: number;
  /** Per light of the hole: 0 at its bottom (or the middle of a stretch of roof) to 1 at the top (or its ends). */
  u: Float32Array;
  /** Per light: -1 to 1 across it. */
  a: Float32Array;
  /** Lights one of its lights. */
  put: (k: number, color: Rgb, amount: number) => void;
  part: Part | null;
  /** The roof position above it, where its sparks fly. */
  roofPos: number;
  state: HoleState;
  gold: boolean;
  /** Seconds in this state. */
  t: number;
  /** Seconds since a whack here missed (a slip), for its red flashes. */
  slip: number;
  /** How long this mole stays up before it sinks. */
  stay: number;
  n: number;
  points: number;
}

/** A steady flicker per light, so a sparkle does not flash the same on every LED. */
const twinkle = (k: number, t: number) => {
  const v = Math.sin(k * 12.9898 + t * 9.3) * Math.sin(k * 4.1414 + t * 5.7);
  return v > 0.55 ? (v - 0.55) / 0.45 : 0;
};

export interface WhackPeek {
  holes: { id: string; state: HoleState; gold: boolean; t: number; stay: number }[];
  phase: Phase;
  timeLeft: number;
  bestStreak: number;
  onRoof: boolean;
  /** Whacks at empty holes this round, and the seconds they cost. */
  slips: number;
  lost: number;
}

export function whackGame(stage: Stage): Game & { peek(): WhackPeek } {
  const yard = new Yard(stage);
  const { roof } = yard;
  const n = roof.n;
  const sparks = new Sparks(roof, 40, 2);
  const flare = new Flare(3);
  const fx = new Fx(yard, { sparks, flare });
  const { show } = fx;

  // The holes: every bush and tree, or stretches of the roof on a yard with fewer than three.
  const objects = [...yard.bushes, ...yard.trees].sort((p, q) => q.count - p.count).slice(0, MAX_HOLES).sort((p, q) => p.x - q.x);
  const onRoof = objects.length < 3;
  const holes: Hole[] = [];
  const hole = (h: Omit<Hole, 'id' | 'color' | 'state' | 'gold' | 't' | 'slip' | 'stay' | 'n' | 'points'>) => {
    const i = holes.length;
    holes.push({ ...h, id: `h${i}`, color: hsv(HOLE_HUES[i % HOLE_HUES.length]), state: 'empty', gold: false, t: REST, slip: 9, stay: 1, n: 0, points: 0 });
  };
  if (!onRoof) {
    for (const p of objects) hole({ kind: p.fixture.kind === 'tree' ? 'tree' : 'bush', x: p.x, y: (p.top + p.bottom) / 2, top: p.top, u: p.up, a: p.across, put: (k, c, v) => yard.add(p.offset + k, c, v), part: p, roofPos: n ? roof.above(p.x) : 0 });
  } else if (n >= 30) {
    // Stretches of the roof, evenly along it, each where it can be seen from the street.
    const count = Math.max(3, Math.min(6, Math.floor(n / 60)));
    const half = Math.max(3, Math.floor((n / count) * 0.32));
    const zones: number[] = [];
    for (let j = 0; j < count; j++) {
      let c = Math.round(((j + 0.5) / count) * (n - 1));
      for (let d = 0; d < n / count / 2 && roof.hiddenAt(c); d++) c += j % 2 ? -1 : 1;
      zones.push(c);
    }
    zones.sort((p, q) => roof.point(p).x - roof.point(q).x);
    for (const c of zones) {
      const m = half * 2 + 1;
      const u = new Float32Array(m);
      const a = new Float32Array(m);
      for (let k = 0; k < m; k++) {
        a[k] = (k - half) / half;
        u[k] = Math.abs(a[k]);
      }
      const p = roof.point(c);
      hole({ kind: 'roof', x: p.x, y: p.y, top: p.y, u, a, put: (k, col, v) => yard.roofAt(c - half + k, col, v), part: null, roofPos: c });
    }
  }
  const playable = holes.length >= 2;
  /** Bushes and trees that are not holes keep the time. */
  const clocks = onRoof ? objects : [];
  for (const h of holes) if (h.part) show.dim(h.part, 0.4);
  for (const p of clocks) show.dim(p, 0.4);
  show.roofLevel = onRoof ? 0.4 : 0.6;
  // The roof's x range, for the clock that shrinks toward the middle of the house.
  let roofLeft = Infinity;
  let roofRight = -Infinity;
  for (let i = 0; i < n; i++) {
    roofLeft = Math.min(roofLeft, roof.x[i]);
    roofRight = Math.max(roofRight, roof.x[i]);
  }

  let level: Level = 'normal';
  // A board for each speed.
  const round = new Round<Phase>('whack', 'ready', { restartAfter: OVER_LOCK, resetAfter: 12, board: () => `whack-${level}`, title: (name) => `${name}: ${LEVEL_NAMES[level]}` });
  let score = 0;
  let streak = 0;
  let hits = 0;
  let missed = 0;
  let golds = 0;
  /** Whacks at empty holes this round, the seconds they cost, and the hole of the last one. */
  let slips = 0;
  let lost = 0;
  let slipHole = '';
  /** Seconds since the last slip. */
  let sinceSlip = 9;
  let bestStreak = 0;
  let newBest = false;
  let nextMole = 0;
  /** The pack due next (0 until its time comes), and how long it has waited for holes to be free. */
  let pack = 0;
  let packWait = 0;
  let lastHole = -1;
  /** Seconds since the last whack of any kind, for the roof's flash. */
  let sinceWhack = 9;
  let lastCount = -1;

  const elapsed = () => (round.phase === 'running' ? Math.min(ROUND, round.time) : 0);
  const timeLeftExact = () => (round.phase === 'running' ? Math.max(0, ROUND - round.time - lost) : round.phase === 'over' ? 0 : ROUND);
  const mult = () => 1 + MULT_AT.filter((m) => streak >= m).length;
  const upCount = () => holes.filter((h) => h.state === 'up').length;
  const isFree = (h: Hole) => h.state === 'empty' && h.t >= REST;
  const freeCount = () => holes.filter(isFree).length;

  function clearHoles() {
    for (const h of holes) {
      h.state = 'empty';
      h.t = REST;
      h.slip = 9;
      h.gold = false;
    }
  }

  function start() {
    score = streak = hits = missed = golds = bestStreak = slips = lost = 0;
    sinceSlip = 9;
    newBest = false;
    lastCount = -1;
    pack = 0;
    clearHoles();
    fx.clear();
    round.to('countdown');
  }

  /**
   * Moles pop up together in `count` empty holes (not the last one, when there is a choice), at
   * most one of them golden. Returns how many came up.
   */
  function popMoles(count: number, demo = false) {
    const free = holes.map((h, i) => ({ h, i })).filter(({ h }) => isFree(h));
    const choice = free.length > count ? free.filter(({ i }) => i !== lastHole) : free;
    const pack = Math.min(count, choice.length);
    const pace = PACE[level];
    const p = elapsed() / ROUND;
    let gold = !demo && Math.random() < pace.gold && p > 0.1;
    for (let j = 0; j < pack; j++) {
      const { h, i } = choice.splice(Math.floor(Math.random() * choice.length), 1)[0];
      h.state = 'up';
      h.t = 0;
      h.gold = gold;
      gold = false;
      h.stay = demo ? 1.6 : lerp(pace.stay[0], pace.stay[1], p) * (h.gold ? 0.75 : 1) * (1 + PACK_STAY * (pack - 1)) * (0.85 + Math.random() * 0.3);
      h.n++;
      lastHole = i;
    }
    return pack;
  }

  /** How many moles pop up together now: one at first, packs as the round speeds up, the biggest more often than not. */
  function packSize() {
    const pace = PACE[level];
    const most = Math.max(1, Math.round(lerp(pace.pack[0], pace.pack[1], elapsed() / ROUND)));
    return Math.min(most, 1 + Math.floor(Math.random() * (most + 1)));
  }

  /** The colors of a whack's explosion: the hole's own, its opposite, gold and two more. */
  function blastColors(h: Hole): Rgb[] {
    const base = Math.random();
    return h.gold ? [COLORS.gold, hsv(base), hsv(base + 0.33), hsv(base + 0.66), mix(COLORS.gold, WHITE, 0.4)] : [h.color, turn(h.color, 0.5), COLORS.gold, hsv(base), hsv(base + 0.4)];
  }

  function whack(h: Hole) {
    const gold = h.gold;
    const before = mult();
    streak++;
    bestStreak = Math.max(bestStreak, streak);
    hits++;
    if (gold) golds++;
    const m = mult();
    h.points = (gold ? GOLD_POINTS : POINTS) * m;
    score += h.points;
    h.state = 'hit';
    h.t = 0;
    h.n++;
    sinceWhack = 0;
    // The explosion: a flash and a shockwave through the house, a firework bursting right over
    // the hole, sparks flying along the roof above it, and the house's windows catching the color.
    const colors = blastColors(h);
    const kinds: FireworkKind[] = ['peony', 'ring', 'crackle', 'willow'];
    show.explode(h.x, h.y, h.color, { size: gold ? 1.6 : 1 });
    show.burst(h.x, h.top - show.m * 0.6, colors, { kind: gold ? 'ring' : kinds[Math.floor(Math.random() * kinds.length)], size: gold ? 1.6 : 1.05 });
    show.ripple(h.x, h.y, gold ? COLORS.gold : turn(h.color, 0.5), { amount: 0.45 });
    if (n) sparks.burst(h.roofPos, colors, gold ? 50 : 28, n * 0.35);
    flare.add(h.color, 0.9);
    if (gold) {
      // A golden mole: gold sweeps up the whole yard and fireworks go up all over.
      show.sweep(COLORS.gold, { dir: 'up', amount: 0.7, duration: 0.7 });
      show.finale(3, { colors: [[COLORS.gold, hsv(Math.random())], [COLORS.gold, WHITE]] });
      flare.add(COLORS.gold, 1.2);
    }
    // A new multiplier: a rainbow sweep across the house, and a volley.
    if (m > before) {
      show.sweep(hsv(Math.random()), { dir: Math.random() < 0.5 ? 'left' : 'right', amount: 0.6 });
      show.rocket([hsv(Math.random()), COLORS.gold], { size: 1.1, kind: 'ring' });
      show.rocket([hsv(Math.random()), hsv(Math.random())], { size: 1 });
    } else show.rocket([h.color, COLORS.gold], { size: 0.7, max: 2 });
  }

  /**
   * A whack at a hole with no mole in it (a slip): the streak starts over, the clock loses a
   * few seconds, and the hole, the roof's clock and the yard flash red. Another tap on a mole
   * just whacked (a double tap) costs nothing.
   */
  function bonk(h: Hole) {
    if (h.state === 'hit') return;
    streak = 0;
    sinceWhack = 0;
    slips++;
    lost += SLIP_COST[level];
    slipHole = h.id;
    sinceSlip = 0;
    h.slip = 0;
    // No mole pops up right where the slip was: it would look like the whack missed it.
    if (h.state === 'empty') h.t = 0;
    show.flash(h.x, h.y, RED, { size: 1.1, duration: 0.4 });
    show.pulse(RED, 0.18);
    if (n) sparks.burst(h.roofPos, [RED, COLORS.ember], 12, n * 0.12);
  }

  function getAway(h: Hole) {
    h.state = 'miss';
    h.t = 0;
    h.gold = false;
    missed++;
    streak = 0;
    show.flash(h.x, h.y, RED, { size: 0.9, duration: 0.3 });
  }

  function endRound() {
    clearHoles();
    newBest = round.record(score);
    round.to('over');
    // Time's up: a finale over the whole house, bigger for more whacks, gold for a new best.
    show.sweep(COLORS.gold, { dir: 'out', amount: 0.8, duration: 0.9 });
    show.finale(Math.min(10, 4 + Math.floor(hits / 6)));
    if (newBest) {
      show.finale(7, { colors: [[COLORS.gold, WHITE], [COLORS.gold]] });
      show.pulse(COLORS.gold, 0.3);
    }
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    const h = e.button ? holes.find((x) => x.id === e.button) : undefined;
    if (round.canStart) return start();
    if (round.phase !== 'running' || !h) return;
    if (h.state === 'up') whack(h);
    else bonk(h);
  }

  /**
   * The yard's mood: every hue going slowly round while it waits; deep blue and violet for a
   * new round, heating through magenta and orange to a racing rainbow as the multiplier climbs;
   * orange-red and throbbing in the last ten seconds; a slow gold and rainbow after the round.
   */
  function moodNow(): Mood {
    if (round.phase === 'ready') return attractMood(round.clock);
    if (round.phase === 'over') return { a: hsv(round.clock * 0.08), b: COLORS.gold, level: 1, drift: 1.2 };
    if (round.phase === 'countdown') return { ...NIGHT_MOOD, level: 0.8 };
    if (timeLeftExact() <= HURRY) return { a: COLORS.ember, b: [0.7, 0.02, 0.2], level: 0.9, throb: 2 };
    const m = mult();
    if (m >= 4) return { a: hsv(round.clock * 0.4), b: hsv(round.clock * 0.4 + 0.5), level: 1.2, drift: 2.5 };
    if (m === 3) return { a: [1, 0.4, 0.02], b: [0.9, 0.05, 0.6], level: 1.1, drift: 1.8 };
    if (m === 2) return { a: [0.8, 0.05, 0.8], b: [0.05, 0.6, 0.9], level: 1, drift: 1.4 };
    return { a: [0.08, 0.15, 0.7], b: [0.4, 0.06, 0.7], level: 0.9, drift: 1 };
  }

  function step(dt: number) {
    sinceWhack += dt;
    sinceSlip += dt;
    for (const h of holes) {
      h.t += dt;
      h.slip += dt;
      if (h.state === 'up' && h.t >= h.stay + SINK) {
        if (round.phase === 'running') getAway(h);
        else {
          h.state = 'empty';
          h.t = 0;
        }
      } else if (h.state === 'hit' && h.t >= HIT_TIME) {
        h.state = 'empty';
        h.t = 0;
      } else if (h.state === 'miss' && h.t >= MISS_TIME) {
        h.state = 'empty';
        h.t = 0;
      }
    }
    if (round.phase === 'countdown') {
      const count = Math.floor(round.time);
      if (count !== lastCount && count < COUNTDOWN) {
        // 3, 2, 1: the house kicks in a new color each second.
        lastCount = count;
        const c = hsv(count * 0.33 + 0.55);
        show.sweep(c, { dir: 'up', amount: 0.55, duration: 0.6 });
        show.pulse(c, 0.15);
      }
      if (round.time >= COUNTDOWN) {
        round.to('running');
        nextMole = 0.2;
        show.finale(4);
        show.pulse(COLORS.gold, 0.2);
      }
    } else if (round.phase === 'running') {
      const pace = PACE[level];
      const p = elapsed() / ROUND;
      const most = Math.max(1, Math.min(holes.length - 1, Math.round(Math.max(lerp(pace.up[0], pace.up[1], p), lerp(pace.pack[0], pace.pack[1], p)))));
      nextMole -= dt;
      // Never a dull moment: with no mole up, the next ones come sooner.
      const up = upCount();
      if (up === 0) nextMole = Math.min(nextMole, 0.25);
      if (nextMole <= 0 && up < most) {
        if (!pack) {
          pack = packSize();
          packWait = 0;
        }
        // Holes still bursting from the last whacks: a pack waits a moment for them, then comes as big as it can.
        const want = Math.min(pack, most - up);
        packWait += dt;
        if (freeCount() >= want || packWait >= PACK_WAIT) {
          const popped = popMoles(want);
          // A pack takes longer to whack: the next comes a little later.
          if (popped) {
            nextMole = lerp(pace.gap[0], pace.gap[1], p) * (1 + 0.25 * (popped - 1)) * (0.7 + Math.random() * 0.6);
            pack = 0;
          }
        }
      }
      if (timeLeftExact() <= 0) endRound();
    } else if (round.phase === 'ready') {
      // A demo: moles pop up slowly in the yard to draw a crowd.
      nextMole -= dt;
      if (nextMole <= 0 && upCount() < 1 && popMoles(1, true)) nextMole = 1.2 + Math.random();
      if (Math.random() < dt * 0.3) show.rocket([hsv(Math.random()), hsv(Math.random())], { size: 0.8 });
    } else if (round.phase === 'over') {
      if (round.time < 6 && Math.random() < dt * (newBest ? 3 : 1.5)) show.rocket([hsv(Math.random()), hsv(Math.random()), COLORS.gold], { size: 1 });
      if (round.timedOut) round.to('ready');
    }
    fx.update(dt);
    show.followMood(moodNow(), 2.5, dt);
    // In a round the roof is the clock: the show's backdrop steps back from it (fireworks still reach it).
    if (!onRoof) show.roofShare = round.phase === 'running' || round.phase === 'countdown' ? 0.35 : 1;
  }

  /** One hole: a mole popping up, standing, sinking; an explosion of color; three red flashes. */
  function drawHole(h: Hole) {
    const m = h.u.length;
    // A slip here: two quick red flashes over whatever the hole shows.
    if (h.slip < SLIP_TIME && Math.floor((h.slip / SLIP_TIME) * 4) % 2 === 0) {
      for (let k = 0; k < m; k++) h.put(k, RED, 0.9);
      return;
    }
    if (h.state === 'empty') {
      // The hole's rim: its lowest lights glow faintly in its color, so kids can see where moles come from.
      for (let k = 0; k < m; k++) if (h.u[k] < 0.22) h.put(k, h.color, 0.05 + 0.03 * Math.sin(round.clock * 2 + h.x * 0.01));
      return;
    }
    if (h.state === 'up') {
      // How far up the mole is: it pops up (overshooting a little), stands, and sinks at the end.
      const rise = h.t < RISE ? ease(h.t / RISE) * 1.08 : h.t < RISE + 0.1 ? 1.08 - 0.08 * ((h.t - RISE) / 0.1) : 1;
      const r = h.t > h.stay ? Math.max(0, 1 - (h.t - h.stay) / SINK) : rise;
      // Near the end of its time it twitches faster: hurry!
      const late = Math.max(0, (h.t - h.stay * 0.7) / (h.stay * 0.3));
      const beat = 0.85 + 0.15 * Math.sin(round.clock * (8 + late * 14));
      for (let k = 0; k < m; k++) {
        const u = h.u[k];
        if (u > r) continue;
        const head = r - u < 0.2;
        if (h.gold) {
          // A golden mole: rainbow bands running up through it, under a sparkling gold head.
          const body = hsv(u * 1.4 - round.clock * 1.6 + h.a[k] * 0.2);
          const c = head ? mix(COLORS.gold, WHITE, 0.35 + 0.4 * twinkle(k, round.clock * 2)) : mix(body, COLORS.gold, 0.25);
          h.put(k, c, (head ? 1 : 0.7) * beat);
        } else {
          // The hole's color, brighter toward the head, and the head white-hot and twinkling.
          const c = head ? mix(h.color, WHITE, 0.45 + 0.35 * twinkle(k, round.clock)) : h.color;
          h.put(k, c, (head ? 1 : 0.45 + 0.35 * u) * beat);
        }
      }
      return;
    }
    if (h.state === 'hit') {
      // The explosion: a flash in the hole's color, then the rainbow swirling out of it, with
      // sparkles, fading away.
      const t = h.t / HIT_TIME;
      const fade = (1 - t) ** 1.3;
      for (let k = 0; k < m; k++) {
        const u = h.u[k];
        if (t < 0.08) {
          h.put(k, mix(h.color, WHITE, 0.3), 1.1);
          continue;
        }
        const hue = u * 1.6 - h.t * 2.5 + h.a[k] * 0.35 + (h.gold ? round.clock : 0);
        const ring = Math.exp(-(((u - t * 1.6) / 0.25) ** 2));
        const sparkle = twinkle(k, round.clock * 1.7);
        h.put(k, sparkle > 0.3 ? mix(hsv(hue), WHITE, 0.3) : hsv(hue), fade * (0.55 + 0.5 * ring + 0.6 * sparkle));
      }
      return;
    }
    // Got away: three red flashes, and it is gone.
    const on = Math.floor((h.t / MISS_TIME) * 6) % 2 === 0;
    if (on) for (let k = 0; k < m; k++) h.put(k, RED, 0.8 * (1 - h.t / MISS_TIME / 2));
  }

  /**
   * The roof: an arcade marquee. Waiting, rainbow bulbs chase along it; in a round it is the
   * clock, a band of chasing rainbow lights that shrinks toward the middle of the house as time
   * runs out, orange and ticking in the last ten seconds; the 3-2-1 fills it from the middle out.
   */
  function drawRoof() {
    if (!n || onRoof) {
      if (onRoof && round.phase === 'ready') for (let i = 0; i < n; i++) yard.roofAt(i, hsv(i / n + round.clock * 0.1), 0.05);
      sparks.draw(yard);
      return;
    }
    const mid = (roofLeft + roofRight) / 2;
    const half = Math.max(1, (roofRight - roofLeft) / 2);
    const left = timeLeftExact();
    const share = round.phase === 'countdown' ? ease(Math.min(1, round.time / COUNTDOWN)) : round.phase === 'running' ? left / ROUND : 1;
    const hurry = round.phase === 'running' && left <= HURRY;
    // In the last seconds, a tick on every second.
    const tick = hurry ? Math.exp(-(1 - (left % 1)) * 6) : 0;
    const speed = round.phase === 'running' ? 1.5 + mult() * 0.6 : 1;
    for (let i = 0; i < n; i++) {
      const d = Math.abs(roof.x[i] - mid) / half;
      if (d > share + 0.002) continue;
      const bulb = Math.max(0, Math.cos((i / 5 - round.clock * speed * 2) * Math.PI * 2)) ** 6;
      let c = hsv(i / n * 1.5 - round.clock * 0.25);
      if (hurry) c = mix(COLORS.ember, COLORS.gold, 0.5 + 0.5 * Math.sin(round.clock * 6));
      // A slip: the clock flashes red as it loses its seconds.
      if (round.phase === 'running' && sinceSlip < SLIP_TIME && Math.floor((sinceSlip / SLIP_TIME) * 4) % 2 === 0) c = RED;
      if (round.phase === 'over') c = mix(hsv(i / n * 2 + round.clock * 0.5), COLORS.gold, 0.3);
      // The band's ends burn brighter, so the shrinking reads from the street.
      const end = Math.exp(-((((share - d) * half) / (stage.scale * 0.25)) ** 2));
      yard.roofAt(i, c, (round.phase === 'ready' ? 0.08 + 0.4 * bulb : 0.3 + 0.4 * bulb + 0.35 * tick) + 0.6 * end * (round.phase === 'running' || round.phase === 'countdown' ? 1 : 0));
    }
    // Gold glitter along the band for a multiplier.
    if (round.phase === 'running' && mult() > 1) {
      for (let i = 0; i < n; i += 3) {
        const d = Math.abs(roof.x[i] - mid) / half;
        if (d <= share) {
          const s = twinkle(i, round.clock * 1.3);
          if (s > 0.4) yard.roofAt(i, COLORS.gold, 0.35 * s * (mult() - 1) * 0.5);
        }
      }
    }
    sparks.draw(yard);
  }

  /** Bushes and trees that are not holes (a yard playing on its roof): the time left, from the base up. */
  function drawClocks() {
    const share = round.phase === 'running' ? timeLeftExact() / ROUND : round.phase === 'countdown' ? Math.min(1, round.time / COUNTDOWN) : 1;
    const hurry = round.phase === 'running' && timeLeftExact() <= HURRY;
    for (const p of clocks) {
      for (let k = 0; k < p.count; k++) {
        const u = p.up[k];
        if (u > share) continue;
        yard.add(p.offset + k, hurry ? COLORS.ember : hsv(u * 0.8 + round.clock * 0.2), 0.4);
      }
    }
  }

  function drawDecor() {
    const glow = flare.color;
    const warm = round.phase === 'running' ? (mult() - 1) * 0.04 : 0;
    for (const d of yard.decor) {
      if (glow[0] + glow[1] + glow[2] > 0.02) yard.fill(d, glow, 0.6);
      if (warm) yard.fill(d, COLORS.gold, warm);
    }
  }

  return {
    id: 'whack',

    scoreBoard: () => round.scoreBoard(),

    input,

    setting(id: string, value: string) {
      if (round.phase === 'running' || round.phase === 'countdown') return;
      if (id === 'level' && (LEVELS as string[]).includes(value)) level = value as Level;
    },

    update(dt: number, frame: Frame) {
      round.tick(dt);
      yard.begin(frame);
      if (!playable) return;
      step(dt);
      drawRoof();
      for (const h of holes) drawHole(h);
      drawClocks();
      drawDecor();
      fx.draw(frame);
    },

    status(): GameStatusFields {
      if (!playable) return round.setup('Add bushes or trees (or a roofline) in Layout first.');
      const best = round.best();
      const left = Math.ceil(timeLeftExact() - 1e-6);
      const moles: MoleBoard = {
        holes: holes.map((h) => ({ id: h.id, color: hex(h.color), kind: h.kind, state: h.state === 'up' ? (h.gold ? 'gold' : 'up') : h.state, n: h.n, points: h.points })),
        timeLeft: left,
        duration: ROUND,
        countdown: round.phase === 'countdown' ? String(COUNTDOWN - Math.floor(round.time)) : round.phase === 'running' && round.time < 0.7 ? 'GO!' : null,
        mult: round.phase === 'running' ? mult() : 1,
        streak: round.phase === 'running' ? streak : 0,
        best,
        hits,
        missed,
        slips,
        slip: slips && round.phase === 'running' && sinceSlip < SLIP_NEWS ? { n: slips, hole: slipHole, cost: SLIP_COST[level] } : null
      };
      const settings: GameSetting[] = [{ id: 'level', label: 'Speed', value: level, choices: LEVELS.map((l) => ({ value: l, label: LEVEL_NAMES[l] })) }];
      const common = { score, lives: null, goal: null, moles, keysHint: `${holes.length > 9 ? 'Keys 1–9 and 0' : `Keys 1–${holes.length}`} whack the holes, space to start` };
      switch (round.phase) {
        case 'ready':
          return { ...common, phase: round.phase, message: 'Whack every mole that pops up! Tap GO to start.', button: 'GO!', tone: 'go', settings };
        case 'countdown':
          return { ...common, phase: round.phase, message: 'Get ready…', button: '…', tone: 'wait' };
        case 'running': {
          const m = mult();
          const message =
            sinceSlip < SLIP_NEWS
              ? `Missed! −${SLIP_COST[level]} s. Aim for the moles!`
              : timeLeftExact() <= HURRY ? 'Hurry! The clock is running out!' : m >= 4 ? `MOLE MANIA! ×4 points!` : m > 1 ? `${streak} in a row! ×${m} points!` : hits ? 'Whack! Keep going!' : 'Whack the moles that pop up!';
          return { ...common, phase: round.phase, message, button: 'WHACK', tone: 'go' };
        }
        case 'over':
          return {
            ...common,
            phase: round.phase,
            message: newBest
              ? `New best: ${score}!`
              : `Time's up! ${score} points, ${hits} mole${hits === 1 ? '' : 's'} whacked${golds ? `, ${golds} golden` : ''}${slips ? `, ${slips} slip${slips === 1 ? '' : 's'} (−${lost} s)` : ''}.`,
            button: round.canStart ? 'GO!' : '…',
            tone: round.canStart ? 'go' : 'wait',
            settings
          };
      }
    },

    peek: () => ({ holes: holes.map((h) => ({ id: h.id, state: h.state, gold: h.gold, t: h.t, stay: h.stay })), phase: round.phase, timeLeft: timeLeftExact(), bestStreak, onRoof, slips, lost })
  };
}
