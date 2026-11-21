import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, scale, WHITE, type Rgb } from '../../../shared/color.ts';
import { type Frame } from './frame.ts';
import { COLORS, heat, Recent, TONES, Yard, type Part } from './kit.ts';
import { endGlow, Fx, MIN_ROOF, Round } from './round.ts';
import { overMood, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Color Gate: your light sits near the start of the roof. Walls of colored light stream toward
// it from the far end. Each tap changes your color, always in the same order: green, blue, pink,
// green… A wall that reaches you in your own color passes through you (points, gold sparks);
// one in another color shatters red and costs a life. The next wall to reach you has thin white
// brackets around it: that is the one to match. There is no finish line: the walls come faster
// and closer together, then in quick runs that need two taps between them, up to a pace a sharp
// player can keep up forever. Walls in a row multiply the points (up to ×4).
//
// Colors mean one thing each: green, blue and pink are the walls and you; white is only ever the
// brackets on the next wall; gold is points, red a mistake.
//
// The yard: the bushes all glow your color, big and steady, so you can read it from the street
// (they pulse when you switch, flash gold on a pass). The trees fill from the base up toward the
// next multiplier. Everything else is the light show (see show.ts): the whole yard glows in a
// mood that drifts between your color and the streak's heat (cool indigo at first, fire as the
// streak grows, red and throbbing on your last life), kicks in your color on every switch and in
// the wall's color on every pass. Passes send up fireworks, a new multiplier a volley and a gold
// sweep; a wrong color blows up at your light and sends red across the yard.

type Phase = 'ready' | 'run' | 'miss' | 'over';

interface Wall {
  pos: number;
  tone: number;
  /** When it reached your light (null: still on its way). */
  arrived: number | null;
}

interface Shard {
  pos: number;
  vel: number;
  color: Rgb;
  life: number;
  max: number;
}

const LIVES = 3;
/** A tap can arrive this late (Wi-Fi): a wall is judged this long after it reaches you. */
export const LAG = 0.1;
/** Walls in a row for each step of the multiplier. */
const PER_MULT = 8;
const MAX_MULT = 4;
/** Your colors and the walls': far apart on real LEDs, and none of white, gold or red. */
export const GATE_COLORS: Rgb[] = [TONES.green, TONES.blue, TONES.magenta];
const NAMES = ['GREEN', 'BLUE', 'PINK'];
/** Half the width of a wall, in roof steps. */
const WALL_HALF = 1.5;
/** At top speed, the least time between two walls for 0, 1 or 2 taps (about 6 taps a second, and a moment to see it). */
const MIN_GAP = [0.32, 0.45, 0.66];

/** Taps from one color to another, going round in order. */
export const tapsBetween = (from: number, to: number) => (to - from + GATE_COLORS.length) % GATE_COLORS.length;

export function colorgateGame(stage: Stage): Game {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= MIN_ROOF;
  const fx = new Fx(yard);
  const { motes, waves, show } = fx;
  for (const t of yard.trees) show.dim(t, 0.45);
  // The roof is the playfield, and white there means the next wall: the show stays faint on it.
  show.roofShare = 0.3;
  show.roofLevel = 0.6;

  // Your light: near the start of the roof, where it can be seen from the street.
  let home = Math.max(3, Math.round(n * 0.06));
  while (home < n / 3 && roof.hiddenAt(home)) home++;
  const start = n - 1;
  const travel = Math.max(1, start - home);

  const round = new Round<Phase>('colorgate', 'ready');
  let lives = LIVES;
  let score = 0;
  let streak = 0;
  let longest = 0;
  let judged = 0;
  let newBest = false;
  /** Your color (index into GATE_COLORS). */
  let you = 0;
  let walls: Wall[] = [];
  let shards: Shard[] = [];
  /** Walls waiting to come on: their color and how far behind the last one (in roof steps). */
  let queue: { tone: number; gap: number }[] = [];
  /** The tone of the last wall that came on (for the taps a run needs). */
  let lastTone = 0;
  let speed = 0;
  /** Your colors lately, by time: a wall is judged by what you showed while it was at your light. */
  const seen = new Recent<number>(1);
  let switchPulse = 0;
  let passFlash = 0;
  let missFlash = 0;
  let meter = 0;

  // How it gets harder: a level every 10 walls; faster, closer, then quick runs. Capped at level 15.
  const level = () => Math.min(15, 1 + Math.floor(judged / 10));
  const crossTime = (lv: number) => Math.max(1.7, 4.2 - (lv - 1) * 0.18);
  const speedFor = (lv: number) => travel / crossTime(lv);
  const speedMax = speedFor(15);
  const gapTime = (lv: number) => Math.max(0.6, 1.8 - (lv - 1) * 0.09);
  const runChance = (lv: number) => (lv >= 4 ? Math.min(0.35, 0.08 * (lv - 3)) : 0);
  const mult = () => Math.min(MAX_MULT, 1 + Math.floor(streak / PER_MULT));

  /** The least distance between two walls for this many taps, at top speed: it is enough at any speed. */
  const minDist = (taps: number) => speedMax * MIN_GAP[taps];

  /** Picks the next walls: one at a time, or (later) a quick run of three or four. */
  function plan() {
    const lv = level();
    if (Math.random() < runChance(lv)) {
      const count = 3 + (Math.random() < 0.5 ? 1 : 0);
      let tone = lastTone;
      for (let k = 0; k < count; k++) {
        // Every wall of a run is another color: one or two taps.
        const next = (tone + 1 + Math.floor(Math.random() * 2)) % GATE_COLORS.length;
        const gap = k === 0 ? Math.max(minDist(tapsBetween(tone, next)), speed * gapTime(lv)) : minDist(tapsBetween(tone, next));
        queue.push({ tone: next, gap });
        tone = next;
      }
      return;
    }
    const tone = Math.floor(Math.random() * GATE_COLORS.length) % GATE_COLORS.length;
    queue.push({ tone, gap: Math.max(minDist(tapsBetween(lastTone, tone)), speed * gapTime(lv)) });
  }

  function spawn() {
    if (!queue.length) plan();
    const last = walls.at(-1);
    const next = queue[0];
    if (last && start - last.pos < next.gap) return;
    queue.shift();
    walls.push({ pos: start, tone: next.tone, arrived: null });
    lastTone = next.tone;
  }

  function reset() {
    lives = LIVES;
    score = 0;
    streak = 0;
    longest = 0;
    judged = 0;
    newBest = false;
    you = 0;
    walls = [];
    queue = [];
    shards = [];
    lastTone = 0;
    speed = speedFor(1);
    meter = 0;
    seen.clear();
    seen.push(round.clock, you);
    fx.clear();
  }

  function newGame() {
    reset();
    round.to('run');
    show.setMood(moodNow(), { wipe: roof.startsLeft ? 'right' : 'left' });
    spawn();
  }

  function burst(pos: number, colors: Rgb[], count: number, power: number, life = 0.8) {
    for (let i = 0; i < count; i++) {
      const max = life * (0.5 + Math.random() * 0.8);
      shards.push({ pos, vel: (Math.random() - 0.5) * 2 * power * (0.3 + Math.random()), color: colors[i % colors.length], life: max, max });
    }
  }

  /** The next wall to reach you: the one in white brackets. */
  const nextWall = () => walls.find((w) => w.arrived === null || round.clock - w.arrived < LAG);

  /** Was this color showing at any moment while the wall was at your light (late taps count)? */
  function matched(w: Wall) {
    const at = w.arrived ?? round.clock;
    const shown = [seen.at(at), ...seen.since(at)];
    return shown.some((c) => c === w.tone);
  }

  function pass(w: Wall, demo: boolean) {
    const color = GATE_COLORS[w.tone];
    burst(home, [COLORS.gold, color, mix(color, COLORS.gold, 0.5)], 20, n * 0.25);
    passFlash = 1;
    show.pulse(color, 0.12 + 0.03 * mult());
    if (demo) {
      show.rocket([color, COLORS.gold], { size: 0.6 });
      return;
    }
    const before = mult();
    streak++;
    longest = Math.max(longest, streak);
    judged++;
    score += mult();
    if (mult() > before) {
      const p = roof.point(home);
      waves.add(p.x, p.y, COLORS.gold, { amount: 1 });
      for (const b of yard.bushes) waves.add(b.x, b.top, color, { amount: 0.6 });
      // A new multiplier: a volley, one firework more at every step, and gold up the yard.
      show.sweep(COLORS.gold, { dir: 'up', amount: 0.7 });
      show.finale(1 + mult(), { colors: [[COLORS.gold, color], [color, WHITE]] });
    } else if (streak % PER_MULT === 0) {
      // Every eighth wall in a row at ×4: the wall's color sweeps across the house.
      show.sweep(color, { dir: streak % (PER_MULT * 2) ? 'right' : 'left', amount: 0.6 });
      show.finale(3, { colors: [[COLORS.gold, color]] });
    } else show.rocket([color, COLORS.gold], { size: 0.6 + 0.15 * mult() });
  }

  function miss(w: Wall) {
    lives--;
    streak = 0;
    judged++;
    missFlash = 1;
    burst(home, [COLORS.bad, COLORS.ember, GATE_COLORS[w.tone]], 30, n * 0.3, 1);
    // Every wall still coming shatters and falls off the gutter: a moment to breathe.
    for (const o of walls) {
      if (o === w) continue;
      burst(o.pos, [mix(GATE_COLORS[o.tone], COLORS.bad, 0.5)], 6, n * 0.08, 0.6);
      const p = roof.point(o.pos);
      motes.drop(p.x, p.y, mix(GATE_COLORS[o.tone], COLORS.bad, 0.6), { vx: (Math.random() - 0.5) * 60, size: 18 });
    }
    walls = [];
    queue = [];
    const p = roof.point(home);
    if (lives <= 0) {
      newBest = round.record(score);
      // The house blows, and the yard goes dark red (gold fireworks for a new best).
      show.gameOver(p.x, p.y, { newBest });
      round.to('over');
    } else {
      // A wrong color blows up at your light, and red runs away across the yard.
      show.explode(p.x, p.y, COLORS.bad, { size: 1.3 });
      show.sweep(COLORS.bad, { dir: roof.startsLeft ? 'right' : 'left', amount: 0.6, duration: 0.7 });
      round.to('miss');
    }
  }

  function switchColor() {
    you = (you + 1) % GATE_COLORS.length;
    seen.push(round.clock, you);
    switchPulse = 1;
    // The whole yard flicks to your new color.
    show.pulse(GATE_COLORS[you], 0.07);
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (round.canStart) return newGame();
    if (round.phase === 'run' || round.phase === 'miss') switchColor();
  }

  function stepWalls(dt: number, demo: boolean) {
    speed += (speedFor(level()) - speed) * Math.min(1, dt * 1.5);
    spawn();
    for (const w of walls) {
      if (w.arrived !== null) continue;
      w.pos -= speed * dt;
      if (w.pos <= home) {
        // When it got there, between frames.
        w.arrived = round.clock - (home - w.pos) / Math.max(1e-6, speed);
        w.pos = home;
      }
    }
    // In the attract loop, the house plays: it takes the color of a wall that is nearly there.
    if (demo) {
      const w = nextWall();
      if (w && w.pos - home < travel * 0.25 && you !== w.tone) {
        you = w.tone;
        seen.push(round.clock, you);
        switchPulse = 1;
      }
    }
    for (const w of [...walls]) {
      if (w.arrived === null || round.clock - w.arrived < LAG) continue;
      if (demo || matched(w)) {
        walls = walls.filter((x) => x !== w);
        pass(w, demo);
      } else return miss(w);
    }
  }

  function stepShards(dt: number) {
    const k = Math.exp(-dt * 2);
    for (const s of shards) {
      s.life -= dt;
      s.vel *= k;
      s.pos += s.vel * dt;
    }
    shards = shards.filter((s) => s.life > 0 && s.pos >= 0 && s.pos <= n - 1);
  }

  // ---------- Drawing ----------

  /**
   * The yard's mood from the game: in the attract loop, a slow rainbow; while playing, the
   * streak's heat (indigo to fire) drifting with your color, brighter and faster with the
   * multiplier; red and throbbing on the last life; dark red after.
   */
  function moodNow(): Mood {
    if (round.phase === 'ready') return { a: hsv(round.clock * 0.04), b: hsv(round.clock * 0.04 + 0.33), level: 1.1, drift: 1.4 };
    if (round.phase === 'over') return overMood(round.time);
    const m = mult();
    if (lives === 1) return { a: COLORS.bad, b: mix(GATE_COLORS[you], COLORS.bad, 0.6), level: 1.1, throb: 1.6 };
    const warm = Math.min(1, streak / (PER_MULT * MAX_MULT));
    const a = mix([0.25, 0.1, 0.8], COLORS.fire, warm);
    return { a, b: mix(a, GATE_COLORS[you], 0.6), level: 1.2 + 0.25 * (m - 1), drift: 1 + 0.3 * (m - 1) };
  }

  function drawRoof() {
    const next = round.phase === 'over' ? undefined : nextWall();
    for (const w of walls) {
      const c = GATE_COLORS[w.tone];
      // Walls come on softly at the far end.
      const fadeIn = Math.min(1, 0.3 + (start - w.pos) / 5);
      for (let i = Math.ceil(w.pos - WALL_HALF); i <= Math.floor(w.pos + WALL_HALF); i++) yard.roofAt(i, c, 0.85 * fadeIn);
      yard.roofSplat(w.pos, c, 2.5, 0.15 * fadeIn);
      if (w === next) {
        // The brackets: the only white on the roof.
        // One LED on each side, a step clear of the wall, so it stays crisp at a distance.
        const blink = 0.85 + 0.15 * Math.sin(round.clock * 14);
        yard.roofAt(Math.round(w.pos - WALL_HALF - 1.5), WHITE, 0.95 * blink * fadeIn);
        yard.roofAt(Math.round(w.pos + WALL_HALF + 1.5), WHITE, 0.95 * blink * fadeIn);
      }
    }
    // Your light: a big soft dot in your color, brighter for a moment when you switch.
    if (round.phase !== 'over') {
      const c = GATE_COLORS[you];
      const ready = round.phase === 'ready' ? 0.75 + 0.25 * Math.sin(round.clock * 3) : 1;
      yard.roofSplat(home, c, 2.2, (0.9 + switchPulse * 0.5) * ready);
      yard.roofSplat(home, c, 5, 0.18 + switchPulse * 0.2);
    }
    if ((round.phase === 'miss' || round.phase === 'over') && round.time < 1) yard.roofSplat(home, COLORS.bad, 2 + round.time * 12, 1 - round.time);
    for (const s of shards) {
      const age = 1 - s.life / s.max;
      const flicker = age > 0.6 ? 0.6 + 0.4 * Math.random() : 1;
      yard.roofSplat(s.pos, s.color, 0.9, (s.life / s.max) ** 0.8 * flicker);
    }
  }

  function drawBushes() {
    // Every bush is your color: you can read it from across the street.
    const base = round.phase === 'over' ? scale(COLORS.bad, 0.25) : GATE_COLORS[you];
    const c = mix(mix(base, COLORS.gold, passFlash * 0.6), COLORS.bad, missFlash * 0.8);
    for (const b of yard.bushes) {
      for (let i = 0; i < b.count; i++) {
        const shimmer = 0.06 * Math.sin(round.clock * 3 + i * 1.3);
        yard.add(b.offset + i, c, (round.phase === 'over' ? 0.4 : 0.65) + shimmer + switchPulse * 0.45 + passFlash * 0.25);
      }
    }
  }

  function drawTree(part: Part) {
    // Toward the next multiplier: full and twinkling gold at ×4.
    const top = meter >= 0.999;
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (u <= meter) {
        const c = top ? mix(COLORS.gold, WHITE, Math.max(0, Math.sin(round.clock * 8 + i * 1.7)) * 0.4) : heat(u * 0.85);
        yard.add(part.offset + i, c, top ? 0.85 : 0.6);
      }
    }
  }

  reset();

  return {
    id: 'colorgate',

    scoreBoard: () => round.scoreBoard(),

    input,

    update(dt: number, frame: Frame) {
      round.tick(dt);
      yard.begin(frame);
      if (!playable) return;

      if (round.phase === 'ready') stepWalls(dt, true);
      else if (round.phase === 'run') stepWalls(dt, false);
      else if (round.phase === 'miss' && round.time > 1.4) round.to('run');
      if (round.timedOut) {
        reset();
        round.to('ready');
      }
      seen.push(round.clock, you);
      stepShards(dt);
      fx.update(dt);
      if (round.settled) show.followMood(moodNow(), 2, dt);
      switchPulse = Math.max(0, switchPulse - dt * 5);
      passFlash = Math.max(0, passFlash - dt * 4);
      missFlash = Math.max(0, missFlash - dt * 2);
      const want = round.phase === 'ready' ? 0 : mult() >= MAX_MULT ? 1 : (streak % PER_MULT) / PER_MULT;
      meter += (want - meter) * Math.min(1, dt * 6);

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      if (round.phase === 'over') endGlow(yard, round.time, 0.05);
      // The windows, doors and the rest are the show's.
      fx.draw(frame);
    },

    status(): GameStatusFields {
      if (!playable) return round.setup();
      const best = Math.max(round.best(), score);
      const stats = [
        { label: 'Score', value: score },
        { label: 'You', value: NAMES[you] },
        { label: 'Speed', value: level() },
        { label: 'Best', value: best }
      ];
      const common = { score, lives, goal: null, stats };
      switch (round.phase) {
        case 'ready':
          return { ...common, phase: round.phase, lives: null, message: 'Tap to start! Each tap changes your color. Match every wall as it reaches you.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'run': {
          const w = nextWall();
          const m = mult();
          return {
            ...common,
            stats: m > 1 ? [...stats, { label: 'Combo', value: `×${m}` }] : stats,
            phase: round.phase,
            message: w ? `Next: ${NAMES[w.tone]}. Tap to match the wall in the white brackets!` : 'Get ready…',
            button: 'SWITCH',
            tone: 'go'
          };
        }
        case 'miss':
          return { ...common, phase: round.phase, message: lives === 1 ? `Wrong color! Last life!` : `Wrong color! ${lives} lives left.`, button: 'SWITCH', tone: 'bad' };
        case 'over':
          return { ...common, phase: round.phase, message: newBest ? `New best: ${score}!` : `Game over: ${score} points. Longest streak ${longest}.`, button: 'GO!', tone: 'go' };
      }
    }
  };
}
