import type { Stage } from '../../../shared/layout.ts';
import { mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, COLORS, Flare, heat, Motes, Recent, record, scale, Waves, Yard, type Part } from './kit.ts';
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
// next multiplier. Windows and doors catch the color of every wall you pass and glow warmer with
// the streak.

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
const NIGHT: Rgb = [0.02, 0.012, 0.035];
/** Your colors and the walls': far apart on real LEDs, and none of white, gold or red. */
export const GATE_COLORS: Rgb[] = [
  [0.05, 1, 0.12],
  [0.14, 0.08, 1],
  [1, 0, 0.7]
];
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
  const playable = n >= 30;
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const decorFlare = new Flare(2.2);

  // Your light: near the start of the roof, where it can be seen from the street.
  let home = Math.max(3, Math.round(n * 0.06));
  while (home < n / 3 && roof.hiddenAt(home)) home++;
  const start = n - 1;
  const travel = Math.max(1, start - home);

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
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

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

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
    seen.push(clock, you);
    motes.clear();
    waves.clear();
  }

  function newGame() {
    reset();
    setPhase('run');
    spawn();
  }

  function burst(pos: number, colors: Rgb[], count: number, power: number, life = 0.8) {
    for (let i = 0; i < count; i++) {
      const max = life * (0.5 + Math.random() * 0.8);
      shards.push({ pos, vel: (Math.random() - 0.5) * 2 * power * (0.3 + Math.random()), color: colors[i % colors.length], life: max, max });
    }
  }

  /** The next wall to reach you: the one in white brackets. */
  const nextWall = () => walls.find((w) => w.arrived === null || clock - w.arrived < LAG);

  /** Was this color showing at any moment while the wall was at your light (late taps count)? */
  function matched(w: Wall) {
    const at = w.arrived ?? clock;
    const shown = [seen.at(at), ...seen.since(at)];
    return shown.some((c) => c === w.tone);
  }

  function pass(w: Wall, demo: boolean) {
    const color = GATE_COLORS[w.tone];
    burst(home, [COLORS.gold, color, mix(color, COLORS.gold, 0.5)], 20, n * 0.25);
    decorFlare.add(color, 0.7);
    passFlash = 1;
    if (demo) return;
    const before = mult();
    streak++;
    longest = Math.max(longest, streak);
    judged++;
    score += mult();
    if (mult() > before) {
      const p = roof.point(home);
      waves.add(p.x, p.y, COLORS.gold, { amount: 1 });
      for (const b of yard.bushes) waves.add(b.x, b.top, color, { amount: 0.6 });
    }
  }

  function miss(w: Wall) {
    lives--;
    streak = 0;
    judged++;
    missFlash = 1;
    burst(home, [COLORS.bad, [1, 0.3, 0], GATE_COLORS[w.tone]], 30, n * 0.3, 1);
    // Every wall still coming shatters and falls off the gutter: a moment to breathe.
    for (const o of walls) {
      if (o === w) continue;
      burst(o.pos, [mix(GATE_COLORS[o.tone], COLORS.bad, 0.5)], 6, n * 0.08, 0.6);
      const p = roof.point(o.pos);
      motes.drop(p.x, p.y, mix(GATE_COLORS[o.tone], COLORS.bad, 0.6), { vx: (Math.random() - 0.5) * 60, size: 18 });
    }
    walls = [];
    queue = [];
    if (lives <= 0) {
      newBest = record('colorgate', score).isNew;
      setPhase('over');
    } else setPhase('miss');
  }

  function switchColor() {
    you = (you + 1) % GATE_COLORS.length;
    seen.push(clock, you);
    switchPulse = 1;
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    if (phase === 'run' || phase === 'miss') switchColor();
  }

  function stepWalls(dt: number, demo: boolean) {
    speed += (speedFor(level()) - speed) * Math.min(1, dt * 1.5);
    spawn();
    for (const w of walls) {
      if (w.arrived !== null) continue;
      w.pos -= speed * dt;
      if (w.pos <= home) {
        // When it got there, between frames.
        w.arrived = clock - (home - w.pos) / Math.max(1e-6, speed);
        w.pos = home;
      }
    }
    // In the attract loop, the house plays: it takes the color of a wall that is nearly there.
    if (demo) {
      const w = nextWall();
      if (w && w.pos - home < travel * 0.25 && you !== w.tone) {
        you = w.tone;
        seen.push(clock, you);
        switchPulse = 1;
      }
    }
    for (const w of [...walls]) {
      if (w.arrived === null || clock - w.arrived < LAG) continue;
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

  function drawRoof() {
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT, 1 + 0.3 * Math.sin(clock * 0.8 - i * 0.04));
    const next = phase === 'over' ? undefined : nextWall();
    for (const w of walls) {
      const c = GATE_COLORS[w.tone];
      // Walls come on softly at the far end.
      const fadeIn = Math.min(1, 0.3 + (start - w.pos) / 5);
      for (let i = Math.ceil(w.pos - WALL_HALF); i <= Math.floor(w.pos + WALL_HALF); i++) yard.roofAt(i, c, 0.85 * fadeIn);
      yard.roofSplat(w.pos, c, 2.5, 0.15 * fadeIn);
      if (w === next) {
        // The brackets: the only white on the roof.
        // One LED on each side, a step clear of the wall, so it stays crisp at a distance.
        const blink = 0.85 + 0.15 * Math.sin(clock * 14);
        yard.roofAt(Math.round(w.pos - WALL_HALF - 1.5), WHITE, 0.95 * blink * fadeIn);
        yard.roofAt(Math.round(w.pos + WALL_HALF + 1.5), WHITE, 0.95 * blink * fadeIn);
      }
    }
    // Your light: a big soft dot in your color, brighter for a moment when you switch.
    if (phase !== 'over') {
      const c = GATE_COLORS[you];
      const ready = phase === 'ready' ? 0.75 + 0.25 * Math.sin(clock * 3) : 1;
      yard.roofSplat(home, c, 2.2, (0.9 + switchPulse * 0.5) * ready);
      yard.roofSplat(home, c, 5, 0.18 + switchPulse * 0.2);
    }
    if ((phase === 'miss' || phase === 'over') && phaseTime < 1) yard.roofSplat(home, COLORS.bad, 2 + phaseTime * 12, 1 - phaseTime);
    for (const s of shards) {
      const age = 1 - s.life / s.max;
      const flicker = age > 0.6 ? 0.6 + 0.4 * Math.random() : 1;
      yard.roofSplat(s.pos, s.color, 0.9, (s.life / s.max) ** 0.8 * flicker);
    }
  }

  function drawBushes() {
    // Every bush is your color: you can read it from across the street.
    const base = phase === 'over' ? scale(COLORS.bad, 0.25) : GATE_COLORS[you];
    const c = mix(mix(base, COLORS.gold, passFlash * 0.6), COLORS.bad, missFlash * 0.8);
    for (const b of yard.bushes) {
      for (let i = 0; i < b.count; i++) {
        const shimmer = 0.06 * Math.sin(clock * 3 + i * 1.3);
        yard.add(b.offset + i, c, (phase === 'over' ? 0.4 : 0.65) + shimmer + switchPulse * 0.45 + passFlash * 0.25);
      }
    }
  }

  function drawTree(part: Part) {
    // Toward the next multiplier: full and twinkling gold at ×4.
    const top = meter >= 0.999;
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (u <= meter) {
        const c = top ? mix(COLORS.gold, WHITE, Math.max(0, Math.sin(clock * 8 + i * 1.7)) * 0.4) : heat(u * 0.85);
        yard.add(part.offset + i, c, top ? 0.85 : 0.6);
      } else yard.add(part.offset + i, [0.02, 0.015, 0.04]);
    }
  }

  function drawDecor(part: Part) {
    const warm = Math.min(1, streak / (PER_MULT * 3));
    for (let i = 0; i < part.count; i++) {
      yard.add(part.offset + i, NIGHT, 1.2);
      yard.add(part.offset + i, decorFlare.color, 1);
      if (warm > 0) yard.add(part.offset + i, COLORS.fire, warm * (0.15 + 0.05 * Math.sin(clock * 2 + i * 0.4)));
    }
  }

  reset();

  return {
    id: 'colorgate',

    input,

    update(dt: number, frame: Frame) {
      clock += dt;
      phaseTime += dt;
      yard.begin(frame);
      if (!playable) return;

      if (phase === 'ready') stepWalls(dt, true);
      else if (phase === 'run') stepWalls(dt, false);
      else if (phase === 'miss' && phaseTime > 1.4) setPhase('run');
      if (phase === 'over' && phaseTime > 10) {
        reset();
        setPhase('ready');
      }
      seen.push(clock, you);
      stepShards(dt);
      motes.update(dt);
      waves.update(dt);
      decorFlare.update(dt);
      switchPulse = Math.max(0, switchPulse - dt * 5);
      passFlash = Math.max(0, passFlash - dt * 4);
      missFlash = Math.max(0, missFlash - dt * 2);
      const want = phase === 'ready' ? 0 : mult() >= MAX_MULT ? 1 : (streak % PER_MULT) / PER_MULT;
      meter += (want - meter) * Math.min(1, dt * 6);

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      for (const d of yard.decor) drawDecor(d);
      if (phase === 'miss' && phaseTime < 0.6) yard.wash(COLORS.bad, 0.18 * (1 - phaseTime / 0.6));
      if (phase === 'over') yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(phaseTime * 3)), 0.05);
      motes.draw();
      waves.draw();
    },

    status(): GameStatusFields {
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score: 0, lives: null, goal: null };
      const best = Math.max(bestScore('colorgate'), score);
      const stats = [
        { label: 'Score', value: score },
        { label: 'You', value: NAMES[you] },
        { label: 'Speed', value: level() },
        { label: 'Best', value: best }
      ];
      const common = { score, lives, goal: null, stats };
      switch (phase) {
        case 'ready':
          return { ...common, phase, lives: null, message: 'Tap to start! Each tap changes your color. Match every wall as it reaches you.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'run': {
          const w = nextWall();
          const m = mult();
          return {
            ...common,
            stats: m > 1 ? [...stats, { label: 'Combo', value: `×${m}` }] : stats,
            phase,
            message: w ? `Next: ${NAMES[w.tone]}. Tap to match the wall in the white brackets!` : 'Get ready…',
            button: 'SWITCH',
            tone: 'go'
          };
        }
        case 'miss':
          return { ...common, phase, message: lives === 1 ? `Wrong color! Last life!` : `Wrong color! ${lives} lives left.`, button: 'SWITCH', tone: 'bad' };
        case 'over':
          return { ...common, phase, message: newBest ? `New best: ${score}!` : `Game over: ${score} points. Longest streak ${longest}.`, button: 'GO!', tone: 'go' };
      }
    }
  };
}
