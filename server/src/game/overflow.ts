import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Rgb } from '../../../shared/color.ts';
import { type Frame } from './frame.ts';
import { COLORS, Flare, heat, Sparks, Yard, type Part } from './kit.ts';
import { Fx, Round } from './round.ts';
import { overMood, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Overflow: hold the button and light pours from the gutter into a bush (or up a tree), filling
// it from the ground up. A ring of white light marks a height: let go so the light settles inside
// the ring. The pour speeds up the longer you hold, and it keeps rising for a moment after you
// let go, with a surface that sloshes. Learning that overshoot is the game.
//
// The light's color says how close you are, like hot and cold: deep blue far below the ring,
// green and yellow as it nears, gold inside, red over it. A stop inside the ring fires a rocket
// from the bush up to the roof, where it bursts; dead center (PERFECT) bursts in every color
// and sends a shockwave over the house. Filled bushes and trees stay lit with what they won.
// Windows and doors glow warmer with every success in a row.
//
// The whole yard plays along (see show.ts): while you pour, the whole house glows in the pour's
// hot-and-cold color, so the yard tells you how close you are; over the ring it throbs red. A
// stop in the ring sends a firework up from the bush (every color for a PERFECT), a bigger streak
// multiplier sweeps gold up the house, a spill blows up red, and a level done ends in a finale.

type Phase = 'ready' | 'aim' | 'pour' | 'settle' | 'good' | 'perfect' | 'short' | 'spill' | 'clear' | 'over';

interface Vessel {
  part: Part;
  /** The roof position above it, where the light pours from (-1: no roof). */
  spout: number;
  result: 'good' | 'perfect' | null;
  /** The level it reached when it was won. */
  kept: number;
}

const LIVES = 3;
const COLUMNS = 12;
const DEEP: Rgb = [0.02, 0.1, 1];

/** The color of the light for how far it is from the ring (in ring half-widths): cold far below, gold inside, red over. */
function closeness(d: number): Rgb {
  if (d > 1) return mix([1, 0.25, 0], COLORS.bad, Math.min(1, (d - 1) / 1.5));
  if (d >= -1) return mix(COLORS.gold, [1, 0.95, 0.6], Math.max(0, 1 - Math.abs(d) * 2.5));
  // Blue, cyan, green, yellow as it nears.
  const t = Math.max(0, Math.min(1, (d + 5) / 4));
  return t < 0.02 ? DEEP : hsv(0.64 - t * 0.5, 1);
}

export function overflowGame(stage: Stage): Game {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const sparks = new Sparks(roof, roof.n * 0.12, 1.4);
  const decorFlare = new Flare(2.5);
  const fx = new Fx(yard, { sparks, flare: decorFlare });
  const { motes, waves, show } = fx;
  const vessels: Vessel[] = [...yard.bushes, ...yard.trees].sort((a, b) => a.x - b.x).map((part) => ({ part, spout: roof.n ? roof.above(part.x) : -1, result: null, kept: 0 }));
  const playable = vessels.length > 0;
  /** The vessel whose backdrop is turned down (the one being filled: its ring must read clearly). */
  let dimmed = -1;

  const round = new Round<Phase>('overflow', 'ready', { resetAfter: 12 });
  let level = 1;
  let lives = LIVES;
  let score = 0;
  let streak = 0;
  let current = 0;
  let newBest = false;
  let lastPoints = 0;
  /** The fill (0..1 of the vessel's height) and how fast it rises. */
  let fill = 0;
  let speed = 0;
  let holdTime = 0;
  let holder: string | null = null;
  /** The ring: its middle when it was set, and half its height. */
  let ringBase = 0.5;
  let ringHalf = 0.1;
  let ringAtJudge = 0.5;
  const wave = new Float32Array(COLUMNS);
  const waveVel = new Float32Array(COLUMNS);
  let dripClock = 0;

  // How each level gets harder: a thinner ring, a faster pour, more momentum, then a ring that moves.
  const ringHalfFor = (lv: number) => Math.max(0.035, 0.1 - (lv - 1) * 0.012);
  const pourStart = (lv: number) => 0.12 + lv * 0.02;
  const pourRamp = (lv: number) => 0.35 + lv * 0.08;
  const settleRate = (lv: number) => Math.max(2.4, 6 - (lv - 1) * 0.45);
  const ringMoves = (lv: number) => (lv >= 3 ? 0.05 + Math.min(0.1, (lv - 3) * 0.02) : 0);

  const vessel = () => vessels[current];
  const ring = () => ringBase + ringMoves(level) * Math.sin(round.clock * (1.1 + level * 0.15));

  function newRing() {
    ringHalf = ringHalfFor(level);
    const move = ringMoves(level);
    ringBase = 0.3 + move + Math.random() * (0.9 - ringHalf - 0.3 - move * 2);
    fill = 0;
    speed = 0;
    holdTime = 0;
    wave.fill(0);
    waveVel.fill(0);
  }

  function newGame() {
    level = 1;
    lives = LIVES;
    score = 0;
    streak = 0;
    current = 0;
    newBest = false;
    for (const v of vessels) v.result = null;
    fx.clear();
    show.sweep(COLORS.hint, { dir: 'up', amount: 0.5 });
    newRing();
    round.to('aim');
  }

  function spoutPoint(v: Vessel) {
    if (v.spout >= 0) return roof.point(v.spout);
    return { x: v.part.x, y: v.part.top - stage.scale * 2.5 };
  }

  const surfaceY = (v: Vessel, level: number) => v.part.bottom - level * (v.part.bottom - v.part.top);

  function startPour(id: string) {
    holder = id;
    holdTime = 0;
    round.to('pour');
  }

  function stopPour() {
    holder = null;
    // Stopping the stream sets the surface rocking.
    for (let k = 0; k < COLUMNS; k++) waveVel[k] += (Math.random() - 0.5) * 3 * speed * 4;
    round.to('settle');
  }

  function judge() {
    const v = vessel();
    ringAtJudge = ring();
    const d = (fill - ringAtJudge) / ringHalf;
    if (Math.abs(d) <= 1) {
      const perfect = Math.abs(d) <= 0.3;
      streak++;
      const mult = Math.min(4, 1 + Math.floor((streak - 1) / 3));
      lastPoints = (perfect ? 3 : 1) * mult;
      score += lastPoints;
      // A bigger multiplier: gold sweeps up the house, with a volley.
      if (mult > 1 && (streak - 1) % 3 === 0) {
        show.sweep(COLORS.gold, { dir: 'up', amount: 0.7 });
        show.finale(1 + mult, { colors: [[COLORS.gold, WHITE]] });
      }
      v.result = perfect ? 'perfect' : 'good';
      v.kept = fill;
      launch(v, perfect);
      round.to(perfect ? 'perfect' : 'good');
    } else {
      fail(d < 0 ? 'short' : 'spill');
    }
  }

  function launch(v: Vessel, perfect: boolean) {
    const from = { x: v.part.x, y: surfaceY(v, fill) };
    const to = spoutPoint(v);
    const color = perfect ? WHITE : COLORS.gold;
    show.pulse(COLORS.gold, perfect ? 0.2 : 0.1);
    if (show.rocketsUp < 3) show.firework({ x: v.part.x, colors: perfect ? [hsv(Math.random()), hsv(Math.random()), COLORS.gold] : [COLORS.gold, [1, 0.45, 0.05]], size: perfect ? 1.4 : 0.9, kind: perfect ? 'peony' : 'willow' });
    motes.fly(from, to, color, 0.55, {
      size: 30,
      arrive: () => {
        if (v.spout >= 0) {
          const colors: Rgb[] = perfect ? [hsv(Math.random()), hsv(Math.random()), hsv(Math.random()), WHITE, COLORS.gold] : [COLORS.gold, WHITE, [1, 0.45, 0.05]];
          sparks.burst(v.spout, colors, perfect ? 90 : 45, roof.n * (perfect ? 0.55 : 0.35), perfect ? 1.6 : 1.1);
        }
        if (perfect) waves.add(to.x, to.y, WHITE, { amount: 1 });
        show.burst(to.x, to.y, perfect ? [hsv(Math.random()), hsv(Math.random()), COLORS.gold] : [COLORS.gold, [1, 0.45, 0.05]], { size: perfect ? 1.1 : 0.6, kind: perfect ? 'crackle' : 'peony' });
        if (perfect) show.ripple(to.x, to.y, WHITE, { amount: 0.5 });
        decorFlare.add(perfect ? WHITE : COLORS.gold, perfect ? 1 : 0.5);
      }
    });
  }

  function fail(kind: 'short' | 'spill') {
    holder = null;
    lives--;
    streak = 0;
    const v = vessel();
    if (kind === 'spill') {
      // It spills over the top and runs down to the ground on both sides.
      for (let i = 0; i < 18; i++) {
        const side = i % 2 ? 1 : -1;
        motes.drop(v.part.x + side * (v.part.right - v.part.left) * 0.3, v.part.top, mix(COLORS.ember, COLORS.bad, Math.random()), {
          vx: side * stage.scale * (0.8 + Math.random() * 1.6),
          vy: -stage.scale * (1 + Math.random() * 2),
          size: 22
        });
      }
      waves.add(v.part.x, v.part.top, COLORS.bad, { amount: 0.5 });
      if (lives > 0) show.explode(v.part.x, v.part.top, COLORS.bad, { size: 1.1 });
    } else {
      // Too low: it drains away, and a dull ripple runs out from the vessel.
      show.ripple(v.part.x, v.part.bottom, [0.5, 0.05, 0.15], { amount: 0.6 });
      show.pulse(COLORS.bad, 0.12);
    }
    decorFlare.add(COLORS.bad, 0.5);
    if (lives <= 0) {
      newBest = round.record(score);
      // The house blows, and the yard goes dark red (gold fireworks for a new best).
      show.gameOver(v.part.x, v.part.top, { newBest });
    } else show.sweep(COLORS.bad, { dir: 'down', amount: 0.5, duration: 0.7 });
    round.to(kind);
  }

  function next() {
    current++;
    if (current >= vessels.length) {
      round.to('clear');
      newBest = round.record(score) || newBest;
      for (const v of vessels) waves.add(v.part.x, v.part.top, COLORS.gold, { amount: 0.7 });
      show.finale(Math.max(5, vessels.length + 2), { colors: [[COLORS.gold, WHITE], [hsv(0.55), COLORS.gold], [hsv(0.85), hsv(0.15)]] });
      show.sweep(COLORS.gold, { dir: 'out', amount: 0.8, duration: 1 });
      return;
    }
    newRing();
    round.to('aim');
  }

  function nextLevel() {
    level++;
    current = 0;
    for (const v of vessels) v.result = null;
    newRing();
    round.to('aim');
  }

  // ---------- Physics ----------

  function stepLiquid(dt: number) {
    if (round.phase === 'pour') {
      holdTime += dt;
      const inflow = pourStart(level) + pourRamp(level) * holdTime;
      speed += (inflow - speed) * Math.min(1, dt * 8);
      fill += speed * dt;
      // The stream stirs the surface where it lands.
      const k = Math.floor(COLUMNS / 2 + (Math.random() - 0.5) * 3);
      waveVel[Math.max(0, Math.min(COLUMNS - 1, k))] -= speed * 6 * dt * 10;
      if (fill > 1) fail('spill');
    } else if (round.phase === 'settle') {
      // Momentum: it keeps rising after the stream stops.
      speed *= Math.exp(-settleRate(level) * dt);
      fill += speed * dt;
      if (fill > 1) fail('spill');
      else if (speed < 0.004 && round.time > 0.25) judge();
    } else if (round.phase === 'short' || round.phase === 'spill') {
      fill = Math.max(0, fill - dt * 0.7);
    }
    // The surface: springs between neighbouring columns, pulled back to flat.
    for (let k = 0; k < COLUMNS; k++) {
      const l = wave[Math.max(0, k - 1)];
      const r = wave[Math.min(COLUMNS - 1, k + 1)];
      waveVel[k] += (40 * (l + r - 2 * wave[k]) - 18 * wave[k] - 2.2 * waveVel[k]) * dt;
    }
    for (let k = 0; k < COLUMNS; k++) wave[k] = Math.max(-1, Math.min(1, wave[k] + waveVel[k] * dt));
  }

  // ---------- Drawing ----------

  function drawVessel(v: Vessel, active: boolean) {
    const p = v.part;
    const r = ring();
    const amp = 0.05;
    for (let i = 0; i < p.count; i++) {
      const u = p.up[i];
      const at = p.offset + i;
      if (!active) {
        if (v.result) {
          // What it won: gold, or white gold that shimmers for a perfect.
          if (u <= v.kept) {
            const c = v.result === 'perfect' ? mix(COLORS.gold, WHITE, 0.4 + 0.3 * Math.sin(round.clock * 5 + i * 1.9)) : COLORS.gold;
            yard.add(at, c, round.phase === 'clear' ? 0.6 + 0.6 * Math.max(0, Math.sin(round.clock * 8 + i)) : 0.5);
          }
        }
        continue;
      }
      const col = Math.max(0, Math.min(COLUMNS - 1, Math.floor(((p.across[i] + 1) / 2) * COLUMNS)));
      const surface = fill + amp * wave[col];
      const d = (fill - r) / ringHalf;
      const failing = round.phase === 'short' || round.phase === 'spill';
      if (u <= surface && fill > 0.005) {
        const depth = (surface - u) / Math.max(0.05, surface);
        let c = failing ? (round.phase === 'short' ? [0.15, 0.18, 0.3] as Rgb : mix([1, 0.2, 0], COLORS.bad, depth)) : closeness(d);
        // Deeper light is richer, with caustics drifting through it.
        c = mix(c, DEEP, depth * 0.25);
        const caustic = 0.08 * Math.sin(round.clock * 4 + i * 1.3 + u * 9);
        const foam = surface - u < 0.04 ? 0.5 : 0;
        yard.add(at, c, 0.6 + 0.35 * (1 - depth) + caustic);
        if (foam && !failing) yard.add(at, WHITE, foam);
        // The ring under the light: it glows hot where the light fills it.
        if (Math.abs(u - r) <= ringHalf && !failing) yard.add(at, COLORS.gold, 0.35);
      } else {
        if (round.phase !== 'good' && round.phase !== 'perfect' && !failing && Math.abs(u - r) <= ringHalf) {
          // The ring: soft inside, bright edges, breathing while it waits for you.
          const edge = Math.abs(Math.abs(u - r) - ringHalf) < ringHalf * 0.35 ? 1 : 0.45;
          yard.add(at, COLORS.hint, edge * (0.6 + 0.2 * Math.sin(round.clock * 4)));
        }
      }
    }
    if (round.phase === 'good' || round.phase === 'perfect') {
      // The bloom: a flash that runs up the vessel.
      const t = round.time / 0.6;
      if (t < 1) for (let i = 0; i < p.count; i++) if (Math.abs(p.up[i] - t) < 0.12) yard.add(p.offset + i, WHITE, 0.8 * (1 - t));
    }
  }

  function drawRoof() {
    const v = vessel();
    if (v && v.spout >= 0 && (round.phase === 'aim' || round.phase === 'pour' || round.phase === 'settle')) {
      // The spout above the vessel: it glows while you aim, and runs with light while you pour.
      const c = round.phase === 'aim' ? COLORS.hint : closeness((fill - ring()) / ringHalf);
      const k = round.phase === 'pour' ? 1 : round.phase === 'settle' ? Math.max(0, 1 - round.time * 3) : 0.35 + 0.15 * Math.sin(round.clock * 4);
      yard.roofSplat(v.spout, c, 3, k);
    }
    sparks.draw(yard);
  }

  /** The house: the show's canvas, with the flare of every result. */
  function drawDecor(p: Part) {
    for (let i = 0; i < p.count; i++) yard.add(p.offset + i, decorFlare.color, 0.5);
  }


  /** The yard's mood from the game's state: the pour's hot-and-cold color while pouring. */
  function moodNow(): Mood {
    const warm = Math.min(1, streak / 9);
    switch (round.phase) {
      case 'ready': {
        // Waiting: the pour's colors, cold to hot, round and round.
        const t = (round.clock * 0.08) % 1;
        return { a: closeness(-5 + t * 6), b: closeness(-5 + ((t + 0.4) % 1) * 6), level: 1, drift: 1.3 };
      }
      case 'aim':
        if (lives === 1) return { a: mix(DEEP, COLORS.bad, 0.5), b: [0.15, 0.02, 0.3], level: 0.9, throb: 0.8 };
        return { a: mix(DEEP, heat(0.4), warm * 0.6), b: [0.1, 0.5, 0.6], level: 0.8 + 0.4 * warm };
      case 'pour':
      case 'settle': {
        // The whole yard is the pour's color: cold far below the ring, gold inside it, red over it.
        const d = (fill - ring()) / ringHalf;
        if (d > 1) return { a: COLORS.bad, b: [1, 0.25, 0], level: 1.2, throb: 4 };
        return { a: closeness(d), b: mix(closeness(d), DEEP, 0.5), level: 0.9 + 0.3 * Math.max(0, 1 - Math.abs(d) / 5), drift: 1.5 };
      }
      case 'good':
      case 'perfect':
        return { a: COLORS.gold, b: round.phase === 'perfect' ? hsv(round.clock * 0.5) : [1, 0.45, 0.05], level: 1.3, drift: 1.8 };
      case 'short':
      case 'spill':
        return lives <= 0 ? overMood(round.time) : { a: [0.6, 0.03, 0.02], b: [0.35, 0.05, 0.3], level: 0.8, drift: 0.5 };
      case 'clear':
        return { a: hsv(round.clock * 0.2), b: COLORS.gold, level: 1.4, drift: 2 };
      case 'over':
        return overMood(round.time + 2);
    }
  }

  newRing();

  return {
    id: 'overflow',

    scoreBoard: () => round.scoreBoard(),

    input(e: GameInput) {
      if (!playable) return;
      if (e.action === 'press') {
        if (round.canStart) return newGame();
        if (round.phase === 'aim' && round.time > 0.3) return startPour(e.playerId);
        if (round.phase === 'clear' && round.time > 2) return nextLevel();
      } else if (round.phase === 'pour' && e.playerId === holder) stopPour();
    },

    leave(playerId: string) {
      if (round.phase === 'pour' && playerId === holder) stopPour();
    },

    update(dt: number, frame: Frame) {
      round.tick(dt);
      yard.begin(frame);
      if (!playable) return;

      stepLiquid(dt);
      fx.update(dt);
      if (round.settled) show.followMood(moodNow(), round.phase === 'pour' || round.phase === 'settle' ? 6 : 2.5, dt);
      // The vessel being filled gets only a faint backdrop: its ring and its light must read clearly.
      const active = round.phase === 'aim' || round.phase === 'pour' || round.phase === 'settle' || round.phase === 'good' || round.phase === 'perfect' || round.phase === 'short' || round.phase === 'spill' ? current : -1;
      if (active !== dimmed) {
        for (const x of vessels) show.dim(x.part, x.part.fixture.kind === 'tree' ? 0.5 : 0.7);
        if (active >= 0 && vessels[active]) show.dim(vessels[active].part, 0.15);
        dimmed = active;
      }

      const v = vessel();
      if (round.phase === 'pour' && v) {
        // The stream: drops from the spout to the surface, past whatever hangs between.
        dripClock += dt * (12 + speed * 30);
        const from = spoutPoint(v);
        while (dripClock >= 1) {
          dripClock--;
          const c = closeness((fill - ring()) / ringHalf);
          motes.dropTo(from.x + (Math.random() - 0.5) * 10, from.y + 8, v.part.x + (Math.random() - 0.5) * (v.part.right - v.part.left) * 0.25, surfaceY(v, fill), c, { size: 24 });
        }
      } else if (round.phase === 'aim' && v) {
        // A slow drip from the spout says where the light will come from.
        dripClock += dt * 1.2;
        if (dripClock >= 1) {
          dripClock = 0;
          const from = spoutPoint(v);
          motes.dropTo(from.x, from.y + 8, v.part.x, v.part.bottom, COLORS.hint, { size: 18 });
        }
      }
      if ((round.phase === 'good' || round.phase === 'perfect') && round.time > 1.8) next();
      if ((round.phase === 'short' || round.phase === 'spill') && round.time > 2) {
        if (lives <= 0) round.to('over');
        else {
          newRing();
          round.to('aim');
        }
      }
      if (round.phase === 'clear') {
        if (Math.random() < dt * 4) sparks.burst(Math.random() * roof.n, [hsv(Math.random()), COLORS.gold, WHITE], 30, roof.n * 0.35);
        if (Math.random() < dt * 1.5 && show.rocketsUp < 3) show.firework({ colors: [hsv(Math.random()), COLORS.gold] });
        if (round.time > 5) nextLevel();
      }
      if (round.timedOut) {
        for (const x of vessels) x.result = null;
        current = 0;
        newRing();
        round.to('ready');
      }

      drawRoof();
      vessels.forEach((x, i) => drawVessel(x, i === current && round.phase !== 'clear' && round.phase !== 'over' && round.phase !== 'ready'));
      if (round.phase === 'ready') {
        // Waiting: each vessel breathes in the colors of the pour, one after another.
        vessels.forEach((x, vi) => {
          const t = (round.clock * 0.5 + vi * 0.35) % 1;
          for (let i = 0; i < x.part.count; i++) if (x.part.up[i] < t) yard.add(x.part.offset + i, closeness(-5 + t * 6), 0.25);
        });
      }
      for (const d of yard.decor) drawDecor(d);
      fx.draw(frame);
    },

    status(): GameStatusFields {
      if (!playable) return round.setup('Add a bush or a tree in Layout first.');
      const best = Math.max(round.best(), score);
      const stats = [
        { label: 'Level', value: level },
        { label: 'Score', value: score },
        ...(streak >= 3 ? [{ label: 'Streak', value: `×${Math.min(4, 1 + Math.floor((streak - 1) / 3))}` }] : []),
        { label: 'Best', value: best }
      ];
      const done = vessels.filter((x) => x.result).length;
      const common = { score, lives, goal: null, stats, progress: { value: done, max: vessels.length } };
      const name = vessel()?.part.fixture.name ?? '';
      switch (round.phase) {
        case 'ready':
          return { ...common, phase: round.phase, lives: null, progress: undefined, stats: [{ label: 'Best', value: best }], message: 'Hold to pour light. Let go so it settles inside the ring!', button: 'GO!', tone: 'go' };
        case 'aim':
          return { ...common, phase: round.phase, message: `${name}: hold to pour…`, button: 'HOLD', tone: 'calm' };
        case 'pour':
          return { ...common, phase: round.phase, message: 'Pouring… let go before the ring!', button: 'LET GO', tone: 'go' };
        case 'settle':
          return { ...common, phase: round.phase, message: 'Settling…', button: '…', tone: 'wait' };
        case 'perfect':
          return { ...common, phase: round.phase, message: `PERFECT! +${lastPoints}`, button: '★', tone: 'good' };
        case 'good':
          return { ...common, phase: round.phase, message: `In the ring! +${lastPoints}`, button: '✓', tone: 'good' };
        case 'short':
          return { ...common, phase: round.phase, message: lives > 0 ? 'Too low! It drains away…' : 'Too low!', button: '✗', tone: 'bad' };
        case 'spill':
          return { ...common, phase: round.phase, message: lives > 0 ? 'Overflow! It spilled over.' : 'Overflow!', button: '✗', tone: 'bad' };
        case 'clear':
          return { ...common, phase: round.phase, message: `Level ${level} done! Next: ${ringMoves(level + 1) ? 'the ring moves' : 'a thinner ring and a faster pour'}.`, button: 'NEXT', tone: 'good' };
        case 'over':
          return { ...common, phase: round.phase, progress: undefined, message: newBest ? `New best: ${score}!` : `Game over: ${score} points.`, button: 'GO!', tone: 'go' };
      }
    }
  };
}
