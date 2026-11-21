import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Rgb } from '../../../shared/color.ts';
import { type Frame } from './frame.ts';
import { bounce, COLORS, Flare, FOUR_TONES, heat, Recent, Sparks, Trail, Yard, type Part } from './kit.ts';
import { endGlow, Fx, MIN_ROOF, Round } from './round.ts';
import { overMood, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Ricochet: a white comet races along the roofline toward a green gate. Tap while it is in the
// gate and it turns around at once, and the next gate is already waiting somewhere ahead of it.
// There is no pause between gates: catch, turn, catch, turn, a little faster every time, with a
// gate that slowly narrows. One mistake ends the run: a tap outside the gate, or a comet that
// gets all the way through it. A catch dead in the middle of the gate is PERFECT: double points,
// and the bushes, trees and windows flash gold. Perfect play goes on forever.
//
// Colors mean one thing each: white is only ever the comet (with a blue-white tail), the gate is
// green, gold is points, red is the mistake that ends the run.
//
// The roof is kept clear for the comet and the gate: the comet turns around right where the next
// run starts, so a catch makes only a small gold flash that stays where the gate was (no sparks
// flying along the roof with the comet, nothing green or white). The celebration is in the rest
// of the yard.
//
// The yard: every 10 catches the streak flies from the gate into the next bush, which lights up
// in its own color (the next one fills faintly from the ground as the catches add up). When every
// bush is lit they all flash gold and start over in new colors. Trees are a speedometer, filling
// from the base up as the comet speeds up. Windows and doors catch the color of every catch.
//
// The whole yard is a light show around the game (see Show): it glows in a mood that heats up
// from deep blue to fire as the comet speeds up, pumps gold on every catch, sends up a firework
// for each one (a bigger one for a PERFECT), sweeps gold up the house every 10 catches and blows
// up red at the end. On the roof the show stays faint, so the comet stays the only white and the
// gate the only green there.

type Phase = 'ready' | 'running' | 'over';

/** A press counts if the comet was in the gate at any moment this long before it: Wi-Fi is late. */
const GRACE = 0.12;
/** Catches per bush. */
const PER_BUSH = 10;
/** A catch this close to the gate's middle (in steps) is PERFECT. */
const PERFECT = 1.2;
/** Each catch makes the comet this much faster. */
const SPEEDUP = 1.02;
/** How long the streak takes from the gate to its bush, in seconds. */
const STREAK = 0.55;
/** How long a catch's gold flash lasts on the roof, in seconds (a perfect one a little longer). */
const POP = 0.3;
const POP_PERFECT = 0.45;

const COMET_TAIL: Rgb = [0.45, 0.7, 1];
const GATE: Rgb = [0.15, 1, 0.45];
/** Bush colors: none of white (the comet), gold (points) or red (the mistake). */
const BUSH_COLORS: Rgb[] = [...FOUR_TONES, [0.55, 0, 1], [0, 1, 0.6]];

/** What the tests can see: the comet and the gate. */
export interface RicochetPeek {
  pos: number;
  dir: number;
  gate: number;
  halfWidth: number;
  /** Steps along the comet's path to the gate's middle (negative: past it). */
  toGo: number;
}

export function ricochetGame(stage: Stage): Game & { peek(): RicochetPeek } {
  const yard = new Yard(stage);
  const { roof, bushes } = yard;
  const n = roof.n;
  const playable = n >= MIN_ROOF;
  const sparks = new Sparks(roof, n * 0.1, 2);
  const flare = new Flare(3);
  // The yard around the roof: a mood that heats up with the speed, and fireworks for catches.
  const fx = new Fx(yard, { sparks, flare });
  const { motes, waves, show } = fx;
  for (const t of yard.trees) show.dim(t, 0.45);
  // The roof is the playfield: while the comet runs, the show stays off it (fireworks bursting
  // over the roof would add up to white, and white is only the comet) and the game draws a faint
  // backdrop there in the mood's colors itself. Waiting and after the end, the show has it too.
  show.roofLevel = 0.5;
  /** The mood now (set every frame), for the roof's own backdrop. */
  let mood: Mood = { a: [0, 0, 0], b: [0, 0, 0] };
  const trail = new Trail(Math.max(1, n));
  /** How far the comet still had to go to the gate's middle, lately. */
  const seen = new Recent<number>(0.4);

  const startSpeed = n / 3.2;
  const maxSpeed = n / 0.9;
  const startHalf = Math.max(5, Math.round(n * 0.04));
  const minHalf = Math.max(3, n * 0.012);

  const round = new Round<Phase>('ricochet', 'ready');
  let score = 0;
  let catches = 0;
  let perfects = 0;
  let newBest = false;
  let pos = 0;
  let dir = 1;
  let speed = startSpeed;
  let halfWidth = startHalf;
  let gate = 0;
  /** Steps along the comet's (bouncing) path to the gate's middle. */
  let toGo = 0;
  let missAt = 0;
  /** Seconds since the last PERFECT, for the phone's message. */
  let sincePerfect = Infinity;
  /** Gold flashes where gates were caught: two dots that open out from the gate's middle and fade. */
  let pops: { pos: number; half: number; t: number; perfect: boolean }[] = [];
  /** Seconds since the last catch: the bushes and trees flash. */
  let sinceCatch = Infinity;
  /** Which set of bush colors (each full yard starts a new one). */
  let set = 0;
  /** 0..1 fill of each bush, following litTarget. */
  const lit = bushes.map(() => 0);
  const litTarget = bushes.map(() => 0);
  let flashAll = 0;

  const bushColor = (i: number) => BUSH_COLORS[(i + set * 2) % BUSH_COLORS.length];

  /**
   * A new gate ahead of the comet, a random distance along its path (it may bounce off an end
   * first), where it can be seen from the street, and never on a stretch the comet crosses on
   * the way there (it would look like it went through the gate).
   */
  function placeGate() {
    let best: { at: number; d: number } | null = null;
    for (let tries = 0; tries < 40; tries++) {
      const d = n * (0.12 + Math.random() * 0.33);
      const at = bounce(pos, dir, d, n).pos;
      if (at < halfWidth + 1 || at > n - 2 - halfWidth || roof.hiddenAt(at)) continue;
      let clear = true;
      let p = pos;
      let pd = dir;
      for (let s = 0; s < d - halfWidth - 2 && clear; s += 1) {
        ({ pos: p, dir: pd } = bounce(p, pd, 1, n));
        if (Math.abs(p - at) <= halfWidth + 1) clear = false;
      }
      if (!clear) continue;
      best = { at, d };
      break;
    }
    if (!best) {
      // Nowhere fits: just ahead, inside the roof.
      const d = n * 0.2;
      best = { at: bounce(pos, dir, d, n).pos, d };
    }
    gate = best.at;
    toGo = best.d;
    seen.clear();
  }

  function reset() {
    score = 0;
    catches = 0;
    perfects = 0;
    newBest = false;
    speed = startSpeed;
    halfWidth = startHalf;
    pos = Math.round(n * 0.08);
    dir = 1;
    set = 0;
    lit.fill(0);
    litTarget.fill(0);
    flashAll = 0;
    sincePerfect = Infinity;
    sinceCatch = Infinity;
    pops = [];
    sparks.clear();
    motes.clear();
    waves.clear();
    trail.clear();
    placeGate();
  }

  function start() {
    reset();
    round.to('running');
    show.clear();
    show.setMood(moodNow(), { wipe: roof.startsLeft ? 'right' : 'left' });
  }

  /** The streak flies from the gate into the next bush; a full yard flashes and starts over. */
  function winBush() {
    if (!bushes.length) return;
    const index = Math.floor(catches / PER_BUSH - 1) % bushes.length;
    const bush = bushes[index];
    const color = bushColor(index);
    const from = roof.point(gate);
    motes.fly(from, yard.topOf(bush), mix(color, WHITE, 0.3), STREAK, {
      arc: 40,
      size: 28,
      arrive: () => {
        litTarget[index] = 1;
        flare.add(color, 0.8);
        show.explode(bush.x, bush.top, color, { size: 0.8 });
        if (litTarget.every((v) => v >= 1)) {
          flashAll = 1.6;
          for (const b of bushes) waves.add(b.x, b.top, COLORS.gold, { amount: 0.5 });
          // A full yard: fireworks in every bush's color.
          show.finale(Math.max(4, bushes.length * 2), { colors: bushes.map((_, i) => [bushColor(i), COLORS.gold]) });
        }
      }
    });
  }

  function caught(closest: number) {
    const perfect = closest <= PERFECT;
    catches++;
    score += perfect ? 2 : 1;
    sinceCatch = 0;
    pops.push({ pos: gate, half: halfWidth, t: 0, perfect });
    // The comet turns back over its own tail: wipe it, so the turn is crisp and the gold flash
    // does not mix with it into white.
    trail.clear();
    if (perfect) {
      perfects++;
      sincePerfect = 0;
      flare.add(COLORS.gold, 1.1);
    } else flare.add(COLORS.gold, 0.45);
    // The yard: a gold kick, and a firework (a big one for a PERFECT, with a ring through the house).
    show.pulse(COLORS.gold, perfect ? 0.14 : 0.07);
    show.rocket([COLORS.gold, bushColor(Math.floor(catches / PER_BUSH))], { size: perfect ? 1.1 : 0.6, kind: perfect ? 'ring' : undefined });
    if (perfect) {
      const p = roof.point(gate);
      show.ripple(p.x, p.y, COLORS.gold, { amount: 0.5 });
    }
    // Every 10 catches (a new bush, a faster comet): gold sweeps up the whole yard and a volley goes up.
    if (catches % PER_BUSH === 0) {
      show.sweep(COLORS.gold, { dir: 'up', amount: 0.6 });
      show.finale(3, { colors: [[COLORS.gold, bushColor(Math.floor(catches / PER_BUSH) - 1)]] });
    }
    if (catches % PER_BUSH === 0) winBush();
    // Turn around at once, a little faster, and the next gate is already there.
    dir = -dir;
    speed = Math.min(maxSpeed, speed * SPEEDUP);
    halfWidth = Math.max(minHalf, halfWidth * 0.985);
    placeGate();
  }

  function gameOver(at: number) {
    missAt = at;
    sparks.burst(at, [COLORS.bad, COLORS.ember], 40, n * 0.3);
    // What was lit falls off the gutter.
    for (let k = 0; k < 14; k++) {
      const p = roof.point(Math.random() * (n - 1));
      motes.drop(p.x, p.y, mix(COMET_TAIL, COLORS.bad, 0.7), { vx: (Math.random() - 0.5) * 60, size: 20 });
    }
    litTarget.fill(0);
    newBest = round.record(score);
    // The house blows, and the yard goes dark red (gold fireworks for a new best).
    const p = roof.point(at);
    show.gameOver(p.x, p.y, { newBest });
    round.to('over');
  }

  /**
   * The yard's mood: a slow rainbow while it waits; deep blue and violet at the start of a run,
   * heating up through magenta to fire as the comet speeds up; dark red after the end.
   */
  function moodNow(): Mood {
    if (round.phase === 'ready') return { a: hsv(round.clock * 0.04), b: hsv(round.clock * 0.04 + 0.3), level: 0.9, drift: 1.4 };
    if (round.phase === 'over') return overMood(round.time);
    const t = Math.max(0, Math.min(1, (speed - startSpeed) / (maxSpeed - startSpeed)));
    const a = t < 0.5 ? mix([0.1, 0.15, 0.75], [0.7, 0.05, 0.75], t * 2) : mix([0.7, 0.05, 0.75], [1, 0.3, 0.02], t * 2 - 1);
    const b = t < 0.5 ? mix([0.4, 0.05, 0.7], [1, 0.05, 0.4], t * 2) : mix([1, 0.05, 0.4], [1, 0.05, 0.05], t * 2 - 1);
    return { a, b, level: 0.9 + 0.5 * t, drift: 1 + 1.5 * t };
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (round.canStart) return start();
    if (round.phase !== 'running') return;
    // Judged by what the player saw: where the comet was over the grace window.
    const recent = [...seen.since(round.clock - GRACE), toGo];
    const closest = Math.min(...recent.map((t) => Math.abs(t)));
    if (closest <= halfWidth) caught(closest);
    else gameOver(pos);
  }

  // ---------- Drawing ----------

  function drawGate(color: Rgb) {
    const breathe = 0.6 + 0.4 * Math.sin(round.clock * 6);
    for (let i = Math.ceil(gate - halfWidth); i <= Math.floor(gate + halfWidth); i++) yard.roofAt(i, color, 0.12 + 0.08 * breathe);
    yard.roofSplat(gate - halfWidth, color, 1, 0.9 * breathe + 0.3);
    yard.roofSplat(gate + halfWidth, color, 1, 0.9 * breathe + 0.3);
  }

  /**
   * A catch's flash: gold, at the old gate, opening out a few steps and fading fast. The comet
   * leaves through it, so it is not drawn where the comet's tail is: the comet stays on top
   * (gold added to the blue-white tail would look white, like the comet).
   */
  function drawPops() {
    const clear = (i: number) => (trail.level[Math.round(i)] ?? 0) < 0.03 && Math.abs(i - pos) > 2.5;
    for (const p of pops) {
      const life = p.perfect ? POP_PERFECT : POP;
      const f = p.t / life;
      const spread = p.half * (0.3 + f * 0.9);
      const amount = (1 - f) ** 1.5 * (p.perfect ? 0.9 : 0.6);
      for (const at of [p.pos - spread, p.pos + spread]) {
        for (let i = Math.floor(at - 2); i <= Math.ceil(at + 2); i++) {
          const d = (i - at) / 0.9;
          if (i >= 0 && i < n && clear(i)) yard.roofAt(i, COLORS.gold, amount * Math.exp(-d * d));
        }
      }
      if (p.perfect && f < 0.35) for (let i = Math.ceil(p.pos - spread); i <= Math.floor(p.pos + spread); i++) if (clear(i)) yard.roofAt(i, COLORS.gold, 0.25 * (1 - f / 0.35));
    }
  }

  function drawRoof() {
    // The roof's faint backdrop in the mood's colors, drifting along it (far too dim to look white or green).
    if (round.phase === 'running') {
      const k = 0.05 * (mood.level ?? 1);
      // Not under the comet's tail: it would push the tail toward white.
      for (let i = 0; i < n; i++) yard.roofAt(i, mix(mood.a, mood.b, 0.5 + 0.5 * Math.sin(i * 0.06 - round.clock * 0.8)), k * Math.max(0, 1 - trail.level[i] * 10));
    }
    drawPops();
    if (round.phase !== 'over') drawGate(GATE);
    trail.draw(yard, (v) => mix(COMET_TAIL, WHITE, v * v * 0.7), 0.9);
    if (round.phase !== 'over') yard.roofSplat(pos, WHITE, 1.1, 1);
    else yard.roofSplat(missAt, COLORS.bad, 2 + round.time * 10, Math.max(0, 1 - round.time));
    sparks.draw(yard);
  }

  function drawBushes() {
    const next = bushes.length ? Math.floor(catches / PER_BUSH) % bushes.length : 0;
    const partial = (catches % PER_BUSH) / PER_BUSH;
    bushes.forEach((b, bi) => {
      const color = bushColor(bi);
      const filled = lit[bi];
      for (let k = 0; k < b.count; k++) {
        const i = b.bottomUp[k];
        const u = k / Math.max(1, b.count - 1);
        const sparkle = 0.75 + 0.25 * Math.sin(round.clock * 7 + i * 2.3);
        // Every catch flashes the bushes gold (a perfect one brighter and longer).
        const glint = sincePerfect < 0.5 ? 1 - sincePerfect / 0.5 : sinceCatch < 0.25 ? 0.5 * (1 - sinceCatch / 0.25) : 0;
        if (glint > 0) yard.add(b.offset + i, COLORS.gold, glint * 0.6);
        if (flashAll > 0) {
          const f = Math.max(0, Math.sin(round.clock * 14 + i));
          yard.add(b.offset + i, mix(color, COLORS.gold, f * 0.7), 0.5 + f * 0.5);
        } else if (u < filled) yard.add(b.offset + i, color, 0.65 * sparkle);
        else if (round.phase === 'running' && bi === next && litTarget[bi] < 1 && u < partial) yard.add(b.offset + i, color, 0.18);
      }
    });
  }

  function drawTree(part: Part) {
    // A speedometer: from the base up, hotter as the comet speeds up.
    const t = round.phase === 'running' ? (speed - startSpeed) / (maxSpeed - startSpeed) : 0;
    const level = Math.max(0.04, Math.min(1, 0.04 + t * 0.96));
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (u <= level) yard.add(part.offset + i, heat(u * 0.9), 0.6 + (u > level - 0.05 ? 0.3 : 0));
      // A perfect catch: a gold flash that runs up the tree.
      if (sincePerfect < 0.6) {
        const d = u - sincePerfect / 0.5;
        if (Math.abs(d) < 0.15) yard.add(part.offset + i, COLORS.gold, 0.8 * (1 - Math.abs(d) / 0.15));
      }
    }
  }

  /** The house: the show's canvas, with a touch of the flare of every catch. */
  function drawDecor(part: Part) {
    for (let i = 0; i < part.count; i++) yard.add(part.offset + i, flare.color, 0.15);
  }

  function step(dt: number) {
    if (round.phase === 'running') {
      const move = speed * dt;
      ({ pos, dir } = bounce(pos, dir, move, n));
      toGo -= move;
      seen.push(round.clock, toGo);
      // All the way through the gate, and past the grace for a late press: the run is over.
      if (toGo < -halfWidth - speed * GRACE - 0.5) gameOver(pos);
    } else if (round.phase === 'ready') {
      // The attract loop: the comet runs slowly through a gate in the middle.
      gate = n / 2;
      halfWidth = startHalf;
      ({ pos, dir } = bounce(pos, dir, (n / 5) * dt, n));
      // Now and then a firework, to draw a crowd.
      if (Math.random() < dt * 0.35) show.rocket([hsv(Math.random()), hsv(Math.random())], { size: 0.8 });
    }
    if (round.timedOut) {
      reset();
      round.to('ready');
    }
    fx.update(dt);
    mood = moodNow();
    if (round.settled) show.followMood(mood, 2, dt);
    show.roofShare = round.phase === 'running' ? 0 : Math.min(1, show.roofShare + dt * 2);
    sincePerfect += dt;
    sinceCatch += dt;
    for (const p of pops) p.t += dt;
    pops = pops.filter((p) => p.t < (p.perfect ? POP_PERFECT : POP));
    if (flashAll > 0) {
      flashAll -= dt;
      if (flashAll <= 0) {
        // A full yard starts over in new colors.
        set++;
        lit.fill(0);
        litTarget.fill(0);
      }
    }
    trail.fade(dt, 7);
    if (round.phase !== 'over') trail.mark(pos);
    lit.forEach((v, i) => (lit[i] = v + (litTarget[i] - v) * Math.min(1, dt * 2.5)));
  }

  reset();

  return {
    id: 'ricochet',

    scoreBoard: () => round.scoreBoard(),

    input,

    update(dt: number, frame: Frame) {
      round.tick(dt);
      yard.begin(frame);
      if (!playable) return;
      step(dt);
      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      for (const d of yard.decor) drawDecor(d);
      if (round.phase === 'over') endGlow(yard, round.time, 0.04, 0.2);
      fx.draw(frame);
    },

    status(): GameStatusFields {
      if (!playable) return round.setup();
      const best = round.best();
      const common = { score, lives: null, goal: null };
      switch (round.phase) {
        case 'ready':
          return { ...common, phase: round.phase, message: 'Tap to start! Catch the comet in the green gate. It turns around every time.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'running':
          return {
            ...common,
            phase: round.phase,
            message: sincePerfect < 0.8 ? 'PERFECT! Double points!' : catches ? `${catches} in a row! Catch it in the gate.` : 'Catch it in the gate. It turns around every time!',
            button: 'CATCH',
            tone: 'go',
            stats: [
              { label: 'Score', value: score },
              { label: 'Best', value: Math.max(best, score) },
              { label: 'Speed', value: `×${(speed / startSpeed).toFixed(2)}` }
            ]
          };
        case 'over':
          return {
            ...common,
            phase: round.phase,
            message: newBest ? `New best: ${score}!` : `Game over: ${score} points, ${catches} catches${perfects ? `, ${perfects} perfect` : ''}.`,
            button: round.canStart ? 'GO!' : '…',
            tone: round.canStart ? 'go' : 'bad',
            stats: [
              { label: 'Score', value: score },
              { label: 'Best', value: best }
            ]
          };
      }
    },

    peek: () => ({ pos, dir, gate, halfWidth, toGo })
  };
}
