import type { Stage } from '../../../shared/layout.ts';
import { mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, bounce, COLORS, Flare, heat, Motes, Recent, record, scale, Sparks, Trail, Waves, Yard, type Part } from './kit.ts';
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
// from the base up as the comet speeds up. Windows and doors catch the color of every catch and
// glow warmer as the speed climbs.

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
const NIGHT: Rgb = [0.01, 0.012, 0.035];
const BUSH_DARK: Rgb = [0.015, 0.03, 0.02];
/** Bush colors: none of white (the comet), gold (points) or red (the mistake). */
const BUSH_COLORS: Rgb[] = [
  [0.05, 1, 0.12],
  [0, 0.72, 1],
  [0.14, 0.08, 1],
  [1, 0, 0.7],
  [0.55, 0, 1],
  [0, 1, 0.6]
];

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
  const playable = n >= 30;
  const sparks = new Sparks(roof, n * 0.1, 2);
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const flare = new Flare(3);
  const trail = new Trail(Math.max(1, n));
  /** How far the comet still had to go to the gate's middle, lately. */
  const seen = new Recent<number>(0.4);

  const startSpeed = n / 3.2;
  const maxSpeed = n / 0.9;
  const startHalf = Math.max(5, Math.round(n * 0.04));
  const minHalf = Math.max(3, n * 0.012);

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
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

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

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
    setPhase('running');
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
        if (litTarget.every((v) => v >= 1)) {
          flashAll = 1.6;
          for (const b of bushes) waves.add(b.x, b.top, COLORS.gold, { amount: 0.5 });
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
    if (catches % PER_BUSH === 0) winBush();
    // Turn around at once, a little faster, and the next gate is already there.
    dir = -dir;
    speed = Math.min(maxSpeed, speed * SPEEDUP);
    halfWidth = Math.max(minHalf, halfWidth * 0.985);
    placeGate();
  }

  function gameOver(at: number) {
    missAt = at;
    sparks.burst(at, [COLORS.bad, [1, 0.3, 0]], 40, n * 0.3);
    // What was lit falls off the gutter.
    for (let k = 0; k < 14; k++) {
      const p = roof.point(Math.random() * (n - 1));
      motes.drop(p.x, p.y, mix(COMET_TAIL, COLORS.bad, 0.7), { vx: (Math.random() - 0.5) * 60, size: 20 });
    }
    litTarget.fill(0);
    newBest = record('ricochet', score).isNew;
    setPhase('over');
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return start();
    if (phase !== 'running') return;
    // Judged by what the player saw: where the comet was over the grace window.
    const recent = [...seen.since(clock - GRACE), toGo];
    const closest = Math.min(...recent.map((t) => Math.abs(t)));
    if (closest <= halfWidth) caught(closest);
    else gameOver(pos);
  }

  // ---------- Drawing ----------

  function drawGate(color: Rgb) {
    const breathe = 0.6 + 0.4 * Math.sin(clock * 6);
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
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT);
    drawPops();
    if (phase !== 'over') drawGate(GATE);
    trail.draw(yard, (v) => mix(COMET_TAIL, WHITE, v * v * 0.7), 0.9);
    if (phase !== 'over') yard.roofSplat(pos, WHITE, 1.1, 1);
    else yard.roofSplat(missAt, COLORS.bad, 2 + phaseTime * 10, Math.max(0, 1 - phaseTime));
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
        const sparkle = 0.75 + 0.25 * Math.sin(clock * 7 + i * 2.3);
        // Every catch flashes the bushes gold (a perfect one brighter and longer).
        const glint = sincePerfect < 0.5 ? 1 - sincePerfect / 0.5 : sinceCatch < 0.25 ? 0.5 * (1 - sinceCatch / 0.25) : 0;
        if (glint > 0) yard.add(b.offset + i, COLORS.gold, glint * 0.6);
        if (flashAll > 0) {
          const f = Math.max(0, Math.sin(clock * 14 + i));
          yard.add(b.offset + i, mix(color, COLORS.gold, f * 0.7), 0.5 + f * 0.5);
        } else if (u < filled) yard.add(b.offset + i, color, 0.65 * sparkle);
        else if (phase === 'running' && bi === next && litTarget[bi] < 1 && u < partial) yard.add(b.offset + i, color, 0.18);
        else yard.add(b.offset + i, BUSH_DARK);
      }
    });
  }

  function drawTree(part: Part) {
    // A speedometer: from the base up, hotter as the comet speeds up.
    const t = phase === 'running' ? (speed - startSpeed) / (maxSpeed - startSpeed) : 0;
    const level = Math.max(0.04, Math.min(1, 0.04 + t * 0.96));
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (u <= level) yard.add(part.offset + i, heat(u * 0.9), 0.6 + (u > level - 0.05 ? 0.3 : 0));
      else yard.add(part.offset + i, [0.02, 0.015, 0.04]);
      // A perfect catch: a gold flash that runs up the tree.
      if (sincePerfect < 0.6) {
        const d = u - sincePerfect / 0.5;
        if (Math.abs(d) < 0.15) yard.add(part.offset + i, COLORS.gold, 0.8 * (1 - Math.abs(d) / 0.15));
      }
    }
  }

  function drawDecor(part: Part) {
    const warm = phase === 'running' ? (speed - startSpeed) / (maxSpeed - startSpeed) : 0;
    for (let i = 0; i < part.count; i++) {
      yard.add(part.offset + i, NIGHT, 1.5);
      yard.add(part.offset + i, heat(0.2 + warm * 0.4), warm * 0.25);
      yard.add(part.offset + i, flare.color, 1);
    }
  }

  function step(dt: number) {
    if (phase === 'running') {
      const move = speed * dt;
      ({ pos, dir } = bounce(pos, dir, move, n));
      toGo -= move;
      seen.push(clock, toGo);
      // All the way through the gate, and past the grace for a late press: the run is over.
      if (toGo < -halfWidth - speed * GRACE - 0.5) gameOver(pos);
    } else if (phase === 'ready') {
      // The attract loop: the comet runs slowly through a gate in the middle.
      gate = n / 2;
      halfWidth = startHalf;
      ({ pos, dir } = bounce(pos, dir, (n / 5) * dt, n));
    }
    if (phase === 'over' && phaseTime > 10) {
      reset();
      setPhase('ready');
    }
    sparks.update(dt);
    motes.update(dt);
    waves.update(dt);
    flare.update(dt);
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
    if (phase !== 'over') trail.mark(pos);
    lit.forEach((v, i) => (lit[i] = v + (litTarget[i] - v) * Math.min(1, dt * 2.5)));
  }

  reset();

  return {
    id: 'ricochet',

    input,

    update(dt: number, frame: Frame) {
      clock += dt;
      phaseTime += dt;
      yard.begin(frame);
      if (!playable) return;
      step(dt);
      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      for (const d of yard.decor) drawDecor(d);
      if (phase === 'over') {
        if (phaseTime < 0.6) yard.wash(COLORS.bad, 0.2 * (1 - phaseTime / 0.6));
        yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(phaseTime * 3)), 0.04);
      }
      motes.draw();
      waves.draw();
    },

    status(): GameStatusFields {
      const best = bestScore('ricochet');
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score: 0, lives: null, goal: null };
      const common = { score, lives: null, goal: null };
      switch (phase) {
        case 'ready':
          return { ...common, phase, message: 'Tap to start! Catch the comet in the green gate. It turns around every time.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'running':
          return {
            ...common,
            phase,
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
            phase,
            message: newBest ? `New best: ${score}!` : `Game over: ${score} points, ${catches} catches${perfects ? `, ${perfects} perfect` : ''}.`,
            button: phaseTime > 1.5 ? 'GO!' : '…',
            tone: phaseTime > 1.5 ? 'go' : 'bad',
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
