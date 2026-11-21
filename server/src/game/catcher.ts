import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Rgb } from '../../../shared/color.ts';
import { bounce, COLORS, Motes, Recent, Sparks, Trail, Yard, type Part } from './kit.ts';
import { overMood, Show, type Mood } from './show.ts';
import { Round } from './round.ts';
import type { Game, GameInput } from './types.ts';

// Comet Catcher: a comet races along the roofline. Tap to stop it inside the glowing gate, which
// slowly closes in while you wait.
// Each catch sends a streak of light down into the next bush, which fills with color; light
// every bush to win a yard-wide finale.
//
// The whole yard is a light show around the game (see Show): a cool blue mood that warms up
// with every catch, a firework for each catch and a burst of color in its bush when the streak
// lands, red explosions for a miss, a red throbbing yard on the last life, and a firework finale
// for a full yard. The trees fill from the base up in gold as the catches add up. While the comet
// runs, the show stays off the roof, so the comet is the only white there.

type Phase = 'ready' | 'running' | 'hit' | 'miss' | 'won' | 'over';

const LIVES = 3;
const GOAL_WITHOUT_BUSHES = 8;
/** Inputs this many seconds late still count, so Wi-Fi delay does not cost a kid a catch. */
const GRACE = 0.12;
/** How long the streak takes from the gate to its bush, in seconds. */
const STREAK = 0.55;
/** While the comet runs, the gate closes in by this share of its starting width each second… */
const SHRINK = 0.05;
/** …down to this share of it (and never under two LEDs either side). */
const SMALLEST = 0.4;

const BUSH_COLORS: Rgb[] = [hsv(0.0), hsv(0.12), hsv(0.33), hsv(0.55), hsv(0.75), hsv(0.9)];
const COMET: Rgb = [0.55, 0.85, 1];
const GATE: Rgb = [0.15, 1, 0.45];
const RED: Rgb = [1, 0.06, 0.02];

export function catcherGame(stage: Stage): Game {
  // "The roof" is every roof object joined in strip order, measured as it looks from the street,
  // so the comet crosses the front of the house at an even speed (see Roof).
  const yard = new Yard(stage);
  const { roof, bushes } = yard;
  const n = roof.n;
  const playable = n >= 10;
  const goal = bushes.length || GOAL_WITHOUT_BUSHES;
  const sparks = new Sparks(roof, 0, 2.2);
  const motes = new Motes(yard);
  const trail = new Trail(n);
  /** Where the comet was lately: a press is judged by what the player saw. */
  const seen = new Recent<number>(0.3);
  const show = new Show(yard);
  for (const t of yard.trees) show.dim(t, 0.45);
  show.roofLevel = 0.5;
  /** The mood now (set every frame), for the roof's own backdrop. */
  let mood: Mood = { a: [0, 0, 0], b: [0, 0, 0] };
  /** The trees' gold, following the score. */
  let treeLevel = 0;

  const round = new Round<Phase>('catcher', 'ready', { resetAfter: 4 });
  let score = 0;
  let lives = LIVES;
  let pos = 0;
  let dir = 1;
  let speed = 0;
  let gate = 0;
  /** How wide each new gate starts (half of it): narrower after every catch. */
  let startHalf = 0;
  /** How wide the gate is now: it closes in while the comet runs. */
  let halfWidth = 0;
  let missAt = 0;
  /** 0..1 fill of each bush (left to right); it follows litTarget. */
  const lit = bushes.map(() => 0);
  const litTarget = bushes.map(() => 0);

  function reset() {
    score = 0;
    lives = LIVES;
    speed = n / 3.2;
    startHalf = Math.max(5, Math.round(n * 0.04));
    halfWidth = startHalf;
    pos = 0;
    dir = 1;
    lit.fill(0);
    litTarget.fill(0);
    motes.clear();
    placeGate();
  }

  /**
   * The yard's mood: a slow rainbow while it waits; cool blue at the start of a game, warming
   * through violet and magenta to gold with every catch; red and throbbing on the last life;
   * dark red after the end; a fast rainbow for a full yard.
   */
  function moodNow(): Mood {
    if (round.phase === 'ready') return { a: hsv(round.clock * 0.04), b: hsv(round.clock * 0.04 + 0.3), level: 0.9, drift: 1.4 };
    if (round.phase === 'won') return { a: hsv(round.clock * 0.3), b: hsv(round.clock * 0.3 + 0.5), level: 1.4, drift: 2.5 };
    if (round.phase === 'over') return overMood(round.time);
    const t = Math.max(0, Math.min(1, score / Math.max(1, goal - 1)));
    const a = t < 0.5 ? mix([0.05, 0.3, 0.9], [0.55, 0.1, 0.9], t * 2) : mix([0.55, 0.1, 0.9], [1, 0.55, 0.05], t * 2 - 1);
    const b = t < 0.5 ? mix([0.25, 0.1, 0.8], [1, 0.1, 0.6], t * 2) : mix([1, 0.1, 0.6], [1, 0.25, 0.1], t * 2 - 1);
    if (lives === 1) return { a: RED, b: mix(a, RED, 0.6), level: 1.1, throb: 1.5 };
    return { a, b, level: 0.9 + 0.4 * t, drift: 1 + t };
  }

  function placeGate() {
    halfWidth = startHalf;
    const margin = startHalf + 4;
    const corners = roof.corners.filter((c) => c > margin && c < n - margin);
    for (let tries = 0; tries < 20; tries++) {
      const atCorner = corners.length > 0 && Math.random() < 0.6;
      const g = atCorner ? corners[Math.floor(Math.random() * corners.length)] : margin + Math.random() * (n - margin * 2);
      // Not right next to the comet, so every gate takes a little waiting, and where it can be
      // seen from the street (the comet hurries through the rest).
      if ((Math.abs(g - pos) > n * 0.2 && !roof.hiddenAt(g)) || tries === 19) {
        gate = Math.round(g);
        return;
      }
    }
  }

  function start() {
    reset();
    round.to('running');
    show.clear();
    treeLevel = 0;
    show.setMood(moodNow(), { wipe: roof.startsLeft ? 'right' : 'left' });
  }

  /** The catch flies from the gate into the next bush, which then fills. */
  function lightBush(index: number) {
    const bush = bushes[index];
    const color = BUSH_COLORS[index % BUSH_COLORS.length];
    motes.fly(roof.point(gate), yard.topOf(bush), mix(color, WHITE, 0.4), STREAK, {
      arc: 40,
      size: 28,
      arrive: () => {
        litTarget[index] = 1;
        // The bush bursts into its color, and the color sweeps up the house.
        show.explode(bush.x, bush.top, color, { size: 0.8 });
        show.sweep(color, { dir: 'up', amount: 0.5 });
      }
    });
  }

  function press() {
    if (!playable) return;
    if (round.phase === 'ready' || round.phase === 'over' || (round.phase === 'won' && round.time > 2)) return start();
    if (round.phase !== 'running') return;
    // Accept the press if the comet was in the gate at any moment in the grace window.
    if (seen.since(round.clock - GRACE).some((p) => Math.abs(p - gate) <= halfWidth)) {
      score++;
      sparks.burst(gate, [hsv(Math.random()), WHITE, GATE], 46, n * 0.5);
      if (bushes.length) lightBush(score - 1);
      const color = BUSH_COLORS[(score - 1) % BUSH_COLORS.length];
      show.pulse(COLORS.gold, 0.12);
      const p = roof.point(gate);
      show.ripple(p.x, p.y, COLORS.gold, { amount: 0.5 });
      show.rocket([color, COLORS.gold], { size: 0.9 });
      if (score >= goal) {
        // A full yard: a volley of fireworks across the house, and a rainbow sweep.
        show.finale(8);
        show.sweep(COLORS.gold, { dir: 'up', amount: 0.8, duration: 1 });
        return round.to('won');
      }
      speed = Math.min(n / 0.9, speed / 0.9);
      startHalf = Math.max(3, Math.round(startHalf * 0.88));
      round.to('hit');
    } else {
      lives--;
      missAt = pos;
      sparks.burst(pos, [RED, COLORS.ember], 18, n * 0.15);
      const p = roof.point(pos);
      if (lives > 0) {
        show.explode(p.x, p.y, RED, { size: 1.6 });
        show.sweep(RED, { dir: 'down', amount: 0.6, duration: 0.7 });
        show.pulse(RED, 0.25);
      } else {
        // Out of lives: the house blows, and the yard goes dark red.
        show.gameOver(p.x, p.y, { color: RED });
      }
      round.to(lives > 0 ? 'miss' : 'over');
    }
  }

  function step(dt: number) {
    if (round.phase === 'running') {
      ({ pos, dir } = bounce(pos, dir, speed * dt, n));
      seen.push(round.clock, pos);
      halfWidth = Math.max(Math.max(2, startHalf * SMALLEST), halfWidth - startHalf * SHRINK * dt);
    }
    if (round.phase === 'hit' && round.time > 0.9) {
      placeGate();
      round.to('running');
    }
    if (round.phase === 'miss' && round.time > 1.3) {
      // A fresh try: the gate opens back up.
      halfWidth = startHalf;
      round.to('running');
    }
    if (round.timedOut) round.to('ready');
    if (round.phase === 'won' && round.time > 9) {
      reset();
      round.to('ready');
    }
    sparks.update(dt);
    motes.update(dt);
    show.update(dt);
    mood = moodNow();
    if (round.settled) show.followMood(mood, 2, dt);
    // While the comet runs (or waits after a catch or a miss), the show keeps off the roof.
    const busy = round.phase === 'running' || round.phase === 'hit' || round.phase === 'miss';
    show.roofShare = busy ? 0 : Math.min(1, show.roofShare + dt * 2);
    // Now and then a firework while waiting, to draw a crowd; a steady volley for a full yard.
    if (round.phase === 'ready' && Math.random() < dt * 0.35) show.rocket([hsv(Math.random()), hsv(Math.random())], { size: 0.8 });
    if (round.phase === 'won' && round.time < 7 && Math.random() < dt * 3) show.rocket([hsv(Math.random()), hsv(Math.random()), COLORS.gold], { size: 1.1 });
    treeLevel += (score / goal - treeLevel) * Math.min(1, dt * 3);
    trail.fade(dt, round.phase === 'running' ? 9 : 3);
    if (round.phase === 'running' || round.phase === 'hit') trail.mark(pos);
    lit.forEach((v, i) => (lit[i] = v + (litTarget[i] - v) * Math.min(1, dt * 2.5)));
  }

  function drawRoof() {
    // The roof's faint backdrop in the mood's colors, drifting along it (too dim to look white or
    // green), and not under the comet's tail. Waiting or after the end, the show lights the roof.
    const k = round.phase === 'running' || round.phase === 'hit' || round.phase === 'miss' ? 0.05 * (mood.level ?? 1) : 0;
    if (k) for (let i = 0; i < n; i++) yard.roofAt(i, mix(mood.a, mood.b, 0.5 + 0.5 * Math.sin(i * 0.06 - round.clock * 0.8)), k * Math.max(0, 1 - trail.level[i] * 10));
    // The gate: a dim fill between bright posts that breathe; red after a miss.
    if (round.phase !== 'won') {
      const flashRed = (round.phase === 'miss' || round.phase === 'over') && Math.floor(round.time * 6) % 2 === 0;
      const color = flashRed ? RED : GATE;
      const breathe = 0.6 + 0.4 * Math.sin(round.clock * 6);
      for (let i = Math.ceil(gate - halfWidth); i <= gate + halfWidth; i++) yard.roofAt(i, color, 0.14 + 0.08 * breathe);
      yard.roofSplat(gate - halfWidth, color, 1, 0.9 * breathe + 0.3);
      yard.roofSplat(gate + halfWidth, color, 1, 0.9 * breathe + 0.3);
    }
    // The comet: a bright head with a blue-white tail.
    if (round.phase === 'ready') yard.roofSplat(0, COMET, 1.5, 0.5 + 0.5 * Math.sin(round.clock * 4));
    trail.draw(yard, (v) => mix(COMET, WHITE, v * 0.6));
    if (round.phase === 'miss' || round.phase === 'over') yard.roofSplat(missAt, RED, 2 + round.time * 10, Math.max(0, 1 - round.time));
    sparks.draw(yard);
  }

  function drawBushes() {
    // Each catch fills one bush with its color, from the middle out, with sparkle.
    bushes.forEach((b, bi) => {
      const color = BUSH_COLORS[bi % BUSH_COLORS.length];
      const filled = lit[bi] * b.count;
      for (let i = 0; i < b.count; i++) {
        const sparkle = 0.75 + 0.25 * Math.sin(round.clock * 7 + i * 2.3);
        if (i < filled) yard.add(b.offset + i, color, 0.65 * sparkle);
      }
    });
    motes.draw();
  }

  /** The trees: the catches so far, gold from the base up, the top LED of the fill twinkling. */
  function drawTree(part: Part) {
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (u <= treeLevel) yard.add(part.offset + i, COLORS.gold, 0.55 + (u > treeLevel - 0.05 ? 0.3 * Math.sin(round.clock * 10) : 0));
    }
  }

  function drawFinale(dt: number) {
    // Fireworks on the roof and rainbow bushes.
    if (Math.random() < dt * 6) sparks.burst(Math.random() * n, [hsv(Math.random()), hsv(Math.random()), WHITE], 30, n * 0.4);
    bushes.forEach((b, bi) => {
      for (let i = 0; i < b.count; i++) yard.add(b.offset + i, hsv((round.clock * 0.3 + i / b.count + bi * 0.2) % 1), 0.5);
    });
  }

  reset();

  return {
    id: 'catcher',

    input(e: GameInput) {
      if (e.action === 'press') press();
    },

    update(dt, frame) {
      round.tick(dt);
      yard.begin(frame);
      if (!playable) return;
      step(dt);
      drawRoof();
      drawBushes();
      if (round.phase !== 'won') for (const t of yard.trees) drawTree(t);
      if (round.phase === 'won') drawFinale(dt);
      show.draw(frame);
    },

    status() {
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score, lives, goal };
      const message: Record<Phase, string> = {
        ready: 'Tap to start!',
        running: 'Stop the comet in the green gate before it closes in!',
        hit: bushes.length ? 'Got it! A bush lights up!' : 'Got it!',
        miss: lives === 1 ? 'So close! Last try!' : 'So close! Try again!',
        won: 'You lit up the whole yard!',
        over: 'Good try! Tap to play again.'
      };
      return { phase: round.phase, message: message[round.phase], score, lives, goal };
    }
  };
}
