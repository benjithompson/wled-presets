import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import type { Game, GameInput } from './types.ts';

// Comet Catcher: a comet races along the roofline. Tap to stop it inside the glowing gate.
// Each catch fills the next bush with light; light every bush to win a yard-wide finale.

type Phase = 'ready' | 'running' | 'hit' | 'miss' | 'won' | 'over';

interface Spark {
  pos: number;
  vel: number;
  color: Rgb;
  life: number;
}

const LIVES = 3;
const GOAL_WITHOUT_BUSHES = 8;
/** Inputs this many seconds late still count, so Wi-Fi delay does not cost a kid a catch. */
const GRACE = 0.12;

const BUSH_COLORS: Rgb[] = [hsv(0.0), hsv(0.12), hsv(0.33), hsv(0.55), hsv(0.75), hsv(0.9)];
const COMET: Rgb = [0.55, 0.85, 1];
const GATE: Rgb = [0.15, 1, 0.45];
const RED: Rgb = [1, 0.06, 0.02];

export function catcherGame(stage: Stage): Game {
  // "The roof" is every roof object joined in strip order; gaps between runs are skipped.
  const path = stage.roofPath;
  const roof = path.length ? { corners: stage.roofCorners } : undefined;
  const bushes = stage.fixtures.filter((f) => f.kind === 'bush');
  const n = path.length;
  const goal = bushes.length || GOAL_WITHOUT_BUSHES;

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
  let score = 0;
  let lives = LIVES;
  let pos = 0;
  let dir = 1;
  let speed = 0;
  let gate = 0;
  let halfWidth = 0;
  let missAt = 0;
  const history: { t: number; pos: number }[] = [];
  const trail = new Float32Array(n);
  const sparks: Spark[] = [];
  /** 0..1 fill of each bush; colors are fixed per bush. */
  const lit = bushes.map(() => 0);
  const litTarget = bushes.map(() => 0);

  function reset() {
    score = 0;
    lives = LIVES;
    speed = n / 3.2;
    halfWidth = Math.max(5, Math.round(n * 0.04));
    pos = 0;
    dir = 1;
    lit.fill(0);
    litTarget.fill(0);
    placeGate();
  }

  function placeGate() {
    const margin = halfWidth + 4;
    const corners = (roof?.corners ?? []).filter((c) => c > margin && c < n - margin);
    for (let tries = 0; tries < 20; tries++) {
      const atCorner = corners.length > 0 && Math.random() < 0.6;
      const g = atCorner ? corners[Math.floor(Math.random() * corners.length)] : margin + Math.random() * (n - margin * 2);
      // Not right next to the comet, so every gate takes a little waiting.
      if (Math.abs(g - pos) > n * 0.2 || tries === 19) {
        gate = Math.round(g);
        return;
      }
    }
  }

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

  function burst(at: number, colors: Rgb[], count: number, power: number) {
    for (let i = 0; i < count; i++) {
      sparks.push({
        pos: at,
        vel: (Math.random() - 0.5) * 2 * power * (0.4 + Math.random()),
        color: colors[i % colors.length],
        life: 0.7 + Math.random() * 0.8
      });
    }
  }

  function inGate(): boolean {
    // Accept the press if the comet was in the gate at any moment in the grace window.
    return history.some((h) => clock - h.t <= GRACE && Math.abs(h.pos - gate) <= halfWidth);
  }

  function press() {
    if (!roof || n < 10) return;
    if (phase === 'ready' || phase === 'over') {
      reset();
      setPhase('running');
      return;
    }
    if (phase === 'won' && phaseTime > 2) {
      reset();
      setPhase('running');
      return;
    }
    if (phase !== 'running') return;
    if (inGate()) {
      score++;
      burst(gate, [hsv(Math.random()), WHITE, GATE], 46, n * 0.5);
      if (bushes.length) litTarget[score - 1] = 1;
      if (score >= goal) {
        setPhase('won');
        return;
      }
      speed = Math.min(n / 0.9, speed / 0.9);
      halfWidth = Math.max(3, Math.round(halfWidth * 0.88));
      setPhase('hit');
    } else {
      lives--;
      missAt = pos;
      burst(pos, [RED, [1, 0.3, 0]], 18, n * 0.15);
      setPhase(lives > 0 ? 'miss' : 'over');
    }
  }

  reset();

  return {
    id: 'catcher',

    input(e: GameInput) {
      if (e.action === 'press') press();
    },

    update(dt, frame) {
      clock += dt;
      phaseTime += dt;
      frame.clear();
      if (!roof || n < 10) return;
      const at = (i: number, color: Rgb, amount = 1) => {
        if (i >= 0 && i < n) frame.add(path[Math.floor(i)], color, amount);
      };
      const splat = (p: number, color: Rgb, width = 1.5, amount = 1) => {
        const lo = Math.max(0, Math.floor(p - width * 2));
        const hi = Math.min(n - 1, Math.ceil(p + width * 2));
        for (let i = lo; i <= hi; i++) at(i, color, Math.exp(-(((i - p) / width) ** 2)) * amount);
      };

      // Comet motion.
      if (phase === 'running') {
        pos += dir * speed * dt;
        if (pos >= n - 1) {
          pos = n - 1 - (pos - (n - 1));
          dir = -1;
        } else if (pos <= 0) {
          pos = -pos;
          dir = 1;
        }
        history.push({ t: clock, pos });
        while (history.length && clock - history[0].t > 0.3) history.shift();
      }
      if (phase === 'hit' && phaseTime > 0.9) {
        placeGate();
        setPhase('running');
      }
      if (phase === 'miss' && phaseTime > 1.3) setPhase('running');
      if (phase === 'over' && phaseTime > 4) setPhase('ready');

      // Roof base glow.
      for (let i = 0; i < n; i++) at(i, [0.06, 0.035, 0.02]);

      // Gate: dim fill with bright posts that breathe.
      if (phase !== 'won') {
        const flashRed = (phase === 'miss' || phase === 'over') && Math.floor(phaseTime * 6) % 2 === 0;
        const color = flashRed ? RED : GATE;
        const breathe = 0.6 + 0.4 * Math.sin(clock * 6);
        for (let i = gate - halfWidth; i <= gate + halfWidth; i++) at(i, color, 0.14 + 0.08 * breathe);
        splat(gate - halfWidth, color, 1, 0.9 * breathe + 0.3);
        splat(gate + halfWidth, color, 1, 0.9 * breathe + 0.3);
      }

      // Comet: bright head and a fading trail.
      const k = Math.exp(-dt * (phase === 'running' ? 9 : 3));
      for (let i = 0; i < n; i++) trail[i] *= k;
      if (phase === 'running' || phase === 'hit') {
        const lo = Math.max(0, Math.floor(pos - 2));
        const hi = Math.min(n - 1, Math.ceil(pos + 2));
        for (let i = lo; i <= hi; i++) trail[i] = Math.max(trail[i], Math.exp(-((i - pos) ** 2) / 1.5));
      }
      if (phase === 'ready') {
        splat(0, COMET, 1.5, 0.5 + 0.5 * Math.sin(clock * 4));
      }
      for (let i = 0; i < n; i++) if (trail[i] > 0.01) at(i, mix(COMET, WHITE, trail[i] * 0.6), trail[i]);
      if (phase === 'miss' || phase === 'over') {
        splat(missAt, RED, 2 + phaseTime * 10, Math.max(0, 1 - phaseTime));
      }

      // Sparks fly along the roof and fade.
      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.life -= dt;
        s.pos += s.vel * dt;
        s.vel *= Math.exp(-dt * 2.2);
        if (s.life <= 0 || s.pos < 0 || s.pos >= n) {
          sparks.splice(i, 1);
          continue;
        }
        splat(s.pos, s.color, 1, Math.min(1, s.life * 1.5));
      }

      // Bushes: each catch fills one bush with its color, from the middle out, with sparkle.
      bushes.forEach((b, bi) => {
        lit[bi] += (litTarget[bi] - lit[bi]) * Math.min(1, dt * 2.5);
        const color = BUSH_COLORS[bi % BUSH_COLORS.length];
        const filled = lit[bi] * b.count;
        for (let i = 0; i < b.count; i++) {
          const sparkle = 0.75 + 0.25 * Math.sin(clock * 7 + i * 2.3);
          if (i < filled) frame.add(b.offset + i, color, 0.65 * sparkle);
          else frame.add(b.offset + i, [0.02, 0.05, 0.02]);
        }
      });

      // Finale: fireworks on the roof and rainbow bushes.
      if (phase === 'won') {
        if (Math.random() < dt * 6) burst(Math.random() * n, [hsv(Math.random()), hsv(Math.random()), WHITE], 30, n * 0.4);
        bushes.forEach((b, bi) => {
          for (let i = 0; i < b.count; i++) frame.add(b.offset + i, hsv((clock * 0.3 + i / b.count + bi * 0.2) % 1), 0.5);
        });
        if (phaseTime > 9) {
          reset();
          setPhase('ready');
        }
      }
    },

    status() {
      if (!roof || n < 10) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score, lives, goal };
      const message: Record<Phase, string> = {
        ready: 'Tap to start!',
        running: 'Stop the comet in the green gate!',
        hit: bushes.length ? 'Got it! A bush lights up!' : 'Got it!',
        miss: lives === 1 ? 'So close! Last try!' : 'So close! Try again!',
        won: 'You lit up the whole yard!',
        over: 'Good try! Tap to play again.'
      };
      return { phase, message: message[phase], score, lives, goal };
    }
  };
}
