import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, bounce, COLORS, Flare, heat, Motes, Recent, record, scale, Sparks, spreadHue, Waves, Yard, type Part } from './kit.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Cascade: glowing orbs of every color roll along the roofline under real gravity: they speed up
// down the slopes, slow down climbing, and bounce off each other and the ends. A white spark
// sweeps the roof; one tap sets off a blast there. Every orb the blast touches bursts in its own
// color and sets off the orbs it touches: pop enough of them in one chain reaction to clear the
// level.
//
// The yard: each popped orb drips its color off the gutter, past the windows, into the bush
// below, so the bushes fill up with a picture of the chain (full bushes: the target is reached).
// Trees fill up like a thermometer as the chain grows. Windows and doors flash with every burst.

type Phase = 'ready' | 'aim' | 'chain' | 'clear' | 'fail' | 'over';

interface Orb {
  pos: number;
  vel: number;
  hue: number;
  color: Rgb;
  /** Gold: worth more, and a bigger blast. */
  gold: boolean;
  /** Armored orbs need two different blasts. */
  armor: boolean;
  hits: Set<number>;
  /** Seconds since it appeared, for the arrival flash. */
  age: number;
}

interface Blast {
  id: number;
  pos: number;
  color: Rgb;
  radius: number;
  t: number;
  player: boolean;
}

interface Paint {
  color: Rgb;
  /** Seconds since it landed: a fresh drop flashes. */
  age: number;
}

const LIVES = 3;
/** How long a blast lasts, in seconds: it grows, holds, then shrinks away. */
const GROW = 0.18;
const HOLD = 1.05;
const END = 1.35;
/** A press counts where the spark was this long ago: the phone and Wi-Fi are a little late. */
const LAG = 0.08;
const ORB_RADIUS = 1.4;
const NIGHT: Rgb = [0.025, 0.008, 0.05];

export function cascadeGame(stage: Stage): Game {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= 30;
  const sparks = new Sparks(roof, n * 0.12, 1.6);
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const decorFlare = new Flare(3.5);
  const bushPaint: (Paint | null)[][] = yard.bushes.map((b) => Array.from({ length: b.count }, () => null));
  const bushNext = yard.bushes.map(() => 0);

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
  let level = 1;
  let lives = LIVES;
  let score = 0;
  let chain = 0;
  let longest = 0;
  let target = 0;
  let orbs: Orb[] = [];
  let blasts: Blast[] = [];
  let blastId = 0;
  let cursor = 0;
  let cursorDir = 1;
  let quietFor = 0;
  let newBest = false;
  /** Where the spark was lately: a tap sets off the blast where the player saw it. */
  const seen = new Recent<number>(0.4);
  /** The tree meter, smoothed. */
  let meter = 0;

  const orbCount = (lv: number) => Math.max(4, Math.min(Math.floor(n / 14), 6 + lv * 3));
  const targetFor = (lv: number, count: number) => Math.ceil(count * Math.min(0.85, 0.35 + lv * 0.07));
  const blastRadius = (lv: number) => Math.max(5, n * Math.max(0.022, 0.044 - lv * 0.0025));
  const sweepSpeed = (lv: number) => n / Math.max(1.6, 2.9 - lv * 0.12);
  const gravity = n * 0.18;
  const maxSpeed = n * 0.33;

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

  function spawn(lv: number, demo = false) {
    const count = demo ? Math.min(orbCount(3), 14) : orbCount(lv);
    target = targetFor(lv, count);
    orbs = [];
    blasts = [];
    chain = 0;
    meter = 0;
    const goldAt = lv >= 3 && !demo ? Math.floor(Math.random() * count) : -1;
    for (let i = 0; i < count; i++) {
      let pos = 0;
      for (let tries = 0; tries < 30; tries++) {
        pos = 3 + Math.random() * (n - 6);
        if (orbs.every((o) => Math.abs(o.pos - pos) > 5)) break;
      }
      const hue = spreadHue(i + lv * 3);
      const gold = i === goldAt;
      const speed = n * (0.04 + Math.random() * 0.08) * (1 + lv * 0.05);
      orbs.push({
        pos,
        vel: (Math.random() < 0.5 ? -1 : 1) * speed,
        hue,
        color: gold ? COLORS.gold : hsv(hue),
        gold,
        armor: !gold && lv >= 5 && !demo && i % 4 === 1,
        hits: new Set(),
        age: -i * 0.05
      });
    }
    // A fresh canvas in the bushes for each try.
    for (const p of bushPaint) p.fill(null);
    bushNext.fill(0);
    cursor = Math.random() < 0.5 ? 0 : n - 1;
    cursorDir = cursor === 0 ? 1 : -1;
    seen.clear();
  }

  function newGame() {
    level = 1;
    lives = LIVES;
    score = 0;
    longest = 0;
    newBest = false;
    sparks.clear();
    motes.clear();
    waves.clear();
    spawn(level);
    setPhase('aim');
  }

  const cursorAt = (t: number) => seen.at(t) ?? cursor;

  function detonate(pos: number, color: Rgb, player: boolean, radius: number) {
    blasts.push({ id: blastId++, pos, color, radius, t: 0, player });
    const p = roof.point(pos);
    if (player) {
      sparks.burst(pos, [WHITE, [0.7, 0.8, 1]], 30, n * 0.35, 0.9);
      waves.add(p.x, p.y, [0.6, 0.7, 1], { amount: 0.5 });
      decorFlare.add(WHITE, 0.6);
    }
  }

  function paintBush(x: number, y: number, color: Rgb) {
    const bush = yard.nearest(yard.bushes, x);
    if (!bush) return;
    const bi = yard.bushes.indexOf(bush);
    // Drip off the gutter and fall into the bush, past whatever hangs in between.
    motes.dropTo(x, y + 10, bush.x + (Math.random() - 0.5) * (bush.right - bush.left) * 0.5, bush.top + (bush.bottom - bush.top) * 0.3, color, {
      lift: yard.stage.scale * 1.2,
      size: 26,
      land: () => {
        // Each drop fills its share: the bushes are full when the target is reached.
        const per = Math.max(1, Math.ceil((bush.count * yard.bushes.length) / Math.max(1, target)));
        for (let k = 0; k < per; k++) {
          const at = bush.bottomUp[bushNext[bi] % bush.count];
          bushPaint[bi][at] = { color: mix(color, hsv(Math.random()), 0.08), age: 0 };
          bushNext[bi]++;
        }
      }
    });
  }

  function pop(o: Orb, by: Blast) {
    orbs = orbs.filter((x) => x !== o);
    chain++;
    longest = Math.max(longest, chain);
    score += chain + (o.gold ? 10 : 0);
    const p = roof.point(o.pos);
    detonate(o.pos, o.color, false, blastRadius(level) * (o.gold ? 1.7 : 1));
    sparks.burst(o.pos, [o.color, mix(o.color, WHITE, 0.5), by.color], o.gold ? 50 : 22, n * (o.gold ? 0.45 : 0.25), o.gold ? 1.4 : 1);
    decorFlare.add(o.color, o.gold ? 1.2 : 0.45);
    if (o.gold) waves.add(p.x, p.y, COLORS.gold, { amount: 1 });
    else if (chain % 5 === 0) waves.add(p.x, p.y, o.color, { amount: 0.8 });
    paintBush(p.x, p.y, o.color);
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    if (phase === 'aim') {
      const pos = cursorAt(clock - LAG);
      detonate(pos, WHITE, true, blastRadius(level));
      setPhase('chain');
      return;
    }
    if ((phase === 'clear' || phase === 'fail') && phaseTime > 1.2) next();
  }

  function next() {
    if (phase === 'clear') level++;
    sparks.clear();
    spawn(level);
    setPhase('aim');
  }

  function judge() {
    if (chain >= target) {
      score += (chain - target) * 2;
      setPhase('clear');
      // The bushes erupt, the roof answers with fireworks.
      for (const b of yard.bushes) waves.add(b.x, b.top, COLORS.gold, { amount: 0.9 });
      newBest = record('cascade', score).isNew || newBest;
    } else {
      lives--;
      // What is left fizzles and falls off the gutter.
      for (const o of orbs) {
        const p = roof.point(o.pos);
        motes.drop(p.x, p.y, mix(o.color, COLORS.bad, 0.6), { vx: (Math.random() - 0.5) * 60, size: 20 });
      }
      orbs = [];
      if (lives <= 0) {
        newBest = record('cascade', score).isNew;
        setPhase('over');
      } else setPhase('fail');
    }
  }

  // ---------- Physics ----------

  function stepOrbs(dt: number) {
    for (const o of orbs) {
      o.age += dt;
      if (o.age < 0) continue;
      o.vel -= gravity * roof.slopeAt(o.pos) * dt;
      o.vel *= Math.exp(-dt * 0.06);
      // Keep every orb moving, so the roof never goes still.
      if (Math.abs(o.vel) < n * 0.02) o.vel += (o.vel >= 0 ? 1 : -1) * n * 0.04 * dt;
      o.vel = Math.max(-maxSpeed, Math.min(maxSpeed, o.vel));
      o.pos += o.vel * dt;
      if (o.pos < ORB_RADIUS) {
        o.pos = 2 * ORB_RADIUS - o.pos;
        o.vel = Math.abs(o.vel);
      } else if (o.pos > n - 1 - ORB_RADIUS) {
        o.pos = 2 * (n - 1 - ORB_RADIUS) - o.pos;
        o.vel = -Math.abs(o.vel);
      }
    }
    // Elastic collisions between neighbours: equal masses swap their speeds.
    const live = orbs.filter((o) => o.age >= 0).sort((a, b) => a.pos - b.pos);
    for (let i = 0; i + 1 < live.length; i++) {
      const a = live[i];
      const b = live[i + 1];
      const gap = b.pos - a.pos;
      if (gap < ORB_RADIUS * 2 && a.vel > b.vel) {
        const va = a.vel;
        a.vel = b.vel * 0.97;
        b.vel = va * 0.97;
        const push = (ORB_RADIUS * 2 - gap) / 2;
        a.pos -= push;
        b.pos += push;
      }
    }
  }

  const blastSize = (b: Blast) => (b.t < GROW ? b.radius * (b.t / GROW) ** 0.6 : b.t < HOLD ? b.radius : b.radius * Math.max(0, 1 - (b.t - HOLD) / (END - HOLD)));

  function stepBlasts(dt: number) {
    for (const b of blasts) b.t += dt;
    blasts = blasts.filter((b) => b.t < END);
    for (const b of [...blasts]) {
      const r = blastSize(b) + ORB_RADIUS;
      for (const o of [...orbs]) {
        if (!orbs.includes(o) || o.age < 0 || Math.abs(o.pos - b.pos) > r || o.hits.has(b.id)) continue;
        o.hits.add(b.id);
        if (o.armor && o.hits.size < 2) {
          // Cracked: it flashes white and slows down; the next blast pops it.
          sparks.burst(o.pos, [WHITE], 8, n * 0.1, 0.5);
          o.vel *= 0.5;
          continue;
        }
        pop(o, b);
      }
    }
  }

  // ---------- Drawing ----------

  function drawRoof() {
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT, 1 + 0.4 * Math.sin(clock * 0.7 + i * 0.05));
    for (const b of blasts) {
      const r = blastSize(b);
      const life = b.t < HOLD ? 1 : Math.max(0, 1 - (b.t - HOLD) / (END - HOLD));
      const core = b.t < 0.12 ? 1 - b.t / 0.12 : 0;
      const lo = Math.max(0, Math.floor(b.pos - r - 2));
      const hi = Math.min(n - 1, Math.ceil(b.pos + r + 2));
      for (let i = lo; i <= hi; i++) {
        const d = Math.abs(i - b.pos);
        if (d > r + 1.5) continue;
        // A glowing body with bright rims where it is still growing, and a white flash at first.
        const rim = Math.exp(-(((d - r) / 1.2) ** 2));
        const inside = d <= r ? 0.4 + 0.2 * Math.sin(clock * 20 + i * 1.7) : 0;
        yard.roofAt(i, b.color, (inside + rim) * life);
        // A white-hot edge while it grows.
        if (b.t < GROW * 2) yard.roofAt(i, WHITE, rim * 0.6);
        if (core) yard.roofAt(i, WHITE, core * Math.exp(-((d / 3) ** 2)));
      }
    }
    for (const o of orbs) {
      if (o.age < 0) continue;
      const arrive = o.age < 0.3 ? 1 - o.age / 0.3 : 0;
      const shimmer = 0.85 + 0.15 * Math.sin(clock * 9 + o.hue * 20);
      const color = arrive ? mix(o.color, WHITE, arrive) : o.armor && o.hits.size === 0 ? mix(o.color, WHITE, 0.35 + 0.25 * Math.sin(clock * 6)) : o.color;
      yard.roofSplat(o.pos, color, ORB_RADIUS, shimmer);
      yard.roofSplat(o.pos, o.color, 3.5, 0.12);
      if (o.gold && Math.random() < 0.3) yard.roofAt(o.pos + (Math.random() - 0.5) * 6, WHITE, 0.6);
      if (o.armor && o.hits.size) yard.roofSplat(o.pos, WHITE, 0.8, Math.random() < 0.5 ? 0.8 : 0.2);
    }
    if (phase === 'aim' || phase === 'ready') {
      // The spark, with faint marks where its blast would reach.
      const r = blastRadius(level);
      const pulse = 0.75 + 0.25 * Math.sin(clock * 12);
      yard.roofSplat(cursor, WHITE, 1.3, pulse);
      yard.roofSplat(cursor, [0.6, 0.7, 1], 4, 0.15);
      yard.roofSplat(cursor - r, [0.5, 0.6, 1], 0.8, 0.25 * pulse);
      yard.roofSplat(cursor + r, [0.5, 0.6, 1], 0.8, 0.25 * pulse);
    }
    sparks.draw(yard);
  }

  function drawBushes() {
    yard.bushes.forEach((b, bi) => {
      for (let i = 0; i < b.count; i++) {
        const p = bushPaint[bi][i];
        if (!p) {
          yard.add(b.offset + i, [0.02, 0.03, 0.06]);
          continue;
        }
        const fresh = p.age < 0.25 ? 1 - p.age / 0.25 : 0;
        const twinkle = phase === 'clear' ? 0.6 + 0.7 * Math.max(0, Math.sin(clock * 9 + i * 2.7)) : 0.55 + 0.1 * Math.sin(clock * 3 + i);
        yard.add(b.offset + i, mix(p.color, WHITE, fresh), twinkle + fresh);
      }
    });
  }

  function drawTrees(part: Part) {
    // A thermometer: the chain climbs the tree; it turns gold at the target.
    const t = target ? meter / target : 0;
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (u <= Math.min(1, t)) {
        const done = t >= 1;
        const c = done ? mix(COLORS.gold, WHITE, Math.max(0, Math.sin(clock * 8 + i * 1.7)) * 0.6) : heat(u * 0.85);
        yard.add(part.offset + i, c, done ? 0.9 : 0.6);
      } else yard.add(part.offset + i, [0.02, 0.015, 0.04]);
    }
  }

  function drawDecor(part: Part) {
    const c = decorFlare.color;
    const heatGlow = Math.min(1, chain / 12);
    for (let i = 0; i < part.count; i++) {
      yard.add(part.offset + i, NIGHT, 1.2);
      yard.add(part.offset + i, c, 1.1);
      if (heatGlow > 0.3) yard.add(part.offset + i, hsv((clock * 0.4 + i * 0.03) % 1), (heatGlow - 0.3) * 0.25);
    }
  }

  spawn(3, true);

  return {
    id: 'cascade',

    input,

    update(dt: number, frame: Frame) {
      clock += dt;
      phaseTime += dt;
      yard.begin(frame);
      if (!playable) return;

      const sweeping = phase === 'aim' || phase === 'ready';
      if (sweeping) {
        ({ pos: cursor, dir: cursorDir } = bounce(cursor, cursorDir, sweepSpeed(level) * dt, n));
        seen.push(clock, cursor);
      }
      if (phase !== 'over') stepOrbs(dt);
      stepBlasts(dt);
      sparks.update(dt);
      motes.update(dt);
      waves.update(dt);
      decorFlare.update(dt);
      meter += (chain - meter) * Math.min(1, dt * 6);
      for (const p of bushPaint) for (const x of p) if (x) x.age += dt;

      if (phase === 'chain') {
        quietFor = blasts.length ? 0 : quietFor + dt;
        if (quietFor > 0.35) judge();
      }
      if (phase === 'clear') {
        // Fireworks over the roof in the colors that were popped.
        if (Math.random() < dt * 5) {
          const colors = bushPaint.flat().filter((x): x is Paint => !!x).map((x) => x.color);
          sparks.burst(Math.random() * n, colors.length ? [colors[Math.floor(Math.random() * colors.length)], WHITE] : [hsv(Math.random()), WHITE], 26, n * 0.3);
        }
        if (phaseTime > 4) next();
      }
      if (phase === 'fail' && phaseTime > 5) next();
      if (phase === 'over' && phaseTime > 10) {
        spawn(3, true);
        setPhase('ready');
      }

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTrees(t);
      for (const d of yard.decor) drawDecor(d);
      if (phase === 'fail' && phaseTime < 0.6) yard.wash(COLORS.bad, 0.18 * (1 - phaseTime / 0.6));
      if (phase === 'over') yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(phaseTime * 3)), 0.05);
      motes.draw();
      waves.draw();
    },

    status(): GameStatusFields {
      const best = bestScore('cascade');
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score: 0, lives: null, goal: null };
      const stats = [
        { label: 'Level', value: level },
        { label: 'Score', value: score },
        { label: 'Best', value: Math.max(best, score) }
      ];
      const progress = { value: Math.min(chain, target), max: target };
      const common = { score, lives, goal: null, stats };
      switch (phase) {
        case 'ready':
          return { ...common, phase, lives: null, message: 'Tap to start! One tap sets off a blast: catch the orbs in a chain.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'aim':
          return { ...common, phase, progress, message: `Level ${level}: pop ${target} of ${orbs.length} orbs. Wait for them to bunch up…`, button: 'BOOM!', tone: 'go' };
        case 'chain':
          return { ...common, phase, progress, message: chain ? `Chain ×${chain}!` : 'Boom…', button: '…', tone: 'wait' };
        case 'clear':
          return { ...common, phase, progress, message: `Level ${level} cleared! Chain of ${chain}.`, button: 'NEXT', tone: 'good' };
        case 'fail':
          return { ...common, phase, progress, message: lives === 1 ? `${chain} of ${target}. Last try!` : `${chain} of ${target}. So close! Try again.`, button: 'AGAIN', tone: 'bad' };
        case 'over':
          return { ...common, phase, message: newBest ? `New best: ${score}!` : `Game over: ${score} points. Longest chain ${longest}.`, button: 'GO!', tone: 'go' };
      }
    }
  };
}
