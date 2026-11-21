import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, bounce, COLORS, Flare, heat, Motes, Recent, record, scale, Sparks, Waves, Yard, type Part, type Sink } from './kit.ts';
import { NIGHT_MOOD, overMood, Show, turnHue, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Cascade: glowing orbs in four colors roll along the roofline under real gravity: they speed up
// down the slopes, slow down climbing, and bounce off each other and the ends. The bomb, a white
// comet with a burning fuse for a tail, sweeps the roof, with the stretch its blast would cover
// lit faintly and the orbs in it glowing brighter; one tap sets it off (when the fuse burns down,
// it goes off by itself). Every orb the blast touches bursts in its own color and sets off the
// orbs it touches: pop enough of them in one chain reaction to clear the level. A burst that
// pops an orb of its own color is a combo: double points and a bigger blast. Popping every orb
// is a clean sweep: a bonus, and a life back.
//
// Colors mean one thing each: white is only ever the bomb (and the flash of a blast), the orbs
// are green, cyan, blue and magenta, gold is points, red is a miss.
//
// The yard: each popped orb drips its color off the gutter, past the windows, into the bush
// below, so the bushes fill up with a picture of the chain (full bushes: the target is reached).
// Trees fill up like a thermometer as the chain grows. Windows and doors flash with every burst.
//
// The whole yard plays along (see show.ts): calm blue while you aim, red and throbbing when the
// fuse runs low or on the last life; a chain heats it up, every pop pulses the house in the orb's
// color, combos and every fifth pop send up fireworks in their colors, reaching the target sweeps
// gold up the house, and a cleared level ends in a finale.

type Phase = 'ready' | 'aim' | 'chain' | 'clear' | 'fail' | 'over';

interface Orb {
  pos: number;
  vel: number;
  hue: number;
  /** Which of ORB_COLORS (gold orbs: -1). */
  tone: number;
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
  /** The color of the orb that burst (ORB_COLORS index); the bomb and gold orbs: null. */
  tone: number | null;
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
/**
 * The orbs' colors: few, far apart on real LEDs, and none of the colors that mean something
 * else (white: the bomb, gold: points, red: a miss).
 */
export const ORB_COLORS: Rgb[] = [
  [0.05, 1, 0.12],
  [0, 0.72, 1],
  [0.14, 0.08, 1],
  [1, 0, 0.7]
];
/** Seconds of fuse: then the bomb goes off where it is. */
export const FUSE = 12;
/** A combo (an orb popped by a burst of its own color) makes this much bigger a blast. */
const COMBO_BLAST = 1.35;

export function cascadeGame(stage: Stage): Game {
  const yard = new Yard(stage);
  /**
   * The orbs' light. Each orb is drawn by itself (`one`), and each LED shows the orb that is
   * brightest there (`orbLight`). Mixed, two colors side by side (green and pink, blue and
   * pink) would make white where they touch, and white is the bomb.
   */
  const orbLayer = () => ({ rgb: new Float32Array(stage.pixelCount * 3), lit: new Uint8Array(stage.pixelCount), list: [] as number[] });
  const one = orbLayer();
  const orbLight = orbLayer();
  const addOne: Sink = (i, [r, g, b], amount) => {
    const k = i * 3;
    if (!one.lit[i]) (one.lit[i] = 1), one.list.push(i);
    one.rgb[k] += r * amount;
    one.rgb[k + 1] += g * amount;
    one.rgb[k + 2] += b * amount;
  };
  /** Keeps the orb just drawn on the LEDs where it is the brightest, and clears it for the next. */
  const keepOne = () => {
    for (const i of one.list) {
      const k = i * 3;
      if (!orbLight.lit[i]) (orbLight.lit[i] = 1), orbLight.list.push(i);
      const mine = one.rgb[k] + one.rgb[k + 1] + one.rgb[k + 2];
      if (mine > orbLight.rgb[k] + orbLight.rgb[k + 1] + orbLight.rgb[k + 2]) orbLight.rgb.set(one.rgb.subarray(k, k + 3), k);
      one.rgb[k] = one.rgb[k + 1] = one.rgb[k + 2] = one.lit[i] = 0;
    }
    one.list.length = 0;
  };
  /** Puts the orbs' light in the frame. */
  const drawOrbLight = () => {
    for (const i of orbLight.list) {
      const k = i * 3;
      yard.add(i, [orbLight.rgb[k], orbLight.rgb[k + 1], orbLight.rgb[k + 2]]);
      orbLight.rgb[k] = orbLight.rgb[k + 1] = orbLight.rgb[k + 2] = orbLight.lit[i] = 0;
    }
    orbLight.list.length = 0;
  };
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= 30;
  const sparks = new Sparks(roof, n * 0.12, 1.6);
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const decorFlare = new Flare(3.5);
  const bushPaint: (Paint | null)[][] = yard.bushes.map((b) => Array.from({ length: b.count }, () => null));
  const bushNext = yard.bushes.map(() => 0);
  const show = new Show(yard);
  for (const t of yard.trees) show.dim(t, 0.45);
  for (const b of yard.bushes) show.dim(b, 0.6);
  /** The colors popped in this chain (for the yard's mood). */
  let chainColors: Rgb[] = [];

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
  /** Seconds of fuse left while aiming. */
  let fuse = FUSE;
  /** Combos in this chain. */
  let combos = 0;
  /** The last chain popped every orb. */
  let swept = false;
  let sweepBonus = 0;
  let lifeBack = false;
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
    chainColors = [];
    combos = 0;
    swept = false;
    lifeBack = false;
    fuse = FUSE;
    meter = 0;
    // The colors come round in turn from a random start, so each one has its share.
    const first = Math.floor(Math.random() * ORB_COLORS.length);
    const goldAt = lv >= 3 && !demo ? Math.floor(Math.random() * count) : -1;
    for (let i = 0; i < count; i++) {
      let pos = 0;
      for (let tries = 0; tries < 30; tries++) {
        pos = 3 + Math.random() * (n - 6);
        if (orbs.every((o) => Math.abs(o.pos - pos) > 5)) break;
      }
      const tone = (first + i) % ORB_COLORS.length;
      const hue = tone / ORB_COLORS.length;
      const gold = i === goldAt;
      const speed = n * (0.04 + Math.random() * 0.08) * (1 + lv * 0.05);
      orbs.push({
        pos,
        vel: (Math.random() < 0.5 ? -1 : 1) * speed,
        hue,
        tone: gold ? -1 : tone,
        color: gold ? COLORS.gold : ORB_COLORS[tone],
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
    show.clear();
    show.sweep(COLORS.hint, { dir: 'up', amount: 0.5 });
    spawn(level);
    setPhase('aim');
  }

  const cursorAt = (t: number) => seen.at(t) ?? cursor;

  function detonate(pos: number, color: Rgb, player: boolean, radius: number, tone: number | null = null) {
    blasts.push({ id: blastId++, pos, color, tone, radius, t: 0, player });
    const p = roof.point(pos);
    if (player) {
      sparks.burst(pos, [WHITE, [0.7, 0.8, 1]], 30, n * 0.35, 0.9);
      waves.add(p.x, p.y, [0.6, 0.7, 1], { amount: 0.5 });
      decorFlare.add(WHITE, 0.6);
      show.ripple(p.x, p.y, [0.6, 0.7, 1], { amount: 0.5 });
      show.pulse([0.6, 0.7, 1], 0.12);
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
    // A burst that pops an orb of its own color: a combo, worth double, with a bigger blast.
    const combo = by.tone != null && by.tone === o.tone;
    if (combo) combos++;
    score += chain * (combo ? 2 : 1) + (o.gold ? 10 : 0);
    const p = roof.point(o.pos);
    detonate(o.pos, o.color, false, blastRadius(level) * (o.gold ? 1.7 : combo ? COMBO_BLAST : 1), o.gold ? null : o.tone);
    sparks.burst(o.pos, [o.color, mix(o.color, WHITE, 0.5), by.color], o.gold ? 50 : combo ? 40 : 22, n * (o.gold ? 0.45 : combo ? 0.35 : 0.25), o.gold || combo ? 1.4 : 1);
    decorFlare.add(o.color, o.gold ? 1.2 : combo ? 0.9 : 0.45);
    if (o.gold) waves.add(p.x, p.y, COLORS.gold, { amount: 1 });
    else if (combo || chain % 5 === 0) waves.add(p.x, p.y, o.color, { amount: combo ? 1 : 0.8 });
    paintBush(p.x, p.y, o.color);
    chainColors.push(o.color);
    show.pulse(o.color, o.gold ? 0.2 : combo ? 0.12 : 0.06);
    if (o.gold) show.explode(p.x, p.y, COLORS.gold, { size: 1.2 });
    else if (combo || chain % 5 === 0) show.rocket([o.color, by.color], { size: 0.6 + Math.min(0.8, chain * 0.04), kind: combo ? 'ring' : 'peony' });
    // The target reached mid-chain: gold sweeps up the house.
    if (chain === target) {
      show.sweep(COLORS.gold, { dir: 'up', amount: 0.7 });
      show.pulse(COLORS.gold, 0.2);
    }
  }

  /** The bomb goes off where it was (a tap: where the player saw it). */
  function fire(pos: number) {
    detonate(pos, WHITE, true, blastRadius(level));
    setPhase('chain');
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    if (phase === 'aim') return fire(cursorAt(clock - LAG));
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
      // Every orb popped: a clean sweep, worth a bonus and a life back.
      swept = orbs.length === 0;
      if (swept) {
        sweepBonus = 10 * level;
        score += sweepBonus;
        lifeBack = lives < LIVES;
        lives = Math.min(LIVES, lives + 1);
      }
      setPhase('clear');
      // The bushes erupt, the roof answers with fireworks.
      for (const b of yard.bushes) waves.add(b.x, b.top, COLORS.gold, { amount: 0.9 });
      newBest = record('cascade', score).isNew || newBest;
      // A finale in the colors of the chain; a clean sweep gets a bigger one and a rainbow sweep.
      const popped = chainColors.length ? chainColors : ORB_COLORS;
      show.finale(swept ? 8 : 5, { colors: Array.from({ length: 4 }, (_, k) => [popped[(k * 3) % popped.length], k % 2 ? COLORS.gold : popped[(k * 3 + 1) % popped.length]]) });
      show.sweep(COLORS.gold, { dir: roof.startsLeft ? 'right' : 'left', amount: 0.7 });
      if (swept) show.sweep(hsv(clock * 0.2), { dir: 'out', amount: 0.8, duration: 1.2 });
    } else {
      lives--;
      // What is left fizzles and falls off the gutter.
      for (const o of orbs) {
        const p = roof.point(o.pos);
        motes.drop(p.x, p.y, mix(o.color, COLORS.bad, 0.6), { vx: (Math.random() - 0.5) * 60, size: 20 });
      }
      orbs = [];
      const mid = roof.point(n / 2);
      if (lives <= 0) {
        newBest = record('cascade', score).isNew;
        // The house blows, and the yard goes dark red (gold fireworks for a new best).
        show.gameOver(mid.x, mid.y, { newBest });
        setPhase('over');
      } else {
        show.explode(mid.x, mid.y, COLORS.bad, { size: 1.2 });
        show.sweep(COLORS.bad, { dir: 'down', amount: 0.6, duration: 0.7 });
        setPhase('fail');
      }
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
    const aiming = phase === 'aim' || phase === 'ready';
    const reach = blastRadius(level);
    for (const o of orbs) {
      if (o.age < 0) continue;
      const arrive = o.age < 0.2 ? 1 - o.age / 0.2 : 0;
      // Orbs the bomb would catch now glow brighter, with a wider halo.
      const aimed = aiming && Math.abs(o.pos - cursor) <= reach + ORB_RADIUS;
      const shimmer = (aimed ? 1.2 : 0.85) + 0.15 * Math.sin(clock * 9 + o.hue * 20);
      const cracked = o.armor && o.hits.size > 0;
      // A new orb arrives with a flash in its own color (not white: white is the bomb).
      yard.roof.splat(addOne, o.pos, o.color, ORB_RADIUS, (cracked ? shimmer * (Math.random() < 0.5 ? 1 : 0.35) : shimmer) + arrive);
      yard.roof.splat(addOne, o.pos, o.color, 3.5, aimed ? 0.3 : 0.12 + arrive * 0.4);
      // Armor: a shell of two dimmer dots in its own color; the first blast cracks it off.
      if (o.armor && !cracked) {
        yard.roof.splat(addOne, o.pos - 2.6, o.color, 0.7, 0.5);
        yard.roof.splat(addOne, o.pos + 2.6, o.color, 0.7, 0.5);
      }
      keepOne();
      if (o.gold && Math.random() < 0.3) yard.roofAt(o.pos + (Math.random() - 0.5) * 6, mix(COLORS.gold, WHITE, 0.4), 0.6);
    }
    drawOrbLight();
    if (aiming) drawBomb(reach);
    sparks.draw(yard);
  }

  /**
   * The bomb: the only white thing on the roof. A bright head, a tail of fuse behind it that
   * burns shorter, the stretch its blast would cover lit faintly with bright edges. In the last
   * seconds of the fuse it blinks fast.
   */
  function drawBomb(reach: number) {
    const left = phase === 'aim' ? Math.max(0, fuse / FUSE) : 1;
    const urgent = phase === 'aim' && fuse < 3;
    const blink = urgent ? (Math.sin(clock * 28) > 0 ? 1 : 0.2) : 0.85 + 0.15 * Math.sin(clock * 12);
    for (let i = Math.ceil(cursor - reach); i <= Math.floor(cursor + reach); i++) if (i >= 0 && i < n) yard.roofAt(i, COLORS.hint, 0.05);
    yard.roofSplat(cursor - reach, COLORS.hint, 0.7, 0.45 * blink);
    yard.roofSplat(cursor + reach, COLORS.hint, 0.7, 0.45 * blink);
    const tail = 3 + 10 * left;
    for (let k = 1; k <= tail; k++) {
      const at = cursor - cursorDir * k * 0.9;
      if (at < 0 || at > n - 1) break;
      const f = k / (tail + 1);
      // Burning: white near the head, fading to a flickering ember blue.
      yard.roofSplat(at, mix(WHITE, COLORS.hint, f), 0.65, 0.6 * (1 - f) ** 1.4 * (0.8 + 0.4 * Math.random()));
    }
    yard.roofSplat(cursor, WHITE, 1.15, blink);
    yard.roofSplat(cursor, COLORS.hint, 3.5, 0.18);
  }

  function drawBushes() {
    yard.bushes.forEach((b, bi) => {
      for (let i = 0; i < b.count; i++) {
        const p = bushPaint[bi][i];
        if (!p) continue;
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
      }
    }
  }

  /** The house: the show's canvas, with the flare of every burst. */
  function drawDecor(part: Part) {
    for (let i = 0; i < part.count; i++) yard.add(part.offset + i, decorFlare.color, 0.6);
  }


  /** The yard's mood from the game's state. */
  function moodNow(): Mood {
    const t = target ? Math.min(1.5, chain / target) : 0;
    switch (phase) {
      case 'ready':
        // Waiting: the orbs' colors drift round the house.
        return { a: ORB_COLORS[Math.floor(clock / 3) % ORB_COLORS.length], b: ORB_COLORS[(Math.floor(clock / 3) + 2) % ORB_COLORS.length], level: 1, drift: 1.4 };
      case 'aim': {
        // The fuse burning down, or the last life: red, throbbing faster as the fuse runs out.
        if (fuse < 3) return { a: COLORS.bad, b: [0.5, 0, 0.2], level: 1.1, throb: 3 };
        if (lives === 1) return { a: mix(NIGHT_MOOD.a, COLORS.bad, 0.45), b: NIGHT_MOOD.b, level: 0.9, throb: 0.8 };
        return { ...NIGHT_MOOD, level: 0.8 + 0.05 * Math.min(6, level) };
      }
      case 'chain': {
        // A chain heats the yard up, in the color of the last pop.
        const last = chainColors.at(-1) ?? NIGHT_MOOD.b;
        return { a: mix(NIGHT_MOOD.a, heat(0.3 + 0.45 * Math.min(1, t)), Math.min(1, t)), b: mix(NIGHT_MOOD.b, last, 0.7), level: 0.9 + 0.6 * Math.min(1, t), drift: 1 + t };
      }
      case 'clear':
        return { a: COLORS.gold, b: turnHue(chainColors.at(-1) ?? ORB_COLORS[1], 0), level: 1.4, drift: 1.8 };
      case 'fail':
        return { a: [0.6, 0.03, 0.02], b: [0.35, 0.05, 0.3], level: 0.8, drift: 0.5 };
      case 'over':
        return overMood(phaseTime);
    }
  }

  spawn(3, true);

  return {
    id: 'cascade',

    scoreBoard: () => ({ key: 'cascade', title: 'Cascade' }),

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
      // The fuse burns while you aim; at the end the bomb goes off by itself.
      if (phase === 'aim') {
        fuse -= dt;
        if (fuse <= 0) fire(cursor);
      }
      if (phase !== 'over') stepOrbs(dt);
      stepBlasts(dt);
      sparks.update(dt);
      motes.update(dt);
      waves.update(dt);
      decorFlare.update(dt);
      show.update(dt);
      if (phase !== 'over' || phaseTime > 1.5) show.followMood(moodNow(), 2.5, dt);
      // The roof is the playfield: the backdrop stays dim there while you aim, so the orbs and the bomb stand out.
      show.roofLevel = phase === 'aim' ? 0.4 : 0.7;
      meter += (chain - meter) * Math.min(1, dt * 6);
      for (const p of bushPaint) for (const x of p) if (x) x.age += dt;

      if (phase === 'chain') {
        quietFor = blasts.length ? 0 : quietFor + dt;
        if (quietFor > 0.35) judge();
      }
      if (phase === 'clear') {
        // Fireworks over the roof in the colors that were popped.
        if (Math.random() < dt * (swept ? 10 : 5)) {
          const colors = bushPaint.flat().filter((x): x is Paint => !!x).map((x) => x.color);
          sparks.burst(Math.random() * n, colors.length ? [colors[Math.floor(Math.random() * colors.length)], WHITE] : [hsv(Math.random()), WHITE], 26, n * 0.3);
        }
        if (Math.random() < dt * (swept ? 2.5 : 1.2)) {
          const popped = chainColors.length ? chainColors : ORB_COLORS;
          show.rocket([popped[Math.floor(Math.random() * popped.length)], COLORS.gold], { size: 0.8 + Math.random() * 0.5 });
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
      show.draw(frame);
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
          return {
            ...common,
            stats: [...stats, { label: 'Fuse', value: `${Math.max(0, Math.ceil(fuse))}s` }],
            phase,
            progress,
            message: `Level ${level}: pop ${target} of ${orbs.length} orbs. Tap when the bright ones bunch up. Same color hits same color: double!`,
            button: 'BOOM!',
            tone: 'go'
          };
        case 'chain':
          return { ...common, phase, progress, message: chain ? `Chain ×${chain}!${combos ? ` ${combos} color combo${combos > 1 ? 's' : ''}!` : ''}` : 'Boom…', button: '…', tone: 'wait' };
        case 'clear':
          return {
            ...common,
            phase,
            progress,
            message: swept
              ? `Clean sweep! Every orb popped: +${sweepBonus}${lifeBack ? ' and a life back' : ''}.`
              : `Level ${level} cleared! Chain of ${chain}${combos ? `, ${combos} combo${combos > 1 ? 's' : ''}` : ''}. Pop them all for a bonus.`,
            button: 'NEXT',
            tone: 'good'
          };
        case 'fail':
          return { ...common, phase, progress, message: lives === 1 ? `${chain} of ${target}. Last try!` : `${chain} of ${target}. So close! Try again.`, button: 'AGAIN', tone: 'bad' };
        case 'over':
          return { ...common, phase, message: newBest ? `New best: ${score}!` : `Game over: ${score} points. Longest chain ${longest}.`, button: 'GO!', tone: 'go' };
      }
    }
  };
}
