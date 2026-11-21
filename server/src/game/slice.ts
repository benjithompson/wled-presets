import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, COLORS, Flare, Motes, Recent, record, scale, Sparks, Waves, Yard, type Part } from './kit.ts';
import { NIGHT_MOOD, overMood, Show, type Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Slice: a band of light lies on the roof, the top layer of a tower. A bar of the same width, the
// next layer, slides back and forth along the roof with white edges. Tap to drop it: the part that
// lands on the band stays and becomes the new top layer; whatever hangs over the edge breaks off
// and falls from the gutter. So every layer is a little narrower, and the bar a little faster.
// Miss the band entirely and the tower falls.
//
// A drop with the edges lined up is PERFECT: nothing breaks off, the band flashes gold. Five
// perfects in a row and every perfect after that grows the band back a little, so a perfect
// player can stack forever.
//
// A clock runs down while the bar slides, and every drop winds it back up (more for a perfect),
// to a limit. What a drop gives back is measured in the time the bar takes to cross the roof,
// so it is fair at every speed and width: the bar reaches the band in about half a crossing,
// and a drop gives back three quarters of one, so a drop on the first pass gains time; waiting
// for the bar to come round again costs a whole crossing more than that. When the clock runs out, the tower falls. In the last
// seconds the roof and the windows tick red, faster and faster.
//
// The yard: the trees are the tower itself, a layer of color per drop stacking up from the base
// (the newest at the top); perfect layers sparkle gold. The bushes count the perfect streak, one
// more bush lit per perfect in a row, all of them gold when the band grows back. Windows and doors
// catch the color of every layer, and glow warmer with the streak. The pieces that break off fall
// past them.
//
// Colors: the layers come round in four colors far apart on real LEDs (green, cyan, blue,
// magenta). White is only ever the edges of the sliding bar, the thing you time against. Gold is
// a perfect drop, red a piece that broke off and the tower falling.

type Phase = 'ready' | 'sweep' | 'over';

interface Chunk {
  lo: number;
  hi: number;
  color: Rgb;
  t: number;
}

/** The layers' colors, in turn: the Cascade orbs, far apart on real LEDs. */
const LAYER_COLORS: Rgb[] = [
  [0.05, 1, 0.12],
  [0, 0.72, 1],
  [0.14, 0.08, 1],
  [1, 0, 0.7]
];
const NIGHT: Rgb = [0.02, 0.012, 0.04];
/** A press counts where the bar was this long ago: the phone and Wi-Fi are a little late. */
const LAG = 0.08;
/** Perfects in a row before the band starts growing back. */
export const REGROW = 5;
/** How long a broken-off piece takes to fade from the roof. */
const CHUNK_LIFE = 0.7;
/** Layers a tree shows at once (the newest at the top). */
const TREE_LAYERS = 10;
/** The clock, in seconds: at the start, and the most it holds. */
export const TIME_START = 8;
export const TIME_MAX = 10;
/** What a drop and a perfect drop put back on the clock, in crossings of the roof by the bar. */
export const DROP_CROSSINGS = 0.75;
export const PERFECT_CROSSINGS = 1.1;
/** The clock ticks red in the yard below this many seconds. */
const HURRY = 3;

/** Where things are, for tests: the bar's low edge and the top layer, in roof steps. */
export interface SlicePeek {
  bar: number;
  lo: number;
  hi: number;
  /** Seconds on the clock. */
  time: number;
  /** Seconds the bar takes to cross the roof now. */
  crossing: number;
}

export function sliceGame(stage: Stage): Game & { peek(): SlicePeek } {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= 30;
  const sparks = new Sparks(roof, n * 0.1, 1.8);
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const decorFlare = new Flare(3);
  /** Where the bar's low edge was lately: a tap drops it where the player saw it. */
  const seen = new Recent<number>(0.4);
  // The whole yard plays along: a calm night that heats up with the perfect streak, red and
  // throbbing when the clock runs low; fireworks for perfects, debris for every piece that breaks.
  const show = new Show(yard);
  for (const t of yard.trees) show.dim(t, 0.45);
  // The roof is where the timing is: the show stays faint there, so the bar's white edges stand out.
  show.roofShare = 0.25;
  // Fireworks burst below the eaves (where there is something there), so they stay off the roof.
  show.belowRoof();
  show.roofLevel = 0.4;
  /** The last red tick of the clock (so each tick pumps the yard once). */
  let ticked = 0;

  /** The width a game starts with, and the most the band grows back to. */
  const startWidth = Math.max(6, Math.round(n * 0.4));
  /** The middle of the band at the start: the roof right above the middle of the house. */
  const home = Math.max(startWidth / 2, Math.min(n - 1 - startWidth / 2, n ? roof.above(yard.middle) : 0));

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
  let layers = 0;
  let streak = 0;
  let bestStreak = 0;
  let newBest = false;
  /** The top layer, in roof steps. */
  let lo = 0;
  let hi = 0;
  /** The sliding bar's low edge, and which way it goes. */
  let bar = 0;
  let dir = 1;
  /** Seconds since the last drop: the band flashes, gold for a perfect. */
  let since = 9;
  let lastPerfect = false;
  let lastLoss = 0;
  let grew = false;
  let chunks: Chunk[] = [];
  /** Seconds on the clock, and whether it ran out (the game ended on time, not a miss). */
  let timeLeft = TIME_START;
  let timedOut = false;
  /** What the last drop put back on the clock. */
  let lastGain = 0;
  /** Every layer so far: its color and whether it was perfect (for the trees). */
  let tower: { color: Rgb; perfect: boolean; t: number }[] = [];

  const width = () => hi - lo;
  const layerColor = (i: number) => LAYER_COLORS[((i % LAYER_COLORS.length) + LAYER_COLORS.length) % LAYER_COLORS.length];
  /** The bar's speed, in roof steps a second: a crossing in 3.4 s at first, 1.8 s at most. */
  const speed = () => n / Math.max(1.8, 3.4 - layers * 0.05);
  /** Seconds the bar takes to cross the roof, end to end, at its width and speed now. */
  const crossing = () => Math.max(0, n - 1 - width()) / speed();
  /** How far off a drop can be and still count as perfect: a time window, so it stays fair when fast. */
  const tolerance = () => Math.max(1.5, Math.min(width() * 0.15, speed() * 0.03));

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

  /** The next layer comes in from the other end of the roof each time. */
  function nextBar() {
    const w = width();
    if (layers % 2 === 0) {
      bar = 0;
      dir = 1;
    } else {
      bar = Math.max(0, n - 1 - w);
      dir = -1;
    }
    seen.clear();
    seen.push(clock, bar);
  }

  function reset() {
    lo = home - startWidth / 2;
    hi = home + startWidth / 2;
    layers = 0;
    streak = 0;
    bestStreak = 0;
    since = 9;
    lastPerfect = false;
    lastLoss = 0;
    grew = false;
    chunks = [];
    tower = [];
    timeLeft = TIME_START;
    timedOut = false;
    lastGain = 0;
    nextBar();
  }

  function newGame() {
    newBest = false;
    sparks.clear();
    motes.clear();
    waves.clear();
    show.clear();
    show.setMood(moodNow(), { wipe: 'up' });
    reset();
    setPhase('sweep');
  }

  /** A piece of the roof breaks off: it flashes red on the roof and falls from the gutter. */
  function breakOff(a: number, b: number, color: Rgb) {
    if (b - a <= 0.01) return;
    chunks.push({ lo: a, hi: b, color, t: 0 });
    const pieces = Math.max(1, Math.min(12, Math.round((b - a) / 3)));
    for (let k = 0; k < pieces; k++) {
      const p = roof.point(a + ((k + 0.5) / pieces) * (b - a));
      motes.drop(p.x, p.y, mix(color, COLORS.bad, 0.35), { vx: (Math.random() - 0.5) * 40, vy: -yard.stage.scale * (0.5 + Math.random()), size: 22 });
    }
    sparks.burst((a + b) / 2, [color, COLORS.bad], Math.min(30, 6 + Math.round(b - a)), n * 0.15, 0.8);
    // Debris through the yard below, more for a bigger piece.
    const mid = roof.point((a + b) / 2);
    show.explode(mid.x, mid.y, mix(color, COLORS.bad, 0.5), { size: Math.min(1.2, 0.35 + (b - a) / (n * 0.3)) });
  }

  function drop(at: number) {
    const w = width();
    const color = layerColor(layers + 1);
    const off = at - lo;
    since = 0;
    if (Math.abs(off) <= tolerance()) {
      // Perfect: it lands exactly on the band.
      streak++;
      bestStreak = Math.max(bestStreak, streak);
      lastPerfect = true;
      lastLoss = 0;
      grew = false;
      if (streak >= REGROW && w < startWidth) {
        const add = Math.min(startWidth - w, Math.max(2, n * 0.03));
        lo = Math.max(0, lo - add / 2);
        hi = Math.min(n - 1, lo + w + add);
        lo = hi - (w + add);
        grew = true;
      }
      for (const edge of [lo, hi]) sparks.burst(edge, [COLORS.gold, color], 18, n * 0.25);
      const p = roof.point((lo + hi) / 2);
      waves.add(p.x, p.y, grew ? COLORS.gold : color, { amount: grew ? 1 : 0.6 });
      decorFlare.add(COLORS.gold, 0.5);
      show.pulse(COLORS.gold, 0.1);
      if (grew) {
        // The band grows back: gold sweeps up the yard and a volley goes up.
        show.sweep(COLORS.gold, { dir: 'up', amount: 0.7 });
        for (let k = 0; k < 3; k++) show.firework({ x: show.box.x + show.box.w * ((k + 0.5) / 3), colors: [COLORS.gold, color], delay: k * 0.18 });
      } else if (show.rocketsUp < 3) show.firework({ x: p.x + (Math.random() - 0.5) * show.box.w * 0.6, colors: [COLORS.gold, color], size: 0.6 + 0.1 * Math.min(4, streak) });
    } else {
      const a = Math.max(at, lo);
      const b = Math.min(at + w, hi);
      if (b - a < 0.75) {
        // Missed the band: the whole bar falls, and the tower with it.
        breakOff(at, at + w, color);
        lastLoss = w;
        return gameOver();
      }
      // The overhang breaks off; what landed is the new top layer.
      if (at < lo) breakOff(at, lo, color);
      else breakOff(hi, at + w, color);
      lastLoss = w - (b - a);
      lo = a;
      hi = b;
      streak = 0;
      lastPerfect = false;
      grew = false;
      show.pulse(color, 0.06);
    }
    layers++;
    tower.push({ color, perfect: lastPerfect, t: 0 });
    const before = timeLeft;
    timeLeft = Math.min(TIME_MAX, timeLeft + (lastPerfect ? PERFECT_CROSSINGS : DROP_CROSSINGS) * crossing());
    lastGain = timeLeft - before;
    decorFlare.add(color, 0.7);
    nextBar();
  }

  /** The clock ran out: the bar falls where it is, and the tower with it. */
  function outOfTime() {
    timeLeft = 0;
    timedOut = true;
    breakOff(bar, bar + width(), layerColor(layers + 1));
    gameOver();
  }

  function gameOver() {
    newBest = record('slice', layers).isNew;
    // The band falls too.
    breakOff(lo, hi, layerColor(layers));
    for (const t of yard.trees) waves.add(t.x, t.top, COLORS.bad, { amount: 0.6 });
    // The tower comes down over everything: a red flash, red pouring down the yard, then dark red.
    const mid = roof.point((lo + hi) / 2);
    show.gameOver(mid.x, mid.y, { newBest });
    setPhase('over');
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    if (phase === 'sweep') drop(seen.at(clock - LAG) ?? bar);
  }

  // ---------- Drawing ----------

  function drawRoof() {
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT, 1 + 0.3 * Math.sin(clock * 0.8 + i * 0.07));
    // The last seconds on the clock: the whole roof ticks red, faster as it runs out.
    const tick = hurryTick();
    if (tick) for (let i = 0; i < n; i++) yard.roofAt(i, COLORS.bad, 0.1 * tick);
    if (phase !== 'over') {
      // The top layer: its color, with brighter edges to line up with. It flashes after a drop.
      // The bar lies on top of it, not mixed in (two colors added up look white on real LEDs):
      // under the bar, only the band's edges show, as notches in the band's color.
      const color = layerColor(layers);
      const flash = since < 0.4 ? 1 - since / 0.4 : 0;
      const body = lastPerfect && flash ? mix(color, COLORS.gold, flash) : color;
      const w = width();
      const under = (i: number) => phase === 'sweep' || phase === 'ready' ? i >= Math.ceil(bar) && i <= Math.floor(bar + w) : false;
      for (let i = Math.ceil(lo); i <= Math.floor(hi); i++) if (!under(i)) yard.roofAt(i, body, 0.28 + flash * 0.35);
      for (const edge of [lo, hi]) {
        const i = Math.round(edge);
        yard.roofAt(i, color, under(i) ? 1 : 0.9);
        if (!under(i - 1) && !under(i + 1)) yard.roofSplat(edge, color, 0.8, 0.3);
      }
      drawBar(new Set([Math.round(lo), Math.round(hi)]));
    }
    for (const c of chunks) {
      const f = c.t / CHUNK_LIFE;
      const col = mix(c.color, COLORS.bad, Math.min(1, f * 2));
      for (let i = Math.ceil(c.lo); i <= Math.floor(c.hi); i++) yard.roofAt(i, col, (1 - f) * (0.7 + 0.3 * Math.random()));
    }
    sparks.draw(yard);
  }

  /** The sliding bar: the next layer's color, with white edges, the only white on the roof. */
  function drawBar(notches: Set<number>) {
    const w = width();
    const color = layerColor(layers + 1);
    const pulse = phase === 'ready' ? 0.5 + 0.3 * Math.sin(clock * 4) : 0.75;
    for (let i = Math.ceil(bar); i <= Math.floor(bar + w); i++) if (!notches.has(i)) yard.roofAt(i, color, pulse);
    yard.roofSplat(bar, WHITE, 0.9, 1);
    yard.roofSplat(bar + w, WHITE, 0.9, 1);
  }

  function drawTrees(part: Part) {
    // The tower: the newest TREE_LAYERS layers, each a band of the tree, the newest on top.
    const shown = tower.slice(-TREE_LAYERS);
    const falling = phase === 'over' ? Math.min(1, phaseTime / 1.5) : 0;
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      // When the tower falls, it drains down out of the tree.
      const k = Math.floor(u * TREE_LAYERS + falling * TREE_LAYERS);
      const layer = shown[k];
      if (!layer || (phase === 'over' && u > 1 - falling)) continue;
      const fresh = layer.t < 0.3 ? 1 - layer.t / 0.3 : 0;
      const sparkle = layer.perfect ? 0.35 * Math.max(0, Math.sin(clock * 7 + i * 2.1)) : 0;
      const c = phase === 'over' ? mix(layer.color, COLORS.bad, 0.5) : mix(mix(layer.color, COLORS.gold, sparkle), WHITE, fresh * 0.5);
      yard.add(part.offset + i, c, 0.6 + fresh * 0.5);
    }
  }

  function drawBushes() {
    // The perfect streak fills the bushes from the ground up, left to right (each bush its share
    // of REGROW); all of them sparkle gold once the band grows back.
    const m = yard.bushes.length;
    const growing = streak >= REGROW;
    const fresh = since < 0.3 && lastPerfect ? 1 - since / 0.3 : 0;
    yard.bushes.forEach((b, bi) => {
      const share = REGROW / m;
      const fill = growing ? 1 : Math.max(0, Math.min(1, (streak - bi * share) / share));
      for (let i = 0; i < b.count; i++) {
        if (phase === 'over') {
          yard.add(b.offset + i, COLORS.bad, 0.06 * (0.6 + 0.4 * Math.sin(phaseTime * 3)));
          continue;
        }
        if (!fill || b.up[i] > fill) continue;
        const twinkle = growing ? 0.55 + 0.45 * Math.max(0, Math.sin(clock * 8 + i * 2.7)) : 0.6 + 0.1 * Math.sin(clock * 3 + i);
        yard.add(b.offset + i, mix(COLORS.gold, WHITE, fresh * 0.5), twinkle + fresh * 0.4);
      }
    });
  }

  /**
   * 0..1: a red tick for the last seconds on the clock, once a second from HURRY seconds left,
   * twice a second in the last 1.5; each flash fades quickly.
   */
  function hurryTick() {
    if (phase !== 'sweep' || timeLeft >= HURRY) return 0;
    const rate = timeLeft < 1.5 ? 2 : 1;
    const phaseIn = (timeLeft * rate) % 1;
    // A flash right as each whole (or half) second goes by.
    return Math.max(0, 1 - (1 - phaseIn) * 5);
  }

  function drawDecor(part: Part) {
    const warm = Math.min(1, streak / REGROW);
    const tick = hurryTick();
    for (let i = 0; i < part.count; i++) {
      if (tick) yard.add(part.offset + i, COLORS.bad, 0.5 * tick);
      yard.add(part.offset + i, decorFlare.color, 1);
      if (warm > 0) yard.add(part.offset + i, COLORS.gold, warm * 0.18 * (0.8 + 0.2 * Math.sin(clock * 2 + i * 0.3)));
    }
  }

  /**
   * The yard's mood: a slow rainbow while it waits for a player; a calm night that turns gold and
   * warm with the perfect streak and quicker with the tower's height; red and throbbing on every
   * tick of the clock's last seconds; dark red once the tower falls.
   */
  function moodNow(): Mood {
    if (phase === 'over') return overMood(phaseTime);
    if (phase === 'ready') return { a: hsv(clock * 0.04), b: hsv(clock * 0.04 + 0.35), level: 1, drift: 1.2 };
    if (timeLeft < HURRY) return { a: COLORS.bad, b: [0.5, 0, 0.15], level: 1.2, throb: timeLeft < 1.5 ? 2 : 1 };
    const warm = Math.min(1, streak / REGROW);
    const tall = Math.min(1, layers / 30);
    return { a: mix(NIGHT_MOOD.a, COLORS.gold, warm * 0.7), b: mix(NIGHT_MOOD.b, COLORS.fire, warm * 0.5), level: 0.9 + warm * 0.3 + tall * 0.2, drift: 1 + tall * 1.5 };
  }

  reset();

  return {
    id: 'slice',

    scoreBoard: () => ({ key: 'slice', title: 'Slice' }),

    input,

    peek: () => ({ bar, lo, hi, time: timeLeft, crossing: crossing() }),

    update(dt: number, frame: Frame) {
      clock += dt;
      phaseTime += dt;
      since += dt;
      yard.begin(frame);
      if (!playable) return;

      if (phase === 'sweep' || phase === 'ready') {
        const end = Math.max(0, n - 1 - width());
        bar += dir * speed() * dt;
        if (bar >= end) {
          bar = 2 * end - bar;
          dir = -1;
        }
        if (bar <= 0) {
          bar = -bar;
          dir = 1;
        }
        bar = Math.max(0, Math.min(end, bar));
        seen.push(clock, bar);
      }
      if (phase === 'sweep') {
        timeLeft -= dt;
        if (timeLeft <= 0) outOfTime();
      }
      for (const c of chunks) c.t += dt;
      chunks = chunks.filter((c) => c.t < CHUNK_LIFE);
      for (const l of tower) l.t += dt;
      sparks.update(dt);
      motes.update(dt);
      waves.update(dt);
      decorFlare.update(dt);
      show.update(dt);
      if (phase !== 'over' || phaseTime > 1.5) show.followMood(moodNow(), 2, dt);
      // Each red tick of the clock pumps the whole yard.
      const tick = hurryTick();
      if (tick > 0.9 && ticked < 0.9) show.pulse(COLORS.bad, 0.12);
      ticked = tick;
      // Waiting for a player: now and then a firework.
      if (phase === 'ready' && show.rocketsUp === 0 && Math.random() < dt / 2.5) show.firework({ colors: [LAYER_COLORS[Math.floor(Math.random() * 4)], COLORS.gold], size: 0.7 });
      if (phase === 'over' && phaseTime > 10) {
        reset();
        setPhase('ready');
      }

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTrees(t);
      for (const d of yard.decor) drawDecor(d);
      if (phase === 'over' && phaseTime < 0.6) yard.wash(COLORS.bad, 0.2 * (1 - phaseTime / 0.6));
      if (phase === 'over') yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(phaseTime * 3)), 0.04);
      motes.draw();
      waves.draw();
      show.draw(frame);
    },

    status(): GameStatusFields {
      const best = bestScore('slice');
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score: 0, lives: null, goal: null };
      const widthPct = `${Math.round((width() / startWidth) * 100)}%`;
      const stats = [
        { label: 'Layers', value: layers },
        { label: 'Time', value: `${Math.max(0, Math.ceil(timeLeft))}s` },
        { label: 'Width', value: widthPct },
        { label: 'Best', value: Math.max(best, layers) }
      ];
      const common = { score: layers, lives: null, goal: null, stats };
      switch (phase) {
        case 'ready':
          return { ...common, phase, message: 'Tap to start! Drop the sliding light right on top of the band. Whatever hangs over breaks off.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'sweep': {
          const progress = { value: Math.min(streak, REGROW), max: REGROW };
          let message: string;
          const gain = lastGain > 0.05 ? ` +${lastGain.toFixed(1)}s` : '';
          if (timeLeft < HURRY) message = layers ? `Hurry! ${Math.ceil(timeLeft)}s left. Every drop winds the clock back up.` : `Hurry! ${Math.ceil(timeLeft)}s left. Drop it!`;
          else if (!layers) message = 'Tap when the white edges line up with the band! Be quick: the clock is running.';
          else if (grew) message = `PERFECT ×${streak}!${gain} The band grows back.`;
          else if (lastPerfect) message = streak >= REGROW ? `PERFECT ×${streak}!${gain}` : `PERFECT ×${streak}!${gain} ${REGROW - streak} more to grow back.`;
          else message = `Layer ${layers}.${gain} ${Math.max(1, Math.round(lastLoss))} broke off. Line up the edges for a perfect!`;
          return { ...common, phase, progress, message, button: 'DROP', tone: timeLeft < HURRY ? 'bad' : lastPerfect ? 'good' : 'go' };
        }
        case 'over':
          return {
            ...common,
            phase,
            message: newBest
              ? `${timedOut ? 'Out of time! ' : ''}New best: ${layers} layers!`
              : timedOut
                ? `Out of time at ${layers} layer${layers === 1 ? '' : 's'}! Drop sooner to keep the clock going.`
                : `The tower fell at ${layers} layer${layers === 1 ? '' : 's'}. Best perfect streak ${bestStreak}.`,
            button: 'GO!',
            tone: 'bad'
          };
      }
    }
  };
}
