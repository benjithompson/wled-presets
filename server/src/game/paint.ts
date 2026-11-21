import { isLine, type Stage } from '../../../shared/layout.ts';
import { ERASER, PAINT_BUTTONS, PAINT_COLORS, PAINT_EFFECTS, RAINBOW, type PaintStroke } from '../../../shared/paint.ts';
import { hsv, mix, WHITE, type Rgb } from './frame.ts';
import { Yard } from './kit.ts';
import type { Game, GameInput } from './types.ts';

// Light Painter: not a game to win, a paint box for small children. A finger dragged over the
// picture of the yard on the phone paints the lights under it, in a color and with an effect
// (twinkle, heartbeat, fire, waves, a train running along the strip). The fill tool paints a
// whole bush or roofline in one touch, in a ripple from the finger. Undo takes back the last
// stroke; Surprise paints the whole yard at random, in a sweep from left to right; Clear sweeps it
// all away. Nothing can go wrong, so every touch looks good: new paint pops in bright and
// settles, and a soft light follows the finger on the house, so a child looking at the house
// instead of the phone still sees where they paint.

/** Paint per LED: 0 is unpainted, k is PAINT_COLORS[k - 1]. */
const COLOR_INDEX = new Map(PAINT_COLORS.map((c, i) => [c.id, i + 1]));
const EFFECT_INDEX = new Map(PAINT_EFFECTS.map((e, i) => [e.id, i]));
const FX = Object.fromEntries(PAINT_EFFECTS.map((e, i) => [e.id, i])) as Record<string, number>;
/** Colors for Surprise: everything but the eraser. */
const SURPRISE_COLORS = PAINT_COLORS.map((c, i) => ({ c, k: i + 1 })).filter(({ c }) => c.id !== ERASER);

/** Strokes kept for Undo. */
const UNDO_STEPS = 30;
/** New paint pops in this bright and settles over this many seconds. */
const POP_SECONDS = 0.45;
/** A fill spreads over the object from the finger in this long. */
const FILL_SECONDS = 0.5;
/** Clear and Surprise sweep across the yard in this long. */
const SWEEP_SECONDS = 0.9;
/** The light that follows the finger on the house stays this long after it stops. */
const CURSOR_SECONDS = 0.35;
/** The brush, as a share of the yard's size: no smaller and no larger. */
const SMALLEST_BRUSH = 0.004;
const LARGEST_BRUSH = 0.12;

interface Snapshot {
  color: Uint8Array;
  effect: Uint8Array;
}

export function paintGame(stage: Stage): Game {
  const yard = new Yard(stage);
  const n = stage.pixelCount;
  const pos = stage.positions;
  const playable = yard.lit.length > 0;

  // Where the lights are: the rainbow and the sweeps run across them.
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const i of yard.lit) {
    minX = Math.min(minX, pos[i * 2]);
    maxX = Math.max(maxX, pos[i * 2]);
    minY = Math.min(minY, pos[i * 2 + 1]);
    maxY = Math.max(maxY, pos[i * 2 + 1]);
  }
  const span = Math.max(1, maxX - minX, maxY - minY);
  const spanX = Math.max(1, maxX - minX);
  const size = Math.max(stage.width, stage.height, span);

  /** Each LED's object (index into stage.fixtures), or -1. */
  const owner = new Int32Array(n).fill(-1);
  stage.fixtures.forEach((f, k) => {
    for (let i = 0; i < f.count; i++) owner[f.offset + i] = k;
  });

  const color = new Uint8Array(n);
  const effect = new Uint8Array(n);
  /** When each LED was painted (it pops in). */
  const born = new Float32Array(n).fill(-10);
  /** Paint on its way (a fill's ripple, a sweep): it lands at `pendingAt`. */
  const pending = new Uint8Array(n);
  const pendingColor = new Uint8Array(n);
  const pendingEffect = new Uint8Array(n);
  const pendingAt = new Float32Array(n);
  /** Per LED, so twinkles and flames do not move in step. */
  const seed = Float32Array.from({ length: n }, () => Math.random());

  const undo: Snapshot[] = [];
  /** The last point of each finger's stroke, by player and finger. */
  const last = new Map<string, { x: number; y: number }>();
  /** Strokes that already saved a step for Undo. */
  const saved = new Set<string>();
  /** Objects a fill stroke already filled. */
  const filled = new Map<string, Set<number>>();
  /** The light that follows each finger on the house. */
  const cursors = new Map<string, { x: number; y: number; r: number; rgb: Rgb; at: number }>();
  let sweep: { at: number; rainbow: boolean } | null = null;
  let clock = 0;

  /** The painting as it will be once all paint on its way has landed. */
  function settled(): Snapshot {
    const c = color.slice();
    const e = effect.slice();
    for (let i = 0; i < n; i++) {
      if (!pending[i]) continue;
      c[i] = pendingColor[i];
      e[i] = pendingEffect[i];
    }
    return { color: c, effect: e };
  }

  function save() {
    undo.push(settled());
    if (undo.length > UNDO_STEPS) undo.shift();
  }

  /** The stroke saves one step for Undo, before its first change. */
  function saveFor(key: string) {
    if (saved.has(key)) return;
    saved.add(key);
    save();
  }

  function setNow(i: number, c: number, e: number) {
    pending[i] = 0;
    if (color[i] === c && (effect[i] === e || !c)) return;
    color[i] = c;
    effect[i] = e;
    if (c) born[i] = clock;
  }

  function setLater(i: number, c: number, e: number, at: number) {
    pending[i] = 1;
    pendingColor[i] = c;
    pendingEffect[i] = e;
    pendingAt[i] = at;
  }

  const isEmpty = () => {
    for (const i of yard.lit) if (color[i] || (pending[i] && pendingColor[i])) return false;
    return true;
  };

  function paint(e: PaintStroke & { playerId: string }) {
    if (!playable) return;
    const key = `${e.playerId}:${e.finger}`;
    if (e.start) {
      last.delete(key);
      saved.delete(key);
      filled.delete(key);
    }
    const r = Math.min(size * LARGEST_BRUSH, Math.max(size * SMALLEST_BRUSH, e.radius));
    const c = COLOR_INDEX.get(e.color) ?? 0;
    const paintColor = e.color === ERASER ? 0 : c;
    const fx = EFFECT_INDEX.get(e.effect) ?? 0;
    // The LEDs under the stroke: along each piece of it, in steps of half the brush.
    const touched = new Map<number, { x: number; y: number }>();
    let prev = last.get(key) ?? null;
    for (let p = 0; p < e.points.length; p += 2) {
      const x = e.points[p];
      const y = e.points[p + 1];
      const from = prev ?? { x, y };
      const d = Math.hypot(x - from.x, y - from.y);
      const steps = Math.min(200, Math.ceil(d / (r * 0.5)));
      for (let s = 0; s <= steps; s++) {
        const t = steps ? s / steps : 1;
        const qx = from.x + (x - from.x) * t;
        const qy = from.y + (y - from.y) * t;
        yard.within(qx, qy, r, (i) => {
          if (!touched.has(i)) touched.set(i, { x: qx, y: qy });
        });
      }
      prev = { x, y };
    }
    if (prev) last.set(key, prev);
    const rgb = paintColor ? (PAINT_COLORS[paintColor - 1].rgb ?? WHITE) : [0.5, 0.5, 0.5] as Rgb;
    if (prev) cursors.set(key, { x: prev.x, y: prev.y, r, rgb, at: clock });
    if (!touched.size) return;

    if (e.fill) {
      // Each object the finger touched fills, all of it, in a ripple out from where it was touched.
      const done = filled.get(key) ?? new Set<number>();
      filled.set(key, done);
      for (const [i, at] of touched) {
        const k = owner[i];
        if (k < 0 || done.has(k)) continue;
        done.add(k);
        saveFor(key);
        const f = stage.fixtures[k];
        let far = 1;
        for (let j = f.offset; j < f.offset + f.count; j++) far = Math.max(far, Math.hypot(pos[j * 2] - at.x, pos[j * 2 + 1] - at.y));
        for (let j = f.offset; j < f.offset + f.count; j++) {
          if (!stage.active[j]) continue;
          const d = Math.hypot(pos[j * 2] - at.x, pos[j * 2 + 1] - at.y);
          setLater(j, paintColor, fx, clock + (FILL_SECONDS * d) / far);
        }
      }
      return;
    }
    for (const i of touched.keys()) {
      if (color[i] === paintColor && (effect[i] === fx || !paintColor) && !pending[i]) continue;
      saveFor(key);
      setNow(i, paintColor, fx);
    }
  }

  /** Paint lands across the yard from left to right, behind a sweeping band of light. */
  function sweepTo(paintOf: (i: number) => [number, number], rainbow: boolean) {
    save();
    sweep = { at: clock, rainbow };
    for (const i of yard.lit) {
      const [c, e] = paintOf(i);
      setLater(i, c, e, clock + (SWEEP_SECONDS * (pos[i * 2] - minX)) / spanX);
    }
  }

  function surprise() {
    // Every object gets a color and an effect; lines (the roof, windows) often get stripes.
    const pick = () => SURPRISE_COLORS[Math.floor(Math.random() * SURPRISE_COLORS.length)].k;
    const plan = stage.fixtures.map((f) => {
      const striped = isLine(f) && Math.random() < 0.6;
      const a = pick();
      let b = pick();
      while (striped && b === a && SURPRISE_COLORS.length > 1) b = pick();
      return { a, b: striped ? b : a, every: 3 + Math.floor(Math.random() * 6), fx: Math.floor(Math.random() * PAINT_EFFECTS.length) };
    });
    sweepTo((i) => {
      const k = owner[i];
      if (k < 0) return [0, 0];
      const p = plan[k];
      const local = i - stage.fixtures[k].offset;
      return [Math.floor(local / p.every) % 2 ? p.b : p.a, p.fx];
    }, true);
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    if (e.button === PAINT_BUTTONS.undo) {
      const step = undo.pop();
      if (!step) return;
      pending.fill(0);
      color.set(step.color);
      effect.set(step.effect);
      sweep = null;
      saved.clear();
    } else if (e.button === PAINT_BUTTONS.clear) {
      if (!isEmpty()) sweepTo(() => [0, 0], false);
    } else if (e.button === PAINT_BUTTONS.surprise) {
      surprise();
    }
  }

  /** The color of a painted LED now: its paint, moved by its effect. */
  function shade(i: number, out: (c: Rgb, amount: number) => void) {
    const pc = PAINT_COLORS[color[i] - 1];
    const x = pos[i * 2];
    const y = pos[i * 2 + 1];
    const s = seed[i];
    const c: Rgb = pc.id === RAINBOW || !pc.rgb ? hsv(((x - minX) / span) * 0.9 + ((y - minY) / span) * 0.35 - clock * 0.15) : pc.rgb;
    let m = 0.9;
    let glint = 0;
    switch (effect[i]) {
      case FX.twinkle: {
        // Each light glints now and then, on its own time.
        const v = Math.sin(Math.PI * 2 * ((0.3 + s * 0.45) * clock + s * 7));
        glint = Math.max(0, v) ** 24;
        m = 0.45 + 0.4 * glint;
        break;
      }
      case FX.pulse: {
        // Lub-dub, all together.
        const b = (clock * 1.1) % 1;
        const beat = Math.exp(-(((b - 0.04) / 0.07) ** 2)) + 0.75 * Math.exp(-(((b - 0.27) / 0.07) ** 2));
        m = 0.18 + 0.82 * Math.min(1, beat);
        break;
      }
      case FX.flicker: {
        const v = 0.55 + 0.25 * Math.sin(clock * 9.1 + s * 40) + 0.2 * Math.sin(clock * 15.3 + s * 13) * Math.sin(clock * 3.7 + s * 5);
        m = 0.12 + 0.88 * Math.max(0, Math.min(1, v)) ** 2;
        break;
      }
      case FX.wave: {
        // Waves about two meters apart roll from left to right.
        const v = 0.5 + 0.5 * Math.sin(Math.PI * 2 * (x / (stage.scale * 2.2)) - clock * 3.2);
        m = 0.08 + 0.92 * v * v;
        break;
      }
      case FX.chase: {
        // Cars of light run along the strip, like a train.
        const k = owner[i] >= 0 ? i - stage.fixtures[owner[i]].offset : i;
        const p = (((k - clock * 12) % 10) + 10) % 10;
        m = p < 5 ? 0.95 : 0.06;
        break;
      }
    }
    out(c, m);
    if (glint > 0.02) out(mix(c, WHITE, 0.7), glint * 0.8);
    // New paint pops in bright and settles.
    const age = clock - born[i];
    if (age >= 0 && age < POP_SECONDS) out(mix(c, WHITE, 0.5), (1 - age / POP_SECONDS) ** 2 * 0.9);
  }

  return {
    id: 'paint',
    idleAfterMs: 15 * 60_000,

    paint,
    input,

    leave(playerId) {
      for (const map of [last, filled, cursors]) for (const key of [...map.keys()]) if (key.startsWith(`${playerId}:`)) map.delete(key);
    },

    update(dt, frame) {
      clock += dt;
      yard.begin(frame);
      if (!playable) return;
      for (const i of yard.lit) {
        if (pending[i] && pendingAt[i] <= clock) setNow(i, pendingColor[i], pendingEffect[i]);
        if (!color[i]) continue;
        shade(i, (c, amount) => yard.add(i, c, amount));
      }
      // The band of light that sweeps across for Clear (warm white) and Surprise (a rainbow).
      if (sweep) {
        const t = (clock - sweep.at) / SWEEP_SECONDS;
        if (t > 1.15) sweep = null;
        else {
          const front = minX + spanX * t;
          const width = Math.max(spanX * 0.04, stage.scale * 0.4);
          for (const i of yard.lit) {
            const d = (pos[i * 2] - front) / width;
            if (d < -3 || d > 3) continue;
            const c = sweep.rainbow ? hsv((pos[i * 2 + 1] - minY) / Math.max(1, maxY - minY)) : ([1, 0.85, 0.6] as Rgb);
            yard.add(i, mix(c, WHITE, 0.3), Math.exp(-d * d) * 0.9);
          }
        }
      }
      // A soft light follows each finger on the house.
      for (const [key, cur] of cursors) {
        const age = clock - cur.at;
        if (age > CURSOR_SECONDS) {
          cursors.delete(key);
          continue;
        }
        yard.glow(cur.x, cur.y, cur.r * 1.3, mix(cur.rgb, WHITE, 0.6), 0.45 * (1 - age / CURSOR_SECONDS));
      }
    },

    status() {
      if (!playable) return { phase: 'setup', message: 'Add some lights in Layout first.', score: 0, lives: null, goal: null };
      const empty = isEmpty();
      return {
        phase: 'paint',
        message: empty ? 'Pick a color, then paint the lights with your finger!' : 'So pretty! Keep painting!',
        score: 0,
        lives: null,
        goal: null,
        paint: { canUndo: undo.length > 0, empty }
      };
    }
  };
}
