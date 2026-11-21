import { describe, expect, it } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { Frame } from '../src/game/frame.ts';
import { Yard } from '../src/game/kit.ts';
import { DROP_CROSSINGS, PERFECT_CROSSINGS, REGROW, sliceGame, TIME_MAX, TIME_START } from '../src/game/slice.ts';
import type { Game } from '../src/game/types.ts';

const press = (g: Game) => g.input({ playerId: 'p', action: 'press' });
const run = (g: Game, frame: Frame, seconds: number) => {
  for (let i = 0; i < Math.round(seconds * 60); i++) g.update(1 / 60, frame);
};

type Slice = ReturnType<typeof sliceGame>;

/**
 * Drops the bar with its low edge on `lo`: the game judges a press by where the bar was 0.08 s
 * earlier (5 frames), so press once the edge was there 5 frames ago.
 */
function dropAt(game: Slice, frame: Frame, lo: number) {
  const edges: number[] = [];
  for (let f = 0; f < 600; f++) {
    game.update(1 / 60, frame);
    // The clock ran out on the way.
    if (game.status().phase !== 'sweep') return;
    edges.push(game.peek().bar);
    if (edges.length < 7) continue;
    const then = edges[edges.length - 6];
    const before = edges[edges.length - 7];
    if ((before - lo) * (then - lo) <= 0) {
      press(game);
      return;
    }
  }
  throw new Error('the bar never reached the band');
}

describe('Slice', () => {
  const stage = buildStage(sampleLayout());
  const yard = new Yard(stage);
  const n = yard.roof.n;
  const width = Math.round(n * 0.4);
  const lo = Math.round(yard.roof.above(yard.middle) - width / 2);

  it('drops the sliding bar on a tap; lined up, nothing breaks off', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    press(game);
    expect(game.status()).toMatchObject({ phase: 'sweep', button: 'DROP', score: 0 });
    dropAt(game, frame, lo);
    const s = game.status();
    expect(s.score).toBe(1);
    expect(s.message).toMatch(/PERFECT/);
    expect(s.stats).toContainEqual({ label: 'Width', value: '100%' });
    expect(s.progress).toEqual({ value: 1, max: REGROW });
  });

  it('cuts off what hangs over, and the tower falls when the bar misses the band', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    // Right away: the bar is at the left end, mostly to the left of the band.
    run(game, frame, 0.05);
    press(game);
    const s = game.status();
    expect(s.phase).toBe('sweep');
    expect(s.score).toBe(1);
    expect(s.message).toMatch(/broke off/);
    expect(Number(String(s.stats!.find((x) => x.label === 'Width')!.value).replace('%', ''))).toBeLessThan(50);
    // The next bar comes from the right end, far from the narrow band on the left.
    run(game, frame, 0.05);
    press(game);
    expect(game.status()).toMatchObject({ phase: 'over', score: 1 });
    // A tap right after does not start a new game; a moment later it does.
    press(game);
    expect(game.status().phase).toBe('over');
    run(game, frame, 2);
    press(game);
    expect(game.status()).toMatchObject({ phase: 'sweep', score: 0 });
  });

  it('grows the band back after enough perfects in a row', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    // Lose a little first, then stack perfects on the narrower band.
    run(game, frame, 0.05);
    let s = game.status();
    dropAt(game, frame, lo + 12);
    s = game.status();
    expect(s.message).toMatch(/broke off/);
    const narrow = Number(String(s.stats!.find((x) => x.label === 'Width')!.value).replace('%', ''));
    expect(narrow).toBeLessThan(100);
    for (let i = 0; i < REGROW; i++) dropAt(game, frame, lo + 12);
    s = game.status();
    expect(s.message).toMatch(/grows back/);
    const wider = Number(String(s.stats!.find((x) => x.label === 'Width')!.value).replace('%', ''));
    expect(wider).toBeGreaterThan(narrow);
  });

  it('lights a bush for a perfect, and stacks the layers up a tree', () => {
    const layout = sampleLayout();
    const bush = layout.fixtures.find((f) => f.kind === 'bush')!;
    layout.fixtures.push({ ...bush, id: 'tree', name: 'Tree', kind: 'tree' });
    const stage = buildStage(layout);
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    const yard = new Yard(stage);
    const lit = (p: { offset: number; count: number }) => Array.from({ length: p.count }, (_, i) => frame.data[(p.offset + i) * 3] + frame.data[(p.offset + i) * 3 + 1] + frame.data[(p.offset + i) * 3 + 2]).filter((v) => v > 0.3).length;
    const tree = yard.trees[0];
    const first = yard.bushes[0];
    press(game);
    // Once the new game's colors have swept up the yard.
    run(game, frame, 1);
    expect(lit(tree)).toBe(0);
    expect(lit(first)).toBe(0);
    dropAt(game, frame, lo);
    run(game, frame, 0.5);
    expect(game.status().message).toMatch(/PERFECT/);
    expect(lit(tree)).toBeGreaterThan(0);
    expect(lit(first)).toBeGreaterThan(first.count / 4);
    expect(lit(yard.bushes[2])).toBe(0);
  });

  it('asks for a roofline when there is none, and plays on a roof alone', () => {
    const none = sampleLayout();
    none.fixtures = none.fixtures.filter((f) => f.kind !== 'roof');
    expect(sliceGame(buildStage(none)).status().phase).toBe('setup');
    const roofOnly = sampleLayout();
    roofOnly.fixtures = roofOnly.fixtures.filter((f) => f.kind === 'roof');
    const s = buildStage(roofOnly);
    const game = sliceGame(s);
    const frame = new Frame(s.pixelCount);
    press(game);
    run(game, frame, 0.3);
    press(game);
    run(game, frame, 1);
    expect(game.status().score).toBe(1);
  });

  it('runs a clock down while the bar slides: waiting too long topples the tower', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    expect(game.status().stats).toContainEqual({ label: 'Time', value: `${TIME_START}s` });
    run(game, frame, TIME_START - 2.5);
    expect(game.status()).toMatchObject({ phase: 'sweep', tone: 'bad' });
    expect(game.status().message).toMatch(/Hurry/);
    // The last seconds tick red over the whole roof.
    let most = 0;
    for (let i = 0; i < 60; i++) {
      game.update(1 / 60, frame);
      const red = stage.roofPath.filter((led) => frame.data[led * 3] - frame.data[led * 3 + 1] > 0.04).length;
      most = Math.max(most, red);
    }
    expect(most).toBeGreaterThan(n * 0.25);
    run(game, frame, 1.6);
    expect(game.status().phase).toBe('over');
    expect(game.status().message).toMatch(/Out of time/);
  });

  it('winds the clock back up with every drop, more for a perfect, up to its limit', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    dropAt(game, frame, lo);
    expect(game.status().message).toMatch(/PERFECT/);
    // The bar came in from the left end and reached the band in under a crossing; the perfect
    // gave back more than a crossing.
    expect(game.peek().time).toBeGreaterThan(TIME_START);
    expect(game.peek().time).toBeLessThanOrEqual(TIME_MAX);
    run(game, frame, 0.05);
    const before = game.peek().time;
    press(game);
    expect(game.status().message).toMatch(/broke off/);
    // A plain drop gives back three quarters of a crossing (at the new, narrower width).
    expect(game.peek().time).toBeCloseTo(Math.min(TIME_MAX, before + DROP_CROSSINGS * game.peek().crossing), 2);
    expect(PERFECT_CROSSINGS).toBeGreaterThan(DROP_CROSSINGS);
  });

  it('lets a player who drops on the first pass stack for ever', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    for (let i = 0; i < 60; i++) dropAt(game, frame, game.peek().lo);
    expect(game.status()).toMatchObject({ phase: 'sweep', score: 60 });
    expect(game.peek().time).toBeGreaterThan(TIME_START - 1);
  });

  it('runs out for a player who waits for the bar to come round again', () => {
    const game = sliceGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    let layers = 0;
    for (let i = 0; i < 20 && game.status().phase === 'sweep'; i++) {
      // Let it go by once, then drop it on the way back.
      const pass = (target: number) => {
        let was = game.peek().bar - target;
        for (let f = 0; f < 600 && game.status().phase === 'sweep'; f++) {
          game.update(1 / 60, frame);
          const now = game.peek().bar - target;
          if (was * now <= 0) return;
          was = now;
        }
      };
      pass(game.peek().lo);
      if (game.status().phase !== 'sweep') break;
      dropAt(game, frame, game.peek().lo);
      layers = game.status().score;
    }
    expect(game.status().phase).toBe('over');
    expect(game.status().message).toMatch(/Out of time/);
    expect(layers).toBeLessThan(12);
  });
});
