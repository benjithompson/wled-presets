import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildStage, CONTROL_ID, sampleLayout, type Fixture, type Layout } from '../../shared/layout.ts';
import { Frame } from '../src/game/frame.ts';
import { bestScore, memoryScores, scoreboard, useScoreStore, Yard } from '../src/game/kit.ts';
import { ROUND, whackGame } from '../src/game/whack.ts';

beforeEach(() => useScoreStore(memoryScores()));
afterEach(() => {
  useScoreStore(memoryScores());
  vi.restoreAllMocks();
});

const tree = (id: string, x: number): Fixture => ({ id, name: id, kind: 'tree', points: [{ x, y: 820, z: 260 }], radius: 70, height: 300, pattern: 'spiral', turns: 8, pixels: 120, deviceId: null, startPixel: 0, reversed: false }) as Fixture;

/** The sample yard (three bushes) with two trees, one at each end. */
function yardWithTrees(): Layout {
  const base = sampleLayout();
  return { ...base, fixtures: [...base.fixtures, tree('tree-l', 110), tree('tree-r', 1490)] };
}

function setup(layout = yardWithTrees()) {
  const stage = buildStage(layout);
  const game = whackGame(stage);
  const frame = new Frame(stage.pixelCount);
  const run = (seconds: number, each?: () => void) => {
    for (let i = 0; i < Math.round(seconds * 60); i++) {
      game.update(1 / 60, frame);
      each?.();
    }
  };
  const press = (button?: string) => game.input({ playerId: 'p', action: 'press', ...(button ? { button } : {}) });
  /** Runs until a mole is up (and has been for `after` seconds), and returns its hole. */
  const nextMole = (after = 0.2) => {
    for (let i = 0; i < 600; i++) {
      game.update(1 / 60, frame);
      const h = game.peek().holes.find((x) => x.state === 'up' && x.t >= after);
      if (h) return h;
    }
    throw new Error('no mole came up');
  };
  /** Skips the 3-2-1. */
  const begin = () => {
    press();
    run(3.05);
  };
  return { stage, game, frame, run, press, nextMole, begin };
}

describe('Whack-a-Mole', () => {
  it('makes every bush and tree a hole, left to right, each in its own color and never red', () => {
    const { game } = setup();
    const board = game.status().moles!;
    expect(board.holes.map((h) => h.kind)).toEqual(['tree', 'bush', 'bush', 'bush', 'tree']);
    for (const h of board.holes) {
      expect(h.id).toMatch(CONTROL_ID);
      // Red means a mole got away: no hole is red.
      const [r, g, b] = [1, 3, 5].map((k) => parseInt(h.color.slice(k, k + 2), 16));
      expect(r > 200 && g < 60 && b < 60).toBe(false);
    }
    expect(new Set(board.holes.map((h) => h.color)).size).toBe(board.holes.length);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
  });

  it('counts down 3, 2, 1, then moles pop up for a 45-second round', () => {
    const { game, run, press } = setup();
    press();
    expect(game.status()).toMatchObject({ phase: 'countdown' });
    expect(game.status().moles!.countdown).toBe('3');
    run(1.02);
    expect(game.status().moles!.countdown).toBe('2');
    run(2.02);
    expect(game.status()).toMatchObject({ phase: 'running' });
    expect(game.status().moles!.countdown).toBe('GO!');
    expect(game.status().moles!.timeLeft).toBe(ROUND);
    run(1);
    expect(game.peek().holes.some((h) => h.state === 'up')).toBe(true);
  });

  it('scores a whack, breaks the streak on an empty hole, and lets an unwhacked mole get away in red', () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    const { game, frame, stage, run, press, nextMole, begin } = setup();
    begin();
    const h = nextMole();
    press(h.id);
    expect(game.status().score).toBe(10);
    expect(game.status().moles).toMatchObject({ hits: 1, streak: 1 });
    expect(game.status().moles!.holes.find((x) => x.id === h.id)).toMatchObject({ state: 'hit', points: 10 });
    // A whack at a hole with no mole: no points, and the streak starts over.
    const empty = game.peek().holes.find((x) => x.state === 'empty')!;
    press(empty.id);
    expect(game.status().score).toBe(10);
    expect(game.status().moles!.streak).toBe(0);
    // Leave the next mole alone: it gets away, flashes red, and is gone.
    const left = nextMole(0);
    let missedAt = -1;
    for (let i = 0; i < 300 && missedAt < 0; i++) {
      game.update(1 / 60, frame);
      if (game.peek().holes.find((x) => x.id === left.id)!.state === 'miss') missedAt = i;
    }
    expect(missedAt).toBeGreaterThan(0);
    expect(game.status().moles!.missed).toBe(1);
    // Red on the hole's lights (a bush or a tree), then dark again.
    const hole = game.peek().holes.findIndex((x) => x.id === left.id);
    const yard = new Yard(stage);
    const part = [...yard.bushes, ...yard.trees].sort((p, q) => p.x - q.x)[hole];
    let red = 0;
    for (let i = part.offset; i < part.offset + part.count; i++) if (frame.data[i * 3] > 0.5 && frame.data[i * 3 + 1] < 0.15) red++;
    expect(red).toBeGreaterThan(part.count / 2);
    run(0.8);
    expect(game.peek().holes.find((x) => x.id === left.id)!.state).not.toBe('miss');
  });

  it('still counts a whack while the mole ducks back down (a late tap over Wi-Fi)', () => {
    const { game, press, nextMole, begin } = setup();
    begin();
    const h = nextMole(0);
    // Past its time: it is sinking.
    while (game.peek().holes.find((x) => x.id === h.id)!.t < h.stay + 0.1) game.update(1 / 60, new Frame(1));
    expect(game.peek().holes.find((x) => x.id === h.id)!.state).toBe('up');
    press(h.id);
    expect(game.status().moles!.hits).toBe(1);
  });

  it('doubles the points from the fifth whack in a row', () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    const { game, press, nextMole, begin } = setup();
    begin();
    for (let k = 0; k < 6; k++) press(nextMole().id);
    expect(game.status().moles!.mult).toBe(2);
    expect(game.status().score).toBe(4 * 10 + 2 * 20);
  });

  it('ends after 45 seconds, puts the score on the board for its speed, and waits a moment before the next round', () => {
    const { game, run, press, begin } = setup();
    game.setting!('level', 'easy');
    begin();
    run(ROUND - 0.5, () => {
      for (const h of game.peek().holes) if (h.state === 'up' && h.t > 0.5) press(h.id);
    });
    expect(game.status().phase).toBe('running');
    // No change of speed in the middle of a round.
    game.setting!('level', 'hard');
    run(0.6);
    const s = game.status();
    expect(s.phase).toBe('over');
    expect(s.score).toBeGreaterThan(200);
    expect(game.scoreBoard!()).toEqual({ key: 'whack-easy', title: 'Whack-a-Mole: Easy' });
    expect(bestScore('whack-easy')).toBe(s.score);
    expect(scoreboard('whack-normal')).toEqual([]);
    // A frantic last whack does not start the next round…
    press('h0');
    press();
    expect(game.status().phase).toBe('over');
    // …but GO does, a moment later.
    run(2.1);
    press();
    expect(game.status().phase).toBe('countdown');
  });

  it('is fair for a quick kid on Hard: one who whacks each mole 0.45 s after it shows misses none', () => {
    const { game, frame, run, press, begin } = setup();
    game.setting!('level', 'hard');
    begin();
    let bad = 0;
    run(ROUND + 1, () => {
      for (const h of game.peek().holes) if (h.state === 'up' && h.t >= 0.45) press(h.id);
      for (const v of frame.data) if (!Number.isFinite(v) || v < 0) bad++;
    });
    expect(game.status().phase).toBe('over');
    expect(bad).toBe(0);
    expect(game.status().moles!.missed).toBe(0);
    expect(game.status().moles!.hits).toBeGreaterThan(50);
  });

  it('plays on stretches of the roof when the yard has fewer than three bushes and trees', () => {
    const base = sampleLayout();
    const { game, press, nextMole, begin } = setup({ ...base, fixtures: base.fixtures.filter((f) => f.kind === 'roof') });
    expect(game.peek().onRoof).toBe(true);
    const holes = game.status().moles!.holes;
    expect(holes.length).toBeGreaterThanOrEqual(3);
    expect(holes.every((h) => h.kind === 'roof')).toBe(true);
    begin();
    press(nextMole().id);
    expect(game.status().score).toBe(10);
  });

  it('asks for something to play on in a yard with no lights', () => {
    const { game } = setup({ ...sampleLayout(), fixtures: [] });
    expect(game.status().phase).toBe('setup');
  });
});
