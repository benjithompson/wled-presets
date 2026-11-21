import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildStage, sampleLayout, type Layout } from '../../shared/layout.ts';
import { GAME_CATALOG } from '../../shared/games.ts';
import { GAMES } from '../src/game/host.ts';
import { endRun, memoryScores, useScoreStore } from '../src/game/kit.ts';
import { hasEnded, Round, showsBoard } from '../src/game/round.ts';
import { GAME_LOOKS } from '../../web/src/lib/gameLooks.ts';
import { press, run, setup } from './harness.ts';

beforeEach(() => useScoreStore(memoryScores()));
afterEach(() => useScoreStore(memoryScores()));

describe('a round', () => {
  it('counts the time in each phase, and the time since it began', () => {
    const round = new Round<'ready' | 'play' | 'over'>('slice', 'ready');
    round.tick(0.5);
    round.to('play');
    round.tick(0.25);
    expect(round.phase).toBe('play');
    expect(round.time).toBe(0.25);
    expect(round.clock).toBe(0.75);
  });

  it('starts again with a press while waiting, or a little after the end, and goes back to waiting later', () => {
    const round = new Round<'ready' | 'play' | 'over'>('slice', 'ready', { restartAfter: 2, resetAfter: 12 });
    expect(round.canStart).toBe(true);
    round.to('play');
    expect(round.canStart).toBe(false);
    round.to('over');
    round.tick(1);
    expect(round.settled).toBe(false);
    round.tick(0.9);
    expect(round.canStart).toBe(false);
    expect(round.settled).toBe(true);
    round.tick(0.2);
    expect(round.canStart).toBe(true);
    expect(round.timedOut).toBe(false);
    round.tick(10);
    expect(round.timedOut).toBe(true);
  });

  it('keeps scores on its board, named after the game', () => {
    const round = new Round('ricochet', 'ready');
    expect(round.scoreBoard()).toEqual({ key: 'ricochet', title: 'Ricochet' });
    expect(round.record(12)).toBe(true);
    expect(round.best()).toBe(12);
    endRun();
    expect(round.record(5)).toBe(false);
    expect(round.best()).toBe(12);
    const levels = new Round('whack', 'ready', { board: () => 'whack-hard', title: (name) => `${name}: Hard` });
    expect(levels.scoreBoard()).toEqual({ key: 'whack-hard', title: 'Whack-a-Mole: Hard' });
  });

  it('names the phases the host goes by', () => {
    expect(['ready', 'over'].every(showsBoard)).toBe(true);
    expect(['running', 'won', 'setup'].some(showsBoard)).toBe(false);
    expect(['over', 'won'].every(hasEnded)).toBe(true);
    expect(hasEnded('ready')).toBe(false);
  });
});

describe('every game in the catalog', () => {
  const empty: Layout = { ...sampleLayout(), fixtures: [] };

  it('has a game on the server and a look on the play page', () => {
    for (const g of GAME_CATALOG) {
      expect(GAMES.find((x) => x.id === g.id)?.create, g.id).toBeTypeOf('function');
      expect(GAME_LOOKS[g.id], g.id).toBeDefined();
    }
  });

  for (const g of GAMES) {
    it(`${g.id}: plays on the sample yard, with its scoreboard named after it`, () => {
      const { game, frame } = setup(g.create);
      expect(game.id).toBe(g.id);
      for (let i = 0; i < 20; i++) {
        press(game);
        run(game, frame, 0.5);
      }
      expect(game.status().phase).toBeTypeOf('string');
      const board = game.scoreBoard?.();
      if (board) expect(board.title.startsWith(g.name)).toBe(true);
    });

    it(`${g.id}: says what the layout needs when there is nowhere to play`, () => {
      const { game, frame } = setup(g.create, empty);
      press(game);
      run(game, frame, 1);
      const s = game.status();
      expect(s.phase).toBe('setup');
      expect(s.message).toMatch(/Layout/);
    });
  }

  it('builds an empty stage without trouble', () => {
    expect(buildStage(empty).pixelCount).toBe(0);
  });
});
