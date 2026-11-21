// What the game tests share: a game on a stage with a frame to draw into, running it for a
// while, presses, and random numbers that come out the same every time.
import { vi } from 'vitest';
import { buildStage, sampleLayout, type Layout, type Stage } from '../../shared/layout.ts';
import { Frame } from '../src/game/frame.ts';
import type { Game } from '../src/game/types.ts';

/** Runs a game for `seconds`, at 60 frames a second. */
export function run(game: Pick<Game, 'update'>, frame: Frame, seconds: number) {
  for (let i = 0; i < Math.round(seconds * 60); i++) game.update(1 / 60, frame);
}

type Input = Pick<Game, 'input'>;
const input = (game: Input, action: 'press' | 'release', playerId: string, button?: string) => game.input({ playerId, action, ...(button ? { button } : {}) });

/** The player 'p' presses the big button, or `button`. */
export const press = (game: Input, button?: string, playerId = 'p') => input(game, 'press', playerId, button);
export const release = (game: Input, button?: string, playerId = 'p') => input(game, 'release', playerId, button);
/** Another player presses (games with sides, or a second phone). */
export const pressAs = (game: Input, playerId: string, button?: string) => input(game, 'press', playerId, button);
export const releaseAs = (game: Input, playerId: string, button?: string) => input(game, 'release', playerId, button);

/** A game on the stage of `layout` (default: the sample yard), and a frame for it. */
export function setup<G extends Game>(create: (stage: Stage) => G, layout: Layout = sampleLayout()) {
  const stage = buildStage(layout);
  const game = create(stage);
  const frame = new Frame(stage.pixelCount);
  return { stage, game, frame, run: (seconds: number) => run(game, frame, seconds) };
}

/** Math.random gives the same numbers every time from here on (mulberry32). Undo with vi.restoreAllMocks. */
export function seedRandom(seed: number) {
  vi.spyOn(Math, 'random').mockImplementation(() => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  });
}
