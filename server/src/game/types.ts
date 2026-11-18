import type { GameStatus, Stage } from '../../../shared/layout.ts';
import type { Frame } from './frame.ts';

export interface GameInput {
  playerId: string;
  action: 'press' | 'release';
  /** Server time of the input, in seconds since the game started. */
  at: number;
}

export type GameStatusFields = Omit<GameStatus, 'players' | 'game'>;

/** A game or an animation that draws the stage. The host calls update() 60 times a second. */
export interface Game {
  readonly id: string;
  update(dt: number, frame: Frame): void;
  input(e: GameInput): void;
  status(): GameStatusFields;
  /**
   * What one player sees on top of status(), for games where each phone differs (its side, its
   * button). Called for every connected player.
   */
  playerStatus?(playerId: string): Partial<GameStatusFields>;
  /** A player closed the page. */
  leave?(playerId: string): void;
  /** True when the game is over and the host can return to the idle animation. */
  readonly finished?: boolean;
}

export type GameFactory = (stage: Stage) => Game;
