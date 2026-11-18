import type { GameStatus, Stage } from '../../../shared/layout.ts';
import type { Frame } from './frame.ts';

export interface GameInput {
  playerId: string;
  action: 'press' | 'release';
  /** Which button (see GameStatus.controls); not set: the big button, 'main'. */
  button?: string;
}

export type GameStatusFields = Omit<GameStatus, 'players' | 'game'>;

/** A game or an animation that draws the stage. The host calls update() on every frame (see FRAME_HZ). */
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
  /** A player picked a choice for the next game (see GameStatus.settings). */
  setting?(id: string, value: string): void;
  /** The scoreboard this game's scores go on now (see record in kit.ts), and its title. */
  scoreBoard?(): { key: string; title: string } | null;
}

export type GameFactory = (stage: Stage) => Game;
