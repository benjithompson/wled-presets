// What every game on the yard shares around its own rules: the phase it is in and how long it
// has been there, starting again after the end, its scoreboard, the status when the layout has
// nowhere to play it, and the effects it draws with.
//
// A game keeps only its rules: what a press does, what scores, what ends the run. The phases
// the host and the phones go by are named here: 'ready' before a game (the start screen, with
// the scoreboard) and 'over' (or 'won') after it.

import { scale } from '../../../shared/color.ts';
import { GAME_CATALOG, type GameId } from '../../../shared/games.ts';
import type { Frame } from './frame.ts';
import { bestScore, COLORS, Flare, Motes, record, Sparks, Waves, type Yard } from './kit.ts';
import { Show } from './show.ts';
import type { GameStatusFields } from './types.ts';

/** Phases with the scoreboard on the phone: before a game and after it. */
export const showsBoard = (phase: string) => phase === 'ready' || phase === 'over';

/** Phases at the end of a game. */
export const hasEnded = (phase: string) => phase === 'over' || phase === 'won';

/** The fewest roof LEDs a roof game can be played on. */
export const MIN_ROOF = 30;

/** What the layout needs before most games can be played. */
export const NEED_ROOF = 'Draw a roofline in Layout first.';

/** After the end, a press starts the next game once this many seconds have passed. */
const RESTART_AFTER = 1.5;
/** After the end, the game goes back to waiting after this many seconds. */
const RESET_AFTER = 10;
/** After the end, the show follows the game's mood again after this many seconds. */
const SETTLE_AFTER = 1.5;

export interface RoundOptions {
  /** Seconds after the end before a press starts the next game (default 1.5). */
  restartAfter?: number;
  /** Seconds after the end before the game goes back to waiting (default 10). */
  resetAfter?: number;
  /** The board this game's scores go on now (default: the game's id). */
  board?: () => string;
  /** The board's title, from the game's name (default: the name). */
  title?: (name: string) => string;
}

/** A game's phase, its clocks and its scoreboard. */
export class Round<P extends string> {
  readonly id: GameId;
  phase: P;
  /** Seconds in this phase. */
  time = 0;
  /** Seconds since the game was made. */
  clock = 0;
  private readonly restartAfter: number;
  private readonly resetAfter: number;
  private readonly board: () => string;
  private readonly title: () => string;

  constructor(id: GameId, first: P, opts: RoundOptions = {}) {
    this.id = id;
    this.phase = first;
    this.restartAfter = opts.restartAfter ?? RESTART_AFTER;
    this.resetAfter = opts.resetAfter ?? RESET_AFTER;
    this.board = opts.board ?? (() => id);
    const name = GAME_CATALOG.find((g) => g.id === id)?.name ?? id;
    const title = opts.title;
    this.title = title ? () => title(name) : () => name;
  }

  /** Into a new phase: its clock starts at 0. */
  to(phase: P) {
    this.phase = phase;
    this.time = 0;
  }

  /** Every frame, first. */
  tick(dt: number) {
    this.clock += dt;
    this.time += dt;
  }

  /** A press now starts a new game: waiting for one, or long enough after the end. */
  get canStart() {
    return this.phase === 'ready' || (this.phase === 'over' && this.time > this.restartAfter);
  }

  /** Long after the end: time to go back to waiting. */
  get timedOut() {
    return this.phase === 'over' && this.time > this.resetAfter;
  }

  /** Not in the first moments after the end (the red flash): the show follows the mood. */
  get settled() {
    return this.phase !== 'over' || this.time > SETTLE_AFTER;
  }

  /** The scoreboard this game's scores go on now, and its title (see Game.scoreBoard). */
  scoreBoard() {
    return { key: this.board(), title: this.title() };
  }

  /** The best score on the board now. */
  best() {
    return bestScore(this.board());
  }

  /** Puts a score on the board (see record in kit.ts). True: a new best. */
  record(score: number) {
    return record(this.board(), score).isNew;
  }

  /** The status when the layout has nowhere to play the game. */
  setup(message = NEED_ROOF): GameStatusFields {
    return { phase: 'setup', message, score: 0, lives: null, goal: null };
  }
}

/**
 * The effects a game draws with, ticked, drawn and cleared together: the show around the game,
 * motes and waves, and sparks and a flare if the game has them. The game draws its sparks with
 * its roof; the rest goes after its pieces, so the show steps back where a piece is lit.
 */
export class Fx {
  readonly show: Show;
  readonly motes: Motes;
  readonly waves: Waves;
  readonly sparks: Sparks | null;
  readonly flare: Flare | null;

  constructor(yard: Yard, opts: { sparks?: Sparks; flare?: Flare } = {}) {
    this.sparks = opts.sparks ?? null;
    this.motes = new Motes(yard);
    this.waves = new Waves(yard);
    this.flare = opts.flare ?? null;
    this.show = new Show(yard);
  }

  update(dt: number) {
    this.sparks?.update(dt);
    this.motes.update(dt);
    this.waves.update(dt);
    this.flare?.update(dt);
    this.show.update(dt);
  }

  /** After the game's pieces: the motes, the waves, and the show under everything. */
  draw(frame: Frame) {
    this.motes.draw();
    this.waves.draw();
    this.show.draw(frame);
  }

  /** A new game: nothing left over from the last one. */
  clear() {
    this.sparks?.clear();
    this.motes.clear();
    this.waves.clear();
    this.show.clear();
  }
}

/**
 * After the end (`t` seconds after it): the yard throbs a dark red, `glow` strong, after a red
 * flash `flash` strong that fades in the first 0.6 s (0: no flash).
 */
export function endGlow(yard: Yard, t: number, glow: number, flash = 0) {
  if (flash > 0 && t < 0.6) yard.wash(COLORS.bad, flash * (1 - t / 0.6));
  yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(t * 3)), glow);
}
