// Taking turns with the lights. The site is open to anyone, so many people can want the house at
// once: they wait in one line, like at an arcade or a request jukebox for a light show. A game is
// a turn for one player; a scene or a color plays for a while before the next person in line goes.

/** What someone waits in line for. */
export type LineWant = { kind: 'game'; game: string } | { kind: 'scene'; id: string } | { kind: 'color'; hex: string };

export interface LineSettings {
  /** Off: no line, the last choice wins at once (fine at home, on the local network). */
  enabled: boolean;
  /**
   * A scene or a color picked while nobody else waits keeps the lights this long: someone who
   * comes along next (for a scene or a game) waits no longer than that. It is also a throttle:
   * after a scene or a color of theirs plays, a visitor cannot pick another for this long.
   */
  quickSeconds: number;
  /** A scene or a color whose turn comes while others still wait plays this long. */
  showSeconds: number;
  /**
   * When someone is waiting, a game turn ends when its game ends, or this long after the wait
   * began, whichever comes first. With nobody waiting, a turn lasts as long as the player likes.
   */
  turnMinutes: number;
  /** The next player has this long to tap Play, or the line moves on without them. */
  offerSeconds: number;
}

export const DEFAULT_LINE: LineSettings = { enabled: true, quickSeconds: 10, showSeconds: 60, turnMinutes: 5, offerSeconds: 30 };

/** The most people in line at once. */
export const LINE_MAX = 30;

/** What one visitor sees of the line. Times are milliseconds from now (clocks differ). */
export interface LineView {
  enabled: boolean;
  /** What has the lights now: a game being played, or a scene or color someone picked. */
  now: { kind: LineWant['kind']; label: string; you: boolean } | null;
  /** When the turn now ends, if it has to (someone is waiting, or a scene's time is not up). */
  endsIn: number | null;
  /** People waiting, not counting the one being asked to play. */
  waiting: number;
  /** True when a tap plays at once: nobody has the lights, or a scene's time is up and nobody waits. */
  free: boolean;
  /**
   * This visitor's place in line (1: next) and what for. startsIn: about when their turn comes,
   * when that can be told (not with a game ahead of them, which may end any time).
   */
  you: { place: number; kind: LineWant['kind']; label: string; startsIn: number | null } | null;
  /** It is this visitor's turn to play: they have until then to tap Play. */
  offer: { game: string; label: string; endsIn: number } | null;
  /** Someone else is being asked to play (the lights wait for them). */
  calling: boolean;
  /** This visitor changed the lights lately: they can pick a scene or a color again after this. */
  cooldown: number | null;
}

/** The line as an admin sees it (Admin → Games). */
export interface LineAdmin {
  settings: LineSettings;
  now: { kind: LineWant['kind']; label: string; since: number; endsIn: number | null } | null;
  offer: { label: string; endsIn: number } | null;
  entries: { id: number; kind: LineWant['kind']; label: string; waited: number }[];
}

/** 1st, 2nd, 3rd… */
export const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? 'th' : (['th', 'st', 'nd', 'rd'][n % 10] ?? 'th')}`;

/** "0:45", "4:10". */
export const clock = (ms: number) => {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};
