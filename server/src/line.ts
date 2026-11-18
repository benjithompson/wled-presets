import { DEFAULT_LINE, LINE_MAX, type LineAdmin, type LineSettings, type LineView, type LineWant } from '../../shared/line.ts';

// The line for the lights (see shared/line.ts): one turn at a time, everyone else waits.
//
// - A tap when the lights are free plays at once and becomes the turn now.
// - Otherwise it joins the end of the line (one place per visitor: a second tap changes what the
//   place is for, and keeps the place).
// - A scene or a color is a turn of showSeconds: then the next in line goes, if anyone waits.
// - A game is a turn for one player. With nobody waiting it lasts as long as they like. Once
//   someone waits, it ends when the game ends (the game host tells the line), or turnMinutes
//   after the wait began.
// - The next player in line is asked to tap Play first (they may have walked off): they have
//   offerSeconds, or the line moves on without them.
// - A signed-in admin never waits: their tap takes the lights at once.
// - Switched off, there is no line: the last tap wins at once, as on a home network.

/** Who asked: their visitor id (a cookie), and what the activity log shows. */
export interface Visitor {
  id: string;
  admin?: boolean;
  actor?: { ip: string; userAgent: string | null };
}

interface Entry {
  id: number;
  who: Visitor;
  want: LineWant;
  label: string;
  joined: number;
}

interface Turn {
  who: Visitor;
  want: LineWant;
  label: string;
  since: number;
  /** When the turn has to end, if it does: a scene's time, or a game's once someone waits. */
  deadline: number | null;
}

export type Asked = { result: 'now' } | { result: 'queued'; place: number } | { result: 'full' };

export type ShowWant = Exclude<LineWant, { kind: 'game' }>;

const isShow = (w: LineWant): w is ShowWant => w.kind !== 'game';

export class Line {
  settings: LineSettings;
  /** Plays a scene or a color whose turn came. */
  onShow: (want: ShowWant, who: Visitor) => void = () => {};
  /** A game turn ended: the game stops. */
  onEndGame: (reason: string) => void = () => {};
  /** Something changed that visitors see. */
  private listeners = new Set<() => void>();
  log: (msg: string) => void = () => {};

  private queue: Entry[] = [];
  private turn: Turn | null = null;
  private offerTo: { entry: Entry; until: number } | null = null;
  private nextId = 1;
  /** Whether the lights were free at the last tick: a scene's time running out frees them. */
  private wasFree = true;
  private now: () => number;

  constructor(settings: LineSettings = DEFAULT_LINE, now: () => number = Date.now) {
    this.settings = { ...settings };
    this.now = now;
  }

  subscribe(fn: () => void) {
    this.listeners.add(fn);
    return () => void this.listeners.delete(fn);
  }

  private changed() {
    for (const fn of this.listeners) fn();
  }

  configure(settings: LineSettings) {
    this.settings = { ...settings };
    if (!settings.enabled) {
      this.queue = [];
      this.offerTo = null;
    }
    if (this.turn) this.turn.deadline = this.deadline(this.turn, this.now(), true);
    this.changed();
  }

  // ---------- Asking ----------

  /** True when a tap plays at once. */
  free(now = this.now()) {
    if (!this.settings.enabled) return true;
    if (this.offerTo || this.queue.length) return false;
    if (!this.turn) return true;
    return isShow(this.turn.want) && now >= this.turn.since + this.settings.showSeconds * 1000;
  }

  /**
   * Someone wants the lights. 'now': the caller plays it at once (and ends what was playing).
   * 'queued': they wait; the line plays it when their turn comes (a scene or color), or asks them
   * to tap Play (a game). 'full': the line is too long.
   */
  ask(who: Visitor, want: LineWant, label: string): Asked {
    const now = this.now();
    const t = this.turn;
    const mine = t?.who.id === who.id;
    if (!this.settings.enabled || who.admin || this.free(now)) {
      // A fresh turn: the clock starts again, unless it is the same player picking another game.
      this.begin(who, want, label, now, mine && !isShow(t!.want) && !isShow(want));
      return { result: 'now' };
    }
    // The one with the lights can change what plays during their turn, but its clock keeps
    // running: another game in a game turn, or a scene or a color in place of either. Turning a
    // scene's minute into a game turn has to wait in line like everyone else.
    if (mine && !(isShow(t!.want) && !isShow(want))) {
      this.begin(who, want, label, now, true);
      return { result: 'now' };
    }
    const at = this.queue.findIndex((e) => e.who.id === who.id);
    if (at >= 0) {
      Object.assign(this.queue[at], { want, label, who });
      this.changed();
      return { result: 'queued', place: at + 1 };
    }
    if (this.queue.length >= LINE_MAX) return { result: 'full' };
    this.queue.push({ id: this.nextId++, who, want, label, joined: now });
    if (this.turn) this.turn.deadline = this.deadline(this.turn, now);
    this.log(`Joined the line for ${label} (${this.queue.length} waiting)`);
    this.changed();
    return { result: 'queued', place: this.queue.length };
  }

  private begin(who: Visitor, want: LineWant, label: string, now: number, keepClock: boolean) {
    const prev = this.turn;
    const turn: Turn = { who, want, label, since: keepClock && prev ? prev.since : now, deadline: keepClock && prev ? prev.deadline : null };
    turn.deadline = this.deadline(turn, now, !keepClock || isShow(want) !== isShow(prev!.want));
    this.turn = turn;
    // Playing now: they no longer wait.
    this.queue = this.queue.filter((e) => e.who.id !== who.id);
    if (this.offerTo?.entry.who.id === who.id) this.offerTo = null;
    this.changed();
  }

  /** When the turn has to end: a scene's minute; a game's turn from when someone began to wait. */
  private deadline(t: Turn, now: number, fresh = false): number | null {
    if (isShow(t.want)) return t.since + this.settings.showSeconds * 1000;
    if (!this.waitingCount()) return null;
    return !fresh && t.deadline != null ? t.deadline : now + this.settings.turnMinutes * 60_000;
  }

  /** The player being asked to play takes their turn. Returns the game, or null if it was not theirs. */
  accept(visitor: string): string | null {
    const o = this.offerTo;
    if (!o || o.entry.who.id !== visitor || o.entry.want.kind !== 'game') return null;
    this.offerTo = null;
    const now = this.now();
    this.turn = { who: o.entry.who, want: o.entry.want, label: o.entry.label, since: now, deadline: null };
    this.turn.deadline = this.deadline(this.turn, now, true);
    this.log(`Turn: ${o.entry.label}`);
    this.changed();
    return o.entry.want.game;
  }

  /** A visitor leaves the line (or says no to their turn). */
  leave(visitor: string) {
    const before = this.queue.length;
    this.queue = this.queue.filter((e) => e.who.id !== visitor);
    let changed = before !== this.queue.length;
    if (this.offerTo?.entry.who.id === visitor) {
      this.offerTo = null;
      this.next();
      changed = true;
    }
    if (changed) {
      this.settle();
      this.changed();
    }
  }

  /** The player's game turn is over (the game ended with someone waiting, they stopped, or they left). */
  release(visitor: string, reason: string) {
    if (this.holder() !== visitor) return;
    this.pass(reason);
  }

  /** Ends the turn now, whatever it is, and the next in line goes. */
  pass(reason: string) {
    const t = this.turn;
    this.turn = null;
    if (t && !isShow(t.want)) this.onEndGame(reason);
    this.next();
    this.changed();
  }

  /** An admin takes someone out of the line. */
  remove(id: number) {
    if (this.offerTo?.entry.id === id) {
      this.offerTo = null;
      this.next();
    } else {
      const before = this.queue.length;
      this.queue = this.queue.filter((e) => e.id !== id);
      if (before === this.queue.length) return false;
    }
    this.settle();
    this.changed();
    return true;
  }

  /** The next in line goes: a scene or a color plays, or the next player is asked. */
  private next() {
    if (this.offerTo || this.turn) return;
    const e = this.queue.shift();
    if (!e) return;
    const now = this.now();
    if (e.want.kind === 'game') {
      this.offerTo = { entry: e, until: now + this.settings.offerSeconds * 1000 };
      this.log(`Next up: ${e.label}`);
      return;
    }
    this.turn = { who: e.who, want: e.want, label: e.label, since: now, deadline: now + this.settings.showSeconds * 1000 };
    this.log(`From the line: ${e.label}`);
    this.onShow(e.want, e.who);
  }

  /** After someone left the line: a game turn with nobody waiting has no end any more. */
  private settle() {
    if (this.turn) this.turn.deadline = this.deadline(this.turn, this.now());
  }

  /** Checks the timers (offers that run out, turns whose time is up). The game host calls it twice a second. */
  tick() {
    const now = this.now();
    if (this.offerTo && now >= this.offerTo.until) {
      this.log(`Skipped in the line: ${this.offerTo.entry.label} (no answer)`);
      this.offerTo = null;
      this.next();
      this.settle();
      this.changed();
    }
    const t = this.turn;
    if (t && this.waitingCount() && t.deadline != null && now >= t.deadline) this.pass(isShow(t.want) ? 'its time was up' : 'the turn was up');
    else if (!this.turn && !this.offerTo && this.queue.length) {
      this.next();
      this.changed();
    }
    const free = this.free(now);
    if (free !== this.wasFree) {
      this.wasFree = free;
      this.changed();
    }
  }

  // ---------- Looking ----------

  /** The visitor with a game turn now. */
  holder(): string | null {
    return this.turn && !isShow(this.turn.want) ? this.turn.who.id : null;
  }

  /** People waiting, counting the one being asked to play. */
  waitingCount() {
    return this.queue.length + (this.offerTo ? 1 : 0);
  }

  /** The game the visitor is being asked to play, if it is their turn. */
  offerFor(visitor: string) {
    return this.offerTo?.entry.who.id === visitor && this.offerTo.entry.want.kind === 'game' ? this.offerTo.entry.want.game : null;
  }

  /** Whole seconds, so a view only changes once a second. */
  private left(at: number, now: number) {
    return Math.max(0, Math.ceil((at - now) / 1000) * 1000);
  }

  view(visitor: string): LineView {
    const now = this.now();
    const t = this.turn;
    const at = this.queue.findIndex((e) => e.who.id === visitor);
    const o = this.offerTo;
    const counts = t?.deadline != null && (this.waitingCount() > 0 || (isShow(t.want) && now < t.deadline));
    return {
      enabled: this.settings.enabled,
      now: t ? { kind: t.want.kind, label: t.label, you: t.who.id === visitor } : null,
      endsIn: counts ? this.left(t!.deadline!, now) : null,
      waiting: this.queue.length,
      free: this.free(now),
      you: at >= 0 ? { place: at + 1, kind: this.queue[at].want.kind, label: this.queue[at].label } : null,
      offer: o && o.entry.who.id === visitor && o.entry.want.kind === 'game' ? { game: o.entry.want.game, label: o.entry.label, endsIn: this.left(o.until, now) } : null,
      calling: !!o && o.entry.who.id !== visitor
    };
  }

  adminView(): LineAdmin {
    const now = this.now();
    const t = this.turn;
    return {
      settings: { ...this.settings },
      now: t ? { kind: t.want.kind, label: t.label, since: t.since, endsIn: t.deadline != null ? Math.max(0, t.deadline - now) : null } : null,
      offer: this.offerTo ? { label: this.offerTo.entry.label, endsIn: Math.max(0, this.offerTo.until - now) } : null,
      entries: [...(this.offerTo ? [this.offerTo.entry] : []), ...this.queue].map((e) => ({ id: e.id, kind: e.want.kind, label: e.label, waited: now - e.joined }))
    };
  }
}
