import { DEFAULT_LINE, LINE_MAX, LINE_SHOWN, type LineAdmin, type LineSettings, type LineView, type LineWant } from '../../shared/line.ts';
import { isLoopbackIp } from './clientIp.ts';

/**
 * The most places in line from one address. A household or a group on one Wi-Fi shares an
 * address; more than this from one is someone filling the line so nobody else gets a turn.
 */
export const LINE_PER_ADDRESS = 4;

// The line for the lights (see shared/line.ts): one turn at a time, everyone else waits.
//
// - A tap when the lights are free plays at once and becomes the turn now.
// - Otherwise it joins the end of the line (one place per visitor: a second tap changes what the
//   place is for, and keeps the place).
// - A scene or a color is a short turn (quickSeconds) when nobody else waits, so the next one to
//   come along is not kept waiting for nothing; one whose turn comes while others still wait
//   plays showSeconds. Then the next in line goes, if anyone waits.
// - A game is a turn for one player, turnMinutes long: everyone sees its clock. With nobody waiting
//   when the time is up, it plays on; then someone who joins gives it one more minute (LAST_CALL_MS).
//   With someone waiting, it also ends when the game ends (the game host tells the line).
// - The next player's game starts on its own when their turn comes, if their play page is open
//   (the game host says); then they have offerSeconds to start playing. Otherwise they are asked
//   to tap Play (they may have walked off): they have offerSeconds, or the line moves on without them.
// - The one with the lights who picks again while others wait goes to the back of the line, so
//   nobody can keep the lights by picking over and over.
// - Throttle: after a scene or a color of theirs plays, a visitor cannot pick another for
//   quickSeconds (not even to change their own turn), so nobody can flick the lights about.
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
  /** When the turn has to end, if it does: a scene's time, or a game's (see LAST_CALL_MS). */
  deadline: number | null;
  /** A game turn's time ran out with nobody waiting, and someone joined: it got its last minute. */
  lastCall?: boolean;
}

/** A game turn whose time ran out with nobody waiting ends this long after someone joins. */
export const LAST_CALL_MS = 60_000;

export type Asked = { result: 'now' } | { result: 'queued'; place: number } | { result: 'full' } | { result: 'wait'; retryIn: number };

export type ShowWant = Exclude<LineWant, { kind: 'game' }>;

const isShow = (w: LineWant): w is ShowWant => w.kind !== 'game';

export class Line {
  settings: LineSettings;
  /** Plays a scene or a color whose turn came. */
  onShow: (want: ShowWant, who: Visitor) => void = () => {};
  /** A game turn ended: the game stops. */
  onEndGame: (reason: string) => void = () => {};
  /** Whether a visitor has a play page open: then their game starts on its own when their turn comes. */
  present: (visitor: string) => boolean = () => false;
  /** A game turn began from the line, without a tap: the game host starts the game for them. */
  onStartGame: (game: string, who: Visitor) => void = () => {};
  /** Something changed that visitors see. */
  private listeners = new Set<() => void>();
  log: (msg: string) => void = () => {};

  private queue: Entry[] = [];
  private turn: Turn | null = null;
  private offerTo: { entry: Entry; until: number } | null = null;
  private nextId = 1;
  /** When each visitor's last scene or color began to play (for the throttle). */
  private changedAt = new Map<string, number>();
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
    this.version++;
    for (const fn of this.listeners) fn();
  }

  /** Bumped with every change: views are worked out once for each (see starts). */
  private version = 0;
  private startsCache: { key: string; at: number[] } | null = null;
  private placesCache: { version: number; at: Map<string, number> } | null = null;

  /** A visitor's place in line (0: next), or -1. */
  private placeOf(visitor: string) {
    if (this.placesCache?.version !== this.version) this.placesCache = { version: this.version, at: new Map(this.queue.map((e, i) => [e.who.id, i])) };
    return this.placesCache.at.get(visitor) ?? -1;
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
    return isShow(this.turn.want) && this.turn.deadline != null && now >= this.turn.deadline;
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
    const retryIn = isShow(want) && !who.admin ? this.cooldown(who.id, now) : 0;
    if (retryIn > 0) return { result: 'wait', retryIn };
    if (!this.settings.enabled || who.admin || this.free(now)) {
      // A fresh turn: the clock starts again, unless it is the same player picking another game.
      this.begin(who, want, label, now, mine && !isShow(t!.want) && !isShow(want));
      return { result: 'now' };
    }
    // While nobody else waits, the one with the lights can change what plays during their turn,
    // but its clock keeps running: another game in a game turn, or a scene or a color in place of
    // either. While others wait, a pick of theirs goes to the back of the line like anyone's.
    if (mine && !this.waitingCount()) {
      this.begin(who, want, label, now, true);
      return { result: 'now' };
    }
    const at = this.queue.findIndex((e) => e.who.id === who.id);
    if (at >= 0) {
      Object.assign(this.queue[at], { want, label, who });
      this.changed();
      return { result: 'queued', place: at + 1 };
    }
    if (this.queue.length >= LINE_MAX || this.placesOf(who) >= LINE_PER_ADDRESS) return { result: 'full' };
    this.queue.push({ id: this.nextId++, who, want, label, joined: now });
    this.settle();
    this.log(`Joined the line for ${label} (${this.queue.length} waiting)`);
    this.changed();
    return { result: 'queued', place: this.queue.length };
  }

  private begin(who: Visitor, want: LineWant, label: string, now: number, keepClock: boolean) {
    const prev = this.turn;
    const turn: Turn = { who, want, label, since: keepClock && prev ? prev.since : now, deadline: keepClock && prev ? prev.deadline : null, lastCall: keepClock && prev ? prev.lastCall : false };
    turn.deadline = this.deadline(turn, now, !keepClock || isShow(want) !== isShow(prev!.want));
    this.turn = turn;
    if (isShow(want) && !who.admin) this.changedAt.set(who.id, now);
    // Playing now: they no longer wait.
    this.queue = this.queue.filter((e) => e.who.id !== who.id);
    if (this.offerTo?.entry.who.id === who.id) this.offerTo = null;
    this.changed();
  }

  /**
   * Places in line held from this visitor's address. A visitor id is only a cookie: one person can
   * make as many as they like, so the line counts addresses too. A loopback address is a proxy's
   * own (TRUST_PROXY off): it does not tell visitors apart, so it is not counted.
   */
  private placesOf(who: Visitor) {
    const ip = who.actor?.ip;
    if (who.admin || !ip || ip === 'unknown' || isLoopbackIp(ip)) return 0;
    return this.queue.filter((e) => e.who.actor?.ip === ip).length;
  }

  /**
   * When the turn has to end: a scene's time; a game's turnMinutes from its start. A game whose
   * time ran out with nobody waiting plays on, and gets one last minute once someone waits.
   */
  private deadline(t: Turn, now: number, fresh = false): number | null {
    if (isShow(t.want)) return !fresh && t.deadline != null ? t.deadline : t.since + this.showLength();
    const end = fresh || t.deadline == null ? t.since + this.settings.turnMinutes * 60_000 : t.deadline;
    if (fresh) t.lastCall = false;
    if (this.waitingCount() && !t.lastCall && now >= end) {
      t.lastCall = true;
      return now + LAST_CALL_MS;
    }
    return end;
  }

  /** How long until this visitor may pick a scene or a color again (0: now). */
  private cooldown(visitor: string, now: number) {
    const at = this.changedAt.get(visitor);
    if (at == null || !this.settings.enabled) return 0;
    return Math.max(0, at + this.settings.quickSeconds * 1000 - now);
  }

  /** How long a scene or a color starting now plays: short with nobody else waiting. */
  private showLength() {
    return (this.waitingCount() ? this.settings.showSeconds : this.settings.quickSeconds) * 1000;
  }

  /** The player being asked to play takes their turn. Returns the game, or null if it was not theirs. */
  accept(visitor: string): string | null {
    const o = this.offerTo;
    if (!o || o.entry.who.id !== visitor || o.entry.want.kind !== 'game') return null;
    this.offerTo = null;
    const now = this.now();
    this.gameTurn(o.entry, now);
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

  /** Empties the line and ends the turn now, for example when an admin switches the lights off. */
  clear(reason: string) {
    const t = this.turn;
    this.turn = null;
    this.offerTo = null;
    this.queue = [];
    if (t && !isShow(t.want)) this.onEndGame(reason);
    this.log(`The line was emptied: ${reason}`);
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
    // Views worked out before this are out of date (the callbacks below may send some).
    this.version++;
    const now = this.now();
    if (e.want.kind === 'game') {
      if (this.present(e.who.id)) {
        // Their play page is open: the game starts for them.
        this.gameTurn(e, now);
        this.log(`Turn: ${e.label}`);
        this.onStartGame(e.want.game, e.who);
        return;
      }
      this.offerTo = { entry: e, until: now + this.settings.offerSeconds * 1000 };
      this.log(`Next up: ${e.label}`);
      return;
    }
    this.turn = { who: e.who, want: e.want, label: e.label, since: now, deadline: now + this.showLength() };
    if (!e.who.admin) this.changedAt.set(e.who.id, now);
    this.log(`From the line: ${e.label}`);
    this.onShow(e.want, e.who);
  }

  private gameTurn(e: Entry, now: number) {
    this.turn = { who: e.who, want: e.want, label: e.label, since: now, deadline: null };
    this.turn.deadline = this.deadline(this.turn, now, true);
  }

  /** After someone joined or left the line: a scene's or a game's end may change (see deadline). */
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
    // A throttle that runs out: that visitor sees they can pick again.
    let cooled = false;
    for (const [id] of this.changedAt) {
      if (this.cooldown(id, now) > 0) continue;
      this.changedAt.delete(id);
      cooled = true;
    }
    if (cooled) this.changed();
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

  /**
   * At the latest, when each place in line gets its turn (a time, not from now): what plays now,
   * then each turn ahead at its longest (a game may end sooner). Worked out once for every view of
   * the same line in the same second: hundreds of phones each get one, many times a second.
   */
  private starts(now: number): number[] {
    const key = `${this.version}:${Math.floor(now / 1000)}`;
    if (this.startsCache?.key === key) return this.startsCache.at;
    const t = this.turn;
    let at = now;
    if (t?.deadline != null) at = Math.max(now, t.deadline);
    const turn = this.settings.turnMinutes * 60_000;
    const game = this.settings.offerSeconds * 1000 + turn;
    if (this.offerTo) at = Math.max(at, this.offerTo.until) + turn;
    const out: number[] = [];
    for (const e of this.queue) {
      out.push(at);
      at += e.want.kind === 'game' ? game : this.settings.showSeconds * 1000;
    }
    this.startsCache = { key, at: out };
    return out;
  }

  /** When the one at this place in line (0: next) gets their turn, at the latest, from now. */
  private startsIn(at: number, now: number): number {
    return this.left(this.starts(now)[at] ?? now, now);
  }

  view(visitor: string): LineView {
    const now = this.now();
    const t = this.turn;
    const at = this.placeOf(visitor);
    const o = this.offerTo;
    const counts = t?.deadline != null && (this.waitingCount() > 0 || now < t.deadline);
    const shown = [...(o ? [{ who: o.entry.who, want: o.entry.want, label: o.entry.label, startsIn: 0 }] : []), ...this.queue.slice(0, LINE_SHOWN).map((e, i) => ({ ...e, startsIn: this.startsIn(i, now) }))].slice(0, LINE_SHOWN);
    return {
      enabled: this.settings.enabled,
      now: t ? { kind: t.want.kind, label: t.label, you: t.who.id === visitor } : null,
      endsIn: counts ? this.left(t!.deadline!, now) : null,
      waiting: this.queue.length,
      ahead: shown.map((e) => ({ kind: e.want.kind, label: e.label, you: e.who.id === visitor, startsIn: e.startsIn })),
      free: this.free(now),
      you: at >= 0 ? { place: at + 1, kind: this.queue[at].want.kind, label: this.queue[at].label, startsIn: this.startsIn(at, now) } : null,
      offer: o && o.entry.who.id === visitor && o.entry.want.kind === 'game' ? { game: o.entry.want.game, label: o.entry.label, endsIn: this.left(o.until, now) } : null,
      calling: !!o && o.entry.who.id !== visitor,
      cooldown: this.cooldown(visitor, now) > 0 ? this.left(now + this.cooldown(visitor, now), now) : null
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
