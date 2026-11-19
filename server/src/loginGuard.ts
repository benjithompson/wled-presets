// Slows down password guessing on the admin sign-in. Failed sign-ins are counted per address and
// per username: a few are free (typos), then each further one has to wait twice as long as the
// last, up to 15 minutes. Per address stops one guesser; per username stops a guesser with many
// addresses. The owner on the home network is never locked out by strangers guessing the
// username (see `lan`), and a good sign-in clears both counts.

const FREE_PER_IP = 5;
const FREE_PER_NAME = 10;
const MAX_WAIT_MS = 15 * 60_000;
/** A count with no failure for this long is forgotten. */
const FORGET_MS = 60 * 60_000;
/** At most this many addresses and usernames are remembered (a flood of new ones cannot fill memory). */
const MAX_KEYS = 10_000;

interface Count {
  fails: number;
  /** No attempt before this. */
  until: number;
  last: number;
}

class Counter {
  private map = new Map<string, Count>();
  private free: number;
  private now: () => number;
  constructor(free: number, now: () => number) {
    this.free = free;
    this.now = now;
  }

  wait(key: string) {
    const c = this.map.get(key);
    return c ? Math.max(0, c.until - this.now()) : 0;
  }

  fail(key: string) {
    const now = this.now();
    let c = this.map.get(key);
    if (c && now - c.last > FORGET_MS) c = undefined;
    if (!c) {
      if (this.map.size >= MAX_KEYS) this.sweep(now);
      c = { fails: 0, until: 0, last: now };
    }
    this.map.delete(key); // re-inserted at the end: the map stays in order of last failure
    c.fails++;
    c.last = now;
    const over = c.fails - this.free;
    if (over > 0) c.until = now + Math.min(MAX_WAIT_MS, 1000 * 2 ** (over - 1));
    this.map.set(key, c);
  }

  clear(key: string) {
    this.map.delete(key);
  }

  private sweep(now: number) {
    for (const [k, c] of this.map) if (now - c.last > FORGET_MS) this.map.delete(k);
    // Still full: forget the oldest.
    for (const k of this.map.keys()) {
      if (this.map.size < MAX_KEYS) break;
      this.map.delete(k);
    }
  }
}

export interface SignInFrom {
  ip: string;
  /** Straight from the home network: the username lock does not apply. */
  lan?: boolean;
}

export class LoginGuard {
  private ips: Counter;
  private names: Counter;

  constructor(now: () => number = Date.now) {
    this.ips = new Counter(FREE_PER_IP, now);
    this.names = new Counter(FREE_PER_NAME, now);
  }

  private static key = (username: string) => username.trim().toLowerCase().slice(0, 100);

  /** Milliseconds until this sign-in may be tried (0: now). A passkey sign-in has no username (null). */
  wait(username: string | null, from: SignInFrom) {
    return Math.max(this.ips.wait(from.ip), from.lan || username == null ? 0 : this.names.wait(LoginGuard.key(username)));
  }

  fail(username: string | null, from: SignInFrom) {
    this.ips.fail(from.ip);
    if (!from.lan && username != null) this.names.fail(LoginGuard.key(username));
  }

  succeed(username: string | null, from: SignInFrom) {
    this.ips.clear(from.ip);
    if (username != null) this.names.clear(LoginGuard.key(username));
  }
}
