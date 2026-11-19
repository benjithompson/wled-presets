import { bodyLimit } from 'hono/body-limit';
import type { MiddlewareHandler } from 'hono';

/** Fixed-window, in-memory rate limiter keyed by client IP. Enough for a single-container LAN app. */
export function rateLimit({ windowMs, max, clientIp, skip }: { windowMs: number; max: number; clientIp: (c: any) => string; skip?: (c: any) => boolean }): MiddlewareHandler {
  const hits = new Map<string, { count: number; reset: number }>();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();

  return async (c, next) => {
    if (skip?.(c)) return next();
    const key = clientIp(c);
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.reset < now) hits.set(key, (h = { count: 0, reset: now + windowMs }));
    h.count++;
    c.header('RateLimit-Limit', String(max));
    c.header('RateLimit-Remaining', String(Math.max(0, max - h.count)));
    if (h.count > max) {
      c.header('Retry-After', String(Math.ceil((h.reset - now) / 1000)));
      return c.json({ error: 'Too many requests. Wait a moment and try again.' }, 429);
    }
    await next();
  };
}

/**
 * Long-lived connections (event streams, WebSockets) open at once: at most `perKey` for one
 * address and `total` in all, so one visitor cannot hold every socket the server has.
 */
export class ConnectionLimit {
  private open = new Map<string, number>();
  private count = 0;
  private perKey: number;
  private total: number;
  constructor(perKey: number, total: number) {
    this.perKey = perKey;
    this.total = total;
  }

  /**
   * Takes a place for `key`. Returns the function that gives it back (call it once the connection
   * closed), or null when there is no place. `shared`: a key that many visitors share (a proxy's
   * own address when TRUST_PROXY is off) only counts toward the total.
   */
  take(key: string, shared = false): (() => void) | null {
    const n = this.open.get(key) ?? 0;
    if (this.count >= this.total || (!shared && n >= this.perKey)) return null;
    this.open.set(key, n + 1);
    this.count++;
    let given = false;
    return () => {
      if (given) return;
      given = true;
      this.count--;
      const left = (this.open.get(key) ?? 1) - 1;
      if (left > 0) this.open.set(key, left);
      else this.open.delete(key);
    };
  }
}

/**
 * A size limit for request bodies that are read before anyone signed in (sign-in, colors): the
 * server would otherwise hold a body of any size in memory.
 */
export const limitBody =
  (maxSize: number, skip?: (c: any) => boolean): MiddlewareHandler =>
  async (c, next) => {
    if (skip?.(c)) return next();
    return bodyLimit({ maxSize, onError: (c) => c.json({ error: 'The request is too large' }, 413) })(c, next);
  };
