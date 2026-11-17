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
