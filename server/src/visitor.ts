import crypto from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import type { Visitor } from './line.ts';
import { isLoopbackIp, upgradeIp, viaHttps, type TrustProxy } from './clientIp.ts';
import type { ConnectionLimit } from './rateLimit.ts';

// Who is who, for the line for the lights: each browser gets a random visitor id in a cookie
// (no name, nothing else). The same id on the public page and the play page, and after a reload,
// keeps a visitor's place in line and their turn.

export const VISITOR_COOKIE = 'wled_visitor';
const VALID = /^[A-Za-z0-9_-]{16,64}$/;
const YEAR_S = 365 * 24 * 3600;

/** Ids given out by this request (the browser only sends the cookie from its next request). */
const given = new WeakMap<Request, string>();

/** Gives each browser without a visitor id one. */
export const visitorCookie =
  (secure: boolean): MiddlewareHandler =>
  async (c, next) => {
    const have = getCookie(c, VISITOR_COOKIE);
    const id = have && VALID.test(have) ? null : crypto.randomBytes(18).toString('base64url');
    if (id) given.set(c.req.raw, id);
    await next();
    if (!id) return;
    try {
      setCookie(c, VISITOR_COOKIE, id, { httpOnly: true, sameSite: 'Lax', secure: secure || viaHttps(c), path: '/', maxAge: YEAR_S });
    } catch {
      // A response whose headers cannot change: the next request gets one.
    }
  };

/** The visitor id of a request. */
export function visitorId(c: Context): string {
  const have = getCookie(c, VISITOR_COOKIE);
  if (have && VALID.test(have)) return have;
  return given.get(c.req.raw) ?? `r:${crypto.randomUUID()}`;
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? '').split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    const k = part.slice(0, at).trim();
    if (!k || k in out) continue;
    try {
      out[k] = decodeURIComponent(part.slice(at + 1).trim());
    } catch {
      out[k] = part.slice(at + 1).trim();
    }
  }
  return out;
}

/**
 * Who opened a WebSocket: their visitor id, whether an admin, and their IP (for the log, and the
 * line's limit per address). Without a visitor cookie, a new visitor each time.
 */
export function upgradeVisitor(req: IncomingMessage, opts: { trustProxy: TrustProxy; isAdmin: (sessionToken: string) => boolean; sessionCookie: string }): Visitor {
  const cookies = parseCookies(req.headers.cookie);
  const id = cookies[VISITOR_COOKIE];
  const token = cookies[opts.sessionCookie];
  const ip = upgradeIp(req, opts.trustProxy);
  const ua = req.headers['user-agent'];
  const actor = { ip, userAgent: typeof ua === 'string' ? ua.slice(0, 300) : null };
  if (!id || !VALID.test(id)) return { id: `c:${crypto.randomUUID()}`, actor };
  return { id, admin: !!token && opts.isAdmin(token), actor };
}

/**
 * Whether a WebSocket may open. A page on another site cannot open one (its Origin names another
 * host), and one address holds only so many at once. Returns the function to call once the
 * socket closed, or null to refuse it.
 */
export function admitUpgrade(req: IncomingMessage, opts: { trustProxy: TrustProxy; limit: ConnectionLimit }): (() => void) | null {
  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).host !== req.headers.host) return null;
    } catch {
      return null;
    }
  }
  const ip = upgradeIp(req, opts.trustProxy);
  return opts.limit.take(ip, isLoopbackIp(ip));
}

/**
 * A visitor's short tag in the activity log: the start of their id, the same on every visit
 * from that browser, so one person's picks can be followed without telling who they are.
 */
export const visitorTag = (id: string) => id.replace(/^c:/, '').slice(0, 6);

/** How a visitor is named in the activity log: their tag and the address they came from. */
export const visitorLabel = (tag: string, ip?: string | null) => (ip ? `Visitor ${tag} (${ip})` : `Visitor ${tag}`);
