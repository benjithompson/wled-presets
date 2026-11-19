import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { Context, MiddlewareHandler } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { Db } from './db.ts';
import { viaHttps } from './clientIp.ts';
import { LoginGuard, type SignInFrom } from './loginGuard.ts';

export const COOKIE = 'wled_session';
const TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days, renewed on use
const RENEW_AFTER_MS = 1000 * 60 * 60; // write at most once an hour
const COST = 12;

const hash = (token: string) => crypto.createHash('sha256').update(token).digest('hex');
// Compared against when the username is unknown, so response time does not reveal valid names.
// A fixed hash of a random password (same cost), so even the first such sign-in takes as long.
const DUMMY_HASH = '$2b$12$PPwLkc6WzLbB8yKeiGtye.NoZtGcEo660Wfr80lyy95Ub3DYEMxKG';

/**
 * Passwords from the examples (.env.example, docker-compose.yml) and other first guesses. The
 * site is on the internet: an account that still has one only signs in from the home network.
 */
const EXAMPLE_PASSWORDS = new Set(['change-me-to-something-long', 'change-me', 'changeme', 'admin', 'password', 'wled', 'christmas']);
export const isExamplePassword = (p: string) => EXAMPLE_PASSWORDS.has(p.trim().toLowerCase());

export type SignIn = { ok: true; user: { id: string; username: string } } | { ok: false; retryIn?: number };

export type AuthEnv = { Variables: { user: { id: string; username: string } } };

export function createAuth(db: Db, opts: { secureCookie: boolean }) {
  const guard = new LoginGuard();

  function currentUser(c: Context) {
    const token = getCookie(c, COOKIE);
    if (!token) return null;
    const key = hash(token);
    const s = db.getSession(key);
    if (!s || s.expiresAt < Date.now()) {
      if (s) db.deleteSession(key);
      return null;
    }
    if (s.expiresAt - Date.now() < TTL_MS - RENEW_AFTER_MS) {
      db.touchSession(key, Date.now() + TTL_MS);
      setSessionCookie(c, token);
    }
    return db.getUserById(s.userId);
  }

  function setSessionCookie(c: Context, token: string) {
    setCookie(c, COOKIE, token, {
      httpOnly: true,
      sameSite: 'Strict',
      // Also over HTTPS at a proxy in front (Cloudflare): the browser then only sends it over HTTPS.
      secure: opts.secureCookie || viaHttps(c),
      path: '/',
      maxAge: TTL_MS / 1000
    });
  }

  /** The user of a session token (a WebSocket's cookie), without renewing the session. */
  function userForToken(token: string) {
    const s = db.getSession(hash(token));
    return s && s.expiresAt >= Date.now() ? db.getUserById(s.userId) : null;
  }

  return {
    currentUser,
    userForToken,

    async verify(username: string, password: string) {
      const user = db.getUserByName(username.trim());
      const ok = await bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH);
      return user && ok ? user : null;
    },

    /**
     * Signs in and sets the session cookie. Failed sign-ins slow down further tries (per address
     * and per username, see LoginGuard): `retryIn` says how long to wait.
     */
    async login(c: Context, username: string, password: string, from: SignInFrom = { ip: 'unknown' }): Promise<SignIn> {
      const wait = guard.wait(username, from);
      if (wait > 0) return { ok: false, retryIn: wait };
      let user = await this.verify(username, password);
      // An example password is known to everyone: it only works from the home network.
      if (user && isExamplePassword(password) && !from.lan) user = null;
      if (!user) {
        guard.fail(username, from);
        return { ok: false };
      }
      guard.succeed(username, from);
      const token = crypto.randomBytes(32).toString('base64url');
      db.purgeSessions();
      db.createSession(hash(token), user.id, Date.now() + TTL_MS);
      setSessionCookie(c, token);
      return { ok: true, user: { id: user.id, username: user.username } };
    },

    logout(c: Context) {
      const token = getCookie(c, COOKIE);
      if (token) db.deleteSession(hash(token));
      deleteCookie(c, COOKIE, { path: '/' });
    },

    /** A new password signs out the user's other sessions (a stolen cookie stops working). `c`: the session to keep. */
    async setPassword(userId: string, password: string, c?: Context) {
      db.updatePassword(userId, await bcrypt.hash(password, COST));
      const token = c ? getCookie(c, COOKIE) : undefined;
      db.deleteUserSessions(userId, token ? hash(token) : '');
    },

    async createUser(username: string, password: string) {
      const passwordHash = await bcrypt.hash(password, COST);
      return db.createUser(crypto.randomUUID(), username.trim(), passwordHash);
    },

    require: (): MiddlewareHandler<AuthEnv> => async (c, next) => {
      const user = currentUser(c);
      if (!user) return c.json({ error: 'Unauthorized' }, 401);
      c.set('user', user);
      await next();
    }
  };
}

export type Auth = ReturnType<typeof createAuth>;

/**
 * CSRF guard for cookie-authenticated writes. The cookie is SameSite=Strict already;
 * this also rejects requests whose Origin names another host.
 */
export const sameOrigin = (): MiddlewareHandler => async (c, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) return next();
  const origin = c.req.header('origin');
  // No Origin (an older browser, or a form post): the browser still says where it came from.
  if (!origin && c.req.header('sec-fetch-site') === 'cross-site') return c.json({ error: 'Forbidden' }, 403);
  if (origin) {
    try {
      if (new URL(origin).host !== c.req.header('host')) return c.json({ error: 'Forbidden' }, 403);
    } catch {
      return c.json({ error: 'Forbidden' }, 403);
    }
  }
  await next();
};
