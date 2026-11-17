import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { Context, MiddlewareHandler } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { Db } from './db.ts';

export const COOKIE = 'wled_session';
const TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days, renewed on use
const RENEW_AFTER_MS = 1000 * 60 * 60; // write at most once an hour

const hash = (token: string) => crypto.createHash('sha256').update(token).digest('hex');
// Compared against when the username is unknown, so response time does not reveal valid names.
let dummyHash: string | null = null;

export type AuthEnv = { Variables: { user: { id: string; username: string } } };

export function createAuth(db: Db, opts: { secureCookie: boolean }) {
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
      secure: opts.secureCookie,
      path: '/',
      maxAge: TTL_MS / 1000
    });
  }

  return {
    currentUser,

    async verify(username: string, password: string) {
      const user = db.getUserByName(username.trim());
      dummyHash ??= await bcrypt.hash(crypto.randomUUID(), 12);
      const ok = await bcrypt.compare(password, user?.passwordHash ?? dummyHash);
      return user && ok ? user : null;
    },

    async login(c: Context, username: string, password: string) {
      const user = await this.verify(username, password);
      if (!user) return null;
      const token = crypto.randomBytes(32).toString('base64url');
      db.purgeSessions();
      db.createSession(hash(token), user.id, Date.now() + TTL_MS);
      setSessionCookie(c, token);
      return { id: user.id, username: user.username };
    },

    logout(c: Context) {
      const token = getCookie(c, COOKIE);
      if (token) db.deleteSession(hash(token));
      deleteCookie(c, COOKIE, { path: '/' });
    },

    async setPassword(userId: string, password: string) {
      db.updatePassword(userId, await bcrypt.hash(password, 12));
    },

    async createUser(username: string, password: string) {
      const passwordHash = await bcrypt.hash(password, 12);
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
  if (origin) {
    try {
      if (new URL(origin).host !== c.req.header('host')) return c.json({ error: 'Forbidden' }, 403);
    } catch {
      return c.json({ error: 'Forbidden' }, 403);
    }
  }
  await next();
};
