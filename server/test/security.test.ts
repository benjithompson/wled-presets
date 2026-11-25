import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { WebSocket } from 'ws';
import { createApp } from '../src/app.ts';
import { COOKIE, createAuth } from '../src/auth.ts';
import { addressKey, isDirectLan, isLocal, parseTrustProxy, pickIp } from '../src/clientIp.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { GameHost } from '../src/game/host.ts';
import { Lights } from '../src/lights.ts';
import { LINE_PER_ADDRESS, Line } from '../src/line.ts';
import { LoginGuard } from '../src/loginGuard.ts';
import { ConnectionLimit } from '../src/rateLimit.ts';
import { admitUpgrade, upgradeVisitor } from '../src/visitor.ts';
import { DEFAULT_LINE } from '../../shared/line.ts';
import { sampleLayout } from '../../shared/layout.ts';

const headers =
  (h: Record<string, string>) =>
  (name: string): string | undefined =>
    h[name];

describe('client address', () => {
  it('reads TRUST_PROXY', () => {
    expect(parseTrustProxy(undefined)).toBe(false);
    expect(parseTrustProxy('0')).toBe(false);
    expect(parseTrustProxy('1')).toBe(1);
    expect(parseTrustProxy('true')).toBe(1);
    expect(parseTrustProxy('2')).toBe(2);
    expect(parseTrustProxy('cloudflare')).toBe('cloudflare');
  });

  it('believes only the entries the trusted proxies added to X-Forwarded-For', () => {
    // The visitor sent "X-Forwarded-For: 127.0.0.1"; Cloudflare appended their real address.
    const h = headers({ 'x-forwarded-for': '127.0.0.1, 203.0.113.9' });
    expect(pickIp(h, '127.0.0.1', 1)).toBe('203.0.113.9');
    expect(pickIp(h, '127.0.0.1', 2)).toBe('127.0.0.1');
    expect(pickIp(h, '127.0.0.1', false)).toBe('127.0.0.1');
    expect(pickIp(headers({ 'x-forwarded-for': 'not-an-ip' }), '10.0.0.2', 1)).toBe('10.0.0.2');
  });

  it('reads CF-Connecting-IP with TRUST_PROXY=cloudflare only', () => {
    const h = headers({ 'cf-connecting-ip': '198.51.100.7', 'x-forwarded-for': '1.1.1.1, 198.51.100.7' });
    expect(pickIp(h, '127.0.0.1', 'cloudflare')).toBe('198.51.100.7');
    expect(pickIp(headers({ 'cf-connecting-ip': '127.0.0.1' }), '192.168.1.5', false)).toBe('192.168.1.5');
  });

  it('does not take a request through cloudflared for one from this computer', () => {
    // cloudflared on the same computer: the connection is from 127.0.0.1.
    expect(isLocal(headers({ host: 'lights.example.com', 'cf-connecting-ip': '203.0.113.9', 'x-forwarded-for': '203.0.113.9' }), '127.0.0.1')).toBe(false);
    // Even a proxy that adds no headers: the host is not this computer.
    expect(isLocal(headers({ host: 'lights.example.com' }), '127.0.0.1')).toBe(false);
    expect(isLocal(headers({ host: 'localhost:8790', 'x-forwarded-for': '127.0.0.1' }), '127.0.0.1')).toBe(false);
    expect(isLocal(headers({ host: 'localhost:8790' }), '::ffff:127.0.0.1')).toBe(true);
    expect(isLocal(headers({ host: '127.0.0.1:8790' }), '127.0.0.1')).toBe(true);
    expect(isLocal(headers({ host: 'localhost:8790' }), '192.168.1.20')).toBe(false);
  });

  it('knows the home network', () => {
    expect(isDirectLan(headers({}), '192.168.1.20')).toBe(true);
    expect(isDirectLan(headers({}), '::ffff:10.0.0.4')).toBe(true);
    expect(isDirectLan(headers({}), '203.0.113.9')).toBe(false);
    expect(isDirectLan(headers({ 'cf-ray': 'abc' }), '127.0.0.1')).toBe(false);
  });
});

describe('address keys for limits', () => {
  it('counts an IPv6 visitor by their /64, and an IPv4 one by their address', () => {
    expect(addressKey('203.0.113.7')).toBe('203.0.113.7');
    expect(addressKey('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(addressKey('2001:db8:aa:bb:1:2:3:4')).toBe('2001:db8:aa:bb::/64');
    expect(addressKey('2001:DB8:AA:BB::9')).toBe('2001:db8:aa:bb::/64');
    expect(addressKey('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(addressKey('fe80::1%eth0')).toBe('fe80:0:0:0::/64');
    expect(addressKey('::1')).toBe('0:0:0:0::/64');
  });

  it('holds one /64 to the limits of one address', () => {
    const l = new ConnectionLimit(2, 100);
    expect(l.take('2001:db8:1:2::a')).not.toBeNull();
    expect(l.take('2001:db8:1:2::b')).not.toBeNull();
    expect(l.take('2001:db8:1:2::c')).toBeNull();
    expect(l.take('2001:db8:1:3::a')).not.toBeNull();
    const line = new Line(DEFAULT_LINE);
    line.ask({ id: 'p0', actor: { ip: '198.51.100.1', userAgent: null } }, { kind: 'game', game: 'slice' }, 'Slice');
    for (let i = 1; i <= LINE_PER_ADDRESS; i++) expect(line.ask({ id: `p${i}`, actor: { ip: `2001:db8:1:2::${i}`, userAgent: null } }, { kind: 'game', game: 'slice' }, 'Slice').result).toBe('queued');
    expect(line.ask({ id: 'p99', actor: { ip: '2001:db8:1:2::99', userAgent: null } }, { kind: 'game', game: 'slice' }, 'Slice').result).toBe('full');
  });
});

describe('login guard', () => {
  it('slows down one address, and one username from many addresses', () => {
    let now = 0;
    const g = new LoginGuard(() => now);
    for (let i = 0; i < 5; i++) g.fail('admin', { ip: '1.1.1.1' });
    expect(g.wait('admin', { ip: '1.1.1.1' })).toBe(0);
    g.fail('admin', { ip: '1.1.1.1' });
    expect(g.wait('anyone', { ip: '1.1.1.1' })).toBeGreaterThan(0);
    // Each address a few times: the username locks.
    for (let i = 0; i < 12; i++) g.fail('Admin ', { ip: `2.2.2.${i}` });
    expect(g.wait('admin', { ip: '3.3.3.3' })).toBeGreaterThan(0);
    // The owner at home is not locked out by the guessing.
    expect(g.wait('admin', { ip: '192.168.1.20', lan: true })).toBe(0);
    // It grows, but not past 15 minutes, and then the try is allowed.
    for (let i = 0; i < 40; i++) g.fail('admin', { ip: `4.4.4.${i}` });
    const w = g.wait('admin', { ip: '5.5.5.5' });
    expect(w).toBeLessThanOrEqual(15 * 60_000);
    now += w;
    expect(g.wait('admin', { ip: '5.5.5.5' })).toBe(0);
    // A good sign-in clears the count.
    g.succeed('admin', { ip: '5.5.5.5' });
    g.fail('admin', { ip: '5.5.5.5' });
    expect(g.wait('admin', { ip: '6.6.6.6' })).toBe(0);
  });
});

describe('connection limit', () => {
  it('holds a few per address and a total, and gives places back once', () => {
    const l = new ConnectionLimit(2, 3);
    const a = l.take('a')!;
    l.take('a');
    expect(l.take('a')).toBeNull();
    l.take('b');
    expect(l.take('c')).toBeNull();
    a();
    a();
    expect(l.take('a')).not.toBeNull();
    expect(l.take('c')).toBeNull();
  });
});

describe('line', () => {
  it('holds only a few places for one address, whatever the visitor ids', () => {
    const line = new Line(DEFAULT_LINE);
    const visitor = (n: number, ip = '203.0.113.9') => ({ id: `v${n}`, actor: { ip, userAgent: null } });
    expect(line.ask(visitor(0, '198.51.100.1'), { kind: 'game', game: 'slice' }, 'Slice').result).toBe('now');
    for (let i = 1; i <= LINE_PER_ADDRESS; i++) expect(line.ask(visitor(i), { kind: 'game', game: 'slice' }, 'Slice').result).toBe('queued');
    expect(line.ask(visitor(99), { kind: 'game', game: 'slice' }, 'Slice').result).toBe('full');
    // Someone else still gets in.
    expect(line.ask(visitor(100, '198.51.100.2'), { kind: 'game', game: 'slice' }, 'Slice').result).toBe('queued');
    // A proxy's own address (TRUST_PROXY off) does not tell visitors apart: not limited.
    for (let i = 200; i < 210; i++) expect(line.ask(visitor(i, '127.0.0.1'), { kind: 'game', game: 'slice' }, 'Slice').result).toBe('queued');
  });
});

describe('play WebSocket', () => {
  async function start(limit = new ConnectionLimit(2, 10)) {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const host = new GameHost(sampleLayout(), () => {});
    host.attach(
      server,
      '/api/play',
      (req) => upgradeVisitor(req, { trustProxy: false, sessionCookie: COOKIE, isAdmin: () => false }),
      (req) => admitUpgrade(req, { trustProxy: false, limit })
    );
    const port = (server.address() as { port: number }).port;
    const open = (origin?: string) =>
      new Promise<WebSocket | number>((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`, origin ? { origin: origin === 'same' ? `http://127.0.0.1:${port}` : origin } : {});
        ws.on('open', () => resolve(ws));
        ws.on('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0));
        ws.on('error', () => resolve(0));
      });
    const stop = () => {
      host.stop();
      server.close();
    };
    return { open, stop };
  }

  it('refuses a page on another site, and too many sockets from one address', async () => {
    const { open, stop } = await start();
    expect(await open('https://evil.example')).toBe(429);
    const a = await open('same');
    // Same host and port as the page: allowed.
    expect(a).toBeInstanceOf(WebSocket);
    (a as WebSocket).close();
    stop();
  });

  it('holds only a few sockets per address (loopback counts toward the total only)', async () => {
    const limit = new ConnectionLimit(1, 2);
    const { open, stop } = await start(limit);
    const a = await open();
    const b = await open();
    expect(a).toBeInstanceOf(WebSocket);
    expect(b).toBeInstanceOf(WebSocket);
    expect(await open()).toBe(429);
    (a as WebSocket).close();
    await new Promise((r) => setTimeout(r, 100));
    expect(await open()).toBeInstanceOf(WebSocket);
    stop();
  });

  it('closes a socket that sends a message larger than any the page sends', async () => {
    const { open, stop } = await start();
    const ws = (await open()) as WebSocket;
    const closed = new Promise<number>((r) => ws.on('close', (code) => r(code)));
    ws.send('x'.repeat(64 * 1024));
    expect(await closed).toBe(1009);
    stop();
  });
});

describe('app hardening', () => {
  async function setup(password = 'correct horse battery') {
    const db = openDatabase(':memory:');
    const bus = new Bus();
    const lights = new Lights(db, bus);
    const config = { ...loadConfig({ TRUST_PROXY: '1' }), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
    const app = createApp({ config, db, bus, lights, discover: async () => [] });
    await createAuth(db, { secureCookie: false }).createUser('admin', password);
    const req = async (method: string, url: string, body?: unknown, extra: Record<string, string> = {}) => {
      const res = await app.request(url, {
        method,
        headers: { host: 'lights.example.com', 'content-type': 'application/json', ...extra },
        body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body)
      });
      return { status: res.status, cookie: res.headers.getSetCookie().find((c) => c.startsWith(`${COOKIE}=`))?.split(';')[0] ?? '', res };
    };
    return { req, db };
  }

  it('stops guessing the admin password from rotating addresses', async () => {
    const { req } = await setup();
    // The visitor makes up the first X-Forwarded-For entry each time; Cloudflare appends the real one.
    for (let i = 0; i < 11; i++) {
      const r = await req('POST', '/api/auth/login', { username: 'admin', password: `guess ${i}` }, { 'x-forwarded-for': `10.9.9.${i}, 203.0.113.${i}` });
      expect(r.status).toBe(401);
    }
    const r = await req('POST', '/api/auth/login', { username: 'admin', password: 'guess x' }, { 'x-forwarded-for': '203.0.113.200' });
    expect(r.status).toBe(429);
    expect(Number(r.res.headers.get('retry-after'))).toBeGreaterThan(0);
    // Even the right password waits: the lock does not tell guesses apart.
    expect((await req('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' }, { 'x-forwarded-for': '203.0.113.201' })).status).toBe(429);
  }, 30_000);

  it('slows down one address guessing many usernames', async () => {
    const { req } = await setup();
    for (let i = 0; i < 6; i++) expect((await req('POST', '/api/auth/login', { username: `user${i}`, password: 'x' }, { 'x-forwarded-for': '1.2.3.4, 203.0.113.50' })).status).toBe(401);
    expect((await req('POST', '/api/auth/login', { username: 'admin', password: 'x' }, { 'x-forwarded-for': '9.9.9.9, 203.0.113.50' })).status).toBe(429);
  }, 30_000);

  it('does not let a forged X-Forwarded-For create the first admin', async () => {
    const db = openDatabase(':memory:');
    const bus = new Bus();
    const config = { ...loadConfig({ TRUST_PROXY: '1' }), webDir: '/nonexistent' };
    const app = createApp({ config, db, bus, lights: new Lights(db, bus) });
    const res = await app.request('/api/auth/bootstrap', {
      method: 'POST',
      headers: { host: 'localhost:8790', 'content-type': 'application/json', 'x-forwarded-for': '127.0.0.1' },
      body: JSON.stringify({ username: 'mallory', password: 'a long password here' })
    });
    expect(res.status).toBe(403);
    expect(db.countUsers()).toBe(0);
  });

  it('does not let the example password sign in from the internet', async () => {
    const { req } = await setup('change-me-to-something-long');
    expect((await req('POST', '/api/auth/login', { username: 'admin', password: 'change-me-to-something-long' }, { 'x-forwarded-for': '203.0.113.9' })).status).toBe(401);
  });

  it('signs out the other sessions when the password changes', async () => {
    const { req } = await setup();
    const a = (await req('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' }, { 'x-forwarded-for': '203.0.113.1' })).cookie;
    const b = (await req('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' }, { 'x-forwarded-for': '203.0.113.2' })).cookie;
    expect(a && b && a !== b).toBeTruthy();
    expect((await req('POST', '/api/admin/auth/password', { current: 'correct horse battery', next: 'a brand new password' }, { cookie: a })).status).toBe(200);
    expect((await req('GET', '/api/admin/overview', undefined, { cookie: a })).status).toBe(200);
    expect((await req('GET', '/api/admin/overview', undefined, { cookie: b })).status).toBe(401);
    // The example password is not a new password.
    expect((await req('POST', '/api/admin/auth/password', { current: 'a brand new password', next: 'change-me-to-something-long' }, { cookie: a })).status).toBe(400);
  }, 30_000);

  it('marks the session cookie Secure when the visitor came over HTTPS', async () => {
    const { req } = await setup();
    const r = await req('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' }, { 'x-forwarded-for': '203.0.113.1', 'x-forwarded-proto': 'https' });
    expect(r.res.headers.getSetCookie().find((c) => c.startsWith(`${COOKIE}=`))).toMatch(/;\s*Secure/i);
  });

  it('refuses large bodies on public routes', async () => {
    const { req } = await setup();
    const big = JSON.stringify({ username: 'admin', password: 'x'.repeat(200_000) });
    expect((await req('POST', '/api/auth/login', big, { 'x-forwarded-for': '203.0.113.1' })).status).toBe(413);
    expect((await req('POST', '/api/color', JSON.stringify({ color: '#ff0000', pad: 'x'.repeat(100_000) }))).status).toBe(413);
  });

  it("refuses another site's page changing the lights or the line", async () => {
    const { req } = await setup();
    expect((await req('POST', '/api/color', { color: '#ff0000' }, { origin: 'https://evil.example' })).status).toBe(403);
    expect((await req('POST', '/api/color', { color: '#ff0000' }, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await req('POST', '/api/scenes/x/apply', undefined, { origin: 'https://evil.example' })).status).toBe(403);
    expect((await req('POST', '/api/line/leave', undefined, { origin: 'https://evil.example' })).status).toBe(403);
    // The site's own page may.
    expect((await req('POST', '/api/line/leave', undefined, { origin: 'https://lights.example.com' })).status).toBe(200);
  });

  it('tells a browser that came over HTTPS to keep to it', async () => {
    const { req } = await setup();
    expect((await req('GET', '/api/health', undefined, { 'x-forwarded-proto': 'https' })).res.headers.get('strict-transport-security')).toMatch(/max-age=\d+/);
    expect((await req('GET', '/api/health')).res.headers.get('strict-transport-security')).toBeNull();
  });

  it('limits requests from one IPv6 /64 together', async () => {
    const { req } = await setup();
    let last = 0;
    for (let i = 0; i < 125; i++) last = (await req('GET', '/api/layout', undefined, { 'x-forwarded-for': `2001:db8:5:6::${i.toString(16)}` })).status;
    expect(last).toBe(429);
    expect((await req('GET', '/api/layout', undefined, { 'x-forwarded-for': '2001:db8:5:7::1' })).status).toBe(200);
  });

  it('refuses a cross-site sign-in with no Origin', async () => {
    const { req } = await setup();
    expect((await req('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' }, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
  });
});
