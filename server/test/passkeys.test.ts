import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createApp } from '../src/app.ts';
import { createAuth } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { Lights } from '../src/lights.ts';
import { siteOf } from '../src/passkeys.ts';

const b64 = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const sha256 = (b: Uint8Array | string) => crypto.createHash('sha256').update(b).digest();

/** A pretend phone: makes passkeys and signs with them, the way a real authenticator does. */
function authenticator() {
  const keys = new Map<string, { key: crypto.KeyObject; rpId: string; userHandle: string; counter: number }>();
  const flags = 0x01 | 0x04; // user present, user verified
  return {
    create(options: any, origin: string) {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwk = publicKey.export({ format: 'jwk' });
      const cose = isoCBOR.encode(
        new Map<number, number | Uint8Array>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, Buffer.from(jwk.x!, 'base64url')],
          [-3, Buffer.from(jwk.y!, 'base64url')]
        ])
      );
      const id = crypto.randomBytes(16);
      const rpId = options.rp.id;
      const len = Buffer.alloc(2);
      len.writeUInt16BE(id.length);
      const authData = Buffer.concat([sha256(rpId), Buffer.from([flags | 0x40]), Buffer.alloc(4), Buffer.alloc(16), len, id, Buffer.from(cose)]);
      const clientData = JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false });
      const attestation = isoCBOR.encode(
        new Map<string, string | Uint8Array | Map<string, string>>([
          ['fmt', 'none'],
          ['attStmt', new Map<string, string>()],
          ['authData', authData]
        ])
      );
      keys.set(b64(id), { key: privateKey, rpId, userHandle: options.user.id, counter: 0 });
      return {
        id: b64(id),
        rawId: b64(id),
        type: 'public-key',
        response: { clientDataJSON: b64(Buffer.from(clientData)), attestationObject: b64(attestation), transports: ['internal'] },
        clientExtensionResults: {}
      };
    },
    /** Signs in with the passkey for the options' site (or the one named), as from `origin`. */
    get(options: any, origin: string, pick?: string) {
      const [id, k] = pick ? [pick, keys.get(pick)!] : [...keys].find(([, k]) => k.rpId === options.rpId)!;
      const count = Buffer.alloc(4);
      count.writeUInt32BE(++k.counter);
      const authData = Buffer.concat([sha256(k.rpId), Buffer.from([flags]), count]);
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
      const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientData)]), k.key);
      return {
        id,
        rawId: id,
        type: 'public-key',
        response: { clientDataJSON: b64(clientData), authenticatorData: b64(authData), signature: b64(signature), userHandle: k.userHandle },
        clientExtensionResults: {}
      };
    },
    ids: () => [...keys.keys()]
  };
}

const SITE = 'https://lights.example.com';

async function setup() {
  const db = openDatabase(':memory:');
  const bus = new Bus();
  const lights = new Lights(db, bus);
  const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
  const app = createApp({ config, db, bus, lights, discover: async () => [] });
  await createAuth(db, { secureCookie: false }).createUser('admin', 'correct horse battery');
  let cookie = '';
  const call = async (method: string, url: string, body?: unknown, origin = SITE) => {
    const res = await app.request(url, {
      method,
      headers: { host: new URL(origin).host, origin, ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined
    });
    const jar = new Map(cookie ? cookie.split('; ').map((p) => p.split('=') as [string, string]) : []);
    for (const set of res.headers.getSetCookie()) {
      const [kv] = set.split(';');
      const [k, v] = kv.split('=');
      if (v) jar.set(k, v);
      else jar.delete(k);
    }
    cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null };
  };
  const signIn = () => call('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' });
  const signOut = () => call('POST', '/api/auth/logout');
  const phone = authenticator();
  /** Adds a passkey on the phone, signed in with the password. */
  const addPasskey = async (name = 'Phone', origin = SITE) => {
    const o = await call('POST', '/api/admin/passkeys/options', { password: 'correct horse battery' }, origin);
    expect(o.status).toBe(200);
    return call('POST', '/api/admin/passkeys', { name, response: phone.create(o.json.options, origin) }, origin);
  };
  /** Signs in with the phone's passkey. */
  const passkeySignIn = async (origin = SITE, tamper?: (r: any) => void) => {
    const o = await call('POST', '/api/auth/passkey/options', {}, origin);
    expect(o.status).toBe(200);
    const response = phone.get(o.json.options, origin, phone.ids()[0]);
    tamper?.(response);
    return call('POST', '/api/auth/passkey/login', { response }, origin);
  };
  return { db, call, signIn, signOut, phone, addPasskey, passkeySignIn };
}

describe('passkeys', () => {
  it('work only over HTTPS at a name, or on localhost', () => {
    expect(siteOf('https://lights.example.com', 'lights.example.com', false)).toEqual({ origin: 'https://lights.example.com', rpId: 'lights.example.com' });
    expect(siteOf('http://localhost:5173', 'localhost:5173', false)).toEqual({ origin: 'http://localhost:5173', rpId: 'localhost' });
    expect(siteOf('http://lights.example.com', 'lights.example.com', false)).toHaveProperty('error');
    expect(siteOf('https://203.0.113.9:8790', '203.0.113.9:8790', true)).toHaveProperty('error');
    expect(siteOf('http://192.168.1.20:8790', '192.168.1.20:8790', false)).toHaveProperty('error');
    expect(siteOf(undefined, 'lights.example.com', true)).toEqual({ origin: 'https://lights.example.com', rpId: 'lights.example.com' });
  });

  it('are added with the password, then sign in without it', async () => {
    const t = await setup();
    expect((await t.call('POST', '/api/admin/passkeys/options', { password: 'x' })).status).toBe(401);
    await t.signIn();
    // A stolen session cookie alone cannot add a passkey.
    const wrong = await t.call('POST', '/api/admin/passkeys/options', { password: 'not the password' });
    expect(wrong.status).toBe(400);
    const added = await t.addPasskey('My phone');
    expect(added.status).toBe(200);
    expect(added.json).toMatchObject({ name: 'My phone', rpId: 'lights.example.com', lastUsedAt: null });
    expect((await t.call('GET', '/api/admin/passkeys')).json).toHaveLength(1);

    await t.signOut();
    expect((await t.call('GET', '/api/admin/passkeys')).status).toBe(401);
    const r = await t.passkeySignIn();
    expect(r.status).toBe(200);
    expect(r.json.user.username).toBe('admin');
    const list = await t.call('GET', '/api/admin/passkeys');
    expect(list.status).toBe(200);
    expect(list.json[0].lastUsedAt).not.toBeNull();
  });

  it('refuse a replayed, forged or foreign answer', async () => {
    const t = await setup();
    await t.signIn();
    await t.addPasskey();
    await t.signOut();

    // The same signed answer twice: the challenge works once.
    const o = await t.call('POST', '/api/auth/passkey/options', {});
    const response = t.phone.get(o.json.options, SITE, t.phone.ids()[0]);
    expect((await t.call('POST', '/api/auth/passkey/login', { response })).status).toBe(200);
    await t.signOut();
    expect((await t.call('POST', '/api/auth/passkey/login', { response })).status).toBe(401);

    // A changed signature.
    const forged = await t.passkeySignIn(SITE, (r) => {
      const sig = Buffer.from(r.response.signature, 'base64url');
      sig[sig.length - 1] ^= 1;
      r.response.signature = b64(sig);
    });
    expect(forged.status).toBe(401);
    // Signed by another admin's device (the user handle says so).
    expect((await t.passkeySignIn(SITE, (r) => (r.response.userHandle = b64(crypto.randomBytes(32))))).status).toBe(401);
    // An unknown passkey.
    expect((await t.passkeySignIn(SITE, (r) => (r.id = r.rawId = b64(crypto.randomBytes(16))))).status).toBe(401);
    // The passkey belongs to lights.example.com: another of the site's names does not take it.
    expect((await t.passkeySignIn('https://other.example.net')).status).toBe(401);
    expect((await t.call('GET', '/api/admin/passkeys')).status).toBe(401);
  });

  it('need HTTPS and the site name', async () => {
    const t = await setup();
    await t.signIn();
    const http = await t.call('POST', '/api/admin/passkeys/options', { password: 'correct horse battery' }, 'http://lights.example.com');
    expect(http.status).toBe(400);
    expect(http.json.error).toMatch(/HTTPS/);
    const ip = await t.call('POST', '/api/auth/passkey/options', {}, 'https://203.0.113.9');
    expect(ip.status).toBe(400);
    expect(ip.json.error).toMatch(/IP address/);
  });

  it('can be renamed and removed, and a removed one no longer signs in', async () => {
    const t = await setup();
    await t.signIn();
    const { json: key } = await t.addPasskey('Laptop');
    const renamed = await t.call('PATCH', `/api/admin/passkeys/${encodeURIComponent(key.id)}`, { name: 'Work laptop' });
    expect(renamed.json[0].name).toBe('Work laptop');
    expect((await t.call('DELETE', `/api/admin/passkeys/${encodeURIComponent(key.id)}`)).json).toEqual([]);
    expect((await t.call('DELETE', `/api/admin/passkeys/${encodeURIComponent(key.id)}`)).status).toBe(404);
    await t.signOut();
    expect((await t.passkeySignIn()).status).toBe(401);
  });

  it('count failed passkey sign-ins against the address', async () => {
    const t = await setup();
    await t.signIn();
    await t.addPasskey();
    await t.signOut();
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await t.passkeySignIn(SITE, (r) => (r.response.signature = b64(crypto.randomBytes(70))))).status);
    expect(statuses.slice(0, 5).every((s) => s === 401)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });
});
