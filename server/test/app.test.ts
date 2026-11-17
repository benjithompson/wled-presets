import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.ts';
import { createAuth } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase, type Db } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { Lights } from '../src/lights.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';
import { discoverWled } from '../src/discovery.ts';

type Mock = Awaited<ReturnType<typeof startMockWled>>;
let mocks: Mock[] = [];

beforeAll(async () => {
  mocks = await Promise.all([startMockWled(0, 'Roof'), startMockWled(0, 'Tree')]);
});
afterAll(async () => {
  await Promise.all(mocks.map((m) => m.close()));
});

async function setup() {
  const db = openDatabase(':memory:');
  const bus = new Bus();
  const lights = new Lights(db, bus);
  const config = { ...loadConfig({}), webDir: '/nonexistent' };
  const app = createApp({ config, db, bus, lights, discover: async () => [] });
  await createAuth(db, { secureCookie: false }).createUser('admin', 'correct horse battery');
  let cookie = '';
  const call = async (method: string, url: string, body?: unknown, extra: Record<string, string> = {}) => {
    const res = await app.request(url, {
      method,
      headers: { host: 'lights.lan', ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...extra },
      body: body ? JSON.stringify(body) : undefined
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null };
  };
  return { db, lights, call };
}

let t: Awaited<ReturnType<typeof setup>>;
beforeEach(async () => {
  for (const m of mocks) m.requests.length = 0;
  t = await setup();
});

async function login() {
  const r = await t.call('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' });
  expect(r.status).toBe(200);
}

async function addDevices() {
  const ids: string[] = [];
  for (const m of mocks) {
    const r = await t.call('POST', '/api/admin/devices', { host: '127.0.0.1', port: m.port });
    expect(r.status).toBe(201);
    ids.push(r.json.id);
  }
  return ids;
}

describe('auth', () => {
  it('rejects admin routes without a session', async () => {
    expect((await t.call('GET', '/api/admin/overview')).status).toBe(401);
  });
  it('rejects a wrong password', async () => {
    expect((await t.call('POST', '/api/auth/login', { username: 'admin', password: 'nope' })).status).toBe(401);
  });
  it('signs in and out', async () => {
    await login();
    expect((await t.call('GET', '/api/admin/overview')).status).toBe(200);
    await t.call('POST', '/api/auth/logout');
    expect((await t.call('GET', '/api/admin/overview')).status).toBe(401);
  });
  it('blocks bootstrap when an admin exists', async () => {
    expect((await t.call('POST', '/api/auth/bootstrap', { username: 'x', password: 'xxxxxxxxxxxxxx' })).status).toBe(409);
  });
  it('rejects cross-origin writes', async () => {
    await login();
    expect((await t.call('POST', '/api/admin/scenes', { name: 'x' }, { origin: 'http://evil.example' })).status).toBe(403);
    expect((await t.call('POST', '/api/admin/scenes', { name: 'x' }, { origin: 'http://lights.lan' })).status).toBe(201);
  });
});

describe('devices and scenes', () => {
  it('names a new device from WLED and imports its presets', async () => {
    await login();
    const [roof] = await addDevices();
    const ov = await t.call('GET', '/api/admin/overview');
    expect(ov.json.devices.find((d: any) => d.id === roof).name).toBe('Roof');
    const sync = await t.call('POST', '/api/admin/devices/presets/sync');
    expect(sync.json.results.every((r: any) => r.ok)).toBe(true);
    const ov2 = await t.call('GET', '/api/admin/overview');
    expect(ov2.json.devicePresets[roof]).toHaveLength(7);
  });

  it('applies a scene to every mapped device and records it', async () => {
    await login();
    const [a, b] = await addDevices();
    const scene = (await t.call('POST', '/api/admin/scenes', { name: 'Party', devicePresets: { [a]: 3, [b]: 5 } })).json;
    const r = await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(r.status).toBe(200);
    expect(r.json.applied.sort()).toEqual([a, b].sort());
    expect(mocks[0].requests.some((q) => q.url === '/json/state' && (q.body as any)?.ps === 3)).toBe(true);
    expect(mocks[1].requests.some((q) => q.url === '/json/state' && (q.body as any)?.ps === 5)).toBe(true);
    expect((await t.call('GET', '/api/state')).json.currentSceneId).toBe(scene.id);
  });

  it('skips devices without a mapping', async () => {
    await login();
    const [a, b] = await addDevices();
    const scene = (await t.call('POST', '/api/admin/scenes', { name: 'Half', devicePresets: { [a]: 1 } })).json;
    const r = await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(r.json.skipped).toEqual([b]);
  });

  it('sets a solid color on all segments', async () => {
    await login();
    await addDevices();
    const r = await t.call('POST', '/api/color', { color: '#FF8800' });
    expect(r.status).toBe(200);
    const body = mocks[0].requests.find((q) => q.method === 'POST')!.body as any;
    expect(body.on).toBe(true);
    expect(body.seg[0].col[0]).toEqual([255, 136, 0]);
    expect((await t.call('GET', '/api/state')).json.currentColor).toBe('#ff8800');
  });

  it('rejects bad colors', async () => {
    expect((await t.call('POST', '/api/color', { color: 'red' })).status).toBe(400);
  });

  it('reports 502 when no light responds', async () => {
    await login();
    const d = (await t.call('POST', '/api/admin/devices', { name: 'Ghost', host: '127.0.0.1', port: 1 })).json;
    const scene = (await t.call('POST', '/api/admin/scenes', { name: 'X', devicePresets: { [d.id]: 1 } })).json;
    expect((await t.call('POST', `/api/scenes/${scene.id}/apply`)).status).toBe(502);
  });

  it('marks scenes offline when their devices are down', async () => {
    await login();
    const d = (await t.call('POST', '/api/admin/devices', { name: 'Ghost', host: '127.0.0.1', port: 1 })).json;
    await t.call('POST', '/api/admin/scenes', { name: 'X', devicePresets: { [d.id]: 1 } });
    await t.lights.refreshStatus();
    const s = (await t.call('GET', '/api/state')).json;
    expect(s.scenes[0].online).toBe(false);
    expect(s.anyOnline).toBe(false);
  });

  it('keeps device presets when another device is edited', async () => {
    await login();
    const [a, b] = await addDevices();
    await t.call('POST', '/api/admin/devices/presets/sync');
    await t.call('PUT', `/api/admin/devices/${b}`, { name: 'Renamed', host: '127.0.0.1', port: mocks[1].port, enabled: true });
    const ov = await t.call('GET', '/api/admin/overview');
    expect(ov.json.devicePresets[a]).toHaveLength(7);
    expect(ov.json.devicePresets[b]).toHaveLength(7);
  });

  it('reorders scenes', async () => {
    await login();
    const x = (await t.call('POST', '/api/admin/scenes', { name: 'A' })).json;
    const y = (await t.call('POST', '/api/admin/scenes', { name: 'B' })).json;
    await t.call('PUT', '/api/admin/scenes/order', { ids: [y.id, x.id] });
    expect((await t.call('GET', '/api/state')).json.scenes.map((s: any) => s.name)).toEqual(['B', 'A']);
  });
});

describe('automatic preset import', () => {
  it('imports presets when a device is added', async () => {
    await login();
    const r = await t.call('POST', '/api/admin/devices', { host: '127.0.0.1', port: mocks[0].port });
    expect(r.json.presets).toMatchObject({ ok: true, count: 7 });
    const ov = await t.call('GET', '/api/admin/overview');
    expect(ov.json.devicePresets[r.json.id]).toHaveLength(7);
  });

  it('imports presets for devices added from discovery', async () => {
    await login();
    const r = await t.call('POST', '/api/admin/devices/bulk', { devices: mocks.map((m) => ({ host: '127.0.0.1', port: m.port })) });
    expect(r.json.presets.every((p: any) => p.ok && p.count === 7)).toBe(true);
  });

  it('still adds the device when its presets cannot be read', async () => {
    await login();
    const r = await t.call('POST', '/api/admin/devices', { name: 'Ghost', host: '127.0.0.1', port: 1 });
    expect(r.status).toBe(201);
    expect(r.json.presets.ok).toBe(false);
  });

  it('re-imports when the address changes', async () => {
    await login();
    const d = (await t.call('POST', '/api/admin/devices', { name: 'Ghost', host: '127.0.0.1', port: 1 })).json;
    await t.call('PUT', `/api/admin/devices/${d.id}`, { name: 'Ghost', host: '127.0.0.1', port: mocks[1].port, enabled: true });
    expect((await t.call('GET', '/api/admin/overview')).json.devicePresets[d.id]).toHaveLength(7);
  });
});

describe('backup', () => {
  it('restores onto a new install by matching device addresses', async () => {
    await login();
    const [a] = await addDevices();
    await t.call('POST', '/api/admin/scenes', { name: 'Party', devicePresets: { [a]: 4 } });
    const backup = (await t.call('GET', '/api/admin/scenes/export')).json;

    t = await setup();
    await login();
    const [a2] = await addDevices();
    expect(a2).not.toBe(a);
    const r = await t.call('POST', '/api/admin/scenes/import', backup);
    expect(r.json.restored).toBe(1);
    const scenes = (await t.call('GET', '/api/admin/overview')).json.scenes;
    expect(scenes[0].devicePresets).toEqual({ [a2]: 4 });
  });

  it('accepts a v1 backup file', async () => {
    await login();
    const [a] = await addDevices();
    const v1 = { version: 1, exportedAt: 'x', publicPresets: [{ id: 'p1', name: 'Old', devicePresets: { [a]: 2 } }] };
    expect((await t.call('POST', '/api/admin/scenes/import', v1)).json.restored).toBe(1);
  });
});

describe('auto-revert', () => {
  it('schedules a revert after a non-default scene, and cancels it on the default', async () => {
    await login();
    const [a] = await addDevices();
    const def = (await t.call('POST', '/api/admin/scenes', { name: 'Default', devicePresets: { [a]: 1 } })).json;
    const other = (await t.call('POST', '/api/admin/scenes', { name: 'Other', devicePresets: { [a]: 2 } })).json;
    const settings = (await t.call('GET', '/api/admin/overview')).json.settings;
    await t.call('PUT', '/api/admin/settings', { ...settings, defaultSceneId: def.id, revertMinutes: 5 });

    await t.call('POST', `/api/scenes/${other.id}/apply`);
    const at = (await t.call('GET', '/api/state')).json.revertAt;
    expect(Date.parse(at) - Date.now()).toBeGreaterThan(4 * 60_000);

    await t.call('POST', `/api/scenes/${def.id}/apply`);
    expect((await t.call('GET', '/api/state')).json.revertAt).toBeNull();
    t.lights.stop();
  });

  it('clears the default scene when that scene is deleted', async () => {
    await login();
    const def = (await t.call('POST', '/api/admin/scenes', { name: 'Default' })).json;
    const settings = (await t.call('GET', '/api/admin/overview')).json.settings;
    await t.call('PUT', '/api/admin/settings', { ...settings, defaultSceneId: def.id });
    await t.call('DELETE', `/api/admin/scenes/${def.id}`);
    expect((await t.call('GET', '/api/admin/overview')).json.settings.defaultSceneId).toBeNull();
  });
});

describe('v1 database', () => {
  it('opens a v1 database and keeps its data', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wled-v1-'));
    const file = path.join(dir, 'v1.sqlite');
    const v1 = new Database(file);
    v1.exec(`
      CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE admin_users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
      CREATE TABLE devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 80, enabled INTEGER NOT NULL DEFAULT 1);
      CREATE TABLE public_presets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
      CREATE TABLE public_preset_mappings (publicPresetId TEXT NOT NULL, deviceId TEXT NOT NULL, presetId INTEGER NOT NULL, PRIMARY KEY (publicPresetId, deviceId));
      INSERT INTO devices VALUES ('d1', 'Roof', '10.0.0.5', 80, 1);
      INSERT INTO public_presets VALUES ('p2', 'Zebra'), ('p1', 'Apple');
      INSERT INTO public_preset_mappings VALUES ('p1', 'd1', 7);
      INSERT INTO settings VALUES ('defaultPresetId', 'p1'), ('revertTimeout', '15');
    `);
    v1.close();

    const db: Db = openDatabase(file);
    expect(db.listDevices()[0].name).toBe('Roof');
    expect(db.listScenes().map((s) => s.name)).toEqual(['Apple', 'Zebra']);
    expect(db.getScene('p1')!.devicePresets).toEqual({ d1: 7 });
    db.close();
  });
});

describe('discovery', () => {
  it('finds devices on extra hosts and ports', async () => {
    const found = await discoverWled({ subnets: ['192.0.2.0/30'], hosts: ['127.0.0.1'], ports: mocks.map((m) => m.port), timeoutMs: 300 });
    expect(found.map((f) => f.name).sort()).toEqual(['Roof', 'Tree']);
    expect(found.map((f) => f.port).sort()).toEqual(mocks.map((m) => m.port).sort());
  });
});
