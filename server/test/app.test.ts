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
import { sampleLayout } from '../../shared/layout.ts';
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
  // Files (pictures, audio) go to a temporary folder, not the repository's data folder.
  const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
  const app = createApp({ config, db, bus, lights, discover: async () => [] });
  await createAuth(db, { secureCookie: false }).createUser('admin', 'correct horse battery');
  let cookie = '';
  const call = async (method: string, url: string, body?: unknown, extra: Record<string, string> = {}) => {
    const res = await app.request(url, {
      method,
      headers: { host: 'lights.lan', ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...extra },
      body: body ? JSON.stringify(body) : undefined
    });
    // A small cookie jar: the session and the visitor id.
    const jar = new Map(cookie ? cookie.split('; ').map((p) => p.split('=') as [string, string]) : []);
    for (const set of res.headers.getSetCookie()) {
      const [kv, ...attrs] = set.split(';');
      const [k, v] = kv.split('=');
      if (attrs.some((a) => /max-age=0/i.test(a.trim())) || !v) jar.delete(k);
      else jar.set(k, v);
    }
    cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null };
  };
  const raw = (method: string, url: string, data?: Uint8Array<ArrayBuffer>, extra: Record<string, string> = {}) =>
    app.request(url, { method, headers: { host: 'lights.lan', ...(cookie ? { cookie } : {}), ...extra }, body: data });
  return { db, lights, call, raw };
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

  it('stores a scene with effects, plays them, and stops them when a color is chosen', async () => {
    await login();
    const [a, b] = await addDevices();
    // The roof is on device a; the bushes have no device (simulator only).
    const layout = (await t.call('GET', '/api/layout')).json;
    layout.fixtures[0].deviceId = a;
    expect((await t.call('PUT', '/api/admin/layout', layout)).status).toBe(200);
    const plays: (string[] | null)[] = [];
    t.lights.setEffectPlayer((show) => {
      const fx = show?.effects;
      plays.push(fx ? Object.keys(fx).sort() : null);
      return fx ? { devices: [a], objects: Object.keys(fx).length } : { devices: [], objects: 0 };
    });
    const effects = {
      roof: { effect: 'aurora', palette: 'aurora', speed: 0.5, intensity: 0.5, size: 0.5, brightness: 0.8 },
      'bush-1': { effect: 'fireworks', palette: 'custom', colors: ['#ff0000', '#00ff00'], speed: 0.7, intensity: 0.4, size: 0.5, brightness: 1, reverse: true }
    };
    const bad = await t.call('POST', '/api/admin/scenes', { name: 'Bad', effects: { roof: { ...effects.roof, speed: 2 } } });
    expect(bad.status).toBe(400);
    const created = await t.call('POST', '/api/admin/scenes', { name: 'Wonderland', devicePresets: { [a]: 2, [b]: 3 }, effects });
    expect(created.status).toBe(201);
    expect(created.json.effects).toEqual(effects);
    // Renaming in the scene editor leaves the effects alone.
    const renamed = await t.call('PUT', `/api/admin/scenes/${created.json.id}`, { name: 'Winter', devicePresets: { [a]: 2, [b]: 3 } });
    expect(renamed.json.effects).toEqual(effects);

    const r = await t.call('POST', `/api/scenes/${created.json.id}/apply`);
    expect(r.status).toBe(200);
    expect(r.json.effects).toBe(2);
    // Device a plays the effects, not its preset; device b plays its preset.
    expect(r.json.applied.sort()).toEqual([a, b].sort());
    expect(mocks[0].requests.some((q) => (q.body as any)?.ps === 2)).toBe(false);
    expect(mocks[1].requests.some((q) => (q.body as any)?.ps === 3)).toBe(true);
    expect(plays).toEqual([['bush-1', 'roof']]);
    const state = (await t.call('GET', '/api/state')).json;
    expect(state.currentSceneId).toBe(created.json.id);
    expect(state.scenes[0].palette.length).toBeGreaterThan(0);

    // Saving new effects while the scene plays shows them at once.
    await t.call('PUT', `/api/admin/scenes/${created.json.id}`, { name: 'Winter', devicePresets: {}, effects: { roof: effects.roof } });
    expect(plays.at(-1)).toEqual(['roof']);

    await t.call('POST', '/api/color', { color: '#ff8800' });
    expect(plays.at(-1)).toBeNull();

    // A backup keeps the effects.
    const backup = (await t.call('GET', '/api/admin/scenes/export')).json;
    expect(backup.publicPresets[0].effects).toEqual({ roof: effects.roof });
    await t.call('POST', '/api/admin/scenes/import', backup);
    expect((await t.call('GET', '/api/admin/overview')).json.scenes[0].effects).toEqual({ roof: effects.roof });
  });

  it('plays a scene with effects only on objects that are in the simulator only', async () => {
    await login();
    t.lights.setEffectPlayer((fx) => ({ devices: [], objects: fx ? 1 : 0 }));
    const scene = (await t.call('POST', '/api/admin/scenes', { name: 'Sim', effects: { 'roof#1': { effect: 'plasma', palette: 'rainbow', speed: 0.5, intensity: 0.5, size: 0.5, brightness: 1 } } })).json;
    const r = await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(r.status).toBe(200);
    const state = (await t.call('GET', '/api/state')).json;
    expect(state.currentSceneId).toBe(scene.id);
    // A segment's effect counts for its object: the scene shows its colors.
    expect(state.scenes[0].palette.length).toBeGreaterThan(0);
  });

  it('changes scenes with the scene transition from the settings', async () => {
    await login();
    const transitions: unknown[] = [];
    t.lights.setEffectPlayer((show, transition) => {
      transitions.push(transition ?? null);
      return { devices: [], objects: show ? 1 : 0 };
    });
    const settings = (await t.call('GET', '/api/admin/overview')).json.settings;
    expect(settings).toMatchObject({ sceneTransition: 'fade', sceneTransitionSeconds: 1 });
    const scene = (await t.call('POST', '/api/admin/scenes', { name: 'Glow', effects: { roof: { effect: 'plasma', palette: 'rainbow', speed: 0.5, intensity: 0.5, size: 0.5, brightness: 1 } } })).json;
    await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(transitions.at(-1)).toEqual({ type: 'fade', seconds: 1 });

    expect((await t.call('PUT', '/api/admin/settings', { ...settings, sceneTransition: 'random', sceneTransitionSeconds: 2.5 })).json).toMatchObject({ sceneTransition: 'random', sceneTransitionSeconds: 2.5 });
    await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(transitions.at(-1)).toEqual({ type: 'random', seconds: 2.5 });
    // Settings saved without them (an older page) keep them.
    const { sceneTransition: _, sceneTransitionSeconds: __, ...older } = settings;
    expect((await t.call('PUT', '/api/admin/settings', older)).json.sceneTransition).toBe('random');
    expect((await t.call('PUT', '/api/admin/settings', { ...settings, sceneTransition: 'sideways' })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/settings', { ...settings, sceneTransitionSeconds: 60 })).status).toBe(400);

    await t.call('PUT', '/api/admin/settings', { ...settings, sceneTransition: 'none' });
    await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(transitions.at(-1)).toBeNull();
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

describe('layout pictures', () => {
  it('keeps the picture from above for signed-in users only', async () => {
    const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
    expect((await t.raw('POST', '/api/admin/layout/aerial', png, { 'content-type': 'image/png' })).status).toBe(401);
    await login();
    expect((await t.raw('POST', '/api/admin/layout/aerial', png, { 'content-type': 'text/plain' })).status).toBe(400);
    const up = await t.raw('POST', '/api/admin/layout/aerial', png, { 'content-type': 'image/png' });
    expect(up.status).toBe(200);
    const { url } = JSON.parse(await up.text());
    expect(url).toMatch(/^\/api\/admin\/layout\/aerial\?v=\d+$/);
    const back = await t.raw('GET', url);
    expect(back.headers.get('content-type')).toBe('image/png');
    expect(new Uint8Array(await back.arrayBuffer())).toEqual(png);
    // The editor places it and saves the layout.
    const layout = (await t.call('GET', '/api/layout')).json;
    const aerial = { url, x: 800, z: 0, width: 3200, aspect: 0.5, rotation: 12 };
    expect((await t.call('PUT', '/api/admin/layout', { ...layout, aerial })).status).toBe(200);
    expect((await t.call('GET', '/api/layout')).json.aerial).toEqual(aerial);
    const gone = await t.call('DELETE', '/api/admin/layout/aerial');
    expect(gone.json.aerial).toBeNull();
    expect((await t.raw('GET', url)).status).toBe(404);
  });
});

describe('layout files', () => {
  it('exports a layout with its pictures and devices, and imports it on another install', async () => {
    await login();
    const [a] = await addDevices();
    const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3]);
    await t.raw('POST', '/api/admin/layout/background', png, { 'content-type': 'image/png' });
    const { url } = JSON.parse(await (await t.raw('POST', '/api/admin/layout/aerial', png, { 'content-type': 'image/png' })).text());
    const layout = (await t.call('GET', '/api/layout')).json;
    layout.fixtures[0].deviceId = a;
    layout.aerial = { url, x: 800, z: 0, width: 3200, aspect: 0.5, rotation: 12 };
    expect((await t.call('PUT', '/api/admin/layout', layout)).status).toBe(200);
    await t.call('PUT', '/api/admin/games/area', { exclude: [layout.fixtures[1].id] });

    const file = (await t.call('GET', '/api/admin/layout/export')).json;
    expect(file).toMatchObject({ kind: 'wled-layout', version: 1, gameArea: { exclude: [layout.fixtures[1].id] } });
    expect(file.devices).toHaveLength(1);
    expect(Buffer.from(file.pictures.background.data, 'base64')).toEqual(Buffer.from(png));
    expect(file.pictures.aerial.type).toBe('image/png');

    // A new install: other device ids, the same addresses.
    t = await setup();
    await login();
    const [b] = await addDevices();
    expect(b).not.toBe(a);
    const r = await t.call('POST', '/api/admin/layout/import', file);
    expect(r.status).toBe(200);
    expect(r.json.unmatched).toBe(0);
    expect(r.json.layout.fixtures[0].deviceId).toBe(b);
    expect(r.json.layout.fixtures.map((f: { id: string }) => f.id)).toEqual(layout.fixtures.map((f: { id: string }) => f.id));
    expect((await t.call('GET', '/api/layout')).json).toEqual(r.json.layout);
    const bg = await t.raw('GET', r.json.layout.background);
    expect(new Uint8Array(await bg.arrayBuffer())).toEqual(png);
    expect((await t.raw('GET', r.json.layout.aerial.url)).status).toBe(200);
    expect((await t.call('GET', '/api/admin/games/area')).json.area.exclude).toEqual([layout.fixtures[1].id]);
  });

  it('reads a bare layout, drops devices it cannot find, and refuses a broken file', async () => {
    await login();
    const layout = sampleLayout();
    layout.fixtures[0] = { ...layout.fixtures[0], deviceId: 'gone' };
    const r = await t.call('POST', '/api/admin/layout/import', layout);
    expect(r.status).toBe(200);
    expect(r.json.unmatched).toBe(1);
    expect(r.json.layout.fixtures[0].deviceId).toBeNull();
    expect(r.json.layout.background).toBeNull();
    expect((await t.call('POST', '/api/admin/layout/import', { layout: { fixtures: 'no' } })).status).toBe(400);
    expect((await t.call('POST', '/api/admin/layout/import', { hello: 1 })).status).toBe(400);
    // Nothing changed.
    expect((await t.call('GET', '/api/layout')).json).toEqual(r.json.layout);
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

  it('moves effects on a whole device to the matching device', async () => {
    await login();
    const [a] = await addDevices();
    const fx = { effect: 'rainbow', palette: 'rainbow', speed: 0.5, intensity: 0.5, size: 0.5, brightness: 0.8 };
    await t.call('POST', '/api/admin/scenes', { name: 'Glow', devicePresets: {}, effects: { [`@${a}`]: fx, '@gone': fx } });
    const backup = (await t.call('GET', '/api/admin/scenes/export')).json;
    t = await setup();
    await login();
    const [a2] = await addDevices();
    await t.call('POST', '/api/admin/scenes/import', backup);
    const scenes = (await t.call('GET', '/api/admin/overview')).json.scenes;
    expect(Object.keys(scenes[0].effects)).toEqual([`@${a2}`]);
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

describe('sequences', () => {
  const clip = { id: 'c1', start: 0, duration: 5, targets: ['*'], effect: { effect: 'wash', palette: 'rainbow', speed: 0.5, intensity: 0.5, size: 0.5, brightness: 1, direction: 'up' } };
  const body = { name: 'Show', duration: 30, loop: true, tracks: [{ id: 't1', name: 'Layer 1', opacity: 1, blend: 'normal', clips: [clip] }], audio: [], markers: [{ id: 'm1', t: 4 }] };

  it('creates, lists, saves and deletes a sequence; a scene plays it', async () => {
    await login();
    const created = await t.call('POST', '/api/admin/sequences', body);
    expect(created.status).toBe(201);
    const id = created.json.id;
    expect((await t.call('GET', '/api/admin/sequences')).json.sequences).toMatchObject([{ id, name: 'Show', layers: 1, clips: 1 }]);
    expect((await t.call('POST', '/api/admin/sequences', { ...body, tracks: [{ ...body.tracks[0], blend: 'x' }] })).status).toBe(400);

    const shows: unknown[] = [];
    t.lights.setEffectPlayer((show) => {
      shows.push(show?.sequence?.name ?? null);
      return show?.sequence ? { devices: [], objects: 4 } : { devices: [], objects: 0 };
    });
    expect((await t.call('POST', '/api/admin/scenes', { name: 'Nope', sequenceId: 'missing' })).status).toBe(400);
    const scene = (await t.call('POST', '/api/admin/scenes', { name: 'Show time', sequenceId: id })).json;
    expect(scene.sequenceId).toBe(id);
    const r = await t.call('POST', `/api/scenes/${scene.id}/apply`);
    expect(r.status).toBe(200);
    expect(r.json.effects).toBe(4);
    expect(shows).toEqual(['Show']);
    const state = (await t.call('GET', '/api/state')).json;
    expect(state.scenes[0].palette.length).toBeGreaterThan(0);

    // Saving the sequence plays the new version on the lights.
    const saved = await t.call('PUT', `/api/admin/sequences/${id}`, { ...body, name: 'Show 2' });
    expect(saved.status).toBe(200);
    expect(shows.at(-1)).toBe('Show 2');
    expect((await t.call('GET', `/api/admin/sequences/${id}`)).json.markers).toEqual(body.markers);

    // Deleting it unlinks the scene and stops it.
    expect((await t.call('DELETE', `/api/admin/sequences/${id}`)).status).toBe(200);
    expect(shows.at(-1)).toBeNull();
    expect((await t.call('GET', '/api/admin/overview')).json.scenes[0].sequenceId).toBeUndefined();
  });

  it('refuses a preview on the lights from an editor that is not in front (an older page)', async () => {
    await login();
    const req = { active: true, sequence: body, time: 0, playing: false };
    const old = await t.call('POST', '/api/admin/sequence-preview', req);
    expect(old.status).toBe(400);
    expect(JSON.stringify(old.json)).toContain('Reload this page');
    expect((await t.call('POST', '/api/admin/sequence-preview', { ...req, inFront: true })).status).toBe(200);
  });

  it('lights a custom object for its photo, within limits', async () => {
    await login();
    const base = { active: true, layout: sampleLayout(), selected: null, corner: null };
    const photo = { deviceId: 'd1', from: 0, to: 49, rgb: [0, 140, 0], start: [255, 0, 0] };
    expect((await t.call('POST', '/api/admin/layout/preview', { ...base, photo })).status).toBe(200);
    expect((await t.call('POST', '/api/admin/layout/preview', { ...base, photo: { ...photo, to: 5000 } })).status).toBe(400);
    expect((await t.call('POST', '/api/admin/layout/preview', { ...base, photo: { ...photo, rgb: [0, 300, 0] } })).status).toBe(400);
  });

  it('shows a check of the layout on the lights', async () => {
    await login();
    const base = { active: true, layout: sampleLayout(), selected: null, corner: null };
    for (const check of [{ kind: 'slice', axis: 'x', at: null }, { kind: 'slice', axis: 'z', at: 120 }, { kind: 'bands', axis: 'y', step: 80 }, { kind: 'picture', id: 'roof' }, { kind: 'chase', id: 'roof' }])
      expect((await t.call('POST', '/api/admin/layout/preview', { ...base, check })).status).toBe(200);
    expect((await t.call('POST', '/api/admin/layout/preview', { ...base, check: { kind: 'slice', axis: 'w', at: 0 } })).status).toBe(400);
    expect((await t.call('POST', '/api/admin/layout/preview', { ...base, check: { kind: 'bands', axis: 'x', step: 0 } })).status).toBe(400);
  });

  it('stores audio files', async () => {
    await login();
    const wav = new Uint8Array([82, 73, 70, 70, 1, 2, 3, 4]);
    const up = await t.call('POST', '/api/admin/audio', undefined, {});
    expect(up.status).toBe(400);
    const res = await (async () => {
      const r = await t.call('GET', '/api/admin/audio');
      expect(r.json.files).toEqual([]);
      return r;
    })();
    expect(res.status).toBe(200);
    const sent = await t.raw('POST', '/api/admin/audio', wav, { 'content-type': 'audio/wav', 'x-file-name': encodeURIComponent('Jingle bells.wav') });
    expect(sent.status).toBe(201);
    const file = JSON.parse(await sent.text());
    expect(file).toMatchObject({ name: 'Jingle bells.wav', type: 'audio/wav', size: 8 });
    const back = await t.raw('GET', `/api/admin/audio/${file.id}`);
    expect(new Uint8Array(await back.arrayBuffer())).toEqual(wav);
    expect((await t.call('DELETE', `/api/admin/audio/${file.id}`)).status).toBe(200);
    expect((await t.raw('GET', `/api/admin/audio/${file.id}`)).status).toBe(404);
  });
});

describe('game area', () => {
  it('keeps only what leaves something out, for objects in the layout', async () => {
    expect((await t.call('GET', '/api/admin/games/area')).status).toBe(401);
    await login();
    const layout = sampleLayout();
    expect((await t.call('PUT', '/api/admin/layout', layout)).status).toBe(200);
    const [roof, bush] = layout.fixtures;
    const r = await t.call('PUT', '/api/admin/games/area', { exclude: [bush.id, 'nope'], skip: { [roof.id]: [1], other: [0] }, trim: { [roof.id]: [3, 0], [bush.id]: [0, 0] } });
    expect(r.status).toBe(200);
    expect(r.json.area).toEqual({ exclude: [bush.id], skip: { [roof.id]: [1] }, trim: { [roof.id]: [3, 0] } });
    expect((await t.call('GET', '/api/admin/games/area')).json.area).toEqual(r.json.area);
    expect((await t.call('PUT', '/api/admin/games/area', {})).json.area).toBeNull();
  });
});
