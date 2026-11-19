import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.ts';
import { createAuth } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { Lights } from '../src/lights.ts';
import { RoofView, type Peek } from '../src/roofView.ts';
import { WledPeek } from '../src/wledPeek.ts';
import { sampleLayout, type Layout } from '../../shared/layout.ts';
import type { DeviceTarget } from '../src/lightSender.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';

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
  const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
  const app = createApp({ config, db, bus, lights, discover: async () => [] });
  await createAuth(db, { secureCookie: false }).createUser('admin', 'correct horse battery');
  let cookie = '';
  const call = async (method: string, url: string, body?: unknown) => {
    const res = await app.request(url, {
      method,
      headers: { host: 'lights.lan', ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined
    });
    const jar = new Map(cookie ? cookie.split('; ').map((p) => p.split('=') as [string, string]) : []);
    for (const set of res.headers.getSetCookie()) {
      const [kv] = set.split(';');
      const [k, v] = kv.split('=');
      if (v) jar.set(k, v);
    }
    cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null };
  };
  const signOut = () => (cookie = '');
  return { db, lights, call, signOut };
}

let t: Awaited<ReturnType<typeof setup>>;
let ids: string[] = [];
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

beforeEach(async () => {
  for (const m of mocks) {
    m.requests.length = 0;
    Object.assign(m.state, { on: true, bri: 128 });
  }
  t = await setup();
  expect((await t.call('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' })).status).toBe(200);
  ids = [];
  for (const m of mocks) ids.push((await t.call('POST', '/api/admin/devices', { host: '127.0.0.1', port: m.port })).json.id);
});

describe('power', () => {
  it('needs an admin', async () => {
    t.signOut();
    expect((await t.call('PUT', '/api/admin/lights/power', { on: false })).status).toBe(401);
    expect((await t.call('PUT', '/api/admin/lights/brightness', { level: 50 })).status).toBe(401);
  });

  it('switches every light off, and off holds until switched on', async () => {
    const r = await t.call('PUT', '/api/admin/lights/power', { on: false });
    expect(r.status).toBe(200);
    expect(r.json.controls.off.sort()).toEqual([...ids].sort());
    expect(mocks.every((m) => m.state.on === false)).toBe(true);
    expect((await t.call('GET', '/api/state')).json.lightsOff).toBe(true);

    // Nobody can play a color or a scene on lights that are off.
    t.signOut();
    const color = await t.call('POST', '/api/color', { color: '#ff0000' });
    expect(color.status).toBe(409);
    expect(mocks.every((m) => m.state.on === false)).toBe(true);

    await t.call('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' });
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    expect(mocks.every((m) => m.state.on === true)).toBe(true);
    expect((await t.call('GET', '/api/state')).json.lightsOff).toBe(false);
  });

  it('keeps one device off while colors play on the others', async () => {
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
    expect((await t.call('GET', '/api/state')).json.lightsOff).toBe(false);
    const r = await t.call('POST', '/api/color', { color: '#00ff00' });
    expect(r.status).toBe(200);
    expect(r.json.applied).toEqual([ids[0]]);
    expect(mocks[0].state.on).toBe(true);
    expect(mocks[1].state.on).toBe(false);
    // Off devices get no frames either.
    expect(t.lights.liveDevices().find((d) => d.id === ids[1])?.enabled).toBe(false);
  });

  it('refuses an unknown device', async () => {
    expect((await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: 'nope' })).status).toBe(404);
  });
});

describe('brightness', () => {
  it('sets every light, and a device level wins over it', async () => {
    await t.call('PUT', '/api/admin/lights/brightness', { level: 50 });
    expect(mocks.map((m) => m.state.bri)).toEqual([128, 128]);
    await t.call('PUT', '/api/admin/lights/brightness', { level: 20, deviceId: ids[1] });
    expect(mocks.map((m) => m.state.bri)).toEqual([128, 51]);
    const r = await t.call('GET', '/api/admin/lights');
    expect(r.json.brightness).toEqual({ all: 50, devices: { [ids[1]]: 20 } });

    // A color keeps the levels.
    await t.call('POST', '/api/color', { color: '#0000ff' });
    expect(mocks.map((m) => m.state.bri)).toEqual([128, 51]);

    // The device follows all lights again.
    await t.call('PUT', '/api/admin/lights/brightness', { level: null, deviceId: ids[1] });
    expect(mocks[1].state.bri).toBe(128);
  });

  it('puts the level back after a preset brings its own', async () => {
    await t.call('PUT', '/api/admin/lights/brightness', { level: 40 });
    const scene = await t.call('POST', '/api/admin/scenes', { name: 'Warm', devicePresets: { [ids[0]]: 1, [ids[1]]: 1 } });
    await t.call('POST', `/api/scenes/${scene.json.id}/apply`);
    // The mock's presets set bri 160; the level goes on a moment later.
    await wait(400);
    expect(mocks.map((m) => m.state.bri)).toEqual([102, 102]);
  });

  it('checks the level', async () => {
    expect((await t.call('PUT', '/api/admin/lights/brightness', { level: 0 })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/lights/brightness', { level: 101 })).status).toBe(400);
  });
});

describe('roof view', () => {
  const layout = (): Layout => {
    const l = sampleLayout();
    for (const f of l.fixtures) f.deviceId = f.kind === 'roof' ? 'dev' : null;
    return l;
  };
  const device = { id: 'dev', name: 'Roof', host: '127.0.0.1', port: 1, enabled: true, info: { leds: { count: 2000 } } } as DeviceTarget;

  function fakePeek(): Peek & { live: boolean | null } {
    return { leds: null, step: 1, at: 0, on: null, bri: null, live: null, setLive(v: boolean) { this.live = v; }, close() {} };
  }

  it('shows what the server sends the roof, scaled by the device brightness', () => {
    const l = layout();
    const sent = new Uint8Array(6000).fill(0);
    for (let i = 0; i < sent.length; i += 3) sent[i] = 200;
    const peek = fakePeek();
    peek.bri = 128;
    const view = new RoofView({ layout: () => l, devices: () => [device], deviceFrame: () => sent, simFrame: () => null }, () => peek);
    const f = view.frame();
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]).toBeGreaterThan(90);
    expect(f[0]).toBeLessThan(110);
    expect(f[1]).toBe(0);
    // The device gets frames: it is not asked for its own colors.
    expect(peek.live).toBe(false);
  });

  it('shows what the device plays by itself, and nothing for a switched-off device', () => {
    const l = layout();
    const peek = fakePeek();
    peek.leds = new Uint8Array(3000).fill(0).map((_, i) => (i % 3 === 2 ? 180 : 0));
    peek.at = Date.now();
    let enabled = true;
    const view = new RoofView({ layout: () => l, devices: () => [{ ...device, enabled }], deviceFrame: () => null, simFrame: () => null }, () => peek);
    const f = view.frame();
    expect(peek.live).toBe(true);
    expect(f[2]).toBe(180);
    enabled = false;
    expect(view.frame().every((v) => v === 0)).toBe(true);
  });

  it('lays the cells out left to right, the peak highest', () => {
    const l = layout();
    const view = new RoofView({ layout: () => l, devices: () => [device], deviceFrame: () => null, simFrame: () => null }, fakePeek);
    const geometry: { x: number[]; y: number[] }[] = [];
    const stop = view.watch((e) => e.event === 'geometry' && geometry.push(JSON.parse(e.data)));
    stop?.();
    view.close();
    const g = geometry[0];
    expect(g.x.length).toBeGreaterThan(10);
    expect(g.x).toEqual([...g.x].sort((a, b) => a - b));
    expect(Math.max(...g.y)).toBeGreaterThan(0.95);
    // The sample roof is a gable: high in the middle, low at the ends.
    const mid = g.y[Math.floor(g.y.length / 2)];
    expect(mid).toBeGreaterThan(g.y[0]);
  });
});

describe('WLED peek', () => {
  it('reads the live colors and the state over the WebSocket', async () => {
    const m = mocks[0];
    Object.assign(m.state, { on: true, bri: 255, seg: [{ id: 0, col: [[10, 20, 30]], fx: 0 }] });
    const peek = new WledPeek({ host: '127.0.0.1', port: m.port }, () => 150);
    for (let i = 0; i < 40 && !peek.leds; i++) await wait(50);
    peek.close();
    expect(peek.on).toBe(true);
    expect(peek.bri).toBe(255);
    expect(Array.from(peek.leds!.subarray(0, 3))).toEqual([10, 20, 30]);
    expect(peek.step).toBe(1);
  });
});
