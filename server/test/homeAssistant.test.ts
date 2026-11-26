import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.ts';
import { createAuth } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { Lights } from '../src/lights.ts';
import { cleanHaUrl, HomeAssistant } from '../src/homeAssistant.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';
import { startMockHa } from '../../scripts/mock-ha.ts';

type Wled = Awaited<ReturnType<typeof startMockWled>>;
type Ha = Awaited<ReturnType<typeof startMockHa>>;
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(ok: () => boolean, ms = 3000) {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error('Timed out waiting');
    await wait(20);
  }
}

let ha: Ha;
let roof: Wled;
let tree: Wled;
beforeAll(async () => {
  ha = await startMockHa();
  [roof, tree] = await Promise.all([startMockWled(0, 'Roof'), startMockWled(0, 'Tree')]);
});
afterAll(async () => {
  await Promise.all([ha.close(), roof.close(), tree.close()]);
});

async function setup() {
  const db = openDatabase(':memory:');
  const bus = new Bus();
  const lights = new Lights(db, bus);
  const home = new HomeAssistant(db);
  lights.ha = home;
  lights.plugDelayMs = 10;
  const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
  const app = createApp({ config, db, bus, lights, ha: home, discover: async () => [] });
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
      const [k, v] = set.split(';')[0].split('=');
      if (v) jar.set(k, v);
    }
    cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const text = await res.text();
    return { status: res.status, text, json: text ? JSON.parse(text) : null };
  };
  return { db, lights, home, call, signOut: () => (cookie = '') };
}

let t: Awaited<ReturnType<typeof setup>>;
let ids: string[] = [];
beforeEach(async () => {
  for (const m of [roof, tree]) {
    m.requests.length = 0;
    Object.assign(m.state, { on: true, bri: 128 });
  }
  ha.calls.length = 0;
  ha.hooks.onSwitch = undefined;
  for (const [id, s] of [['switch.roof_psu', 'on'], ['switch.tree_psu', 'on'], ['light.porch', 'off'], ['light.garage', 'off']]) ha.states.get(id)!.state = s;
  t = await setup();
  expect((await t.call('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' })).status).toBe(200);
  ids = [];
  for (const m of [roof, tree]) ids.push((await t.call('POST', '/api/admin/devices', { host: '127.0.0.1', port: m.port })).json.id);
});
afterEach(() => t.lights.stop());

const connect = (extra: object = {}) => t.call('PUT', '/api/admin/ha', { url: ha.url, token: ha.token, plugs: { [ids[0]]: 'switch.roof_psu' }, lights: ['light.porch', 'light.garage'], ...extra });

describe('home assistant settings', () => {
  it('cleans the address', () => {
    expect(cleanHaUrl('192.168.29.29:8123')).toBe('http://192.168.29.29:8123');
    expect(cleanHaUrl('https://ha.example.com/lovelace/0')).toBe('https://ha.example.com');
    expect(cleanHaUrl('ftp://x')).toBeNull();
    expect(cleanHaUrl('http://user:pw@x')).toBeNull();
    expect(cleanHaUrl('')).toBe('');
  });

  it('keeps the token to itself: never sent back, never logged', async () => {
    const r = await connect();
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ url: ha.url, hasToken: true, status: { ok: true, version: '2026.11.3', location: 'Home' } });
    expect(r.json.entities.map((e: { id: string }) => e.id)).toEqual(['switch.fan', 'light.garage', 'light.porch', 'switch.roof_psu', 'switch.tree_psu']);
    expect(r.json.entities.find((e: { id: string }) => e.id === 'light.porch')).toMatchObject({ color: true, dimmable: true, outlet: false, area: 'Front yard', device: 'Porch bulb', integration: 'hue' });
    expect(r.json.entities.find((e: { id: string }) => e.id === 'switch.roof_psu')).toMatchObject({ outlet: true, area: 'Garage' });
    expect(r.json.entities.find((e: { id: string }) => e.id === 'switch.fan')).toMatchObject({ area: '', device: '' });
    expect(r.text).not.toContain(ha.token);
    expect((await t.call('GET', '/api/admin/ha')).text).not.toContain(ha.token);
    expect(JSON.stringify(t.db.listLogs(1000, null))).not.toContain(ha.token);

    // Saving without a token keeps it; null removes it.
    expect((await t.call('PUT', '/api/admin/ha', { url: ha.url, plugs: {}, lights: [] })).json.hasToken).toBe(true);
    expect((await t.call('PUT', '/api/admin/ha', { url: ha.url, token: null, plugs: {}, lights: [] })).json.hasToken).toBe(false);
  });

  it('says when the token is refused, and is for admins only', async () => {
    const r = await connect({ token: 'not-the-right-token-at-all-0000' });
    expect(r.json.status).toEqual({ ok: false, error: 'Home Assistant refused the token' });
    expect((await connect({ url: 'ftp://nope' })).status).toBe(400);
    expect((await connect({ lights: ['sensor.outside'] })).status).toBe(400);
    t.signOut();
    expect((await t.call('GET', '/api/admin/ha')).status).toBe(401);
    expect((await connect()).status).toBe(401);
  });
});

describe('lights in home assistant', () => {
  it('switch with all lights, and on their own', async () => {
    await connect();
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    expect(ha.states.get('light.porch')!.state).toBe('on');
    expect(ha.states.get('light.garage')!.state).toBe('on');

    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: 'ha:light.garage' });
    expect(ha.states.get('light.garage')!.state).toBe('off');
    expect(t.lights.isOff('ha:light.garage')).toBe(true);
    expect(t.lights.allOff()).toBe(false);

    await t.call('PUT', '/api/admin/lights/brightness', { level: 50, deviceId: 'ha:light.porch' });
    expect(ha.states.get('light.porch')!.attributes.brightness).toBe(128);

    // Every light, the plug's device and Home Assistant's lights: all off.
    await t.call('PUT', '/api/admin/lights/power', { on: false });
    expect(t.lights.allOff()).toBe(true);
    expect(ha.states.get('light.porch')!.state).toBe('off');
    expect((await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: 'ha:light.nope' })).status).toBe(404);
  });

  it('take a visitor color when they can show one', async () => {
    await connect();
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    ha.calls.length = 0;
    t.signOut();
    expect((await t.call('POST', '/api/color', { color: '#ff0000' })).status).toBe(200);
    expect(ha.states.get('light.porch')!.attributes.rgb_color).toEqual([255, 0, 0]);
    // The garage light has no color: it is switched on, no color sent.
    const garage = ha.calls.find((c) => c.body.entity_id === 'light.garage')!;
    expect(garage.body.rgb_color).toBeUndefined();
  });

  it('follow a light switched in home assistant', async () => {
    await connect();
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    t.lights.settleMs = 0;
    (t.lights as unknown as { pollMs: number }).pollMs = 0;
    await wait(5);
    ha.states.get('light.porch')!.state = 'off';
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.porch')).toBe(true);
  });
});

describe('plugs that power a controller', () => {
  it('cut the power after the lights go off, and give it back before', async () => {
    await connect();
    await t.lights.refreshStatus();
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[0] });
    expect(roof.state.on).toBe(false);
    expect(ha.states.get('switch.roof_psu')!.state).toBe('off');
    const order = [...roof.requests.filter((r) => r.method === 'POST').map(() => 'wled'), ...ha.calls.map((c) => c.service)];
    expect(order).toEqual(['wled', 'switch.turn_off']);
    // The tree has no plug: its power stays.
    expect(ha.states.get('switch.tree_psu')!.state).toBe('on');
    const dev = t.lights.devicesWithStatus().find((d) => d.id === ids[0])!;
    expect(dev.plug).toEqual({ entity: 'switch.roof_psu', name: 'Roof PSU', on: false });
  });

  it('let a controller boot, then give it the switches and what plays', async () => {
    await connect();
    await t.lights.refreshStatus();
    // A red color plays; the roof's power goes.
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[0] });
    await t.call('POST', '/api/color', { color: '#00ff00' });
    const port = roof.port;
    await roof.close();
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    expect(t.lights.devicesWithStatus().find((d) => d.id === ids[0])!.online).toBe(false);

    // On: the plug comes on, and the controller boots a moment later, as WLED does (on, its own look).
    let booted: Wled | null = null;
    ha.hooks.onSwitch = (entity, on) => {
      if (entity === 'switch.roof_psu' && on) void startMockWled(port, 'Roof').then((m) => (booted = roof = m));
    };
    const r = await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: ids[0] });
    expect(r.json.result.failed).toEqual([]);
    expect(ha.states.get('switch.roof_psu')!.state).toBe('on');
    await until(() => booted !== null);
    await t.lights.refreshStatus();
    await until(() => roof.requests.some((q) => q.method === 'POST' && JSON.stringify(q.body).includes('[0,255,0]')));
    expect(roof.state.on).toBe(true);
    expect(t.lights.isOff(ids[0])).toBe(false);
  }, 10_000);

  it('follow a plug switched off in home assistant', async () => {
    await connect();
    await t.lights.refreshStatus();
    t.lights.settleMs = 0;
    (t.lights as unknown as { pollMs: number }).pollMs = 0;
    await wait(5);
    ha.states.get('switch.roof_psu')!.state = 'off';
    await t.lights.refreshStatus();
    expect(t.lights.isOff(ids[0])).toBe(true);
    expect(t.lights.isOff(ids[1])).toBe(false);
  });
});

describe('lights added on the devices page', () => {
  it('are kept when the settings are saved, and a plug is never one', async () => {
    await connect();
    const r = await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'switch.fan'] });
    expect(r.json.lights).toEqual(['light.porch', 'switch.fan']);
    expect((await t.call('PUT', '/api/admin/ha/lights', { lights: ['switch.roof_psu'] })).status).toBe(400);
    // Saving the connection (no lights in it) keeps them; a new plug leaves the lights.
    const s = await t.call('PUT', '/api/admin/ha', { url: ha.url, plugs: { [ids[0]]: 'switch.fan' } });
    expect(s.json.lights).toEqual(['light.porch']);
    t.signOut();
    expect((await t.call('PUT', '/api/admin/ha/lights', { lights: [] })).status).toBe(401);
  });
});

describe('home assistant lights in the layout', () => {
  it('get the mix of their LEDs from each frame, as fast as set, one command at a time', async () => {
    const { FramePipeline, meanColor } = await import('../src/framePipeline.ts');
    const { LightSender } = await import('../src/lightSender.ts');
    const { HaFrames } = await import('../src/haFrames.ts');
    await connect();
    const off = new Set<string>();
    const frames = new HaFrames(t.home, (id, wakes) => wakes || !off.has(id), () => null);
    let clock = 1_000_000;
    frames.now = () => clock;
    const map = { deviceId: 'ha:light.porch', size: 2, pairs: Int32Array.from([0, 0, 1, 1]), objects: ['Porch lamp'] };
    const frame = { maps: [map], bytes: Uint8Array.from([200, 0, 0, 100, 0, 0]) };
    expect(meanColor(frame, map)).toEqual([150, 0, 0]);

    const got: unknown[] = [];
    const pipeline = new FramePipeline(() => [], new LightSender());
    pipeline.haSink = (id, rgb, wakes) => {
      got.push([id, rgb]);
      frames.frame(id, rgb, wakes);
    };
    const source = { running: true, tick: () => frame };
    pipeline.add(source);
    pipeline.wake();
    await until(() => ha.states.get('light.porch')!.state === 'on');
    // Full color, at the brightness of the mix, with a fade as long as the gap (2 a second).
    expect(ha.states.get('light.porch')!.attributes.rgb_color).toEqual([255, 0, 0]);
    expect(ha.states.get('light.porch')!.attributes.brightness).toBe(150);
    expect(ha.calls.at(-1)!.body.transition).toBe(0.5);
    pipeline.remove(source);
    await until(() => got.some((g) => (g as unknown[])[1] === null));
    pipeline.close();

    // Let go, then frames again: the first goes at once. The same color again: nothing. A new
    // color, too soon: it waits for its time.
    const before = ha.calls.length;
    frames.frame('ha:light.porch', [150, 0, 0], false);
    await until(() => ha.calls.length === before + 1);
    const sent = ha.calls.length;
    frames.frame('ha:light.porch', [150, 0, 0], false);
    frames.frame('ha:light.porch', [0, 0, 150], false);
    await wait(50);
    clock += 200;
    frames.frame('ha:light.porch', [0, 0, 150], false);
    await wait(50);
    expect(ha.calls.length).toBe(sent);
    clock += 400;
    frames.frame('ha:light.porch', [0, 0, 150], false);
    await until(() => ha.calls.length === sent + 1);
    // Only the color: the brightness did not change (on Zigbee it is a command of its own).
    expect(ha.calls.at(-1)!.body).toMatchObject({ rgb_color: [0, 0, 255] });
    expect(ha.calls.at(-1)!.body.brightness).toBeUndefined();

    // Faster when set: 10 a second, a fade of a tenth.
    t.home.setFps(10);
    clock += 100;
    frames.frame('ha:light.porch', [0, 150, 0], false);
    await until(() => ha.calls.length === sent + 2);
    expect(ha.calls.at(-1)!.body.transition).toBe(0.1);

    // Dark: off. Switched off by an admin: nothing is sent.
    clock += 100;
    frames.frame('ha:light.porch', [0, 0, 0], false);
    await until(() => ha.states.get('light.porch')!.state === 'off');
    off.add('ha:light.porch');
    clock += 100;
    frames.frame('ha:light.porch', [0, 255, 0], false);
    await wait(50);
    expect(ha.states.get('light.porch')!.state).toBe('off');
    expect(frames.report()['ha:light.porch'].sent).toBeGreaterThanOrEqual(4);
    frames.close();
  });

  it('go over the WebSocket when Home Assistant has one, and REST when not', async () => {
    await connect();
    ha.calls.length = 0;
    expect((await t.home.set('light.porch', true, { rgb: [0, 0, 255] })).ok).toBe(true);
    expect(ha.calls.at(-1)).toMatchObject({ service: 'light.turn_on', via: 'ws', body: { rgb_color: [0, 0, 255] } });
    expect((await t.home.set('light.porch', false, { via: 'rest' })).ok).toBe(true);
    expect(ha.calls.at(-1)).toMatchObject({ service: 'light.turn_off', via: 'rest' });
    t.home.close();
  });

  it('can be speed tested, one test at a time', async () => {
    await connect();
    ha.states.get('light.porch')!.state = 'off';
    await t.home.refresh();
    const r = await t.call('POST', '/api/admin/ha/speedtest', { entity: 'light.porch', fps: 10, seconds: 2 });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ entity: 'light.porch', via: 'ws', fps: 10, inflight: 1, fade: true, errors: 0 });
    expect(r.json.sent).toBeGreaterThanOrEqual(15);
    expect(r.json.achieved).toBeGreaterThan(7);
    // It was off: it is off again.
    expect(ha.states.get('light.porch')!.state).toBe('off');
    expect((await t.call('POST', '/api/admin/ha/speedtest', { entity: 'switch.fan', fps: 10, seconds: 2 })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/ha/rate', { fps: 8 })).json).toMatchObject({ fps: 8, inflight: 1, fade: true });
    expect((await t.call('PUT', '/api/admin/ha/rate', { fps: 8, inflight: 2, fade: false })).json).toMatchObject({ fps: 8, inflight: 2, fade: false });
    // Two at once, against a light that takes 150 ms: twice as many.
    ha.timing.serviceMs = 150;
    try {
      const one = (await t.call('POST', '/api/admin/ha/speedtest', { entity: 'light.porch', fps: 20, seconds: 2 })).json;
      const two = (await t.call('POST', '/api/admin/ha/speedtest', { entity: 'light.porch', fps: 20, seconds: 2, inflight: 2, fade: false })).json;
      expect(one.achieved).toBeLessThan(8);
      expect(two.achieved).toBeGreaterThan(one.achieved * 1.6);
      expect(ha.calls.at(-2)!.body.transition).toBe(0);
    } finally {
      ha.timing.serviceMs = 0;
    }
    expect((await t.call('PUT', '/api/admin/ha/rate', { fps: 99 })).status).toBe(400);
    t.home.close();
  }, 20_000);
});
