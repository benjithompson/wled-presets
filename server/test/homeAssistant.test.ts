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
    expect(r.json.entities.find((e: { id: string }) => e.id === 'light.porch')).toMatchObject({ color: true, dimmable: true, outlet: false, area: 'Front yard', device: 'Porch bulb', integration: 'zha', zigbee: true });
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

  it('get a power switch again only when it failed, and go off after the colors on their way', async () => {
    await connect();
    await t.lights.refreshStatus();
    t.lights.haRetryMs = [100];
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    // Home Assistant fails the porch light's off; a moment later it takes it.
    const porch = ha.states.get('light.porch')!;
    ha.states.delete('light.porch');
    const r = await t.call('PUT', '/api/admin/lights/power', { on: false });
    ha.states.set('light.porch', porch);
    expect(r.json.result.failed.map((f: { deviceId: string }) => f.deviceId)).toEqual(['ha:light.porch']);
    expect(t.db.listLogs(5, null).find((l) => l.message.startsWith('All lights switched off'))?.message).toContain('not taken by "Porch" (Unknown entity)');
    await until(() => porch.state === 'off');
    expect(t.db.listLogs(5, null)[0].message).toBe('"Porch" switched off again, as it failed before');

    // Switched on in Home Assistant by someone: no check sends the site's off again.
    const calls = ha.calls.length;
    porch.state = 'on';
    await wait(300);
    expect(ha.calls.length).toBe(calls);

    // A color from the effects on its way: the off waits for it, so it ends off.
    const { HaFrames } = await import('../src/haFrames.ts');
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    const frames = new HaFrames(t.home, (id) => !t.lights.isOff(id), () => null);
    t.lights.haFramesIdle = (id) => frames.idle(id);
    // The color takes a while; the off alone would be done first, and the light would end on.
    ha.timing.serviceMs = 150;
    frames.frame('ha:light.porch', [255, 0, 0], false);
    await wait(40);
    ha.timing.serviceMs = 0;
    await t.call('PUT', '/api/admin/lights/power', { on: false });
    // Both done, whatever their order.
    await wait(300);
    const order = ha.calls.filter((c) => c.body.entity_id === 'light.porch').slice(-2).map((c) => c.service);
    expect(order).toEqual(['light.turn_on', 'light.turn_off']);
    expect(porch.state).toBe('off');
  });

  it("keep each change on its WLED device: WLED's sync would copy it to the others", async () => {
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
    await t.call('POST', '/api/color', { color: '#00ff00' });
    const posts = roof.requests.filter((q) => q.method === 'POST' && q.url === '/json/state');
    expect(posts.length).toBeGreaterThan(0);
    expect(posts.every((q) => (q.body as { udpn?: { nn?: boolean } }).udpn?.nn === true)).toBe(true);
  });

  it('give a device that missed a switch the switch at the next check, though its WebSocket says nothing', async () => {
    await t.lights.refreshStatus();
    await until(() => t.lights.devicesWithStatus().every((d) => d.power != null));
    (t.lights as unknown as { missed: Set<string> }).missed.add(ids[1]);
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
    tree.state.on = true;
    (t.lights as unknown as { missed: Set<string> }).missed.add(ids[1]);
    await t.lights.refreshStatus();
    await until(() => tree.state.on === false);
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
    // Once two checks say so: off for a moment, then on again, is not switched off.
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.porch')).toBe(false);
    ha.states.get('light.porch')!.state = 'on';
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.porch')).toBe(false);
    ha.states.get('light.porch')!.state = 'off';
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.porch')).toBe(true);
  });
});

describe('home assistant events', () => {
  it('show a light switched in home assistant at once, and the site follows it at the next check', async () => {
    await connect();
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    await t.lights.refreshStatus();
    await until(() => ha.watching() > 0);
    t.lights.settleMs = 0;
    (t.lights as unknown as { pollMs: number }).pollMs = 0;
    await wait(5);
    ha.states.get('light.porch')!.state = 'off';
    ha.emit('light.porch');
    // The console has it at once, with no check in between.
    await until(() => t.home.entity('light.porch')?.state === 'off');
    expect((await t.call('GET', '/api/admin/ha')).json.entities.find((e: { id: string }) => e.id === 'light.porch').state).toBe('off');
    expect(t.lights.isOff('ha:light.porch')).toBe(false);
    await wait(5);
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.porch')).toBe(true);
    t.home.close();
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

  it('give a color picked while the controller starts up to it when it answers', async () => {
    await connect();
    await t.lights.refreshStatus();
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[0] });
    const port = roof.port;
    await roof.close();
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    let booted: Wled | null = null;
    ha.hooks.onSwitch = (entity, on) => {
      if (entity === 'switch.roof_psu' && on) setTimeout(() => void startMockWled(port, 'Roof').then((m) => (booted = roof = m)), 100);
    };
    await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: ids[0] });
    // Picked before the controller answers: it is starting, not failed, and gets the color.
    const r = await t.call('POST', '/api/color', { color: '#0000ff' });
    expect(r.status).toBe(200);
    expect(r.json.starting).toEqual([ids[0]]);
    expect(r.json.failed).toEqual([]);
    await until(() => booted !== null);
    await t.lights.refreshStatus();
    await until(() => roof.requests.some((q) => q.method === 'POST' && JSON.stringify(q.body).includes('[0,0,255]')));
  }, 10_000);

  it('follow a plug switched off in home assistant', async () => {
    await connect();
    await t.lights.refreshStatus();
    t.lights.settleMs = 0;
    (t.lights as unknown as { pollMs: number }).pollMs = 0;
    await wait(5);
    ha.states.get('switch.roof_psu')!.state = 'off';
    await t.lights.refreshStatus();
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

describe('a disabled home assistant light', () => {
  it('stays in the list but the site leaves it alone, and comes back when enabled', async () => {
    await connect();
    const r = await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: ['light.garage', 'light.nope'] });
    expect(r.json).toMatchObject({ lights: ['light.porch', 'light.garage'], disabled: ['light.garage'] });
    expect(t.lights.haLights()).toEqual(['ha:light.porch']);
    expect(t.db.listLogs(1000, null).some((l) => l.message.includes('"Garage" disabled') || l.message.includes('"light.garage" disabled'))).toBe(true);
    ha.calls.length = 0;
    await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: null });
    expect(ha.calls.some((c) => c.body.entity_id === 'light.porch')).toBe(true);
    expect(ha.calls.some((c) => c.body.entity_id === 'light.garage')).toBe(false);
    expect((await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: 'ha:light.garage' })).status).toBe(404);
    // Saving the connection keeps it disabled; switched in Home Assistant, it is not followed.
    expect((await t.call('PUT', '/api/admin/ha', { url: ha.url, plugs: {} })).json.disabled).toEqual(['light.garage']);
    // Enabled again: the site switches it.
    expect((await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: [] })).json.disabled).toEqual([]);
    expect(t.lights.haLights()).toEqual(['ha:light.porch', 'ha:light.garage']);
  });
});

describe('a home assistant light enabled again', () => {
  it('is as the other lights: switched on while it was disabled, it is on, and shows the color', async () => {
    await connect();
    await t.call('PUT', '/api/admin/lights/power', { on: false });
    expect(t.lights.isOff('ha:light.porch')).toBe(true);
    await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: ['light.porch'] });
    ha.calls.length = 0;
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    // Nothing went to it, but its switch is on with the rest.
    expect(ha.calls.some((c) => c.body.entity_id === 'light.porch')).toBe(false);
    expect(t.lights.isOff('ha:light.porch')).toBe(false);
    await t.call('POST', '/api/color', { color: '#00ff00' });
    await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: [] });
    expect(ha.states.get('light.porch')).toMatchObject({ state: 'on', attributes: { rgb_color: [0, 255, 0] } });
  });

  it('held off while the others are on (from before this version) comes on with them', async () => {
    await connect();
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: ['light.porch'] });
    const c = t.lights.controls();
    (t.lights as unknown as { saveControls: (c: unknown) => void }).saveControls({ ...c, off: [...c.off, 'ha:light.porch'] });
    await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: [] });
    expect(t.lights.isOff('ha:light.porch')).toBe(false);
    // All off: one enabled again stays off.
    await t.call('PUT', '/api/admin/lights/power', { on: false });
    await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: ['light.porch'] });
    await t.call('PUT', '/api/admin/ha/lights', { lights: ['light.porch', 'light.garage'], disabled: [] });
    expect(t.lights.isOff('ha:light.porch')).toBe(true);
  });
});

describe('home assistant lights that misbehave', () => {
  it('coming back from unavailable are not taken as switched off', async () => {
    await connect();
    await t.lights.setPower(true, null);
    t.lights.settleMs = 0;
    (t.lights as unknown as { pollMs: number }).pollMs = 0;
    await wait(5);
    ha.states.get('light.porch')!.state = 'unavailable';
    await t.lights.refreshStatus();
    ha.states.get('light.porch')!.state = 'off';
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.porch')).toBe(false);
    // Switched off from on: followed.
    ha.states.get('light.garage')!.state = 'off';
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    expect(t.lights.isOff('ha:light.garage')).toBe(true);
  });

  it('are read again by Home Assistant after a command fails, at most now and then', async () => {
    await connect();
    ha.calls.length = 0;
    expect((await t.home.set('light.nope', true, { rgb: [255, 0, 0] })).ok).toBe(false);
    expect((await t.home.set('light.nope', true, { rgb: [0, 255, 0] })).ok).toBe(false);
    await until(() => ha.calls.some((c) => c.service === 'homeassistant.update_entity'));
    await wait(50);
    expect(ha.calls.filter((c) => c.service === 'homeassistant.update_entity')).toHaveLength(1);
    t.home.close();
  });

  it('in the layout come on through light.turn_on, then take Zigbee colors, and dim right down when dark', async () => {
    const { HaFrames } = await import('../src/haFrames.ts');
    await connect();
    t.home.setFrames({ fps: 10, direct: true });
    const frames = new HaFrames(t.home, () => true, () => null);
    let clock = 1_000_000;
    frames.now = () => clock;
    ha.calls.length = 0;
    frames.frame('ha:light.porch', [255, 0, 0], false);
    await until(() => ha.calls.length === 1);
    expect(ha.calls[0].service).toBe('light.turn_on');
    clock += 200;
    frames.frame('ha:light.porch', [0, 0, 255], false);
    await until(() => ha.calls.length === 2);
    expect(ha.calls[1]).toMatchObject({ service: 'zha.issue_zigbee_cluster_command', body: { cluster_id: 0x0300 } });
    // Dark: the level right down, as a Zigbee command (move to level, which never switches it off); lit: the level back.
    clock += 200;
    frames.frame('ha:light.porch', [0, 0, 0], false);
    await until(() => ha.calls.length === 3);
    expect(ha.calls[2]).toMatchObject({ service: 'zha.issue_zigbee_cluster_command', body: { cluster_id: 0x0008, command: 0, params: { level: 1 } } });
    clock += 200;
    frames.frame('ha:light.porch', [0, 255, 0], false);
    await until(() => ha.calls.length === 5);
    expect(ha.calls.slice(3).map((c) => c.body.cluster_id as number).sort((a, b) => a - b)).toEqual([0x0008, 0x0300]);
    expect(ha.calls.some((c) => c.service === 'light.turn_off')).toBe(false);
    frames.close();
    t.home.close();
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
    // Full color, at the light's own level (none set: full), with a fade as long as the gap (2 a second).
    expect(ha.states.get('light.porch')!.attributes.rgb_color).toEqual([255, 0, 0]);
    expect(ha.states.get('light.porch')!.attributes.brightness).toBe(255);
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
    // Only the color, though the mix is dimmer: the brightness is the light's own (on Zigbee it is a command of its own).
    expect(ha.calls.at(-1)!.body).toMatchObject({ rgb_color: [0, 0, 255] });
    expect(ha.calls.at(-1)!.body.brightness).toBeUndefined();

    // Faster when set: 10 a second, a fade of a tenth.
    t.home.setFps(10);
    clock += 100;
    frames.frame('ha:light.porch', [0, 150, 0], false);
    await until(() => ha.calls.length === sent + 2);
    expect(ha.calls.at(-1)!.body.transition).toBe(0.1);

    // Dark: never off, its last color right down (only the brightness goes). Dark again: nothing more.
    clock += 100;
    const lit = ha.calls.length;
    frames.frame('ha:light.porch', [0, 0, 0], false);
    await until(() => ha.calls.length === lit + 1);
    expect(ha.calls.at(-1)).toMatchObject({ service: 'light.turn_on', body: { brightness: 1 } });
    expect(ha.calls.at(-1)!.body.rgb_color).toBeUndefined();
    expect(ha.states.get('light.porch')!.state).toBe('on');
    clock += 1000;
    frames.frame('ha:light.porch', [0, 0, 0], false);
    await wait(50);
    expect(ha.calls.length).toBe(lit + 1);
    // Switched off by an admin: nothing is sent.
    await t.home.set('light.porch', false);
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

  it('take a color as one Zigbee command when they are ZHA lights that are on', async () => {
    const { rgbToXy } = await import('../../shared/color.ts');
    const [x, y] = rgbToXy([255, 0, 0]);
    expect(x).toBeCloseTo(0.64, 2);
    expect(y).toBeCloseTo(0.33, 2);
    await connect();
    ha.calls.length = 0;
    // Off: light.turn_on first, which switches it on with its color and level.
    expect((await t.home.set('light.porch', true, { rgb: [255, 0, 0], bri: 200, transition: 0.1, direct: true })).ok).toBe(true);
    expect(ha.calls.at(-1)!.service).toBe('light.turn_on');
    // On: the color, and the level, straight to the light: the color cluster on its endpoint (11).
    expect((await t.home.set('light.porch', true, { rgb: [255, 0, 0], bri: 100, transition: 0.1, direct: true })).ok).toBe(true);
    const sent = ha.calls.slice(-2).map((c) => c.body);
    expect(sent).toContainEqual({ ieee: '00:17:88:01:0b:2a:3c:4d', endpoint_id: 11, cluster_id: 0x0300, cluster_type: 'in', command_type: 'server', command: 7, params: { color_x: Math.round(x * 65535), color_y: Math.round(y * 65535), transition_time: 1 } });
    // Move to level, not with on/off: on and off go through light.turn_on and turn_off only, so Home Assistant's state stays right.
    expect(sent).toContainEqual(expect.objectContaining({ cluster_id: 0x0008, command: 0, params: { level: 100, transition_time: 1 } }));
    // Not asked for, or not a ZHA light: light.turn_on.
    await t.home.set('light.porch', true, { rgb: [0, 255, 0] });
    expect(ha.calls.at(-1)!.service).toBe('light.turn_on');
    await t.home.set('light.garage', true, { bri: 50, direct: true });
    expect(ha.calls.at(-1)!.service).toBe('light.turn_on');
    const r = await t.call('POST', '/api/admin/ha/speedtest', { entity: 'light.porch', fps: 10, seconds: 2, direct: true });
    expect(r.json).toMatchObject({ direct: true, errors: 0 });
    expect(ha.calls.filter((c) => c.service === 'zha.issue_zigbee_cluster_command').length).toBeGreaterThan(15);
    expect((await t.call('PUT', '/api/admin/ha/rate', { fps: 10, direct: true })).json).toMatchObject({ fps: 10, direct: true });
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
