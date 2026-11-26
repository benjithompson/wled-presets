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
import { RoofView, type Peek } from '../src/roofView.ts';
import { WledPeek } from '../src/wledPeek.ts';
import { sampleLayout, type Layout } from '../../shared/layout.ts';
import { LightSender, type DeviceTarget } from '../src/lightSender.ts';
import { FramePipeline, layoutOutput } from '../src/framePipeline.ts';
import { LayoutPreview } from '../src/layoutPreview.ts';
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
  it('lights a switched-off device for an editor that shows it on the lights, and switches it off after', async () => {
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
    await wait(700);
    expect(mocks[1].state.on).toBe(false);
    const pipeline = new FramePipeline(() => t.lights.liveDevices(), new LightSender());
    const preview = new LayoutPreview(pipeline, () => {});
    try {
      // The object designer's photo: LEDs 0 to 9 of that device.
      const names = preview.show({ layout: sampleLayout(), selected: null, corner: null, photo: { deviceId: ids[1], from: 0, to: 9, rgb: [255, 255, 255], start: [0, 255, 0] } });
      expect(names).toHaveLength(1);
      await wait(1500);
      expect(mocks[1].state.on).toBe(true);
      expect(Array.from(mocks[1].realtime.leds.subarray(0, 3))).toEqual([0, 255, 0]);
      expect(Array.from(mocks[1].realtime.leds.subarray(15, 18))).toEqual([255, 255, 255]);
      // The other device, on all along, is left as it was.
      expect(mocks[0].state.on).toBe(true);
      preview.stop();
      await wait(300);
      expect(mocks[1].state.on).toBe(false);
      expect(mocks[0].state.on).toBe(true);
      // Still off for everyone else.
      expect(t.lights.isOff(ids[1])).toBe(true);
    } finally {
      preview.close();
      pipeline.close();
    }
  }, 10_000);

  it('leaves a device on that an admin switched on while an editor lit it', async () => {
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
    await wait(700);
    const pipeline = new FramePipeline(() => t.lights.liveDevices(), new LightSender());
    const preview = new LayoutPreview(pipeline, () => {});
    try {
      preview.show({ layout: sampleLayout(), selected: null, corner: null, photo: { deviceId: ids[1], from: 0, to: 9, rgb: [255, 255, 255], start: [0, 255, 0] } });
      await wait(400);
      await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: ids[1] });
      await wait(800);
      preview.stop();
      await wait(300);
      expect(mocks[1].state.on).toBe(true);
    } finally {
      preview.close();
      pipeline.close();
    }
  }, 10_000);

  it('leaves a device on that an admin switched off and on again while a scene played on it, also after a restart', async () => {
    // A scene's effects on the tree (device 1), as the game host plays them: frames that do not wake.
    const layout: Layout = { ...sampleLayout(), fixtures: sampleLayout().fixtures.map((f, i) => ({ ...f, deviceId: i === 1 ? ids[1] : null })) };
    const out = layoutOutput(layout);
    const bytes = new Uint8Array(out.stage.pixelCount * 3).fill(120);
    const sender = new LightSender();
    const pipeline = new FramePipeline(() => t.lights.liveDevices(), sender);
    pipeline.add({ running: true, tick: () => ({ maps: out.maps, bytes }) });
    pipeline.wake();
    try {
      await wait(400);
      expect(mocks[1].state.on).toBe(true);
      // Off, and on again a few seconds later.
      await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
      await wait(500);
      expect(mocks[1].state.on).toBe(false);
      await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: ids[1] });
      await wait(600);
      expect(mocks[1].state.on).toBe(true);
      // The server stops (a deploy), as index.ts does it.
      await sender.release(t.lights.devicesWithStatus());
      pipeline.close();
      await wait(300);
      expect(mocks[1].state.on).toBe(true);
    } finally {
      pipeline.close();
      sender.close();
    }
    // The next server finds the device as the switch left it, so it does not switch it off here.
    const next = new Lights(t.db, new Bus());
    next.settleMs = 50;
    next.start(100);
    try {
      await wait(800);
      expect(next.isOff(ids[1])).toBe(false);
    } finally {
      next.stop();
    }
  }, 10_000);
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

describe('following the devices', () => {
  /** Waits until `ok` holds (checked every 20 ms), or fails after `ms`. */
  const until = async (ok: () => boolean, ms = 2000) => {
    const end = Date.now() + ms;
    while (!ok()) {
      if (Date.now() > end) throw new Error('Timed out');
      await wait(20);
    }
  };
  const power = (id: string) => t.lights.devicesWithStatus().find((d) => d.id === id)?.power;

  beforeEach(async () => {
    t.lights.settleMs = 100;
    await t.lights.refreshStatus();
    // Each device's WebSocket says its state, and the app's own requests have settled.
    await until(() => ids.every((id) => power(id)?.bri === 128));
    await wait(250);
  });
  afterEach(() => t.lights.stop());

  it("reports each device's own power and brightness", async () => {
    expect(power(ids[0])).toEqual({ on: true, bri: 128 });
    mocks[0].press({ bri: 200 });
    await until(() => power(ids[0])?.bri === 200);
  });

  it('switches a light off here when it is switched off on the device, and on again', async () => {
    mocks[1].press({ on: false });
    await until(() => t.lights.isOff(ids[1]));
    expect(power(ids[1])?.on).toBe(false);
    // Off holds here now: a color leaves it dark.
    const r = await t.call('POST', '/api/color', { color: '#ff0000' });
    expect(r.json.applied).toEqual([ids[0]]);
    expect(mocks[1].state.on).toBe(false);

    await wait(250);
    mocks[1].press({ on: true });
    await until(() => !t.lights.isOff(ids[1]));
  });

  it('says the lights are off when every device was switched off on the device', async () => {
    let ended = 0;
    t.lights.onAllOff = () => ended++;
    for (const m of mocks) m.press({ on: false });
    await until(() => t.lights.allOff());
    expect((await t.call('GET', '/api/state')).json.lightsOff).toBe(true);
    expect(ended).toBe(1);
  });

  it("does not take the app's own switches for changes made on the device", async () => {
    await t.call('PUT', '/api/admin/lights/brightness', { level: 50 });
    await until(() => power(ids[0])?.bri === 128 && power(ids[1])?.bri === 128);
    await t.call('PUT', '/api/admin/lights/brightness', { level: 20 });
    await until(() => power(ids[0])?.bri === 51);
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[0] });
    await until(() => power(ids[0])?.on === false);
    await t.call('PUT', '/api/admin/lights/power', { on: true, deviceId: ids[0] });
    await until(() => power(ids[0])?.on === true);
    await wait(300);
    expect(t.lights.controls()).toEqual({ off: [], brightness: { all: 20, devices: {} } });
  });

  it('follows a level changed on the device, where the app sets one', async () => {
    // With no level here, each scene's presets set it: nothing to follow.
    mocks[0].press({ bri: 40 });
    await until(() => power(ids[0])?.bri === 40);
    expect(t.lights.controls().brightness).toEqual({ all: null, devices: {} });

    await t.call('PUT', '/api/admin/lights/brightness', { level: 50 });
    await wait(250);
    mocks[1].press({ bri: 230 });
    await until(() => t.lights.controls().brightness.devices[ids[1]] === 90);
    expect(t.lights.levelOf(ids[1])).toBe(230);
    expect(t.lights.levelOf(ids[0])).toBe(128);
  });

  it("lends the roof view the device's colors over the same WebSocket", async () => {
    const device = t.db.getDevice(ids[0])!;
    const peek = t.lights.peek(device);
    expect(peek.on).toBe(true);
    peek.setLive(true);
    await until(() => peek.leds !== null);
    expect(peek.leds!.length).toBe(150 * 3);
    // Closing it stops the colors, not the connection that tells the server its state.
    peek.close();
    mocks[0].press({ bri: 77 });
    await until(() => power(ids[0])?.bri === 77);
  });

  it('keeps the colors coming while any view still wants them', async () => {
    const device = t.db.getDevice(ids[0])!;
    const roof = t.lights.peek(device);
    const yard = t.lights.peek(device);
    const live = () => (t.lights as unknown as { watchers: Map<string, { peek: { live: boolean } }> }).watchers.get(device.id)!.peek.live;
    roof.setLive(true);
    yard.setLive(true);
    expect(live()).toBe(true);
    // The roofline closes (nobody on the home page): the yard view still gets the colors.
    roof.close();
    expect(live()).toBe(true);
    yard.close();
    expect(live()).toBe(false);
  });

  it('shows an offline device as offline, and gives it the switch it missed when it is back', async () => {
    const spare = await startMockWled(0, 'Spare');
    const port = spare.port;
    const id = (await t.call('POST', '/api/admin/devices', { host: '127.0.0.1', port })).json.id;
    await t.lights.refreshStatus();
    await until(() => power(id)?.on === true);
    await spare.close();
    // Two missed checks in a row: offline.
    await t.lights.refreshStatus();
    await t.lights.refreshStatus();
    const gone = t.lights.devicesWithStatus().find((d) => d.id === id)!;
    expect(gone.online).toBe(false);
    expect(gone.power).toBeNull();

    // Switched off while it does not answer.
    const r = await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: id });
    expect(r.json.result.failed.map((f: { deviceId: string }) => f.deviceId)).toEqual([id]);

    // Back, and on (as after a power cut): it is switched off, not taken as switched on.
    const back = await startMockWled(port, 'Spare');
    try {
      await t.lights.refreshStatus();
      await until(() => back.state.on === false);
      await wait(300);
      expect(t.lights.isOff(id)).toBe(true);
      expect(t.lights.devicesWithStatus().find((d) => d.id === id)?.online).toBe(true);
    } finally {
      t.lights.stop();
      await back.close();
    }
  }, 10_000);
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

  it('gathers the roof into cells in strip order, its left end first', () => {
    const l = layout();
    // Light only the roof's first LED (strip order): it shows in the first cell.
    const sent = new Uint8Array(6000);
    const view = new RoofView({ layout: () => l, devices: () => [device], deviceFrame: () => sent, simFrame: () => null }, fakePeek);
    const geometry: { cells: number }[] = [];
    const stop = view.watch((e) => e.event === 'geometry' && geometry.push(JSON.parse(e.data)));
    stop?.();
    view.close();
    const cells = geometry[0].cells;
    expect(cells).toBeGreaterThan(10);
    expect(cells).toBeLessThanOrEqual(240);
    const roof = l.fixtures.find((f) => f.kind === 'roof')!;
    // The sample roof's strip starts at its left end: LED 0 is the first cell.
    const first = roof.reversed ? roof.startPixel + roof.pixels - 1 : roof.startPixel;
    sent[first * 3] = 255;
    const f = view.frame();
    expect(f.length).toBe(cells * 3);
    expect(f[0]).toBe(255);
    expect(f.slice(3).every((v) => v === 0)).toBe(true);
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

describe('activity of visitors', () => {
  it('logs a visitor who changes the lights as one, with a tag, and an admin as before', async () => {
    // An admin's color: applied.
    expect((await t.call('POST', '/api/color', { color: '#ff0000' })).status).toBe(200);
    let logs = t.db.listLogs(5, null);
    expect(logs[0]).toMatchObject({ action: 'applied', message: expect.stringMatching(/^Color #ff0000/) });
    // A visitor's: their own entry, under Visitors.
    t.signOut();
    expect((await t.call('POST', '/api/color', { color: '#00ff00' })).status).toBe(200);
    logs = t.db.listLogs(5, 'visitor');
    expect(logs[0]).toMatchObject({ action: 'visitor', message: expect.stringMatching(/^Visitor [\w-]{6}: color #00ff00 applied/) });
    expect((logs[0].details as { visitor: string }).visitor).toMatch(/^[\w-]{6}$/);
  });
});
