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
import { LightScheduler } from '../src/lightSchedule.ts';
import { sunTimes } from '../../shared/sun.ts';
import { cleanSchedule, DEFAULT_PERIOD, DEFAULT_SCHEDULE, describeDays, describeTime, nextEvent, scheduleEvents, scheduledOn, wallTime, type LightSchedule, type SchedulePeriod } from '../../shared/schedule.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';

const NY: LightSchedule = { ...DEFAULT_SCHEDULE, enabled: true, latitude: 40.7128, longitude: -74.006, timeZone: 'America/New_York' };
/** The schedule with its one period (the evening) changed. */
const evening = (s: LightSchedule, patch: Partial<SchedulePeriod>): LightSchedule => ({ ...s, periods: [{ ...s.periods[0], ...patch }] });
const period = (patch: Partial<SchedulePeriod>): SchedulePeriod => ({ ...DEFAULT_PERIOD, ...patch });
const at = (iso: string) => Date.parse(iso);
const minutes = (a: number, b: number) => Math.abs(a - b) / 60_000;

describe('sun', () => {
  it('rises and sets within a couple of minutes of the almanac', () => {
    // New York, midsummer: 5:25 and 20:31 EDT.
    const ny = sunTimes(at('2026-06-21T16:00:00Z'), 40.7128, -74.006);
    expect(minutes(ny.sunrise!, at('2026-06-21T09:25:00Z'))).toBeLessThan(2);
    expect(minutes(ny.sunset!, at('2026-06-22T00:31:00Z'))).toBeLessThan(2);
    // London, midwinter: 8:04 and 15:53 GMT.
    const lon = sunTimes(at('2026-12-21T12:00:00Z'), 51.5074, -0.1278);
    expect(minutes(lon.sunrise!, at('2026-12-21T08:04:00Z'))).toBeLessThan(2);
    expect(minutes(lon.sunset!, at('2026-12-21T15:53:00Z'))).toBeLessThan(2);
    // Sydney, its midsummer: 5:41 and 20:05 AEDT.
    const syd = sunTimes(at('2026-12-21T02:00:00Z'), -33.8688, 151.2093);
    expect(minutes(syd.sunrise!, at('2026-12-20T18:41:00Z'))).toBeLessThan(2);
    expect(minutes(syd.sunset!, at('2026-12-21T09:05:00Z'))).toBeLessThan(2);
  });

  it('has no sunrise or sunset in the polar night', () => {
    expect(sunTimes(at('2026-12-21T12:00:00Z'), 69.65, 18.96)).toEqual({ sunrise: null, sunset: null });
  });
});

describe('schedule times', () => {
  it('reads a clock in a time zone, through the changes of the clocks', () => {
    expect(new Date(wallTime('America/New_York', 2026, 11, 25, 23, 0)).toISOString()).toBe('2026-11-26T04:00:00.000Z');
    expect(new Date(wallTime('America/New_York', 2026, 7, 4, 23, 0)).toISOString()).toBe('2026-07-05T03:00:00.000Z');
    // 2:30 does not happen on the morning the clocks go forward: an hour later, 3:30 EDT.
    expect(new Date(wallTime('America/New_York', 2026, 3, 8, 2, 30)).toISOString()).toBe('2026-03-08T07:30:00.000Z');
    // 1:30 happens twice when they go back: the first time, EDT.
    expect(new Date(wallTime('America/New_York', 2026, 11, 1, 1, 30)).toISOString()).toBe('2026-11-01T05:30:00.000Z');
  });

  it('lists the times to switch, in order: on at sunset, off at a time', () => {
    const events = scheduleEvents(NY, at('2026-11-25T12:00:00Z'), at('2026-11-27T12:00:00Z'));
    expect(events.map((e) => e.kind)).toEqual(['on', 'off', 'on', 'off']);
    expect(minutes(events[0].at, at('2026-11-25T21:33:00Z'))).toBeLessThan(2);
    expect(new Date(events[1].at).toISOString()).toBe('2026-11-26T04:00:00.000Z');
  });

  it('moves sunrise and sunset by the offset', () => {
    const plain = nextEvent(NY, at('2026-11-25T12:00:00Z'), 'on')!;
    const early = nextEvent(evening(NY, { on: { at: 'sunset', offset: -30, time: '00:00' } }), at('2026-11-25T12:00:00Z'), 'on')!;
    expect(plain.at - early.at).toBe(30 * 60_000);
    const morning = nextEvent(evening(NY, { off: { at: 'sunrise', offset: 15, time: '00:00' } }), at('2026-11-25T15:00:00Z'), 'off')!;
    expect(new Date(morning.at).toISOString().slice(0, 10)).toBe('2026-11-26');
  });

  it('does nothing when off, or without a place for the sun', () => {
    expect(scheduleEvents({ ...NY, enabled: false }, 0, at('2030-01-01T00:00:00Z'))).toEqual([]);
    expect(scheduleEvents({ ...NY, latitude: null }, at('2026-11-25T00:00:00Z'), at('2026-11-27T00:00:00Z'))).toEqual([]);
    // Clock times need no place.
    const clock = { ...evening(NY, { on: { at: 'time', offset: 0, time: '17:00' } }), latitude: null, longitude: null };
    expect(scheduleEvents(clock, at('2026-11-25T00:00:00Z'), at('2026-11-26T00:00:00Z')).map((e) => e.kind)).toEqual(['off', 'on']);
  });

  it('says its times in words, and cleans what it keeps', () => {
    expect(describeTime({ at: 'sunset', offset: 0, time: '' })).toBe('sunset');
    expect(describeTime({ at: 'sunset', offset: -30, time: '' })).toBe('30 minutes before sunset');
    expect(describeTime({ at: 'sunrise', offset: 60, time: '' })).toBe('1 hour after sunrise');
    expect(describeTime({ at: 'time', offset: 0, time: '23:00' })).toBe('23:00');
    expect(cleanSchedule({ enabled: true, latitude: 200, timeZone: 'Mars/Base', periods: [{ id: 'evening', name: 'Evening', on: { at: 'noon', time: '25:00' } }] })).toEqual({ ...DEFAULT_SCHEDULE, enabled: true });
    expect(describeDays([1, 2, 3, 4, 5])).toBe('weekdays');
    expect(describeDays([5, 6])).toBe('Fri, Sat');
  });

  it('keeps a schedule from before there were periods as its evening', () => {
    const old = { enabled: true, latitude: 40.7, longitude: -74, timeZone: 'America/New_York', on: { at: 'time', offset: 0, time: '18:00' }, off: { at: 'sunrise', offset: 0, time: '23:00' }, wake: false, idleMinutes: 30 };
    expect(cleanSchedule(old)).toEqual({ ...old, on: undefined, off: undefined, periods: [{ ...DEFAULT_PERIOD, on: old.on, off: old.off }] });
  });
});

describe('schedule periods', () => {
  // An evening, sunset to 23:00, and a morning, 06:00 to sunrise (7:00 in late November in New York).
  const MORNING = period({ id: 'morning', name: 'Morning', on: { at: 'time', offset: 0, time: '06:00' }, off: { at: 'sunrise', offset: 0, time: '00:00' } });
  const TWO = { ...NY, periods: [DEFAULT_PERIOD, MORNING] };

  it('switches on and off for each one, in order', () => {
    const events = scheduleEvents(TWO, at('2026-11-25T12:00:00Z'), at('2026-11-26T20:00:00Z'));
    expect(events.map((e) => `${e.kind} ${e.label}`)).toEqual(['on Evening, sunset', 'off Evening, at 23:00', 'on Morning, at 06:00', 'off Morning, sunrise']);
    expect(new Date(events[2].at).toISOString()).toBe('2026-11-26T11:00:00.000Z');
    expect(scheduledOn(TWO, at('2026-11-26T11:30:00Z'))).toBe(true);
    expect(scheduledOn(TWO, at('2026-11-26T09:00:00Z'))).toBe(false);
  });

  it('leaves out a morning the sun is already up for', () => {
    // Midsummer: sunrise is 5:25, before 06:00. No morning, not 23 hours on.
    const events = scheduleEvents({ ...TWO, periods: [MORNING] }, at('2026-06-20T12:00:00Z'), at('2026-06-23T12:00:00Z'));
    expect(events).toEqual([]);
  });

  it('runs one past midnight, and makes ones that overlap or touch one stretch', () => {
    const late = { ...NY, periods: [period({ off: { at: 'time', offset: 0, time: '01:00' } })] };
    const e = scheduleEvents(late, at('2026-11-25T12:00:00Z'), at('2026-11-26T12:00:00Z'));
    expect(e.map((x) => x.kind)).toEqual(['on', 'off']);
    expect(new Date(e[1].at).toISOString()).toBe('2026-11-26T06:00:00.000Z');
    // 17:00 to 21:00 and 21:00 to 23:30, and 20:00 to 22:00 inside: on at 17:00, off at 23:30, once.
    const clock = (on: string, off: string) => ({ on: { at: 'time' as const, offset: 0, time: on }, off: { at: 'time' as const, offset: 0, time: off } });
    const many = { ...NY, periods: [period({ id: 'a', ...clock('17:00', '21:00') }), period({ id: 'b', ...clock('21:00', '23:30') }), period({ id: 'c', name: 'Party', ...clock('20:00', '22:00') })] };
    const m = scheduleEvents(many, at('2026-11-25T12:00:00Z'), at('2026-11-26T12:00:00Z'));
    expect(m.map((x) => [x.kind, new Date(x.at).toISOString()])).toEqual([
      ['on', '2026-11-25T22:00:00.000Z'],
      ['off', '2026-11-26T04:30:00.000Z']
    ]);
    // Each time says the period it is: its off is the one that ends last.
    expect(m.map((x) => x.period)).toEqual(['a', 'b']);
  });

  it('runs on its days only, and not at all when switched off', () => {
    // Fridays and Saturdays: Friday 27 and Saturday 28 November.
    const weekend = { ...NY, periods: [period({ days: [5, 6] })] };
    const days = scheduleEvents(weekend, at('2026-11-23T12:00:00Z'), at('2026-11-30T12:00:00Z'))
      .filter((e) => e.kind === 'on')
      .map((e) => new Date(e.at).toISOString().slice(0, 10));
    expect(days).toEqual(['2026-11-27', '2026-11-28']);
    expect(scheduleEvents({ ...NY, periods: [period({ enabled: false })] }, at('2026-11-23T12:00:00Z'), at('2026-11-30T12:00:00Z'))).toEqual([]);
    expect(scheduleEvents({ ...NY, periods: [period({ days: [] })] }, at('2026-11-23T12:00:00Z'), at('2026-11-30T12:00:00Z'))).toEqual([]);
  });
});

type Mock = Awaited<ReturnType<typeof startMockWled>>;
let mocks: Mock[] = [];
beforeAll(async () => {
  mocks = await Promise.all([startMockWled(0, 'Roof'), startMockWled(0, 'Tree')]);
});
afterAll(async () => {
  await Promise.all(mocks.map((m) => m.close()));
});

describe('scheduler', () => {
  let clock = 0;
  let ended = 0;
  let busy = false;
  let t: Awaited<ReturnType<typeof setup>>;

  async function setup() {
    const db = openDatabase(':memory:');
    const bus = new Bus();
    const lights = new Lights(db, bus);
    const schedule = new LightScheduler(db, lights, bus, { now: () => clock, afterOff: () => ended++, busy: () => busy });
    lights.lightsOnAt = () => schedule.nextOnAt();
    lights.nightWake = () => ({ wake: schedule.canWake(), idleMinutes: schedule.idleMinutes() });
    const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
    const app = createApp({ config, db, bus, lights, schedule, discover: async () => [] });
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
      return { status: res.status, json: text ? JSON.parse(text) : null };
    };
    return { db, lights, schedule, call, signOut: () => (cookie = '') };
  }

  let ids: string[] = [];
  beforeEach(async () => {
    for (const m of mocks) Object.assign(m.state, { on: true, bri: 128 });
    clock = at('2026-11-25T23:00:00Z'); // 18:00 in New York: after sunset, so the lights are on
    ended = 0;
    busy = false;
    t = await setup();
    expect((await t.call('POST', '/api/auth/login', { username: 'admin', password: 'correct horse battery' })).status).toBe(200);
    ids = [];
    for (const m of mocks) ids.push((await t.call('POST', '/api/admin/devices', { host: '127.0.0.1', port: m.port })).json.id);
  });
  afterEach(() => t.schedule.stop());

  it('is for admins, and checks what it saves', async () => {
    expect((await t.call('GET', '/api/admin/lights/schedule')).json).toEqual(DEFAULT_SCHEDULE);
    expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, latitude: null })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, timeZone: 'Nowhere/Here' })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/lights/schedule', evening(NY, { off: DEFAULT_PERIOD.on }))).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, periods: [] })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, periods: [DEFAULT_PERIOD, DEFAULT_PERIOD] })).status).toBe(400);
    expect((await t.call('PUT', '/api/admin/lights/schedule', NY)).json).toEqual(NY);
    t.signOut();
    expect((await t.call('PUT', '/api/admin/lights/schedule', DEFAULT_SCHEDULE)).status).toBe(401);
  });

  it('switches the lights off and on at its times, and tells visitors when they come back on', async () => {
    await t.call('PUT', '/api/admin/lights/schedule', NY);
    // On now, as the schedule says: saving changes nothing.
    expect(t.lights.allOff()).toBe(false);

    clock = at('2026-11-26T04:00:30Z'); // just after 23:00
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(true);
    expect(mocks.every((m) => m.state.on === false)).toBe(true);
    expect(ended).toBe(1);
    const state = (await t.call('GET', '/api/state')).json;
    expect(state.lightsOff).toBe(true);
    expect(minutes(Date.parse(state.lightsOnAt), at('2026-11-26T21:33:00Z'))).toBeLessThan(2);

    // The same time does not happen twice.
    await t.schedule.check();
    expect(ended).toBe(1);

    clock = at('2026-11-26T22:00:00Z'); // after sunset
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(false);
    expect(mocks.every((m) => m.state.on === true)).toBe(true);
    expect((await t.call('GET', '/api/state')).json.lightsOnAt).toBeNull();
  });

  it('switches on again for a morning, and off at sunrise', async () => {
    const morning = period({ id: 'morning', name: 'Morning', on: { at: 'time', offset: 0, time: '06:00' }, off: { at: 'sunrise', offset: 0, time: '00:00' } });
    await t.call('PUT', '/api/admin/lights/schedule', { ...NY, periods: [DEFAULT_PERIOD, morning] });
    clock = at('2026-11-26T04:00:30Z'); // 23:00: off for the night
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(true);
    const state = (await t.call('GET', '/api/state')).json;
    expect(state.lightsOnAt).toBe('2026-11-26T11:00:00.000Z');
    clock = at('2026-11-26T11:00:30Z'); // 06:00
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(false);
    expect(mocks.every((m) => m.state.on === true)).toBe(true);
    clock = at('2026-11-26T12:30:00Z'); // after sunrise
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(true);
    expect(minutes(Date.parse((await t.call('GET', '/api/state')).json.lightsOnAt), at('2026-11-26T21:33:00Z'))).toBeLessThan(2);
  });

  it("sets each period's Home Assistant lights and switches at its off, and again when woken lights go off", async () => {
    const offs: [string[], string, boolean][] = [];
    const real = t.lights.scheduleOff.bind(t.lights);
    t.lights.scheduleOff = (actions, why, all) => (offs.push([actions.map((a) => `${a.entity} ${a.on ? `on ${a.brightness}` : 'off'}`), why, all]), real(actions, why, all));
    const evening = { ...DEFAULT_PERIOD, atOff: [{ entity: 'light.driveway', on: true, brightness: 40 }, { entity: 'switch.porch', on: false, brightness: 100 }] };
    const morning = period({ id: 'morning', name: 'Morning', on: { at: 'time', offset: 0, time: '06:00' }, off: { at: 'sunrise', offset: 0, time: '00:00' }, atOff: [{ entity: 'light.driveway', on: false, brightness: 100 }] });
    expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, periods: [evening, morning] })).status).toBe(200);
    clock = at('2026-11-26T04:00:30Z'); // 23:00
    await t.schedule.check();
    expect(offs.at(-1)).toEqual([['light.driveway on 40', 'switch.porch off'], 'by the schedule (Evening, at 23:00)', true]);

    // Woken in the night and left: off again, and the evening's off again too.
    expect((await t.call('POST', '/api/color', { color: '#ff8800' })).status).toBe(200);
    clock = at('2026-11-26T04:20:00Z');
    await t.schedule.checkIdle();
    expect(t.lights.allOff()).toBe(true);
    expect(offs.at(-1)?.[0]).toEqual(['light.driveway on 40', 'switch.porch off']);

    // The morning's off, at sunrise, has its own.
    clock = at('2026-11-26T11:00:30Z');
    await t.schedule.check();
    clock = at('2026-11-26T12:30:00Z');
    await t.schedule.check();
    expect(offs.at(-1)?.slice(0, 2)).toEqual([['light.driveway off'], 'by the schedule (Morning, sunrise)']);

    // Switched off already by an admin: the off's Home Assistant part still happens.
    clock = at('2026-11-26T22:00:00Z');
    await t.schedule.check();
    await t.call('PUT', '/api/admin/lights/power', { on: false });
    clock = at('2026-11-27T04:00:30Z');
    await t.schedule.check();
    expect(offs.at(-1)).toEqual([['light.driveway on 40', 'switch.porch off'], 'by the schedule (Evening, at 23:00)', false]);

    // Checked: lights and switches only, each once.
    const put = (atOff: unknown[]) => t.call('PUT', '/api/admin/lights/schedule', { ...NY, periods: [{ ...DEFAULT_PERIOD, atOff }] });
    expect((await put([{ entity: 'sensor.outside', on: true, brightness: 50 }])).status).toBe(400);
    expect((await put([{ entity: 'light.a', on: true, brightness: 50 }, { entity: 'light.a', on: false, brightness: 50 }])).status).toBe(400);
    expect((await put([{ entity: 'light.a', on: true, brightness: 0 }])).status).toBe(400);
  });

  it('leaves a light an admin switched off on its own off', async () => {
    await t.call('PUT', '/api/admin/lights/schedule', NY);
    await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
    clock = at('2026-11-26T04:01:00Z');
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(true);
    clock = at('2026-11-26T22:00:00Z');
    await t.schedule.check();
    expect(t.lights.isOff(ids[0])).toBe(false);
    expect(t.lights.isOff(ids[1])).toBe(true);
  });

  it('puts the lights as it says for now when it is saved', async () => {
    clock = at('2026-11-26T15:00:00Z'); // 10:00: between 23:00 and sunset
    await t.call('PUT', '/api/admin/lights/schedule', NY);
    expect(t.lights.allOff()).toBe(true);
    expect(ended).toBe(1);
    expect((await t.call('GET', '/api/state')).json).toMatchObject({ lightsOff: true, lightsWake: true });
    // Saved again in the night: nothing more happens.
    await t.call('PUT', '/api/admin/lights/schedule', { ...NY, idleMinutes: 20 });
    expect(ended).toBe(1);
    // On from 09:00 now: it is no longer the night, and they come on.
    await t.call('PUT', '/api/admin/lights/schedule', evening(NY, { on: { at: 'time', offset: 0, time: '09:00' } }));
    expect(t.lights.allOff()).toBe(false);
    expect(mocks.every((m) => m.state.on === true)).toBe(true);
    // Switched off by hand in the day, they stay off through a save that keeps it the day.
    await t.call('PUT', '/api/admin/lights/power', { on: false });
    await t.call('PUT', '/api/admin/lights/schedule', evening(NY, { on: { at: 'time', offset: 0, time: '08:00' } }));
    expect(t.lights.allOff()).toBe(true);
  });

  it('does each time once across restarts: an admin switch holds, and a time it never did happens', async () => {
    await t.call('PUT', '/api/admin/lights/schedule', NY);
    clock = at('2026-11-26T04:01:00Z');
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(true);
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    const restart = () => {
      t.schedule.stop();
      t.schedule = new LightScheduler(t.db, t.lights, new Bus(), { now: () => clock, afterOff: () => ended++ });
      t.schedule.start();
      return t.schedule.check();
    };
    clock = at('2026-11-26T15:00:00Z');
    await restart();
    expect(t.lights.allOff()).toBe(false);
    // From a version that did not keep which time it did: the time it is, is done.
    t.db.setSetting('lightScheduleApplied', '');
    await restart();
    expect(t.lights.allOff()).toBe(true);
  });

  it('catches up on the latest time it missed, once', async () => {
    await t.call('PUT', '/api/admin/lights/schedule', NY);
    // Down from before 23:00 until the next morning: the 23:00 off happens when it starts.
    clock = at('2026-11-26T13:00:00Z');
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(true);
    // An admin switches them on in the morning: that holds until the next time.
    await t.call('PUT', '/api/admin/lights/power', { on: true });
    clock = at('2026-11-26T14:00:00Z');
    await t.schedule.check();
    expect(t.lights.allOff()).toBe(false);
  });

  describe('in the night', () => {
    const NIGHT = at('2026-11-26T04:00:30Z'); // just after 23:00, the schedule's off
    const after = (min: number) => NIGHT + min * 60_000;
    const pick = () => t.call('POST', '/api/color', { color: '#ff8800' });
    const state = async () => (await t.call('GET', '/api/state')).json;
    const night = async (s: LightSchedule = NY) => {
      await t.call('PUT', '/api/admin/lights/schedule', s);
      clock = NIGHT;
      await t.schedule.check();
      expect(t.lights.allOff()).toBe(true);
    };

    it("lets a visitor's pick switch the lights on, and switches them off again when nobody uses them", async () => {
      await night();
      expect(await state()).toMatchObject({ lightsOff: true, lightsWake: true, idleOffMinutes: null });
      expect((await pick()).status).toBe(200);
      expect(t.lights.allOff()).toBe(false);
      expect(mocks.every((m) => m.state.on === true)).toBe(true);
      expect(await state()).toMatchObject({ lightsOff: false, lightsWake: false, idleOffMinutes: 15, currentColor: '#ff8800' });

      // Used again after 10 minutes: the 15 start again from there.
      clock = after(10);
      await t.schedule.checkIdle();
      expect((await pick()).status).toBe(200);
      clock = after(24);
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(false);
      clock = after(26);
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(true);
      expect(mocks.every((m) => m.state.on === false)).toBe(true);
      expect(ended).toBe(2);
      // Still the night: the next pick wakes them again.
      expect(await state()).toMatchObject({ lightsOff: true, lightsWake: true });
      expect((await pick()).status).toBe(200);
      expect(t.lights.allOff()).toBe(false);

      // The schedule's on ends the night: on, and no idle minutes.
      clock = at('2026-11-26T22:00:00Z');
      await t.schedule.check();
      expect(await state()).toMatchObject({ lightsOff: false, idleOffMinutes: null });
      clock = at('2026-11-26T23:00:00Z');
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(false);
    });

    it('keeps them on while someone plays, and counts the idle minutes from when they stop', async () => {
      await night();
      await pick();
      busy = true;
      clock = after(40);
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(false);
      busy = false;
      clock = after(54);
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(false);
      clock = after(56);
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(true);
    });

    it('wakes only the lights the schedule switched off', async () => {
      await t.call('PUT', '/api/admin/lights/power', { on: false, deviceId: ids[1] });
      await night();
      await pick();
      expect(t.lights.isOff(ids[0])).toBe(false);
      expect(t.lights.isOff(ids[1])).toBe(true);
    });

    it("leaves them off when visitors may not wake them, or an admin switched them off", async () => {
      await night({ ...NY, wake: false });
      expect((await state()).lightsWake).toBe(false);
      expect((await pick()).status).toBe(409);

      await t.call('PUT', '/api/admin/lights/schedule', NY);
      expect((await state()).lightsWake).toBe(true);
      // The admin's switch holds until the schedule's next time.
      await t.call('PUT', '/api/admin/lights/power', { on: false });
      expect((await state()).lightsWake).toBe(false);
      expect((await pick()).status).toBe(409);
    });

    it("leaves lights an admin switched on alone, until the schedule's next off", async () => {
      await night();
      await t.call('PUT', '/api/admin/lights/power', { on: true });
      clock = after(120);
      await t.schedule.checkIdle();
      expect(t.lights.allOff()).toBe(false);
      expect((await state()).idleOffMinutes).toBeNull();
    });

    it('keeps the idle minutes it is given', async () => {
      expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, idleMinutes: 0 })).status).toBe(400);
      expect((await t.call('PUT', '/api/admin/lights/schedule', { ...NY, idleMinutes: 45 })).json.idleMinutes).toBe(45);
      // Left out (an older page): kept as they are.
      const { wake: _w, idleMinutes: _i, ...old } = NY;
      expect((await t.call('PUT', '/api/admin/lights/schedule', old)).json).toMatchObject({ wake: true, idleMinutes: 45 });
    });
  });
});
