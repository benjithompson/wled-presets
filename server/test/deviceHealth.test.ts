import { afterEach, describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { FrameRateHold } from '../src/frameRateHold.ts';
import { LightSender } from '../src/lightSender.ts';
import { Lights } from '../src/lights.ts';
import { WledPeek } from '../src/wledPeek.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(ok: () => boolean, ms = 3000) {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error('Timed out waiting');
    await wait(20);
  }
}

describe('a device that falls behind', () => {
  it('is held to fewer frames, step by step, and gets them back after a minute of keeping up', () => {
    const hold = new FrameRateHold();
    // Shows a handful of the 30 it is sent: 20.
    expect(hold.checked('w', 'Windows', { ok: true, ms: 120, fps: 9 }, 30, 30)).toMatch(/"Windows" is falling behind \(shows 9 of 30 frames a second\): sending it 20/);
    expect(hold.limit('w')).toBe(20);
    // Still behind at 20, and slow to answer: 15.
    expect(hold.checked('w', 'Windows', { ok: true, ms: 3200, fps: 18 }, 20, 30)).toMatch(/takes 3\.2 s to answer\): sending it 15/);
    // No answer in time: 12.
    expect(hold.checked('w', 'Windows', { ok: false, ms: 3000 }, 15, 30)).toMatch(/no answer in 3\.0 s\): sending it 12/);
    // A quick "no" (switched off at the wall) says nothing about frames.
    expect(hold.checked('w', 'Windows', { ok: false, ms: 40 }, 12, 30)).toBeNull();
    expect(hold.limit('w')).toBe(12);
    // Keeping up: after 6 checks in a row, one step up.
    for (let i = 0; i < 5; i++) expect(hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 11 }, 12, 30)).toBeNull();
    expect(hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 11 }, 12, 30)).toMatch(/keeps up: sending it 15/);
    // A slow check in between starts the count again.
    for (let i = 0; i < 5; i++) hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 15 }, 15, 30);
    hold.checked('w', 'Windows', { ok: true, ms: 1200, fps: 15 }, 15, 30);
    expect(hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 15 }, 15, 30)).toBeNull();
    expect(hold.limit('w')).toBe(15);
    // Up to the admin's limit: free.
    for (let i = 0; i < 5; i++) hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 15 }, 15, 30);
    expect(hold.limit('w')).toBe(20);
    for (let i = 0; i < 5; i++) hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 20 }, 20, 30);
    expect(hold.checked('w', 'Windows', { ok: true, ms: 90, fps: 20 }, 20, 30)).toMatch(/keeps up again/);
    expect(hold.limit('w')).toBe(60);
  });

  it('is not judged by frames while it gets none, and never held below 10', () => {
    const hold = new FrameRateHold();
    expect(hold.checked('w', 'Windows', { ok: true, ms: 5000, fps: 2 }, 0, 60)).toBeNull();
    expect(hold.limit('w')).toBe(60);
    for (const sending of [60, 30, 20, 15, 12, 10, 10]) hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 1 }, sending, 60);
    expect(hold.limit('w')).toBe(10);
  });

  it('steps by even shares of the clock it runs on', () => {
    const hold = new FrameRateHold();
    expect(hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 5 }, 42, 42, 42)).toMatch(/sending it 21 /);
    expect(hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 5 }, 21, 42, 42)).toMatch(/sending it 14 /);
    expect(hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 5 }, 14, 42, 42)).toMatch(/sending it 10.5 /);
    expect(hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 5 }, 10.5, 42, 42)).toBeNull();
    expect(hold.limit('w')).toBe(10.5);
  });

  it('gets fewer frames from the sender, and the link says why', () => {
    const sender = new LightSender();
    sender.maxFps = 30;
    const device = { id: 'w', name: 'Windows', host: '127.0.0.1', port: 1, enabled: true, info: { leds: { count: 150 }, outputs: [{ len: 150, type: 22 }] } };
    expect(sender.rate(device)).toBe(30);
    sender.hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 5 }, 30, 30);
    expect(sender.rate(device)).toBe(20);
    sender.close();
  });

  it('says how many frames a second it sends a device now, and whether it is held', () => {
    const sender = new LightSender();
    sender.maxFps = 30;
    sender.clockHz = 60;
    const device = { id: 'w', name: 'Windows', host: '127.0.0.1', port: 1, enabled: true, info: { leds: { count: 150 }, outputs: [{ len: 150, type: 22 }] } };
    expect(sender.sending(device)).toBeNull();
    sender.send(device, new Uint8Array(450));
    expect(sender.sending(device)).toEqual({ fps: 30, held: false });
    sender.hold.checked('w', 'Windows', { ok: true, ms: 100, fps: 5 }, 30, 30, 60);
    expect(sender.sending(device)).toEqual({ fps: 20, held: true });
    sender.close();
  });
});

describe('status checks of a slow device', () => {
  let close: (() => Promise<void>) | null = null;
  afterEach(async () => {
    await close?.();
    close = null;
  });

  it('give it room: a slow answer sits the next check out, and a quick one ends that', async () => {
    const mock = await startMockWled(0, 'Windows', 150);
    close = mock.close;
    const db = openDatabase(':memory:');
    const lights = new Lights(db, new Bus());
    db.saveDevice({ id: 'w', name: 'Windows', host: '127.0.0.1', port: mock.port, enabled: true });
    const checks: { ok: boolean; ms: number; fps?: number }[] = [];
    lights.onChecked = (_, c) => checks.push(c);
    const asked = () => mock.requests.filter((r) => r.url === '/json/si').length;
    await lights.refreshStatus();
    expect(checks.at(-1)).toMatchObject({ ok: true, fps: 0 });
    mock.behave.answerMs = 2200;
    await lights.refreshStatus();
    expect(checks.at(-1)!.ms).toBeGreaterThan(2000);
    const before = asked();
    // The next check leaves it alone.
    await lights.refreshStatus();
    expect(asked()).toBe(before);
    expect(lights.devicesWithStatus()[0].online).toBe(true);
    // Then it is asked again; quick now, it is checked every time.
    mock.behave.answerMs = 0;
    await lights.refreshStatus();
    expect(asked()).toBe(before + 1);
    await lights.refreshStatus();
    expect(asked()).toBe(before + 2);
  }, 15_000);
});

describe('the connection to a device', () => {
  it('is dropped and made again when the device stops answering pings (it lost power)', async () => {
    const mock = await startMockWled(0, 'Windows', 150);
    const powers: unknown[] = [];
    const peek = new WledPeek({ host: '127.0.0.1', port: mock.port }, () => 150, { live: false, pingMs: 60, onPower: (p) => powers.push(p) });
    try {
      await until(() => peek.connected);
      await wait(200);
      expect(peek.connected).toBe(true);
      mock.behave.deaf = true;
      // Its power is no longer known: the connection closed.
      await until(() => powers.length > 1 && powers.at(-1) === null);
      expect(peek.connected).toBe(false);
    } finally {
      peek.close();
      await mock.close();
    }
  });
});
