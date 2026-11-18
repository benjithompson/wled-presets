import { describe, expect, it } from 'vitest';
import { fromLedRange, matchPoint, matchRange, pointOffsets, sampleLayout, type Fixture, type Layout } from '../../shared/layout.ts';
import { previewFrame } from '../src/layoutPreview.ts';
import { RealtimeOut } from '../src/realtime.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';

const rgb = (f: Uint8Array, i: number) => Array.from(f.subarray(i * 3, i * 3 + 3));

// Roof uses LEDs 87–536, counting down along the drawn line; LEDs 0–86 are a hidden side.
const layout = sampleLayout();
layout.fixtures[0] = { ...layout.fixtures[0], deviceId: 'd', ...fromLedRange(536, 87) };

describe('layout preview on the lights', () => {

  it('marks the first LED green and the last LED red, and leaves the gap off', () => {
    const f = previewFrame({ layout, selected: layout.fixtures[0].id, corner: null }, 'd', 600, true);
    expect(f.length).toBe(600 * 3);
    expect(rgb(f, 536)).toEqual([0, 255, 0]);
    expect(rgb(f, 87)).toEqual([255, 0, 0]);
    expect(rgb(f, 40)).toEqual([0, 0, 0]);
    expect(rgb(f, 560)).toEqual([0, 0, 0]);
    expect(Math.max(...rgb(f, 300))).toBeGreaterThan(0);
  });

  it('sends DNRGB packets that a device decodes', async () => {
    const mock = await startMockWled(0, 'Roof', 600);
    const out = new RealtimeOut();
    const f = previewFrame({ layout, selected: layout.fixtures[0].id, corner: null }, 'd', 600, true);
    out.send('127.0.0.1', mock.port, f, 2);
    await new Promise((r) => setTimeout(r, 150));
    // 600 LEDs need two packets (489 + 111).
    expect(mock.realtime.packets).toBe(2);
    expect(rgb(mock.realtime.leds, 536)).toEqual([0, 255, 0]);
    expect(rgb(mock.realtime.leds, 87)).toEqual([255, 0, 0]);
    out.close();
    await mock.close();
  });
});

describe('matching a drawn line to the real lights', () => {
  // A rough roof drawn in four segments, a string of 50 LEDs from device LED 5.
  const line = (patch: Partial<Fixture> = {}): Fixture => ({
    id: 'r',
    name: 'Roof',
    kind: 'roof',
    points: [
      { x: 0, y: 300 },
      { x: 200, y: 100 },
      { x: 400, y: 300 },
      { x: 600, y: 100 },
      { x: 800, y: 300 }
    ],
    pixels: 50,
    deviceId: 'd',
    startPixel: 5,
    reversed: false,
    ...patch
  });
  const step = (f: Fixture, point: number, offset: number) => ({ ...f, ...matchPoint(f, point, offset) });

  it('walks the start, each corner and the end, and the line takes those LEDs', () => {
    let f = line();
    expect(pointOffsets(f)).toEqual([0, 12, 25, 37, 49]);
    f = step(f, 0, -2); // the string really starts two LEDs earlier
    expect(f).toMatchObject({ startPixel: 3, pixels: 52 });
    f = step(f, 1, 9);
    f = step(f, 2, 30);
    f = step(f, 3, 33);
    f = step(f, 4, 47); // and ends sooner
    expect(f).toMatchObject({ startPixel: 3, pixels: 48, reversed: false });
    expect(pointOffsets(f)).toEqual([0, 9, 30, 33, 47]);
  });

  it('keeps device LED numbers on a string that counts down', () => {
    let f = line({ reversed: true });
    const atCorner = (g: Fixture, i: number) => g.startPixel + g.pixels - 1 - pointOffsets(g)[i];
    f = step(f, 1, 10);
    expect(atCorner(f, 1)).toBe(44);
    f = step(f, 4, 52); // three more LEDs at the end, down to device LED 2
    expect(f).toMatchObject({ startPixel: 2, pixels: 53, reversed: true });
    expect(atCorner(f, 1)).toBe(44);
  });

  it('keeps the points in order, and unpins later corners a new pin passes', () => {
    let f = step(line(), 3, 40);
    f = step(f, 2, 20);
    expect(pointOffsets(f)).toEqual([0, 10, 20, 40, 49]);
    // Corner 1 is really past corner 2 and 3 as drawn: they give way, to be matched next.
    f = step(f, 1, 45);
    expect(pointOffsets(f)[1]).toBe(45);
    expect(f.pointLeds?.[2] ?? null).toBeNull();
    expect(f.pointLeds?.[3] ?? null).toBeNull();
    // A corner leaves one LED for each segment after it, and stays after the point before.
    expect(matchRange(f, 1)).toEqual({ lo: 1, hi: 46 });
    expect(matchRange(f, 2)).toEqual({ lo: 46, hi: 47 });
    // The start never goes below device LED 0.
    expect(matchRange(line(), 0).lo).toBe(-5);
    expect(matchRange(line({ reversed: true }), 4).hi).toBe(54);
  });

  it('stays within the LEDs the device has in WLED', () => {
    // 60 LEDs in WLED (0–59): the line from LED 5 can end at 59 at most, that is offset 54.
    // With no corner pinned yet, the end can come back to one LED for each segment.
    expect(matchRange(line(), 4, 60)).toEqual({ lo: 4, hi: 54 });
    expect({ ...line(), ...matchPoint(line(), 4, 80, 60) }).toMatchObject({ startPixel: 5, pixels: 55 });
    // Counting down from LED 54 to 5: the start can go up to LED 59, that is offset -5.
    expect(matchRange(line({ reversed: true }), 0, 60).lo).toBe(-5);
    expect({ ...line({ reversed: true }), ...matchPoint(line({ reversed: true }), 0, -20, 60) }).toMatchObject({ startPixel: 5, pixels: 55, reversed: true });
    // Not known yet: no limit but the line's own.
    expect(matchRange(line(), 4, null).hi).toBe(1999);
  });

  it('blinks the LED on the device, also past the end of the line', () => {
    const f = line();
    const lay: Layout = { width: 1600, height: 900, background: null, fixtures: [f] };
    const req = (offset: number) => ({ layout: lay, selected: 'r', corner: 1, probe: { point: 1, offset } });
    const on = previewFrame(req(20), 'd', 50, true);
    expect(rgb(on, 25)).toEqual([255, 0, 0]);
    expect(rgb(previewFrame(req(20), 'd', 50, false), 25)).toEqual([0, 0, 0]);
    // From the start up to the blinking LED is brighter than the rest, so it can be followed.
    expect(rgb(on, 15)[2]).toBeGreaterThan(rgb(on, 40)[2]);
    expect(Math.max(...rgb(on, 40))).toBeGreaterThan(0);
    const past = previewFrame({ ...req(55), corner: 4, probe: { point: 4, offset: 55 } }, 'd', 50, true);
    expect(past.length).toBe(61 * 3);
    expect(rgb(past, 60)).toEqual([255, 0, 0]);
  });
});

describe('debug mode: games on the real lights', () => {
  it('maps stage LEDs to device LEDs, scales brightness, and leaves gaps off', async () => {
    const { LightsOutput } = await import('../src/game/output.ts');
    const { buildStage } = await import('../../shared/layout.ts');
    const mock = await startMockWled(0, 'Roof', 600);
    const device = { id: 'd', name: 'Roof', host: '127.0.0.1', port: mock.port, enabled: true, info: { leds: { count: 600 }, udpport: mock.port, ddpport: mock.ddpPort() } };
    let paused = false;
    const out = new LightsOutput(() => [device], () => paused);
    const stage = buildStage(layout);
    out.setStage(layout, stage);
    const frame = new Uint8Array(stage.pixelCount * 3).fill(200);
    out.enabled = false;
    out.push(frame); // off: nothing is sent
    out.enabled = true;
    out.push(frame, false); // no game running: nothing is sent
    expect(out.info().framesSent).toBe(0);
    out.brightness = 0.5;
    paused = true;
    out.push(frame); // paused by the layout preview: nothing is sent
    expect(out.info().framesSent).toBe(0);
    paused = false;
    out.push(frame);
    await new Promise((r) => setTimeout(r, 150));
    expect(out.info()).toMatchObject({ framesSent: 1, devices: [{ name: 'Roof', mappedLeds: 450 }], simulationOnly: ['Left bush', 'Middle bush', 'Right bush'] });
    expect(rgb(mock.realtime.leds, 300)).toEqual([100, 100, 100]);
    expect(rgb(mock.realtime.leds, 40)).toEqual([0, 0, 0]);
    expect(out.targets()).toEqual(['Roof']);
    // The game ends: the device is told at once to show its own state again.
    out.push(frame, false);
    await new Promise((r) => setTimeout(r, 150));
    expect(mock.requests.at(-1)).toMatchObject({ method: 'POST', url: '/json/state', body: { lor: 1 } });
    expect(out.targets()).toEqual([]);
    // A new game undoes that first, so the device shows the stream again.
    out.push(frame);
    await new Promise((r) => setTimeout(r, 150));
    expect(mock.requests.at(-1)).toMatchObject({ body: { lor: 0 } });
    out.close();
    await mock.close();
  });
});

describe('sending to devices', () => {
  it('falls back to HTTP when real-time UDP does not reach the device, and gives the device back after', async () => {
    const { LightSender } = await import('../src/lightSender.ts');
    const mock = await startMockWled(0, 'Roof', 600, { dropUdp: true });
    const logs: string[] = [];
    const sender = new LightSender((_, m) => logs.push(m));
    const device = { id: 'd', name: 'Roof', host: '127.0.0.1', port: mock.port, enabled: true, info: { leds: { count: 600 }, udpport: mock.port, ddpport: mock.ddpPort() } };
    const frame = previewFrame({ layout, selected: layout.fixtures[0].id, corner: null }, 'd', 600, true);
    const until = Date.now() + 1600;
    while (Date.now() < until) {
      sender.send(device, frame);
      await new Promise((r) => setTimeout(r, 33));
    }
    expect(sender.status('d')?.mode).toBe('http');
    expect(logs[0]).toMatch(/UDP did not reach "Roof"/);
    expect(mock.realtime.httpFrames).toBeGreaterThan(0);
    expect(rgb(mock.realtime.leds, 536)).toEqual([0, 255, 0]);
    // After the frames stop, the effect is unfrozen.
    await new Promise((r) => setTimeout(r, 2800));
    expect(mock.requests.at(-1)?.body).toMatchObject({ seg: { id: 0, frz: false } });
    expect(sender.status('d')).toBeNull();
    sender.close();
    await mock.close();
  }, 10_000);

  it('keeps UDP when the device confirms it shows real-time data', async () => {
    const { LightSender } = await import('../src/lightSender.ts');
    const mock = await startMockWled(0, 'Roof', 600);
    const sender = new LightSender();
    const device = { id: 'd', name: 'Roof', host: '127.0.0.1', port: mock.port, enabled: true, info: { leds: { count: 600 }, udpport: mock.port, ddpport: mock.ddpPort() } };
    const frame = new Uint8Array(600 * 3).fill(9);
    const until = Date.now() + 1200;
    while (Date.now() < until) {
      sender.send(device, frame);
      await new Promise((r) => setTimeout(r, 33));
    }
    expect(sender.status('d')?.mode).toBe('udp');
    expect(mock.realtime.httpFrames).toBe(0);
    sender.close();
    await mock.close();
  });
});

describe('DDP', () => {
  it('sends a long strip in several packets and shows it only when the whole frame is there', async () => {
    const mock = await startMockWled(0, 'Long', 1000);
    await new Promise((r) => setTimeout(r, 50));
    const out = new RealtimeOut();
    const frame = new Uint8Array(1000 * 3);
    for (let i = 0; i < 1000; i++) frame.set([i % 256, 7, 200], i * 3);
    out.sendDdp('127.0.0.1', mock.ddpPort(), frame);
    await new Promise((r) => setTimeout(r, 150));
    // 1000 LEDs = 3000 bytes = 3 packets (1440 + 1440 + 120); one frame shown.
    expect(mock.realtime.ddpPackets).toBe(3);
    expect(mock.realtime.ddpFrames).toBe(1);
    expect(rgb(mock.realtime.leds, 999)).toEqual([999 % 256, 7, 200]);
    expect(rgb(mock.realtime.leds, 480)).toEqual([480 % 256, 7, 200]);
    out.close();
    await mock.close();
  });
});

describe('black level for real LEDs', () => {
  it('turns pixels too dim for real LEDs off, and drops tiny channels', async () => {
    const { blackLevel } = await import('../src/lightSender.ts');
    // (7,4,2) is the game's faint roof glow at 50%: real LEDs show it as scattered dots.
    expect(Array.from(blackLevel(Uint8Array.from([7, 4, 2, 11, 25, 12, 40, 20, 2])))).toEqual([0, 0, 0, 11, 25, 12, 40, 20, 0]);
  });
});

describe('the sequence editor on the lights', () => {
  it('plays a sequence from the editor’s time, holds a paused moment, and gives the device back', async () => {
    const { LayoutPreview } = await import('../src/layoutPreview.ts');
    const { LightSender } = await import('../src/lightSender.ts');
    const { emptySequence } = await import('../../shared/sequence.ts');
    const mock = await startMockWled(0, 'Roof', 600);
    const device = { id: 'd', name: 'Roof', host: '127.0.0.1', port: mock.port, enabled: true, info: { leds: { count: 600 }, udpport: mock.port, ddpport: mock.ddpPort() } };
    const sender = new LightSender();
    const logs: string[] = [];
    const preview = new LayoutPreview(() => [device], (m) => logs.push(m), sender);
    const seq = emptySequence('Show');
    // Red on the roof from 2 s to 6 s.
    seq.tracks[1].clips.push({ id: 'c', start: 2, duration: 4, targets: ['roof'], effect: { effect: 'candy', palette: 'custom', colors: ['#ff0000'], speed: 0.5, intensity: 0, size: 0.5, brightness: 1 } });
    try {
      expect(preview.showSequence({ sequence: seq, time: 1, playing: false }, layout)).toEqual(['Roof']);
      await new Promise((r) => setTimeout(r, 150));
      expect(rgb(mock.realtime.leds, 300)).toEqual([0, 0, 0]);
      preview.showSequence({ sequence: seq, time: 3, playing: true }, layout);
      await new Promise((r) => setTimeout(r, 200));
      const [r, g, b] = rgb(mock.realtime.leds, 300);
      expect(r).toBeGreaterThan(100);
      expect(g + b).toBe(0);
      expect(preview.active).toBe(true);
      preview.stop();
      await new Promise((r) => setTimeout(r, 100));
      expect(mock.requests.at(-1)).toMatchObject({ method: 'POST', url: '/json/state', body: { lor: 1 } });
      expect(logs.some((l) => l.includes('Editor preview on the lights started'))).toBe(true);
    } finally {
      preview.close();
      sender.close();
      await mock.close();
    }
  });
});
