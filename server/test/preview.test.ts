import { describe, expect, it } from 'vitest';
import { fromLedRange, sampleLayout } from '../../shared/layout.ts';
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
