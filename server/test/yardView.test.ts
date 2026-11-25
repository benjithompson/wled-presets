import { describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout, type Layout } from '../../shared/layout.ts';
import { layoutOutput } from '../src/framePipeline.ts';
import { ROOF_HZ, RoofView, type Peek } from '../src/roofView.ts';
import type { DeviceTarget } from '../src/lightSender.ts';
import { colorName } from '../../web/src/lib/colorName.ts';

describe('yard view', () => {
  const layout = (): Layout => {
    const l = sampleLayout();
    for (const f of l.fixtures) f.deviceId = f.kind === 'roof' ? 'dev' : null;
    return l;
  };
  const device = { id: 'dev', name: 'Roof', host: '127.0.0.1', port: 1, enabled: true, info: { leds: { count: 2000 } } } as DeviceTarget;
  const fakePeek = (): Peek => ({ leds: null, step: 1, at: 0, on: null, bri: null, setLive() {}, close() {} });

  it('streams every LED of the yard in stage order, with the layout it was built from', () => {
    const l = layout();
    const { stage, maps } = layoutOutput(l);
    const sent = new Uint8Array(6000);
    const sim = new Uint8Array(stage.pixelCount * 3);
    const view = new RoofView({ layout: () => l, devices: () => [device], deviceFrame: () => sent, simFrame: () => sim }, fakePeek, { shape: 'yard' });
    const geometry: { cells: number; layout?: Layout }[] = [];
    const stop = view.watch((e) => e.event === 'geometry' && geometry.push(JSON.parse(e.data)));
    stop?.();
    view.close();
    expect(geometry[0].cells).toBe(stage.pixelCount);
    // The browser builds the same stage from the layout it gets.
    expect(buildStage(geometry[0].layout!).pixelCount).toBe(stage.pixelCount);

    // A roof LED shows what its device is sent; an LED with no device shows the simulator.
    const roofMap = maps.find((m) => m.deviceId === 'dev')!;
    const [stageLed, deviceLed] = [roofMap.pairs[0], roofMap.pairs[1]];
    sent[deviceLed * 3 + 1] = 200;
    const mapped = new Set(Array.from({ length: roofMap.pairs.length / 2 }, (_, k) => roofMap.pairs[k * 2]));
    const free = Array.from({ length: stage.pixelCount }, (_, i) => i).find((i) => !mapped.has(i))!;
    sim[free * 3 + 2] = 150;
    const f = view.frame();
    expect(f.length).toBe(stage.pixelCount * 3);
    expect(f[stageLed * 3 + 1]).toBe(200);
    expect(f[free * 3 + 2]).toBe(150);
  });

  it('keeps to its own viewer limit', () => {
    const l = layout();
    const view = new RoofView({ layout: () => l, devices: () => [], deviceFrame: () => null, simFrame: () => null }, fakePeek, { shape: 'yard', maxViewers: 1 });
    expect(view.watch(() => {})).not.toBeNull();
    expect(view.watch(() => {})).toBeNull();
    view.close();
  });

  it('keeps a group of viewers (the public) to its own limit, and sends each of them every other frame, ending on the last', () => {
    vi.useFakeTimers();
    const l = layout();
    let n = 0;
    let moving = true;
    const view = new RoofView({ layout: () => l, devices: () => [], deviceFrame: () => null, simFrame: () => new Uint8Array(30_000).fill(moving ? ++n : n) }, fakePeek, { shape: 'yard', maxViewers: 10 });
    const pub = { name: 'public', max: 2, every: 2 };
    const frames = { admin: 0, a: 0, b: 0 };
    const last = { admin: '', a: '' };
    view.watch((e) => e.event === 'frame' && (frames.admin++, (last.admin = e.data)));
    expect(view.watch((e) => e.event === 'frame' && (frames.a++, (last.a = e.data)), pub)).not.toBeNull();
    expect(view.watch((e) => e.event === 'frame' && frames.b++, pub)).not.toBeNull();
    expect(view.watch(() => {}, pub)).toBeNull();
    // Others still get in.
    expect(view.watch(() => {})).not.toBeNull();
    vi.advanceTimersByTime((1000 / ROOF_HZ) * 10 + 1);
    expect(frames.admin).toBe(10);
    expect(frames.a).toBe(5);
    // The lights stop changing on a frame the public skipped: they still get it.
    moving = false;
    vi.advanceTimersByTime((1000 / ROOF_HZ) * 3);
    expect(last.a).toBe(last.admin);
    view.close();
    vi.useRealTimers();
  });
});

describe('color names', () => {
  it('names the swatches as the picker does, and never gives a hex', () => {
    expect(colorName('#ffa757')).toBe('Warm white');
    expect(colorName('#FF0000')).toBe('Red');
    expect(colorName('#00e5ff')).toBe('Cyan');
  });

  it('names colors from the hue ring', () => {
    expect(colorName('#00ff80')).toBe('Green');
    expect(colorName('#00ffd5')).toBe('Teal');
    expect(colorName('#ff00ff')).toBe('Magenta');
    expect(colorName('#ff8800')).toBe('Orange');
    expect(colorName('#ffaa00')).toBe('Amber');
    expect(colorName('#ffe600')).toBe('Yellow');
    expect(colorName('#0033ff')).toBe('Blue');
    expect(colorName('#5500ff')).toBe('Indigo');
  });

  it('says how light or deep a color is', () => {
    expect(colorName('#000080')).toBe('Deep blue');
    expect(colorName('#ff9999')).toBe('Pale red');
    expect(colorName('#808080')).toBe('Gray');
    expect(colorName('#000000')).toBe('Off');
  });
});
