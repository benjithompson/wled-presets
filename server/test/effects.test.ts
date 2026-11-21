import { describe, expect, it } from 'vitest';
import { defaultSettings, deviceKey, effectDirection, keyDevice, EFFECTS, effectObjects, EffectRunner, EffectScene, effectKey, effectsLook, effectTarget, isSpatial, layoutEffects, stageSpace, withEffects, YARD, type EffectSettings } from '../../shared/effects.ts';
import { buildStage, extendLine, fromLedRange, insertPoint, mapSegmentEffects, sampleLayout, segmentLeds, segmentsAfterRemove, type Layout } from '../../shared/layout.ts';
import { GameHost } from '../src/game/host.ts';
import { FramePipeline } from '../src/framePipeline.ts';
import { LightSender } from '../src/lightSender.ts';
import { layoutSchema } from '../src/layoutStore.ts';
import { startMockWled } from '../../scripts/mock-wled.ts';

const rgb = (f: Uint8Array | Float32Array, i: number) => Array.from(f.subarray(i * 3, i * 3 + 3));
const lit = (f: Float32Array, i: number) => f[i * 3] + f[i * 3 + 1] + f[i * 3 + 2] > 0;

describe('effects', () => {
  it('draw finite, non-negative light on strings of any length, at every setting', () => {
    for (const { id } of EFFECTS) {
      for (const n of [1, 2, 7, 300]) {
        for (const k of [0, 1]) {
          const s: EffectSettings = { ...defaultSettings(id), speed: k, intensity: k, size: 1 - k, brightness: 1 };
          const r = new EffectRunner(id, n, 7);
          let peak = 0;
          let bad = 0;
          for (let f = 0; f < 240; f++) {
            const out = r.render(1 / 60, s);
            expect(out.length).toBe(n * 3);
            for (const v of out) {
              if (!Number.isFinite(v) || v < 0) bad++;
              else if (v > peak) peak = v;
            }
          }
          expect(bad, `${id} n=${n}`).toBe(0);
          // Even the slowest storm shows its clouds.
          if (n === 300) expect(peak, `${id} lights something`).toBeGreaterThan(0.1);
        }
      }
    }
  });

  it('scale with brightness, and survive a long pause between frames', () => {
    const r = new EffectRunner('plasma', 50, 1);
    const full = Float32Array.from(r.render(1 / 60, { ...defaultSettings('plasma'), brightness: 1 }));
    const r2 = new EffectRunner('plasma', 50, 1);
    const half = r2.render(1 / 60, { ...defaultSettings('plasma'), brightness: 0.5 });
    expect(half[30]).toBeCloseTo(full[30] * 0.5);
    expect([...r2.render(30, defaultSettings('plasma'))].every(Number.isFinite)).toBe(true);
  });

  it('play the basics with exactly the colors picked', () => {
    const red = [1, 0, 0];
    const own = (id: Parameters<typeof defaultSettings>[0], colors: string[], patch: Partial<EffectSettings> = {}): EffectSettings => ({ ...defaultSettings(id), palette: 'custom', colors, brightness: 1, ...patch });
    // Solid: one color everywhere; several colors split the string in equal parts.
    expect(rgb(new EffectRunner('solid', 10, 1).render(1 / 60, own('solid', ['#ff0000'])), 9)).toEqual(red);
    const split = new EffectRunner('solid', 10, 1).render(1 / 60, own('solid', ['#ff0000', '#0000ff']));
    expect([rgb(split, 4), rgb(split, 5)]).toEqual([red, [0, 0, 1]]);
    // Blocks alternate; a gradient runs from the first color to the last.
    const b = new EffectRunner('blocks', 12, 1).render(1 / 60, own('blocks', ['#ff0000', '#00ff00']));
    expect([rgb(b, 0), rgb(b, 3)]).toEqual([red, [0, 1, 0]]);
    const g = new EffectRunner('gradient', 11, 1).render(1 / 60, own('gradient', ['#ff0000', '#0000ff']));
    expect(rgb(g, 0)).toEqual(red);
    expect(rgb(g, 10).map((v) => +v.toFixed(3))).toEqual([0, 0, 1]);
    // Blink: on, then off; a wipe fills the string from the start.
    const blink = new EffectRunner('blink', 5, 1);
    const s = own('blink', ['#ff0000'], { speed: 0.5, intensity: 0.5 });
    expect(rgb(blink.render(0.1, s), 2)).toEqual(red);
    for (let k = 0; k < 7; k++) blink.render(0.1, s);
    expect(lit(blink.render(0.05, s), 2)).toBe(false);
    const wipe = new EffectRunner('wipe', 100, 1);
    let w = wipe.render(0, own('wipe', ['#ff0000']));
    for (let k = 0; k < 60; k++) w = wipe.render(1 / 30, own('wipe', ['#ff0000']));
    expect(lit(w, 2)).toBe(true);
    expect(lit(w, 95)).toBe(false);
  });

  it('start the basics with their own colors, and say which controls they have', () => {
    expect(defaultSettings('solid')).toMatchObject({ palette: 'custom', colors: ['#ffb46e'] });
    expect(defaultSettings('aurora').colors).toBeUndefined();
    const solid = EFFECTS.find((e) => e.id === 'solid')!;
    expect([solid.speed, solid.intensity, solid.size]).toEqual([false, undefined, undefined]);
    expect(EFFECTS.filter((e) => e.basic).length).toBeGreaterThanOrEqual(12);
    // A dark color of its own still shows on the public page.
    expect(effectsLook([{ ...defaultSettings('solid'), colors: ['#000080'] }])[0].colors).toEqual(['#000080']);
  });

  it('describe a scene for the public page', () => {
    const look = effectsLook([defaultSettings('inferno'), { ...defaultSettings('aurora'), palette: 'custom', colors: ['#ff00ff', '#000000'] }]);
    // The fire palette starts at black: dark colors do not make a scene's swatch.
    expect(look[0].colors).not.toContain('#000000');
    expect(look[1].colors).toEqual(['#ff00ff']);
    expect(look[0].energy).toBeGreaterThan(look[1].energy);
  });
});

describe('effect scenes on the stage', () => {
  // The roof's first segment is off: it only links the lit parts.
  const layout: Layout = sampleLayout();
  layout.fixtures[0] = { ...layout.fixtures[0], skip: [0] };
  const stage = buildStage(layout);
  const roof = stage.fixtures[0];
  const candy: EffectSettings = { ...defaultSettings('candy'), intensity: 0, brightness: 1 };

  it('lights only the objects with an effect, and keeps skipped segments dark', () => {
    const scene = new EffectScene(stage, layout, { roof: candy });
    const out = new Float32Array(stage.pixelCount * 3);
    scene.update(1 / 60, out);
    expect(scene.playing()).toEqual(['roof']);
    // Skipped segment (the start of the roof): dark. The rest of the roof: lit.
    expect(lit(out, roof.offset)).toBe(false);
    expect(lit(out, roof.offset + 200)).toBe(true);
    // Bushes have no effect: dark.
    for (let i = 0; i < stage.fixtures[1].count; i++) expect(lit(out, stage.fixtures[1].offset + i)).toBe(false);
  });

  it('runs backward when reversed', () => {
    const a = new Float32Array(stage.pixelCount * 3);
    const b = new Float32Array(stage.pixelCount * 3);
    const bush = stage.fixtures[2];
    new EffectScene(stage, layout, { 'bush-2': candy }).update(0.5, a);
    new EffectScene(stage, layout, { 'bush-2': { ...candy, reverse: true } }).update(0.5, b);
    for (let i = 0; i < bush.count; i++) expect(rgb(b, bush.offset + i)).toEqual(rgb(a, bush.offset + bush.count - 1 - i));
  });

  it('reads the working copy of effects from the layout, which a saved layout keeps', () => {
    const withFx = { ...layout, fixtures: layout.fixtures.map((f, i) => (i === 1 ? { ...f, effect: defaultSettings('starlight') } : f)) };
    expect(Object.keys(layoutEffects(withFx))).toEqual(['bush-1']);
    const parsed = layoutSchema.safeParse(withFx);
    expect(parsed.success).toBe(true);
    expect(parsed.data?.fixtures[1].effect?.effect).toBe('starlight');
    expect(layoutSchema.safeParse({ ...withFx, fixtures: withFx.fixtures.map((f) => ({ ...f, effect: { ...defaultSettings('aurora'), effect: 'nope' } })) }).success).toBe(false);
  });
});

describe('scenes with effects on the real lights', () => {
  it('stream to the devices that play effects, keep playing with nobody watching, and give the lights back', async () => {
    const mock = await startMockWled(0, 'Roof', 600);
    const device = { id: 'd', name: 'Roof', host: '127.0.0.1', port: mock.port, enabled: true, online: true, info: { leds: { count: 600 }, udpport: mock.port, ddpport: mock.ddpPort() } };
    const layout = sampleLayout();
    layout.fixtures[0] = { ...layout.fixtures[0], deviceId: 'd', ...fromLedRange(536, 87) };
    const pipeline = new FramePipeline(() => [device], new LightSender());
    const host = new GameHost(layout, () => {}, pipeline);
    // The games' debug switch is off: scenes still play.
    host.output.enabled = false;
    try {
      const played = host.playEffects({ roof: { ...defaultSettings('candy'), brightness: 1 }, 'bush-1': defaultSettings('aurora') });
      expect(played).toEqual({ devices: ['d'], objects: 2 });
      await new Promise((r) => setTimeout(r, 250));
      expect(mock.realtime.ddpFrames).toBeGreaterThan(3);
      // Candy cane on the roof: red and white, at full brightness.
      const roofLeds = Array.from({ length: 450 }, (_, i) => rgb(mock.realtime.leds, 87 + i));
      expect(roofLeds.some(([r, g, b]) => r > 200 && g < 60 && b < 60)).toBe(true);
      expect(roofLeds.some(([r, g, b]) => r > 150 && g > 150 && b > 150)).toBe(true);
      // LEDs no object uses stay off.
      expect(rgb(mock.realtime.leds, 40)).toEqual([0, 0, 0]);
      expect(host.output.targets()).toEqual(['Roof']);
      // Stop: the device is told at once to show its own state again.
      host.playEffects(null);
      await new Promise((r) => setTimeout(r, 150));
      expect(mock.requests.at(-1)).toMatchObject({ method: 'POST', url: '/json/state', body: { lor: 1 } });
      expect(host.playingEffects).toBe(false);
    } finally {
      host.stop();
      pipeline.close();
      await mock.close();
    }
  });

  it('leaves devices that play a preset alone', () => {
    const layout = sampleLayout();
    layout.fixtures[0] = { ...layout.fixtures[0], deviceId: 'roof-device' };
    layout.fixtures[1] = { ...layout.fixtures[1], deviceId: 'bush-device', startPixel: 0 };
    const host = new GameHost(layout, () => {});
    try {
      expect(host.playEffects({ 'bush-1': defaultSettings('starlight'), gone: defaultSettings('aurora') })).toEqual({ devices: ['bush-device'], objects: 1 });
    } finally {
      host.stop();
    }
  });
});

describe('effects on one segment of a line', () => {
  const layout: Layout = sampleLayout();
  const stage = buildStage(layout);
  const roof = stage.fixtures[0];
  const f = layout.fixtures[0];
  const red: EffectSettings = { ...defaultSettings('candy'), palette: 'custom', colors: ['#ff0000'], intensity: 0, brightness: 1 };
  const blue: EffectSettings = { ...red, colors: ['#0000ff'] };

  it('plays on that segment only; the line’s effect fills the rest', () => {
    const out = new Float32Array(stage.pixelCount * 3);
    const scene = new EffectScene(stage, layout, { roof: blue, [effectKey('roof', 1)]: red });
    scene.update(1 / 60, out);
    const { lo, hi } = segmentLeds(f, 1);
    for (let i = 0; i < roof.count; i++) {
      const [r, , b] = rgb(out, roof.offset + i);
      if (i >= lo && i <= hi) expect([r > 0.5, b]).toEqual([true, 0]);
      else expect([r, b > 0.5]).toEqual([0, true]);
    }
    expect(scene.playing().sort()).toEqual(['roof', 'roof#1']);
    expect(scene.objects()).toEqual(['roof']);
  });

  it('lights only the segment when the line has no effect of its own, and nothing on an off segment', () => {
    const out = new Float32Array(stage.pixelCount * 3);
    new EffectScene(stage, layout, { [effectKey('roof', 2)]: red }).update(1 / 60, out);
    const { lo, hi } = segmentLeds(f, 2);
    expect(lit(out, roof.offset + lo)).toBe(true);
    expect(lit(out, roof.offset + hi)).toBe(true);
    expect(lit(out, roof.offset + lo - 1)).toBe(false);
    expect(lit(out, roof.offset + hi + 1)).toBe(false);
    const off: Layout = { ...layout, fixtures: [{ ...f, skip: [2] }, ...layout.fixtures.slice(1)] };
    const out2 = new Float32Array(stage.pixelCount * 3);
    new EffectScene(buildStage(off), off, { [effectKey('roof', 2)]: red }).update(1 / 60, out2);
    expect(out2.every((v) => v === 0)).toBe(true);
  });

  it('keeps segment effects in the layout and in scenes, under "<object>#<segment>"', () => {
    const withSeg = { ...layout, fixtures: [{ ...f, effect: blue, segmentEffects: { '3': red } }, ...layout.fixtures.slice(1)] };
    expect(layoutEffects(withSeg)).toEqual({ roof: blue, 'roof#3': red });
    expect(effectTarget('roof#3')).toEqual({ id: 'roof', segment: 3 });
    expect(effectTarget('roof')).toEqual({ id: 'roof', segment: null });
    expect(layoutSchema.safeParse(withSeg).success).toBe(true);
    // Loading a scene back into the editor puts each effect on its object or segment.
    const loaded = withEffects(f, { 'roof#0': red, 'roof#9': red, 'bush-1': blue });
    expect(loaded.effect).toBeUndefined();
    expect(loaded.segmentEffects).toEqual({ '0': red });
    expect(withEffects({ ...f, segmentEffects: { '1': red } }, {}).segmentEffects).toBeUndefined();
  });

  it('stay with their segment when points are added or removed', () => {
    const g = { ...f, segmentEffects: { '1': red, '3': blue } };
    // A point inside segment 1: both halves keep its effect; later segments move up.
    expect(insertPoint(g, 1, { x: 400, y: 470 }).segmentEffects).toEqual({ '1': red, '2': red, '4': blue });
    // Removing point 2 joins segments 1 and 2.
    expect(mapSegmentEffects(g.segmentEffects, segmentsAfterRemove(2))).toEqual({ '1': red, '2': blue });
    // Continuing from the first point adds segments in front.
    expect(extendLine(g, 'first', [{ x: 100, y: 470 }]).patch.segmentEffects).toEqual({ '2': red, '4': blue });
  });

  it('send a segment’s effect to the device of its line', () => {
    const l = sampleLayout();
    l.fixtures[0] = { ...l.fixtures[0], deviceId: 'roof-device' };
    const host = new GameHost(l, () => {});
    try {
      expect(host.playEffects({ 'roof#2': defaultSettings('fireworks') })).toEqual({ devices: ['roof-device'], objects: 1 });
    } finally {
      host.stop();
    }
  });
});

describe('3-D effects and the whole yard', () => {
  const layout: Layout = sampleLayout();
  const stage = buildStage(layout);
  const wash: EffectSettings = { ...defaultSettings('wash'), intensity: 0, brightness: 1 };

  it('play on the whole yard as one picture, where objects have no effect of their own', () => {
    const out = new Float32Array(stage.pixelCount * 3);
    const red: EffectSettings = { ...defaultSettings('candy'), palette: 'custom', colors: ['#ff0000'], intensity: 0, brightness: 1 };
    const scene = new EffectScene(stage, layout, { [YARD]: wash, 'bush-2': red });
    scene.update(1 / 60, out);
    expect(scene.objects().sort()).toEqual(['bush-1', 'bush-2', 'bush-3', 'roof']);
    expect(scene.playing().sort()).toEqual([YARD, 'bush-2']);
    // Every LED is lit; the middle bush plays its own effect.
    for (let i = 0; i < stage.pixelCount; i++) expect(lit(out, i)).toBe(true);
    const b2 = stage.fixtures[2];
    expect(rgb(out, b2.offset)[1]).toBe(0);
    // One picture: the left and the right bush show different colors of the wash.
    const left = rgb(out, stage.fixtures[1].offset);
    const right = rgb(out, stage.fixtures[3].offset);
    expect(left).not.toEqual(right);
  });

  it('light the whole yard with every 3-D effect, finite and never negative', () => {
    const out = new Float32Array(stage.pixelCount * 3);
    for (const { id } of EFFECTS.filter((e) => e.space === '3d')) {
      for (const k of [0, 1]) {
        const s: EffectSettings = { ...defaultSettings(id), intensity: k, size: 1 - k, reverse: k === 1, brightness: 1 };
        const scene = new EffectScene(stage, layout, { [YARD]: s });
        let peak = 0;
        let bad = 0;
        // 14 seconds: long enough for the shows that run in cycles (a jump, a supernova, a new shape).
        for (let f = 0; f < 14 * 30; f++) {
          scene.update(1 / 30, out);
          for (const v of out) {
            if (!Number.isFinite(v) || v < 0) bad++;
            else if (v > peak) peak = v;
          }
        }
        expect(bad, `${id} k=${k}`).toBe(0);
        expect(peak, `${id} k=${k} lights the yard`).toBeGreaterThan(0.3);
      }
    }
  });

  it('play a 1-D effect on the yard along every object’s own string', () => {
    const scene = new EffectScene(stage, layout, { [YARD]: defaultSettings('candy') });
    expect(scene.playing()).toEqual([YARD]);
    expect(scene.objects().length).toBe(4);
    expect(effectObjects(layout, [YARD]).length).toBe(4);
    expect(effectObjects(layout, ['roof#1', 'gone'])).toEqual(['roof']);
  });

  it('fill each object in its own space, and follow the direction', () => {
    const bush = stage.fixtures[1];
    const up: EffectSettings = { ...wash, direction: 'up' };
    const out = new Float32Array(stage.pixelCount * 3);
    new EffectScene(stage, layout, { 'bush-1': up }).update(0, out);
    // The wash runs up: LEDs at the same height show the same color, other heights differ.
    const ys = Array.from({ length: bush.count }, (_, i) => stage.positions3[(bush.offset + i) * 3 + 1]);
    const top = ys.indexOf(Math.min(...ys));
    const bottom = ys.indexOf(Math.max(...ys));
    expect(rgb(out, bush.offset + top)).not.toEqual(rgb(out, bush.offset + bottom));
    const sp = stageSpace(stage, Array.from({ length: bush.count }, (_, i) => bush.offset + i));
    expect(Math.max(sp.ex, sp.ey, sp.ez)).toBeCloseTo(1);
    expect(sp.pitch).toBeGreaterThan(0);
  });

  it('keep running when an object moves', () => {
    const scene = new EffectScene(stage, layout, { 'bush-1': defaultSettings('fireflies') });
    const out = new Float32Array(stage.pixelCount * 3);
    for (let f = 0; f < 30; f++) scene.update(1 / 60, out);
    const moved = { ...layout, fixtures: layout.fixtures.map((f) => (f.id === 'bush-1' ? { ...f, points: [{ x: 420, y: 760, z: 80 }] } : f)) };
    scene.setStage(buildStage(moved), moved);
    scene.update(1 / 60, out);
    expect(scene.playing()).toEqual(['bush-1']);
  });

  it('keep the yard effect in the layout and validate it', () => {
    const withYard = { ...layout, effect: wash };
    expect(layoutEffects(withYard)[YARD]).toEqual(wash);
    const kept = layoutSchema.safeParse(withYard);
    expect(kept.success && kept.data.effect).toEqual(wash);
    // The direction is saved (it used to be dropped).
    const up = layoutSchema.safeParse({ ...layout, effect: { ...wash, direction: 'up' } });
    expect(up.success && up.data.effect?.direction).toBe('up');
    expect(layoutSchema.safeParse({ ...layout, effect: { ...wash, direction: 'sideways' } }).success).toBe(false);
    expect(effectDirection({ effect: 'wash', direction: 'in' })).toBe('in');
    expect(effectDirection({ effect: 'wash', direction: undefined })).toBe('right');
    expect(effectDirection({ effect: 'scanner', direction: 'left' })).toBe('right');
    expect(isSpatial('nebula')).toBe(true);
    expect(isSpatial('aurora')).toBe(false);
  });
});

describe('effects on a whole device', () => {
  const base: Layout = sampleLayout();
  // The roof is on device A, the first bush on device B, the rest on no device.
  const layout: Layout = { ...base, fixtures: base.fixtures.map((f, i) => ({ ...f, deviceId: i === 0 ? 'A' : i === 1 ? 'B' : null })) };
  const stage = buildStage(layout);
  const red: EffectSettings = { ...defaultSettings('solid'), palette: 'custom', colors: ['#ff0000'], brightness: 1 };
  const blue: EffectSettings = { ...red, colors: ['#0000ff'] };

  it('plays on every object of that device, under the object’s own effect and over the yard’s', () => {
    expect(effectObjects(layout, [deviceKey('A')])).toEqual([layout.fixtures[0].id]);
    const out = new Float32Array(stage.pixelCount * 3);
    const scene = new EffectScene(stage, layout, { [YARD]: blue, [deviceKey('A')]: red });
    scene.update(0.1, out);
    const [roof, bush, other] = stage.fixtures;
    expect(rgb(out, roof.offset + 5)[0]).toBeGreaterThan(0.5);
    expect(rgb(out, bush.offset)[2]).toBeGreaterThan(0.5);
    expect(rgb(out, other.offset)[2]).toBeGreaterThan(0.5);
    // An object's own effect still wins over its device's.
    const own = new Float32Array(stage.pixelCount * 3);
    new EffectScene(stage, layout, { [deviceKey('A')]: red, [layout.fixtures[0].id]: blue }).update(0.1, own);
    expect(rgb(own, roof.offset + 5)[2]).toBeGreaterThan(0.5);
    expect(keyDevice(deviceKey('A'))).toBe('A');
    expect(keyDevice('roof')).toBeNull();
  });
});
