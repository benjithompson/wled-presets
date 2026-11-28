import { describe, expect, it } from 'vitest';
import { defaultSettings, deviceKey, effectDirection, keyDevice, EFFECTS, effectObjects, EffectRunner, EffectScene, effectKey, effectsLook, effectTarget, effectView, hasView, isSpatial, layoutEffects, stageSpace, withEffects, YARD, type EffectSettings, type Space } from '../../shared/effects.ts';
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
        const s: EffectSettings = { ...defaultSettings(id), intensity: k, size: 1 - k, reverse: k === 1, view: k === 1 ? 'top' : undefined, brightness: 1 };
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

  it('lay a 3-D picture flat over the yard when seen from above', () => {
    // A ring of lights on the ground, around the middle of the lawn.
    const n = 64;
    const x = new Float32Array(n);
    const z = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      x[i] = 0.5 * Math.cos((i / n) * Math.PI * 2);
      z[i] = 0.5 * Math.sin((i / n) * Math.PI * 2);
    }
    const ground: Space = { x, y: new Float32Array(n), z, ex: 1, ey: 0, ez: 1, pitch: 0.05 };
    // The same ring standing up, facing the street, with the house at the top.
    const upright: Space = { x, y: z.map((v) => -v), z: new Float32Array(n), ex: 1, ey: 1, ez: 0, pitch: 0.05 };
    const s: EffectSettings = { ...defaultSettings('kaleidoscope'), brightness: 1 };
    const play = (sp: Space, v: EffectSettings) => {
      const r = new EffectRunner('kaleidoscope', n, 3, sp);
      for (let f = 0; f < 20; f++) r.render(1 / 60, v);
      return Array.from(r.render(1 / 60, v));
    };
    const above = play(ground, { ...s, view: 'top' });
    // From above, the ground ring shows what the upright ring shows from the street.
    expect(above).toEqual(play(upright, s));
    expect(above).not.toEqual(play(ground, s));
    // Effects whose directions already go every way, and 1-D ones, have no view.
    expect([hasView('kaleidoscope'), hasView('vortex'), hasView('wash'), hasView('shockwave'), hasView('aurora')]).toEqual([true, true, false, false, false]);
    expect(effectView({ effect: 'wash', view: 'top' })).toBe('front');
    expect(effectView({ effect: 'vortex', view: undefined })).toBe('front');
    // The view is saved, and only these two.
    const saved = layoutSchema.safeParse({ ...layout, effect: { ...s, view: 'top' } });
    expect(saved.success && saved.data.effect?.view).toBe('top');
    expect(layoutSchema.safeParse({ ...layout, effect: { ...s, view: 'side' } }).success).toBe(false);
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

describe('3-D effects that know the yard’s objects', () => {
  const layout = sampleLayout();
  const stage = buildStage(layout);
  const all = Array.from({ length: stage.pixelCount }, (_, i) => i);
  /** For each object of the sample yard, the stage LEDs it has. */
  const objects = stage.fixtures.map((f) => Array.from({ length: f.count }, (_, i) => f.offset + i));
  const play = (effect: Parameters<typeof defaultSettings>[0], seconds: number, each: (out: Float32Array, t: number) => void, patch: Partial<EffectSettings> = {}) => {
    const scene = new EffectScene(stage, layout, { [YARD]: { ...defaultSettings(effect), brightness: 1, ...patch } });
    const out = new Float32Array(stage.pixelCount * 3);
    for (let f = 1; f <= seconds * 30; f++) {
      scene.update(1 / 30, out);
      each(out, f / 30);
    }
  };
  const sum = (out: Float32Array, i: number) => out[i * 3] + out[i * 3 + 1] + out[i * 3 + 2];

  it('know which object each LED is on, and what kind it is', () => {
    const sp = stageSpace(stage, all);
    expect(sp.kinds).toEqual(['roof', 'bush', 'bush', 'bush']);
    expect(sp.part![0]).toBe(0);
    expect(sp.part![objects[2][5]]).toBe(2);
    // A space of some objects only numbers the ones it has.
    const two = stageSpace(stage, [...objects[3], ...objects[1]]);
    expect(two.kinds).toEqual(['bush', 'bush']);
    expect([two.part![0], two.part![objects[3].length]]).toEqual([0, 1]);
  });

  it('synapses: sparks spread through every object and jump between them', () => {
    // A spark's head is white: each object fires (all its colors high at once) at least once.
    const fired = new Set<number>();
    play('synapse', 20, (out) => {
      objects.forEach((leds, o) => {
        if (leds.some((i) => Math.min(out[i * 3], out[i * 3 + 1], out[i * 3 + 2]) > 0.6)) fired.add(o);
      });
    });
    expect(fired.size).toBe(objects.length);
  });

  it('murmuration: the flock flies over the yard from object to object', () => {
    const visited = new Set<number>();
    play('murmuration', 30, (out) => {
      objects.forEach((leds, o) => {
        if (leds.filter((i) => sum(out, i) > 0.9).length >= 3) visited.add(o);
      });
    });
    expect(visited.size).toBeGreaterThanOrEqual(3);
  });

  it('paint fight: paint covers the yard, then rain washes it off', () => {
    let most = 0;
    let after = 1;
    play('paint', 60, (out) => {
      const painted = all.filter((i) => sum(out, i) > 0.25).length / all.length;
      if (painted > most) most = painted;
      else if (most > 0.6) after = Math.min(after, painted);
    }, { intensity: 1 });
    expect(most).toBeGreaterThan(0.6);
    expect(after).toBeLessThan(0.2);
  });

  it('ripple tank: rings spread from where the drops land', () => {
    // From still water, the light moves: an LED goes from crest to trough and back.
    let lo = Infinity;
    let hi = 0;
    play('ripples', 6, (out, t) => {
      if (t < 1) return;
      const v = sum(out, objects[0][200]);
      lo = Math.min(lo, v);
      hi = Math.max(hi, v);
    });
    expect(hi - lo).toBeGreaterThan(0.3);
  });

  it('colored shadows: an object between a lamp and the wall throws a shadow on it', () => {
    // A wall facing the street, and a bush in front of it.
    const xs: number[] = [];
    const ys: number[] = [];
    const zs: number[] = [];
    const part: number[] = [];
    for (let a = 0; a < 40; a++)
      for (let b = 0; b < 16; b++) {
        xs.push(-0.5 + a / 39);
        ys.push(-0.25 + (b / 15) * 0.5);
        zs.push(-0.25);
        part.push(0);
      }
    for (let k = 0; k < 120; k++) {
      // Points spread over a ball.
      const y = 1 - (2 * (k + 0.5)) / 120;
      const r = Math.sqrt(1 - y * y);
      const a = k * 2.39996;
      xs.push(0.09 * r * Math.cos(a));
      ys.push(-0.1 + 0.09 * y);
      zs.push(0.05 + 0.09 * r * Math.sin(a));
      part.push(1);
    }
    const n = xs.length;
    const space = (kinds: Space['kinds']): Space => ({ x: Float32Array.from(xs), y: Float32Array.from(ys), z: Float32Array.from(zs), ex: 1, ey: 0.5, ez: 0.39, pitch: 0.03, part: Int32Array.from(part), kinds });
    const wallLight = (kinds: Space['kinds']) => {
      const r = new EffectRunner('shadows', n, 5, space(kinds));
      const s = { ...defaultSettings('shadows'), brightness: 1 };
      const frames: number[][] = [];
      for (let f = 0; f < 600; f++) {
        const out = r.render(1 / 30, s);
        frames.push(Array.from({ length: 640 }, (_, i) => out[i * 3] + out[i * 3 + 1] + out[i * 3 + 2]));
      }
      return frames;
    };
    // The same lamps on the same paths: with a bush that throws a shadow, and with one that doesn't.
    const shaded = wallLight(['roof', 'bush']);
    const open = wallLight(['roof', 'line']);
    let darker = 0;
    let total = [0, 0];
    shaded.forEach((frame, f) =>
      frame.forEach((v, i) => {
        total = [total[0] + v, total[1] + open[f][i]];
        if (open[f][i] > 0.2 && v < 0.5 * open[f][i]) darker++;
      })
    );
    expect(total[0]).toBeLessThan(total[1]);
    expect(darker).toBeGreaterThan(200);
  });
});

describe('3-D effects that play the yard object by object', () => {
  // The sample yard with two trees, a sunrise and a lamp.
  const layout = sampleLayout();
  const base = { deviceId: null, startPixel: 0, reversed: false };
  layout.fixtures.push(
    { ...base, id: 'tree-l', name: 'Left tree', kind: 'tree', points: [{ x: 110, y: 820, z: 120 }], radius: 60, height: 300, pattern: 'spiral', turns: 8, pixels: 200 },
    { ...base, id: 'tree-r', name: 'Right tree', kind: 'tree', points: [{ x: 1490, y: 820, z: 120 }], radius: 60, height: 300, pattern: 'spiral', turns: 8, pixels: 200 },
    { ...base, id: 'sun', name: 'Sunrise', kind: 'semicircle', points: [{ x: 1000, y: 820, z: 200 }], radius: 110, strands: 8, pixels: 150 },
    { ...base, id: 'lamp', name: 'Lamp', kind: 'bulb', points: [{ x: 640, y: 600, z: 10 }], radius: 20, pixels: 1 }
  );
  const stage = buildStage(layout);
  const objects = stage.fixtures.map((f) => Array.from({ length: f.count }, (_, i) => f.offset + i));
  const play = (effect: Parameters<typeof defaultSettings>[0], seconds: number, each: (out: Float32Array, t: number) => void, patch: Partial<EffectSettings> = {}) => {
    const scene = new EffectScene(stage, layout, { [YARD]: { ...defaultSettings(effect), brightness: 1, ...patch } });
    const out = new Float32Array(stage.pixelCount * 3);
    for (let f = 1; f <= seconds * 30; f++) {
      scene.update(1 / 30, out);
      each(out, f / 30);
    }
  };
  const sum = (out: Float32Array, i: number) => out[i * 3] + out[i * 3 + 1] + out[i * 3 + 2];
  /** How white an LED is: its weakest color. */
  const white = (out: Float32Array, i: number) => Math.min(out[i * 3], out[i * 3 + 1], out[i * 3 + 2]);

  it('carillon: notes strike key after key, low on the left and high on the right', () => {
    // A strike flashes white where it lands.
    const rang = new Set<number>();
    let strikes = 0;
    let was = false;
    play('carillon', 20, (out) => {
      const now = objects.map((leds) => leds.some((i) => white(out, i) > 0.5));
      now.forEach((on, o) => on && rang.add(o));
      const any = now.some(Boolean);
      if (any && !was) strikes++;
      was = any;
    });
    expect(rang.size).toBeGreaterThanOrEqual(5);
    expect(strikes).toBeGreaterThan(20);
    // The same tune, played the other way round, strikes its first note at the other end.
    const first = (reverse: boolean) => {
      const r = new EffectRunner('carillon', 160, 3);
      const out = r.render(1 / 60, { ...defaultSettings('carillon'), intensity: 0, brightness: 1, reverse });
      let at = 0;
      for (let i = 0; i < 160; i++) if (out[i * 3] + out[i * 3 + 1] + out[i * 3 + 2] > out[at * 3] + out[at * 3 + 1] + out[at * 3 + 2]) at = i;
      return at;
    };
    expect(Math.abs(first(false) + first(true) - 159)).toBeLessThan(12);
  });

  it('roller coaster: one train rides through every object, one or two at a time', () => {
    const order: number[] = [];
    let most = 0;
    play('coaster', 60, (out) => {
      // The front car's headlight is white.
      const on = objects.map((leds) => leds.some((i) => white(out, i) > 0.5));
      on.forEach((x, o) => x && !order.includes(o) && order.push(o));
      most = Math.max(most, on.filter(Boolean).length);
    });
    expect(order.length).toBe(objects.length);
    expect(most).toBeLessThanOrEqual(2);
  });

  it('prize wheel: the light spins round every object, stops on one, and its color floods the yard', () => {
    const passed = new Set<number>();
    let flooded = 0;
    play('wheel', 12, (out, t) => {
      if (t < 3) objects.forEach((leds, o) => leds.some((i) => sum(out, i) > 0.9) && passed.add(o));
      let lit = 0;
      for (let i = 0; i < stage.pixelCount; i++) if (sum(out, i) > 0.4) lit++;
      flooded = Math.max(flooded, lit / stage.pixelCount);
    });
    expect(passed.size).toBe(objects.length);
    expect(flooded).toBeGreaterThan(0.6);
  });

  it('clockwork: the drive reaches the objects one after another', () => {
    // Each object flashes white as the drive reaches it.
    const reached = new Map<number, number>();
    play('clockwork', 6, (out, t) => {
      objects.forEach((leds, o) => !reached.has(o) && leds.some((i) => white(out, i) > 0.6) && reached.set(o, t));
    });
    expect(reached.size).toBe(objects.length);
    const times = [...reached.values()].sort((a, b) => a - b);
    expect(new Set(times).size).toBeGreaterThanOrEqual(3);
    expect(times.filter((t) => t === times[0]).length).toBe(1);
  });

  it('talent show: one object performs at a time, each gets its turn, and all perform in the finale', () => {
    const performed = new Set<number>();
    let crowded = 0;
    let finale = 0;
    const acts = objects.length * 5.3;
    play('talent', acts + 5, (out, t) => {
      const on = objects.map((leds) => leds.some((i) => sum(out, i) > 0.4)).map((x, o) => (x ? o : -1)).filter((o) => o >= 0);
      if (t > acts) finale = Math.max(finale, on.length);
      else if (t % 5.3 > 0.05 && t % 5.3 < 4.1) {
        on.forEach((o) => performed.add(o));
        if (on.length > 1) crowded++;
      }
    });
    expect(performed.size).toBe(objects.length);
    expect(crowded).toBe(0);
    expect(finale).toBe(objects.length);
  });
});
