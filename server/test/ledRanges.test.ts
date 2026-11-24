import { describe, expect, it } from 'vitest';
import { deviceLed, deviceRuns, fromLedRange, isPinned, ledRange, nextFreeLed, pointOffsets, sampleLayout, setLineEnd, sharedLeds, type Fixture, type Layout } from '../../shared/layout.ts';

// A DigQuad with two outputs as one device: the roof on 0–599 (output 1), a tree on 600–699
// (output 2), and a second tree just drawn: new objects start at LED 0 until they are placed.
function yard(): Layout {
  const base = sampleLayout();
  const roof: Fixture = { ...base.fixtures[0], id: 'roof', name: 'Roofline', deviceId: 'quad', ...fromLedRange(0, 599) };
  const tree: Fixture = { ...base.fixtures[0], id: 'tree', name: 'Tree', kind: 'tree', points: [{ x: 0, y: 0, z: 0 }], deviceId: 'quad', ...fromLedRange(600, 699) };
  const tree2: Fixture = { ...tree, id: 'tree2', name: 'Tree 2', ...fromLedRange(0, 149) };
  return { ...base, fixtures: [roof, tree, tree2] };
}

describe('LEDs shared between objects', () => {
  it('names the objects that use the same LEDs, and which LEDs', () => {
    const l = yard();
    expect(sharedLeds(l, 'tree2')).toEqual([{ fixtureId: 'roof', lo: 0, hi: 149 }]);
    expect(sharedLeds(l, 'tree')).toEqual([]);
  });

  it('ignores objects on other devices and objects without one', () => {
    const l = yard();
    l.fixtures[0].deviceId = 'other';
    expect(sharedLeds(l, 'tree2')).toEqual([]);
    l.fixtures[2].deviceId = null;
    expect(sharedLeds(l, 'tree2')).toEqual([]);
  });

  it('finds the LEDs after every other object on the device', () => {
    const l = yard();
    expect(nextFreeLed(l, 'quad', 'tree2')).toBe(700);
    // The object itself does not count, so moving it to the end does not push it farther.
    l.fixtures[2] = { ...l.fixtures[2], ...fromLedRange(700, 849) };
    expect(nextFreeLed(l, 'quad', 'tree2')).toBe(700);
  });

  it('has no overlap once the second tree is on 700–849', () => {
    const l = yard();
    l.fixtures[2] = { ...l.fixtures[2], startPixel: nextFreeLed(l, 'quad', 'tree2') };
    expect(deviceRuns(l).get('quad')!.overlaps).toHaveLength(0);
    expect(ledRange(l.fixtures[2])).toEqual({ first: 700, last: 849 });
  });

  // A curve drawn with many points: no corner is pinned until it is matched to the lights.
  const curve = (over: Partial<Fixture>): Fixture => ({
    ...sampleLayout().fixtures[0],
    id: 'l',
    kind: 'line',
    points: Array.from({ length: 12 }, (_, i) => ({ x: i * 30, y: Math.round(Math.sin(i / 2) * 40), z: 0 })),
    deviceId: 'quad',
    ...fromLedRange(0, 99),
    pointLeds: undefined,
    ...over
  });
  const ordered = (f: Fixture) => pointOffsets(f).every((o, i, a) => i === 0 || o > a[i - 1]);

  it('sets the start and the end of a freshly drawn curve to any LEDs, the corners spreading by length', () => {
    let f = curve({});
    f = { ...f, ...setLineEnd(f, 'last', 849).patch };
    expect(ledRange(f)).toEqual({ first: 0, last: 849 });
    f = { ...f, ...setLineEnd(f, 'first', 700).patch };
    expect(ledRange(f)).toEqual({ first: 700, last: 849 });
    expect(f.pointLeds).toBeUndefined();
    expect(ordered(f)).toBe(true);
    // Counting down works the same way.
    f = { ...f, ...setLineEnd(f, 'first', 900).patch };
    expect(ledRange(f)).toEqual({ first: 900, last: 849 });
    expect(ordered(f)).toBe(true);
  });

  it('takes the two ends typed in either order, whatever the line had before', () => {
    // A new line put after every other object, past where it should go (850–949).
    const start = curve(fromLedRange(850, 949));
    for (const order of [['last', 'first'], ['first', 'last']] as const) {
      let f = start;
      for (const end of order) f = { ...f, ...setLineEnd(f, end, end === 'first' ? 700 : 849).patch };
      expect(ledRange(f)).toEqual({ first: 700, last: 849 });
      expect(f.pixels).toBe(150);
      expect(ordered(f)).toBe(true);
    }
  });

  it('keeps corners matched to the lights on their LEDs when an end moves', () => {
    const f = curve({ ...fromLedRange(422, 849), pointLeds: [null, null, null, null, null, 100, null, null, null, null, null, null] });
    const corner = deviceLed(f, pointOffsets(f)[5]);
    const out = { ...f, ...setLineEnd(f, 'last', 800).patch };
    expect(ledRange(out)).toEqual({ first: 422, last: 800 });
    expect(isPinned(out, 5)).toBe(true);
    expect(deviceLed(out, pointOffsets(out)[5])).toBe(corner);
    expect(ordered(out)).toBe(true);
  });

  it('unpins a matched corner the new LEDs leave no room for, instead of snapping the end back', () => {
    // Line of lights 2: 422–849, corners pinned at 423 and 437.
    const f = curve({ points: curve({}).points.slice(0, 4), ...fromLedRange(422, 849), pointLeds: [null, 1, 15, null] });
    const { patch, unpinned } = setLineEnd(f, 'first', 700);
    const out = { ...f, ...patch };
    expect(ledRange(out)).toEqual({ first: 700, last: 849 });
    expect(out.pixels).toBe(150);
    expect(unpinned).toEqual([1, 2]);
    expect(out.pointLeds).toBeUndefined();
    expect(ordered(out)).toBe(true);
  });
});
