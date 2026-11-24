import { describe, expect, it } from 'vitest';
import { clampPointLed, deviceLed, deviceRuns, fromLedRange, isPinned, ledRange, moveToLed, nextFreeLed, pointOffsets, sampleLayout, sharedLeds, spreadLine, type Fixture, type Layout } from '../../shared/layout.ts';

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

  it('moves a whole object to a first LED, keeping its length and direction', () => {
    const l = yard();
    const t2 = l.fixtures[2];
    expect(ledRange({ ...t2, ...moveToLed(t2, 700) })).toEqual({ first: 700, last: 849 });
    const down = { ...t2, ...fromLedRange(149, 0) };
    expect(ledRange({ ...down, ...moveToLed(down, 849) })).toEqual({ first: 849, last: 700 });
    // Not below LED 0.
    expect(moveToLed(down, 10)).toEqual({ startPixel: 0 });
  });

  it('has no overlap once the second tree is on 700–849', () => {
    const l = yard();
    l.fixtures[2] = { ...l.fixtures[2], ...moveToLed(l.fixtures[2], nextFreeLed(l, 'quad', 'tree2')) };
    expect(deviceRuns(l).get('quad')!.overlaps).toHaveLength(0);
    expect(ledRange(l.fixtures[2])).toEqual({ first: 700, last: 849 });
  });

  it('puts a line with pinned corners on new LEDs when its first LED cannot pass a corner', () => {
    // A line on 422–849 whose first corner is pinned at LED 423 (one LED in the first segment).
    const base = sampleLayout().fixtures[0];
    const line: Fixture = { ...base, id: 'l', kind: 'line', points: [{ x: 0, y: 0, z: 0 }, { x: 10, y: 0, z: 0 }, { x: 20, y: 0, z: 0 }, { x: 400, y: 0, z: 0 }], deviceId: 'quad', ...fromLedRange(422, 849), pointLeds: [null, 1, 15, null] };
    // Moving only the end stops at the corner: the first LED cannot get to 700.
    expect(clampPointLed(line, 0, 700)).toBeLessThan(700);
    const out = { ...line, ...spreadLine(line, 700, 849) };
    expect(ledRange(out)).toEqual({ first: 700, last: 849 });
    expect(out.pixels).toBe(150);
    // The corners are in order, inside the line.
    const offs = pointOffsets(out);
    for (let i = 1; i < offs.length; i++) expect(offs[i]).toBeGreaterThan(offs[i - 1]);
    expect(deviceLed(out, offs.at(-1)!)).toBe(849);
  });

  it('keeps a pinned corner as far along the line as it was', () => {
    const base = sampleLayout().fixtures[0];
    const line: Fixture = { ...base, id: 'l', kind: 'line', points: [{ x: 0, y: 0, z: 0 }, { x: 10, y: 0, z: 0 }, { x: 400, y: 0, z: 0 }], deviceId: 'quad', ...fromLedRange(0, 400), pointLeds: [null, 200, null] };
    const out = { ...line, ...spreadLine(line, 700, 900) };
    expect(isPinned(out, 1)).toBe(true);
    expect(pointOffsets(out)[1]).toBe(100);
  });
});
