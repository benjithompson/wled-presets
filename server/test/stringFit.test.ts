import { describe, expect, it } from 'vitest';
import { ledGap, lineLengths, sampleLayout, wavePasses, type Fixture, type Layout } from '../../shared/layout.ts';
import { fitsString, fitString, keepStrings, stringGap } from '../../shared/stringFit.ts';

// 4 in apart: 0.1016 m, at 80 layout units a meter.
const LIGHTS = 'novabright-bullet-12v-4in';
const GAP = 0.1016 * 80;

const base = (): Layout => ({ ...sampleLayout(), fixtures: [] });
const withF = (...fixtures: Fixture[]): Layout => ({ ...base(), fixtures });

const tree = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 't',
  name: 'Tree',
  kind: 'tree',
  points: [{ x: 800, y: 800, z: 200 }],
  radius: 80,
  height: 240,
  pattern: 'spiral',
  turns: 6,
  pixels: 300,
  lights: LIGHTS,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

const line = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 'l',
  name: 'Fence',
  kind: 'line',
  points: [
    { x: 100, y: 800 },
    { x: 300, y: 800 }
  ],
  pixels: 50,
  lights: LIGHTS,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

const close = (a: number | null, b: number, share = 0.03) => expect(Math.abs((a ?? 0) - b) / b).toBeLessThan(share);

describe('the string sets how a shape winds', () => {
  it('gives a spiral tree as many turns as its string goes round, more with more LEDs', () => {
    const layout = base();
    const a = fitString(tree(), layout);
    close(ledGap(a), GAP);
    const b = fitString(tree({ pixels: 600 }), layout);
    expect(b.turns!).toBeGreaterThan(a.turns!);
    close(ledGap(b), GAP);
    // A ball and a spiral that bunches too.
    close(ledGap(fitString(tree({ shape: 'sphere', bias: 0.5 }), layout)), GAP);
  });

  it('counts the strands, the passes of a wave and the rows of a semicircle', () => {
    const layout = base();
    const s = fitString(tree({ pattern: 'strands', strands: 2 }), layout);
    expect(s.strands).toBeGreaterThan(2);
    expect(ledGap(s)!).toBeLessThanOrEqual(GAP * 1.03);
    expect(ledGap({ ...s, strands: s.strands! + 1 })!).toBeGreaterThan(GAP * 1.03);

    const w = fitString(tree({ pattern: 'wave', pixels: 400 }), layout);
    const passes = wavePasses(w).passes;
    expect(ledGap(w)!).toBeLessThanOrEqual(GAP * 1.03);
    expect(passes).toBeGreaterThan(2);

    const semi: Fixture = { id: 's', name: 'Sun', kind: 'semicircle', points: [{ x: 400, y: 800 }], radius: 100, strands: 2, pixels: 160, lights: LIGHTS, deviceId: null, startPixel: 0, reversed: false };
    const r = fitString(semi, layout);
    expect(r.strands).toBeGreaterThan(2);
    expect(ledGap(r)!).toBeLessThanOrEqual(GAP * 1.03);
  });

  it('makes a ring as big as its string goes round', () => {
    const ring: Fixture = { id: 'b', name: 'Bush', kind: 'bush', points: [{ x: 400, y: 800 }], radius: 30, pattern: 'ring', pixels: 50, lights: LIGHTS, deviceId: null, startPixel: 0, reversed: false };
    const out = fitString(ring, base());
    expect(out.radius!).toBeGreaterThan(30);
    close(ledGap(out), GAP);
  });

  it('leaves objects without a light type, and a net over a bush, as they are', () => {
    const t = tree({ lights: undefined });
    expect(fitString(t, base())).toBe(t);
    const net: Fixture = { id: 'b', name: 'Bush', kind: 'bush', points: [{ x: 400, y: 800 }], radius: 30, pixels: 50, lights: LIGHTS, deviceId: null, startPixel: 0, reversed: false };
    expect(fitString(net, base())).toBe(net);
    expect(ledGap(net)).toBeNull();
    expect(stringGap(t, base())).toBeNull();
  });
});

describe('keeping wires within their strings', () => {
  it('works the turns out again when the tree changes size, not when only its effect changes', () => {
    const prev = withF(tree());
    const bigger = keepStrings(prev, withF(tree({ height: 400 }))).layout.fixtures[0];
    close(ledGap(bigger), GAP);
    expect(bigger.turns).not.toBe(6);
    const fx = tree({ effect: { id: 'solid' } as Fixture['effect'] });
    expect(keepStrings(prev, withF(fx)).layout.fixtures[0]).toBe(fx);
  });

  it('stops a point dragged past the end of the string', () => {
    // 50 LEDs 4 in apart reach 49 gaps.
    const reach = 49 * GAP;
    const prev = withF(line());
    const pulled = line({ points: [line().points[0], { x: 100 + reach * 3, y: 800 }] });
    const out = keepStrings(prev, withF(pulled));
    expect(out.limited).toEqual(['Fence']);
    const len = lineLengths(out.layout.fixtures[0]).reduce((a, b) => a + b, 0);
    expect(len).toBeLessThanOrEqual(reach * 1.03 + 0.5);
    expect(len).toBeGreaterThan(reach * 0.97);
    // Shorter, and moved as a whole: as asked.
    const shorter = line({ points: [line().points[0], { x: 200, y: 800 }] });
    expect(keepStrings(prev, withF(shorter)).layout.fixtures[0]).toBe(shorter);
    expect(fitsString(shorter, base())).toBe(true);
  });

  it('lets a line that is too long already move, and shrink, but not grow', () => {
    const long = line({ points: [{ x: 0, y: 800 }, { x: 1000, y: 800 }] });
    expect(fitsString(long, base())).toBe(false);
    const prev = withF(long);
    const moved = line({ points: [{ x: 10, y: 700 }, { x: 1010, y: 700 }] });
    expect(keepStrings(prev, withF(moved)).layout.fixtures[0]).toBe(moved);
    const grown = keepStrings(prev, withF(line({ points: [{ x: 0, y: 800 }, { x: 1500, y: 800 }] }))).layout.fixtures[0];
    expect(lineLengths(grown)[0]).toBeCloseTo(1000, -1);
    // Fewer LEDs: it cannot be helped by holding the drawing back; it stays, and the editor says so.
    const fewer = line({ pixels: 10 });
    expect(keepStrings(withF(line()), withF(fewer)).layout.fixtures[0]).toBe(fewer);
  });

  it('measures a line with a pinned corner by its widest stretch', () => {
    const f = line({ points: [{ x: 0, y: 800 }, { x: 100, y: 800 }, { x: 400, y: 800 }], pointLeds: [null, 25, null] });
    // 100 units over 25 gaps, 300 units over 24.
    expect(ledGap(f)).toBeCloseTo(300 / 24, 5);
  });

  it('holds back a tree made too big for its string even at the fewest turns', () => {
    const small = fitString(tree({ pixels: 40 }), base());
    const prev = withF(small);
    const out = keepStrings(prev, withF({ ...small, radius: 800, height: 2400 }));
    expect(out.limited).toEqual(['Tree']);
    const t = out.layout.fixtures[0];
    expect(t.radius!).toBeLessThan(800);
    expect(t.radius!).toBeGreaterThan(80);
    expect(fitsString(t, base())).toBe(true);
  });

  it('works shapes out again when the light type changes', () => {
    const prev = withF(fitString(tree(), base()));
    const out = keepStrings(prev, withF({ ...prev.fixtures[0], lights: 'c9-12v-12in' })).layout.fixtures[0];
    close(ledGap(out), 0.3048 * 80);
  });
});
