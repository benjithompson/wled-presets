import { describe, expect, it } from 'vitest';
import { layoutScale, ledGap, sampleLayout, type Fixture, type Layout } from '../../shared/layout.ts';
import { fitsString, keepStrings } from '../../shared/stringFit.ts';
import { autoScale, keepScale, roofScale, setsScale } from '../../shared/yardScale.ts';

// 4 in apart: 0.1016 m.
const LIGHTS = 'novabright-bullet-12v-4in';
const SPACING = 0.1016;

/** A straight roof 1000 units long with 101 LEDs: 100 gaps, 10.16 m of string. */
const roof = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 'roof',
  name: 'Roofline',
  kind: 'roof',
  points: [
    { x: 300, y: 400 },
    { x: 1300, y: 400 }
  ],
  pixels: 101,
  lights: LIGHTS,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

const custom = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 'star',
  name: 'Star',
  kind: 'custom',
  points: [{ x: 800, y: 600, z: 50 }],
  design: [{ points: [{ x: 0, y: 0 }, { x: 1, y: 0 }] }],
  size: 1,
  pixels: 11,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

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

const withF = (...fixtures: Fixture[]): Layout => ({ ...sampleLayout(), scale: 80, fixtures });

describe('the roofline sets the scale', () => {
  it('is the roofline as drawn over the string along it', () => {
    const r = roofScale(withF(roof()));
    expect(r?.scale).toBeCloseTo(1000 / (100 * SPACING), 2);
    expect(r?.meters).toBeCloseTo(10.16, 6);
    expect(r?.roofs).toEqual(['roof']);
  });

  it('goes by the LEDs pinned at the corners, not by how the corners are spread', () => {
    // 400 + 600 units; the corner's LED at 25: the first segment has 25 gaps, the second 75.
    const pts = [
      { x: 0, y: 400 },
      { x: 400, y: 400 },
      { x: 1000, y: 400 }
    ];
    const even = roofScale(withF(roof({ points: pts })))!;
    const pinned = roofScale(withF(roof({ points: pts, pointLeds: [null, 25, null] })))!;
    // The whole roof is 100 gaps either way.
    expect(pinned.scale).toBeCloseTo(even.scale, 6);
    // Skipping the first segment: the second's 600 units over 75 gaps of string.
    expect(roofScale(withF(roof({ points: pts, pointLeds: [null, 25, null], skip: [0] })))!.scale).toBeCloseTo(600 / (75 * SPACING), 2);
  });

  it('adds up every roof with lights; others do not count', () => {
    const a = roof();
    const b = roof({ id: 'b', points: [{ x: 0, y: 200 }, { x: 500, y: 200 }], pixels: 51 });
    const r = roofScale(withF(a, b, roof({ id: 'c', lights: undefined }), { ...roof({ id: 'd' }), kind: 'line' }))!;
    expect(r.roofs).toEqual(['roof', 'b']);
    expect(r.scale).toBeCloseTo(1500 / (150 * SPACING), 2);
  });

  it('has nothing to say without a roof with lights, or when set by hand', () => {
    expect(roofScale(withF(roof({ lights: undefined })))).toBeNull();
    expect(autoScale({ ...withF(roof()), scaleBy: 'hand' })).toBeNull();
    expect(setsScale(roof(), { ...withF(roof()), scaleBy: 'hand' })).toBe(false);
    expect(setsScale(roof(), withF(roof()))).toBe(true);
  });
});

describe('keepScale', () => {
  it('sets the scale from the roof, and objects keep the size they are drawn at', () => {
    const prev = withF(roof(), custom(), tree());
    const next = { ...prev, fixtures: prev.fixtures.map((f) => (f.kind === 'roof' ? { ...f, pixels: 151 } : f)) };
    const out = keepScale(prev, next);
    const scale = layoutScale(out.layout);
    expect(scale).toBeCloseTo(1000 / (150 * SPACING), 2);
    // The star is as big in layout units as it was: its size went the other way.
    const star = out.layout.fixtures.find((f) => f.kind === 'custom')!;
    expect(ledGap(star, scale)).toBeCloseTo(ledGap(custom(), 80)!, 4);
    // prev's star too, so the edit's checks do not see a change; prev keeps its scale.
    expect(out.prev.fixtures.find((f) => f.kind === 'custom')!.size).toBe(star.size);
    expect(out.prev.scale).toBe(80);
    // The tree is as big as it was.
    const t = out.layout.fixtures.find((f) => f.kind === 'tree')!;
    expect([t.radius, t.height, t.points]).toEqual([80, 240, tree().points]);
  });

  it('changes nothing when the scale is right, or set by hand', () => {
    const l = withF(roof());
    const right = { ...l, scale: roofScale(l)!.scale };
    expect(keepScale(right, right).layout).toBe(right);
    const hand = { ...l, scaleBy: 'hand' as const };
    expect(keepScale(hand, hand).layout).toBe(hand);
  });

  it('with keepStrings: trees wind again for the new scale, and the roof is never too long for its string', () => {
    const first = keepScale(withF(roof(), tree()), withF(roof(), tree()));
    const prev = keepStrings(first.prev, first.layout).layout;
    // Drag the roof's end out 30%: the string is the same, so the scale grows instead.
    const dragged = { ...prev, fixtures: prev.fixtures.map((f) => (f.kind === 'roof' ? { ...f, points: [f.points[0], { x: 1600, y: 400 }] } : f)) };
    const scaled = keepScale(prev, dragged);
    const strung = keepStrings(scaled.prev, scaled.layout);
    expect(strung.limited).toEqual([]);
    const r = strung.layout.fixtures.find((f) => f.kind === 'roof')!;
    expect(r.points[1].x).toBe(1600);
    expect(fitsString(r, strung.layout)).toBe(true);
    expect(layoutScale(strung.layout)).toBeCloseTo(1300 / (100 * SPACING), 2);
    // The tree is as big, with more turns: at the bigger scale its string is longer on the drawing.
    const t0 = prev.fixtures.find((f) => f.kind === 'tree')!;
    const t1 = strung.layout.fixtures.find((f) => f.kind === 'tree')!;
    expect(t1.height).toBe(t0.height);
    expect(t1.turns!).toBeGreaterThan(t0.turns!);
  });
});
