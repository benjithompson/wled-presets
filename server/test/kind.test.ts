import { describe, expect, it } from 'vitest';
import { changeKind, fixturePixels, type Fixture } from '../../shared/layout.ts';
import { layoutSchema } from '../src/layoutStore.ts';
import { sampleLayout } from '../../shared/layout.ts';

const bush: Fixture = {
  id: 'b',
  name: 'Porch bush',
  kind: 'bush',
  points: [{ x: 400, y: 700, z: 90 }],
  radius: 100,
  pattern: 'ring',
  pixels: 150,
  lights: 'ws2811-12v',
  deviceId: 'd1',
  startPixel: 300,
  reversed: true,
  effect: { effect: 'twinkle' } as Fixture['effect'],
  locked: true
};

/** The front view's box of an object's LEDs. */
const box = (f: Fixture) => {
  const px = fixturePixels(f);
  const xs = px.map((p) => p.x);
  const ys = px.map((p) => p.y);
  return { left: Math.min(...xs), right: Math.max(...xs), top: Math.min(...ys), bottom: Math.max(...ys) };
};

describe('changing an object into another kind of shape', () => {
  it('keeps its name, LEDs, light string, effect and lock, and drops the old kind’s settings', () => {
    const tree = changeKind(bush, 'tree');
    expect(tree).toMatchObject({ id: 'b', name: 'Porch bush', kind: 'tree', pixels: 150, lights: 'ws2811-12v', deviceId: 'd1', startPixel: 300, reversed: true, effect: bush.effect, locked: true, radius: 100 });
    // A bush becomes a ball of lights; ring is not a tree pattern.
    expect(tree.shape).toBe('sphere');
    expect(tree.pattern).toBe('spiral');
    expect('facing' in tree).toBe(false);
    const semi = changeKind({ ...tree, facing: 45, spin: 'cw', turns: 3 }, 'semicircle');
    expect(semi.facing).toBe(45);
    expect(semi.spin).toBeUndefined();
    expect(semi.turns).toBeUndefined();
    expect(semi.shape).toBeUndefined();
  });

  it('covers the same part of the front view: as wide, on the same ground, as tall', () => {
    const tree = changeKind(bush, 'tree');
    // The tree stands where the bush's LEDs reach down to, and is as tall as the bush.
    expect(tree.points[0]).toEqual({ x: 400, y: 772, z: 90 });
    expect(tree.height).toBe(144);
    const a = box(bush);
    const b = box(tree);
    expect(Math.abs(b.bottom - a.bottom)).toBeLessThan(10);
    expect(Math.abs(b.top - a.top)).toBeLessThan(10);
    expect(Math.abs(b.left - a.left)).toBeLessThan(10);
    // And back: the same bush.
    expect(changeKind(tree, 'bush').points[0]).toEqual(bush.points[0]);
    // A semicircle stands on the same ground line, as tall as the tree.
    const semi = changeKind({ ...tree, height: 200 }, 'semicircle');
    expect(semi.points[0]).toEqual(tree.points[0]);
    expect(semi.height).toBe(200);
  });

  it('leaves lines, custom objects and the same kind alone, and the result saves', () => {
    const roof = sampleLayout().fixtures[0];
    expect(changeKind(roof, 'tree')).toBe(roof);
    expect(changeKind(bush, 'bush')).toBe(bush);
    const layout = { ...sampleLayout(), fixtures: [...sampleLayout().fixtures.slice(0, 1), changeKind({ ...bush, effect: undefined, lights: undefined }, 'tree'), changeKind({ ...bush, id: 'c', deviceId: null, effect: undefined, lights: undefined }, 'semicircle')] };
    expect(layoutSchema.safeParse(layout).success).toBe(true);
  });
});
