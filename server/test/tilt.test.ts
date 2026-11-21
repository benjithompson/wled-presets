import { describe, expect, it } from 'vitest';
import { fixturePixels, keepLocked, objectPaths, sampleLayout, treeOutline, treeSurfaceLength, type Fixture, type Layout } from '../../shared/layout.ts';
import { layoutSchema } from '../src/layoutStore.ts';

const tree = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 't',
  name: 'Tree',
  kind: 'tree',
  points: [{ x: 800, y: 900, z: 300 }],
  radius: 100,
  height: 400,
  shape: 'cylinder',
  pattern: 'spiral',
  turns: 6,
  pixels: 600,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

/** The height (up from the base) where each loop of a spiral passes the front. */
function loopHeights(px: { x: number; y: number; z: number }[]): number[] {
  const out: number[] = [];
  let total = 0;
  let prev = Math.atan2(px[0].x - 800, px[0].z - 300);
  for (let i = 1; i < px.length; i++) {
    const a = Math.atan2(px[i].x - 800, px[i].z - 300);
    let d = a - prev;
    if (d > Math.PI) d -= 2 * Math.PI;
    if (d < -Math.PI) d += 2 * Math.PI;
    const before = total;
    total += d;
    if (Math.floor(total / (2 * Math.PI)) > Math.floor(before / (2 * Math.PI))) out.push(900 - px[i].y);
    prev = a;
  }
  return out;
}

describe('spiral loops', () => {
  it('sit evenly apart, or bunch toward the top or the base', () => {
    const even = loopHeights(fixturePixels(tree()));
    const gaps = (h: number[]) => h.slice(1).map((v, i) => v - h[i]);
    for (const g of gaps(even)) expect(g).toBeCloseTo(400 / 6, -1);
    const top = gaps(loopHeights(fixturePixels(tree({ bias: 0.8 }))));
    expect(top.at(-1)!).toBeLessThan(top[0] / 2);
    const base = gaps(loopHeights(fixturePixels(tree({ bias: -0.8 }))));
    expect(base[0]).toBeLessThan(base.at(-1)! / 2);
  });

  it('measures the way up the surface: a cylinder its height, a ball over its curve', () => {
    expect(treeSurfaceLength(tree())).toBeCloseTo(400, 6);
    // A round ball 200 across: half its circumference from the bottom to the top.
    expect(treeSurfaceLength(tree({ shape: 'sphere', height: 200 }))).toBeCloseTo(Math.PI * 100, 0);
    // Its top half only: a quarter.
    expect(treeSurfaceLength(tree({ shape: 'sphere', height: 200, cover: 90 }))).toBeCloseTo((Math.PI * 100) / 2, 0);
  });
});

describe('tilting', () => {
  it('leans a tree about its base: to the right from the front, toward the street from the side', () => {
    const top = (f: Fixture) => fixturePixels(f).at(-1)!;
    const right = top(tree({ rotation: 90, pattern: 'strands', strands: 1 }));
    expect(right.x).toBeCloseTo(800 + 400, 6);
    expect(right.y).toBeCloseTo(900, 6);
    // The top of its one strand (on its front, 100 toward the street from the axis) lies 400
    // further toward the street, and 100 lower: the front of a tree lying down faces the ground.
    const street = top(tree({ tilt: 90, pattern: 'strands', strands: 1 }));
    expect(street.z).toBeCloseTo(300 + 400, 6);
    expect(street.y).toBeCloseTo(1000, 6);
    // Its outline leans with it.
    const outline = treeOutline(tree({ rotation: 30 }));
    expect(outline[1].x).toBeGreaterThan(800 + 400 * Math.sin(Math.PI / 6) - 100 - 1);
    // The middle of its base stays where it is.
    const outlineBase = treeOutline(tree({ rotation: 20, tilt: -15 }));
    expect((outlineBase[0].x + outlineBase.at(-1)!.x) / 2).toBeCloseTo(800, 6);
    expect((outlineBase[0].y + outlineBase.at(-1)!.y) / 2).toBeCloseTo(900, 6);
  });

  it('tilts a semicircle and its drawing together', () => {
    const semi: Fixture = { id: 's', name: 'Sun', kind: 'semicircle', points: [{ x: 400, y: 800, z: 100 }], radius: 100, pixels: 80, deviceId: null, startPixel: 0, reversed: false, tilt: 90 };
    // Tilted flat toward the street: its top lies 100 in front of its point.
    const px = fixturePixels(semi);
    expect(Math.max(...px.map((p) => p.z))).toBeGreaterThan(185);
    expect(Math.max(...px.map((p) => p.z))).toBeLessThanOrEqual(200 + 1e-6);
    for (const p of px) expect(p.y).toBeCloseTo(800, 6);
    const path = objectPaths(semi)[0];
    expect(Math.max(...path.map((p) => p.z))).toBeCloseTo(200, 6);
  });

  it('keeps a locked object’s tilt, and saves tilts and loop bias', () => {
    const prev: Layout = { ...sampleLayout(), fixtures: [tree({ locked: true })] };
    expect(keepLocked(prev, { ...prev, fixtures: [tree({ locked: true, tilt: 10 })] }).blocked).toEqual(['Tree']);
    expect(layoutSchema.safeParse({ ...sampleLayout(), fixtures: [tree({ tilt: 12, rotation: -8, bias: 0.4 })] }).success).toBe(true);
  });
});
