import { describe, expect, it } from 'vitest';
import { aerialCorners, alignAerial, placeAerial, sampleLayout, scaleAerial, type AerialPicture } from '../../shared/layout.ts';
import { layoutSchema } from '../src/layoutStore.ts';

const pic: AerialPicture = { url: '/api/admin/layout/aerial?v=1', x: 800, z: 0, width: 3200, aspect: 0.5, rotation: 0 };
/** Where a spot of the picture (u, v from its middle, as a share of its width and height) lies. */
const spot = (a: AerialPicture, u: number, v: number) => {
  const [tl, tr, , bl] = aerialCorners(a);
  const s = u + 0.5;
  const t = v + 0.5;
  return { x: tl.x + (tr.x - tl.x) * s + (bl.x - tl.x) * t, z: tl.z + (tr.z - tl.z) * s + (bl.z - tl.z) * t };
};

describe('the picture from above', () => {
  it('starts twice as wide as the front view, its middle on the front wall, and keeps the place of the one it replaces', () => {
    expect(placeAerial(sampleLayout(), 'u', 0.75)).toMatchObject({ x: 800, z: 0, width: 3200, aspect: 0.75, rotation: 0 });
    const moved = { ...pic, x: 10, rotation: 30 };
    expect(placeAerial(sampleLayout(), 'new', 0.6, moved)).toEqual({ ...moved, url: 'new', aspect: 0.6 });
  });

  it('has its corners where it is turned (clockwise from above, the street at the bottom)', () => {
    expect(aerialCorners(pic)[0]).toEqual({ x: -800, z: -800 });
    const turned = aerialCorners({ ...pic, rotation: 90 });
    // The top left corner turns to the top right.
    expect(turned[0].x).toBeCloseTo(1600);
    expect(turned[0].z).toBeCloseTo(-1600);
  });

  it('lines up two spots with where they really are: moved, turned and sized', () => {
    // Two spots on the picture, and where they belong.
    const a = spot(pic, -0.1, 0.1);
    const b = spot(pic, 0.2, 0.1);
    const to1 = { x: 300, z: 0 };
    const to2 = { x: 300, z: 500 };
    const next = alignAerial(pic, a, to1, b, to2);
    expect(next.rotation).toBeCloseTo(90);
    // a and b were 960 apart, now 500.
    expect(next.width).toBeCloseTo((3200 * 500) / 960, 1);
    const a2 = spot(next, -0.1, 0.1);
    const b2 = spot(next, 0.2, 0.1);
    expect(a2.x).toBeCloseTo(300, 0);
    expect(a2.z).toBeCloseTo(0, 0);
    expect(b2.x).toBeCloseTo(300, 0);
    expect(b2.z).toBeCloseTo(500, 0);
    expect(next.aspect).toBe(pic.aspect);
  });

  it('only moves with one pair, or two pairs on the same spot', () => {
    expect(alignAerial(pic, { x: 0, z: 0 }, { x: 50, z: -20 })).toMatchObject({ x: 850, z: -20, width: 3200, rotation: 0 });
    expect(alignAerial(pic, { x: 0, z: 0 }, { x: 50, z: -20 }, { x: 0, z: 0 }, { x: 9, z: 9 })).toMatchObject({ x: 850, z: -20, width: 3200 });
  });

  it('keeps the turn between -180° and 180°', () => {
    const next = alignAerial({ ...pic, rotation: 170 }, { x: 0, z: 0 }, { x: 0, z: 0 }, { x: 100, z: 0 }, { x: 0, z: 100 });
    expect(next.rotation).toBeCloseTo(-100);
  });

  it('scales about a spot that stays put', () => {
    expect(scaleAerial(pic, { x: 0, z: 0 }, 2)).toMatchObject({ x: 1600, z: 0, width: 6400 });
  });

  it('is saved with the layout', () => {
    const layout = { ...sampleLayout(), aerial: { ...pic, opacity: 0.4 } };
    const parsed = layoutSchema.safeParse(layout);
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.aerial).toEqual(layout.aerial);
    expect(layoutSchema.safeParse({ ...sampleLayout(), aerial: null }).success).toBe(true);
    expect(layoutSchema.safeParse({ ...layout, aerial: { ...pic, width: 0 } }).success).toBe(false);
    expect(layoutSchema.safeParse({ ...layout, aerial: { ...pic, opacity: 2 } }).success).toBe(false);
  });
});
