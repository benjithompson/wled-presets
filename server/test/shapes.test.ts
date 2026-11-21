import { describe, expect, it } from 'vitest';
import { buildStage, fixturePixels, sampleLayout, semicircleOutline, treeOutline, zigzagPath, type Fixture, type Point3 } from '../../shared/layout.ts';
import { layoutSchema } from '../src/layoutStore.ts';

const tree = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 't',
  name: 'T',
  kind: 'tree',
  points: [{ x: 800, y: 900, z: 300 }],
  radius: 100,
  height: 400,
  pattern: 'spiral',
  turns: 6,
  pixels: 200,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

const semicircle = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 's',
  name: 'S',
  kind: 'semicircle',
  points: [{ x: 500, y: 800, z: 40 }],
  radius: 100,
  strands: 6,
  pixels: 120,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

/** The angle of an LED round the tree's axis as seen from above, the street at the bottom: counterclockwise is plus. */
const angleFromAbove = (p: Point3) => Math.atan2(-(p.z - 300), p.x - 800);

/** How far the LEDs go round the axis, following the wire (plus: counterclockwise from above). */
function windAngle(px: Point3[]) {
  let total = 0;
  for (let i = 1; i < px.length; i++) {
    let d = angleFromAbove(px[i]) - angleFromAbove(px[i - 1]);
    if (d > Math.PI) d -= 2 * Math.PI;
    if (d < -Math.PI) d += 2 * Math.PI;
    total += d;
  }
  return total;
}

describe('tree shapes, spin and facing', () => {
  it('places a tree saved before these settings exactly as before', () => {
    // The old code: a cone, LEDs spread by s → u = 1 - sqrt(1 - s), the angle u · turns · 2π from the front.
    const f = tree();
    const px = fixturePixels(f);
    px.forEach((p, i) => {
      const s = i / 199;
      const u = 1 - Math.sqrt(1 - s);
      const a = u * 6 * Math.PI * 2;
      const rad = 100 * (1 - u * 0.96);
      expect(p.x).toBeCloseTo(800 + Math.sin(a) * rad, 9);
      expect(p.y).toBeCloseTo(900 - u * 400, 9);
      expect(p.z).toBeCloseTo(300 + Math.cos(a) * rad, 9);
    });
    const strands = fixturePixels(tree({ pattern: 'strands', strands: 4 }));
    expect(strands[50].x).toBeCloseTo(800 + 100 * 0.04, 9);
    expect(strands[0]).toEqual({ x: 800, y: 900, z: 400 });
  });

  it('winds counterclockwise from above by default, clockwise when set, as the mirror image', () => {
    const ccw = fixturePixels(tree({ shape: 'cylinder' }));
    const cw = fixturePixels(tree({ shape: 'cylinder', spin: 'cw' }));
    expect(windAngle(ccw)).toBeCloseTo(6 * Math.PI * 2, 1);
    expect(windAngle(cw)).toBeCloseTo(-6 * Math.PI * 2, 1);
    // Clockwise is the counterclockwise spiral seen in a mirror (left and right swapped).
    cw.forEach((p, i) => {
      expect(p.x).toBeCloseTo(1600 - ccw[i].x, 9);
      expect(p.y).toBeCloseTo(ccw[i].y, 9);
      expect(p.z).toBeCloseTo(ccw[i].z, 9);
    });
    // Strands go round the other way too.
    const s = fixturePixels(tree({ pattern: 'strands', strands: 4, spin: 'cw' }));
    expect(s[50].x).toBeLessThan(800);
  });

  it('starts a spiral at the top: LED 0 at the top, at the front, winding the way it is set', () => {
    for (const spin of ['ccw', 'cw'] as const) {
      const px = fixturePixels(tree({ shape: 'cylinder', start: 'top', spin }));
      expect(px[0].y).toBeCloseTo(500);
      expect(px[0].x).toBeCloseTo(800);
      expect(px[0].z).toBeCloseTo(400);
      expect(px[199].y).toBeCloseTo(900);
      expect(Math.sign(windAngle(px))).toBe(spin === 'ccw' ? 1 : -1);
    }
    // A cone from the top: LED 0 near the axis at the top, the last LED on the wide base.
    const cone = fixturePixels(tree({ start: 'top' }));
    expect(cone[0].y).toBeCloseTo(500);
    expect(Math.hypot(cone[0].x - 800, cone[0].z - 300)).toBeLessThan(5);
    expect(Math.hypot(cone[199].x - 800, cone[199].z - 300)).toBeCloseTo(100);
  });

  it('turns a tree as seen from above: facing 90 starts it on the right', () => {
    const front = fixturePixels(tree({ shape: 'cylinder' }));
    const right = fixturePixels(tree({ shape: 'cylinder', facing: 90 }));
    expect(right[0].x).toBeCloseTo(900);
    expect(right[0].z).toBeCloseTo(300);
    // Every LED turns by the same angle about the axis, at the same height.
    right.forEach((p, i) => {
      let d = angleFromAbove(p) - angleFromAbove(front[i]);
      if (d < -Math.PI) d += 2 * Math.PI;
      if (d > Math.PI) d -= 2 * Math.PI;
      expect(d).toBeCloseTo(Math.PI / 2, 6);
      expect(p.y).toBeCloseTo(front[i].y, 9);
    });
  });

  it('follows the shape: a cylinder keeps its width, a sphere sits on its base, a cone narrows', () => {
    const dist = (p: Point3) => Math.hypot(p.x - 800, p.z - 300);
    for (const p of fixturePixels(tree({ shape: 'cylinder' }))) expect(dist(p)).toBeCloseTo(100, 9);
    const ball = fixturePixels(tree({ shape: 'sphere' }));
    for (const p of ball) {
      // On the ellipsoid of the tree's width and height, standing on the base point.
      const up = (900 - p.y) / 400;
      expect((dist(p) / 100) ** 2 + (2 * up - 1) ** 2).toBeCloseTo(1, 6);
    }
    expect(ball[0].y).toBeCloseTo(900);
    expect(ball[199].y).toBeCloseTo(500);
    // Widest halfway up.
    const widest = ball.reduce((a, p) => (dist(p) > dist(a) ? p : a));
    expect(900 - widest.y).toBeGreaterThan(160);
    expect(900 - widest.y).toBeLessThan(240);
    const cone = fixturePixels(tree({ shape: 'cone' }));
    expect(cone).toEqual(fixturePixels(tree()));
    for (const p of cone) expect(dist(p)).toBeCloseTo(100 * (1 - ((900 - p.y) / 400) * 0.96), 6);
  });

  it('spreads a sphere’s LEDs evenly along its wire', () => {
    const ball = fixturePixels(tree({ shape: 'sphere', turns: 10, pixels: 400 }));
    const gaps = ball.slice(1).map((p, i) => Math.hypot(p.x - ball[i].x, p.y - ball[i].y, p.z - ball[i].z));
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    // Even along the wire; at the very ends, where the spiral leaves the pole in a tight curve,
    // the straight line between two LEDs is a little shorter than the wire.
    for (const g of gaps.slice(2, -2)) expect(Math.abs(g - mean) / mean).toBeLessThan(0.1);
  });

  it('outlines each shape from the front', () => {
    expect(treeOutline(tree())).toEqual([
      { x: 700, y: 900, z: 300 },
      { x: 800, y: 500, z: 300 },
      { x: 900, y: 900, z: 300 }
    ]);
    expect(treeOutline(tree({ shape: 'cylinder' }))).toHaveLength(4);
    const ball = treeOutline(tree({ shape: 'sphere' }));
    expect(Math.min(...ball.map((p) => p.y))).toBeCloseTo(500);
    expect(Math.max(...ball.map((p) => p.x))).toBeCloseTo(900);
  });
});

describe('semicircles', () => {
  it('puts every LED on the half disc, standing on its straight edge, flat facing the street', () => {
    for (const zigzag of ['down', 'up', 'right', 'left'] as const) {
      const px = fixturePixels(semicircle({ zigzag }));
      expect(px).toHaveLength(120);
      for (const p of px) {
        expect(p.z).toBeCloseTo(40, 9);
        expect(p.y).toBeLessThanOrEqual(800 + 1e-9);
        expect(Math.hypot(p.x - 500, p.y - 800)).toBeLessThanOrEqual(100 + 1e-9);
      }
    }
  });

  it('runs the zigzag from where it is set', () => {
    const down = fixturePixels(semicircle({ zigzag: 'down' }));
    const up = fixturePixels(semicircle({ zigzag: 'up' }));
    const right = fixturePixels(semicircle({ zigzag: 'right' }));
    // Down: LED 0 at the left end of the top row; the first row runs to the right, level.
    expect(down[0].y).toBeLessThan(800 - 85);
    expect(down[0].x).toBeLessThan(500);
    expect(down[1].x).toBeGreaterThan(down[0].x);
    expect(down[1].y).toBeCloseTo(down[0].y, 9);
    // Up: LED 0 at the left end of the bottom row.
    expect(up[0].y).toBeGreaterThan(800 - 10);
    expect(up[0].x).toBeLessThan(410);
    // Right: LED 0 at the foot of the left-most column, going up.
    expect(right[0].x).toBeLessThan(420);
    expect(right[0].y).toBeCloseTo(800, 9);
    expect(right[1].y).toBeLessThan(right[0].y);
    expect(right[1].x).toBeCloseTo(right[0].x, 9);
  });

  it('mirrors one zigzag: left is right seen in a mirror, up is down run backwards', () => {
    const right = fixturePixels(semicircle({ zigzag: 'right' }));
    const left = fixturePixels(semicircle({ zigzag: 'left' }));
    left.forEach((p, i) => {
      expect(p.x).toBeCloseTo(1000 - right[i].x, 9);
      expect(p.y).toBeCloseTo(right[i].y, 9);
    });
    // With an even number of rows the zigzag up is the zigzag down, from its other end.
    const down = fixturePixels(semicircle({ zigzag: 'down' }));
    const up = fixturePixels(semicircle({ zigzag: 'up' }));
    up.forEach((p, i) => {
      expect(p.x).toBeCloseTo(down[119 - i].x, 6);
      expect(p.y).toBeCloseTo(down[119 - i].y, 6);
    });
    // One point at each end of each row.
    expect(zigzagPath({ radius: 100, strands: 5 })).toHaveLength(10);
  });

  it('turns: 90° puts the round side to the right; facing 90 turns it edge-on to the street', () => {
    const turned = fixturePixels(semicircle({ rotation: 90 }));
    for (const p of turned) {
      expect(p.x).toBeGreaterThanOrEqual(500 - 1e-9);
      expect(Math.abs(p.y - 800)).toBeLessThanOrEqual(100 + 1e-9);
    }
    const side = fixturePixels(semicircle({ facing: 90 }));
    for (const p of side) expect(p.x).toBeCloseTo(500, 9);
    expect(Math.max(...side.map((p) => p.z)) - Math.min(...side.map((p) => p.z))).toBeGreaterThan(150);
    // The outline turns with it: the round side, then back along the straight edge.
    const outline = semicircleOutline(semicircle({ rotation: 90 }));
    expect(outline[0]).toEqual(outline.at(-1));
    expect(Math.max(...outline.map((p) => p.x))).toBeCloseTo(600);
  });

  it('can be half an ellipse: its height', () => {
    const px = fixturePixels(semicircle({ height: 50 }));
    expect(Math.min(...px.map((p) => p.y))).toBeGreaterThan(750 - 1e-9);
  });
});

describe('saved layouts with the new settings', () => {
  it('keeps old layouts as they were, and keeps the new settings when saved', () => {
    const old = sampleLayout();
    const parsed = layoutSchema.parse(old);
    expect(parsed).toEqual(old);
    const layout = {
      ...old,
      fixtures: [...old.fixtures, tree({ shape: 'sphere', spin: 'cw', start: 'top', facing: 45, startPixel: 1000 }), semicircle({ zigzag: 'left', rotation: 180, facing: -30, height: 80, startPixel: 2000 })]
    };
    const back = layoutSchema.parse(layout);
    expect(back.fixtures.at(-2)).toMatchObject({ shape: 'sphere', spin: 'cw', start: 'top', facing: 45 });
    expect(back.fixtures.at(-1)).toMatchObject({ kind: 'semicircle', zigzag: 'left', rotation: 180, facing: -30, height: 80, strands: 6 });
    expect(layoutSchema.safeParse({ ...layout, fixtures: [semicircle({ zigzag: 'sideways' as never })] }).success).toBe(false);
    expect(layoutSchema.safeParse({ ...layout, fixtures: [tree({ shape: 'pyramid' as never })] }).success).toBe(false);
  });

  it('puts a semicircle on the stage the games draw on', () => {
    const layout = { ...sampleLayout(), fixtures: [semicircle({ deviceId: null })] };
    const stage = buildStage(layout);
    expect(stage.pixelCount).toBe(120);
    expect(stage.fixtures[0].kind).toBe('semicircle');
  });
});
