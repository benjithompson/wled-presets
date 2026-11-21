import { describe, expect, it } from 'vitest';
import { fixturePixels, wavePasses, type Fixture } from '../../shared/layout.ts';
import { currentGuess, wiringGuesses } from '../../shared/check.ts';
import { layoutSchema } from '../src/layoutStore.ts';
import { sampleLayout } from '../../shared/layout.ts';

const tree = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 't',
  name: 'Tree',
  kind: 'tree',
  points: [{ x: 800, y: 800, z: 200 }],
  radius: 80,
  height: 240,
  shape: 'cylinder',
  pattern: 'wave',
  pixels: 300,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});
/** Degrees around the tree from its front (+ to the right, as seen from the street), and the height from the base. */
const where = (p: { x: number; y: number; z: number }) => ({ angle: (Math.atan2(p.x - 800, p.z - 200) * 180) / Math.PI, up: 800 - p.y });

describe('a tree with a wave', () => {
  it('winds back and forth over its front in level passes, from the left at the base up to the top', () => {
    const px = fixturePixels(tree()).map(where);
    expect(px[0].up).toBeCloseTo(0, 0);
    expect(px[0].angle).toBeCloseTo(-90, 0);
    expect(px.at(-1)!.up).toBeCloseTo(240, 0);
    // 8 passes: it ends on the side it started on.
    expect(px.at(-1)!.angle).toBeCloseTo(-90, 0);
    // Never further round than half the sweep, and it never goes back down.
    for (const p of px) expect(Math.abs(p.angle)).toBeLessThanOrEqual(90.5);
    for (let i = 1; i < px.length; i++) expect(px[i].up).toBeGreaterThanOrEqual(px[i - 1].up - 1e-6);
    // It crosses the front 8 times.
    let crossings = 0;
    for (let i = 1; i < px.length; i++) if (Math.sign(px[i].angle) !== Math.sign(px[i - 1].angle)) crossings++;
    expect(crossings).toBe(8);
  });

  it('spreads its LEDs evenly along the wire, and turns in round bends, not sharp corners', () => {
    const px = fixturePixels(tree());
    const gaps = px.slice(1).map((p, i) => Math.hypot(p.x - px[i].x, p.y - px[i].y, p.z - px[i].z));
    expect(Math.max(...gaps) / Math.min(...gaps)).toBeLessThan(1.1);
    // The wire never turns more than about 35° from one LED to the next.
    let sharpest = 0;
    for (let i = 1; i < px.length - 1; i++) {
      const a = [px[i].x - px[i - 1].x, px[i].y - px[i - 1].y, px[i].z - px[i - 1].z];
      const b = [px[i + 1].x - px[i].x, px[i + 1].y - px[i].y, px[i + 1].z - px[i].z];
      const cos = (a[0] * b[0] + a[1] * b[1] + a[2] * b[2]) / (Math.hypot(...a) * Math.hypot(...b));
      sharpest = Math.max(sharpest, (Math.acos(Math.min(1, cos)) * 180) / Math.PI);
    }
    expect(sharpest).toBeLessThan(35);
  });

  it('takes its sweep, its spacing, its start and its sides', () => {
    const wide = fixturePixels(tree({ sweep: 300 })).map(where);
    expect(Math.max(...wide.map((p) => Math.abs(p.angle)))).toBeGreaterThan(145);
    expect(wavePasses(tree({ spacing: 48 })).passes).toBe(6);
    // From the right, at the top.
    const top = fixturePixels(tree({ start: 'top', startSide: 'right' })).map(where);
    expect(top[0].up).toBeCloseTo(240, 0);
    expect(top[0].angle).toBeCloseTo(90, 0);
    // Ending on the other side takes one pass more (or less).
    const p = wavePasses(tree({ spacing: 48, endSide: 'right' }));
    expect(p.passes % 2).toBe(1);
    expect(Math.abs(p.passes - 6)).toBe(1);
    expect(where(fixturePixels(tree({ spacing: 48, endSide: 'right' })).at(-1)!).angle).toBeCloseTo(90, 0);
    // The way a spiral winds does not mirror a wave.
    expect(fixturePixels(tree({ spin: 'cw' }))).toEqual(fixturePixels(tree()));
  });

  it('can be tried each way round with the same passes, and saves', () => {
    const t = tree({ spacing: 48 });
    const g = wiringGuesses(t);
    expect(g).toHaveLength(4);
    expect(currentGuess(t, g)).toBe(0);
    for (const x of g) expect(wavePasses({ ...t, ...x.patch }).passes).toBe(6);
    expect(layoutSchema.safeParse({ ...sampleLayout(), fixtures: [t, tree({ id: 'u', sweep: 270, startSide: 'right', endSide: 'left' })] }).success).toBe(true);
  });
});

describe('a ball with LEDs on its top only (an upside-down bowl)', () => {
  const bowl = (patch: Partial<Fixture> = {}) => tree({ shape: 'sphere', pattern: 'spiral', radius: 120, height: 120, cover: 90, turns: 6, ...patch });

  it('spirals over the cap only, from its outside edge in to the middle', () => {
    const px = fixturePixels(bowl());
    // The cap of a ball 120 tall: its top half, from 60 up to 120.
    for (const p of px) expect(800 - p.y).toBeGreaterThanOrEqual(60 - 1e-6);
    expect(800 - px[0].y).toBeCloseTo(60, 0);
    expect(Math.hypot(px[0].x - 800, px[0].z - 200)).toBeCloseTo(120, 0);
    expect(800 - px.at(-1)!.y).toBeCloseTo(120, 0);
    expect(Math.hypot(px.at(-1)!.x - 800, px.at(-1)!.z - 200)).toBeLessThan(5);
    const gaps = px.slice(1).map((p, i) => Math.hypot(p.x - px[i].x, p.y - px[i].y, p.z - px[i].z));
    expect(Math.max(...gaps) / Math.min(...gaps)).toBeLessThan(1.25);
  });

  it('starts in the middle when it starts at the top, and winds either way', () => {
    const inside = fixturePixels(bowl({ start: 'top' }));
    expect(Math.hypot(inside[0].x - 800, inside[0].z - 200)).toBeLessThan(5);
    expect(Math.hypot(inside.at(-1)!.x - 800, inside.at(-1)!.z - 200)).toBeCloseTo(120, 0);
    // Clockwise mirrors it left to right.
    const ccw = fixturePixels(bowl());
    const cw = fixturePixels(bowl({ spin: 'cw' }));
    for (let i = 0; i < ccw.length; i += 17) expect(cw[i].x - 800).toBeCloseTo(-(ccw[i].x - 800), 6);
  });

  it('a flatter ball makes a flatter bowl; all of it without a cover; and it saves', () => {
    const flat = fixturePixels(bowl({ height: 60 }));
    expect(Math.max(...flat.map((p) => 800 - p.y))).toBeCloseTo(60, 0);
    expect(Math.min(...flat.map((p) => 800 - p.y))).toBeCloseTo(30, 0);
    const whole = fixturePixels(bowl({ cover: undefined }));
    expect(Math.min(...whole.map((p) => 800 - p.y))).toBeLessThan(1);
    expect(layoutSchema.safeParse({ ...sampleLayout(), fixtures: [bowl()] }).success).toBe(true);
  });
});
