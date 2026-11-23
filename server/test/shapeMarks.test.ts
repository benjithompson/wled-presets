import { describe, expect, it } from 'vitest';
import { fixturePixels, ledGap, shapePlaces, validMarks, type Fixture, type ShapeMark } from '../../shared/layout.ts';
import { fitString, keepStrings } from '../../shared/stringFit.ts';
import { layoutShape } from '../../server/src/layoutStore.ts';
import { sampleLayout } from '../../shared/layout.ts';

const tree = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 't',
  name: 'Ball',
  kind: 'tree',
  points: [{ x: 800, y: 800, z: 200 }],
  radius: 80,
  height: 160,
  shape: 'sphere',
  cover: 90,
  pattern: 'spiral',
  turns: 6,
  pixels: 200,
  deviceId: null,
  startPixel: 0,
  reversed: false,
  ...patch
});

/** Degrees from a to b, the nearer way. */
const turn = (a: number, b: number) => ((((b - a + 180) % 360) + 360) % 360) - 180;

describe('a tree shaped to the lights', () => {
  it('puts each marked LED where it was seen', () => {
    const marks: ShapeMark[] = [
      { led: 0, angle: -135, height: 0.05 },
      { led: 60, angle: 90, height: 0.3 },
      { led: 120, angle: 180, height: 0.6 },
      { led: 199, angle: 30, height: 1 }
    ];
    const places = shapePlaces(tree({ marks }));
    for (const m of marks) {
      expect(places[m.led].height).toBeCloseTo(m.height!, 2);
      // The very top of a ball has no angle to speak of.
      if (m.height! < 1) expect(Math.abs(turn(places[m.led].angle, m.angle))).toBeLessThan(0.5);
    }
  });

  it('changes nothing much when the marks are where the pattern has them', () => {
    const plain = tree();
    const at = shapePlaces(plain);
    const marks = [0, 50, 100, 150, 199].map((led) => ({ led, angle: at[led].angle, height: at[led].height }));
    const a = fixturePixels(plain);
    const b = fixturePixels(tree({ marks }));
    const worst = Math.max(...a.map((p, i) => Math.hypot(p.x - b[i].x, p.y - b[i].y, p.z - b[i].z)));
    expect(worst).toBeLessThan(0.5);
  });

  it('goes round the way the spiral winds between quarter-turn marks', () => {
    // Front, right, back, left, front: a turn in four quarters, then the pattern goes on.
    const marks = ['0', '90', '180', '-90', '0'].map((a, k) => ({ led: 10 + k * 8, angle: Number(a), height: 0.1 + k * 0.05 }));
    const places = shapePlaces(tree({ marks }));
    for (let k = 0; k < 4; k++) {
      const steps = Array.from({ length: 8 }, (_, i) => turn(places[10 + k * 8 + i].angle, places[10 + k * 8 + i + 1].angle));
      expect(steps.every((s) => s > 0 && s < 30)).toBe(true);
    }
    // Clockwise: the other way round.
    const cw = shapePlaces(tree({ spin: 'cw', marks: [0, -90, 180, 90].map((angle, k) => ({ led: 10 + k * 8, angle, height: 0.2 })) }));
    expect(turn(cw[10].angle, cw[11].angle)).toBeLessThan(0);
  });

  it('goes round as often as the spiral would between marks far apart', () => {
    const turns = (places: { angle: number }[]) => {
      let total = 0;
      for (let i = 0; i < 100; i++) total += turn(places[i].angle, places[i + 1].angle);
      return total / 360;
    };
    const plain = turns(shapePlaces(tree()));
    // A quarter turn later than the pattern has it, at LED 100.
    const at = shapePlaces(tree());
    const marked = turns(shapePlaces(tree({ marks: [{ led: 0, angle: at[0].angle, height: 0 }, { led: 100, angle: at[100].angle + 90, height: at[100].height }] })));
    expect(marked - plain).toBeCloseTo(0.25, 1);
  });

  it('a wave goes straight across between its sides', () => {
    const marks = [
      { led: 20, angle: -80, height: 0.1 },
      { led: 45, angle: 85, height: 0.25 },
      { led: 70, angle: -75, height: 0.4 }
    ];
    const places = shapePlaces(tree({ pattern: 'wave', shape: undefined, cover: undefined, marks }));
    for (let i = 20; i <= 70; i++) expect(Math.abs(places[i].angle)).toBeLessThanOrEqual(86);
    expect(places[32].angle).toBeGreaterThan(-80);
    expect(places[32].angle).toBeLessThan(85);
  });

  it('measures the marked wire, and the turns no longer come from the string', () => {
    const marked = tree({ lights: 'novabright-bullet-12v-4in', marks: [{ led: 0, angle: 0, height: 0 }, { led: 199, angle: 0, height: 1 }] });
    expect(ledGap(marked)).not.toBeCloseTo(ledGap(tree())!, 3);
    expect(fitString(marked, sampleLayout())).toBe(marked);
  });

  it('keeps marks that make sense: one per LED, within the LEDs', () => {
    expect(validMarks({ pixels: 10, marks: [{ led: 12, angle: 0, height: 0 }, { led: 3, angle: 0, height: 0 }, { led: 3, angle: 90, height: 0 }, { led: 1, angle: 0, height: 0 }] }).map((m) => m.led)).toEqual([1, 3]);
    // Strands do not take marks.
    const strands = tree({ pattern: 'strands', marks: [{ led: 5, angle: 180, height: 0.5 }] });
    expect(fixturePixels(strands)).toEqual(fixturePixels(tree({ pattern: 'strands' })));
  });

  it('moves a marked LED by hand anywhere, off the shape, and the LEDs between move along', () => {
    const marks: ShapeMark[] = [
      { led: 40, angle: 90, height: 0.2 },
      { led: 80, angle: 180, height: 0.4, offset: { x: 0, y: 10, z: -20 } }
    ];
    const on = fixturePixels(tree({ marks: marks.map(({ offset: _o, ...m }) => m) }));
    const off = fixturePixels(tree({ marks }));
    // Up 10 (y counts down on the picture) and 20 toward the house, as the tree faces the street.
    expect(off[80].x - on[80].x).toBeCloseTo(0, 6);
    expect(off[80].y - on[80].y).toBeCloseTo(-10, 6);
    expect(off[80].z - on[80].z).toBeCloseTo(-20, 6);
    // Halfway from the unmoved mark: half the move.
    expect(off[60].z - on[60].z).toBeCloseTo(-10, 6);
    expect(off[40]).toEqual(on[40]);
    // After the last mark the pattern takes over again, unmoved, by the end.
    expect(off[199]).toEqual(on[199]);
    expect(shapePlaces(tree({ marks }))[60].offset).toEqual({ x: 0, y: 5, z: -10 });
  });

  it('turns the move with the tree', () => {
    // Facing right (90): its own right is toward the house.
    const marks: ShapeMark[] = [{ led: 50, angle: 0, height: 0.3, offset: { x: 10, y: 0, z: 0 } }];
    const plain = fixturePixels(tree({ facing: 90, marks: [{ led: 50, angle: 0, height: 0.3 }] }))[50];
    const moved = fixturePixels(tree({ facing: 90, marks }))[50];
    expect(moved.x - plain.x).toBeCloseTo(0, 6);
    expect(moved.z - plain.z).toBeCloseTo(-10, 6);
  });

  describe('a wave in rows', () => {
    // Starts at the left, turns at the right after 30 LEDs, at the left after 20 more, ends at the right.
    const wave = (patch: Partial<Fixture> = {}) =>
      tree({
        pattern: 'wave',
        shape: undefined,
        cover: undefined,
        pixels: 100,
        radius: 100,
        height: 300,
        marks: [
          { led: 0, angle: -90 },
          { led: 30, angle: 90 },
          { led: 50, angle: -90 },
          { led: 99, angle: 90 }
        ],
        ...patch
      });
    /** How far the LED is from the tree's axis. */
    const out = (f: Fixture, led: number) => {
      const p = fixturePixels(f)[led];
      return Math.hypot(p.x - 800, p.z - 200);
    };

    it('makes each row as wide as its LEDs: fewer LEDs, a narrower row; the widest at the radius', () => {
      const f = wave();
      // The middle of each row, away from the bends.
      expect(out(f, 75)).toBeCloseTo(100, 3);
      expect(out(f, 40)).toBeCloseTo((100 * 20) / 49, 3);
      expect(out(f, 15)).toBeCloseTo((100 * 30) / 49, 3);
    });

    it('puts the rows evenly apart up the tree, unless a turn has its height set', () => {
      const at = shapePlaces(wave());
      // Three rows: at the base, halfway, at the top; the turns between them.
      expect(at[15].height).toBeCloseTo(0, 2);
      expect(at[40].height).toBeCloseTo(0.5, 2);
      expect(at[75].height).toBeCloseTo(1, 2);
      expect(at[30].height).toBeCloseTo(0.25, 2);
      const set = shapePlaces(wave({ marks: [{ led: 0, angle: -90 }, { led: 30, angle: 90, height: 0.5 }, { led: 50, angle: -90 }, { led: 99, angle: 90 }] }));
      expect(set[30].height).toBeCloseTo(0.5, 2);
    });

    it('gets its size from the string when its marks change, and keeps a size set by hand', () => {
      const layout = (f: Fixture) => ({ ...sampleLayout(), scale: 80, fixtures: [f] });
      const f = wave({ lights: 'novabright-bullet-12v-4in' });
      const fitted = keepStrings(layout(wave({ lights: 'novabright-bullet-12v-4in', marks: undefined })), layout(f)).layout.fixtures[0];
      // 49 LEDs 4 in apart round half the tree: radius about 49 * 0.1016 m / pi.
      expect(fitted.radius! / 80).toBeCloseTo((49 * 0.1016) / Math.PI, 0);
      const bigger = { ...fitted, radius: fitted.radius! + 40 };
      expect(keepStrings(layout(fitted), layout(bigger)).layout.fixtures[0].radius).toBe(bigger.radius);
    });
  });

  it('saves with the layout', () => {
    const l = { ...sampleLayout(), fixtures: [tree({ marks: [{ led: 3, angle: -90, height: 0.4 }] })] };
    expect(layoutShape.safeParse(l).success).toBe(true);
    expect(layoutShape.safeParse({ ...l, fixtures: [tree({ marks: [{ led: 3, angle: -90, height: 0.4, offset: { x: 1, y: -2, z: 30 } }] })] }).success).toBe(true);
    expect(layoutShape.safeParse({ ...l, fixtures: [tree({ marks: [{ led: 3, angle: -90, height: 2 }] })] }).success).toBe(false);
  });
});
