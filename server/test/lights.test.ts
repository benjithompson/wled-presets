import { describe, expect, it } from 'vitest';
import { buildStage, designCounts, designLeds, designPaths, fixturePixels, ledRange, resizeSegment, sampleLayout, segmentLeds, type Fixture, type Layout } from '../../shared/layout.ts';
import { BUILT_IN_LIGHTS, ledsForLength, lightsOf, maxAmps, spacingText, strandStarts, strandText, stringLength } from '../../shared/lights.ts';
import { layoutSchema } from '../src/layoutStore.ts';

const nova = BUILT_IN_LIGHTS.find((l) => l.id === 'novabright-bullet-12v-4in')!;

describe('light strings', () => {
  it('know the NovaBright bullet pixels', () => {
    expect(nova).toMatchObject({ chip: 'WS2811', volts: 12, perStrand: 50 });
    expect(spacingText(nova.spacing)).toBe('4 in');
    expect(spacingText(nova.spacing, 'm')).toBe('10.2 cm');
  });

  it('count the LEDs that fit a length, and the strands', () => {
    // 10 ft at 4 in: 30 gaps, so 31 LEDs with one at each end, 30 for a segment.
    const tenFeet = 10 * 0.3048;
    expect(ledsForLength(tenFeet, nova.spacing)).toBe(31);
    expect(ledsForLength(tenFeet, nova.spacing, false)).toBe(30);
    expect(stringLength(51, nova.spacing)).toBeCloseTo(50 * 0.1016);
    expect(strandText(150, 50)).toBe('3 strands of 50');
    expect(strandText(113, 50)).toBe('2 strands of 50 + 13 LEDs');
    expect(strandText(20, 50)).toBe('20 of a strand of 50');
    expect(strandText(300, null)).toBeNull();
    expect(strandStarts(120, 50)).toEqual([50, 100]);
    expect(maxAmps(100, nova)).toBeCloseTo(2.5);
  });

  it('find your own light types before the built-in ones', () => {
    const mine = { ...nova, id: 'mine', name: 'Mine' };
    expect(lightsOf({ lightTypes: [mine] }, 'mine')?.name).toBe('Mine');
    expect(lightsOf({}, 'novabright-bullet-12v-4in')?.name).toBe(nova.name);
    expect(lightsOf({}, 'gone')).toBeNull();
  });
});

describe('segments', () => {
  const roof: Fixture = {
    id: 'r',
    name: 'Roof',
    kind: 'roof',
    points: [
      { x: 0, y: 0 },
      { x: 100, y: 0 },
      { x: 200, y: 0 },
      { x: 300, y: 0 }
    ],
    pixels: 91,
    deviceId: null,
    startPixel: 10,
    reversed: false
  };

  it('resize one segment, and the LEDs after it move along', () => {
    expect(segmentLeds(roof, 1)).toEqual({ lo: 30, hi: 59 });
    const next = { ...roof, ...resizeSegment(roof, 1, 36) };
    expect(next.pixels).toBe(97);
    expect(segmentLeds(next, 0)).toEqual({ lo: 0, hi: 29 });
    expect(segmentLeds(next, 1)).toEqual({ lo: 30, hi: 65 });
    expect(segmentLeds(next, 2)).toEqual({ lo: 66, hi: 96 });
    // The first LED keeps its number.
    expect(ledRange(next).first).toBe(10);
    // The last segment: only the end moves.
    const last = { ...roof, ...resizeSegment(roof, 2, 25) };
    expect(last.pixels).toBe(85);
    expect(segmentLeds(last, 2)).toEqual({ lo: 60, hi: 84 });
  });
});

describe('custom objects', () => {
  const star = [
    {
      closed: true,
      points: [
        { x: 0, y: 1 },
        { x: 1, y: 0 },
        { x: 0, y: -1 },
        { x: -1, y: 0 }
      ]
    }
  ];

  it('spread the LEDs evenly around a closed stroke, and along open ones with both ends lit', () => {
    const leds = designLeds(star, 8);
    expect(leds[0]).toEqual({ x: 0, y: 1 });
    expect(leds[2].x).toBeCloseTo(1);
    // Closed: the last LED is one step before the first, not on it.
    expect(leds[7].x).toBeCloseTo(-0.5);
    const line = designLeds([{ points: [{ x: 0, y: 0 }, { x: 3, y: 0 }] }], 4);
    expect(line.map((p) => p.x)).toEqual([0, 1, 2, 3]);
  });

  it('share LEDs between strokes by length, at one spacing', () => {
    const two = [{ points: [{ x: 0, y: 0 }, { x: 4, y: 0 }] }, { points: [{ x: 0, y: 1 }, { x: 1, y: 1 }] }];
    // 5 m of wire, 7 LEDs: 5 gaps of 1 m, plus one LED at the start of each stroke.
    expect(designCounts(two, 7)).toEqual([5, 2]);
    expect(designCounts(two, 7).reduce((a, b) => a + b)).toBe(7);
    expect(designCounts([], 7)).toEqual([]);
  });

  it('place a design in the yard: sized, turned and facing', () => {
    const f: Fixture = { id: 'c', name: 'Star', kind: 'custom', points: [{ x: 500, y: 400, z: 20 }], design: star, pixels: 4, deviceId: null, startPixel: 0, reversed: false };
    // 80 units per meter; y is down in the yard.
    expect(fixturePixels(f, 80)[0]).toEqual({ x: 500, y: 320, z: 20 });
    expect(fixturePixels({ ...f, size: 2 }, 80)[1]).toEqual({ x: 660, y: 400, z: 20 });
    const turned = fixturePixels({ ...f, rotation: 90 }, 80)[0];
    expect([turned.x, turned.y]).toEqual([580, 400]);
    // Facing right: the design's x runs toward the house (z goes down).
    const side = fixturePixels({ ...f, facing: 90 }, 80)[1];
    expect(side.x).toBeCloseTo(500);
    expect(side.z).toBeCloseTo(-60);
    expect(designPaths(f, 80)[0]).toHaveLength(5);
  });

  it('are saved with the layout, with their library and light types', () => {
    const layout: Layout = sampleLayout();
    const design = { id: 'd1', name: 'Star', strokes: star, pixels: 40, lights: 'mine' };
    const lightTypes = [{ ...nova, id: 'mine', name: 'Mine' }];
    const withCustom: Layout = {
      ...layout,
      lights: 'mine',
      lightTypes,
      designs: [design],
      fixtures: [...layout.fixtures, { id: 'c1', name: 'Star', kind: 'custom', points: [{ x: 800, y: 300 }], design: star, designId: 'd1', size: 1.5, rotation: 10, facing: 90, pixels: 40, lights: 'mine', deviceId: null, startPixel: 0, reversed: false }]
    };
    const parsed = layoutSchema.safeParse(withCustom);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.designs).toEqual([design]);
    expect(parsed.data.lightTypes).toEqual(lightTypes);
    expect(parsed.data.lights).toBe('mine');
    expect(parsed.data.fixtures.at(-1)).toMatchObject({ kind: 'custom', designId: 'd1', size: 1.5, facing: 90, lights: 'mine' });
    const stage = buildStage(parsed.data as Layout);
    expect(stage.fixtures.at(-1)?.count).toBe(40);
    expect(layoutSchema.safeParse({ ...withCustom, lightTypes: [{ ...lightTypes[0], spacing: 0 }] }).success).toBe(false);
  });
});
