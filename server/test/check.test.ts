import { describe, expect, it } from 'vitest';
import { BAND_RGB, HALF_RGB, STRING_RGB, checkMoves, currentGuess, paintCheck, pictureBlocks, pictureCut, PICTURE_RGB, slicePosition, SLICE_HIGH_RGB, SLICE_LOW_RGB, wiringGuesses, type LayoutCheck } from '../../shared/check.ts';
import { buildStage, fromLedRange, sampleLayout, type Fixture, type Layout } from '../../shared/layout.ts';
import { previewFrame } from '../src/layoutPreview.ts';

const rgb = (f: Uint8Array, i: number) => Array.from(f.subarray(i * 3, i * 3 + 3));
const WHITE = [255, 255, 255];

const tree = (patch: Partial<Fixture> = {}): Fixture => ({
  id: 'tree',
  name: 'Tree',
  kind: 'tree',
  points: [{ x: 800, y: 800, z: 200 }],
  radius: 80,
  height: 240,
  pattern: 'spiral',
  turns: 6,
  pixels: 200,
  deviceId: 'd',
  startPixel: 0,
  reversed: false,
  ...patch
});

const paint = (layout: Layout, check: LayoutCheck, now = 0, pulse = true) => {
  const stage = buildStage(layout);
  const out = new Uint8Array(stage.pixelCount * 3);
  paintCheck(layout, stage, check, now, pulse, out);
  return { stage, out };
};

describe('slice', () => {
  it('lights the LEDs in the slice white, and the two sides in their colors', () => {
    const layout = sampleLayout();
    const { stage, out } = paint(layout, { kind: 'slice', axis: 'x', at: 800 });
    const half = 0.15 * stage.scale;
    let white = 0;
    for (let i = 0; i < stage.pixelCount; i++) {
      const x = stage.positions3[i * 3];
      if (Math.abs(x - 800) <= half) {
        expect(rgb(out, i)).toEqual(WHITE);
        white++;
      } else if (x < 800 - half * 3) expect(rgb(out, i)).toEqual(SLICE_LOW_RGB);
      else if (x > 800 + half * 3) expect(rgb(out, i)).toEqual(SLICE_HIGH_RGB);
    }
    // The roof's peak and the middle bush are under it.
    expect(white).toBeGreaterThan(3);
  });

  it('sweeps across the LEDs of the yard and back, on the wall clock', () => {
    const layout = sampleLayout();
    const stage = buildStage(layout);
    const check = { kind: 'slice', axis: 'x', at: null } as const;
    expect(checkMoves(check)).toBe(true);
    expect(checkMoves({ ...check, at: 10 })).toBe(false);
    const xs = Array.from({ length: 200 }, (_, i) => slicePosition(stage, check, i * 100));
    // From before the leftmost LED (220) to past the rightmost (1380).
    expect(Math.min(...xs)).toBeLessThan(220);
    expect(Math.max(...xs)).toBeGreaterThan(1380);
    expect(slicePosition(stage, check, 123_456)).toBeCloseTo(slicePosition(stage, check, 123_456));
  });

  it('reaches the real lights, moving with the time the frame shows', () => {
    const layout = sampleLayout();
    layout.fixtures[0] = { ...layout.fixtures[0], deviceId: 'd', ...fromLedRange(0, 449) };
    const req = { layout, selected: null, corner: null, check: { kind: 'slice', axis: 'y', at: 470 } as LayoutCheck };
    const f = previewFrame(req, 'd', 450, true);
    // The eaves (y 470) are in the slice; the peak (LED ~225, y 250) is above it.
    expect(rgb(f, 0)).toEqual(WHITE);
    expect(rgb(f, 449)).toEqual(WHITE);
    expect(rgb(f, 225)).toEqual(SLICE_LOW_RGB);
    const sweep = { ...req, check: { kind: 'slice', axis: 'x', at: null } as LayoutCheck };
    expect(previewFrame(sweep, 'd', 450, true, 1000)).not.toEqual(previewFrame(sweep, 'd', 450, true, 3000));
  });
});

describe('ruler', () => {
  it('colors bands of height from the ground up', () => {
    const layout: Layout = { ...sampleLayout(), groundY: 900 };
    const { stage, out } = paint(layout, { kind: 'bands', axis: 'y', step: 80 });
    for (let i = 0; i < stage.pixelCount; i++) {
      const height = 900 - stage.positions3[i * 3 + 1];
      expect(rgb(out, i)).toEqual(BAND_RGB[Math.floor(height / 80) % 4]);
    }
  });
});

describe('color test', () => {
  it('colors one object in eight blocks: left and right, top and bottom, street side and house side, LED 0 blinking white, the rest dark', () => {
    const layout: Layout = { ...sampleLayout(), fixtures: [...sampleLayout().fixtures, tree()] };
    const { stage, out } = paint(layout, { kind: 'picture', id: 'tree' });
    const sf = stage.fixtures.find((f) => f.id === 'tree')!;
    expect(rgb(out, sf.offset)).toEqual(WHITE);
    // Cut at the middle of the LEDs along each axis.
    const axis = (a: number) => Array.from({ length: sf.count }, (_, j) => stage.positions3[(sf.offset + j) * 3 + a]);
    const mid = (v: number[]) => (Math.min(...v) + Math.max(...v)) / 2;
    const [xs, ys, zs] = [axis(0), axis(1), axis(2)];
    const [cx, cy, cz] = [mid(xs), mid(ys), mid(zs)];
    const seen = new Set<string>();
    for (let j = 1; j < sf.count; j++) {
      const side = zs[j] < cz ? PICTURE_RGB.back : PICTURE_RGB.front;
      const right = xs[j] > cx;
      const bottom = ys[j] > cy;
      const want = bottom ? (right ? side.bottomRight : side.bottomLeft) : right ? side.topRight : side.topLeft;
      expect(rgb(out, sf.offset + j)).toEqual(want);
      seen.add(String(want));
    }
    expect(seen.size).toBe(8);
    // Everything else is dark.
    for (let i = 0; i < sf.offset; i++) expect(rgb(out, i)).toEqual([0, 0, 0]);
    expect(rgb(paint(layout, { kind: 'picture', id: 'tree' }, 0, false).out, sf.offset)).not.toEqual(WHITE);
  });

  it('colors one object in two halves along the axis asked for: left and right, top and bottom, or street side and house side', () => {
    const layout: Layout = { ...sampleLayout(), fixtures: [...sampleLayout().fixtures, tree()] };
    for (const [split, a] of [['x', 0], ['y', 1], ['z', 2]] as const) {
      const { stage, out } = paint(layout, { kind: 'picture', id: 'tree', split });
      const sf = stage.fixtures.find((f) => f.id === 'tree')!;
      const vs = Array.from({ length: sf.count }, (_, j) => stage.positions3[(sf.offset + j) * 3 + a]);
      const mid = (Math.min(...vs) + Math.max(...vs)) / 2;
      const seen = new Set<string>();
      for (let j = 1; j < sf.count; j++) {
        // The second half: the right, the bottom (y counts down), the house side (z toward the street).
        const second = a === 2 ? vs[j] < mid : vs[j] > mid;
        expect(rgb(out, sf.offset + j)).toEqual(HALF_RGB[second ? 1 : 0]);
        seen.add(String(rgb(out, sf.offset + j)));
      }
      expect(seen.size).toBe(2);
      expect(rgb(out, sf.offset)).toEqual(WHITE);
    }
  });

  it('cuts a long low line left and right when asked for halves it does not have', () => {
    const layout = sampleLayout();
    const flat: Layout = { ...layout, fixtures: [{ ...layout.fixtures[0], points: [{ x: 100, y: 400 }, { x: 900, y: 410 }] }] };
    const stage = buildStage(flat);
    const blocks = pictureBlocks(stage, 'roof')!;
    expect(pictureCut(blocks, 'y')).toBe('x');
    expect(pictureCut(blocks, 'z')).toBe('x');
    expect(pictureCut(blocks, 'all')).toBe('all');
    const { out } = paint(flat, { kind: 'picture', id: 'roof', split: 'y' });
    expect(rgb(out, 5)).toEqual(HALF_RGB[0]);
    expect(rgb(out, stage.pixelCount - 5)).toEqual(HALF_RGB[1]);
  });

  it('has eight different colors', () => {
    const all = [PICTURE_RGB.front, PICTURE_RGB.back].flatMap((s) => [s.topLeft, s.topRight, s.bottomLeft, s.bottomRight]).map(String);
    expect(new Set(all).size).toBe(8);
  });

  it('cuts a long low line only left and right', () => {
    const layout = sampleLayout();
    const { stage, out } = paint({ ...layout, fixtures: [{ ...layout.fixtures[0], points: [{ x: 100, y: 400 }, { x: 900, y: 410 }] }] }, { kind: 'picture', id: 'roof' });
    expect(rgb(out, 5)).toEqual(PICTURE_RGB.front.topLeft);
    expect(rgb(out, stage.pixelCount - 5)).toEqual(PICTURE_RGB.front.topRight);
  });

  it('shows on the house in the order of the device: the wrong wiring shows other colors', () => {
    // The real string winds clockwise; the drawing says counterclockwise.
    const drawn: Layout = { ...sampleLayout(), fixtures: [tree()] };
    const real: Layout = { ...sampleLayout(), fixtures: [tree({ spin: 'cw' })] };
    const check: LayoutCheck = { kind: 'picture', id: 'tree' };
    const wrong = previewFrame({ layout: drawn, selected: 'tree', corner: null, check }, 'd', 200, true);
    const right = previewFrame({ layout: real, selected: 'tree', corner: null, check }, 'd', 200, true);
    let differ = 0;
    for (let i = 0; i < 200; i++) if (String(rgb(wrong, i)) !== String(rgb(right, i))) differ++;
    expect(differ).toBeGreaterThan(50);
  });
});

describe('strings', () => {
  const lineOf = (patch: Partial<Fixture> = {}): Fixture => ({
    id: 'l',
    name: 'Fence',
    kind: 'line',
    points: [
      { x: 100, y: 800 },
      { x: 900, y: 800 }
    ],
    pixels: 120,
    lights: 'novabright-bullet-12v-4in',
    deviceId: 'd',
    startPixel: 0,
    reversed: false,
    ...patch
  });

  it('colors each string of 50, its first LED blinking white and its last LED white', () => {
    const layout: Layout = { ...sampleLayout(), fixtures: [lineOf()] };
    const { out } = paint(layout, { kind: 'strings', id: 'l' });
    expect(rgb(out, 0)).toEqual(WHITE);
    expect(rgb(paint(layout, { kind: 'strings', id: 'l' }, 0, false).out, 0)).toEqual([0, 0, 0]);
    expect(rgb(out, 10)).toEqual(STRING_RGB[0]);
    expect(rgb(out, 49)).toEqual(WHITE);
    expect(rgb(out, 50)).toEqual(WHITE);
    expect(rgb(out, 60)).toEqual(STRING_RGB[1]);
    expect(rgb(out, 110)).toEqual(STRING_RGB[2]);
  });

  it('follows the strings set by hand, in the order of the device LEDs, across every object', () => {
    const layout: Layout = {
      ...sampleLayout(),
      fixtures: [lineOf({ reversed: true, stringBreaks: [30] }), { ...lineOf(), id: 'm', name: 'Path', pixels: 20, startPixel: 120 }]
    };
    const { stage, out } = paint(layout, { kind: 'strings', id: null });
    // Counting down: the first string (device LEDs 0–29) is at the end of the drawn line.
    expect(rgb(out, 100)).toEqual(STRING_RGB[0]);
    expect(rgb(out, 50)).toEqual(STRING_RGB[1]);
    // The next object goes on with the next color.
    const m = stage.fixtures.find((f) => f.id === 'm')!;
    expect(rgb(out, m.offset + 5)).toEqual(STRING_RGB[2]);
  });
});

describe('chase', () => {
  it('runs one white light along the wire from LED 0', () => {
    const layout: Layout = { ...sampleLayout(), fixtures: [tree()] };
    const heads = [0, 500, 1000, 2000].map((t) => {
      const { out } = paint(layout, { kind: 'chase', id: 'tree' }, t);
      const lit = Array.from({ length: 200 }, (_, i) => i).filter((i) => String(rgb(out, i)) === String(WHITE));
      expect(lit.length).toBeLessThanOrEqual(1);
      return lit[0] ?? -1;
    });
    expect(heads[0]).toBe(0);
    expect(heads[1]).toBeGreaterThan(heads[0]);
    expect(heads[2]).toBeGreaterThan(heads[1]);
    expect(checkMoves({ kind: 'chase', id: 'tree' })).toBe(true);
  });
});

describe('ways the string can run', () => {
  it('lists each way once, and finds the one the object is set to', () => {
    const t = tree();
    const g = wiringGuesses(t);
    expect(g.map((x) => x.label)).toHaveLength(4);
    expect(currentGuess(t, g)).toBe(0);
    expect(currentGuess(tree({ start: 'top', spin: 'cw' }), g)).toBe(3);
    // Strands: going round either way, from either end.
    expect(wiringGuesses(tree({ pattern: 'strands', strands: 8 }))).toHaveLength(4);
    // A line: from either end.
    expect(wiringGuesses(sampleLayout().fixtures[0])).toHaveLength(2);
  });

  it('drops ways that light the house the same: an even zigzag from the other end is the zigzag the other way up', () => {
    const semi = (rows: number, patch: Partial<Fixture> = {}): Fixture => ({
      id: 's',
      name: 'Sun',
      kind: 'semicircle',
      points: [{ x: 400, y: 800 }],
      radius: 100,
      strands: rows,
      pixels: 160,
      deviceId: null,
      startPixel: 0,
      reversed: false,
      ...patch
    });
    expect(wiringGuesses(semi(8))).toHaveLength(4);
    expect(wiringGuesses(semi(7))).toHaveLength(8);
    // Set to "rows from the bottom up, from the other end": the same as rows from the top down.
    const g = wiringGuesses(semi(8));
    expect(currentGuess(semi(8, { zigzag: 'up', reversed: true }), g)).toBe(0);
  });
});
