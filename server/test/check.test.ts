import { describe, expect, it } from 'vitest';
import { BAND_RGB, checkMoves, currentGuess, paintCheck, PICTURE_RGB, slicePosition, SLICE_HIGH_RGB, SLICE_LOW_RGB, wiringGuesses, type LayoutCheck } from '../../shared/check.ts';
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
  it('colors one object in four blocks as seen from the street, LED 0 blinking white, the rest dark', () => {
    const layout: Layout = { ...sampleLayout(), fixtures: [...sampleLayout().fixtures, tree()] };
    const { stage, out } = paint(layout, { kind: 'picture', id: 'tree' });
    const sf = stage.fixtures.find((f) => f.id === 'tree')!;
    expect(rgb(out, sf.offset)).toEqual(WHITE);
    // Cut at the middle of the LEDs, as seen from the street.
    const xs = Array.from({ length: sf.count }, (_, j) => stage.positions3[(sf.offset + j) * 3]);
    const ys = Array.from({ length: sf.count }, (_, j) => stage.positions3[(sf.offset + j) * 3 + 1]);
    const cx = (Math.min(...xs) + Math.max(...xs)) / 2;
    const cy = (Math.min(...ys) + Math.max(...ys)) / 2;
    const seen = new Set<string>();
    for (let j = 1; j < sf.count; j++) {
      const i = sf.offset + j;
      const right = xs[j] > cx;
      const bottom = ys[j] > cy;
      const want = bottom ? (right ? PICTURE_RGB.bottomRight : PICTURE_RGB.bottomLeft) : right ? PICTURE_RGB.topRight : PICTURE_RGB.topLeft;
      expect(rgb(out, i)).toEqual(want);
      seen.add(String(want));
    }
    expect(seen.size).toBe(4);
    // Everything else is dark.
    for (let i = 0; i < sf.offset; i++) expect(rgb(out, i)).toEqual([0, 0, 0]);
    expect(rgb(paint(layout, { kind: 'picture', id: 'tree' }, 0, false).out, sf.offset)).not.toEqual(WHITE);
  });

  it('cuts a long low line only left and right', () => {
    const layout = sampleLayout();
    const { stage, out } = paint({ ...layout, fixtures: [{ ...layout.fixtures[0], points: [{ x: 100, y: 400 }, { x: 900, y: 410 }] }] }, { kind: 'picture', id: 'roof' });
    expect(rgb(out, 5)).toEqual(PICTURE_RGB.topLeft);
    expect(rgb(out, stage.pixelCount - 5)).toEqual(PICTURE_RGB.topRight);
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
