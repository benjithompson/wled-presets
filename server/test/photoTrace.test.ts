import { describe, expect, it } from 'vitest';
import { designLeds } from '../../shared/layout.ts';
import { autoDots, CODE_RGB, codeDigit, codeDigits, codeFrames, colorfulMaps, decodeDigits, decodeScan, glowMaps, orderByNumber, isLoop, ledStep, orderDots, PHOTO_COLORS, photoDesign, strokesFromOrder, traceDots, type Pixels, type Pt, type RGB } from '../../shared/photoTrace.ts';

const GREEN = PHOTO_COLORS[0];

/** A night photo: dark, a little noise, a lit window, and LEDs that glow (white in the middle). */
function photo(w: number, h: number, leds: { p: Pt; rgb: RGB }[], extras: (img: Pixels) => void = () => {}): Pixels {
  const data = new Uint8ClampedArray(w * h * 4);
  let seed = 7;
  const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  for (let i = 0; i < w * h; i++) {
    const n = 10 + rand() * 14;
    data.set([n, n * 0.9, n * 1.1, 255], i * 4);
  }
  const img = { width: w, height: h, data };
  extras(img);
  for (const { p, rgb } of leds) {
    for (let y = Math.floor(p.y - 6); y <= p.y + 6; y++)
      for (let x = Math.floor(p.x - 6); x <= p.x + 6; x++) {
        if (x < 0 || y < 0 || x >= w || y >= h) continue;
        const d = Math.hypot(x - p.x, y - p.y);
        const i = (y * w + x) * 4;
        if (d < 1.6) data.set([255, 255, 255], i);
        else if (d < 4.5) {
          const k = 1 - (d - 1.6) / 3;
          for (let c = 0; c < 3; c++) data[i + c] = Math.max(data[i + c], (rgb[c] ? 255 : 70) * k * (rgb[c] ? 1 : 0.4) + 20);
        }
      }
  }
  return img;
}

const circle = (n: number, cx: number, cy: number, r: number) => Array.from({ length: n }, (_, i) => ({ x: cx + Math.sin((i / n) * Math.PI * 2) * r, y: cy - Math.cos((i / n) * Math.PI * 2) * r }));

const window = (img: Pixels) => {
  // A lit window: white and yellow, no green.
  for (let y = 10; y < 40; y++) for (let x = 10; x < 50; x++) img.data.set(x < 30 ? [255, 255, 255] : [250, 220, 120], (y * img.width + x) * 4);
};

describe('a custom object from a photo', () => {
  it('finds the lit LEDs and the first one, not the window', () => {
    const pts = circle(30, 200, 150, 100);
    const img = photo(400, 300, pts.map((p, i) => ({ p, rgb: i === 0 ? GREEN.start : GREEN.rgb })), window);
    const { dots } = autoDots(glowMaps(img, GREEN), 30);
    expect(dots).toHaveLength(30);
    const start = dots.filter((d) => d.start);
    expect(start).toHaveLength(1);
    expect(Math.hypot(start[0].x - pts[0].x, start[0].y - pts[0].y)).toBeLessThan(1.5);
    for (const p of pts) expect(Math.min(...dots.map((d) => Math.hypot(d.x - p.x, d.y - p.y)))).toBeLessThan(1.5);
  });

  it('finds them without knowing how many there are', () => {
    const pts = circle(24, 200, 150, 90);
    const img = photo(400, 300, pts.map((p) => ({ p, rgb: GREEN.rgb })), window);
    expect(autoDots(glowMaps(img, GREEN)).dots).toHaveLength(24);
  });

  it('puts the dots in wire order from the first LED, and closes a loop', () => {
    const pts = circle(40, 0, 0, 100);
    const shuffled = pts.map((p, i) => ({ p, i })).sort((a, b) => ((a.i * 7919) % 40) - ((b.i * 7919) % 40));
    const dots = shuffled.map((s) => s.p);
    const order = orderDots(dots, shuffled.findIndex((s) => s.i === 0));
    expect(order).toHaveLength(1);
    const seq = order[0].map((k) => shuffled[k].i);
    // Either way round the loop.
    const forward = seq.every((v, k) => v === k);
    const backward = seq.every((v, k) => v === (40 - k) % 40);
    expect(forward || backward).toBe(true);
    const strokes = strokesFromOrder(dots, order);
    expect(strokes[0].closed).toBe(true);
  });

  it('follows a zigzag without cutting across, and jumps between two parts', () => {
    // An open zigzag, then (after a gap with no LEDs) a short straight run.
    const corners = Array.from({ length: 7 }, (_, k) => ({ x: k * 25, y: k % 2 ? 0 : 120 }));
    const zig: Pt[] = [];
    for (let k = 0; k < corners.length - 1; k++) {
      const a = corners[k];
      const b = corners[k + 1];
      const steps = Math.round(Math.hypot(b.x - a.x, b.y - a.y) / 10);
      for (let i = 0; i < steps; i++) zig.push({ x: a.x + ((b.x - a.x) * i) / steps, y: a.y + ((b.y - a.y) * i) / steps });
    }
    zig.push(corners.at(-1)!);
    const run = Array.from({ length: 8 }, (_, i) => ({ x: 400 + i * 10, y: 300 }));
    const dots = [...zig, ...run];
    const order = orderDots(dots, 0);
    expect(order).toHaveLength(2);
    expect(order[0]).toEqual(zig.map((_, i) => i));
    expect(order[1].map((i) => dots[i].x)).toEqual(run.map((p) => p.x));
    expect(strokesFromOrder(dots, order).some((s) => s.closed)).toBe(false);
  });

  it('collects the dots a finger passes, in that order', () => {
    const dots = [
      { x: 0, y: 0 },
      { x: 50, y: 0 },
      { x: 100, y: 0 },
      { x: 50, y: 50 }
    ];
    // Down the middle, then right along the top: dot 3, then 1, then 2 (dot 0 is off the path).
    const got = traceDots(
      dots,
      [
        { x: 50, y: 60 },
        { x: 50, y: 5 },
        { x: 110, y: 5 }
      ],
      12
    );
    expect(got).toEqual([3, 1, 2]);
    expect(traceDots(dots, [{ x: 50, y: 60 }, { x: 50, y: 5 }], 12, new Set([1]))).toEqual([3]);
  });

  it('turns the traced wire into a design in meters, with the LEDs where the photo has them', () => {
    // 21 LEDs 10 cm apart along a straight line, 20 px apart in the photo.
    const points = Array.from({ length: 21 }, (_, i) => ({ x: 100 + i * 20, y: 200 }));
    const strokes = [{ points, dots: true }];
    expect(ledStep(strokes)).toBe(20);
    const design = photoDesign(strokes, 0.1 / ledStep(strokes));
    // A straight run keeps only its ends, 2 m apart, with the anchor in the middle.
    expect(design).toEqual([{ points: [{ x: -1, y: 0 }, { x: 1, y: 0 }] }]);
    const leds = designLeds(design, 21);
    expect(leds[1].x).toBeCloseTo(-0.9);
    // y is up in a design.
    const up = photoDesign([{ points: [{ x: 0, y: 100 }, { x: 0, y: 0 }], dots: false }], 0.01);
    expect(up[0].points[1].y).toBeGreaterThan(up[0].points[0].y);
    expect(isLoop(circle(10, 0, 0, 50), 31)).toBe(true);
  });

  it('keeps a traced loop closed in the design', () => {
    const pts = circle(36, 0, 0, 100);
    const design = photoDesign([{ points: pts, dots: true, closed: true }], 0.005);
    expect(design[0].closed).toBe(true);
    const r = Math.max(...design[0].points.map((p) => Math.hypot(p.x, p.y)));
    expect(r).toBeCloseTo(0.5, 1);
  });

  it('numbers LEDs with a color code that catches a misread digit', () => {
    expect(codeDigits(2)).toBe(1);
    expect(codeDigits(9)).toBe(2);
    expect(codeDigits(10)).toBe(3);
    expect(codeFrames(300)).toBe(7);
    for (const n of [5, 50, 300]) {
      for (let i = 0; i < n; i++) {
        const digits = Array.from({ length: codeFrames(n) }, (_, f) => codeDigit(i, f, n));
        expect(decodeDigits(digits, n)).toBe(i);
        // One digit read wrong does not give another LED's number.
        for (let f = 0; f < digits.length; f++) expect(decodeDigits(digits.map((d, k) => (k === f ? (d + 1) % 3 : d)), n)).toBeNull();
      }
    }
  });

  it('reads every LED number from camera frames, where the wire crosses itself and the hand shakes', () => {
    // A figure eight: the wire crosses in the middle, so no guess from the shape can be sure.
    // 150 LEDs: the top digit is never 2, so that frame shows no blue at all.
    const n = 150;
    const pts = Array.from({ length: n }, (_, i) => {
      const a = ((i + 0.5) / n) * Math.PI * 2;
      return { x: 400 + Math.sin(a) * 340, y: 250 + Math.sin(2 * a) * 160 };
    });
    const shake = [
      { x: 0, y: 0 },
      { x: 3, y: -2 },
      { x: -2, y: 4 },
      { x: 5, y: 1 },
      { x: -4, y: -3 },
      { x: 2, y: 3 }
    ];
    expect(codeFrames(n)).toBe(shake.length);
    const frames = shake.map((s, f) => photo(800, 500, pts.map((p, i) => ({ p: { x: p.x + s.x, y: p.y + s.y }, rgb: CODE_RGB[codeDigit(i, f, n)] })), window));
    const { dots, threshold } = autoDots(colorfulMaps(frames[0]), n);
    expect(dots).toHaveLength(n);
    const ids = decodeScan(frames, dots, n, threshold);
    for (let k = 0; k < dots.length; k++) {
      const i = ids[k];
      expect(i).not.toBeNull();
      expect(Math.hypot(dots[k].x - pts[i!].x, dots[k].y - pts[i!].y)).toBeLessThan(1.5);
    }
    const order = orderByNumber(dots, ids);
    expect(order).toHaveLength(1);
    expect(order[0].map((k) => ids[k])).toEqual(pts.map((_, i) => i));
  });

  it('starts a new stroke where the numbered LEDs jump, and skips a missing one', () => {
    const dots = [...Array.from({ length: 6 }, (_, i) => ({ x: i * 10, y: 0 })), ...Array.from({ length: 6 }, (_, i) => ({ x: 200 + i * 10, y: 0 }))];
    const ids = dots.map((_, i) => (i === 2 ? null : i));
    const order = orderByNumber(dots, ids);
    expect(order).toEqual([[0, 1, 3, 4, 5], [6, 7, 8, 9, 10, 11]]);
  });
});

