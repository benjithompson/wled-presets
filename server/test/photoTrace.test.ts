import { describe, expect, it } from 'vitest';
import { designLeds } from '../../shared/layout.ts';
import { autoDots, codeColor, codeDigit, codeDigits, codeFrames, decodeDigits, decodeScan, glowMaps, lineUp, orderByNumber, scanDots, isLoop, ledStep, orderDots, PHOTO_COLORS, photoDesign, strokesFromOrder, traceDots, type Pixels, type Pt, type RGB } from '../../shared/photoTrace.ts';

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

  it('numbers LEDs with a color code that catches a misread digit, and every LED changes color', () => {
    expect(codeDigits(2)).toBe(1);
    expect(codeDigits(9)).toBe(2);
    expect(codeDigits(10)).toBe(3);
    expect(codeFrames(300)).toBe(8);
    for (const n of [5, 50, 300]) {
      const d = codeDigits(n);
      for (let i = 0; i < n; i++) {
        const digits = Array.from({ length: d + 1 }, (_, k) => codeDigit(i, k, n));
        expect(decodeDigits(digits, n)).toBe(i);
        // One digit read wrong does not give another LED's number.
        for (let k = 0; k < digits.length; k++) expect(decodeDigits(digits.map((x, j) => (j === k ? (x + 1) % 3 : x)), n)).toBeNull();
        // The first frame is white; after it, no LED keeps one color all through (LED 0 neither).
        const colors = new Set(Array.from({ length: d + 1 }, (_, k) => codeColor(i, k + 1, n).join()));
        expect(colors.size).toBeGreaterThan(1);
      }
    }
  });

  /**
   * The camera's view of a scan in a lit room: a warm lamp, a purple wall, colorful things that
   * look like LEDs but never change, a hand that shakes, and a camera that changes its color
   * balance from frame to frame.
   */
  function room(w: number, h: number, leds: { p: Pt; rgb: RGB }[], shake: Pt, balance: RGB): Pixels {
    const data = new Uint8ClampedArray(w * h * 4);
    let seed = 11;
    const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    const decoys = Array.from({ length: 30 }, (_, k) => ({ x: 40 + ((k * 137) % (w - 80)), y: 30 + ((k * 89) % (h - 60)), rgb: [[255, 40, 40], [40, 255, 60], [60, 60, 255]][k % 3] }));
    for (let y = 0; y < h; y++)
      for (let x = 0; x < w; x++) {
        const sx = x - shake.x;
        const sy = y - shake.y;
        // The lamp lights the room warm; the right part is a purple wall.
        const lamp = 1 - Math.min(1, Math.hypot(sx - 120, sy - 80) / 700);
        let c = sx > w * 0.75 ? [90 + 60 * lamp, 60 + 40 * lamp, 140 + 50 * lamp] : [80 + 120 * lamp, 60 + 90 * lamp, 40 + 50 * lamp];
        for (const d of decoys) {
          const dd = Math.hypot(sx - d.x, sy - d.y);
          if (dd < 5) c = d.rgb.map((v, i) => Math.max(c[i], v * (1 - dd / 6)));
        }
        const n = (rand() - 0.5) * 14;
        data.set([c[0] + n, c[1] + n, c[2] + n, 255], (y * w + x) * 4);
      }
    for (const { p, rgb } of leds) {
      const px = p.x + shake.x;
      const py = p.y + shake.y;
      for (let y = Math.floor(py - 7); y <= py + 7; y++)
        for (let x = Math.floor(px - 7); x <= px + 7; x++) {
          if (x < 0 || y < 0 || x >= w || y >= h) continue;
          const d = Math.hypot(x - px, y - py);
          const i = (y * w + x) * 4;
          const k = Math.max(0, 1 - d / 6);
          for (let c = 0; c < 3; c++) data[i + c] = d < 1.6 ? 255 : data[i + c] + (rgb[c] / 170) * 255 * k;
        }
    }
    for (let i = 0; i < w * h; i++) for (let c = 0; c < 3; c++) data[i * 4 + c] = data[i * 4 + c] * balance[c];
    return { width: w, height: h, data };
  }

  it('reads every LED number in a lit room, where the wire crosses itself and the hand shakes', () => {
    // A figure eight: the wire crosses in the middle, so no guess from the shape can be sure.
    // 150 LEDs: the top digit is never 2.
    const n = 150;
    const curve = Array.from({ length: 2000 }, (_, i) => {
      const a = ((i + 0.5) / 2000) * Math.PI * 2;
      return { x: 400 + Math.sin(a) * 300, y: 250 + Math.sin(2 * a) * 150 };
    });
    // Evenly spaced along the wire, as on a real string.
    const len = curve.slice(1).map((p, i) => Math.hypot(p.x - curve[i].x, p.y - curve[i].y));
    const total = len.reduce((a, b) => a + b, 0);
    const pts: Pt[] = [];
    for (let i = 0, acc = 0, j = 0; i < n; i++) {
      const want = ((i + 0.5) / n) * total;
      while (j < len.length - 1 && acc + len[j] < want) acc += len[j++];
      pts.push(curve[j]);
    }
    const F = codeFrames(n);
    const frames = Array.from({ length: F }, (_, f) =>
      room(
        800,
        500,
        pts.map((p, i) => ({ p, rgb: codeColor(i, f, n) })),
        { x: Math.round(Math.sin(f * 1.7) * 4), y: Math.round(Math.cos(f * 2.3) * 4) },
        [1 + Math.sin(f) * 0.12, 1 + Math.cos(f * 1.3) * 0.08, 1 - Math.sin(f * 0.7) * 0.12]
      )
    );
    const lined = lineUp(frames, n);
    const { dots } = scanDots(lined, n);
    expect(dots).toHaveLength(n);
    const ids = decodeScan(lined, dots, n);
    // Dots are in frame 1's place. Every number read is right; at most one or two (where the
    // wire crosses) are not read.
    const s1 = { x: Math.round(Math.sin(1.7) * 4), y: Math.round(Math.cos(2.3) * 4) };
    expect(ids.filter((i) => i == null).length).toBeLessThanOrEqual(2);
    for (let k = 0; k < dots.length; k++) {
      const i = ids[k];
      if (i != null) expect(Math.hypot(dots[k].x - pts[i].x - s1.x, dots[k].y - pts[i].y - s1.y)).toBeLessThan(1.5);
    }
    const order = orderByNumber(dots, ids);
    expect(order).toHaveLength(1);
    expect(order[0].map((k) => ids[k])).toEqual(ids.filter((i) => i != null).sort((a, b) => a! - b!));
  });

  it('starts a new stroke where the numbered LEDs jump, and skips a missing one', () => {
    const dots = [...Array.from({ length: 6 }, (_, i) => ({ x: i * 10, y: 0 })), ...Array.from({ length: 6 }, (_, i) => ({ x: 200 + i * 10, y: 0 }))];
    const ids = dots.map((_, i) => (i === 2 ? null : i));
    const order = orderByNumber(dots, ids);
    expect(order).toEqual([[0, 1, 3, 4, 5], [6, 7, 8, 9, 10, 11]]);
  });
});

