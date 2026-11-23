import { describe, expect, it } from 'vitest';
import { ellipsePolygon, pickAt, type PickShape } from '../../web/src/yard/pick.ts';
import { frameCam, lerpCam, viewBoxOf } from '../../web/src/yard/camera.ts';

const roof: PickShape = { id: 'roof', line: true, wire: [[{ u: 0, v: 100 }, { u: 200, v: 0 }, { u: 400, v: 100 }]] };
// A big arch whose box covers a bush, drawn on top of it (later in the list).
const bush: PickShape = { id: 'bush', wire: [], leds: [195, 300, 205, 300], area: ellipsePolygon({ u: 200, v: 300 }, 20, 15) };
const arch: PickShape = {
  id: 'arch',
  wire: [[{ u: 100, v: 400 }, { u: 200, v: 200 }, { u: 300, v: 400 }]],
  area: [{ u: 100, v: 200 }, { u: 300, v: 200 }, { u: 300, v: 400 }, { u: 100, v: 400 }]
};

describe('picking in a 2D view', () => {
  it('picks the segment of a line nearest the pointer', () => {
    expect(pickAt([roof], { u: 300, v: 52 }, 10)).toEqual({ id: 'roof', seg: 1 });
    expect(pickAt([roof], { u: 100, v: 48 }, 10)).toEqual({ id: 'roof', seg: 0 });
    expect(pickAt([roof], { u: 300, v: 90 }, 10)).toBeNull();
  });

  it('picks a small object inside a big one, even when the big one is drawn on top', () => {
    expect(pickAt([bush, arch], { u: 200, v: 302 }, 10)).toEqual({ id: 'bush', seg: null });
    // Inside both outlines, near neither one's LEDs or wire: the smaller one.
    expect(pickAt([bush, arch], { u: 215, v: 305 }, 2)).toEqual({ id: 'bush', seg: null });
    // On the arch's wire: the arch.
    expect(pickAt([bush, arch], { u: 150, v: 300 }, 10)).toEqual({ id: 'arch', seg: null });
    // Only inside the arch's box.
    expect(pickAt([bush, arch], { u: 120, v: 220 }, 10)).toEqual({ id: 'arch', seg: null });
  });

  it('picks nothing on empty space', () => {
    expect(pickAt([roof, bush, arch], { u: 600, v: 600 }, 10)).toBeNull();
  });
});

describe('framing a selected object', () => {
  const px = { w: 400, h: 300 };
  it('centers it and fills the view with it, leaving room for its handles', () => {
    const box = { x: 100, y: 50, w: 100, h: 40 };
    const cam = frameCam(box, px, 0, 50);
    expect(cam.cx).toBe(150);
    expect(cam.cy).toBe(70);
    // The width is what limits: 100 units over 400 - 2 × 50 pixels.
    expect(cam.k).toBeCloseTo(100 / 300);
    const vb = viewBoxOf(cam, px);
    expect(vb.x).toBeCloseTo(100 - 50 * cam.k);
  });

  it('does not blow up a tiny object past its smallest size', () => {
    expect(frameCam({ x: 0, y: 0, w: 2, h: 2 }, px, 0, 50, 100).k).toBeCloseTo(100 / 200);
  });

  it('glides with the zoom changing evenly in scale', () => {
    const mid = lerpCam({ cx: 0, cy: 0, k: 1 }, { cx: 100, cy: 50, k: 4 }, 0.5);
    expect(mid).toEqual({ cx: 50, cy: 25, k: 2 });
  });
});
