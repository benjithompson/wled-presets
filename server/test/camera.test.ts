import { describe, expect, it } from 'vitest';
import { clampCam, pinch, viewBoxOf, type Cam } from '../../web/src/yard/camera.ts';

const px = { w: 400, h: 200 };
const far: Cam = { cx: 200, cy: 100, k: 1 };
const bounds = { x: 0, y: 0, w: 400, h: 200 };

describe('pinch and pan on a touch screen', () => {
  it('zooms by how far the fingers spread, keeping the spot between them in place', () => {
    const cam = pinch(far, px, [{ x: 100, y: 100 }, { x: 140, y: 100 }], [{ x: 80, y: 100 }, { x: 160, y: 100 }]);
    expect(cam.k).toBeCloseTo(0.5);
    // The spot at pixel (120, 100) was layout (120, 100); it is still under (120, 100).
    const box = viewBoxOf(cam, px);
    expect(box.x + (120 / px.w) * box.w).toBeCloseTo(120);
    expect(box.y + (100 / px.h) * box.h).toBeCloseTo(100);
  });

  it('pans with two fingers moving together', () => {
    const start: Cam = { cx: 200, cy: 100, k: 0.5 };
    const cam = pinch(start, px, [{ x: 100, y: 100 }, { x: 200, y: 100 }], [{ x: 150, y: 120 }, { x: 250, y: 120 }]);
    expect(cam.k).toBeCloseTo(0.5);
    expect(cam.cx).toBeCloseTo(200 - 50 * 0.5);
    expect(cam.cy).toBeCloseTo(100 - 20 * 0.5);
  });

  it('stays on the lights: no farther out than all of them, no closer than the limit, no panning off the edge', () => {
    expect(clampCam({ cx: 900, cy: -50, k: 3 }, px, far, bounds, 8)).toEqual(far);
    expect(clampCam({ cx: 200, cy: 100, k: 0.01 }, px, far, bounds, 8).k).toBeCloseTo(1 / 8);
    const edge = clampCam({ cx: -500, cy: 1000, k: 0.5 }, px, far, bounds, 8);
    expect(viewBoxOf(edge, px)).toEqual({ x: 0, y: 100, w: 200, h: 100 });
  });
});
