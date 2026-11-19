// Follows the LEDs through the pictures of a walk round in AR (see scanWalk.ts), away from the
// page so the camera keeps moving smoothly. Each picture comes at full size, rows from the bottom
// up; it is made smaller (each pixel the mean of a square of them) and turned top down here.

import type { PosedCam } from '../../../../shared/scan3d.ts';
import { Walk, type WalkResult, type WalkStatus } from '../../../../shared/scanWalk.ts';

export type WalkIn =
  | { type: 'start'; n: number; maxSide: number }
  | { type: 'frame'; width: number; height: number; data: ArrayBuffer; cam: PosedCam; code: number | null; cycle: number }
  | { type: 'finish' };

export type WalkOut =
  | { type: 'status'; status: WalkStatus; width: number; height: number; buffer: ArrayBuffer }
  | { type: 'done'; result: WalkResult; first: { width: number; height: number; data: Uint8ClampedArray } | null }
  | { type: 'error'; message: string };

let walk: Walk | null = null;
let maxSide = 960;
let first: { width: number; height: number; data: Uint8ClampedArray } | null = null;

const post = (msg: WalkOut, transfer: Transferable[] = []) => (self as unknown as { postMessage: (m: unknown, o: { transfer: Transferable[] }) => void }).postMessage(msg, { transfer });

/** Smaller by a whole number, and top down. */
function shrink(width: number, height: number, src: Uint8Array) {
  const s = Math.max(1, Math.ceil(Math.max(width, height) / maxSide));
  const w = Math.floor(width / s);
  const h = Math.floor(height / s);
  const out = new Uint8ClampedArray(w * h * 4);
  const area = s * s;
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++) {
      let r = 0;
      let g = 0;
      let b = 0;
      for (let dy = 0; dy < s; dy++) {
        // From the bottom up: row y from the top is row height − 1 − y.
        const row = (height - 1 - (y * s + dy)) * width;
        for (let dx = 0; dx < s; dx++) {
          const i = (row + x * s + dx) * 4;
          r += src[i];
          g += src[i + 1];
          b += src[i + 2];
        }
      }
      const o = (y * w + x) * 4;
      out[o] = r / area;
      out[o + 1] = g / area;
      out[o + 2] = b / area;
      out[o + 3] = 255;
    }
  return { s, w, h, out };
}

self.onmessage = (e: MessageEvent<WalkIn>) => {
  const m = e.data;
  try {
    if (m.type === 'start') {
      walk = new Walk(m.n);
      maxSide = m.maxSide;
      first = null;
    } else if (m.type === 'frame' && walk) {
      const { s, w, h, out } = shrink(m.width, m.height, new Uint8Array(m.data));
      // The camera for the smaller picture (pixel centers at whole numbers).
      const c = m.cam;
      const cam: PosedCam = { R: c.R, t: c.t, f: c.f / s, fy: (c.fy ?? c.f) / s, cu: (c.cu + 0.5) / s - 0.5, cv: (c.cv + 0.5) / s - 0.5 };
      if (!first) first = { width: w, height: h, data: out.slice() };
      const status = walk.add({ pixels: { width: w, height: h, data: out }, cam, code: m.code, cycle: m.cycle });
      post({ type: 'status', status, width: w, height: h, buffer: m.data }, [m.data]);
    } else if (m.type === 'finish' && walk) {
      const result = walk.finish();
      post({ type: 'done', result, first });
      walk = null;
      first = null;
    }
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) });
  }
};
