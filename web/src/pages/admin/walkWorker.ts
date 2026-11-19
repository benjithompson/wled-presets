// Follows the LEDs through the pictures of a walk round in AR (see scanWalk.ts), away from the
// page so the camera keeps moving smoothly. Each picture comes small already, rows top down
// (arWalk.ts makes it smaller on the GPU), with the camera for its pixels.

import type { PosedCam } from '../../../../shared/scan3d.ts';
import { Walk, type WalkResult, type WalkStatus } from '../../../../shared/scanWalk.ts';

export type WalkIn =
  | { type: 'start'; n: number }
  | { type: 'frame'; width: number; height: number; data: ArrayBuffer; cam: PosedCam; code: number | null; cycle: number }
  | { type: 'finish' };

export type WalkOut =
  | { type: 'status'; status: WalkStatus; width: number; height: number; buffer: ArrayBuffer }
  | { type: 'done'; result: WalkResult; first: { width: number; height: number; data: Uint8ClampedArray } | null }
  | { type: 'error'; message: string };

let walk: Walk | null = null;
let first: { width: number; height: number; data: Uint8ClampedArray } | null = null;

const post = (msg: WalkOut, transfer: Transferable[] = []) => (self as unknown as { postMessage: (m: unknown, o: { transfer: Transferable[] }) => void }).postMessage(msg, { transfer });

self.onmessage = (e: MessageEvent<WalkIn>) => {
  const m = e.data;
  try {
    if (m.type === 'start') {
      walk = new Walk(m.n);
      first = null;
    } else if (m.type === 'frame' && walk) {
      const data = new Uint8ClampedArray(m.data);
      if (!first) first = { width: m.width, height: m.height, data: data.slice() };
      const status = walk.add({ pixels: { width: m.width, height: m.height, data }, cam: m.cam, code: m.code, cycle: m.cycle });
      // The buffer goes back, to read the next picture into.
      post({ type: 'status', status, width: m.width, height: m.height, buffer: m.data }, [m.data]);
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
