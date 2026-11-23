// The front view's camera: where it looks at the yard from (Layout.frontView). The yard turns
// about the pivot, the middle of the front wall at the ground, under the picture of the house,
// which stays as it is: set the angle the picture was taken from, and the objects line up with
// it. Straight on and from far away (the default) is the plain front view: x across, y down.
import { layoutGround, MAX_PITCH, MAX_YAW, type Layout, type Point3 } from '../../../shared/layout.ts';

type Vec = [number, number, number];

/** A turned front view (see frontCamera). Directions are unit vectors in the yard (x, y down, z toward the street). */
export interface FrontCam {
  /** The pivot: the middle of the front wall, at the ground (depth 0). */
  cx: number;
  cy: number;
  /** To the right on the screen, down on the screen, and toward the camera. */
  right: Vec;
  down: Vec;
  back: Vec;
  /** From the pivot to the camera, in layout units; Infinity: far away (no perspective). */
  dist: number;
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));
const dot = (a: Vec, x: number, y: number, z: number) => a[0] * x + a[1] * y + a[2] * z;

/** The front view's camera, or null for the plain front view (straight on, from far away). */
export function frontCamera(layout: Pick<Layout, 'width' | 'height' | 'groundY' | 'frontView'> | null | undefined): FrontCam | null {
  const v = layout?.frontView;
  if (!v) return null;
  const yaw = clamp(v.yaw ?? 0, -MAX_YAW, MAX_YAW);
  const pitch = clamp(v.pitch ?? 0, 0, MAX_PITCH);
  const dist = v.distance && v.distance > 0 ? v.distance : Infinity;
  if (!yaw && !pitch && dist === Infinity) return null;
  const t = (yaw * Math.PI) / 180;
  const p = (pitch * Math.PI) / 180;
  // The camera is out toward the street, turned to the right by yaw and raised by pitch (up is -y).
  const back: Vec = [Math.sin(t) * Math.cos(p), -Math.sin(p), Math.cos(t) * Math.cos(p)];
  const right: Vec = [Math.cos(t), 0, -Math.sin(t)];
  const down: Vec = [Math.sin(t) * Math.sin(p), Math.cos(p), Math.cos(t) * Math.sin(p)];
  return { cx: layout!.width / 2, cy: layoutGround(layout!), right, down, back, dist };
}

/** How much bigger a point looks than one at the pivot's depth: 1 from far away. */
function grow(cam: FrontCam, c: number) {
  if (cam.dist === Infinity) return 1;
  // Points behind the camera do not show; close to it, they stop growing.
  return cam.dist / Math.max(cam.dist * 0.05, cam.dist - c);
}

/** Where a point of the yard is in the front view (u to the right, v down). */
export function project(cam: FrontCam, x: number, y: number, z: number): { u: number; v: number } {
  const dx = x - cam.cx;
  const dy = y - cam.cy;
  const k = grow(cam, dot(cam.back, dx, dy, z));
  return { u: cam.cx + dot(cam.right, dx, dy, z) * k, v: cam.cy + dot(cam.down, dx, dy, z) * k };
}

/** LED positions (x, y, z each) in the front view: u, v each. */
export function projectAll(cam: FrontCam, positions3: Float32Array): Float32Array {
  const n = positions3.length / 3;
  const out = new Float32Array(n * 2);
  for (let i = 0; i < n; i++) {
    const p = project(cam, positions3[i * 3], positions3[i * 3 + 1], positions3[i * 3 + 2]);
    out[i * 2] = p.u;
    out[i * 2 + 1] = p.v;
  }
  return out;
}

/**
 * The point of the yard at a spot of the front view, at depth z: where the line of sight
 * through the spot meets the upright plane at that depth. So a point dragged in the view keeps
 * its depth, as in the plain front view.
 */
export function unproject(cam: FrontCam, u: number, v: number, z: number): Point3 {
  const a = u - cam.cx;
  const b = v - cam.cy;
  // The spot on the picture's plane, through the pivot.
  const q: Vec = [cam.cx + a * cam.right[0] + b * cam.down[0], cam.cy + a * cam.right[1] + b * cam.down[1], a * cam.right[2] + b * cam.down[2]];
  // The line of sight: from the camera through that spot, or (from far away) straight in.
  const far = cam.dist === Infinity;
  const o: Vec = far ? q : [cam.cx + cam.dist * cam.back[0], cam.cy + cam.dist * cam.back[1], cam.dist * cam.back[2]];
  const d: Vec = far ? [-cam.back[0], -cam.back[1], -cam.back[2]] : [q[0] - o[0], q[1] - o[1], q[2] - o[2]];
  // The front view never turns edge on (MAX_YAW), so the line always meets the plane.
  const s = Math.abs(d[2]) > 1e-9 ? (z - o[2]) / d[2] : 0;
  return { x: o[0] + s * d[0], y: o[1] + s * d[1], z };
}

/** The direction across the screen, in the ground plane (x, z): to draw a tree's outline as seen from the camera. */
export const acrossOf = (cam: FrontCam) => ({ x: cam.right[0], z: cam.right[2] });
