// The camera of a 2D view (front or top): where it looks and how far it is zoomed, as in CAD
// programs. The wheel zooms at the pointer; the middle button, Space-drag or the Hand tool pans.

/** A rectangle in view units (u to the right, v down). */
export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** The size of a view on the screen, in CSS pixels. */
export interface PaneSize {
  w: number;
  h: number;
}

/**
 * The middle of the view, in view units, and the zoom as layout units per CSS pixel.
 * `cy` is a world coordinate: the height (y) in the front view and the depth (z) in the top
 * view, so the top view does not jump when the range of depths it shows changes.
 */
export interface Cam {
  cx: number;
  cy: number;
  k: number;
}

/** The zoom limits: from 0.05 layout units per pixel (close up) to 40 (far out). */
export const MIN_K = 0.05;
export const MAX_K = 40;
const clampK = (k: number) => Math.min(MAX_K, Math.max(MIN_K, k));

/** A camera that shows all of `box` with a margin. `off` is v minus the world coordinate (−zMin in the top view). */
export function fitCam(box: Box, px: PaneSize, off = 0, margin = 1.08): Cam {
  const k = clampK(Math.max(box.w / Math.max(1, px.w), box.h / Math.max(1, px.h)) * margin);
  return { cx: box.x + box.w / 2, cy: box.y + box.h / 2 - off, k };
}

/** The rectangle of view units that the camera shows. */
export function viewBoxOf(cam: Cam, px: PaneSize, off = 0): Box {
  const w = Math.max(1, px.w) * cam.k;
  const h = Math.max(1, px.h) * cam.k;
  return { x: cam.cx - w / 2, y: cam.cy + off - h / 2, w, h };
}

/** Zooms by `factor` (above 1: closer) and keeps the spot under the pointer (`at`, pixels in the pane) in place. */
export function zoomAt(cam: Cam, px: PaneSize, at: { x: number; y: number }, factor: number): Cam {
  const k = clampK(cam.k / factor);
  // The spot under the pointer, relative to the middle of the pane.
  const dx = at.x - px.w / 2;
  const dy = at.y - px.h / 2;
  return { cx: cam.cx + dx * (cam.k - k), cy: cam.cy + dy * (cam.k - k), k };
}

/** Moves the camera so the content follows a pointer that moved by (dx, dy) pixels. */
export function panBy(cam: Cam, dx: number, dy: number): Cam {
  return { ...cam, cx: cam.cx - dx * cam.k, cy: cam.cy - dy * cam.k };
}

/** The zoom factor for one wheel event: a mouse wheel notch is about 15%; a pinch zooms faster per pixel. */
export function wheelFactor(e: { deltaY: number; deltaMode: number; ctrlKey: boolean }): number {
  const dy = e.deltaMode === 1 ? e.deltaY * 33 : e.deltaMode === 2 ? e.deltaY * 400 : e.deltaY;
  return Math.exp(-dy * (e.ctrlKey ? 0.01 : 0.0015));
}
