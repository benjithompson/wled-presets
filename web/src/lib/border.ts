/**
 * The window's border as one loop for the roofline: it starts at the bottom-left corner and runs
 * clockwise (up the left side, across the top, down the right side, back along the bottom), so
 * the roof's left end shows on the left of the window and its right end on the right.
 */

export interface BorderPoint {
  /** Where on the border, in window fractions (x right, y down). */
  x: number;
  y: number;
  /** Which way is in, toward the middle of the window. */
  nx: number;
  ny: number;
}

/** The point at `t` (0..1) along the border of a window `w` by `h`. */
export function borderPoint(t: number, w: number, h: number): BorderPoint {
  const p = 2 * (w + h);
  let d = (((t % 1) + 1) % 1) * p;
  if (d < h) return { x: 0, y: 1 - d / h, nx: 1, ny: 0 };
  d -= h;
  if (d < w) return { x: d / w, y: 0, nx: 0, ny: 1 };
  d -= w;
  if (d < h) return { x: 1, y: d / h, nx: -1, ny: 0 };
  d -= h;
  return { x: 1 - d / w, y: 1, nx: 0, ny: -1 };
}

/** Where along the border (0..1) the point nearest to (x, y) is, in window pixels, and how far in it is. */
export function nearestOnBorder(x: number, y: number, w: number, h: number): { t: number; depth: number } {
  const p = 2 * (w + h);
  const left = x;
  const top = y;
  const right = w - x;
  const bottom = h - y;
  const depth = Math.min(left, top, right, bottom);
  let d: number;
  if (depth === left) d = h - y;
  else if (depth === top) d = h + x;
  else if (depth === right) d = h + w + y;
  else d = 2 * h + w + (w - x);
  return { t: d / p, depth };
}
