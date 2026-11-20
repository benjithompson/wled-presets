// Light Painter: the paint box. The phone shows these colors and effects; the server paints with
// them. A stroke is a finger dragged over the picture of the yard: every light under it takes the
// color and the effect.

/** A color in the paint box. `rgb`: frame color (linear 0..1); null for the moving rainbow. */
export interface PaintColor {
  id: string;
  name: string;
  /** The swatch on the phone (a CSS color or gradient). */
  css: string;
  rgb: [number, number, number] | null;
}

/** The eraser: lights painted with it go dark. */
export const ERASER = 'erase';
export const RAINBOW = 'rainbow';

export const PAINT_COLORS: PaintColor[] = [
  { id: 'red', name: 'Red', css: '#ff2b2b', rgb: [1, 0.02, 0.02] },
  { id: 'orange', name: 'Orange', css: '#ff8a1f', rgb: [1, 0.3, 0] },
  { id: 'yellow', name: 'Yellow', css: '#ffe02e', rgb: [1, 0.78, 0] },
  { id: 'green', name: 'Green', css: '#2ee65a', rgb: [0.05, 1, 0.12] },
  { id: 'teal', name: 'Teal', css: '#1fe0d0', rgb: [0, 0.9, 0.75] },
  { id: 'blue', name: 'Blue', css: '#2f6bff', rgb: [0.03, 0.2, 1] },
  { id: 'purple', name: 'Purple', css: '#a14bff', rgb: [0.5, 0.05, 1] },
  { id: 'pink', name: 'Pink', css: '#ff4fc3', rgb: [1, 0.08, 0.55] },
  { id: 'white', name: 'Snow', css: '#fff4e0', rgb: [1, 0.85, 0.65] },
  { id: RAINBOW, name: 'Rainbow', css: 'conic-gradient(#ff2b2b, #ffe02e, #2ee65a, #1fe0d0, #2f6bff, #a14bff, #ff4fc3, #ff2b2b)', rgb: null },
  { id: ERASER, name: 'Eraser', css: '#1c1917', rgb: null }
];

/** How painted lights move. */
export interface PaintEffect {
  id: string;
  name: string;
  /** A picture a five-year-old knows, for the button. */
  icon: string;
}

export const PAINT_EFFECTS: PaintEffect[] = [
  { id: 'still', name: 'Glow', icon: '💡' },
  { id: 'twinkle', name: 'Twinkle', icon: '✨' },
  { id: 'pulse', name: 'Heartbeat', icon: '💗' },
  { id: 'flicker', name: 'Fire', icon: '🔥' },
  { id: 'wave', name: 'Waves', icon: '🌊' },
  { id: 'chase', name: 'Train', icon: '🚂' }
];

/** Strokes at once per phone (one per finger). */
export const PAINT_FINGERS = 4;
/** Points in one paint message (x, y pairs). */
export const PAINT_MAX_POINTS = 32;

/**
 * Part of a stroke, sent while the finger moves: the points it passed (front view, layout units,
 * as a flat list x0, y0, x1, y1…), the brush's radius, and what it paints with.
 */
export interface PaintStroke {
  /** Which finger (0 to PAINT_FINGERS - 1). */
  finger: number;
  /** True for the first part of a stroke: it does not join the last one. */
  start: boolean;
  points: number[];
  radius: number;
  color: string;
  effect: string;
  /** Fill each object the finger touches, all of it, instead of painting under the finger. */
  fill: boolean;
}

/** The paint box's buttons that are not strokes (GameInput buttons). */
export const PAINT_BUTTONS = { undo: 'undo', clear: 'clear', surprise: 'surprise' } as const;

/** What the phone needs to know about the painting (GameStatus.paint): it shows the paint box. */
export interface PaintPad {
  canUndo: boolean;
  /** Nothing is painted yet. */
  empty: boolean;
}

/** A paint message from a browser, checked: null when it is not one. */
export function cleanStroke(m: unknown): PaintStroke | null {
  if (!m || typeof m !== 'object') return null;
  const s = m as Record<string, unknown>;
  const finger = s.finger;
  if (typeof finger !== 'number' || !Number.isInteger(finger) || finger < 0 || finger >= PAINT_FINGERS) return null;
  const points = s.points;
  if (!Array.isArray(points) || points.length < 2 || points.length % 2 || points.length > PAINT_MAX_POINTS * 2) return null;
  if (!points.every((v) => typeof v === 'number' && Number.isFinite(v) && Math.abs(v) < 1e6)) return null;
  const radius = s.radius;
  if (typeof radius !== 'number' || !Number.isFinite(radius) || radius <= 0) return null;
  if (typeof s.color !== 'string' || !PAINT_COLORS.some((c) => c.id === s.color)) return null;
  if (typeof s.effect !== 'string' || !PAINT_EFFECTS.some((e) => e.id === s.effect)) return null;
  return { finger, start: s.start === true, points: points as number[], radius, color: s.color, effect: s.effect, fill: s.fill === true };
}
