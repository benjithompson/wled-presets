import { useEffect, useRef, useState } from 'react';
import type { RoofGeometry } from '../../../shared/types.ts';
import { fieldRoof } from '../lightfield/LightField.tsx';
import { nearestOnBorder } from '../lib/border.ts';

export interface RoofStream {
  geometry: RoofGeometry | null;
  /** The latest colors: one RGB triple per cell, in strip order. */
  frame: React.RefObject<Uint8Array | null>;
}

/**
 * The roofline as it is now, from the server (see RoofView): how many cells once, then their
 * colors up to 20 times a second. The stream closes while the page is hidden.
 */
export function useRoofStream(): RoofStream {
  const [geometry, setGeometry] = useState<RoofGeometry | null>(null);
  const frame = useRef<Uint8Array | null>(null);
  const cells = useRef(0);

  useEffect(() => {
    let es: EventSource | null = null;
    const open = () => {
      if (es) return;
      es = new EventSource('/api/roof');
      es.addEventListener('geometry', (e) => {
        const g = JSON.parse((e as MessageEvent).data) as RoofGeometry;
        cells.current = g.cells;
        frame.current = new Uint8Array(g.cells * 3);
        setGeometry(g.cells ? g : null);
        fieldRoof(null);
      });
      es.addEventListener('frame', (e) => {
        const bin = atob((e as MessageEvent).data);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        frame.current = bytes;
        if (bytes.length === cells.current * 3) fieldRoof(bytes);
      });
      // Too many people watch: no roofline for now, and no retrying.
      es.addEventListener('busy', () => close());
    };
    const close = () => {
      es?.close();
      es = null;
    };
    const onVisible = () => (document.hidden ? close() : open());
    open();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      close();
      fieldRoof(null);
    };
  }, []);

  return { geometry, frame };
}

/** Samples around the border loop: the roof's cells are spread over these. */
const RING = 480;
/** Pixels of the glow canvas along the window's longer side; the browser scales it up, smoothly. */
const GRID = 160;

/**
 * The roofline as a soft glow from the whole border of the window: the roof's lights in strip
 * order, wrapped clockwise from the bottom-left corner, each part of the border glowing inward in
 * the color the real lights show there now.
 */
export function Roofline({ roof, dark }: { roof: RoofStream; dark: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const { geometry, frame } = roof;

  useEffect(() => {
    const c = canvas.current;
    if (!c || !geometry) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const n = geometry.cells;
    // What is drawn eases toward the latest frame, so 20 frames a second look smooth at 60.
    const shown = new Float32Array(n * 3);
    const ring = new Float32Array(RING * 3);
    const blurred = new Float32Array(RING * 3);
    let raf = 0;
    let image: ImageData | null = null;
    // Per glowing pixel of the small canvas: its index, its place on the ring, and its glow.
    let pix = new Int32Array(0);
    let at = new Int32Array(0);
    let glow = new Float32Array(0);

    const layout = () => {
      const w = Math.max(1, window.innerWidth);
      const h = Math.max(1, window.innerHeight);
      const s = Math.max(w, h) / GRID;
      const cols = Math.max(8, Math.round(w / s));
      const rows = Math.max(8, Math.round(h / s));
      c.width = cols;
      c.height = rows;
      image = ctx.createImageData(cols, rows);
      // The glow reaches about a seventh of the way in on the shorter side, fading as it goes.
      const reach = Math.min(w, h) * 0.16;
      const p: number[] = [];
      const a: number[] = [];
      const g: number[] = [];
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          const { t, depth } = nearestOnBorder((x + 0.5) * s, (y + 0.5) * s, w, h);
          if (depth > reach) continue;
          const k = 1 - depth / reach;
          p.push(y * cols + x);
          a.push(Math.min(RING - 1, Math.floor(t * RING)));
          g.push(k * k * (0.35 + 0.65 * k));
        }
      }
      pix = Int32Array.from(p);
      at = Int32Array.from(a);
      glow = Float32Array.from(g);
    };
    layout();
    window.addEventListener('resize', layout);

    const draw = () => {
      raf = requestAnimationFrame(draw);
      const f = frame.current;
      if (f && f.length === n * 3) for (let i = 0; i < f.length; i++) shown[i] += (f[i] - shown[i]) * 0.4;
      // The cells, spread around the ring (each blends into the next).
      for (let r = 0; r < RING; r++) {
        const u = (r / RING) * n - 0.5;
        const i0 = Math.max(0, Math.min(n - 1, Math.floor(u)));
        const i1 = Math.min(n - 1, i0 + 1);
        const k = Math.max(0, Math.min(1, u - i0));
        for (let ch = 0; ch < 3; ch++) ring[r * 3 + ch] = shown[i0 * 3 + ch] * (1 - k) + shown[i1 * 3 + ch] * k;
      }
      // Diffuse along the border, so the glow is soft and the corners blend.
      const R = 6;
      for (let r = 0; r < RING; r++) {
        let sr = 0;
        let sg = 0;
        let sb = 0;
        for (let d = -R; d <= R; d++) {
          const q = ((r + d + RING) % RING) * 3;
          sr += ring[q];
          sg += ring[q + 1];
          sb += ring[q + 2];
        }
        blurred[r * 3] = sr / (2 * R + 1);
        blurred[r * 3 + 1] = sg / (2 * R + 1);
        blurred[r * 3 + 2] = sb / (2 * R + 1);
      }
      if (!image) return;
      const d = image.data;
      const strength = dark ? 0.95 : 1;
      for (let j = 0; j < pix.length; j++) {
        const q = at[j] * 3;
        const r = blurred[q];
        const g = blurred[q + 1];
        const b = blurred[q + 2];
        const m = Math.max(r, g, b);
        const o = pix[j] * 4;
        if (m < 2) {
          d[o + 3] = 0;
          continue;
        }
        // Full color, with the light's brightness as how strongly it shows.
        const k = 255 / m;
        d[o] = r * k;
        d[o + 1] = g * k;
        d[o + 2] = b * k;
        d[o + 3] = glow[j] * (m / 255) * strength * 255;
      }
      ctx.putImageData(image, 0, 0);
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', layout);
    };
  }, [geometry, dark, frame]);

  if (!geometry) return null;
  return <canvas ref={canvas} aria-hidden className="pointer-events-none fixed inset-0 -z-[5] block h-full w-full" />;
}
