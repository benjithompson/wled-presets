import { useEffect, useRef, useState } from 'react';
import type { RoofGeometry } from '../../../shared/types.ts';
import { fieldRoof } from '../lightfield/LightField.tsx';

/** Height of the strip, in CSS pixels. The page leaves room for it. */
export const ROOF_HEIGHT = 40;
/** Space at each end of the strip. */
const SIDE = 14;
/** How far the roof's highest point rises over its lowest. */
const RISE = 16;

export interface RoofStream {
  geometry: RoofGeometry | null;
  /** The latest colors: one RGB triple per cell. */
  frame: React.RefObject<Uint8Array | null>;
}

/**
 * The roofline as it is now, from the server (see RoofView): its shape once, then its colors
 * up to 20 times a second. The stream closes while the page is hidden.
 */
export function useRoofStream(): RoofStream {
  const [geometry, setGeometry] = useState<RoofGeometry | null>(null);
  const frame = useRef<Uint8Array | null>(null);
  const shape = useRef<RoofGeometry | null>(null);

  useEffect(() => {
    let es: EventSource | null = null;
    const open = () => {
      if (es) return;
      es = new EventSource('/api/roof');
      es.addEventListener('geometry', (e) => {
        const g = JSON.parse((e as MessageEvent).data) as RoofGeometry;
        shape.current = g;
        frame.current = new Uint8Array(g.x.length * 3);
        setGeometry(g.x.length ? g : null);
        fieldRoof(null);
      });
      es.addEventListener('frame', (e) => {
        const bin = atob((e as MessageEvent).data);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        frame.current = bytes;
        const g = shape.current;
        if (g && bytes.length === g.x.length * 3) fieldRoof(screenX(g.x), bytes);
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

/** A cell's place across the window (0..1), with the strip's side margins. */
function screenX(x: number[]): Float32Array {
  const w = window.innerWidth || 1;
  const m = Math.min(SIDE / w, 0.1);
  return Float32Array.from(x, (v) => m + v * (1 - 2 * m));
}

/**
 * The roof's lights along the top edge of the window, drawn in the shape of the roof (its
 * peaks higher), each cell a glowing bulb in the color the real lights show now.
 */
export function Roofline({ roof, dark }: { roof: RoofStream; dark: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const { geometry, frame } = roof;

  useEffect(() => {
    const c = canvas.current;
    if (!c || !geometry) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const n = geometry.x.length;
    // What is drawn eases toward the latest frame, so 20 frames a second look smooth at 60.
    const shown = new Float32Array(n * 3);
    let raf = 0;
    let w = 0;
    let h = 0;
    const resize = () => {
      const dpr = Math.min(devicePixelRatio || 1, 2);
      w = c.clientWidth;
      h = c.clientHeight;
      c.width = Math.round(w * dpr);
      c.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      raf = requestAnimationFrame(draw);
      const f = frame.current;
      if (f && f.length === n * 3) for (let i = 0; i < f.length; i++) shown[i] += (f[i] - shown[i]) * 0.45;
      ctx.clearRect(0, 0, w, h);
      const side = Math.min(SIDE, w * 0.1);
      const span = w - side * 2;
      const px = (i: number) => side + geometry.x[i] * span;
      const py = (i: number) => 6 + (1 - geometry.y[i]) * RISE;
      const gap = span / Math.max(n, 1);
      const r = Math.max(1.2, Math.min(3.2, gap * 0.38));

      // The wire: the roof's outline, faint, so the shape reads when the lights are dark.
      ctx.globalCompositeOperation = 'source-over';
      ctx.strokeStyle = dark ? 'rgba(255,255,255,0.10)' : 'rgba(28,25,23,0.14)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        // A wide gap is between two roofs: the wire does not cross it.
        if (i && geometry.x[i] - geometry.x[i - 1] > 0.06) ctx.moveTo(px(i), py(i));
        else if (i) ctx.lineTo(px(i), py(i));
        else ctx.moveTo(px(i), py(i));
      }
      ctx.stroke();

      // Glow first (added light in the dark, a soft stain on paper), then the bulbs.
      ctx.globalCompositeOperation = dark ? 'lighter' : 'source-over';
      for (let i = 0; i < n; i++) {
        const R = shown[i * 3];
        const G = shown[i * 3 + 1];
        const B = shown[i * 3 + 2];
        const lum = Math.max(R, G, B) / 255;
        if (lum < 0.03) continue;
        const x = px(i);
        const y = py(i);
        const g = ctx.createRadialGradient(x, y, 0, x, y, r * 5);
        g.addColorStop(0, `rgba(${R | 0},${G | 0},${B | 0},${(dark ? 0.55 : 0.35) * lum})`);
        g.addColorStop(1, `rgba(${R | 0},${G | 0},${B | 0},0)`);
        ctx.fillStyle = g;
        ctx.fillRect(x - r * 5, y - r * 5, r * 10, r * 10);
      }
      ctx.globalCompositeOperation = 'source-over';
      for (let i = 0; i < n; i++) {
        const R = shown[i * 3];
        const G = shown[i * 3 + 1];
        const B = shown[i * 3 + 2];
        const lum = Math.max(R, G, B) / 255;
        ctx.beginPath();
        ctx.arc(px(i), py(i), r, 0, Math.PI * 2);
        if (lum < 0.03) ctx.fillStyle = dark ? 'rgba(255,255,255,0.12)' : 'rgba(28,25,23,0.16)';
        else {
          // A lit bulb: its color, brightened toward white at the core as real LEDs look.
          const k = 255 / Math.max(R, G, B, 1);
          const mix = (v: number) => Math.round(v * k * 0.8 + 255 * 0.2);
          ctx.fillStyle = `rgba(${mix(R)},${mix(G)},${mix(B)},${0.35 + 0.65 * lum})`;
        }
        ctx.fill();
      }
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, [geometry, dark, frame]);

  if (!geometry) return null;
  return (
    <canvas
      ref={canvas}
      aria-hidden
      className="pointer-events-none fixed inset-x-0 z-10 block w-full"
      style={{ top: 'env(safe-area-inset-top, 0px)', height: ROOF_HEIGHT }}
    />
  );
}
