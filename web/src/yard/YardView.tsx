import { useEffect, useRef, type ReactNode } from 'react';
import { buildStage, FEET_PER_METER, isLine, layoutScale, type Layout, type Point } from '../../../shared/layout.ts';
import { cn } from '../lib/utils.ts';

/** Which side the yard is seen from. Front: the picture. Top: from above, the street at the bottom. */
export type ViewSide = 'front' | 'top';

/** The size of a view, in layout units. The top view shows depths zMin (back) to zMax (street). */
export function viewSize(layout: Layout, side: ViewSide, zRange: [number, number]) {
  return side === 'front' ? { w: layout.width, h: layout.height } : { w: layout.width, h: zRange[1] - zRange[0] };
}

/** A point in view coordinates (u to the right, v down). */
export function toView(p: Point, side: ViewSide, zMin: number): { u: number; v: number } {
  return side === 'front' ? { u: p.x, v: p.y } : { u: p.x, v: (p.z ?? 0) - zMin };
}

/**
 * Draws the yard: the background picture (or a night sky), faint guides along each light
 * object, and every LED as a glowing bulb in the color of the current frame.
 * `getFrame` is called on every animation frame and returns RGB bytes, one triple per LED.
 * The top view shows a grid (1 m, or 5 ft) and the front wall of the house instead of the picture.
 */
export function YardView({
  layout,
  getFrame,
  className,
  children,
  highlight,
  maxHeight,
  side = 'front',
  zRange = [-480, 480]
}: {
  layout: Layout;
  getFrame: (t: number) => Uint8Array | null;
  className?: string;
  children?: ReactNode;
  /** Id of an object to outline. */
  highlight?: string | null;
  /** CSS length, for example '50dvh'. The view keeps its shape and fits under this height. */
  maxHeight?: string;
  side?: ViewSide;
  /** Top view only: the depths at the top and the bottom edge. */
  zRange?: [number, number];
}) {
  const [zMin, zMax] = zRange;
  const size = viewSize(layout, side, zRange);
  const canvas = useRef<HTMLCanvasElement>(null);
  const getFrameRef = useRef(getFrame);
  getFrameRef.current = getFrame;
  const highlightRef = useRef(highlight);
  highlightRef.current = highlight;

  useEffect(() => {
    const cv = canvas.current;
    if (!cv) return;
    const ctx = cv.getContext('2d');
    if (!ctx) return;
    const stage = buildStage(layout);
    const top = side === 'top';
    // LED positions in view coordinates.
    const n0 = stage.pixelCount;
    const pos = new Float32Array(n0 * 2);
    for (let i = 0; i < n0; i++) {
      pos[i * 2] = stage.positions3[i * 3];
      pos[i * 2 + 1] = top ? stage.positions3[i * 3 + 2] - zMin : stage.positions3[i * 3 + 1];
    }
    const view = (p: Point) => toView(p, side, zMin);
    const scale = layoutScale(layout);
    const gridStep = layout.units === 'm' ? scale : (scale * 5) / FEET_PER_METER;
    const bloom = document.createElement('canvas');
    const bctx = bloom.getContext('2d')!;
    let bg: HTMLImageElement | null = null;
    if (layout.background) {
      bg = new Image();
      bg.src = layout.background;
    }
    let raf = 0;
    const t0 = performance.now();

    const draw = () => {
      raf = requestAnimationFrame(draw);
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = Math.round(cv.clientWidth * dpr);
      const h = Math.round(cv.clientHeight * dpr);
      if (!w || !h) return;
      if (cv.width !== w || cv.height !== h) {
        cv.width = w;
        cv.height = h;
      }
      // Checked on its own: a new layout makes a new bloom layer while the canvas size stays the same.
      const bw = Math.max(1, Math.round(w / 4));
      const bh = Math.max(1, Math.round(h / 4));
      if (bloom.width !== bw || bloom.height !== bh) {
        bloom.width = bw;
        bloom.height = bh;
      }
      const sx = w / size.w;
      const sy = h / size.h;
      const s = Math.min(sx, sy);

      // Background: the photo, darkened so the lights read as night, or a night sky.
      ctx.globalCompositeOperation = 'source-over';
      ctx.filter = 'none';
      const sky = ctx.createLinearGradient(0, 0, 0, h);
      sky.addColorStop(0, '#05070f');
      sky.addColorStop(1, '#0d0b10');
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, w, h);
      if (!top && bg?.complete && bg.naturalWidth) {
        ctx.globalAlpha = 0.42;
        ctx.drawImage(bg, 0, 0, w, h);
        ctx.globalAlpha = 1;
      }
      if (top) {
        // Grid lines from the left edge and from the front wall of the house.
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.beginPath();
        for (let x = 0; x <= size.w; x += gridStep) (ctx.moveTo(x * sx, 0), ctx.lineTo(x * sx, h));
        for (let z = Math.ceil(zMin / gridStep) * gridStep; z <= zMax; z += gridStep) (ctx.moveTo(0, (z - zMin) * sy), ctx.lineTo(w, (z - zMin) * sy));
        ctx.stroke();
        // The front wall of the house (depth 0), and the house behind it.
        ctx.fillStyle = 'rgba(255,255,255,0.025)';
        ctx.fillRect(0, 0, w, -zMin * sy);
        ctx.strokeStyle = 'rgba(251,191,36,0.35)';
        ctx.lineWidth = 2 * dpr;
        ctx.beginPath();
        ctx.moveTo(0, -zMin * sy);
        ctx.lineTo(w, -zMin * sy);
        ctx.stroke();
      }

      // Guides: the wire of each object, so its shape shows even when its LEDs are off.
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      for (const f of layout.fixtures) {
        const hl = highlightRef.current === f.id;
        ctx.strokeStyle = hl ? 'rgba(40,170,255,0.9)' : 'rgba(255,255,255,0.08)';
        ctx.lineWidth = (hl ? 3 : 1.5) * dpr;
        const c = view(f.points[0] ?? { x: 0, y: 0 });
        const r = f.radius ?? 60;
        ctx.beginPath();
        if (isLine(f)) {
          f.points.forEach((p, i) => {
            const q = view(p);
            if (i) ctx.lineTo(q.u * sx, q.v * sy);
            else ctx.moveTo(q.u * sx, q.v * sy);
          });
        } else if (top) {
          // From above, bushes and trees are circles.
          ctx.ellipse(c.u * sx, c.v * sy, r * sx + (hl ? 6 * dpr : 0), r * sy + (hl ? 6 * dpr : 0), 0, 0, Math.PI * 2);
        } else if (f.kind === 'tree') {
          const th = f.height ?? 240;
          ctx.moveTo((c.u - r) * sx, c.v * sy);
          ctx.lineTo(c.u * sx, (c.v - th) * sy);
          ctx.lineTo((c.u + r) * sx, c.v * sy);
          ctx.closePath();
        } else if (hl) {
          ctx.ellipse(c.u * sx, c.v * sy, r * sx + 6 * dpr, r * 0.72 * sy + 6 * dpr, 0, 0, Math.PI * 2);
        }
        ctx.stroke();
      }

      const frame = getFrameRef.current((performance.now() - t0) / 1000);
      const n = stage.pixelCount;
      const bulb = Math.max(1.2, 2.6 * s * dpr);

      // Unlit bulbs.
      ctx.fillStyle = 'rgba(255,255,255,0.10)';
      for (let i = 0; i < n; i++) {
        // LEDs in skipped segments are not drawn: they stay dark on the house too.
        if (!stage.active[i]) continue;
        ctx.fillRect(pos[i * 2] * sx - bulb / 2, pos[i * 2 + 1] * sy - bulb / 2, bulb, bulb);
      }
      if (!frame || frame.length < n * 3) return;

      // Bloom: draw lit bulbs into a quarter-size layer, blur it, add it. The layer keeps the
      // brightest bulb per spot ('lighten'), not the sum, so dense strips do not blow out.
      bctx.clearRect(0, 0, bloom.width, bloom.height);
      bctx.globalCompositeOperation = 'lighten';
      const bsx = bloom.width / w;
      const bsy = bloom.height / h;
      for (let i = 0; i < n; i++) {
        const r = frame[i * 3],
          gg = frame[i * 3 + 1],
          b = frame[i * 3 + 2];
        if (r + gg + b < 12) continue;
        bctx.fillStyle = `rgb(${r},${gg},${b})`;
        const size = Math.max(1.5, 7 * s * dpr * bsx);
        bctx.fillRect(pos[i * 2] * sx * bsx - size / 2, pos[i * 2 + 1] * sy * bsy - size / 2, size, size);
      }
      ctx.globalCompositeOperation = 'lighter';
      ctx.filter = `blur(${Math.max(2, 10 * s * dpr)}px)`;
      ctx.drawImage(bloom, 0, 0, w, h);
      ctx.globalAlpha = 0.6;
      ctx.filter = `blur(${Math.max(4, 26 * s * dpr)}px)`;
      ctx.drawImage(bloom, 0, 0, w, h);
      ctx.globalAlpha = 1;
      ctx.filter = 'none';

      // Crisp bulbs on top, with a white-hot core when bright.
      for (let i = 0; i < n; i++) {
        const r = frame[i * 3],
          gg = frame[i * 3 + 1],
          b = frame[i * 3 + 2];
        const m = Math.max(r, gg, b);
        if (m < 6) continue;
        const x = pos[i * 2] * sx;
        const y = pos[i * 2 + 1] * sy;
        ctx.fillStyle = `rgb(${r},${gg},${b})`;
        ctx.beginPath();
        ctx.arc(x, y, bulb * 0.9, 0, Math.PI * 2);
        ctx.fill();
        if (m > 160) {
          ctx.fillStyle = `rgba(255,255,255,${((m - 160) / 95) * 0.8})`;
          ctx.beginPath();
          ctx.arc(x, y, bulb * 0.45, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      ctx.globalCompositeOperation = 'source-over';
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [layout, side, zMin, zMax]);

  return (
    <div
      className={cn('relative mx-auto w-full overflow-hidden rounded-2xl bg-[#05070f] ring-1 ring-white/10', className)}
      style={{ aspectRatio: `${size.w} / ${size.h}`, maxWidth: maxHeight ? `calc(${maxHeight} * ${size.w / size.h})` : undefined }}
    >
      <canvas ref={canvas} className="absolute inset-0 h-full w-full" />
      {children}
    </div>
  );
}
