import { useEffect, useRef, type ReactNode } from 'react';
import { buildStage, fixturePixels, type Layout } from '../../../shared/layout.ts';
import { cn } from '../lib/utils.ts';

/**
 * Draws the yard: the background picture (or a night sky), faint guides along each light
 * object, and every LED as a glowing bulb in the color of the current frame.
 * `getFrame` is called on every animation frame and returns RGB bytes, one triple per LED.
 */
export function YardView({
  layout,
  getFrame,
  className,
  children,
  highlight,
  maxHeight
}: {
  layout: Layout;
  getFrame: (t: number) => Uint8Array | null;
  className?: string;
  children?: ReactNode;
  /** Id of an object to outline. */
  highlight?: string | null;
  /** CSS length, for example '50dvh'. The view keeps its shape and fits under this height. */
  maxHeight?: string;
}) {
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
    const guides = layout.fixtures.map((f) => ({ id: f.id, kind: f.kind, pts: f.kind === 'roof' ? f.points : fixturePixels(f) }));
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
      const sx = w / layout.width;
      const sy = h / layout.height;
      const s = Math.min(sx, sy);

      // Background: the photo, darkened so the lights read as night, or a night sky.
      ctx.globalCompositeOperation = 'source-over';
      ctx.filter = 'none';
      const sky = ctx.createLinearGradient(0, 0, 0, h);
      sky.addColorStop(0, '#05070f');
      sky.addColorStop(1, '#0d0b10');
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, w, h);
      if (bg?.complete && bg.naturalWidth) {
        ctx.globalAlpha = 0.42;
        ctx.drawImage(bg, 0, 0, w, h);
        ctx.globalAlpha = 1;
      }

      // Guides: the wire of each object, so its shape shows even when its LEDs are off.
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      for (const g of guides) {
        const hl = highlightRef.current === g.id;
        ctx.strokeStyle = hl ? 'rgba(40,170,255,0.9)' : 'rgba(255,255,255,0.08)';
        ctx.lineWidth = (hl ? 3 : 1.5) * dpr;
        if (g.kind === 'roof') {
          ctx.beginPath();
          g.pts.forEach((p, i) => (i ? ctx.lineTo(p.x * sx, p.y * sy) : ctx.moveTo(p.x * sx, p.y * sy)));
          ctx.stroke();
        } else if (hl) {
          const f = layout.fixtures.find((x) => x.id === g.id)!;
          ctx.beginPath();
          ctx.ellipse(f.points[0].x * sx, f.points[0].y * sy, (f.radius ?? 60) * sx + 6 * dpr, (f.radius ?? 60) * 0.72 * sy + 6 * dpr, 0, 0, Math.PI * 2);
          ctx.stroke();
        }
      }

      const frame = getFrameRef.current((performance.now() - t0) / 1000);
      const pos = stage.positions;
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
        const r = frame[i * 3], gg = frame[i * 3 + 1], b = frame[i * 3 + 2];
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
        const r = frame[i * 3], gg = frame[i * 3 + 1], b = frame[i * 3 + 2];
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
  }, [layout]);

  return (
    <div
      className={cn('relative mx-auto w-full overflow-hidden rounded-2xl bg-[#05070f] ring-1 ring-white/10', className)}
      style={{ aspectRatio: `${layout.width} / ${layout.height}`, maxWidth: maxHeight ? `calc(${maxHeight} * ${layout.width / layout.height})` : undefined }}
    >
      <canvas ref={canvas} className="absolute inset-0 h-full w-full" />
      {children}
    </div>
  );
}
