import { useEffect, useRef, type ReactNode } from 'react';
import type React from 'react';
import { AERIAL_OPACITY, buildStage, designPaths, FEET_PER_METER, isLine, layoutGround, layoutScale, type Layout, type Point } from '../../../shared/layout.ts';
import type { Box } from './camera.ts';
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
 * The top view shows the front wall of the house instead, over the picture from above
 * (Layout.aerial) when there is one. `grid` draws a grid
 * (1 m, or 5 ft) from the left edge and from the ground (front) or the front wall (top).
 *
 * By default the view keeps the shape of the yard and shows all of it. With `fill`, it fills
 * its parent, and `viewBox` (view units) sets what it shows: a CAD camera that pans and zooms.
 */
export function YardView({
  layout,
  getFrame,
  className,
  children,
  highlight,
  maxHeight,
  side = 'front',
  zRange = [-480, 480],
  fill = false,
  viewBox,
  grid,
  onPick,
  onHover
}: {
  layout: Layout;
  getFrame: (t: number) => Uint8Array | null;
  className?: string;
  children?: ReactNode;
  /** Id(s) of objects to outline. */
  highlight?: string | string[] | null;
  /** CSS length, for example '50dvh'. The view keeps its shape and fits under this height. */
  maxHeight?: string;
  side?: ViewSide;
  /** Top view only: the depths at the top and the bottom edge. */
  zRange?: [number, number];
  /** Fill the parent (which must be positioned) instead of keeping the shape of the yard. */
  fill?: boolean;
  /** What the view shows, in view units. Default: the whole yard. */
  viewBox?: Box;
  /** Draw a grid. Default: in the top view only. */
  grid?: boolean;
  /** A click on (or near) an LED: its object. A click on nothing: null. `add`: Ctrl, ⌘ or Shift was down. */
  onPick?: (id: string | null, add: boolean) => void;
  /** The object under the pointer (null: none), and where the pointer is in the view (CSS pixels). */
  onHover?: (id: string | null, at: { x: number; y: number }) => void;
}) {
  const [zMin, zMax] = zRange;
  const size = viewSize(layout, side, zRange);
  const canvas = useRef<HTMLCanvasElement>(null);
  const getFrameRef = useRef(getFrame);
  getFrameRef.current = getFrame;
  const highlightRef = useRef<Set<string>>(new Set());
  highlightRef.current = new Set(highlight == null ? [] : Array.isArray(highlight) ? highlight : [highlight]);
  /** What the last frame drew, to find the LED under the pointer. */
  const hitRef = useRef<{ stage: ReturnType<typeof buildStage>; pos: Float32Array; vb: Box; w: number; h: number } | null>(null);
  // Read on every frame, so panning and zooming do not restart the drawing loop.
  const boxRef = useRef<Box>({ x: 0, y: 0, w: size.w, h: size.h });
  boxRef.current = viewBox ?? { x: 0, y: 0, w: size.w, h: size.h };
  const gridRef = useRef(grid ?? side === 'top');
  gridRef.current = grid ?? side === 'top';

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
    // Grid lines count from the left edge, and from the ground (front) or the front wall (top).
    const gridV0 = top ? -zMin : layoutGround(layout);
    const bloom = document.createElement('canvas');
    const bctx = bloom.getContext('2d')!;
    let bg: HTMLImageElement | null = null;
    if (layout.background) {
      bg = new Image();
      bg.src = layout.background;
    }
    const aerial = top && layout.aerial && (layout.aerial.opacity ?? AERIAL_OPACITY) > 0 ? layout.aerial : null;
    let aerialImg: HTMLImageElement | null = null;
    if (aerial) {
      aerialImg = new Image();
      aerialImg.src = aerial.url;
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
      const vb = boxRef.current;
      hitRef.current = { stage, pos, vb, w: cv.clientWidth, h: cv.clientHeight };
      const sx = w / vb.w;
      const sy = h / vb.h;
      const X = (u: number) => (u - vb.x) * sx;
      const Y = (v: number) => (v - vb.y) * sy;
      // Bulbs and glow grow when you zoom in, up to a limit.
      const s = Math.min(sx, sy, 3 * dpr);

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
        ctx.drawImage(bg, X(0), Y(0), size.w * sx, size.h * sy);
        ctx.globalAlpha = 1;
      }
      if (aerial && aerialImg?.complete && aerialImg.naturalWidth) {
        // In view units: moved to its middle, turned, then drawn about its middle.
        const aw = aerial.width;
        const ah = aerial.width * aerial.aspect;
        ctx.save();
        ctx.globalAlpha = aerial.opacity ?? AERIAL_OPACITY;
        ctx.setTransform(sx, 0, 0, sy, X(aerial.x), Y(aerial.z - zMin));
        ctx.rotate((aerial.rotation * Math.PI) / 180);
        ctx.drawImage(aerialImg, -aw / 2, -ah / 2, aw, ah);
        ctx.restore();
      }
      if (fill && !top) {
        // The edge of the picture.
        ctx.strokeStyle = 'rgba(255,255,255,0.12)';
        ctx.lineWidth = dpr;
        ctx.strokeRect(X(0), Y(0), size.w * sx, size.h * sy);
      }
      if (top) {
        // The house behind the front wall (depth 0).
        ctx.fillStyle = 'rgba(255,255,255,0.025)';
        ctx.fillRect(0, 0, w, Math.max(0, Y(-zMin)));
      }
      if (gridRef.current) {
        // Grid lines; every fifth line is brighter. Lines closer than 6 pixels are left out.
        const u0 = vb.x;
        const v0 = vb.y;
        const lines = (major: boolean) => {
          const step = gridStep * (major ? 5 : 1);
          if (step * sx < 6 * dpr) return;
          ctx.beginPath();
          for (let u = Math.ceil(u0 / step) * step; u <= u0 + vb.w; u += step) (ctx.moveTo(X(u), 0), ctx.lineTo(X(u), h));
          for (let v = gridV0 + Math.ceil((v0 - gridV0) / step) * step; v <= v0 + vb.h; v += step) (ctx.moveTo(0, Y(v)), ctx.lineTo(w, Y(v)));
          ctx.stroke();
        };
        ctx.lineWidth = 1;
        ctx.strokeStyle = top ? 'rgba(255,255,255,0.05)' : 'rgba(255,255,255,0.045)';
        lines(false);
        ctx.strokeStyle = 'rgba(255,255,255,0.1)';
        lines(true);
      }
      if (top) {
        ctx.strokeStyle = 'rgba(251,191,36,0.35)';
        ctx.lineWidth = 2 * dpr;
        ctx.beginPath();
        ctx.moveTo(0, Y(-zMin));
        ctx.lineTo(w, Y(-zMin));
        ctx.stroke();
      }

      // Guides: the wire of each object, so its shape shows even when its LEDs are off.
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      for (const f of layout.fixtures) {
        const hl = highlightRef.current.has(f.id);
        ctx.strokeStyle = hl ? 'rgba(40,170,255,0.9)' : 'rgba(255,255,255,0.08)';
        ctx.lineWidth = (hl ? 3 : 1.5) * dpr;
        const c = view(f.points[0] ?? { x: 0, y: 0 });
        const r = f.radius ?? 60;
        ctx.beginPath();
        if (isLine(f) || f.kind === 'custom') {
          for (const path of isLine(f) ? [f.points] : designPaths(f, layoutScale(layout)))
            path.forEach((p, i) => {
              const q = view(p);
              if (i) ctx.lineTo(X(q.u), Y(q.v));
              else ctx.moveTo(X(q.u), Y(q.v));
            });
        } else if (top) {
          // From above, bushes and trees are circles.
          ctx.ellipse(X(c.u), Y(c.v), r * sx + (hl ? 6 * dpr : 0), r * sy + (hl ? 6 * dpr : 0), 0, 0, Math.PI * 2);
        } else if (f.kind === 'tree') {
          const th = f.height ?? 240;
          ctx.moveTo(X(c.u - r), Y(c.v));
          ctx.lineTo(X(c.u), Y(c.v - th));
          ctx.lineTo(X(c.u + r), Y(c.v));
          ctx.closePath();
        } else if (hl) {
          ctx.ellipse(X(c.u), Y(c.v), r * sx + 6 * dpr, r * 0.72 * sy + 6 * dpr, 0, 0, Math.PI * 2);
        }
        ctx.stroke();
      }

      const frame = getFrameRef.current((performance.now() - t0) / 1000);
      const n = stage.pixelCount;
      const bulb = Math.max(1.2, 2.6 * s * dpr);
      const onScreen = (x: number, y: number) => x > -40 && y > -40 && x < w + 40 && y < h + 40;

      // Unlit bulbs.
      ctx.fillStyle = 'rgba(255,255,255,0.10)';
      for (let i = 0; i < n; i++) {
        // LEDs in skipped segments are not drawn: they stay dark on the house too.
        if (!stage.active[i]) continue;
        const x = X(pos[i * 2]);
        const y = Y(pos[i * 2 + 1]);
        if (onScreen(x, y)) ctx.fillRect(x - bulb / 2, y - bulb / 2, bulb, bulb);
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
        const x = X(pos[i * 2]);
        const y = Y(pos[i * 2 + 1]);
        if (!onScreen(x, y)) continue;
        bctx.fillStyle = `rgb(${r},${gg},${b})`;
        const size = Math.max(1.5, 7 * s * dpr * bsx);
        bctx.fillRect(x * bsx - size / 2, y * bsy - size / 2, size, size);
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
        const x = X(pos[i * 2]);
        const y = Y(pos[i * 2 + 1]);
        if (!onScreen(x, y)) continue;
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
  }, [layout, side, zMin, zMax, fill]);

  /** The object of the LED nearest to the pointer, within 14 pixels. */
  const hit = (e: { clientX: number; clientY: number }) => {
    const h = hitRef.current;
    const cv = canvas.current;
    if (!h || !cv) return null;
    const r = cv.getBoundingClientRect();
    const px = e.clientX - r.left;
    const py = e.clientY - r.top;
    const u = h.vb.x + (px / h.w) * h.vb.w;
    const v = h.vb.y + (py / h.h) * h.vb.h;
    const k = h.vb.w / h.w;
    let best = (14 * k) ** 2;
    let idx = -1;
    for (let i = 0; i < h.stage.pixelCount; i++) {
      if (!h.stage.active[i]) continue;
      const d = (h.pos[i * 2] - u) ** 2 + (h.pos[i * 2 + 1] - v) ** 2;
      if (d < best) {
        best = d;
        idx = i;
      }
    }
    const f = idx < 0 ? null : h.stage.fixtures.find((x) => idx >= x.offset && idx < x.offset + x.count);
    return { id: f?.id ?? null, x: px, y: py };
  };
  const pointer = {
    onClick: onPick ? (e: React.MouseEvent) => onPick(hit(e)?.id ?? null, e.ctrlKey || e.metaKey || e.shiftKey) : undefined,
    onPointerMove: onHover
      ? (e: React.PointerEvent) => {
          const r = hit(e);
          if (r) onHover(r.id, { x: r.x, y: r.y });
        }
      : undefined,
    onPointerLeave: onHover ? () => onHover(null, { x: 0, y: 0 }) : undefined
  };

  if (fill) {
    return (
      <div className={cn('absolute inset-0 overflow-hidden bg-[#05070f]', className)}>
        <canvas ref={canvas} className={cn('absolute inset-0 h-full w-full', onPick && 'cursor-pointer')} {...pointer} />
        {children}
      </div>
    );
  }
  return (
    <div
      className={cn('relative mx-auto w-full overflow-hidden rounded-2xl bg-[#05070f] ring-1 ring-white/10', className)}
      style={{ aspectRatio: `${size.w} / ${size.h}`, maxWidth: maxHeight ? `calc(${maxHeight} * ${size.w / size.h})` : undefined }}
    >
      <canvas ref={canvas} className={cn('absolute inset-0 h-full w-full', onPick && 'cursor-pointer')} {...pointer} />
      {children}
    </div>
  );
}
