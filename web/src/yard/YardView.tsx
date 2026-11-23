import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import type React from 'react';
import { AERIAL_OPACITY, buildStage, BUSH_TALL, drawnByPaths, FEET_PER_METER, layoutGround, layoutScale, objectPaths, radiusOf, treeOutline, type Layout, type Point } from '../../../shared/layout.ts';
import type { Box } from './camera.ts';
import { fitBox, toView, viewPositions, viewSize, type ViewSide } from './views.ts';
import { acrossOf, frontCamera } from './frontCamera.ts';
import { cn } from '../lib/utils.ts';

/** True when the first `n` bytes of two arrays are the same. */
function sameBytes(a: Uint8Array, b: Uint8Array, n: number) {
  if (a.length < n || b.length < n) return false;
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Draws the yard: the background picture (or a night sky), faint guides along each light
 * object, and every LED as a glowing bulb in the color of the current frame.
 * `getFrame` is called on every animation frame and returns RGB bytes, one triple per LED.
 * The top view shows the front wall of the house instead, over the picture from above
 * (Layout.aerial) when there is one. `grid` draws a grid (every `gridStep` layout units, by
 * default 1 m or 5 ft) from the left edge and from the ground (front) or the front wall (top).
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
  edge = true,
  viewBox,
  grid,
  gridStep: gridStepProp,
  gridMajor = 5,
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
  /** With `fill`: outline the edge of the picture. */
  edge?: boolean;
  /** What the view shows, in view units. Default: the whole yard. */
  viewBox?: Box;
  /** Draw a grid. Default: in the top view only. */
  grid?: boolean;
  /** Layout units between grid lines. Default: 1 m, or 5 ft. */
  gridStep?: number;
  /** Every this many grid lines, one is brighter. */
  gridMajor?: number;
  /** A click on (or near) an LED: its object. A click on nothing: null. `add`: Ctrl, ⌘ or Shift was down. */
  onPick?: (id: string | null, add: boolean) => void;
  /** The object under the pointer (null: none), and where the pointer is in the view (CSS pixels). */
  onHover?: (id: string | null, at: { x: number; y: number }) => void;
}) {
  const [zMin, zMax] = zRange;
  const size = viewSize(layout, side, zRange);
  // Everything always fits: the default box takes in every LED, even outside the yard.
  const fit = useMemo(() => fitBox(layout, side, [zMin, zMax]), [layout, side, zMin, zMax]);
  const canvas = useRef<HTMLCanvasElement>(null);
  const getFrameRef = useRef(getFrame);
  getFrameRef.current = getFrame;
  const highlightRef = useRef<Set<string>>(new Set());
  highlightRef.current = new Set(highlight == null ? [] : Array.isArray(highlight) ? highlight : [highlight]);
  /** What the last frame drew, to find the LED under the pointer. */
  const hitRef = useRef<{
    stage: ReturnType<typeof buildStage>;
    pos: Float32Array;
    vb: Box;
    w: number;
    h: number;
  } | null>(null);
  // Read on every frame, so panning and zooming do not restart the drawing loop.
  const boxRef = useRef<Box>(fit);
  boxRef.current = viewBox ?? fit;
  const gridRef = useRef(grid ?? side === 'top');
  gridRef.current = grid ?? side === 'top';
  const gridSizeRef = useRef({ step: gridStepProp, major: gridMajor });
  gridSizeRef.current = { step: gridStepProp, major: gridMajor };

  useEffect(() => {
    const cv = canvas.current;
    if (!cv) return;
    const ctx = cv.getContext('2d');
    if (!ctx) return;
    const stage = buildStage(layout);
    const top = side === 'top';
    const sideView = side === 'side';
    // LED positions in view coordinates.
    // The front view, turned to where its picture was taken from (Layout.frontView).
    const cam = side === 'front' ? frontCamera(layout) : null;
    const pos = viewPositions(stage.positions3, side, zMin, cam);
    const view = (p: Point) => toView(p, side, zMin, cam);
    const scale = layoutScale(layout);
    const defaultGridStep = layout.units === 'm' ? scale : (scale * 5) / FEET_PER_METER;
    // Grid lines count from the left edge, and from the ground (front) or the front wall (top).
    const gridV0 = top ? -zMin : layoutGround(layout);
    // Layers, all reused from frame to frame:
    // - base: what does not change while the view holds still (sky, pictures, grid, guides, unlit
    //   bulbs), drawn again only when the view moves or the canvas changes size;
    // - bloom: the lit bulbs, a quarter of the size, written pixel by pixel;
    // - glow: the bloom blurred, at the same small size (blurring the full-size canvas costs
    //   sixteen times as much, and a wide blur looks the same).
    const base = document.createElement('canvas');
    const bloom = document.createElement('canvas');
    const bctx = bloom.getContext('2d')!;
    const glow = document.createElement('canvas');
    const gctx = glow.getContext('2d')!;
    let bloomPixels: ImageData | null = null;
    let baseKey = '';
    let drawnKey = '';
    let drawn: Uint8Array | null = null;
    let drawnCopy = new Uint8Array(0);
    // Lit bulbs by color (quantized, 32 levels a channel): one path and one fill per color.
    const byColor = new Map<number, number[]>();
    const cores = Array.from({ length: 8 }, () => [] as number[]);
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
      const vb = boxRef.current;
      hitRef.current = {
        stage,
        pos,
        vb,
        w: cv.clientWidth,
        h: cv.clientHeight
      };
      const sx = w / vb.w;
      const sy = h / vb.h;
      const X = (u: number) => (u - vb.x) * sx;
      const Y = (v: number) => (v - vb.y) * sy;
      // Bulbs and glow grow when you zoom in, up to a limit.
      const s = Math.min(sx, sy, 3 * dpr);

      const n = stage.pixelCount;
      const bulb = Math.max(1.2, 2.6 * s * dpr);
      const onScreen = (x: number, y: number) => x > -40 && y > -40 && x < w + 40 && y < h + 40;

      // The still part of the picture: drawn again only when it changed.
      const bgReady = !!(bg?.complete && bg.naturalWidth);
      const aerialReady = !!(aerialImg?.complete && aerialImg.naturalWidth);
      const key = `${w}x${h} ${vb.x},${vb.y},${vb.w},${vb.h} ${[...highlightRef.current].join(',')} ${gridRef.current} ${gridSizeRef.current.step} ${gridSizeRef.current.major} ${bgReady} ${aerialReady}`;
      if (key !== baseKey) {
        baseKey = key;
        if (base.width !== w || base.height !== h) {
          base.width = w;
          base.height = h;
        }
        paintBase(base.getContext('2d')!);
      }
      function paintBase(ctx: CanvasRenderingContext2D) {
        // Background: the photo, darkened so the lights read as night, or a night sky.
        ctx.globalCompositeOperation = 'source-over';
        ctx.filter = 'none';
        const sky = ctx.createLinearGradient(0, 0, 0, h);
        sky.addColorStop(0, '#05070f');
        sky.addColorStop(1, '#0d0b10');
        ctx.fillStyle = sky;
        ctx.fillRect(0, 0, w, h);
        if (side === 'front' && bg?.complete && bg.naturalWidth) {
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
        if (fill && edge && side === 'front') {
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
        if (sideView) {
          // The house, left of its front wall (depth 0), above the ground.
          ctx.fillStyle = 'rgba(255,255,255,0.025)';
          ctx.fillRect(0, 0, Math.max(0, X(0)), Math.max(0, Y(layoutGround(layout))));
        }
        if (gridRef.current) {
          // Grid lines; every `gridMajor`th line is brighter. Lines closer than 6 pixels are left out.
          const u0 = vb.x;
          const v0 = vb.y;
          const { step: setStep, major: every } = gridSizeRef.current;
          const gridStep = setStep && setStep > 0 ? setStep : defaultGridStep;
          const lines = (major: boolean) => {
            const step = gridStep * (major ? Math.max(1, Math.round(every)) : 1);
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
        if (sideView) {
          // The front wall of the house (depth 0) and the ground.
          ctx.strokeStyle = 'rgba(251,191,36,0.35)';
          ctx.lineWidth = 2 * dpr;
          ctx.beginPath();
          ctx.moveTo(X(0), 0);
          ctx.lineTo(X(0), Y(layoutGround(layout)));
          ctx.stroke();
          ctx.strokeStyle = 'rgba(52,211,153,0.35)';
          ctx.beginPath();
          ctx.moveTo(0, Y(layoutGround(layout)));
          ctx.lineTo(w, Y(layoutGround(layout)));
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
          const r = radiusOf(f);
          ctx.beginPath();
          if (drawnByPaths(f)) {
            for (const path of objectPaths(f, layoutScale(layout)))
              path.forEach((p, i) => {
                const q = view(p);
                if (i) ctx.lineTo(X(q.u), Y(q.v));
                else ctx.moveTo(X(q.u), Y(q.v));
              });
          } else if (top) {
            // From above, bushes and trees are circles.
            ctx.ellipse(X(c.u), Y(c.v), r * sx + (hl ? 6 * dpr : 0), r * sy + (hl ? 6 * dpr : 0), 0, 0, Math.PI * 2);
          } else if (f.kind === 'tree') {
            treeOutline(f, sideView ? 'side' : cam ? acrossOf(cam) : 'front').forEach((p, i) => {
              const q = view(p);
              if (i) ctx.lineTo(X(q.u), Y(q.v));
              else ctx.moveTo(X(q.u), Y(q.v));
            });
            ctx.closePath();
          } else if (hl) {
            ctx.ellipse(X(c.u), Y(c.v), r * sx + 6 * dpr, r * BUSH_TALL * sy + 6 * dpr, 0, 0, Math.PI * 2);
          }
          ctx.stroke();
        }

        // Unlit bulbs.
        ctx.fillStyle = 'rgba(255,255,255,0.10)';
        for (let i = 0; i < n; i++) {
          // LEDs in skipped segments are not drawn: they stay dark on the house too.
          if (!stage.active[i]) continue;
          const x = X(pos[i * 2]);
          const y = Y(pos[i * 2 + 1]);
          if (onScreen(x, y)) ctx.fillRect(x - bulb / 2, y - bulb / 2, bulb, bulb);
        }
      }

      const frame = getFrameRef.current((performance.now() - t0) / 1000);
      const lit = !!frame && frame.length >= n * 3;
      // Nothing new: the frames come 30 times a second, the screen asks up to 120.
      if (key === drawnKey && (lit ? drawn === frame && sameBytes(frame, drawnCopy, n * 3) : drawn === null)) return;
      drawnKey = key;
      drawn = lit ? frame : null;
      if (lit) {
        if (drawnCopy.length !== n * 3) drawnCopy = new Uint8Array(n * 3);
        drawnCopy.set(frame.subarray(0, n * 3));
      }

      ctx.globalCompositeOperation = 'copy';
      ctx.filter = 'none';
      ctx.globalAlpha = 1;
      ctx.drawImage(base, 0, 0);
      ctx.globalCompositeOperation = 'source-over';
      if (!lit) return;

      // Bloom: lit bulbs in a quarter-size layer, blurred, added. The layer keeps the brightest
      // bulb per spot (per channel), not the sum, so dense strips do not blow out.
      const bw = Math.max(1, Math.round(w / 4));
      const bh = Math.max(1, Math.round(h / 4));
      if (bloom.width !== bw || bloom.height !== bh) {
        bloom.width = glow.width = bw;
        bloom.height = glow.height = bh;
      }
      if (!bloomPixels || bloomPixels.width !== bw || bloomPixels.height !== bh) bloomPixels = bctx.createImageData(bw, bh);
      const px = bloomPixels.data;
      px.fill(0);
      const bsx = bw / w;
      const bsy = bh / h;
      const half = Math.max(1.5, 7 * s * dpr * bsx) / 2;
      byColor.forEach((list) => (list.length = 0));
      for (const c of cores) c.length = 0;
      for (let i = 0; i < n; i++) {
        const r = frame[i * 3],
          gg = frame[i * 3 + 1],
          b = frame[i * 3 + 2];
        const m = Math.max(r, gg, b);
        if (m < 6) continue;
        const x = X(pos[i * 2]);
        const y = Y(pos[i * 2 + 1]);
        if (!onScreen(x, y)) continue;
        const q = ((r >> 3) << 10) | ((gg >> 3) << 5) | (b >> 3);
        let list = byColor.get(q);
        if (!list) byColor.set(q, (list = []));
        list.push(i);
        if (m > 160) cores[Math.min(7, ((m - 160) * 8) / 96) | 0].push(i);
        if (r + gg + b < 12) continue;
        const bx = x * bsx;
        const by = y * bsy;
        const x0 = Math.max(0, Math.round(bx - half));
        const x1 = Math.min(bw, Math.max(x0 + 1, Math.round(bx + half)));
        const y0 = Math.max(0, Math.round(by - half));
        const y1 = Math.min(bh, Math.max(y0 + 1, Math.round(by + half)));
        for (let yy = y0; yy < y1; yy++) {
          for (let k = (yy * bw + x0) * 4, e = (yy * bw + x1) * 4; k < e; k += 4) {
            if (px[k] < r) px[k] = r;
            if (px[k + 1] < gg) px[k + 1] = gg;
            if (px[k + 2] < b) px[k + 2] = b;
            px[k + 3] = 255;
          }
        }
      }
      bctx.putImageData(bloomPixels, 0, 0);
      gctx.globalCompositeOperation = 'copy';
      gctx.filter = `blur(${Math.max(2, 10 * s * dpr) * bsx}px)`;
      gctx.drawImage(bloom, 0, 0);
      gctx.globalCompositeOperation = 'lighter';
      gctx.globalAlpha = 0.6;
      gctx.filter = `blur(${Math.max(4, 26 * s * dpr) * bsx}px)`;
      gctx.drawImage(bloom, 0, 0);
      gctx.globalAlpha = 1;
      gctx.filter = 'none';
      ctx.globalCompositeOperation = 'lighter';
      ctx.drawImage(glow, 0, 0, w, h);

      // Crisp bulbs on top (added, like the glow), with a white-hot core when bright: one path per color.
      const rad = bulb * 0.9;
      byColor.forEach((list, q) => {
        if (!list.length) return;
        ctx.fillStyle = `rgb(${((q >> 10) << 3) | 4},${(((q >> 5) & 31) << 3) | 4},${((q & 31) << 3) | 4})`;
        ctx.beginPath();
        for (const i of list) {
          const x = X(pos[i * 2]);
          const y = Y(pos[i * 2 + 1]);
          ctx.moveTo(x + rad, y);
          ctx.arc(x, y, rad, 0, Math.PI * 2);
        }
        ctx.fill();
      });
      cores.forEach((list, step) => {
        if (!list.length) return;
        ctx.fillStyle = `rgba(255,255,255,${(((step + 0.5) * 12) / 95) * 0.8})`;
        ctx.beginPath();
        for (const i of list) {
          const x = X(pos[i * 2]);
          const y = Y(pos[i * 2 + 1]);
          ctx.moveTo(x + bulb * 0.45, y);
          ctx.arc(x, y, bulb * 0.45, 0, Math.PI * 2);
        }
        ctx.fill();
      });
      ctx.globalCompositeOperation = 'source-over';
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [layout, side, zMin, zMax, fill, edge]);

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
      style={{
        aspectRatio: `${fit.w} / ${fit.h}`,
        maxWidth: maxHeight ? `calc(${maxHeight} * ${fit.w / fit.h})` : undefined
      }}
    >
      <canvas ref={canvas} className={cn('absolute inset-0 h-full w-full', onPick && 'cursor-pointer')} {...pointer} />
      {children}
    </div>
  );
}
