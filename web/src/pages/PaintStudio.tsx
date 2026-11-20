import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { BrushCleaning, Eraser, PaintBucket, Shrink, Undo2, WandSparkles } from 'lucide-react';
import type { GameStatus, Layout } from '../../../shared/layout.ts';
import { ERASER, PAINT_BUTTONS, PAINT_COLORS, PAINT_EFFECTS, PAINT_MAX_POINTS, type PaintStroke } from '../../../shared/paint.ts';
import { YardView, coverBox, ledBox } from '../yard/YardView.tsx';
import type { PlayMessage } from '../yard/usePlaySocket.ts';
import { clampCam, panBy, pinch, viewBoxOf, wheelFactor, zoomAt, type Cam, type Pair } from '../yard/camera.ts';
import { Cabinet } from './GameWindow.tsx';
import { cn } from '../lib/utils.ts';

// Light Painter on the phone: the yard to paint on with a finger, and a paint box under it made
// for a five-year-old: big round colors, effects as pictures, and a few big tools. Nothing here
// needs reading.

/** The brushes: a radius in CSS pixels on the picture (so a brush is the same size on any phone). */
const BRUSHES = { small: 14, big: 34 } as const;
type Tool = keyof typeof BRUSHES | 'fill';
/** How often a moving finger sends what it painted (a message holds every point since the last). */
const SEND_MS = 40;

type Choice = { color: string; effect: string; tool: Tool };

export function PaintStudio({
  layout,
  getFrame,
  status,
  send,
  banner
}: {
  layout: Layout;
  getFrame: () => Uint8Array | null;
  status: GameStatus;
  send: (m: PlayMessage) => void;
  banner?: React.ReactNode;
}) {
  const [choice, setChoice] = useState<Choice>({ color: 'pink', effect: 'twinkle', tool: 'big' });
  const pad = status.paint;
  const erasing = choice.color === ERASER;
  const swatch = PAINT_COLORS.find((c) => c.id === choice.color)?.css ?? '#fff';
  const tap = (button: string) => {
    send({ type: 'input', action: 'press', button });
    send({ type: 'input', action: 'release', button });
    navigator.vibrate?.(15);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex min-h-52 flex-1 flex-col">
        <Cabinet className="border-white/10">
          <PaintScreen layout={layout} getFrame={getFrame} choice={choice} swatch={swatch} send={send} />
        </Cabinet>
      </div>
      {banner}
      <p className="text-center text-base leading-snug font-bold tracking-tight text-balance sm:text-xl" aria-live="polite">
        {status.message}
      </p>

      {/* Colors: big round swatches, two rows on a phone. */}
      <div role="radiogroup" aria-label="Colors" className="mx-auto grid w-full max-w-2xl grid-cols-6 gap-2 sm:grid-cols-11">
        {PAINT_COLORS.map((c) => {
          const on = c.id === choice.color;
          return (
            <button
              key={c.id}
              type="button"
              role="radio"
              aria-checked={on}
              aria-label={c.name}
              title={c.name}
              onClick={() => setChoice((s) => ({ ...s, color: c.id }))}
              style={{ background: c.css, boxShadow: on && c.id !== ERASER ? `0 0 18px 2px ${c.id === 'rainbow' ? '#f0abfc' : c.css}` : undefined }}
              className={cn(
                'mx-auto grid aspect-square w-full max-w-14 touch-manipulation place-items-center rounded-full transition select-none',
                on ? 'scale-110 ring-4 ring-white' : 'ring-2 ring-white/15 active:scale-95',
                c.id === ERASER && 'text-white/80'
              )}
            >
              {c.id === ERASER ? <Eraser className="size-5" /> : null}
            </button>
          );
        })}
      </div>

      {/* Effects: a picture each. */}
      <div role="radiogroup" aria-label="Effects" className={cn('mx-auto grid w-full max-w-2xl grid-cols-6 gap-1.5 transition', erasing && 'opacity-40')}>
        {PAINT_EFFECTS.map((e) => {
          const on = e.id === choice.effect;
          return (
            <button
              key={e.id}
              type="button"
              role="radio"
              aria-checked={on}
              onClick={() => setChoice((s) => ({ ...s, effect: e.id, color: s.color === ERASER ? 'pink' : s.color }))}
              className={cn(
                'flex touch-manipulation flex-col items-center gap-0.5 rounded-2xl py-1.5 transition select-none',
                on ? 'bg-white/20 ring-2 ring-white' : 'bg-white/5 ring-1 ring-white/10 active:scale-95'
              )}
            >
              <span className="text-2xl leading-none sm:text-3xl" aria-hidden>
                {e.icon}
              </span>
              <span className="text-[10px] font-semibold text-white/70 sm:text-xs">{e.name}</span>
            </button>
          );
        })}
      </div>

      {/* Tools: the brushes and the fill bucket, then undo, surprise and clear. */}
      <div className="mx-auto flex w-full max-w-2xl items-stretch justify-center gap-1.5">
        <div role="radiogroup" aria-label="Brush" className="flex flex-[3] gap-1.5">
          {(['small', 'big', 'fill'] as const).map((t) => {
            const on = t === choice.tool;
            const label = t === 'small' ? 'Thin brush' : t === 'big' ? 'Fat brush' : 'Fill';
            return (
              <button
                key={t}
                type="button"
                role="radio"
                aria-checked={on}
                aria-label={label}
                title={label}
                onClick={() => setChoice((s) => ({ ...s, tool: t }))}
                className={cn('grid h-14 flex-1 touch-manipulation place-items-center rounded-2xl transition select-none', on ? 'bg-white/20 ring-2 ring-white' : 'bg-white/5 ring-1 ring-white/10 active:scale-95')}
              >
                {t === 'fill' ? (
                  <PaintBucket className="size-7" style={{ color: erasing ? undefined : swatch.startsWith('#') ? swatch : '#f0abfc' }} />
                ) : (
                  <span className="rounded-full ring-2 ring-white/40" style={{ background: erasing ? '#57534e' : swatch, width: t === 'small' ? 12 : 30, height: t === 'small' ? 12 : 30 }} />
                )}
              </button>
            );
          })}
        </div>
        <span className="w-1" />
        <ToolButton label="Undo" disabled={!pad?.canUndo} onClick={() => tap(PAINT_BUTTONS.undo)}>
          <Undo2 className="size-7" />
        </ToolButton>
        <ToolButton label="Surprise!" onClick={() => tap(PAINT_BUTTONS.surprise)} className="bg-gradient-to-br from-fuchsia-500/40 via-amber-400/30 to-sky-500/40">
          <WandSparkles className="size-7 text-amber-200" />
        </ToolButton>
        <ToolButton label="Clear all" disabled={pad?.empty} onClick={() => tap(PAINT_BUTTONS.clear)}>
          <BrushCleaning className="size-7" />
        </ToolButton>
      </div>
    </div>
  );
}

function ToolButton({ label, disabled, onClick, className, children }: { label: string; disabled?: boolean; onClick: () => void; className?: string; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className={cn('grid h-14 flex-1 touch-manipulation place-items-center rounded-2xl bg-white/5 ring-1 ring-white/10 transition select-none active:scale-95 disabled:opacity-30', className)}
    >
      {children}
    </button>
  );
}

/** A finger painting: its stroke, and the points it passed that are not sent yet. */
interface Stroke {
  pointer: number;
  start: boolean;
  points: number[];
  /** A touch waits this long (ms timestamp) before it paints: it may be the first finger of a pinch. */
  sendAt: number;
}

/** A touch is held back this long, so a pinch that starts with one finger leaves no dot. */
const HOLD_MS = 90;
/** Zoomed in at most this many times closer than all the lights. */
const CLOSEST = 8;

/**
 * The yard, zoomed in on its lights like a game's screen, and painted on with a finger, which
 * sends the points it passes (layout units) a few times a second. Two fingers zoom (pinch) and
 * pan; on a computer, the wheel zooms at the pointer and the right or middle button pans.
 */
function PaintScreen({ layout, getFrame, choice, swatch, send }: { layout: Layout; getFrame: () => Uint8Array | null; choice: Choice; swatch: string; send: (m: PlayMessage) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [px, setPx] = useState({ w: 0, h: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setPx({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const lights = useMemo(() => ledBox(layout, 'front', [-480, 480]), [layout]);
  /** All the lights, filling the screen: as far out as the camera goes, and as far as it pans. */
  const bounds = px.w && px.h ? coverBox(lights, px.w / px.h) : null;
  const far: Cam | null = bounds ? { cx: bounds.x + bounds.w / 2, cy: bounds.y + bounds.h / 2, k: bounds.w / px.w } : null;
  /** The camera; null: all the lights. */
  const [cam, setCam] = useState<Cam | null>(null);
  const shown = far && bounds ? clampCam(cam ?? far, px, far, bounds, CLOSEST) : null;
  const vb = shown ? viewBoxOf(shown, px) : null;
  const zoomed = !!(shown && far && shown.k < far.k * 0.98);

  const view = useRef({ shown, far, bounds, px });
  view.current = { shown, far, bounds, px };
  const choiceRef = useRef(choice);
  choiceRef.current = choice;
  /** Sets the camera, kept on the lights. */
  const moveTo = useCallback((c: Cam) => {
    const { far: f, bounds: b, px: p } = view.current;
    if (f && b) setCam(clampCam(c, p, f, b, CLOSEST));
  }, []);

  /** Every pointer down on the picture, where it is (pixels in the pane). */
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const stroke = useRef<Stroke | null>(null);
  const gesture = useRef<{ ids: [number, number]; from: Pair; start: Cam } | null>(null);
  /** After a pinch, the fingers left down do not paint until all of them lift. */
  const locked = useRef(false);
  const mousePan = useRef<{ id: number; x: number; y: number } | null>(null);
  /** The circle under the painting finger, in pixels. */
  const [ring, setRing] = useState<{ x: number; y: number } | null>(null);
  const radiusPx = choice.tool === 'fill' ? 18 : BRUSHES[choice.tool];

  /** A pane pixel in layout units. */
  const toLayout = (p: { x: number; y: number }) => {
    const { shown: c, px: size } = view.current;
    if (!c) return null;
    const b = viewBoxOf(c, size);
    return { x: b.x + (p.x / size.w) * b.w, y: b.y + (p.y / size.h) * b.h };
  };

  const flush = useCallback(
    (s: Stroke, force = false) => {
      if (!s.points.length || (!force && performance.now() < s.sendAt)) return;
      const c = choiceRef.current;
      const k = view.current.shown?.k ?? 1;
      const m: PaintStroke = { finger: 0, start: s.start, points: s.points, radius: (c.tool === 'fill' ? 18 : BRUSHES[c.tool]) * k, color: c.color, effect: c.effect, fill: c.tool === 'fill' };
      send({ type: 'paint', ...m });
      if (s.start) navigator.vibrate?.(10);
      s.start = false;
      s.points = [];
    },
    [send]
  );

  // While a finger paints, what it passed goes out every SEND_MS.
  useEffect(() => {
    const t = setInterval(() => stroke.current && flush(stroke.current), SEND_MS);
    return () => clearInterval(t);
  }, [flush]);

  // The wheel (or a trackpad pinch) zooms at the pointer. React's wheel events cannot be stopped
  // from scrolling the page, so this one is added by hand.
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const wheel = (e: WheelEvent) => {
      const { shown: c, px: size } = view.current;
      if (!c) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      moveTo(zoomAt(c, size, { x: e.clientX - r.left, y: e.clientY - r.top }, wheelFactor(e)));
    };
    // Safari's own pinch events would zoom the whole page instead of the picture.
    const gesture = (e: Event) => e.preventDefault();
    el.addEventListener('wheel', wheel, { passive: false });
    el.addEventListener('gesturestart', gesture);
    el.addEventListener('gesturechange', gesture);
    return () => {
      el.removeEventListener('wheel', wheel);
      el.removeEventListener('gesturestart', gesture);
      el.removeEventListener('gesturechange', gesture);
    };
  }, [moveTo]);

  const at = (e: React.PointerEvent) => {
    const r = ref.current!.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };
  const pairOf = (ids: [number, number]): Pair | null => {
    const a = pointers.current.get(ids[0]);
    const b = pointers.current.get(ids[1]);
    return a && b ? [{ ...a }, { ...b }] : null;
  };

  /** The painting finger stops: what it painted goes out, unless it never really started (a pinch). */
  const endStroke = (keep: boolean) => {
    const s = stroke.current;
    if (!s) return;
    if (keep || !s.start) flush(s, true);
    stroke.current = null;
    setRing(null);
  };

  const down = (e: React.PointerEvent) => {
    e.preventDefault();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    const p = at(e);
    // The right or middle mouse button pans.
    if (e.pointerType === 'mouse' && e.button !== 0) {
      mousePan.current = { id: e.pointerId, ...p };
      return;
    }
    pointers.current.set(e.pointerId, p);
    if (pointers.current.size === 2 && view.current.shown) {
      // A second finger: this is a pinch, not painting. A first touch that has not painted yet
      // is dropped; one that has keeps what it painted.
      endStroke(false);
      const ids = [...pointers.current.keys()] as [number, number];
      gesture.current = { ids, from: pairOf(ids)!, start: view.current.shown };
      locked.current = true;
      return;
    }
    if (pointers.current.size > 1 || locked.current) return;
    const q = toLayout(p);
    if (!q) return;
    stroke.current = { pointer: e.pointerId, start: true, points: [q.x, q.y], sendAt: e.pointerType === 'touch' ? performance.now() + HOLD_MS : 0 };
    flush(stroke.current);
    setRing(p);
  };

  const move = (e: React.PointerEvent) => {
    const p = at(e);
    const pan = mousePan.current;
    if (pan && pan.id === e.pointerId) {
      const c = view.current.shown;
      if (c) moveTo(panBy(c, p.x - pan.x, p.y - pan.y));
      mousePan.current = { id: pan.id, ...p };
      return;
    }
    if (!pointers.current.has(e.pointerId)) return;
    pointers.current.set(e.pointerId, p);
    const g = gesture.current;
    if (g) {
      const to = pairOf(g.ids);
      if (to) moveTo(pinch(g.start, view.current.px, g.from, to));
      return;
    }
    const s = stroke.current;
    if (!s || s.pointer !== e.pointerId) return;
    const q = toLayout(p);
    if (!q) return;
    s.points.push(q.x, q.y);
    if (s.points.length >= PAINT_MAX_POINTS * 2) flush(s, true);
    setRing(p);
  };

  const up = (e: React.PointerEvent) => {
    if (mousePan.current?.id === e.pointerId) {
      mousePan.current = null;
      return;
    }
    if (!pointers.current.delete(e.pointerId)) return;
    // A quick tap paints, even before its wait is over.
    if (stroke.current?.pointer === e.pointerId) endStroke(true);
    if (gesture.current?.ids.includes(e.pointerId)) gesture.current = null;
    if (!pointers.current.size) locked.current = false;
  };

  return (
    <div
      ref={ref}
      className="relative min-h-0 flex-1 cursor-crosshair touch-none overflow-hidden rounded-2xl ring-1 ring-white/10 select-none [-webkit-touch-callout:none]"
      onPointerDown={down}
      onPointerMove={move}
      onPointerUp={up}
      onPointerCancel={up}
      onLostPointerCapture={up}
      onContextMenu={(e) => e.preventDefault()}
    >
      {vb ? <YardView layout={layout} getFrame={getFrame} fill edge={false} viewBox={vb} /> : null}
      {ring ? (
        <span
          className="pointer-events-none absolute rounded-full border-2 border-white/80"
          style={{
            left: ring.x - radiusPx,
            top: ring.y - radiusPx,
            width: radiusPx * 2,
            height: radiusPx * 2,
            background: choice.color === ERASER ? 'rgba(0,0,0,0.35)' : swatch,
            opacity: 0.45,
            boxShadow: '0 0 16px rgba(255,255,255,0.5)'
          }}
        />
      ) : null}
      {zoomed ? (
        <button
          type="button"
          aria-label="See all the lights"
          title="See all the lights"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={() => setCam(null)}
          className="absolute top-2 right-2 grid size-11 touch-manipulation place-items-center rounded-full bg-black/60 text-white ring-1 ring-white/25 backdrop-blur transition active:scale-95"
        >
          <Shrink className="size-5" />
        </button>
      ) : null}
    </div>
  );
}
