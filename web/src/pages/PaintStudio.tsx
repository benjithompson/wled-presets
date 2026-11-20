import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { BrushCleaning, Eraser, PaintBucket, Undo2, WandSparkles } from 'lucide-react';
import type { GameStatus, Layout } from '../../../shared/layout.ts';
import { ERASER, PAINT_BUTTONS, PAINT_COLORS, PAINT_EFFECTS, PAINT_FINGERS, PAINT_MAX_POINTS, type PaintStroke } from '../../../shared/paint.ts';
import { YardView, coverBox, ledBox } from '../yard/YardView.tsx';
import type { PlayMessage } from '../yard/usePlaySocket.ts';
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

/** A finger on the picture: its stroke, and the points it passed that are not sent yet. */
interface Finger {
  finger: number;
  start: boolean;
  points: number[];
  /** Where it is, in CSS pixels on the picture (for the circle under it). */
  x: number;
  y: number;
}

/**
 * The yard, zoomed in on its lights like a game's screen, and painted on with fingers: each
 * finger sends the points it passes, in layout units, a few times a second.
 */
function PaintScreen({ layout, getFrame, choice, swatch, send }: { layout: Layout; getFrame: () => Uint8Array | null; choice: Choice; swatch: string; send: (m: PlayMessage) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState({ w: 0, h: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setBox({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const lights = useMemo(() => ledBox(layout, 'front', [-480, 480]), [layout]);
  const vb = box.w && box.h ? coverBox(lights, box.w / box.h) : null;
  const vbRef = useRef(vb);
  vbRef.current = vb;
  const choiceRef = useRef(choice);
  choiceRef.current = choice;

  const fingers = useRef(new Map<number, Finger>());
  const [shown, setShown] = useState<{ id: number; x: number; y: number }[]>([]);
  const show = () => setShown([...fingers.current].map(([id, f]) => ({ id, x: f.x, y: f.y })));

  const radiusPx = choice.tool === 'fill' ? 18 : BRUSHES[choice.tool];

  const flush = useCallback(
    (f: Finger) => {
      if (!f.points.length) return;
      const c = choiceRef.current;
      // Layout units per CSS pixel of the picture.
      const k = vbRef.current && ref.current?.clientWidth ? vbRef.current.w / ref.current.clientWidth : 1;
      const stroke: PaintStroke = {
        finger: f.finger,
        start: f.start,
        points: f.points,
        radius: (c.tool === 'fill' ? 18 : BRUSHES[c.tool]) * k,
        color: c.color,
        effect: c.effect,
        fill: c.tool === 'fill'
      };
      send({ type: 'paint', ...stroke });
      f.start = false;
      f.points = [];
    },
    [send]
  );

  // While a finger is down, what it painted goes out every SEND_MS.
  useEffect(() => {
    const t = setInterval(() => {
      for (const f of fingers.current.values()) flush(f);
    }, SEND_MS);
    return () => clearInterval(t);
  }, [flush]);

  const at = (e: React.PointerEvent) => {
    const r = ref.current!.getBoundingClientRect();
    const px = e.clientX - r.left;
    const py = e.clientY - r.top;
    const v = vbRef.current;
    if (!v) return null;
    return { px, py, x: v.x + (px / r.width) * v.w, y: v.y + (py / r.height) * v.h };
  };

  const down = (e: React.PointerEvent) => {
    e.preventDefault();
    const p = at(e);
    if (!p) return;
    const used = new Set([...fingers.current.values()].map((f) => f.finger));
    const free = Array.from({ length: PAINT_FINGERS }, (_, i) => i).find((i) => !used.has(i));
    if (free == null) return;
    e.currentTarget.setPointerCapture?.(e.pointerId);
    const f: Finger = { finger: free, start: true, points: [p.x, p.y], x: p.px, y: p.py };
    fingers.current.set(e.pointerId, f);
    // A tap paints at once.
    flush(f);
    navigator.vibrate?.(10);
    show();
  };
  const move = (e: React.PointerEvent) => {
    const f = fingers.current.get(e.pointerId);
    if (!f) return;
    const p = at(e);
    if (!p) return;
    f.x = p.px;
    f.y = p.py;
    f.points.push(p.x, p.y);
    if (f.points.length >= PAINT_MAX_POINTS * 2) flush(f);
    show();
  };
  const up = (e: React.PointerEvent) => {
    const f = fingers.current.get(e.pointerId);
    if (!f) return;
    flush(f);
    fingers.current.delete(e.pointerId);
    show();
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
      {shown.map((f) => (
        <span
          key={f.id}
          className="pointer-events-none absolute rounded-full border-2 border-white/80"
          style={{
            left: f.x - radiusPx,
            top: f.y - radiusPx,
            width: radiusPx * 2,
            height: radiusPx * 2,
            background: choice.color === ERASER ? 'rgba(0,0,0,0.35)' : swatch,
            opacity: 0.45,
            boxShadow: '0 0 16px rgba(255,255,255,0.5)'
          }}
        />
      ))}
    </div>
  );
}
