import { useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { Heart, Star } from 'lucide-react';
import type { GameStatus, Layout } from '../../../shared/layout.ts';
import { YardView } from '../yard/YardView.tsx';
import { coverBox, ledBox } from '../yard/views.ts';
import { cn } from '../lib/utils.ts';

// The game window on the Play page: the yard as the screen of an arcade cabinet, with the game's
// numbers (score, best, lives, stars, team scores) in a bar above it and its progress in a bar
// below. Nothing is drawn over the yard itself, so what happens on the lights is always easy to
// see. Beat Drop has its own, livelier bars (ArcadeHud.tsx) in the same cabinet. The cabinet
// fills the room the controls leave, and the screen zooms in on the lights to fill it.

/**
 * The cabinet's screen: the yard, zoomed in on its lights as far as they all still fit, filling
 * whatever room it is given.
 */
export function GameScreen({ layout, getFrame }: { layout: Layout; getFrame: () => Uint8Array | null }) {
  const ref = useRef<HTMLDivElement>(null);
  const [shape, setShape] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setShape(e.contentRect.height > 0 ? e.contentRect.width / e.contentRect.height : 0));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const lights = useMemo(() => ledBox(layout, 'front', [-480, 480]), [layout]);
  return (
    <div ref={ref} className="relative min-h-0 flex-1 overflow-hidden rounded-2xl ring-1 ring-white/10">
      {shape ? <YardView layout={layout} getFrame={getFrame} fill edge={false} viewBox={coverBox(lights, shape)} /> : null}
    </div>
  );
}

/** The yard as a cabinet's screen, with a bar above it and one below (either can be left out). */
export function Cabinet({
  top,
  bottom,
  className,
  style,
  children
}: {
  top?: React.ReactNode;
  bottom?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  children: React.ReactNode;
}) {
  return (
    <div className={cn('relative flex min-h-0 w-full flex-1 flex-col overflow-hidden rounded-3xl border bg-black/70 p-1.5 font-mono', className)} style={style}>
      {top}
      {children}
      {bottom}
    </div>
  );
}

/** Every game but Beat Drop: the yard, with the game's numbers above it and its progress below. */
export function GameWindow({ status, children }: { status: GameStatus; children: React.ReactNode }) {
  const progress = status.progress;
  const stars = status.goal != null ? { value: status.score, max: status.goal } : progress && progress.max <= 10 ? progress : null;
  const top = !!(status.scores?.length || status.stats?.length || status.lives != null || stars);
  const bottom = progress != null && progress.max > 10;
  const many = (status.stats?.length ?? 0) + (status.lives != null ? 1 : 0) + (stars ? 1 : 0) > 4;
  return (
    <Cabinet
      className="border-white/10"
      top={
        top ? (
          <div className="flex h-14 items-center justify-center gap-4 overflow-hidden px-2.5 sm:gap-10">
            {status.scores?.length ? (
              <div className="flex items-center gap-3">
                {status.scores.map((s, i) => (
                  <div key={s.name} className="flex items-center gap-3">
                    {i > 0 ? <span className="text-lg text-white/30">–</span> : null}
                    <Figure label={s.name} value={s.value} big color={s.color} />
                  </div>
                ))}
              </div>
            ) : null}
            {status.stats?.map((s) => (
              <Figure key={s.label} label={s.label} value={s.value} big={!many} />
            ))}
            {stars ? (
              <div className="flex shrink-0 gap-0.5" aria-label={`${stars.value} of ${stars.max}`}>
                {Array.from({ length: stars.max }, (_, i) => (
                  <Star key={i} className={cn('transition', stars.max > 6 ? 'size-3.5 sm:size-4' : 'size-4 sm:size-5', i < stars.value ? 'fill-amber-300 text-amber-300 drop-shadow-[0_0_6px_rgba(252,211,77,0.8)]' : 'text-white/20')} />
                ))}
              </div>
            ) : null}
            {status.lives != null ? (
              <div className="flex shrink-0 gap-0.5" aria-label={`${status.lives} lives left`}>
                {Array.from({ length: 3 }, (_, i) => (
                  <Heart key={i} className={cn('size-4 sm:size-5', i < (status.lives ?? 0) ? 'fill-rose-500 text-rose-500' : 'text-white/20')} />
                ))}
              </div>
            ) : null}
          </div>
        ) : null
      }
      bottom={progress && bottom ? <ProgressBar value={progress.value} max={progress.max} className="h-8" /> : null}
    >
      {children}
    </Cabinet>
  );
}

/** One number in a bar: a small label over the value. */
function Figure({ label, value, big, color }: { label: string; value: string | number; big?: boolean; color?: string }) {
  return (
    <div className="min-w-0 text-center">
      <p className="truncate text-[9px] leading-none font-bold tracking-[0.2em] text-white/45 uppercase">{label}</p>
      <p
        className={cn('mt-1 truncate leading-none font-black tabular-nums', big ? 'text-lg sm:text-2xl' : 'text-sm sm:text-lg', !color && 'text-white')}
        style={color ? { color, textShadow: `0 0 12px ${color}` } : undefined}
      >
        {value}
      </p>
    </div>
  );
}

/** A long goal as a bar, with the count beside it. */
export function ProgressBar({ value, max, label, className }: { value: number; max: number; label?: string; className?: string }) {
  return (
    <div className={cn('flex items-center gap-2.5 px-2.5 text-[10px] font-bold tracking-[0.15em] text-white/50 uppercase sm:text-xs', className)} aria-label={`${label ?? ''} ${value} of ${max}`.trim()}>
      {label ? <span className="shrink-0">{label}</span> : null}
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full bg-gradient-to-r from-amber-300 to-yellow-200 shadow-[0_0_10px_rgba(252,211,77,0.8)] transition-[width] duration-300" style={{ width: `${Math.min(100, (value / max) * 100)}%` }} />
      </div>
      <span className="shrink-0 text-white/70 tabular-nums">
        {value}/{max}
      </span>
    </div>
  );
}
