import { useEffect, useRef, useState } from 'react';
import type React from 'react';
import type { ArcadeHud as Hud } from '../../../shared/layout.ts';
import { cn } from '../lib/utils.ts';

// Beat Drop's score display on the phone, like an arcade cabinet: a rolling score, the
// multiplier with a meter charging toward the next one, the streak, and a pop for every
// judgment. A new multiplier takes over the whole screen (bigger at every step); losing one
// shakes the display.

/** Each multiplier's color: ×1 plain, ×2 cyan, ×3 magenta, ×4 a rainbow. */
const MULT_COLOR = ['#e7e5e4', '#e7e5e4', '#22d3ee', '#e879f9', '#fde047'];
const multColor = (m: number) => MULT_COLOR[Math.min(m, MULT_COLOR.length - 1)];

const JUDGED: Record<NonNullable<Hud['judged']>['kind'], string> = {
  perfect: 'text-amber-200 [text-shadow:0_0_18px_rgba(252,211,77,0.9),0_0_40px_rgba(251,146,60,0.6)]',
  held: 'text-emerald-200 [text-shadow:0_0_18px_rgba(52,211,153,0.9)]',
  good: 'text-sky-200 [text-shadow:0_0_14px_rgba(56,189,248,0.8)]',
  miss: 'text-red-400 [text-shadow:0_0_18px_rgba(239,68,68,0.9)]',
  stray: 'text-orange-300 [text-shadow:0_0_14px_rgba(251,146,60,0.8)]'
};

export function ArcadeHud({ hud }: { hud: Hud }) {
  const shown = useRolling(hud.score);
  const top = hud.mult >= hud.maxMult;
  const color = multColor(hud.mult);
  const newBest = hud.best > 0 && hud.score > hud.best;

  // Points as they land: "+6" floats up from the score.
  const [gains, setGains] = useState<{ id: number; value: number }[]>([]);
  const lastScore = useRef(hud.score);
  useEffect(() => {
    const d = hud.score - lastScore.current;
    lastScore.current = hud.score;
    if (d <= 0) return;
    const id = Date.now() + Math.random();
    setGains((g) => [...g.slice(-3), { id, value: d }]);
    const t = setTimeout(() => setGains((g) => g.filter((x) => x.id !== id)), 900);
    return () => clearTimeout(t);
  }, [hud.score]);

  // A new multiplier: the whole screen celebrates. Losing one: the display shakes.
  const power = useEdge(hud.ups, 1600);
  const crash = useEdge(hud.drops, 600);
  const best = useEdge(newBest ? 1 : 0, 1600);
  useEffect(() => {
    if (power) navigator.vibrate?.(Array.from({ length: hud.mult * 2 - 1 }, (_, i) => (i % 2 ? 40 : 60)));
  }, [power, hud.mult]);
  useEffect(() => {
    if (crash) navigator.vibrate?.(150);
  }, [crash]);

  const digits = String(shown).padStart(7, '0');
  const lead = digits.length - String(shown).length;

  return (
    <div className="relative w-full max-w-xl">
      <div
        className={cn(
          'relative overflow-hidden rounded-3xl border-2 bg-black/50 p-4 font-mono transition-[box-shadow,border-color] duration-500 sm:p-5',
          crash ? 'hud-shake border-red-500/80' : top ? 'border-amber-300/70' : 'border-white/10'
        )}
        style={{ boxShadow: `0 0 ${12 + hud.mult * 10}px ${hud.mult > 1 ? color : 'transparent'}66, inset 0 0 40px rgba(0,0,0,0.6)` }}
      >
        {crash ? <div className="hud-flash pointer-events-none absolute inset-0 bg-red-600/40" /> : null}
        {/* The score and the best. */}
        <div className="flex items-start justify-between gap-3">
          <div className="relative min-w-0">
            <p className="text-[10px] font-bold tracking-[0.3em] text-white/50 uppercase sm:text-xs">Score</p>
            <p className="text-4xl leading-none font-black tracking-tight tabular-nums sm:text-5xl" aria-label={`Score ${hud.score}`}>
              <span className="text-white/15">{digits.slice(0, lead)}</span>
              <span className="text-white [text-shadow:0_0_14px_rgba(255,255,255,0.45)]">{digits.slice(lead)}</span>
            </p>
            {gains.map((g) => (
              <span key={g.id} className="hud-float pointer-events-none absolute top-6 right-0 text-lg font-black" style={{ color, textShadow: `0 0 10px ${color}` }}>
                +{g.value}
              </span>
            ))}
          </div>
          <div className="shrink-0 text-right">
            {/* Beaten: the best is this game's score now, in a rainbow. */}
            <p className={cn('text-[10px] font-bold tracking-[0.3em] uppercase sm:text-xs', newBest ? 'hud-rainbow font-black' : 'text-white/50')}>{newBest ? 'New best!' : 'Best'}</p>
            <p className="text-lg font-bold text-amber-200/80 tabular-nums sm:text-xl">{Math.max(hud.best, shown)}</p>
            <p className="mt-1 text-[10px] tracking-widest text-white/40 uppercase sm:text-xs">
              {hud.info.map((x) => `${x.label} ${x.value}`).join(' · ')}
            </p>
          </div>
        </div>

        {/* The multiplier, and its meter charging toward the next one. */}
        <div className="mt-4 flex items-center gap-3">
          <div
            key={hud.ups}
            className={cn('hud-bump grid size-16 shrink-0 place-items-center rounded-2xl border-2 text-3xl font-black sm:size-20 sm:text-4xl', top && 'hud-charge')}
            style={{ color, borderColor: `color-mix(in srgb, ${color} 60%, transparent)`, backgroundColor: `color-mix(in srgb, ${color} ${hud.mult > 1 ? 18 : 6}%, transparent)`, boxShadow: hud.mult > 1 ? `0 0 ${hud.mult * 8}px ${color}` : undefined }}
            aria-label={`Multiplier ×${hud.mult}`}
          >
            {top ? <span className="hud-rainbow">×{hud.mult}</span> : `×${hud.mult}`}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex gap-1" aria-hidden>
              {Array.from({ length: hud.perStep }, (_, i) => {
                const on = i < hud.charge;
                const next = multColor(Math.min(hud.maxMult, hud.mult + 1));
                return (
                  <span
                    key={i}
                    className={cn('h-4 flex-1 rounded-sm transition-all duration-150 sm:h-5', top && 'hud-charge')}
                    style={
                      on
                        ? { backgroundColor: top ? `hsl(${(i / hud.perStep) * 300} 95% 62%)` : next, boxShadow: `0 0 8px ${top ? '#fde047' : next}` }
                        : { backgroundColor: 'rgba(255,255,255,0.08)' }
                    }
                  />
                );
              })}
            </div>
            <p className="mt-1.5 flex items-baseline justify-between text-[10px] font-bold tracking-[0.2em] text-white/50 uppercase sm:text-xs">
              <span>{top ? <span className="hud-rainbow">Max multiplier!</span> : `${hud.perStep - hud.charge} to ×${hud.mult + 1}`}</span>
              {hud.streak >= 2 ? (
                <span key={hud.streak} className="hud-bump inline-block text-base text-white sm:text-lg" style={{ textShadow: `0 0 10px ${color}` }}>
                  {hud.streak} <span className="text-[10px] text-white/60 sm:text-xs">combo</span>
                </span>
              ) : null}
            </p>
          </div>
        </div>
      </div>

      {/* Each judgment pops under the display. */}
      <div className="pointer-events-none relative mt-2 grid h-10 place-items-center sm:h-12" aria-live="polite">
        {hud.judged ? (
          <span key={hud.judged.n} className={cn('hud-pop text-3xl font-black tracking-wide uppercase italic sm:text-4xl', JUDGED[hud.judged.kind])}>
            {hud.judged.text}
          </span>
        ) : null}
      </div>

      {power ? <PowerUp key={hud.ups} mult={hud.mult} top={top} /> : best && !power ? <Banner key="best" text="New best!" /> : null}
    </div>
  );
}

/** A new multiplier, over the whole screen: a flash, rings, sparks and a huge ×N, bigger at every step. */
function PowerUp({ mult, top }: { mult: number; top: boolean }) {
  const color = multColor(mult);
  const rays = useState(() =>
    Array.from({ length: 10 + mult * 6 }, (_, i) => {
      const a = (i / (10 + mult * 6)) * Math.PI * 2 + Math.random() * 0.3;
      const d = 120 + Math.random() * (80 + mult * 50);
      return { dx: Math.cos(a) * d, dy: Math.sin(a) * d, hue: Math.round(Math.random() * 360), size: 6 + Math.random() * (4 + mult * 2) };
    })
  )[0];
  const size = mult >= 4 ? 'text-[9rem] sm:text-[12rem]' : mult === 3 ? 'text-8xl sm:text-[9rem]' : 'text-7xl sm:text-8xl';
  return (
    <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center overflow-hidden" aria-live="assertive">
      <div className="hud-scrim absolute inset-0 bg-black/45" />
      <div className="hud-flash absolute inset-0" style={{ background: `radial-gradient(circle at center, ${color}cc 0%, ${color}33 40%, transparent 75%)` }} />
      {Array.from({ length: mult - 1 }, (_, i) => (
        <div
          key={i}
          className="hud-ring absolute size-64 rounded-full border-4"
          style={{ borderColor: top ? `hsl(${i * 120} 95% 65%)` : color, animationDelay: `${i * 120}ms`, boxShadow: `0 0 30px ${color}` }}
        />
      ))}
      {rays.map((r, i) => (
        <span
          key={i}
          className="hud-ray absolute top-1/2 left-1/2 rounded-full"
          style={{ width: r.size, height: r.size, backgroundColor: top ? `hsl(${r.hue} 95% 65%)` : color, boxShadow: `0 0 12px ${top ? `hsl(${r.hue} 95% 65%)` : color}`, ['--dx' as string]: `${r.dx}px`, ['--dy' as string]: `${r.dy}px` } as React.CSSProperties}
        />
      ))}
      <div className="hud-power relative text-center font-mono font-black italic">
        <p className={cn(size, 'leading-none', top ? 'hud-rainbow' : '')} style={top ? undefined : { color, textShadow: `0 0 30px ${color}, 0 0 80px ${color}` }}>
          ×{mult}
        </p>
        <p className="mt-2 text-xl tracking-[0.4em] text-white uppercase sm:text-2xl" style={{ textShadow: `0 0 16px ${color}` }}>
          {top ? 'Max power!' : 'Multiplier!'}
        </p>
      </div>
    </div>
  );
}

/** A smaller celebration, for example a new best score. */
function Banner({ text }: { text: string }) {
  return (
    <div className="pointer-events-none fixed inset-x-0 top-1/3 z-50 grid place-items-center" aria-live="polite">
      <p className="hud-power font-mono text-5xl font-black tracking-wider uppercase italic sm:text-6xl">
        <span className="hud-rainbow">{text}</span>
      </p>
    </div>
  );
}

/** The score counts up to its new value, like the reels of an arcade cabinet. */
function useRolling(target: number) {
  const [shown, setShown] = useState(target);
  const at = useRef(target);
  useEffect(() => {
    let raf = 0;
    const step = () => {
      const diff = target - at.current;
      if (Math.abs(diff) < 1 || diff < 0) {
        at.current = target;
        setShown(target);
        return;
      }
      at.current += Math.max(1, diff * 0.2);
      setShown(Math.round(at.current));
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target]);
  return shown;
}

/**
 * True for a while after a count goes up (not when the page first shows it): a celebration
 * that plays once per new multiplier, crash or record.
 */
function useEdge(count: number, ms: number) {
  const seen = useRef(count);
  const [on, setOn] = useState(false);
  useEffect(() => {
    const up = count > seen.current;
    seen.current = count;
    if (!up) return;
    setOn(true);
    const t = setTimeout(() => setOn(false), ms);
    return () => clearTimeout(t);
  }, [count, ms]);
  return on;
}
