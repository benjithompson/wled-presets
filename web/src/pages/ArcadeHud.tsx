import { useEffect, useRef, useState } from 'react';
import type React from 'react';
import type { ArcadeHud as Hud } from '../../../shared/layout.ts';
import { cn } from '../lib/utils.ts';
import { Cabinet, ProgressBar } from './GameWindow.tsx';

// Beat Drop's view of the yard as an arcade cabinet: the yard is the screen, with the score, the
// best and the multiplier in a bar above it, and the meter charging toward the next multiplier
// and the combo in a bar below. Every judgment pops in the middle of the top bar. Nothing is ever
// drawn over the yard itself, so the notes coming down the roof are always easy to see.

/** Each multiplier's color: ×1 plain, ×2 cyan, ×3 magenta, ×4 a rainbow. */
const MULT_COLOR = ['#e7e5e4', '#e7e5e4', '#22d3ee', '#e879f9', '#fde047'];
const multColor = (m: number) => MULT_COLOR[Math.min(m, MULT_COLOR.length - 1)];

const JUDGED: Record<NonNullable<Hud['judged']>['kind'], string> = {
  perfect: 'text-amber-200 [text-shadow:0_0_12px_rgba(252,211,77,0.9)]',
  held: 'text-emerald-200 [text-shadow:0_0_12px_rgba(52,211,153,0.9)]',
  good: 'text-sky-200 [text-shadow:0_0_10px_rgba(56,189,248,0.8)]',
  miss: 'text-red-400 [text-shadow:0_0_12px_rgba(239,68,68,0.9)]',
  stray: 'text-orange-300 [text-shadow:0_0_10px_rgba(251,146,60,0.8)]'
};

export function ArcadeWindow({ hud, health, children }: { hud: Hud; health?: { value: number; max: number }; children: React.ReactNode }) {
  const shown = useRolling(hud.score);
  const top = hud.mult >= hud.maxMult;
  const color = multColor(hud.mult);
  const newBest = hud.best > 0 && hud.score > hud.best;

  // Points as they land: "+6" floats up off the score.
  const [gains, setGains] = useState<{ id: number; value: number }[]>([]);
  const lastScore = useRef(hud.score);
  useEffect(() => {
    const d = hud.score - lastScore.current;
    lastScore.current = hud.score;
    if (d <= 0) return;
    const id = Date.now() + Math.random();
    setGains((g) => [...g.slice(-2), { id, value: d }]);
    const t = setTimeout(() => setGains((g) => g.filter((x) => x.id !== id)), 800);
    return () => clearTimeout(t);
  }, [hud.score]);

  // A new multiplier: the cabinet's edge flashes in its color and the top bar announces it.
  // Losing one: the top bar shakes and the edge flashes red.
  const power = useEdge(hud.ups, 1400);
  const crash = useEdge(hud.drops, 500);
  const best = useEdge(newBest ? 1 : 0, 1600);
  useEffect(() => {
    if (power) navigator.vibrate?.(top ? [50, 40, 50, 40, 90] : [50, 40, 50]);
  }, [power, top]);
  useEffect(() => {
    if (crash) navigator.vibrate?.(120);
  }, [crash]);

  const digits = String(shown).padStart(7, '0');
  const lead = digits.length - String(shown).length;

  return (
    <Cabinet
      className={cn('transition-[box-shadow,border-color] duration-500', top ? 'border-amber-300/50' : 'border-white/10')}
      style={{ boxShadow: hud.mult > 1 ? `0 0 ${8 + hud.mult * 6}px ${color}55` : undefined }}
    >
      {/* The top bar: score, the judgment (or a new multiplier, or a new best), best and the multiplier. */}
      <div className={cn('grid h-14 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 px-2.5', crash && 'hud-shake')}>
        <div className="relative">
          <p className="text-[9px] leading-none font-bold tracking-[0.3em] text-white/45 uppercase">Score</p>
          <p className="mt-1 text-2xl leading-none font-black tracking-tight tabular-nums sm:text-3xl" aria-label={`Score ${hud.score}`}>
            <span className="text-white/15">{digits.slice(0, lead)}</span>
            <span className="text-white [text-shadow:0_0_10px_rgba(255,255,255,0.4)]">{digits.slice(lead)}</span>
          </p>
          {gains.map((g) => (
            <span key={g.id} className="hud-float pointer-events-none absolute top-3 right-0 text-sm font-black sm:text-base" style={{ color, textShadow: `0 0 8px ${color}` }}>
              +{g.value}
            </span>
          ))}
        </div>

        <div className="grid h-full min-w-0 place-items-center text-center" aria-live="polite">
          {power ? (
            <div key={`up${hud.ups}`} className="hud-power leading-none italic">
              <p className={cn('text-3xl font-black sm:text-4xl', top && 'hud-rainbow')} style={top ? undefined : { color, textShadow: `0 0 14px ${color}` }}>
                ×{hud.mult}
              </p>
              <p className="mt-0.5 text-[9px] font-bold tracking-[0.25em] text-white uppercase sm:text-[10px]">{top ? 'Max power!' : 'Multiplier!'}</p>
            </div>
          ) : best ? (
            <p key="best" className="hud-power text-base font-black tracking-wider uppercase italic sm:text-xl">
              <span className="hud-rainbow">New best!</span>
            </p>
          ) : hud.judged ? (
            <span key={hud.judged.n} className={cn('hud-pop text-base font-black tracking-wide whitespace-nowrap uppercase italic sm:text-2xl', JUDGED[hud.judged.kind])}>
              {hud.judged.text}
            </span>
          ) : null}
        </div>

        <div className="flex items-center gap-2.5">
          <div className="text-right">
            {/* Beaten: the best is this game's score now, in a rainbow. */}
            <p className={cn('text-[9px] leading-none font-bold tracking-[0.2em] uppercase', newBest ? 'hud-rainbow font-black' : 'text-white/45')}>{newBest ? 'New best' : 'Best'}</p>
            <p className="mt-1 text-sm leading-none font-bold text-amber-200/80 tabular-nums sm:text-base">{Math.max(hud.best, shown)}</p>
          </div>
          <div
            key={hud.ups}
            className={cn('hud-bump grid size-11 shrink-0 place-items-center rounded-xl border-2 text-xl font-black sm:size-12 sm:text-2xl', top && 'hud-charge')}
            style={{ color, borderColor: `color-mix(in srgb, ${color} 60%, transparent)`, backgroundColor: `color-mix(in srgb, ${color} ${hud.mult > 1 ? 18 : 6}%, transparent)`, boxShadow: hud.mult > 1 ? `0 0 ${hud.mult * 5}px ${color}` : undefined }}
            aria-label={`Multiplier ×${hud.mult}`}
          >
            {top ? <span className="hud-rainbow">×{hud.mult}</span> : `×${hud.mult}`}
          </div>
        </div>
      </div>

      {/* The screen: the yard. */}
      {children}

      {/* The bottom bar: the meter charging toward the next multiplier, the combo, the stage. */}
      <div className="flex h-9 items-center gap-2.5 px-2.5 text-[10px] font-bold tracking-[0.15em] text-white/50 uppercase sm:text-xs">
        <span className="shrink-0 whitespace-nowrap">{top ? <span className="hud-rainbow">Max!</span> : `${hud.perStep - hud.charge} to ×${hud.mult + 1}`}</span>
        <div className="flex min-w-0 flex-1 gap-0.5 sm:gap-1" aria-hidden>
          {Array.from({ length: hud.perStep }, (_, i) => {
            const on = i < hud.charge;
            const next = multColor(Math.min(hud.maxMult, hud.mult + 1));
            return (
              <span
                key={i}
                className={cn('h-2 flex-1 rounded-sm transition-all duration-150 sm:h-2.5', top && 'hud-charge')}
                style={
                  on
                    ? { backgroundColor: top ? `hsl(${(i / hud.perStep) * 300} 95% 62%)` : next, boxShadow: `0 0 6px ${top ? '#fde047' : next}` }
                    : { backgroundColor: 'rgba(255,255,255,0.08)' }
                }
              />
            );
          })}
        </div>
        <span className="w-16 shrink-0 text-right whitespace-nowrap sm:w-20">
          {hud.streak >= 2 ? (
            <span key={hud.streak} className="hud-bump inline-block text-white" style={{ textShadow: `0 0 8px ${color}` }}>
              <span className="text-sm sm:text-base">{hud.streak}</span> combo
            </span>
          ) : null}
        </span>
        <span className="hidden shrink-0 whitespace-nowrap text-white/40 sm:inline">{hud.info.map((x) => `${x.label} ${x.value}`).join(' · ')}</span>
      </div>
      {health ? <ProgressBar value={health.value} max={health.max} label="Health" className="h-6 pb-1" /> : null}

      {/* The cabinet's edge flashes: in the new multiplier's color, or red for a lost one. */}
      {power ? <div key={`edge${hud.ups}`} className="hud-flash pointer-events-none absolute inset-0 rounded-3xl border-4" style={{ borderColor: color }} /> : null}
      {crash ? <div key={`crash${hud.drops}`} className="hud-flash pointer-events-none absolute inset-0 rounded-3xl border-4 border-red-500" /> : null}
    </Cabinet>
  );
}

/** The score counts up to its new value, like the reels of an arcade cabinet. */
export function useRolling(target: number) {
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
export function useEdge(count: number, ms: number) {
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
