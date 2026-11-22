import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type React from 'react';
import type { ButtonTone, MoleBoard as Board, MoleHole } from '../../../shared/layout.ts';
import { burst } from '../components/Burst.tsx';
import { cn } from '../lib/utils.ts';
import { useEdge, useRolling } from './ArcadeHud.tsx';
import { Cabinet } from './GameWindow.tsx';

// Whack-a-Mole's arcade on the phone. Above: the yard as the cabinet's screen, under a marquee of
// chasing bulbs with the score, the clock and the multiplier. Below: the playfield, a grassy deck
// in a candy-striped frame with one hole per bush or tree of the yard, left to right as seen from
// the street. A mole pops up in a hole here when it pops up in the yard, in that hole's color;
// a whack blows it up in confetti, and one that gets away flashes red and is gone. A whack at an
// empty hole (a slip) flashes the hole and the clock red and takes seconds off the clock.

/** Each multiplier's color: ×1 plain, ×2 cyan, ×3 magenta, ×4 a rainbow. */
const MULT_COLOR = ['#fef3c7', '#fef3c7', '#22d3ee', '#e879f9', '#fde047'];
const BULBS = ['#fde047', '#f472b6', '#22d3ee', '#a3e635', '#fb923c', '#a78bfa'];

/** A row of marquee bulbs that chase along the cabinet's edge. */
function Bulbs({ count = 18, fast }: { count?: number; fast?: boolean }) {
  return (
    <div className="flex h-2.5 items-center justify-between px-3" aria-hidden>
      {Array.from({ length: count }, (_, i) => (
        <span
          key={i}
          className="mole-bulb size-1.5 rounded-full sm:size-2"
          style={{ backgroundColor: BULBS[i % BULBS.length], boxShadow: `0 0 6px ${BULBS[i % BULBS.length]}`, animationDelay: `${-(i % 3) * (fast ? 0.12 : 0.25)}s`, animationDuration: fast ? '0.36s' : '0.75s' }}
        />
      ))}
    </div>
  );
}

/** The cabinet: the marquee, the yard as its screen, and the round's clock as a bar under it. */
export function WhackWindow({ board, score, phase, children }: { board: Board; score: number; phase: string; children: React.ReactNode }) {
  const shown = useRolling(score);
  const color = MULT_COLOR[Math.min(board.mult, MULT_COLOR.length - 1)];
  const top = board.mult >= 4;
  const hurry = phase === 'running' && board.timeLeft <= 10;
  const newBest = board.best > 0 && score > board.best;
  const best = useEdge(newBest ? 1 : 0, 1600);
  const power = useEdge(board.mult, 1200);
  // A slip: the clock flashes red, "−2 s" drops off it, and the cabinet's edge flashes red.
  const slip = board.slip;

  // Points as they land: "+20" floats up off the score.
  const [gains, setGains] = useState<{ id: number; value: number }[]>([]);
  const lastScore = useRef(score);
  useEffect(() => {
    const d = score - lastScore.current;
    lastScore.current = score;
    if (d <= 0) return;
    const id = Date.now() + Math.random();
    setGains((g) => [...g.slice(-2), { id, value: d }]);
    const t = setTimeout(() => setGains((g) => g.filter((x) => x.id !== id)), 800);
    return () => clearTimeout(t);
  }, [score]);

  return (
    <Cabinet
      className={cn('border-2 transition-[box-shadow,border-color] duration-500', top ? 'border-amber-300/70' : hurry ? 'border-orange-400/70' : 'border-fuchsia-400/40')}
      style={{ boxShadow: board.mult > 1 ? `0 0 ${10 + board.mult * 7}px ${color}66` : '0 0 24px rgba(217,70,239,0.25)' }}
    >
      <Bulbs fast={phase === 'running' && board.mult > 1} />
      <div className="grid h-14 grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2 px-2.5">
        <div className="relative min-w-0">
          <p className="text-[9px] leading-none font-bold tracking-[0.3em] text-white/50 uppercase">Score</p>
          <p className="mt-1 truncate text-2xl leading-none font-black tracking-tight text-white tabular-nums [text-shadow:0_0_12px_rgba(244,114,182,0.7)] sm:text-3xl">{shown}</p>
          {gains.map((g) => (
            <span key={g.id} className="hud-float pointer-events-none absolute top-3 left-16 text-sm font-black sm:text-base" style={{ color, textShadow: `0 0 8px ${color}` }}>
              +{g.value}
            </span>
          ))}
        </div>

        {/* The middle: the game's name, and the clock (orange and throbbing in the last ten seconds). */}
        <div className="text-center" aria-live="off">
          <p className="hud-rainbow text-[10px] leading-none font-black tracking-[0.2em] whitespace-nowrap uppercase italic sm:text-xs">Whack-a-Mole</p>
          {best ? (
            <p key="best" className="hud-power mt-1 text-base font-black tracking-wider uppercase italic sm:text-xl">
              <span className="hud-rainbow">New best!</span>
            </p>
          ) : (
            <p
              key={slip ? `slip${slip.n}` : hurry ? board.timeLeft : 'clock'}
              className={cn('relative mt-1 text-2xl leading-none font-black tabular-nums sm:text-3xl', hurry ? 'hud-bump text-orange-300 [text-shadow:0_0_14px_rgba(251,146,60,0.9)]' : 'text-cyan-200 [text-shadow:0_0_12px_rgba(34,211,238,0.7)]', slip && 'mole-slip-clock')}
              aria-label={`${board.timeLeft} seconds left`}
            >
              0:{String(board.timeLeft).padStart(2, '0')}
              {slip ? (
                <span className="hud-float pointer-events-none absolute top-0 left-full ml-1.5 text-base font-black whitespace-nowrap text-red-400 [text-shadow:0_0_10px_#ef4444]">
                  −{slip.cost} s
                </span>
              ) : null}
            </p>
          )}
        </div>

        <div className="flex min-w-0 items-center justify-end gap-2.5">
          <div className="min-w-0 text-right">
            <p className={cn('text-[9px] leading-none font-bold tracking-[0.2em] uppercase', newBest ? 'hud-rainbow font-black' : 'text-white/50')}>{newBest ? 'New best' : 'Best'}</p>
            <p className="mt-1 text-sm leading-none font-bold text-amber-200/80 tabular-nums sm:text-base">{Math.max(board.best, shown)}</p>
          </div>
          <div
            key={board.mult}
            className={cn('grid size-11 shrink-0 place-items-center rounded-xl border-2 text-xl font-black sm:size-12 sm:text-2xl', power && 'hud-bump', top && 'hud-charge')}
            style={{ color, borderColor: `color-mix(in srgb, ${color} 60%, transparent)`, backgroundColor: `color-mix(in srgb, ${color} ${board.mult > 1 ? 18 : 6}%, transparent)`, boxShadow: board.mult > 1 ? `0 0 ${board.mult * 5}px ${color}` : undefined }}
            aria-label={`Points ×${board.mult}`}
          >
            {top ? <span className="hud-rainbow">×{board.mult}</span> : `×${board.mult}`}
          </div>
        </div>
      </div>

      {children}

      {/* The clock as a bar: a rainbow that drains, orange at the end. */}
      <div className="flex h-8 items-center gap-2.5 px-2.5 text-[10px] font-bold tracking-[0.15em] text-white/55 uppercase sm:text-xs">
        <span className="shrink-0">Time</span>
        <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-white/10">
          <div
            className={cn('h-full rounded-full transition-[width] duration-1000 ease-linear', hurry ? 'bg-gradient-to-r from-orange-500 to-amber-300 shadow-[0_0_10px_rgba(251,146,60,0.9)]' : 'mole-rainbow-bar shadow-[0_0_10px_rgba(244,114,182,0.6)]')}
            style={{ width: `${Math.min(100, (board.timeLeft / board.duration) * 100)}%` }}
          />
        </div>
        <span className="w-24 shrink-0 text-right whitespace-nowrap">
          {board.streak >= 2 ? (
            <span key={board.streak} className="hud-bump inline-block text-white" style={{ textShadow: `0 0 8px ${color}` }}>
              <span className="text-sm sm:text-base">{board.streak}</span> in a row
            </span>
          ) : (
            <span className="tabular-nums">{board.hits} whacked</span>
          )}
        </span>
      </div>
      <Bulbs fast={phase === 'running' && board.mult > 1} />
      {power && board.mult > 1 ? <div key={`edge${board.mult}`} className="hud-flash pointer-events-none absolute inset-0 rounded-3xl border-4" style={{ borderColor: color }} /> : null}
      {slip ? <div key={`slip${slip.n}`} className="hud-flash pointer-events-none absolute inset-0 rounded-3xl border-4 border-red-500 bg-red-500/15" /> : null}
    </Cabinet>
  );
}

/** Rows of holes: enough that every hole is at least this wide (in CSS pixels), up to four. */
const MIN_HOLE = 72;
const MAX_HOLE = 112;

/** Where each hole goes: staggered rows that keep the yard's left-to-right order. */
function placeHoles(count: number, width: number) {
  // The holes' middles spread evenly from one edge to the other; holes in the same row are
  // `rows` steps apart, and a little more than one hole wide.
  const fit = (rows: number) => (count <= 1 ? Math.min(MAX_HOLE, width * 0.4) : Math.min(MAX_HOLE, (0.9 * rows * width) / (count - 1 + 0.9 * rows), count <= 3 ? width * 0.3 : Infinity));
  let rows = 1;
  if (count > 3) while (rows < 4 && fit(rows) < MIN_HOLE) rows++;
  const size = Math.max(52, fit(rows));
  const step = count > 1 ? (width - size) / (count - 1) : 0;
  // Neighbours sit in different rows: far enough apart up and down not to touch.
  const rowStep = rows > 1 ? Math.max(size * 0.7, Math.sqrt(Math.max(0, size * size - step * step)) + 6) : 0;
  const spots = Array.from({ length: count }, (_, i) => ({
    left: count > 1 ? i * step : (width - size) / 2,
    top: (i % rows) * rowStep
  }));
  return { size, spots, height: (rows - 1) * rowStep + size };
}

const TONES: Record<ButtonTone, string> = {
  go: 'from-amber-300 to-orange-500 shadow-orange-500/50',
  good: 'from-emerald-400 to-green-600 shadow-emerald-500/50',
  bad: 'from-rose-500 to-red-600 shadow-red-500/50',
  calm: 'from-sky-400 to-indigo-600 shadow-sky-500/50',
  wait: 'from-slate-500 to-slate-700 shadow-black/40'
};

/**
 * The playfield: a hole for each bush and tree, finger-sized for kids (at least about 2 cm), and
 * before a round (or after one) a big GO! button over them. The 3-2-1 counts down over the holes.
 */
export function MoleBoard({
  board,
  phase,
  button,
  tone,
  pressed,
  onPress,
  onRelease
}: {
  board: Board;
  phase: string;
  button: string;
  tone: ButtonTone;
  pressed: ReadonlySet<string>;
  onPress: (id: string) => void;
  onRelease: (id: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth);
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const { size, spots, height } = placeHoles(board.holes.length, width || 320);
  const idle = phase === 'ready' || phase === 'over';

  return (
    <div className="mole-frame w-full max-w-2xl rounded-[2rem] p-2 shadow-2xl shadow-fuchsia-900/40">
      <div className="mole-field relative overflow-hidden rounded-[1.6rem] px-3 py-3.5 sm:px-5">
        <div ref={ref} className="relative w-full" style={{ height }}>
          {width
            ? board.holes.map((h, i) => (
                <Hole
                  key={h.id}
                  hole={h}
                  index={i}
                  size={size}
                  style={{ left: spots[i].left, top: spots[i].top }}
                  down={pressed.has(h.id)}
                  slip={board.slip?.hole === h.id ? board.slip : null}
                  disabled={idle || phase === 'countdown' || phase === 'setup'}
                  onPress={onPress}
                  onRelease={onRelease}
                />
              ))
            : null}
        </div>

        {/* 3, 2, 1, GO! */}
        {board.countdown ? (
          <div className="pointer-events-none absolute inset-0 grid place-items-center bg-black/25">
            <span key={board.countdown} className="hud-power text-7xl font-black italic sm:text-8xl">
              <span className="hud-rainbow [-webkit-text-stroke:1px_rgba(255,255,255,0.25)]">{board.countdown}</span>
            </span>
          </div>
        ) : null}

        {/* Before a round, and after one: the big button over the holes. */}
        {idle ? (
          <div className="absolute inset-0 grid place-items-center bg-black/35 backdrop-blur-[1px]">
            <button
              type="button"
              onPointerDown={(e) => {
                e.preventDefault();
                e.currentTarget.setPointerCapture?.(e.pointerId);
                onPress('main');
              }}
              onPointerUp={() => onRelease('main')}
              onPointerCancel={() => onRelease('main')}
              onLostPointerCapture={() => onRelease('main')}
              onContextMenu={(e) => e.preventDefault()}
              className={cn(
                'mole-go grid size-28 touch-manipulation place-items-center rounded-full bg-gradient-to-b text-3xl font-black tracking-wider text-white shadow-2xl ring-4 ring-white/40 transition select-none [-webkit-touch-callout:none] [text-shadow:0_2px_8px_rgba(0,0,0,0.5)]',
                'pointer-fine:size-24 pointer-fine:text-2xl',
                TONES[tone],
                pressed.has('main') ? 'scale-90 brightness-125' : 'hover:scale-[1.05]'
              )}
            >
              {button}
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** One hole: dark earth in a ring of its color, and the mole that pops up out of it. */
function Hole({
  hole,
  index,
  size,
  style,
  down,
  slip,
  disabled,
  onPress,
  onRelease
}: {
  hole: MoleHole;
  index: number;
  size: number;
  style: React.CSSProperties;
  down: boolean;
  /** The last slip, when it was in this hole: it flashes red. */
  slip: Board['slip'];
  disabled: boolean;
  onPress: (id: string) => void;
  onRelease: (id: string) => void;
}) {
  const ref = useRef<HTMLButtonElement>(null);
  const { state, color } = hole;
  const up = state === 'up' || state === 'gold';
  const glow = state === 'gold' ? '#fde047' : color;
  // A whack: confetti flies out of the hole and the phone buzzes. A mole that got away: a longer buzz.
  const seen = useRef(`${state}:${hole.n}`);
  useEffect(() => {
    const key = `${state}:${hole.n}`;
    if (key === seen.current) return;
    seen.current = key;
    if (state === 'hit' && ref.current) {
      burst(ref.current);
      navigator.vibrate?.(25);
    } else if (state === 'miss') navigator.vibrate?.([30, 40, 30]);
  }, [state, hole.n]);
  // A slip: one long buzz, unlike a whack's tap.
  const slipN = slip?.n;
  useEffect(() => {
    if (slipN) navigator.vibrate?.(120);
  }, [slipN]);

  return (
    <button
      ref={ref}
      type="button"
      aria-label={`Hole ${index + 1}${up ? ': a mole!' : ''}`}
      onPointerDown={(e) => {
        e.preventDefault();
        e.currentTarget.setPointerCapture?.(e.pointerId);
        onPress(hole.id);
      }}
      onPointerUp={() => onRelease(hole.id)}
      onPointerCancel={() => onRelease(hole.id)}
      onLostPointerCapture={() => onRelease(hole.id)}
      onContextMenu={(e) => e.preventDefault()}
      onKeyDown={(e) => e.key === ' ' && e.preventDefault()}
      disabled={disabled}
      className={cn('absolute touch-manipulation rounded-full transition-transform duration-75 select-none [-webkit-touch-callout:none]', down ? 'scale-90' : up ? 'scale-105' : '')}
      style={{ ...style, width: size, height: size }}
    >
      {/* The ring in the hole's color: bright and pulsing with a mole in it, faint when empty. */}
      <span
        className={cn('absolute inset-0 rounded-full transition-[box-shadow,background-color] duration-150', up && 'mole-pulse', state === 'miss' && 'mole-miss')}
        style={{
          backgroundColor: up ? `color-mix(in srgb, ${glow} 30%, #1c1917)` : '#1c1917',
          boxShadow: up
            ? `0 0 0 4px ${glow}, 0 0 ${size * 0.35}px ${glow}, inset 0 -${size * 0.08}px ${size * 0.2}px rgba(0,0,0,0.6)`
            : `0 0 0 3px color-mix(in srgb, ${color} 45%, transparent), inset 0 ${size * 0.08}px ${size * 0.22}px rgba(0,0,0,0.85)`
        }}
      />
      {/* A slip: the hole flashes red and shakes, and "−2 s" pops off it. */}
      {slip ? <span key={`slip${slip.n}`} className="mole-slip pointer-events-none absolute -inset-1 rounded-full" /> : null}
      {slip ? (
        <span key={`cost${slip.n}`} className="hud-pop pointer-events-none absolute -bottom-1 left-1/2 -translate-x-1/2 rounded-full bg-red-600 px-2 py-0.5 text-xs font-black tracking-wider whitespace-nowrap text-white shadow-lg">
          MISS −{slip.cost} s
        </span>
      ) : null}
      {/* A whack: a ring of rainbow spins out of the hole. */}
      {state === 'hit' ? <span key={`ring${hole.n}`} className="mole-blast pointer-events-none absolute -inset-2 rounded-full" /> : null}
      {/* The mole, clipped by the hole: it pops up from below and ducks back down. */}
      <span className="absolute inset-0 overflow-hidden rounded-full">
        <span key={`${hole.n}`} className={cn('absolute inset-x-[10%] bottom-0 top-[12%] transition-transform', up ? 'mole-up' : state === 'hit' ? 'mole-bonked' : 'translate-y-full duration-200')}>
          <Mole color={state === 'gold' ? '#fbbf24' : color} gold={state === 'gold' || (state === 'hit' && hole.points >= 50)} dizzy={state === 'hit'} />
        </span>
      </span>
      {/* The points, popping off the hole. */}
      {state === 'hit' && hole.points ? (
        <span key={`pts${hole.n}`} className="hud-float pointer-events-none absolute -top-2 left-1/2 -translate-x-1/2 text-lg font-black whitespace-nowrap text-white [text-shadow:0_0_8px_rgba(0,0,0,0.8),0_0_14px_#fde047]">
          +{hole.points}
        </span>
      ) : null}
      {state === 'hit' ? (
        <span key={`bonk${hole.n}`} className="hud-pop pointer-events-none absolute -bottom-1 left-1/2 -translate-x-1/2 rounded-full bg-white px-2 py-0.5 text-xs font-black tracking-wider text-fuchsia-600 italic shadow-lg">
          BONK!
        </span>
      ) : null}
    </button>
  );
}

/** A friendly mole in a color: round head, big eyes, a pink nose and two teeth. Whacked: dizzy. */
function Mole({ color, gold, dizzy }: { color: string; gold: boolean; dizzy: boolean }) {
  return (
    <svg viewBox="0 0 100 110" className="h-full w-full drop-shadow-[0_2px_4px_rgba(0,0,0,0.5)]" aria-hidden>
      <defs>
        <radialGradient id={`fur-${color.slice(1)}`} cx="40%" cy="30%" r="75%">
          <stop offset="0%" stopColor={`color-mix(in srgb, ${color} 55%, white)`} />
          <stop offset="70%" stopColor={color} />
          <stop offset="100%" stopColor={`color-mix(in srgb, ${color} 60%, black)`} />
        </radialGradient>
      </defs>
      {gold ? <path d="M30 18 L36 4 L44 14 L50 0 L56 14 L64 4 L70 18 Z" fill="#fde047" stroke="#b45309" strokeWidth="2" /> : null}
      <ellipse cx="50" cy="70" rx="42" ry="50" fill={`url(#fur-${color.slice(1)})`} />
      <ellipse cx="50" cy="80" rx="26" ry="22" fill="rgba(255,255,255,0.35)" />
      {dizzy ? (
        <g stroke="#1c1917" strokeWidth="4" strokeLinecap="round">
          <path d="M28 46 l10 10 M38 46 l-10 10" />
          <path d="M62 46 l10 10 M72 46 l-10 10" />
        </g>
      ) : (
        <g>
          <circle cx="35" cy="52" r="8" fill="#1c1917" />
          <circle cx="65" cy="52" r="8" fill="#1c1917" />
          <circle cx="37.5" cy="49.5" r="2.8" fill="white" />
          <circle cx="67.5" cy="49.5" r="2.8" fill="white" />
        </g>
      )}
      <ellipse cx="50" cy="68" rx="8" ry="6" fill="#f472b6" />
      <rect x="44" y="75" width="5.5" height="8" rx="1.5" fill="white" />
      <rect x="50.5" y="75" width="5.5" height="8" rx="1.5" fill="white" />
      <circle cx="22" cy="72" r="5" fill="#fb7185" opacity="0.5" />
      <circle cx="78" cy="72" r="5" fill="#fb7185" opacity="0.5" />
      {dizzy ? (
        <g fill="#fde047">
          <path d="M20 22 l3 6 6 1 -4.5 4 1 6 -5.5 -3 -5.5 3 1 -6 -4.5 -4 6 -1z" />
          <path d="M80 16 l2.5 5 5 .8 -3.6 3.4 .8 5 -4.7 -2.4 -4.7 2.4 .8 -5 -3.6 -3.4 5 -.8z" />
        </g>
      ) : null}
    </svg>
  );
}
