import { useEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronUp, X } from 'lucide-react';
import type { GameStatus, Scoreboard as Board } from '../../../shared/layout.ts';
import { cn } from '../lib/utils.ts';

// Arcade high scores on the Play page: the table of a game's best scores with initials, and the
// three-letter entry after a game that made the board.

/** Letters, then digits: what an initials slot cycles through. */
const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const LAST_KEY = 'play.initials';

const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? 'TH' : ['TH', 'ST', 'ND', 'RD'][n % 10] ?? 'TH'}`;
/** Rows in arcade colors: gold, silver, bronze, then a cycle of bright ones. */
const ROW_COLORS = ['text-amber-300', 'text-slate-200', 'text-orange-400', 'text-cyan-300', 'text-fuchsia-300', 'text-lime-300', 'text-sky-300', 'text-rose-300', 'text-violet-300', 'text-emerald-300'];

const arcade = 'font-mono font-black tracking-[0.2em] uppercase';

export function Scoreboard({ board, onRemove }: { board: Board; onRemove?: (id: number) => void }) {
  return (
    <section aria-label={`High scores: ${board.title}`} className="w-full max-w-sm rounded-2xl bg-black/70 p-4 ring-1 ring-white/15 shadow-[0_0_40px_rgba(56,189,248,0.15)]">
      <h2 className={cn(arcade, 'text-center text-lg text-amber-300 [text-shadow:0_0_12px_rgba(252,211,77,0.7)]')}>High scores</h2>
      <p className="mb-3 text-center text-xs tracking-widest text-white/50 uppercase">{board.title}</p>
      {board.entries.length ? (
        <ol className={cn(arcade, 'space-y-1 text-sm sm:text-base')}>
          {board.entries.map((e, i) => (
            <li
              key={e.id}
              className={cn('grid grid-cols-[3.5rem_4rem_1fr_auto] items-center gap-2', ROW_COLORS[i % ROW_COLORS.length], e.id === board.fresh && 'animate-pulse [text-shadow:0_0_10px_currentColor]')}
            >
              <span>{ordinal(e.rank)}</span>
              <span>{e.initials}</span>
              <span className="text-right tabular-nums">{e.score.toLocaleString()}</span>
              {onRemove ? (
                <button type="button" onClick={() => onRemove(e.id)} className="rounded-full p-1 text-white/40 hover:bg-white/10 hover:text-white" aria-label={`Remove ${e.initials} ${e.score}`}>
                  <X className="size-3.5" />
                </button>
              ) : (
                <span />
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className={cn(arcade, 'py-3 text-center text-sm text-white/40')}>No scores yet. Be the first!</p>
      )}
    </section>
  );
}

/**
 * Three letters for a score that made the board, arcade style: ▲ and ▼ turn each letter, or type
 * them on a keyboard (← → move between letters, Enter saves).
 */
export function InitialsEntry({ entry, onSave }: { entry: NonNullable<GameStatus['enterInitials']>; onSave: (initials: string) => void }) {
  const [letters, setLetters] = useState<string[]>(() => {
    let last = '';
    try {
      last = localStorage.getItem(LAST_KEY) ?? '';
    } catch {
      // No storage (a private window): start from AAA.
    }
    return /^[A-Z0-9]{3}$/.test(last) ? last.split('') : ['A', 'A', 'A'];
  });
  const [slot, setSlot] = useState(0);
  const [sent, setSent] = useState(false);
  // A refused try (or a new score) asks again.
  useEffect(() => setSent(false), [entry.id, entry.refused]);

  const turn = (i: number, by: number) => {
    setSlot(i);
    setLetters((l) => l.map((c, k) => (k === i ? CHARS[(CHARS.indexOf(c) + by + CHARS.length) % CHARS.length] : c)));
  };
  const save = () => {
    const v = letters.join('');
    try {
      localStorage.setItem(LAST_KEY, v);
    } catch {
      // Not remembered: fine.
    }
    setSent(true);
    onSave(v);
  };

  // Keyboard: type letters, arrows to move and turn, Enter to save.
  const state = useRef({ slot, save, turn });
  state.current = { slot, save, turn };
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const { slot: at, save: go, turn: spin } = state.current;
      const ch = e.key.length === 1 ? e.key.toUpperCase() : '';
      if (ch && CHARS.includes(ch)) {
        e.preventDefault();
        setLetters((l) => l.map((c, k) => (k === at ? ch : c)));
        setSlot(Math.min(2, at + 1));
      } else if (e.key === 'ArrowLeft' || e.key === 'Backspace') {
        e.preventDefault();
        setSlot(Math.max(0, at - 1));
      } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        setSlot(Math.min(2, at + 1));
      } else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        e.preventDefault();
        spin(at, e.key === 'ArrowUp' ? 1 : -1);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        go();
      }
    };
    window.addEventListener('keydown', down);
    return () => window.removeEventListener('keydown', down);
  }, []);

  return (
    <section aria-label="Enter your initials" className="w-full max-w-sm rounded-2xl bg-black/70 p-4 text-center ring-2 ring-amber-300/60 shadow-[0_0_40px_rgba(252,211,77,0.25)]">
      <p className={cn(arcade, 'animate-pulse text-lg text-amber-300 [text-shadow:0_0_12px_rgba(252,211,77,0.8)]')}>New high score!</p>
      <p className={cn(arcade, 'mb-3 text-sm text-white/70')}>
        {ordinal(entry.rank)} place · {entry.score.toLocaleString()}
      </p>
      <div className="flex justify-center gap-3">
        {letters.map((c, i) => (
          <div key={i} className="flex flex-col items-center gap-1">
            <button type="button" onClick={() => turn(i, 1)} className="rounded-lg p-2 text-white/70 hover:bg-white/10 active:scale-90" aria-label={`Letter ${i + 1} up`}>
              <ChevronUp className="size-7" />
            </button>
            <button
              type="button"
              onClick={() => setSlot(i)}
              className={cn(arcade, 'grid h-16 w-14 place-items-center rounded-xl bg-white/5 text-4xl tracking-normal text-cyan-300 ring-2 transition', i === slot ? 'ring-cyan-300 [text-shadow:0_0_14px_rgba(103,232,249,0.9)]' : 'ring-white/10')}
              aria-label={`Letter ${i + 1}: ${c}`}
            >
              {c}
            </button>
            <button type="button" onClick={() => turn(i, -1)} className="rounded-lg p-2 text-white/70 hover:bg-white/10 active:scale-90" aria-label={`Letter ${i + 1} down`}>
              <ChevronDown className="size-7" />
            </button>
          </div>
        ))}
      </div>
      {entry.refused ? <p className="mt-2 text-sm text-rose-300">Those letters are not allowed. Pick others!</p> : null}
      <button
        type="button"
        onClick={save}
        disabled={sent && !entry.refused}
        className={cn(arcade, 'mt-3 rounded-full bg-gradient-to-b from-amber-300 to-orange-500 px-8 py-3 text-lg text-white shadow-lg shadow-orange-500/40 transition active:scale-95 disabled:opacity-50')}
      >
        Enter
      </button>
      <p className="mt-2 hidden text-xs text-white/40 sm:block">Type your initials, then Enter</p>
    </section>
  );
}
