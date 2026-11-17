import { useEffect, useRef, useState } from 'react';
import { Gauge } from 'lucide-react';
import { DEFAULT_SPEED } from '../lightfield/engine.ts';
import { fromSlider, setBackgroundSpeed, speedLabel, toSlider, useBackgroundSpeed } from '../lib/backgroundSpeed.ts';
import { cn } from '../lib/utils.ts';

/** Round button that opens a small panel with the background speed slider. */
export function SpeedControl({ className }: { className?: string }) {
  const speed = useBackgroundSpeed();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent | TouchEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('touchstart', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('touchstart', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-label={`Background speed: ${speedLabel(speed)}`}
        title="Background speed"
        className={cn(
          'grid size-10 place-items-center rounded-full text-stone-500 ring-1 ring-stone-200 backdrop-blur transition hover:text-stone-900 dark:text-stone-400 dark:ring-white/10 dark:hover:text-white',
          open && 'text-stone-900 dark:text-white',
          className
        )}
      >
        <Gauge className="size-[18px]" />
      </button>
      {open ? (
        <div data-no-burst className="absolute right-0 z-20 mt-2 w-64 rounded-2xl bg-white/90 p-4 shadow-xl ring-1 ring-stone-200 backdrop-blur-xl dark:bg-stone-900/90 dark:ring-white/10">
          <div className="mb-3 flex items-baseline justify-between">
            <label htmlFor="bg-speed" className="text-sm font-medium">
              Background speed
            </label>
            <span className="text-xs text-stone-500 dark:text-stone-400">{speedLabel(speed)}</span>
          </div>
          <input
            id="bg-speed"
            type="range"
            min={0}
            max={100}
            step={1}
            value={toSlider(speed)}
            onChange={(e) => setBackgroundSpeed(fromSlider(Number(e.target.value)))}
            className="h-2 w-full cursor-pointer accent-stone-900 dark:accent-amber-400"
          />
          <div className="mt-2 flex items-center justify-between text-xs text-stone-400">
            <span>Slower</span>
            <button
              type="button"
              onClick={() => setBackgroundSpeed(DEFAULT_SPEED)}
              disabled={speed === DEFAULT_SPEED}
              className="rounded-md px-2 py-0.5 font-medium text-stone-600 hover:bg-stone-100 disabled:opacity-40 dark:text-stone-300 dark:hover:bg-stone-800"
            >
              Reset
            </button>
            <span>Faster</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}
