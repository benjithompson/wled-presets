// A property inspector, as in CAD and design programs: folding sections, with one property per
// row (the label on the left, the value on the right). Drag a number's label left or right to
// change the number (Shift: 10 times faster), or use the arrow keys in the field.
import { createContext, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { inputBase } from '../../components/ui.tsx';
import { cn } from '../../lib/utils.ts';

export const propInput =
  'h-7 w-full min-w-0 rounded-md bg-white px-2 text-xs tabular-nums ring-1 ring-inset ring-stone-200 placeholder:text-stone-400 transition focus:ring-2 focus:ring-accent-500 focus:outline-none disabled:opacity-60 dark:bg-stone-950 dark:ring-stone-700 dark:placeholder:text-stone-600';

const SELECT_CHEVRON = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23a8a29e' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`;

/** Whether a folding part of the inspector is open, remembered in this browser by `id`. */
function useOpen(id: string, fallback: boolean): [boolean, () => void] {
  const key = `layout.section.${id}`;
  const [open, setOpen] = useState(() => {
    try {
      const v = localStorage.getItem(key);
      return v == null ? fallback : v === 'open';
    } catch {
      return fallback;
    }
  });
  const toggle = () =>
    setOpen((v) => {
      try {
        localStorage.setItem(key, v ? 'closed' : 'open');
      } catch {}
      return !v;
    });
  return [open, toggle];
}

/**
 * An accordion: inside one, only one section is open at a time (the one named `open`), so a
 * small screen shows one group of settings instead of a long page of them.
 */
export const PropAccordion = createContext<{ open: string | null; set: (id: string | null) => void } | null>(null);

/** A section of the inspector that folds away. It remembers if it is open (in an accordion, the accordion does). */
export function PropSection({ id, title, actions, children, defaultOpen = true }: { id: string; title: ReactNode; actions?: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [own, toggleOwn] = useOpen(id, defaultOpen);
  const acc = useContext(PropAccordion);
  const open = acc ? acc.open === id : own;
  const toggle = acc ? () => acc.set(open ? null : id) : toggleOwn;
  return (
    <section className="border-b border-stone-200 dark:border-stone-800">
      <div className={cn('flex items-center gap-1 pr-2', acc ? 'h-11' : 'h-8')}>
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          className={cn(
            'flex h-full min-w-0 flex-1 items-center gap-1.5 px-3 text-left font-semibold tracking-wide text-stone-600 uppercase hover:text-stone-950 dark:text-stone-400 dark:hover:text-white',
            acc ? 'text-xs' : 'text-[11px]'
          )}
        >
          <ChevronDown className={cn('size-3.5 shrink-0 transition', !open && '-rotate-90')} />
          <span className="truncate">{title}</span>
        </button>
        {actions}
      </div>
      {open ? <div className="space-y-1.5 px-3 pb-3">{children}</div> : null}
    </section>
  );
}

/**
 * Settings that most people do not need, folded away inside a section (closed at first). It
 * remembers if it is open.
 */
export function PropAdvanced({ id, label = 'Advanced', children }: { id: string; label?: ReactNode; children: ReactNode }) {
  const [open, toggle] = useOpen(`advanced.${id}`, false);
  return (
    <div className="pt-0.5">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex items-center gap-1 text-[11px] font-medium text-stone-500 hover:text-stone-900 dark:text-stone-400 dark:hover:text-white"
      >
        <ChevronDown className={cn('size-3 shrink-0 transition', !open && '-rotate-90')} />
        {label}
      </button>
      {open ? <div className="mt-1.5 space-y-1.5 border-l-2 border-stone-200 pl-2 dark:border-stone-700">{children}</div> : null}
    </div>
  );
}

/** One property: the label on the left, the value on the right. */
export function PropRow({
  label,
  hint,
  children,
  htmlFor,
  onScrubStart,
  onScrub
}: {
  label: ReactNode;
  /** Shown when the pointer is on the label. */
  hint?: string;
  children: ReactNode;
  htmlFor?: string;
  /** Drag the label to change the value: called with the number of steps since the press. */
  onScrubStart?: () => void;
  onScrub?: (steps: number) => void;
}) {
  const drag = useRef<{ x: number; last: number } | null>(null);
  return (
    <div className="grid min-h-7 grid-cols-[minmax(0,7rem)_minmax(0,1fr)] items-center gap-2">
      <label
        htmlFor={htmlFor}
        title={hint ?? (onScrub ? 'Drag left or right to change (Shift: faster)' : undefined)}
        className={cn('truncate text-xs text-stone-500 select-none dark:text-stone-400', onScrub && 'cursor-ew-resize')}
        onPointerDown={(e) => {
          if (!onScrub || e.button !== 0) return;
          e.preventDefault();
          try {
            e.currentTarget.setPointerCapture(e.pointerId);
          } catch {}
          drag.current = { x: e.clientX, last: 0 };
          onScrubStart?.();
        }}
        onPointerMove={(e) => {
          const d = drag.current;
          if (!d || !onScrub) return;
          const steps = Math.round((e.clientX - d.x) / 4) * (e.shiftKey ? 10 : 1);
          if (steps !== d.last) {
            d.last = steps;
            onScrub(steps);
          }
        }}
        onPointerUp={() => (drag.current = null)}
        onPointerCancel={() => (drag.current = null)}
      >
        {label}
      </label>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

/** A short note under some properties. */
export function PropNote({ children, tone }: { children: ReactNode; tone?: 'red' }) {
  return <p className={cn('text-[11px] leading-snug', tone === 'red' ? 'text-red-600 dark:text-red-400' : 'text-stone-500 dark:text-stone-400')}>{children}</p>;
}

/**
 * A number field. A typed number applies 0.7 s after the last key, or at once with Enter or
 * when the field loses focus; Escape puts the old number back. The arrow keys step the number
 * by `step` (Shift: 10 steps) and apply at once. `decimal` allows a sign and a decimal point.
 * `compact`: the small style of the inspector.
 */
export function NumberInput({
  id,
  value,
  min = 0,
  max = 100_000,
  step = 1,
  decimal = false,
  onCommit,
  placeholder,
  className,
  compact = false
}: {
  id?: string;
  value: number | null;
  min?: number;
  max?: number;
  step?: number;
  decimal?: boolean;
  onCommit: (n: number) => void;
  placeholder?: string;
  className?: string;
  compact?: boolean;
}) {
  const [text, setText] = useState(value == null ? '' : String(value));
  /** True while you are typing a number that is not applied yet. */
  const typing = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Show the applied value (it can be limited, for example so segments do not cross),
  // except while you are in the middle of typing.
  useEffect(() => {
    if (!typing.current) setText(value == null ? '' : String(value));
  }, [value]);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);
  const clamp = (n: number) => Math.min(max, Math.max(min, n));
  const parse = (t: string) => (t === '' || t === '-' || t === '.' || t === '-.' ? NaN : Number(t));
  const commit = (t = text) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    typing.current = false;
    const n = parse(t);
    if (Number.isFinite(n) && clamp(n) !== value) onCommit(clamp(n));
    else setText(value == null ? '' : String(value));
  };
  return (
    <input
      id={id}
      inputMode={decimal ? 'decimal' : 'numeric'}
      value={text}
      placeholder={placeholder}
      className={cn(compact ? propInput : cn(inputBase, 'h-10'), className)}
      onBlur={() => commit()}
      onKeyDown={(e) => {
        if (e.key === 'Enter') commit();
        if (e.key === 'Escape') {
          typing.current = false;
          if (timer.current) clearTimeout(timer.current);
          setText(value == null ? '' : String(value));
          (e.target as HTMLInputElement).blur();
        }
        if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
          e.preventDefault();
          const base = Number.isFinite(parse(text)) ? parse(text) : (value ?? 0);
          const next = base + (e.key === 'ArrowUp' ? 1 : -1) * step * (e.shiftKey ? 10 : 1);
          commit(String(clamp(Math.round(next * 1000) / 1000)));
        }
      }}
      onChange={(e) => {
        // A typed number applies when you stop typing for a moment, or press Enter. Half-typed
        // numbers (and an empty field) are never applied, so they cannot upset other segments.
        const t = decimal ? e.target.value.replace(/[^\d.-]/g, '') : e.target.value.replace(/\D/g, '');
        setText(t);
        typing.current = true;
        if (timer.current) clearTimeout(timer.current);
        if (Number.isFinite(parse(t))) timer.current = setTimeout(() => commit(t), 700);
      }}
    />
  );
}

/**
 * A number property. `unit` shows inside the field. − and + buttons beside it step the number
 * by `step` (Shift-click: 10 steps), for adjusting while you look at the lights; `steppers={false}`
 * leaves them out. `tone` puts a green or red dot in the field.
 */
export function PropNumber({
  label,
  value,
  onChange,
  min = 0,
  max = 100_000,
  step = 1,
  decimal = false,
  unit,
  tone,
  steppers = true,
  hint,
  placeholder = 'varies'
}: {
  label: ReactNode;
  value: number | null;
  onChange: (n: number) => void;
  min?: number;
  max?: number;
  step?: number;
  decimal?: boolean;
  unit?: string;
  tone?: 'green' | 'red';
  steppers?: boolean;
  hint?: string;
  placeholder?: string;
}) {
  const id = useId();
  const start = useRef(0);
  const clamp = (n: number) => Math.min(max, Math.max(min, Math.round(n * 1000) / 1000));
  const bump = (d: number, big: boolean) => value != null && onChange(clamp(value + d * step * (big ? 10 : 1)));
  const btn =
    'grid h-7 w-6 shrink-0 place-items-center rounded-md bg-stone-100 text-xs font-semibold text-stone-600 transition hover:bg-stone-200 active:scale-95 disabled:opacity-40 dark:bg-stone-800 dark:text-stone-300 dark:hover:bg-stone-700';
  return (
    <PropRow label={label} hint={hint} htmlFor={id} onScrubStart={() => (start.current = value ?? 0)} onScrub={value == null ? undefined : (steps) => onChange(clamp(start.current + steps * step))}>
      <div className="flex items-center gap-1">
        <div className="relative min-w-0 flex-1">
          {tone ? <span className={cn('pointer-events-none absolute top-1/2 left-2 size-2 -translate-y-1/2 rounded-full', tone === 'green' ? 'bg-green-500' : 'bg-red-500')} /> : null}
          <NumberInput id={id} compact decimal={decimal} value={value} min={min} max={max} step={step} placeholder={placeholder} onCommit={onChange} className={cn(tone && 'pl-6', unit && 'pr-7')} />
          {unit ? <span className="pointer-events-none absolute top-1/2 right-2 -translate-y-1/2 text-[11px] text-stone-400">{unit}</span> : null}
        </div>
        {steppers ? (
          <>
            <button type="button" className={btn} disabled={value == null} onClick={(e) => bump(-1, e.shiftKey)} title={`−${step} (Shift: −${step * 10})`} aria-label={`Lower ${String(label)}`}>
              −
            </button>
            <button type="button" className={btn} disabled={value == null} onClick={(e) => bump(1, e.shiftKey)} title={`+${step} (Shift: +${step * 10})`} aria-label={`Raise ${String(label)}`}>
              +
            </button>
          </>
        ) : null}
      </div>
    </PropRow>
  );
}

export function PropText({ label, value, onChange, maxLength }: { label: ReactNode; value: string; onChange: (v: string) => void; maxLength?: number }) {
  const id = useId();
  return (
    <PropRow label={label} htmlFor={id}>
      <input id={id} value={value} maxLength={maxLength} onChange={(e) => onChange(e.target.value)} className={propInput} />
    </PropRow>
  );
}

export function PropSelect<T extends string>({
  label,
  value,
  onChange,
  options,
  groups,
  hint
}: {
  label: ReactNode;
  value: T;
  onChange: (v: T) => void;
  options: [T, string][];
  /** More options, under headings. */
  groups?: { label: string; options: [T, string][] }[];
  hint?: string;
}) {
  const id = useId();
  return (
    <PropRow label={label} htmlFor={id} hint={hint}>
      <select
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value as T)}
        className={cn(propInput, 'appearance-none bg-[length:14px] bg-[right_0.4rem_center] bg-no-repeat pr-6')}
        style={{ backgroundImage: SELECT_CHEVRON }}
      >
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
        {groups?.map((g) => (
          <optgroup key={g.label} label={g.label}>
            {g.options.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </PropRow>
  );
}

/** A small button for the inspector. */
export function PropButton({ children, onClick, disabled, title, danger }: { children: ReactNode; onClick: () => void; disabled?: boolean; title?: string; danger?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={cn(
        'inline-flex h-7 items-center gap-1.5 rounded-md bg-stone-100 px-2.5 text-xs font-medium transition hover:bg-stone-200 disabled:pointer-events-none disabled:opacity-50 dark:bg-stone-800 dark:hover:bg-stone-700 [&_svg]:size-3.5',
        danger ? 'text-red-600 dark:text-red-400' : 'text-stone-700 dark:text-stone-200'
      )}
    >
      {children}
    </button>
  );
}

/** A 0..1 property as a slider, with the value in percent beside it. */
export function PropSlider({ label, value, onChange, hint }: { label: ReactNode; value: number; onChange: (v: number) => void; hint?: string }) {
  const id = useId();
  return (
    <PropRow label={label} htmlFor={id} hint={hint}>
      <div className="flex items-center gap-2">
        <input
          id={id}
          type="range"
          min={0}
          max={1}
          step={0.01}
          value={value}
          onChange={(e) => onChange(Number(e.target.value))}
          className="h-7 min-w-0 flex-1 cursor-pointer accent-sky-600 dark:accent-sky-400"
        />
        <span className="w-7 shrink-0 text-right text-[11px] text-stone-500 tabular-nums">{Math.round(value * 100)}</span>
      </div>
    </PropRow>
  );
}
