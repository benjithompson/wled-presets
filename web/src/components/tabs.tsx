import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/utils.ts';

export type TabItem<T extends string> = { id: T; label: string; icon?: LucideIcon; badge?: ReactNode };

/**
 * The tab of a page that is open, kept in the address (`?tab=`), so a reload, the back button
 * and a link open the same one. The first tab has no `?tab=`.
 */
export function useTab<T extends string>(tabs: readonly TabItem<T>[]) {
  const [params, setParams] = useSearchParams();
  const raw = params.get('tab');
  const tab = tabs.find((t) => t.id === raw)?.id ?? tabs[0].id;
  const setTab = (t: T) =>
    setParams(
      (p) => {
        const next = new URLSearchParams(p);
        if (t === tabs[0].id) next.delete('tab');
        else next.set('tab', t);
        return next;
      },
      { replace: true }
    );
  return [tab, setTab] as const;
}

/**
 * A row of tabs under a page's header: one part of the page at a time, instead of every part
 * one below the other. On a phone the row scrolls sideways when it is wider than the screen.
 * The arrow keys move between the tabs.
 */
export function Tabs<T extends string>({ tabs, value, onChange, label, className }: { tabs: readonly TabItem<T>[]; value: T; onChange: (t: T) => void; label: string; className?: string }) {
  const list = useRef<HTMLDivElement>(null);
  // On a phone, the open tab is scrolled into the row's view (sideways only: the page stays put).
  useEffect(() => {
    const row = list.current?.parentElement;
    const on = list.current?.querySelector<HTMLElement>('[aria-selected=true]');
    if (!row || !on || row.scrollWidth <= row.clientWidth) return;
    const left = on.getBoundingClientRect().left - row.getBoundingClientRect().left + row.scrollLeft;
    if (left < row.scrollLeft || left + on.offsetWidth > row.scrollLeft + row.clientWidth) row.scrollLeft = left - 16;
  }, [value]);
  const onKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex((t) => t.id === value);
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    const to = e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : step ? (i + step + tabs.length) % tabs.length : -1;
    if (to < 0) return;
    e.preventDefault();
    onChange(tabs[to].id);
    list.current?.querySelectorAll<HTMLButtonElement>('[role=tab]')[to]?.focus();
  };
  return (
    <div className={cn('-mx-4 mb-5 overflow-x-auto px-4 [scrollbar-width:none] sm:mx-0 sm:px-0 md:mb-6 [&::-webkit-scrollbar]:hidden', className)}>
      <div ref={list} role="tablist" aria-label={label} onKeyDown={onKey} className="flex min-w-max gap-1 border-b border-stone-200 dark:border-stone-800">
        {tabs.map((t) => {
          const on = t.id === value;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={on}
              tabIndex={on ? 0 : -1}
              onClick={() => onChange(t.id)}
              className={cn(
                '-mb-px inline-flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium whitespace-nowrap transition select-none [&_svg]:size-4',
                on
                  ? 'border-accent-500 text-stone-900 dark:border-accent-400 dark:text-white'
                  : 'border-transparent text-stone-500 hover:border-stone-300 hover:text-stone-800 dark:text-stone-400 dark:hover:border-stone-700 dark:hover:text-stone-200'
              )}
            >
              {t.icon ? <t.icon /> : null}
              {t.label}
              {t.badge != null ? <span className="rounded-full bg-stone-200/80 px-1.5 text-xs text-stone-600 tabular-nums dark:bg-stone-800 dark:text-stone-300">{t.badge}</span> : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** One tab's part of the page. */
export function TabPanel({ id, children, className }: { id: string; children: ReactNode; className?: string }) {
  return (
    <div role="tabpanel" aria-labelledby={`tab-${id}`} className={className}>
      {children}
    </div>
  );
}

/** A link in a sentence that opens another tab (`<Link to="?tab=…">`). */
export const tabLink = 'font-medium text-stone-700 underline decoration-stone-300 underline-offset-2 hover:text-stone-900 dark:text-stone-300 dark:decoration-stone-600 dark:hover:text-white';
