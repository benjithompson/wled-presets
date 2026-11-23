// The pieces that make the admin pages work like phone apps on small screens: an action sheet
// (a menu that rises from the bottom), a bottom sheet with tabs that opens halfway or fully,
// a ⋯ button for the actions that do not fit, and a bar of actions pinned to the bottom.
import { useEffect, useRef, useState, type HTMLAttributes, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, ChevronUp, Ellipsis, Maximize2, Minimize2, type LucideIcon } from 'lucide-react';
import { cn } from '../lib/utils.ts';
import { useMedia } from '../lib/useMedia.ts';

/** Below Tailwind's `md`: a phone, held either way up. */
export const PHONE_QUERY = '(max-width: 767px)';
export function usePhone() {
  return useMedia(PHONE_QUERY);
}

export type ActionItem = { label: string; icon?: LucideIcon; danger?: boolean; disabled?: boolean; keys?: string; run: () => void };

/** A menu that rises from the bottom of the screen, with big rows and Cancel, as phone apps do. */
export function ActionSheet({ title, items, onClose, ...rest }: { title?: ReactNode; items: ActionItem[]; onClose: () => void } & Omit<HTMLAttributes<HTMLDivElement>, 'title'>) {
  useEffect(() => {
    const key = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', key);
    return () => document.removeEventListener('keydown', key);
  }, [onClose]);
  // On the body, so nothing on the page (a transform, a stacking context) can cover or clip it.
  return createPortal(
    <div
      className="animate-fade-in fixed inset-0 z-50 flex items-end bg-stone-950/40"
      onClick={(e) => e.target === e.currentTarget && onClose()}
      onContextMenu={(e) => e.preventDefault()}
    >
      <div
        role="menu"
        className="animate-sheet-in max-h-[80dvh] w-full overflow-y-auto rounded-t-2xl bg-white p-2 text-base text-stone-900 shadow-2xl dark:bg-stone-900 dark:text-stone-100"
        style={{ paddingBottom: 'calc(0.5rem + env(safe-area-inset-bottom, 0px))' }}
        {...rest}
      >
        {title ? <p className="truncate px-3 pt-2 pb-2 text-center text-xs font-medium text-stone-500">{title}</p> : null}
        {items.map((it) => (
          <button
            key={it.label}
            type="button"
            role="menuitem"
            disabled={it.disabled}
            onClick={() => {
              onClose();
              it.run();
            }}
            className={cn(
              'flex min-h-12 w-full items-center gap-3 rounded-xl px-3 text-left active:bg-stone-100 disabled:opacity-40 dark:active:bg-stone-800 [&_svg]:size-5 [&_svg]:shrink-0',
              it.danger ? 'text-red-600 dark:text-red-400' : 'text-stone-800 dark:text-stone-100'
            )}
          >
            {it.icon ? <it.icon className={it.danger ? undefined : 'text-stone-500 dark:text-stone-400'} /> : null}
            {it.label}
          </button>
        ))}
        <button
          type="button"
          onClick={onClose}
          className="mt-1 flex min-h-12 w-full items-center justify-center rounded-xl bg-stone-100 font-semibold text-stone-800 active:bg-stone-200 dark:bg-stone-800 dark:text-stone-100 dark:active:bg-stone-700"
        >
          Cancel
        </button>
      </div>
    </div>,
    document.body
  );
}

/** A ⋯ button that opens an action sheet. */
export function MoreButton({ title, items, label = 'More actions', className }: { title?: ReactNode; items: ActionItem[]; label?: string; className?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(true)}
        className={cn(
          'grid size-10 shrink-0 place-items-center rounded-xl text-stone-600 transition active:bg-stone-200 dark:text-stone-300 dark:active:bg-stone-800 [&_svg]:size-5',
          className
        )}
      >
        <Ellipsis />
      </button>
      {open ? <ActionSheet title={title} items={items} onClose={() => setOpen(false)} /> : null}
    </>
  );
}

/**
 * On a phone: a bar pinned to the bottom of the screen, for the action a page is waiting on
 * (Save). Elsewhere it renders nothing: wide screens keep the button in the page header.
 */
export function PhoneActionBar({ show, children }: { show: boolean; children: ReactNode }) {
  const phone = usePhone();
  if (!phone || !show) return null;
  return (
    <>
      {/* Room at the end of the page, so the bar never covers the last row. */}
      <div aria-hidden className="h-20" />
      <div
        className="animate-sheet-in fixed inset-x-0 bottom-0 z-30 flex items-center gap-2 border-t border-stone-200 bg-white/90 px-4 pt-3 shadow-[0_-8px_24px_-12px_rgba(0,0,0,0.3)] backdrop-blur-lg dark:border-stone-800 dark:bg-stone-900/90"
        style={{ paddingBottom: 'calc(0.75rem + env(safe-area-inset-bottom, 0px))' }}
      >
        {children}
      </div>
    </>
  );
}

export type SheetSize = 'peek' | 'half' | 'full';
const SIZES: SheetSize[] = ['peek', 'half', 'full'];

const sheetIcon =
  'grid size-10 shrink-0 place-items-center rounded-lg text-stone-600 transition hover:bg-stone-200/70 active:bg-stone-200 dark:text-stone-300 dark:hover:bg-stone-800 dark:active:bg-stone-700 [&_svg]:size-[18px]';

/**
 * A phone's bottom sheet: a row of tabs that opens to half the screen or all of it. Swipe the
 * handle up or down, or tap it, to change its size. It sits at the end of a full-height column.
 */
export function BottomSheet<T extends string>({
  label,
  size,
  onSize,
  tabs,
  tab,
  onTab,
  children
}: {
  label: string;
  size: SheetSize;
  onSize: (s: SheetSize) => void;
  tabs: { id: T; content: ReactNode }[];
  tab: T;
  onTab: (t: T) => void;
  children: ReactNode;
}) {
  const drag = useRef<number | null>(null);
  const step = (d: number) => onSize(SIZES[Math.max(0, Math.min(SIZES.length - 1, SIZES.indexOf(size) + d))]);
  const toggle = () => onSize(size === 'peek' ? 'half' : 'peek');
  return (
    <section
      aria-label={label}
      className={cn(
        'flex min-h-0 shrink-0 flex-col border-t border-stone-200 bg-white text-sm shadow-[0_-8px_24px_-12px_rgba(0,0,0,0.3)] dark:border-stone-800 dark:bg-stone-900',
        size === 'half' && 'h-[40dvh]',
        size === 'full' && 'flex-1'
      )}
      style={{ paddingBottom: 'env(safe-area-inset-bottom, 0px)' }}
    >
      <button
        type="button"
        aria-label={size === 'peek' ? 'Open the panel' : 'Close the panel'}
        className="flex h-5 w-full shrink-0 touch-none items-center justify-center"
        onPointerDown={(e) => {
          drag.current = e.clientY;
          e.currentTarget.setPointerCapture(e.pointerId);
        }}
        onPointerUp={(e) => {
          const y = drag.current;
          drag.current = null;
          if (y == null) return;
          const dy = e.clientY - y;
          if (dy < -24) step(1);
          else if (dy > 24) step(-1);
          else toggle();
        }}
        onPointerCancel={() => (drag.current = null)}
        // The keyboard (a click with no pointer) opens and closes it too.
        onClick={(e) => e.detail === 0 && toggle()}
      >
        <span className="h-1 w-10 rounded-full bg-stone-300 dark:bg-stone-600" />
      </button>
      <div className="flex shrink-0 items-center gap-1 px-2 pb-1.5">
        <div role="tablist" aria-label={label} className="flex min-w-0 flex-1 rounded-lg bg-stone-100 p-0.5 dark:bg-stone-800">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => (onTab(t.id), size === 'peek' && onSize('half'))}
              className={cn(
                'inline-flex h-9 min-w-0 flex-1 items-center justify-center gap-1.5 rounded-md px-2 text-[13px] font-medium transition [&_svg]:size-4 [&_svg]:shrink-0',
                tab === t.id && size !== 'peek' ? 'bg-white text-stone-900 shadow-sm dark:bg-stone-950 dark:text-white' : 'text-stone-600 dark:text-stone-300'
              )}
            >
              {t.content}
            </button>
          ))}
        </div>
        {size !== 'peek' ? (
          <button type="button" onClick={() => onSize(size === 'full' ? 'half' : 'full')} aria-label={size === 'full' ? 'Make the panel smaller' : 'Make the panel full height'} className={sheetIcon}>
            {size === 'full' ? <Minimize2 /> : <Maximize2 />}
          </button>
        ) : null}
        <button type="button" onClick={toggle} aria-label={size === 'peek' ? 'Open the panel' : 'Close the panel'} className={sheetIcon}>
          {size === 'peek' ? <ChevronUp /> : <ChevronDown />}
        </button>
      </div>
      {size !== 'peek' ? <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain border-t border-stone-200 dark:border-stone-800">{children}</div> : null}
    </section>
  );
}
