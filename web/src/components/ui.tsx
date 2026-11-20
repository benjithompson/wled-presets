import { useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react';
import { Loader2, X } from 'lucide-react';
import { cn } from '../lib/utils.ts';
import { MoreButton, type ActionItem } from './mobile.tsx';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
type Size = 'sm' | 'md' | 'icon';

const variants: Record<Variant, string> = {
  primary:
    'bg-stone-900 text-white hover:bg-stone-800 dark:bg-accent-400 dark:text-stone-950 dark:hover:bg-accent-300 shadow-sm',
  secondary:
    'bg-white text-stone-800 ring-1 ring-inset ring-stone-200 hover:bg-stone-50 dark:bg-stone-900 dark:text-stone-100 dark:ring-stone-800 dark:hover:bg-stone-800/70 shadow-xs',
  ghost: 'text-stone-600 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800/70 dark:hover:text-stone-100',
  danger: 'bg-red-600 text-white hover:bg-red-500 shadow-sm'
};
const sizes: Record<Size, string> = {
  sm: 'h-8 px-3 text-[13px] gap-1.5 rounded-lg',
  md: 'h-10 px-4 text-sm gap-2 rounded-xl',
  icon: 'size-9 rounded-xl justify-center'
};

export function Button({
  variant = 'secondary',
  size = 'md',
  loading,
  className,
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size; loading?: boolean }) {
  return (
    <button
      type="button"
      className={cn(
        'inline-flex shrink-0 items-center font-medium whitespace-nowrap transition-colors select-none disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4',
        variants[variant],
        sizes[size],
        className
      )}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <Loader2 className="animate-spin" /> : null}
      {children}
    </button>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn('size-4 animate-spin text-stone-400', className)} />;
}

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn('rounded-2xl bg-white ring-1 ring-stone-200/80 shadow-xs dark:bg-stone-900/60 dark:ring-stone-800', className)}>
      {children}
    </div>
  );
}

export function CardHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-stone-100 px-5 py-4 dark:border-stone-800">
      <div className="min-w-0">
        <h2 className="text-[15px] font-semibold tracking-tight">{title}</h2>
        {description ? <p className="mt-0.5 text-sm text-stone-500 dark:text-stone-400">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/**
 * A page's title, what it is for, and its buttons. `more`: the actions after the main ones:
 * buttons on wide screens, a ⋯ menu on a phone. On a phone a long description is cut to two
 * lines, with More to read all of it.
 */
export function PageHeader({ title, description, actions, more }: { title: string; description?: ReactNode; actions?: ReactNode; more?: ActionItem[] }) {
  const [full, setFull] = useState(false);
  const long = typeof description === 'string' && description.length > 110;
  return (
    <div className="mb-5 grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 md:mb-6 md:items-end">
      <h1 className="col-start-1 row-start-1 text-2xl font-semibold tracking-tight">{title}</h1>
      {more?.length || actions ? (
        <div className="col-start-2 row-start-1 flex flex-wrap items-center justify-end gap-2 md:row-span-2">
          {more?.map((m) => (
            <Button key={m.label} onClick={m.run} disabled={m.disabled} className="max-md:hidden">
              {m.icon ? <m.icon /> : null} {m.label}
            </Button>
          ))}
          {more?.length ? <MoreButton items={more} title={title} className="-mr-2 md:hidden" /> : null}
          {actions}
        </div>
      ) : null}
      {description ? (
        <div className="col-span-2 col-start-1 row-start-2 md:col-span-1">
          <p className={cn('max-w-prose text-sm text-stone-500 dark:text-stone-400', long && !full && 'max-md:line-clamp-2')}>{description}</p>
          {long ? (
            <button type="button" onClick={() => setFull((v) => !v)} className="mt-0.5 text-sm font-medium text-stone-700 md:hidden dark:text-stone-300">
              {full ? 'Less' : 'More'}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export const inputBase =
  'w-full rounded-xl bg-white px-3 text-sm ring-1 ring-inset ring-stone-200 placeholder:text-stone-400 transition focus:ring-2 focus:ring-accent-500 focus:outline-none dark:bg-stone-950 dark:ring-stone-800 dark:placeholder:text-stone-600 disabled:opacity-60';

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(inputBase, 'h-10', className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn(inputBase, 'h-10 appearance-none bg-[length:16px] bg-[right_0.6rem_center] bg-no-repeat pr-8', className)} style={{ backgroundImage: CHEVRON }} {...rest}>
      {children}
    </select>
  );
}
const CHEVRON = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23a8a29e' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`;

export function Field({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string | null; children: (id: string) => ReactNode }) {
  const id = useId();
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium text-stone-700 dark:text-stone-300">
        {label}
      </label>
      {children(id)}
      {error ? <p className="text-xs text-red-600 dark:text-red-400">{error}</p> : hint ? <p className="text-xs text-stone-500 dark:text-stone-400">{hint}</p> : null}
    </div>
  );
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-6 w-10 shrink-0 items-center rounded-full transition-colors disabled:opacity-50',
        checked ? 'bg-emerald-500' : 'bg-stone-300 dark:bg-stone-700'
      )}
    >
      <span className={cn('inline-block size-5 rounded-full bg-white shadow transition-transform', checked ? 'translate-x-[18px]' : 'translate-x-0.5')} />
    </button>
  );
}

type Tone = 'neutral' | 'green' | 'red' | 'amber' | 'blue';
const tones: Record<Tone, string> = {
  neutral: 'bg-stone-100 text-stone-600 dark:bg-stone-800 dark:text-stone-300',
  green: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400',
  red: 'bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400',
  amber: 'bg-amber-50 text-amber-800 dark:bg-amber-500/10 dark:text-amber-300',
  blue: 'bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300'
};

export function Badge({ tone = 'neutral', children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium', tones[tone], className)}>{children}</span>;
}

export function StatusDot({ online }: { online: boolean | null }) {
  return (
    <span className="relative inline-flex size-2.5">
      {online ? <span className="absolute inset-0 animate-ping rounded-full bg-emerald-400 opacity-40" /> : null}
      <span className={cn('relative inline-flex size-2.5 rounded-full', online === null ? 'bg-stone-300 dark:bg-stone-600' : online ? 'bg-emerald-500' : 'bg-red-500')} />
    </span>
  );
}

export function Empty({ icon, title, children, action }: { icon: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <div className="mb-4 grid size-12 place-items-center rounded-2xl bg-stone-100 text-stone-500 dark:bg-stone-800 dark:text-stone-400 [&_svg]:size-6">{icon}</div>
      <h3 className="font-semibold">{title}</h3>
      {children ? <p className="mt-1 max-w-sm text-sm text-stone-500 dark:text-stone-400">{children}</p> : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md'
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      // Only its own: a dialog opened inside this one sends its close here too (through React).
      onClose={(e) => e.target === ref.current && onClose()}
      onCancel={(e) => {
        if (e.target !== ref.current) return;
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      className={cn(
        // On a phone it rises from the bottom, as a sheet.
        'm-auto w-[calc(100%-2rem)] rounded-2xl bg-white p-0 max-sm:mx-0 max-sm:mt-auto max-sm:mb-0 max-sm:w-full max-sm:max-w-none max-sm:animate-sheet-in max-sm:rounded-b-none text-stone-900 shadow-2xl ring-1 ring-stone-200 backdrop:bg-stone-950/40 backdrop:backdrop-blur-sm dark:bg-stone-900 dark:text-stone-100 dark:ring-stone-800',
        size === 'sm' ? 'max-w-sm' : size === 'lg' ? 'max-w-2xl' : size === 'xl' ? 'max-w-6xl' : 'max-w-lg'
      )}
    >
      {open ? (
        <div className="flex max-h-[85dvh] flex-col max-sm:max-h-[92dvh]">
          <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-3 sm:px-6">
            <div>
              <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
              {description ? <p className="mt-1 text-sm text-stone-500 dark:text-stone-400">{description}</p> : null}
            </div>
            <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close" className="-mt-1 -mr-2">
              <X />
            </Button>
          </div>
          {children ? <div className="overflow-y-auto overscroll-contain px-5 py-2 sm:px-6">{children}</div> : null}
          {footer ? (
            <div
              className="flex flex-wrap justify-end gap-2 border-t border-stone-100 px-5 pt-4 pb-[calc(1rem+env(safe-area-inset-bottom,0px))] sm:px-6 sm:pb-4 dark:border-stone-800 max-sm:[&>button]:h-11 max-sm:[&>button]:flex-1 max-sm:[&>button]:justify-center"
            >
              {footer}
            </div>
          ) : null}
        </div>
      ) : null}
    </dialog>
  );
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel = 'Confirm',
  danger,
  loading,
  onConfirm,
  onClose
}: {
  open: boolean;
  title: string;
  children?: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  loading?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      description={children}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={danger ? 'danger' : 'primary'} loading={loading} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </>
      }
    />
  );
}
