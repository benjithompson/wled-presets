import { Monitor, Moon, Sun } from 'lucide-react';
import { setTheme, useTheme, type Theme } from '../lib/theme.ts';
import { cn } from '../lib/utils.ts';

const OPTIONS: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor }
];

/** Segmented control with the three theme choices. */
export function ThemeSwitcher({ className }: { className?: string }) {
  const theme = useTheme();
  return (
    <div role="radiogroup" aria-label="Theme" className={cn('inline-flex rounded-xl bg-stone-100 p-1 dark:bg-stone-800/80', className)}>
      {OPTIONS.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={theme === value}
          title={label}
          onClick={() => setTheme(value)}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium transition',
            theme === value
              ? 'bg-white text-stone-900 shadow-sm dark:bg-stone-700 dark:text-white'
              : 'text-stone-500 hover:text-stone-800 dark:text-stone-400 dark:hover:text-stone-200'
          )}
        >
          <Icon className="size-3.5" />
          {label}
        </button>
      ))}
    </div>
  );
}

/** One button that cycles light → dark → system. */
export function ThemeCycleButton({ className }: { className?: string }) {
  const theme = useTheme();
  const i = OPTIONS.findIndex((o) => o.value === theme);
  const { icon: Icon, label } = OPTIONS[i];
  const next = OPTIONS[(i + 1) % OPTIONS.length];
  return (
    <button
      type="button"
      onClick={() => setTheme(next.value)}
      aria-label={`Theme: ${label}. Switch to ${next.label}.`}
      title={`Theme: ${label}`}
      className={cn(
        'grid size-10 place-items-center rounded-full text-stone-500 ring-1 ring-stone-200 backdrop-blur transition hover:text-stone-900 dark:text-stone-400 dark:ring-white/10 dark:hover:text-white',
        className
      )}
    >
      <Icon className="size-[18px]" />
    </button>
  );
}
