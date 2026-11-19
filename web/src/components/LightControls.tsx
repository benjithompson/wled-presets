import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Power, Sun, SunDim } from 'lucide-react';
import { toast } from 'sonner';
import type { LightControls } from '../../../shared/types.ts';
import { api } from '../lib/api.ts';
import { cn, errorText } from '../lib/utils.ts';

export const LIGHTS = ['admin', 'lights'];

/** The admin's power and brightness switches (see LightControls). */
export function useLightControls(enabled = true) {
  return useQuery({ queryKey: LIGHTS, queryFn: api.lightControls, enabled });
}

/** Power and brightness changes for every light or one device, with the caches they touch kept fresh. */
export function useLightMutations() {
  const qc = useQueryClient();
  const done = (r: { controls: LightControls; result: { failed: { error: string }[] } }) => {
    qc.setQueryData(LIGHTS, r.controls);
    void qc.invalidateQueries({ queryKey: ['admin', 'overview'] });
    void qc.invalidateQueries({ queryKey: ['public-state'] });
    if (r.result.failed.length) toast.warning(`${r.result.failed.length} light(s) did not answer: ${r.result.failed[0].error}`);
  };
  const power = useMutation({
    mutationFn: ({ on, deviceId = null }: { on: boolean; deviceId?: string | null }) => api.setPower(on, deviceId),
    onSuccess: done,
    onError: (e) => toast.error(errorText(e))
  });
  const brightness = useMutation({
    mutationFn: ({ level, deviceId = null }: { level: number | null; deviceId?: string | null }) => api.setBrightness(level, deviceId),
    onSuccess: done,
    onError: (e) => toast.error(errorText(e))
  });
  return { power, brightness };
}

/** A round power button: lit when the lights are on. */
export function PowerButton({ on, onToggle, label, disabled, size = 'md' }: { on: boolean; onToggle: () => void; label: string; disabled?: boolean; size?: 'sm' | 'md' }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      title={on ? `${label}: on` : `${label}: off`}
      disabled={disabled}
      onClick={onToggle}
      className={cn(
        'grid shrink-0 place-items-center rounded-full transition disabled:opacity-50',
        size === 'sm' ? 'size-8 [&_svg]:size-4' : 'size-10 [&_svg]:size-5',
        on
          ? 'bg-accent-400 text-stone-950 shadow-[0_0_18px_-2px] shadow-accent-400/70 hover:bg-accent-300'
          : 'bg-stone-200 text-stone-500 hover:bg-stone-300 dark:bg-stone-800 dark:text-stone-400 dark:hover:bg-stone-700'
      )}
    >
      <Power />
    </button>
  );
}

/**
 * A brightness slider (percent). It moves at once and sends the level a moment after the hand
 * stops, so a drag is one or two requests, not dozens.
 */
export function LevelSlider({ value, placeholder = 100, onCommit, label, disabled, className }: { value: number | null; placeholder?: number; onCommit: (v: number) => void; label: string; disabled?: boolean; className?: string }) {
  const [local, setLocal] = useState<number | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);
  // A new value from the server ends the local drag state.
  useEffect(() => setLocal(null), [value]);
  const shown = local ?? value ?? placeholder;
  return (
    <label className={cn('flex min-w-0 items-center gap-2', disabled && 'opacity-50', className)}>
      <SunDim className="size-4 shrink-0 text-stone-400" aria-hidden />
      <input
        type="range"
        min={1}
        max={100}
        value={shown}
        disabled={disabled}
        aria-label={label}
        aria-valuetext={value == null && local == null ? 'Set by each scene' : `${shown}%`}
        onChange={(e) => {
          const v = Number(e.target.value);
          setLocal(v);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => onCommit(v), 250);
        }}
        className={cn('h-1.5 min-w-16 flex-1 cursor-pointer accent-amber-500', value == null && local == null && 'opacity-60')}
      />
      <Sun className="size-4 shrink-0 text-stone-400" aria-hidden />
      <span className="w-10 shrink-0 text-right text-xs text-stone-500 tabular-nums dark:text-stone-400">{value == null && local == null ? 'auto' : `${shown}%`}</span>
    </label>
  );
}
