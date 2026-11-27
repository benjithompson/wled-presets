import { useEffect, useRef, useState } from 'react';
import { useMutation, useMutationState, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Power, Sun, SunDim } from 'lucide-react';
import { toast } from 'sonner';
import type { LightControls } from '../../../shared/types.ts';
import { api } from '../lib/api.ts';
import { cn, errorText } from '../lib/utils.ts';

export const LIGHTS = ['admin', 'lights'];
const POWER = ['lights', 'power'];
/** The key of all lights' switch (see useLightMutations' switchOf). */
const ALL = '*';
/**
 * How long a light keeps showing the switch it was given once the command is done, while what
 * it says of itself catches up (a WLED device's WebSocket, the next check).
 */
const SETTLE_MS = 4000;

type PowerVars = { on: boolean; deviceId?: string | null };
/** A switch on its way or just done: the state asked for, whether it is still on its way, and whether it was this light's own (not all lights'). */
export type Switching = { on: boolean; busy: boolean; own: boolean };

/** The admin's power and brightness switches (see LightControls). */
export function useLightControls(enabled = true) {
  return useQuery({ queryKey: LIGHTS, queryFn: api.lightControls, enabled });
}

/**
 * Power and brightness changes for every light or one device, with the caches they touch kept
 * fresh. `switchOf` says how a light's switch shows at once: as asked, while the command is on
 * its way (and a moment after, see SETTLE_MS), so a press shows straight away.
 */
export function useLightMutations() {
  const qc = useQueryClient();
  const done = async (r: { controls: LightControls; result: { failed: { error: string }[] } }) => {
    qc.setQueryData(LIGHTS, r.controls);
    if (r.result.failed.length) toast.warning(`${r.result.failed.length} light(s) did not answer: ${r.result.failed[0].error}`);
    // Still on its way until the page has what the lights say now.
    await Promise.all([qc.invalidateQueries({ queryKey: ['admin', 'overview'] }), qc.invalidateQueries({ queryKey: ['public-state'] })]);
  };
  const [settled, setSettled] = useState<ReadonlyMap<string, { on: boolean; at: number }>>(new Map());
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => timers.current.forEach(clearTimeout), []);
  const power = useMutation({
    mutationKey: POWER,
    mutationFn: ({ on, deviceId = null }: PowerVars) => api.setPower(on, deviceId),
    onSuccess: async (r, { on, deviceId = null }) => {
      const key = deviceId ?? ALL;
      const at = Date.now();
      setSettled((m) => new Map(m).set(key, { on, at }));
      const timer = setTimeout(() => {
        timers.current.delete(timer);
        setSettled((m) => (m.get(key)?.at === at ? new Map([...m].filter(([k]) => k !== key)) : m));
      }, SETTLE_MS);
      timers.current.add(timer);
      await done(r);
    },
    onError: (e) => toast.error(errorText(e))
  });
  // Every switch on its way, from any part of the page, oldest first.
  const pending = useMutationState({ filters: { mutationKey: POWER, status: 'pending' }, select: (m) => m.state.variables as PowerVars });
  /** How a light's switch (null: all lights') shows now, when a switch is on its way or just done; null: as the light says. */
  const switchOf = (deviceId: string | null = null): Switching | null => {
    const own = pending.findLast((v) => (v.deviceId ?? null) === deviceId);
    const all = deviceId != null ? pending.findLast((v) => v.deviceId == null) : undefined;
    if (own || all) return { on: (own ?? all)!.on, busy: true, own: !!own };
    const mine = settled.get(deviceId ?? ALL);
    const every = deviceId != null ? settled.get(ALL) : undefined;
    const last = mine && (!every || mine.at >= every.at) ? mine : every;
    return last ? { on: last.on, busy: false, own: last === mine } : null;
  };
  const brightness = useMutation({
    mutationFn: ({ level, deviceId = null }: { level: number | null; deviceId?: string | null }) => api.setBrightness(level, deviceId),
    onSuccess: done,
    onError: (e) => toast.error(errorText(e))
  });
  return { power, brightness, switchOf };
}

/** A round power button: lit when the lights are on; `busy` spins while its switch is on its way. */
export function PowerButton({ on, onToggle, label, disabled, busy, size = 'md' }: { on: boolean; onToggle: () => void; label: string; disabled?: boolean; busy?: boolean; size?: 'sm' | 'md' }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      aria-busy={busy || undefined}
      title={busy ? `${label}: switching ${on ? 'on' : 'off'}…` : on ? `${label}: on` : `${label}: off`}
      disabled={disabled || busy}
      onClick={onToggle}
      className={cn(
        'grid shrink-0 place-items-center rounded-full transition',
        busy ? 'cursor-wait' : 'disabled:opacity-50',
        size === 'sm' ? 'size-8 [&_svg]:size-4' : 'size-10 [&_svg]:size-5',
        on
          ? 'bg-accent-400 text-stone-950 shadow-[0_0_18px_-2px] shadow-accent-400/70 hover:bg-accent-300'
          : 'bg-stone-200 text-stone-500 hover:bg-stone-300 dark:bg-stone-800 dark:text-stone-400 dark:hover:bg-stone-700'
      )}
    >
      {busy ? <Loader2 className="animate-spin" /> : <Power />}
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
