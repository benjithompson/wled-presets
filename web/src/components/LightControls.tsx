import { useEffect, useRef, useState } from 'react';
import { useMutation, useMutationState, useQuery, useQueryClient, type QueryKey } from '@tanstack/react-query';
import { Loader2, Power, Sun, SunDim } from 'lucide-react';
import { toast } from 'sonner';
import { haId, type HaView } from '../../../shared/homeAssistant.ts';
import type { LightControls, PublicState } from '../../../shared/types.ts';
import { api, type Overview } from '../lib/api.ts';
import { cn, errorText } from '../lib/utils.ts';

export const LIGHTS = ['admin', 'lights'];
const POWER = ['lights', 'power'];
// The caches a switch changes (HA and OVERVIEW as the admin pages name them, the public page's state).
const HA = ['admin', 'lights', 'ha'];
const OVERVIEW = ['admin', 'overview'];
const PUBLIC = ['public-state'];

type PowerVars = { on: boolean; deviceId?: string | null };

/** What a light that is being switched says meanwhile. */
export const switchText = (on: boolean) => (on ? 'Turning on…' : 'Turning off…');

/** The admin's power and brightness switches (see LightControls). */
export function useLightControls(enabled = true) {
  return useQuery({ queryKey: LIGHTS, queryFn: api.lightControls, enabled });
}

/**
 * Power and brightness changes for every light or one device, with the caches they touch kept
 * fresh. A switch shows at once: the page's data says the lights are as asked while the
 * command is on its way (and goes back if it fails), and `switchingTo` says which lights it is
 * still on its way to, for a spinner.
 */
export function useLightMutations() {
  const qc = useQueryClient();
  const done = async (r: { controls: LightControls; result: { failed: { error: string }[] } }) => {
    qc.setQueryData(LIGHTS, r.controls);
    if (r.result.failed.length) toast.warning(`${r.result.failed.length} light(s) did not answer: ${r.result.failed[0].error}`);
    // Still on its way until the page has what the lights say now.
    await Promise.all([OVERVIEW, HA, PUBLIC].map((queryKey) => qc.invalidateQueries({ queryKey, exact: true })));
  };
  const power = useMutation({
    mutationKey: POWER,
    mutationFn: ({ on, deviceId = null }: PowerVars) => api.setPower(on, deviceId),
    onMutate: async ({ on, deviceId = null }) => {
      const keys = [LIGHTS, OVERVIEW, HA, PUBLIC];
      await Promise.all(keys.map((queryKey) => qc.cancelQueries({ queryKey, exact: true })));
      const before = keys.map((k): [QueryKey, unknown] => [k, qc.getQueryData(k)]);
      // As the server switches them (Lights.setPower): one light, or every one it knows.
      const every = () => [...(qc.getQueryData<Overview>(OVERVIEW)?.devices.map((d) => d.id) ?? []), ...(qc.getQueryData<HaView>(HA)?.lights.map(haId) ?? [])];
      const ids = new Set(deviceId != null ? [deviceId] : on ? [] : every());
      qc.setQueryData<LightControls>(LIGHTS, (c) => c && { ...c, off: on ? (deviceId == null ? [] : c.off.filter((id) => !ids.has(id))) : [...new Set([...c.off, ...ids])] });
      // A WLED device says its own power: the one that answers shows it switched.
      qc.setQueryData<Overview>(OVERVIEW, (o) => {
        if (!o) return o;
        const devices = o.devices.map((d) => (d.power && (deviceId == null || d.id === deviceId) ? { ...d, power: { ...d.power, on } } : d));
        return { ...o, devices, state: deviceId == null ? { ...o.state, lightsOff: !on } : o.state };
      });
      // A Home Assistant light that was off comes on (off, the switches above say so).
      if (on) qc.setQueryData<HaView>(HA, (v) => v && { ...v, entities: v.entities.map((e) => (e.state === 'off' && (deviceId == null ? v.lights.includes(e.id) : haId(e.id) === deviceId) ? { ...e, state: 'on' } : e)) });
      if (deviceId == null) qc.setQueryData<PublicState>(PUBLIC, (s) => s && { ...s, lightsOff: !on });
      return { before };
    },
    onSuccess: done,
    onError: (e, _v, ctx) => {
      for (const [k, v] of ctx?.before ?? []) qc.setQueryData(k, v);
      toast.error(errorText(e));
    }
  });
  // Every switch on its way, from any part of the page, oldest first.
  const pending = useMutationState({ filters: { mutationKey: POWER, status: 'pending' }, select: (m) => m.state.variables as PowerVars });
  /** While a switch is on its way to a light (its own, or all lights'; null: all lights' own), the state asked for; else null. */
  const switchingTo = (deviceId: string | null = null): boolean | null =>
    (pending.findLast((v) => (v.deviceId ?? null) === deviceId) ?? (deviceId != null ? pending.findLast((v) => v.deviceId == null) : undefined))?.on ?? null;
  const brightness = useMutation({
    mutationFn: ({ level, deviceId = null }: { level: number | null; deviceId?: string | null }) => api.setBrightness(level, deviceId),
    onSuccess: done,
    onError: (e) => toast.error(errorText(e))
  });
  return { power, brightness, switchingTo };
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
