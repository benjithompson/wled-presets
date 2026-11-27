import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { LocateFixed, Moon, Sunrise, Sunset } from 'lucide-react';
import { toast } from 'sonner';
import { IDLE_MINUTES, nextEvent, OFFSET_MINUTES, scheduleRuns, sunToday, type LightSchedule, type ScheduleTime } from '../../../../shared/schedule.ts';
import { Button, Card, CardHeader, Field, Input, Select, Spinner, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { errorText, soonTime } from '../../lib/utils.ts';

const SCHEDULE = ['admin', 'lights', 'schedule'];
const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const zones = (() => {
  try {
    return Intl.supportedValuesOf('timeZone');
  } catch {
    return [browserZone];
  }
})();

/**
 * The schedule that switches every light on and off each day: at sunrise or sunset (moved by
 * minutes either way) or at a time on the clock. While the lights are off, visitors see when
 * they come back on, and can wake them with a scene, a color or a game: they go off again
 * after some minutes with nobody using them.
 */
export function ScheduleCard() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: SCHEDULE, queryFn: api.lightSchedule });
  const [form, setForm] = useState<LightSchedule | null>(null);
  const [locating, setLocating] = useState(false);
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    // A schedule never set up starts in this browser's time zone.
    if (data && !form) setForm(data.latitude == null && !data.enabled ? { ...data, timeZone: browserZone } : data);
  }, [data, form]);

  const save = useMutation({
    mutationFn: api.saveLightSchedule,
    onSuccess: (s) => {
      setForm(s);
      qc.setQueryData(SCHEDULE, s);
      void qc.invalidateQueries({ queryKey: ['public-state'] });
      toast.success(s.enabled ? 'Schedule saved' : 'Schedule off');
    },
    onError: (e) => toast.error(errorText(e))
  });

  const preview = useMemo(() => {
    if (!form) return null;
    const live = { ...form, enabled: true };
    return { sun: sunToday(live, now), on: scheduleRuns(live) ? nextEvent(live, now, 'on') : null, off: scheduleRuns(live) ? nextEvent(live, now, 'off') : null };
  }, [form, now]);

  if (!form || !data) {
    return (
      <Card className="mb-6 grid place-items-center py-10">
        <Spinner />
      </Card>
    );
  }

  const set = (patch: Partial<LightSchedule>) => setForm({ ...form, ...patch });
  const usesSun = form.on.at !== 'time' || form.off.at !== 'time';
  const changed = JSON.stringify(form) !== JSON.stringify(data);
  const missingPlace = usesSun && (form.latitude == null || form.longitude == null);
  const zone = form.timeZone !== browserZone ? form.timeZone : undefined;
  const when = (ms: number | null | undefined) => (ms == null ? 'never' : soonTime(ms, { timeZone: zone, now }));
  const canLocate = typeof navigator !== 'undefined' && 'geolocation' in navigator && window.isSecureContext;

  const locate = () => {
    setLocating(true);
    navigator.geolocation.getCurrentPosition(
      (p) => {
        setLocating(false);
        // Two decimals is about a kilometer: plenty for the sun, and no closer than that is kept.
        set({ latitude: Math.round(p.coords.latitude * 100) / 100, longitude: Math.round(p.coords.longitude * 100) / 100, timeZone: browserZone });
      },
      (e) => {
        setLocating(false);
        toast.error(`Could not find this device's location: ${e.message}`);
      },
      { timeout: 15_000 }
    );
  };

  return (
    <Card className="mb-6">
      <CardHeader
        title="Schedule"
        description="Switch every light on and off each day. Saving puts the lights as it says for now; switching all of them by hand in between holds until the next time. While they are off, visitors see when they come back on."
        actions={<Switch label="Schedule on" checked={form.enabled} onChange={(enabled) => set({ enabled })} />}
      />
      <form
        className="space-y-5 p-5"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(form);
        }}
      >
        <div className="grid gap-5 sm:grid-cols-2">
          <TimeField label="Switch on" value={form.on} onChange={(on) => set({ on })} />
          <TimeField label="Switch off" value={form.off} onChange={(off) => set({ off })} />
        </div>

        <div className="flex flex-wrap items-start gap-x-6 gap-y-3 rounded-xl border border-stone-200 px-4 py-3 dark:border-stone-800">
          <div className="flex min-w-0 flex-1 basis-64 items-start gap-3">
            <Switch label="Visitors can switch them on while they're off" checked={form.wake} onChange={(wake) => set({ wake })} />
            <div className="min-w-0 text-sm">
              <p className="font-medium text-stone-700 dark:text-stone-300">Visitors can switch them on while they're off</p>
              <p className="text-xs text-stone-500 dark:text-stone-400">Picking a scene, a color or a game switches the lights back on. They go off again once nobody has used them for a while.</p>
            </div>
          </div>
          {form.wake ? (
            <label className="flex items-center gap-2 text-sm text-stone-600 dark:text-stone-300">
              Off again after
              <Input
                type="number"
                className="!w-20"
                min={IDLE_MINUTES.min}
                max={IDLE_MINUTES.max}
                value={form.idleMinutes}
                onChange={(e) => set({ idleMinutes: Math.min(IDLE_MINUTES.max, Math.max(IDLE_MINUTES.min, Math.round(Number(e.target.value) || IDLE_MINUTES.min))) })}
              />
              min unused
            </label>
          ) : null}
        </div>

        <div className="grid gap-5 sm:grid-cols-[1fr_1fr_1.4fr]">
          <Field label="Latitude" hint={usesSun ? 'North is positive.' : 'Only sunrise and sunset need it.'}>
            {(id) => <CoordInput id={id} value={form.latitude} limit={90} placeholder="40.71" onChange={(latitude) => set({ latitude })} />}
          </Field>
          <Field label="Longitude" hint="East is positive, west negative.">
            {(id) => <CoordInput id={id} value={form.longitude} limit={180} placeholder="-74.01" onChange={(longitude) => set({ longitude })} />}
          </Field>
          <Field label="Time zone" hint="The clock times are in it.">
            {(id) => (
              <Select id={id} value={form.timeZone} onChange={(e) => set({ timeZone: e.target.value })}>
                {(zones.includes(form.timeZone) ? zones : [form.timeZone, ...zones]).map((z) => (
                  <option key={z} value={z}>
                    {z.replaceAll('_', ' ')}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {canLocate ? (
            <Button size="sm" onClick={locate} loading={locating}>
              <LocateFixed /> Use this device's location
            </Button>
          ) : (
            <span className="text-xs text-stone-500 dark:text-stone-400">Finding the location needs the site's HTTPS address; type it in here instead.</span>
          )}
        </div>

        <div className="rounded-xl bg-stone-50 px-4 py-3 text-sm text-stone-600 dark:bg-stone-800/50 dark:text-stone-300">
          {missingPlace ? (
            <p>Set where the lights are to work out sunrise and sunset.</p>
          ) : (
            <div className="flex flex-wrap gap-x-6 gap-y-1.5">
              {preview?.sun ? (
                <>
                  <span className="inline-flex items-center gap-1.5">
                    <Sunrise className="size-4 text-amber-500" /> Sunrise {preview.sun.sunrise == null ? 'none today' : soonTime(preview.sun.sunrise, { timeZone: zone, now: preview.sun.sunrise })}
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <Sunset className="size-4 text-orange-500" /> Sunset {preview.sun.sunset == null ? 'none today' : soonTime(preview.sun.sunset, { timeZone: zone, now: preview.sun.sunset })}
                  </span>
                </>
              ) : null}
              <span className="inline-flex items-center gap-1.5">
                <Moon className="size-4 text-stone-400" />
                {form.enabled ? 'Next' : 'Would be'}: on {when(preview?.on?.at)}, off {when(preview?.off?.at)}
              </span>
              {zone ? <span className="text-stone-500">Times in {zone.replaceAll('_', ' ')}</span> : null}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2">
          {changed ? (
            <Button variant="ghost" onClick={() => setForm(data)}>
              Undo changes
            </Button>
          ) : null}
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!changed || (form.enabled && missingPlace)}>
            Save schedule
          </Button>
        </div>
      </form>
    </Card>
  );
}

/** When one switch happens: at sunrise or sunset, minutes before or after, or at a clock time. */
function TimeField({ label, value, onChange }: { label: string; value: ScheduleTime; onChange: (t: ScheduleTime) => void }) {
  const minutes = Math.abs(value.offset);
  const sign = value.offset < 0 ? -1 : 1;
  return (
    <Field label={label}>
      {(id) => (
        <div className="flex flex-wrap gap-2">
          <Select id={id} className="!w-36" value={value.at} onChange={(e) => onChange({ ...value, at: e.target.value as ScheduleTime['at'] })}>
            <option value="sunset">At sunset</option>
            <option value="sunrise">At sunrise</option>
            <option value="time">At a time</option>
          </Select>
          {value.at === 'time' ? (
            <Input type="time" className="!w-36" aria-label={`${label}: time`} required value={value.time} onChange={(e) => e.target.value && onChange({ ...value, time: e.target.value })} />
          ) : (
            <>
              <Input
                type="number"
                className="!w-20"
                aria-label={`${label}: minutes`}
                min={0}
                max={OFFSET_MINUTES}
                step={5}
                value={minutes}
                onChange={(e) => onChange({ ...value, offset: sign * Math.min(OFFSET_MINUTES, Math.max(0, Math.round(Number(e.target.value) || 0))) })}
              />
              <Select className="!w-32" aria-label={`${label}: before or after`} value={sign} onChange={(e) => onChange({ ...value, offset: Number(e.target.value) * minutes })}>
                <option value={1}>min after</option>
                <option value={-1}>min before</option>
              </Select>
            </>
          )}
        </div>
      )}
    </Field>
  );
}

/** A latitude or longitude: degrees, or empty. It keeps what is typed until it is a number. */
function CoordInput({ id, value, limit, placeholder, onChange }: { id: string; value: number | null; limit: number; placeholder: string; onChange: (v: number | null) => void }) {
  const [text, setText] = useState(value == null ? '' : String(value));
  useEffect(() => {
    if (value !== (text.trim() === '' ? null : Number(text))) setText(value == null ? '' : String(value));
    // Only a change from outside (the location button, undo) resets the text.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return (
    <Input
      id={id}
      inputMode="decimal"
      placeholder={placeholder}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        const n = Number(e.target.value);
        if (e.target.value.trim() === '') onChange(null);
        else if (Number.isFinite(n) && Math.abs(n) <= limit) onChange(n);
      }}
    />
  );
}
