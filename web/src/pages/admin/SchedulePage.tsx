import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CalendarClock, LocateFixed, MapPin, Moon, Plus, Router as RouterIcon, Sunrise, Sunset, Trash2, X } from 'lucide-react';
import { Link } from 'react-router';
import { toast } from 'sonner';
import {
  activePeriods,
  ALL_DAYS,
  DAY_NAMES,
  dayBounds,
  IDLE_MINUTES,
  ACTION_MODES,
  KELVIN,
  MAX_ACTIONS,
  NEW_ACTION,
  MAX_PERIODS,
  nextEvent,
  OFFSET_MINUTES,
  PERIOD_NAME_MAX,
  sameTime,
  scheduleRuns,
  scheduleSpans,
  sunToday,
  usesSun,
  type LightSchedule,
  type ActionMode,
  type ScheduleAction,
  type SchedulePeriod,
  type ScheduleTime
} from '../../../../shared/schedule.ts';
import { Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Switch } from '../../components/ui.tsx';
import { Tabs, TabPanel, tabLink, useTab } from '../../components/tabs.tsx';
import { api } from '../../lib/api.ts';
import { haId, type HaEntity, type HaView } from '../../../../shared/homeAssistant.ts';
import { kelvinRgb } from '../../../../shared/color.ts';
import type { DeviceWithStatus } from '../../../../shared/types.ts';
import { useOverview } from './AdminLayout.tsx';
import { EntityIcon } from './EntityTable.tsx';
import { useHomeAssistant } from './HomeAssistantCard.tsx';
import { cn, errorText, soonTime } from '../../lib/utils.ts';

const SCHEDULE = ['admin', 'lights', 'schedule'];
const TABS = [
  { id: 'times', label: 'On times', icon: CalendarClock },
  { id: 'off', label: 'While off', icon: Moon },
  { id: 'place', label: 'Location', icon: MapPin }
] as const;
const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const zones = (() => {
  try {
    return Intl.supportedValuesOf('timeZone');
  } catch {
    return [browserZone];
  }
})();

/** An id for a new period (crypto.randomUUID needs HTTPS, and the LAN address is plain HTTP). */
const newId = () => Math.random().toString(36).slice(2, 10);

/** What "Add a schedule" adds: a morning first (06:00 to sunrise), then an evening's hours. */
function newPeriod(periods: SchedulePeriod[]): SchedulePeriod {
  const clock = (time: string): ScheduleTime => ({ at: 'time', offset: 0, time });
  if (!periods.some((p) => p.name.toLowerCase() === 'morning')) return { id: newId(), name: 'Morning', enabled: true, days: ALL_DAYS, on: clock('06:00'), off: { at: 'sunrise', offset: 0, time: '07:00' }, atOff: [] };
  return { id: newId(), name: `Schedule ${periods.length + 1}`, enabled: true, days: ALL_DAYS, on: clock('18:00'), off: clock('22:00'), atOff: [] };
}

/**
 * Admin → Schedule: switches every light on and off each day, in one or more periods (an
 * evening, a morning…), each at sunrise or sunset (moved by minutes either way) or at a time on
 * the clock, on the days it is set for. While the lights are off, visitors see when they come
 * back on, and can wake them with a scene, a color or a game: they go off again after some
 * minutes with nobody using them.
 */
export function SchedulePage() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: SCHEDULE, queryFn: api.lightSchedule });
  // Connected to Home Assistant: an on time's off can set its lights and switches too.
  // The lights an on time's off can set (see ScheduleAction): the devices, and Home Assistant's when connected.
  const { data: haView } = useHomeAssistant();
  const { data: overview } = useOverview();
  const targets = useMemo(() => actionTargets(overview?.devices ?? [], haView?.url && haView.hasToken ? haView : undefined), [overview?.devices, haView]);
  const [form, setForm] = useState<LightSchedule | null>(null);
  const [locating, setLocating] = useState(false);
  const [tab, setTab] = useTab(TABS);
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

  // As it would run if it were on: the preview shows a schedule before it is switched on.
  const live = useMemo(() => (form ? { ...form, enabled: true } : null), [form]);

  if (!form || !data || !live) {
    return (
      <div className="grid place-items-center py-24">
        <Spinner />
      </div>
    );
  }

  const set = (patch: Partial<LightSchedule>) => setForm({ ...form, ...patch });
  const setPeriod = (id: string, patch: Partial<SchedulePeriod>) => set({ periods: form.periods.map((p) => (p.id === id ? { ...p, ...patch } : p)) });
  const sun = usesSun(form);
  const changed = JSON.stringify(form) !== JSON.stringify(data);
  const missingPlace = sun && (form.latitude == null || form.longitude == null);
  const noPeriods = activePeriods(form).length === 0;
  const clash = form.periods.find((p) => p.enabled && sameTime(p.on, p.off));
  const blocked = form.enabled && (missingPlace || noPeriods || !!clash);
  const zone = form.timeZone !== browserZone ? form.timeZone : undefined;
  const when = (ms: number | null | undefined) => (ms == null ? 'not this week' : soonTime(ms, { timeZone: zone, now }));
  const canLocate = typeof navigator !== 'undefined' && 'geolocation' in navigator && window.isSecureContext;
  const runs = scheduleRuns(live);
  // The number of on times, and a mark on the place while sunrise and sunset need it.
  const tabs = TABS.map((t) => ({ ...t, badge: t.id === 'times' ? form.periods.length || undefined : t.id === 'place' && missingPlace ? '!' : undefined }));
  const nextOn = runs ? nextEvent(live, now, 'on') : null;
  const nextOff = runs ? nextEvent(live, now, 'off') : null;

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
    <>
      <PageHeader
        title="Schedule"
        description="Switch every light on and off by itself each day: an evening, a morning, as many as you like. Saving puts the lights as it says for now; switching them by hand holds until the next time."
        actions={
          <label className="flex items-center gap-2 text-sm font-medium">
            <span className="max-sm:sr-only">{form.enabled ? 'On' : 'Off'}</span>
            <Switch label="Schedule on" checked={form.enabled} onChange={(enabled) => set({ enabled })} />
          </label>
        }
      />
      <form
        className="space-y-6"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(form);
        }}
      >
        <Card>
          <div className="space-y-3 p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 text-sm text-stone-600 dark:text-stone-300">
              {missingPlace ? (
                <span>
                  Set{' '}
                  <Link to="?tab=place" className={tabLink}>
                    where the lights are
                  </Link>{' '}
                  to work out sunrise and sunset.
                </span>
              ) : runs ? (
                <span className="inline-flex items-center gap-1.5">
                  <Moon className="size-4 text-stone-400" />
                  {`${form.enabled ? 'Next' : 'Off for now. It would be'}: on ${when(nextOn?.at)}${nextOn ? ` (${nextOn.label.split(',')[0]})` : ''}, off ${when(nextOff?.at)}`}
                </span>
              ) : (
                <span>Switch on one of the on times.</span>
              )}
              {zone ? <span className="text-stone-500">Times in {zone.replaceAll('_', ' ')}</span> : null}
            </div>
            {missingPlace ? null : <DayBar schedule={live} now={now} zone={zone} />}
          </div>
        </Card>

        <div>
          <Tabs tabs={tabs} value={tab} onChange={setTab} label="Schedule" />
          <TabPanel id={tab}>
            {tab === 'times' ? (
              <Card>
                <CardHeader
                  title="On times"
                  description="Each one switches the lights on, then off again, on the days you pick. Ones that overlap join up. An off before its on runs past midnight; one the sun gets ahead of (off at sunrise, after the sun is up) skips that day."
                  actions={
                    <Button size="sm" onClick={() => set({ periods: [...form.periods, newPeriod(form.periods)] })} disabled={form.periods.length >= MAX_PERIODS}>
                      <Plus /> Add
                    </Button>
                  }
                />
                {form.periods.length ? (
                  <ul className="divide-y divide-stone-100 dark:divide-stone-800">
                    {form.periods.map((p) => (
                      <PeriodRow
                        key={p.id}
                        period={p}
                        place={live}
                        now={now}
                        zone={zone}
                        targets={targets}
                        onChange={(patch) => setPeriod(p.id, patch)}
                        onRemove={() => set({ periods: form.periods.filter((x) => x.id !== p.id) })}
                      />
                    ))}
                  </ul>
                ) : (
                  <div className="flex flex-col items-center gap-3 px-5 py-10 text-center text-sm text-stone-500">
                    <CalendarClock className="size-6 text-stone-400" />
                    No on times yet: the lights stay as they are.
                    <Button size="sm" variant="primary" onClick={() => set({ periods: [{ ...newPeriod([]), name: 'Evening', on: { at: 'sunset', offset: 0, time: '17:00' }, off: { at: 'time', offset: 0, time: '23:00' } }] })}>
                      <Plus /> Add an evening
                    </Button>
                  </div>
                )}
              </Card>
            ) : tab === 'off' ? (
              <Card>
                <CardHeader title="While they're off" description="Between the on times, visitors see when the lights come back on." />
                <div className="flex flex-wrap items-start gap-x-6 gap-y-3 p-5">
                  <div className="flex min-w-0 flex-1 basis-64 items-start gap-3">
                    <Switch label="Visitors can switch them on while they're off" checked={form.wake} onChange={(wake) => set({ wake })} />
                    <div className="min-w-0 text-sm">
                      <p className="font-medium text-stone-700 dark:text-stone-300">Visitors can switch them on</p>
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
              </Card>
            ) : (
              <Card>
                <CardHeader title="Where the lights are" description="For sunrise and sunset, and the time zone the clock times are in." />
                <div className="space-y-4 p-5">
                  <div className="grid gap-5 sm:grid-cols-[1fr_1fr_1.4fr]">
                    <Field label="Latitude" hint={sun ? 'North is positive.' : 'Only sunrise and sunset need it.'}>
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
                  <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-stone-600 dark:text-stone-300">
                    {canLocate ? (
                      <Button size="sm" onClick={locate} loading={locating}>
                        <LocateFixed /> Use this device's location
                      </Button>
                    ) : (
                      <span className="text-xs text-stone-500 dark:text-stone-400">Finding the location needs the site's HTTPS address; type it in here instead.</span>
                    )}
                    <SunToday schedule={live} now={now} zone={zone} />
                  </div>
                </div>
              </Card>
            )}
          </TabPanel>
        </div>

        {/* On a phone the button stays at the bottom of the screen. */}
        <div className="flex flex-wrap items-center justify-end gap-2 max-md:sticky max-md:bottom-0 max-md:z-20 max-md:-mx-4 max-md:border-t max-md:border-stone-200 max-md:bg-stone-50/90 max-md:px-4 max-md:pt-3 max-md:pb-[calc(0.75rem+env(safe-area-inset-bottom,0px))] max-md:backdrop-blur-lg dark:max-md:border-stone-800 dark:max-md:bg-stone-950/90">
          {form.enabled && blocked ? (
            <span className="mr-auto text-sm text-amber-700 dark:text-amber-400">
              {missingPlace ? 'Set where the lights are first.' : noPeriods ? 'Switch on at least one on time, on at least one day.' : `${clash!.name || 'An on time'} switches on and off at the same time.`}
            </span>
          ) : null}
          {changed ? (
            <Button variant="ghost" onClick={() => setForm(data)}>
              Undo changes
            </Button>
          ) : null}
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!changed || blocked} className="max-md:h-11 max-md:flex-1 max-md:justify-center">
            Save schedule
          </Button>
        </div>
      </form>
    </>
  );
}

/** One on time: its name, its days, when it switches on and off, and when it does next. */
function PeriodRow({
  period: p,
  place,
  now,
  zone,
  targets,
  onChange,
  onRemove
}: {
  period: SchedulePeriod;
  place: LightSchedule;
  now: number;
  zone: string | undefined;
  /** The lights its off can set. */
  targets: Target[];
  onChange: (patch: Partial<SchedulePeriod>) => void;
  onRemove: () => void;
}) {
  const alone = { ...place, periods: [{ ...p, enabled: true }] };
  const span = p.enabled && scheduleRuns(alone) ? scheduleSpans(alone, now, now + 8 * 86_400_000)[0] : undefined;
  const when = (ms: number) => soonTime(ms, { timeZone: zone, now });
  const name = p.name || 'This on time';
  return (
    <li className={cn('space-y-4 px-5 py-4', !p.enabled && 'opacity-60')}>
      <div className="flex flex-wrap items-center gap-3">
        <Switch label={`${name}: on`} checked={p.enabled} onChange={(enabled) => onChange({ enabled })} />
        <Input aria-label="Name" className="!w-44 font-medium" value={p.name} maxLength={PERIOD_NAME_MAX} placeholder="Name" onChange={(e) => onChange({ name: e.target.value })} />
        <DayPicker days={p.days} name={name} onChange={(days) => onChange({ days })} />
        <Button size="sm" variant="ghost" onClick={onRemove} aria-label={`Remove ${name}`} title="Remove" className="ml-auto px-2 text-stone-500 hover:text-red-600">
          <Trash2 />
        </Button>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <TimeField label="Switch on" name={name} value={p.on} onChange={(on) => onChange({ on })} />
        <TimeField label="Switch off" name={name} value={p.off} onChange={(off) => onChange({ off })} />
      </div>
      {targets.length ? <OffActions targets={targets} name={name} actions={p.atOff} onChange={(atOff) => onChange({ atOff })} /> : null}
      {p.enabled ? (
        <p className="text-xs text-stone-500 dark:text-stone-400">
          {sameTime(p.on, p.off)
            ? 'It switches on and off at the same time: change one of them.'
            : !p.days.length
              ? 'Pick at least one day.'
              : span
                ? span.start <= now
                  ? `On now, until ${when(span.end)}.`
                  : `Next: on ${when(span.start)}, off ${when(span.end)}.`
                : scheduleRuns(alone)
                  ? 'Not this week: the sun gets there first.'
                  : 'Set where the lights are first.'}
        </p>
      ) : null}
    </li>
  );
}

/** A light an action can set (see ScheduleAction): its id, name and group, and what it can do. */
type Target = { id: string; name: string; group: string; modes: ActionMode[]; dimmable: boolean; entity?: HaEntity; wled?: boolean };

const MODE_NAMES: Record<ActionMode, string> = { off: 'Off', on: 'On', white: 'White', color: 'Color' };

/**
 * Every light an action can set: the WLED devices, and with Home Assistant connected its lights
 * the site switches, its other lights and its switches (not a controller's plug: it goes with
 * its device). What each can do follows what it takes: a WLED device or a color light a white
 * or a color; a white light a white; a dimmer or a switch on.
 */
function actionTargets(devices: DeviceWithStatus[], ha: HaView | undefined): Target[] {
  const out: Target[] = devices.filter((d) => d.enabled).map((d) => ({ id: d.id, name: d.name, group: 'WLED devices', modes: ['off', 'white', 'color'], dimmable: true, wled: true }));
  if (!ha) return out;
  const plugs = new Set(Object.values(ha.plugs));
  const site = new Set(ha.lights.filter((id) => !ha.disabled.includes(id)));
  for (const e of ha.entities) {
    if (plugs.has(e.id)) continue;
    const light = e.id.startsWith('light.');
    const modes: ActionMode[] = !light ? ['off', 'on'] : e.color ? ['off', 'white', 'color'] : e.temp ? ['off', 'white'] : ['off', 'on'];
    const group = site.has(e.id) ? 'Home Assistant lights the site switches' : light ? 'Other Home Assistant lights' : 'Home Assistant switches';
    out.push({ id: haId(e.id), name: e.name, group, modes, dimmable: light && e.dimmable, entity: e });
  }
  return out;
}

/**
 * At an on time's off, every light goes off with the rest; here, lights that do something else
 * instead (see ScheduleAction): a WLED device or a Home Assistant light in a color or a white
 * at a brightness, a switch on, or any other light or switch in Home Assistant set too, so the
 * night needs no automation of its own. The same choices for every kind of light.
 */
function OffActions({ targets, name, actions, onChange }: { targets: Target[]; name: string; actions: ScheduleAction[]; onChange: (a: ScheduleAction[]) => void }) {
  const byId = new Map(targets.map((t) => [t.id, t]));
  const free = targets.filter((t) => !actions.some((a) => a.target === t.id));
  const groups = [...new Set(free.map((t) => t.group))].map((g) => ({ label: g, list: free.filter((t) => t.group === g) }));
  const set = (i: number, patch: Partial<ScheduleAction>) => onChange(actions.map((a, j) => (j === i ? { ...a, ...patch } : a)));
  const add = (id: string) => {
    const t = byId.get(id);
    if (!t) return;
    // What it most likely should do instead of going off: a white, or on.
    const mode = t.modes.includes('white') ? 'white' : 'on';
    onChange([...actions, { ...NEW_ACTION, target: id, mode }]);
  };
  return (
    <div className="rounded-xl bg-stone-50 px-3 py-2.5 ring-1 ring-stone-200/70 dark:bg-stone-950/40 dark:ring-stone-800">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <p className="min-w-0 flex-1 basis-60 text-xs text-stone-500 dark:text-stone-400">
          <Moon className="mr-1 -mt-0.5 inline size-3.5" />
          At its off, every light goes off
          {targets.some((t) => t.entity) ? ' (Home Assistant lights back in their own white)' : ''}
          {actions.length ? '. Instead:' : '. Set a light to a color or a white instead, or a switch on.'}
        </p>
        {groups.length && actions.length < MAX_ACTIONS ? (
          <Select aria-label={`${name}: set a light at its off`} className="!h-8 !w-auto max-w-full text-xs" value="" onChange={(e) => add(e.target.value)}>
            <option value="">Set a light…</option>
            {groups.map((g) => (
              <optgroup key={g.label} label={g.label}>
                {g.list.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                    {t.entity?.area ? ` (${t.entity.area})` : ''}
                  </option>
                ))}
              </optgroup>
            ))}
          </Select>
        ) : null}
      </div>
      {actions.length ? (
        <ul className="mt-2 space-y-1.5">
          {actions.map((a, i) => {
            const t = byId.get(a.target);
            const label = t?.name ?? a.target;
            const modes = t?.modes ?? ACTION_MODES;
            return (
              <li key={a.target} className="flex flex-wrap items-center gap-2 text-sm">
                {t?.entity ? <EntityIcon e={t.entity} /> : <RouterIcon className="size-4 shrink-0 text-stone-400" />}
                <span className="min-w-0 flex-1 basis-32 truncate" title={t?.entity ? t.entity.id : undefined}>
                  {label}
                  {!t ? <span className="text-xs text-amber-700 dark:text-amber-300"> (gone)</span> : null}
                </span>
                <Select aria-label={`${label} at the off`} className="!h-8 !w-auto text-xs" value={a.mode} onChange={(ev) => set(i, { mode: ev.target.value as ActionMode })}>
                  {(modes.includes(a.mode) ? modes : [...modes, a.mode]).map((m) => (
                    <option key={m} value={m}>
                      {MODE_NAMES[m]}
                    </option>
                  ))}
                </Select>
                {a.mode === 'white' ? (
                  <label className="flex items-center gap-1 text-xs text-stone-500">
                    <span className="size-4 rounded-full ring-1 ring-stone-300 dark:ring-stone-700" style={{ background: `rgb(${kelvinRgb(a.kelvin).join(',')})` }} />
                    <Input
                      aria-label={`${label}: color temperature, kelvin`}
                      type="number"
                      min={KELVIN.min}
                      max={KELVIN.max}
                      step={100}
                      className="!h-8 !w-20 text-xs text-stone-900 dark:text-stone-100"
                      value={a.kelvin}
                      onChange={(ev) => set(i, { kelvin: Math.round(Number(ev.target.value)) || NEW_ACTION.kelvin })}
                      onBlur={() => set(i, { kelvin: Math.min(KELVIN.max, Math.max(KELVIN.min, a.kelvin)) })}
                    />
                    K
                  </label>
                ) : a.mode === 'color' ? (
                  <input
                    type="color"
                    aria-label={`${label}: color`}
                    className="h-8 w-10 cursor-pointer rounded-lg bg-transparent"
                    value={a.color}
                    onChange={(ev) => set(i, { color: ev.target.value.toLowerCase() })}
                  />
                ) : null}
                {a.mode !== 'off' && (t?.dimmable ?? true) ? (
                  <label className="flex items-center gap-1 text-xs text-stone-500">
                    <Input
                      aria-label={`${label}: brightness at the off`}
                      type="number"
                      min={1}
                      max={100}
                      className="!h-8 !w-16 text-xs text-stone-900 dark:text-stone-100"
                      value={a.brightness}
                      onChange={(ev) => set(i, { brightness: Math.min(100, Math.max(1, Math.round(Number(ev.target.value)) || 1)) })}
                    />
                    %
                  </label>
                ) : null}
                <Button size="sm" variant="ghost" aria-label={`Leave ${label} out`} title="Leave out: off with the rest" className="px-2 text-stone-500" onClick={() => onChange(actions.filter((_, j) => j !== i))}>
                  <X />
                </Button>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}

/** The days of the week an on time starts on: seven toggles, Sunday first. */
function DayPicker({ days, name, onChange }: { days: number[]; name: string; onChange: (days: number[]) => void }) {
  const on = new Set(days);
  return (
    <div role="group" aria-label={`${name}: days`} className="flex gap-1">
      {ALL_DAYS.map((d) => (
        <button
          key={d}
          type="button"
          aria-pressed={on.has(d)}
          aria-label={DAY_NAMES[d]}
          title={DAY_NAMES[d]}
          onClick={() => onChange(ALL_DAYS.filter((x) => (x === d ? !on.has(d) : on.has(x))))}
          className={cn(
            'grid size-8 place-items-center rounded-lg text-xs font-semibold transition',
            on.has(d) ? 'bg-stone-900 text-white dark:bg-accent-400 dark:text-stone-950' : 'bg-stone-100 text-stone-500 hover:bg-stone-200 dark:bg-stone-800 dark:text-stone-400 dark:hover:bg-stone-700'
          )}
        >
          {DAY_NAMES[d][0]}
        </button>
      ))}
    </div>
  );
}

/** Today, midnight to midnight in the yard's time zone: when the lights are on, sunrise and sunset, and now. */
function DayBar({ schedule, now, zone }: { schedule: LightSchedule; now: number; zone: string | undefined }) {
  const { start, end } = dayBounds(schedule.timeZone, now);
  const spans = scheduleSpans(schedule, start, end);
  const sun = sunToday(schedule, now);
  const pos = (ms: number) => `${(Math.min(Math.max((ms - start) / (end - start), 0), 1) * 100).toFixed(2)}%`;
  const time = (ms: number) => soonTime(ms, { timeZone: zone, now: ms });
  return (
    <div>
      <div className="relative h-7 overflow-hidden rounded-lg bg-stone-100 dark:bg-stone-800" role="img" aria-label={spans.length ? `Today the lights are on ${spans.map((s) => `${time(Math.max(s.start, start))} to ${time(Math.min(s.end, end))}`).join(', ')}` : 'Today the lights are not switched on'}>
        {sun?.sunrise != null && sun.sunset != null ? <div className="absolute inset-y-0 bg-sky-100 dark:bg-sky-950/60" style={{ left: pos(sun.sunrise), right: `calc(100% - ${pos(sun.sunset)})` }} /> : null}
        {spans.map((s) => (
          <div key={s.start} className="absolute inset-y-1 rounded bg-accent-400 shadow-sm" style={{ left: pos(s.start), right: `calc(100% - ${pos(s.end)})` }} title={`${s.onLabel} to ${s.offLabel}`} />
        ))}
        <div className="absolute inset-y-0 w-0.5 bg-red-500" style={{ left: pos(now) }} title="Now" />
      </div>
      <div className="mt-1 flex justify-between text-[11px] text-stone-400 tabular-nums">
        {['0:00', '6:00', '12:00', '18:00', '24:00'].map((h) => (
          <span key={h}>{h}</span>
        ))}
      </div>
      <p className="mt-1 flex flex-wrap gap-x-4 text-xs text-stone-500">
        <span className="inline-flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-accent-400" /> Lights on today
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-sky-100 ring-1 ring-sky-200 dark:bg-sky-950 dark:ring-sky-900" /> Daylight
        </span>
      </p>
    </div>
  );
}

function SunToday({ schedule, now, zone }: { schedule: LightSchedule; now: number; zone: string | undefined }) {
  const sun = sunToday(schedule, now);
  if (!sun) return null;
  const at = (ms: number | null) => (ms == null ? 'none today' : soonTime(ms, { timeZone: zone, now: ms }));
  return (
    <span className="inline-flex flex-wrap gap-x-4 gap-y-1">
      <span className="inline-flex items-center gap-1.5">
        <Sunrise className="size-4 text-amber-500" /> Sunrise {at(sun.sunrise)}
      </span>
      <span className="inline-flex items-center gap-1.5">
        <Sunset className="size-4 text-orange-500" /> Sunset {at(sun.sunset)}
      </span>
    </span>
  );
}

/** When one switch happens: at sunrise or sunset, minutes before or after, or at a clock time. */
function TimeField({ label, name, value, onChange }: { label: string; name: string; value: ScheduleTime; onChange: (t: ScheduleTime) => void }) {
  const minutes = Math.abs(value.offset);
  const sign = value.offset < 0 ? -1 : 1;
  const aria = `${name}, ${label.toLowerCase()}`;
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
            <Input type="time" className="!w-36" aria-label={`${aria}: time`} required value={value.time} onChange={(e) => e.target.value && onChange({ ...value, time: e.target.value })} />
          ) : (
            <>
              <Input
                type="number"
                className="!w-20"
                aria-label={`${aria}: minutes`}
                min={0}
                max={OFFSET_MINUTES}
                step={5}
                value={minutes}
                onChange={(e) => onChange({ ...value, offset: sign * Math.min(OFFSET_MINUTES, Math.max(0, Math.round(Number(e.target.value) || 0))) })}
              />
              <Select className="!w-32" aria-label={`${aria}: before or after`} value={sign} onChange={(e) => onChange({ ...value, offset: Number(e.target.value) * minutes })}>
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
