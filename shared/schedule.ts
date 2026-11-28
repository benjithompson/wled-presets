import { HA_KELVIN, HA_PREFIX, isSwitchable } from './homeAssistant.ts';
import { sunTimes } from './sun.ts';

/**
 * The lights' schedule: every light switches on and off each day, in one or more *periods* (an
 * evening, a morning before sunrise…): each with an on and an off, at sunrise or sunset (with an
 * offset) or at a time on the clock, on the days of the week it is set for. The lights are on
 * while any period is; periods that overlap or touch are one stretch, with no blink between.
 * It acts when a time comes and not between: an admin's switch in the meantime holds until the
 * schedule's next time.
 *
 * Between the periods (the night), visitors can still switch the lights on again, by picking a
 * scene, a color or a game (`wake`); after `idleMinutes` with nobody using them, they go off again.
 */
export interface LightSchedule {
  enabled: boolean;
  /** Where the yard is, for the sun's times. Degrees, north and east positive. */
  latitude: number | null;
  longitude: number | null;
  /** The yard's time zone (IANA, such as America/New_York): the clock times are in it. */
  timeZone: string;
  periods: SchedulePeriod[];
  /** In the night, a visitor's scene, color or game switches the lights on again. */
  wake: boolean;
  /** Woken in the night, the lights go off again after this many minutes with nobody using them. */
  idleMinutes: number;
}

/**
 * One stretch of the day with the lights on. It starts on the days it is set for; an off that
 * comes before the on that day is the next day's (on at 17:00, off at 01:00). One that would
 * last longer than MAX_PERIOD_HOURS is left out that day: its off came first (off at sunrise,
 * on at 06:00, in summer).
 */
export interface SchedulePeriod {
  id: string;
  /** What it is called: Evening, Morning. */
  name: string;
  enabled: boolean;
  /** The days of the week it starts on: 0 Sunday to 6 Saturday. */
  days: number[];
  on: ScheduleTime;
  off: ScheduleTime;
  /** At its off: lights set to something else than off (see ScheduleAction). */
  atOff: ScheduleAction[];
}

/**
 * At a period's off, what one light does instead of going off with the rest: any WLED device,
 * and any Home Assistant light or switch (the site's own, or any other, so the night needs no
 * automation in Home Assistant). One the site switches is held in it until the lights come on
 * again (see Lights.scheduleOff): the site counts it as off, and plays nothing on it.
 */
export interface ScheduleAction {
  /** A WLED device's id, or "ha:" and a Home Assistant light's or switch's entity id. */
  target: string;
  /**
   * off: off (a Home Assistant light the site gave colors back in its own white first, see
   * HaWhite); on: on, at the brightness (a switch, or a light that takes no color); white: a
   * white of `kelvin`; color: `color`.
   */
  mode: ActionMode;
  /** For color: #rrggbb. */
  color: string;
  /** For white: the color temperature, kelvin. */
  kelvin: number;
  /** On, white and color: 1 to 100 %. */
  brightness: number;
}

export type ActionMode = 'off' | 'on' | 'white' | 'color';
export const ACTION_MODES: readonly ActionMode[] = ['off', 'on', 'white', 'color'];
export const KELVIN = HA_KELVIN;
/** What a light added to the list starts as. */
export const NEW_ACTION: Omit<ScheduleAction, 'target'> = { mode: 'off', color: '#ffb46b', kelvin: 2700, brightness: 100 };

/** At most this many lights at one period's off. */
export const MAX_ACTIONS = 32;

/** True when an action's target is one the schedule can set: a device id, or "ha:" and a light or switch. */
export const isActionTarget = (t: string) => (t.startsWith(HA_PREFIX) ? isSwitchable(t.slice(HA_PREFIX.length)) : /^[\w-]{1,64}$/.test(t));

export interface ScheduleTime {
  at: 'sunrise' | 'sunset' | 'time';
  /** For sunrise and sunset: minutes after it (negative: before). */
  offset: number;
  /** For a time on the clock: HH:MM, 24-hour. */
  time: string;
}

export type ScheduleKind = 'on' | 'off';
export interface ScheduleEvent {
  kind: ScheduleKind;
  at: number;
  /** The period and time it comes from, in words: "Evening, at sunset". */
  label: string;
  /** The id of the period it comes from (of a stretch made of several, the one whose time it is). */
  period: string;
}

/** A stretch of time with the lights on, from the periods that make it (ms). */
export interface ScheduleSpan {
  start: number;
  end: number;
  /** The periods' labels for its on and its off (see ScheduleEvent.label), and their ids. */
  onLabel: string;
  offLabel: string;
  onPeriod: string;
  offPeriod: string;
}

/** Offsets go this far either side of sunrise or sunset. */
export const OFFSET_MINUTES = 240;
/** How long the lights, woken in the night, stay on with nobody using them: minutes. */
export const IDLE_MINUTES = { min: 1, max: 240 };
/** At most this many periods. */
export const MAX_PERIODS = 12;
/** A period longer than this on a day is left out that day (see SchedulePeriod). */
export const MAX_PERIOD_HOURS = 20;
export const PERIOD_NAME_MAX = 40;
export const ALL_DAYS = [0, 1, 2, 3, 4, 5, 6];

export const DEFAULT_PERIOD: SchedulePeriod = {
  id: 'evening',
  name: 'Evening',
  enabled: true,
  days: ALL_DAYS,
  on: { at: 'sunset', offset: 0, time: '17:00' },
  off: { at: 'time', offset: 0, time: '23:00' },
  atOff: []
};

export const DEFAULT_SCHEDULE: LightSchedule = {
  enabled: false,
  latitude: null,
  longitude: null,
  timeZone: 'UTC',
  periods: [DEFAULT_PERIOD],
  wake: true,
  idleMinutes: 15
};

const DAY_MS = 86_400_000;
const TIME = /^([01]\d|2[0-3]):([0-5]\d)$/;

export const isClockTime = (v: string) => TIME.test(v);

export function isTimeZone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** The periods that count: switched on, on at least one day. */
export const activePeriods = (s: Pick<LightSchedule, 'periods'>) => s.periods.filter((p) => p.enabled && p.days.length > 0);

/** True when a period that counts switches at sunrise or sunset: the schedule needs a place. */
export const usesSun = (s: Pick<LightSchedule, 'periods'>) => activePeriods(s).some((p) => p.on.at !== 'time' || p.off.at !== 'time');

/** True when the schedule has what it needs to run: switched on, a period, and a place for the sun. */
export function scheduleRuns(s: Omit<LightSchedule, 'wake' | 'idleMinutes'>): boolean {
  return s.enabled && isTimeZone(s.timeZone) && activePeriods(s).length > 0 && (!usesSun(s) || (s.latitude != null && s.longitude != null));
}

/** True when a period's on and off are the same time: it would never be on. */
export function sameTime(a: ScheduleTime, b: ScheduleTime): boolean {
  return a.at === b.at && (a.at === 'time' ? a.time === b.time : a.offset === b.offset);
}

const formats = new Map<string, Intl.DateTimeFormat>();
function partsIn(tz: string, ms: number) {
  let f = formats.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' });
    formats.set(tz, f);
  }
  const p = Object.fromEntries(f.formatToParts(ms).map((x) => [x.type, Number(x.value)]));
  return { y: p.year, m: p.month, d: p.day, h: p.hour % 24, mi: p.minute, s: p.second };
}

/** How far the time zone's clock is ahead of UTC at an instant, in ms. */
function zoneOffset(tz: string, ms: number) {
  const p = partsIn(tz, ms);
  return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - Math.floor(ms / 1000) * 1000;
}

/**
 * The instant a clock in the time zone shows this date and time. In the hour a clock skips in
 * spring, an hour later; in the hour it repeats in autumn, the first time.
 */
export function wallTime(tz: string, y: number, m: number, d: number, h: number, mi: number): number {
  const guess = Date.UTC(y, m - 1, d, h, mi);
  // The zone's offsets around then: at most two, either side of a change of the clocks.
  const tries = [-12, 0, 12].map((hours) => guess - zoneOffset(tz, guess + hours * 3_600_000));
  const shows = (ms: number) => {
    const p = partsIn(tz, ms);
    return p.d === d && p.h === h && p.mi === mi;
  };
  const real = tries.filter(shows);
  return real.length ? Math.min(...real) : Math.max(...tries);
}

type Place = Pick<LightSchedule, 'latitude' | 'longitude' | 'timeZone'>;

/** When a schedule time falls on a local date (y, m, d), or null (no sunrise there that day). */
function timeOn(t: ScheduleTime, s: Place, y: number, m: number, d: number): number | null {
  if (t.at === 'time') {
    const [, h, mi] = TIME.exec(t.time) ?? [];
    return h == null ? null : wallTime(s.timeZone, y, m, d, Number(h), Number(mi));
  }
  if (s.latitude == null || s.longitude == null) return null;
  const sun = sunTimes(wallTime(s.timeZone, y, m, d, 12, 0), s.latitude, s.longitude)[t.at];
  return sun == null ? null : sun + t.offset * 60_000;
}

const label = (p: SchedulePeriod, t: ScheduleTime) => `${p.name || 'Schedule'}, ${t.at === 'time' ? `at ${t.time}` : describeTime(t)}`;

/**
 * The stretches with the lights on that reach past `from` and start by `to` (ms), in order:
 * the periods of every day around them, overlapping or touching ones made one. None when the
 * schedule does not run.
 */
export function scheduleSpans(s: LightSchedule, from: number, to: number): ScheduleSpan[] {
  if (!scheduleRuns(s) || !(to > from)) return [];
  const periods = activePeriods(s);
  const raw: ScheduleSpan[] = [];
  const start = partsIn(s.timeZone, from);
  // Two days before: a period can run past midnight, and merged ones further. One after: an offset can move a time onto the next date.
  const days = Math.ceil((to - from) / DAY_MS) + 2;
  for (let i = -2; i < days; i++) {
    const day = new Date(Date.UTC(start.y, start.m - 1, start.d + i));
    const [y, m, d] = [day.getUTCFullYear(), day.getUTCMonth() + 1, day.getUTCDate()];
    const next = new Date(Date.UTC(y, m - 1, d + 1));
    for (const p of periods) {
      if (!p.days.includes(day.getUTCDay())) continue;
      const on = timeOn(p.on, s, y, m, d);
      if (on == null) continue;
      let off = timeOn(p.off, s, y, m, d);
      if (off == null || off <= on) off = timeOn(p.off, s, next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate());
      if (off == null || off <= on || off - on > MAX_PERIOD_HOURS * 3_600_000) continue;
      raw.push({ start: on, end: off, onLabel: label(p, p.on), offLabel: label(p, p.off), onPeriod: p.id, offPeriod: p.id });
    }
  }
  raw.sort((a, b) => a.start - b.start);
  const out: ScheduleSpan[] = [];
  for (const r of raw) {
    const last = out.at(-1);
    if (last && r.start <= last.end) {
      if (r.end > last.end) Object.assign(last, { end: r.end, offLabel: r.offLabel, offPeriod: r.offPeriod });
    } else out.push({ ...r });
  }
  return out.filter((x) => x.end > from && x.start <= to);
}

/** The schedule's times after `from` and up to `to` (ms), in order. None when it does not run. */
export function scheduleEvents(s: LightSchedule, from: number, to: number): ScheduleEvent[] {
  const out: ScheduleEvent[] = [];
  for (const x of scheduleSpans(s, from - 2 * DAY_MS, to)) {
    if (x.start > from && x.start <= to) out.push({ kind: 'on', at: x.start, label: x.onLabel, period: x.onPeriod });
    if (x.end > from && x.end <= to) out.push({ kind: 'off', at: x.end, label: x.offLabel, period: x.offPeriod });
  }
  return out;
}

/** The schedule's next time after `now` (of one kind, or either), within a week; or null. */
export function nextEvent(s: LightSchedule, now: number, kind?: ScheduleKind): ScheduleEvent | null {
  return scheduleEvents(s, now, now + 8 * DAY_MS).find((e) => !kind || e.kind === kind) ?? null;
}

/** True when the schedule has the lights on at `now`. */
export function scheduledOn(s: LightSchedule, now: number): boolean {
  return scheduleSpans(s, now - DAY_MS, now).some((x) => x.start <= now && now < x.end);
}

/** Where the date it is at `ms` in the time zone starts and ends (ms): its midnights. */
export function dayBounds(tz: string, ms: number): { start: number; end: number } {
  const p = partsIn(tz, ms);
  const next = new Date(Date.UTC(p.y, p.m - 1, p.d + 1));
  return { start: wallTime(tz, p.y, p.m, p.d, 0, 0), end: wallTime(tz, next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate(), 0, 0) };
}

/** Sunrise and sunset on the date it is now in the schedule's time zone, or null (no place). */
export function sunToday(s: LightSchedule, now: number): { sunrise: number | null; sunset: number | null } | null {
  if (s.latitude == null || s.longitude == null || !isTimeZone(s.timeZone)) return null;
  const p = partsIn(s.timeZone, now);
  return sunTimes(wallTime(s.timeZone, p.y, p.m, p.d, 12, 0), s.latitude, s.longitude);
}

/** A schedule as it is kept: anything missing or out of range back to the default. */
export function cleanSchedule(v: unknown): LightSchedule {
  const o = v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
  const num = (x: unknown, max: number) => (typeof x === 'number' && Number.isFinite(x) && Math.abs(x) <= max ? x : null);
  const time = (x: unknown, fallback: ScheduleTime): ScheduleTime => {
    const t = x && typeof x === 'object' ? (x as Record<string, unknown>) : {};
    const at = t.at === 'sunrise' || t.at === 'sunset' || t.at === 'time' ? t.at : fallback.at;
    const offset = Math.round(num(t.offset, OFFSET_MINUTES) ?? 0);
    return { at, offset, time: typeof t.time === 'string' && isClockTime(t.time) ? t.time : fallback.time };
  };
  // Kept before there were periods: one on and one off, the evening.
  const list = Array.isArray(o.periods) ? o.periods : o.on || o.off ? [{ ...DEFAULT_PERIOD, on: o.on, off: o.off }] : DEFAULT_SCHEDULE.periods;
  const ids = new Set<string>();
  const periods = list.slice(0, MAX_PERIODS).map((x, i): SchedulePeriod => {
    const p = x && typeof x === 'object' ? (x as Record<string, unknown>) : {};
    let id = typeof p.id === 'string' && /^[\w-]{1,40}$/.test(p.id) ? p.id : `p${i + 1}`;
    while (ids.has(id)) id = `${id}-${i + 1}`;
    ids.add(id);
    const days = Array.isArray(p.days) ? ALL_DAYS.filter((d) => (p.days as unknown[]).includes(d)) : ALL_DAYS;
    return {
      id,
      name: typeof p.name === 'string' ? p.name.trim().slice(0, PERIOD_NAME_MAX) : '',
      enabled: p.enabled !== false,
      days,
      on: time(p.on, DEFAULT_PERIOD.on),
      off: time(p.off, DEFAULT_PERIOD.off),
      atOff: cleanActions(p.atOff)
    };
  });
  return {
    enabled: o.enabled === true,
    latitude: num(o.latitude, 90),
    longitude: num(o.longitude, 180),
    timeZone: typeof o.timeZone === 'string' && isTimeZone(o.timeZone) ? o.timeZone : DEFAULT_SCHEDULE.timeZone,
    periods,
    wake: typeof o.wake === 'boolean' ? o.wake : DEFAULT_SCHEDULE.wake,
    idleMinutes: typeof o.idleMinutes === 'number' && Number.isInteger(o.idleMinutes) && o.idleMinutes >= IDLE_MINUTES.min && o.idleMinutes <= IDLE_MINUTES.max ? o.idleMinutes : DEFAULT_SCHEDULE.idleMinutes
  };
}

/** A period's lights at its off, as kept: each one once, in range. */
function cleanActions(v: unknown): ScheduleAction[] {
  if (!Array.isArray(v)) return [];
  const seen = new Set<string>();
  const out: ScheduleAction[] = [];
  const int = (x: unknown, min: number, max: number, fallback: number) => (typeof x === 'number' && Number.isFinite(x) ? Math.min(max, Math.max(min, Math.round(x))) : fallback);
  for (const x of v) {
    const a = x && typeof x === 'object' ? (x as Record<string, unknown>) : {};
    if (typeof a.target !== 'string' || !isActionTarget(a.target) || seen.has(a.target)) continue;
    seen.add(a.target);
    out.push({
      target: a.target,
      mode: ACTION_MODES.includes(a.mode as ActionMode) ? (a.mode as ActionMode) : 'off',
      color: typeof a.color === 'string' && /^#[0-9a-f]{6}$/i.test(a.color) ? a.color.toLowerCase() : NEW_ACTION.color,
      kelvin: int(a.kelvin, KELVIN.min, KELVIN.max, NEW_ACTION.kelvin),
      brightness: int(a.brightness, 1, 100, NEW_ACTION.brightness)
    });
    if (out.length >= MAX_ACTIONS) break;
  }
  return out;
}

/** An action in words: "off", "on" (a switch), "on at 40 %", "white 2700 K at 40 %", "#ff8800 at 40 %". */
export function describeAction(a: ScheduleAction): string {
  if (a.mode === 'off') return 'off';
  const at = `at ${a.brightness} %`;
  if (a.mode === 'on') return a.target.startsWith(`${HA_PREFIX}switch.`) ? 'on' : `on ${at}`;
  return a.mode === 'white' ? `white ${a.kelvin} K ${at}` : `${a.color} ${at}`;
}

/** A schedule time in words: "sunset", "30 minutes before sunrise", "23:00". */
export function describeTime(t: ScheduleTime): string {
  if (t.at === 'time') return t.time;
  if (!t.offset) return t.at;
  const n = Math.abs(t.offset);
  const span = n % 60 === 0 ? `${n / 60} hour${n === 60 ? '' : 's'}` : `${n} minute${n === 1 ? '' : 's'}`;
  return `${span} ${t.offset < 0 ? 'before' : 'after'} ${t.at}`;
}

/** The days a period starts on, in words: "every day", "weekdays", "Fri, Sat". */
export function describeDays(days: number[]): string {
  const set = new Set(days);
  if (set.size === 7) return 'every day';
  if (set.size === 0) return 'no days';
  if (set.size === 5 && [1, 2, 3, 4, 5].every((d) => set.has(d))) return 'weekdays';
  if (set.size === 2 && set.has(0) && set.has(6)) return 'weekends';
  return ALL_DAYS.filter((d) => set.has(d))
    .map((d) => DAY_NAMES[d].slice(0, 3))
    .join(', ');
}

export const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/** A period in words: "Evening: sunset to 23:00", with its days unless every day. */
export function describePeriod(p: SchedulePeriod): string {
  const days = describeDays(p.days);
  return `${p.name || 'Schedule'}: ${describeTime(p.on)} to ${describeTime(p.off)}${days === 'every day' ? '' : ` (${days})`}`;
}
