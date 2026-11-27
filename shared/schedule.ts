import { sunTimes } from './sun.ts';

/**
 * The lights' schedule: every light switches on at one time of day and off at another, each at
 * sunrise or sunset (with an offset), or at a time on the clock. It acts when the time comes and
 * not between: an admin's switch in the meantime holds until the schedule's next time.
 *
 * Between its off and its on (the night), visitors can still switch the lights on again, by
 * picking a scene, a color or a game (`wake`); after `idleMinutes` with nobody using them, they
 * go off again.
 */
export interface LightSchedule {
  enabled: boolean;
  /** Where the yard is, for the sun's times. Degrees, north and east positive. */
  latitude: number | null;
  longitude: number | null;
  /** The yard's time zone (IANA, such as America/New_York): the clock times are in it. */
  timeZone: string;
  on: ScheduleTime;
  off: ScheduleTime;
  /** In the night, a visitor's scene, color or game switches the lights on again. */
  wake: boolean;
  /** Woken in the night, the lights go off again after this many minutes with nobody using them. */
  idleMinutes: number;
}

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
}

/** Offsets go this far either side of sunrise or sunset. */
export const OFFSET_MINUTES = 240;
/** How long the lights, woken in the night, stay on with nobody using them: minutes. */
export const IDLE_MINUTES = { min: 1, max: 240 };

export const DEFAULT_SCHEDULE: LightSchedule = {
  enabled: false,
  latitude: null,
  longitude: null,
  timeZone: 'UTC',
  on: { at: 'sunset', offset: 0, time: '17:00' },
  off: { at: 'time', offset: 0, time: '23:00' },
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

/** True when the schedule has what it needs to run: switched on, and a place for the sun. */
export function scheduleRuns(s: Omit<LightSchedule, 'wake' | 'idleMinutes'>): boolean {
  const sun = s.on.at !== 'time' || s.off.at !== 'time';
  return s.enabled && isTimeZone(s.timeZone) && (!sun || (s.latitude != null && s.longitude != null));
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

/** When a schedule time falls on a local date (y, m, d), or null (no sunrise there that day). */
function timeOn(t: ScheduleTime, s: LightSchedule, y: number, m: number, d: number): number | null {
  if (t.at === 'time') {
    const [, h, mi] = TIME.exec(t.time) ?? [];
    return h == null ? null : wallTime(s.timeZone, y, m, d, Number(h), Number(mi));
  }
  if (s.latitude == null || s.longitude == null) return null;
  const sun = sunTimes(wallTime(s.timeZone, y, m, d, 12, 0), s.latitude, s.longitude)[t.at];
  return sun == null ? null : sun + t.offset * 60_000;
}

/** The schedule's times after `from` and up to `to` (ms), in order. None when it does not run. */
export function scheduleEvents(s: LightSchedule, from: number, to: number): ScheduleEvent[] {
  if (!scheduleRuns(s) || !(to > from)) return [];
  const out: ScheduleEvent[] = [];
  const start = partsIn(s.timeZone, from);
  // A day either side: an offset can move a time onto the next or the last date.
  const days = Math.ceil((to - from) / DAY_MS) + 3;
  for (let i = -1; i < days; i++) {
    const day = new Date(Date.UTC(start.y, start.m - 1, start.d + i));
    const [y, m, d] = [day.getUTCFullYear(), day.getUTCMonth() + 1, day.getUTCDate()];
    for (const kind of ['on', 'off'] as const) {
      const at = timeOn(s[kind], s, y, m, d);
      if (at != null && at > from && at <= to) out.push({ kind, at });
    }
  }
  return out.sort((a, b) => a.at - b.at);
}

/** The schedule's next time after `now` (of one kind, or either), within a week; or null. */
export function nextEvent(s: LightSchedule, now: number, kind?: ScheduleKind): ScheduleEvent | null {
  return scheduleEvents(s, now, now + 8 * DAY_MS).find((e) => !kind || e.kind === kind) ?? null;
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
  return {
    enabled: o.enabled === true,
    latitude: num(o.latitude, 90),
    longitude: num(o.longitude, 180),
    timeZone: typeof o.timeZone === 'string' && isTimeZone(o.timeZone) ? o.timeZone : DEFAULT_SCHEDULE.timeZone,
    on: time(o.on, DEFAULT_SCHEDULE.on),
    off: time(o.off, DEFAULT_SCHEDULE.off),
    wake: typeof o.wake === 'boolean' ? o.wake : DEFAULT_SCHEDULE.wake,
    idleMinutes: typeof o.idleMinutes === 'number' && Number.isInteger(o.idleMinutes) && o.idleMinutes >= IDLE_MINUTES.min && o.idleMinutes <= IDLE_MINUTES.max ? o.idleMinutes : DEFAULT_SCHEDULE.idleMinutes
  };
}

/** A schedule time in words: "sunset", "30 minutes before sunrise", "23:00". */
export function describeTime(t: ScheduleTime): string {
  if (t.at === 'time') return t.time;
  if (!t.offset) return t.at;
  const n = Math.abs(t.offset);
  const span = n % 60 === 0 ? `${n / 60} hour${n === 60 ? '' : 's'}` : `${n} minute${n === 1 ? '' : 's'}`;
  return `${span} ${t.offset < 0 ? 'before' : 'after'} ${t.at}`;
}
