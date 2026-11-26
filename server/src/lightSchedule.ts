import { describeTime, nextEvent, scheduleEvents, scheduleRuns, type LightSchedule, type ScheduleEvent } from '../../shared/schedule.ts';
import type { Bus } from './events.ts';
import type { Db } from './db.ts';
import type { Actor, Lights } from './lights.ts';
import { KEY, readSchedule, writeSchedule } from './settings.ts';

const HOUR_MS = 3_600_000;
/** After the server was down, the latest time it missed in this long still happens. */
const CATCH_UP_MS = 2 * 24 * HOUR_MS;

/**
 * Switches the lights on and off at the schedule's times (see LightSchedule). Each time acts
 * once, when it comes: an admin's switch in between holds until the next one. A time missed
 * while the server was down happens when it starts (only the latest one).
 *
 * Off switches every light off, and remembers the lights that were off already; on switches
 * the rest on again, so a light an admin switched off on its own stays off.
 */
export class LightScheduler {
  private timer: NodeJS.Timeout | null = null;
  private chain: Promise<void> = Promise.resolve();
  private stopped = false;

  private db: Db;
  private lights: Lights;
  private bus: Bus;
  private opts: { afterOff?: () => void; now?: () => number };

  /** `afterOff`: after the schedule switched every light off (games end, the line empties). */
  constructor(db: Db, lights: Lights, bus: Bus, opts: { afterOff?: () => void; now?: () => number } = {}) {
    this.db = db;
    this.lights = lights;
    this.bus = bus;
    this.opts = opts;
  }

  private now() {
    return this.opts.now?.() ?? Date.now();
  }

  get(): LightSchedule {
    return readSchedule(this.db);
  }

  /** Saves the schedule. Its times from now on count: one that just passed does not happen. */
  save(s: LightSchedule, actor?: Actor): Promise<void> {
    const before = this.get();
    writeSchedule(this.db, s);
    this.db.setSetting(KEY.scheduleRan, new Date(this.now()).toISOString());
    const after = this.get();
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      const what = after.enabled ? `on at ${describeTime(after.on)}, off at ${describeTime(after.off)}` : 'off';
      this.lights.log('info', 'schedule', `Schedule ${what}`, { before, after }, actor);
    }
    this.bus.emit('state');
    return this.check();
  }

  /** When the schedule switches the lights on next (ISO), or null. */
  nextOnAt(): string | null {
    const e = nextEvent(this.get(), this.now(), 'on');
    return e ? new Date(e.at).toISOString() : null;
  }

  start() {
    this.stopped = false;
    void this.check();
  }

  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  /** Does what is due (once), then waits for the next time. One check at a time. */
  check(): Promise<void> {
    this.chain = this.chain.then(() => this.run()).catch((e) => this.lights.log('error', 'schedule', `Schedule failed: ${(e as Error).message}`));
    return this.chain;
  }

  private async run() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const s = this.get();
    if (!scheduleRuns(s) || this.stopped) return;
    const now = this.now();
    const ran = Date.parse(this.db.getSetting(KEY.scheduleRan) ?? '');
    this.db.setSetting(KEY.scheduleRan, new Date(now).toISOString());
    const due = Number.isFinite(ran) ? scheduleEvents(s, Math.max(ran, now - CATCH_UP_MS), now).at(-1) : undefined;
    if (due) await this.apply(due, s);
    // A timer at most an hour long: the clock may change (summer time, the server's clock set).
    const next = nextEvent(s, now);
    const wait = next ? Math.min(Math.max(next.at - now, 1000), HOUR_MS) : HOUR_MS;
    if (!this.stopped) {
      this.timer = setTimeout(() => void this.check(), wait);
      this.timer.unref?.();
    }
  }

  private async apply(e: ScheduleEvent, s: LightSchedule) {
    const why = `by the schedule (${describeTime(s[e.kind])})`;
    const off = this.lights.controls().off;
    if (e.kind === 'off') {
      // Already off (an admin's switch): nothing to do, and on switches every light on.
      if (this.lights.allOff()) return void this.db.setSetting(KEY.scheduleHeld, '[]');
      this.db.setSetting(KEY.scheduleHeld, JSON.stringify(off));
      await this.lights.setPower(false, null, undefined, why);
      this.opts.afterOff?.();
      return;
    }
    const held = new Set(this.held());
    this.db.setSetting(KEY.scheduleHeld, '[]');
    const ids = off.filter((id) => !held.has(id));
    if (ids.length) await this.lights.setPower(true, ids, undefined, why);
  }

  private held(): string[] {
    try {
      const v = JSON.parse(this.db.getSetting(KEY.scheduleHeld) || '[]');
      return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
    } catch {
      return [];
    }
  }
}
