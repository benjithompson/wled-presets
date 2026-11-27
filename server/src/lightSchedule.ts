import { describeTime, nextEvent, scheduleEvents, scheduleRuns, type LightSchedule, type ScheduleEvent } from '../../shared/schedule.ts';
import type { Bus } from './events.ts';
import type { Db } from './db.ts';
import type { ApplyResult } from '../../shared/types.ts';
import type { Actor, Lights } from './lights.ts';
import { KEY, readSchedule, writeSchedule } from './settings.ts';

const HOUR_MS = 3_600_000;
/** After the server was down, the latest time it missed in this long still happens. */
const CATCH_UP_MS = 2 * 24 * HOUR_MS;
/** How often the lights, woken in the night, are checked for nobody using them. */
const IDLE_CHECK_MS = 20_000;

export interface SchedulerOptions {
  /** After the schedule switched every light off (games end, the line empties). */
  afterOff?: () => void;
  /** True while someone uses the lights: a game plays, a turn runs, someone waits in line. */
  busy?: () => boolean;
  now?: () => number;
}

/**
 * Switches the lights on and off at the schedule's times (see LightSchedule). Each time acts
 * once, when it comes: an admin's switch in between holds until the next one. A time missed
 * while the server was down happens when it starts (only the latest one).
 *
 * Off switches every light off, and remembers the lights that were off already; on switches
 * the rest on again, so a light an admin switched off on its own stays off.
 *
 * In between (the night), a visitor's scene, color or game wakes the lights (`wake`): the ones
 * the schedule switched off come on again, and go off again after the schedule's idle minutes
 * with nobody using them. An admin's switch of all the lights ends the night: it holds.
 */
export class LightScheduler {
  private timer: NodeJS.Timeout | null = null;
  private idleTimer: NodeJS.Timeout | null = null;
  private chain: Promise<void> = Promise.resolve();
  private stopped = false;
  /** When a visitor last used the lights (ms), for the idle minutes in the night. */
  private lastUsed = 0;
  /** The idle check last saw every light off: lights on since then (any way) start the idle minutes. */
  private sawOff = false;

  private db: Db;
  private lights: Lights;
  private bus: Bus;
  private opts: SchedulerOptions;

  constructor(db: Db, lights: Lights, bus: Bus, opts: SchedulerOptions = {}) {
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
      const what = after.enabled ? `on at ${describeTime(after.on)}, off at ${describeTime(after.off)}${after.wake ? `, visitors wake them for ${after.idleMinutes} min at a time` : ''}` : 'off';
      this.lights.log('info', 'schedule', `Schedule ${what}`, { before, after }, actor);
    }
    // Switched off, it has no night; woken lights get the new idle minutes from now.
    if (!scheduleRuns(after)) this.setNight(false);
    this.lastUsed = this.now();
    this.armIdle();
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
    // From before the night was kept: the night it is if the schedule's last time was off and the lights are off.
    if (this.db.getSetting(KEY.scheduleNight) == null) {
      const s = this.get();
      const last = scheduleEvents(s, this.now() - CATCH_UP_MS, this.now()).at(-1);
      this.setNight(last?.kind === 'off' && this.lights.allOff());
    }
    this.lastUsed = this.now();
    this.sawOff = this.lights.allOff();
    this.armIdle();
    void this.check();
  }

  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.disarmIdle();
  }

  /** Does what is due (once), then waits for the next time. One check at a time. */
  check(): Promise<void> {
    this.chain = this.chain.then(() => this.run()).catch((e) => this.lights.log('error', 'schedule', `Schedule failed: ${(e as Error).message}`));
    return this.chain;
  }

  // ---------- The night ----------

  /** True between the schedule's off and its on, unless an admin switched the lights since. */
  night(): boolean {
    return scheduleRuns(this.get()) && this.db.getSetting(KEY.scheduleNight) === '1';
  }

  /** True when the lights are off for the night, and a visitor's scene, color or game would wake them. */
  canWake(): boolean {
    return this.night() && this.get().wake && this.lights.allOff() && this.toWake().length > 0;
  }

  /** While the lights are on in the night: the minutes with nobody using them before they go off again. */
  idleMinutes(): number | null {
    const s = this.get();
    return this.night() && s.wake && !this.lights.allOff() ? s.idleMinutes : null;
  }

  /**
   * A visitor wants the lights in the night: switches on the ones the schedule switched off.
   * Null when it cannot (not the night, or not off). The lights count as on at once, when
   * this returns; the promise is the devices being told.
   */
  wake(what: string): Promise<ApplyResult> | null {
    if (!this.canWake()) return null;
    this.lastUsed = this.now();
    this.sawOff = false;
    const done = this.lights.setPower(true, this.toWake(), undefined, `for ${what}, in the schedule's night (off until ${describeTime(this.get().on)})`);
    this.armIdle();
    return done;
  }

  /** A visitor used the lights: the idle minutes start again. */
  used() {
    this.lastUsed = this.now();
  }

  /** An admin switched the lights: the night ends, and their switch holds until the schedule's next time. */
  handSwitched() {
    if (this.db.getSetting(KEY.scheduleNight) !== '1') return;
    this.setNight(false);
    this.bus.emit('state');
  }

  /**
   * On in the night (woken by a visitor, or switched on one by one) and unused for the idle
   * minutes: the lights go off again.
   */
  async checkIdle(): Promise<void> {
    const s = this.get();
    if (!this.night() || !s.wake) return this.disarmIdle();
    const now = this.now();
    if (this.lights.allOff()) return void (this.sawOff = true);
    if (this.sawOff || this.opts.busy?.()) this.lastUsed = now;
    this.sawOff = false;
    if (now - this.lastUsed < s.idleMinutes * 60_000) return;
    this.db.setSetting(KEY.scheduleHeld, JSON.stringify(this.lights.controls().off));
    await this.lights.setPower(false, null, undefined, `after ${s.idleMinutes} minute${s.idleMinutes === 1 ? '' : 's'} with nobody using them, in the schedule's night (off until ${describeTime(s.on)})`);
    this.sawOff = true;
    this.opts.afterOff?.();
  }

  /** The lights the schedule switched off, and that are off now: what waking switches on. */
  private toWake(): string[] {
    const held = new Set(this.held());
    return this.lights.controls().off.filter((id) => !held.has(id));
  }

  private setNight(on: boolean) {
    this.db.setSetting(KEY.scheduleNight, on ? '1' : '');
  }

  /** Checks for nobody using the lights, every little while through the night. */
  private armIdle() {
    if (this.idleTimer || this.stopped || !this.night() || !this.get().wake) return;
    this.idleTimer = setInterval(() => void this.checkIdle().catch((e) => this.lights.log('error', 'schedule', `Schedule failed: ${(e as Error).message}`)), IDLE_CHECK_MS);
    this.idleTimer.unref?.();
  }

  private disarmIdle() {
    if (this.idleTimer) clearInterval(this.idleTimer);
    this.idleTimer = null;
  }

  // ---------- The schedule's times ----------

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
      if (this.lights.allOff()) {
        this.setNight(false);
        return void this.db.setSetting(KEY.scheduleHeld, '[]');
      }
      this.db.setSetting(KEY.scheduleHeld, JSON.stringify(off));
      this.setNight(true);
      this.sawOff = true;
      this.armIdle();
      await this.lights.setPower(false, null, undefined, why);
      this.opts.afterOff?.();
      return;
    }
    const held = new Set(this.held());
    this.db.setSetting(KEY.scheduleHeld, '[]');
    this.setNight(false);
    this.disarmIdle();
    const ids = off.filter((id) => !held.has(id));
    if (ids.length) await this.lights.setPower(true, ids, undefined, why);
    else this.bus.emit('state');
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
