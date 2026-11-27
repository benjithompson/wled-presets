import { MAX_FPS } from './ledTiming.ts';

/** A device is not held below this many frames a second. */
const FLOOR = 10;
/** A check that took longer than this: the device is busy (it answers between frames). */
export const SLOW_MS = 2000;
/** An answer this quick, and the frames shown: the device keeps up. */
const QUICK_MS = 800;
/** Behind: it shows fewer than this share of the frames it is sent. */
const BEHIND = 0.5;
/** Keeping up: it shows at least this share. */
const KEEPING_UP = 0.7;
/** Checks in a row that keep up before a held device gets more frames again (about a minute). */
const RECOVER_CHECKS = 6;

/** One status check of a device: answered or not, how long it took, the frames a second it says it shows. */
export interface DeviceCheck {
  ok: boolean;
  ms: number;
  fps?: number;
}

/**
 * Holds a device that falls behind to fewer frames. A WLED controller that cannot keep up with
 * the frames it is sent queues them, and then everything it does slows down: the LEDs show a
 * handful a second, it takes seconds to answer, and only a restart brings it back. So when a
 * status check finds a device that gets frames answering slowly, or showing well under half of
 * them, it is sent the next lower even share of the clock (60: 30, 20, 15, 12, 10), then lower
 * again at the next check if it still lags, never below FLOOR. After a minute of keeping up it gets the next higher rate, until it is free again.
 */
export class FrameRateHold {
  private held = new Map<string, { fps: number; good: number }>();

  /** The most frames a second this device may be sent now (MAX_FPS: not held). */
  limit(id: string): number {
    return this.held.get(id)?.fps ?? MAX_FPS;
  }

  /** Every device held now, and its rate. */
  all(): Record<string, number> {
    return Object.fromEntries([...this.held].map(([id, h]) => [id, h.fps]));
  }

  /**
   * A status check of a device. `sending`: the frames a second it gets now (0: none, so it is
   * not judged by its frames). `cap`: the most any device gets (the admin's limit). `clock`: the
   * pipeline's rate, whose even shares it can be sent. Returns what changed, for the log, or null.
   */
  checked(id: string, name: string, c: DeviceCheck, sending: number, cap: number, clock: number = MAX_FPS): string | null {
    const h = this.held.get(id);
    if (!sending) {
      // Not getting frames: nothing of ours to blame. A held one that answers quickly counts toward its release.
      if (h && c.ok && c.ms < QUICK_MS) return this.good(id, name, h, cap, clock);
      return null;
    }
    // A quick "no": switched off at the wall, say. Not behind, not keeping up.
    if (!c.ok && c.ms <= SLOW_MS) {
      if (h) h.good = 0;
      return null;
    }
    const shows = c.ok && typeof c.fps === 'number' ? c.fps : null;
    const behind = c.ms > SLOW_MS || (shows != null && shows < sending * BEHIND);
    if (behind) {
      // The next even share of the clock below what it gets: every second frame, every third…
      const next = clock / (Math.round(clock / Math.min(sending, clock)) + 1);
      if (next < FLOOR - 0.01 || (h && h.fps <= next)) {
        if (h) h.good = 0;
        return null;
      }
      this.held.set(id, { fps: next, good: 0 });
      const why = !c.ok ? `no answer in ${(c.ms / 1000).toFixed(1)} s` : shows != null && shows < sending * BEHIND ? `shows ${shows} of ${sending} frames a second` : `takes ${(c.ms / 1000).toFixed(1)} s to answer`;
      return `"${name}" is falling behind (${why}): sending it ${fmt(next)} frames a second until it keeps up`;
    }
    if (!h) return null;
    if (c.ok && c.ms < QUICK_MS && (shows == null || shows >= sending * KEEPING_UP)) return this.good(id, name, h, cap, clock);
    h.good = 0;
    return null;
  }

  private good(id: string, name: string, h: { fps: number; good: number }, cap: number, clock: number): string | null {
    if (++h.good < RECOVER_CHECKS) return null;
    // The next even share above: every frame of the clock at most.
    const every = Math.max(1, Math.round(clock / h.fps) - 1);
    const up = clock / every;
    if (up >= Math.min(cap, clock) - 0.01) {
      this.held.delete(id);
      return `"${name}" keeps up again: it gets up to ${fmt(Math.min(cap, clock))} frames a second again`;
    }
    this.held.set(id, { fps: up, good: 0 });
    return `"${name}" keeps up: sending it ${fmt(up)} frames a second`;
  }

  /** Forgets a device (removed). */
  forget(id: string) {
    this.held.delete(id);
  }
}

const fmt = (fps: number) => String(Math.round(fps * 10) / 10);
