import { FRAME_RATES } from '../../shared/types.ts';
import { MAX_FPS } from './ledTiming.ts';

/** The lowest rate a device is held to. */
const FLOOR = FRAME_RATES[FRAME_RATES.length - 1];
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
 * them, it is sent the next lower rate (FRAME_RATES), then lower again at the next check if it
 * still lags. After a minute of keeping up it gets the next higher rate, until it is free again.
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
   * not judged by its frames). `cap`: the most any device gets (the admin's limit). Returns what
   * changed, for the log, or null.
   */
  checked(id: string, name: string, c: DeviceCheck, sending: number, cap: number): string | null {
    const h = this.held.get(id);
    if (!sending) {
      // Not getting frames: nothing of ours to blame. A held one that answers quickly counts toward its release.
      if (h && c.ok && c.ms < QUICK_MS) return this.good(id, name, h, cap);
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
      const next = [...FRAME_RATES].find((r) => r < sending) ?? FLOOR;
      if (h && h.fps <= next) {
        h.good = 0;
        return null;
      }
      this.held.set(id, { fps: next, good: 0 });
      const why = !c.ok ? `no answer in ${(c.ms / 1000).toFixed(1)} s` : shows != null && shows < sending * BEHIND ? `shows ${shows} of ${sending} frames a second` : `takes ${(c.ms / 1000).toFixed(1)} s to answer`;
      return `"${name}" is falling behind (${why}): sending it ${next} frames a second until it keeps up`;
    }
    if (!h) return null;
    if (c.ok && c.ms < QUICK_MS && (shows == null || shows >= sending * KEEPING_UP)) return this.good(id, name, h, cap);
    h.good = 0;
    return null;
  }

  private good(id: string, name: string, h: { fps: number; good: number }, cap: number): string | null {
    if (++h.good < RECOVER_CHECKS) return null;
    const up = [...FRAME_RATES].reverse().find((r) => r > h.fps) ?? MAX_FPS;
    if (up >= Math.min(cap, MAX_FPS)) {
      this.held.delete(id);
      return `"${name}" keeps up again: it gets every frame (up to ${Math.min(cap, MAX_FPS)} a second) again`;
    }
    this.held.set(id, { fps: up, good: 0 });
    return `"${name}" keeps up: sending it ${up} frames a second`;
  }

  /** Forgets a device (removed). */
  forget(id: string) {
    this.held.delete(id);
  }
}
