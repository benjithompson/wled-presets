import zlib from 'node:zlib';
import type { WebSocket } from 'ws';

/**
 * The simulated yard, streamed to the browsers of the Play page: one binary message per frame,
 * RGB bytes in stage order. It goes 30 times a second (a screen looks the same as at 60, and it
 * shares the home Wi-Fi with the lights), only when the yard changed, and compressed (deflate,
 * raw) for browsers that asked for it: mostly dark frames shrink 5 to 25 times.
 */

/** Frames a second to the browsers. */
export const VIEW_HZ = 30;
/** A browser that has this much unsent is slow: it skips frames instead of queueing a backlog. */
const BACKLOG = 64 * 1024;
/**
 * A frame goes out this early (ms). The clock ticks 60 times a second, but Node's timers run in
 * whole milliseconds, so a tick can come a fraction before the frame is due. Without slack that
 * frame waits a whole tick: a 50 ms gap, then a 17 ms one, a few times a second, and the yard
 * on the Play page stutters while the lights run smoothly.
 */
const SLACK = 5;

export interface Viewer {
  /** It decompresses frames (asked for with ?frames=deflate). */
  deflate: boolean;
  /** It has no frame yet: it gets the next one even if the yard did not change. */
  fresh: boolean;
}

export class ViewStream {
  private period = 1000 / VIEW_HZ;
  private due = 0;
  private last: Uint8Array | null = null;
  private now: () => number;

  constructor(now = () => performance.now()) {
    this.now = now;
  }

  /** Sends the frame (RGB bytes in stage order) to the viewers when one is due. */
  push(bytes: Uint8Array, viewers: Iterable<[WebSocket, Viewer]>) {
    const now = this.now();
    if (now < this.due - SLACK) return;
    // On a steady beat; after a stall, start again from now.
    this.due = now - this.due > this.period ? now + this.period : this.due + this.period;
    const changed = !this.last || !Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).equals(this.last);
    if (changed) this.last = Uint8Array.from(bytes);
    let packed: Buffer | null = null;
    for (const [ws, v] of viewers) {
      if (!changed && !v.fresh) continue;
      if (ws.readyState !== ws.OPEN || ws.bufferedAmount > BACKLOG) continue;
      if (v.deflate) ws.send((packed ??= zlib.deflateRawSync(bytes, { level: 1 })));
      else ws.send(bytes);
      v.fresh = false;
    }
  }
}
