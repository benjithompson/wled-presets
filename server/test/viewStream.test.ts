import { describe, expect, it } from 'vitest';
import { ViewStream, type Viewer } from '../src/game/viewStream.ts';

/** A browser that keeps the times its frames came. */
function browser() {
  const got: number[] = [];
  let now = 0;
  const ws = { readyState: 1, OPEN: 1, bufferedAmount: 0, send: () => got.push(now) };
  const viewers = new Map([[ws as never, { deflate: false, fresh: false } as Viewer]]);
  return { got, viewers, at: (t: number) => (now = t) };
}

describe('the yard streamed to the Play page', () => {
  it('goes out on a steady beat when the 60 Hz clock ticks a hair early', () => {
    // Node's timers run in whole milliseconds: a tick can come a fraction early. The frame due
    // then still goes, instead of waiting a whole tick (a 50 ms gap, then a 17 ms one).
    let now = 0;
    const view = new ViewStream(() => now);
    const b = browser();
    const frame = new Uint8Array(30);
    for (let k = 0; k < 600; k++) {
      now = (k * 1000) / 60 - (k % 3 === 0 ? 0.6 : 0) + (k % 7 === 0 ? 0.8 : 0);
      b.at(now);
      frame[0] = k & 255;
      view.push(frame, b.viewers);
    }
    const gaps = b.got.slice(1).map((t, i) => t - b.got[i]);
    expect(b.got.length).toBeGreaterThanOrEqual(299);
    expect(Math.max(...gaps)).toBeLessThan(40);
    expect(Math.min(...gaps)).toBeGreaterThan(25);
  });

  it('sends 30 frames a second from a 60 Hz clock, not more', () => {
    let now = 0;
    const view = new ViewStream(() => now);
    const b = browser();
    const frame = new Uint8Array(30);
    for (let k = 0; k < 60; k++) {
      now = (k * 1000) / 60;
      b.at(now);
      frame[0] = k;
      view.push(frame, b.viewers);
    }
    expect(b.got.length).toBe(30);
  });

  it('starts again from now after a stall, without a burst', () => {
    let now = 0;
    const view = new ViewStream(() => now);
    const b = browser();
    const frame = new Uint8Array(30);
    const tick = (t: number) => {
      now = t;
      b.at(t);
      frame[0]++;
      view.push(frame, b.viewers);
    };
    tick(0);
    tick(500);
    tick(517);
    tick(533);
    expect(b.got).toEqual([0, 500, 533]);
  });
});
