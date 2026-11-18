/**
 * Calls `fn` a given number of times a second, on a steady beat. Node's setInterval waits a
 * whole number of milliseconds after each call starts, so 60 a second comes out near 58, and a
 * late call pushes all the later ones back. Here each call aims at its own deadline (the start
 * plus n periods), so the rate holds on average; after a stall of more than a frame it skips
 * ahead instead of running the missed frames back to back.
 */
export class FrameLoop {
  private timer: NodeJS.Timeout | null = null;
  private next = 0;
  private period: number;
  private fn: () => void;

  constructor(fn: () => void, hz: number) {
    this.fn = fn;
    this.period = 1000 / hz;
  }

  get running() {
    return this.timer !== null;
  }

  /** Changes the rate; a running loop keeps its beat from the next frame on. */
  setRate(hz: number) {
    this.period = 1000 / hz;
  }

  start() {
    if (this.timer) return;
    this.next = performance.now() + this.period;
    this.schedule();
  }

  stop() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private schedule() {
    this.timer = setTimeout(this.run, Math.max(0, this.next - performance.now()));
  }

  private run = () => {
    const timer = this.timer;
    this.fn();
    // fn may have stopped (or restarted) the loop.
    if (this.timer !== timer) return;
    const now = performance.now();
    this.next += this.period;
    if (now - this.next > this.period) this.next = now + this.period;
    this.schedule();
  };
}
