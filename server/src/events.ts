import { EventEmitter } from 'node:events';
import type { LogEntry } from '../../shared/types.ts';

interface Events {
  /** Public state changed (scene, color, device status, settings). */
  state: [];
  /** Device list or device status changed. */
  devices: [];
  log: [LogEntry | null];
  /** The line for the lights changed. */
  line: [];
}

export class Bus extends EventEmitter<Events> {
  constructor() {
    super();
    this.setMaxListeners(0); // one listener per open browser tab
  }
}
