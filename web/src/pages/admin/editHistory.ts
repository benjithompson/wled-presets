/** How far back Undo goes. */
const STEPS = 100;
/** Changes closer together than this are one step for Undo (for example, one drag). */
const GROUP_MS = 600;

/**
 * Undo and redo for an editor that keeps whole states (layouts): the state before each edit,
 * with edits in quick succession (a drag) kept as one step.
 */
export class EditHistory<T> {
  private past: T[] = [];
  private future: T[] = [];
  /** When the last edit was (ms); 0: the next edit is a step of its own. */
  private last = 0;
  private readonly steps: number;
  private readonly groupMs: number;

  constructor(steps = STEPS, groupMs = GROUP_MS) {
    this.steps = steps;
    this.groupMs = groupMs;
  }

  /**
   * Before an edit of `current`: keeps it to go back to, unless the last edit was only just
   * before (then both are one step). True: a step was added (what Undo and Redo can do changed).
   */
  record(current: T, now = Date.now()): boolean {
    const added = now - this.last > this.groupMs;
    if (added) {
      this.past = [...this.past.slice(1 - this.steps), current];
      this.future = [];
    }
    this.last = now;
    return added;
  }

  /** The state before the last step, with `current` kept for Redo. Null: nothing to undo. */
  undo(current: T): T | null {
    const prev = this.past.pop();
    if (prev === undefined) return null;
    this.future.push(current);
    this.last = 0;
    return prev;
  }

  /** The state Undo went back from, with `current` kept for Undo. Null: nothing to redo. */
  redo(current: T): T | null {
    const next = this.future.pop();
    if (next === undefined) return null;
    this.past.push(current);
    this.last = 0;
    return next;
  }

  /** The next edit is a step of its own (a new drag, say), however soon it comes. */
  newStep() {
    this.last = 0;
  }

  /** Where the history is now, to go back to with rollback. */
  mark() {
    return this.past.length;
  }

  /** Forgets the steps taken since `mark` (a touch that turned out to be a pinch, not an edit). */
  rollback(mark: number) {
    this.past = this.past.slice(0, mark);
    this.last = 0;
  }

  /** Nothing to undo or redo (a new layout). */
  clear() {
    this.past = [];
    this.future = [];
  }

  get canUndo() {
    return this.past.length > 0;
  }

  get canRedo() {
    return this.future.length > 0;
  }
}
