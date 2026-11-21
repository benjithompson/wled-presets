// What the layout editors show on the lights, and in their own views: the same picture in both
// places, at the same moment (see editorPulse).
import { paintCheck, type LayoutCheck } from './check.ts';
import { paintEditor, paintGameArea, paintMatch, type GameArea, type Layout, type MatchProbe, type Stage } from './layout.ts';

type Rgb = [number, number, number];

/** Sets LED `led` of object `fixtureIndex` (it may be past the object's end: the wizard's). */
export type PutLed = (fixtureIndex: number, led: number, rgb: Rgb) => void;

/** What an editor is doing, which decides the picture. */
export interface EditorView {
  selected: string | null;
  corner: number | null;
  /** A line's selected segment (between point k and point k + 1). */
  segment?: number | null;
  /** The "match to the lights" wizard: one LED of the selected line blinks (see paintMatch). */
  probe?: MatchProbe | null;
  /** A check of the drawing against the yard, already checked against the layout (see validCheck). */
  check?: LayoutCheck | null;
  /** The Games page: the game area (see paintGameArea). Not set: another editor. */
  area?: GameArea | null;
}

/**
 * Paints the editor's picture of the layout: the wizard's blinking LED, else a check, else the
 * game area, else every object with the selected one (and its corner or segment) picked out.
 * Objects' LEDs go through `put`; a check draws straight into `bytes`, the stage's frame.
 */
export function paintEditorView(layout: Layout, stage: Stage, view: EditorView, nowMs: number, pulse: boolean, put: PutLed, bytes: Uint8Array) {
  if (view.probe && view.selected) paintMatch(layout, view.selected, view.probe, pulse, put);
  else if (view.check) paintCheck(layout, stage, view.check, nowMs, pulse, bytes);
  else if (view.area !== undefined) paintGameArea(layout, view.area, view.selected ? { id: view.selected, segment: view.segment ?? null } : null, pulse, put);
  else paintEditor(layout, view.selected, view.corner, view.segment ?? null, pulse, put);
}

/** A PutLed into a stage's frame. LEDs past an object's end go to `outside`, if given. */
export function framePut(stage: Stage, bytes: Uint8Array, outside?: PutLed): PutLed {
  return (fi, i, rgb) => {
    const sf = stage.fixtures[fi];
    if (i >= 0 && i < sf.count) bytes.set(rgb, (sf.offset + i) * 3);
    else outside?.(fi, i, rgb);
  };
}
