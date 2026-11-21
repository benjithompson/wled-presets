// What the layout editors show on the lights, and in their own views: the same picture in both
// places, at the same moment (see editorPulse).
import { paintCheck, type LayoutCheck } from './check.ts';
import { paintEditor, paintGameArea, paintMatch, type GameArea, type Layout, type MatchProbe, type Stage } from './layout.ts';
import type { Sequence } from './sequence.ts';

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

/** The preview on the lights stops when the editor has not sent it again for this long (ms). */
export const PREVIEW_EXPIRE_MS = 8_000;
/** How often an editor sends its preview again (ms): a lost request or two does not let it stop. */
export const PREVIEW_KEEPALIVE_MS = 3_000;

/** What an editor shows on the lights (see editorFrame on the server). */
export interface PreviewRequest {
  layout: Layout;
  selected: string | null;
  corner: number | null;
  /** Roof only: the selected segment (between point k and point k + 1). */
  segment?: number | null;
  /** Show the objects' effects (layout fixture "effect") instead of the editor's colors. */
  play?: boolean;
  /** The Games page: show the game area (see paintGameArea), with `selected` and `segment` in focus. */
  area?: GameArea | null;
  /** The editor's "match to the lights" wizard: one LED of the selected line blinks red (see paintMatch). */
  probe?: MatchProbe | null;
  /** The object designer's photo: these LEDs light up in one color (the first in another), all else dark. */
  photo?: PhotoLights | null;
  /** A check of the drawing against the yard: a slice, a ruler, or one object's color test or chase (see shared/check.ts). */
  check?: LayoutCheck | null;
}

/**
 * LEDs to light for a photo of a custom object (see shared/photoTrace.ts): device LEDs `from`
 * to `to` (either way round) in `rgb`, LED `from` (where the wire starts) in `start`; or, for a
 * camera scan, each in the color of one digit of its number.
 */
export interface PhotoLights {
  deviceId: string;
  from: number;
  to: number;
  rgb: [number, number, number];
  start: [number, number, number];
  /** A frame of a camera scan instead (see codeColor): every LED shows a digit of its number. */
  code?: number | null;
}

/** The sequence editor's preview: a sequence, the time the editor shows, and whether it plays. */
export interface SequencePreviewRequest {
  sequence: Sequence;
  time: number;
  playing: boolean;
}
