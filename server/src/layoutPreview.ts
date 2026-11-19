import { EffectScene, layoutEffects, toBytes } from '../../shared/effects.ts';
import { buildStage, deviceLed, editorPulse, layoutShapeKey, paintEditor, paintGameArea, paintMatch, type GameArea, type Layout, type MatchProbe, type Stage } from '../../shared/layout.ts';
import { codeColor } from '../../shared/photoTrace.ts';
import { SequencePlayer, type Sequence } from '../../shared/sequence.ts';
import { deviceMaps, PRIORITY, renderDevice, type DeviceMap, type ExtraLed, type FramePipeline, type FrameSource, type LightFrame } from './framePipeline.ts';

/** The preview stops when the editor has not refreshed it for this long. */
const EXPIRE_MS = 8_000;

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

/** A layout as the lights need it: its stage, and where the stage's LEDs go on each device. */
interface View {
  key: string;
  stage: Stage;
  maps: DeviceMap[];
}

const viewOf = (layout: Layout, key = layoutShapeKey(layout)): View => {
  const stage = buildStage(layout);
  return { key, stage, maps: deviceMaps(layout, stage) };
};

/**
 * The editor's view of the layout as a frame for the lights (see paintEditor, paintGameArea
 * and paintMatch). LEDs past the end of a line (the wizard's) are set by device number.
 */
export function editorFrame(req: PreviewRequest, view: Pick<View, 'stage' | 'maps'>, pulse: boolean): LightFrame {
  const { stage } = view;
  const bytes = new Uint8Array(stage.pixelCount * 3);
  const extra: ExtraLed[] = [];
  const put = (fi: number, i: number, rgb: [number, number, number]) => {
    const sf = stage.fixtures[fi];
    if (i >= 0 && i < sf.count) return bytes.set(rgb, (sf.offset + i) * 3);
    const f = req.layout.fixtures[fi];
    if (f.deviceId) extra.push({ deviceId: f.deviceId, led: deviceLed(f, i), rgb });
  };
  if (req.photo) {
    const p = req.photo;
    req.layout.fixtures.forEach((_, fi) => {
      for (let i = 0; i < stage.fixtures[fi].count; i++) put(fi, i, [0, 0, 0]);
    });
    const dir = p.to >= p.from ? 1 : -1;
    const n = Math.abs(p.to - p.from) + 1;
    for (let i = 0, led = p.from; i < n; i++, led += dir) {
      const rgb = p.code != null ? codeColor(i, p.code, n) : i === 0 ? p.start : p.rgb;
      extra.push({ deviceId: p.deviceId, led, rgb });
    }
    // A device with no objects in the layout yet still gets the frame.
    const maps = view.maps.some((m) => m.deviceId === p.deviceId) ? view.maps : [...view.maps, emptyMap(p.deviceId)];
    return { maps, bytes, extra, wakes: true };
  }
  if (req.probe && req.selected) paintMatch(req.layout, req.selected, req.probe, pulse, put);
  else if (req.area !== undefined) paintGameArea(req.layout, req.area, req.selected ? { id: req.selected, segment: req.segment ?? null } : null, pulse, put);
  else paintEditor(req.layout, req.selected, req.corner, req.segment ?? null, pulse, put);
  return { maps: view.maps, bytes, extra, wakes: true };
}

/** One device's colors for the editor's view (see editorFrame). */
export function previewFrame(req: PreviewRequest, deviceId: string, ledCount: number, pulse: boolean): Uint8Array {
  const view = viewOf(req.layout);
  const frame = editorFrame(req, view, pulse);
  return renderDevice(frame, frame.maps.find((x) => x.deviceId === deviceId) ?? emptyMap(deviceId), ledCount);
}

const emptyMap = (deviceId: string): DeviceMap => ({ deviceId, size: 0, pairs: new Int32Array(), objects: [] });

/**
 * Shows the layout being edited on the real lights while an editor asks for it: the layout
 * editor's colors or effects, the Games page's game area, or the sequence editor's sequence.
 * A source of the FramePipeline that wins over games and scenes; when the editor stops asking,
 * they get the lights back. It lights devices that are off too, in WLED or switched off here
 * (the admin turned it on to see them), and they go off again after.
 */
export class LayoutPreview implements FrameSource {
  private req: PreviewRequest | null = null;
  private until = 0;
  private pipeline: FramePipeline;
  private log: (msg: string) => void;
  /** The layout being shown, as the lights need it. Rebuilt only when its shape changes. */
  private view: View | null = null;
  /** While the effects play: the running effects, and their frame. */
  private fx: { stage: Stage; scene: EffectScene; data: Float32Array; bytes: Uint8Array } | null = null;
  /** The sequence editor's preview: the player, and whether it plays or shows one moment. */
  private seq: { stage: Stage; player: SequencePlayer; data: Float32Array; bytes: Uint8Array; playing: boolean } | null = null;
  /** The editor's colors change only with a request or a blink: painted once for each. */
  private painted: { req: PreviewRequest; pulse: boolean; frame: LightFrame } | null = null;

  constructor(pipeline: FramePipeline, log: (msg: string) => void) {
    this.log = log;
    this.pipeline = pipeline;
    pipeline.add(this, PRIORITY.editor);
  }

  /** Starts or updates the preview. Returns the names of the devices it lights. */
  show(req: PreviewRequest): string[] {
    this.seq = null;
    const view = this.viewFor(req.layout);
    if (req.play) this.syncEffects(req.layout, view.stage);
    else this.fx = null;
    return this.start(req);
  }

  /**
   * Plays a sequence on the lights for the sequence editor, from `time`. While it plays, the
   * pipeline's clock moves it on; a time far from it (a jump) moves it. Paused, it shows `time`.
   */
  showSequence(req: SequencePreviewRequest, layout: Layout): string[] {
    const { stage } = this.viewFor(layout);
    const cur = this.seq;
    if (!cur || cur.stage !== stage) {
      const player = new SequencePlayer(stage, layout, req.sequence);
      player.seek(req.time);
      this.seq = { stage, player, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3), playing: req.playing };
    } else {
      cur.player.setSequence(req.sequence);
      // Small differences are the network delay; only a jump (or a paused editor) moves the clock.
      if (!req.playing || !cur.playing || Math.abs(cur.player.time - req.time) > 0.25) cur.player.seek(req.time, req.playing ? 2.5 : 1);
      cur.playing = req.playing;
    }
    this.fx = null;
    return this.start({ layout, selected: null, corner: null, play: true });
  }

  /** True while an editor shows a preview on the lights. */
  get active() {
    return !!this.req;
  }

  get running() {
    return this.active;
  }

  stop() {
    if (!this.req) return;
    this.req = null;
    this.fx = null;
    this.seq = null;
    this.painted = null;
    // On the next frame, a game or scene takes the lights back, or each device gets its own state back.
    this.pipeline.wake();
    this.log('Editor preview on the lights stopped');
  }

  close() {
    this.stop();
    this.pipeline.remove(this);
  }

  tick(dt: number, showAt: number): LightFrame | null {
    const req = this.req;
    if (!req || !this.view) return null;
    if (Date.now() > this.until) {
      this.stop();
      return null;
    }
    const sq = this.seq;
    if (sq) {
      sq.player.update(sq.playing ? dt : 0, sq.data);
      toBytes(sq.data, sq.bytes);
      return { maps: this.view.maps, bytes: sq.bytes, wakes: true };
    }
    const fx = this.fx;
    if (fx) {
      fx.scene.update(dt, fx.data);
      toBytes(fx.data, fx.bytes);
      return { maps: this.view.maps, bytes: fx.bytes, wakes: true };
    }
    // Drawn for when it shows, so the lights blink in step with the editor.
    const pulse = editorPulse(showAt);
    if (this.painted?.req !== req || this.painted.pulse !== pulse) this.painted = { req, pulse, frame: editorFrame(req, this.view, pulse) };
    return this.painted.frame;
  }

  private start(req: PreviewRequest): string[] {
    const started = !this.req;
    this.req = req;
    this.until = Date.now() + EXPIRE_MS;
    this.pipeline.wake();
    const ids = new Set([...req.layout.fixtures.map((f) => f.deviceId), req.photo?.deviceId].filter(Boolean));
    const names = this.pipeline
      .deviceList()
      .filter((d) => (d.enabled || d.switchedOff) && ids.has(d.id))
      .map((d) => d.name);
    if (started && names.length) this.log(`Editor preview on the lights started (${names.join(', ')})`);
    return names;
  }

  private viewFor(layout: Layout): View {
    const key = layoutShapeKey(layout);
    if (this.view?.key !== key) this.view = viewOf(layout, key);
    return this.view;
  }

  /** Keeps the effects running across edits: a changed yard moves them to its new stage. */
  private syncEffects(layout: Layout, stage: Stage) {
    const effects = layoutEffects(layout);
    if (!this.fx) this.fx = { stage, scene: new EffectScene(stage, layout, effects), data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3) };
    else if (this.fx.stage !== stage) this.fx = { ...this.fx, stage, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3) };
    this.fx.scene.setStage(stage, layout);
    this.fx.scene.setEffects(effects);
  }
}
