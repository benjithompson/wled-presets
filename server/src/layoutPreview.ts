import { LayoutEffects, toBytes } from '../../shared/effects.ts';
import { framePut, paintEditorView, PREVIEW_EXPIRE_MS, type PreviewRequest, type SequencePreviewRequest } from '../../shared/editorView.ts';
import { buildStage, deviceLed, editorPulse, layoutShapeKey, type Layout, type Stage } from '../../shared/layout.ts';
import { checkMoves, validCheck } from '../../shared/check.ts';
import { codeColor } from '../../shared/photoTrace.ts';
import { SequencePlayer } from '../../shared/sequence.ts';
import { deviceMaps, PRIORITY, renderDevice, type DeviceMap, type ExtraLed, type FramePipeline, type FrameSource, type LightFrame } from './framePipeline.ts';

export type { PhotoLights, PreviewRequest, SequencePreviewRequest } from '../../shared/editorView.ts';

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
export function editorFrame(req: PreviewRequest, view: Pick<View, 'stage' | 'maps'>, pulse: boolean, nowMs = Date.now()): LightFrame {
  const { stage } = view;
  const bytes = new Uint8Array(stage.pixelCount * 3);
  const extra: ExtraLed[] = [];
  // LEDs past an object's end (the wizard's) are set by their device number.
  const put = framePut(stage, bytes, (fi, i, rgb) => {
    const f = req.layout.fixtures[fi];
    if (f.deviceId) extra.push({ deviceId: f.deviceId, led: deviceLed(f, i), rgb });
  });
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
  paintEditorView(req.layout, stage, { ...req, check: req.probe ? null : validCheck(req.check, req.layout) }, nowMs, pulse, put, bytes);
  return { maps: view.maps, bytes, extra, wakes: true };
}

/** One device's colors for the editor's view (see editorFrame). */
export function previewFrame(req: PreviewRequest, deviceId: string, ledCount: number, pulse: boolean, nowMs = Date.now()): Uint8Array {
  const view = viewOf(req.layout);
  const frame = editorFrame(req, view, pulse, nowMs);
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
  private fx: LayoutEffects | null = null;
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
    if (!req.play) this.fx = null;
    else if (this.fx) this.fx.sync(view.stage, req.layout);
    else this.fx = new LayoutEffects(view.stage, req.layout);
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
    if (this.fx) return { maps: this.view.maps, bytes: this.fx.frame(dt), wakes: true };
    // Drawn for when it shows, so the lights blink (and a check moves) in step with the editor.
    const pulse = editorPulse(showAt);
    if (checkMoves(req.check) && !req.probe) return editorFrame(req, this.view, pulse, showAt);
    if (this.painted?.req !== req || this.painted.pulse !== pulse) this.painted = { req, pulse, frame: editorFrame(req, this.view, pulse, showAt) };
    return this.painted.frame;
  }

  private start(req: PreviewRequest): string[] {
    const started = !this.req;
    this.req = req;
    this.until = Date.now() + PREVIEW_EXPIRE_MS;
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
}
