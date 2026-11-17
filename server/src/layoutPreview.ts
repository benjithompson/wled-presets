import { EffectScene, layoutEffects, toBytes } from '../../shared/effects.ts';
import { buildStage, deviceLed, editorPulse, paintEditor, type Layout, type Stage } from '../../shared/layout.ts';
import { SequencePlayer, type Sequence } from '../../shared/sequence.ts';
import type { Device, DeviceInfo } from '../../shared/types.ts';
import type { LightSender } from './lightSender.ts';

/** Often enough that a changed number shows on the lights at once. */
const TICK_MS = 50;
/** While the effects play: every frame, as smooth as a scene. */
const PLAY_TICK_MS = 1000 / 60;
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
}

/** The sequence editor's preview: a sequence, the time the editor shows, and whether it plays. */
export interface SequencePreviewRequest {
  sequence: Sequence;
  time: number;
  playing: boolean;
}

/** Colors for one device from a whole stage frame (RGB bytes in stage order). */
export function stageFrame(layout: Layout, stage: Stage, bytes: Uint8Array, deviceId: string, ledCount: number): Uint8Array {
  const fixtures = layout.fixtures.filter((f) => f.deviceId === deviceId);
  const size = Math.max(ledCount, ...fixtures.map((f) => f.startPixel + f.pixels));
  const out = new Uint8Array(size * 3);
  layout.fixtures.forEach((f, fi) => {
    if (f.deviceId !== deviceId) return;
    const sf = stage.fixtures[fi];
    for (let i = 0; i < sf.count; i++) {
      const led = deviceLed(f, i);
      if (led >= 0 && led < size) out.set(bytes.subarray((sf.offset + i) * 3, (sf.offset + i) * 3 + 3), led * 3);
    }
  });
  return out;
}

/** Colors for one device: the editor's view (see paintEditor), mapped to the device's LED numbers. */
export function previewFrame(req: PreviewRequest, deviceId: string, ledCount: number, pulse: boolean): Uint8Array {
  const fixtures = req.layout.fixtures.filter((f) => f.deviceId === deviceId);
  const size = Math.max(ledCount, ...fixtures.map((f) => f.startPixel + f.pixels));
  const out = new Uint8Array(size * 3);
  paintEditor(req.layout, req.selected, req.corner, req.segment ?? null, pulse, (fi, i, rgb) => {
    const f = req.layout.fixtures[fi];
    if (f.deviceId !== deviceId) return;
    const led = deviceLed(f, i);
    if (led >= 0 && led < size) out.set(rgb, led * 3);
  });
  return out;
}

/** Shows the layout being edited on the real lights, while the editor asks for it. */
export class LayoutPreview {
  private req: PreviewRequest | null = null;
  private until = 0;
  private timer: NodeJS.Timeout | null = null;
  private sender: LightSender;

  private devices: () => (Device & { info: DeviceInfo | null })[];
  private log: (msg: string) => void;
  /** While the effects play: the stage, the running effects, and the last frame's time. */
  private fx: { key: string; stage: Stage; scene: EffectScene; data: Float32Array; bytes: Uint8Array; last: number } | null = null;
  private tickMs = 0;
  /** The sequence editor's preview: the player, and whether it plays or shows one moment. */
  private seq: { key: string; player: SequencePlayer; stage: Stage; layout: Layout; data: Float32Array; bytes: Uint8Array; playing: boolean; last: number } | null = null;

  constructor(devices: () => (Device & { info: DeviceInfo | null })[], log: (msg: string) => void, sender: LightSender) {
    this.devices = devices;
    this.sender = sender;
    this.log = log;
  }

  /** Starts or updates the preview. Returns the names of the devices it lights. */
  show(req: PreviewRequest): string[] {
    this.seq = null;
    return this.start(req);
  }

  /**
   * Plays a sequence on the lights for the sequence editor, from `time`. While it plays, the
   * server keeps its own clock; a time far from it (a jump) moves it. Paused, it shows `time`.
   */
  showSequence(req: SequencePreviewRequest, layout: Layout): string[] {
    const cur = this.seq;
    const key = JSON.stringify(layout);
    if (!cur || cur.key !== key) {
      const stage = buildStage(layout);
      const player = new SequencePlayer(stage, layout, req.sequence);
      player.seek(req.time);
      this.seq = { key, player, stage, layout, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3), playing: req.playing, last: performance.now() };
    } else {
      cur.player.setSequence(req.sequence);
      // Small differences are the network delay; only a jump (or a paused editor) moves the clock.
      if (!req.playing || !cur.playing || Math.abs(cur.player.time - req.time) > 0.25) cur.player.seek(req.time, req.playing ? 2.5 : 1);
      cur.playing = req.playing;
      cur.last = performance.now();
    }
    this.fx = null;
    return this.start({ layout, selected: null, corner: null, play: true });
  }

  private start(req: PreviewRequest): string[] {
    const started = !this.req;
    this.req = req;
    this.until = Date.now() + EXPIRE_MS;
    if (this.seq) this.fx = null;
    else if (req.play) this.syncEffects(req.layout);
    else this.fx = null;
    const tick = req.play ? PLAY_TICK_MS : TICK_MS;
    if (this.timer && this.tickMs !== tick) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (!this.timer) {
      this.timer = setInterval(() => this.send(), tick);
      this.tickMs = tick;
    }
    this.send();
    const names = this.targets().map((d) => d.name);
    if (started && names.length) this.log(`Editor preview on the lights started (${names.join(', ')})`);
    return names;
  }

  /** True while the editor shows a preview on the lights. */
  get active() {
    return !!this.req;
  }

  stop() {
    if (!this.req) return;
    const targets = this.targets();
    this.req = null;
    this.fx = null;
    this.seq = null;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    // Put each device's own color, scene or preset back at once.
    for (const d of targets) this.sender.end(d);
    this.log('Editor preview on the lights stopped');
  }

  close() {
    this.stop();
  }

  private targets() {
    const ids = new Set(this.req?.layout.fixtures.map((f) => f.deviceId).filter(Boolean));
    return this.devices().filter((d) => d.enabled && ids.has(d.id));
  }

  /** Keeps the effects running across edits: only a changed shape or LED count restarts one. */
  private syncEffects(layout: Layout) {
    const key = JSON.stringify(layout.fixtures.map(({ effect: _e, segmentEffects: _s, name: _n, deviceId: _d, ...f }) => f));
    const effects = layoutEffects(layout);
    if (!this.fx || this.fx.key !== key) {
      const stage = buildStage(layout);
      const scene = this.fx ? (this.fx.scene.setStage(stage, layout), this.fx.scene) : new EffectScene(stage, layout, effects);
      this.fx = { key, stage, scene, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3), last: performance.now() };
    } else this.fx.scene.setStage(this.fx.stage, layout);
    this.fx.scene.setEffects(effects);
  }

  private send() {
    if (!this.req) return;
    if (Date.now() > this.until) return this.stop();
    const sq = this.seq;
    if (sq) {
      const now = performance.now();
      const dt = sq.playing ? Math.min(0.1, (now - sq.last) / 1000) : 0;
      sq.last = now;
      sq.player.update(dt, sq.data);
      toBytes(sq.data, sq.bytes);
      for (const d of this.targets()) this.sender.send(d, stageFrame(sq.layout, sq.stage, sq.bytes, d.id, d.info?.leds?.count ?? 0));
      return;
    }
    const fx = this.fx;
    if (fx) {
      const now = performance.now();
      fx.scene.update((now - fx.last) / 1000, fx.data);
      fx.last = now;
      toBytes(fx.data, fx.bytes);
      for (const d of this.targets()) this.sender.send(d, stageFrame(this.req.layout, fx.stage, fx.bytes, d.id, d.info?.leds?.count ?? 0));
      return;
    }
    for (const d of this.targets()) {
      // Draw ahead by the time the frame takes to arrive, so the lights pulse in step with the editor.
      const frame = previewFrame(this.req, d.id, d.info?.leds?.count ?? 0, editorPulse(Date.now() + this.sender.delay(d.id)));
      this.sender.send(d, frame);
    }
  }
}
