import { EffectScene, layoutEffects, toBytes } from '../../shared/effects.ts';
import { buildStage, deviceLed, editorPulse, paintEditor, paintGameArea, paintMatch, type GameArea, type Layout, type MatchProbe, type Stage } from '../../shared/layout.ts';
import { SequencePlayer, type Sequence } from '../../shared/sequence.ts';
import type { Device, DeviceInfo } from '../../shared/types.ts';
import { FrameLoop } from './frameLoop.ts';
import { deviceFrame, deviceMaps, type DeviceMap } from './game/output.ts';
import type { LightSender } from './lightSender.ts';

/** Often enough that a changed number shows on the lights at once. */
const TICK_HZ = 20;
/** While the effects play: every frame, as smooth as a scene. */
const PLAY_TICK_HZ = 60;
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
}

/** The sequence editor's preview: a sequence, the time the editor shows, and whether it plays. */
export interface SequencePreviewRequest {
  sequence: Sequence;
  time: number;
  playing: boolean;
}

/** Colors for one device: the editor's view (see paintEditor), mapped to the device's LED numbers. */
export function previewFrame(req: PreviewRequest, deviceId: string, ledCount: number, pulse: boolean): Uint8Array {
  const fixtures = req.layout.fixtures.filter((f) => f.deviceId === deviceId);
  const matched = req.probe && req.selected ? req.layout.fixtures.find((f) => f.id === req.selected && f.deviceId === deviceId) : undefined;
  // The wizard's blinking LED can sit past the end of its line.
  const probeLed = matched && req.probe ? deviceLed(matched, req.probe.offset) : -1;
  const size = Math.max(ledCount, probeLed + 1, ...fixtures.map((f) => f.startPixel + f.pixels));
  const out = new Uint8Array(size * 3);
  const put = (fi: number, i: number, rgb: [number, number, number]) => {
    const f = req.layout.fixtures[fi];
    if (f.deviceId !== deviceId) return;
    const led = deviceLed(f, i);
    if (led >= 0 && led < size) out.set(rgb, led * 3);
  };
  if (req.probe && req.selected) paintMatch(req.layout, req.selected, req.probe, pulse, put);
  else if (req.area !== undefined) paintGameArea(req.layout, req.area, req.selected ? { id: req.selected, segment: req.segment ?? null } : null, pulse, put);
  else paintEditor(req.layout, req.selected, req.corner, req.segment ?? null, pulse, put);
  return out;
}

/** Shows the layout being edited on the real lights, while the editor asks for it. */
export class LayoutPreview {
  private req: PreviewRequest | null = null;
  private until = 0;
  private loop = new FrameLoop(() => this.send(), TICK_HZ);
  private sender: LightSender;

  private devices: () => (Device & { info: DeviceInfo | null })[];
  private log: (msg: string) => void;
  /** While the effects play: the stage, the running effects, and the last frame's time. */
  private fx: { key: string; stage: Stage; scene: EffectScene; data: Float32Array; bytes: Uint8Array; last: number } | null = null;
  /** The sequence editor's preview: the player, and whether it plays or shows one moment. */
  private seq: { key: string; player: SequencePlayer; stage: Stage; data: Float32Array; bytes: Uint8Array; playing: boolean; last: number } | null = null;
  /** While effects or a sequence play: where their stage's LEDs go on each device, and each device's frame. */
  private maps = new Map<string, DeviceMap>();
  private buffers = new Map<string, Uint8Array>();

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
      this.seq = { key, player, stage, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3), playing: req.playing, last: performance.now() };
    } else {
      cur.player.setSequence(req.sequence);
      // Small differences are the network delay; only a jump (or a paused editor) moves the clock.
      if (!req.playing || !cur.playing || Math.abs(cur.player.time - req.time) > 0.25) cur.player.seek(req.time, req.playing ? 2.5 : 1);
      cur.playing = req.playing;
      cur.last = performance.now();
    }
    this.fx = null;
    this.mapStage(layout, this.seq!.stage);
    return this.start({ layout, selected: null, corner: null, play: true });
  }

  private start(req: PreviewRequest): string[] {
    const started = !this.req;
    this.req = req;
    this.until = Date.now() + EXPIRE_MS;
    if (this.seq) this.fx = null;
    else if (req.play) this.syncEffects(req.layout);
    else this.fx = null;
    this.loop.setRate(req.play ? PLAY_TICK_HZ : TICK_HZ);
    this.loop.start();
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
    this.loop.stop();
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
    // The stage stays across edits, but LED numbers or devices may have changed.
    this.mapStage(layout, this.fx.stage);
  }

  /** Where the playing stage's LEDs go on each device: once per request, not on every frame. */
  private mapStage(layout: Layout, stage: Stage) {
    this.maps = new Map(deviceMaps(layout, stage).map((m) => [m.deviceId, m]));
    // A reused frame would keep the colors of LEDs that are no longer mapped.
    this.buffers.clear();
  }

  /** Sends a whole stage frame (RGB bytes in stage order) to every device of the preview. */
  private sendStage(bytes: Uint8Array) {
    for (const d of this.targets()) {
      const m = this.maps.get(d.id);
      if (!m) continue;
      const buf = deviceFrame(m, bytes, d.info?.leds?.count ?? 0, 1, this.buffers.get(d.id));
      this.buffers.set(d.id, buf);
      this.sender.send(d, buf);
    }
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
      this.sendStage(sq.bytes);
      return;
    }
    const fx = this.fx;
    if (fx) {
      const now = performance.now();
      // As in a scene: a stall (a busy server) does not make the effects jump ahead.
      fx.scene.update(Math.min(0.1, (now - fx.last) / 1000), fx.data);
      fx.last = now;
      toBytes(fx.data, fx.bytes);
      this.sendStage(fx.bytes);
      return;
    }
    for (const d of this.targets()) {
      // Draw ahead by the time the frame takes to arrive, so the lights pulse in step with the editor.
      const frame = previewFrame(this.req, d.id, d.info?.leds?.count ?? 0, editorPulse(Date.now() + this.sender.delay(d.id)));
      this.sender.send(d, frame);
    }
  }
}
