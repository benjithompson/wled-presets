import { buildStage, deviceLed, type Layout, type Stage } from '../../shared/layout.ts';
import { FrameLoop } from './frameLoop.ts';
import { takesFrames, type DeviceTarget, type LightSender } from './lightSender.ts';
import { isHaId } from '../../shared/homeAssistant.ts';

/**
 * Where the color of a Home Assistant light goes (see HaFrames): one color for each frame, the
 * mix of its objects' LEDs, or null when it no longer gets frames. `wakes`: see LightFrame.
 */
export type HaSink = (id: string, rgb: [number, number, number] | null, wakes: boolean) => void;

/** The mean color of a device map's LEDs in a frame (a Home Assistant light shows one color). */
export function meanColor(frame: LightFrame, m: DeviceMap): [number, number, number] {
  const { bytes, k = 1 } = frame;
  let r = 0;
  let g = 0;
  let b = 0;
  const n = m.pairs.length / 2;
  for (let p = 0; p < m.pairs.length; p += 2) {
    const src = m.pairs[p] * 3;
    r += bytes[src];
    g += bytes[src + 1];
    b += bytes[src + 2];
  }
  return n ? [Math.round((r / n) * k), Math.round((g / n) * k), Math.round((b / n) * k)] : [0, 0, 0];
}

/**
 * The one way frames reach the lights. Everything that draws (games, scenes, the layout and
 * sequence editors) is a FrameSource. One clock ticks every source that runs, and the frame of
 * the most important source that has one goes to the devices: the editors over a game, a game
 * over a scene. A device that stops getting frames is given back at once (it shows its own
 * color, scene or preset); a device that passes from one source to another just keeps going.
 */

/** Frames per second. */
export const FRAME_HZ = 60;
/** Which source wins the lights: the higher. */
export const PRIORITY = {
  /** Games and scenes. */
  show: 0,
  /** The layout, games and sequence editors' previews. */
  editor: 10
} as const;
/** The longest step a source is asked to take: after a stall, animations do not jump ahead. */
const MAX_DT = 0.05;

/** Where the LEDs of a stage go on one device. Built once per stage, used on every frame. */
export interface DeviceMap {
  deviceId: string;
  /** One past the highest device LED number used. */
  size: number;
  /** Pairs of (stage LED index, device LED number). */
  pairs: Int32Array;
  /** Names of the objects on the device. */
  objects: string[];
}

/** One DeviceMap for each device that drives an object of the layout. */
export function deviceMaps(layout: Layout, stage: Stage): DeviceMap[] {
  const byDevice = new Map<string, DeviceMap & { list: number[] }>();
  layout.fixtures.forEach((f, fi) => {
    if (!f.deviceId) return;
    const s = stage.fixtures[fi];
    const m = byDevice.get(f.deviceId) ?? { deviceId: f.deviceId, size: 0, pairs: new Int32Array(), objects: [], list: [] };
    for (let i = 0; i < s.count; i++) {
      const led = deviceLed(f, i);
      m.list.push(s.offset + i, led);
      m.size = Math.max(m.size, led + 1);
    }
    m.objects.push(f.name);
    byDevice.set(f.deviceId, m);
  });
  return [...byDevice.values()].map(({ list, ...m }) => ({ ...m, pairs: Int32Array.from(list) }));
}

const outputs = new WeakMap<Layout, { stage: Stage; maps: DeviceMap[] }>();

/**
 * A layout as the lights need it: its stage, and where the stage's LEDs go on each device.
 * Built once for each layout: the game host and the roof view share the yard's.
 */
export function layoutOutput(layout: Layout): { stage: Stage; maps: DeviceMap[] } {
  let out = outputs.get(layout);
  if (!out) {
    const stage = buildStage(layout);
    outputs.set(layout, (out = { stage, maps: deviceMaps(layout, stage) }));
  }
  return out;
}

/** One LED set by device number, outside the stage (the layout wizard's LED past a line's end). */
export interface ExtraLed {
  deviceId: string;
  led: number;
  rgb: readonly [number, number, number];
}

/** What a source shows on the lights for one frame. */
export interface LightFrame {
  /** Where the stage's LEDs go (see deviceMaps). */
  maps: readonly DeviceMap[];
  /** RGB bytes in stage order. */
  bytes: Uint8Array;
  /** Brightness factor. Default: 1. */
  k?: number;
  /** Only these devices get the frame; the others are left to their own state. Default: all. */
  devices?: ReadonlySet<string>;
  /** LEDs set by device number, after the stage's. */
  extra?: readonly ExtraLed[];
  /**
   * Lights switched off by an admin get the frame too (an editor's preview, which the admin
   * turned on to see it on the lights). They go off again after. Default: they stay off.
   */
  wakes?: boolean;
}

/**
 * One device's colors for a frame: the whole strip from LED 0, so LEDs that no object uses
 * (gaps, a hidden side) stay off. `buf` is reused when it has the right size.
 */
export function renderDevice(frame: LightFrame, m: DeviceMap, ledCount: number, buf?: Uint8Array): Uint8Array {
  let size = Math.max(m.size, ledCount);
  if (frame.extra) for (const e of frame.extra) if (e.deviceId === m.deviceId) size = Math.max(size, e.led + 1);
  if (!buf || buf.length !== size * 3) buf = new Uint8Array(size * 3);
  else buf.fill(0);
  const { bytes, k = 1 } = frame;
  const pairs = m.pairs;
  for (let p = 0; p < pairs.length; p += 2) {
    const src = pairs[p] * 3;
    const dst = pairs[p + 1] * 3;
    buf[dst] = bytes[src] * k;
    buf[dst + 1] = bytes[src + 1] * k;
    buf[dst + 2] = bytes[src + 2] * k;
  }
  if (frame.extra) for (const e of frame.extra) if (e.deviceId === m.deviceId && e.led >= 0) buf.set(e.rgb, e.led * 3);
  return buf;
}

/** Something that draws frames. */
export interface FrameSource {
  /** True while it needs ticks (the clock stops when no source does). */
  readonly running: boolean;
  /**
   * Advances by `dt` seconds and returns what to show on the lights, or null for nothing.
   * `showAt` (a Date.now() time) is when the frame will show on the slowest device: an
   * animation that must keep time with a clock (the editor's blink) draws for that moment.
   */
  tick(dt: number, showAt: number): LightFrame | null;
}

export class FramePipeline {
  private loop = new FrameLoop(() => this.tick(), FRAME_HZ);

  /** The clock's rate (see frameClock): sources move by the time between frames, so they keep their pace. */
  setRate(hz: number) {
    this.loop.setRate(hz);
  }
  /** Most important first. */
  private sources: { source: FrameSource; priority: number }[] = [];
  private devices: () => DeviceTarget[];
  private sender: LightSender;
  private last = 0;
  /** Devices that got the last frame, and the source it came from. */
  private sending = new Set<string>();
  private ownerOf: FrameSource | null = null;
  private buffers = new Map<string, Uint8Array>();
  private sent = new WeakMap<FrameSource, number>();
  /** Home Assistant lights in the layout get their color here (see HaSink). */
  haSink: HaSink | null = null;
  private haSending = new Set<string>();

  constructor(devices: () => DeviceTarget[], sender: LightSender) {
    this.devices = devices;
    this.sender = sender;
  }

  /** Adds a source. Of the sources with a frame, the one with the highest priority gets the lights. */
  add(source: FrameSource, priority: number = PRIORITY.show) {
    this.sources = [...this.sources, { source, priority }].sort((a, b) => b.priority - a.priority);
  }

  remove(source: FrameSource) {
    this.sources = this.sources.filter((s) => s.source !== source);
    this.wake();
  }

  /** A source started running, or stopped and may have to give its devices back: tick again. */
  wake() {
    if (this.loop.running) return;
    this.last = performance.now();
    this.loop.start();
  }

  /** The source whose frame the lights showed last, or null. */
  get owner(): FrameSource | null {
    return this.ownerOf;
  }

  /** Names of the devices that got the last frame of `source`. */
  targets(source: FrameSource): string[] {
    if (this.ownerOf !== source) return [];
    return this.devices()
      .filter((d) => this.sending.has(d.id))
      .map((d) => d.name);
  }

  /** How many frames of `source` went to the lights. */
  framesSent(source: FrameSource): number {
    return this.sent.get(source) ?? 0;
  }

  /** The devices that drive the lights, as known now. */
  deviceList(): DeviceTarget[] {
    return this.devices();
  }

  /**
   * The colors the device was sent last (one byte triple per device LED, from LED 0), while it
   * gets frames; null when it shows its own state.
   */
  deviceFrame(deviceId: string): Uint8Array | null {
    return this.sending.has(deviceId) ? (this.buffers.get(deviceId) ?? null) : null;
  }

  /** How frames reach a device (see LightSender.status). */
  link(deviceId: string) {
    return this.sender.status(deviceId);
  }

  /** Stops the clock and gives every device back. */
  close() {
    this.loop.stop();
    this.show(null, null);
  }

  private tick() {
    const now = performance.now();
    const dt = Math.min(MAX_DT, (now - this.last) / 1000);
    this.last = now;
    let showAt = Date.now();
    for (const id of this.sending) showAt = Math.max(showAt, Date.now() + this.sender.delay(id));
    let frame: LightFrame | null = null;
    let owner: FrameSource | null = null;
    let running = false;
    // Every running source moves on (a game keeps playing in the browsers while an editor has
    // the lights); the first one with a frame for the lights gets them.
    for (const { source: s } of this.sources) {
      if (!s.running) continue;
      running = true;
      const f = s.tick(dt, showAt);
      if (f && !frame) {
        frame = f;
        owner = s;
      }
    }
    this.show(frame, owner);
    if (!running) this.loop.stop();
  }

  private show(frame: LightFrame | null, owner: FrameSource | null) {
    const devices = new Map(this.devices().map((d) => [d.id, d]));
    const next = new Set<string>();
    const haNext = new Set<string>();
    if (frame) {
      for (const m of frame.maps) {
        if (frame.devices && !frame.devices.has(m.deviceId)) continue;
        if (isHaId(m.deviceId)) {
          if (!this.haSink) continue;
          this.haSink(m.deviceId, meanColor(frame, m), !!frame.wakes);
          haNext.add(m.deviceId);
          continue;
        }
        const d = devices.get(m.deviceId);
        if (!d || !takesFrames(d, frame.wakes)) continue;
        const buf = renderDevice(frame, m, d.info?.leds?.count ?? 0, this.buffers.get(d.id));
        this.buffers.set(d.id, buf);
        this.sender.send(d, buf);
        next.add(d.id);
      }
      if (owner) this.sent.set(owner, (this.sent.get(owner) ?? 0) + 1);
    }
    // A device that no longer gets frames goes back to its own state at once.
    for (const id of this.sending) {
      const d = devices.get(id);
      if (!next.has(id) && d) this.sender.end(d);
    }
    for (const id of this.haSending) if (!haNext.has(id)) this.haSink?.(id, null, false);
    this.haSending = haNext;
    this.sending = next;
    this.ownerOf = next.size || haNext.size ? owner : null;
  }
}
