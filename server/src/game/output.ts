import { deviceLed, type Layout, type OutputInfo, type Stage } from '../../../shared/layout.ts';
import type { Device, DeviceInfo } from '../../../shared/types.ts';
import { LightSender } from '../lightSender.ts';
import { DDP_PORT } from '../realtime.ts';

type DeviceWithInfo = Device & { info: DeviceInfo | null };

/** Where the LEDs of a stage go on one device. Built once per stage, used on every frame. */
export interface DeviceMap {
  deviceId: string;
  /** One past the highest device LED number used. */
  size: number;
  /** Pairs of (stage LED index, device LED number). */
  pairs: Int32Array;
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

/**
 * One device's colors from a stage frame (RGB bytes in stage order), times `k`: the whole strip
 * from LED 0, so LEDs that no object uses (gaps, a hidden side) stay off. `buf` is reused when
 * it has the right size.
 */
export function deviceFrame(m: DeviceMap, frame: Uint8Array, ledCount: number, k = 1, buf?: Uint8Array): Uint8Array {
  const size = Math.max(m.size, ledCount);
  if (!buf || buf.length !== size * 3) buf = new Uint8Array(size * 3);
  const pairs = m.pairs;
  for (let p = 0; p < pairs.length; p += 2) {
    const src = pairs[p] * 3;
    const dst = pairs[p + 1] * 3;
    buf[dst] = frame[src] * k;
    buf[dst + 1] = frame[src + 1] * k;
    buf[dst + 2] = frame[src + 2] * k;
  }
  return buf;
}

/**
 * Debug mode: sends the game frames to the real WLED devices with real-time UDP, using each
 * object's device and LED numbers. It is off after every server start. The devices go back
 * to normal by themselves 2 seconds after the frames stop.
 */
export class LightsOutput {
  /** On by default: a running game shows on the real lights. The debug panel can turn it off. */
  enabled = true;
  /** Devices that got frames since the last release. */
  private sending = new Set<string>();
  brightness = 0.5;
  private framesSent = 0;
  private maps: DeviceMap[] = [];
  private simOnly: string[] = [];
  private buffers = new Map<string, Uint8Array>();
  private sender: LightSender;
  private devices: () => DeviceWithInfo[];
  private paused: () => boolean;

  constructor(devices: () => DeviceWithInfo[], paused: () => boolean = () => false, sender = new LightSender()) {
    this.devices = devices;
    this.paused = paused;
    this.sender = sender;
  }

  setStage(layout: Layout, stage: Stage) {
    this.simOnly = layout.fixtures.filter((f) => !f.deviceId).map((f) => f.name);
    this.maps = deviceMaps(layout, stage);
    this.buffers.clear();
  }

  /**
   * Called by the game loop with every frame (RGB bytes in stage order). `active`: a game is
   * running. With no game, nothing goes to the lights, and they show their own color or scene.
   */
  push(frame: Uint8Array, active = true) {
    if (!this.enabled || !active || this.paused()) {
      // The layout editor's preview owns the lights while it runs; do not end its stream.
      if (!this.paused()) this.release();
      return;
    }
    this.send(frame, null, this.brightness);
  }

  /**
   * A scene's effects: to the devices in `devices` only (the others play their own preset), at
   * full brightness (each effect has its own). The debug switch is for games and does not apply.
   */
  pushScene(frame: Uint8Array, devices: ReadonlySet<string>) {
    if (this.paused()) return;
    this.send(frame, devices, 1);
  }

  /** Every frame of the game loop goes out: WLED shows the newest frame it has. */
  private send(frame: Uint8Array, only: ReadonlySet<string> | null, k: number) {
    const devices = new Map(this.devices().map((d) => [d.id, d]));
    // A device that no longer takes part goes back to its own state at once.
    if (only) {
      for (const id of [...this.sending]) {
        if (only.has(id)) continue;
        const d = devices.get(id);
        if (d) this.sender.end(d);
        this.sending.delete(id);
      }
    }
    for (const m of this.maps) {
      if (only && !only.has(m.deviceId)) continue;
      const d = devices.get(m.deviceId);
      if (!d || !d.enabled) continue;
      const buf = deviceFrame(m, frame, d.info?.leds?.count ?? 0, k, this.buffers.get(m.deviceId));
      this.buffers.set(m.deviceId, buf);
      this.sender.send(d, buf);
      this.sending.add(d.id);
    }
    this.framesSent++;
  }

  /** Stops sending and puts each device's own color, scene or preset back at once. */
  release() {
    if (!this.sending.size) return;
    const devices = this.devices();
    for (const id of this.sending) {
      const d = devices.find((x) => x.id === id);
      if (d) this.sender.end(d);
    }
    this.sending.clear();
  }

  /** Names of the devices that get frames now. */
  targets(): string[] {
    if (!this.sending.size) return [];
    return this.devices()
      .filter((d) => d.enabled && this.sending.has(d.id))
      .map((d) => d.name);
  }

  info(): OutputInfo {
    const all = this.devices();
    return {
      enabled: this.enabled,
      brightness: this.brightness,
      paused: this.paused(),
      framesSent: this.framesSent,
      devices: this.maps.map((m) => {
        const d = all.find((x) => x.id === m.deviceId);
        return {
          id: m.deviceId,
          name: d?.name ?? 'Unknown device',
          host: d?.host ?? '',
          ddpPort: d?.info?.ddpport ?? DDP_PORT,
          online: !!(d as { online?: boolean | null } | undefined)?.online,
          mappedLeds: m.pairs.length / 2,
          link: this.sender.status(m.deviceId),
          objects: m.objects
        };
      }),
      simulationOnly: this.simOnly
    };
  }

  close() {
    this.sender.close();
  }
}
