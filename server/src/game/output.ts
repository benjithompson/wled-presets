import { deviceLed, type Layout, type OutputInfo, type Stage } from '../../../shared/layout.ts';
import type { Device, DeviceInfo } from '../../../shared/types.ts';
import { LightSender } from '../lightSender.ts';
import { DDP_PORT } from '../realtime.ts';

/**
 * Frames per second sent to the lights: every game frame. WLED shows the newest frame it has,
 * so sending faster than it can draw adds no delay.
 */
const OUTPUT_HZ = 60;

type DeviceWithInfo = Device & { info: DeviceInfo | null };

interface DeviceMap {
  deviceId: string;
  size: number;
  /** Pairs of (stage LED index, device LED number). */
  pairs: Int32Array;
  objects: string[];
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
  private lastSend = 0;
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
    const byDevice = new Map<string, DeviceMap & { list: number[] }>();
    this.simOnly = [];
    layout.fixtures.forEach((f, fi) => {
      if (!f.deviceId) {
        this.simOnly.push(f.name);
        return;
      }
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
    this.maps = [...byDevice.values()].map(({ list, ...m }) => ({ ...m, pairs: Int32Array.from(list) }));
    this.buffers.clear();
  }

  /** Called by the game loop with every frame (RGB bytes in stage order). */
  /**
   * Called by the game loop with every frame. `active`: a game is running. With no game (the
   * idle animation), nothing goes to the lights, and they show their own color or scene.
   */
  push(frame: Uint8Array, active = true) {
    if (!this.enabled || !active || this.paused()) {
      // The layout editor's preview owns the lights while it runs; do not end its stream.
      if (!this.paused()) this.release();
      return;
    }
    const now = performance.now();
    if (now - this.lastSend < 1000 / OUTPUT_HZ - 2) return;
    this.lastSend = now;
    const devices = new Map(this.devices().map((d) => [d.id, d]));
    const k = this.brightness;
    for (const m of this.maps) {
      const d = devices.get(m.deviceId);
      if (!d || !d.enabled) continue;
      // Send the whole strip, so LEDs no object uses (gaps, a hidden side) stay off.
      const size = Math.max(m.size, d.info?.leds?.count ?? 0);
      let buf = this.buffers.get(m.deviceId);
      if (!buf || buf.length !== size * 3) this.buffers.set(m.deviceId, (buf = new Uint8Array(size * 3)));
      for (let p = 0; p < m.pairs.length; p += 2) {
        const src = m.pairs[p] * 3;
        const dst = m.pairs[p + 1] * 3;
        buf[dst] = frame[src] * k;
        buf[dst + 1] = frame[src + 1] * k;
        buf[dst + 2] = frame[src + 2] * k;
      }
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
    if (!this.enabled || !this.sending.size) return [];
    const ids = new Set(this.maps.map((m) => m.deviceId));
    return this.devices()
      .filter((d) => d.enabled && ids.has(d.id))
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
