import type { OutputInfo } from '../../../shared/layout.ts';
import { DDP_PORT } from '../realtime.ts';
import type { DeviceMap, FramePipeline, FrameSource } from '../framePipeline.ts';

/**
 * Games on the real lights: the debug panel's switch and brightness, and what it shows about
 * the devices. The frames themselves go through the FramePipeline, like every other source.
 */
export class GameOutput {
  /** On by default: a running game shows on the real lights. The debug panel can turn it off. */
  enabled = true;
  /** 0.05..1, for every game frame (scenes have their own brightness per effect). */
  brightness = 0.5;
  private pipeline: FramePipeline;
  private source: FrameSource;
  private maps: () => readonly DeviceMap[];
  private simOnly: () => string[];

  constructor(pipeline: FramePipeline, source: FrameSource, maps: () => readonly DeviceMap[], simOnly: () => string[]) {
    this.pipeline = pipeline;
    this.source = source;
    this.maps = maps;
    this.simOnly = simOnly;
  }

  /** Names of the devices that show the game or scene now. */
  targets(): string[] {
    return this.pipeline.targets(this.source);
  }

  info(): OutputInfo {
    const all = this.pipeline.deviceList();
    const owner = this.pipeline.owner;
    return {
      enabled: this.enabled,
      brightness: this.brightness,
      // An editor shows its preview on the lights: game frames wait.
      paused: !!owner && owner !== this.source,
      framesSent: this.pipeline.framesSent(this.source),
      devices: this.maps().map((m) => {
        const d = all.find((x) => x.id === m.deviceId);
        return {
          id: m.deviceId,
          name: d?.name ?? 'Unknown device',
          host: d?.host ?? '',
          ddpPort: d?.info?.ddpport ?? DDP_PORT,
          online: !!(d as { online?: boolean | null } | undefined)?.online,
          mappedLeds: m.pairs.length / 2,
          link: this.pipeline.link(m.deviceId),
          objects: m.objects
        };
      }),
      simulationOnly: this.simOnly()
    };
  }
}
