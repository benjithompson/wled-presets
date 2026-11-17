import { deviceLed, editorPulse, paintEditor, type Layout } from '../../shared/layout.ts';
import type { Device, DeviceInfo } from '../../shared/types.ts';
import type { LightSender } from './lightSender.ts';

/** Often enough that a changed number shows on the lights at once. */
const TICK_MS = 50;
/** The preview stops when the editor has not refreshed it for this long. */
const EXPIRE_MS = 8_000;

export interface PreviewRequest {
  layout: Layout;
  selected: string | null;
  corner: number | null;
  /** Roof only: the selected segment (between point k and point k + 1). */
  segment?: number | null;
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

  constructor(devices: () => (Device & { info: DeviceInfo | null })[], log: (msg: string) => void, sender: LightSender) {
    this.devices = devices;
    this.sender = sender;
    this.log = log;
  }

  /** Starts or updates the preview. Returns the names of the devices it lights. */
  show(req: PreviewRequest): string[] {
    const started = !this.req;
    this.req = req;
    this.until = Date.now() + EXPIRE_MS;
    if (!this.timer) this.timer = setInterval(() => this.send(), TICK_MS);
    this.send();
    const names = this.targets().map((d) => d.name);
    if (started && names.length) this.log(`Layout preview on the lights started (${names.join(', ')})`);
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
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    // Put each device's own color, scene or preset back at once.
    for (const d of targets) this.sender.end(d);
    this.log('Layout preview on the lights stopped');
  }

  close() {
    this.stop();
  }

  private targets() {
    const ids = new Set(this.req?.layout.fixtures.map((f) => f.deviceId).filter(Boolean));
    return this.devices().filter((d) => d.enabled && ids.has(d.id));
  }

  private send() {
    if (!this.req) return;
    if (Date.now() > this.until) return this.stop();
    for (const d of this.targets()) {
      // Draw ahead by the time the frame takes to arrive, so the lights pulse in step with the editor.
      const frame = previewFrame(this.req, d.id, d.info?.leds?.count ?? 0, editorPulse(Date.now() + this.sender.delay(d.id)));
      this.sender.send(d, frame);
    }
  }
}
