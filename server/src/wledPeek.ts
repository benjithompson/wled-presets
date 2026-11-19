import WebSocket from 'ws';
import { baseUrl, type Endpoint } from './wled.ts';

/** How long to wait before connecting again after the device closed the connection. */
const RETRY_MS = 5000;
/** Live colors that stopped coming this long ago are asked for again (WLED's own page may have taken them). */
const ASK_AGAIN_MS = 5000;

/**
 * Watches what a WLED device shows, over its WebSocket (what WLED's own page uses for "Peek"):
 * its LED colors a few times a second, after its brightness, and its state (on, brightness)
 * whenever it changes. It reconnects until closed.
 */
export class WledPeek {
  /** RGB per sampled LED (WLED sends every `step`th LED of a long strip), or null before the first. */
  leds: Uint8Array | null = null;
  /** Device LEDs per sample. */
  step = 1;
  /** When the last colors came (Date.now()). */
  at = 0;
  /** The device's state, from its last message. Null until it said. */
  on: boolean | null = null;
  bri: number | null = null;

  private ws: WebSocket | null = null;
  private live = true;
  private askedAt = 0;
  private retry: NodeJS.Timeout | null = null;
  private closed = false;
  private ep: Endpoint;
  private ledCount: () => number;

  /** `ledCount`: the device's LED count (from its info), to know how many LEDs a sample stands for. */
  constructor(ep: Endpoint, ledCount: () => number) {
    this.ep = ep;
    this.ledCount = ledCount;
    this.connect();
  }

  /**
   * Live colors on or off. Off while the server sends the device frames: it knows the colors
   * already, and the device has less to do.
   */
  setLive(live: boolean) {
    const now = Date.now();
    if (live !== this.live) {
      this.live = live;
      this.ask(live);
    } else if (live && now - this.at > ASK_AGAIN_MS && now - this.askedAt > ASK_AGAIN_MS) this.ask(true);
  }

  close() {
    this.closed = true;
    if (this.retry) clearTimeout(this.retry);
    this.ws?.terminate();
    this.ws = null;
  }

  private ask(live: boolean) {
    this.askedAt = Date.now();
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify({ lv: live }));
  }

  private connect() {
    if (this.closed) return;
    const ws = new WebSocket(`${baseUrl(this.ep).replace(/^http/, 'ws')}/ws`, { handshakeTimeout: 3000, maxPayload: 64 * 1024 });
    this.ws = ws;
    ws.on('open', () => this.live && this.ask(true));
    ws.on('message', (data, isBinary) => {
      const buf = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data);
      if (isBinary) this.onLeds(buf);
      else this.onState(buf.toString());
    });
    ws.on('error', () => {});
    ws.on('close', () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.leds = null;
      if (!this.closed) {
        this.retry = setTimeout(() => this.connect(), RETRY_MS);
        this.retry.unref?.();
      }
    });
  }

  /** "L", a version (1: a strip; 2: a matrix, with its width and height), then RGB per LED. */
  private onLeds(buf: Buffer) {
    if (buf.length < 2 || buf[0] !== 0x4c) return;
    const start = buf[1] === 2 ? 4 : 2;
    const count = Math.floor((buf.length - start) / 3);
    if (count <= 0) return;
    this.leds = Uint8Array.from(buf.subarray(start, start + count * 3));
    this.step = Math.max(1, Math.ceil(this.ledCount() / count));
    this.at = Date.now();
  }

  private onState(text: string) {
    try {
      const j = JSON.parse(text);
      const st = j?.state ?? j;
      if (typeof st?.on === 'boolean') this.on = st.on;
      if (typeof st?.bri === 'number') this.bri = st.bri;
    } catch {
      /* not JSON */
    }
  }
}
