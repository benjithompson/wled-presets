import dgram from 'node:dgram';

/** WLED's default port for real-time UDP (Settings → Sync Interfaces). */
export const WLED_UDP_PORT = 21324;
/** The standard DDP port. */
export const DDP_PORT = 4048;
/** DDP: 480 RGB LEDs (1440 bytes) per packet, as WLED and xLights use. */
const DDP_MAX_BYTES = 1440;
const DDP_VERSION_1 = 0x40;
const DDP_PUSH = 0x01;
const DDP_TYPE_RGB24 = 0x0b;
const DDP_ID_DISPLAY = 0x01;
/** DNRGB: protocol 4, up to 489 LEDs per packet, with a start index. */
const DNRGB = 4;
const MAX_PER_PACKET = 489;

/**
 * Sends LED colors to WLED devices with the real-time UDP protocol (DNRGB). The device shows
 * the colors at once and goes back to its normal state by itself `timeoutSec` seconds after
 * the last packet, so nothing is saved on the device.
 */
export class RealtimeOut {
  private socket = dgram.createSocket('udp4');
  private seq = 0;

  constructor() {
    this.socket.on('error', () => {});
    this.socket.unref();
  }

  /** `rgb` holds one byte triple per LED, starting at device LED 0. */
  send(host: string, port: number, rgb: Uint8Array, timeoutSec = 2) {
    const count = Math.floor(rgb.length / 3);
    for (let start = 0; start < count; start += MAX_PER_PACKET) {
      const n = Math.min(MAX_PER_PACKET, count - start);
      const packet = Buffer.alloc(4 + n * 3);
      packet[0] = DNRGB;
      packet[1] = Math.max(1, Math.min(255, timeoutSec));
      packet[2] = start >> 8;
      packet[3] = start & 0xff;
      packet.set(rgb.subarray(start * 3, (start + n) * 3), 4);
      this.socket.send(packet, port, host);
    }
  }

  /**
   * Sends one frame with DDP. A frame larger than one packet goes out in several packets; only
   * the last one carries the "push" flag, so the device shows the whole frame at once and a
   * long strip never shows half an old frame. The device returns to normal by itself after
   * its real-time timeout (WLED: 2.5 s by default).
   */
  sendDdp(host: string, port: number, rgb: Uint8Array) {
    this.seq = (this.seq % 15) + 1;
    for (let offset = 0; offset < rgb.length; offset += DDP_MAX_BYTES) {
      const len = Math.min(DDP_MAX_BYTES, rgb.length - offset);
      const last = offset + len >= rgb.length;
      const packet = Buffer.alloc(10 + len);
      packet[0] = DDP_VERSION_1 | (last ? DDP_PUSH : 0);
      packet[1] = this.seq;
      packet[2] = DDP_TYPE_RGB24;
      packet[3] = DDP_ID_DISPLAY;
      packet.writeUInt32BE(offset, 4);
      packet.writeUInt16BE(len, 8);
      packet.set(rgb.subarray(offset, offset + len), 10);
      this.socket.send(packet, port, host);
    }
  }

  close() {
    try {
      this.socket.close();
    } catch {}
  }
}
