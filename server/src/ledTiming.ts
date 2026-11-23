import type { DeviceInfo } from '../../shared/types.ts';

/**
 * How fast a WLED device can show frames. One-wire LED strips (WS2811, WS2812B, SK6812…) take
 * every bit of every LED in turn, at 800 kHz: a 1,000-LED output needs 30 ms per frame, so it
 * shows at most about 33 frames a second. Frames sent faster are thrown away by the device,
 * but they still take Wi-Fi airtime and room in its network buffer, where a lost packet shows
 * part of the strip a frame late. WLED drives its outputs side by side, so the longest output
 * sets the pace.
 */

/** The fastest any device is sent frames: the pipeline's own rate. */
export const MAX_FPS = 60;
/** The time between frames that WLED and the LEDs need on top of the data (latch), in µs. */
const LATCH_US = 300;

/** Bits per LED, and µs per bit, of WLED's LED types (bus types in /json/cfg). */
function wire(type: number): { bits: number; bitUs: number } | null {
  // 16–39: one-wire digital strips. Others (analog PWM, two-wire SPI, network) are not limited
  // by a data line clocked at 800 kHz.
  if (type < 16 || type > 39) return null;
  if (type === 24) return { bits: 24, bitUs: 2.5 }; // WS2811 at 400 kHz
  if (type === 30 || type === 31) return { bits: 32, bitUs: 1.25 }; // RGBW: SK6812, TM1814
  if (type === 26) return { bits: 48, bitUs: 1.25 }; // UCS8903, 16 bits a color
  if (type === 29) return { bits: 64, bitUs: 1.25 }; // UCS8904, 16-bit RGBW
  return { bits: 24, bitUs: 1.25 };
}

/**
 * The most frames a second a device can show, from its outputs (see DeviceInfo.outputs). With
 * the outputs unknown, all its LEDs count as one WS2812B output, which is the usual setup.
 */
export function maxFps(info: DeviceInfo | null | undefined): number {
  const outputs = info?.outputs?.length ? info.outputs : info?.leds?.count ? [{ len: info.leds.count, type: 22 }] : [];
  let us = 0;
  for (const o of outputs) {
    const w = wire(o.type);
    if (w) us = Math.max(us, o.len * w.bits * w.bitUs);
  }
  return us ? Math.min(MAX_FPS, 1e6 / (us + LATCH_US)) : MAX_FPS;
}

/**
 * How many frames a second a device is sent: every frame of the pipeline's clock, or, for one
 * that cannot show them all, every second, third… frame, the most it can show. Sending 54 of
 * 60 would skip frames at uneven gaps, and WLED shows such frames unevenly too (it waits until
 * its strip is done), so the lights judder; it would also take Wi-Fi airtime that a device with
 * a weak signal does not have. An even 30 looks smooth, with half the packets.
 */
export function sendFps(info: DeviceInfo | null | undefined): number {
  const fps = maxFps(info);
  // Within a frame or two of the clock (outputs side by side, a tolerance in the estimate): all.
  if (fps >= MAX_FPS - 2) return MAX_FPS;
  return MAX_FPS / Math.ceil(MAX_FPS / fps);
}
