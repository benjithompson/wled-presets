import { describe, expect, it } from 'vitest';
import { bytes, clamp, ease, fromHex, hex, hsv, hsvBytes, mix, mix8, parseHex, scale8, seededRandom, smooth, toBytes } from '../../shared/color.ts';

describe('the colour kit', () => {
  it('makes hues, wrapping round', () => {
    expect(hsv(0)).toEqual([1, 0, 0]);
    expect(hsv(1 / 3)).toEqual([0, 1, 0]);
    expect(hsv(-1 / 3)).toEqual(hsv(2 / 3));
    expect(hsv(0, 0, 0.5)).toEqual([0.5, 0.5, 0.5]);
    expect(hsvBytes(2 / 3, 0.5)).toEqual([0, 0, 128]);
  });

  it('turns colors into bytes and hex, clamped, and back', () => {
    expect(bytes([1.4, 0.5, -1])).toEqual([255, 128, 0]);
    expect(hex([1, 0.5, 0])).toBe('#ff8000');
    expect(fromHex('#ff8000')).toEqual([1, 128 / 255, 0]);
    expect(fromHex('nope')).toEqual([0, 0, 0]);
    expect(parseHex(' ff8800 ')).toEqual([255, 136, 0]);
    expect(parseHex('#abc')).toBeNull();
  });

  it('mixes and scales byte colors, rounded', () => {
    expect(mix([0, 0, 0], [1, 1, 1], 0.25)).toEqual([0.25, 0.25, 0.25]);
    expect(mix8([0, 0, 0], [255, 100, 3], 0.5)).toEqual([128, 50, 2]);
    expect(scale8([40, 170, 255], 0.3)).toEqual([12, 51, 77]);
  });

  it('gives a frame a soft shoulder above 0.8', () => {
    expect([...toBytes(new Float32Array([-1, 0.5, 0.8, 1.5, 3]), new Uint8Array(5))]).toEqual([0, 128, 204, 255, 255]);
  });

  it('eases and clamps', () => {
    expect([ease(0), ease(0.5), ease(1)]).toEqual([0, 0.5, 1]);
    expect([smooth(2, 4, 1), smooth(2, 4, 3), smooth(2, 4, 5)]).toEqual([0, 0.5, 1]);
    expect([clamp(-1, 0, 2), clamp(3, 0, 2)]).toEqual([0, 2]);
  });

  it('gives the same random numbers for the same seed', () => {
    const a = seededRandom(7);
    const b = seededRandom(7);
    const xs = [a(), a(), a()];
    expect([b(), b(), b()]).toEqual(xs);
    expect(xs.every((x) => x >= 0 && x < 1)).toBe(true);
    expect(seededRandom(0)()).toBe(seededRandom(1)());
  });
});
