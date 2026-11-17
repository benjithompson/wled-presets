import { describe, expect, it } from 'vitest';
import { hostsIn, inRanges, parseCidr } from '../src/net.ts';
import { parsePorts } from '../src/config.ts';
import { mergeLooks, presetLook } from '../src/presetLook.ts';
import { baseUrl, hexToRgb, normalizeHost, parsePresets } from '../src/wled.ts';

describe('net', () => {
  it('parses CIDR and normalises the network address', () => {
    expect(parseCidr('192.168.1.77/24')!.label).toBe('192.168.1.0/24');
    expect(parseCidr('10.0.0.0/33')).toBeNull();
    expect(parseCidr('300.0.0.0/24')).toBeNull();
    expect(parseCidr('nonsense')).toBeNull();
  });
  it('lists host addresses without network and broadcast', () => {
    const hosts = hostsIn(parseCidr('192.168.1.0/30')!, 100);
    expect(hosts).toEqual(['192.168.1.1', '192.168.1.2']);
    expect(hostsIn(parseCidr('10.0.0.0/16')!, 10)).toHaveLength(10);
  });
  it('checks membership', () => {
    expect(inRanges('192.168.1.9', [parseCidr('192.168.1.0/24')!])).toBe(true);
    expect(inRanges('192.168.2.9', [parseCidr('192.168.1.0/24')!])).toBe(false);
  });
});

describe('wled helpers', () => {
  it('normalises hosts', () => {
    expect(normalizeHost(' http://10.0.0.5/ ')).toBe('10.0.0.5');
    expect(baseUrl({ host: '10.0.0.5', port: 80 })).toBe('http://10.0.0.5');
    expect(baseUrl({ host: 'tree.local', port: 8080 })).toBe('http://tree.local:8080');
  });
  it('parses presets.json and drops the placeholder entry', () => {
    expect(parsePresets({ '0': {}, '2': { n: 'Fire' }, '1': {} })).toMatchObject([
      { id: 1, name: 'Preset 1' },
      { id: 2, name: 'Fire' }
    ]);
  });
  it('converts hex colors', () => {
    expect(hexToRgb('#ff8800')).toEqual([255, 136, 0]);
    expect(hexToRgb('nope')).toBeNull();
  });
});

describe('discovery ports', () => {
  it('parses lists and ranges', () => {
    expect(parsePorts('80,9101-9103')).toEqual([80, 9101, 9102, 9103]);
    expect(parsePorts('')).toEqual([80]);
    expect(parsePorts('abc,0')).toEqual([80]);
  });
});

describe('preset look', () => {
  it('reads segment colors and treats a solid preset as calm', () => {
    const look = presetLook(1, { '1': { seg: [{ col: [[255, 160, 70], [0, 0, 0]], fx: 0 }] } });
    expect(look.colors).toEqual(['#ffa046']);
    expect(look.energy).toBeLessThan(0.2);
  });
  it('uses palette colors and effect speed', () => {
    const look = presetLook(1, { '1': { seg: [{ col: [[255, 0, 0]], fx: 66, sx: 255, ix: 255, pal: 35 }] } });
    expect(look.colors.length).toBeGreaterThan(2);
    expect(look.energy).toBeGreaterThan(0.9);
  });
  it('blends the white channel of RGBW colors', () => {
    expect(presetLook(1, { '1': { seg: [{ col: [[0, 0, 0, 255]] }] } }).colors[0]).not.toBe('#000000');
  });
  it('follows a playlist to its first preset', () => {
    const all = { '1': { seg: [{ col: [[0, 0, 255]] }] }, '2': { playlist: { ps: [1] } } };
    expect(presetLook(2, all).colors).toEqual(['#0000ff']);
  });
  it('merges scenes across devices and drops near-duplicates', () => {
    const m = mergeLooks([
      { colors: ['#ff0000', '#ffffff'], energy: 0.2 },
      { colors: ['#fe0101', '#0000ff'], energy: 0.6 }
    ]);
    expect(m.colors).toEqual(['#ff0000', '#ffffff', '#0000ff']);
    expect(m.energy).toBe(0.4);
  });
});
