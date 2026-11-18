import { describe, expect, it } from 'vitest';
import { defaultSettings, YARD, type EffectSettings } from '../../shared/effects.ts';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { emptySequence, neighbours, SequencePlayer, targetLeds, type SeqClip, type Sequence } from '../../shared/sequence.ts';
import { GameHost } from '../src/game/host.ts';
import { sequenceInput } from '../src/sequenceStore.ts';

const layout = sampleLayout();
const stage = buildStage(layout);
const solid = (hex: string): EffectSettings => ({ ...defaultSettings('candy'), palette: 'custom', colors: [hex], intensity: 0, brightness: 1 });
const RED = solid('#ff0000');
const BLUE = solid('#0000ff');
const at = (out: Float32Array, i: number) => [out[i * 3], out[i * 3 + 1], out[i * 3 + 2]];
const bush = (k: number) => stage.fixtures[k];

function seq(tracks: { clips: Partial<SeqClip>[]; blend?: 'normal' | 'add' | 'lighten' | 'multiply'; opacity?: number; hidden?: boolean; solo?: boolean }[]): Sequence {
  const s = emptySequence('Test');
  s.duration = 30;
  s.tracks = tracks.map((t, ti) => ({
    id: `t${ti}`,
    name: `Layer ${ti}`,
    blend: t.blend ?? 'normal',
    opacity: t.opacity ?? 1,
    hidden: t.hidden,
    solo: t.solo,
    clips: t.clips.map((c, ci) => ({ id: `c${ti}-${ci}`, start: 0, duration: 10, targets: [YARD], effect: RED, ...c }))
  }));
  return s;
}

/** A solid candy cane (no shine) is 0.7 bright. */
const FULL = 0.7;

function frame(s: Sequence, t: number, warm = 0) {
  const p = new SequencePlayer(stage, layout, s);
  p.seek(t, warm);
  const out = new Float32Array(stage.pixelCount * 3);
  p.update(0, out);
  return { out, player: p };
}

describe('sequences', () => {
  it('play a clip on its targets only, while it runs', () => {
    const s = seq([{ clips: [{ start: 2, duration: 4, targets: ['bush-1'] }] }]);
    expect(frame(s, 1).out.every((v) => v === 0)).toBe(true);
    const { out } = frame(s, 3);
    expect(at(out, bush(1).offset)[0]).toBeCloseTo(FULL);
    expect(at(out, bush(2).offset)).toEqual([0, 0, 0]);
    expect(frame(s, 6.5).out.every((v) => v === 0)).toBe(true);
  });

  it('cover lower layers with upper ones, or add to them', () => {
    const normal = seq([{ clips: [{ effect: BLUE, targets: ['bush-1'] }] }, { clips: [{ effect: RED }] }]);
    let o = frame(normal, 1).out;
    expect(at(o, bush(1).offset)).toEqual([0, 0, expect.any(Number)]);
    expect(at(o, bush(2).offset)[0]).toBeGreaterThan(0.5);
    const add = seq([{ blend: 'add', clips: [{ effect: BLUE, targets: ['bush-1'] }] }, { clips: [{ effect: RED }] }]);
    o = frame(add, 1).out;
    const [r, , b] = at(o, bush(1).offset);
    expect(r).toBeGreaterThan(0.5);
    expect(b).toBeGreaterThan(0.5);
    // Half opacity shows half of each.
    const half = seq([{ opacity: 0.5, clips: [{ effect: BLUE, targets: ['bush-1'] }] }, { clips: [{ effect: RED }] }]);
    const [r2, , b2] = at(frame(half, 1).out, bush(1).offset);
    expect(r2).toBeCloseTo(FULL / 2, 1);
    expect(b2).toBeCloseTo(FULL / 2, 1);
    // Hidden layers do not play; a solo layer plays alone.
    expect(at(frame(seq([{ hidden: true, clips: [{ effect: BLUE }] }, { clips: [{ effect: RED }] }]), 1).out, 0)[2]).toBe(0);
    expect(at(frame(seq([{ clips: [{ effect: BLUE }] }, { solo: true, clips: [{ effect: RED }] }]), 1).out, 0)[2]).toBe(0);
  });

  it('fade a clip in and out', () => {
    const s = seq([{ clips: [{ start: 0, duration: 10, fadeIn: 2, fadeOut: 2 }] }]);
    const red = (t: number) => at(frame(s, t).out, bush(1).offset)[0];
    expect(red(1)).toBeGreaterThan(0.2);
    expect(red(1)).toBeLessThan(0.5);
    expect(red(5)).toBeGreaterThan(FULL - 0.05);
    expect(red(9)).toBeLessThan(0.5);
  });

  it('cross over from one object to another where two clips overlap on a layer', () => {
    // Bush 1 red from 0 to 6, bush 3 blue from 4 to 10: a 2 s crossfade.
    const s = seq([{ clips: [{ start: 0, duration: 6, targets: ['bush-1'] }, { start: 4, duration: 6, targets: ['bush-3'], effect: BLUE }] }]);
    const b1 = (t: number) => at(frame(s, t).out, bush(1).offset)[0];
    const b3 = (t: number) => at(frame(s, t).out, bush(3).offset)[2];
    expect(b1(3)).toBeGreaterThan(FULL - 0.05);
    expect(b3(3)).toBe(0);
    expect(b1(5)).toBeCloseTo(FULL / 2, 1);
    expect(b3(5)).toBeCloseTo(FULL / 2, 1);
    expect(b1(6.5)).toBe(0);
    expect(b3(6.5)).toBeGreaterThan(FULL - 0.05);
    expect(neighbours(s.tracks[0])[1].prev?.id).toBe('c0-0');
    const { player } = frame(s, 5);
    const now = player.active();
    expect(now.map((a) => a.clipId).sort()).toEqual(['c0-0', 'c0-1']);
    expect(now.find((a) => a.clipId === 'c0-1')?.from).toMatchObject({ clipId: 'c0-0', transition: 'fade' });
  });

  it('wipe from left to right: the left of the yard changes first', () => {
    const s = seq([{ clips: [{ start: 0, duration: 6, effect: RED }, { start: 4, duration: 6, effect: BLUE, transitionIn: 'wipeRight' }] }]);
    const o = frame(s, 5).out;
    expect(at(o, bush(1).offset)[2]).toBeGreaterThan(FULL - 0.05);
    expect(at(o, bush(3).offset)[0]).toBeGreaterThan(FULL - 0.05);
  });

  it('dip to black in the middle of the crossover', () => {
    const s = seq([{ clips: [{ start: 0, duration: 6 }, { start: 4, duration: 6, effect: BLUE, transitionIn: 'dip' }] }]);
    expect(Math.max(...at(frame(s, 5).out, bush(1).offset))).toBeLessThan(0.05);
  });

  it('loop at the end, and finds the LEDs of segment targets', () => {
    const s = seq([{ clips: [{ start: 0, duration: 30 }] }]);
    const p = new SequencePlayer(stage, layout, s);
    const out = new Float32Array(stage.pixelCount * 3);
    p.seek(29.95);
    p.update(0.1, out, true);
    expect(p.time).toBeLessThan(1);
    const leds = targetLeds(stage, layout, ['roof#1', 'bush-2']);
    expect(leds.map((g) => g.fixture)).toEqual(['roof', 'bush-2']);
    expect(leds[1].leds.length).toBe(bush(2).count);
  });

  it('play 3-D and particle effects anywhere in the timeline', () => {
    const s = seq([{ clips: [{ start: 5, duration: 20, effect: defaultSettings('starburst') }] }, { clips: [{ effect: defaultSettings('fireworks'), targets: ['roof'] }] }]);
    const { out } = frame(s, 12, 2.5);
    expect(out.every(Number.isFinite)).toBe(true);
    expect(out.some((v) => v > 0)).toBe(true);
  });

  it('validate what the editor sends', () => {
    const s = seq([{ clips: [{}] }]);
    expect(sequenceInput.safeParse(s).success).toBe(true);
    expect(sequenceInput.safeParse({ ...s, tracks: [{ ...s.tracks[0], blend: 'nope' }] }).success).toBe(false);
    expect(sequenceInput.safeParse({ ...s, tracks: [{ ...s.tracks[0], clips: [{ ...s.tracks[0].clips[0], targets: [] }] }] }).success).toBe(false);
  });

  it('play on the real lights from a scene, looping, with nobody watching', async () => {
    const l = sampleLayout();
    l.fixtures[1] = { ...l.fixtures[1], deviceId: 'bush-device' };
    const host = new GameHost(l, () => {});
    try {
      const s = seq([{ clips: [{ targets: ['bush-1', 'bush-2'] }] }]);
      expect(host.playShow({ sequence: s })).toEqual({ devices: ['bush-device'], objects: 2 });
      expect(host.playingEffects).toBe(true);
      // An empty sequence plays nothing.
      expect(host.playShow({ sequence: emptySequence() })).toEqual({ devices: [], objects: 0 });
    } finally {
      host.stop();
    }
  });
});
