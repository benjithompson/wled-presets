import { describe, expect, it } from 'vitest';
import { defaultSettings, YARD, type EffectSettings } from '../../shared/effects.ts';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { emptySequence, SequencePlayer, type SeqClip, type Sequence } from '../../shared/sequence.ts';
import { crossFrames, hashUnit, LedPlaces, pickTransition, TRANSITIONS, transitionInfo } from '../../shared/transitions.ts';
import { GameHost } from '../src/game/host.ts';
import { sequenceInput } from '../src/sequenceStore.ts';

const layout = sampleLayout();
const stage = buildStage(layout);
const solid = (hex: string): EffectSettings => ({ ...defaultSettings('candy'), palette: 'custom', colors: [hex], intensity: 0, brightness: 1 });
const RED = solid('#ff0000');
const BLUE = solid('#0000ff');

function fill(r: number, g: number, b: number) {
  const f = new Float32Array(stage.pixelCount * 3);
  for (let i = 0; i < stage.pixelCount; i++) f.set([r, g, b], i * 3);
  return f;
}

describe('transitions', () => {
  const places = new LedPlaces(stage);
  const from = fill(1, 0, 0);
  const to = fill(0, 0, 1);

  it('start on the old show and end on the new one, every one of them', () => {
    const out = new Float32Array(from.length);
    for (const t of TRANSITIONS) {
      crossFrames(t.id, 0, from, to, out, places);
      expect(out, `${t.id} at the start`).toEqual(from);
      crossFrames(t.id, 1, from, to, out, places);
      expect(out, `${t.id} at the end`).toEqual(to);
    }
  });

  it('change the LEDs in their own order', () => {
    const out = new Float32Array(from.length);
    const changed = (id: (typeof TRANSITIONS)[number]['id'], p: number) => {
      crossFrames(id, p, from, to, out, places);
      let n = 0;
      for (let i = 0; i < stage.pixelCount; i++) if (out[i * 3 + 2] > 0.5) n++;
      return n / stage.pixelCount;
    };
    // Halfway through a wipe, some of the yard has changed, not all.
    for (const id of ['wipeRight', 'diagonal', 'splitOut', 'splitIn', 'irisClose', 'clock', 'blinds', 'strings'] as const) {
      const half = changed(id, 0.5);
      expect(half, id).toBeGreaterThan(0.05);
      expect(half, id).toBeLessThan(0.95);
    }
    // Along the strings: each string's first LED goes before its last.
    crossFrames('strings', 0.5, from, to, out, places);
    const roof = stage.fixtures[0];
    expect(out[roof.offset * 3 + 2]).toBeGreaterThan(0.9);
    expect(out[(roof.offset + roof.count - 1) * 3]).toBeGreaterThan(0.9);
  });

  it('flash to white halfway', () => {
    const out = new Float32Array(from.length);
    crossFrames('flash', 0.5, from, to, out, places);
    expect([out[0], out[1], out[2]]).toEqual([1, 1, 1]);
    crossFrames('flash', 0.25, from, to, out, places);
    expect(out[0]).toBeCloseTo(1);
    expect(out[1]).toBeCloseTo(0.5);
  });

  it('pick a real transition for "random"', () => {
    const picked = new Set([0, 0.1, 0.3, 0.5, 0.7, 0.99, 1].map((r) => pickTransition('random', r)));
    for (const id of picked) expect(TRANSITIONS.some((t) => t.id === id)).toBe(true);
    expect(picked.size).toBeGreaterThan(4);
    expect(pickTransition('iris', 0.5)).toBe('iris');
    expect(pickTransition(undefined, 0.5)).toBe('fade');
    expect(hashUnit('a')).toBe(hashUnit('a'));
    expect(transitionInfo('random').name).toBe('Random');
  });
});

describe('random transitions in a sequence', () => {
  function seq(clips: Partial<SeqClip>[]): Sequence {
    const s = emptySequence('Test');
    s.duration = 20;
    s.tracks = [{ id: 't0', name: 'Layer', blend: 'normal', opacity: 1, clips: clips.map((c, i) => ({ id: `c${i}`, start: 0, duration: 10, targets: [YARD], effect: RED, ...c })) }];
    return s;
  }

  it('pick one transition for a clip, the same on every frame, and again each time round', () => {
    const s = seq([{ start: 0, duration: 6 }, { start: 4, duration: 6, effect: BLUE, transitionIn: 'random' }]);
    expect(sequenceInput.safeParse(s).success).toBe(true);
    const p = new SequencePlayer(stage, layout, s);
    const first = p.transitionOf('random', 'c1', 'in');
    expect(TRANSITIONS.some((t) => t.id === first)).toBe(true);
    expect(p.transitionOf('random', 'c1', 'in')).toBe(first);
    const out = new Float32Array(stage.pixelCount * 3);
    p.seek(5, 0);
    p.update(0, out);
    expect(out.every(Number.isFinite)).toBe(true);
    expect(p.active().find((a) => a.clipId === 'c1')?.from?.transition).toBe(first);
    const picks = new Set<string>();
    for (let k = 0; k < 12; k++) {
      p.pass = k;
      picks.add(p.transitionOf('random', 'c1', 'in'));
    }
    expect(picks.size).toBeGreaterThan(2);
  });

  it('flash a clip in from nothing', () => {
    const s = seq([{ start: 0, duration: 10, effect: BLUE, transitionIn: 'flash', fadeIn: 2 }]);
    const p = new SequencePlayer(stage, layout, s);
    const out = new Float32Array(stage.pixelCount * 3);
    p.seek(1, 0);
    p.update(0, out);
    const i = stage.fixtures[1].offset;
    expect(out[i * 3]).toBeGreaterThan(0.9);
    expect(out[i * 3 + 1]).toBeGreaterThan(0.9);
  });
});

describe('scene transitions on the host', () => {
  it('cross over from the scene playing to the new one, then play only the new one', () => {
    const l = sampleLayout();
    l.fixtures[1] = { ...l.fixtures[1], deviceId: 'bush-device' };
    const host = new GameHost(l, () => {});
    try {
      const i = buildStage(l).fixtures[1].offset;
      const rgb = (bytes: Uint8Array) => [bytes[i * 3], bytes[i * 3 + 1], bytes[i * 3 + 2]];
      host.playShow({ effects: { [YARD]: RED } });
      expect(rgb(host.tick(0.1)!.bytes)[0]).toBeGreaterThan(150);
      const played = host.playShow({ effects: { [YARD]: BLUE } }, { type: 'fade', seconds: 1 });
      expect(played.devices).toEqual(['bush-device']);
      const [r, , b] = rgb(host.tick(0.5)!.bytes);
      expect(r).toBeGreaterThan(40);
      expect(b).toBeGreaterThan(40);
      const end = rgb(host.tick(0.6)!.bytes);
      expect(end[0]).toBe(0);
      expect(end[2]).toBeGreaterThan(150);
      // The transition has ended: the new scene plays on its own.
      expect((host as any).scene.constructor.name).toBe('EffectScene');
      // Without a transition, the change is at once.
      host.playShow({ effects: { [YARD]: RED } });
      expect(rgb(host.tick(0.05)!.bytes)[2]).toBe(0);
    } finally {
      host.stop();
    }
  });

  it('come in at once with no scene playing before', () => {
    const host = new GameHost(sampleLayout(), () => {});
    try {
      host.playShow({ effects: { [YARD]: BLUE } }, { type: 'random', seconds: 2 });
      expect((host as any).scene.constructor.name).toBe('EffectScene');
    } finally {
      host.stop();
    }
  });
});
