import { describe, expect, it } from 'vitest';
import { buildStage, sampleLayout, type Layout } from '../../shared/layout.ts';
import { neighbours, SequencePlayer } from '../../shared/sequence.ts';
import { showcase, SHOWCASE_BPM, SHOWCASE_SECONDS } from '../../shared/showcase.ts';
import { sequenceInput } from '../src/sequenceStore.ts';

const BEAT = 60 / SHOWCASE_BPM;

/** A yard with a band: a roof with eight segments, two trees, four bushes and a sunrise. */
function yard(): Layout {
  const l = sampleLayout();
  l.fixtures[0] = {
    ...l.fixtures[0],
    pixels: 600,
    points: [200, 420, 560, 700, 800, 900, 1040, 1180, 1400].map((x, i) => ({ x, y: i % 2 ? 330 : 470 }))
  };
  const base = { deviceId: null, startPixel: 0, reversed: false };
  l.fixtures.push(
    { ...base, id: 'tree-l', name: 'Left tree', kind: 'tree', points: [{ x: 110, y: 820, z: 120 }], radius: 60, height: 300, pattern: 'spiral', turns: 8, pixels: 200 },
    { ...base, id: 'tree-r', name: 'Right tree', kind: 'tree', points: [{ x: 1490, y: 820, z: 120 }], radius: 60, height: 300, pattern: 'spiral', turns: 8, pixels: 200 },
    { ...base, id: 'sun', name: 'Sunrise', kind: 'semicircle', points: [{ x: 1000, y: 820, z: 200 }], radius: 110, strands: 8, pixels: 150 }
  );
  return l;
}

function play(layout: Layout, until: number) {
  const { sequence } = showcase(layout);
  const stage = buildStage(layout);
  const p = new SequencePlayer(stage, layout, sequence);
  const out = new Float32Array(stage.pixelCount * 3);
  const frames: { t: number; out: Float32Array }[] = [];
  while (p.time < until - 1e-9) {
    p.update(Math.min(1 / 60, until - p.time), out);
    frames.push({ t: p.time, out: out.slice() });
  }
  return { stage, frames };
}

const level = (stage: ReturnType<typeof buildStage>, out: Float32Array, id: string) => {
  const f = stage.fixtures.find((x) => x.id === id)!;
  let sum = 0;
  for (let i = f.offset; i < f.offset + f.count; i++) sum += Math.max(out[i * 3], out[i * 3 + 1], out[i * 3 + 2]);
  return sum / f.count;
};

describe('the showcase', () => {
  it('is a valid 60-second sequence to a beat, and only its pictures and the roof colors cross over', () => {
    for (const layout of [yard(), sampleLayout(), { ...sampleLayout(), fixtures: [] }]) {
      const { sequence } = showcase(layout);
      expect(sequenceInput.safeParse(sequence).success).toBe(true);
      expect(sequence.duration).toBe(SHOWCASE_SECONDS);
      expect(sequence.bpm).toBe(SHOWCASE_BPM);
      expect(sequence.markers.map((m) => m.label)).toContain('Drop');
      for (const t of sequence.tracks) {
        const crossing = neighbours(t).filter((n) => n.prev).length;
        if (!['Yard 3-D', 'Roof (color)'].includes(t.name)) expect(crossing, t.name).toBe(0);
      }
    }
  });

  it('plays the objects as instruments: the kick on the trees, the melody along the roof, low notes on the left', () => {
    const layout = yard();
    const { sequence, score } = showcase(layout);
    const clips = (name: string) => sequence.tracks.find((t) => t.name.startsWith(name))!.clips;
    // Every kick of the score flashes the trees at its moment.
    const kicks = score.filter((n) => n.inst === 'kick');
    expect(clips('Kick').map((c) => c.start)).toEqual(kicks.map((n) => Math.round(n.t * 10000) / 10000));
    expect(new Set(clips('Kick').flatMap((c) => c.targets))).toEqual(new Set(['tree-l', 'tree-r']));
    // The melody hops between the roof's segments, by pitch.
    const lead = score.filter((n) => n.inst === 'lead');
    const keys = clips('Melody').map((c) => c.targets[0]);
    expect(new Set(keys).size).toBeGreaterThanOrEqual(5);
    expect(keys.every((k) => k.startsWith('roof#'))).toBe(true);
    const seg = (k: string) => Number(k.split('#')[1]);
    const low = lead.findIndex((n) => n.notes[0] === Math.min(...lead.map((x) => x.notes[0])));
    const high = lead.findIndex((n) => n.notes[0] === Math.max(...lead.map((x) => x.notes[0])));
    expect(seg(keys[low])).toBeLessThan(seg(keys[high]));
    // The music sounds where the light is.
    expect(kicks[0].pan).toBeCloseTo(0, 1);
    expect(lead[low].pan).toBeLessThan(lead[high].pan);
  });

  it('flashes the trees on the beat in the drop, and goes dark the beat before it', () => {
    const layout = yard();
    const drop = 12 * 4 * BEAT;
    const { stage, frames } = play(layout, drop + 1.5 * BEAT);
    const at = (t: number) => frames.reduce((a, f) => (Math.abs(f.t - t) < Math.abs(a.t - t) ? f : a)).out;
    expect(frames.every((f) => f.out.every(Number.isFinite))).toBe(true);
    const dark = at(drop - BEAT / 2);
    expect(Math.max(...dark)).toBeLessThan(0.01);
    const onBeat = level(stage, at(drop + BEAT + 0.03), 'tree-l');
    const between = level(stage, at(drop + 1.4 * BEAT), 'tree-l');
    expect(onBeat).toBeGreaterThan(0.5);
    expect(onBeat).toBeGreaterThan(between + 0.2);
  });

  it('gives the roof a color of its own every bar, and sweeps a new one across it on every beat of the drops', () => {
    const layout = yard();
    const { sequence } = showcase(layout);
    const roof = sequence.tracks.find((t) => t.name === 'Roof (color)')!.clips;
    for (let bar = 0; bar < 30; bar++) {
      const mid = (bar + 0.5) * 4 * BEAT;
      expect(roof.filter((c) => c.start <= mid && c.start + c.duration > mid).length, `bar ${bar}`).toBe(1);
    }
    expect(new Set(roof.map((c) => c.effect.colors!.join())).size).toBeGreaterThanOrEqual(4);

    const drop = 12 * 4 * BEAT;
    const { stage, frames } = play(layout, drop + 9 * BEAT);
    const at = (t: number) => frames.reduce((a, f) => (Math.abs(f.t - t) < Math.abs(a.t - t) ? f : a)).out;
    const color = (out: Float32Array) => {
      const f = stage.fixtures.find((x) => x.id === 'roof')!;
      const c = [0, 0, 0];
      for (let i = f.offset; i < f.offset + f.count; i++) for (let k = 0; k < 3; k++) c[k] += out[i * 3 + k] / f.count;
      const m = Math.max(...c);
      return { level: m, hue: c.map((x) => x / m) };
    };
    // After the drop's first flash: each beat, a bright roof in a color unlike the beat before.
    const beats = [2, 3, 4, 5, 6, 7, 8].map((k) => color(at(drop + (k + 0.4) * BEAT)));
    for (const b of beats) expect(b.level).toBeGreaterThan(0.35);
    const changes = beats.slice(1).filter((b, i) => Math.hypot(...b.hue.map((x, k) => x - beats[i].hue[k])) > 0.3).length;
    expect(changes).toBeGreaterThanOrEqual(5);
  });
});
