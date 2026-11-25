import { describe, expect, it } from 'vitest';
import { buildStage, sampleLayout, type Layout } from '../../shared/layout.ts';
import { neighbours, SequencePlayer } from '../../shared/sequence.ts';
import { showcase, SHOWCASE_BPM, SHOWCASE_SECONDS } from '../../shared/showcase.ts';
import { YARD } from '../../shared/effects.ts';
import { LedPlaces } from '../../shared/transitions.ts';
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
    // Every kick of the score flashes the trees at its moment, or, where the trees play the hook
    // or a chase, sends a shockwave out from the middle of the yard.
    const kicks = score.filter((n) => n.inst === 'kick');
    const r4 = (x: number) => Math.round(x * 10000) / 10000;
    const onTrees = new Set(clips('Kick').map((c) => c.start));
    const rings = new Set(clips('Beat: shockwaves').map((c) => c.start));
    for (const k of kicks) expect(onTrees.has(r4(k.t)) || rings.has(r4(k.t)), `kick at ${k.t}`).toBe(true);
    expect(onTrees.size).toBeGreaterThan(kicks.length / 2);
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

  it('sweeps a new color across the roof on every beat of the drops, and gives it its own color only in the rise and the second drop', () => {
    const layout = yard();
    const { sequence } = showcase(layout);
    const roof = sequence.tracks.find((t) => t.name === 'Roof (color)')!.clips;
    const bars = (c: { start: number; duration: number }) => [Math.round(c.start / (4 * BEAT)), (c.start + c.duration) / (4 * BEAT)];
    for (const c of roof) {
      const [from, to] = bars(c);
      expect((from >= 8 && to <= 12) || (from >= 24 && to <= 30.01), `${from}–${to}`).toBe(true);
    }

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

  it('shows every quarter note as motion: a light that walks, each object side to side or up and down, lasers', () => {
    const { sequence } = showcase(yard());
    const beatTracks = sequence.tracks.filter((t) => t.name.startsWith('Beat:'));
    const starts = new Set(beatTracks.flatMap((t) => t.clips.flatMap((c) => (c.effect.effect === 'scanner' ? [0, 1, 2, 3].map((k) => c.start + k * BEAT) : [c.start]))).map((x) => Math.round(x * 100)));
    // Every beat up to the finale moves, but the beat of silence before each drop.
    for (let k = 0; k < 120; k++) {
      if (k === 47 || k === 95) continue;
      expect(starts.has(Math.round(k * BEAT * 100)), `beat ${k}`).toBe(true);
    }
    const clips = beatTracks.flatMap((t) => t.clips);
    // Each object crosses on its own, both ways, both side to side and up and down.
    const each = clips.filter((c) => c.eachObject);
    expect(new Set(each.map((c) => c.transitionIn))).toEqual(new Set(['wipeRight', 'wipeLeft', 'wipeUp', 'wipeDown']));
    for (const c of each) expect(c.transitionOut).toBe(c.transitionIn);
    // Lasers across the bushes and up the trees, a pass a beat, from a downbeat.
    const lasers = clips.filter((c) => c.effect.effect === 'scanner');
    expect(new Set(lasers.map((c) => c.effect.direction))).toEqual(new Set(['right', 'up']));
    expect(lasers.some((c) => c.targets.join() === 'bush-1,bush-2,bush-3')).toBe(true);
    for (const c of lasers) expect(Math.round(c.start / (4 * BEAT)) * 4 * BEAT).toBeCloseTo(c.start, 3);
  });

  it('moves each bush on its own: on a beat that wipes right, the left of every bush lights first', () => {
    const layout = yard();
    // Bar 14: every object on the ground side to side; beat 0 wipes right.
    const t = 14 * 4 * BEAT + 0.2 * BEAT;
    const { stage, frames } = play(layout, t);
    const out = frames[frames.length - 1].out;
    for (const id of ['bush-1', 'bush-2', 'bush-3']) {
      const f = stage.fixtures.find((x) => x.id === id)!;
      const xs = Array.from({ length: f.count }, (_, j) => stage.positions3[(f.offset + j) * 3]);
      const mid = (Math.min(...xs) + Math.max(...xs)) / 2;
      let left = 0;
      let right = 0;
      for (let j = 0; j < f.count; j++) {
        const i = f.offset + j;
        const v = Math.max(out[i * 3], out[i * 3 + 1], out[i * 3 + 2]);
        if (xs[j] < mid) left += v;
        else right += v;
      }
      expect(left, id).toBeGreaterThan(right * 1.5);
    }
  });

  it('keeps most of the yard dark in the quiet parts and lights more of it as the music grows', () => {
    const layout = yard();
    const { sequence } = showcase(layout);
    const stage = buildStage(layout);
    const p = new SequencePlayer(stage, layout, sequence);
    const out = new Float32Array(stage.pixelCount * 3);
    const lit: number[] = [];
    // The share of LEDs lit, sampled through each bar.
    const perBar = Array.from({ length: 32 }, () => [] as number[]);
    while (p.time < sequence.duration - 0.05) {
      p.update(1 / 20, out);
      let on = 0;
      for (let i = 0; i < stage.pixelCount; i++) if (Math.max(out[i * 3], out[i * 3 + 1], out[i * 3 + 2]) > 0.08) on++;
      perBar[Math.min(31, Math.floor(p.time / (4 * BEAT)))].push(on / stage.pixelCount);
      lit.push(on / stage.pixelCount);
    }
    const mean = (from: number, to: number) => {
      const v = perBar.slice(from, to).flat();
      return v.reduce((a, b) => a + b, 0) / v.length;
    };
    const intro = mean(0, 4);
    const build = mean(4, 8);
    const drop = mean(12, 18);
    const breakdown = mean(20, 22);
    const drop2 = mean(26, 30);
    expect(intro).toBeLessThan(0.2);
    expect(build).toBeGreaterThan(intro);
    expect(drop).toBeGreaterThan(build);
    expect(breakdown).toBeLessThan(drop / 2);
    expect(drop2).toBeGreaterThan(drop);
    // Even the first drop leaves dark between its moving lights.
    expect(drop).toBeLessThan(0.75);
    // The yard's 3-D pictures play in under half of the show.
    const bed = sequence.tracks.find((t) => t.name === 'Yard 3-D')!.clips.reduce((a, c) => a + c.duration, 0);
    expect(bed / sequence.duration).toBeLessThan(0.5);
  });

  it('sends shockwaves out from the middle of the whole yard: the middle lights first, the edges after', () => {
    const layout = yard();
    const { sequence } = showcase(layout);
    const rings = sequence.tracks.find((t) => t.name.startsWith('Beat: shockwaves'))!;
    expect(rings.clips.length).toBeGreaterThan(20);
    for (const c of rings.clips) expect(c.targets).toEqual([YARD]);
    // Only the rings, from the first beat of bar 16 (a ring a beat).
    const only = { ...sequence, tracks: [rings] };
    const stage = buildStage(layout);
    const places = new LedPlaces(stage);
    const p = new SequencePlayer(stage, layout, only);
    const out = new Float32Array(stage.pixelCount * 3);
    const t0 = 16 * 4 * BEAT;
    // The nearest third of the LEDs to the middle of the yard, and the farthest third.
    const dist = Array.from({ length: stage.pixelCount }, (_, i) => i).filter((i) => stage.active[i]).map((i) => ({ i, r: Math.hypot(places.ux[i] - 0.5, places.uy[i] - 0.5) }));
    dist.sort((a, b) => a.r - b.r);
    const third = Math.floor(dist.length / 3);
    const near = dist.slice(0, third).map((d) => d.i);
    const far = dist.slice(-third).map((d) => d.i);
    const mean = (leds: number[]) => leds.reduce((a, i) => a + Math.max(out[i * 3], out[i * 3 + 1], out[i * 3 + 2]), 0) / leds.length;
    const sample = (t: number) => {
      while (p.time < t - 1e-9) p.update(Math.min(1 / 60, t - p.time), out);
      return { inner: mean(near), outer: mean(far) };
    };
    const early = sample(t0 + 0.4 * BEAT);
    const late = sample(t0 + 0.85 * BEAT);
    expect(early.inner).toBeGreaterThan(early.outer + 0.2);
    expect(late.inner).toBeLessThan(0.02);
    expect(late.outer).toBeGreaterThan(0.05);
  });

  it('blinks whole trees one after another: with the hook\'s notes, and in turn in the second drop', () => {
    const { sequence, score } = showcase(yard());
    const bar = (t: number) => Math.floor(t / (4 * BEAT) + 1e-6);
    // The hook on the trees: low notes on the left tree, high ones on the right.
    const hook = sequence.tracks.find((t) => t.name.startsWith('Hook'))!.clips;
    const notes = score.filter((n) => n.inst === 'lead' && bar(n.t) >= 16 && bar(n.t) < 18);
    expect(hook.length).toBe(notes.length);
    hook.forEach((c, i) => expect(c.targets).toEqual([notes[i].notes[0] <= 75 ? 'tree-l' : 'tree-r']));
    // The chases: one whole object at a time, the trees in turn, then everything on the ground in order, left to right.
    const chase = sequence.tracks.find((t) => t.name.startsWith('Beat: whole objects'))!.clips;
    for (const c of chase) expect(c.targets).toHaveLength(1);
    const trees = chase.filter((c) => bar(c.start) >= 26 && bar(c.start) < 28).map((c) => c.targets[0]);
    expect(trees.slice(0, 4)).toEqual(['tree-l', 'tree-r', 'tree-l', 'tree-r']);
    const ground = chase.filter((c) => bar(c.start) >= 28).map((c) => c.targets[0]);
    expect(ground.slice(0, 6)).toEqual(['tree-l', 'bush-1', 'bush-2', 'sun', 'bush-3', 'tree-r']);
    // The sunrise has its own part: the claps, with the roof.
    expect(sequence.tracks.find((t) => t.name.startsWith('Clap'))!.clips[0].targets).toContain('sun');
  });

  it('lights every object, also one added to the layout after the show was made', () => {
    const layout = yard();
    const { sequence } = showcase(layout);
    const later: Layout = { ...layout, fixtures: [...layout.fixtures, { ...layout.fixtures.find((f) => f.id === 'bush-2')!, id: 'new-bush', points: [{ x: 1300, y: 760, z: 40 }] }] };
    const stage = buildStage(later);
    const p = new SequencePlayer(stage, later, sequence);
    const out = new Float32Array(stage.pixelCount * 3);
    const lit = new Map<string, number>();
    let frames = 0;
    while (p.time < sequence.duration - 0.05) {
      p.update(1 / 20, out);
      frames++;
      for (const f of stage.fixtures) if (level(stage, out, f.id) > 0.1) lit.set(f.id, (lit.get(f.id) ?? 0) + 1);
    }
    for (const f of stage.fixtures) expect((lit.get(f.id) ?? 0) / frames, f.id).toBeGreaterThan(f.id === 'new-bush' ? 0.25 : 0.4);
  });
});
