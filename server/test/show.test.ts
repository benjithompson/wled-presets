import { describe, expect, it } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { Frame } from '../src/game/frame.ts';
import { Yard } from '../src/game/kit.ts';
import { Show } from '../src/game/show.ts';

function setup() {
  const stage = buildStage(sampleLayout());
  const yard = new Yard(stage);
  const show = new Show(yard);
  const frame = new Frame(stage.pixelCount);
  const run = (seconds: number, draw?: () => void) => {
    for (let t = 0; t < seconds - 1e-9; t += 1 / 60) {
      yard.begin(frame);
      draw?.();
      show.update(1 / 60);
      show.draw(frame);
    }
  };
  const light = (i: number) => frame.data[i * 3] + frame.data[i * 3 + 1] + frame.data[i * 3 + 2];
  return { stage, yard, show, frame, run, light };
}

describe('the light show around a game', () => {
  it('keeps every LED of the yard glowing, dim, in the mood', () => {
    const { yard, show, frame, run, light } = setup();
    show.setMood({ a: [1, 0, 0], b: [1, 0.2, 0] }, { fade: 0.1 });
    run(0.5);
    for (const i of yard.lit) {
      expect(light(i)).toBeGreaterThan(0.01);
      expect(light(i)).toBeLessThan(0.5);
    }
    // Red, as asked.
    const i = yard.bushes[0].offset;
    expect(frame.data[i * 3]).toBeGreaterThan(frame.data[i * 3 + 2] * 5);
  });

  it('steps back where the game lit a piece, so the piece keeps its own color', () => {
    const { yard, show, frame, run } = setup();
    const piece = yard.roof.track.leds[100];
    show.setMood({ a: [0, 0, 1], b: [0, 0.5, 1], level: 3 }, { fade: 0.05 });
    run(0.3, () => yard.add(piece, [1, 0, 0], 1));
    expect(frame.data[piece * 3]).toBeCloseTo(1, 5);
    expect(frame.data[piece * 3 + 1]).toBeCloseTo(0, 5);
    expect(frame.data[piece * 3 + 2]).toBeCloseTo(0, 5);
  });

  it('leaves the roof to the game when asked, except for the big moments', () => {
    const { yard, show, run, light } = setup();
    show.roofShare = 0;
    show.explode(800, 400, [1, 0, 0], { size: 2 });
    run(0.2);
    for (const i of yard.roof.track.leds) expect(light(i)).toBe(0);
    expect(yard.bushes.some((b) => light(b.offset) > 0)).toBe(true);
    show.explode(800, 400, [1, 0, 0], { size: 2, over: true });
    run(0.1);
    expect(yard.roof.track.leds.some((i) => light(i) > 0.1)).toBe(true);
  });

  it('sends a firework up, bursts it over the house, and lets it burn out', () => {
    const { yard, show, frame, run } = setup();
    show.master = 0;
    show.firework({ x: 800, y: 350, colors: [[0, 1, 0]], kind: 'peony' });
    expect(show.rocketsUp).toBe(1);
    run(0.9);
    expect(show.rocketsUp).toBe(0);
    // Green sparks on the roof, well away from the middle.
    const roof = yard.roof.track.leds;
    const green = roof.filter((i) => frame.data[i * 3 + 1] > 0.05 && Math.abs(yard.stage.positions[i * 2] - 800) > 80);
    expect(green.length).toBeGreaterThan(5);
    run(4);
    expect(show.busy).toBe(false);
    expect(Math.max(...frame.data)).toBe(0);
  });

  it('wipes a new mood across the yard from one side', () => {
    const { yard, show, frame, run } = setup();
    show.setMood({ a: [0, 0, 1], b: [0, 0, 1] }, { fade: 0.05 });
    run(0.2);
    show.setMood({ a: [1, 0, 0], b: [1, 0, 0] }, { wipe: 'right', fade: 1 });
    run(0.5);
    const [left, right] = [yard.bushes[0], yard.bushes.at(-1)!];
    const red = (p: typeof left) => frame.data[p.offset * 3] > frame.data[p.offset * 3 + 2];
    expect(red(left)).toBe(true);
    expect(red(right)).toBe(false);
  });

  it('never lights a skipped LED', () => {
    const layout = sampleLayout();
    const roof = layout.fixtures.find((f) => f.kind === 'roof')!;
    roof.skip = [1];
    const stage = buildStage(layout);
    const yard = new Yard(stage);
    const show = new Show(yard);
    const frame = new Frame(stage.pixelCount);
    show.finale(5, { over: true });
    show.sweep([1, 1, 1], { over: true, duration: 0.3 });
    for (let t = 0; t < 2; t += 1 / 60) {
      yard.begin(frame);
      show.update(1 / 60);
      show.draw(frame);
      for (let i = 0; i < stage.pixelCount; i++) if (!stage.active[i]) expect(frame.data[i * 3] + frame.data[i * 3 + 1] + frame.data[i * 3 + 2]).toBe(0);
    }
  });
});
