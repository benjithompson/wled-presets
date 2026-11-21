import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { colorgateGame, LAG, tapsBetween } from '../src/game/colorgate.ts';
import { Frame } from '../src/game/frame.ts';
import { press, run } from './harness.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

/** A game whose walls are all blue (Math.random fixed at 0.5); you start green. */
function setup() {
  vi.spyOn(Math, 'random').mockReturnValue(0.5);
  const stage = buildStage(sampleLayout());
  const game = colorgateGame(stage);
  const frame = new Frame(stage.pixelCount);
  // The first wall reaches your light after crossing the roof at the first level's pace.
  const arrival = 4.2;
  return { stage, game, frame, arrival };
}

describe('Color Gate', () => {
  it('counts the taps to go round from one color to another', () => {
    expect(tapsBetween(0, 0)).toBe(0);
    expect(tapsBetween(0, 1)).toBe(1);
    expect(tapsBetween(0, 2)).toBe(2);
    expect(tapsBetween(2, 0)).toBe(1);
  });

  it('starts on a tap, and a wall in your color passes for points', () => {
    const { game, frame } = setup();
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    press(game);
    expect(game.status()).toMatchObject({ phase: 'run', button: 'SWITCH', lives: 3, score: 0 });
    expect(game.status().message).toMatch(/BLUE/);
    press(game);
    expect(game.status().stats).toContainEqual({ label: 'You', value: 'BLUE' });
    for (let i = 0; i < 60 * 8 && game.status().score === 0; i++) game.update(1 / 60, frame);
    expect(game.status().score).toBe(1);
    expect(game.status().lives).toBe(3);
    // Blue again and again: you stay blue, and the streak goes on.
    run(game, frame, 20);
    expect(game.status().score).toBeGreaterThan(5);
    expect(game.status().lives).toBe(3);
  });

  it('costs a life when a wall reaches you in another color, then game over', () => {
    const { game, frame, arrival } = setup();
    press(game);
    run(game, frame, arrival + 0.3);
    expect(game.status().phase).toBe('miss');
    expect(game.status().lives).toBe(2);
    expect(game.status().tone).toBe('bad');
    for (let i = 0; i < 60 * 60 && game.status().phase !== 'over'; i++) game.update(1 / 60, frame);
    expect(game.status()).toMatchObject({ phase: 'over', lives: 0, button: 'GO!' });
    // A tap right away does not start a new game by accident; a little later it does.
    press(game);
    expect(game.status().phase).toBe('over');
    run(game, frame, 2);
    press(game);
    expect(game.status().phase).toBe('run');
  });

  it('counts a tap that arrives a moment after the wall (Wi-Fi is late)', () => {
    const { game, frame, arrival } = setup();
    press(game);
    run(game, frame, arrival + LAG / 2);
    press(game);
    run(game, frame, 0.5);
    expect(game.status()).toMatchObject({ score: 1, lives: 3 });
  });

  it('marks only the next wall in white', () => {
    const { stage, game, frame } = setup();
    press(game);
    const roof = stage.fixtures.find((f) => f.kind === 'roof')!;
    for (let t = 0; t < 12; t++) {
      run(game, frame, 0.25);
      const white: number[] = [];
      for (let i = 0; i < roof.count; i++) {
        const k = (roof.offset + i) * 3;
        if (Math.min(frame.data[k], frame.data[k + 1], frame.data[k + 2]) > 0.5) white.push(i);
      }
      expect(white.length).toBeGreaterThan(0);
      expect(Math.max(...white) - Math.min(...white)).toBeLessThan(10);
    }
  });

  it('paints the bushes your color', () => {
    const { stage, game, frame } = setup();
    press(game);
    run(game, frame, 0.5);
    const bush = stage.fixtures.find((f) => f.kind === 'bush')!;
    const k = bush.offset * 3;
    // Green: green bright, red and blue dim.
    expect(frame.data[k + 1]).toBeGreaterThan(0.4);
    expect(frame.data[k]).toBeLessThan(0.15);
    press(game);
    run(game, frame, 0.5);
    // Blue.
    expect(frame.data[k + 2]).toBeGreaterThan(0.4);
    expect(frame.data[k + 1]).toBeLessThan(0.15);
  });

  it('plays the house in its attract loop without losing', () => {
    const { game, frame } = setup();
    run(game, frame, 15);
    expect(game.status().phase).toBe('ready');
  });

  it('plays on a roof alone, and asks for a roofline when there is none', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind === 'roof');
    const stage = buildStage(layout);
    const game = colorgateGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    expect(() => run(game, frame, 8)).not.toThrow();
    expect(game.status().phase).not.toBe('setup');

    const bare = sampleLayout();
    bare.fixtures = bare.fixtures.filter((f) => f.kind !== 'roof');
    expect(colorgateGame(buildStage(bare)).status().phase).toBe('setup');
  });

  it('never sends walls closer than the taps between them need, even at top speed', () => {
    // Real random numbers, a long game played perfectly by reading the next wall.
    const stage = buildStage(sampleLayout());
    const game = colorgateGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const order = ['GREEN', 'BLUE', 'PINK'];
    let you = 0;
    let lastTap = -1;
    let t = 0;
    for (let i = 0; i < 60 * 240; i++) {
      game.update(1 / 60, frame);
      t += 1 / 60;
      const s = game.status();
      const want = order.findIndex((c) => s.message.includes(`Next: ${c}`));
      // A sharp player: at most 6 taps a second.
      if (want >= 0 && want !== you && t - lastTap >= 1 / 6) {
        press(game);
        you = (you + 1) % 3;
        lastTap = t;
      }
    }
    expect(game.status().lives).toBe(3);
    expect(game.status().stats).toContainEqual({ label: 'Speed', value: 15 });
  });
});
