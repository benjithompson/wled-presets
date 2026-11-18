import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { Frame } from '../src/game/frame.ts';
import { ricochetGame } from '../src/game/ricochet.ts';

const press = (g: { input: (e: { playerId: string; action: 'press' | 'release' }) => void }) => g.input({ playerId: 'p', action: 'press' });

afterEach(() => {
  vi.restoreAllMocks();
});

function setup(layout = sampleLayout()) {
  const stage = buildStage(layout);
  const game = ricochetGame(stage);
  const frame = new Frame(stage.pixelCount);
  return { stage, game, frame };
}

/** The roof position (along the roof track) of the brightest white LED: the comet's head. */
function head(stage: ReturnType<typeof buildStage>, frame: Frame) {
  let best = -1;
  let at = -1;
  for (let i = 0; i < stage.roofPath.length; i++) {
    const k = stage.roofPath[i] * 3;
    const v = Math.min(frame.data[k], frame.data[k + 1], frame.data[k + 2]);
    if (v > best) {
      best = v;
      at = i;
    }
  }
  return at;
}

/** Runs until the comet is no more than `within` steps from the middle of the gate (0: it just crossed the middle). */
function runUntilInGate(game: ReturnType<typeof ricochetGame>, frame: Frame, within = 1) {
  for (let i = 0; i < 2000; i++) {
    game.update(1 / 60, frame);
    if (game.peek().toGo <= within) return true;
  }
  return false;
}

describe('Ricochet', () => {
  it('starts on a press, scores a catch in the gate, and turns the comet around', () => {
    const { stage, game, frame } = setup();
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    press(game);
    expect(game.status()).toMatchObject({ phase: 'running', button: 'CATCH', score: 0 });
    // The gate is ahead, where the comet has not been on its way there.
    expect(game.peek().toGo).toBeGreaterThan(0);
    // Close to the middle, but not dead center: one point.
    expect(runUntilInGate(game, frame, game.peek().halfWidth * 0.6)).toBe(true);
    const before = head(stage, frame);
    const dir = game.peek().dir;
    const gateBefore = game.peek().gate;
    press(game);
    expect(game.status()).toMatchObject({ phase: 'running', score: 1 });
    expect(game.peek().dir).toBe(-dir);
    // A new gate is already waiting, somewhere else.
    expect(game.peek().gate).not.toBe(gateBefore);
    expect(game.peek().toGo).toBeGreaterThan(game.peek().halfWidth);
    // The head moves back the way it came.
    for (let i = 0; i < 12; i++) game.update(1 / 60, frame);
    expect(Math.sign(head(stage, frame) - before)).toBe(-dir);
  });

  it('gives double for a catch dead in the middle, and speeds up with every catch', () => {
    const { game, frame } = setup();
    press(game);
    expect(runUntilInGate(game, frame, 0)).toBe(true);
    press(game);
    expect(game.status().score).toBe(2);
    expect(game.status().message).toMatch(/PERFECT/);
    expect(game.status().stats).toContainEqual({ label: 'Speed', value: '×1.02' });
  });

  it('ends the run on a press outside the gate', () => {
    const { game, frame } = setup();
    press(game);
    game.update(1 / 60, frame);
    expect(game.peek().toGo).toBeGreaterThan(game.peek().halfWidth * 2);
    press(game);
    expect(game.status().phase).toBe('over');
    // A quick tap does not start again at once.
    press(game);
    expect(game.status().phase).toBe('over');
    for (let i = 0; i < 100; i++) game.update(1 / 60, frame);
    press(game);
    expect(game.status().phase).toBe('running');
  });

  it('ends the run when the comet gets through the gate, not before the grace for a late tap', () => {
    const { game, frame } = setup();
    press(game);
    let passedAt = Infinity;
    for (let i = 0; i < 600 && game.status().phase === 'running'; i++) {
      game.update(1 / 60, frame);
      const { toGo, halfWidth } = game.peek();
      if (toGo < -halfWidth && passedAt === Infinity) passedAt = i;
    }
    expect(game.status().phase).toBe('over');
    // A late press just after the comet leaves the gate still counts.
    const late = setup();
    press(late.game);
    for (let i = 0; i < 600; i++) {
      late.game.update(1 / 60, late.frame);
      const { toGo, halfWidth } = late.game.peek();
      if (toGo < -halfWidth) break;
    }
    expect(late.game.status().phase).toBe('running');
    press(late.game);
    expect(late.game.status()).toMatchObject({ phase: 'running', score: 1 });
  });

  it('lights a bush every 10 catches and keeps going', () => {
    const { stage, game, frame } = setup();
    press(game);
    for (let c = 0; c < 10; c++) {
      expect(runUntilInGate(game, frame, 3)).toBe(true);
      press(game);
      expect(game.status().phase).toBe('running');
    }
    // Keep catching while the streak flies to the first bush and it lights up.
    for (let i = 0; i < 90; i++) {
      game.update(1 / 60, frame);
      if (game.peek().toGo <= 3) press(game);
    }
    expect(game.status().phase).toBe('running');
    const bush = stage.fixtures.find((f) => f.kind === 'bush')!;
    const lit = Array.from({ length: bush.count }, (_, i) => Math.max(frame.data[(bush.offset + i) * 3], frame.data[(bush.offset + i) * 3 + 1], frame.data[(bush.offset + i) * 3 + 2])).filter((v) => v > 0.3).length;
    expect(lit).toBeGreaterThan(bush.count * 0.5);
  });

  it('asks for a roofline when there is none, and plays on a roof alone', () => {
    const none = sampleLayout();
    none.fixtures = none.fixtures.filter((f) => f.kind !== 'roof');
    expect(ricochetGame(buildStage(none)).status().phase).toBe('setup');

    const roofOnly = sampleLayout();
    roofOnly.fixtures = roofOnly.fixtures.filter((f) => f.kind === 'roof');
    const { game, frame } = setup(roofOnly);
    press(game);
    for (let c = 0; c < 3; c++) {
      expect(runUntilInGate(game, frame, 2)).toBe(true);
      press(game);
    }
    expect(game.status().score).toBeGreaterThanOrEqual(3);
    for (let i = 0; i < 1200; i++) game.update(1 / 60, frame);
    expect(game.status().phase).not.toBe('running');
  });
});
