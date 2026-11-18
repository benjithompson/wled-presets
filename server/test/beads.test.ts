import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { beadsGame } from '../src/game/beads.ts';
import { ORB_COLORS } from '../src/game/cascade.ts';
import { Frame } from '../src/game/frame.ts';
import { Yard } from '../src/game/kit.ts';
import type { Game } from '../src/game/types.ts';

const press = (g: Game, playerId = 'p') => g.input({ playerId, action: 'press' });
const release = (g: Game, playerId = 'p') => g.input({ playerId, action: 'release' });
const tap = (g: Game) => {
  press(g);
  release(g);
};
const run = (g: Game, frame: Frame, seconds: number) => {
  for (let i = 0; i < Math.round(seconds * 60); i++) g.update(1 / 60, frame);
};

/** Fixed random numbers, so a game plays the same every time. */
function seeded(seed: number) {
  vi.spyOn(Math, 'random').mockImplementation(() => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  });
}

/** Which bead color a bush shows: the one its average color points the same way as. */
function bushTone(stage: ReturnType<typeof buildStage>, frame: Frame, nearest: number) {
  const yard = new Yard(stage);
  const x0 = yard.roof.point(0).x;
  const bush = [...yard.bushes].sort((a, b) => Math.abs(a.x - x0) - Math.abs(b.x - x0))[nearest];
  const sum = [0, 0, 0];
  for (let i = 0; i < bush.count; i++) for (let c = 0; c < 3; c++) sum[c] += frame.data[(bush.offset + i) * 3 + c];
  const len = Math.hypot(...sum);
  let best = -1;
  let tone = -1;
  ORB_COLORS.forEach((col, k) => {
    const cos = (col[0] * sum[0] + col[1] * sum[1] + col[2] * sum[2]) / (len * Math.hypot(...col));
    if (cos > best) {
      best = cos;
      tone = k;
    }
  });
  return { tone, match: best };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Bead Rush', () => {
  it('starts on a tap, and the chain creeps toward the launcher', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    press(game);
    release(game);
    expect(game.status()).toMatchObject({ phase: 'play', button: 'FIRE', lives: 3, score: 0 });
    run(game, frame, 1);
    expect(game.status().message).toMatch(/tap to fire, hold to swap/i);
  });

  it('fires on a quick tap, and pops three of a color at the front', () => {
    seeded(11);
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    tap(game);
    run(game, frame, 0.2);
    // Shots that match the front of the chain (with a swap first when only the next bead does).
    const before = game.peek().tones.length;
    let shots = 0;
    for (let i = 0; i < 40 && game.status().score === 0; i++) {
      const p = game.peek();
      if (p.loaded !== p.tones[0]) {
        press(game);
        run(game, frame, 0.4);
        release(game);
      }
      tap(game);
      shots++;
      run(game, frame, 0.35);
    }
    expect(game.status().score).toBeGreaterThan(0);
    expect(shots).toBeLessThanOrEqual(2);
    // The popped beads left the chain (shots added some, the feed adds more at the far end).
    expect(game.peek().front).toBeGreaterThan(stage.roofPath.length * 0.5);
    expect(before).toBeGreaterThan(0);
  });

  it('swaps the loaded and next beads on a long hold, and does not fire on its release', () => {
    const stage = buildStage(sampleLayout());
    const frame = new Frame(stage.pixelCount);
    // A game whose loaded and next beads differ (they can be the same color).
    let game = beadsGame(stage);
    let loaded = { tone: -1, match: 0 };
    let next = { tone: -1, match: 0 };
    for (let seed = 1; seed < 20 && loaded.tone === next.tone; seed++) {
      vi.restoreAllMocks();
      seeded(seed);
      game = beadsGame(stage);
      tap(game);
      run(game, frame, 0.2);
      loaded = bushTone(stage, frame, 0);
      next = bushTone(stage, frame, 1);
    }
    expect(loaded.match).toBeGreaterThan(0.95);
    expect(next.match).toBeGreaterThan(0.95);
    expect(loaded.tone).not.toBe(next.tone);
    press(game);
    run(game, frame, 0.4);
    expect(bushTone(stage, frame, 0).tone).toBe(next.tone);
    expect(bushTone(stage, frame, 1).tone).toBe(loaded.tone);
    release(game);
    run(game, frame, 0.2);
    // No shot: the launcher still holds the swapped bead.
    expect(bushTone(stage, frame, 0).tone).toBe(next.tone);
  });

  it('costs a life when the chain reaches the launcher, and ends the game when nobody plays', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    tap(game);
    let lostOne = false;
    for (let i = 0; i < 60 * 400 && game.status().phase !== 'over'; i++) {
      game.update(1 / 60, frame);
      if (game.status().phase === 'breach') lostOne = true;
    }
    expect(lostOne).toBe(true);
    expect(game.status()).toMatchObject({ phase: 'over', lives: 0, button: 'GO!' });
    // A tap right away does not start a new game; one a little later does.
    tap(game);
    expect(game.status().phase).toBe('over');
    run(game, frame, 2);
    tap(game);
    expect(game.status().phase).toBe('play');
  });

  it('forgets a held button when its player leaves', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    tap(game);
    press(game, 'a');
    game.leave!('a');
    run(game, frame, 0.5);
    release(game, 'a');
    expect(game.status().phase).toBe('play');
  });

  it('asks for a roofline when there is none', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind !== 'roof');
    expect(beadsGame(buildStage(layout)).status().phase).toBe('setup');
  });

  it('plays on a roof alone', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind === 'roof');
    const stage = buildStage(layout);
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    tap(game);
    for (let i = 0; i < 30; i++) {
      tap(game);
      run(game, frame, 0.3);
    }
    expect(['play', 'breach']).toContain(game.status().phase);
    expect(frame.data.some((v) => v > 0.3)).toBe(true);
  });

  it('always offers a matching bead, so a quick player who plans the swaps keeps up for ever', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    tap(game);
    let wasted = 0;
    let holdUntil = -1;
    let closest = Infinity;
    // Ten minutes at full pace (it ramps up over the first three), one move every 0.4 s.
    for (let f = 0; f < 60 * 600; f++) {
      game.update(1 / 60, frame);
      const p = game.peek();
      if (f > 60) closest = Math.min(closest, p.front);
      if (holdUntil >= 0) {
        if (f >= holdUntil) {
          release(game);
          holdUntil = -1;
        }
        continue;
      }
      if (p.flying || f % 24) continue;
      const front = p.tones[0];
      if (p.loaded === front || front === -1) tap(game);
      else if (p.next === front) {
        press(game);
        holdUntil = f + 21;
      } else {
        wasted++;
        tap(game);
      }
    }
    expect(wasted).toBe(0);
    expect(game.status()).toMatchObject({ phase: 'play', lives: 3 });
    expect(closest).toBeGreaterThan(stage.roofPath.length * 0.15);
  });
});
