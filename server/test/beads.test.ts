import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { BEAD_COLORS, beadsGame, STAGE_EVERY } from '../src/game/beads.ts';
import { Frame } from '../src/game/frame.ts';
import { hex } from '../../shared/color.ts';
import { Yard } from '../src/game/kit.ts';
import { press, release, run } from './harness.ts';

/** Which bead color a bush shows: the one its average color points the same way as. */
function bushTone(stage: ReturnType<typeof buildStage>, frame: Frame, index: number) {
  const bush = new Yard(stage).bushes[index];
  const sum = [0, 0, 0];
  for (let i = 0; i < bush.count; i++) for (let c = 0; c < 3; c++) sum[c] += frame.data[(bush.offset + i) * 3 + c];
  const len = Math.hypot(...sum);
  let best = -1;
  let tone = -1;
  BEAD_COLORS.forEach(({ color: col }, k) => {
    const cos = (col[0] * sum[0] + col[1] * sum[1] + col[2] * sum[2]) / (len * Math.hypot(...col));
    if (cos > best) {
      best = cos;
      tone = k;
    }
  });
  return { tone, match: best };
}

/**
 * A good player: one move every `every` frames once the shot has landed: fire when the loaded
 * color matches the front (or the front is gold), else turn the short way round toward it.
 */
function play(game: ReturnType<typeof beadsGame>, frame: Frame, seconds: number, every: number) {
  let closest = Infinity;
  for (let f = 0; f < 60 * seconds && game.status().phase !== 'over'; f++) {
    game.update(1 / 60, frame);
    const p = game.peek();
    if (f > 60) closest = Math.min(closest, p.front);
    if (p.flying || f % every) continue;
    const front = p.tones[0];
    if (front === -1 || front === p.loaded) {
      press(game);
      continue;
    }
    const m = p.palette.length;
    const right = (p.palette.indexOf(front) - p.palette.indexOf(p.loaded) + m) % m;
    press(game, right <= m - right ? 'right' : 'left');
  }
  return closest;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Bead Rush', () => {
  it('starts on a tap, with three buttons in play and the big one before and after', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    expect(game.status().controls).toBeUndefined();
    // Left and right do not start a game.
    press(game, 'left');
    expect(game.status().phase).toBe('ready');
    press(game);
    expect(game.status()).toMatchObject({ phase: 'play', button: 'FIRE', lives: 3, score: 0 });
    run(game, frame, 1);
    const s = game.status();
    expect(s.controls!.map((c) => c.id)).toEqual(['left', 'main', 'right']);
    expect(s.controls![1]).toMatchObject({ big: true, color: hex(BEAD_COLORS[game.peek().loaded].color) });
    expect(s.controls![0].keys).toContain('ArrowLeft');
    expect(s.controls![2].keys).toContain('ArrowRight');
    expect(s.keysHint).toMatch(/←/);
    expect(s.stats).toContainEqual({ label: 'Colors', value: 3 });
  });

  it('turns the color wheel left and right, wrapping round, and the bushes follow', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const { palette } = game.peek();
    expect(palette.map((t) => BEAD_COLORS[t].name)).toEqual(['green', 'blue', 'magenta']);
    const at = () => palette.indexOf(game.peek().loaded);
    const start = at();
    press(game, 'right');
    expect(at()).toBe((start + 1) % 3);
    press(game, 'right');
    press(game, 'right');
    expect(at()).toBe(start);
    press(game, 'left');
    expect(at()).toBe((start + 2) % 3);
    // Releases do nothing.
    release(game, 'left');
    release(game);
    expect(at()).toBe((start + 2) % 3);
    expect(game.peek().flying).toBe(false);
    run(game, frame, 0.1);
    // The middle bush shows the loaded color; the left and right bushes what the buttons would pick.
    const loaded = game.peek().loaded;
    expect(bushTone(stage, frame, 1)).toMatchObject({ tone: loaded });
    expect(bushTone(stage, frame, 0).tone).toBe(palette[(at() + 2) % 3]);
    expect(bushTone(stage, frame, 2).tone).toBe(palette[(at() + 1) % 3]);
    expect(game.status().controls![0].color).toBe(hex(BEAD_COLORS[palette[(at() + 2) % 3]].color));
  });

  it('fires on the press, and pops three of a color at the front', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    run(game, frame, 0.2);
    press(game);
    expect(game.peek().flying).toBe(true);
    const closest = play(game, frame, 5, 12);
    expect(game.status().score).toBeGreaterThan(0);
    expect(closest).toBeGreaterThan(stage.roofPath.length * 0.4);
  });

  it('adds a color at each stage and keeps the selected one', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    play(game, frame, STAGE_EVERY - 1, 18);
    expect(game.peek().stage).toBe(1);
    const loaded = game.peek().loaded;
    run(game, frame, 1.5);
    expect(game.peek()).toMatchObject({ stage: 2, loaded });
    expect(game.peek().palette.map((t) => BEAD_COLORS[t].name)).toEqual(['green', 'cyan', 'blue', 'magenta']);
    expect(game.status().message).toBe('New color: cyan!');
    expect(game.status().stats).toContainEqual({ label: 'Colors', value: 4 });
    play(game, frame, STAGE_EVERY, 18);
    expect(game.peek().stage).toBe(3);
    expect(game.peek().palette).toHaveLength(5);
    // New beads come in all five colors.
    play(game, frame, 30, 18);
    const tones = new Set(game.peek().tones.filter((t) => t >= 0));
    expect(tones.size).toBe(5);
  });

  it('costs a life when the chain reaches the launcher, and ends the game when nobody plays', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    let lostOne = false;
    for (let i = 0; i < 60 * 400 && game.status().phase !== 'over'; i++) {
      game.update(1 / 60, frame);
      if (game.status().phase === 'breach') lostOne = true;
    }
    expect(lostOne).toBe(true);
    expect(game.status()).toMatchObject({ phase: 'over', lives: 0, button: 'GO!' });
    expect(game.status().controls).toBeUndefined();
    // A tap right away does not start a new game; one a little later does.
    press(game);
    expect(game.status().phase).toBe('over');
    run(game, frame, 2);
    press(game);
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
    press(game);
    play(game, frame, 10, 18);
    expect(['play', 'breach']).toContain(game.status().phase);
    expect(game.status().score).toBeGreaterThan(0);
    expect(frame.data.some((v) => v > 0.3)).toBe(true);
  });

  it('lets a quick player who turns the short way keep up for ever, with every color in play', () => {
    const stage = buildStage(sampleLayout());
    const game = beadsGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    // Ten minutes: every stage and the full creep (it ramps up over the first three), one move every 0.3 s.
    const closest = play(game, frame, 600, 18);
    expect(game.peek().stage).toBe(3);
    expect(game.status()).toMatchObject({ phase: 'play', lives: 3 });
    expect(closest).toBeGreaterThan(stage.roofPath.length * 0.15);
  });
});
