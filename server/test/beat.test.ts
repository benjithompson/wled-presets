import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { beatGame, LAG, PERFECT, type BeatGame } from '../src/game/beat.ts';
import { Frame } from '../src/game/frame.ts';

const press = (g: BeatGame, playerId = 'p') => g.input({ playerId, action: 'press' });
const release = (g: BeatGame, playerId = 'p') => g.input({ playerId, action: 'release' });
const tick = (g: BeatGame, frame: Frame) => g.update(1 / 60, frame);
const run = (g: BeatGame, frame: Frame, seconds: number) => {
  for (let i = 0; i < Math.round(seconds * 60); i++) tick(g, frame);
};

/** Waits until the press would be judged right on the next coming note's moment. */
function waitFor(g: BeatGame, frame: Frame, pick: (hold: boolean) => boolean = () => true) {
  for (let i = 0; i < 60 * 30; i++) {
    const { song, notes } = g.chart();
    const next = notes.find((x) => x.state === 'coming');
    if (next && song - LAG + 1 / 60 > next.time) {
      if (pick(next.hold)) return next;
    }
    tick(g, frame);
  }
  throw new Error('no note came');
}

/** Plays perfectly: presses on every note's moment and holds each hold to its end. */
function bot(g: BeatGame, frame: Frame, seconds: number) {
  let held = false;
  for (let i = 0; i < Math.round(seconds * 60); i++) {
    const { song, notes } = g.chart();
    if (held && !notes.some((x) => x.state === 'held')) {
      release(g);
      held = false;
    }
    const next = notes.find((x) => x.state === 'coming');
    if (!held && next && song - LAG + 1 / 60 > next.time && song - LAG <= next.time + PERFECT) {
      press(g);
      held = next.hold;
    }
    tick(g, frame);
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Beat Drop', () => {
  it('starts on a tap, and scores a tap right on a note', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    run(game, frame, 1);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    press(game);
    expect(game.status()).toMatchObject({ phase: 'play', button: 'TAP', lives: null, progress: { value: 60, max: 100 } });
    const note = waitFor(game, frame);
    press(game);
    expect(note.state).not.toBe('coming');
    expect(game.status().score).toBe(2);
    expect(game.status().message).toMatch(/PERFECT/);
  });

  it('counts a tap with no note near it as a stray, without points', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    run(game, frame, 0.5);
    press(game);
    expect(game.status().score).toBe(0);
    expect(game.status().progress!.value).toBeLessThan(60);
  });

  it('drains the health meter to game over when nobody plays', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    for (let i = 0; i < 60 * 40 && game.status().phase === 'play'; i++) tick(game, frame);
    expect(game.status().phase).toBe('over');
    expect(game.status().message).toMatch(/Game over|New best/);
    // A tap right away does not start a new game; after a moment it does.
    press(game);
    expect(game.status().phase).toBe('over');
    run(game, frame, 2);
    press(game);
    expect(game.status().phase).toBe('play');
  });

  it('scores a hold held to its end more than a tap', () => {
    // The last pattern of each list: the first bars bring a hold of 2 beats and a tap.
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    waitFor(game, frame);
    press(game);
    const tap = game.status().score;
    expect(tap).toBe(2);

    const hold = waitFor(game, frame, (h) => {
      if (!h) {
        press(game);
        return false;
      }
      return true;
    });
    const before = game.status().score;
    press(game);
    expect(hold.state).toBe('held');
    expect(game.status().button).toBe('HOLD');
    while (hold.state === 'held') tick(game, frame);
    release(game);
    expect(hold.state).toBe('done');
    expect(game.status().score - before).toBeGreaterThan(tap);
  });

  it('breaks a hold let go too soon', () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const hold = waitFor(game, frame, (h) => {
      if (!h) {
        press(game);
        return false;
      }
      return true;
    });
    press(game);
    run(game, frame, 0.2);
    release(game);
    expect(hold.state).toBe('broken');
    expect(game.status().message).toMatch(/too soon/);
  });

  it('goes on and on for a perfect player, faster and faster, up to ×4', () => {
    let seed = 3;
    vi.spyOn(Math, 'random').mockImplementation(() => {
      seed = (seed * 16807) % 2147483647;
      return seed / 2147483647;
    });
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const bpm = () => Number(game.status().stats!.find((s) => s.label === 'BPM')!.value);
    const start = bpm();
    bot(game, frame, 90);
    const s = game.status();
    expect(s.phase).toBe('play');
    expect(s.progress!.value).toBe(100);
    expect(s.stats).toContainEqual({ label: 'Multiplier', value: '×4' });
    expect(bpm()).toBeGreaterThan(start + 30);
    expect(s.score).toBeGreaterThan(300);
  });

  it('lights the bushes gold as the multiplier climbs', () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.3);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    const bushes = stage.fixtures.filter((f) => f.kind === 'bush');
    const litBushes = () => bushes.filter((b) => frame.data[b.offset * 3] > 0.25).length;
    press(game);
    run(game, frame, 0.1);
    expect(litBushes()).toBe(0);
    bot(game, frame, 40);
    expect(litBushes()).toBe(3);
  });

  it('asks for a roofline when there is none', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind !== 'roof');
    expect(beatGame(buildStage(layout)).status().phase).toBe('setup');
  });

  it('plays on a roof alone', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind === 'roof');
    const stage = buildStage(layout);
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    bot(game, frame, 8);
    expect(game.status().phase).toBe('play');
    expect(game.status().score).toBeGreaterThan(0);
    expect(Math.max(...frame.data)).toBeGreaterThan(0.3);
  });
});
