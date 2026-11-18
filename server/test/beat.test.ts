import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { BUTTONS, beatGame, CHANGE_GAP, LAG, LEVELS, PERFECT, type BeatGame, type BeatNote, type Level } from '../src/game/beat.ts';
import { Frame } from '../src/game/frame.ts';

/** The big button (button undefined), or a color button by its index. */
const press = (g: BeatGame, tone?: number, playerId = 'p') => g.input({ playerId, action: 'press', ...(tone === undefined ? {} : { button: BUTTONS[tone] }) });
const release = (g: BeatGame, tone?: number, playerId = 'p') => g.input({ playerId, action: 'release', ...(tone === undefined ? {} : { button: BUTTONS[tone] }) });
const tick = (g: BeatGame, frame: Frame) => g.update(1 / 60, frame);
const run = (g: BeatGame, frame: Frame, seconds: number) => {
  for (let i = 0; i < Math.round(seconds * 60); i++) tick(g, frame);
};

/** Fixed random numbers, so a chart comes out the same every time. */
function seeded(seed: number) {
  vi.spyOn(Math, 'random').mockImplementation(() => {
    seed = (seed * 16807) % 2147483647;
    return seed / 2147483647;
  });
}

/** Waits until the press would be judged right on the next coming note's moment. */
function waitFor(g: BeatGame, frame: Frame, pick: (note: Readonly<BeatNote>) => boolean = () => true) {
  for (let i = 0; i < 60 * 30; i++) {
    const { song, notes } = g.chart();
    const next = notes.find((x) => x.state === 'coming');
    if (next && song - LAG + 1 / 60 > next.time) {
      if (pick(next)) return next;
    }
    tick(g, frame);
  }
  throw new Error('no note came');
}

/**
 * Plays perfectly: presses on every note's moment (with its color's button, or the big button
 * with one color) and holds each hold to its end.
 */
function bot(g: BeatGame, frame: Frame, seconds: number, oneColor = false) {
  let held: number | null = null;
  for (let i = 0; i < Math.round(seconds * 60); i++) {
    const { song, notes } = g.chart();
    if (held !== null && !notes.some((x) => x.state === 'held')) {
      release(g, oneColor ? undefined : held);
      held = null;
    }
    const next = notes.find((x) => x.state === 'coming');
    if (held === null && next && song - LAG + 1 / 60 > next.time && song - LAG <= next.time + PERFECT) {
      press(g, oneColor ? undefined : next.tone);
      if (next.hold) held = next.tone;
    }
    tick(g, frame);
  }
}

const health = (g: BeatGame) => g.status().progress!.value;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Beat Drop', () => {
  it('starts on a tap, and scores a press of the right color right on a note', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    run(game, frame, 1);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    expect(game.status().controls).toBeUndefined();
    press(game);
    expect(game.status()).toMatchObject({ phase: 'play', lives: null, progress: { value: 60, max: 100 } });
    // Four color buttons while playing, left to right, with the arrow keys.
    const controls = game.status().controls!;
    expect(controls.map((c) => c.id)).toEqual(['c0', 'c1', 'c2', 'c3']);
    expect(controls.map((c) => c.keys![0])).toEqual(['ArrowLeft', 'ArrowDown', 'ArrowUp', 'ArrowRight']);
    expect(controls.every((c) => /^#[0-9a-f]{6}$/.test(c.color!))).toBe(true);
    const note = waitFor(game, frame);
    press(game, note.tone);
    expect(note.state).not.toBe('coming');
    expect(game.status().score).toBe(2);
    expect(game.status().message).toMatch(/PERFECT/);
  });

  it('counts the wrong color as a stray, and the note can still be hit with the right one', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const note = waitFor(game, frame);
    press(game, (note.tone + 1) % 4);
    expect(note.state).toBe('coming');
    expect(game.status().message).toMatch(/Wrong color/);
    expect(health(game)).toBeLessThan(60);
    expect(game.status().score).toBe(0);
    press(game, note.tone);
    expect(note.state).not.toBe('coming');
    expect(game.status().score).toBe(2);
    // The big button does nothing while playing with four colors.
    const next = waitFor(game, frame, (x) => x !== note);
    press(game);
    expect(next.state).toBe('coming');
  });

  it('counts a press with no note near it as a stray, without points', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    run(game, frame, 0.5);
    press(game, 0);
    expect(game.status().score).toBe(0);
    expect(game.status().message).toMatch(/Too early/);
    expect(health(game)).toBeLessThan(60);
  });

  it('drains the health meter to game over when nobody plays', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    for (let i = 0; i < 60 * 40 && game.status().phase === 'play'; i++) tick(game, frame);
    expect(game.status().phase).toBe('over');
    expect(game.status().message).toMatch(/Game over|New best/);
    expect(game.status().controls).toBeUndefined();
    // A tap right away does not start a new game; after a moment it does.
    press(game);
    expect(game.status().phase).toBe('over');
    run(game, frame, 2);
    press(game);
    expect(game.status().phase).toBe('play');
  });

  it('scores a hold held to its end, with its own color, more than a tap', () => {
    // The last pattern of each list: the first bars bring a hold of 2 beats and a tap.
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const first = waitFor(game, frame);
    press(game, first.tone);
    const tap = game.status().score;
    expect(tap).toBe(2);

    const hold = waitFor(game, frame, (x) => {
      if (!x.hold) {
        press(game, x.tone);
        return false;
      }
      return true;
    });
    const before = game.status().score;
    const other = (hold.tone + 1) % 4;
    press(game, hold.tone);
    expect(hold.state).toBe('held');
    expect(game.status().button).toBe('HOLD');
    // Another button let go does not let go of the hold.
    release(game, other);
    expect(hold.state).toBe('held');
    while (hold.state === 'held') tick(game, frame);
    release(game, hold.tone);
    expect(hold.state).toBe('done');
    expect(game.status().score - before).toBeGreaterThan(tap);
  });

  it('breaks a hold when its button is let go too soon', () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const hold = waitFor(game, frame, (x) => {
      if (!x.hold) {
        press(game, x.tone);
        return false;
      }
      return true;
    });
    press(game, hold.tone);
    run(game, frame, 0.2);
    release(game, hold.tone);
    expect(hold.state).toBe('broken');
    expect(game.status().message).toMatch(/too soon/);
  });

  it('never changes color between notes too close together, and never sends two at once', () => {
    seeded(5);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.setting!('level', 'hard');
    press(game);
    const seen = new Map<BeatNote, Readonly<BeatNote>>();
    for (let i = 0; i < 60 * 120; i++) {
      for (const x of game.chart().notes) seen.set(x as BeatNote, { ...x });
      bot(game, frame, 1 / 60);
    }
    const all = [...seen.values()].sort((a, b) => a.time - b.time);
    expect(new Set(all.map((x) => x.tone)).size).toBe(4);
    for (let i = 1; i < all.length; i++) {
      const gap = all[i].time - all[i - 1].end;
      expect(gap).toBeGreaterThan(0.16);
      if (gap < CHANGE_GAP - 1e-9) expect(all[i].tone).toBe(all[i - 1].tone);
    }
    expect(game.status().phase).toBe('play');
  });

  it('goes on and on for a perfect player, faster and faster, up to ×4', () => {
    seeded(3);
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

  describe.each(['easy', 'normal', 'hard'] as Level[])('on %s', (level) => {
    it.each([
      ['1', true],
      ['2', false],
      ['4', false]
    ] as const)('lets a perfect player go on with %s color(s)', (colors, oneColor) => {
      seeded(level.length * 7 + Number(colors));
      const stage = buildStage(sampleLayout());
      const game = beatGame(stage);
      const frame = new Frame(stage.pixelCount);
      game.setting!('colors', colors);
      game.setting!('level', level);
      press(game);
      if (oneColor) expect(game.status().controls).toBeUndefined();
      else expect(game.status().controls).toHaveLength(Number(colors));
      const bpm = Number(game.status().stats!.find((s) => s.label === 'BPM')!.value);
      expect(bpm).toBe(LEVELS[level].bpmStart);
      bot(game, frame, 60, oneColor);
      expect(game.status().phase).toBe('play');
      expect(health(game)).toBe(100);
      const tones = new Set(game.chart().notes.map((x) => x.tone));
      if (oneColor) expect([...tones]).toEqual([0]);
      if (colors === '2') expect([...tones].sort()).toEqual([0, 3]);
    });
  });

  it('plays the one-color game with the big button, on any note', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.setting!('colors', '1');
    expect(game.status().message).toMatch(/1 color/);
    press(game);
    expect(game.status()).toMatchObject({ phase: 'play', button: 'TAP' });
    expect(game.status().controls).toBeUndefined();
    waitFor(game, frame);
    press(game);
    expect(game.status().score).toBe(2);
  });

  it('plays the two-color game with the two outside buttons, ← and →', () => {
    seeded(5);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.setting!('colors', '2');
    expect(game.status().message).toMatch(/Normal, 2 colors/);
    press(game);
    const controls = game.status().controls!;
    expect(controls.map((c) => c.id)).toEqual(['c0', 'c3']);
    expect(controls.map((c) => c.label)).toEqual(['←', '→']);
    expect(controls[0].keys).toContain('ArrowLeft');
    expect(controls[1].keys).toContain('ArrowRight');
    expect(game.status().keysHint).toMatch(/two colors/);
    // A while in, both colors have come, and nothing else.
    bot(game, frame, 40);
    expect(health(game)).toBe(100);
    const tones = new Set(game.chart().notes.map((x) => x.tone));
    expect([...tones].sort()).toEqual([0, 3]);
    // The wrong one of the two is a stray; the right one scores.
    const note = waitFor(game, frame, (x) => !x.hold);
    const score = game.status().score;
    press(game, note.tone === 0 ? 3 : 0);
    release(game, note.tone === 0 ? 3 : 0);
    expect(game.status().message).toMatch(/Wrong color/);
    press(game, note.tone);
    expect(game.status().score).toBeGreaterThan(score);
  });

  it('shows the settings before and after a game, not during one, and ignores changes while playing', () => {
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    const ready = game.status().settings!;
    expect(ready.map((x) => [x.id, x.value])).toEqual([
      ['colors', '4'],
      ['level', 'normal']
    ]);
    expect(ready[0].choices.map((c) => c.label)).toEqual(['1 color', '2 colors', '4 colors']);
    expect(ready[1].choices.map((c) => c.label)).toEqual(['Easy', 'Normal', 'Hard']);
    game.setting!('level', 'easy');
    game.setting!('level', 'nonsense');
    game.setting!('speed', 'fast');
    expect(game.status().settings![1].value).toBe('easy');
    expect(game.status().message).toMatch(/Easy, 4 colors/);
    press(game);
    expect(game.status().settings).toBeUndefined();
    game.setting!('level', 'hard');
    game.setting!('colors', '1');
    expect(game.status().controls).toHaveLength(4);
    for (let i = 0; i < 60 * 60 && game.status().phase === 'play'; i++) tick(game, frame);
    expect(game.status().phase).toBe('over');
    // Kept for the next game.
    expect(game.status().settings!.map((x) => x.value)).toEqual(['4', 'easy']);
  });

  it('keeps a best score for each combination of settings', () => {
    seeded(11);
    const stage = buildStage(sampleLayout());
    const game = beatGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.setting!('level', 'hard');
    game.setting!('colors', '1');
    press(game);
    bot(game, frame, 20, true);
    // Stop playing: the health runs out and the score is the best for Hard, 1 color.
    for (let i = 0; i < 60 * 60 && game.status().phase === 'play'; i++) tick(game, frame);
    const scored = game.status().score;
    expect(scored).toBeGreaterThan(0);
    const best = () => game.status().stats!.find((s) => s.label === 'Best')!.value;
    run(game, frame, 11);
    expect(game.status().phase).toBe('ready');
    expect(best()).toBe(scored);
    game.setting!('colors', '4');
    expect(best()).not.toBe(scored);
    game.setting!('colors', '2');
    expect(best()).not.toBe(scored);
    game.setting!('colors', '1');
    game.setting!('level', 'easy');
    expect(best()).not.toBe(scored);
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
