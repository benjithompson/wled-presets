import { describe, expect, it } from 'vitest';
import http from 'node:http';
import { WebSocket } from 'ws';
import { buildStage, sampleLayout } from '../../shared/layout.ts';
import { cleanStroke, type PaintStroke } from '../../shared/paint.ts';
import { Frame } from '../src/game/frame.ts';
import { GameHost } from '../src/game/host.ts';
import { Yard } from '../src/game/kit.ts';
import { paintGame } from '../src/game/paint.ts';
import type { Game } from '../src/game/types.ts';

const stage = buildStage(sampleLayout());
const yard = new Yard(stage);
const [left, middle, right] = yard.bushes;
const roof = stage.fixtures.find((f) => f.kind === 'roof')!;

const run = (g: Game, frame: Frame, seconds: number) => {
  for (let i = 0; i < Math.round(seconds * 60); i++) g.update(1 / 60, frame);
};
const stroke = (points: number[], more: Partial<PaintStroke> = {}): PaintStroke & { playerId: string } => ({
  playerId: 'p',
  finger: 0,
  start: true,
  points,
  radius: 40,
  color: 'blue',
  effect: 'still',
  fill: false,
  ...more
});
const tap = (g: Game, button: string) => g.input({ playerId: 'p', action: 'press', button });
/** How many LEDs of an object are lit, and how bright its brightest one is in each channel. */
function lit(frame: Frame, part: { offset: number; count: number }) {
  let count = 0;
  const max = [0, 0, 0];
  for (let i = part.offset; i < part.offset + part.count; i++) {
    const rgb = [0, 1, 2].map((c) => frame.data[i * 3 + c]);
    if (rgb.some((v) => v > 0.05)) count++;
    rgb.forEach((v, c) => (max[c] = Math.max(max[c], v)));
  }
  return { count, max };
}
const middleOf = (b: typeof left) => [b.x, (b.top + b.bottom) / 2];

describe('Light Painter', () => {
  it('paints the lights under the finger in its color, and nothing else', () => {
    const game = paintGame(stage);
    const frame = new Frame(stage.pixelCount);
    expect(game.status()).toMatchObject({ phase: 'paint', paint: { empty: true, canUndo: false } });
    game.paint!(stroke(middleOf(left)));
    run(game, frame, 1);
    const l = lit(frame, left);
    expect(l.count).toBeGreaterThan(5);
    expect(l.count).toBeLessThan(left.count);
    // Blue: much more blue than red.
    expect(l.max[2]).toBeGreaterThan(l.max[0] * 3);
    expect(lit(frame, middle).count).toBe(0);
    expect(lit(frame, roof).count).toBe(0);
    expect(game.status()).toMatchObject({ paint: { empty: false, canUndo: true } });
  });

  it('joins the points of a stroke, so a fast finger leaves no gaps', () => {
    const game = paintGame(stage);
    const frame = new Frame(stage.pixelCount);
    // Two points a whole bush apart, sent as one stroke.
    game.paint!(stroke([left.left, (left.top + left.bottom) / 2], { radius: 15 }));
    game.paint!(stroke([left.right, (left.top + left.bottom) / 2], { radius: 15, start: false }));
    run(game, frame, 1);
    const lights = Array.from({ length: left.count }, (_, i) => left.offset + i).filter((i) => frame.data[i * 3 + 2] > 0.05);
    const xs = lights.map((i) => stage.positions[i * 2]);
    // Lit all the way across, not just at the two ends.
    const middleX = (left.left + left.right) / 2;
    expect(xs.some((x) => Math.abs(x - middleX) < (left.right - left.left) * 0.15)).toBe(true);
  });

  it('fills a whole object in one touch, in a ripple from the finger', () => {
    const game = paintGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.paint!(stroke(middleOf(middle), { fill: true, color: 'green', radius: 20 }));
    run(game, frame, 0.1);
    const early = lit(frame, middle).count;
    run(game, frame, 1);
    const later = lit(frame, middle).count;
    expect(early).toBeLessThan(later);
    expect(later).toBe(middle.count);
    expect(lit(frame, left).count).toBe(0);
  });

  it('takes back a stroke, sweeps everything away, and puts it back', () => {
    const game = paintGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.paint!(stroke(middleOf(left), { fill: true }));
    game.paint!(stroke(middleOf(right), { fill: true, color: 'red' }));
    run(game, frame, 1);
    expect(lit(frame, right).count).toBe(right.count);
    tap(game, 'undo');
    run(game, frame, 0.6);
    expect(lit(frame, right).count).toBe(0);
    expect(lit(frame, left).count).toBe(left.count);
    tap(game, 'clear');
    run(game, frame, 2);
    expect(lit(frame, left).count).toBe(0);
    expect(game.status()).toMatchObject({ paint: { empty: true } });
    tap(game, 'undo');
    run(game, frame, 0.6);
    expect(lit(frame, left).count).toBe(left.count);
  });

  it('erases where the eraser goes', () => {
    const game = paintGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.paint!(stroke(middleOf(left), { fill: true }));
    run(game, frame, 1);
    game.paint!(stroke(middleOf(left), { color: 'erase', radius: 400 }));
    run(game, frame, 1);
    expect(lit(frame, left).count).toBe(0);
  });

  it('paints the whole yard on Surprise', () => {
    const game = paintGame(stage);
    const frame = new Frame(stage.pixelCount);
    tap(game, 'surprise');
    run(game, frame, 2);
    for (const f of stage.fixtures) expect(lit(frame, f).count, f.name).toBeGreaterThan(0);
  });

  it('turns down paint messages that are not right', () => {
    const good = { finger: 0, start: true, points: [1, 2], radius: 10, color: 'red', effect: 'chase', fill: false };
    expect(cleanStroke(good)).toEqual(good);
    expect(cleanStroke({ ...good, finger: 9 })).toBeNull();
    expect(cleanStroke({ ...good, points: [1] })).toBeNull();
    expect(cleanStroke({ ...good, points: [1, Infinity] })).toBeNull();
    expect(cleanStroke({ ...good, points: Array(200).fill(1) })).toBeNull();
    expect(cleanStroke({ ...good, color: '#123456' })).toBeNull();
    expect(cleanStroke({ ...good, effect: 'boom' })).toBeNull();
    expect(cleanStroke({ ...good, radius: -1 })).toBeNull();
  });

  it('gets strokes from the phone with the turn through the game host', async () => {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(sampleLayout(), () => {});
    host.attach(server, '/api/play');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    let status: Record<string, unknown> | null = null;
    ws.on('message', (data, isBinary) => {
      if (isBinary) return;
      const m = JSON.parse(String(data));
      if (m.type === 'status') status = m.status;
    });
    await new Promise((r) => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', game: 'paint' }));
    await new Promise((r) => setTimeout(r, 50));
    expect(status).toMatchObject({ game: 'paint', paint: { empty: true } });
    const [x, y] = middleOf(left);
    ws.send(JSON.stringify({ type: 'paint', finger: 0, start: true, points: [x, y], radius: 40, color: 'pink', effect: 'twinkle', fill: true }));
    ws.send(JSON.stringify({ type: 'paint', finger: 0, start: true, points: [x, y], radius: 40, color: 'nope', effect: 'twinkle', fill: true }));
    await new Promise((r) => setTimeout(r, 150));
    expect(status).toMatchObject({ game: 'paint', paint: { empty: false, canUndo: true } });
    ws.close();
    host.stop();
    server.close();
  });
});
