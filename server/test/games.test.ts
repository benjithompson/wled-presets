import { afterEach, describe, expect, it, vi } from 'vitest';
import http from 'node:http';
import { WebSocket } from 'ws';
import { buildStage, sampleLayout, type GameStatus } from '../../shared/layout.ts';
import { cascadeGame } from '../src/game/cascade.ts';
import { duelGame } from '../src/game/duel.ts';
import { Frame } from '../src/game/frame.ts';
import { GameHost } from '../src/game/host.ts';
import { Yard } from '../src/game/kit.ts';
import { overflowGame } from '../src/game/overflow.ts';
import type { Game } from '../src/game/types.ts';

const press = (g: Game, playerId = 'p') => g.input({ playerId, action: 'press', at: 0 });
const release = (g: Game, playerId = 'p') => g.input({ playerId, action: 'release', at: 0 });
const run = (g: Game, frame: Frame, seconds: number) => {
  for (let i = 0; i < Math.round(seconds * 60); i++) g.update(1 / 60, frame);
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the yard as games see it', () => {
  it('knows which way the roof slopes, and sorts the other objects by what they are for', () => {
    const stage = buildStage(sampleLayout());
    const yard = new Yard(stage);
    const { roof } = yard;
    expect(roof.n).toBe(450);
    expect(roof.startsLeft).toBe(true);
    // The sample roof: flat, up to the peak, down, flat.
    const peak = stage.roofCorners.length ? stage.fixtures[0].corners[1] : 0;
    expect(roof.slope[50]).toBeCloseTo(0);
    expect(roof.slope[peak - 30]).toBeGreaterThan(0.5);
    expect(roof.slope[peak + 30]).toBeLessThan(-0.5);
    expect(yard.bushes.map((b) => b.fixture.name)).toEqual(['Left bush', 'Middle bush', 'Right bush']);
    expect(yard.middle).toBeCloseTo(800);
    // The roof right above the middle bush is the peak.
    expect(Math.abs(roof.above(800) - peak)).toBeLessThan(3);
    // Each bush LED knows its height in the bush.
    const b = yard.bushes[0];
    expect(Math.min(...b.up)).toBe(0);
    expect(Math.max(...b.up)).toBe(1);
    expect(b.up[b.bottomUp[0]]).toBe(0);
  });

  it('lights LEDs near a point of the yard, not far ones', () => {
    const stage = buildStage(sampleLayout());
    const yard = new Yard(stage);
    const frame = new Frame(stage.pixelCount);
    yard.begin(frame);
    const bush = yard.bushes[0];
    yard.glow(bush.x, (bush.top + bush.bottom) / 2, 60, [1, 1, 1]);
    const lit = (from: number, count: number) => Array.from({ length: count }, (_, i) => frame.data[(from + i) * 3]).filter((v) => v > 0).length;
    expect(lit(bush.offset, bush.count)).toBeGreaterThan(10);
    expect(lit(yard.bushes[2].offset, yard.bushes[2].count)).toBe(0);
  });
});

describe('Cascade', () => {
  it('sets off a blast on a tap and judges the chain', () => {
    const stage = buildStage(sampleLayout());
    const game = cascadeGame(stage);
    const frame = new Frame(stage.pixelCount);
    expect(game.status()).toMatchObject({ phase: 'ready', button: 'GO!' });
    press(game);
    expect(game.status()).toMatchObject({ phase: 'aim', button: 'BOOM!', lives: 3 });
    expect(game.status().progress!.max).toBeGreaterThan(0);
    run(game, frame, 0.5);
    press(game);
    expect(game.status().phase).toBe('chain');
    run(game, frame, 6);
    expect(['clear', 'fail', 'aim']).toContain(game.status().phase);
  });

  it('pops orbs over a few tries, and paints the bushes with their colors', () => {
    const stage = buildStage(sampleLayout());
    const game = cascadeGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    let painted = 0;
    for (let tries = 0; tries < 3 && game.status().phase !== 'over'; tries++) {
      run(game, frame, 0.3 + tries * 0.4);
      press(game);
      // Watch the chain; the drops land in the bushes.
      for (let i = 0; i < 120; i++) {
        game.update(1 / 60, frame);
        const bushes = stage.fixtures.filter((f) => f.kind === 'bush');
        painted = Math.max(painted, bushes.reduce((a, b) => a + Array.from({ length: b.count }, (_, k) => frame.data[(b.offset + k) * 3] + frame.data[(b.offset + k) * 3 + 1]).filter((v) => v > 0.3).length, 0));
      }
      run(game, frame, 5);
      if (game.status().phase === 'clear' || game.status().phase === 'fail') press(game);
    }
    expect(game.status().score).toBeGreaterThan(0);
    expect(painted).toBeGreaterThan(0);
  });

  it('asks for a roofline when there is none', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind !== 'roof');
    expect(cascadeGame(buildStage(layout)).status().phase).toBe('setup');
  });
});

describe('Overflow', () => {
  /** Plays one pour with a fixed ring: hold for `hold` seconds, let go, wait for the verdict. */
  function pour(hold: number) {
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    const stage = buildStage(sampleLayout());
    const game = overflowGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    run(game, frame, 0.5);
    press(game);
    expect(game.status()).toMatchObject({ phase: 'pour', button: 'LET GO' });
    run(game, frame, hold);
    release(game);
    for (let i = 0; i < 300 && ['pour', 'settle'].includes(game.status().phase); i++) game.update(1 / 60, frame);
    vi.restoreAllMocks();
    return game.status();
  }

  it('fills while held and judges where the light settles: too low, in the ring, or over', () => {
    expect(pour(0.3).phase).toBe('short');
    const results = new Set<string>();
    for (let t = 0.6; t < 3; t += 1 / 30) results.add(pour(t).phase);
    expect([...results].some((p) => p === 'good' || p === 'perfect')).toBe(true);
    // Held too long: it spills over the top while pouring.
    const over = pour(2.8);
    expect(over.phase).toBe('spill');
    expect(over.lives).toBe(2);
  });

  it('scores a stop in the ring and moves on to the next bush', () => {
    let won: GameStatus['phase'] | null = null;
    for (let t = 0.6; t < 3 && !won; t += 1 / 30) {
      const s = pour(t);
      if (s.phase === 'good' || s.phase === 'perfect') {
        won = s.phase;
        expect(s.score).toBeGreaterThan(0);
        expect(s.progress).toEqual({ value: 1, max: 3 });
      }
    }
    expect(won).not.toBeNull();
  });

  it('stops pouring when the player who holds the button leaves', () => {
    const stage = buildStage(sampleLayout());
    const game = overflowGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    run(game, frame, 0.5);
    press(game, 'a');
    release(game, 'b');
    expect(game.status().phase).toBe('pour');
    game.leave!('a');
    expect(game.status().phase).toBe('settle');
  });

  it('asks for a bush or a tree when there is none', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind === 'roof');
    expect(overflowGame(buildStage(layout)).status().phase).toBe('setup');
  });
});

describe('Roof Duel', () => {
  /** The roof position of the brightest LED: the ball. */
  function ball(stage: ReturnType<typeof buildStage>, frame: Frame) {
    let best = -1;
    let at = -1;
    for (let i = 0; i < stage.roofPath.length; i++) {
      const k = stage.roofPath[i] * 3;
      const v = frame.data[k] + frame.data[k + 1] + frame.data[k + 2];
      if (v > best) {
        best = v;
        at = i;
      }
    }
    return at;
  }

  it('gives each phone a side, plays a rally, and scores a ball that gets past an end', () => {
    const stage = buildStage(sampleLayout());
    const game = duelGame(stage);
    const frame = new Frame(stage.pixelCount);
    const n = stage.roofPath.length;
    press(game, 'a');
    expect(game.playerStatus!('a').you).toMatchObject({ name: 'Fire' });
    expect(game.status().phase).toBe('lobby');
    press(game, 'b');
    expect(game.playerStatus!('b').you).toMatchObject({ name: 'Ice' });
    expect(game.status().phase).toBe('countdown');
    // A third phone watches.
    press(game, 'c');
    expect(game.playerStatus!('c')).toMatchObject({ you: null, button: '👀' });

    run(game, frame, 3.5);
    expect(game.status().phase).toBe('serve');
    const serverId = game.playerStatus!('a').button === 'SERVE' ? 'a' : 'b';
    const receiverId = serverId === 'a' ? 'b' : 'a';
    // Fire's end is on the left: roof position 0 on the sample roof.
    const receiverEnd = receiverId === 'a' ? 0 : n - 1;
    press(game, serverId);
    expect(game.status().phase).toBe('rally');

    let hitIt = false;
    for (let i = 0; i < 600; i++) {
      game.update(1 / 60, frame);
      if (Math.abs(ball(stage, frame) - receiverEnd) < n * 0.06) {
        press(game, receiverId);
        hitIt = true;
        break;
      }
    }
    expect(hitIt).toBe(true);
    expect(game.status().message).toMatch(/hit|SMASH/i);
    // Nobody hits it back: it gets past the server's end.
    for (let i = 0; i < 600 && game.status().phase === 'rally'; i++) game.update(1 / 60, frame);
    expect(game.status().phase).toBe('point');
    const scores = game.status().scores!;
    expect(scores[receiverId === 'a' ? 0 : 1].value).toBe(1);
    expect(scores[serverId === 'a' ? 0 : 1].value).toBe(0);
  });

  it('plays the house when one phone taps twice, and the house takes over a side that leaves', () => {
    const stage = buildStage(sampleLayout());
    const game = duelGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game, 'a');
    press(game, 'a');
    expect(game.status().phase).toBe('countdown');
    expect(game.status().scores![1].name).toMatch(/house/);
    game.leave!('a');
    // Nobody is left: back to the lobby.
    expect(game.status().phase).toBe('lobby');
    press(game, 'a');
    press(game, 'b');
    game.leave!('b');
    expect(game.status().scores![1].name).toMatch(/house/);
    // The house serves and plays on its own until someone scores.
    run(game, frame, 3.1);
    for (let i = 0; i < 60 * 60 && game.status().phase !== 'point'; i++) {
      game.update(1 / 60, frame);
      if (game.playerStatus!('a').button === 'SERVE') press(game, 'a');
    }
    expect(game.status().phase).toBe('point');
  });
});

describe('game host with sides', () => {
  it('sends each phone its own side, and passes the release on', async () => {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(sampleLayout(), () => {});
    host.attach(server, '/api/play');
    const open = async () => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
      const last: { status: GameStatus | null } = { status: null };
      ws.on('message', (data, isBinary) => {
        if (isBinary) return;
        const m = JSON.parse(String(data));
        if (m.type === 'status') last.status = m.status;
      });
      await new Promise((r) => ws.on('open', r));
      return { ws, last };
    };
    const a = await open();
    const b = await open();
    a.ws.send(JSON.stringify({ type: 'start', game: 'duel' }));
    await new Promise((r) => setTimeout(r, 50));
    a.ws.send(JSON.stringify({ type: 'input', action: 'press' }));
    a.ws.send(JSON.stringify({ type: 'input', action: 'release' }));
    await new Promise((r) => setTimeout(r, 50));
    b.ws.send(JSON.stringify({ type: 'input', action: 'press' }));
    await new Promise((r) => setTimeout(r, 100));
    expect(a.last.status).toMatchObject({ game: 'duel', you: { name: 'Fire' } });
    expect(b.last.status).toMatchObject({ game: 'duel', you: { name: 'Ice' }, phase: 'countdown' });

    a.ws.send(JSON.stringify({ type: 'start', game: 'overflow' }));
    await new Promise((r) => setTimeout(r, 600));
    a.ws.send(JSON.stringify({ type: 'input', action: 'press' }));
    await new Promise((r) => setTimeout(r, 450));
    a.ws.send(JSON.stringify({ type: 'input', action: 'press' }));
    await new Promise((r) => setTimeout(r, 100));
    expect(a.last.status).toMatchObject({ game: 'overflow', phase: 'pour', button: 'LET GO' });
    a.ws.send(JSON.stringify({ type: 'input', action: 'release' }));
    await new Promise((r) => setTimeout(r, 50));
    expect(a.last.status!.phase).not.toBe('pour');
    a.ws.close();
    b.ws.close();
    host.stop();
    server.close();
  });
});
