import { afterEach, describe, expect, it, vi } from 'vitest';
import http from 'node:http';
import { WebSocket } from 'ws';
import { buildStage, GAME_UNSEEN_RGB, MAX_SPEEDUP, paintGameArea, roofTrack, sampleLayout, segmentLeds, type Fixture, type GameStatus, type Layout, type Point } from '../../shared/layout.ts';
import { catcherGame } from '../src/game/catcher.ts';
import { cascadeGame } from '../src/game/cascade.ts';
import { duelGame } from '../src/game/duel.ts';
import { Frame } from '../src/game/frame.ts';
import { GameHost } from '../src/game/host.ts';
import { Yard } from '../src/game/kit.ts';
import { overflowGame } from '../src/game/overflow.ts';
import type { Game } from '../src/game/types.ts';

const press = (g: Game, playerId = 'p') => g.input({ playerId, action: 'press' });
const release = (g: Game, playerId = 'p') => g.input({ playerId, action: 'release' });
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

describe('the roof as it looks from the street', () => {
  /** A layout with one roof line through these points (z: toward the street), 3 LEDs per 10 units. */
  function roofLayout(points: Point[]): Layout {
    const layout = sampleLayout();
    let length = 0;
    for (let i = 1; i < points.length; i++) length += Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y, (points[i].z ?? 0) - (points[i - 1].z ?? 0));
    const roof: Fixture = { ...layout.fixtures[0], points, pixels: Math.round(length * 0.3) };
    layout.fixtures = [roof, ...layout.fixtures.slice(1)];
    return layout;
  }
  /** The roof LEDs that show from the street, and the ones that do not. */
  function split(stage: ReturnType<typeof buildStage>) {
    const t = roofTrack(stage);
    const seen = Array.from(t.leds).filter((_, k) => !t.hidden[k]);
    const hidden = Array.from(t.leds).filter((_, k) => t.hidden[k]);
    return { t, seen, hidden };
  }

  it('runs very quickly, but not in one jump, through a stretch that cannot be seen from the street', () => {
    // Along the front, then 6 m straight back along the right side, then along the back.
    const stage = buildStage(roofLayout([{ x: 200, y: 470 }, { x: 1000, y: 470 }, { x: 1000, y: 470, z: -600 }, { x: 200, y: 470, z: -600 }]));
    const { t, seen, hidden } = split(stage);
    // The side, and the back (behind the front as seen from the street), are hidden.
    expect(hidden.length).toBeGreaterThan(stage.fixtures[0].count * 0.6);
    expect(seen.length).toBeGreaterThan(230);
    // Along the front, one step per LED (less for the pair across the corner, which is partly
    // on the side); through the hidden stretch, 1 / MAX_SPEEDUP of a step.
    let odd = 0;
    for (let k = 1; k < t.leds.length; k++) {
      const d = t.at[k] - t.at[k - 1];
      if (t.hidden[k] || t.hidden[k - 1]) expect(d).toBeCloseTo(1 / MAX_SPEEDUP, 2);
      else if (Math.abs(d - 1) > 0.05) odd++;
    }
    expect(odd).toBeLessThanOrEqual(1);
    expect(t.n).toBeCloseTo(seen.length + hidden.length / MAX_SPEEDUP, -1);
    // A dot that moves along the roof lights every LED as it passes, hidden ones too.
    const yard = new Yard(stage);
    const frame = new Frame(stage.pixelCount);
    const most = new Float32Array(stage.pixelCount);
    for (let p = 0; p < yard.roof.n; p += 0.25) {
      yard.begin(frame);
      yard.roofSplat(p, [1, 1, 1]);
      for (const i of t.leds) most[i] = Math.max(most[i], frame.data[i * 3]);
    }
    for (const i of t.leds) expect(most[i]).toBeGreaterThan(0.8);
  });

  it('moves evenly across a stretch at an angle to the street, which looks shorter', () => {
    // The middle stretch turns 60° away from the street: 3 m long, 1.5 m wide from the front.
    const c = Math.cos(Math.PI / 3);
    const s = Math.sin(Math.PI / 3);
    const stage = buildStage(roofLayout([{ x: 200, y: 470 }, { x: 500, y: 470 }, { x: 500 + 300 * c, y: 470, z: -300 * s }, { x: 950 - 300 * (1 - c), y: 470, z: -300 * s }]));
    const { t, hidden } = split(stage);
    expect(hidden).toHaveLength(0);
    const width = 300 + 300 * c + 300 - 300 * (1 - c);
    for (let k = 0; k < t.leds.length; k++) expect(Math.abs(stage.positions[t.leds[k] * 2] - (200 + (t.at[k] / (t.n - 1)) * width))).toBeLessThan(6);
    // Fewer steps than LEDs: the turned stretch takes half its LEDs' worth.
    expect(t.n).toBeLessThan(t.leds.length * 0.9);
  });

  it('sends the comet across the front at an even speed, and quickly through the side', () => {
    const stage = buildStage(roofLayout([{ x: 200, y: 470 }, { x: 600, y: 470 }, { x: 600, y: 470, z: -400 }, { x: 600, y: 300, z: -400 }, { x: 1000, y: 300, z: -400 }]));
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    const game = catcherGame(stage);
    const frame = new Frame(stage.pixelCount);
    const { t, hidden } = split(stage);
    const isHidden = new Set(hidden);
    expect(hidden.length).toBeGreaterThan(100);
    press(game);
    // Where the comet's head is each frame (the brightest roof LED in red: the comet is
    // blue-white, the gate green), until it has gone past the side stretch and up the rake.
    const heads: { x: number; y: number; hidden: boolean }[] = [];
    const lit = new Set<number>();
    for (let f = 0; f < 150; f++) {
      game.update(1 / 60, frame);
      let best = -1;
      let at = 0;
      for (const i of t.leds) {
        const v = frame.data[i * 3];
        if (v > 0.3) lit.add(i);
        if (v > best) {
          best = v;
          at = i;
        }
      }
      heads.push({ x: stage.positions[at * 2], y: stage.positions[at * 2 + 1], hidden: isHidden.has(at) });
    }
    expect(heads.at(-1)!.y).toBeLessThan(300.5);
    expect(heads.at(-1)!.x).toBeGreaterThan(620);
    // It runs through every LED of the side, quickly but over several frames: 120 LEDs at most
    // six times the speed along the front (about 140 LEDs a second there).
    for (const i of hidden) expect(lit.has(i)).toBe(true);
    const inSide = heads.filter((h) => h.hidden).length;
    expect(inSide).toBeGreaterThan(4);
    expect(inSide).toBeLessThan(20);
    // Everywhere else it moves about the same distance across the front every frame.
    const window = 6;
    const moves: number[] = [];
    for (let i = window; i < heads.length; i++) {
      if (heads.slice(i - window, i + 1).some((h) => h.hidden)) continue;
      moves.push(Math.hypot(heads[i].x - heads[i - window].x, heads[i].y - heads[i - window].y));
    }
    const mid = [...moves].sort((a, b) => a - b)[moves.length >> 1];
    expect(moves.length).toBeGreaterThan(80);
    expect(Math.min(...moves)).toBeGreaterThan(mid * 0.6);
    expect(Math.max(...moves)).toBeLessThan(mid * 1.4);
  });

  it('shows the hidden stretch on the Games page in its own color', () => {
    const layout = roofLayout([{ x: 200, y: 470 }, { x: 1000, y: 470 }, { x: 1000, y: 470, z: -600 }]);
    const colors = new Map<string, number>();
    paintGameArea(layout, null, null, false, (fi, _i, rgb) => fi === 0 && colors.set(rgb.join(), (colors.get(rgb.join()) ?? 0) + 1));
    const unseen = GAME_UNSEEN_RGB.map((v) => Math.round(v * 0.55)).join();
    expect(colors.get(unseen)).toBeGreaterThan(100);
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
    // Fixed random numbers: blind taps miss every orb in about 1 game in 60.
    let seed = 7;
    vi.spyOn(Math, 'random').mockImplementation(() => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    });
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

  it('burns a fuse while you aim, then the bomb goes off by itself', async () => {
    const { FUSE } = await import('../src/game/cascade.ts');
    const stage = buildStage(sampleLayout());
    const game = cascadeGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    run(game, frame, 1);
    expect(game.status().stats).toContainEqual({ label: 'Fuse', value: `${FUSE - 1}s` });
    run(game, frame, FUSE - 1.5);
    expect(game.status().phase).toBe('aim');
    run(game, frame, 1);
    expect(game.status().phase).not.toBe('aim');
  });

  it('draws the bomb as the only white light on the roof', () => {
    const stage = buildStage(sampleLayout());
    const game = cascadeGame(stage);
    const frame = new Frame(stage.pixelCount);
    press(game);
    const roof = stage.fixtures.find((f) => f.kind === 'roof')!;
    for (let t = 0; t < 20; t++) {
      run(game, frame, 0.25);
      // White: every channel bright. Only the bomb's head (a few LEDs in a row) is.
      const white: number[] = [];
      for (let i = 0; i < roof.count; i++) {
        const k = (roof.offset + i) * 3;
        if (Math.min(frame.data[k], frame.data[k + 1], frame.data[k + 2]) > 0.55) white.push(i);
      }
      expect(white.length).toBeGreaterThan(0);
      expect(white.length).toBeLessThan(12);
      expect(Math.max(...white) - Math.min(...white)).toBeLessThan(12);
    }
  });

  it('never makes white where orbs of different colors meet', () => {
    // Random games that once lit a stray white LED: green and pink orbs side by side, mixed.
    for (const seed of [113, 148, 189, 214, 233, 274]) {
      let a = seed * 2654435761;
      vi.spyOn(Math, 'random').mockImplementation(() => {
        // mulberry32
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      });
      const stage = buildStage(sampleLayout());
      const game = cascadeGame(stage);
      const frame = new Frame(stage.pixelCount);
      press(game);
      const roof = stage.fixtures.find((f) => f.kind === 'roof')!;
      for (let t = 0; t < 20; t++) {
        run(game, frame, 0.25);
        const white: number[] = [];
        for (let i = 0; i < roof.count; i++) {
          const k = (roof.offset + i) * 3;
          if (Math.min(frame.data[k], frame.data[k + 1], frame.data[k + 2]) > 0.55) white.push(i);
        }
        expect(Math.max(...white) - Math.min(...white), `seed ${seed}`).toBeLessThan(12);
      }
      vi.restoreAllMocks();
    }
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

describe('game host with several buttons and settings', () => {
  it('passes each button and setting on to the game, and drops ids it does not accept', async () => {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(sampleLayout(), () => {});
    host.attach(server, '/api/play');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    await new Promise((r) => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', game: 'slice' }));
    await new Promise((r) => setTimeout(r, 50));
    const game = (host as unknown as { game: Game }).game;
    const inputs: unknown[] = [];
    const settings: unknown[] = [];
    game.input = (e) => void inputs.push(e);
    game.setting = (id, value) => void settings.push([id, value]);
    const send = (m: object) => ws.send(JSON.stringify(m));
    send({ type: 'input', action: 'press', button: 'left' });
    send({ type: 'input', action: 'release', button: 'left' });
    send({ type: 'input', action: 'press' });
    send({ type: 'input', action: 'press', button: 'main' });
    send({ type: 'input', action: 'press', button: 'Not OK!' });
    send({ type: 'setting', id: 'level', value: 'hard' });
    send({ type: 'setting', id: 'level', value: '<script>' });
    await new Promise((r) => setTimeout(r, 100));
    expect(inputs).toEqual([
      { playerId: expect.any(String), action: 'press', button: 'left' },
      { playerId: expect.any(String), action: 'release', button: 'left' },
      { playerId: expect.any(String), action: 'press' },
      { playerId: expect.any(String), action: 'press' },
      { playerId: expect.any(String), action: 'press' }
    ]);
    expect(settings).toEqual([['level', 'hard']]);
    ws.close();
    host.stop();
    server.close();
  });
});

describe('the game area', () => {
  const layout = sampleLayout();
  const roof = layout.fixtures.find((f) => f.kind === 'roof')!;
  const bush = layout.fixtures.find((f) => f.kind === 'bush')!;
  const full = buildStage(layout);

  it('keeps the LEDs in place but leaves the hidden ones out of the roof and the yard', () => {
    const { lo, hi } = segmentLeds(roof, 1);
    const stage = buildStage(layout, { exclude: [bush.id], skip: { [roof.id]: [1] }, trim: { [roof.id]: [5, 7] } });
    expect(stage.pixelCount).toBe(full.pixelCount);
    expect(stage.roofPath.length).toBe(full.roofPath.length - (hi - lo + 1) - 12);
    expect(stage.fixtures.some((f) => f.id === bush.id)).toBe(false);
    const r = full.fixtures.find((f) => f.id === roof.id)!;
    expect(stage.active[r.offset]).toBe(0);
    expect(stage.active[r.offset + lo]).toBe(0);
    expect(stage.active[r.offset + hi + 1]).toBe(1);
    expect(new Yard(stage).bushes.some((p) => p.fixture.id === bush.id)).toBe(false);
  });

  it('keeps the lights outside the area dark while a game runs', async () => {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(layout, () => {});
    host.setGameArea({ exclude: [roof.id] });
    host.attach(server, '/api/play');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    let lit = 0;
    let frames = 0;
    const r = full.fixtures.find((f) => f.id === roof.id)!;
    ws.on('message', (data, isBinary) => {
      if (!isBinary) return;
      const b = data as Buffer;
      frames++;
      for (let i = r.offset; i < r.offset + r.count; i++) lit += b[i * 3] + b[i * 3 + 1] + b[i * 3 + 2];
    });
    await new Promise((res) => ws.on('open', res));
    ws.send(JSON.stringify({ type: 'start', game: 'catcher' }));
    ws.send(JSON.stringify({ type: 'input', action: 'press' }));
    await new Promise((res) => setTimeout(res, 400));
    // Frames came (a yard that does not change is not sent again), and the roof stayed dark.
    expect(frames).toBeGreaterThan(0);
    expect(lit).toBe(0);
    ws.close();
    host.stop();
    server.close();
  });
});
