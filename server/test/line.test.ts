import { describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { WebSocket } from 'ws';
import { createApp } from '../src/app.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { GameHost } from '../src/game/host.ts';
import { Line, type Visitor } from '../src/line.ts';
import { Lights } from '../src/lights.ts';
import { DEFAULT_LINE, LINE_MAX } from '../../shared/line.ts';
import { sampleLayout, type GameStatus } from '../../shared/layout.ts';

function clockLine(settings = DEFAULT_LINE) {
  let t = 1_000_000;
  const line = new Line(settings, () => t);
  const shows: string[] = [];
  const ended: string[] = [];
  line.onShow = (w) => shows.push(w.kind === 'scene' ? w.id : w.hex);
  line.onEndGame = (r) => ended.push(r);
  return { line, shows, ended, wait: (s: number) => ((t += s * 1000), line.tick()) };
}
const v = (id: string, admin = false): Visitor => ({ id, admin });
const scene = (id: string) => ({ kind: 'scene' as const, id });
const game = (id: string) => ({ kind: 'game' as const, game: id });
const color = (hex: string) => ({ kind: 'color' as const, hex });

describe('the line for the lights', () => {
  it('plays a tap at once when the lights are free; a scene picked alone keeps them 10 seconds, then the next in line plays', () => {
    const { line, shows, wait } = clockLine();
    expect(line.ask(v('a'), scene('red'), 'Red')).toEqual({ result: 'now' });
    // Within the 10 seconds: B waits, and sees how long.
    wait(4);
    expect(line.ask(v('b'), scene('blue'), 'Blue')).toEqual({ result: 'queued', place: 1 });
    expect(line.view('b')).toMatchObject({ free: false, waiting: 1, you: { place: 1, label: 'Blue', startsIn: 6_000 }, now: { kind: 'scene', label: 'Red', you: false }, endsIn: 6_000 });
    // A cannot change the lights again so soon (a throttle), not even their own turn.
    expect(line.view('a').cooldown).toBe(6_000);
    expect(line.ask(v('a'), scene('green'), 'Green')).toEqual({ result: 'wait', retryIn: 6_000 });
    wait(5);
    expect(shows).toEqual([]);
    wait(1);
    expect(shows).toEqual(['blue']);
    expect(line.view('b').now).toMatchObject({ label: 'Blue', you: true });
    // Nobody else waited, so B's turn is short too: then a tap plays at once again.
    wait(9);
    expect(line.view('c').free).toBe(false);
    wait(1);
    expect(line.view('c').free).toBe(true);
    expect(line.ask(v('c'), scene('red'), 'Red').result).toBe('now');
  });

  it('lets a visitor change their own turn while nobody else waits, keeping its clock; with others waiting, a pick goes to the back of the line', () => {
    const { line, wait } = clockLine();
    line.ask(v('a'), scene('red'), 'Red');
    line.ask(v('b'), scene('blue'), 'Blue');
    line.ask(v('c'), scene('white'), 'White');
    wait(10);
    // B's turn is a minute (C waits): B's next pick waits its 10 seconds, then goes behind C.
    expect(line.ask(v('b'), color('#00ff00'), 'Color #00ff00')).toEqual({ result: 'wait', retryIn: 10_000 });
    wait(10);
    expect(line.view('b').cooldown).toBeNull();
    expect(line.ask(v('b'), color('#00ff00'), 'Color #00ff00')).toEqual({ result: 'queued', place: 2 });
    expect(line.view('b')).toMatchObject({ now: { label: 'Blue', you: true }, endsIn: 50_000, you: { place: 2, label: 'Color #00ff00', startsIn: 110_000 } });
    expect(line.view('x').ahead).toEqual([
      { kind: 'scene', label: 'White', you: false, startsIn: 50_000 },
      { kind: 'color', label: 'Color #00ff00', you: false, startsIn: 110_000 }
    ]);
    // C's turn: nobody waits behind C, so C's next pick plays at once.
    line.leave('b');
    wait(50);
    expect(line.view('c').now).toMatchObject({ label: 'White', you: true });
    wait(10);
    expect(line.ask(v('c'), color('#0000ff'), 'Color #0000ff')).toEqual({ result: 'now' });
    expect(line.view('c').now).toMatchObject({ label: 'Color #0000ff', you: true });
    // Admins are never throttled.
    expect(line.ask(v('boss', true), scene('red'), 'Red').result).toBe('now');
    expect(line.ask(v('boss', true), scene('blue'), 'Blue').result).toBe('now');
  });

  it('gives a scene a minute when its turn comes while others still wait', () => {
    const { line, shows, wait } = clockLine();
    line.ask(v('a'), scene('red'), 'Red');
    line.ask(v('b'), scene('blue'), 'Blue');
    line.ask(v('c'), game('slice'), 'Slice');
    expect(line.view('c').you).toMatchObject({ place: 2, startsIn: 70_000 });
    wait(10);
    expect(shows).toEqual(['blue']);
    expect(line.view('c')).toMatchObject({ endsIn: 60_000, you: { place: 1, startsIn: 60_000 } });
    wait(59);
    expect(line.view('c').offer).toBeNull();
    wait(1);
    expect(line.view('c').offer).toMatchObject({ game: 'slice' });
  });

  it('keeps someone who wants a game waiting no more than 10 seconds behind a scene', () => {
    const { line, wait } = clockLine();
    line.ask(v('a'), color('#ff0000'), 'Color #ff0000');
    wait(3);
    expect(line.ask(v('b'), game('beat'), 'Beat Drop')).toEqual({ result: 'queued', place: 1 });
    expect(line.view('b').you).toMatchObject({ kind: 'game', startsIn: 7_000 });
    wait(7);
    expect(line.view('b').offer).toMatchObject({ game: 'beat', endsIn: 30_000 });
  });

  it('keeps one place per visitor: a second tap changes what it is for', () => {
    const { line } = clockLine();
    line.ask(v('a'), game('slice'), 'Slice');
    line.ask(v('b'), scene('red'), 'Red');
    line.ask(v('c'), scene('blue'), 'Blue');
    expect(line.ask(v('b'), game('beat'), 'Beat Drop')).toEqual({ result: 'queued', place: 1 });
    expect(line.view('b').you).toEqual({ place: 1, kind: 'game', label: 'Beat Drop', startsIn: 5 * 60_000 });
    expect(line.view('c').you!.place).toBe(2);
    line.leave('b');
    expect(line.view('c').you!.place).toBe(1);
    expect(line.view('b').you).toBeNull();
  });

  it('gives a game turn five minutes on a clock everyone sees; someone who joins later waits for the rest of it', () => {
    const { line, ended, wait } = clockLine();
    line.ask(v('a'), game('slice'), 'Slice');
    expect(line.view('a').endsIn).toBe(5 * 60_000);
    expect(line.view('b')).toMatchObject({ now: { kind: 'game', you: false }, endsIn: 5 * 60_000, waiting: 0 });
    wait(60);
    line.ask(v('b'), game('beat'), 'Beat Drop');
    expect(line.view('a').endsIn).toBe(4 * 60_000);
    expect(line.view('b').you).toMatchObject({ place: 1, startsIn: 4 * 60_000 });
    wait(4 * 60);
    expect(ended).toEqual(['the turn was up']);
  });

  it('lets a game play on when its time is up and nobody waits; then someone who joins gives it one more minute', () => {
    const { line, ended, wait } = clockLine();
    line.ask(v('a'), game('slice'), 'Slice');
    wait(30 * 60);
    expect(line.holder()).toBe('a');
    expect(line.view('a').endsIn).toBeNull();
    line.ask(v('b'), game('beat'), 'Beat Drop');
    expect(line.view('a').endsIn).toBe(60_000);
    // Joining and leaving again gives it no more time.
    line.ask(v('c'), scene('red'), 'Red');
    line.leave('c');
    wait(59);
    expect(ended).toEqual([]);
    wait(1);
    expect(ended).toEqual(['the turn was up']);
    expect(line.holder()).toBeNull();
    // B is asked to tap Play, and the lights wait for them.
    expect(line.view('b').offer).toMatchObject({ game: 'beat', label: 'Beat Drop', endsIn: 30_000 });
    expect(line.view('c')).toMatchObject({ calling: true, free: false });
    expect(line.accept('c')).toBeNull();
    expect(line.accept('b')).toBe('beat');
    expect(line.holder()).toBe('b');
  });

  it('moves on without a player who does not tap Play in time', () => {
    const { line, shows, wait } = clockLine();
    line.ask(v('a'), game('slice'), 'Slice');
    line.ask(v('b'), game('beat'), 'Beat Drop');
    line.ask(v('c'), scene('red'), 'Red');
    line.release('a', 'the game ended');
    expect(line.view('b').offer).not.toBeNull();
    wait(29);
    expect(shows).toEqual([]);
    wait(1);
    expect(line.view('b').offer).toBeNull();
    expect(line.view('b').you).toBeNull();
    expect(shows).toEqual(['red']);
  });

  it("lets a scene's turn change scenes but not become a game turn while others wait", () => {
    const { line } = clockLine();
    line.ask(v('a'), scene('red'), 'Red');
    line.ask(v('b'), scene('blue'), 'Blue');
    expect(line.ask(v('a'), game('slice'), 'Slice')).toEqual({ result: 'queued', place: 2 });
    expect(line.holder()).toBeNull();
  });

  it('lets the one with a scene on switch to a game at once while nobody else waits', () => {
    const { line } = clockLine();
    line.ask(v('a'), scene('red'), 'Red');
    expect(line.ask(v('a'), game('slice'), 'Slice')).toEqual({ result: 'now' });
    expect(line.holder()).toBe('a');
    expect(line.view('a').endsIn).toBe(5 * 60_000);
  });

  it("starts the next player's game on its own when their play page is open", () => {
    const { line, wait } = clockLine();
    const started: string[] = [];
    line.present = (id) => id === 'b';
    line.onStartGame = (g, who) => started.push(`${who.id}:${g}`);
    line.ask(v('a'), game('slice'), 'Slice');
    line.ask(v('b'), game('beat'), 'Beat Drop');
    line.ask(v('c'), game('slice'), 'Slice');
    line.release('a', 'the game ended');
    expect(started).toEqual(['b:beat']);
    expect(line.holder()).toBe('b');
    expect(line.view('c')).toMatchObject({ now: { label: 'Beat Drop', you: false }, endsIn: 5 * 60_000, you: { place: 1 } });
    // C's page is not open: C is asked to tap Play.
    line.release('b', 'the game ended');
    expect(started).toEqual(['b:beat']);
    expect(line.view('c').offer).toMatchObject({ game: 'slice' });
    expect(line.view('b').ahead).toEqual([{ kind: 'game', label: 'Slice', you: false, startsIn: 0 }]);
    wait(1);
  });

  it('never makes an admin wait, and is not there when switched off', () => {
    const { line } = clockLine();
    line.ask(v('a'), game('slice'), 'Slice');
    expect(line.ask(v('boss', true), scene('red'), 'Red').result).toBe('now');
    expect(line.view('a').now).toMatchObject({ label: 'Red', you: false });
    line.ask(v('b'), scene('blue'), 'Blue');
    line.configure({ ...DEFAULT_LINE, enabled: false });
    expect(line.view('b').you).toBeNull();
    expect(line.ask(v('c'), game('slice'), 'Slice').result).toBe('now');
    expect(line.ask(v('d'), game('beat'), 'Beat Drop').result).toBe('now');
  });

  it('has room for so many people', () => {
    const { line } = clockLine();
    line.ask(v('a'), game('slice'), 'Slice');
    for (let i = 0; i < LINE_MAX; i++) expect(line.ask(v(`p${i}`), scene('red'), 'Red').result).toBe('queued');
    expect(line.ask(v('late'), scene('red'), 'Red')).toEqual({ result: 'full' });
  });
});

describe('taking turns on the play page', () => {
  async function phone(port: number, visitor: string) {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`, { headers: { cookie: `wled_visitor=${visitor}` } });
    const last: { status: GameStatus | null } = { status: null };
    ws.on('message', (data, isBinary) => {
      if (!isBinary && JSON.parse(String(data)).type === 'status') last.status = JSON.parse(String(data)).status;
    });
    await new Promise((r) => ws.on('open', r));
    const send = async (m: object, wait = 80) => {
      ws.send(JSON.stringify(m));
      await new Promise((r) => setTimeout(r, wait));
    };
    return { ws, last, send };
  }
  async function start() {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const host = new GameHost(sampleLayout(), () => {});
    host.line.configure(DEFAULT_LINE);
    host.attach(server, '/api/play', (req) => {
      const id = /wled_visitor=([\w-]+)/.exec(req.headers.cookie ?? '')?.[1];
      return id ? { id } : null;
    });
    return { host, server, port: (server.address() as { port: number }).port };
  }

  it('lets only the player with the turn play; the next player gets the lights when the game ends', async () => {
    const { host, server, port } = await start();
    const a = await phone(port, 'aaaaaaaaaaaaaaaaaaaa');
    const b = await phone(port, 'bbbbbbbbbbbbbbbbbbbb');
    await a.send({ type: 'start', game: 'slice' });
    expect(a.last.status).toMatchObject({ game: 'slice', canPlay: true, line: { now: { kind: 'game', label: 'Slice', you: true } } });
    // B picks a game: B waits in line and watches.
    await b.send({ type: 'start', game: 'catcher' });
    expect(b.last.status).toMatchObject({ game: 'slice', canPlay: false, line: { you: { place: 1, kind: 'game' }, now: { you: false } } });
    expect(a.last.status!.line).toMatchObject({ waiting: 1, endsIn: 5 * 60_000 });
    // B's presses do nothing to A's game.
    await b.send({ type: 'input', action: 'press' });
    expect(a.last.status!.phase).toBe('ready');
    // A plays Slice to the end (see scores.test.ts): the button now ends the turn.
    for (let i = 0; i < 3; i++) await a.send({ type: 'input', action: 'press' }, 140);
    await new Promise((r) => setTimeout(r, 600));
    expect(a.last.status).toMatchObject({ phase: 'over', button: 'DONE' });
    // B's page is open: B's game starts on its own.
    await a.send({ type: 'input', action: 'press' });
    expect(b.last.status).toMatchObject({ game: 'catcher', canPlay: true, line: { now: { you: true }, endsIn: 5 * 60_000 } });
    expect(a.last.status).toMatchObject({ game: 'catcher', canPlay: false });
    // B says goodbye (closes the page): the turn is over, and the lights are free.
    await b.send({ type: 'leave' });
    expect(a.last.status).toMatchObject({ game: null, line: { free: true, now: null } });
    a.ws.close();
    host.stop();
    server.close();
  });

  it('lets one page play a game: the same visitor in another tab watches, and plays on if the first one closes', async () => {
    const { host, server, port } = await start();
    const a = await phone(port, 'aaaaaaaaaaaaaaaaaaaa');
    const tab = await phone(port, 'aaaaaaaaaaaaaaaaaaaa');
    await a.send({ type: 'start', game: 'slice' });
    expect(a.last.status).toMatchObject({ game: 'slice', canPlay: true });
    expect(tab.last.status).toMatchObject({ game: 'slice', canPlay: false, elsewhere: true });
    await tab.send({ type: 'input', action: 'press' });
    expect(a.last.status!.phase).toBe('ready');
    a.ws.close();
    await new Promise((r) => setTimeout(r, 100));
    expect(tab.last.status).toMatchObject({ game: 'slice', canPlay: true });
    tab.ws.close();
    host.stop();
    server.close();
  });

  it('ends the turn of a next player whose game started on its own but who does not play in time', async () => {
    const { host, server, port } = await start();
    host.line.configure({ ...DEFAULT_LINE, offerSeconds: 0.3 });
    const a = await phone(port, 'aaaaaaaaaaaaaaaaaaaa');
    const b = await phone(port, 'bbbbbbbbbbbbbbbbbbbb');
    const c = await phone(port, 'cccccccccccccccccccc');
    await a.send({ type: 'start', game: 'slice' });
    await b.send({ type: 'start', game: 'catcher' });
    await c.send({ type: 'start', game: 'slice' });
    // A stops: B's game starts on its own.
    await a.send({ type: 'stop' });
    expect(b.last.status).toMatchObject({ game: 'catcher', canPlay: true });
    await new Promise((r) => setTimeout(r, 1000));
    // B never pressed: C's game started.
    expect(c.last.status).toMatchObject({ game: 'slice', canPlay: true });
    expect(b.last.status).toMatchObject({ canPlay: false, line: { you: null } });
    for (const p of [a, b, c]) p.ws.close();
    host.stop();
    server.close();
  });

  it('keeps the place and the turn of a phone that reconnects', async () => {
    const { host, server, port } = await start();
    const a = await phone(port, 'aaaaaaaaaaaaaaaaaaaa');
    await a.send({ type: 'start', game: 'slice' });
    a.ws.terminate();
    await new Promise((r) => setTimeout(r, 100));
    const again = await phone(port, 'aaaaaaaaaaaaaaaaaaaa');
    await again.send({ type: 'input', action: 'press' });
    expect(again.last.status).toMatchObject({ game: 'slice', canPlay: true });
    expect(again.last.status!.phase).not.toBe('ready');
    again.ws.close();
    host.stop();
    server.close();
  });
});

describe('taking turns on the public page', () => {
  it('puts a color in line while someone plays, plays it when its turn comes, and lets people leave the line', async () => {
    const db = openDatabase(':memory:');
    const bus = new Bus();
    const lights = new Lights(db, bus);
    const host = new GameHost(sampleLayout(), () => {});
    host.line.configure(DEFAULT_LINE);
    const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
    const app = createApp({ config, db, bus, lights, host, discover: async () => [] });
    const color = (visitor: string, hex: string) =>
      app.request('/api/color', { method: 'POST', headers: { host: 'lights.lan', 'content-type': 'application/json', cookie: `wled_visitor=${visitor}` }, body: JSON.stringify({ color: hex }) });
    // Someone has a game turn.
    host.line.ask({ id: 'player-player-player' }, { kind: 'game', game: 'slice' }, 'Slice');
    const applied = vi.spyOn(lights, 'applyColor');
    const r = await color('neighbor-neighbor-01', '#ff0000');
    expect(r.status).toBe(202);
    expect((await r.json()).queued).toMatchObject({ place: 1, message: "You're 1st in line. Color #ff0000 plays when it's your turn." });
    expect(applied).not.toHaveBeenCalled();
    const r2 = await color('neighbor-neighbor-02', '#00ff00');
    expect((await r2.json()).queued.place).toBe(2);
    // The second neighbor leaves the line.
    await app.request('/api/line/leave', { method: 'POST', headers: { host: 'lights.lan', cookie: 'wled_visitor=neighbor-neighbor-02' } });
    expect(host.line.view('neighbor-neighbor-02').you).toBeNull();
    // The game turn ends: the color plays.
    host.line.release('player-player-player', 'the game ended');
    expect(applied).toHaveBeenCalledWith('#ff0000', expect.objectContaining({ ip: expect.any(String) }));
    expect(host.line.view('neighbor-neighbor-01').now).toMatchObject({ kind: 'color', you: true });
    // Right away again: too soon (the throttle).
    const soon = await color('neighbor-neighbor-01', '#0000ff');
    expect(soon.status).toBe(429);
    expect(soon.headers.get('retry-after')).toBe('10');
    expect((await soon.json()).error).toBe('You just changed the lights. Pick again in 10 seconds.');
    // A new browser gets a visitor id.
    const first = await app.request('/api/state', { headers: { host: 'lights.lan' } });
    expect(first.headers.getSetCookie().some((c) => c.startsWith('wled_visitor='))).toBe(true);
    host.stop();
  });
});
