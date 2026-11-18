import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { WebSocket } from 'ws';
import { createApp } from '../src/app.ts';
import { createAuth } from '../src/auth.ts';
import { loadConfig } from '../src/config.ts';
import { openDatabase } from '../src/db.ts';
import { Bus } from '../src/events.ts';
import { GameHost } from '../src/game/host.ts';
import { BOARD_SIZE, bestScore, cleanInitials, endRun, memoryScores, nameScore, NO_INITIALS, pendingInitials, record, scoreboard, useScoreStore } from '../src/game/kit.ts';
import { Lights } from '../src/lights.ts';
import { databaseScores } from '../src/scoreStore.ts';
import { sampleLayout, type GameStatus } from '../../shared/layout.ts';

beforeEach(() => useScoreStore(memoryScores()));
afterEach(() => useScoreStore(memoryScores()));

/** Plays one game that ends with `score`, and starts the next. */
function game(board: string, score: number) {
  const r = record(board, score);
  endRun();
  return r;
}

describe('scoreboards', () => {
  it('keeps the best ten of each board, best first, equal scores in the order they came', () => {
    for (const s of [5, 50, 20, 20, 80, 1, 30, 70, 60, 40, 10]) game('slice', s);
    const top = scoreboard('slice');
    expect(top).toHaveLength(BOARD_SIZE);
    expect(top.map((e) => e.score)).toEqual([80, 70, 60, 50, 40, 30, 20, 20, 10, 5]);
    // The two 20s: the first one first.
    expect(top[6].id).toBeLessThan(top[7].id);
    // A score that would not make a full board does not go on it.
    expect(game('slice', 3)).toEqual({ best: 80, isNew: false });
    expect(scoreboard('slice').map((e) => e.score).at(-1)).toBe(5);
    // Each board on its own.
    expect(scoreboard('beat:4:hard')).toEqual([]);
    expect(bestScore('slice')).toBe(80);
    expect(game('slice', 90)).toEqual({ best: 90, isNew: true });
  });

  it('puts a game that records along the way on the board once, at its final score', () => {
    record('cascade', 10);
    record('cascade', 25);
    expect(record('cascade', 40)).toEqual({ best: 40, isNew: true });
    expect(scoreboard('cascade').map((e) => [e.initials, e.score])).toEqual([[NO_INITIALS, 40]]);
    // The next game is a new line.
    endRun();
    record('cascade', 30);
    expect(scoreboard('cascade').map((e) => e.score)).toEqual([40, 30]);
  });

  it('asks for initials for a score that made the board, and takes three letters or digits', () => {
    game('ricochet', 50);
    record('ricochet', 20);
    expect(pendingInitials('ricochet')).toMatchObject({ rank: 2, score: 20 });
    expect(pendingInitials('slice')).toBeNull();
    const { id } = pendingInitials('ricochet')!;
    expect(nameScore(id, 'ass')).toBe('refused');
    expect(nameScore(id + 99, 'BOB')).toBe('gone');
    expect(nameScore(id, 'b.o-b!x')).toBe('ok');
    expect(scoreboard('ricochet').map((e) => e.initials)).toEqual([NO_INITIALS, 'BOB']);
    // Named: it no longer asks.
    expect(pendingInitials('ricochet')).toBeNull();
    expect(cleanInitials('j2')).toBe('J2');
    expect(cleanInitials('!!')).toBeNull();
  });

  it('keeps the scores in the database, through a restart', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-scores-')), 'db.sqlite');
    let db = openDatabase(file);
    useScoreStore(databaseScores(db.raw));
    for (const s of [3, 9, 6]) game('beads', s);
    record('beads', 12);
    nameScore(pendingInitials('beads')!.id, 'ACE');
    for (let i = 0; i < 12; i++) game('beads', 100 + i);
    db.close();
    db = openDatabase(file);
    useScoreStore(databaseScores(db.raw));
    const top = scoreboard('beads');
    expect(top).toHaveLength(BOARD_SIZE);
    expect(top[0]).toMatchObject({ score: 111, initials: NO_INITIALS });
    expect(bestScore('beads')).toBe(111);
    // Only the best ten are kept.
    expect((db.raw.prepare("SELECT COUNT(*) AS n FROM high_scores WHERE board = 'beads'").get() as { n: number }).n).toBe(BOARD_SIZE);
    db.close();
  });
});

describe('scoreboards on the phone', () => {
  async function connect(host: GameHost) {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    host.attach(server, '/api/play');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    const last: { status: GameStatus | null } = { status: null };
    ws.on('message', (data, isBinary) => {
      if (!isBinary && JSON.parse(String(data)).type === 'status') last.status = JSON.parse(String(data)).status;
    });
    await new Promise((r) => ws.on('open', r));
    const send = async (m: object, wait = 60) => {
      ws.send(JSON.stringify(m));
      await new Promise((r) => setTimeout(r, wait));
    };
    return { ws, last, send, close: () => (ws.close(), server.close()) };
  }

  it('shows the board after a game, asks for initials, and lights up the line named', async () => {
    const host = new GameHost(sampleLayout(), () => {});
    const phone = await connect(host);
    await phone.send({ type: 'start', game: 'slice' });
    expect(phone.last.status).toMatchObject({ game: 'slice', phase: 'ready', scoreboard: { title: 'Slice', entries: [] } });
    expect(phone.last.status!.enterInitials).toBeUndefined();
    // Slice: a drop right away lands mostly off the band; the next one misses it.
    await phone.send({ type: 'input', action: 'press' }, 120);
    await phone.send({ type: 'input', action: 'press' }, 120);
    expect(phone.last.status!.scoreboard).toBeUndefined();
    await phone.send({ type: 'input', action: 'press' }, 200);
    expect(phone.last.status).toMatchObject({ phase: 'over', score: 1, enterInitials: { rank: 1, score: 1 } });
    expect(phone.last.status!.scoreboard!.entries).toEqual([{ id: expect.any(Number), rank: 1, initials: NO_INITIALS, score: 1 }]);
    const id = phone.last.status!.enterInitials!.id;
    await phone.send({ type: 'initials', id, initials: 'tit' });
    expect(phone.last.status!.enterInitials).toMatchObject({ refused: true });
    await phone.send({ type: 'initials', id, initials: 'zed' });
    expect(phone.last.status!.enterInitials).toBeUndefined();
    expect(phone.last.status!.scoreboard).toMatchObject({ fresh: id, entries: [{ initials: 'ZED', score: 1 }] });
    // An admin can take it off again.
    expect(host.removeScore(id)).toBe(true);
    await new Promise((r) => setTimeout(r, 30));
    expect(phone.last.status!.scoreboard!.entries).toEqual([]);
    phone.close();
    host.stop();
  });

  it('no longer asks once the next game starts', async () => {
    const host = new GameHost(sampleLayout(), () => {});
    const phone = await connect(host);
    await phone.send({ type: 'start', game: 'slice' });
    for (let i = 0; i < 3; i++) await phone.send({ type: 'input', action: 'press' }, 120);
    expect(phone.last.status!.enterInitials).toBeDefined();
    await new Promise((r) => setTimeout(r, 1500));
    await phone.send({ type: 'input', action: 'press' });
    expect(phone.last.status!.phase).toBe('sweep');
    expect(pendingInitials('slice')).toBeNull();
    phone.close();
    host.stop();
  });

  it('lets a signed-in admin remove a line', async () => {
    const db = openDatabase(':memory:');
    const bus = new Bus();
    const lights = new Lights(db, bus);
    const host = new GameHost(sampleLayout(), () => {});
    const config = { ...loadConfig({}), webDir: '/nonexistent', databasePath: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wled-test-')), 'db.sqlite') };
    const app = createApp({ config, db, bus, lights, host, discover: async () => [] });
    await createAuth(db, { secureCookie: false }).createUser('admin', 'correct horse battery');
    game('slice', 7);
    const id = scoreboard('slice')[0].id;
    const del = (cookie = '') => app.request(`/api/admin/play/scores/${id}`, { method: 'DELETE', headers: { host: 'lights.lan', ...(cookie ? { cookie } : {}) } });
    expect((await del()).status).toBe(401);
    const login = await app.request('/api/auth/login', { method: 'POST', headers: { host: 'lights.lan', 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'correct horse battery' }) });
    const cookie = login.headers.get('set-cookie')!.split(';')[0];
    expect((await del(cookie)).status).toBe(200);
    expect(scoreboard('slice')).toEqual([]);
    expect((await del(cookie)).status).toBe(404);
    host.stop();
  });
});
