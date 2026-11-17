import crypto from 'node:crypto';
import type { IncomingMessage, Server } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { buildStage, type GameInfo, type GameStatus, type Layout, type Stage } from '../../../shared/layout.ts';
import { catcherGame } from './catcher.ts';
import { Frame } from './frame.ts';
import { idleGame } from './idle.ts';
import type { LightsOutput } from './output.ts';
import type { Game, GameFactory } from './types.ts';

export const GAMES: (GameInfo & { create: GameFactory })[] = [
  {
    id: 'catcher',
    name: 'Comet Catcher',
    description: 'Stop the comet inside the green gate. Every catch lights up a bush.',
    create: catcherGame
  }
];

const TICK_HZ = 60;
/** A game with no input for this long goes back to the idle animation. */
const IDLE_AFTER_MS = 3 * 60_000;

type ClientMessage = { type: 'start'; game: string } | { type: 'stop' } | { type: 'leave' } | { type: 'input'; action: 'press' | 'release' };

/** How often the host checks that each browser is still there (WebSocket ping). */
const HEARTBEAT_MS = 4000;

/**
 * Runs games on the stage. Browsers connect over a WebSocket to watch the simulated yard
 * (binary RGB frames, one byte triple per LED) and to send input. Later, the same frames
 * also go to the real lights.
 */
export class GameHost {
  private stage: Stage;
  private layout: Layout;
  private frame: Frame;
  private bytes: Uint8Array<ArrayBuffer>;
  private game: Game;
  private clients = new Map<WebSocket, { id: string }>();
  private timer: NodeJS.Timeout | null = null;
  private last = 0;
  private lastInput = Date.now();
  private lastStatus = '';
  private wss = new WebSocketServer({ noServer: true });
  private log: (msg: string) => void;
  /** Debug mode: the same frames also go to the real lights. */
  readonly output?: LightsOutput;

  private heartbeatMs: number;

  constructor(layout: Layout, log: (msg: string) => void, output?: LightsOutput, heartbeatMs = HEARTBEAT_MS) {
    this.heartbeatMs = heartbeatMs;
    this.layout = layout;
    this.output = output;
    this.stage = buildStage(layout);
    output?.setStage(layout, this.stage);
    this.frame = new Frame(this.stage.pixelCount);
    this.bytes = new Uint8Array(this.stage.pixelCount * 3);
    this.game = idleGame(this.stage);
    this.log = log;
  }

  /** Accepts WebSocket upgrades on the given path. */
  attach(server: Server, path: string) {
    server.on('upgrade', (req: IncomingMessage, socket, head) => {
      if (!req.url || new URL(req.url, 'http://x').pathname !== path) return;
      this.wss.handleUpgrade(req, socket, head, (ws) => this.connect(ws));
    });
  }

  setLayout(layout: Layout) {
    this.layout = layout;
    this.stage = buildStage(layout);
    this.output?.setStage(layout, this.stage);
    this.frame = new Frame(this.stage.pixelCount);
    this.bytes = new Uint8Array(this.stage.pixelCount * 3);
    // A game cannot continue on a changed yard.
    this.game = idleGame(this.stage);
    this.broadcastJson({ type: 'layout', layout });
    this.sendStatus(true);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
    for (const ws of this.clients.keys()) ws.close();
    this.wss.close();
    this.output?.close();
  }

  // ---------- Connections ----------

  /** Browsers that answered the last ping. */
  private alive = new WeakSet<WebSocket>();
  private heartbeat: NodeJS.Timeout | null = null;

  /**
   * Drops a browser that left. Also called for a browser that stopped answering pings: a
   * connection through a proxy can stay half-open after the page closed, and the game would
   * otherwise keep running on the real lights for nobody.
   */
  private drop(ws: WebSocket, hard = false) {
    if (!this.clients.delete(ws)) return;
    // A goodbye closes politely; a browser that stopped answering is cut off.
    if (hard) ws.terminate();
    else if (ws.readyState === ws.OPEN) ws.close(1000);
    if (this.clients.size === 0) {
      // Nobody is playing: end the game, so the next visitor starts at the game picker.
      this.game = idleGame(this.stage);
      this.pause();
    }
    this.sendStatus(true);
  }

  private connect(ws: WebSocket) {
    this.clients.set(ws, { id: crypto.randomUUID() });
    this.alive.add(ws);
    ws.on('pong', () => this.alive.add(ws));
    if (!this.heartbeat) {
      this.heartbeat = setInterval(() => {
        for (const c of [...this.clients.keys()]) {
          if (!this.alive.has(c)) {
            this.drop(c, true);
            continue;
          }
          this.alive.delete(c);
          try {
            c.ping();
          } catch {
            this.drop(c, true);
          }
        }
      }, this.heartbeatMs);
      this.heartbeat.unref();
    }
    ws.send(JSON.stringify({ type: 'layout', layout: this.layout }));
    ws.send(JSON.stringify({ type: 'games', games: GAMES.map(({ id, name, description }) => ({ id, name, description })) }));
    this.sendStatus(true);
    ws.on('message', (raw, isBinary) => {
      if (isBinary) return;
      let msg: ClientMessage;
      try {
        msg = JSON.parse(String(raw));
      } catch {
        return;
      }
      this.onMessage(ws, msg);
    });
    ws.on('close', () => this.drop(ws));
    ws.on('error', () => this.drop(ws, true));
    this.resume();
  }

  private onMessage(ws: WebSocket, msg: ClientMessage) {
    const client = this.clients.get(ws);
    if (!client) return;
    if (msg.type === 'leave') return this.drop(ws);
    this.lastInput = Date.now();
    if (msg.type === 'start') {
      const g = GAMES.find((x) => x.id === msg.game);
      if (!g) return;
      this.game = g.create(this.stage);
      this.log(`Game started: ${g.name}`);
    } else if (msg.type === 'stop') {
      if (this.game.id !== 'idle') this.log('Game stopped');
      this.game = idleGame(this.stage);
    } else if (msg.type === 'input' && (msg.action === 'press' || msg.action === 'release')) {
      this.game.input({ playerId: client.id, action: msg.action, at: 0 });
    }
    this.sendStatus(true);
  }

  // ---------- Loop ----------

  private resume() {
    if (this.timer) return;
    this.last = performance.now();
    this.timer = setInterval(() => this.tick(), 1000 / TICK_HZ);
  }

  private pause() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    // Nobody is watching: give the lights back at once.
    this.output?.release();
  }

  private tick() {
    const now = performance.now();
    const dt = Math.min(0.05, (now - this.last) / 1000);
    this.last = now;
    if (this.game.id !== 'idle' && Date.now() - this.lastInput > IDLE_AFTER_MS) {
      this.game = idleGame(this.stage);
    }
    this.game.update(dt, this.frame);
    this.frame.toBytes(this.bytes);
    this.output?.push(this.bytes, this.game.id !== 'idle');
    for (const ws of this.clients.keys()) {
      // Skip a frame for a slow client instead of queueing a backlog.
      if (ws.readyState === ws.OPEN && ws.bufferedAmount < 64 * 1024) ws.send(this.bytes);
    }
    this.sendStatus(false);
  }

  private status(): GameStatus {
    return { ...this.game.status(), game: this.game.id === 'idle' ? null : this.game.id, players: this.clients.size, realLights: this.output?.targets() ?? [] };
  }

  /**
   * Ends the running game, for example when someone picks a color or a scene: the last choice
   * wins, so a game left open in another tab cannot keep the lights. The lights go back at once.
   */
  endGame(reason: string) {
    if (this.game.id === 'idle') return;
    this.log(`Game ended: ${reason}`);
    this.game = idleGame(this.stage);
    this.output?.release();
    this.sendStatus(true);
  }

  /** Sends the status now, for example after the debug output changed. */
  refreshStatus() {
    this.sendStatus(true);
  }

  private sendStatus(force: boolean) {
    const s = JSON.stringify({ type: 'status', status: this.status() });
    if (!force && s === this.lastStatus) return;
    this.lastStatus = s;
    this.broadcastJson(null, s);
  }

  private broadcastJson(msg: unknown, raw?: string) {
    const text = raw ?? JSON.stringify(msg);
    for (const ws of this.clients.keys()) if (ws.readyState === ws.OPEN) ws.send(text);
  }
}
