import crypto from 'node:crypto';
import type { IncomingMessage, Server } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { EffectScene, type EffectSettings } from '../../../shared/effects.ts';
import { SequencePlayer, type Sequence } from '../../../shared/sequence.ts';
import { buildStage, type GameArea, type GameInfo, type GameStatus, type Layout, type Stage } from '../../../shared/layout.ts';
import { GAME_CATALOG } from '../../../shared/games.ts';
import { cascadeGame } from './cascade.ts';
import { catcherGame } from './catcher.ts';
import { duelGame } from './duel.ts';
import { Frame } from './frame.ts';
import { idleGame } from './idle.ts';
import type { LightsOutput } from './output.ts';
import { overflowGame } from './overflow.ts';
import type { Game, GameFactory } from './types.ts';

const CREATE: Record<string, GameFactory> = { catcher: catcherGame, cascade: cascadeGame, overflow: overflowGame, duel: duelGame };

export const GAMES: (GameInfo & { create: GameFactory })[] = GAME_CATALOG.map(({ tagline: _, ...info }) => ({ ...info, create: CREATE[info.id] }));

const TICK_HZ = 60;
/** A game with no input for this long goes back to the idle animation. */
const IDLE_AFTER_MS = 3 * 60_000;

type ClientMessage = { type: 'start'; game: string } | { type: 'stop' } | { type: 'leave' } | { type: 'input'; action: 'press' | 'release' };

/** What a scene plays on the lights: effects on the yard and its objects, or a sequence (it loops). */
export interface Show {
  effects?: Record<string, EffectSettings> | null;
  sequence?: Sequence | null;
}

/** A scene's effects or a sequence, drawn frame by frame. */
interface Program {
  setStage(stage: Stage, layout: Layout): void;
  update(dt: number, out: Float32Array): void;
  objects(): string[];
}

function sequenceProgram(stage: Stage, layout: Layout, seq: Sequence): Program {
  const p = new SequencePlayer(stage, layout, seq);
  return { setStage: (s, l) => p.setStage(s, l), update: (dt, out) => p.update(dt, out, true), objects: () => p.objects() };
}

/** How often the host checks that each browser is still there (WebSocket ping). */
const HEARTBEAT_MS = 4000;

/**
 * Runs games on the stage. Browsers connect over a WebSocket to watch the simulated yard
 * (binary RGB frames, one byte triple per LED) and to send input. Later, the same frames
 * also go to the real lights.
 */
export class GameHost {
  /** Every LED of the layout: scenes play on it. */
  private stage: Stage;
  /** The same LEDs, with only the game area active: games play on it. */
  private gameStage: Stage;
  private area: GameArea | null;
  /** LEDs outside the game area: they stay dark during a game. */
  private outside = new Int32Array(0);
  private layout: Layout;
  private frame: Frame;
  private bytes: Uint8Array<ArrayBuffer>;
  private game: Game;
  private clients = new Map<WebSocket, { id: string }>();
  private timer: NodeJS.Timeout | null = null;
  private last = 0;
  private lastInput = Date.now();
  /** The last status sent to each browser, so an unchanged one is not sent again. */
  private lastStatus = new WeakMap<WebSocket, string>();
  /** When the running game started, for GameInput.at. */
  private started = performance.now();
  private wss = new WebSocketServer({ noServer: true });
  private log: (msg: string) => void;
  /** Debug mode: the same frames also go to the real lights. */
  readonly output?: LightsOutput;

  private heartbeatMs: number;
  /**
   * A scene's effects. They play whenever no game runs (also with nobody watching), go to the
   * real lights, and show in the simulator instead of the idle animation.
   */
  private scene: Program | null = null;
  private show: Show | null = null;
  /** Devices that get the scene's frames: those with an object that plays an effect. */
  private sceneDevices = new Set<string>();

  constructor(layout: Layout, log: (msg: string) => void, output?: LightsOutput, heartbeatMs = HEARTBEAT_MS) {
    this.heartbeatMs = heartbeatMs;
    this.layout = layout;
    this.output = output;
    this.area = null;
    this.stage = buildStage(layout);
    this.gameStage = this.buildGameStage();
    output?.setStage(layout, this.stage);
    this.frame = new Frame(this.stage.pixelCount);
    this.bytes = new Uint8Array(this.stage.pixelCount * 3);
    this.game = idleGame(this.gameStage);
    this.log = log;
  }

  private buildGameStage(): Stage {
    const g = buildStage(this.layout, this.area);
    const out: number[] = [];
    for (let i = 0; i < g.pixelCount; i++) if (!g.active[i] && this.stage.active[i]) out.push(i);
    this.outside = Int32Array.from(out);
    return g;
  }

  /** The part of the yard that games use. A running game ends: it cannot go on in a changed area. */
  setGameArea(area: GameArea | null) {
    this.area = area;
    this.gameStage = this.buildGameStage();
    if (this.game.id !== 'idle') this.log('Game ended: the game area changed');
    this.game = idleGame(this.gameStage);
    this.sendStatus(true);
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
    this.gameStage = this.buildGameStage();
    this.output?.setStage(layout, this.stage);
    this.frame = new Frame(this.stage.pixelCount);
    this.bytes = new Uint8Array(this.stage.pixelCount * 3);
    // A game cannot continue on a changed yard.
    this.game = idleGame(this.gameStage);
    // A scene keeps playing on the changed yard.
    if (this.show) this.playShow(this.show);
    this.broadcastJson({ type: 'layout', layout });
    this.sendStatus(true);
  }

  /**
   * Plays a scene's effects (by effect key: "*", an object id, or "<object id>#<segment>"), or
   * stops them (null). Returns the devices that get them and the number of objects that play one.
   * Objects that are not in the layout are left out.
   */
  playEffects(effects: Record<string, EffectSettings> | null): { devices: string[]; objects: number } {
    return this.playShow(effects ? { effects } : null);
  }

  /**
   * Plays a scene's show: a sequence (looping), or effects. Null, or a show with nothing in it,
   * stops. The same show again (on a changed yard) keeps running where it can.
   */
  playShow(show: Show | null): { devices: string[]; objects: number } {
    const seq = show?.sequence && show.sequence.tracks.some((t) => t.clips.length) ? show.sequence : null;
    const fx = !seq && show?.effects && Object.keys(show.effects).length ? show.effects : null;
    if (!seq && !fx) {
      this.show = null;
      this.scene = null;
      this.sceneDevices.clear();
      // Give the devices back, unless a game has them now.
      if (this.game.id === 'idle') this.output?.release();
      if (!this.clients.size) this.pause();
      return { devices: [], objects: 0 };
    }
    const same = this.show && (seq ? this.show.sequence === seq : this.show.effects === fx);
    this.show = seq ? { sequence: seq } : { effects: fx };
    if (seq) {
      if (!same || !this.scene) this.scene = sequenceProgram(this.stage, this.layout, seq);
      else this.scene.setStage(this.stage, this.layout);
    } else if (this.scene instanceof EffectScene) {
      this.scene.setStage(this.stage, this.layout);
      this.scene.setEffects(fx!);
    } else this.scene = new EffectScene(this.stage, this.layout, fx!);
    const playing = new Set(this.scene.objects());
    this.sceneDevices = new Set(this.layout.fixtures.filter((f) => playing.has(f.id) && f.deviceId).map((f) => f.deviceId!));
    this.resume();
    return { devices: [...this.sceneDevices], objects: playing.size };
  }

  /** True while a scene's effects play. */
  get playingEffects() {
    return !!this.scene;
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
    const client = this.clients.get(ws);
    if (!client || !this.clients.delete(ws)) return;
    this.game.leave?.(client.id);
    // A goodbye closes politely; a browser that stopped answering is cut off.
    if (hard) ws.terminate();
    else if (ws.readyState === ws.OPEN) ws.close(1000);
    if (this.clients.size === 0) {
      // Nobody is playing: end the game, so the next visitor starts at the game picker.
      // A scene's effects keep playing for the people outside: they take the lights back on
      // the next frame, and devices that play a preset get it back.
      this.game = idleGame(this.gameStage);
      if (!this.scene) this.pause();
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
    ws.send(JSON.stringify({ type: 'games', games: GAMES.map(({ id, name, description, players }) => ({ id, name, description, players })) }));
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
      this.game = g.create(this.gameStage);
      this.started = performance.now();
      this.log(`Game started: ${g.name}`);
    } else if (msg.type === 'stop') {
      if (this.game.id !== 'idle') this.log('Game stopped');
      this.game = idleGame(this.gameStage);
    } else if (msg.type === 'input' && (msg.action === 'press' || msg.action === 'release')) {
      this.game.input({ playerId: client.id, action: msg.action, at: (performance.now() - this.started) / 1000 });
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
      this.game = idleGame(this.gameStage);
    }
    const gameOn = this.game.id !== 'idle';
    if (!gameOn && this.scene) this.scene.update(dt, this.frame.data);
    else {
      this.game.update(dt, this.frame);
      // Lights outside the game area stay dark, whatever the game drew there.
      const d = this.frame.data;
      for (const i of this.outside) d[i * 3] = d[i * 3 + 1] = d[i * 3 + 2] = 0;
    }
    this.frame.toBytes(this.bytes);
    if (!gameOn && this.scene) this.output?.pushScene(this.bytes, this.sceneDevices);
    else this.output?.push(this.bytes, gameOn);
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
    this.game = idleGame(this.gameStage);
    // A scene's effects take the lights back on the next frame (and give the other devices
    // back). With no scene, every device goes back to its own state now.
    if (!this.scene) this.output?.release();
    this.sendStatus(true);
  }

  /** Sends the status now, for example after the debug output changed. */
  refreshStatus() {
    this.sendStatus(true);
  }

  /** Sends each browser its status: the game's, with that player's own side and button on top. */
  private sendStatus(force: boolean) {
    const base = this.status();
    const shared = this.game.playerStatus ? null : JSON.stringify({ type: 'status', status: base });
    for (const [ws, client] of this.clients) {
      if (ws.readyState !== ws.OPEN) continue;
      const s = shared ?? JSON.stringify({ type: 'status', status: { ...base, ...this.game.playerStatus!(client.id) } });
      if (!force && s === this.lastStatus.get(ws)) continue;
      this.lastStatus.set(ws, s);
      ws.send(s);
    }
  }

  private broadcastJson(msg: unknown) {
    const text = JSON.stringify(msg);
    for (const ws of this.clients.keys()) if (ws.readyState === ws.OPEN) ws.send(text);
  }
}
