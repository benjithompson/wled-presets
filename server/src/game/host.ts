import crypto from 'node:crypto';
import type { IncomingMessage, Server } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { EffectScene, type EffectSettings } from '../../../shared/effects.ts';
import { SequencePlayer, type Sequence } from '../../../shared/sequence.ts';
import { buildStage, CONTROL_ID, type GameArea, type GameInfo, type GameStatus, type Layout, type Stage } from '../../../shared/layout.ts';
import { GAME_CATALOG } from '../../../shared/games.ts';
import { endRun, nameScore, pendingInitials, removeScore, scoreboard } from './kit.ts';
import { cascadeGame } from './cascade.ts';
import { catcherGame } from './catcher.ts';
import { duelGame } from './duel.ts';
import { deviceMaps, FramePipeline, type DeviceMap, type FrameSource, type LightFrame } from '../framePipeline.ts';
import { LightSender } from '../lightSender.ts';
import { Frame } from './frame.ts';
import { idleGame } from './idle.ts';
import { GameOutput } from './output.ts';
import { ViewStream, type Viewer } from './viewStream.ts';
import { overflowGame } from './overflow.ts';
import { beadsGame } from './beads.ts';
import { beatGame } from './beat.ts';
import { colorgateGame } from './colorgate.ts';
import { ricochetGame } from './ricochet.ts';
import { sliceGame } from './slice.ts';
import type { Game, GameFactory } from './types.ts';

const CREATE: Record<string, GameFactory> = {
  catcher: catcherGame,
  cascade: cascadeGame,
  overflow: overflowGame,
  duel: duelGame,
  slice: sliceGame,
  colorgate: colorgateGame,
  ricochet: ricochetGame,
  beads: beadsGame,
  beat: beatGame
};

export const GAMES: (GameInfo & { create: GameFactory })[] = GAME_CATALOG.map(({ tagline: _, ...info }) => ({ ...info, create: CREATE[info.id] }));

/** A game with no input for this long goes back to the idle animation. */
const IDLE_AFTER_MS = 3 * 60_000;

type ClientMessage = { type: 'start'; game: string } | { type: 'stop' } | { type: 'leave' } | { type: 'input'; action: 'press' | 'release'; button?: string } | { type: 'setting'; id: string; value: string } | { type: 'initials'; id: number; initials: string };

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

/** Phases with the scoreboard on the phone: before a game and after it. */
const SHOWS_BOARD = new Set(['ready', 'over']);

/** How often the host checks that each browser is still there (WebSocket ping). */
const HEARTBEAT_MS = 4000;

/**
 * Runs games and scenes on the stage. Browsers connect over a WebSocket to watch the simulated
 * yard (binary RGB frames, one byte triple per LED, see ViewStream) and to send input. It is a source of the
 * FramePipeline, which ticks it and sends its frames to the real lights: a running game (unless
 * the debug switch is off), or else a scene's effects.
 */
export class GameHost implements FrameSource {
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
  private clients = new Map<WebSocket, Viewer & { id: string }>();
  /** The simulated yard for the browsers. */
  private view = new ViewStream();
  /** Where the stage's LEDs go on the devices. */
  private maps: DeviceMap[] = [];
  private pipeline: FramePipeline;
  /** True when the host made its own pipeline (no lights given): it closes it on stop. */
  private ownPipeline: boolean;
  private lastInput = Date.now();
  /** The last status sent to each browser, so an unchanged one is not sent again. */
  private lastStatus = new WeakMap<WebSocket, string>();
  private wss = new WebSocketServer({ noServer: true });
  private log: (msg: string) => void;
  /** Games on the real lights: the debug switch and brightness, and the debug panel's view. */
  readonly output: GameOutput;

  /** The scoreboard line named last, lit up on the phones for a minute. */
  private freshScore: { id: number; until: number } | null = null;
  /** Phones whose initials were refused: they are asked again. */
  private refused = new Set<string>();

  private heartbeatMs: number;
  /**
   * A scene's effects. They play whenever no game runs (also with nobody watching), go to the
   * real lights, and show in the simulator instead of the idle animation.
   */
  private scene: Program | null = null;
  private show: Show | null = null;
  /** Devices that get the scene's frames: those with an object that plays an effect. */
  private sceneDevices = new Set<string>();

  /** `pipeline`: the lights. Without one, the host ticks on its own and nothing reaches a device. */
  constructor(layout: Layout, log: (msg: string) => void, pipeline?: FramePipeline, heartbeatMs = HEARTBEAT_MS) {
    this.heartbeatMs = heartbeatMs;
    this.log = log;
    this.ownPipeline = !pipeline;
    this.pipeline = pipeline ?? new FramePipeline(() => [], new LightSender());
    this.pipeline.add(this);
    this.output = new GameOutput(this.pipeline, this, () => this.maps, () => this.layout.fixtures.filter((f) => !f.deviceId).map((f) => f.name));
    this.area = null;
    this.layout = layout;
    this.stage = buildStage(layout);
    this.gameStage = this.buildGameStage();
    this.maps = deviceMaps(layout, this.stage);
    this.frame = new Frame(this.stage.pixelCount);
    this.bytes = new Uint8Array(this.stage.pixelCount * 3);
    this.game = idleGame(this.gameStage);
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
      // ?frames=deflate: the browser takes compressed frames (see ViewStream).
      const deflate = new URL(req.url, 'http://x').searchParams.get('frames') === 'deflate';
      this.wss.handleUpgrade(req, socket, head, (ws) => this.connect(ws, deflate));
    });
  }

  setLayout(layout: Layout) {
    this.layout = layout;
    this.stage = buildStage(layout);
    this.gameStage = this.buildGameStage();
    this.maps = deviceMaps(layout, this.stage);
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
      // The pipeline gives the devices back on the next frame, unless a game has them.
      this.pipeline.wake();
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
    this.pipeline.wake();
    return { devices: [...this.sceneDevices], objects: playing.size };
  }

  /** True while a scene's effects play. */
  get playingEffects() {
    return !!this.scene;
  }

  stop() {
    if (this.ownPipeline) this.pipeline.close();
    else this.pipeline.remove(this);
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
    for (const ws of this.clients.keys()) ws.close();
    this.wss.close();
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
      // With no scene, the host stops running: the pipeline gives the lights back.
      this.pipeline.wake();
    }
    this.sendStatus(true);
  }

  private connect(ws: WebSocket, deflate = false) {
    this.clients.set(ws, { id: crypto.randomUUID(), deflate, fresh: true });
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
    this.pipeline.wake();
  }

  private onMessage(ws: WebSocket, msg: ClientMessage) {
    const client = this.clients.get(ws);
    if (!client) return;
    if (msg.type === 'leave') return this.drop(ws);
    this.lastInput = Date.now();
    // A new game (a game started, or a press that starts the next one) is a new run: the last
    // one's score can no longer be named.
    const before = this.game.status().phase;
    if (msg.type === 'start') {
      const g = GAMES.find((x) => x.id === msg.game);
      if (!g) return;
      endRun();
      this.game = g.create(this.gameStage);
      this.log(`Game started: ${g.name}`);
    } else if (msg.type === 'stop') {
      if (this.game.id !== 'idle') this.log('Game stopped');
      this.game = idleGame(this.gameStage);
    } else if (msg.type === 'input' && (msg.action === 'press' || msg.action === 'release')) {
      const button = typeof msg.button === 'string' && CONTROL_ID.test(msg.button) && msg.button !== 'main' ? msg.button : undefined;
      this.game.input({ playerId: client.id, action: msg.action, ...(button ? { button } : {}) });
    } else if (msg.type === 'initials' && typeof msg.id === 'number' && typeof msg.initials === 'string') {
      const result = nameScore(msg.id, msg.initials.slice(0, 8));
      if (result === 'ok') {
        this.freshScore = { id: msg.id, until: Date.now() + 60_000 };
        this.refused.delete(client.id);
        this.log(`High score named: ${msg.initials.slice(0, 3).toUpperCase()}`);
      } else if (result === 'refused') this.refused.add(client.id);
    } else if (msg.type === 'setting' && typeof msg.id === 'string' && typeof msg.value === 'string' && CONTROL_ID.test(msg.id) && CONTROL_ID.test(msg.value)) {
      this.game.setting?.(msg.id, msg.value);
    }
    if (msg.type === 'input' && SHOWS_BOARD.has(before) && !SHOWS_BOARD.has(this.game.status().phase)) endRun();
    this.sendStatus(true);
  }

  // ---------- Frames ----------

  /** Ticks while someone watches, or a scene plays for the people outside. */
  get running() {
    return this.clients.size > 0 || !!this.scene;
  }

  tick(dt: number): LightFrame | null {
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
    this.view.push(this.bytes, this.clients);
    this.sendStatus(false);
    // A scene goes to the devices that play its effects, at full brightness (each effect has
    // its own); the other devices keep their preset. A game goes everywhere, if switched on.
    if (!gameOn && this.scene) return { maps: this.maps, bytes: this.bytes, devices: this.sceneDevices };
    if (gameOn && this.output.enabled) return { maps: this.maps, bytes: this.bytes, k: this.output.brightness };
    return null;
  }

  private status(): GameStatus {
    const s: GameStatus = { ...this.game.status(), game: this.game.id === 'idle' ? null : this.game.id, players: this.clients.size, realLights: this.output.targets() };
    // The high scores, on the start and game-over screens.
    const board = SHOWS_BOARD.has(s.phase) ? this.game.scoreBoard?.() : null;
    if (board) {
      const fresh = this.freshScore && this.freshScore.until > Date.now() ? this.freshScore.id : undefined;
      s.scoreboard = { title: board.title, entries: scoreboard(board.key).map((e, i) => ({ ...e, rank: i + 1 })), ...(fresh ? { fresh } : {}) };
      const pending = pendingInitials(board.key);
      if (pending) s.enterInitials = pending;
    }
    return s;
  }

  /** An admin takes a line off a scoreboard. */
  removeScore(id: number) {
    const ok = removeScore(id);
    if (ok) this.sendStatus(true);
    return ok;
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
    // back). With no scene, the pipeline gives every device back on the next frame.
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
      const own = this.game.playerStatus?.(client.id);
      // Initials this phone tried that are not allowed: it asks again.
      const refused = base.enterInitials && this.refused.has(client.id) ? { enterInitials: { ...base.enterInitials, refused: true } } : null;
      const s = !own && !refused && shared ? shared : JSON.stringify({ type: 'status', status: { ...base, ...own, ...refused } });
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
