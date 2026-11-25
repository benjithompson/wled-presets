import crypto from 'node:crypto';
import type { IncomingMessage, Server } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { EffectScene, type EffectSettings } from '../../../shared/effects.ts';
import { SequencePlayer, type Sequence } from '../../../shared/sequence.ts';
import { Crossover, pickTransition, type SceneTransition } from '../../../shared/transitions.ts';
import { buildStage, CONTROL_ID, gameAreaFor, type GameArea, type GameInfo, type GameStatus, type Layout, type Stage } from '../../../shared/layout.ts';
import { GAME_CATALOG, type GameId, type PlayMessage } from '../../../shared/games.ts';
import { endRun, nameScore, pendingInitials, removeScore, scoreboard } from './kit.ts';
import { DEFAULT_LINE } from '../../../shared/line.ts';
import { Line, type Visitor } from '../line.ts';
import { cascadeGame } from './cascade.ts';
import { catcherGame } from './catcher.ts';
import { duelGame } from './duel.ts';
import { FramePipeline, layoutOutput, type DeviceMap, type FrameSource, type LightFrame } from '../framePipeline.ts';
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
import { paintGame } from './paint.ts';
import { whackGame } from './whack.ts';
import { cleanStroke } from '../../../shared/paint.ts';
import { hasEnded, showsBoard } from './round.ts';
import type { Game, GameFactory } from './types.ts';

const CREATE: Record<GameId, GameFactory> = {
  catcher: catcherGame,
  cascade: cascadeGame,
  overflow: overflowGame,
  duel: duelGame,
  slice: sliceGame,
  colorgate: colorgateGame,
  ricochet: ricochetGame,
  beads: beadsGame,
  beat: beatGame,
  whack: whackGame,
  paint: paintGame
};

export const GAMES: (GameInfo & { create: GameFactory })[] = GAME_CATALOG.map(({ tagline: _, ...info }) => ({ ...info, create: CREATE[info.id] }));

/** A game with no input for this long goes back to the idle animation. */
const IDLE_AFTER_MS = 3 * 60_000;

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

/** With someone waiting: the turn ends this long after the game ended (the board is on the phone)… */
const BOARD_MS = 8000;
/** …or, while initials are being typed, this long. */
const NAMING_MS = 40_000;
/** With someone waiting, a turn with no input for this long ends. */
const IDLE_WAITING_MS = 45_000;
/** A player whose phone lost its connection (without saying goodbye) keeps the turn this long. */
const AWAY_MS = 20_000;
/** How often the host checks the turn. */
const TURN_CHECK_MS = 500;
/** The largest message a browser may send. */
const MAX_MESSAGE_BYTES = 4096;
/**
 * Messages a browser may send in a second: fast tapping in Beat Drop is a few presses and
 * releases a second. More are dropped (each one sends every browser a status); far more closes it.
 */
const MESSAGES_PER_SECOND = 60;
const CLOSE_AT_MESSAGES_PER_SECOND = 300;

/** Who a browser is: a visitor id from its cookie (so a reload keeps its place in line), and whether an admin. */
export type Identify = (req: IncomingMessage) => Visitor | null;

/**
 * Runs games and scenes on the stage. Browsers connect over a WebSocket to watch the simulated
 * yard (binary RGB frames, one byte triple per LED, see ViewStream) and to send input. It is a source of the
 * FramePipeline, which ticks it and sends its frames to the real lights: a running game (unless
 * the debug switch is off), or else a scene's effects.
 */
export class GameHost implements FrameSource {
  /** Every LED of the layout: scenes play on it. */
  private stage: Stage;
  private area: GameArea | null;
  /**
   * The same LEDs, with only the game area active: games play on it. One for every game with
   * its own choice of objects ('': the area for all games), each with its LEDs outside the
   * area, which stay dark during the game. Built when first needed.
   */
  private stages = new Map<string, { stage: Stage; outside: Int32Array }>();
  /** Games hidden from visitors: only admins see them and can start them. */
  private hidden = new Set<string>();
  private layout: Layout;
  private frame: Frame;
  private bytes: Uint8Array<ArrayBuffer>;
  private game: Game;
  private clients = new Map<WebSocket, Viewer & { id: string; visitor: Visitor }>();
  /**
   * The line for the lights: one turn at a time (see line.ts). Off until configured: then the
   * last choice wins, as before.
   */
  readonly line = new Line({ ...DEFAULT_LINE, enabled: false });
  private turnTimer: NodeJS.Timeout | null = null;
  /** When the player with the turn lost their connection. */
  private awaySince: number | null = null;
  /** When the game of the turn now ended (its board shows), until the next game starts. */
  private overSince: number | null = null;
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
  // Browsers send short JSON messages: a bigger one is not from the page (ws allows 100 MB).
  private wss = new WebSocketServer({ noServer: true, maxPayload: MAX_MESSAGE_BYTES });
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

  /** Why no game can start now (the lights are switched off), or null. */
  closed: () => string | null = () => null;

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
    ({ stage: this.stage, maps: this.maps } = layoutOutput(layout));
    this.frame = new Frame(this.stage.pixelCount);
    this.bytes = new Uint8Array(this.stage.pixelCount * 3);
    this.game = idleGame(this.gameStage);
    this.line.onEndGame = (reason) => this.endGame(reason);
    this.line.subscribe(() => this.sendStatus(true));
    this.line.log = log;
    // The line's timers (a scene's minute, a player who does not tap Play) run with nobody here too.
    this.turnTimer = setInterval(() => this.checkTurn(), TURN_CHECK_MS);
    this.turnTimer.unref();
  }

  /** The stage a game plays on (see stages): its own, when it has its own choice of objects. */
  private stageFor(gameId: string) {
    const key = this.area?.games?.[gameId] ? gameId : '';
    let s = this.stages.get(key);
    if (!s) {
      const stage = buildStage(this.layout, gameAreaFor(this.area, key));
      const out: number[] = [];
      for (let i = 0; i < stage.pixelCount; i++) if (!stage.active[i] && this.stage.active[i]) out.push(i);
      s = { stage, outside: Int32Array.from(out) };
      this.stages.set(key, s);
    }
    return s;
  }

  /** The stage of the area for all games (the idle animation plays on it). */
  private get gameStage(): Stage {
    return this.stageFor('').stage;
  }

  /** The part of the yard that games use. A running game ends: it cannot go on in a changed area. */
  setGameArea(area: GameArea | null) {
    this.area = area;
    this.stages.clear();
    if (this.game.id !== 'idle') this.log('Game ended: the game area changed');
    this.game = idleGame(this.gameStage);
    this.sendStatus(true);
  }

  /**
   * Accepts WebSocket upgrades on the given path. `identify`: who each browser is (no cookie: a
   * new visitor each time). `admit`: whether this one may open (see admitUpgrade); it returns the
   * function to call once the socket closed, or null to refuse.
   */
  attach(server: Server, path: string, identify?: Identify, admit?: (req: IncomingMessage) => (() => void) | null) {
    server.on('upgrade', (req: IncomingMessage, socket, head) => {
      if (!req.url || new URL(req.url, 'http://x').pathname !== path) return;
      const release = admit ? admit(req) : () => {};
      if (!release) {
        socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        socket.destroy();
        return;
      }
      socket.once('close', release);
      // ?frames=deflate: the browser takes compressed frames (see ViewStream).
      const deflate = new URL(req.url, 'http://x').searchParams.get('frames') === 'deflate';
      const who = identify?.(req) ?? null;
      this.wss.handleUpgrade(req, socket, head, (ws) => this.connect(ws, deflate, who));
    });
  }

  /** The yard as the host plays it now. */
  get yard(): Layout {
    return this.layout;
  }

  /**
   * The simulated yard's last frame (RGB bytes in stage order, see buildStage), or null when
   * nothing plays on it (no game, no scene, nobody watching).
   */
  simFrame(): Uint8Array | null {
    return this.running ? this.bytes : null;
  }

  setLayout(layout: Layout) {
    this.layout = layout;
    ({ stage: this.stage, maps: this.maps } = layoutOutput(layout));
    this.stages.clear();
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
   * `transition`: the show that plays now gives way to this one with it (when one plays, and no
   * game runs). Devices that only the old show lit go back to their own state at once.
   */
  playShow(show: Show | null, transition?: SceneTransition | null): { devices: string[]; objects: number } {
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
    const prev = this.scene;
    if (transition && transition.seconds > 0 && prev && !same && this.game.id === 'idle') {
      const next: Program = seq ? sequenceProgram(this.stage, this.layout, seq) : new EffectScene(this.stage, this.layout, fx!);
      this.scene = new Crossover<Layout, Program>(this.stage, prev, next, pickTransition(transition.type, Math.random()), transition.seconds);
    } else if (seq) {
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
    if (this.turnTimer) clearInterval(this.turnTimer);
    this.turnTimer = null;
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
  private drop(ws: WebSocket, hard = false, goodbye = false) {
    const client = this.clients.get(ws);
    if (!client || !this.clients.delete(ws)) return;
    this.refused.delete(client.id);
    this.game.leave?.(client.id);
    // A goodbye closes politely; a browser that stopped answering is cut off.
    if (hard) ws.terminate();
    else if (ws.readyState === ws.OPEN) ws.close(1000);
    const holder = this.line.settings.enabled ? this.line.holder() : null;
    const stillHere = [...this.clients.values()].some((c) => c.visitor.id === client.visitor.id);
    if (holder && holder === client.visitor.id && !stillHere) {
      // The player with the turn: a goodbye ends it now. A lost connection (a phone that went to
      // sleep) keeps it for a little while, paused if nobody else watches (see checkTurn).
      if (goodbye) this.line.release(holder, 'the player left');
    } else if (this.clients.size === 0 && !holder) {
      // Nobody is playing: end the game, so the next visitor starts at the game picker.
      // A scene's effects keep playing for the people outside: they take the lights back on
      // the next frame, and devices that play a preset get it back.
      this.game = idleGame(this.gameStage);
      // With no scene, the host stops running: the pipeline gives the lights back.
      this.pipeline.wake();
    }
    this.sendStatus(true);
  }

  private connect(ws: WebSocket, deflate = false, who: Visitor | null = null) {
    const id = crypto.randomUUID();
    this.clients.set(ws, { id, deflate, fresh: true, visitor: who ?? { id: `c:${id}` } });
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
    this.sendGames(ws, this.clients.get(ws)!.visitor);
    this.sendStatus(true);
    let second = 0;
    let sent = 0;
    ws.on('message', (raw, isBinary) => {
      const now = Math.floor(Date.now() / 1000);
      if (now !== second) [second, sent] = [now, 0];
      if (++sent > CLOSE_AT_MESSAGES_PER_SECOND) return this.drop(ws, true);
      if (sent > MESSAGES_PER_SECOND || isBinary) return;
      let msg: PlayMessage;
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

  private onMessage(ws: WebSocket, msg: PlayMessage) {
    const client = this.clients.get(ws);
    if (!client) return;
    if (msg.type === 'leave') return this.drop(ws, false, true);
    const who = client.visitor;
    const line = this.line;
    const lined = line.settings.enabled;
    // With the line on, only the player with the turn plays; in a game with sides (Duel), anyone
    // watching can take the free side.
    const theirs = !lined || line.holder() === who.id;
    const mayInput = theirs || !!this.game.playerStatus;
    // A new game (a game started, or a press that starts the next one) is a new run: the last
    // one's score can no longer be named.
    const before = this.game.status().phase;
    const closed = msg.type === 'start' || msg.type === 'accept' ? this.closed() : null;
    if (closed) return this.notice(ws, closed);
    if (msg.type === 'start') {
      const g = GAMES.find((x) => x.id === msg.game);
      if (!g) return;
      if (this.hidden.has(g.id) && !who.admin) return this.notice(ws, `${g.name} isn't on right now. Pick another game!`);
      const asked = line.ask(who, { kind: 'game', game: g.id }, g.name);
      if (asked.result === 'now') this.startGame(g.id);
      else if (asked.result === 'full') this.notice(ws, 'The line is full right now. Try again in a few minutes!');
    } else if (msg.type === 'accept') {
      const game = line.accept(who.id);
      if (game) this.startGame(game);
    } else if (msg.type === 'leaveLine') {
      line.leave(who.id);
    } else if (msg.type === 'stop') {
      if (!theirs) return;
      if (this.game.id !== 'idle') this.log('Game stopped');
      if (lined) line.release(who.id, 'the player stopped');
      this.game = idleGame(this.gameStage);
    } else if (msg.type === 'input' && (msg.action === 'press' || msg.action === 'release')) {
      if (!mayInput) return;
      this.lastInput = Date.now();
      // Someone is waiting and this game is over: the press ends the turn, not a new game.
      if (lined && theirs && msg.action === 'press' && this.overSince != null && line.waitingCount()) {
        line.release(who.id, 'the game ended');
        return;
      }
      const button = typeof msg.button === 'string' && CONTROL_ID.test(msg.button) && msg.button !== 'main' ? msg.button : undefined;
      this.game.input({ playerId: client.id, action: msg.action, ...(button ? { button } : {}) });
    } else if (msg.type === 'initials' && typeof msg.id === 'number' && typeof msg.initials === 'string') {
      if (!theirs) return;
      this.lastInput = Date.now();
      const result = nameScore(msg.id, msg.initials.slice(0, 8));
      if (result === 'ok') {
        this.freshScore = { id: msg.id, until: Date.now() + 60_000 };
        this.refused.delete(client.id);
        this.log(`High score named: ${msg.initials.slice(0, 3).toUpperCase()}`);
      } else if (result === 'refused') this.refused.add(client.id);
    } else if (msg.type === 'paint') {
      // A finger moving over the picture of the yard (Light Painter): many a second, and each one
      // changes only the lights, so the status goes out only if it changed.
      if (!theirs || !this.game.paint) return;
      const stroke = cleanStroke(msg);
      if (!stroke) return;
      this.lastInput = Date.now();
      this.game.paint({ ...stroke, playerId: client.id });
      return this.sendStatus(false);
    } else if (msg.type === 'setting' && typeof msg.id === 'string' && typeof msg.value === 'string' && CONTROL_ID.test(msg.id) && CONTROL_ID.test(msg.value)) {
      if (!theirs) return;
      this.lastInput = Date.now();
      this.game.setting?.(msg.id, msg.value);
    }
    if (msg.type === 'input' && showsBoard(before) && !showsBoard(this.game.status().phase)) endRun();
    this.sendStatus(true);
  }

  private startGame(id: string) {
    const g = GAMES.find((x) => x.id === id)!;
    endRun();
    this.game = g.create(this.stageFor(g.id).stage);
    this.lastInput = Date.now();
    this.overSince = null;
    this.awaySince = null;
    this.log(`Game started: ${g.name}`);
  }

  /**
   * Games an admin hid from visitors. Phones get the new list at once; a hidden game that runs
   * now plays to its end.
   */
  setHiddenGames(ids: string[]) {
    this.hidden = new Set(ids);
    for (const [ws, c] of this.clients) this.sendGames(ws, c.visitor);
  }

  /** The games a browser may pick: visitors get the ones not hidden; admins all, the hidden ones marked. */
  private sendGames(ws: WebSocket, who: Visitor) {
    if (ws.readyState !== ws.OPEN) return;
    const games = GAMES.filter((g) => who.admin || !this.hidden.has(g.id)).map(({ id, name, description, players }) => ({ id, name, description, players, ...(this.hidden.has(id) ? { hidden: true } : {}) }));
    ws.send(JSON.stringify({ type: 'games', games }));
  }

  private notice(ws: WebSocket, text: string) {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type: 'notice', text }));
  }

  /**
   * Ends the turn of the player with the lights when it is over: they left (and did not come
   * back), stopped playing, or someone is waiting and their game ended.
   */
  private checkTurn() {
    const line = this.line;
    line.tick();
    const holder = line.settings.enabled ? line.holder() : null;
    if (!holder) {
      this.awaySince = this.overSince = null;
      return;
    }
    const now = Date.now();
    // The game is gone (the layout changed, a scene took the lights): so is the turn.
    if (this.game.id === 'idle') return line.release(holder, 'the game ended');
    if ([...this.clients.values()].some((c) => c.visitor.id === holder)) this.awaySince = null;
    else if (now - (this.awaySince ??= now) > AWAY_MS) return line.release(holder, 'the player left');
    const waiting = line.waitingCount() > 0;
    if (now - this.lastInput > (waiting ? IDLE_WAITING_MS : (this.game.idleAfterMs ?? IDLE_AFTER_MS))) return line.release(holder, 'nobody played');
    const phase = this.game.status().phase;
    if (hasEnded(phase)) this.overSince ??= now;
    else if (!showsBoard(phase)) this.overSince = null;
    if (waiting && this.overSince != null) {
      const board = this.game.scoreBoard?.();
      const naming = board ? !!pendingInitials(board.key) : false;
      const t = now - this.overSince;
      if ((!naming && t > BOARD_MS) || t > NAMING_MS) line.release(holder, 'the game ended');
    }
  }

  // ---------- Frames ----------

  /** Ticks while someone watches, or a scene plays for the people outside. */
  get running() {
    return this.clients.size > 0 || !!this.scene;
  }

  tick(dt: number): LightFrame | null {
    if (this.game.id !== 'idle' && Date.now() - this.lastInput > (this.game.idleAfterMs ?? IDLE_AFTER_MS)) {
      this.game = idleGame(this.gameStage);
    }
    const gameOn = this.game.id !== 'idle';
    if (!gameOn && this.scene) {
      this.scene.update(dt, this.frame.data);
      // A transition that has ended leaves the new show.
      if (this.scene instanceof Crossover && this.scene.done) this.scene = this.scene.to;
    } else {
      this.game.update(dt, this.frame);
      // Lights outside the game's area stay dark, whatever the game drew there.
      const d = this.frame.data;
      for (const i of this.stageFor(this.game.id).outside) d[i * 3] = d[i * 3 + 1] = d[i * 3 + 2] = 0;
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
    const board = showsBoard(s.phase) ? this.game.scoreBoard?.() : null;
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

  /**
   * Sends each browser its status: the game's, with that player's own side and button on top,
   * and their place in the line.
   */
  private sendStatus(force: boolean) {
    const base = this.status();
    const lined = this.line.settings.enabled;
    const holder = this.line.holder();
    const waiting = this.line.waitingCount() > 0;
    for (const [ws, client] of this.clients) {
      if (ws.readyState !== ws.OPEN) continue;
      const own = this.game.playerStatus?.(client.id);
      const theirs = !lined || holder === client.visitor.id;
      // Initials this phone tried that are not allowed: it asks again.
      const refused = base.enterInitials && this.refused.has(client.id) ? { enterInitials: { ...base.enterInitials, refused: true } } : null;
      // Someone waits and the game is over: the button ends the turn.
      const done = lined && theirs && waiting && this.overSince != null ? { button: 'DONE', tone: 'calm' as const } : null;
      const canPlay = theirs || !!this.game.playerStatus;
      const s = JSON.stringify({ type: 'status', status: { ...base, ...own, ...refused, ...done, canPlay, ...(theirs ? {} : { enterInitials: undefined }), line: this.line.view(client.visitor.id) } });
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
