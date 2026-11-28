import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Hono, type Context } from 'hono';
import { secureHeaders } from 'hono/secure-headers';
import { streamSSE } from 'hono/streaming';
import { serveStatic } from '@hono/node-server/serve-static';
import { z } from 'zod';
import { FRAME_RATE, type BackupFile, type DiscoveredDevice, type Scene, type SessionInfo } from '../../shared/types.ts';
import { createAuth, isExamplePassword, sameOrigin, type AuthEnv } from './auth.ts';
import { isLoopbackIp, requestIp, requestIsDirectLan, requestIsLocal, viaHttps, warnUntrustedProxy } from './clientIp.ts';
import type { AppConfig } from './config.ts';
import type { Db } from './db.ts';
import { discoverWled } from './discovery.ts';
import type { Bus } from './events.ts';
import type { Lights } from './lights.ts';
import { isValidCidr } from './net.ts';
import { createPasskeys, PasskeyError, siteOf } from './passkeys.ts';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { ConnectionLimit, limitBody, rateLimit } from './rateLimit.ts';
import { cleanGameArea, readGameArea, readHiddenGames, readSettings, writeGameArea, writeHiddenGames, writeLineSettings, writeSettings } from './settings.ts';
import { GAME_CATALOG } from '../../shared/games.ts';
import { visitorCookie, visitorId, visitorTag } from './visitor.ts';
import type { Visitor } from './line.ts';
import { DEFAULT_LINE, ordinal } from '../../shared/line.ts';
import { SCENE_TRANSITION_SECONDS, TRANSITION_CHOICES, type SceneTransitionChoice } from '../../shared/transitions.ts';
import type { GameHost } from './game/host.ts';
import type { RoofView } from './roofView.ts';
import type { LightScheduler } from './lightSchedule.ts';
import { cleanHaUrl, HA_FPS, HA_INFLIGHT_MAX, type HomeAssistant } from './homeAssistant.ts';
import { haSpeedTest } from './haSpeedTest.ts';
import { haId, isSwitchable } from '../../shared/homeAssistant.ts';
import { activePeriods, IDLE_MINUTES, isClockTime, isTimeZone, MAX_PERIODS, OFFSET_MINUTES, PERIOD_NAME_MAX, sameTime, scheduleRuns } from '../../shared/schedule.ts';
import type { LayoutPreview, SequencePreviewRequest } from './layoutPreview.ts';
import { deleteBackground, effectsSchema, layoutSchema, layoutShape, readBackground, readLayout, saveBackground, writeLayout } from './layoutStore.ts';
import { normalizeHost, wled } from './wled.ts';
import { readAudio, removeAudio, sequenceInput, writeAudio } from './sequenceStore.ts';
import { summarize } from '../../shared/sequence.ts';
import { deviceKey, keyDevice } from '../../shared/effects.ts';
import { cleanPlaylist, PLAYLIST_SECONDS } from '../../shared/playlist.ts';
import { MAX_FIXTURE_PIXELS } from '../../shared/layout.ts';
import { DEFAULT_LED_TYPES, parseSettingsScript, pickStatus, protectedSection, unappliedPaths, type WledSettings } from '../../shared/wledConfig.ts';

export interface AppDeps {
  config: AppConfig;
  db: Db;
  bus: Bus;
  lights: Lights;
  discover?: typeof discoverWled;
  host?: GameHost;
  preview?: LayoutPreview;
  roof?: RoofView;
  /** Every LED of the yard as it is now, for the admin's live view (see RoofView, shape 'yard'). */
  yard?: RoofView;
  /** Switches the lights on and off at set times (see LightSchedule). */
  schedule?: LightScheduler;
  /** Home Assistant: plugs that power the controllers, and other lights (see HaSettings). */
  ha?: HomeAssistant;
}

const deviceInput = z.object({
  name: z.string().trim().max(100).default(''),
  host: z.string().trim().min(1, 'Host is required').max(255).transform(normalizeHost),
  port: z.coerce.number().int().min(1).max(65535).default(80),
  enabled: z.boolean().default(true)
});

const transitionChoice = z.enum(['none', ...TRANSITION_CHOICES.map((t) => t.id)] as [SceneTransitionChoice, ...SceneTransitionChoice[]]);
const playlistSeconds = z.coerce.number().min(PLAYLIST_SECONDS.min).max(PLAYLIST_SECONDS.max);
const playlistSchema = z.object({
  all: z.boolean(),
  sceneIds: z.array(z.string().max(64)).max(500).default([]),
  seconds: playlistSeconds,
  durations: z.record(z.string().max(64), playlistSeconds).optional(),
  transition: transitionChoice,
  transitionSeconds: z.coerce.number().min(0).max(SCENE_TRANSITION_SECONDS.max)
});

const sceneInput = z.object({
  name: z.string().trim().min(1, 'Name is required').max(100),
  devicePresets: z.record(z.string(), z.coerce.number().int().min(1).max(250)).default({}),
  /** Left out: an update keeps the scene's effects. An empty object removes them. */
  effects: effectsSchema.optional(),
  /** Left out: an update keeps the scene's sequence. Null removes it. */
  sequenceId: z.string().max(64).nullable().optional(),
  /** Left out: an update keeps the scene a playlist, or not. Null makes it a scene of its own. */
  playlist: playlistSchema.nullable().optional()
});

const settingsInput = z.object({
  siteTitle: z.string().trim().min(1).max(80),
  siteSubtitle: z.string().trim().max(200),
  showColors: z.boolean(),
  defaultSceneId: z.string().nullable(),
  revertMinutes: z.coerce.number().int().min(0).max(24 * 60),
  discoverySubnets: z.array(z.string().trim().refine(isValidCidr, 'Use CIDR form, for example 192.168.1.0/24')).max(16),
  /** Left out: kept as it is. */
  sceneTransition: z.enum(['none', ...TRANSITION_CHOICES.map((t) => t.id)] as [SceneTransitionChoice, ...SceneTransitionChoice[]]).optional(),
  sceneTransitionSeconds: z.number().finite().min(SCENE_TRANSITION_SECONDS.min).max(SCENE_TRANSITION_SECONDS.max).optional(),
  /** Left out: kept as it is. */
  maxFps: z.number().int('Use a whole number').min(FRAME_RATE.min).max(FRAME_RATE.max).optional(),
  /** Left out: kept as it is. */
  debugHa: z.boolean().optional()
});

const scheduleTime = z.object({
  at: z.enum(['sunrise', 'sunset', 'time']),
  offset: z.number().int().min(-OFFSET_MINUTES).max(OFFSET_MINUTES),
  time: z.string().refine(isClockTime, 'Use a time such as 23:00')
});
const schedulePeriod = z.object({
  id: z.string().regex(/^[\w-]{1,40}$/, 'Bad period id'),
  name: z.string().trim().max(PERIOD_NAME_MAX),
  enabled: z.boolean(),
  days: z.array(z.number().int().min(0).max(6)).max(7),
  on: scheduleTime,
  off: scheduleTime
});
const scheduleInput = z
  .object({
    enabled: z.boolean(),
    latitude: z.number().finite().min(-90).max(90).nullable(),
    longitude: z.number().finite().min(-180).max(180).nullable(),
    timeZone: z.string().max(64).refine(isTimeZone, 'Unknown time zone'),
    periods: z.array(schedulePeriod).max(MAX_PERIODS, `At most ${MAX_PERIODS} schedules`),
    /** Left out (an older page): kept as they are. */
    wake: z.boolean().optional(),
    idleMinutes: z.number().int('Use a whole number of minutes').min(IDLE_MINUTES.min).max(IDLE_MINUTES.max).optional()
  })
  .refine((s) => new Set(s.periods.map((p) => p.id)).size === s.periods.length, 'Two schedules have the same id')
  .refine((s) => !s.enabled || activePeriods(s).length > 0, 'Switch on at least one schedule, on at least one day')
  .refine((s) => !s.enabled || scheduleRuns(s), 'Set where the lights are: sunrise and sunset need it')
  .refine((s) => !s.periods.some((p) => p.enabled && sameTime(p.on, p.off)), 'The lights cannot switch on and off at the same time');

/** An RGB color, each part 0..255. */
const rgbInput = z.tuple([z.number().int().min(0).max(255), z.number().int().min(0).max(255), z.number().int().min(0).max(255)]);

const gameAreaInput = z.object({
  exclude: z.array(z.string().min(1).max(64)).max(512).optional(),
  skip: z.record(z.string().min(1).max(64), z.array(z.number().int().min(0).max(9999)).max(512)).optional(),
  trim: z.record(z.string().min(1).max(64), z.tuple([z.number().int().min(0).max(99999), z.number().int().min(0).max(99999)])).optional(),
  games: z.record(z.string().min(1).max(64), z.record(z.string().min(1).max(64), z.boolean())).optional()
});

const GAME_IDS = GAME_CATALOG.map((g) => g.id);

/** A picture in a layout file: its type, and its bytes in base64 (up to 12 MB). */
const pictureInput = z.object({ type: z.enum(['image/png', 'image/jpeg', 'image/webp', 'image/gif']), data: z.string().max(17_000_000) });
/**
 * A layout file (Layout → File → Export): the layout, the devices its objects use (so they
 * match devices by address on another install), the game area, and the pictures. A bare
 * layout (an object with `fixtures`) is read as a file with only the layout.
 */
const layoutFileInput = z.preprocess(
  (raw) => (raw && typeof raw === 'object' && 'fixtures' in raw ? { layout: raw } : raw),
  z.object({
    kind: z.literal('wled-layout').optional(),
    version: z.number().optional(),
    layout: layoutShape,
    devices: z.array(z.object({ id: z.string(), name: z.string().optional(), host: z.string(), port: z.number().optional() })).max(256).optional(),
    gameArea: gameAreaInput.nullable().optional(),
    pictures: z.object({ background: pictureInput.nullable().optional(), aerial: pictureInput.nullable().optional() }).optional()
  })
);

const backupInput = z.object({
  version: z.number().optional(),
  devices: z.array(z.object({ id: z.string(), host: z.string(), port: z.number().optional() })).optional(),
  publicPresets: z.array(
    z.object({
      id: z.string().min(1),
      name: z.string().trim().min(1),
      sortOrder: z.number().optional(),
      devicePresets: z.record(z.string(), z.coerce.number()).default({}),
      effects: effectsSchema.optional().catch(undefined),
      sequenceId: z.string().max(64).nullable().optional().catch(undefined),
      playlist: playlistSchema.nullable().optional().catch(undefined)
    })
  )
});

/** A new admin password: long, and not one from the examples (the site is on the internet). */
const newPassword = z
  .string()
  .min(12, 'Use at least 12 characters')
  .max(1000)
  .refine((p) => !isExamplePassword(p), 'That password is in the examples: pick your own');

/** What a browser sends back from a passkey (checked in full by Passkeys; this keeps it in shape). */
const credentialJson = z
  .object({
    id: z.string().min(1).max(1400),
    rawId: z.string().max(1400),
    type: z.literal('public-key'),
    response: z.looseObject({ clientDataJSON: z.string().max(8192) }),
    clientExtensionResults: z.looseObject({}).default({})
  })
  .loose();

function errorMessage(e: z.ZodError): string {
  const i = e.issues[0];
  return i ? `${i.path.join('.') || 'input'}: ${i.message}` : 'Invalid input';
}

async function body<T extends z.ZodType>(c: Context, schema: T): Promise<z.infer<T>> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    raw = {};
  }
  const r = schema.safeParse(raw);
  if (!r.success) throw new HttpError(400, errorMessage(r.error));
  return r.data;
}

/** How long WLED takes to apply new settings (it sets up LED outputs after it answers). */
const WLED_SETTLE_MS = 800;

/** Visitors watching the Live tab at once, and how often each gets a frame (see RoofView). */
const PUBLIC_YARD_VIEWERS = { name: 'public', max: 60, every: 2 };

class HttpError extends Error {
  status: 400 | 401 | 403 | 404 | 409 | 502;
  constructor(status: HttpError['status'], message: string) {
    super(message);
    this.status = status;
  }
}

export function createApp({ config, db, bus, lights, discover = discoverWled, host, preview, roof, yard, schedule, ha }: AppDeps) {
  const app = new Hono();
  const auth = createAuth(db, { secureCookie: config.secureCookie });
  const passkeys = createPasskeys(db);

  // The visitor's address: proxy headers count only as far as TRUST_PROXY says (see clientIp.ts).
  const clientIp = (c: Context): string => {
    warnUntrustedProxy(c, config.trustProxy);
    return requestIp(c, config.trustProxy);
  };
  const actor = (c: Context) => ({ ip: clientIp(c), userAgent: c.req.header('user-agent')?.slice(0, 300) ?? null });
  // Made on this computer: not just from 127.0.0.1, which every request through cloudflared is.
  const isLoopback = (c: Context) => requestIsLocal(c);

  app.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    if (err instanceof PasskeyError) return c.json({ error: err.message }, 400);
    console.error(err);
    return c.json({ error: 'Internal error' }, 500);
  });

  app.use(
    '*',
    secureHeaders({
      contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        // blob: the object designer's photo, which stays in the browser.
        imgSrc: ["'self'", 'data:', 'blob:'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'"],
        mediaSrc: ["'self'", 'blob:'],
        frameAncestors: ["'none'"]
      },
      // The app is usually served over plain HTTP on a LAN.
      strictTransportSecurity: false,
      crossOriginEmbedderPolicy: false
    })
  );
  // Over HTTPS (at the proxy in front), the browser keeps to HTTPS for this name from then on. A
  // plain-HTTP address on the home network gets no such header (a browser ignores it there anyway).
  app.use('*', async (c, next) => {
    await next();
    if (viaHttps(c)) c.header('Strict-Transport-Security', 'max-age=15552000');
  });
  app.use('/api/*', async (c, next) => {
    await next();
    if (!c.res.headers.has('Cache-Control')) c.header('Cache-Control', 'no-store');
  });
  // Bodies read before signing in are small. Admin uploads (signed in) can be large.
  app.use('/api/*', limitBody(64 * 1024, (c) => c.req.path.startsWith('/api/admin/')));
  // A visitor id for the line for the lights.
  app.use('*', visitorCookie(config.secureCookie));
  const visitor = (c: Context): Visitor => ({ id: visitorId(c), admin: !!auth.currentUser(c), actor: actor(c) });
  /** Who changes the lights from the public page: a visitor who is not an admin is logged as one (see Actor.visitor). */
  const publicActor = (c: Context) => {
    const v = visitor(c);
    return v.admin ? actor(c) : { ...actor(c), visitor: visitorTag(v.id) };
  };
  /** The line for the lights: with no game host (tests), there is none and the last choice wins. */
  const line = host?.line ?? null;

  const signInFrom = (c: Context) => ({ ip: clientIp(c), lan: requestIsDirectLan(c) });
  const tooMany = (c: Context, retryIn: number) => {
    const s = Math.ceil(retryIn / 1000);
    c.header('Retry-After', String(s));
    return c.json({ error: `Too many failed sign-ins. Try again in ${s > 90 ? `${Math.ceil(s / 60)} minutes` : `${s} seconds`}.` }, 429);
  };
  /** The page's site, for passkeys: refused over plain HTTP or at an IP address (see siteOf). */
  const site = (c: Context) => {
    const s = siteOf(c.req.header('origin'), c.req.header('host'), viaHttps(c));
    if ('error' in s) throw new HttpError(400, s.error);
    return s;
  };

  // No limits for requests from this computer (localhost): that is you, testing.
  const publicLimiter = rateLimit({ windowMs: 60_000, max: 120, clientIp, skip: isLoopback });
  // Generous enough for quick taps on the color wheel; still stops a runaway script.
  const applyLimiter = rateLimit({ windowMs: 10_000, max: 30, clientIp, skip: isLoopback });
  const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 20, clientIp });
  // Open event streams: a few tabs per address, and not every socket the server has.
  const streams = new ConnectionLimit(20, 2000);

  // ---------------- Public ----------------

  app.get('/api/health', (c) => c.json({ ok: true }));

  app.get('/api/state', publicLimiter, (c) => c.json(lights.publicState()));

  app.get('/api/events', publicLimiter, (c) => {
    const me = visitorId(c);
    const ip = clientIp(c);
    const release = streams.take(ip, isLoopbackIp(ip));
    if (!release) return c.json({ error: 'Too many open pages from your address' }, 429);
    return streamSSE(c, async (stream) => {
      stream.onAbort(release);
      let timer: NodeJS.Timeout | null = null;
      const send = () => {
        if (timer) return;
        // Coalesce bursts (for example many devices changing at once) into one message.
        timer = setTimeout(() => {
          timer = null;
          void stream.writeSSE({ event: 'state', data: JSON.stringify(lights.publicState()) });
        }, 50);
      };
      // This visitor's view of the line: who has the lights, and their place.
      let lastLine = '';
      const sendLine = () => {
        if (!line) return;
        const v = JSON.stringify(line.view(me));
        if (v === lastLine) return;
        lastLine = v;
        void stream.writeSSE({ event: 'line', data: v });
      };
      bus.on('state', send);
      bus.on('line', sendLine);
      await stream.writeSSE({ event: 'state', data: JSON.stringify(lights.publicState()) });
      sendLine();
      const ping = setInterval(() => void stream.writeSSE({ event: 'ping', data: '' }), 25_000);
      await new Promise<void>((resolve) => stream.onAbort(resolve));
      clearInterval(ping);
      if (timer) clearTimeout(timer);
      bus.off('state', send);
      bus.off('line', sendLine);
    });
  });

  // The roofline as it is now, for the strip along the top of the home page (see RoofView).
  app.get('/api/roof', publicLimiter, (c) => {
    if (!roof) return c.json({ error: 'No roof view' }, 404);
    const ip = clientIp(c);
    const release = streams.take(ip, isLoopbackIp(ip));
    if (!release) return c.json({ error: 'Too many open pages from your address' }, 429);
    return streamSSE(c, async (stream) => {
      stream.onAbort(release);
      const stop = roof.watch((e) => void stream.writeSSE(e).catch(() => {}));
      if (!stop) {
        await stream.writeSSE({ event: 'busy', data: '' });
        release();
        return;
      }
      const ping = setInterval(() => void stream.writeSSE({ event: 'ping', data: '' }).catch(() => {}), 25_000);
      await new Promise<void>((resolve) => stream.onAbort(resolve));
      clearInterval(ping);
      stop();
    });
  });

  // The whole yard as the lights show it now (the home page's Live tab). Everyone shares the
  // admins' view of the devices; visitors are a group of their own, so an admin always gets in,
  // and each gets every other frame (10 a second): every LED of the yard, for many people, is a
  // lot to send.
  app.get('/api/yard', publicLimiter, (c) => {
    if (!yard) return c.json({ error: 'No yard view' }, 404);
    const ip = clientIp(c);
    const release = streams.take(ip, isLoopbackIp(ip));
    if (!release) return c.json({ error: 'Too many open pages from your address' }, 429);
    return streamSSE(c, async (stream) => {
      stream.onAbort(release);
      const stop = yard.watch((e) => void stream.writeSSE(e).catch(() => {}), PUBLIC_YARD_VIEWERS);
      if (!stop) {
        await stream.writeSSE({ event: 'busy', data: '' });
        release();
        return;
      }
      const ping = setInterval(() => void stream.writeSSE({ event: 'ping', data: '' }).catch(() => {}), 25_000);
      await new Promise<void>((resolve) => stream.onAbort(resolve));
      clearInterval(ping);
      stop();
    });
  });

  /** A color or scene chosen on the public page wins over a game or a layout preview. */
  const takeLights = (what: string) => {
    host?.endGame(`${what} was chosen`);
    preview?.stop();
  };

  // Scenes and colors from the line, when their turn comes.
  if (line) {
    line.subscribe(() => bus.emit('line'));
    line.onShow = (want, who) => {
      takeLights(want.kind === 'scene' ? 'a scene from the line' : 'a color from the line');
      const by = who.admin ? who.actor : { ...who.actor, visitor: visitorTag(who.id) };
      void (want.kind === 'scene' ? lights.applyScene(want.id, by) : lights.applyColor(want.hex, by)).catch(() => {});
    };
  }

  /**
   * Asks the line for the lights. Null: play it now. Otherwise the answer for the browser: its
   * place in line (202), or that the line is full (409).
   */
  const askLine = (c: Context, want: Parameters<NonNullable<typeof line>['ask']>[1], label: string) => {
    if (!line) return null;
    const asked = line.ask(visitor(c), want, label);
    if (asked.result === 'now') return null;
    if (asked.result === 'full') return c.json({ error: 'The line is full right now. Try again in a few minutes!' }, 409);
    if (asked.result === 'wait') {
      const s = Math.ceil(asked.retryIn / 1000);
      c.header('Retry-After', String(s));
      return c.json({ error: `You just changed the lights. Pick again in ${s} second${s === 1 ? '' : 's'}.`, retryIn: asked.retryIn }, 429);
    }
    return c.json({ queued: { place: asked.place, message: `You're ${ordinal(asked.place)} in line. ${label} plays when it's your turn.` } }, 202);
  };

  const LIGHTS_OFF = 'The lights are switched off right now.';
  /**
   * A visitor's pick while every light is off: in the schedule's night it switches them on
   * again (see LightScheduler.wake), else it is refused. Either way the lights count as used.
   */
  const wakeFor = async (what: string) => {
    if (lights.allOff()) {
      const woke = schedule?.wake(what);
      if (!woke) throw new HttpError(409, LIGHTS_OFF);
      await woke;
    }
    schedule?.used();
  };

  // Changing the lights is for this site's own pages: another site's page cannot do it with its
  // visitors' browsers (each one a new visitor, from a new address, in line).
  app.use('/api/scenes/*', sameOrigin());
  app.use('/api/color', sameOrigin());
  app.use('/api/line/*', sameOrigin());

  app.post('/api/scenes/:id/apply', applyLimiter, async (c) => {
    const id = c.req.param('id');
    const name = lights.publicState().scenes.find((s) => s.id === id)?.name;
    if (!name) throw new HttpError(404, 'Unknown scene');
    await wakeFor(`a visitor's scene "${name}"`);
    const queued = askLine(c, { kind: 'scene', id }, name);
    if (queued) return queued;
    takeLights('a scene');
    const result = await lights.applyScene(id, publicActor(c));
    if (!result) throw new HttpError(404, 'Unknown scene');
    if (result.applied.length === 0 && !result.effects && !result.starting?.length) return c.json({ error: 'No light responded. Check that the lights are on.', ...result }, 502);
    return c.json(result);
  });

  app.post('/api/color', applyLimiter, async (c) => {
    const { color } = await body(c, z.object({ color: z.string().regex(/^#?[0-9a-fA-F]{6}$/, 'Use a hex color like #ff8800') }));
    const hex = `#${color.replace('#', '').toLowerCase()}`;
    await wakeFor(`a visitor's color ${hex}`);
    const queued = askLine(c, { kind: 'color', hex }, `Color ${hex}`);
    if (queued) return queued;
    takeLights('a color');
    const result = await lights.applyColor(color, publicActor(c));
    if (!result || (result.applied.length === 0 && !result.starting?.length)) return c.json({ error: 'No light responded. Check that the lights are on.', ...result }, 502);
    return c.json(result);
  });

  // Leave the line (the public page's "Leave the line").
  app.post('/api/line/leave', applyLimiter, (c) => {
    line?.leave(visitorId(c));
    return c.json({ ok: true });
  });

  // ---------------- Yard layout (public read) ----------------

  app.get('/api/layout', publicLimiter, (c) => c.json(readLayout(db)));

  app.get('/api/layout/background', publicLimiter, (c) => {
    const bg = readBackground(db, config.databasePath);
    if (!bg) return c.json({ error: 'No background picture' }, 404);
    return new Response(new Uint8Array(bg.bytes), { headers: { 'Content-Type': bg.type, 'Cache-Control': 'no-cache' } });
  });

  // ---------------- Auth ----------------

  app.use('/api/auth/*', sameOrigin());

  app.get('/api/auth/session', (c) => {
    const info: SessionInfo = { user: auth.currentUser(c), needsBootstrap: db.countUsers() === 0 };
    return c.json(info);
  });

  app.post('/api/auth/login', loginLimiter, async (c) => {
    const { username, password } = await body(c, z.object({ username: z.string().min(1).max(100), password: z.string().min(1).max(1000) }));
    const r = await auth.login(c, username, password, signInFrom(c));
    if (r.ok === false && r.retryIn) return tooMany(c, r.retryIn);
    if (r.ok === false) {
      lights.log('warn', 'admin', `Failed sign-in for "${username.slice(0, 40)}"`, null, actor(c));
      throw new HttpError(401, 'Wrong username or password');
    }
    lights.log('info', 'admin', `${r.user.username} signed in`, null, actor(c));
    return c.json({ user: r.user });
  });

  // Passkeys: the browser asks for a challenge, the device signs it, the server checks the signature.
  app.post('/api/auth/passkey/options', publicLimiter, async (c) => c.json({ options: await passkeys.authenticationOptions(site(c)) }));

  app.post('/api/auth/passkey/login', loginLimiter, async (c) => {
    const { response } = await body(c, z.object({ response: credentialJson }));
    const where = site(c);
    const r = await auth.loginWith(c, () => passkeys.authenticate(response as unknown as AuthenticationResponseJSON, where), signInFrom(c));
    if (r.ok === false && r.retryIn) return tooMany(c, r.retryIn);
    if (r.ok === false) {
      lights.log('warn', 'admin', 'Failed passkey sign-in', null, actor(c));
      throw new HttpError(401, 'That passkey did not work here. Try again, or sign in with your password.');
    }
    lights.log('info', 'admin', `${r.who.user.username} signed in with passkey "${r.who.passkey}"`, null, actor(c));
    return c.json({ user: r.who.user });
  });

  app.post('/api/auth/logout', (c) => {
    auth.logout(c);
    return c.json({ ok: true });
  });

  app.post('/api/auth/bootstrap', loginLimiter, async (c) => {
    if (db.countUsers() > 0) throw new HttpError(409, 'An admin account already exists');
    if (!isLoopback(c)) throw new HttpError(403, 'Create the first admin from the server itself, or set ADMIN_USERNAME and ADMIN_PASSWORD');
    const { username, password } = await body(
      c,
      z.object({ username: z.string().trim().min(1).max(64), password: newPassword })
    );
    await auth.createUser(username, password);
    lights.log('info', 'admin', `Admin account "${username}" created`, null, actor(c));
    const r = await auth.login(c, username, password, { ip: clientIp(c), lan: true });
    return c.json({ user: r.ok ? r.user : null });
  });

  // ---------------- Admin ----------------

  const admin = new Hono<AuthEnv>();
  admin.use('*', sameOrigin(), auth.require());

  // The whole yard as it is now, LED by LED, for the live view (a picture of the lights, not the editor).
  admin.get('/yard', (c) => {
    if (!yard) return c.json({ error: 'No yard view' }, 404);
    const ip = clientIp(c);
    const release = streams.take(ip, isLoopbackIp(ip));
    if (!release) return c.json({ error: 'Too many open pages from your address' }, 429);
    return streamSSE(c, async (stream) => {
      stream.onAbort(release);
      const stop = yard.watch((e) => void stream.writeSSE(e).catch(() => {}));
      if (!stop) {
        await stream.writeSSE({ event: 'busy', data: '' });
        release();
        return;
      }
      const ping = setInterval(() => void stream.writeSSE({ event: 'ping', data: '' }).catch(() => {}), 25_000);
      await new Promise<void>((resolve) => stream.onAbort(resolve));
      clearInterval(ping);
      stop();
    });
  });

  admin.get('/overview', (c) =>
    c.json({
      devices: lights.devicesWithStatus(),
      scenes: db.listScenes(),
      devicePresets: db.listDevicePresets(),
      settings: readSettings(db),
      state: lights.publicState(),
      controls: lights.controls()
    })
  );

  // Power and brightness, for every light or one device (see LightControls).
  admin.get('/lights', (c) => c.json(lights.controls()));

  const deviceTarget = z.string().min(1).max(64).nullable().default(null);
  const knownDevice = (id: string | null) => {
    if (id && !db.getDevice(id) && !lights.haLights().includes(id)) throw new HttpError(404, 'Unknown device');
  };

  admin.put('/lights/power', async (c) => {
    const { on, deviceId } = await body(c, z.object({ on: z.boolean(), deviceId: deviceTarget }));
    knownDevice(deviceId);
    const result = await lights.setPower(on, deviceId, actor(c));
    // The admin's switch of all the lights holds until the schedule's next time: no waking in the night.
    if (deviceId == null || lights.allOff()) schedule?.handSwitched();
    if (!on && lights.allOff()) {
      // Nothing plays on lights that are off: the game ends and the line empties.
      host?.endGame('the lights were switched off');
      line?.clear('the lights were switched off');
    }
    return c.json({ controls: lights.controls(), result });
  });

  // Home Assistant (see HaSettings). The token goes one way: in, never back out, never logged.
  const entityId = z.string().max(255).refine(isSwitchable, 'Pick a light or a switch');
  const haInput = z.object({
    url: z.string().max(300).transform((v, ctx) => {
      const u = cleanHaUrl(v);
      if (u == null) ctx.addIssue({ code: 'custom', message: 'Use an address such as http://192.168.29.29:8123' });
      return u ?? '';
    }),
    /** Left out: the token kept stays. Null removes it. */
    token: z.string().trim().min(20, 'That is too short for a long-lived access token').max(2000).regex(/^\S+$/, 'A token has no spaces').nullable().optional(),
    plugs: z.record(z.string().max(64), entityId).default({}),
    /** Left out: the lights in use stay (they are added on the Devices page). */
    lights: z.array(entityId).max(64).optional()
  });
  const needHa = () => {
    if (!ha) throw new HttpError(404, 'No Home Assistant here');
    return ha;
  };

  admin.get('/ha', (c) => c.json(needHa().view()));

  /** How each Home Assistant light takes its commands (Settings → Debug shows them on the Devices page). */
  admin.get('/ha/commands', (c) => c.json(needHa().commandStats()));

  admin.put('/ha', async (c) => {
    const h = needHa();
    const input = await body(c, haInput);
    for (const id of Object.keys(input.plugs)) if (!db.getDevice(id)) throw new HttpError(400, 'Unknown device');
    const before = h.settings();
    // A plug is not also a light.
    const plugs = new Set(Object.values(input.plugs));
    h.save({ url: input.url, plugs: input.plugs, lights: (input.lights ?? before.lights).filter((id) => !plugs.has(id)), disabled: before.disabled }, input.token);
    const token = input.token === undefined ? '' : input.token === null ? ', token removed' : ', new token';
    lights.log('info', 'settings', `Home Assistant settings changed${token}`, { before, after: h.settings() }, actor(c));
    if (h.connected()) await h.test();
    bus.emit('devices');
    bus.emit('state');
    return c.json(h.view());
  });

  // The lights to use (see HaSettings.lights): added and removed on the Devices page.
  admin.put('/ha/lights', async (c) => {
    const h = needHa();
    /** disabled: left out, the ones disabled stay so. */
    const { lights: next, disabled } = await body(c, z.object({ lights: z.array(entityId).max(64), disabled: z.array(entityId).max(64).optional() }));
    const before = h.settings();
    const plugs = new Set(Object.values(before.plugs));
    if (next.some((id) => plugs.has(id))) throw new HttpError(400, 'That one is the power plug of a controller');
    h.save({ ...before, lights: next, disabled: disabled ?? before.disabled });
    const after = h.settings();
    const added = next.filter((id) => !before.lights.includes(id));
    const removed = before.lights.filter((id) => !next.includes(id));
    const name = (id: string) => h.entity(id)?.name ?? id;
    const changes = [
      added.length ? `added: ${added.join(', ')}` : '',
      removed.length ? `removed: ${removed.join(', ')}` : '',
      ...after.disabled.filter((id) => !before.disabled.includes(id)).map((id) => `"${name(id)}" disabled`),
      ...before.disabled.filter((id) => !after.disabled.includes(id) && next.includes(id)).map((id) => `"${name(id)}" enabled`)
    ].filter(Boolean);
    if (changes.length) lights.log('info', 'settings', `Home Assistant lights: ${changes.join('; ')}`, null, actor(c));
    const again = before.disabled.filter((id) => !after.disabled.includes(id) && next.includes(id)).map(haId);
    await lights.haEnabledAgain(again);
    bus.emit('devices');
    bus.emit('state');
    return c.json(h.view());
  });

  // How fast the lights in the layout may take colors (see HaFrames).
  admin.put('/ha/rate', async (c) => {
    const h = needHa();
    const input = await body(
      c,
      z.object({ fps: z.number().int().min(HA_FPS.min).max(HA_FPS.max), inflight: z.number().int().min(1).max(HA_INFLIGHT_MAX).optional(), fade: z.boolean().optional(), direct: z.boolean().optional() })
    );
    const before = { fps: h.fps(), inflight: h.inflight(), fade: h.fade(), direct: h.direct() };
    h.setFrames(input);
    const after = { fps: h.fps(), inflight: h.inflight(), fade: h.fade(), direct: h.direct() };
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      lights.log('info', 'settings', `Home Assistant lights in the layout: ${after.fps} colors a second, ${after.inflight} at once, ${after.fade ? 'fading' : 'no fade'}${after.direct ? ', as Zigbee commands' : ''}`, { before, after }, actor(c));
    }
    return c.json(h.view());
  });

  // A speed test: a rainbow on one light, as fast as asked, to see what it can take. One at a time.
  let testing = false;
  admin.post('/ha/speedtest', async (c) => {
    const h = needHa();
    const input = await body(
      c,
      z.object({
        entity: entityId,
        fps: z.number().int().min(1).max(30),
        seconds: z.number().int().min(2).max(30).default(10),
        via: z.enum(['ws', 'rest']).default('ws'),
        inflight: z.number().int().min(1).max(HA_INFLIGHT_MAX).default(1),
        fade: z.boolean().default(true),
        direct: z.boolean().default(false)
      })
    );
    if (!input.entity.startsWith('light.')) throw new HttpError(400, 'Pick a light');
    if (!h.connected()) throw new HttpError(400, 'Home Assistant is not connected');
    if (testing) throw new HttpError(409, 'A speed test is running');
    testing = true;
    try {
      const { entity, ...how } = input;
      const result = await haSpeedTest(h, entity, how);
      lights.log('info', 'settings', `Speed test of ${entity}: ${result.achieved} of ${input.fps} colors a second over ${input.via === 'ws' ? 'the WebSocket' : 'REST'}, ${input.inflight} at once${result.direct ? ', as Zigbee commands' : ''}, ${result.latency.p50} ms each`, result, actor(c));
      return c.json(result);
    } finally {
      testing = false;
    }
  });

  admin.post('/ha/test', async (c) => {
    const h = needHa();
    await h.test();
    bus.emit('devices');
    return c.json(h.view());
  });

  // The schedule that switches every light on and off (see LightSchedule).
  admin.get('/lights/schedule', (c) => {
    if (!schedule) throw new HttpError(404, 'No schedule here');
    return c.json(schedule.get());
  });

  admin.put('/lights/schedule', async (c) => {
    if (!schedule) throw new HttpError(404, 'No schedule here');
    await schedule.save({ ...schedule.get(), ...(await body(c, scheduleInput)) }, actor(c));
    return c.json(schedule.get());
  });

  admin.put('/lights/brightness', async (c) => {
    const { level, deviceId } = await body(c, z.object({ level: z.number().int().min(1).max(100).nullable(), deviceId: deviceTarget }));
    knownDevice(deviceId);
    const result = await lights.setBrightness(level, deviceId, actor(c));
    return c.json({ controls: lights.controls(), result });
  });

  admin.post('/auth/password', async (c) => {
    const { current, next } = await body(c, z.object({ current: z.string().min(1).max(1000), next: newPassword }));
    const me = c.get('user');
    const ok = await auth.confirmPassword(me, current, signInFrom(c));
    if (ok.retryIn) return tooMany(c, ok.retryIn);
    if (!ok.ok) throw new HttpError(400, 'Current password is wrong');
    // Signs out the other sessions, so a stolen cookie stops working too.
    await auth.setPassword(me.id, next, c);
    lights.log('info', 'admin', `${me.username} changed their password`, null, actor(c));
    return c.json({ ok: true });
  });

  // Passkeys of the signed-in admin.
  admin.get('/passkeys', (c) => c.json(passkeys.list(c.get('user').id)));

  // A new passkey needs the password too: a stolen session cookie alone cannot add a way back in.
  admin.post('/passkeys/options', loginLimiter, async (c) => {
    const { password } = await body(c, z.object({ password: z.string().min(1).max(1000) }));
    const me = c.get('user');
    const where = site(c);
    const ok = await auth.confirmPassword(me, password, signInFrom(c));
    if (ok.retryIn) return tooMany(c, ok.retryIn);
    if (!ok.ok) throw new HttpError(400, 'Password is wrong');
    return c.json({ options: await passkeys.registrationOptions(me, where) });
  });

  const passkeyName = z.string().trim().max(60);

  admin.post('/passkeys', async (c) => {
    const { response, name } = await body(c, z.object({ response: credentialJson, name: passkeyName.default('') }));
    const me = c.get('user');
    const key = await passkeys.register(me, response as unknown as RegistrationResponseJSON, site(c), name);
    lights.log('info', 'admin', `${me.username} added passkey "${key.name}"`, null, actor(c));
    return c.json(key);
  });

  admin.patch('/passkeys/:id', async (c) => {
    const { name } = await body(c, z.object({ name: passkeyName.min(1) }));
    if (!passkeys.rename(c.get('user').id, c.req.param('id'), name)) throw new HttpError(404, 'No such passkey');
    return c.json(passkeys.list(c.get('user').id));
  });

  admin.delete('/passkeys/:id', (c) => {
    const me = c.get('user');
    const key = passkeys.list(me.id).find((p) => p.id === c.req.param('id'));
    if (!key || !passkeys.remove(me.id, key.id)) throw new HttpError(404, 'No such passkey');
    lights.log('info', 'admin', `${me.username} removed passkey "${key.name}"`, null, actor(c));
    return c.json(passkeys.list(me.id));
  });

  // Devices
  const deviceChanged = () => {
    bus.emit('devices');
    bus.emit('state');
    void lights.refreshStatus();
  };

  admin.post('/devices', async (c) => {
    const input = await body(c, deviceInput);
    let name = input.name;
    if (!name) {
      const r = await wled.info(input, 1500);
      name = (r.ok && r.data.name) || input.host;
    }
    const device = { id: crypto.randomUUID(), ...input, name };
    db.saveDevice(device);
    lights.log('info', 'config', `Device "${device.name}" added (${device.host}:${device.port})`, null, actor(c));
    const [presets] = device.enabled ? await lights.importPresetsForNew([device.id], actor(c)) : [];
    deviceChanged();
    return c.json({ ...device, presets: presets ?? null }, 201);
  });

  admin.post('/devices/bulk', async (c) => {
    const { devices } = await body(c, z.object({ devices: z.array(deviceInput).max(256) }));
    const existing = new Set(db.listDevices().map((d) => `${d.host}:${d.port}`));
    const added = [];
    for (const d of devices) {
      if (existing.has(`${d.host}:${d.port}`)) continue;
      const device = { id: crypto.randomUUID(), ...d, name: d.name || d.host };
      db.saveDevice(device);
      existing.add(`${d.host}:${d.port}`);
      added.push(device);
    }
    lights.log('info', 'config', `${added.length} discovered device(s) added`, null, actor(c));
    const presets = await lights.importPresetsForNew(added.filter((d) => d.enabled).map((d) => d.id), actor(c));
    deviceChanged();
    return c.json({ added, presets });
  });

  admin.put('/devices/:id', async (c) => {
    const prev = db.getDevice(c.req.param('id'));
    if (!prev) throw new HttpError(404, 'Unknown device');
    const input = await body(c, deviceInput);
    const device = { ...prev, ...input, name: input.name || input.host };
    db.saveDevice(device);
    lights.log('info', 'config', `Device "${device.name}" updated`, null, actor(c));
    // A new address can be a different controller with different presets.
    const moved = prev.host !== device.host || prev.port !== device.port;
    const enabledNow = device.enabled && !prev.enabled;
    if (device.enabled && (moved || enabledNow)) await lights.importPresetsForNew([device.id], actor(c));
    deviceChanged();
    return c.json(device);
  });

  admin.delete('/devices/:id', (c) => {
    const prev = db.getDevice(c.req.param('id'));
    if (!prev || !db.deleteDevice(prev.id)) throw new HttpError(404, 'Unknown device');
    lights.log('info', 'config', `Device "${prev.name}" removed`, null, actor(c));
    deviceChanged();
    return c.json({ ok: true });
  });

  admin.post('/probe', async (c) => {
    const { host, port } = await body(c, deviceInput.pick({ host: true, port: true }));
    const r = await wled.info({ host, port }, 2500);
    return c.json(r.ok ? { ok: true, info: r.data } : { ok: false, error: r.error });
  });

  admin.post('/devices/:id/apply', async (c) => {
    const device = db.getDevice(c.req.param('id'));
    if (!device) throw new HttpError(404, 'Unknown device');
    const { presetId } = await body(c, z.object({ presetId: z.number().int().min(1).max(250) }));
    const r = await wled.applyPreset(device, presetId);
    if (!r.ok) throw new HttpError(502, `${device.name}: ${r.error}`);
    return c.json({ ok: true });
  });

  // A device's own WLED settings, so they can be changed here instead of in WLED's app.
  const needDevice = (c: Context) => {
    const device = db.getDevice(c.req.param('id')!);
    if (!device) throw new HttpError(404, 'Unknown device');
    return device;
  };
  const wledError = (name: string, r: { status: number; error: string }) =>
    new HttpError(502, r.status === 401 ? `${name} has a settings PIN. Remove it in WLED's security settings to change its settings here.` : `${name}: ${r.error}`);

  admin.get('/devices/:id/wled', async (c) => {
    const device = needDevice(c);
    const [config, script, info] = await Promise.all([wled.config(device), wled.ledSettingsScript(device), wled.rawInfo(device)]);
    if (!config.ok) throw wledError(device.name, config);
    const parsed = script.ok ? parseSettingsScript(script.data) : { ledTypes: null, gpio: null };
    const out: WledSettings = { config: config.data, ledTypes: parsed.ledTypes ?? DEFAULT_LED_TYPES, gpio: parsed.gpio, info: info.ok ? pickStatus(info.data) : null };
    return c.json(out);
  });

  admin.put('/devices/:id/wled', async (c) => {
    const device = needDevice(c);
    const { patch } = await body(c, z.object({ patch: z.record(z.string(), z.unknown()) }));
    const blocked = protectedSection(patch);
    if (blocked) throw new HttpError(400, `Settings for ${blocked} are not changed from here: a mistake there loses the device. Use WLED's own page on the network.`);
    if (!Object.keys(patch).length) throw new HttpError(400, 'Nothing to change');
    const r = await wled.saveConfig(device, patch);
    if (!r.ok) throw wledError(device.name, r);
    // WLED sets up changed LED outputs on its next loop, after it has answered.
    await new Promise((done) => setTimeout(done, WLED_SETTLE_MS));
    const after = await wled.config(device);
    lights.log('info', 'config', `WLED settings of "${device.name}" changed (${Object.keys(patch).join(', ')})`, patch, actor(c));
    await lights.settingsChanged(device.id);
    bus.emit('devices');
    return c.json({ config: after.ok ? after.data : null, unapplied: after.ok ? unappliedPaths(patch, after.data) : [] });
  });

  admin.post('/devices/:id/wled/restart', async (c) => {
    const device = needDevice(c);
    const r = await wled.restart(device);
    if (!r.ok) throw wledError(device.name, r);
    lights.log('info', 'config', `"${device.name}" restarted`, null, actor(c));
    return c.json({ ok: true });
  });

  admin.post('/devices/:id/presets/sync', async (c) => {
    const r = await lights.importPresets(c.req.param('id'));
    if (!r.ok) throw new HttpError(502, `Could not read presets: ${r.error}`);
    lights.log('info', 'import', `Imported ${r.count} preset(s) from device`, r, actor(c));
    return c.json(r);
  });

  admin.post('/devices/presets/sync', async (c) => {
    const devices = db.listDevices().filter((d) => d.enabled);
    const results = await Promise.all(devices.map((d) => lights.importPresets(d.id)));
    const ok = results.filter((r) => r.ok);
    const total = ok.reduce((n, r) => n + (r.ok ? r.count : 0), 0);
    lights.log(
      ok.length === results.length ? 'info' : 'warn',
      'import',
      `Imported ${total} preset(s) from ${ok.length}/${results.length} device(s)`,
      results,
      actor(c)
    );
    return c.json({ results });
  });

  admin.post('/discover', async (c) => {
    const { subnets } = await body(c, z.object({ subnets: z.array(z.string().refine(isValidCidr, 'Invalid subnet')).optional() }));
    const effective = subnets?.length ? subnets : config.discoverySubnets.length ? config.discoverySubnets : readSettings(db).discoverySubnets;
    lights.log('info', 'discovery', `Discovery started${effective.length ? ` on ${effective.join(', ')}` : ' on local networks'}`, null, actor(c));
    const found = await discover({ subnets: effective, hosts: config.discoveryHosts, ports: config.discoveryPorts, log: config.discoveryDebug ? (m) => console.log(`[discovery] ${m}`) : undefined });
    const existing = new Set(db.listDevices().map((d) => `${d.host}:${d.port}`));
    const out: DiscoveredDevice[] = found.map((f) => ({ ...f, alreadyAdded: existing.has(`${f.host}:${f.port}`) }));
    lights.log('info', 'discovery', `Discovery found ${out.length} device(s)`, null, actor(c));
    return c.json({ found: out, subnets: effective });
  });

  // Scenes
  const sceneChanged = () => bus.emit('state');

  admin.post('/scenes', async (c) => {
    const input = await body(c, sceneInput);
    if (input.sequenceId && !db.getSequence(input.sequenceId)) throw new HttpError(400, 'That sequence does not exist');
    const id = crypto.randomUUID();
    const { playlist, ...rest } = input;
    const scene: Scene = { id, sortOrder: db.nextSortOrder(), ...rest, ...(playlist ? { playlist: cleanPlaylist(playlist, id, db.listScenes().map((s) => s.id)) } : {}) };
    db.saveScene(scene);
    const fx = Object.keys(scene.effects ?? {}).length;
    lights.log('info', 'config', `Scene "${scene.name}" created${fx ? ` with effects on ${fx} object(s)` : ''}`, null, actor(c));
    sceneChanged();
    return c.json(db.getScene(scene.id), 201);
  });

  admin.put('/scenes/order', async (c) => {
    const { ids } = await body(c, z.object({ ids: z.array(z.string()) }));
    db.reorderScenes(ids);
    sceneChanged();
    return c.json({ ok: true });
  });

  admin.put('/scenes/:id', async (c) => {
    const prev = db.getScene(c.req.param('id'));
    if (!prev) throw new HttpError(404, 'Unknown scene');
    const input = await body(c, sceneInput);
    if (input.sequenceId && !db.getSequence(input.sequenceId)) throw new HttpError(400, 'That sequence does not exist');
    const playlist = input.playlist === undefined ? prev.playlist : input.playlist && cleanPlaylist(input.playlist, prev.id, db.listScenes().map((s) => s.id));
    db.saveScene({ ...prev, ...input, effects: input.effects ?? prev.effects, sequenceId: input.sequenceId === undefined ? prev.sequenceId : input.sequenceId, playlist: playlist ?? null });
    lights.log('info', 'config', `Scene "${input.name}" updated`, null, actor(c));
    // A scene that is playing now shows its new effects at once.
    lights.sceneChanged(prev.id);
    sceneChanged();
    return c.json(db.getScene(prev.id));
  });

  admin.delete('/scenes/:id', (c) => {
    const prev = db.getScene(c.req.param('id'));
    if (!prev || !db.deleteScene(prev.id)) throw new HttpError(404, 'Unknown scene');
    const s = readSettings(db);
    if (s.defaultSceneId === prev.id) writeSettings(db, { ...s, defaultSceneId: null });
    lights.sceneDeleted(prev.id);
    lights.log('info', 'config', `Scene "${prev.name}" deleted`, null, actor(c));
    sceneChanged();
    return c.json({ ok: true });
  });

  admin.get('/scenes/export', (c) => {
    const file: BackupFile & { devices: { id: string; name: string; host: string; port: number }[] } = {
      version: 2,
      exportedAt: new Date().toISOString(),
      devices: db.listDevices().map(({ id, name, host, port }) => ({ id, name, host, port })),
      publicPresets: db.listScenes()
    };
    c.header('Content-Disposition', `attachment; filename="wled-scenes-${new Date().toISOString().slice(0, 10)}.json"`);
    return c.json(file);
  });

  admin.post('/scenes/import', async (c) => {
    const file = await body(c, backupInput);
    // A v2 backup lists devices. Match them to local devices by host:port, so a backup
    // restores on a new install where the device ids differ.
    const local = db.listDevices();
    const byId = new Set(local.map((d) => d.id));
    const byAddr = new Map(local.map((d) => [`${d.host}:${d.port}`, d.id]));
    const remap = new Map<string, string>();
    for (const d of file.devices ?? []) {
      if (byId.has(d.id)) remap.set(d.id, d.id);
      else {
        const match = byAddr.get(`${normalizeHost(d.host)}:${d.port ?? 80}`);
        if (match) remap.set(d.id, match);
      }
    }
    const scenes: Scene[] = file.publicPresets.map((p, i) => {
      const devicePresets: Record<string, number> = {};
      for (const [devId, presetId] of Object.entries(p.devicePresets)) {
        const target = remap.get(devId) ?? (byId.has(devId) ? devId : null);
        if (target && Number.isInteger(presetId) && presetId >= 1) devicePresets[target] = presetId;
      }
      // Effects on a whole device follow the device too; ones for a device that is not here go.
      const effects = p.effects
        ? Object.fromEntries(
            Object.entries(p.effects).flatMap(([key, fx]) => {
              const devId = keyDevice(key);
              if (devId == null) return [[key, fx]];
              const target = remap.get(devId) ?? (byId.has(devId) ? devId : null);
              return target ? [[deviceKey(target), fx]] : [];
            })
          )
        : null;
      const sequenceId = p.sequenceId && db.getSequence(p.sequenceId) ? p.sequenceId : null;
      const playlist = p.playlist ? cleanPlaylist(p.playlist, p.id, file.publicPresets.map((q) => q.id)) : null;
      return { id: p.id, name: p.name, sortOrder: p.sortOrder ?? i, devicePresets, ...(effects ? { effects } : {}), ...(sequenceId ? { sequenceId } : {}), ...(playlist ? { playlist } : {}) };
    });
    db.replaceScenes(scenes);
    lights.log('info', 'config', `Restored ${scenes.length} scene(s) from backup`, null, actor(c));
    sceneChanged();
    return c.json({ restored: scenes.length });
  });

  // Sequences
  admin.get('/sequences', (c) => c.json({ sequences: db.listSequences().map(summarize) }));

  admin.get('/sequences/:id', (c) => {
    const seq = db.getSequence(c.req.param('id'));
    if (!seq) throw new HttpError(404, 'Unknown sequence');
    return c.json(seq);
  });

  admin.post('/sequences', async (c) => {
    const input = await body(c, sequenceInput);
    const seq = db.saveSequence({ ...input, id: crypto.randomUUID() });
    lights.log('info', 'config', `Sequence "${seq.name}" created`, null, actor(c));
    return c.json(seq, 201);
  });

  // A sequence opened from a file: checked as one being saved, but not saved.
  admin.post('/sequences/check', async (c) => c.json({ ...(await body(c, sequenceInput)), id: '' }));

  admin.put('/sequences/:id', async (c) => {
    const prev = db.getSequence(c.req.param('id'));
    if (!prev) throw new HttpError(404, 'Unknown sequence');
    const input = await body(c, sequenceInput);
    const seq = db.saveSequence({ ...input, id: prev.id });
    lights.log('info', 'config', `Sequence "${seq.name}" saved`, null, actor(c));
    // A scene that plays it now plays the new version.
    lights.sequenceChanged(prev.id);
    bus.emit('state');
    return c.json(seq);
  });

  admin.delete('/sequences/:id', (c) => {
    const prev = db.getSequence(c.req.param('id'));
    if (!prev || !db.deleteSequence(prev.id)) throw new HttpError(404, 'Unknown sequence');
    lights.sequenceChanged(prev.id);
    lights.log('info', 'config', `Sequence "${prev.name}" deleted`, null, actor(c));
    bus.emit('state');
    return c.json({ ok: true });
  });

  // The sequence editor's preview on the real lights. inFront: sent only by an editor whose
  // window is in front. Before v2.6.0 the editor also sent from a background tab, about once a
  // minute, and each request took every light for 8 seconds; such a page, still open, is refused.
  const seqPreviewSchema = z.object({ active: z.literal(true), inFront: z.literal(true, { error: 'Reload this page to show the sequence on the lights' }), sequence: sequenceInput.extend({ id: z.string().max(64).default('') }), time: z.number().min(0), playing: z.boolean() });
  admin.post('/sequence-preview', async (c) => {
    const req = await body(c, seqPreviewSchema);
    return c.json({ devices: preview?.showSequence(req as SequencePreviewRequest, readLayout(db)) ?? [] });
  });
  admin.delete('/sequence-preview', (c) => {
    preview?.stop();
    return c.json({ ok: true });
  });

  // Audio for sequences
  admin.get('/audio', (c) => c.json({ files: db.listAudio() }));

  admin.post('/audio', async (c) => {
    const type = (c.req.header('content-type') ?? '').split(';')[0].trim();
    if (!/^audio\/[\w.+-]+$/.test(type)) throw new HttpError(400, 'Use an audio file (MP3, WAV, OGG, M4A or FLAC)');
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    if (!bytes.length) throw new HttpError(400, 'The file is empty');
    if (bytes.length > 80 * 1024 * 1024) throw new HttpError(400, 'The file is larger than 80 MB');
    let name = 'Audio';
    try {
      name = decodeURIComponent(c.req.header('x-file-name') ?? 'Audio').slice(0, 200) || 'Audio';
    } catch {}
    const file = { id: crypto.randomUUID(), name, type, size: bytes.length };
    writeAudio(config.databasePath, file.id, bytes);
    db.addAudio(file);
    lights.log('info', 'config', `Audio "${name}" uploaded (${Math.round(bytes.length / 1024)} KB)`, null, actor(c));
    return c.json(db.getAudio(file.id), 201);
  });

  admin.get('/audio/:id', (c) => {
    const file = db.getAudio(c.req.param('id'));
    const bytes = file ? readAudio(config.databasePath, file.id) : null;
    if (!file || !bytes) throw new HttpError(404, 'Unknown audio file');
    return new Response(new Uint8Array(bytes), { headers: { 'Content-Type': file.type, 'Cache-Control': 'private, max-age=31536000, immutable' } });
  });

  admin.delete('/audio/:id', (c) => {
    const file = db.getAudio(c.req.param('id'));
    if (!file) throw new HttpError(404, 'Unknown audio file');
    db.deleteAudio(file.id);
    removeAudio(config.databasePath, file.id);
    return c.json({ ok: true });
  });

  // Settings
  admin.put('/settings', async (c) => {
    const input = await body(c, settingsInput);
    if (input.defaultSceneId && !db.getScene(input.defaultSceneId)) throw new HttpError(400, 'Default scene does not exist');
    const prev = readSettings(db);
    writeSettings(db, { ...prev, ...input });
    // Switched on: the Home Assistant lights' command times count from now.
    if (input.debugHa && !prev.debugHa) ha?.resetCommandStats();
    const changes = (Object.keys(input) as (keyof typeof input)[]).filter((k) => JSON.stringify(input[k]) !== JSON.stringify(prev[k]));
    if (changes.length) lights.log('info', 'settings', `Settings changed: ${changes.join(', ')}`, { before: prev, after: input }, actor(c));
    lights.onSettingsChanged();
    return c.json(readSettings(db));
  });

  admin.post('/revert/cancel', (c) => {
    lights.cancelRevert();
    bus.emit('state');
    return c.json({ ok: true });
  });

  // Yard layout
  // active: sent only by an editor window that is in front (an older page that does not send it is ignored).
  // play: show the objects' effects (the editor's working copy) instead of the editor's colors.
  // area: the Games page shows the game area instead.
  const checkAxis = z.enum(['x', 'y', 'z']);
  const previewSchema = z.object({
    active: z.literal(true),
    layout: layoutShape,
    selected: z.string().nullable(),
    corner: z.number().int().nullable(),
    segment: z.number().int().nullable().optional(),
    play: z.boolean().optional(),
    area: gameAreaInput.nullable().optional(),
    probe: z
      .object({ point: z.number().int().min(0).max(10_000), offset: z.number().int().min(-2000).max(4000) })
      .nullable()
      .optional(),
    check: z
      .discriminatedUnion('kind', [
        z.object({ kind: z.literal('slice'), axis: checkAxis, at: z.number().min(-100_000).max(100_000).nullable() }),
        z.object({ kind: z.literal('bands'), axis: checkAxis, step: z.number().min(1).max(100_000) }),
        z.object({ kind: z.literal('picture'), id: z.string().min(1).max(64), split: z.enum(['x', 'y', 'z', 'all']).optional() }),
        z.object({ kind: z.literal('chase'), id: z.string().min(1).max(64) }),
        z.object({ kind: z.literal('strings'), id: z.string().min(1).max(64).nullable() })
      ])
      .nullable()
      .optional(),
    photo: z
      .object({ deviceId: z.string().min(1).max(64), from: z.number().int().min(0).max(10_000), to: z.number().int().min(0).max(10_000), rgb: rgbInput, start: rgbInput, code: z.number().int().min(0).max(12).nullable().optional() })
      .refine((p) => Math.abs(p.to - p.from) < MAX_FIXTURE_PIXELS, `At most ${MAX_FIXTURE_PIXELS} LEDs`)
      .nullable()
      .optional()
  });
  admin.post('/layout/preview', async (c) => {
    const req = await body(c, previewSchema);
    return c.json({ devices: preview?.show(req) ?? [] });
  });
  admin.delete('/layout/preview', (c) => {
    preview?.stop();
    return c.json({ ok: true });
  });

  // The part of the yard that games use (Games page).
  admin.get('/games/area', (c) => c.json({ area: readGameArea(db) }));
  admin.put('/games/area', async (c) => {
    const input = await body(c, gameAreaInput);
    // Keep only what leaves something out, for objects that are in the layout and games in the catalog.
    const area = cleanGameArea(input, readLayout(db).fixtures.map((f) => f.id), GAME_IDS);
    writeGameArea(db, area);
    host?.setGameArea(area);
    const own = Object.keys(area?.games ?? {}).length;
    lights.log(
      'info',
      'config',
      area
        ? `Game area saved: ${area.exclude?.length ?? 0} object(s) left out, ${Object.keys(area.skip ?? {}).length + Object.keys(area.trim ?? {}).length} line(s) shortened${own ? `, ${own} game(s) with their own objects` : ''}`
        : 'Game area saved: games use the whole yard',
      null,
      actor(c)
    );
    return c.json({ area });
  });

  // Games hidden from visitors (Games page). Admins still see them, to try them.
  admin.get('/games/hidden', (c) => c.json({ hidden: readHiddenGames(db) }));
  admin.put('/games/hidden', async (c) => {
    const input = await body(c, z.object({ hidden: z.array(z.string().min(1).max(64)).max(64) }));
    const hidden = GAME_IDS.filter((id) => input.hidden.includes(id));
    writeHiddenGames(db, hidden);
    host?.setHiddenGames(hidden);
    bus.emit('state');
    const names = GAME_CATALOG.filter((g) => hidden.includes(g.id)).map((g) => g.name);
    lights.log('info', 'config', names.length ? `Games hidden from visitors: ${names.join(', ')}` : 'Every game shows on the play page', null, actor(c));
    return c.json({ hidden });
  });

  // Debug mode: send the games to the real lights too.
  // A line that should not be on a scoreboard (rude initials, a test game).
  admin.delete('/play/scores/:id', (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id) || !host?.removeScore(id)) throw new HttpError(404, 'Unknown score');
    lights.log('info', 'game', `High score ${id} removed`, null, actor(c));
    return c.json({ ok: true });
  });

  // The line for the lights: its settings, who waits, and taking turns away.
  const lineSettings = z.object({
    enabled: z.boolean(),
    quickSeconds: z.number().int().min(3).max(600).default(DEFAULT_LINE.quickSeconds),
    showSeconds: z.number().int().min(10).max(3600),
    turnMinutes: z.number().min(1).max(60),
    offerSeconds: z.number().int().min(10).max(300)
  });
  const needLine = () => {
    if (!line) throw new HttpError(409, 'Games are not running on this server');
    return line;
  };
  admin.get('/line', (c) => c.json(needLine().adminView()));
  admin.put('/line', async (c) => {
    const input = await body(c, lineSettings);
    needLine().configure(input);
    writeLineSettings(db, input);
    lights.log('info', 'config', input.enabled ? `Line on: scenes ${input.quickSeconds} s (${input.showSeconds} s when others wait), game turns ${input.turnMinutes} min when someone waits` : 'Line off: the last choice wins', null, actor(c));
    return c.json(line!.adminView());
  });
  admin.delete('/line/:id', (c) => {
    if (!needLine().remove(Number(c.req.param('id')))) throw new HttpError(404, 'Not in the line');
    lights.log('info', 'game', 'Someone was taken out of the line', null, actor(c));
    return c.json(line!.adminView());
  });
  admin.post('/line/pass', (c) => {
    needLine().pass('an admin ended the turn');
    lights.log('info', 'game', 'Turn ended by an admin', null, actor(c));
    return c.json(line!.adminView());
  });

  admin.get('/play/output', (c) => c.json(host?.output?.info() ?? null));
  admin.put('/play/output', async (c) => {
    const input = await body(c, z.object({ enabled: z.boolean().optional(), brightness: z.number().min(0.05).max(1).optional() }));
    const out = host?.output;
    if (!out) throw new HttpError(409, 'Games are not running on this server');
    if (input.brightness != null) out.brightness = input.brightness;
    if (input.enabled != null && input.enabled !== out.enabled) {
      out.enabled = input.enabled;
      lights.log('info', 'game', out.enabled ? `Debug mode on: games also show on the real lights (${out.targets().join(', ') || 'no device chosen in Layout'})` : 'Debug mode off: games show in the simulator only', null, actor(c));
    }
    host!.refreshStatus();
    return c.json(out.info());
  });

  // A layout file: export everything a layout needs, and import one in place of the layout.
  admin.get('/layout/export', (c) => {
    const layout = readLayout(db);
    const used = new Set(layout.fixtures.map((f) => f.deviceId).filter(Boolean));
    const pic = (kind: 'background' | 'aerial') => {
      const p = readBackground(db, config.databasePath, kind);
      return p ? { type: p.type, data: p.bytes.toString('base64') } : null;
    };
    c.header('Content-Disposition', `attachment; filename="wled-layout-${new Date().toISOString().slice(0, 10)}.json"`);
    return c.json({
      kind: 'wled-layout',
      version: 1,
      exportedAt: new Date().toISOString(),
      layout,
      devices: db
        .listDevices()
        .filter((d) => used.has(d.id))
        .map(({ id, name, host, port }) => ({ id, name, host, port })),
      gameArea: readGameArea(db),
      pictures: { background: layout.background ? pic('background') : null, aerial: layout.aerial ? pic('aerial') : null }
    });
  });

  admin.post('/layout/import', async (c) => {
    const file = await body(c, layoutFileInput);
    // Objects keep their device when it is here: the same id, else the same address, else the same name.
    const local = db.listDevices();
    const byId = new Set(local.map((d) => d.id));
    const byAddr = new Map(local.map((d) => [`${d.host}:${d.port}`, d.id]));
    const byName = new Map(local.map((d) => [d.name.trim().toLowerCase(), d.id]));
    const remap = new Map<string, string>();
    for (const d of file.devices ?? []) {
      const match = byId.has(d.id) ? d.id : (byAddr.get(`${normalizeHost(d.host)}:${d.port ?? 80}`) ?? (d.name ? byName.get(d.name.trim().toLowerCase()) : undefined));
      if (match) remap.set(d.id, match);
    }
    let unmatched = 0;
    const fixtures = file.layout.fixtures.map((f) => {
      if (!f.deviceId) return f;
      const deviceId = remap.get(f.deviceId) ?? (byId.has(f.deviceId) ? f.deviceId : null);
      if (!deviceId) unmatched++;
      return { ...f, deviceId };
    });
    // The pictures in the file replace the ones here; without one, the layout has none.
    const decode = (p: z.infer<typeof pictureInput>) => {
      const bytes = Buffer.from(p.data, 'base64');
      if (!bytes.length) throw new HttpError(400, 'A picture in the file is empty');
      if (bytes.length > 12 * 1024 * 1024) throw new HttpError(400, 'A picture in the file is larger than 12 MB');
      return bytes;
    };
    const bg = file.pictures?.background ? decode(file.pictures.background) : null;
    const aerialPic = file.layout.aerial && file.pictures?.aerial ? decode(file.pictures.aerial) : null;
    const now = Date.now();
    const checked = layoutSchema.safeParse({
      ...file.layout,
      fixtures,
      background: bg ? `/api/layout/background?v=${now}` : null,
      aerial: file.layout.aerial && aerialPic ? { ...file.layout.aerial, url: `/api/admin/layout/aerial?v=${now}` } : null
    });
    if (!checked.success) throw new HttpError(400, errorMessage(checked.error));
    const layout = checked.data;
    if (bg) saveBackground(db, config.databasePath, bg, file.pictures!.background!.type);
    else deleteBackground(config.databasePath);
    if (aerialPic) saveBackground(db, config.databasePath, aerialPic, file.pictures!.aerial!.type, 'aerial');
    else deleteBackground(config.databasePath, 'aerial');
    writeLayout(db, layout);
    host?.setLayout(layout);
    // The game area goes with the layout (only for its objects); a file without one leaves the game area as it is.
    if (file.gameArea !== undefined) {
      const area = cleanGameArea(file.gameArea, layout.fixtures.map((f) => f.id), GAME_IDS);
      writeGameArea(db, area);
      host?.setGameArea(area);
    }
    const pixels = layout.fixtures.reduce((n, f) => n + f.pixels, 0);
    lights.log('info', 'config', `Yard layout imported: ${layout.fixtures.length} object(s), ${pixels} LED(s)${unmatched ? `; ${unmatched} object(s) without their device` : ''}`, null, actor(c));
    return c.json({ layout, unmatched });
  });

  admin.put('/layout', async (c) => {
    const layout = await body(c, layoutSchema);
    writeLayout(db, layout);
    host?.setLayout(layout);
    const pixels = layout.fixtures.reduce((n, f) => n + f.pixels, 0);
    lights.log('info', 'config', `Yard layout saved: ${layout.fixtures.length} object(s), ${pixels} LED(s)`, null, actor(c));
    return c.json(layout);
  });

  /** A picture from the request body: PNG, JPEG, WebP or GIF, up to 12 MB. */
  const pictureBody = async (c: Context) => {
    const type = c.req.header('content-type') ?? '';
    if (!/^image\/(png|jpeg|webp|gif)$/.test(type)) throw new HttpError(400, 'Use a PNG, JPEG, WebP or GIF picture');
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    if (bytes.length > 12 * 1024 * 1024) throw new HttpError(400, 'The picture is larger than 12 MB');
    return { type, bytes };
  };

  admin.post('/layout/background', async (c) => {
    const { type, bytes } = await pictureBody(c);
    saveBackground(db, config.databasePath, bytes, type);
    const layout = { ...readLayout(db), background: `/api/layout/background?v=${Date.now()}` };
    writeLayout(db, layout);
    host?.setLayout(layout);
    return c.json(layout);
  });

  admin.delete('/layout/background', (c) => {
    deleteBackground(config.databasePath);
    const layout = { ...readLayout(db), background: null };
    writeLayout(db, layout);
    host?.setLayout(layout);
    return c.json(layout);
  });

  // The yard from above. Only for signed-in users, as it shows where the house is. The editor
  // places it (Layout.aerial) and saves the layout.
  admin.get('/layout/aerial', (c) => {
    const pic = readBackground(db, config.databasePath, 'aerial');
    if (!pic) return c.json({ error: 'No picture from above' }, 404);
    return new Response(new Uint8Array(pic.bytes), { headers: { 'Content-Type': pic.type, 'Cache-Control': 'private, no-cache' } });
  });

  admin.post('/layout/aerial', async (c) => {
    const { type, bytes } = await pictureBody(c);
    saveBackground(db, config.databasePath, bytes, type, 'aerial');
    return c.json({ url: `/api/admin/layout/aerial?v=${Date.now()}` });
  });

  admin.delete('/layout/aerial', (c) => {
    deleteBackground(config.databasePath, 'aerial');
    const layout = { ...readLayout(db), aerial: null };
    writeLayout(db, layout);
    host?.setLayout(layout);
    return c.json(layout);
  });

  // Logs
  admin.get('/logs', (c) => {
    const limit = Math.min(1000, Math.max(1, Number(c.req.query('limit')) || 200));
    const action = c.req.query('action') || null;
    return c.json({ logs: db.listLogs(limit, action) });
  });

  admin.get('/events', (c) =>
    streamSSE(c, async (stream) => {
      const onLog = () => void stream.writeSSE({ event: 'log', data: '' });
      const onDevices = () => void stream.writeSSE({ event: 'devices', data: '' });
      const onState = () => void stream.writeSSE({ event: 'state', data: '' });
      bus.on('log', onLog);
      bus.on('devices', onDevices);
      bus.on('state', onState);
      const ping = setInterval(() => void stream.writeSSE({ event: 'ping', data: '' }), 25_000);
      await new Promise<void>((resolve) => stream.onAbort(resolve));
      clearInterval(ping);
      bus.off('log', onLog);
      bus.off('devices', onDevices);
      bus.off('state', onState);
    })
  );

  app.route('/api/admin', admin);
  app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404));

  // ---------------- Web client ----------------

  if (fs.existsSync(config.webDir)) {
    app.use(
      '/assets/*',
      serveStatic({
        root: config.webDir,
        onFound: (_p, c) => {
          c.header('Cache-Control', 'public, max-age=31536000, immutable');
        }
      })
    );
    app.use('*', serveStatic({ root: config.webDir }));
    const indexHtml = fs.readFileSync(path.join(config.webDir, 'index.html'), 'utf8');
    app.get('*', (c) => {
      c.header('Cache-Control', 'no-cache');
      return c.html(indexHtml);
    });
  }

  return app;
}
