import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Hono, type Context } from 'hono';
import { secureHeaders } from 'hono/secure-headers';
import { streamSSE } from 'hono/streaming';
import { getConnInfo } from '@hono/node-server/conninfo';
import { serveStatic } from '@hono/node-server/serve-static';
import { z } from 'zod';
import type { BackupFile, DiscoveredDevice, Scene, SessionInfo } from '../../shared/types.ts';
import { createAuth, sameOrigin, type AuthEnv } from './auth.ts';
import type { AppConfig } from './config.ts';
import type { Db } from './db.ts';
import { discoverWled } from './discovery.ts';
import type { Bus } from './events.ts';
import type { Lights } from './lights.ts';
import { isValidCidr } from './net.ts';
import { rateLimit } from './rateLimit.ts';
import { readSettings, writeSettings } from './settings.ts';
import type { GameHost } from './game/host.ts';
import type { LayoutPreview, SequencePreviewRequest } from './layoutPreview.ts';
import { deleteBackground, effectsSchema, layoutSchema, layoutShape, readBackground, readLayout, saveBackground, writeLayout } from './layoutStore.ts';
import { normalizeHost, wled } from './wled.ts';
import { readAudio, removeAudio, sequenceInput, writeAudio } from './sequenceStore.ts';
import { summarize, type Sequence } from '../../shared/sequence.ts';

export interface AppDeps {
  config: AppConfig;
  db: Db;
  bus: Bus;
  lights: Lights;
  discover?: typeof discoverWled;
  host?: GameHost;
  preview?: LayoutPreview;
}

const deviceInput = z.object({
  name: z.string().trim().max(100).default(''),
  host: z.string().trim().min(1, 'Host is required').max(255).transform(normalizeHost),
  port: z.coerce.number().int().min(1).max(65535).default(80),
  enabled: z.boolean().default(true)
});

const sceneInput = z.object({
  name: z.string().trim().min(1, 'Name is required').max(100),
  devicePresets: z.record(z.string(), z.coerce.number().int().min(1).max(250)).default({}),
  /** Left out: an update keeps the scene's effects. An empty object removes them. */
  effects: effectsSchema.optional(),
  /** Left out: an update keeps the scene's sequence. Null removes it. */
  sequenceId: z.string().max(64).nullable().optional()
});

const settingsInput = z.object({
  siteTitle: z.string().trim().min(1).max(80),
  siteSubtitle: z.string().trim().max(200),
  showColors: z.boolean(),
  defaultSceneId: z.string().nullable(),
  revertMinutes: z.coerce.number().int().min(0).max(24 * 60),
  discoverySubnets: z.array(z.string().trim().refine(isValidCidr, 'Use CIDR form, for example 192.168.1.0/24')).max(16)
});

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
      sequenceId: z.string().max(64).nullable().optional().catch(undefined)
    })
  )
});

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

class HttpError extends Error {
  status: 400 | 401 | 403 | 404 | 409 | 502;
  constructor(status: HttpError['status'], message: string) {
    super(message);
    this.status = status;
  }
}

export function createApp({ config, db, bus, lights, discover = discoverWled, host, preview }: AppDeps) {
  const app = new Hono();
  const auth = createAuth(db, { secureCookie: config.secureCookie });

  const clientIp = (c: Context): string => {
    if (config.trustProxy) {
      const fwd = c.req.header('x-forwarded-for')?.split(',')[0]?.trim();
      if (fwd) return fwd;
    }
    try {
      return getConnInfo(c).remote.address ?? 'unknown';
    } catch {
      return 'unknown';
    }
  };
  const actor = (c: Context) => ({ ip: clientIp(c), userAgent: c.req.header('user-agent') ?? null });
  const isLoopback = (c: Context) => {
    const ip = clientIp(c);
    return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  };

  app.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    console.error(err);
    return c.json({ error: 'Internal error' }, 500);
  });

  app.use(
    '*',
    secureHeaders({
      contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
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
  app.use('/api/*', async (c, next) => {
    await next();
    if (!c.res.headers.has('Cache-Control')) c.header('Cache-Control', 'no-store');
  });

  // No limits for requests from this computer (localhost): that is you, testing.
  const publicLimiter = rateLimit({ windowMs: 60_000, max: 120, clientIp, skip: isLoopback });
  // Generous enough for quick taps on the color wheel; still stops a runaway script.
  const applyLimiter = rateLimit({ windowMs: 10_000, max: 30, clientIp, skip: isLoopback });
  const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 20, clientIp });

  // ---------------- Public ----------------

  app.get('/api/health', (c) => c.json({ ok: true }));

  app.get('/api/state', publicLimiter, (c) => c.json(lights.publicState()));

  app.get('/api/events', (c) =>
    streamSSE(c, async (stream) => {
      let timer: NodeJS.Timeout | null = null;
      const send = () => {
        if (timer) return;
        // Coalesce bursts (for example many devices changing at once) into one message.
        timer = setTimeout(() => {
          timer = null;
          void stream.writeSSE({ event: 'state', data: JSON.stringify(lights.publicState()) });
        }, 50);
      };
      bus.on('state', send);
      await stream.writeSSE({ event: 'state', data: JSON.stringify(lights.publicState()) });
      const ping = setInterval(() => void stream.writeSSE({ event: 'ping', data: '' }), 25_000);
      await new Promise<void>((resolve) => stream.onAbort(resolve));
      clearInterval(ping);
      if (timer) clearTimeout(timer);
      bus.off('state', send);
    })
  );

  /** A color or scene chosen on the public page wins over a game or a layout preview. */
  const takeLights = (what: string) => {
    host?.endGame(`${what} was chosen`);
    preview?.stop();
  };

  app.post('/api/scenes/:id/apply', applyLimiter, async (c) => {
    takeLights('a scene');
    const result = await lights.applyScene(c.req.param('id'), actor(c));
    if (!result) throw new HttpError(404, 'Unknown scene');
    if (result.applied.length === 0 && !result.effects) return c.json({ error: 'No light responded. Check that the lights are on.', ...result }, 502);
    return c.json(result);
  });

  app.post('/api/color', applyLimiter, async (c) => {
    const { color } = await body(c, z.object({ color: z.string().regex(/^#?[0-9a-fA-F]{6}$/, 'Use a hex color like #ff8800') }));
    takeLights('a color');
    const result = await lights.applyColor(color, actor(c));
    if (!result || result.applied.length === 0) return c.json({ error: 'No light responded. Check that the lights are on.', ...result }, 502);
    return c.json(result);
  });

  // ---------------- Yard layout (public read) ----------------

  app.get('/api/layout', publicLimiter, (c) => c.json(readLayout(db)));

  app.get('/api/layout/background', (c) => {
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
    const { username, password } = await body(c, z.object({ username: z.string().min(1), password: z.string().min(1) }));
    const user = await auth.login(c, username, password);
    if (!user) {
      lights.log('warn', 'admin', `Failed sign-in for "${username}"`, null, actor(c));
      throw new HttpError(401, 'Wrong username or password');
    }
    lights.log('info', 'admin', `${user.username} signed in`, null, actor(c));
    return c.json({ user });
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
      z.object({ username: z.string().trim().min(1).max(64), password: z.string().min(12, 'Use at least 12 characters') })
    );
    await auth.createUser(username, password);
    lights.log('info', 'admin', `Admin account "${username}" created`, null, actor(c));
    const user = await auth.login(c, username, password);
    return c.json({ user });
  });

  // ---------------- Admin ----------------

  const admin = new Hono<AuthEnv>();
  admin.use('*', sameOrigin(), auth.require());

  admin.get('/overview', (c) =>
    c.json({
      devices: lights.devicesWithStatus(),
      scenes: db.listScenes(),
      devicePresets: db.listDevicePresets(),
      settings: readSettings(db),
      state: lights.publicState()
    })
  );

  admin.post('/auth/password', async (c) => {
    const { current, next } = await body(c, z.object({ current: z.string().min(1), next: z.string().min(12, 'Use at least 12 characters') }));
    const me = c.get('user');
    const ok = await auth.verify(me.username, current);
    if (!ok) throw new HttpError(400, 'Current password is wrong');
    await auth.setPassword(me.id, next);
    lights.log('info', 'admin', `${me.username} changed their password`, null, actor(c));
    return c.json({ ok: true });
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
    const scene: Scene = { id: crypto.randomUUID(), sortOrder: db.nextSortOrder(), ...input };
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
    db.saveScene({ ...prev, ...input, effects: input.effects ?? prev.effects, sequenceId: input.sequenceId === undefined ? prev.sequenceId : input.sequenceId });
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
      const sequenceId = p.sequenceId && db.getSequence(p.sequenceId) ? p.sequenceId : null;
      return { id: p.id, name: p.name, sortOrder: p.sortOrder ?? i, devicePresets, ...(p.effects ? { effects: p.effects } : {}), ...(sequenceId ? { sequenceId } : {}) };
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
    const seq = db.saveSequence({ ...input, id: crypto.randomUUID() } as Sequence);
    lights.log('info', 'config', `Sequence "${seq.name}" created`, null, actor(c));
    return c.json(seq, 201);
  });

  admin.put('/sequences/:id', async (c) => {
    const prev = db.getSequence(c.req.param('id'));
    if (!prev) throw new HttpError(404, 'Unknown sequence');
    const input = await body(c, sequenceInput);
    const seq = db.saveSequence({ ...input, id: prev.id } as Sequence);
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

  // The sequence editor's preview on the real lights.
  const seqPreviewSchema = z.object({ active: z.literal(true), sequence: sequenceInput.extend({ id: z.string().max(64).default('') }), time: z.number().min(0), playing: z.boolean() });
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
    writeSettings(db, input);
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
  const previewSchema = z.object({ active: z.literal(true), layout: layoutShape, selected: z.string().nullable(), corner: z.number().int().nullable(), segment: z.number().int().nullable().optional(), play: z.boolean().optional() });
  admin.post('/layout/preview', async (c) => {
    const req = await body(c, previewSchema);
    return c.json({ devices: preview?.show(req) ?? [] });
  });
  admin.delete('/layout/preview', (c) => {
    preview?.stop();
    return c.json({ ok: true });
  });

  // Debug mode: send the games to the real lights too.
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

  admin.put('/layout', async (c) => {
    const layout = await body(c, layoutSchema);
    writeLayout(db, layout);
    host?.setLayout(layout);
    const pixels = layout.fixtures.reduce((n, f) => n + f.pixels, 0);
    lights.log('info', 'config', `Yard layout saved: ${layout.fixtures.length} object(s), ${pixels} LED(s)`, null, actor(c));
    return c.json(layout);
  });

  admin.post('/layout/background', async (c) => {
    const type = c.req.header('content-type') ?? '';
    if (!/^image\/(png|jpeg|webp|gif)$/.test(type)) throw new HttpError(400, 'Use a PNG, JPEG, WebP or GIF picture');
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    if (bytes.length > 12 * 1024 * 1024) throw new HttpError(400, 'The picture is larger than 12 MB');
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
