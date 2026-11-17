import { serve } from '@hono/node-server';
import { createApp } from './app.ts';
import { createAuth } from './auth.ts';
import { loadConfig } from './config.ts';
import { openDatabase } from './db.ts';
import { discoverWled } from './discovery.ts';
import { Bus } from './events.ts';
import { Lights } from './lights.ts';
import { migrateV1Settings, readSettings } from './settings.ts';
import type { Server } from 'node:http';
import { GameHost } from './game/host.ts';
import { readLayout } from './layoutStore.ts';
import { LayoutPreview } from './layoutPreview.ts';
import { LightsOutput } from './game/output.ts';
import { LightSender } from './lightSender.ts';

const config = loadConfig();
const db = openDatabase(config.databasePath);
const bus = new Bus();
const lights = new Lights(db, bus);

migrateV1Settings(db);

// First admin account from the environment.
if (db.countUsers() === 0) {
  if (config.adminUsername && config.adminPassword) {
    await createAuth(db, { secureCookie: config.secureCookie }).createUser(config.adminUsername, config.adminPassword);
    lights.log('info', 'admin', `Admin account "${config.adminUsername}" created from environment`);
    if (config.adminPassword.length < 12) console.warn('WARNING: ADMIN_PASSWORD is shorter than 12 characters.');
  } else {
    console.warn('No admin account exists. Set ADMIN_USERNAME and ADMIN_PASSWORD, or open /admin from the server itself.');
  }
}

const sender = new LightSender((level, msg) => lights.log(level, 'lights', msg));
const preview = new LayoutPreview(() => lights.devicesWithStatus(), (msg) => lights.log('info', 'layout', msg), sender);
const output = new LightsOutput(() => lights.devicesWithStatus(), () => preview.active, sender);
const host = new GameHost(readLayout(db), (msg) => lights.log('info', 'game', msg), output);
// Scenes with effects: the game host draws them and sends them to the lights.
lights.setEffectPlayer((show) => host.playShow(show));
const app = createApp({ config, db, bus, lights, host, preview });
const server = serve({ fetch: app.fetch, port: config.port }, (info) => {
  lights.log('info', 'startup', `Listening on http://localhost:${info.port}`);
});

host.attach(server as unknown as Server, '/api/play');
lights.start(config.statusIntervalMs);
// A scene with effects that was playing before a restart plays again.
lights.resumeEffects();

// Presets on a device change over time, and older installs stored no colors. Read them again.
const enabledIds = db.listDevices().filter((d) => d.enabled).map((d) => d.id);
if (enabledIds.length) {
  void Promise.all(enabledIds.map((id) => lights.importPresets(id))).then((results) => {
    const ok = results.filter((r) => r.ok).length;
    lights.log(ok === results.length ? 'info' : 'warn', 'import', `Startup preset refresh: ${ok}/${results.length} device(s) read`, results);
    bus.emit('state');
  });
}

if (config.discoveryOnStartup) {
  const subnets = config.discoverySubnets.length ? config.discoverySubnets : readSettings(db).discoverySubnets;
  void discoverWled({ subnets, hosts: config.discoveryHosts, ports: config.discoveryPorts, log: config.discoveryDebug ? (m) => console.log(`[discovery] ${m}`) : undefined }).then((found) => {
    lights.log('info', 'discovery', `Startup discovery found ${found.length} device(s)`);
    if (!config.discoveryAutoSave) return;
    const existing = new Set(db.listDevices().map((d) => `${d.host}:${d.port}`));
    const fresh = found.filter((f) => !existing.has(`${f.host}:${f.port}`));
    const ids: string[] = [];
    for (const f of fresh) {
      const id = crypto.randomUUID();
      db.saveDevice({ id, name: f.name, host: f.host, port: f.port, enabled: true });
      ids.push(id);
    }
    if (fresh.length) {
      lights.log('info', 'discovery', `Added ${fresh.length} new device(s): ${fresh.map((f) => f.name).join(', ')}`);
      void lights.importPresetsForNew(ids);
      void lights.refreshStatus();
      bus.emit('devices');
    }
  });
}

async function shutdown() {
  // Unfreeze devices that got frames over HTTP, so they do not stay on the last frame.
  await Promise.race([sender.release(lights.devicesWithStatus()), new Promise((r) => setTimeout(r, 1000))]);
  lights.stop();
  host.stop();
  preview.close();
  sender.close();
  server.close();
  db.close();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
