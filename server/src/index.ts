import { serve } from '@hono/node-server';
import { createApp } from './app.ts';
import { COOKIE, createAuth, isExamplePassword } from './auth.ts';
import { ConnectionLimit } from './rateLimit.ts';
import { loadConfig } from './config.ts';
import { openDatabase } from './db.ts';
import { useScoreStore } from './game/kit.ts';
import { databaseScores } from './scoreStore.ts';
import { discoverWled } from './discovery.ts';
import { Bus } from './events.ts';
import { Lights } from './lights.ts';
import { migrateV1Settings, readGameArea, readHiddenGames, readLineSettings, readSettings } from './settings.ts';
import { admitUpgrade, upgradeVisitor, visitorLabel, visitorTag } from './visitor.ts';
import type { Server } from 'node:http';
import { GameHost } from './game/host.ts';
import { readLayout } from './layoutStore.ts';
import { LayoutPreview } from './layoutPreview.ts';
import { FramePipeline } from './framePipeline.ts';
import { LightSender } from './lightSender.ts';
import { frameClock } from './ledTiming.ts';
import { RoofView } from './roofView.ts';
import { LightScheduler } from './lightSchedule.ts';
import { HomeAssistant } from './homeAssistant.ts';
import { HaFrames } from './haFrames.ts';

const config = loadConfig();
const db = openDatabase(config.databasePath);
const bus = new Bus();
const lights = new Lights(db, bus);
// Home Assistant: plugs that power WLED controllers, and other lights (used once it is set up).
const ha = new HomeAssistant(db);
lights.ha = ha;

migrateV1Settings(db);

// First admin account from the environment.
if (db.countUsers() === 0) {
  if (config.adminUsername && config.adminPassword && isExamplePassword(config.adminPassword)) {
    // The site is on the internet, and the example password is in the README.
    console.error('ERROR: ADMIN_PASSWORD is the example password. No admin account was created: set a password of your own.');
  } else if (config.adminUsername && config.adminPassword) {
    await createAuth(db, { secureCookie: config.secureCookie }).createUser(config.adminUsername, config.adminPassword);
    lights.log('info', 'admin', `Admin account "${config.adminUsername}" created from environment`);
    if (config.adminPassword.length < 12) console.warn('WARNING: ADMIN_PASSWORD is shorter than 12 characters.');
  } else {
    console.warn('No admin account exists. Set ADMIN_USERNAME and ADMIN_PASSWORD, or open /admin from the server itself.');
  }
}

const sender = new LightSender((level, msg) => lights.log(level, 'lights', msg));
// The admin's frame rate limit (Settings → Frame rate), now and whenever it changes: the clock follows it (see frameClock).
const applyFrameRate = () => {
  const limit = readSettings(db).maxFps;
  sender.maxFps = limit;
  sender.clockHz = frameClock(limit);
  pipeline.setRate(sender.clockHz);
};
// The console shows the frames a second each device is sent now.
lights.sendingTo = (d) => sender.sending(d);
// A device that falls behind while it gets frames gets fewer (see FrameRateHold).
lights.onChecked = (d, c) => {
  const live = lights.liveDevices().find((x) => x.id === d.id);
  if (live) sender.checked(live, c);
};
// Everything that draws on the lights goes through one pipeline: the editors' previews win
// over games and scenes.
const pipeline = new FramePipeline(() => lights.liveDevices(), sender);
applyFrameRate();
lights.settingsHook = applyFrameRate;
// Home Assistant lights in the layout take the colors of their objects, about once a second.
const haFrames = new HaFrames(ha, (id, wakes) => lights.haEnabled(id) && (wakes || !lights.isOff(id)), (id) => lights.levelOf(id));
pipeline.haSink = haFrames.frame;
const preview = new LayoutPreview(pipeline, (msg) => lights.log('info', 'layout', msg));
useScoreStore(databaseScores(db.raw));
const host = new GameHost(readLayout(db), (msg) => lights.log('info', 'game', msg), pipeline);
// Visitors' games in the activity log (an admin's are not: they test).
host.activity = (who, message, details) => {
  if (who.admin) return;
  const tag = visitorTag(who.id);
  lights.log('info', 'visitor', `${visitorLabel(tag, who.actor?.ip)}: ${message}`, { visitor: tag, ip: who.actor?.ip, ...details }, who.actor);
};
host.setGameArea(readGameArea(db));
host.setHiddenGames(readHiddenGames(db));
// One turn at a time with the lights: everyone else waits in line.
host.line.configure(readLineSettings(db));
// Scenes with effects: the game host draws them and sends them to the lights.
lights.setEffectPlayer((show, transition) => host.playShow(show, transition));
// A playlist waits while a game has the lights.
lights.holdPlaylist = () => host.playingGame;
// No game starts on lights that are switched off, except in the schedule's night: there it
// switches them on again (see LightScheduler.wake).
host.closed = () => {
  if (!lights.allOff()) return schedule.used(), null;
  const woke = schedule.wake("a visitor's game");
  return woke ? (void woke.catch(() => {}), null) : 'The lights are switched off right now.';
};
// Lights switched off on the devices themselves end the game, as the admin's switch does.
lights.onAllOff = () => {
  host.endGame('the lights were switched off');
  host.line.clear('the lights were switched off');
};
// What the roofline shows, for the home page. It watches the devices over the same WebSockets
// that tell the server their power and brightness.
const viewSources = {
  layout: () => host.yard,
  devices: () => lights.liveDevices(),
  deviceFrame: (id: string) => pipeline.deviceFrame(id),
  simFrame: () => host.simFrame()
};
// The schedule switches every light on and off at its times; visitors are told when they come on.
// In its night, visitors wake the lights, and they go off again when nobody uses them.
const schedule = new LightScheduler(db, lights, bus, {
  afterOff: () => lights.onAllOff?.(),
  busy: () => host.playingGame || host.line.holder() != null || host.line.waitingCount() > 0
});
lights.lightsOnAt = () => schedule.nextOnAt();
lights.nightWake = () => ({ wake: schedule.canWake(), idleMinutes: schedule.idleMinutes() });
const roof = new RoofView(viewSources, (d) => lights.peek(d));
// The same, for every LED of the yard: the Live tab (visitors at most 60 of these, see app.ts).
const yard = new RoofView(viewSources, (d) => lights.peek(d), { shape: 'yard', maxViewers: 80 });
const app = createApp({ config, db, bus, lights, host, preview, roof, yard, schedule, ha });
const server = serve({ fetch: app.fetch, port: config.port }, (info) => {
  lights.log('info', 'startup', `Listening on http://localhost:${info.port}`);
});

const auth = createAuth(db, { secureCookie: config.secureCookie });
// Play pages open at once: a few per address (a household shares one), a few hundred in all.
const sockets = new ConnectionLimit(20, 500);
host.attach(
  server as unknown as Server,
  '/api/play',
  (req) => upgradeVisitor(req, { trustProxy: config.trustProxy, sessionCookie: COOKIE, isAdmin: (t) => !!auth.userForToken(t) }),
  (req) => admitUpgrade(req, { trustProxy: config.trustProxy, limit: sockets })
);
// An upgrade on a path that no WebSocket handler took stays open for ever (Node hands the socket
// over and stops timing it): many of them would use up the server's sockets. A socket that a
// handler took reads data; one that nobody took is closed.
(server as unknown as Server).on('upgrade', (_req, socket) => {
  setTimeout(() => {
    if (!socket.destroyed && socket.listenerCount('data') === 0) socket.destroy();
  }, 10_000).unref();
});
if (db.countUsers() > 0 && config.adminPassword && isExamplePassword(config.adminPassword)) {
  console.warn('WARNING: ADMIN_PASSWORD is the example password. If an admin still uses it, it only signs in from the home network: change it in the admin console.');
}
lights.start(config.statusIntervalMs);
schedule.start();
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
  schedule.stop();
  haFrames.close();
  ha.close();
  lights.stop();
  roof.close();
  yard.close();
  host.stop();
  preview.close();
  pipeline.close();
  sender.close();
  server.close();
  db.close();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
