import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import helmet from 'helmet';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import {
  openDatabase,
  getSetting,
  setSetting,
  getDevices,
  replaceDevices,
  getPublicPresetsWithMappings,
  replacePublicPresets,
  getDevicePresets,
  replaceDevicePresets,
  isEmpty,
  countAdminUsers,
  getAdminUserByUsername,
  getAdminUserById,
  createAdminUser
} from './db.js';

const execFileAsync = promisify(execFile);

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 8790;
const ROOT = process.cwd();
const PUBLIC_DIR = path.join(ROOT, 'public');
const CONFIG_PATH = path.join(ROOT, 'config.json');

const db = await openDatabase({ rootDir: ROOT });

const isProd = process.env.NODE_ENV === 'production';
// Allow disabling secure cookies for local testing in production mode (e.g., Docker without HTTPS)
const secureCookie = process.env.SECURE_COOKIE === '0' ? false : isProd;

app.disable('x-powered-by');

if (isProd || process.env.TRUST_PROXY === '1') {
  // Needed when deployed behind a TLS-terminating reverse proxy.
  app.set('trust proxy', 1);
}

app.use(helmet());

const SQLiteStore = SQLiteStoreFactory(session);
const sessionSecret = (process.env.SESSION_SECRET && String(process.env.SESSION_SECRET).trim()) || null;
if (!sessionSecret) {
  console.warn('WARNING: SESSION_SECRET is not set. Set it in production.');
}

app.use(
  session({
    name: 'wled_admin_session',
    secret: sessionSecret || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookie,
      maxAge: 1000 * 60 * 60 * 8 // 8 hours
    },
    store: new SQLiteStore({
      db: 'sessions.sqlite',
      dir: path.join(ROOT, 'data'),
      table: 'sessions'
    })
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(express.static(PUBLIC_DIR));

function normalizeHost(host) {
  return String(host || '').trim().replace(/^https?:\/\//i, '').replace(/\/$/, '');
}

function normalizePublicPresets(rawPresets) {
  const list = Array.isArray(rawPresets) ? rawPresets : [];
  const out = [];
  for (const p of list) {
    if (!p) continue;

    // New format: { id: string, name: string, devicePresets: { [deviceId]: presetId } }
    // Legacy format: { id: number, name?: string }
    const legacyNumericId = typeof p.id === 'number' && Number.isFinite(p.id) ? p.id : null;
    const id = typeof p.id === 'string' && p.id.trim() ? p.id.trim() : (legacyNumericId != null ? `legacy-${legacyNumericId}` : safeId());
    const name = String(p.name || '').trim() || (legacyNumericId != null ? `Preset ${legacyNumericId}` : '');
    if (!name) continue;

    const devicePresets = {};
    if (p.devicePresets && typeof p.devicePresets === 'object') {
      for (const [deviceId, presetIdRaw] of Object.entries(p.devicePresets)) {
        const presetId = Number(presetIdRaw);
        if (!deviceId) continue;
        if (!Number.isFinite(presetId) || presetId < 1) continue;
        devicePresets[String(deviceId)] = presetId;
      }
    }

    out.push({ id, name, devicePresets });
  }
  return out;
}

async function readConfig() {
  const adminToken = await getSetting(db, 'adminToken', 'change-me');

  let discoverySubnets = [];
  try {
    const raw = await getSetting(db, 'discoverySubnets', '[]');
    const parsed = JSON.parse(raw);
    discoverySubnets = Array.isArray(parsed) ? parsed : [];
  } catch {
    discoverySubnets = [];
  }

  const devices = await getDevices(db);
  const publicPresets = await getPublicPresetsWithMappings(db);
  const devicePresets = await getDevicePresets(db);
  
  console.log('readConfig: loaded', devices.length, 'devices and', Object.keys(devicePresets).length, 'device preset groups');

  return {
    adminToken,
    devices,
    publicPresets,
    devicePresets,
    discoverySubnets
  };
}

async function writeConfig(config) {
  if (Object.prototype.hasOwnProperty.call(config, 'adminToken')) {
    await setSetting(db, 'adminToken', config.adminToken ?? '');
  }
  if (Object.prototype.hasOwnProperty.call(config, 'discoverySubnets')) {
    await setSetting(db, 'discoverySubnets', JSON.stringify(Array.isArray(config.discoverySubnets) ? config.discoverySubnets : []));
  }

  if (Object.prototype.hasOwnProperty.call(config, 'devices')) {
    await replaceDevices(db, Array.isArray(config.devices) ? config.devices : []);
  }

  if (Object.prototype.hasOwnProperty.call(config, 'publicPresets')) {
    await replacePublicPresets(db, Array.isArray(config.publicPresets) ? config.publicPresets : []);
  }
}

async function migrateConfigJsonToDbIfEmpty() {
  const empty = await isEmpty(db);
  if (!empty) return;

  try {
    const raw = await fs.readFile(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);

    const adminToken = parsed.adminToken ?? 'change-me';
    const discoverySubnets = Array.isArray(parsed.discoverySubnets) ? parsed.discoverySubnets : [];
    const devices = Array.isArray(parsed.devices) ? parsed.devices : [];
    const publicPresets = normalizePublicPresets(parsed.publicPresets);

    const normalizedDevices = devices
      .filter(Boolean)
      .map((d) => ({
        id: d.id || safeId(),
        name: String(d.name || '').trim() || normalizeHost(d.host),
        host: normalizeHost(d.host),
        port: d.port ? Number(d.port) : 80,
        enabled: d.enabled !== false
      }))
      .filter((d) => d.host.length > 0);

    await setSetting(db, 'adminToken', String(adminToken ?? ''));
    await setSetting(db, 'discoverySubnets', JSON.stringify(discoverySubnets.map((s) => String(s || '').trim()).filter(Boolean)));
    await replaceDevices(db, normalizedDevices);
    await replacePublicPresets(db, publicPresets);
  } catch {
    // no config.json or invalid JSON; start with empty DB
  }
}

await migrateConfigJsonToDbIfEmpty();

function isLocalRequest(req) {
  const ip = String(req.ip || '');
  return ip === '::1' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1' || ip.endsWith('::1');
}

function requireAdminSession(req) {
  const userId = req.session?.userId;
  return typeof userId === 'string' && userId.length > 0;
}

function requireSameOrigin(req, res, next) {
  // Basic CSRF hardening for cookie-auth endpoints.
  if (!isProd) return next();
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();

  const expectedHost = String(req.headers.host || '');
  const origin = String(req.headers.origin || '');
  const referer = String(req.headers.referer || '');

  const ok = (value) => {
    if (!value) return false;
    try {
      const u = new URL(value);
      return u.host === expectedHost;
    } catch {
      return false;
    }
  };

  if (ok(origin) || ok(referer)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

function okJson(res, data) {
  res.setHeader('Cache-Control', 'no-store');
  res.json(data);
}

function ipToInt(ip) {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.');
}

function maskToInt(mask) {
  return ipToInt(mask);
}

function prefixToMask(prefix) {
  const p = Number(prefix);
  if (!Number.isFinite(p) || p < 0 || p > 32) return null;
  if (p === 0) return 0;
  return ((0xffffffff << (32 - p)) >>> 0);
}

function parseCidr(cidr) {
  const s = String(cidr || '').trim();
  const m = s.match(/^(.+)\/(\d{1,2})$/);
  if (!m) return null;
  const ip = m[1].trim();
  const prefix = Number(m[2]);
  const ipInt = ipToInt(ip);
  const maskInt = prefixToMask(prefix);
  if (ipInt == null || maskInt == null) return null;
  const network = ipInt & maskInt;
  const broadcast = network | (~maskInt >>> 0);
  return { cidr: `${intToIp(network)}/${prefix}`, prefix, network, broadcast };
}

function popcount32(n) {
  let v = n >>> 0;
  let c = 0;
  while (v) {
    v &= (v - 1) >>> 0;
    c++;
  }
  return c;
}

function netmaskToPrefix(netmask) {
  const maskInt = maskToInt(netmask);
  if (maskInt == null) return null;
  return popcount32(maskInt);
}

function getLocalIPv4Networks() {
  const nets = os.networkInterfaces();
  const networks = [];
  for (const ifname of Object.keys(nets)) {
    for (const ni of nets[ifname] || []) {
      if (ni.family !== 'IPv4' || ni.internal) continue;
      if (!ni.address || !ni.netmask) continue;
      const ipInt = ipToInt(ni.address);
      const maskInt = maskToInt(ni.netmask);
      if (ipInt == null || maskInt == null) continue;
      const network = ipInt & maskInt;
      const broadcast = network | (~maskInt >>> 0);
      const prefix = netmaskToPrefix(ni.netmask);
      networks.push({ ifname, address: ni.address, netmask: ni.netmask, prefix, network, broadcast });
    }
  }
  return networks;
}

function ipInAnyNetwork(ip, networks) {
  const ipInt = ipToInt(ip);
  if (ipInt == null) return false;
  return networks.some((n) => ipInt >= n.network && ipInt <= n.broadcast);
}

async function getArpTableIps() {
  const ips = new Set();

  const commands = [
    // macOS / BSD
    { cmd: 'arp', args: ['-a', '-n'] },
    { cmd: 'arp', args: ['-a'] },
    // Linux (if available)
    { cmd: 'ip', args: ['neigh', 'show'] }
  ];

  for (const c of commands) {
    try {
      const { stdout } = await execFileAsync(c.cmd, c.args, { timeout: 1200, maxBuffer: 1024 * 1024 });
      const text = String(stdout || '');

      // arp -a: "? (192.168.1.1) at ..."
      for (const match of text.matchAll(/\((\d{1,3}(?:\.\d{1,3}){3})\)/g)) {
        ips.add(match[1]);
      }

      // ip neigh: "192.168.1.12 dev ..."
      for (const match of text.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)) {
        ips.add(match[1]);
      }

      if (ips.size) break;
    } catch {
      // ignore and try next
    }
  }

  return Array.from(ips);
}

async function fetchJsonWithTimeout(url, { method = 'GET', body, timeoutMs = 1200 } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJsonWithTimeoutDetailed(url, { method = 'GET', body, timeoutMs = 1200 } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal
    });

    const status = res.status;
    const headers = Object.fromEntries(res.headers.entries());
    const text = await res.text();
    const bodySnippet = text.slice(0, 400);

    if (!res.ok) {
      return { ok: false, url, status, headers, error: `http_${status}`, bodySnippet };
    }

    try {
      const json = text ? JSON.parse(text) : null;
      return { ok: true, url, status, headers, json, bodySnippet };
    } catch (e) {
      return { ok: false, url, status, headers, error: `json_parse:${e?.name || 'Error'}`, bodySnippet };
    }
  } catch (e) {
    return { ok: false, url, status: 0, headers: {}, error: `fetch_error:${e?.name || 'Error'}`, bodySnippet: '' };
  } finally {
    clearTimeout(timeout);
  }
}

async function discoverWledDevices({
  concurrency = 128,
  timeoutMs = 650,
  maxHosts = 2048,
  preferScanPrefix = 24,
  subnets = [],
  debug = false
} = {}) {
  const networks = getLocalIPv4Networks();
  const selfIps = new Set(networks.map((n) => n.address));
  const candidates = [];
  const candidateSet = new Set();

  const debugInfo = {
    candidates: 0,
    probed: 0,
    found: 0,
    failures: {}
  };

  // 0) Explicit subnet sweep (when provided)
  const explicit = (Array.isArray(subnets) ? subnets : []).map(parseCidr).filter(Boolean);
  const explicitMode = explicit.length > 0;
  for (const cidr of explicit) {
    let start = cidr.network;
    let end = cidr.broadcast;
    if (cidr.prefix <= 30) {
      start = cidr.network + 1;
      end = cidr.broadcast - 1;
    }

    const count = Math.max(0, (end - start + 1) >>> 0);
    if (count > maxHosts) end = start + (maxHosts - 1);

    for (let ip = start; ip <= end; ip++) {
      const s = intToIp(ip >>> 0);
      if (!candidateSet.has(s)) {
        candidateSet.add(s);
        candidates.push(s);
      }
    }
  }

  // 1) Prefer ARP table IPs (usually much smaller set and already "known active")
  try {
    const arpIps = await getArpTableIps();
    for (const ip of arpIps) {
      if (explicitMode) {
        const ipInt = ipToInt(ip);
        if (ipInt == null) continue;
        const inExplicit = explicit.some((c) => ipInt >= c.network && ipInt <= c.broadcast);
        if (!inExplicit) continue;
      } else {
        if (!ipInAnyNetwork(ip, networks)) continue;
      }
      if (!candidateSet.has(ip)) {
        candidateSet.add(ip);
        candidates.push(ip);
      }
    }
  } catch {
    // ignore
  }

  // 2) Subnet sweep, but bounded.
  // If explicit subnets are provided, we skip interface-based sweeps to avoid scanning unrelated networks.
  if (explicitMode) {
    // continue to probing
  } else {
  // Many home networks are /24. Some are /16 (or larger) which would take minutes.
  // If subnet is larger than maxHosts, we scan a /24 that contains the interface address.
  for (const net of networks) {
    const subnetSize = (net.broadcast - net.network + 1) >>> 0;
    let start = net.network + 1;
    let end = net.broadcast - 1;

    if (subnetSize > maxHosts) {
      const ipInt = ipToInt(net.address);
      if (ipInt != null) {
        const scanPrefix = preferScanPrefix;
        if (scanPrefix === 24) {
          const base = ipInt & 0xffffff00;
          start = base + 1;
          end = base + 254;
        }
      }
    }

    // Hard cap even if we didn't shrink above
    const count = Math.max(0, (end - start + 1) >>> 0);
    if (count > maxHosts) {
      end = start + (maxHosts - 1);
    }

    for (let ip = start; ip <= end; ip++) {
      const s = intToIp(ip >>> 0);
      if (!candidateSet.has(s)) {
        candidateSet.add(s);
        candidates.push(s);
      }
    }
  }
  }

  const results = [];
  let idx = 0;

  async function worker() {
    while (idx < candidates.length) {
      const ip = candidates[idx++];
      if (selfIps.has(ip)) continue;
      debugInfo.probed++;
      const out = await fetchJsonWithTimeoutDetailed(`http://${ip}/json/info`, { timeoutMs });
      if (out.ok && out.json && (out.json.ver || out.json.name || out.json.leds)) {
        results.push({ host: ip, port: 80, name: out.json.name || ip, info: out.json });
        debugInfo.found++;
      } else if (debug) {
        const key = out.error || 'unknown';
        debugInfo.failures[key] = (debugInfo.failures[key] || 0) + 1;
      }
    }
  }

  debugInfo.candidates = candidates.length;

  const workers = Array.from({ length: Math.min(concurrency, candidates.length || 1) }, () => worker());
  await Promise.all(workers);

  // Deduplicate by host
  const seen = new Set();
  const deduped = results.filter((r) => {
    if (seen.has(r.host)) return false;
    seen.add(r.host);
    return true;
  });

  return debug ? { results: deduped, debug: debugInfo } : { results: deduped };
}

function safeId() {
  return crypto.randomUUID();
}

async function ensureBootstrapAdminUser() {
  const existing = await countAdminUsers(db);
  if (existing > 0) return;

  const username = (process.env.ADMIN_USERNAME && String(process.env.ADMIN_USERNAME).trim()) || '';
  const password = (process.env.ADMIN_PASSWORD && String(process.env.ADMIN_PASSWORD).trim()) || '';

  if (!username || !password) {
    console.warn('WARNING: No admin user exists. Set ADMIN_USERNAME and ADMIN_PASSWORD to create the first admin.');
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  await createAdminUser(db, { id: safeId(), username, passwordHash });
  console.log(`Admin user created for username: ${username}`);
}

await ensureBootstrapAdminUser();

// Protect cookie-auth endpoints from cross-site requests (CSRF hardening)
app.use('/api/auth', requireSameOrigin);
app.use('/api/admin', requireSameOrigin);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.get('/api/auth/bootstrap', async (req, res) => {
  const existing = await countAdminUsers(db);
  okJson(res, { needsBootstrap: existing === 0, localOnly: true });
});

app.post('/api/auth/bootstrap', loginLimiter, async (req, res) => {
  const existing = await countAdminUsers(db);
  if (existing > 0) return res.status(409).json({ error: 'Admin already exists' });
  if (!isLocalRequest(req)) return res.status(403).json({ error: 'Forbidden' });

  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });

  const passwordHash = await bcrypt.hash(password, 12);
  await createAdminUser(db, { id: safeId(), username, passwordHash });
  okJson(res, { ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });
  const user = await getAdminUserById(db, req.session.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  okJson(res, { ok: true, user: { id: user.id, username: user.username } });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  const user = await getAdminUserByUsername(db, username);
  const ok = user ? await bcrypt.compare(password, user.passwordHash) : false;
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  req.session.userId = user.id;
  okJson(res, { ok: true, user: { id: user.id, username: user.username } });
});

app.post('/api/auth/logout', (req, res) => {
  req.session?.destroy(() => {
    res.clearCookie('wled_admin_session');
    okJson(res, { ok: true });
  });
});

// Rate limiter for public preset API to prevent abuse
const publicApiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' }
});

// Stricter rate limiter for apply endpoint
const applyLimiter = rateLimit({
  windowMs: 10 * 1000, // 10 seconds
  max: 10, // 10 requests per 10 seconds
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' }
});

app.get('/api/config/public', publicApiLimiter, async (req, res) => {
  const config = await readConfig();
  // Only expose preset IDs and names - no device info (internal network details)
  const publicPresets = config.publicPresets
    .filter((p) => p && typeof p.id === 'string' && p.id.length > 0)
    .map((p) => ({ id: p.id, name: p.name }));

  // Get currently selected preset
  const currentPresetId = await getSetting(db, 'currentPresetId', null);

  okJson(res, { publicPresets, currentPresetId });
});

app.post('/api/apply', applyLimiter, async (req, res) => {
  const config = await readConfig();
  const { publicPresetId } = req.body || {};

  // Only allow applying public presets - direct device control requires admin auth
  if (!publicPresetId) {
    return res.status(400).json({ error: 'Missing publicPresetId' });
  }

  const preset = config.publicPresets.find((p) => p && p.id === String(publicPresetId || ''));
  if (!preset) return res.status(400).json({ error: 'Unknown public preset' });

  const enabledDevices = config.devices.filter((d) => d && d.enabled);
  const applied = [];
  const skipped = [];
  const errors = [];

  const work = [];
  for (const device of enabledDevices) {
    const mapped = preset.devicePresets ? preset.devicePresets[device.id] : undefined;
    const mappedId = Number(mapped);
    if (!Number.isFinite(mappedId) || mappedId < 1) {
      skipped.push({ deviceId: device.id, reason: 'No mapping' });
      continue;
    }
    work.push({ device, mappedId });
  }

  const results = await Promise.allSettled(
    work.map(async ({ device, mappedId }) => {
      const host = normalizeHost(device.host);
      const port = device.port ?? 80;
      const out = await fetchJsonWithTimeoutDetailed(`http://${host}:${port}/json/state`, {
        method: 'POST',
        body: { ps: mappedId },
        timeoutMs: 1500
      });
      if (!out.ok) throw new Error('Failed to contact WLED device');
      return { deviceId: device.id, presetId: mappedId };
    })
  );

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const meta = work[i];
    if (r.status === 'fulfilled') {
      applied.push(r.value);
    } else {
      const msg = r.reason && r.reason.message ? r.reason.message : 'Failed to apply';
      errors.push({ deviceId: meta.device.id, presetId: meta.mappedId, error: msg });
    }
  }

  // Save the current preset selection if at least one device was successfully updated
  if (applied.length > 0) {
    await setSetting(db, 'currentPresetId', String(publicPresetId));
  }

  okJson(res, { ok: true, applied, skipped, errors });

});

// Admin-only endpoint for direct device control
app.post('/api/admin/apply', async (req, res) => {
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });
  
  const config = await readConfig();
  const { deviceId, presetId } = req.body || {};

  if (!deviceId || presetId == null) {
    return res.status(400).json({ error: 'Missing deviceId or presetId' });
  }

  const device = config.devices.find((d) => d && d.enabled && d.id === deviceId);
  const idNum = Number(presetId);
  if (!device) return res.status(400).json({ error: 'Unknown or disabled device' });
  if (!Number.isFinite(idNum) || idNum < 1) return res.status(400).json({ error: 'Invalid presetId' });

  const host = normalizeHost(device.host);
  const port = device.port ?? 80;
  const out = await fetchJsonWithTimeoutDetailed(`http://${host}:${port}/json/state`, {
    method: 'POST',
    body: { ps: idNum },
    timeoutMs: 1500
  });

  if (!out.ok) return res.status(502).json({ error: 'Failed to contact WLED device' });
  return okJson(res, { ok: true, applied: [{ deviceId: device.id, presetId: idNum }], skipped: [], errors: [] });
});

app.get('/api/admin/config', async (req, res) => {
  const config = await readConfig();
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });
  okJson(res, { devices: config.devices, publicPresets: config.publicPresets, devicePresets: config.devicePresets });
});

app.post('/api/admin/config', async (req, res) => {
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const config = await readConfig();
    const next = req.body || {};
    const devices = Array.isArray(next.devices) ? next.devices : config.devices;
    const publicPresets = Array.isArray(next.publicPresets) ? next.publicPresets : config.publicPresets;

    // Minimal normalization
    const normalizedDevices = devices
      .filter(Boolean)
      .map((d) => ({
        id: d.id || safeId(),
        name: String(d.name || '').trim() || normalizeHost(d.host),
        host: normalizeHost(d.host),
        port: d.port ? Number(d.port) : 80,
        enabled: Boolean(d.enabled)
      }))
      .filter((d) => d.host.length > 0);

    const normalizedPresets = normalizePublicPresets(publicPresets);

    console.log('Saving config with', normalizedDevices.length, 'devices');
    await writeConfig({ ...config, devices: normalizedDevices, publicPresets: normalizedPresets });
    console.log('Config saved successfully');
    okJson(res, { ok: true });
  } catch (err) {
    console.error('Error saving config:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/presets/importAll', async (req, res) => {
  const config = await readConfig();
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });

  const devices = config.devices.filter((d) => d && d.enabled);
  const results = [];
  const errors = [];

  for (const device of devices) {
    const host = normalizeHost(device.host);
    const port = device.port ?? 80;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    try {
      const resp = await fetch(`http://${host}:${port}/presets.json`, { signal: controller.signal });
      if (!resp.ok) throw new Error('Failed to fetch presets.json');
      const presetsJson = await resp.json();

      const imported = [];
      for (const [key, value] of Object.entries(presetsJson || {})) {
        const id = Number(key);
        if (!Number.isFinite(id) || id < 1) continue;
        const name = value && typeof value === 'object' ? String(value.n || '').trim() : '';
        imported.push({ id, name: name || `Preset ${id}` });
      }

      imported.sort((a, b) => a.id - b.id);
      results.push({ deviceId: device.id, presets: imported });
      
      // Save to database
      console.log(`Saving ${imported.length} presets for device ${device.id}`);
      await replaceDevicePresets(db, device.id, imported);
      console.log(`Saved presets for device ${device.id}`);
    } catch (e) {
      console.error(`Error importing presets for device ${device.id}:`, e);
      errors.push({ deviceId: device.id, error: e?.message || 'Failed to contact WLED device' });
      results.push({ deviceId: device.id, presets: [] });
    } finally {
      clearTimeout(timeout);
    }
  }

  console.log('Import complete. Results:', results.length, 'Errors:', errors.length);
  okJson(res, { ok: true, devices: results, errors });
});

app.post('/api/admin/discover', async (req, res) => {
  const config = await readConfig();
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });

  const bodySubnets = Array.isArray(req.body?.subnets) ? req.body.subnets : [];
  const envSubnets = String(process.env.DISCOVERY_SUBNETS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const configSubnets = Array.isArray(config.discoverySubnets) ? config.discoverySubnets : [];

  const subnets = bodySubnets.length ? bodySubnets : (envSubnets.length ? envSubnets : configSubnets);

  const wantDebug = Boolean(req.body?.debug) || process.env.DISCOVERY_DEBUG === '1';

  const out = await discoverWledDevices({
    concurrency: 128,
    timeoutMs: 650,
    maxHosts: 2048,
    preferScanPrefix: 24,
    subnets,
    debug: wantDebug
  });

  okJson(res, {
    found: out.results.map((d) => ({ host: d.host, port: d.port, name: d.name })),
    ...(wantDebug ? { debug: out.debug } : {})
  });
});

app.post('/api/admin/probe', async (req, res) => {
  const config = await readConfig();
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });

  const host = normalizeHost(req.body?.host);
  const port = req.body?.port ? Number(req.body.port) : 80;
  const probePath = String(req.body?.path || '/json/info');

  if (!host) return res.status(400).json({ error: 'Missing host' });
  if (!Number.isFinite(port) || port <= 0 || port > 65535) return res.status(400).json({ error: 'Invalid port' });
  if (!probePath.startsWith('/')) return res.status(400).json({ error: 'Path must start with /' });

  const url = `http://${host}:${port}${probePath}`;
  const out = await fetchJsonWithTimeoutDetailed(url, { timeoutMs: 1500 });
  okJson(res, out);
});

app.post('/api/admin/presets/import', async (req, res) => {
  const config = await readConfig();
  if (!requireAdminSession(req)) return res.status(401).json({ error: 'Unauthorized' });

  const { deviceId } = req.body || {};
  const device = config.devices.find((d) => d && d.id === deviceId);
  if (!device) return res.status(400).json({ error: 'Unknown device' });

  const host = normalizeHost(device.host);
  const port = device.port ?? 80;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2000);

  try {
    const resp = await fetch(`http://${host}:${port}/presets.json`, { signal: controller.signal });
    if (!resp.ok) return res.status(502).json({ error: 'Failed to fetch presets.json' });
    const presetsJson = await resp.json();

    const imported = [];
    for (const [key, value] of Object.entries(presetsJson || {})) {
      const id = Number(key);
      if (!Number.isFinite(id) || id < 1) continue;
      const name = value && typeof value === 'object' ? String(value.n || '').trim() : '';
      imported.push({ id, name: name || `Preset ${id}` });
    }

    imported.sort((a, b) => a.id - b.id);
    okJson(res, { presets: imported });
  } catch {
    res.status(502).json({ error: 'Failed to contact WLED device' });
  } finally {
    clearTimeout(timeout);
  }
});

// SPA fallback
app.get('/login', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

function requireAuthOrRedirect(req, res, next) {
  if (!requireAdminSession(req)) {
    const redirect = encodeURIComponent(req.originalUrl);
    return res.redirect(`/login?redirect=${redirect}`);
  }
  next();
}

app.get('/admin', requireAuthOrRedirect, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

app.get('/admin.html', requireAuthOrRedirect, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`WLED Presets Site running on http://localhost:${PORT}`);
});
