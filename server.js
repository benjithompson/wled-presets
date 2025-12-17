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

async function getArpTableIps(debug = false) {
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

      if (ips.size) {
        if (debug) {
          console.log(`ARP table queried via '${c.cmd} ${c.args.join(' ')}': found ${ips.size} IPs`);
        }
        break;
      }
    } catch (err) {
      if (debug) {
        console.log(`Failed to query ARP table via '${c.cmd}': ${err.message}`);
      }
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

  if (debug) {
    console.log('=== WLED Discovery Debug ===');
    console.log(`Local networks found: ${networks.length}`);
    for (const net of networks) {
      console.log(`  ${net.ifname}: ${net.address}/${net.prefix} (${intToIp(net.network)} - ${intToIp(net.broadcast)})`);
    }
  }

  // 0) Explicit subnet sweep (when provided)
  const explicit = (Array.isArray(subnets) ? subnets : []).map(parseCidr).filter(Boolean);
  const explicitMode = explicit.length > 0;
  
  if (debug) {
    if (explicitMode) {
      console.log(`Explicit subnets mode: ${explicit.map(c => c.cidr).join(', ')}`);
    } else {
      console.log('Auto-detect mode: scanning all local networks');
    }
  }

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

  if (debug && explicitMode) {
    console.log(`Explicit subnet sweep added ${candidates.length} candidates`);
  }

  // 1) Prefer ARP table IPs (usually much smaller set and already "known active")
  try {
    const arpIps = await getArpTableIps(debug);
    if (debug) {
      console.log(`ARP table returned ${arpIps.length} IPs`);
    }
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
    if (debug) {
      console.log(`After ARP filtering: ${candidates.length} candidate IPs`);
    }
  } catch (err) {
    if (debug) {
      console.log(`ARP table query failed: ${err.message}`);
    }
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
      if (debug) {
        console.log(`  Large subnet on ${net.ifname} (/${net.prefix}), limiting to /24 scan`);
      }
    }

    // Hard cap even if we didn't shrink above
    const count = Math.max(0, (end - start + 1) >>> 0);
    if (count > maxHosts) {
      end = start + (maxHosts - 1);
    }

    if (debug) {
      const actualCount = Math.max(0, (end - start + 1) >>> 0);
      console.log(`  Scanning ${net.ifname}: ${intToIp(start)} - ${intToIp(end)} (${actualCount} hosts)`);
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

  if (debug) {
    console.log(`Total candidates to probe: ${candidates.length}`);
    console.log(`Starting discovery with ${Math.min(concurrency, candidates.length || 1)} workers, ${timeoutMs}ms timeout...`);
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

// Run automatic discovery on startup if enabled
async function runStartupDiscovery() {
  const enabled = process.env.DISCOVERY_ON_STARTUP === '1';
  if (!enabled) return;

  console.log('=== Startup Discovery Enabled ===');
  
  const config = await readConfig();
  const envSubnets = String(process.env.DISCOVERY_SUBNETS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const configSubnets = Array.isArray(config.discoverySubnets) ? config.discoverySubnets : [];
  const subnets = envSubnets.length ? envSubnets : configSubnets;

  console.log('Discovery subnets:', subnets.length ? subnets : 'auto (all local networks)');
  
  // Get network info for logging
  const networks = getLocalIPv4Networks();
  console.log('Local IPv4 networks detected:');
  for (const net of networks) {
    console.log(`  - ${net.ifname}: ${net.address}/${net.prefix} (${intToIp(net.network)} - ${intToIp(net.broadcast)})`);
  }

  const wantDebug = process.env.DISCOVERY_DEBUG === '1';
  const out = await discoverWledDevices({
    concurrency: 128,
    timeoutMs: 650,
    maxHosts: 2048,
    preferScanPrefix: 24,
    subnets,
    debug: wantDebug
  });

  console.log(`Discovery found ${out.results.length} WLED device(s):`);
  for (const device of out.results) {
    console.log(`  - ${device.name} (${device.host}:${device.port})`);
  }

  if (wantDebug && out.debug) {
    console.log('Discovery debug info:', JSON.stringify(out.debug, null, 2));
  }

  // Auto-save discovered devices if configured
  if (process.env.DISCOVERY_AUTO_SAVE === '1' && out.results.length > 0) {
    console.log('Auto-saving discovered devices to database...');
    const existingDevices = config.devices;
    const existingHosts = new Set(existingDevices.map(d => `${normalizeHost(d.host)}:${d.port ?? 80}`));
    
    const newDevices = [];
    for (const device of out.results) {
      const hostKey = `${device.host}:${device.port}`;
      if (!existingHosts.has(hostKey)) {
        newDevices.push({
          id: safeId(),
          name: device.name,
          host: device.host,
          port: device.port,
          enabled: true
        });
      }
    }

    if (newDevices.length > 0) {
      const allDevices = [...existingDevices, ...newDevices];
      await writeConfig({ devices: allDevices });
      console.log(`Added ${newDevices.length} new device(s) to configuration`);
    } else {
      console.log('No new devices to add (all already configured)');
    }
  }

  console.log('=== Startup Discovery Complete ===');
}

await runStartupDiscovery();

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

app.get('/api/device-status', publicApiLimiter, async (req, res) => {
  const config = await readConfig();
  
  // Get all devices used by public presets
  const devicesUsedByPresets = new Set();
  for (const preset of config.publicPresets) {
    if (preset.devicePresets && typeof preset.devicePresets === 'object') {
      for (const deviceId of Object.keys(preset.devicePresets)) {
        devicesUsedByPresets.add(deviceId);
      }
    }
  }
  
  // Check status of each device
  const enabledDevices = config.devices.filter((d) => d && d.enabled && devicesUsedByPresets.has(d.id));
  
  const statusChecks = await Promise.allSettled(
    enabledDevices.map(async (device) => {
      const host = normalizeHost(device.host);
      const port = device.port ?? 80;
      const out = await fetchJsonWithTimeoutDetailed(`http://${host}:${port}/json/info`, {
        method: 'GET',
        timeoutMs: 1000
      });
      return { deviceId: device.id, online: out.ok };
    })
  );
  
  // Build device status map
  const deviceStatus = {};
  statusChecks.forEach((result, i) => {
    if (result.status === 'fulfilled') {
      deviceStatus[result.value.deviceId] = result.value.online;
    } else {
      deviceStatus[enabledDevices[i].id] = false;
    }
  });
  
  // Map preset IDs to their online status
  const presetStatus = {};
  for (const preset of config.publicPresets) {
    if (!preset.devicePresets || typeof preset.devicePresets !== 'object') {
      presetStatus[preset.id] = true; // No devices mapped = always "online"
      continue;
    }
    
    // Preset is online if at least one of its devices is online
    let hasAnyOnline = false;
    for (const deviceId of Object.keys(preset.devicePresets)) {
      if (deviceStatus[deviceId]) {
        hasAnyOnline = true;
        break;
      }
    }
    presetStatus[preset.id] = hasAnyOnline;
  }
  
  okJson(res, { presetStatus });
});

// Set all devices to a solid color
app.post('/api/color', applyLimiter, async (req, res) => {
  const config = await readConfig();
  const { color } = req.body || {};

  if (!color || typeof color !== 'string') {
    return res.status(400).json({ error: 'Missing color' });
  }

  // Parse hex color to RGB
  const hex = color.replace('#', '');
  if (!/^[0-9A-Fa-f]{6}$/.test(hex)) {
    return res.status(400).json({ error: 'Invalid color format' });
  }
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);

  const enabledDevices = config.devices.filter((d) => d && d.enabled);
  const applied = [];
  const errors = [];

  const results = await Promise.allSettled(
    enabledDevices.map(async (device) => {
      const host = normalizeHost(device.host);
      const port = device.port ?? 80;
      // Set solid color using WLED JSON API
      // Create array of segments 0-15 to ensure ALL segments get updated
      // WLED ignores segment IDs that don't exist
      const segmentUpdates = [];
      for (let i = 0; i < 16; i++) {
        segmentUpdates.push({ id: i, col: [[r, g, b]], fx: 0 });
      }
      const out = await fetchJsonWithTimeoutDetailed(`http://${host}:${port}/json/state`, {
        method: 'POST',
        body: {
          on: true,
          seg: segmentUpdates
        },
        timeoutMs: 1500
      });
      if (!out.ok) throw new Error('Failed to contact WLED device');
      return { deviceId: device.id };
    })
  );

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const device = enabledDevices[i];
    if (result.status === 'fulfilled') {
      applied.push(result.value);
    } else {
      const msg = result.reason && result.reason.message ? result.reason.message : 'Failed to apply';
      errors.push({ deviceId: device.id, error: msg });
    }
  }

  // Clear current preset since we're using solid color
  if (applied.length > 0) {
    await setSetting(db, 'currentPresetId', '');
  }

  okJson(res, { ok: true, applied, errors });
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
