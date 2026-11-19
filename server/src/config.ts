import path from 'node:path';
import { parseTrustProxy, type TrustProxy } from './clientIp.ts';

const flag = (v: string | undefined, fallback = false) => (v == null || v === '' ? fallback : v === '1' || v.toLowerCase() === 'true');
const list = (v: string | undefined) =>
  String(v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

export interface AppConfig {
  port: number;
  databasePath: string;
  webDir: string;
  isProd: boolean;
  adminUsername: string;
  adminPassword: string;
  secureCookie: boolean;
  /** Which proxy headers tell a visitor's address (see clientIp.ts). */
  trustProxy: TrustProxy;
  discoveryOnStartup: boolean;
  discoveryAutoSave: boolean;
  discoverySubnets: string[];
  discoveryDebug: boolean;
  /** Extra hosts probed on every scan, in addition to the subnets. */
  discoveryHosts: string[];
  /** Ports probed on each address. WLED uses 80. */
  discoveryPorts: number[];
  statusIntervalMs: number;
}

/** "80,9101-9104" -> [80, 9101, 9102, 9103, 9104]. Invalid parts are ignored. */
export function parsePorts(v: string | undefined): number[] {
  const out = new Set<number>();
  for (const part of list(v)) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) continue;
    const a = Number(m[1]);
    const b = Number(m[2] ?? m[1]);
    for (let p = a; p <= b && p - a < 64; p++) if (p >= 1 && p <= 65535) out.add(p);
  }
  return out.size ? [...out] : [80];
}

export function loadConfig(env = process.env): AppConfig {
  const root = path.resolve(import.meta.dirname, '../..');
  const isProd = env.NODE_ENV === 'production';
  return {
    port: Number(env.PORT) || 8790,
    databasePath: env.DATABASE_PATH || path.join(root, 'data', 'wled-presets.sqlite'),
    webDir: env.WEB_DIR || path.join(root, 'dist', 'web'),
    isProd,
    adminUsername: String(env.ADMIN_USERNAME ?? '').trim(),
    adminPassword: String(env.ADMIN_PASSWORD ?? ''),
    // v1 defaulted to secure cookies in production. Most installs are plain HTTP on a LAN,
    // so v2 defaults to off and SECURE_COOKIE=1 turns it on.
    secureCookie: flag(env.SECURE_COOKIE, false),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    discoveryOnStartup: flag(env.DISCOVERY_ON_STARTUP),
    discoveryAutoSave: flag(env.DISCOVERY_AUTO_SAVE),
    discoverySubnets: list(env.DISCOVERY_SUBNETS),
    discoveryDebug: flag(env.DISCOVERY_DEBUG),
    discoveryHosts: list(env.DISCOVERY_HOSTS),
    discoveryPorts: parsePorts(env.DISCOVERY_PORTS),
    statusIntervalMs: Number(env.STATUS_INTERVAL_MS) || 10_000
  };
}
