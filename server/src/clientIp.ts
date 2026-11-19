import net from 'node:net';
import type { IncomingMessage } from 'node:http';
import type { Context } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';

// Who sent a request. The site is open to the internet (usually through Cloudflare Tunnel), so
// anything a visitor can put in a header is not to be believed:
//
// - X-Forwarded-For is a list that every proxy appends to. Its first entry is whatever the
//   visitor sent; only the entries the trusted proxies added, at the right end, are real.
// - Cloudflare sets CF-Connecting-IP itself and overwrites one sent by the visitor.
// - Behind cloudflared (or nginx) on the same computer, every request comes from 127.0.0.1. So a
//   request "from this computer" also has to carry no proxy headers at all, and name this
//   computer as its host.

/**
 * TRUST_PROXY. false: use the address of the connection. A number: that many proxies in front,
 * each appending to X-Forwarded-For (1 for one proxy or for Cloudflare Tunnel). 'cloudflare':
 * CF-Connecting-IP (Cloudflare Tunnel, or a proxied DNS record).
 */
export type TrustProxy = false | number | 'cloudflare';

export function parseTrustProxy(v: string | undefined): TrustProxy {
  const s = String(v ?? '').trim().toLowerCase();
  if (!s || s === '0' || s === 'false' || s === 'no') return false;
  if (s === 'cloudflare' || s === 'cf') return 'cloudflare';
  const n = Number(s);
  if (Number.isInteger(n) && n > 0) return Math.min(n, 10);
  return 1; // "1", "true", "yes"
}

type Header = (name: string) => string | undefined;

/** Headers that only a proxy adds: a request with one of them was passed on, not made here. */
const PROXY_HEADERS = ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip', 'forwarded', 'cf-connecting-ip', 'cf-ray', 'true-client-ip', 'cdn-loop'];

const plain = (ip: string) => (ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7)) ? ip.slice(7) : ip);

export function isLoopbackIp(ip: string | undefined): boolean {
  if (!ip) return false;
  const a = plain(ip);
  return a === '::1' || (net.isIPv4(a) && a.startsWith('127.'));
}

/** Loopback, or an address of a home network (RFC 1918, link-local, IPv6 unique local). */
export function isPrivateIp(ip: string | undefined): boolean {
  if (!ip) return false;
  const a = plain(ip);
  if (isLoopbackIp(a)) return true;
  if (net.isIPv4(a)) {
    const [p, q] = a.split('.').map(Number);
    return p === 10 || (p === 172 && q >= 16 && q <= 31) || (p === 192 && q === 168) || (p === 169 && q === 254);
  }
  const l = a.toLowerCase();
  return net.isIPv6(l) && (/^f[cd]/.test(l) || /^fe[89ab]/.test(l));
}

/** The visitor's address: from the trusted proxy's headers, else the connection's. */
export function pickIp(header: Header, socketIp: string | undefined, trust: TrustProxy): string {
  if (trust === 'cloudflare') {
    const cf = header('cf-connecting-ip')?.trim();
    if (cf && net.isIP(cf)) return cf;
  }
  if (trust !== false) {
    const hops = trust === 'cloudflare' ? 1 : trust;
    const list = (header('x-forwarded-for') ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    // The proxy nearest to us appended the last entry: count back from the right.
    const ip = list[list.length - hops];
    if (ip && net.isIP(plain(ip))) return ip;
  }
  return socketIp || 'unknown';
}

/** A request made on this computer itself (not passed on by a proxy that runs here). */
export function isLocal(header: Header, socketIp: string | undefined): boolean {
  if (!isLoopbackIp(socketIp)) return false;
  if (PROXY_HEADERS.some((h) => header(h) != null)) return false;
  const host = (header('host') ?? '').toLowerCase().replace(/:\d+$/, '');
  return host === 'localhost' || host === '[::1]' || isLoopbackIp(host);
}

/** A request straight from the home network (no proxy in between), for example the owner's laptop. */
export function isDirectLan(header: Header, socketIp: string | undefined): boolean {
  return isPrivateIp(socketIp) && !PROXY_HEADERS.some((h) => header(h) != null);
}

/** Whether the visitor reached the site over HTTPS (directly or at the proxy in front). */
export function viaHttps(c: Context): boolean {
  if (c.req.header('x-forwarded-proto')?.split(',')[0]?.trim() === 'https') return true;
  try {
    return new URL(c.req.url).protocol === 'https:';
  } catch {
    return false;
  }
}

function socketOf(c: Context): string | undefined {
  try {
    return getConnInfo(c).remote.address;
  } catch {
    return undefined;
  }
}

const honoHeader = (c: Context): Header => (name) => c.req.header(name);
const nodeHeader =
  (req: IncomingMessage): Header =>
  (name) => {
    const v = req.headers[name];
    return Array.isArray(v) ? v.join(', ') : v;
  };

export const requestIp = (c: Context, trust: TrustProxy) => pickIp(honoHeader(c), socketOf(c), trust);
export const requestIsLocal = (c: Context) => isLocal(honoHeader(c), socketOf(c));
export const requestIsDirectLan = (c: Context) => isDirectLan(honoHeader(c), socketOf(c));
export const upgradeIp = (req: IncomingMessage, trust: TrustProxy) => pickIp(nodeHeader(req), req.socket.remoteAddress, trust);

let warned = false;
/**
 * Says once in the server log that requests come through a proxy that is not trusted: every
 * visitor then looks like the same one (127.0.0.1), and shares one rate limit.
 */
export function warnUntrustedProxy(c: Context, trust: TrustProxy) {
  if (warned || trust !== false) return;
  const h = honoHeader(c);
  if (!isLoopbackIp(socketOf(c)) || !(h('x-forwarded-for') || h('cf-connecting-ip'))) return;
  warned = true;
  console.warn('WARNING: requests arrive through a proxy (X-Forwarded-For / CF-Connecting-IP) but TRUST_PROXY is off. Every visitor shares one address and one rate limit. Set TRUST_PROXY=cloudflare for Cloudflare Tunnel, or TRUST_PROXY=1 for one reverse proxy.');
}
