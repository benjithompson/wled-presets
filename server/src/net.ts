import os from 'node:os';

export interface Range {
  label: string;
  network: number;
  broadcast: number;
  prefix: number;
}

export function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

export function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

const prefixToMask = (p: number) => (p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);

export function parseCidr(cidr: string): Range | null {
  const m = /^\s*([\d.]+)\/(\d{1,2})\s*$/.exec(String(cidr));
  if (!m) return null;
  const ip = ipToInt(m[1]);
  const prefix = Number(m[2]);
  if (ip == null || prefix > 32) return null;
  const mask = prefixToMask(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { label: `${intToIp(network)}/${prefix}`, network, broadcast, prefix };
}

export function isValidCidr(cidr: string): boolean {
  return parseCidr(cidr) !== null;
}

/** Host addresses in a range; skips network and broadcast for prefixes up to /30. */
export function hostsIn(r: Range, max: number): string[] {
  let start = r.network;
  let end = r.broadcast;
  if (r.prefix <= 30) {
    start += 1;
    end -= 1;
  }
  const out: string[] = [];
  for (let n = start; n <= end && out.length < max; n++) out.push(intToIp(n >>> 0));
  return out;
}

export interface LocalNetwork extends Range {
  ifname: string;
  address: string;
}

export function localNetworks(): LocalNetwork[] {
  const out: LocalNetwork[] = [];
  for (const [ifname, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family !== 'IPv4' || a.internal || !a.cidr) continue;
      let r = parseCidr(a.cidr);
      if (!r) continue;
      // Subnets larger than /21 (2046 hosts) take minutes to sweep. Fall back to the /24 around this host.
      if (r.prefix < 21) r = parseCidr(`${a.address}/24`)!;
      out.push({ ...r, ifname, address: a.address });
    }
  }
  return out;
}

export function inRanges(ip: string, ranges: Range[]): boolean {
  const n = ipToInt(ip);
  return n != null && ranges.some((r) => n >= r.network && n <= r.broadcast);
}
