import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { hostsIn, inRanges, localNetworks, parseCidr, type Range } from './net.ts';
import { wled } from './wled.ts';

const run = promisify(execFile);

export interface DiscoveryOptions {
  subnets?: string[];
  /** Hosts probed in addition to the subnets, for example 127.0.0.1 in development. */
  hosts?: string[];
  /** Ports probed on each address. Default: 80. */
  ports?: number[];
  concurrency?: number;
  timeoutMs?: number;
  maxHosts?: number;
  log?: (msg: string) => void;
}

export interface Found {
  host: string;
  port: number;
  name: string;
  version: string | null;
}

/** IPs the OS has seen recently. They are probed first because they are known to be alive. */
async function arpIps(log?: (m: string) => void): Promise<string[]> {
  const ips = new Set<string>();
  // /proc/net/arp exists on Linux (and in Docker with host networking) without extra tools.
  try {
    const { readFile } = await import('node:fs/promises');
    const text = await readFile('/proc/net/arp', 'utf8');
    for (const line of text.split('\n').slice(1)) {
      const ip = line.split(/\s+/)[0];
      if (ip) ips.add(ip);
    }
  } catch {
    /* not Linux */
  }
  if (ips.size === 0) {
    for (const [cmd, args] of [
      ['arp', ['-a', '-n']],
      ['ip', ['neigh', 'show']]
    ] as const) {
      try {
        const { stdout } = await run(cmd, [...args], { timeout: 1500, maxBuffer: 1 << 20 });
        for (const m of stdout.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)) ips.add(m[1]);
        if (ips.size) break;
      } catch {
        /* tool not present */
      }
    }
  }
  log?.(`ARP table: ${ips.size} address(es)`);
  return [...ips];
}

export async function discoverWled(opts: DiscoveryOptions = {}): Promise<Found[]> {
  const { concurrency = 128, timeoutMs = 700, maxHosts = 2048, log } = opts;
  const explicit = (opts.subnets ?? []).map(parseCidr).filter((r): r is Range => r !== null);
  const locals = localNetworks();
  const self = new Set(locals.map((n) => n.address));
  const ranges: Range[] = explicit.length ? explicit : locals;

  log?.(explicit.length ? `Scanning subnets: ${explicit.map((r) => r.label).join(', ')}` : `Scanning local networks: ${locals.map((n) => `${n.ifname} ${n.label}`).join(', ') || 'none'}`);

  const candidates = new Set<string>();
  for (const ip of await arpIps(log)) if (inRanges(ip, ranges)) candidates.add(ip);
  for (const r of ranges) for (const ip of hostsIn(r, maxHosts)) candidates.add(ip);
  for (const ip of self) candidates.delete(ip);

  const ports = opts.ports?.length ? opts.ports : [80];
  const found: Found[] = [];

  // Configured hosts are probed first and on their own. In the big sweep they would wait
  // behind thousands of probes, and a busy first scan could time them out.
  const extra = [...new Set((opts.hosts ?? []).map((h) => h.trim()).filter(Boolean))];
  for (const h of extra) candidates.delete(h);
  const extraResults = await Promise.all(
    extra.flatMap((host) => ports.map(async (port) => ({ host, port, r: await wled.info({ host, port }, Math.max(timeoutMs, 2000)) })))
  );
  for (const { host, port, r } of extraResults) {
    if (r.ok) found.push({ host, port, name: r.data.name || host, version: r.data.ver ?? null });
  }
  if (extra.length) log?.(`Extra hosts ${extra.join(', ')}: ${found.length} device(s)`);

  const queue = [...candidates].flatMap((host) => ports.map((port) => ({ host, port })));
  log?.(`Probing ${queue.length} address(es) on port(s) ${ports.join(', ')} with ${Math.min(concurrency, queue.length)} workers`);

  const worker = async () => {
    for (let ep = queue.shift(); ep; ep = queue.shift()) {
      const r = await wled.info(ep, timeoutMs);
      if (r.ok) found.push({ ...ep, name: r.data.name || ep.host, version: r.data.ver ?? null });
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, queue.length)) }, worker));

  log?.(`Found ${found.length} WLED device(s)`);
  return found.sort((a, b) => a.name.localeCompare(b.name));
}
