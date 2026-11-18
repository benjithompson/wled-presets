import type { DeviceInfo, DevicePreset } from '../../shared/types.ts';
import { presetLook } from './presetLook.ts';

export interface Endpoint {
  host: string;
  port: number;
}

export type FetchResult<T> = { ok: true; status: number; data: T } | { ok: false; status: number; error: string };

export function normalizeHost(host: string): string {
  return String(host || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '');
}

export function baseUrl({ host, port }: Endpoint): string {
  const h = normalizeHost(host);
  const bracketed = h.includes(':') && !h.startsWith('[') ? `[${h}]` : h;
  return port && port !== 80 ? `http://${bracketed}:${port}` : `http://${bracketed}`;
}

export async function requestJson<T = unknown>(
  url: string,
  { method = 'GET', body, timeoutMs = 1500 }: { method?: string; body?: unknown; timeoutMs?: number } = {}
): Promise<FetchResult<T>> {
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs)
    });
    const text = await res.text();
    if (!res.ok) return { ok: false, status: res.status, error: `HTTP ${res.status}` };
    try {
      return { ok: true, status: res.status, data: (text ? JSON.parse(text) : null) as T };
    } catch {
      return { ok: false, status: res.status, error: 'Response is not JSON' };
    }
  } catch (e) {
    const name = (e as Error)?.name;
    return { ok: false, status: 0, error: name === 'TimeoutError' || name === 'AbortError' ? 'Timed out' : 'Unreachable' };
  }
}

export function isWledInfo(data: unknown): data is DeviceInfo {
  if (!data || typeof data !== 'object') return false;
  const d = data as Record<string, unknown>;
  return typeof d.ver === 'string' || (typeof d.leds === 'object' && d.leds !== null && 'count' in d.leds);
}

export function pickInfo(d: any): DeviceInfo {
  return {
    ver: d?.ver,
    name: d?.name,
    mac: d?.mac,
    arch: d?.arch,
    leds: d?.leds ? { count: d.leds.count } : undefined,
    wifi: d?.wifi ? { signal: d.wifi.signal } : undefined,
    udpport: typeof d?.udpport === 'number' ? d.udpport : undefined,
    ddpport: typeof d?.ddpport === 'number' ? d.ddpport : undefined
  };
}

export const wled = {
  async info(ep: Endpoint, timeoutMs = 1500): Promise<FetchResult<DeviceInfo>> {
    const r = await requestJson(`${baseUrl(ep)}/json/info`, { timeoutMs });
    if (!r.ok) return r;
    if (!isWledInfo(r.data)) return { ok: false, status: r.status, error: 'Not a WLED device' };
    return { ok: true, status: r.status, data: pickInfo(r.data) };
  },

  /** The LED outputs (see DeviceInfo.outputs), from the device's settings. */
  async outputs(ep: Endpoint, timeoutMs = 3000): Promise<FetchResult<NonNullable<DeviceInfo['outputs']>>> {
    const r = await requestJson<{ hw?: { led?: { ins?: { len?: unknown; type?: unknown }[] } } }>(`${baseUrl(ep)}/json/cfg`, { timeoutMs });
    if (!r.ok) return r;
    const ins = r.data?.hw?.led?.ins;
    if (!Array.isArray(ins)) return { ok: false, status: r.status, error: 'No LED outputs in the settings' };
    return { ok: true, status: r.status, data: ins.filter((o) => typeof o?.len === 'number' && typeof o?.type === 'number').map((o) => ({ len: o.len as number, type: o.type as number })) };
  },

  setState(ep: Endpoint, state: Record<string, unknown>) {
    return requestJson(`${baseUrl(ep)}/json/state`, { method: 'POST', body: state, timeoutMs: 2000 });
  },

  applyPreset(ep: Endpoint, presetId: number) {
    return wled.setState(ep, { ps: presetId });
  },

  /** Sets every segment to one solid color. WLED ignores segment ids that do not exist. */
  applyColor(ep: Endpoint, [r, g, b]: [number, number, number]) {
    // frz: false unfreezes a segment that a real-time preview over HTTP left frozen.
    const seg = Array.from({ length: 16 }, (_, id) => ({ id, col: [[r, g, b]], fx: 0, frz: false }));
    return wled.setState(ep, { on: true, seg });
  },

  async presets(ep: Endpoint): Promise<FetchResult<DevicePreset[]>> {
    const r = await requestJson<Record<string, any>>(`${baseUrl(ep)}/presets.json`, { timeoutMs: 3000 });
    if (!r.ok) return r;
    return { ok: true, status: r.status, data: parsePresets(r.data) };
  }
};

export function parsePresets(json: Record<string, any> | null): DevicePreset[] {
  const out: DevicePreset[] = [];
  for (const [key, value] of Object.entries(json ?? {})) {
    const id = Number(key);
    if (!Number.isInteger(id) || id < 1) continue; // "0" is WLED's placeholder entry
    const name = value && typeof value === 'object' ? String(value.n ?? '').trim() : '';
    out.push({ id, name: name || `Preset ${id}`, ...presetLook(id, json ?? {}) });
  }
  return out.sort((a, b) => a.id - b.id);
}

export function hexToRgb(hex: string): [number, number, number] | null {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
