import type { DeviceInfo, DevicePreset } from '../../shared/types.ts';
import { presetLook } from './presetLook.ts';

export interface Endpoint {
  host: string;
  port: number;
}

export type FetchResult<T> = { ok: true; status: number; data: T } | { ok: false; status: number; error: string };

/** A device's power and master brightness (1 to 255; when off, the level it comes back on at). */
export interface PowerState {
  on: boolean;
  bri: number;
}

/**
 * When this app last told each device to change its state (by base URL). A change the device
 * reports with no such request around it was made somewhere else: WLED's own app, a button,
 * one of its timers (see Lights.observe).
 */
const writes = new Map<string, number>();

/** When this app last sent the device a state change (Date.now()), or 0. */
export function lastWrite(ep: Endpoint): number {
  return writes.get(baseUrl(ep)) ?? 0;
}

function noteWrite(url: string, method: string) {
  if (method === 'GET') return;
  const m = /^(.*)\/json(?:\/state|\/si)?$/.exec(url);
  if (m) writes.set(m[1], Date.now());
}

/** The power and brightness in a WLED state object, or null when it has none. */
export function pickPower(st: any): PowerState | null {
  return typeof st?.on === 'boolean' && typeof st?.bri === 'number' ? { on: st.on, bri: st.bri } : null;
}

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
  noteWrite(url, method);
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs)
    });
    const text = await res.text();
    // The device has the change now: what it reports from here on may come from it.
    noteWrite(url, method);
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

  /**
   * Info and the power state in one request (WLED's /json/si). An old WLED without it gets
   * info only.
   */
  async infoAndPower(ep: Endpoint, timeoutMs = 1500): Promise<FetchResult<{ info: DeviceInfo; power: PowerState | null }>> {
    const r = await requestJson<{ state?: unknown; info?: unknown }>(`${baseUrl(ep)}/json/si`, { timeoutMs });
    if (r.ok && isWledInfo(r.data?.info)) return { ok: true, status: r.status, data: { info: pickInfo(r.data.info), power: pickPower(r.data.state) } };
    if (!r.ok && r.status === 0) return r;
    const i = await wled.info(ep, timeoutMs);
    return i.ok ? { ...i, data: { info: i.data, power: null } } : i;
  },

  /** The LED outputs (see DeviceInfo.outputs), from the device's settings. */
  async outputs(ep: Endpoint, timeoutMs = 3000): Promise<FetchResult<NonNullable<DeviceInfo['outputs']>>> {
    const r = await requestJson<{ hw?: { led?: { ins?: { len?: unknown; type?: unknown }[] } } }>(`${baseUrl(ep)}/json/cfg`, { timeoutMs });
    if (!r.ok) return r;
    const ins = r.data?.hw?.led?.ins;
    if (!Array.isArray(ins)) return { ok: false, status: r.status, error: 'No LED outputs in the settings' };
    return { ok: true, status: r.status, data: ins.filter((o) => typeof o?.len === 'number' && typeof o?.type === 'number').map((o) => ({ len: o.len as number, type: o.type as number })) };
  },

  /** The device's state (only what this app reads of it). */
  state(ep: Endpoint, timeoutMs = 1500) {
    return requestJson<{ on?: boolean }>(`${baseUrl(ep)}/json/state`, { timeoutMs });
  },
  /** Whether the device shows real-time data now (WLED's info says "live"). */
  async live(ep: Endpoint, timeoutMs = 1500): Promise<FetchResult<boolean>> {
    const r = await requestJson<{ live?: boolean }>(`${baseUrl(ep)}/json/info`, { timeoutMs });
    return r.ok ? { ...r, data: !!r.data?.live } : r;
  },
  setState(ep: Endpoint, state: Record<string, unknown>, timeoutMs = 2000) {
    return requestJson(`${baseUrl(ep)}/json/state`, { method: 'POST', body: state, timeoutMs });
  },

  applyPreset(ep: Endpoint, presetId: number) {
    return wled.setState(ep, { ps: presetId });
  },

  /** Sets every segment to one solid color. WLED ignores segment ids that do not exist. */
  applyColor(ep: Endpoint, [r, g, b]: [number, number, number], bri?: number | null) {
    // frz: false unfreezes a segment that a real-time preview over HTTP left frozen.
    const seg = Array.from({ length: 16 }, (_, id) => ({ id, col: [[r, g, b]], fx: 0, frz: false }));
    return wled.setState(ep, { on: true, ...(bri ? { bri } : {}), seg });
  },

  /** Switches the device on or off; `bri` (1 to 255) also sets its brightness. */
  power(ep: Endpoint, on: boolean, bri?: number | null) {
    return wled.setState(ep, { on, ...(on && bri ? { bri } : {}) });
  },

  /** Sets the device's master brightness (1 to 255). */
  brightness(ep: Endpoint, bri: number) {
    return wled.setState(ep, { bri });
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

