import { isSwitchable, type HaEntity, type HaSettings, type HaView } from '../../shared/homeAssistant.ts';
import type { Db } from './db.ts';
import type { FetchResult } from './wled.ts';

const KEY = { url: 'haUrl', token: 'haToken', plugs: 'haPlugs', lights: 'haLights' } as const;

const COLOR_MODES = new Set(['hs', 'xy', 'rgb', 'rgbw', 'rgbww']);

/** A Home Assistant state, as /api/states lists it. */
interface HaState {
  entity_id: string;
  state: string;
  attributes?: { friendly_name?: string; supported_color_modes?: string[]; device_class?: string };
}

/** Where an entity is in Home Assistant: its area, its device and the integration it comes from. */
type Place = { area: string; device: string; integration: string };
const NOWHERE: Place = { area: '', device: '', integration: '' };

function entityOf(s: HaState, place: Place = NOWHERE): HaEntity {
  const modes = s.attributes?.supported_color_modes ?? [];
  return {
    id: s.entity_id,
    name: s.attributes?.friendly_name || s.entity_id,
    state: s.state,
    color: modes.some((m) => COLOR_MODES.has(m)),
    dimmable: modes.some((m) => m !== 'onoff'),
    outlet: s.attributes?.device_class === 'outlet',
    ...place
  };
}

/**
 * The area, device and integration of every light and switch, in one request: /api/states has
 * none of them, and the registries are only on the WebSocket API. Home Assistant renders this
 * template (its own Jinja) to JSON: [[entity id, area, device, integration], ...].
 */
export const PLACES_TEMPLATE = [
  '{%- set ns = namespace(rows=[]) -%}',
  '{%- for s in (states.light | list) + (states.switch | list) -%}',
  '{%- set ids = device_attr(s.entity_id, "identifiers") -%}',
  '{%- set ns.rows = ns.rows + [[s.entity_id, area_name(s.entity_id) or "", device_attr(s.entity_id, "name_by_user") or device_attr(s.entity_id, "name") or "", ((ids | list | first | first) if ids else "") or ""]] -%}',
  '{%- endfor -%}',
  '{{ ns.rows | tojson }}'
].join('');

/** How long the areas and devices are kept before they are read again. */
const PLACES_MS = 10 * 60_000;

/** An address for Home Assistant: http or https, with no path. Null when it is not one. */
export function cleanHaUrl(input: string): string | null {
  const v = input.trim();
  if (!v) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) && !/^https?:\/\//i.test(v)) return null;
  try {
    const u = new URL(/^https?:\/\//i.test(v) ? v : `http://${v}`);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (u.username || u.password) return null;
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

/**
 * Talks to Home Assistant over its REST API, with a long-lived access token. The token is kept
 * in the database and only ever sent to Home Assistant: never to a browser, never to the log.
 */
export class HomeAssistant {
  private db: Db;
  private states = new Map<string, HaEntity>();
  private places = new Map<string, Place>();
  private placesAt = 0;
  private status: HaView['status'] = null;
  /** When this app last switched each entity (Date.now()): a change soon after is its own. */
  private writes = new Map<string, number>();
  /** How long a request may take (shorter in tests). */
  timeoutMs = 5000;

  constructor(db: Db) {
    this.db = db;
  }

  private cache: HaSettings | null = null;

  settings(): HaSettings {
    return (this.cache ??= this.read());
  }

  private read(): HaSettings {
    const parse = <T>(key: string, fallback: T, ok: (v: unknown) => v is T): T => {
      try {
        const v = JSON.parse(this.db.getSetting(key) || 'null');
        return ok(v) ? v : fallback;
      } catch {
        return fallback;
      }
    };
    const record = (v: unknown): v is Record<string, string> => !!v && typeof v === 'object' && !Array.isArray(v);
    const plugs = Object.fromEntries(Object.entries(parse(KEY.plugs, {}, record)).filter(([, e]) => typeof e === 'string' && isSwitchable(e)));
    const lights = parse(KEY.lights, [] as string[], Array.isArray).filter((e) => typeof e === 'string' && isSwitchable(e));
    return { url: this.db.getSetting(KEY.url) || '', plugs, lights };
  }

  hasToken(): boolean {
    return !!this.db.getSetting(KEY.token);
  }

  /** True when there is an address and a token: the site uses Home Assistant. */
  connected(): boolean {
    return !!this.settings().url && this.hasToken();
  }

  /** Saves the settings. `token`: undefined keeps the one kept, null removes it. */
  save(s: HaSettings, token?: string | null) {
    this.db.setSetting(KEY.url, s.url);
    this.db.setSetting(KEY.plugs, JSON.stringify(s.plugs));
    this.db.setSetting(KEY.lights, JSON.stringify([...new Set(s.lights)]));
    if (token !== undefined) this.db.setSetting(KEY.token, token ?? '');
    this.cache = null;
    if (!this.connected()) {
      this.states.clear();
      this.status = null;
    }
  }

  view(): HaView {
    return { ...this.settings(), hasToken: this.hasToken(), status: this.status, entities: [...this.states.values()].sort((a, b) => a.name.localeCompare(b.name)) };
  }

  /** The entity as Home Assistant last said (see refresh), or undefined. */
  entity(id: string): HaEntity | undefined {
    return this.states.get(id);
  }

  lastWrite(id: string): number {
    return this.writes.get(id) ?? 0;
  }

  private async request<T>(path: string, body?: unknown): Promise<FetchResult<T>> {
    const url = this.settings().url;
    const token = this.db.getSetting(KEY.token);
    if (!url || !token) return { ok: false, status: 0, error: 'Home Assistant is not set up' };
    try {
      const res = await fetch(url + path, {
        method: body ? 'POST' : 'GET',
        headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: 'error'
      });
      if (res.status === 401 || res.status === 403) return { ok: false, status: res.status, error: 'Home Assistant refused the token' };
      if (!res.ok) return { ok: false, status: res.status, error: `Home Assistant answered HTTP ${res.status}` };
      const text = await res.text();
      return { ok: true, status: res.status, data: (text ? JSON.parse(text) : null) as T };
    } catch (e) {
      const name = (e as Error)?.name;
      return { ok: false, status: 0, error: name === 'TimeoutError' || name === 'AbortError' ? 'Home Assistant did not answer in time' : 'Home Assistant is unreachable' };
    }
  }

  /** Asks Home Assistant who it is, and reads its lights and switches. */
  async test(): Promise<HaView['status']> {
    const r = await this.request<{ version?: string; location_name?: string }>('/api/config');
    this.status = r.ok ? { ok: true, version: r.data?.version ?? '?', location: r.data?.location_name ?? '' } : { ok: false, error: r.error };
    this.placesAt = 0;
    if (r.ok) await this.refresh();
    return this.status;
  }

  /** Reads the state of every light and switch. Returns the ones that changed since the last read. */
  async refresh(): Promise<{ ok: boolean; changed: HaEntity[] }> {
    const r = await this.request<HaState[]>('/api/states');
    if (!r.ok) {
      this.status = { ok: false, error: r.error };
      return { ok: false, changed: [] };
    }
    if (this.status?.ok !== true) this.status = { ok: true, version: '', location: '' };
    const list = (Array.isArray(r.data) ? r.data : []).filter((s) => s && typeof s.entity_id === 'string' && isSwitchable(s.entity_id));
    // Areas and devices change seldom: read again now and then, and when a new entity comes.
    if (Date.now() - this.placesAt > PLACES_MS || list.some((s) => !this.places.has(s.entity_id))) await this.readPlaces();
    const changed: HaEntity[] = [];
    const next = new Map<string, HaEntity>();
    for (const s of list) {
      const e = entityOf(s, this.places.get(s.entity_id));
      const prev = this.states.get(e.id);
      if (prev && prev.state !== e.state) changed.push(e);
      next.set(e.id, e);
    }
    this.states = next;
    return { ok: true, changed };
  }

  /** Reads where each light and switch is (see PLACES_TEMPLATE). Without it, they are nowhere. */
  private async readPlaces() {
    this.placesAt = Date.now();
    const r = await this.request<unknown>('/api/template', { template: PLACES_TEMPLATE });
    if (!r.ok || !Array.isArray(r.data)) return;
    const str = (v: unknown) => (typeof v === 'string' ? v : '');
    this.places = new Map(
      r.data.filter((row): row is unknown[] => Array.isArray(row) && typeof row[0] === 'string').map((row) => [row[0] as string, { area: str(row[1]), device: str(row[2]), integration: str(row[3]) }])
    );
  }

  /**
   * Switches an entity on or off. A light takes a brightness (1 to 255), a color and a
   * transition (seconds) when it can; a switch only goes on or off.
   */
  async set(id: string, on: boolean, opts: { bri?: number | null; rgb?: [number, number, number] | null; transition?: number } = {}): Promise<FetchResult<unknown>> {
    const [domain] = id.split('.');
    const e = this.states.get(id);
    const body: Record<string, unknown> = { entity_id: id };
    if (on && domain === 'light') {
      if (opts.bri != null && e?.dimmable !== false) body.brightness = Math.max(1, Math.min(255, Math.round(opts.bri)));
      if (opts.rgb && e?.color) body.rgb_color = opts.rgb;
    }
    if (domain === 'light' && opts.transition != null) body.transition = opts.transition;
    this.writes.set(id, Date.now());
    const r = await this.request(`/api/services/${domain}/turn_${on ? 'on' : 'off'}`, body);
    this.writes.set(id, Date.now());
    if (r.ok && e) this.states.set(id, { ...e, state: on ? 'on' : 'off' });
    return r;
  }
}
