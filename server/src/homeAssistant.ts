import { isSwitchable, type HaEntity, type HaSettings, type HaView } from '../../shared/homeAssistant.ts';
import { rgbToXy } from '../../shared/color.ts';
import type { Db } from './db.ts';
import type { FetchResult } from './wled.ts';
import { HaSocket } from './haSocket.ts';

const KEY = { url: 'haUrl', token: 'haToken', plugs: 'haPlugs', lights: 'haLights', disabled: 'haDisabled', fps: 'haFps', inflight: 'haInflight', fade: 'haFade', direct: 'haDirect' } as const;

/** Zigbee clusters and commands for a color sent straight to a ZHA light (see HomeAssistant.set). */
const ZCL = { level: 0x0008, color: 0x0300, moveToLevel: 0x00, moveToColor: 0x07 } as const;

/** After a command to a light fails, Home Assistant reads the light again, at most this often. */
const REREAD_MS = 15_000;

/** How often a light in the layout may take a new color, per second (see HaFrames): the default, and the range. */
export const HA_FPS = { default: 2, min: 1, max: 20 } as const;
/** Commands on their way to one light at once (see HaFrames): the most. */
export const HA_INFLIGHT_MAX = 3;

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
  /** ZHA lights: the device's IEEE address and the endpoint with the color cluster (see readZha). */
  private zha = new Map<string, { ieee: string; endpoint: number }>();
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
    const disabled = parse(KEY.disabled, [] as string[], Array.isArray).filter((e) => lights.includes(e));
    return { url: this.db.getSetting(KEY.url) || '', plugs, lights, disabled };
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
    const lights = [...new Set(s.lights)];
    this.db.setSetting(KEY.lights, JSON.stringify(lights));
    this.db.setSetting(KEY.disabled, JSON.stringify([...new Set(s.disabled)].filter((id) => lights.includes(id))));
    if (token !== undefined) this.db.setSetting(KEY.token, token ?? '');
    this.cache = null;
    // A new address or token: a new connection.
    this.socket?.close();
    this.socket = null;
    if (!this.connected()) {
      this.states.clear();
      this.status = null;
    }
  }

  view(): HaView {
    return { ...this.settings(), hasToken: this.hasToken(), status: this.status, fps: this.fps(), inflight: this.inflight(), fade: this.fade(), direct: this.direct(), entities: [...this.states.values()].sort((a, b) => a.name.localeCompare(b.name)) };
  }

  /** How many colors a second a light in the layout may take (see HaFrames). */
  fps(): number {
    const n = Number(this.db.getSetting(KEY.fps));
    return Number.isFinite(n) && n >= HA_FPS.min && n <= HA_FPS.max ? n : HA_FPS.default;
  }

  setFps(n: number) {
    this.db.setSetting(KEY.fps, Math.min(HA_FPS.max, Math.max(HA_FPS.min, n)));
  }

  /** Commands on their way to one light at once (1: each waits for the light to answer the last). */
  inflight(): number {
    const n = Number(this.db.getSetting(KEY.inflight));
    return Number.isInteger(n) && n >= 1 && n <= HA_INFLIGHT_MAX ? n : 1;
  }

  /** True: each color fades in over the gap to the next; false: it changes at once. */
  fade(): boolean {
    return this.db.getSetting(KEY.fade) !== '0';
  }

  /** The way the lights in the layout take colors (see HaFrames). */
  setFrames(f: { fps: number; inflight?: number; fade?: boolean; direct?: boolean }) {
    if (f.direct != null) this.db.setSetting(KEY.direct, f.direct ? '1' : '0');
    this.setFps(f.fps);
    if (f.inflight != null) this.db.setSetting(KEY.inflight, Math.min(HA_INFLIGHT_MAX, Math.max(1, Math.round(f.inflight))));
    if (f.fade != null) this.db.setSetting(KEY.fade, f.fade ? '1' : '0');
  }

  private socket: HaSocket | null = null;

  /** The WebSocket to Home Assistant, made when first needed. */
  private ws(): HaSocket | null {
    const url = this.settings().url;
    const token = this.db.getSetting(KEY.token);
    if (!url || !token) return null;
    return (this.socket ??= new HaSocket(url, token));
  }

  close() {
    this.socket?.close();
    this.socket = null;
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

  /** Reads the state of every light and switch. Returns the ones that changed since the last read, and what each was. */
  async refresh(): Promise<{ ok: boolean; changed: (HaEntity & { from: string })[] }> {
    const r = await this.request<HaState[]>('/api/states');
    if (!r.ok) {
      this.status = { ok: false, error: r.error };
      return { ok: false, changed: [] };
    }
    if (this.status?.ok !== true) this.status = { ok: true, version: '', location: '' };
    const list = (Array.isArray(r.data) ? r.data : []).filter((s) => s && typeof s.entity_id === 'string' && isSwitchable(s.entity_id));
    // Areas and devices change seldom: read again now and then, and when a new entity comes.
    if (Date.now() - this.placesAt > PLACES_MS || list.some((s) => !this.places.has(s.entity_id))) await this.readPlaces();
    const changed: (HaEntity & { from: string })[] = [];
    const next = new Map<string, HaEntity>();
    for (const s of list) {
      const e = { ...entityOf(s, this.places.get(s.entity_id)), zigbee: this.zha.has(s.entity_id) };
      const prev = this.states.get(e.id);
      if (prev && prev.state !== e.state) changed.push({ ...e, from: prev.state });
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
    if ([...this.places.values()].some((p) => p.integration === 'zha')) await this.readZha();
  }

  /**
   * ZHA's devices (its zha/devices command, on the WebSocket): for each light, the device's IEEE
   * address and the endpoint that has the color cluster, so a color can go to it as one Zigbee
   * command (see set, direct).
   */
  private async readZha() {
    const r = await this.ws()?.send({ type: 'zha/devices' });
    if (!r?.ok || !Array.isArray(r.result)) return;
    const next = new Map<string, { ieee: string; endpoint: number }>();
    const num = (v: unknown) => (typeof v === 'number' ? v : typeof v === 'string' ? parseInt(v, v.startsWith('0x') ? 16 : 10) : NaN);
    for (const d of r.result as { ieee?: string; entities?: { entity_id?: string }[]; signature?: { endpoints?: Record<string, { input_clusters?: unknown[] }> } }[]) {
      if (typeof d?.ieee !== 'string') continue;
      const eps = Object.entries(d.signature?.endpoints ?? {}).map(([k, v]) => ({ id: num(k), clusters: (v?.input_clusters ?? []).map(num) }));
      const ep = eps.find((e) => e.clusters.includes(ZCL.color)) ?? eps.find((e) => e.clusters.includes(ZCL.level));
      if (!ep || !Number.isFinite(ep.id)) continue;
      for (const e of d.entities ?? []) if (typeof e?.entity_id === 'string' && e.entity_id.startsWith('light.')) next.set(e.entity_id, { ieee: d.ieee, endpoint: ep.id });
    }
    this.zha = next;
  }

  /** True when a color can go straight to the light as a Zigbee command (a ZHA light). */
  canDirect(id: string): boolean {
    return this.zha.has(id);
  }

  /** True: lights in the layout get their colors as Zigbee commands when they can (see set). */
  direct(): boolean {
    return this.db.getSetting(KEY.direct) === '1';
  }

  /**
   * A color straight to a ZHA light, as Zigbee commands: move to color (xy), and the level when
   * one is given, at once, instead of light.turn_on, which sends each in turn and waits for each.
   * Neither switches the light on or off: Home Assistant does not see these commands, so on and
   * off only ever go through light.turn_on and turn_off, and its state stays right.
   */
  private async zigbee(id: string, rgb: [number, number, number] | null, bri: number | null, transition: number): Promise<FetchResult<unknown>> {
    const z = this.zha.get(id)!;
    const t = Math.max(0, Math.round(transition * 10));
    const send = (cluster: number, command: number, params: Record<string, number>) =>
      this.ws()!.call('zha', 'issue_zigbee_cluster_command', null, { ieee: z.ieee, endpoint_id: z.endpoint, cluster_id: cluster, cluster_type: 'in', command_type: 'server', command, params });
    const work: Promise<{ ok: boolean; error?: string } | null>[] = [];
    if (rgb) {
      const [x, y] = rgbToXy(rgb);
      work.push(send(ZCL.color, ZCL.moveToColor, { color_x: Math.round(x * 65535), color_y: Math.round(y * 65535), transition_time: t }));
    }
    if (bri != null) work.push(send(ZCL.level, ZCL.moveToLevel, { level: Math.max(1, Math.min(254, Math.round(bri))), transition_time: t }));
    const results = await Promise.all(work);
    const bad = results.find((r) => !r || !r.ok);
    if (!bad) return { ok: true, status: 200, data: null };
    this.reread(id);
    return { ok: false, status: 0, error: bad.error ?? 'No connection to Home Assistant' };
  }

  private rereadAt = new Map<string, number>();

  /**
   * Asks Home Assistant to read a light again from the light itself (homeassistant.update_entity).
   * A Zigbee command can fail in Home Assistant even though the light took it (its answer got
   * lost): ZHA then keeps the old state, and the light shows off while it is on. At most once
   * every REREAD_MS per light.
   */
  private reread(id: string) {
    if (!id.startsWith('light.')) return;
    const now = Date.now();
    if (now - (this.rereadAt.get(id) ?? 0) < REREAD_MS) return;
    this.rereadAt.set(id, now);
    void this.ws()?.call('homeassistant', 'update_entity', id, {});
  }

  /**
   * Switches an entity on or off. A light takes a brightness (1 to 255), a color and a
   * transition (seconds) when it can; a switch only goes on or off.
   */
  async set(
    id: string,
    on: boolean,
    opts: { bri?: number | null; rgb?: [number, number, number] | null; transition?: number; via?: 'ws' | 'rest'; direct?: boolean } = {}
  ): Promise<FetchResult<unknown>> {
    // A light that is on, a color, and Zigbee commands asked for: straight to the light.
    if (opts.direct && on && opts.via !== 'rest' && this.zha.has(id) && this.states.get(id)?.state === 'on' && (opts.rgb || opts.bri != null)) {
      this.writes.set(id, Date.now());
      const r = await this.zigbee(id, opts.rgb ?? null, opts.bri ?? null, opts.transition ?? 0);
      this.writes.set(id, Date.now());
      return r;
    }
    const [domain] = id.split('.');
    const e = this.states.get(id);
    const body: Record<string, unknown> = { entity_id: id };
    if (on && domain === 'light') {
      if (opts.bri != null && e?.dimmable !== false) body.brightness = Math.max(1, Math.min(255, Math.round(opts.bri)));
      if (opts.rgb && e?.color) body.rgb_color = opts.rgb;
    }
    if (domain === 'light' && opts.transition != null) body.transition = opts.transition;
    this.writes.set(id, Date.now());
    // Over the WebSocket when it is open (or opens), else REST.
    const { entity_id: _, ...data } = body;
    const viaWs = opts.via === 'rest' ? null : await this.ws()?.call(domain, `turn_${on ? 'on' : 'off'}`, id, data);
    const r: FetchResult<unknown> = viaWs ? (viaWs.ok ? { ok: true, status: 200, data: null } : { ok: false, status: 0, error: viaWs.error }) : await this.request(`/api/services/${domain}/turn_${on ? 'on' : 'off'}`, body);
    this.writes.set(id, Date.now());
    if (r.ok && e) this.states.set(id, { ...e, state: on ? 'on' : 'off' });
    if (!r.ok) this.reread(id);
    return r;
  }
}
