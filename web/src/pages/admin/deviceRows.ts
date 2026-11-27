// The Devices page's table: every light the site controls, WLED devices and Home Assistant
// lights alike, as rows to filter, group and sort (see DeviceTable).
import type { DeviceWithStatus } from '../../../../shared/types.ts';
import { haId, type HaCommandStats, type HaEntity, type HaView } from '../../../../shared/homeAssistant.ts';

export type Source = 'wled' | 'ha';
/** How a row stands: lit, dark, not answering, or left alone by the site. */
export type Status = 'on' | 'off' | 'offline' | 'disabled';

export interface DeviceRow {
  /** Its id in the lights' switches: a WLED device's id, or ha:<entity id>. */
  key: string;
  source: Source;
  name: string;
  /** Host (and port when not 80) of a WLED device; entity id of a Home Assistant light. */
  address: string;
  enabled: boolean;
  status: Status;
  /** The status in words: On, Off, Plug off, Offline, Starting up, Unavailable, Disabled… */
  statusText: string;
  /** Home Assistant's area ('' for WLED devices, which have none). */
  area: string;
  /** WLED, or the integration a Home Assistant light comes from. */
  integration: string;
  leds: number | null;
  /**
   * The frames a second in its FPS column: what the site sends a WLED device while it gets
   * frames, else what the device says it shows on its own (null: offline, disabled, or not WLED).
   */
  fps: number | null;
  /** The most frames a second the site sends it now (null: none lately); held: fewer, as it fell behind. */
  sending: { fps: number; held: boolean } | null;
  /**
   * The frames a second the device says it shows. WLED averages 1000 / the gap between frames,
   * so frames that come over Wi-Fi in bunches read higher than they are.
   */
  shows: number | null;
  /** The layout's objects that use it. */
  objects: string[];
  device?: DeviceWithStatus;
  /**
   * A Home Assistant light: its entity id, what Home Assistant says of it (none: gone from it),
   * and how it takes the site's commands (only with Settings → Debug on).
   */
  ha?: { id: string; entity: HaEntity | undefined; commands?: HaCommandStats };
}

const NO_COMMANDS: HaCommandStats = { answered: 0, late: 0, failed: 0, lastMs: 0, avgMs: 0, maxMs: 0, going: 0, waiting: 0, goingMs: 0 };

/** A time in ms, short: 320 ms, 4.8 s, 42 s. */
const short = (ms: number) => (ms < 1000 ? `${Math.round(ms)} ms` : ms < 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms / 1000)} s`);

/**
 * How a Home Assistant light takes its commands, in a few words (see HaCommandStats), and
 * whether it is behind: slow to answer, or commands waiting for it.
 */
export function commandsText(c: HaCommandStats): { text: string; behind: boolean } {
  const bits: string[] = [];
  if (c.answered) bits.push(`answers in ${short(c.lastMs)} (avg ${short(c.avgMs)}, max ${short(c.maxMs)})`);
  if (c.going) bits.push(`${c.going} on its way${c.goingMs >= 1000 ? ` for ${short(c.goingMs)}` : ''}`);
  if (c.waiting) bits.push(`${c.waiting} waiting`);
  if (c.late) bits.push(`${c.late} of ${c.answered} late`);
  if (c.failed) bits.push(`${c.failed} failed`);
  const text = bits.length ? `Commands: ${bits.join(' · ')}` : 'Commands: none yet';
  return { text, behind: c.avgMs > 2000 || c.goingMs > 5000 || c.waiting > 0 || c.failed > 0 };
}

/** What the rows are built from. `off`: the lights switched off here (LightControls.off). */
export interface RowSources {
  devices: DeviceWithStatus[];
  ha: HaView | undefined;
  off: ReadonlySet<string>;
  fixtures: { name: string; deviceId: string | null }[];
}

/** A device whose plug is off does not answer, and that is as it should be. */
export const unplugged = (d: DeviceWithStatus) => d.online === false && !!d.plug && d.plug.on === false;

/** On, as the site counts it: held off here wins over what Home Assistant says. */
export const haIsOn = (id: string, state: string, off: ReadonlySet<string>) => (off.has(haId(id)) ? false : state !== 'off');

export function buildRows({ devices, ha, off, fixtures }: RowSources): DeviceRow[] {
  const objectsOf = (id: string) => fixtures.filter((f) => f.deviceId === id).map((f) => f.name);
  const rows: DeviceRow[] = devices.map((d) => {
    const [status, statusText] = wledStatus(d, off);
    const live = d.enabled && d.online === true;
    const shows = live && typeof d.info?.leds?.fps === 'number' ? d.info.leds.fps : null;
    const sending = live ? (d.sending ?? null) : null;
    return {
      key: d.id,
      source: 'wled',
      name: d.name,
      address: d.port !== 80 ? `${d.host}:${d.port}` : d.host,
      enabled: d.enabled,
      status,
      statusText,
      area: '',
      integration: 'WLED',
      leds: d.info?.leds?.count ?? null,
      fps: sending ? sending.fps : shows,
      sending,
      shows,
      objects: objectsOf(d.id),
      device: d
    };
  });
  if (ha?.url && ha.hasToken) {
    const byId = new Map(ha.entities.map((e) => [e.id, e]));
    for (const id of ha.lights) {
      const e = byId.get(id);
      const enabled = !ha.disabled.includes(id);
      const on = !!e && haIsOn(id, e.state, off);
      const [status, statusText]: [Status, string] = !enabled
        ? ['disabled', 'Disabled']
        : !e
          ? ['offline', 'Missing']
          : e.state === 'unavailable'
            ? ['offline', 'Unavailable']
            : on
              ? ['on', 'On']
              : ['off', 'Off'];
      rows.push({
        key: haId(id),
        source: 'ha',
        name: e?.name ?? id,
        address: id,
        enabled,
        status,
        statusText,
        area: e?.area ?? '',
        integration: e?.integration || 'Home Assistant',
        leds: null,
        fps: null,
        sending: null,
        shows: null,
        objects: objectsOf(haId(id)),
        ha: { id, entity: e, ...(ha.commands ? { commands: ha.commands[id] ?? NO_COMMANDS } : {}) }
      });
    }
  }
  return rows;
}

function wledStatus(d: DeviceWithStatus, off: ReadonlySet<string>): [Status, string] {
  if (!d.enabled) return ['disabled', 'Disabled'];
  if (unplugged(d)) return ['off', 'Plug off'];
  if (d.online === false) return ['offline', d.plug && !off.has(d.id) ? 'Starting up' : 'Offline'];
  const on = d.power ? d.power.on : !off.has(d.id);
  return [on ? 'on' : 'off', d.online === null ? 'Checking' : on ? 'On' : 'Off'];
}

export interface RowFilter {
  query: string;
  source: 'all' | Source;
  status: 'all' | Status;
  /** '' every area, '-' no area, else that area. */
  area: string;
  layout: 'all' | 'in' | 'out';
}
export const NO_FILTER: RowFilter = { query: '', source: 'all', status: 'all', area: '', layout: 'all' };
export const isFiltering = (f: RowFilter) => f.query.trim() !== '' || f.source !== 'all' || f.status !== 'all' || f.area !== '' || f.layout !== 'all';

export function filterRows(rows: DeviceRow[], f: RowFilter): DeviceRow[] {
  const words = f.query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return rows.filter((r) => {
    if (f.source !== 'all' && r.source !== f.source) return false;
    if (f.status !== 'all' && r.status !== f.status) return false;
    if (f.area && (f.area === '-' ? r.area : r.area !== f.area)) return false;
    if (f.layout !== 'all' && (f.layout === 'in') !== r.objects.length > 0) return false;
    const text = [r.name, r.address, r.area, r.integration, r.statusText, r.device?.info?.ver ?? '', ...r.objects].join(' ').toLowerCase();
    return words.every((w) => text.includes(w));
  });
}

export type SortKey = 'name' | 'status' | 'fps' | 'leds' | 'area';
export interface Sort {
  key: SortKey;
  dir: 'asc' | 'desc';
}

const STATUS_ORDER: Record<Status, number> = { on: 0, off: 1, offline: 2, disabled: 3 };
const STATUS_NAME: Record<Status, string> = { on: 'On', off: 'Off', offline: 'Offline', disabled: 'Disabled' };

/** Sorted by `sort`, then by name. Rows with nothing to sort by (no fps, no area) go last either way. */
export function sortRows(rows: DeviceRow[], sort: Sort): DeviceRow[] {
  const value = (r: DeviceRow): string | number | null =>
    sort.key === 'name' ? r.name.toLowerCase() : sort.key === 'status' ? STATUS_ORDER[r.status] : sort.key === 'area' ? r.area.toLowerCase() || null : r[sort.key];
  const sign = sort.dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = value(a);
    const y = value(b);
    if (x !== y) {
      if (x == null) return 1;
      if (y == null) return -1;
      return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * sign;
    }
    return a.name.localeCompare(b.name) || a.key.localeCompare(b.key);
  });
}

export type GroupBy = 'source' | 'status' | 'area' | 'integration' | 'none';

/** The rows in groups, in a fixed order (WLED first; On, Off, Offline, Disabled; "No area" last). */
export function groupRows(rows: DeviceRow[], by: GroupBy): [string, DeviceRow[]][] {
  if (by === 'none') return [['', rows]];
  const label = (r: DeviceRow) => (by === 'source' ? (r.source === 'wled' ? 'WLED' : 'Home Assistant') : by === 'status' ? STATUS_NAME[r.status] : by === 'area' ? r.area || 'No area' : r.integration);
  const groups = new Map<string, DeviceRow[]>();
  for (const r of rows) groups.set(label(r), [...(groups.get(label(r)) ?? []), r]);
  const rank = (g: string) =>
    by === 'source' ? (g === 'WLED' ? 0 : 1) : by === 'status' ? Object.values(STATUS_NAME).indexOf(g) : by === 'integration' ? (g === 'WLED' ? 0 : 1) : g === 'No area' ? 1 : 0;
  return [...groups].sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b));
}
