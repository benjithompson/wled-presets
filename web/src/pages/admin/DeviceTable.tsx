import { Fragment, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, ChevronDown, Gauge, Lightbulb, List as ListIcon, Pencil, Play, Plug, Plus, Power, Radar, RefreshCw, RotateCcw, Router, Search, SlidersHorizontal, ToggleRight, Trash2, X } from 'lucide-react';
import { toast } from 'sonner';
import type { DevicePreset, DeviceWithStatus } from '../../../../shared/types.ts';
import type { HaEntity } from '../../../../shared/homeAssistant.ts';
import { LevelSlider, PowerButton, useLightControls, useLightMutations } from '../../components/LightControls.tsx';
import { Button, Card, CardHeader, ConfirmDialog, Empty, Input, Select, Spinner, Switch } from '../../components/ui.tsx';
import { MoreButton } from '../../components/mobile.tsx';
import type { ActionItem } from '../../components/mobile.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText, relativeTime } from '../../lib/utils.ts';
import { useMedia } from '../../lib/useMedia.ts';
import { OVERVIEW } from './AdminLayout.tsx';
import { kindOf } from './EntityTable.tsx';
import { FrameSettingsDialog, SpeedTestDialog, useSaveLights } from './HaLightDialogs.tsx';
import { useHomeAssistant } from './HomeAssistantCard.tsx';
import {
  asSwitched,
  buildRows,
  commandsText,
  filterRows,
  groupRows,
  isFiltering,
  NO_FILTER,
  sortRows,
  unplugged,
  type DeviceRow,
  type GroupBy,
  type RowFilter,
  type Sort,
  type SortKey,
  type Status
} from './deviceRows.ts';

/** WLED's brightness (1 to 255) in percent, as the switches count it. */
const percent = (bri: number) => Math.max(1, Math.round((bri / 255) * 100));

/**
 * The columns showing at this width (the rest hide on smaller screens): a row across the table
 * spans exactly these, or the fixed layout would keep room for the hidden ones.
 */
function useColumns() {
  const sm = useMedia('(min-width: 640px)');
  const md = useMedia('(min-width: 768px)');
  const lg = useMedia('(min-width: 1024px)');
  const xl = useMedia('(min-width: 1280px)');
  // Power, name and actions; status and enabled; brightness and fps; LEDs; area.
  return 3 + (sm ? 2 : 0) + (md ? 2 : 0) + (lg ? 1 : 0) + (xl ? 1 : 0);
}

const GROUPS: { value: GroupBy; label: string }[] = [
  { value: 'source', label: 'Group by type' },
  { value: 'status', label: 'Group by status' },
  { value: 'area', label: 'Group by area' },
  { value: 'integration', label: 'Group by integration' },
  { value: 'none', label: 'No groups' }
];
const SORT_KEYS: SortKey[] = ['name', 'status', 'fps', 'leds', 'area'];

/** A choice kept in this browser (the table's grouping and sort), checked when read back. */
function useStored<T>(key: string, initial: T, valid: (v: unknown) => boolean): [T, (next: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      const v: unknown = raw ? JSON.parse(raw) : undefined;
      if (v !== undefined && valid(v)) return v as T;
    } catch {
      /* no storage: the default */
    }
    return initial;
  });
  const set = (next: T | ((prev: T) => T)) =>
    setValue((prev) => {
      const v = typeof next === 'function' ? (next as (p: T) => T)(prev) : next;
      try {
        localStorage.setItem(key, JSON.stringify(v));
      } catch {
        /* kept for this visit only */
      }
      return v;
    });
  return [value, set];
}

/**
 * Every light the site controls in one table: the WLED devices and the Home Assistant lights,
 * each with its power and brightness, how it is (on, off, offline, disabled), its frame rate,
 * LEDs and area, and whether the site uses it. A search, filters, grouping and sorting, as Home
 * Assistant's own tables have; the grouping and sort are kept in this browser. Above it, the
 * switch and brightness for all lights. Off holds: a light switched off here stays dark through
 * scenes, colors and games until it is switched on again.
 */
export function DeviceTable({
  devices,
  presets,
  maxFps,
  loading,
  onAdd,
  onDiscover,
  onEdit,
  onConfigure,
  onRemove
}: {
  devices: DeviceWithStatus[];
  presets: Record<string, DevicePreset[]>;
  /** The admin's frame rate limit (Settings → Frame rate). */
  maxFps: number;
  loading: boolean;
  onAdd: () => void;
  onDiscover: () => void;
  onEdit: (d: DeviceWithStatus) => void;
  onConfigure: (d: DeviceWithStatus) => void;
  onRemove: (d: DeviceWithStatus) => void;
}) {
  const qc = useQueryClient();
  const { data: controls } = useLightControls();
  const { power, brightness, switchOf } = useLightMutations();
  const { data: ha } = useHomeAssistant();
  const { data: layout } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const saveHa = useSaveLights();
  const [filter, setFilter] = useState<RowFilter>(NO_FILTER);
  const [group, setGroup] = useStored<GroupBy>('devices.group', 'source', (v) => GROUPS.some((g) => g.value === v));
  const [sort, setSort] = useStored<Sort>('devices.sort', { key: 'name', dir: 'asc' }, (v) => {
    const s = v as Partial<Sort> | null;
    return !!s && SORT_KEYS.includes(s.key as SortKey) && (s.dir === 'asc' || s.dir === 'desc');
  });
  const [folded, setFolded] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [testing, setTesting] = useState<HaEntity | null>(null);
  const [tuning, setTuning] = useState(false);
  const [removingHa, setRemovingHa] = useState<DeviceRow | null>(null);
  const columns = useColumns();

  const toggle = useMutation({
    mutationFn: (d: DeviceWithStatus) => api.updateDevice(d.id, { name: d.name, host: d.host, port: d.port, enabled: !d.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: OVERVIEW }),
    onError: (e) => toast.error(errorText(e))
  });
  const syncOne = useMutation({
    mutationFn: (id: string) => api.syncPresets(id),
    onSuccess: (r) => {
      toast.success(`Imported ${r.count} preset(s)`);
      void qc.invalidateQueries({ queryKey: OVERVIEW });
    },
    onError: (e) => toast.error(errorText(e))
  });

  const off = useMemo(() => new Set(controls?.off ?? []), [controls]);
  const haConnected = !!ha?.url && ha.hasToken;
  // A switch shows at once, as asked, while it is on its way.
  const rows = buildRows({ devices, ha, off, fixtures: layout?.fixtures ?? [] }).map((r) => asSwitched(r, switchOf(r.key)));
  const allSwitch = switchOf(null);
  const shown = sortRows(filterRows(rows, filter), sort);
  const groups = groupRows(shown, group);
  const areas = [...new Set(rows.map((r) => r.area).filter(Boolean))].sort();
  const filtering = isFiltering(filter);
  const set = (f: Partial<RowFilter>) => setFilter((x) => ({ ...x, ...f }));
  const fold = (g: string) => setFolded((f) => (f.has(g) ? new Set([...f].filter((x) => x !== g)) : new Set([...f, g])));

  // All lights: the ones that answer say how they are; an offline one cannot.
  const enabled = rows.filter((r) => r.enabled);
  const reachable = enabled.filter((r) => r.status !== 'offline');
  const lit = reachable.filter((r) => r.status === 'on').length;
  const offline = enabled.length - reachable.length;
  const allOff = reachable.length ? lit === 0 : enabled.every((r) => off.has(r.key));
  const all = controls?.brightness.all ?? null;
  const summary = allSwitch?.busy
    ? `Turning ${allSwitch.on ? 'on' : 'off'}…`
    : !reachable.length
      ? 'Offline'
      : allOff
        ? 'Off'
        : lit < reachable.length
          ? `${reachable.length - lit} of ${reachable.length} off`
          : 'On';

  const setHaEnabled = (r: DeviceRow, on: boolean) =>
    ha &&
    saveHa.mutate(
      { lights: ha.lights, disabled: on ? ha.disabled.filter((x) => x !== r.ha!.id) : [...ha.disabled, r.ha!.id] },
      { onSuccess: () => toast.success(`${r.name} ${on ? 'enabled' : 'disabled: the site leaves it alone'}`) }
    );
  const speedTest = (r: DeviceRow) =>
    setTesting(r.ha!.entity ?? { id: r.ha!.id, name: r.ha!.id, state: '', color: true, dimmable: true, outlet: false, area: '', device: '', integration: '' });

  const sortBy = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'fps' || key === 'leds' ? 'desc' : 'asc' }));
  const head = (key: SortKey, label: ReactNode, className?: string, title?: string) => (
    <th className={cn('px-2 py-2 font-medium', className)} aria-sort={sort.key === key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'} title={title}>
      <button type="button" onClick={() => sortBy(key)} className={cn('inline-flex items-center gap-1 hover:text-stone-900 dark:hover:text-white', sort.key === key && 'text-stone-800 dark:text-stone-200')}>
        {label}
        {sort.key === key ? sort.dir === 'asc' ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" /> : null}
      </button>
    </th>
  );

  /** Its power button: a light offline cannot be switched, unless its plug can. */
  const powerOf = (r: DeviceRow) => {
    const on = r.status === 'on';
    const gone = r.status === 'offline';
    if (!r.enabled) return <PowerButton size="sm" on={false} label={`${r.name} (disabled)`} disabled onToggle={() => {}} />;
    const d = r.device;
    return (
      <PowerButton
        size="sm"
        on={on}
        label={gone ? `${r.name} (offline)` : r.name}
        busy={r.switching}
        disabled={!controls || (gone && !d?.plug)}
        onToggle={() => power.mutate({ on: gone && d?.plug ? off.has(r.key) : !on, deviceId: r.key })}
      />
    );
  };

  /** Its brightness: a slider while it can take one, else why not. */
  const levelOf = (r: DeviceRow) => {
    const own = controls?.brightness.devices[r.key] ?? null;
    const reset =
      own != null ? (
        <button
          type="button"
          onClick={() => brightness.mutate({ level: null, deviceId: r.key })}
          className="grid size-7 shrink-0 place-items-center rounded-lg text-stone-400 hover:bg-stone-100 hover:text-stone-800 dark:hover:bg-stone-800 dark:hover:text-white"
          title="It has its own level. Follow the brightness of all lights again"
          aria-label={`${r.name}: follow the brightness of all lights`}
        >
          <RotateCcw className="size-3.5" />
        </button>
      ) : (
        <span className="w-7 shrink-0" />
      );
    const note = (text: ReactNode, tone?: 'red') => <span className={cn('text-sm', tone ? 'text-red-600 dark:text-red-400' : 'text-stone-500 dark:text-stone-400')}>{text}</span>;
    if (!r.enabled) return note('Left alone by the site');
    const d = r.device;
    if (d) {
      if (unplugged(d)) return note(`${d.plug!.name} is off`);
      if (d.online === false) return note(d.lastSeen ? `Last seen ${relativeTime(d.lastSeen)}` : 'Not seen yet', 'red');
      return (
        <div className="flex items-center gap-1">
          <LevelSlider
            className="min-w-0 flex-1"
            label={`Brightness of ${r.name}`}
            value={d.power ? percent(d.power.bri) : (own ?? all)}
            disabled={r.status !== 'on'}
            onCommit={(level) => brightness.mutate({ level, deviceId: r.key })}
          />
          {reset}
        </div>
      );
    }
    const e = r.ha!.entity;
    if (!e) return note('Gone from Home Assistant', 'red');
    if (e.state === 'unavailable') return note('Unavailable in Home Assistant', 'red');
    if (!e.dimmable) return note('On or off only');
    return (
      <div className="flex items-center gap-1">
        <LevelSlider className="min-w-0 flex-1" label={`Brightness of ${r.name}`} value={own ?? all} disabled={r.status !== 'on'} onCommit={(level) => brightness.mutate({ level, deviceId: r.key })} />
        {reset}
      </div>
    );
  };

  const menuOf = (r: DeviceRow): ActionItem[] => {
    const d = r.device;
    if (d) {
      const n = presets[d.id]?.length ?? 0;
      return [
        { label: `${expanded === d.id ? 'Hide' : 'Show'} presets (${n})`, icon: ChevronDown, run: () => setExpanded(expanded === d.id ? null : d.id) },
        { label: 'WLED settings', icon: SlidersHorizontal, run: () => onConfigure(d) },
        { label: 'Edit', icon: Pencil, run: () => onEdit(d) },
        { label: 'Import its presets', icon: RefreshCw, disabled: !d.enabled, run: () => syncOne.mutate(d.id) },
        { label: d.enabled ? 'Disable' : 'Enable', icon: Power, disabled: toggle.isPending, run: () => toggle.mutate(d) },
        { label: 'Remove', icon: Trash2, danger: true, run: () => onRemove(d) }
      ];
    }
    return [
      ...(r.ha!.id.startsWith('light.') ? [{ label: 'Speed test', icon: Gauge, run: () => speedTest(r) }] : []),
      { label: r.enabled ? 'Disable' : 'Enable', icon: Power, disabled: saveHa.isPending, run: () => setHaEnabled(r, !r.enabled) },
      { label: 'Remove', icon: Trash2, danger: true, run: () => setRemovingHa(r) }
    ];
  };

  const actionsOf = (r: DeviceRow) => {
    const d = r.device;
    const icon = 'max-lg:hidden';
    return (
      <div className="flex items-center justify-end gap-0.5">
        {d ? (
          <>
            <button
              type="button"
              onClick={() => setExpanded(expanded === d.id ? null : d.id)}
              aria-expanded={expanded === d.id}
              aria-label={`Presets of ${r.name}`}
              title={`${presets[d.id]?.length ?? 0} presets on it`}
              className="inline-flex h-8 items-center gap-1 rounded-lg px-2 text-[13px] font-medium whitespace-nowrap text-stone-600 tabular-nums hover:bg-stone-100 max-lg:hidden dark:text-stone-400 dark:hover:bg-stone-800"
            >
              <ListIcon className="size-3.5" />
              {presets[d.id]?.length ?? 0}
              <ChevronDown className={cn('size-3.5 transition', expanded === d.id && 'rotate-180')} />
            </button>
            <Button size="sm" variant="ghost" title="WLED settings" aria-label={`WLED settings of ${r.name}`} onClick={() => onConfigure(d)} className={icon}>
              <SlidersHorizontal />
            </Button>
            <Button size="sm" variant="ghost" title="Edit" aria-label={`Edit ${r.name}`} onClick={() => onEdit(d)} className={icon}>
              <Pencil />
            </Button>
          </>
        ) : r.ha!.id.startsWith('light.') ? (
          <Button size="sm" variant="ghost" title="Speed test: how fast can it change color?" aria-label={`Speed test of ${r.name}`} onClick={() => speedTest(r)} className={icon}>
            <Gauge />
          </Button>
        ) : null}
        <Button
          size="sm"
          variant="ghost"
          title="Remove"
          aria-label={`Remove ${r.name}`}
          onClick={() => (d ? onRemove(d) : setRemovingHa(r))}
          className={cn('hover:text-red-600 dark:hover:text-red-400', icon)}
        >
          <Trash2 />
        </Button>
        <MoreButton className="lg:hidden" label={`More for ${r.name}`} title={r.name} items={menuOf(r)} />
      </div>
    );
  };

  /** What it is, in a few words under its name. */
  const detailsOf = (r: DeviceRow) => {
    const d = r.device;
    const e = r.ha?.entity;
    const bits: ReactNode[] = [<span key="addr" className="font-mono">{r.address}</span>];
    if (d?.info?.ver) bits.push(<span key="ver">WLED {d.info.ver}</span>);
    if (d && r.enabled && d.online && typeof d.info?.wifi?.signal === 'number') bits.push(<span key="wifi">Wi-Fi {d.info.wifi.signal}%</span>);
    if (r.fps != null) bits.push(<span key="fps" className="md:hidden">{r.sending ? `${r.fps} fps` : `${r.fps} fps on its own`}</span>);
    if (r.leds != null) bits.push(<span key="leds" className="lg:hidden">{r.leds} LEDs</span>);
    if (e) bits.push(<span key="kind">{kindOf(e) === 'light' ? (e.color ? 'Color' : e.dimmable ? 'Dims' : 'On and off') : kindOf(e) === 'outlet' ? 'Plug' : 'Switch'}</span>);
    if (r.area) bits.push(<span key="area" className="xl:hidden">{r.area}</span>);
    bits.push(
      <span key="layout" title={r.objects.join(', ') || undefined}>
        {!r.objects.length ? 'Not in the layout' : r.objects.length <= 2 ? `In the layout: ${r.objects.join(', ')}` : `${r.objects.length} objects in the layout`}
      </span>
    );
    if (r.ha?.commands) {
      const c = commandsText(r.ha.commands);
      bits.push(
        <span
          key="commands"
          className={cn('w-full tabular-nums', c.behind && 'text-amber-600 dark:text-amber-400')}
          title="Debug (Settings → Debug): how long Home Assistant takes to answer the site's commands to this light. Each light takes one at a time; one asked meanwhile waits (the newest). Late: answered after the site stopped waiting (5 s)."
        >
          {c.text}
        </span>
      );
    }
    return bits;
  };

  if (loading) {
    return (
      <Card className="grid place-items-center py-16">
        <Spinner />
      </Card>
    );
  }

  if (!rows.length) {
    return (
      <Card>
        <Empty
          icon={<Router />}
          title="No devices yet"
          action={
            <div className="flex flex-wrap justify-center gap-2">
              <Button onClick={onDiscover}>
                <Radar /> Scan the network
              </Button>
              <Button variant="primary" onClick={onAdd}>
                <Plus /> Add by address
              </Button>
            </div>
          }
        >
          Scan the network to find WLED devices, or add one by its IP address.{haConnected ? ' Home Assistant lights can be added from the menu above.' : ''}
        </Empty>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Lights"
        description={
          allOff && enabled.length
            ? 'Every light is off. Visitors cannot change them, games cannot start, and the auto-revert waits, until you switch them on.'
            : 'Switch the lights on or off and set how bright they are. A light switched off stays off through scenes, colors and games.'
        }
        actions={
          haConnected && ha.lights.length ? (
            <Button size="sm" variant="ghost" title="How the Home Assistant lights in the layout take colors" onClick={() => setTuning(true)}>
              <SlidersHorizontal /> <span className="max-sm:hidden">{`Home Assistant: ${ha.fps}/s · ${ha.fade ? 'fade' : 'instant'}${ha.direct ? ' · Zigbee' : ''}`}</span>
            </Button>
          ) : null
        }
      />

      {enabled.length ? (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-3 border-b border-stone-100 px-4 py-4 sm:px-5 dark:border-stone-800">
          <PowerButton on={allSwitch ? allSwitch.on : !allOff} busy={allSwitch?.busy} label="All lights" disabled={!controls} onToggle={() => power.mutate({ on: allOff })} />
          <div className="min-w-0">
            <p className="font-medium">All lights</p>
            <p className="text-sm text-stone-500 dark:text-stone-400">
              {summary}
              {offline && reachable.length ? <span className="text-red-600 dark:text-red-400">{` · ${offline} offline`}</span> : null}
            </p>
          </div>
          <LevelSlider className="min-w-56 flex-1" label="Brightness of all lights" value={all} onCommit={(level) => brightness.mutate({ level })} />
          {all != null ? (
            <button
              type="button"
              onClick={() => brightness.mutate({ level: null })}
              className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-stone-500 hover:bg-stone-100 hover:text-stone-800 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white"
              title="Each scene's presets set the brightness again"
            >
              <RotateCcw className="size-3.5" /> Let scenes decide
            </button>
          ) : null}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2 border-b border-stone-100 bg-stone-50/70 px-3 py-2 sm:px-4 dark:border-stone-800 dark:bg-stone-900">
        <label className="relative min-w-48 flex-1 max-sm:basis-full">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-stone-400" aria-hidden />
          <Input value={filter.query} onChange={(e) => set({ query: e.target.value })} placeholder="Search name, address, entity ID, area" className="h-9 pr-8 pl-9" aria-label="Search the devices" />
          {filter.query ? (
            <button type="button" onClick={() => set({ query: '' })} className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-stone-400 hover:text-stone-700 dark:hover:text-stone-200" aria-label="Clear the search">
              <X className="size-4" />
            </button>
          ) : null}
        </label>
        {rows.some((r) => r.source === 'ha') ? (
          <Select aria-label="Type" className="h-9 !w-auto" value={filter.source} onChange={(e) => set({ source: e.target.value as RowFilter['source'] })}>
            <option value="all">All types</option>
            <option value="wled">WLED</option>
            <option value="ha">Home Assistant</option>
          </Select>
        ) : null}
        <Select aria-label="Status" className="h-9 !w-auto" value={filter.status} onChange={(e) => set({ status: e.target.value as RowFilter['status'] })}>
          <option value="all">Any status</option>
          <option value="on">On</option>
          <option value="off">Off</option>
          <option value="offline">Offline</option>
          <option value="disabled">Disabled</option>
        </Select>
        {areas.length ? (
          <Select aria-label="Area" className="h-9 !w-auto" value={filter.area} onChange={(e) => set({ area: e.target.value })}>
            <option value="">All areas</option>
            {areas.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
            <option value="-">No area</option>
          </Select>
        ) : null}
        <Select aria-label="In the layout" className="h-9 !w-auto" value={filter.layout} onChange={(e) => set({ layout: e.target.value as RowFilter['layout'] })}>
          <option value="all">In the layout or not</option>
          <option value="in">In the layout</option>
          <option value="out">Not in the layout</option>
        </Select>
        <Select aria-label="Group by" className="h-9 !w-auto" value={group} onChange={(e) => setGroup(e.target.value as GroupBy)}>
          {GROUPS.map((g) => (
            <option key={g.value} value={g.value}>
              {g.label}
            </option>
          ))}
        </Select>
        {filtering ? (
          <Button size="sm" variant="ghost" onClick={() => setFilter(NO_FILTER)}>
            <X /> Clear filters
          </Button>
        ) : null}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full table-fixed text-left text-sm">
          <thead className="text-xs text-stone-500 dark:text-stone-400">
            <tr className="border-b border-stone-100 dark:border-stone-800">
              <th className="w-12 py-2 pr-1 pl-3 font-medium sm:pl-4">
                <span className="sr-only">Power</span>
              </th>
              {head('name', 'Name', 'pl-1')}
              {head('status', 'Status', 'hidden w-24 sm:table-cell')}
              <th className="hidden w-48 px-2 py-2 font-medium md:table-cell xl:w-60">Brightness</th>
              {head('fps', 'FPS', 'hidden w-14 text-right md:table-cell [&>button]:flex-row-reverse', `Frames a second the site sends each WLED device while effects, games and previews play: at most ${maxFps} (Settings → Frame rate), fewer for a long strip or one that fell behind. Grey: the site sends it nothing now, and this is the device's own rate.`)}
              {head('leds', 'LEDs', 'hidden w-16 text-right lg:table-cell [&>button]:flex-row-reverse')}
              {head('area', 'Area', 'hidden w-28 xl:table-cell')}
              <th className="hidden w-20 px-2 py-2 font-medium sm:table-cell" title="Disabled: the site leaves it alone">
                Enabled
              </th>
              <th className="w-14 py-2 pr-3 pl-2 sm:pr-4 lg:w-44">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          {groups.map(([g, list]) => (
            <tbody key={g || 'all'} className="divide-y divide-stone-100 border-b border-stone-100 last:border-b-0 dark:divide-stone-800/70 dark:border-stone-800">
              {group !== 'none' ? (
                <tr className="bg-stone-50 dark:bg-stone-900/80">
                  <th colSpan={columns} className="p-0">
                    <button type="button" onClick={() => fold(g)} className="flex w-full items-center gap-1.5 px-3 py-1.5 text-left text-xs font-semibold text-stone-600 sm:px-4 dark:text-stone-300" aria-expanded={!folded.has(g)}>
                      <ChevronDown className={cn('size-3.5 transition-transform', folded.has(g) && '-rotate-90')} />
                      {g}
                      <span className="font-normal text-stone-400">{list.length}</span>
                    </button>
                  </th>
                </tr>
              ) : null}
              {folded.has(g)
                ? null
                : list.map((r) => {
                    const open = !!r.device && expanded === r.key;
                    return (
                      <Fragment key={r.key}>
                        <tr className="hover:bg-stone-50/70 dark:hover:bg-stone-900/50">
                          <td className="py-2.5 pr-1 pl-3 align-middle sm:pl-4">{powerOf(r)}</td>
                          <td className="py-2.5 pr-2 pl-1">
                            <div className={cn('flex min-w-0 items-center gap-2', !r.enabled && 'opacity-60')}>
                              <RowIcon row={r} />
                              <span className="truncate font-medium">{r.name}</span>
                              <StatusBadge row={r} className="sm:hidden" />
                            </div>
                            <div className={cn('mt-0.5 flex flex-wrap gap-x-2.5 text-xs text-stone-500 dark:text-stone-400', !r.enabled && 'opacity-60')}>{detailsOf(r)}</div>
                            <div className="mt-2 md:hidden">{levelOf(r)}</div>
                          </td>
                          <td className="hidden px-2 py-2.5 sm:table-cell">
                            <StatusBadge row={r} />
                          </td>
                          <td className="hidden px-2 py-2.5 md:table-cell">{levelOf(r)}</td>
                          <td className="hidden px-2 py-2.5 text-right tabular-nums md:table-cell">{fpsOf(r, ha?.fps)}</td>
                          <td className="hidden px-2 py-2.5 text-right text-stone-600 tabular-nums lg:table-cell dark:text-stone-300">{r.leds ?? <span className="text-stone-400">—</span>}</td>
                          <td className="hidden truncate px-2 py-2.5 text-stone-600 xl:table-cell dark:text-stone-300" title={r.area || undefined}>
                            {r.area || <span className="text-stone-400">—</span>}
                          </td>
                          <td className="hidden px-2 py-2.5 sm:table-cell">
                            <Switch
                              label={`${r.name} enabled`}
                              checked={r.enabled}
                              disabled={r.device ? toggle.isPending : saveHa.isPending}
                              onChange={(on) => (r.device ? toggle.mutate(r.device) : setHaEnabled(r, on))}
                            />
                          </td>
                          <td className="py-2.5 pr-2 pl-1 sm:pr-3">{actionsOf(r)}</td>
                        </tr>
                        {open && r.device ? (
                          <tr>
                            <td colSpan={columns} className="bg-stone-50/60 px-4 py-4 sm:px-5 dark:bg-stone-950/40">
                              <PresetsPanel device={r.device} presets={presets[r.key] ?? []} importing={syncOne.isPending && syncOne.variables === r.key} onImport={() => syncOne.mutate(r.key)} />
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
            </tbody>
          ))}
        </table>
        {!shown.length ? (
          <div className="px-3 py-10 text-center text-sm text-stone-500">
            Nothing matches these filters.{' '}
            <button type="button" onClick={() => setFilter(NO_FILTER)} className="font-medium text-stone-800 underline underline-offset-2 dark:text-stone-200">
              Clear them
            </button>
          </div>
        ) : null}
      </div>

      <div className="flex flex-wrap justify-between gap-x-4 gap-y-1 border-t border-stone-100 px-3 py-2 text-xs text-stone-500 sm:px-4 dark:border-stone-800">
        <span>{shown.length === rows.length ? `${rows.length} device${rows.length === 1 ? '' : 's'}` : `${shown.length} of ${rows.length} devices`}</span>
        <span>
          {haConnected ? null : (
            <>
              Connect Home Assistant under{' '}
              <Link to="/admin/settings" className="font-medium text-stone-700 underline underline-offset-2 dark:text-stone-300">
                Settings
              </Link>{' '}
              to add its lights here.{' '}
            </>
          )}
          {`WLED devices get at most ${maxFps} frames a second.`}
        </span>
      </div>

      {testing && ha ? <SpeedTestDialog light={testing} view={ha} onClose={() => setTesting(null)} /> : null}
      {tuning && ha ? <FrameSettingsDialog view={ha} onClose={() => setTuning(false)} /> : null}
      <ConfirmDialog
        open={!!removingHa}
        title={`Remove "${removingHa?.name}"?`}
        confirmLabel="Remove light"
        danger
        loading={saveHa.isPending}
        onConfirm={() =>
          removingHa &&
          ha &&
          saveHa.mutate(
            ha.lights.filter((x) => x !== removingHa.ha!.id),
            {
              onSuccess: () => {
                toast.success(`${removingHa.name} removed`);
                setRemovingHa(null);
              }
            }
          )
        }
        onClose={() => setRemovingHa(null)}
      >
        The site stops switching it and sending it colors. It stays as it is in Home Assistant, and it can be added again.
      </ConfirmDialog>
    </Card>
  );
}

/**
 * A WLED device's frame rate: while the site sends it frames, how many a second (amber when it
 * is held to fewer, or shows under half of them); else, greyed, the rate it says it runs at on
 * its own. For a Home Assistant light in the layout, the most colors a second it takes.
 */
function fpsOf(r: DeviceRow, haFps: number | undefined) {
  if (r.sending) {
    const behind = r.shows != null && r.shows < r.sending.fps * 0.5;
    const said = r.shows == null ? '' : ` The device counts ${r.shows}${behind ? ': it is not keeping up.' : ' (WLED counts high when frames arrive unevenly over Wi-Fi).'}`;
    return (
      <span
        className={cn((r.sending.held || behind) && 'font-medium text-amber-600 dark:text-amber-400')}
        title={`The site sends it up to ${r.sending.fps} frames a second${r.sending.held ? ', fewer than the limit: it fell behind, and gets more again once it keeps up' : ''}.${said}`}
      >
        {r.sending.fps}
      </span>
    );
  }
  if (r.shows != null) {
    return (
      <span className="text-stone-400" title="The site sends it no frames now: this is the rate it says it runs its own effects at, which the site's limit does not set">
        {r.shows}
      </span>
    );
  }
  if (r.ha && r.objects.length && r.enabled && haFps) {
    return (
      <span className="text-stone-400" title="Colors a second it takes at most while effects and games play (Home Assistant light settings)">
        ≤{haFps}
      </span>
    );
  }
  return <span className="text-stone-400">—</span>;
}

const STATUS_TONE: Record<Status, string> = {
  on: 'bg-accent-400/15 text-accent-700 dark:text-accent-300',
  off: 'bg-stone-100 text-stone-600 dark:bg-stone-800 dark:text-stone-300',
  offline: 'bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400',
  disabled: 'bg-transparent text-stone-500 ring-1 ring-inset ring-stone-200 dark:text-stone-400 dark:ring-stone-700'
};

function StatusBadge({ row, className }: { row: DeviceRow; className?: string }) {
  const d = row.device;
  const title = d?.online === false && d.lastSeen ? `Last seen ${relativeTime(d.lastSeen)}` : row.status === 'disabled' ? 'Gets no commands and is not checked' : undefined;
  return (
    <span className={cn('inline-flex shrink-0 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap', STATUS_TONE[row.status], className)} title={title}>
      {row.statusText}
    </span>
  );
}

/** A WLED controller, or what the Home Assistant entity is, lit while it is on. */
function RowIcon({ row }: { row: DeviceRow }) {
  const e = row.ha?.entity;
  const Icon = row.device ? Router : e ? { light: Lightbulb, outlet: Plug, switch: ToggleRight }[kindOf(e)] : Lightbulb;
  return (
    <Icon
      className={cn('size-4 shrink-0', row.status === 'on' ? 'text-accent-500' : row.status === 'offline' ? 'text-red-400' : 'text-stone-400')}
      aria-label={row.device ? 'WLED' : 'Home Assistant'}
    />
  );
}

function PresetsPanel({ device, presets, importing, onImport }: { device: DeviceWithStatus; presets: DevicePreset[]; importing: boolean; onImport: () => void }) {
  return (
    <>
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-sm text-stone-500">Presets stored on {device.name}. Play one to test it.</p>
        <Button size="sm" onClick={onImport} loading={importing} disabled={!device.enabled}>
          <RefreshCw /> Import
        </Button>
      </div>
      {presets.length ? (
        <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
          {presets.map((p) => (
            <PresetChip key={p.id} deviceId={device.id} id={p.id} name={p.name} disabled={!device.enabled || device.online === false} />
          ))}
        </div>
      ) : (
        <p className="text-sm text-stone-500">No presets imported yet.</p>
      )}
    </>
  );
}

function PresetChip({ deviceId, id, name, disabled }: { deviceId: string; id: number; name: string; disabled: boolean }) {
  const play = useMutation({
    mutationFn: () => api.applyDevicePreset(deviceId, id),
    onError: (e) => toast.error(errorText(e))
  });
  return (
    <div className="flex items-center gap-2 rounded-lg bg-white px-3 py-1.5 text-sm ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
      <span className="w-6 shrink-0 text-xs text-stone-400 tabular-nums">{id}</span>
      <span className="min-w-0 flex-1 truncate">{name}</span>
      <button
        type="button"
        aria-label={`Play ${name}`}
        disabled={disabled || play.isPending}
        onClick={() => play.mutate()}
        className="grid size-6 place-items-center rounded-md text-stone-400 hover:bg-stone-100 hover:text-stone-900 disabled:opacity-30 dark:hover:bg-stone-800 dark:hover:text-white"
      >
        {play.isPending ? <Spinner className="size-3.5" /> : <Play className="size-3.5" />}
      </button>
    </div>
  );
}
