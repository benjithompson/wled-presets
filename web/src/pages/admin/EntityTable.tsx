import { useMemo, useState, type ReactNode } from 'react';
import { ChevronDown, Lightbulb, Plug, Search, ToggleRight, X } from 'lucide-react';
import type { HaEntity } from '../../../../shared/homeAssistant.ts';
import { Input, Select } from '../../components/ui.tsx';
import { cn } from '../../lib/utils.ts';

export type GroupBy = 'area' | 'device' | 'type' | 'integration' | 'none';
type Kind = 'all' | 'light' | 'switch' | 'outlet';
type State = 'all' | 'on' | 'off' | 'unavailable';

/** What an entity is, as the table says it. */
export function kindOf(e: HaEntity): Exclude<Kind, 'all'> {
  return e.id.startsWith('light.') ? 'light' : e.outlet ? 'outlet' : 'switch';
}
const KIND_NAME = { light: 'Lights', switch: 'Switches', outlet: 'Plugs' } as const;

export function EntityIcon({ e, className }: { e: HaEntity; className?: string }) {
  const k = kindOf(e);
  const Icon = k === 'light' ? Lightbulb : k === 'outlet' ? Plug : ToggleRight;
  const on = e.state === 'on';
  return <Icon className={cn('size-4 shrink-0', on ? 'text-accent-500' : e.state === 'unavailable' ? 'text-red-400' : 'text-stone-400', className)} aria-hidden />;
}

function StateBadge({ state }: { state: string }) {
  return (
    <span
      className={cn(
        'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
        state === 'on'
          ? 'bg-accent-400/15 text-accent-700 dark:text-accent-300'
          : state === 'off'
            ? 'bg-stone-100 text-stone-600 dark:bg-stone-800 dark:text-stone-300'
            : 'bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400'
      )}
    >
      {state === 'on' ? 'On' : state === 'off' ? 'Off' : state.charAt(0).toUpperCase() + state.slice(1)}
    </span>
  );
}

function groupOf(e: HaEntity, by: GroupBy): string {
  if (by === 'area') return e.area || 'No area';
  if (by === 'device') return e.device || 'No device';
  if (by === 'integration') return e.integration || 'Unknown integration';
  if (by === 'type') return KIND_NAME[kindOf(e)];
  return '';
}

/**
 * Home Assistant's lights and switches as its own entity tables show them: a search, filters
 * (type, state, area, and the ones in use), grouped by area, device, type or integration, each
 * group folding away. `action` is the last column: a switch to use one, a button to pick one.
 */
export function EntityTable({
  entities,
  action,
  used,
  usedLabel = 'In use',
  initialKind = 'all',
  initialGroup = 'area',
  rank,
  className
}: {
  entities: HaEntity[];
  action: (e: HaEntity) => ReactNode;
  /** Entities in use here: a filter shows only these. */
  used?: (e: HaEntity) => boolean;
  usedLabel?: string;
  initialKind?: Kind;
  initialGroup?: GroupBy;
  /** Lower first within a group (then by name). */
  rank?: (e: HaEntity) => number;
  className?: string;
}) {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<Kind>(initialKind);
  const [state, setState] = useState<State>('all');
  const [area, setArea] = useState('');
  const [onlyUsed, setOnlyUsed] = useState(false);
  const [group, setGroup] = useState<GroupBy>(initialGroup);
  const [folded, setFolded] = useState<Set<string>>(new Set());

  const areas = useMemo(() => [...new Set(entities.map((e) => e.area).filter(Boolean))].sort(), [entities]);
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const shown = entities.filter((e) => {
    if (kind !== 'all' && kindOf(e) !== kind) return false;
    if (state === 'unavailable' ? e.state === 'on' || e.state === 'off' : state !== 'all' && e.state !== state) return false;
    if (area && (area === '-' ? e.area : e.area !== area)) return false;
    if (onlyUsed && used && !used(e)) return false;
    const text = `${e.name} ${e.id} ${e.area} ${e.device} ${e.integration}`.toLowerCase();
    return words.every((w) => text.includes(w));
  });
  const groups = (() => {
    const m = new Map<string, HaEntity[]>();
    for (const e of shown) {
      const g = groupOf(e, group);
      m.set(g, [...(m.get(g) ?? []), e]);
    }
    const order = (g: string) => (/^(No |Unknown )/.test(g) ? 1 : 0);
    return [...m]
      .sort(([a], [b]) => order(a) - order(b) || a.localeCompare(b))
      .map(([g, list]) => [g, list.sort((a, b) => (rank?.(a) ?? 0) - (rank?.(b) ?? 0) || a.name.localeCompare(b.name))] as const);
  })();
  const filtering = !!(words.length || kind !== 'all' || state !== 'all' || area || onlyUsed);
  const fold = (g: string) => setFolded((f) => (f.has(g) ? new Set([...f].filter((x) => x !== g)) : new Set([...f, g])));

  return (
    <div className={cn('overflow-hidden rounded-xl ring-1 ring-stone-200 dark:ring-stone-800', className)}>
      <div className="flex flex-wrap items-center gap-2 border-b border-stone-200 bg-stone-50/70 p-2 dark:border-stone-800 dark:bg-stone-900">
        <label className="relative min-w-48 flex-1 max-sm:basis-full">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-stone-400" aria-hidden />
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name, entity ID, area, device" className="h-9 pr-8 pl-9" aria-label="Search" />
          {query ? (
            <button type="button" onClick={() => setQuery('')} className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-stone-400 hover:text-stone-700 dark:hover:text-stone-200" aria-label="Clear the search">
              <X className="size-4" />
            </button>
          ) : null}
        </label>
        <Select aria-label="Type" className="h-9 !w-auto" value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
          <option value="all">All types</option>
          <option value="light">Lights</option>
          <option value="outlet">Plugs</option>
          <option value="switch">Switches</option>
        </Select>
        <Select aria-label="State" className="h-9 !w-auto" value={state} onChange={(e) => setState(e.target.value as State)}>
          <option value="all">Any state</option>
          <option value="on">On</option>
          <option value="off">Off</option>
          <option value="unavailable">Unavailable</option>
        </Select>
        {areas.length ? (
          <Select aria-label="Area" className="h-9 !w-auto" value={area} onChange={(e) => setArea(e.target.value)}>
            <option value="">All areas</option>
            {areas.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
            <option value="-">No area</option>
          </Select>
        ) : null}
        <Select aria-label="Group by" className="h-9 !w-auto" value={group} onChange={(e) => setGroup(e.target.value as GroupBy)}>
          <option value="area">Group by area</option>
          <option value="device">Group by device</option>
          <option value="type">Group by type</option>
          <option value="integration">Group by integration</option>
          <option value="none">No groups</option>
        </Select>
        {used ? (
          <button
            type="button"
            aria-pressed={onlyUsed}
            onClick={() => setOnlyUsed(!onlyUsed)}
            className={cn(
              'h-9 rounded-xl px-3 text-sm font-medium ring-1 ring-inset transition',
              onlyUsed ? 'bg-accent-400/15 text-accent-800 ring-accent-400/50 dark:text-accent-300' : 'bg-white text-stone-600 ring-stone-200 hover:bg-stone-50 dark:bg-stone-950 dark:text-stone-300 dark:ring-stone-800'
            )}
          >
            {usedLabel}
          </button>
        ) : null}
      </div>

      <div className="max-h-[28rem] overflow-y-auto overscroll-contain">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-white text-xs font-medium text-stone-500 shadow-[0_1px_0] shadow-stone-200 dark:bg-stone-950 dark:text-stone-400 dark:shadow-stone-800">
            <tr>
              <th className="py-2 pr-2 pl-3 font-medium">Name</th>
              <th className="hidden px-2 py-2 font-medium md:table-cell">Area</th>
              <th className="hidden px-2 py-2 font-medium lg:table-cell">Device</th>
              <th className="hidden px-2 py-2 font-medium sm:table-cell">State</th>
              <th className="py-2 pr-3 pl-2 text-right font-medium">
                <span className="sr-only">Action</span>
              </th>
            </tr>
          </thead>
          {groups.map(([g, list]) => (
            <tbody key={g || 'all'} className="divide-y divide-stone-100 dark:divide-stone-800/70">
              {group !== 'none' ? (
                <tr className="bg-stone-50 dark:bg-stone-900/80">
                  <th colSpan={5} className="p-0">
                    <button type="button" onClick={() => fold(g)} className="flex w-full items-center gap-1.5 px-3 py-1.5 text-left text-xs font-semibold text-stone-600 dark:text-stone-300" aria-expanded={!folded.has(g)}>
                      <ChevronDown className={cn('size-3.5 transition-transform', folded.has(g) && '-rotate-90')} />
                      {g}
                      <span className="font-normal text-stone-400">{list.length}</span>
                    </button>
                  </th>
                </tr>
              ) : null}
              {folded.has(g)
                ? null
                : list.map((e) => (
                    <tr key={e.id} className="hover:bg-stone-50/70 dark:hover:bg-stone-900/50">
                      <td className="max-w-0 py-2 pr-2 pl-3">
                        <div className="flex min-w-0 items-center gap-2.5">
                          <EntityIcon e={e} />
                          <div className="min-w-0">
                            <div className="truncate font-medium">{e.name}</div>
                            <div className="truncate font-mono text-xs text-stone-500">
                              {e.id}
                              <span className="font-sans sm:hidden">{` · ${e.state}`}</span>
                              <span className="font-sans md:hidden">{e.area ? ` · ${e.area}` : ''}</span>
                              <span className="font-sans">{e.color ? ' · color' : e.dimmable ? ' · dims' : ''}</span>
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="hidden truncate px-2 py-2 text-stone-600 md:table-cell dark:text-stone-300">{e.area || <span className="text-stone-400">—</span>}</td>
                      <td className="hidden max-w-48 truncate px-2 py-2 text-stone-600 lg:table-cell dark:text-stone-300" title={e.integration ? `${e.device} · ${e.integration}` : e.device}>
                        {e.device || <span className="text-stone-400">—</span>}
                      </td>
                      <td className="hidden px-2 py-2 sm:table-cell">
                        <StateBadge state={e.state} />
                      </td>
                      <td className="py-2 pr-3 pl-2 text-right whitespace-nowrap">{action(e)}</td>
                    </tr>
                  ))}
            </tbody>
          ))}
        </table>
        {!shown.length ? <p className="px-3 py-8 text-center text-sm text-stone-500">{filtering ? 'Nothing matches these filters.' : 'Home Assistant has no lights or switches.'}</p> : null}
      </div>
      <div className="border-t border-stone-200 px-3 py-1.5 text-xs text-stone-500 dark:border-stone-800">
        {shown.length === entities.length ? `${entities.length} entities` : `${shown.length} of ${entities.length} entities`}
      </div>
    </div>
  );
}
