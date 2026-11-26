import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Gauge, House, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { haId, type HaEntity, type HaSpeedResult, type HaView } from '../../../../shared/homeAssistant.ts';
import { Badge, Button, Card, CardHeader, Dialog, Empty, Field, Select, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { OVERVIEW } from './AdminLayout.tsx';
import { EntityIcon, EntityTable, kindOf } from './EntityTable.tsx';
import { HA, useHomeAssistant } from './HomeAssistantCard.tsx';

/** Saves the Home Assistant lights in use, with the caches they touch kept fresh. */
function useSaveLights() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (lights: string[]) => api.saveHaLights(lights),
    onSuccess: (v: HaView) => {
      qc.setQueryData(HA, v);
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      void qc.invalidateQueries({ queryKey: ['admin', 'lights'] });
    },
    onError: (e) => toast.error(errorText(e))
  });
}

/**
 * Home Assistant lights the site controls, as devices: added from Home Assistant's lights and
 * switches, each with where it is and what it does. In the layout, any object can be one of
 * them (its Device), so effects and games reach it too.
 */
export function HaLightsCard({ adding, onAdding }: { adding: boolean; onAdding: (v: boolean) => void }) {
  const { data: ha } = useHomeAssistant();
  const { data: layout } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const save = useSaveLights();
  const [testing, setTesting] = useState<HaEntity | null>(null);
  const connected = !!ha?.url && ha.hasToken;
  if (!ha) return null;

  const byId = new Map(ha.entities.map((e) => [e.id, e]));
  const objectsOf = (id: string) => (layout?.fixtures ?? []).filter((f) => f.deviceId === haId(id)).map((f) => f.name);

  return (
    <Card className="mt-6">
      <CardHeader
        title="Home Assistant lights"
        description="Lights from Home Assistant that the site controls: they switch with all lights and the schedule, take scene and visitor colors, and in the layout any object can be one (its Device)."
        actions={
          connected ? (
            <>
              <RateSelect view={ha} />
              <Button size="sm" onClick={() => onAdding(true)}>
                <Plus /> Add lights
              </Button>
            </>
          ) : null
        }
      />
      {!connected ? (
        <Empty icon={<House />} title="Home Assistant is not connected">
          Connect it under <Link to="/admin/settings" className="font-medium text-stone-900 underline underline-offset-2 dark:text-white">Settings → Home Assistant</Link>, then add its lights here.
        </Empty>
      ) : !ha.lights.length ? (
        <Empty
          icon={<House />}
          title="No Home Assistant lights yet"
          action={
            <Button variant="primary" onClick={() => onAdding(true)}>
              <Plus /> Add lights
            </Button>
          }
        >
          Pick lights and switches from Home Assistant to control them with the yard.
        </Empty>
      ) : (
        <ul className="divide-y divide-stone-100 dark:divide-stone-800">
          {ha.lights.map((id) => {
            const e = byId.get(id);
            const objects = objectsOf(id);
            return (
              <li key={id} className="flex items-center gap-3 py-3 pr-2 pl-4 sm:px-5">
                {e ? <EntityIcon e={e} className="size-5" /> : null}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate font-medium">{e?.name ?? id}</span>
                    {!e ? <Badge tone="amber">Not in Home Assistant</Badge> : e.state === 'unavailable' ? <Badge tone="red">Unavailable</Badge> : null}
                  </div>
                  <p className="mt-0.5 flex flex-wrap gap-x-3 text-sm text-stone-500 dark:text-stone-400">
                    <span className="font-mono text-[13px]">{id}</span>
                    {e?.area ? <span>{e.area}</span> : null}
                    {e ? <span>{kindOf(e) === 'light' ? (e.color ? 'Color' : e.dimmable ? 'Dims' : 'On and off') : 'On and off'}</span> : null}
                    <span>{objects.length ? `In the layout: ${objects.join(', ')}` : 'Not in the layout'}</span>
                  </p>
                </div>
                {id.startsWith('light.') ? (
                  <Button size="sm" variant="ghost" title="How fast can it change color?" onClick={() => setTesting(e ?? { id, name: id, state: '', color: true, dimmable: true, outlet: false, area: '', device: '', integration: '' })}>
                    <Gauge /> <span className="max-sm:hidden">Speed test</span>
                  </Button>
                ) : null}
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={`Remove ${e?.name ?? id}`}
                  className="hover:text-red-600 dark:hover:text-red-400"
                  disabled={save.isPending}
                  onClick={() => save.mutate(ha.lights.filter((x) => x !== id), { onSuccess: () => toast.success(`${e?.name ?? id} removed`) })}
                >
                  <Trash2 />
                </Button>
              </li>
            );
          })}
        </ul>
      )}
      {connected ? <AddHaLightsDialog open={adding} view={ha} onClose={() => onAdding(false)} /> : null}
      {testing ? <SpeedTestDialog light={testing} view={ha} onClose={() => setTesting(null)} /> : null}
    </Card>
  );
}

/** Home Assistant's lights and switches, to pick the ones the site controls. Each switch saves at once. */
function AddHaLightsDialog({ open, view, onClose }: { open: boolean; view: HaView; onClose: () => void }) {
  const save = useSaveLights();
  const [busy, setBusy] = useState<string | null>(null);
  const plugs = new Set(Object.values(view.plugs));
  const toggle = (e: HaEntity, on: boolean) => {
    setBusy(e.id);
    save.mutate(on ? [...view.lights, e.id] : view.lights.filter((x) => x !== e.id), { onSettled: () => setBusy(null) });
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="xl"
      title="Add Home Assistant lights"
      description="Switch on the ones the site should control. Then, to place one in the yard, pick it as an object's Device in the layout."
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {open ? (
        <div className="pb-2">
          <EntityTable
            entities={view.entities}
            initialKind="light"
            used={(e) => view.lights.includes(e.id)}
            usedLabel={`Added (${view.lights.length})`}
            action={(e) =>
              plugs.has(e.id) ? (
                <span className="text-xs text-stone-500">Power plug</span>
              ) : (
                <Switch label={`Control ${e.name}`} checked={view.lights.includes(e.id)} disabled={save.isPending || busy === e.id} onChange={(on) => toggle(e, on)} />
              )
            }
          />
        </div>
      ) : null}
    </Dialog>
  );
}

const RATES = [1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20];

/** How many colors a second the lights in the layout take (see HaFrames). */
function RateSelect({ view }: { view: HaView }) {
  const qc = useQueryClient();
  const set = useMutation({
    mutationFn: api.setHaRate,
    onSuccess: (v) => {
      qc.setQueryData(HA, v);
      toast.success(`Home Assistant lights: ${v.fps} colors a second`);
    },
    onError: (e) => toast.error(errorText(e))
  });
  return (
    <label className="flex items-center gap-2 text-sm text-stone-500 dark:text-stone-400" title="How often a Home Assistant light in the layout takes a new color while effects and games play">
      <span className="max-sm:hidden">Colors a second</span>
      <Select aria-label="Colors a second" className="h-8 !w-20" value={view.fps} disabled={set.isPending} onChange={(e) => set.mutate({ fps: Number(e.target.value) })}>
        {(RATES.includes(view.fps) ? RATES : [...RATES, view.fps].sort((a, b) => a - b)).map((n) => (
          <option key={n} value={n}>
            {n}
          </option>
        ))}
      </Select>
    </label>
  );
}

/**
 * Plays a rainbow on one light, as fast as asked, and lists what it took: how many colors a
 * second, and how long Home Assistant took for each (for a Zigbee light, until the light said
 * it had it). Runs stay in the list to compare; one can become the rate for the layout.
 */
function SpeedTestDialog({ light, view, onClose }: { light: HaEntity; view: HaView; onClose: () => void }) {
  const qc = useQueryClient();
  const [fps, setFps] = useState(10);
  const [via, setVia] = useState<'ws' | 'rest'>('ws');
  const [seconds, setSeconds] = useState(10);
  const [inflight, setInflight] = useState(1);
  const [fade, setFade] = useState(true);
  // A ZHA light can take its colors as Zigbee commands: likely faster, so tried first.
  const [direct, setDirect] = useState(!!light.zigbee);
  const [runs, setRuns] = useState<HaSpeedResult[]>([]);
  const run = useMutation({
    mutationFn: () => api.haSpeedTest({ entity: light.id, fps, seconds, via, inflight, fade, direct: direct && via === 'ws' }),
    onSuccess: (r) => setRuns((x) => [r, ...x]),
    onError: (e) => toast.error(errorText(e))
  });
  const rate = useMutation({
    mutationFn: api.setHaRate,
    onSuccess: (v) => {
      qc.setQueryData(HA, v);
      toast.success(`Home Assistant lights: ${v.fps} colors a second`);
    },
    onError: (e) => toast.error(errorText(e))
  });
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={`Speed test: ${light.name}`}
      description="A rainbow plays on the light, asking for this many colors a second, as the layout does. Watch it: smooth, or stepping? The list says what it took, and Use makes the layout send colors that way."
      footer={<Button onClick={onClose}>Done</Button>}
    >
      <div className="space-y-4 pb-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 sm:items-end">
          <Field label="Colors a second">
            {(id) => (
              <Select id={id} value={fps} onChange={(e) => setFps(Number(e.target.value))}>
                {[2, 4, 6, 8, 10, 12, 15, 20, 25, 30].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Sent over">
            {(id) => (
              <Select id={id} value={via} onChange={(e) => setVia(e.target.value as 'ws' | 'rest')}>
                <option value="ws">WebSocket</option>
                <option value="rest">REST</option>
              </Select>
            )}
          </Field>
          <Field label="For">
            {(id) => (
              <Select id={id} value={seconds} onChange={(e) => setSeconds(Number(e.target.value))}>
                {[5, 10, 20, 30].map((n) => (
                  <option key={n} value={n}>
                    {n} seconds
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="At once">
            {(id) => (
              <Select id={id} value={inflight} onChange={(e) => setInflight(Number(e.target.value))}>
                <option value={1}>1 (wait for each)</option>
                <option value={2}>2 on their way</option>
                <option value={3}>3 on their way</option>
              </Select>
            )}
          </Field>
          <Field label="Fade">
            {(id) => (
              <Select id={id} value={fade ? '1' : '0'} onChange={(e) => setFade(e.target.value === '1')}>
                <option value="1">Fade to each color</option>
                <option value="0">Change at once</option>
              </Select>
            )}
          </Field>
          {light.zigbee ? (
            <Field label="Command">
              {(id) => (
                <Select id={id} value={direct ? '1' : '0'} onChange={(e) => setDirect(e.target.value === '1')} disabled={via === 'rest'}>
                  <option value="1">Zigbee color command</option>
                  <option value="0">light.turn_on</option>
                </Select>
              )}
            </Field>
          ) : null}
          <Button variant="primary" className={cn('justify-center max-sm:col-span-2', light.zigbee && 'sm:col-span-2')} loading={run.isPending} onClick={() => run.mutate()}>
            <Gauge /> {run.isPending ? `Playing ${seconds} s…` : 'Run'}
          </Button>
        </div>
        {runs.length ? (
          <div className="overflow-x-auto rounded-xl ring-1 ring-stone-200 dark:ring-stone-800">
            <table className="w-full text-sm whitespace-nowrap">
              <thead className="bg-stone-50/70 text-left text-xs text-stone-500 dark:bg-stone-900 dark:text-stone-400">
                <tr>
                  <th className="px-3 py-2 font-medium">How</th>
                  <th className="px-2 py-2 text-right font-medium">Asked</th>
                  <th className="px-2 py-2 text-right font-medium">Took</th>
                  <th className="px-2 py-2 text-right font-medium" title="Half the commands took this long or less">Typical</th>
                  <th className="px-2 py-2 text-right font-medium" title="95% took this long or less">Slow</th>
                  <th className="px-2 py-2 text-right font-medium">Errors</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-100 dark:divide-stone-800">
                {runs.map((r, i) => {
                  const use = Math.max(1, Math.min(20, Math.floor(r.achieved)));
                  const inUse = view.fps === use && view.inflight === r.inflight && view.fade === r.fade && view.direct === r.direct;
                  return (
                    <tr key={runs.length - i}>
                      <td className="px-3 py-2">
                        {r.via === 'ws' ? 'WebSocket' : 'REST'}
                        <span className="text-stone-500">{` · ${r.direct ? 'Zigbee · ' : ''}${r.inflight} at once · ${r.fade ? 'fade' : 'no fade'}`}</span>
                      </td>
                      <td className="px-2 py-2 text-right tabular-nums">{r.fps}/s</td>
                      <td className={cn('px-2 py-2 text-right font-medium tabular-nums', r.achieved >= r.fps * 0.9 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400')}>{r.achieved}/s</td>
                      <td className="px-2 py-2 text-right tabular-nums">{r.latency.p50} ms</td>
                      <td className="px-2 py-2 text-right tabular-nums">{r.latency.p95} ms</td>
                      <td className={cn('px-2 py-2 text-right tabular-nums', r.errors && 'text-red-600 dark:text-red-400')} title={r.error}>
                        {r.errors}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <Button size="sm" variant="ghost" disabled={inUse || rate.isPending} onClick={() => rate.mutate({ fps: use, inflight: r.inflight, fade: r.fade, direct: r.direct })} title="The lights in the layout take colors this way">
                          {inUse ? 'In use' : `Use ${use}/s`}
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-stone-500">
            Start at 10 a second over the WebSocket. If it takes fewer than asked, the light (or its Zigbee network) cannot go faster: each command waits for the light to answer. The layout now uses {view.fps} a second, {view.inflight} at once, {view.fade ? 'fading' : 'without a fade'}{view.direct ? ', as Zigbee commands' : ''}.
            {light.zigbee ? ' This is a ZHA light: a Zigbee color command is one message to it, where light.turn_on is several, each waiting for the light.' : ''}
          </p>
        )}
      </div>
    </Dialog>
  );
}
