// The Home Assistant lights' dialogs on the Devices page: adding lights, how the ones in the
// layout take colors, and a speed test of one light. The lights themselves are rows of the
// Devices table (see DeviceTable).
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Gauge } from 'lucide-react';
import { toast } from 'sonner';
import type { HaEntity, HaSpeedResult, HaView } from '../../../../shared/homeAssistant.ts';
import { Button, Dialog, Field, Select, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { OVERVIEW } from './AdminLayout.tsx';
import { EntityTable } from './EntityTable.tsx';
import { HA } from './HomeAssistantCard.tsx';

/** Saves the Home Assistant lights in use, with the caches they touch kept fresh. */
export function useSaveLights() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: string[] | { lights: string[]; disabled: string[] }) => (Array.isArray(v) ? api.saveHaLights(v) : api.saveHaLights(v.lights, v.disabled)),
    onSuccess: (v: HaView) => {
      qc.setQueryData(HA, v);
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      void qc.invalidateQueries({ queryKey: ['admin', 'lights'] });
    },
    onError: (e) => toast.error(errorText(e))
  });
}

/** Home Assistant's lights and switches, to pick the ones the site controls. Each switch saves at once. */
export function AddHaLightsDialog({ open, view, onClose }: { open: boolean; view: HaView; onClose: () => void }) {
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

/**
 * How the Home Assistant lights in the layout take colors while effects and games play (see
 * HaFrames), set by hand: the rate, how many commands may be on their way, a fade or an
 * instant change, and for ZHA lights Zigbee color commands or light.turn_on. A speed test finds
 * good values; this sets them without one.
 */
export function FrameSettingsDialog({ view, onClose }: { view: HaView; onClose: () => void }) {
  const qc = useQueryClient();
  const [fps, setFps] = useState(view.fps);
  const [inflight, setInflight] = useState(view.inflight);
  const [fade, setFade] = useState(view.fade);
  const [direct, setDirect] = useState(view.direct);
  const zigbee = view.entities.some((e) => e.zigbee && view.lights.includes(e.id));
  const save = useMutation({
    mutationFn: () => api.setHaRate({ fps, inflight, fade, direct }),
    onSuccess: (v) => {
      qc.setQueryData(HA, v);
      toast.success(`Home Assistant lights: ${v.fps} colors a second, ${v.fade ? 'fading' : 'instant'}`);
      onClose();
    },
    onError: (e) => toast.error(errorText(e))
  });
  const changed = fps !== view.fps || inflight !== view.inflight || fade !== view.fade || direct !== view.direct;
  return (
    <Dialog
      open
      onClose={onClose}
      size="md"
      title="Light settings"
      description="How Home Assistant lights in the layout take colors while effects and games play. Faster looks smoother, if the lights (and their Zigbee network) keep up; a speed test on a light shows what it can take."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} disabled={!changed} onClick={() => save.mutate()}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid gap-4 pb-4 sm:grid-cols-2">
        <Field label="Colors a second" hint="How often a light takes a new color">
          {(id) => (
            <Select id={id} value={fps} onChange={(e) => setFps(Number(e.target.value))}>
              {(RATES.includes(fps) ? RATES : [...RATES, fps].sort((a, b) => a - b)).map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Color change" hint="A fade lasts until the next color">
          {(id) => (
            <Select id={id} value={fade ? '1' : '0'} onChange={(e) => setFade(e.target.value === '1')}>
              <option value="1">Fade to each color</option>
              <option value="0">Instant</option>
            </Select>
          )}
        </Field>
        <Field label="At once" hint="Commands on their way to a light">
          {(id) => (
            <Select id={id} value={inflight} onChange={(e) => setInflight(Number(e.target.value))}>
              <option value={1}>1 (wait for each)</option>
              <option value={2}>2 on their way</option>
              <option value={3}>3 on their way</option>
            </Select>
          )}
        </Field>
        <Field label="Command" hint={zigbee ? 'For ZHA lights; on and off always go through Home Assistant' : 'Zigbee commands are for ZHA lights (none added)'}>
          {(id) => (
            <Select id={id} value={direct ? '1' : '0'} onChange={(e) => setDirect(e.target.value === '1')}>
              <option value="1">Zigbee color command</option>
              <option value="0">light.turn_on</option>
            </Select>
          )}
        </Field>
      </div>
    </Dialog>
  );
}

/**
 * Plays a rainbow on one light, as fast as asked, and lists what it took: how many colors a
 * second, and how long Home Assistant took for each (for a Zigbee light, until the light said
 * it had it). Runs stay in the list to compare; one can become the rate for the layout.
 */
export function SpeedTestDialog({ light, view, onClose }: { light: HaEntity; view: HaView; onClose: () => void }) {
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
