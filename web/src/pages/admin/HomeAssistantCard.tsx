import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, KeyRound, Lightbulb, Plug, RefreshCw, X, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import type { HaEntity, HaSettings, HaView } from '../../../../shared/homeAssistant.ts';
import type { DeviceWithStatus } from '../../../../shared/types.ts';
import { Badge, Button, Card, CardHeader, Dialog, Field, Input, Spinner } from '../../components/ui.tsx';
import { EntityIcon, EntityTable, kindOf } from './EntityTable.tsx';
import { api } from '../../lib/api.ts';
import { errorText } from '../../lib/utils.ts';
import { OVERVIEW } from './AdminLayout.tsx';

export const HA = ['admin', 'lights', 'ha'];

/** Home Assistant as the server sees it: settings, whether a token is kept, and its lights. */
export function useHomeAssistant() {
  return useQuery({ queryKey: HA, queryFn: api.homeAssistant, refetchInterval: 15_000 });
}

/**
 * Home Assistant: its address and a long-lived access token, the plugs that power the WLED
 * controllers, and other lights to switch with these. The token field is write-only: the server
 * keeps the token and never sends it back.
 */
export function HomeAssistantCard({ devices }: { devices: DeviceWithStatus[] }) {
  const qc = useQueryClient();
  const { data } = useHomeAssistant();
  const [form, setForm] = useState<HaSettings | null>(null);
  const [token, setToken] = useState('');
  const [picking, setPicking] = useState<DeviceWithStatus | null>(null);
  useEffect(() => {
    if (data && !form) setForm({ url: data.url || 'http://192.168.29.29:8123', plugs: data.plugs, lights: data.lights });
  }, [data, form]);

  const done = (v: HaView) => {
    qc.setQueryData(HA, v);
    void qc.invalidateQueries({ queryKey: OVERVIEW });
    void qc.invalidateQueries({ queryKey: ['admin', 'lights'] });
  };
  const save = useMutation({
    mutationFn: (t: string | null | undefined) => api.saveHomeAssistant({ url: form!.url, plugs: form!.plugs, ...(t !== undefined ? { token: t } : {}) }),
    onSuccess: (v, t) => {
      done(v);
      setToken('');
      setForm({ url: v.url, plugs: v.plugs, lights: v.lights });
      if (t === null) toast.success('Token removed');
      else if (v.status && !v.status.ok) toast.warning(`Saved, but ${v.status.error.charAt(0).toLowerCase()}${v.status.error.slice(1)}`);
      else toast.success('Home Assistant saved');
    },
    onError: (e) => toast.error(errorText(e))
  });
  const test = useMutation({ mutationFn: api.testHomeAssistant, onSuccess: done, onError: (e) => toast.error(errorText(e)) });

  if (!data || !form) {
    return (
      <Card className="mt-10 grid place-items-center py-10">
        <Spinner />
      </Card>
    );
  }

  const changed = token.trim() !== '' || JSON.stringify({ url: form.url, plugs: form.plugs }) !== JSON.stringify({ url: data.url, plugs: data.plugs });
  const usedAsPlug = new Set(Object.values(form.plugs));
  const byId = new Map(data.entities.map((e) => [e.id, e]));
  const missing = [...Object.values(form.plugs), ...form.lights].filter((id) => data.entities.length && !data.entities.some((e) => e.id === id));
  const setPlug = (deviceId: string, entity: string) => {
    const next = { ...form.plugs };
    if (entity) next[deviceId] = entity;
    else delete next[deviceId];
    setForm({ ...form, plugs: next, lights: form.lights.filter((l) => l !== entity) });
  };

  return (
    <Card className="mt-10">
      <CardHeader
        title="Home Assistant"
        description="Smart plugs that power the WLED controllers, and other lights to switch with them."
        actions={<HaStatus view={data} />}
      />
      <form
        className="space-y-6 p-5"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(token.trim() ? token.trim() : undefined);
        }}
      >
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Address" hint="Home Assistant on the home network, with its port.">
            {(id) => <Input id={id} value={form.url} placeholder="http://192.168.29.29:8123" className="font-mono" onChange={(e) => setForm({ ...form, url: e.target.value })} />}
          </Field>
          <Field
            label="Long-lived access token"
            hint={
              <>
                Make one in Home Assistant: your profile → Security → Long-lived access tokens. The server keeps it and never shows it again.
                {data.hasToken ? (
                  <button type="button" className="ml-1 text-red-600 underline-offset-2 hover:underline dark:text-red-400" onClick={() => save.mutate(null)}>
                    Remove the token
                  </button>
                ) : null}
              </>
            }
          >
            {(id) => (
              <Input
                id={id}
                type="password"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                placeholder={data.hasToken ? '•••••••• kept: type a new one to replace it' : 'Paste the token here'}
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
            )}
          </Field>
        </div>

        {data.entities.length ? (
          <>
            <section>
              <h3 className="flex items-center gap-1.5 text-sm font-medium">
                <Plug className="size-4 text-stone-400" /> Power plugs
              </h3>
              <p className="mt-0.5 text-xs text-stone-500 dark:text-stone-400">
                The plug that powers a controller and its lights. Switching the device off turns WLED off, then the plug; on turns the plug on, and the controller gets what plays once it has started.
              </p>
              <div className="mt-3 overflow-hidden rounded-xl ring-1 ring-stone-200 dark:ring-stone-800">
                <table className="w-full text-left text-sm">
                  <thead className="bg-stone-50/70 text-xs text-stone-500 dark:bg-stone-900 dark:text-stone-400">
                    <tr>
                      <th className="py-2 pr-2 pl-3 font-medium">Controller</th>
                      <th className="hidden px-2 py-2 font-medium sm:table-cell">Plug</th>
                      <th className="hidden px-2 py-2 font-medium sm:table-cell">State</th>
                      <th className="py-2 pr-3 pl-2">
                        <span className="sr-only">Change</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-100 dark:divide-stone-800/70">
                    {devices.map((d) => {
                      const id = form.plugs[d.id];
                      const e = id ? byId.get(id) : undefined;
                      return (
                        <tr key={d.id}>
                          <td className="py-2.5 pr-2 pl-3 max-sm:max-w-0">
                            <div className="truncate font-medium">{d.name}</div>
                            <div className="truncate text-xs text-stone-500 sm:hidden">{id ? `${e?.name ?? id}${e ? ` · ${e.state}` : ''}` : 'No plug'}</div>
                          </td>
                          <td className="hidden max-w-0 px-2 py-2.5 sm:table-cell">
                            {id ? (
                              <div className="flex min-w-0 items-center gap-2">
                                {e ? <EntityIcon e={e} /> : null}
                                <div className="min-w-0">
                                  <div className="truncate">{e?.name ?? id}</div>
                                  <div className="truncate font-mono text-xs text-stone-500">
                                    {id}
                                    {e?.area ? <span className="font-sans">{` · ${e.area}`}</span> : null}
                                  </div>
                                </div>
                              </div>
                            ) : (
                              <span className="text-stone-400">No plug</span>
                            )}
                          </td>
                          <td className="hidden px-2 py-2.5 sm:table-cell">{e ? <span className="text-xs text-stone-500 capitalize">{e.state}</span> : null}</td>
                          <td className="py-2 pr-3 pl-2 text-right whitespace-nowrap">
                            <Button size="sm" onClick={() => setPicking(d)}>
                              {id ? 'Change' : 'Choose'}
                            </Button>
                            {id ? (
                              <Button size="sm" variant="ghost" className="ml-1" aria-label={`Remove the plug of ${d.name}`} onClick={() => setPlug(d.id, '')}>
                                <X />
                              </Button>
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            <p className="text-sm text-stone-500 dark:text-stone-400">
              <Lightbulb className="mr-1.5 -mt-0.5 inline size-4 text-stone-400" />
              Lights to control are added on the{' '}
              <Link to="/admin/devices" className="font-medium text-stone-900 underline underline-offset-2 dark:text-white">
                Devices page
              </Link>
              {data.lights.length ? ` (${data.lights.length} added)` : ''}.
            </p>
          </>
        ) : data.hasToken && data.status?.ok ? (
          <p className="text-sm text-stone-500">Home Assistant has no lights or switches.</p>
        ) : null}

        {missing.length ? <p className="text-sm text-amber-700 dark:text-amber-300">Home Assistant no longer has {missing.join(', ')}.</p> : null}

        <div className="flex flex-wrap items-center justify-end gap-2">
          {data.hasToken && data.url ? (
            <Button onClick={() => test.mutate()} loading={test.isPending}>
              <RefreshCw /> Test
            </Button>
          ) : null}
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!changed}>
            {token.trim() ? (
              <>
                <KeyRound /> Save token
              </>
            ) : (
              'Save'
            )}
          </Button>
        </div>
      </form>
      <PlugPicker
        device={picking}
        entities={data.entities}
        plugs={form.plugs}
        devices={devices}
        onClose={() => setPicking(null)}
        onPick={(entity) => {
          if (picking) setPlug(picking.id, entity);
          setPicking(null);
        }}
      />
    </Card>
  );
}

/**
 * Picks the plug that powers one controller, from Home Assistant's switches and lights: plugs
 * first, then switches, grouped by area, with a search. One plug powers one controller.
 */
function PlugPicker({
  device,
  entities,
  plugs,
  devices,
  onClose,
  onPick
}: {
  device: DeviceWithStatus | null;
  entities: HaEntity[];
  plugs: Record<string, string>;
  devices: DeviceWithStatus[];
  onClose: () => void;
  onPick: (entity: string) => void;
}) {
  const owner = (id: string) => devices.find((d) => plugs[d.id] === id && d.id !== device?.id);
  const current = device ? plugs[device.id] : undefined;
  return (
    <Dialog open={!!device} onClose={onClose} size="xl" title={device ? `Power plug for ${device.name}` : ''} description="The switch or plug in Home Assistant that powers this controller and its lights.">
      {device ? (
        <div className="pb-4">
          <EntityTable
            entities={entities}
            initialKind={entities.some((e) => e.outlet) ? 'outlet' : 'all'}
            rank={(e) => (e.id === current ? -1 : kindOf(e) === 'outlet' ? 0 : kindOf(e) === 'switch' ? 1 : 2)}
            action={(e) => {
              const taken = owner(e.id);
              if (e.id === current) return <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400">Chosen</span>;
              if (taken) return <span className="text-xs text-stone-500">Powers {taken.name}</span>;
              return (
                <Button size="sm" onClick={() => onPick(e.id)}>
                  Use
                </Button>
              );
            }}
          />
        </div>
      ) : null}
    </Dialog>
  );
}

function HaStatus({ view }: { view: HaView }) {
  if (!view.url || !view.hasToken) return <Badge>Not connected</Badge>;
  if (!view.status) return <Badge>Not checked yet</Badge>;
  if (!view.status.ok)
    return (
      <Badge tone="red">
        <XCircle className="size-3.5" /> {view.status.error}
      </Badge>
    );
  return (
    <Badge tone="green">
      <CheckCircle2 className="size-3.5" /> Connected{view.status.version ? ` · ${view.status.version}` : ''}
    </Badge>
  );
}
