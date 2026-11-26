import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, KeyRound, Plug, RefreshCw, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import type { HaEntity, HaSettings, HaView } from '../../../../shared/homeAssistant.ts';
import type { DeviceWithStatus } from '../../../../shared/types.ts';
import { Badge, Button, Card, CardHeader, Field, Input, Select, Spinner, Switch } from '../../components/ui.tsx';
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
  useEffect(() => {
    if (data && !form) setForm({ url: data.url || 'http://192.168.29.29:8123', plugs: data.plugs, lights: data.lights });
  }, [data, form]);

  const done = (v: HaView) => {
    qc.setQueryData(HA, v);
    void qc.invalidateQueries({ queryKey: OVERVIEW });
    void qc.invalidateQueries({ queryKey: ['admin', 'lights'] });
  };
  const save = useMutation({
    mutationFn: (t: string | null | undefined) => api.saveHomeAssistant({ ...form!, ...(t !== undefined ? { token: t } : {}) }),
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

  const changed = token.trim() !== '' || JSON.stringify(form) !== JSON.stringify({ url: data.url, plugs: data.plugs, lights: data.lights });
  const plugs = data.entities.filter((e) => e.id.startsWith('switch.') || e.id.startsWith('light.'));
  const usedAsPlug = new Set(Object.values(form.plugs));
  const lightChoices = data.entities.filter((e) => !usedAsPlug.has(e.id));
  const missing = [...Object.values(form.plugs), ...form.lights].filter((id) => data.entities.length && !data.entities.some((e) => e.id === id));
  const setPlug = (deviceId: string, entity: string) => {
    const next = { ...form.plugs };
    if (entity) next[deviceId] = entity;
    else delete next[deviceId];
    setForm({ ...form, plugs: next, lights: form.lights.filter((l) => l !== entity) });
  };
  const toggleLight = (id: string, on: boolean) => setForm({ ...form, lights: on ? [...form.lights, id] : form.lights.filter((l) => l !== id) });

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
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                {devices.map((d) => (
                  <Field key={d.id} label={d.name}>
                    {(id) => (
                      <Select id={id} value={form.plugs[d.id] ?? ''} onChange={(e) => setPlug(d.id, e.target.value)}>
                        <option value="">No plug</option>
                        {plugs.map((e) => (
                          <option key={e.id} value={e.id} disabled={usedAsPlug.has(e.id) && form.plugs[d.id] !== e.id}>
                            {e.name} ({e.id})
                          </option>
                        ))}
                      </Select>
                    )}
                  </Field>
                ))}
              </div>
            </section>

            <section>
              <h3 className="text-sm font-medium">Lights</h3>
              <p className="mt-0.5 text-xs text-stone-500 dark:text-stone-400">
                They switch with all lights and the schedule, have their own switch under Devices, and take the colors of scenes and visitors' colors when they can show color.
              </p>
              <ul className="mt-3 grid gap-x-6 gap-y-1 sm:grid-cols-2">
                {lightChoices.map((e) => (
                  <li key={e.id} className="flex items-center justify-between gap-3 py-1.5">
                    <EntityName e={e} />
                    <Switch label={`Use ${e.name}`} checked={form.lights.includes(e.id)} onChange={(on) => toggleLight(e.id, on)} />
                  </li>
                ))}
              </ul>
            </section>
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
    </Card>
  );
}

function EntityName({ e }: { e: HaEntity }) {
  return (
    <span className="min-w-0">
      <span className="block truncate text-sm">{e.name}</span>
      <span className="block truncate font-mono text-xs text-stone-500">
        {e.id}
        {e.color ? ' · color' : e.dimmable ? ' · dims' : ''}
        {e.state === 'unavailable' ? ' · unavailable' : ''}
      </span>
    </span>
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
