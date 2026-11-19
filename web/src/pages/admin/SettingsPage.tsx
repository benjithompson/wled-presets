import { useEffect, useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import type { Settings } from '../../../../shared/types.ts';
import { Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { errorText, relativeTime } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';
import { PasskeysCard } from './PasskeysCard.tsx';

export function SettingsPage() {
  const qc = useQueryClient();
  const { data } = useOverview();
  const [form, setForm] = useState<Settings | null>(null);
  const [subnets, setSubnets] = useState('');

  useEffect(() => {
    if (data && !form) {
      setForm(data.settings);
      setSubnets(data.settings.discoverySubnets.join(', '));
    }
  }, [data, form]);

  const save = useMutation({
    mutationFn: (s: Settings) => api.saveSettings(s),
    onSuccess: (s) => {
      setForm(s);
      toast.success('Settings saved');
      qc.invalidateQueries({ queryKey: OVERVIEW });
    },
    onError: (e) => toast.error(errorText(e))
  });
  const cancelRevert = useMutation({ mutationFn: api.cancelRevert, onSuccess: () => qc.invalidateQueries({ queryKey: OVERVIEW }) });

  if (!data || !form) {
    return (
      <div className="grid place-items-center py-24">
        <Spinner />
      </div>
    );
  }

  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({
      ...form,
      discoverySubnets: subnets
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean)
    });
  };
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setForm({ ...form, [k]: v });
  const revertAt = data.state.revertAt;

  return (
    <>
      <PageHeader title="Settings" />
      <form onSubmit={submit} className="space-y-6">
        <Card>
          <CardHeader title="Public page" description="What visitors see at the root address." />
          <div className="grid gap-5 p-5 sm:grid-cols-2">
            <Field label="Title">{(id) => <Input id={id} value={form.siteTitle} maxLength={80} required onChange={(e) => set('siteTitle', e.target.value)} />}</Field>
            <Field label="Subtitle">{(id) => <Input id={id} value={form.siteSubtitle} maxLength={200} onChange={(e) => set('siteSubtitle', e.target.value)} />}</Field>
            <label className="flex items-center justify-between gap-4 sm:col-span-2">
              <span>
                <span className="block text-sm font-medium">Show color picker</span>
                <span className="block text-xs text-stone-500">Lets visitors set all lights to one solid color.</span>
              </span>
              <Switch label="Show color picker" checked={form.showColors} onChange={(v) => set('showColors', v)} />
            </label>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Auto-revert"
            description="After a visitor picks a scene or color, return to the default scene after some time."
            actions={
              revertAt ? (
                <span className="flex items-center gap-2 text-sm text-stone-500">
                  Next revert {relativeTime(revertAt)}
                  <Button size="sm" variant="ghost" onClick={() => cancelRevert.mutate()} loading={cancelRevert.isPending}>
                    Cancel
                  </Button>
                </span>
              ) : null
            }
          />
          <div className="grid gap-5 p-5 sm:grid-cols-2">
            <Field label="Default scene">
              {(id) => (
                <Select id={id} value={form.defaultSceneId ?? ''} onChange={(e) => set('defaultSceneId', e.target.value || null)}>
                  <option value="">None (auto-revert off)</option>
                  {data.scenes.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Revert after (minutes)" hint="0 turns auto-revert off.">
              {(id) => (
                <Input id={id} type="number" min={0} max={1440} step={1} value={form.revertMinutes} onChange={(e) => set('revertMinutes', Math.max(0, Number(e.target.value) || 0))} />
              )}
            </Field>
          </div>
        </Card>

        <Card>
          <CardHeader title="Discovery" description="Where the Discover button looks for WLED devices." />
          <div className="p-5">
            <Field label="Subnets" hint="Comma-separated CIDR ranges, for example 192.168.1.0/24. Empty means the server's own networks. DISCOVERY_SUBNETS in the environment overrides this.">
              {(id) => <Input id={id} value={subnets} onChange={(e) => setSubnets(e.target.value)} placeholder="192.168.1.0/24" className="font-mono" />}
            </Field>
          </div>
        </Card>

        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save settings
          </Button>
        </div>
      </form>

      <PasswordCard />
      <PasskeysCard />
    </>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: () => {
      toast.success('Password changed');
      setCurrent('');
      setNext('');
    },
    onError: (e) => toast.error(errorText(e))
  });
  return (
    <Card className="mt-10">
      <CardHeader title="Account" description="Change the password for this admin account." />
      <form
        className="grid gap-5 p-5 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate();
        }}
      >
        <Field label="Current password">{(id) => <Input id={id} type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />}</Field>
        <Field label="New password">
          {(id) => <Input id={id} type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} placeholder="At least 12 characters" />}
        </Field>
        <Button type="submit" loading={change.isPending}>
          Change password
        </Button>
      </form>
    </Card>
  );
}

