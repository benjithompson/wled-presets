import { useEffect, useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { FRAME_RATES, type Settings } from '../../../../shared/types.ts';
import { SCENE_TRANSITION_SECONDS, TRANSITION_CHOICES, transitionInfo } from '../../../../shared/transitions.ts';
import { Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { errorText, relativeTime } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';
import { PasskeysCard } from './PasskeysCard.tsx';
import { HomeAssistantCard } from './HomeAssistantCard.tsx';

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
      sceneTransitionSeconds: Math.min(SCENE_TRANSITION_SECONDS.max, Math.max(SCENE_TRANSITION_SECONDS.min, form.sceneTransitionSeconds || SCENE_TRANSITION_SECONDS.default)),
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
          <CardHeader title="Scene transitions" description="How the lights go from one scene to the next when a visitor or an admin picks a scene. The auto-revert changes at once." />
          <div className="grid gap-5 p-5 sm:grid-cols-2">
            <Field
              label="Transition"
              hint={
                form.sceneTransition === 'none'
                  ? 'The new scene shows at once.'
                  : `${transitionInfo(form.sceneTransition).description} Effects and sequences transition; a device that plays a WLED preset changes as WLED does.`
              }
            >
              {(id) => (
                <Select id={id} value={form.sceneTransition} onChange={(e) => set('sceneTransition', e.target.value as Settings['sceneTransition'])}>
                  <option value="none">None (cut)</option>
                  {TRANSITION_CHOICES.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Length (seconds)" hint={`${SCENE_TRANSITION_SECONDS.min} to ${SCENE_TRANSITION_SECONDS.max} seconds.`}>
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={SCENE_TRANSITION_SECONDS.min}
                  max={SCENE_TRANSITION_SECONDS.max}
                  step={0.1}
                  disabled={form.sceneTransition === 'none'}
                  value={form.sceneTransitionSeconds}
                  onChange={(e) => set('sceneTransitionSeconds', Math.max(0, Number(e.target.value) || 0))}
                />
              )}
            </Field>
          </div>
        </Card>

        <Card>
          <CardHeader title="Frame rate" description="How many frames a second the WLED devices get while effects, sequences, games and the editors' previews play. Fewer leave a device more room: a controller that stutters or stops answering may keep up at a lower rate." />
          <div className="grid gap-5 p-5 sm:grid-cols-2">
            <Field label="Frames a second, at most" hint="A device whose LED strip is too long for this many gets fewer. Even shares of 60, so every frame lasts as long as the last.">
              {(id) => (
                <Select id={id} value={form.maxFps} onChange={(e) => set('maxFps', Number(e.target.value))}>
                  {FRAME_RATES.map((n) => (
                    <option key={n} value={n}>
                      {n}
                      {n === 60 ? ' (most)' : ''}
                    </option>
                  ))}
                </Select>
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

        {/* On a phone the button stays at the bottom of the screen while the settings are in view. */}
        <div
          className="flex justify-end max-md:sticky max-md:bottom-0 max-md:z-20 max-md:-mx-4 max-md:border-t max-md:border-stone-200 max-md:bg-stone-50/90 max-md:px-4 max-md:pt-3 max-md:pb-[calc(0.75rem+env(safe-area-inset-bottom,0px))] max-md:backdrop-blur-lg dark:max-md:border-stone-800 dark:max-md:bg-stone-950/90"
        >
          <Button type="submit" variant="primary" loading={save.isPending} className="max-md:h-11 max-md:w-full max-md:justify-center">
            Save settings
          </Button>
        </div>
      </form>

      <HomeAssistantCard devices={data.devices.filter((d) => d.enabled)} />
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

