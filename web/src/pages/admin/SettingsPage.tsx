import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Button, Card, CardHeader, Field, Input, PageHeader, Spinner, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { errorText } from '../../lib/utils.ts';
import { PasskeysCard } from './PasskeysCard.tsx';
import { LineCard } from './LineCard.tsx';
import { useSettingsDraft } from './settingsDraft.ts';

/**
 * Admin → Settings: the site itself. What visitors see and how they share the lights, and the
 * admin's own account. Settings for one part of the site are on its page: scenes' playback on
 * Scenes, the schedule on Schedule, the frame rate and Home Assistant on Devices.
 */
export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="The public page, taking turns, and your account. The rest are where they belong: playing scenes on Scenes, on and off times on Schedule, frame rate and Home Assistant on Devices." />
      <h2 className="mb-3 text-xs font-semibold tracking-wide text-stone-500 uppercase">Visitors</h2>
      <PublicPageCard />
      <LineCard />
      <h2 className="mt-10 mb-3 text-xs font-semibold tracking-wide text-stone-500 uppercase">Your account</h2>
      <PasswordCard />
      <PasskeysCard />
    </>
  );
}

const PUBLIC_KEYS = ['siteTitle', 'siteSubtitle', 'showColors'] as const;

function PublicPageCard() {
  const s = useSettingsDraft(PUBLIC_KEYS, (v) => ({ ...v, siteTitle: v.siteTitle.trim(), siteSubtitle: v.siteSubtitle.trim() }));
  if (!s.value) {
    return (
      <Card className="mb-5 grid place-items-center py-10">
        <Spinner />
      </Card>
    );
  }
  const v = s.value;
  return (
    <Card className="mb-5">
      <CardHeader
        title="Public page"
        description="What visitors see at the root address."
        actions={
          s.dirty ? (
            <>
              <Button variant="ghost" onClick={s.undo}>
                Undo
              </Button>
              <Button variant="primary" onClick={s.save} loading={s.saving} disabled={!v.siteTitle.trim()}>
                Save
              </Button>
            </>
          ) : null
        }
      />
      <form
        className="grid gap-5 p-5 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (s.dirty && v.siteTitle.trim()) s.save();
        }}
      >
        <Field label="Title">{(id) => <Input id={id} value={v.siteTitle} maxLength={80} required onChange={(e) => s.set('siteTitle', e.target.value)} />}</Field>
        <Field label="Subtitle">{(id) => <Input id={id} value={v.siteSubtitle} maxLength={200} onChange={(e) => s.set('siteSubtitle', e.target.value)} />}</Field>
        <label className="flex items-center justify-between gap-4 sm:col-span-2">
          <span>
            <span className="block text-sm font-medium">Show color picker</span>
            <span className="block text-xs text-stone-500">Lets visitors set all lights to one solid color.</span>
          </span>
          <Switch label="Show color picker" checked={v.showColors} onChange={(x) => s.set('showColors', x)} />
        </label>
        <button type="submit" hidden />
      </form>
    </Card>
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
    <Card>
      <CardHeader title="Password" description="Change the password for this admin account." />
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

