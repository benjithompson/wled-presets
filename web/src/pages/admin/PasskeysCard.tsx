import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, KeyRound, Pencil, Trash2, X } from 'lucide-react';
import { toast } from 'sonner';
import type { Passkey } from '../../../../shared/types.ts';
import { Badge, Button, Card, CardHeader, ConfirmDialog, Field, Input, Spinner } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { addPasskey, guessDeviceName, passkeyCancelled, passkeyErrorText, passkeysUnavailable } from '../../lib/passkeys.ts';
import { errorText, relativeTime } from '../../lib/utils.ts';

const PASSKEYS = ['admin', 'passkeys'];

/** The signed-in admin's passkeys: add one on this device, rename or remove them. */
export function PasskeysCard() {
  const qc = useQueryClient();
  const { data: keys, isLoading } = useQuery({ queryKey: PASSKEYS, queryFn: api.passkeys });
  const [unavailable] = useState(passkeysUnavailable);
  const [name, setName] = useState(guessDeviceName);
  const [password, setPassword] = useState('');
  const [removing, setRemoving] = useState<Passkey | null>(null);

  const add = useMutation({
    mutationFn: () => addPasskey(password, name),
    onSuccess: (key) => {
      toast.success(`Passkey "${key.name}" added`);
      setPassword('');
      void qc.invalidateQueries({ queryKey: PASSKEYS });
    },
    onError: (e) => {
      if (!passkeyCancelled(e)) toast.error(passkeyErrorText(e));
    }
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.removePasskey(id),
    onSuccess: (list) => {
      qc.setQueryData(PASSKEYS, list);
      setRemoving(null);
    },
    onError: (e) => toast.error(errorText(e))
  });

  return (
    <Card className="mt-6">
      <CardHeader
        title="Passkeys"
        description="Sign in with your phone, computer or security key (fingerprint, face or PIN) instead of typing the password."
      />
      {isLoading ? (
        <div className="p-5">
          <Spinner />
        </div>
      ) : keys?.length ? (
        <ul className="divide-y divide-stone-100 border-b border-stone-100 dark:divide-stone-800/70 dark:border-stone-800/70">
          {keys.map((k) => (
            <PasskeyRow key={k.id} passkey={k} onRemove={() => setRemoving(k)} />
          ))}
        </ul>
      ) : (
        <p className="border-b border-stone-100 px-5 py-4 text-sm text-stone-500 dark:border-stone-800/70 dark:text-stone-400">No passkeys yet.</p>
      )}
      {unavailable ? (
        <p className="m-5 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-500/10 dark:text-amber-300">{unavailable}</p>
      ) : (
        <form
          className="grid gap-5 p-5 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <Field label="Name">{(id) => <Input id={id} required maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
          <Field label="Your password">
            {(id) => <Input id={id} type="password" autoComplete="current-password" required placeholder="Confirms it is you" value={password} onChange={(e) => setPassword(e.target.value)} />}
          </Field>
          <Button type="submit" loading={add.isPending}>
            <KeyRound />
            Add a passkey
          </Button>
        </form>
      )}
      <ConfirmDialog
        open={!!removing}
        title={`Remove "${removing?.name}"?`}
        confirmLabel="Remove passkey"
        danger
        loading={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
        onClose={() => setRemoving(null)}
      >
        It stops signing in here at once. The device may still list it; you can delete it there too.
      </ConfirmDialog>
    </Card>
  );
}

function PasskeyRow({ passkey: k, onRemove }: { passkey: Passkey; onRemove: () => void }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<string | null>(null);
  const rename = useMutation({
    mutationFn: (name: string) => api.renamePasskey(k.id, name),
    onSuccess: (list) => {
      qc.setQueryData(PASSKEYS, list);
      setEditing(null);
    },
    onError: (e) => toast.error(errorText(e))
  });
  const otherSite = k.rpId !== location.hostname;
  return (
    <li className="flex flex-wrap items-center gap-3 px-5 py-3">
      <KeyRound className="size-4 shrink-0 text-stone-400" aria-hidden />
      <div className="min-w-0 flex-1">
        {editing != null ? (
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (editing.trim()) rename.mutate(editing);
            }}
          >
            <Input aria-label="Passkey name" autoFocus maxLength={60} value={editing} onChange={(e) => setEditing(e.target.value)} className="h-8" />
            <Button type="submit" size="icon" variant="ghost" aria-label="Save name" loading={rename.isPending}>
              <Check />
            </Button>
            <Button type="button" size="icon" variant="ghost" aria-label="Cancel" onClick={() => setEditing(null)}>
              <X />
            </Button>
          </form>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium">{k.name}</span>
            {k.backedUp ? <Badge>Synced</Badge> : null}
            {otherSite ? <Badge tone="amber">for {k.rpId}</Badge> : null}
          </div>
        )}
        <p className="mt-0.5 text-xs text-stone-500 dark:text-stone-400">
          Added {relativeTime(k.createdAt)} · {k.lastUsedAt ? `last used ${relativeTime(k.lastUsedAt)}` : 'not used yet'}
        </p>
      </div>
      {editing == null ? (
        <div className="flex items-center gap-1">
          <Button size="icon" variant="ghost" aria-label={`Rename ${k.name}`} title="Rename" onClick={() => setEditing(k.name)}>
            <Pencil />
          </Button>
          <Button size="icon" variant="ghost" aria-label={`Remove ${k.name}`} title="Remove" onClick={onRemove}>
            <Trash2 />
          </Button>
        </div>
      ) : null}
    </li>
  );
}
