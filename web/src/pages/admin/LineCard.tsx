import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { SkipForward, Users, X } from 'lucide-react';
import { toast } from 'sonner';
import { clock, DEFAULT_LINE, type LineSettings } from '../../../../shared/line.ts';
import { Button, Card, CardHeader, Field, Input, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { errorText } from '../../lib/utils.ts';

const KEY = ['admin', 'line'];

// Admin → Games: the line for the lights. People on the public page and the play page take
// turns: who waits, how long a turn is, and taking someone out of the line.
export function LineCard() {
  const qc = useQueryClient();
  const { data, error } = useQuery({ queryKey: KEY, queryFn: api.line, refetchInterval: 2000 });
  const [draft, setDraft] = useState<LineSettings | null>(null);
  const saved = data?.settings ?? DEFAULT_LINE;
  const s = draft ?? saved;
  const dirty = !!draft && JSON.stringify(draft) !== JSON.stringify(saved);
  useEffect(() => {
    if (draft && !dirty) setDraft(null);
  }, [draft, dirty]);

  const done = (r: Awaited<ReturnType<typeof api.line>>) => qc.setQueryData(KEY, r);
  const save = useMutation({
    mutationFn: (v: LineSettings) => api.saveLine(v),
    onSuccess: (r) => {
      done(r);
      setDraft(null);
      toast.success('Saved');
    },
    onError: (e) => toast.error(errorText(e))
  });
  const remove = useMutation({ mutationFn: api.removeFromLine, onSuccess: done, onError: (e) => toast.error(errorText(e)) });
  const pass = useMutation({ mutationFn: api.passTurn, onSuccess: done, onError: (e) => toast.error(errorText(e)) });

  if (error) return null;
  const num = (key: keyof Omit<LineSettings, 'enabled'>) => (e: React.ChangeEvent<HTMLInputElement>) => setDraft({ ...s, [key]: Number(e.target.value) });

  return (
    <Card className="mb-5">
      <CardHeader
        title={
          <span className="inline-flex items-center gap-2">
            <Users className="size-4" /> Taking turns
          </span>
        }
        description="The site is open to anyone, so people take turns with the lights, like an arcade line: a tap when the lights are busy joins the line. Off: the last tap wins at once (fine on a home network). Signed-in admins never wait."
        actions={
          <>
            <Switch checked={s.enabled} onChange={(v) => save.mutate({ ...s, enabled: v })} label="Take turns" disabled={!data || save.isPending} />
            {dirty ? (
              <Button variant="primary" onClick={() => save.mutate(s)} loading={save.isPending}>
                Save
              </Button>
            ) : null}
          </>
        }
      />
      {s.enabled ? (
        <div className="grid gap-4 px-5 py-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Quick turn (seconds)" hint="A scene or a color picked while nobody else waits keeps the lights this long.">
            {(id) => <Input id={id} type="number" min={3} max={600} value={s.quickSeconds} onChange={num('quickSeconds')} />}
          </Field>
          <Field label="Busy turn (seconds)" hint="A scene or a color whose turn comes while others still wait plays this long.">
            {(id) => <Input id={id} type="number" min={10} max={3600} value={s.showSeconds} onChange={num('showSeconds')} />}
          </Field>
          <Field label="Game turn (minutes)" hint="Once someone waits, a turn ends with its game, or this long after the wait began.">
            {(id) => <Input id={id} type="number" min={1} max={60} step={0.5} value={s.turnMinutes} onChange={num('turnMinutes')} />}
          </Field>
          <Field label="Time to tap Play (seconds)" hint="The next player has this long, or the line moves on.">
            {(id) => <Input id={id} type="number" min={10} max={300} value={s.offerSeconds} onChange={num('offerSeconds')} />}
          </Field>
        </div>
      ) : null}
      {data && s.enabled ? (
        <div className="border-t border-stone-100 px-5 py-4 text-sm dark:border-stone-800">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p>
              <span className="text-stone-500 dark:text-stone-400">Now: </span>
              {data.now ? (
                <>
                  <b>{data.now.label}</b> ({data.now.kind === 'game' ? 'a game' : data.now.kind}, for {clock(Date.now() - data.now.since)}
                  {data.now.endsIn != null && data.entries.length ? `, ends in ${clock(data.now.endsIn)}` : ''})
                </>
              ) : data.offer ? (
                <>
                  waiting for the next player to tap Play ({clock(data.offer.endsIn)} left)
                </>
              ) : (
                'nobody: the lights are free'
              )}
            </p>
            {data.now || data.offer ? (
              <Button size="sm" onClick={() => pass.mutate()} loading={pass.isPending} title="End this turn now: the next in line goes">
                <SkipForward /> End this turn
              </Button>
            ) : null}
          </div>
          {data.entries.length ? (
            <ol className="mt-3 divide-y divide-stone-100 rounded-xl ring-1 ring-stone-200/80 dark:divide-stone-800 dark:ring-stone-800">
              {data.entries.map((e, i) => (
                <li key={e.id} className="flex items-center justify-between gap-3 px-3 py-2">
                  <span>
                    <span className="mr-2 text-stone-400 tabular-nums">{i + 1}.</span>
                    {e.label} <span className="text-stone-500 dark:text-stone-400">· {e.kind === 'game' ? 'game' : e.kind} · waiting {clock(e.waited)}</span>
                    {i === 0 && data.offer ? <span className="ml-2 text-amber-600 dark:text-amber-400">being asked to play</span> : null}
                  </span>
                  <button type="button" onClick={() => remove.mutate(e.id)} className="rounded-full p-1 text-stone-400 hover:bg-stone-100 hover:text-stone-700 dark:hover:bg-stone-800 dark:hover:text-stone-200" aria-label={`Take ${e.label} out of the line`}>
                    <X className="size-4" />
                  </button>
                </li>
              ))}
            </ol>
          ) : (
            <p className="mt-2 text-stone-500 dark:text-stone-400">Nobody is waiting.</p>
          )}
        </div>
      ) : null}
    </Card>
  );
}
