// Games: which lights the games on /play use. Leave out lights that cannot be seen (around a
// corner of the house, behind a tree), whole objects, segments of a line, or LEDs at its ends.
// Scenes and effects still use every light.
import { useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, Gamepad2, Radio, RotateCcw, Save } from 'lucide-react';
import { toast } from 'sonner';
import { framePut } from '../../../../shared/editorView.ts';
import { activeLeds, buildStage, editorPulse, gameLeds, GAME_OUT_RGB, GAME_ROLE_RGB, GAME_UNSEEN_RGB, isLine, paintGameArea, roofHidden, segmentLeds, type Fixture, type FixtureKind, type GameArea } from '../../../../shared/layout.ts';
import { Badge, Button, Card, CardHeader, Empty, Input, PageHeader, Spinner, Switch } from '../../components/ui.tsx';
import { PhoneActionBar } from '../../components/mobile.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { useInFront } from '../../lib/useInFront.ts';
import { useLightsPreview } from '../../lib/useLightsPreview.ts';
import { YardView } from '../../yard/YardView.tsx';
import { LineCard } from './LineCard.tsx';

const AREA = ['admin', 'game-area'];

const ROLES: { kind: FixtureKind[]; label: string; role: string }[] = [
  { kind: ['roof'], label: 'Roof', role: 'where the game is played' },
  { kind: ['bush'], label: 'Bushes', role: 'hold what you win' },
  { kind: ['tree'], label: 'Trees', role: 'meters that fill up' },
  { kind: ['line', 'semicircle', 'custom'], label: 'Other lights', role: 'the house reacts' }
];

const css = (c: [number, number, number]) => `rgb(${c.join(' ')})`;

/** The area without empty entries, so an unchanged area compares equal. */
function tidy(a: GameArea | null): GameArea {
  const skip = Object.fromEntries(Object.entries(a?.skip ?? {}).filter(([, v]) => v.length).map(([k, v]) => [k, [...v].sort((x, y) => x - y)]));
  const trim = Object.fromEntries(Object.entries(a?.trim ?? {}).filter(([, [x, y]]) => x > 0 || y > 0));
  return { exclude: [...(a?.exclude ?? [])].sort(), skip, trim };
}

export function GamesPage() {
  const qc = useQueryClient();
  const { data: layout, isLoading } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const { data: saved } = useQuery({ queryKey: AREA, queryFn: api.gameArea });
  const [draft, setDraft] = useState<GameArea | null>(null);
  const [focus, setFocus] = useState<{ id: string; segment: number | null } | null>(null);
  const [onLights, setOnLights] = useState(false);
  const [lightNames, setLightNames] = useState<string[]>([]);

  const base = useMemo(() => tidy(saved?.area ?? null), [saved]);
  const area = draft ?? base;
  const dirty = JSON.stringify(tidy(area)) !== JSON.stringify(base);
  const edit = (fn: (a: GameArea) => GameArea) => setDraft((d) => tidy(fn(tidy(d ?? base))));

  const save = useMutation({
    mutationFn: () => api.saveGameArea(tidy(area)),
    onSuccess: (r) => {
      qc.setQueryData(AREA, r);
      setDraft(null);
      toast.success('Saved. New games use these lights.');
    },
    onError: (e) => toast.error(errorText(e))
  });

  // The view: the stage offsets of each object, and a frame painted from the area.
  const stage = useMemo(() => (layout ? buildStage(layout) : null), [layout]);
  const frame = useRef<Uint8Array | null>(null);
  const live = useRef({ area, focus });
  live.current = { area, focus };
  const getFrame = () => {
    if (!layout || !stage) return null;
    if (!frame.current || frame.current.length !== stage.pixelCount * 3) frame.current = new Uint8Array(stage.pixelCount * 3);
    const out = frame.current;
    paintGameArea(layout, live.current.area, live.current.focus, editorPulse(Date.now()), framePut(stage, out));
    return out;
  };

  // Show on the lights: the same picture on the real lights, kept alive while the page is open.
  const inFront = useInFront();
  useLightsPreview(onLights && inFront && layout ? { layout, selected: focus?.id ?? null, corner: null, segment: focus?.segment ?? null, area: tidy(area) } : null, {
    active: onLights && inFront,
    onDevices: setLightNames,
    onError: (e) => (setLightNames([]), toast.error(errorText(e)))
  });

  const fixtures = layout?.fixtures ?? [];
  const inGame = (f: Fixture) => gameLeds(f, area).reduce((n, v) => n + v, 0);
  const total = fixtures.reduce((n, f) => n + activeLeds(f).reduce((m, v) => m + v, 0), 0);
  const used = fixtures.reduce((n, f) => n + inGame(f), 0);
  // Roof LEDs that cannot be seen from the street: games hurry through them on their own.
  const unseen = useMemo(() => {
    if (!layout) return 0;
    let n = 0;
    for (const hidden of roofHidden(layout, area).values()) for (const v of hidden) n += v;
    return n;
  }, [layout, area]);

  return (
    <>
      <PageHeader
        title="Games"
        description="Choose the lights that games play on. Games follow the roof as it looks from the street, so things move evenly across the front: where the roof runs back along the side of the house or behind another part of it, they still pass through it, very quickly. Leave out other lights that cannot be seen here: a whole object, segments of a line, or LEDs at its ends. Scenes and effects still use every light."
        more={[
          {
            label: 'Use every light',
            icon: RotateCcw,
            run: () => setDraft({}),
            disabled: !fixtures.length || (!area.exclude?.length && !Object.keys(area.skip ?? {}).length && !Object.keys(area.trim ?? {}).length)
          }
        ]}
        actions={
          <>
            <Button
              onClick={() => setOnLights((v) => !v)}
              title="Show this picture on the real lights, so you can see which lights are in"
              aria-label={onLights ? 'Showing on the lights' : 'Show on the lights'}
              aria-pressed={onLights}
            >
              <Radio className={onLights ? 'text-emerald-500' : undefined} /> <span className="sm:hidden">Lights</span>
              <span className="max-sm:hidden">{onLights ? 'Showing on the lights' : 'Show on the lights'}</span>
            </Button>
            <Button variant="primary" onClick={() => save.mutate()} disabled={!dirty} loading={save.isPending} className="max-md:hidden">
              <Save /> Save
            </Button>
          </>
        }
      />

      <LineCard />

      {isLoading ? (
        <Card className="grid place-items-center py-16">
          <Spinner />
        </Card>
      ) : !layout || !fixtures.length ? (
        <Card>
          <Empty icon={<Gamepad2 />} title="No lights in the layout yet">
            Draw the roofline, bushes and trees in the layout editor first. Games play on them.
          </Empty>
        </Card>
      ) : (
        <div className="space-y-5">
          <Card className="overflow-hidden">
            <div className="bg-stone-950 p-3 sm:p-4">
              <YardView layout={layout} getFrame={getFrame} maxHeight="46dvh" highlight={focus?.id ?? null} onPick={(id) => setFocus(id ? { id, segment: null } : null)} />
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3 text-xs text-stone-600 dark:text-stone-400">
              {ROLES.map((r) => (
                <span key={r.label} className="inline-flex items-center gap-1.5">
                  <span className="size-2.5 rounded-full" style={{ background: css(GAME_ROLE_RGB[r.kind[0]]) }} />
                  <b className="font-medium text-stone-800 dark:text-stone-200">{r.label}</b> {r.role}
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2.5 rounded-full" style={{ background: css(GAME_OUT_RGB.map((v) => v * 2.5) as [number, number, number]) }} />
                <b className="font-medium text-stone-800 dark:text-stone-200">Left out</b> stays dark in games
              </span>
              {unseen > 0 && (
                <span className="inline-flex items-center gap-1.5" title="Found from the layout's 3-D positions: roof LEDs that run away from the street, or sit behind other roof LEDs as seen from the front">
                  <span className="size-2.5 rounded-full" style={{ background: css(GAME_UNSEEN_RGB.map((v) => v * 2.5) as [number, number, number]) }} />
                  <b className="font-medium text-stone-800 dark:text-stone-200">Not seen from the street</b> {unseen} roof lights games hurry through
                </span>
              )}
              <span className="ml-auto tabular-nums">
                {used} of {total} lights in games
                {onLights ? ` · on ${lightNames.length ? lightNames.join(', ') : 'no device (give objects a device in the layout)'}` : ''}
              </span>
            </div>
          </Card>

          {ROLES.map((r) => {
            const list = fixtures.filter((f) => r.kind.includes(f.kind));
            if (!list.length) return null;
            return (
              <Card key={r.label}>
                <CardHeader title={r.label} description={`In games: ${r.role}.`} />
                <ul className="divide-y divide-stone-100 dark:divide-stone-800">
                  {list.map((f) => (
                    <ObjectRow key={f.id} f={f} area={area} edit={edit} focus={focus} setFocus={setFocus} inGame={inGame(f)} />
                  ))}
                </ul>
              </Card>
            );
          })}
        </div>
      )}

      <PhoneActionBar show={dirty}>
        <span className="min-w-0 flex-1 text-sm text-stone-600 dark:text-stone-300">Unsaved changes</span>
        <Button onClick={() => setDraft(null)}>Discard</Button>
        <Button variant="primary" onClick={() => save.mutate()} loading={save.isPending}>
          <Save /> Save
        </Button>
      </PhoneActionBar>
    </>
  );
}

function ObjectRow({
  f,
  area,
  edit,
  focus,
  setFocus,
  inGame
}: {
  f: Fixture;
  area: GameArea;
  edit: (fn: (a: GameArea) => GameArea) => void;
  focus: { id: string; segment: number | null } | null;
  setFocus: (f: { id: string; segment: number | null } | null) => void;
  inGame: number;
}) {
  const [open, setOpen] = useState(false);
  const included = !area.exclude?.includes(f.id);
  const line = isLine(f) && f.points.length > 1;
  const lit = activeLeds(f).reduce((n, v) => n + v, 0);
  const skip = area.skip?.[f.id] ?? [];
  const [start, end] = area.trim?.[f.id] ?? [0, 0];
  const n = Math.max(0, Math.floor(f.pixels));
  const clamp = (v: number) => Math.max(0, Math.min(n, v));
  const setTrim = (end: 0 | 1, v: number) =>
    edit((x) => {
      const t: [number, number] = [...(x.trim?.[f.id] ?? [0, 0])];
      t[end] = clamp(v);
      return { ...x, trim: { ...x.trim, [f.id]: t } };
    });
  const toggleSeg = (k: number) =>
    edit((x) => {
      const cur = x.skip?.[f.id] ?? [];
      return { ...x, skip: { ...x.skip, [f.id]: cur.includes(k) ? cur.filter((s) => s !== k) : [...cur, k] } };
    });
  const focused = focus?.id === f.id;

  return (
    <li onPointerEnter={() => setFocus({ id: f.id, segment: null })} className={cn('px-4 py-3 sm:px-5', focused && 'bg-sky-50/60 dark:bg-sky-500/5')}>
      <div className="flex flex-wrap items-center gap-3">
        <Switch checked={included} onChange={(v) => edit((x) => ({ ...x, exclude: v ? (x.exclude ?? []).filter((id) => id !== f.id) : [...(x.exclude ?? []), f.id] }))} label={`Use ${f.name} in games`} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{f.name}</p>
          <p className="text-xs text-stone-500 tabular-nums">{included ? (inGame === lit ? `All ${lit} lights` : `${inGame} of ${lit} lights`) : 'Left out of games'}</p>
        </div>
        {included && inGame < lit ? <Badge tone="amber">Shortened</Badge> : null}
        {line && included ? (
          <Button size="sm" variant="ghost" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
            Segments and ends <ChevronDown className={cn('transition', open && 'rotate-180')} />
          </Button>
        ) : null}
      </div>

      {line && included && open ? (
        <div className="mt-3 space-y-3 sm:pl-[3.25rem]">
          <div className="flex flex-wrap items-end gap-3">
            <label className="space-y-1 text-xs text-stone-600 dark:text-stone-400">
              <span className="block">Leave out at the start (point 1)</span>
              <Input type="number" min={0} max={n} className="h-9 w-32" value={start || ''} placeholder="0 LEDs" onChange={(e) => setTrim(0, Number(e.target.value) || 0)} />
            </label>
            <label className="space-y-1 text-xs text-stone-600 dark:text-stone-400">
              <span className="block">Leave out at the end (point {f.points.length})</span>
              <Input type="number" min={0} max={n} className="h-9 w-32" value={end || ''} placeholder="0 LEDs" onChange={(e) => setTrim(1, Number(e.target.value) || 0)} />
            </label>
            <p className="pb-2 text-xs text-stone-500">Counted along the line as drawn, from point 1.</p>
          </div>
          <div className="flex flex-wrap gap-1.5" onPointerLeave={() => setFocus({ id: f.id, segment: null })}>
            {f.points.slice(0, -1).map((_, k) => {
              const { lo, hi } = segmentLeds(f, k);
              const offInLayout = f.skip?.includes(k);
              const on = !offInLayout && !skip.includes(k);
              return (
                <button
                  key={k}
                  type="button"
                  disabled={offInLayout}
                  onPointerEnter={() => setFocus({ id: f.id, segment: k })}
                  onClick={() => toggleSeg(k)}
                  aria-pressed={on}
                  title={offInLayout ? 'This segment is off in the layout' : on ? 'In games. Click to leave it out.' : 'Left out of games. Click to use it.'}
                  className={cn(
                    'rounded-lg px-2.5 py-1.5 text-left text-xs ring-1 transition disabled:cursor-not-allowed disabled:opacity-40',
                    on ? 'bg-amber-50 text-amber-900 ring-amber-200 hover:bg-amber-100 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/30' : 'bg-red-50 text-red-800 line-through ring-red-200 hover:bg-red-100 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-500/30',
                    focus?.id === f.id && focus.segment === k && 'ring-2 ring-sky-500'
                  )}
                >
                  <span className="font-semibold">
                    {k + 1}→{k + 2}
                  </span>{' '}
                  <span className="opacity-70">{hi - lo + 1} LEDs</span>
                </button>
              );
            })}
          </div>
          <p className="text-xs text-stone-500">Point to a segment to find it in the picture (and on the house, with Show on the lights). Click it to leave it out.</p>
        </div>
      ) : null}
    </li>
  );
}
