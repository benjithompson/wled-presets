// Games: which games visitors see, and which lights the games on /play use. Leave out lights that
// cannot be seen (around a corner of the house, behind a tree), whole objects, segments of a
// line, or LEDs at its ends; and one game can have its own choice of objects. Scenes and
// effects still use every light.
import { useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, Eye, EyeOff, Gamepad2, Link2, Radio, RotateCcw, Save, SlidersHorizontal, Undo2 } from 'lucide-react';
import { toast } from 'sonner';
import { framePut } from '../../../../shared/editorView.ts';
import { activeLeds, buildStage, editorPulse, gameAreaFor, gameLeds, GAME_OUT_RGB, GAME_ROLE_RGB, GAME_UNSEEN_RGB, isLine, paintGameArea, roofHidden, segmentLeds, type Fixture, type FixtureKind, type GameArea } from '../../../../shared/layout.ts';
import { Badge, Button, Card, CardHeader, Empty, Input, PageHeader, Select, Spinner, Switch } from '../../components/ui.tsx';
import { PhoneActionBar } from '../../components/mobile.tsx';
import { api } from '../../lib/api.ts';
import { cn, copyLink, errorText } from '../../lib/utils.ts';
import { gameLook } from '../../lib/gameLooks.ts';
import { GAME_CATALOG } from '../../../../shared/games.ts';
import { gamePath } from '../../../../shared/links.ts';
import { useInFront } from '../../lib/useInFront.ts';
import { useLightsPreview } from '../../lib/useLightsPreview.ts';
import { YardView } from '../../yard/YardView.tsx';
import { LineCard } from './LineCard.tsx';

const AREA = ['admin', 'game-area'];
const HIDDEN = ['admin', 'hidden-games'];

const ROLES: { kind: FixtureKind[]; label: string; role: string }[] = [
  { kind: ['roof'], label: 'Roof', role: 'where the game is played' },
  { kind: ['bush'], label: 'Bushes', role: 'hold what you win' },
  { kind: ['tree'], label: 'Trees', role: 'meters that fill up' },
  { kind: ['line', 'semicircle', 'custom'], label: 'Other lights', role: 'the house reacts' }
];

const css = (c: [number, number, number]) => `rgb(${c.join(' ')})`;

const byKey = <T,>(entries: [string, T][]) => entries.sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0));

/** The area without empty entries, so an unchanged area compares equal. */
function tidy(a: GameArea | null): GameArea {
  const skip = Object.fromEntries(Object.entries(a?.skip ?? {}).filter(([, v]) => v.length).map(([k, v]) => [k, [...v].sort((x, y) => x - y)]));
  const trim = Object.fromEntries(Object.entries(a?.trim ?? {}).filter(([, [x, y]]) => x > 0 || y > 0));
  const games = Object.fromEntries(
    byKey(Object.entries(a?.games ?? {}))
      .map(([g, own]) => [g, Object.fromEntries(byKey(Object.entries(own)))] as [string, Record<string, boolean>])
      .filter(([, own]) => Object.keys(own).length)
  );
  return { exclude: [...(a?.exclude ?? [])].sort(), skip, trim, ...(Object.keys(games).length ? { games } : {}) };
}

/** How many objects a game has its own choice for (see GameArea.games), counting only objects in the layout. */
const ownCount = (area: GameArea, game: string, fixtures: Fixture[]) => fixtures.filter((f) => area.games?.[game]?.[f.id] !== undefined).length;

export function GamesPage() {
  const qc = useQueryClient();
  const { data: layout, isLoading } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const { data: saved } = useQuery({ queryKey: AREA, queryFn: api.gameArea });
  const [draft, setDraft] = useState<GameArea | null>(null);
  const [focus, setFocus] = useState<{ id: string; segment: number | null } | null>(null);
  const [onLights, setOnLights] = useState(false);
  const [lightNames, setLightNames] = useState<string[]>([]);
  /** The game whose own lights are being chosen; null: the lights for all games. */
  const [game, setGame] = useState<string | null>(null);
  const gameName = GAME_CATALOG.find((g) => g.id === game)?.name ?? null;
  const yardRef = useRef<HTMLDivElement>(null);

  const base = useMemo(() => tidy(saved?.area ?? null), [saved]);
  const area = draft ?? base;
  const dirty = JSON.stringify(tidy(area)) !== JSON.stringify(base);
  const edit = (fn: (a: GameArea) => GameArea) => setDraft((d) => tidy(fn(tidy(d ?? base))));
  /** What the picture, the counts and the lights show: the lights of the game chosen, or of all games. */
  const view = useMemo(() => (game ? tidy(gameAreaFor(area, game)) : area), [area, game]);
  /** In a game's own choice: uses the object, or not, whatever all games do (back to the same as all games when it matches). */
  const setOwn = (id: string, used: boolean) =>
    edit((x) => {
      if (!game) return x;
      const own = { ...x.games?.[game] };
      if (used === !x.exclude?.includes(id)) delete own[id];
      else own[id] = used;
      return { ...x, games: { ...x.games, [game]: own } };
    });
  const resetOwn = (g: string) => edit((x) => ({ ...x, games: { ...x.games, [g]: {} } }));
  const chooseFor = (g: string | null) => {
    setGame(g);
    yardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  // Games visitors can pick: a switch saves at once.
  const { data: hiddenData } = useQuery({ queryKey: HIDDEN, queryFn: api.hiddenGames });
  const hidden = hiddenData?.hidden ?? [];
  const setHidden = useMutation({
    mutationFn: (ids: string[]) => api.saveHiddenGames(ids),
    onMutate: (ids) => {
      const prev = qc.getQueryData(HIDDEN);
      qc.setQueryData(HIDDEN, { hidden: ids });
      return { prev };
    },
    onSuccess: (r) => qc.setQueryData(HIDDEN, r),
    onError: (e, _ids, ctx) => {
      qc.setQueryData(HIDDEN, ctx?.prev);
      toast.error(errorText(e));
    }
  });

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
  const live = useRef({ area: view, focus });
  live.current = { area: view, focus };
  const getFrame = () => {
    if (!layout || !stage) return null;
    if (!frame.current || frame.current.length !== stage.pixelCount * 3) frame.current = new Uint8Array(stage.pixelCount * 3);
    const out = frame.current;
    paintGameArea(layout, live.current.area, live.current.focus, editorPulse(Date.now()), framePut(stage, out));
    return out;
  };

  // Show on the lights: the same picture on the real lights, kept alive while the page is open.
  const inFront = useInFront();
  useLightsPreview(onLights && inFront && layout ? { layout, selected: focus?.id ?? null, corner: null, segment: focus?.segment ?? null, area: view } : null, {
    active: onLights && inFront,
    onDevices: setLightNames,
    onError: (e) => (setLightNames([]), toast.error(errorText(e)))
  });

  const fixtures = layout?.fixtures ?? [];
  const inGame = (f: Fixture) => gameLeds(f, view).reduce((n, v) => n + v, 0);
  const total = fixtures.reduce((n, f) => n + activeLeds(f).reduce((m, v) => m + v, 0), 0);
  const used = fixtures.reduce((n, f) => n + inGame(f), 0);
  // Roof LEDs that cannot be seen from the street: games hurry through them on their own.
  const unseen = useMemo(() => {
    if (!layout) return 0;
    let n = 0;
    for (const hid of roofHidden(layout, view).values()) for (const v of hid) n += v;
    return n;
  }, [layout, view]);

  return (
    <>
      <PageHeader
        title="Games"
        description="Choose which games visitors can pick, and the lights that games play on. Games follow the roof as it looks from the street, so things move evenly across the front: where the roof runs back along the side of the house or behind another part of it, they still pass through it, very quickly. Leave out other lights that cannot be seen here: a whole object, segments of a line, or LEDs at its ends. Scenes and effects still use every light."
        more={[
          game
            ? { label: 'Same lights as all games', icon: Undo2, run: () => resetOwn(game), disabled: !ownCount(area, game, fixtures) }
            : {
                label: 'Use every light',
                icon: RotateCcw,
                run: () => setDraft({}),
                disabled: !fixtures.length || (!area.exclude?.length && !Object.keys(area.skip ?? {}).length && !Object.keys(area.trim ?? {}).length && !area.games)
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

      <GameList hidden={hidden} onHide={(ids) => setHidden.mutate(ids)} area={area} fixtures={fixtures} game={game} onChoose={chooseFor} />

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
          <Card className="scroll-mt-4 overflow-hidden">
            <div ref={yardRef} className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-stone-100 px-5 py-3 dark:border-stone-800">
              <label htmlFor="lights-for" className="text-sm font-medium">
                Lights for
              </label>
              <div className="w-56 max-sm:flex-1">
                <Select id="lights-for" className="h-9" value={game ?? ''} onChange={(e) => setGame(e.target.value || null)}>
                  <option value="">All games</option>
                  {GAME_CATALOG.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                      {ownCount(area, g.id, fixtures) ? ' (its own)' : ''}
                    </option>
                  ))}
                </Select>
              </div>
              <p className="min-w-0 flex-1 text-xs text-stone-500 dark:text-stone-400">
                {game
                  ? `Switch objects on or off for ${gameName} only. Segments and ends are the same for every game.`
                  : 'What every game uses, unless a game has its own choice of objects.'}
              </p>
            </div>
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
                {used} of {total} lights in {gameName ?? 'games'}
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
                    <ObjectRow key={f.id} f={f} area={area} view={view} game={game ? { id: game, name: gameName ?? game } : null} edit={edit} setOwn={setOwn} focus={focus} setFocus={setFocus} inGame={inGame(f)} />
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
  view,
  game,
  edit,
  setOwn,
  focus,
  setFocus,
  inGame
}: {
  f: Fixture;
  /** The area as it is edited (for all games, with each game's own choice). */
  area: GameArea;
  /** The area shown: of the game chosen, else of all games. */
  view: GameArea;
  /** The game whose own lights are chosen; null: all games. */
  game: { id: string; name: string } | null;
  edit: (fn: (a: GameArea) => GameArea) => void;
  setOwn: (id: string, used: boolean) => void;
  focus: { id: string; segment: number | null } | null;
  setFocus: (f: { id: string; segment: number | null } | null) => void;
  inGame: number;
}) {
  const [open, setOpen] = useState(false);
  const included = !view.exclude?.includes(f.id);
  const own = game ? area.games?.[game.id]?.[f.id] : undefined;
  // Segments and ends are set for all games.
  const line = isLine(f) && f.points.length > 1 && !game;
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
        <Switch
          checked={included}
          onChange={(v) => (game ? setOwn(f.id, v) : edit((x) => ({ ...x, exclude: v ? (x.exclude ?? []).filter((id) => id !== f.id) : [...(x.exclude ?? []), f.id] })))}
          label={`Use ${f.name} in ${game?.name ?? 'games'}`}
        />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{f.name}</p>
          <p className="text-xs text-stone-500 tabular-nums">{included ? (inGame === lit ? `All ${lit} lights` : `${inGame} of ${lit} lights`) : `Left out of ${game?.name ?? 'games'}`}</p>
        </div>
        {included && inGame < lit ? <Badge tone="amber">Shortened</Badge> : null}
        {own !== undefined ? (
          <>
            <Badge tone="blue">{own ? `Only in ${game!.name}` : `Not in ${game!.name}`}</Badge>
            <Button size="sm" variant="ghost" onClick={() => setOwn(f.id, !own)} title="Use it as all games do">
              <Undo2 /> <span className="max-sm:hidden">Same as all games</span>
            </Button>
          </>
        ) : null}
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

/**
 * Every game: whether visitors can pick it (saved at once), whether it has its own choice of
 * lights, and its link to share.
 */
function GameList({
  hidden,
  onHide,
  area,
  fixtures,
  game,
  onChoose
}: {
  hidden: string[];
  onHide: (ids: string[]) => void;
  area: GameArea;
  fixtures: Fixture[];
  game: string | null;
  onChoose: (id: string | null) => void;
}) {
  const shown = GAME_CATALOG.length - GAME_CATALOG.filter((g) => hidden.includes(g.id)).length;
  return (
    <Card className="mb-5">
      <CardHeader
        title="Games"
        description={`${shown} of ${GAME_CATALOG.length} on the play page. Hidden games stay out of the home page and the play page for visitors; signed in, you still see them, to try them.`}
      />
      <ul className="divide-y divide-stone-100 dark:divide-stone-800">
        {GAME_CATALOG.map((g) => {
          const look = gameLook(g.id);
          const Icon = look.icon;
          const on = !hidden.includes(g.id);
          const own = ownCount(area, g.id, fixtures);
          return (
            <li key={g.id} className={cn('flex flex-wrap items-center gap-3 px-4 py-3 sm:px-5', game === g.id && 'bg-sky-50/60 dark:bg-sky-500/5')}>
              <Switch checked={on} onChange={(v) => onHide(v ? hidden.filter((id) => id !== g.id) : [...hidden, g.id])} label={`Show ${g.name} to visitors`} />
              <span className={cn('grid size-8 shrink-0 place-items-center rounded-lg bg-gradient-to-br text-white shadow-sm', look.className, !on && 'opacity-40 grayscale')}>
                <Icon className="size-4" />
              </span>
              <div className="min-w-0 flex-1">
                <p className={cn('truncate text-sm font-medium', !on && 'text-stone-500')}>{g.name}</p>
                <p className="text-xs text-stone-500">
                  {on ? (
                    <>
                      <Eye className="mr-1 inline size-3" />
                      On the play page
                    </>
                  ) : (
                    <>
                      <EyeOff className="mr-1 inline size-3" />
                      Hidden from visitors
                    </>
                  )}
                  {' · '}
                  {own ? `its own choice for ${own} object${own === 1 ? '' : 's'}` : 'the lights of all games'}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <Button size="sm" variant="ghost" onClick={() => onChoose(game === g.id ? null : g.id)} aria-pressed={game === g.id} title={`Choose the objects ${g.name} plays on`}>
                  <SlidersHorizontal /> <span className="max-sm:hidden">Lights</span>
                </Button>
                <Button size="sm" variant="ghost" onClick={() => void copyLink(gamePath(g.id), `Link to ${g.name}`)} title={`Copy a link that opens ${g.name}`}>
                  <Link2 /> <span className="max-sm:hidden">Copy link</span>
                </Button>
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
