import { useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent, type ReactNode } from 'react';
import { useParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Clock, Eye, EyeOff, Gamepad2, Loader2, Moon, Palette, Power, Settings2, Sparkles, Users, WifiOff, type LucideIcon } from 'lucide-react';
import { toast } from 'sonner';
import type { PublicScene, PublicState } from '../../../shared/types.ts';
import { useMedia } from '../lib/useMedia.ts';
import { burst } from '../components/Burst.tsx';
import { ColorPicker } from '../components/ColorPicker.tsx';
import { ThemeCycleButton } from '../components/ThemeToggle.tsx';
import { fieldBurst, fieldPreview, LightField } from '../lightfield/LightField.tsx';
import type { Look } from '../lightfield/engine.ts';
import { useTheme } from '../lib/theme.ts';
import { useBackgroundSpeed } from '../lib/backgroundSpeed.ts';
import { SpeedControl } from '../components/SpeedControl.tsx';
import { api, isQueued } from '../lib/api.ts';
import { clock, ordinal, type LineView } from '../../../shared/line.ts';
import { useCountdown } from '../lib/useCountdown.ts';
import { gameLook } from '../lib/gameLooks.ts';
import { GAME_CATALOG } from '../../../shared/games.ts';
import { findScene, gamePath } from '../../../shared/links.ts';
import { useEvents } from '../lib/useEvents.ts';
import { fromHex, hex, mix } from '../../../shared/color.ts';
import { cn, errorText, relativeTime, soonTime } from '../lib/utils.ts';
import { colorName } from '../lib/colorName.ts';
import { Roofline, useRoofStream } from '../components/Roofline.tsx';
import { LiveYard } from '../yard/LiveYard.tsx';
import { LevelSlider, PowerButton, useLightControls, useLightMutations } from '../components/LightControls.tsx';

const KEY = ['public-state'];

export function PublicPage() {
  const qc = useQueryClient();
  const { data: state, isLoading, error } = useQuery({ queryKey: KEY, queryFn: api.state, refetchInterval: 60_000 });
  // Signed in as an admin: a bar with the way back to the console, and the lights' switches.
  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.session, staleTime: 60_000 });
  const admin = !!session?.user;
  const roof = useRoofStream();
  const [pending, setPending] = useState<string | null>(null);

  // The line for the lights: who has them, and this visitor's place.
  const [line, setLine] = useState<LineView | null>(null);
  // The server pushes the full state on every change.
  useEvents('/api/events', {
    state: (d) => {
      qc.setQueryData(KEY, JSON.parse(d) as PublicState);
      // Another admin may have switched the lights: the bar follows.
      if (admin) void qc.invalidateQueries({ queryKey: ['admin', 'lights'] });
    },
    line: (d) => setLine(JSON.parse(d) as LineView)
  });

  useEffect(() => {
    if (state?.title) document.title = state.title;
  }, [state?.title]);

  const optimistic = (patch: Partial<PublicState>) => qc.setQueryData<PublicState>(KEY, (s) => (s ? { ...s, ...patch } : s));

  const scene = useMutation({
    mutationFn: (id: string) => api.applyScene(id),
    onMutate: (id) => {
      setPending(id);
      const prev = qc.getQueryData<PublicState>(KEY);
      optimistic({ currentSceneId: id, currentColor: null });
      return { prev };
    },
    onSuccess: (r, _id, ctx) => {
      // The lights are busy: it waits in line, and the page shows what plays now.
      if (!isQueued(r)) return;
      if (ctx?.prev) qc.setQueryData(KEY, ctx.prev);
      toast.success(r.queued.message);
    },
    onError: (e, _id, ctx) => {
      if (ctx?.prev) qc.setQueryData(KEY, ctx.prev);
      toast.error(errorText(e));
    },
    onSettled: () => setPending(null)
  });

  const color = useMutation({
    mutationFn: (hex: string) => api.applyColor(hex),
    onMutate: (hex) => {
      setPending(`color:${hex}`);
      const prev = qc.getQueryData<PublicState>(KEY);
      optimistic({ currentSceneId: null, currentColor: hex });
      return { prev };
    },
    onSuccess: (r, _hex, ctx) => {
      // The lights are busy: it waits in line, and the page shows what plays now.
      if (!isQueued(r)) return;
      if (ctx?.prev) qc.setQueryData(KEY, ctx.prev);
      toast.success(r.queued.message);
    },
    onError: (e, _hex, ctx) => {
      if (ctx?.prev) qc.setQueryData(KEY, ctx.prev);
      toast.error(errorText(e));
    },
    onSettled: () => setPending(null)
  });

  // Opened from a link to a scene (/scene/<name>, or /?scene=<id>): it plays, or joins the line
  // when the lights are busy, once. The address goes back to the home page, so a reload does not
  // play it again (the router is not told: the page stays as it is).
  const params = useParams();
  const linked = useRef<string | null>(params.scene ?? new URLSearchParams(location.search).get('scene'));
  useEffect(() => {
    const ref = linked.current;
    if (!ref || !state) return;
    linked.current = null;
    history.replaceState(history.state, '', '/');
    const s = findScene(ref, state.scenes);
    if (!s) toast.error("That scene isn't here anymore. Pick another one!");
    else if (state.lightsOff && !state.lightsWake) toast.info(`The lights are switched off right now, so ${s.name} can't play.${state.lightsOnAt ? ` They come back on ${soonTime(state.lightsOnAt, { at: true })}.` : ''}`);
    else if (!s.online) toast.info(`${s.name} can't play right now: its lights are offline.`);
    else if (state.currentSceneId !== s.id) scene.mutate(s.id);
  }, [state, scene]);

  // Right after a change of theirs, a visitor waits a few seconds before the next (a throttle).
  const cooling = useCountdown(line?.cooldown ?? null);
  // Off for the schedule's night, a visitor's pick switches them on again: nothing is locked.
  const off = !!state?.lightsOff && !state.lightsWake;
  const locked = !!cooling || off;
  const busy = pending !== null || locked;
  const theme = useTheme();
  const speed = useBackgroundSpeed();
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  const look = useMemo(() => currentLook(state), [state?.currentColor, state?.currentSceneId, state?.playlistSceneId, state?.scenes]);

  // Taps and long presses on the buttons should not select their text (a phone shows its
  // selection handles); text fields still select.
  return (
    <div className="relative min-h-dvh select-none [-webkit-touch-callout:none] [&_input]:select-text [&_textarea]:select-text">
      <LightField look={look} dark={dark} speed={speed} />
      <Roofline roof={roof} dark={dark} />

      <div className="relative mx-auto max-w-5xl px-4 pt-[max(1.25rem,env(safe-area-inset-top))] pb-[max(2rem,env(safe-area-inset-bottom))] sm:px-8 sm:pt-[max(2rem,env(safe-area-inset-top))] sm:pb-[max(3rem,env(safe-area-inset-bottom))]">
        <header className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-balance sm:text-4xl">{state?.title ?? ' '}</h1>
            {state?.subtitle ? <p className="mt-1 text-sm text-stone-500 sm:mt-1.5 sm:text-base dark:text-stone-400">{state.subtitle}</p> : null}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SpeedControl className="bg-white/60 dark:bg-white/5" />
            <ThemeCycleButton className="bg-white/60 dark:bg-white/5" />
          </div>
        </header>

        {admin ? <AdminBar lightsOff={!!state?.lightsOff} /> : null}
        {state ? <StatusLine state={state} line={line} /> : null}
        {line ? <LineBanner line={line} /> : null}

        {isLoading ? (
          <div className="grid place-items-center py-32">
            <Loader2 className="size-6 animate-spin text-stone-400" />
          </div>
        ) : error ? (
          <p className="mt-16 text-center text-stone-500">Could not load. {errorText(error)}</p>
        ) : state ? (
          <HomeChoices
            state={state}
            admin={admin}
            off={off}
            colorDisabled={!state.anyOnline || busy}
            onColor={(hex, el) => {
              burst(el, hex);
              fieldBurst(el, [hex]);
              color.mutate(hex);
            }}
            scenes={
              state.scenes.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-stone-300 p-10 text-center text-sm text-stone-500 dark:border-stone-800">No scenes yet. An admin can add them.</div>
              ) : (
                <div className={cn('grid gap-2 sm:gap-3', TILE_GRID)}>
                  {state.scenes.map((s) => (
                    <SceneTile
                      key={s.id}
                      scene={s}
                      active={state.currentSceneId === s.id}
                      loading={pending === s.id}
                      busy={busy}
                      locked={locked}
                      onPick={() => scene.mutate(s.id)}
                    />
                  ))}
                </div>
              )
            }
          />
        ) : null}
      </div>
    </div>
  );
}

type Tab = 'scenes' | 'games' | 'colors' | 'live';
const TAB_KEY = 'homeTab';

function readTab(): Tab {
  try {
    const t = localStorage.getItem(TAB_KEY);
    return t === 'games' || t === 'colors' || t === 'live' ? t : 'scenes';
  } catch {
    return 'scenes';
  }
}

/** Scene tiles fill the row: three to a phone, more on a wider screen. */
const TILE_GRID = 'grid-cols-[repeat(auto-fill,minmax(6.25rem,1fr))] sm:grid-cols-[repeat(auto-fill,minmax(8.5rem,1fr))]';

/** Cards shared by scenes and games: frosted, with a strip of their colors along the bottom. */
const CARD = cn(
  'group relative overflow-hidden text-left backdrop-blur-md transition duration-200 active:scale-[0.97]',
  'after:absolute after:inset-x-0 after:bottom-0 after:h-1 after:[background:var(--swatch)] after:opacity-80 after:transition-all hover:after:h-1.5'
);
const CARD_IDLE = 'bg-white/65 ring-1 ring-stone-900/10 hover:-translate-y-0.5 hover:bg-white/80 hover:shadow-lg dark:bg-stone-900/45 dark:ring-white/10 dark:hover:bg-stone-900/60';

/**
 * What a visitor can do with the lights, one group at a time behind tabs (scenes, games, a color),
 * so the page fits a phone with little or no scrolling. On a wide screen the color wheel stays
 * beside the tabs, and only scenes and games take turns. The tab picked last is remembered.
 */
function HomeChoices({
  state,
  admin,
  off,
  colorDisabled,
  onColor,
  scenes
}: {
  state: PublicState;
  admin: boolean;
  off: boolean;
  colorDisabled: boolean;
  onColor: (hex: string, el: Element) => void;
  scenes: ReactNode;
}) {
  const hidden = state.hiddenGames ?? [];
  const games = GAME_CATALOG.filter((g) => admin || !hidden.includes(g.id));
  const wide = useMedia('(min-width: 1024px)');
  const side = state.showColors && wide;
  const [picked, setPicked] = useState<Tab>(readTab);
  const tabs: { id: Tab; label: string; icon: LucideIcon; count?: number }[] = [
    { id: 'scenes', label: 'Scenes', icon: Sparkles, count: state.scenes.length },
    ...(games.length ? [{ id: 'games' as const, label: 'Games', icon: Gamepad2, count: games.length }] : []),
    ...(state.showColors && !side ? [{ id: 'colors' as const, label: 'Color', icon: Palette }] : []),
    { id: 'live', label: 'Live', icon: Eye }
  ];
  // A tab that is not offered here (the wheel moved beside it, games all hidden) falls back to scenes.
  const tab = tabs.some((t) => t.id === picked) ? picked : 'scenes';
  const choose = (t: Tab) => {
    setPicked(t);
    try {
      localStorage.setItem(TAB_KEY, t);
    } catch {
      /* private mode: remembered for this page only */
    }
  };
  const refs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({});
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === tab);
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const next = tabs[(i + step + tabs.length) % tabs.length].id;
    choose(next);
    refs.current[next]?.focus();
  };

  const wheel = <ColorPicker value={state.currentColor} disabled={colorDisabled} onPick={onColor} />;

  return (
    <main className={cn('mt-4 grid gap-8 sm:mt-8', side && 'grid-cols-[18rem_1fr] gap-16')}>
      {side ? (
        <section aria-label="Colors" className="pt-14">
          {wheel}
        </section>
      ) : null}

      <div>
        {tabs.length > 1 ? (
          <div
            role="tablist"
            aria-label="What to put on the lights"
            onKeyDown={onKey}
            className="sticky top-[max(0.5rem,env(safe-area-inset-top))] z-10 mb-3 flex gap-1 rounded-full bg-white/70 p-1 ring-1 ring-stone-900/10 backdrop-blur-md sm:mb-5 sm:inline-flex dark:bg-stone-900/60 dark:ring-white/10"
          >
            {tabs.map((t) => {
              const on = t.id === tab;
              return (
                <button
                  key={t.id}
                  ref={(el) => {
                    refs.current[t.id] = el;
                  }}
                  type="button"
                  role="tab"
                  id={`tab-${t.id}`}
                  aria-selected={on}
                  aria-controls={`panel-${t.id}`}
                  tabIndex={on ? 0 : -1}
                  onClick={() => choose(t.id)}
                  className={cn(
                    'inline-flex min-w-0 flex-1 items-center justify-center gap-1 rounded-full px-2 py-2 text-sm font-semibold transition sm:flex-none sm:gap-1.5 sm:px-4',
                    on ? 'bg-stone-900 text-white shadow-sm dark:bg-white dark:text-stone-950' : 'text-stone-600 hover:bg-white/80 dark:text-stone-300 dark:hover:bg-white/10'
                  )}
                >
                  <t.icon className="size-4 shrink-0" />
                  {t.label}
                  {t.count ? <span className={cn('text-xs font-medium tabular-nums max-[420px]:hidden', on ? 'opacity-70' : 'text-stone-400 dark:text-stone-500')}>{t.count}</span> : null}
                </button>
              );
            })}
          </div>
        ) : null}

        <section role="tabpanel" id={`panel-${tab}`} aria-labelledby={tabs.length > 1 ? `tab-${tab}` : undefined} aria-label={tabs.length > 1 ? undefined : 'Scenes'}>
          {tab === 'scenes' ? (
            scenes
          ) : tab === 'games' ? (
            <GameGrid games={games} off={off} hidden={hidden} />
          ) : tab === 'live' ? (
            <LiveYard
              embedded
              src={admin ? '/api/admin/yard' : '/api/yard'}
              actions={
                <a href="/yard" className="hidden rounded-full px-3 py-1 text-sm text-stone-300 ring-1 ring-white/10 hover:bg-white/10 sm:inline-block">
                  Full screen
                </a>
              }
            />
          ) : (
            <div className="pt-2">{wheel}</div>
          )}
        </section>
      </div>
    </main>
  );
}

/** One scene: a small tile with its name and its colors along the bottom. The one playing is lit up (no mark: the name needs the room); a spinner while it starts, a mark when offline. */
function SceneTile({
  scene: s,
  active,
  loading,
  busy,
  locked,
  onPick
}: {
  scene: PublicScene;
  active: boolean;
  loading: boolean;
  busy: boolean;
  locked: boolean;
  onPick: () => void;
}) {
  const swatch = s.palette.length ? s.palette : ['#f59e0b'];
  return (
    <button
      type="button"
      disabled={!s.online || busy}
      aria-pressed={active}
      title={s.online ? s.name : `${s.name} (offline)`}
      onClick={(e) => {
        burst(e.currentTarget);
        fieldBurst(e.currentTarget, s.palette);
        fieldPreview(null);
        onPick();
      }}
      onPointerEnter={(e) => e.pointerType === 'mouse' && s.online && fieldPreview({ colors: s.palette, energy: s.energy })}
      onPointerLeave={() => fieldPreview(null)}
      style={
        {
          '--glow': `color-mix(in oklch, ${swatch[0]} 75%, transparent)`,
          '--swatch': swatch.length > 1 ? `linear-gradient(90deg, ${swatch.join(', ')})` : swatch[0]
        } as CSSProperties
      }
      className={cn(
        CARD,
        'flex min-h-14 items-start gap-1.5 rounded-xl px-3 pt-2.5 pb-3.5 disabled:cursor-not-allowed sm:rounded-2xl sm:px-3.5 sm:pt-3',
        active ? 'animate-glow bg-stone-900/90 text-white dark:bg-white/90 dark:text-stone-950' : CARD_IDLE,
        !s.online && 'opacity-50',
        busy && !loading && s.online && 'opacity-70',
        locked && 'hover:translate-y-0 hover:shadow-none'
      )}
    >
      <span className="line-clamp-2 flex-1 text-sm leading-snug font-semibold break-words sm:text-[15px]">{s.name}</span>
      {loading ? (
        <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin" />
      ) : !s.online ? (
        <>
          <WifiOff className="mt-0.5 size-3.5 shrink-0 text-stone-400" aria-hidden />
          <span className="sr-only">Offline</span>
        </>
      ) : null}
    </button>
  );
}

/**
 * The games: compact cards that open the play page, the icon beside the name and tagline.
 * Games an admin hid are left out; an admin sees them, marked.
 */
function GameGrid({ games, off, hidden }: { games: (typeof GAME_CATALOG)[number][]; off: boolean; hidden: string[] }) {
  return (
    <>
      <p className="mb-2 text-xs text-stone-500 sm:mb-3 dark:text-stone-400">The lights on the house become the game.</p>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(9.5rem,1fr))] gap-2 sm:grid-cols-[repeat(auto-fill,minmax(13rem,1fr))] sm:gap-3">
        {games.map((g) => {
          const look = gameLook(g.id);
          const Icon = look.icon;
          const isHidden = hidden.includes(g.id);
          const two = g.players?.startsWith('2');
          return (
            <a
              key={g.id}
              href={off ? undefined : gamePath(g.id)}
              aria-disabled={off || undefined}
              onClick={(e) => (off ? e.preventDefault() : burst(e.currentTarget))}
              onPointerEnter={(e) => e.pointerType === 'mouse' && fieldPreview({ colors: look.colors, energy: 0.7 })}
              onPointerLeave={() => fieldPreview(null)}
              style={{ '--swatch': `linear-gradient(90deg, ${look.colors.join(', ')})` } as CSSProperties}
              className={cn(CARD, CARD_IDLE, 'flex items-start gap-2.5 rounded-xl px-2.5 pt-2.5 pb-3.5 sm:rounded-2xl sm:px-3.5 sm:pt-3', off && 'pointer-events-none cursor-not-allowed opacity-50')}
            >
              <span className={cn('grid size-8 shrink-0 place-items-center rounded-lg bg-gradient-to-br text-white shadow-md transition group-hover:scale-110', look.className)}>
                <Icon className="size-4" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate text-sm leading-snug font-semibold sm:text-[15px]">{g.name}</span>
                  {isHidden ? (
                    <span title="Hidden from visitors: only admins see it" className="shrink-0 text-stone-400">
                      <EyeOff className="size-3" aria-hidden />
                      <span className="sr-only">Hidden</span>
                    </span>
                  ) : null}
                </span>
                <span className="line-clamp-2 text-xs leading-snug text-stone-500 dark:text-stone-400">
                  {two ? <b className="font-semibold text-stone-600 dark:text-stone-300">2 players · </b> : null}
                  {g.tagline}
                </span>
              </span>
            </a>
          );
        })}
      </div>
    </>
  );
}

/**
 * For a signed-in admin: the way back to the admin console, the live view of the whole layout,
 * and the switches for every light (power and brightness), so the lights can be put out without
 * leaving the page.
 */
function AdminBar({ lightsOff }: { lightsOff: boolean }) {
  const { data: controls } = useLightControls();
  const { power, brightness, switchOf } = useLightMutations();
  // As asked at once, while the switch is on its way.
  const s = switchOf(null);
  const on = s ? s.on : !lightsOff;
  return (
    <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-2xl bg-white/65 px-3 py-2 text-sm ring-1 ring-stone-900/10 backdrop-blur-md dark:bg-stone-900/45 dark:ring-white/10">
      <a
        href="/admin"
        className="inline-flex items-center gap-1.5 rounded-full bg-stone-900 px-3 py-1.5 font-medium text-white shadow-sm hover:bg-stone-800 dark:bg-accent-400 dark:text-stone-950 dark:hover:bg-accent-300"
      >
        <Settings2 className="size-4" /> Admin console
      </a>
      <span className="inline-flex items-center gap-2">
        <PowerButton size="sm" on={on} busy={s?.busy} label="All lights" onToggle={() => power.mutate({ on: !on })} />
        <span className="text-stone-600 dark:text-stone-300">{s?.busy ? `Turning ${on ? 'on' : 'off'}…` : on ? 'Lights on' : 'Lights off'}</span>
      </span>
      <LevelSlider
        className="min-w-48 flex-1 sm:max-w-80"
        label="Brightness of all lights"
        value={controls?.brightness.all ?? null}
        disabled={!controls || lightsOff}
        onCommit={(level) => brightness.mutate({ level })}
      />
    </div>
  );
}

/** The line for the lights: what plays now, your place in line, or that it's your turn to play. */
function LineBanner({ line }: { line: LineView }) {
  const left = useCountdown(line.endsIn);
  const mine = useCountdown(line.you?.startsIn ?? null);
  const cooling = useCountdown(line.cooldown);
  const leave = useMutation({ mutationFn: api.leaveLine, onError: (e) => toast.error(errorText(e)) });
  if (!line.enabled || (line.free && !line.you && !line.offer && !cooling)) return null;
  const now = line.now;
  const box = 'mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-2xl px-4 py-3 text-sm ring-1 backdrop-blur-md';
  if (line.offer) {
    return (
      <div className={cn(box, 'bg-amber-100/80 text-amber-950 ring-amber-300 dark:bg-amber-400/15 dark:text-amber-100 dark:ring-amber-400/40')} aria-live="assertive">
        <Gamepad2 className="size-4" />
        <span>
          <b>It's your turn</b> to play {line.offer.label}!
        </span>
        <a href="/play" className="ml-auto rounded-full bg-amber-500 px-4 py-1.5 font-semibold text-white shadow hover:bg-amber-600">
          Play now
        </a>
      </div>
    );
  }
  return (
    <div className={cn(box, 'bg-white/65 text-stone-700 ring-stone-900/10 dark:bg-stone-900/45 dark:text-stone-300 dark:ring-white/10')} aria-live="polite">
      {/* What plays now is in the status line above; here, only that it is yours. */}
      {now?.you ? (
        <span className="inline-flex items-center gap-2">
          {now.kind === 'game' ? <Gamepad2 className="size-4 text-accent-500" /> : <Sparkles className="size-4 text-accent-500" />}
          Your pick is on: <b className="font-semibold text-stone-900 dark:text-white">{now.label}</b>
        </span>
      ) : now?.kind === 'game' ? (
        <span>Someone has the lights.</span>
      ) : line.calling ? (
        <span>Waiting for the next player…</span>
      ) : null}
      {line.waiting ? (
        <span className="inline-flex items-center gap-1 text-stone-500 dark:text-stone-400">
          <Users className="size-3.5" /> {line.waiting} in line
        </span>
      ) : null}
      {cooling ? (
        <span className="inline-flex items-center gap-1 text-stone-500 tabular-nums dark:text-stone-400">
          <Clock className="size-3.5" /> change again in {clock(cooling)}
        </span>
      ) : null}
      {/* Your own pick's time left is only worth showing when others wait, and not twice. */}
      {left != null && (now?.you ? (line.waiting || now.kind === 'game') && !(cooling && Math.abs(left - cooling) < 1500) : line.waiting || !line.free) ? (
        <span className="inline-flex items-center gap-1 text-stone-500 tabular-nums dark:text-stone-400">
          <Clock className="size-3.5" /> {now?.kind === 'game' ? (line.waiting ? `ends after this game, or in ${clock(left)}` : `${clock(left)} left`) : `next in ${clock(left)}`}
        </span>
      ) : null}
      {line.you ? (
        <span className="flex basis-full flex-wrap items-center justify-between gap-2">
          <span>
            <b className="text-stone-900 dark:text-white">You're {ordinal(line.you.place)} in line</b> for {line.you.label}
            {mine != null ? <span className="tabular-nums">, your turn {mine ? `within ${clock(mine)}` : 'any moment'}</span> : null}.{' '}
            {line.you.kind === 'game' ? (
              <>
                <a href="/play" className="underline underline-offset-2">
                  Wait on the Play page
                </a>
                : your game starts there on its own.
              </>
            ) : (
              'It plays on its own when your turn comes.'
            )}
          </span>
          <button type="button" onClick={() => leave.mutate()} disabled={leave.isPending} className="rounded-full px-3 py-1 text-stone-500 ring-1 ring-stone-900/10 hover:bg-white/80 dark:text-stone-400 dark:ring-white/10 dark:hover:bg-white/10">
            Leave the line
          </button>
        </span>
      ) : !now?.you ? (
        <span className="basis-full text-xs text-stone-500 dark:text-stone-400">Tap a scene, a color or a game to join the line: one turn at a time.</span>
      ) : null}
      <UpNext line={line} />
    </div>
  );
}

/** The first places in line, and when each starts at the latest: a few, with yours among them. */
function UpNext({ line }: { line: LineView }) {
  const all = line.ahead ?? [];
  if (!all.length) return null;
  const mine = all.findIndex((e) => e.you);
  // The first three, and yours if it is further down the list.
  const shown = all.map((e, i) => ({ ...e, place: i + 1 })).filter((e, i) => i < 3 || i === mine);
  const total = line.waiting + (line.calling || line.offer ? 1 : 0);
  return (
    <ol className="grid basis-full gap-1 text-xs">
      {shown.map((e) => (
        <li key={e.place} className={cn('flex items-center gap-2 rounded-lg px-2 py-1', e.you ? 'bg-accent-500/10 font-semibold text-stone-900 dark:text-white' : 'text-stone-600 dark:text-stone-400')}>
          <span className="w-5 text-right tabular-nums opacity-60">{e.place}.</span>
          {e.kind === 'game' ? <Gamepad2 className="size-3.5 shrink-0 opacity-60" /> : <Sparkles className="size-3.5 shrink-0 opacity-60" />}
          <span className="min-w-0 flex-1 truncate">
            {e.label}
            {e.you ? ' (you)' : ''}
          </span>
          <span className="tabular-nums opacity-70">{e.place === 1 && (line.calling || line.offer) ? 'now' : <StartsIn ms={e.startsIn} />}</span>
        </li>
      ))}
      {total > shown.length ? <li className="pl-7 text-stone-500 dark:text-stone-400">and {total - shown.length} more</li> : null}
    </ol>
  );
}

function StartsIn({ ms }: { ms: number }) {
  const left = useCountdown(ms);
  return <>{left ? `by ${clock(left)}` : 'any moment'}</>;
}

function StatusLine({ state, line }: { state: PublicState; line: LineView | null }) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (!state.revertAt) return;
    const t = setInterval(() => tick((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, [state.revertAt]);

  const all = state.totalDevices > 0 && state.onlineDevices === state.totalDevices;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-sm sm:mt-5">
      <span
        className={cn(
          'inline-flex items-center gap-2 rounded-full px-3 py-1 font-medium ring-1',
          state.anyOnline && !state.lightsOff
            ? 'bg-emerald-50 text-emerald-800 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/20'
            : 'bg-stone-100 text-stone-600 ring-stone-200 dark:bg-stone-800/60 dark:text-stone-400 dark:ring-stone-700'
        )}
      >
        {state.lightsOff ? <Power className="size-3.5" /> : <span className={cn('size-1.5 rounded-full', state.anyOnline ? 'bg-emerald-500' : 'bg-stone-400')} />}
        {state.totalDevices === 0
          ? 'No lights set up'
          : state.lightsOff
            ? state.lightsWake
              ? `The lights are resting${state.lightsOnAt ? ` until ${soonTime(state.lightsOnAt)}` : ''}: pick something to switch them on`
              : state.lightsOnAt
                ? `The lights are off until ${soonTime(state.lightsOnAt)}`
                : 'The lights are switched off for now'
            : !state.anyOnline
            ? 'Lights are offline'
            : all
              ? state.totalDevices === 1
                ? 'Light is online'
                : `All ${state.totalDevices} lights online`
              : `${state.onlineDevices} of ${state.totalDevices} lights online`}
      </span>
      <NowPlaying state={state} line={line} />
      {state.idleOffMinutes != null ? (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-white/60 px-3 py-1 text-stone-500 ring-1 ring-stone-200 dark:bg-white/5 dark:text-stone-400 dark:ring-stone-800">
          <Moon className="size-3.5" />
          Off again after {state.idleOffMinutes} min with nobody playing
        </span>
      ) : null}
      {state.revertAt && new Date(state.revertAt).getTime() > Date.now() ? (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-white/60 px-3 py-1 text-stone-500 ring-1 ring-stone-200 dark:bg-white/5 dark:text-stone-400 dark:ring-stone-800">
          <Clock className="size-3.5" />
          Resets {relativeTime(state.revertAt)}
        </span>
      ) : null}
    </div>
  );
}

/**
 * What the lights show now, for visitors who cannot see the house: the game being played, the
 * scene, or the color by its name (with a dot of it), never its hex.
 */
function NowPlaying({ state, line }: { state: PublicState; line: LineView | null }) {
  if (state.lightsOff || !state.anyOnline) return null;
  const chip = 'inline-flex items-center gap-1.5 rounded-full bg-white/60 px-3 py-1 text-stone-600 ring-1 ring-stone-200 backdrop-blur-md dark:bg-white/5 dark:text-stone-300 dark:ring-stone-800';
  const name = 'font-semibold text-stone-900 dark:text-white';
  if (line?.now?.kind === 'game') {
    return (
      <span className={chip} aria-live="polite">
        <Gamepad2 className="size-3.5 text-accent-500" /> Playing <b className={name}>{line.now.label}</b>
      </span>
    );
  }
  if (state.currentColor) {
    return (
      <span className={chip} aria-live="polite">
        <Palette className="size-3.5 text-accent-500" /> Showing
        <span className="size-3 rounded-full ring-1 ring-stone-900/15 dark:ring-white/20" style={{ background: state.currentColor }} aria-hidden />
        <b className={name}>{colorName(state.currentColor)}</b>
      </span>
    );
  }
  const scene = playingScene(state);
  if (!scene) return null;
  return (
    <span className={chip} aria-live="polite">
      <Sparkles className="size-3.5 text-accent-500" /> Now playing <b className={name}>{scene.name}</b>
    </span>
  );
}

/** The scene on the lights now: the current scene, or, when that is a playlist, the scene it is on. */
function playingScene(state: PublicState) {
  return state.scenes.find((s) => s.id === state.playlistSceneId) ?? state.scenes.find((s) => s.id === state.currentSceneId);
}

/** The palette the background shows: the solid color, the playing scene, or the default. */
function currentLook(state: PublicState | undefined): Look {
  if (!state) return { colors: [], energy: 0.3 };
  if (state.currentColor) {
    const c = state.currentColor;
    // A solid color is calm. Add lighter and deeper shades so the field still has depth.
    return { colors: [c, mixHex(c, '#ffffff', 0.45), mixHex(c, '#000000', 0.35)], energy: 0.18 };
  }
  const scene = playingScene(state);
  return scene ? { colors: scene.palette, energy: scene.energy } : { colors: [], energy: 0.3 };
}

const mixHex = (a: string, b: string, t: number) => hex(mix(fromHex(a), fromHex(b), t));
