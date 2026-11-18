import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Clock, Gamepad2, Loader2, Sparkles, WifiOff } from 'lucide-react';
import { toast } from 'sonner';
import type { PublicState } from '../../../shared/types.ts';
import { burst } from '../components/Burst.tsx';
import { ColorPicker } from '../components/ColorPicker.tsx';
import { ThemeCycleButton } from '../components/ThemeToggle.tsx';
import { fieldBurst, fieldPreview, LightField } from '../lightfield/LightField.tsx';
import type { Look } from '../lightfield/engine.ts';
import { useTheme } from '../lib/theme.ts';
import { useBackgroundSpeed } from '../lib/backgroundSpeed.ts';
import { SpeedControl } from '../components/SpeedControl.tsx';
import { api } from '../lib/api.ts';
import { gameLook } from '../lib/gameLooks.ts';
import { GAME_CATALOG } from '../../../shared/games.ts';
import { useEvents } from '../lib/useEvents.ts';
import { cn, errorText, relativeTime } from '../lib/utils.ts';

const KEY = ['public-state'];

export function PublicPage() {
  const qc = useQueryClient();
  const { data: state, isLoading, error } = useQuery({ queryKey: KEY, queryFn: api.state, refetchInterval: 60_000 });
  const [pending, setPending] = useState<string | null>(null);

  // The server pushes the full state on every change.
  useEvents('/api/events', { state: (d) => qc.setQueryData(KEY, JSON.parse(d) as PublicState) });

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
    onError: (e, _hex, ctx) => {
      if (ctx?.prev) qc.setQueryData(KEY, ctx.prev);
      toast.error(errorText(e));
    },
    onSettled: () => setPending(null)
  });

  const busy = pending !== null;
  const theme = useTheme();
  const speed = useBackgroundSpeed();
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  const look = useMemo(() => currentLook(state), [state?.currentColor, state?.currentSceneId, state?.scenes]);

  return (
    <div className="relative min-h-dvh">
      <LightField look={look} dark={dark} speed={speed} />

      <div className="relative mx-auto max-w-5xl px-5 pt-[max(2rem,env(safe-area-inset-top))] pb-[max(3rem,env(safe-area-inset-bottom))] sm:px-8">
        <header className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight text-balance sm:text-4xl">{state?.title ?? ' '}</h1>
            {state?.subtitle ? <p className="mt-1.5 text-stone-500 dark:text-stone-400">{state.subtitle}</p> : null}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SpeedControl className="bg-white/60 dark:bg-white/5" />
            <ThemeCycleButton className="bg-white/60 dark:bg-white/5" />
          </div>
        </header>

        {state ? <StatusLine state={state} /> : null}

        {isLoading ? (
          <div className="grid place-items-center py-32">
            <Loader2 className="size-6 animate-spin text-stone-400" />
          </div>
        ) : error ? (
          <p className="mt-16 text-center text-stone-500">Could not load. {errorText(error)}</p>
        ) : state ? (
          <main className={cn('mt-10 grid gap-12', state.showColors && 'lg:grid-cols-[18rem_1fr] lg:gap-16')}>
            {state.showColors ? (
              <section aria-labelledby="colors-h" className="lg:pt-2">
                <h2 id="colors-h" className="sr-only">
                  Colors
                </h2>
                <ColorPicker
                  value={state.currentColor}
                  disabled={!state.anyOnline || busy}
                  onPick={(hex, el) => {
                    burst(el, hex);
                    fieldBurst(el, [hex]);
                    color.mutate(hex);
                  }}
                />
              </section>
            ) : null}

            <div className="space-y-12">
              <section aria-labelledby="scenes-h">
                <h2 id="scenes-h" className="mb-4 text-xs font-semibold tracking-widest text-stone-400 uppercase dark:text-stone-500">
                  Scenes
                </h2>
                {state.scenes.length === 0 ? (
                  <div className="rounded-2xl border border-dashed border-stone-300 p-10 text-center text-sm text-stone-500 dark:border-stone-800">No scenes yet. An admin can add them.</div>
                ) : (
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                    {state.scenes.map((s) => {
                      const active = state.currentSceneId === s.id;
                      const loading = pending === s.id;
                      const swatch = s.palette.length ? s.palette : ['#f59e0b'];
                      return (
                        <button
                          key={s.id}
                          type="button"
                          disabled={!s.online || busy}
                          aria-pressed={active}
                          onClick={(e) => {
                            burst(e.currentTarget);
                            fieldBurst(e.currentTarget, s.palette);
                            fieldPreview(null);
                            scene.mutate(s.id);
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
                            'group relative flex min-h-24 flex-col justify-between overflow-hidden rounded-2xl p-4 text-left backdrop-blur-md transition duration-200 active:scale-[0.97] disabled:cursor-not-allowed',
                            'after:absolute after:inset-x-0 after:bottom-0 after:h-1 after:[background:var(--swatch)] after:opacity-80 after:transition-all hover:after:h-1.5',
                            active
                              ? 'animate-glow bg-stone-900/90 text-white dark:bg-white/90 dark:text-stone-950'
                              : 'bg-white/65 ring-1 ring-stone-900/10 hover:-translate-y-0.5 hover:bg-white/80 hover:shadow-lg dark:bg-stone-900/45 dark:ring-white/10 dark:hover:bg-stone-900/60',
                            !s.online && 'opacity-50',
                            busy && !loading && s.online && 'opacity-70'
                          )}
                        >
                          <span className="flex items-center justify-between">
                            {loading ? (
                              <Loader2 className="size-4 animate-spin" />
                            ) : active ? (
                              <Check className="size-4" />
                            ) : !s.online ? (
                              <WifiOff className="size-4 text-stone-400" />
                            ) : (
                              <Sparkles className="size-4 text-accent-500 opacity-70 transition group-hover:opacity-100" />
                            )}
                            {!s.online ? <span className="text-[10px] font-semibold tracking-wider text-stone-400 uppercase">Offline</span> : null}
                          </span>
                          <span className="mt-4 text-[15px] leading-snug font-semibold">{s.name}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>
              <GamesSection />
            </div>
          </main>
        ) : null}
      </div>
    </div>
  );
}

/** The games, in their own group: cards the size of the scene buttons that open the play page. */
function GamesSection() {
  return (
    <section aria-labelledby="games-h">
      <h2 id="games-h" className="mb-4 flex items-center gap-2 text-xs font-semibold tracking-widest text-stone-400 uppercase dark:text-stone-500">
        <Gamepad2 className="size-4" /> Games
        <span className="font-normal tracking-normal normal-case">· the lights on the house become the game</span>
      </h2>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {GAME_CATALOG.map((g) => {
          const look = gameLook(g.id);
          const Icon = look.icon;
          return (
            <a
              key={g.id}
              href={`/play?game=${g.id}`}
              onClick={(e) => burst(e.currentTarget)}
              onPointerEnter={(e) => e.pointerType === 'mouse' && fieldPreview({ colors: look.colors, energy: 0.7 })}
              onPointerLeave={() => fieldPreview(null)}
              style={{ '--swatch': `linear-gradient(90deg, ${look.colors.join(', ')})` } as CSSProperties}
              className={cn(
                'group relative flex min-h-24 flex-col justify-between overflow-hidden rounded-2xl p-4 text-left backdrop-blur-md transition duration-200 active:scale-[0.97]',
                'after:absolute after:inset-x-0 after:bottom-0 after:h-1 after:[background:var(--swatch)] after:opacity-80 after:transition-all hover:after:h-1.5',
                'bg-white/65 ring-1 ring-stone-900/10 hover:-translate-y-0.5 hover:bg-white/80 hover:shadow-lg dark:bg-stone-900/45 dark:ring-white/10 dark:hover:bg-stone-900/60'
              )}
            >
              <span className="flex items-center justify-between gap-2">
                <span className={cn('grid size-7 place-items-center rounded-lg bg-gradient-to-br text-white shadow-md transition group-hover:scale-110', look.className)}>
                  <Icon className="size-4" />
                </span>
                <span className="text-[10px] font-semibold tracking-wider text-stone-400 uppercase">{g.players?.startsWith('2') ? '2 players' : '1 player'}</span>
              </span>
              <span className="mt-4">
                <span className="block text-[15px] leading-snug font-semibold">{g.name}</span>
                <span className="block text-xs leading-snug text-stone-500 dark:text-stone-400">{g.tagline}</span>
              </span>
            </a>
          );
        })}
      </div>
    </section>
  );
}

function StatusLine({ state }: { state: PublicState }) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (!state.revertAt) return;
    const t = setInterval(() => tick((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, [state.revertAt]);

  const all = state.totalDevices > 0 && state.onlineDevices === state.totalDevices;
  return (
    <div className="mt-5 flex flex-wrap items-center gap-2 text-sm">
      <span
        className={cn(
          'inline-flex items-center gap-2 rounded-full px-3 py-1 font-medium ring-1',
          state.anyOnline
            ? 'bg-emerald-50 text-emerald-800 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/20'
            : 'bg-stone-100 text-stone-600 ring-stone-200 dark:bg-stone-800/60 dark:text-stone-400 dark:ring-stone-700'
        )}
      >
        <span className={cn('size-1.5 rounded-full', state.anyOnline ? 'bg-emerald-500' : 'bg-stone-400')} />
        {state.totalDevices === 0
          ? 'No lights set up'
          : !state.anyOnline
            ? 'Lights are offline'
            : all
              ? state.totalDevices === 1
                ? 'Light is online'
                : `All ${state.totalDevices} lights online`
              : `${state.onlineDevices} of ${state.totalDevices} lights online`}
      </span>
      {state.revertAt && new Date(state.revertAt).getTime() > Date.now() ? (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-white/60 px-3 py-1 text-stone-500 ring-1 ring-stone-200 dark:bg-white/5 dark:text-stone-400 dark:ring-stone-800">
          <Clock className="size-3.5" />
          Resets {relativeTime(state.revertAt)}
        </span>
      ) : null}
    </div>
  );
}

/** The palette the background shows: the solid color, the playing scene, or the default. */
function currentLook(state: PublicState | undefined): Look {
  if (!state) return { colors: [], energy: 0.3 };
  if (state.currentColor) {
    const c = state.currentColor;
    // A solid color is calm. Add lighter and deeper shades so the field still has depth.
    return { colors: [c, mixHex(c, '#ffffff', 0.45), mixHex(c, '#000000', 0.35)], energy: 0.18 };
  }
  const scene = state.scenes.find((s) => s.id === state.currentSceneId);
  return scene ? { colors: scene.palette, energy: scene.energy } : { colors: [], energy: 0.3 };
}

function mixHex(a: string, b: string, t: number): string {
  const pa = parseInt(a.slice(1), 16);
  const pb = parseInt(b.slice(1), 16);
  const ch = (n: number, s: number) => (n >> s) & 255;
  const m = [16, 8, 0].map((s) => Math.round(ch(pa, s) * (1 - t) + ch(pb, s) * t));
  return `#${m.map((v) => v.toString(16).padStart(2, '0')).join('')}`;
}
