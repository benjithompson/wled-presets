import { useCallback, useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Bug, Heart, Loader2, Play, Radio, Square, Star, WifiOff, X } from 'lucide-react';
import { api } from '../lib/api.ts';
import { YardView } from '../yard/YardView.tsx';
import { usePlaySocket } from '../yard/usePlaySocket.ts';
import { cn } from '../lib/utils.ts';

/** Kid-friendly game screen: the yard as it looks right now, and one huge button. */
export function PlayPage() {
  const { layout, games, status, connected, frame, send } = usePlaySocket();
  const [pressed, setPressed] = useState(false);
  const playing = !!status?.game;
  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.session, retry: false });
  const isAdmin = !!session?.user;
  const [debugOpen, setDebugOpen] = useState(false);
  const realLights = status?.realLights ?? [];

  useEffect(() => {
    document.title = 'Play';
  }, []);

  const press = useCallback(() => {
    send({ type: 'input', action: 'press' });
    navigator.vibrate?.(15);
    setPressed(true);
    setTimeout(() => setPressed(false), 140);
  }, [send]);

  // Space bar or Enter works as the big button on a computer.
  useEffect(() => {
    if (!playing) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.code === 'Space' || e.code === 'Enter') && !e.repeat) {
        e.preventDefault();
        press();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [playing, press]);

  const phase = status?.phase ?? '';
  const buttonLabel = phase === 'ready' || phase === 'over' || phase === 'won' ? 'GO!' : 'STOP!';
  const buttonTone =
    phase === 'miss' || phase === 'over' ? 'from-rose-500 to-red-600 shadow-red-500/40' : phase === 'hit' || phase === 'won' ? 'from-emerald-400 to-green-600 shadow-emerald-500/40' : 'from-amber-300 to-orange-500 shadow-orange-500/40';

  return (
    <div className="dark min-h-dvh bg-[radial-gradient(ellipse_at_top,#1e1b4b_0%,#0c0a09_60%)] text-white">
      <div className="mx-auto flex min-h-dvh max-w-4xl flex-col px-4 pt-[max(1rem,env(safe-area-inset-top))] pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:px-6">
        <header className="flex items-center justify-between py-2">
          <a href="/" className="inline-flex items-center gap-1.5 rounded-full px-3 py-2 text-sm text-white/70 hover:bg-white/10 hover:text-white">
            <ArrowLeft className="size-4" /> Lights
          </a>
          <div className="flex items-center gap-1">
          {realLights.length ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300" title={`Also on the real lights: ${realLights.join(', ')}`}>
              <Radio className="size-3.5" /> Real lights
            </span>
          ) : null}
          {isAdmin ? (
            <button
              type="button"
              onClick={() => setDebugOpen((o) => !o)}
              aria-expanded={debugOpen}
              className={cn('inline-flex items-center gap-1.5 rounded-full px-3 py-2 text-sm hover:bg-white/10 hover:text-white', debugOpen ? 'bg-white/10 text-white' : 'text-white/70')}
            >
              <Bug className="size-4" /> Debug
            </button>
          ) : null}
          {playing ? (
            <button
              type="button"
              onClick={() => send({ type: 'stop' })}
              className="inline-flex items-center gap-1.5 rounded-full px-3 py-2 text-sm text-white/70 hover:bg-white/10 hover:text-white"
            >
              <Square className="size-3.5" /> End game
            </button>
          ) : null}
          </div>
        </header>
        {isAdmin && debugOpen ? <DebugPanel onClose={() => setDebugOpen(false)} /> : null}

        {!connected && !layout ? (
          <div className="grid flex-1 place-items-center">
            <Loader2 className="size-8 animate-spin text-white/50" />
          </div>
        ) : (
          <>
            {!connected ? (
              <p className="mb-3 inline-flex items-center gap-2 self-center rounded-full bg-red-500/15 px-3 py-1 text-sm text-red-300">
                <WifiOff className="size-4" /> Reconnecting…
              </p>
            ) : null}

            {layout ? <YardView layout={layout} getFrame={() => frame.current} maxHeight={playing ? '42dvh' : '60dvh'} className="shadow-2xl shadow-black/60" /> : null}

            {playing ? (
              <section className="flex flex-1 flex-col items-center justify-center gap-5 py-5">
                <p className="text-center text-2xl font-bold tracking-tight text-balance sm:text-3xl" aria-live="polite">
                  {status?.message}
                </p>
                <div className="flex items-center gap-6">
                  {status?.goal ? (
                    <div className="flex flex-wrap justify-center gap-1" aria-label={`${status.score} of ${status.goal} caught`}>
                      {Array.from({ length: status.goal }, (_, i) => (
                        <Star key={i} className={cn('size-7 transition', i < status.score ? 'fill-amber-300 text-amber-300 drop-shadow-[0_0_8px_rgba(252,211,77,0.8)]' : 'text-white/20')} />
                      ))}
                    </div>
                  ) : null}
                  {status?.lives != null ? (
                    <div className="flex gap-1" aria-label={`${status.lives} lives left`}>
                      {Array.from({ length: 3 }, (_, i) => (
                        <Heart key={i} className={cn('size-6', i < (status.lives ?? 0) ? 'fill-rose-500 text-rose-500' : 'text-white/20')} />
                      ))}
                    </div>
                  ) : null}
                </div>
                <button
                  type="button"
                  onPointerDown={(e) => {
                    e.preventDefault();
                    press();
                  }}
                  onKeyDown={(e) => e.key === ' ' && e.preventDefault()}
                  disabled={phase === 'setup'}
                  className={cn(
                    'grid size-40 touch-manipulation place-items-center rounded-full bg-gradient-to-b text-4xl font-black tracking-wider text-white shadow-2xl ring-4 ring-white/20 transition select-none sm:size-52',
                    buttonTone,
                    pressed ? 'scale-90 brightness-125' : 'hover:scale-[1.03]',
                    'disabled:opacity-40'
                  )}
                >
                  {buttonLabel}
                </button>
                <p className="hidden text-sm text-white/40 sm:block">or press the space bar</p>
              </section>
            ) : (
              <section className="flex-1 py-6">
                <h1 className="mb-1 text-2xl font-bold tracking-tight">Pick a game</h1>
                <p className="mb-5 text-white/60">The lights on the house become the game.</p>
                <div className="grid gap-3 sm:grid-cols-2">
                  {games.map((g) => (
                    <button
                      key={g.id}
                      type="button"
                      onClick={() => send({ type: 'start', game: g.id })}
                      className="group flex items-start gap-4 rounded-2xl bg-white/5 p-5 text-left ring-1 ring-white/10 transition hover:bg-white/10 active:scale-[0.98]"
                    >
                      <span className="grid size-12 shrink-0 place-items-center rounded-xl bg-gradient-to-b from-amber-300 to-orange-500 text-stone-950 shadow-lg shadow-orange-500/30">
                        <Play className="size-6 fill-current" />
                      </span>
                      <span>
                        <span className="block text-lg font-semibold">{g.name}</span>
                        <span className="mt-0.5 block text-sm text-white/60">{g.description}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/** Admin only: send the game to the real WLED devices too, for testing on the house. */
function DebugPanel({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const { data: info, error } = useQuery({ queryKey: ['playOutput'], queryFn: api.playOutput, refetchInterval: 2000 });
  const [busy, setBusy] = useState(false);
  const set = async (body: { enabled?: boolean; brightness?: number }) => {
    setBusy(true);
    try {
      qc.setQueryData(['playOutput'], await api.setPlayOutput(body));
    } finally {
      setBusy(false);
    }
  };
  if (error) return <p className="mb-3 rounded-xl bg-red-500/15 p-3 text-sm text-red-300">Debug mode is not available: {String((error as Error).message)}</p>;
  if (!info) return null;
  const noDevice = info.devices.length === 0;
  return (
    <section className="mb-4 rounded-2xl bg-white/5 p-4 text-sm ring-1 ring-white/10">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <h2 className="font-semibold">Real lights</h2>
          <p className="text-white/60">A running game shows on the WLED devices; when the game ends, the lights go back to their color or scene at once. Only signed-in admins see this panel. Turning it off lasts until the server restarts.</p>
        </div>
        <button type="button" onClick={onClose} className="rounded-full p-1.5 text-white/60 hover:bg-white/10 hover:text-white" aria-label="Close debug panel">
          <X className="size-4" />
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <label className="inline-flex items-center gap-3">
          <button
            type="button"
            role="switch"
            aria-checked={info.enabled}
            disabled={busy || noDevice}
            onClick={() => set({ enabled: !info.enabled })}
            className={cn('relative h-6 w-11 rounded-full transition disabled:opacity-40', info.enabled ? 'bg-emerald-500' : 'bg-white/20')}
          >
            <span className={cn('absolute top-0.5 size-5 rounded-full bg-white shadow transition-all', info.enabled ? 'left-[22px]' : 'left-0.5')} />
          </button>
          <span className="font-medium">Show games on the real lights</span>
        </label>
        <label className="inline-flex flex-1 items-center gap-3">
          <span className="shrink-0 text-white/70">Brightness</span>
          <input
            type="range"
            min={5}
            max={100}
            step={5}
            value={Math.round(info.brightness * 100)}
            onChange={(e) => set({ brightness: Number(e.target.value) / 100 })}
            className="w-full min-w-28 accent-emerald-400"
          />
          <span className="w-10 text-right tabular-nums">{Math.round(info.brightness * 100)}%</span>
        </label>
      </div>
      {noDevice ? (
        <p className="mt-3 text-amber-300">
          No object has a WLED device yet. Choose one in{' '}
          <a href="/admin/layout" className="underline">
            Admin → Layout
          </a>
          .
        </p>
      ) : (
        <ul className="mt-3 space-y-1 text-white/70">
          {info.devices.map((d) => (
            <li key={d.id} className="flex flex-wrap justify-between gap-x-3">
              <span>
                <span className={cn('mr-1.5 inline-block size-2 rounded-full', d.online ? 'bg-emerald-400' : 'bg-red-400')} />
                <span className="font-medium text-white">{d.name}</span> ({d.host}, DDP port {d.ddpPort}): {d.objects.join(', ')}
              </span>
              <span className="tabular-nums">{d.mappedLeds} LEDs</span>
              {d.link ? <span className={cn('basis-full text-xs', d.link.mode === 'http' ? 'text-amber-300' : d.link.mode === 'udp' ? 'text-emerald-300' : 'text-white/50')}>{d.link.note}</span> : null}
            </li>
          ))}
          {info.simulationOnly.length ? <li className="text-white/50">Simulator only: {info.simulationOnly.join(', ')}</li> : null}
          <li className="text-white/50 tabular-nums">
            {info.paused ? 'Paused while the layout editor shows its preview.' : info.enabled ? `Frames sent: ${info.framesSent} (up to 60 per second while a game runs).` : 'Off: games show in the simulator only.'}
          </li>
        </ul>
      )}
    </section>
  );
}
