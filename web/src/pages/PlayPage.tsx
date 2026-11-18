import { useCallback, useEffect, useRef, useState } from 'react';
import type React from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Bug, Loader2, Radio, Square, Users, WifiOff, X } from 'lucide-react';
import type { ButtonTone, GameControl, GameSetting } from '../../../shared/layout.ts';
import { api } from '../lib/api.ts';
import { YardView } from '../yard/YardView.tsx';
import { usePlaySocket } from '../yard/usePlaySocket.ts';
import { gameLook } from '../lib/gameLooks.ts';
import { InitialsEntry, Scoreboard } from './HighScores.tsx';
import { LineCard, OfferCard, TurnBanner } from './LineParts.tsx';
import { ArcadeWindow } from './ArcadeHud.tsx';
import { GameScreen, GameWindow } from './GameWindow.tsx';
import { cn } from '../lib/utils.ts';

/** Kid-friendly game screen: the yard as it looks right now, and one huge button (or a row of them). */
export function PlayPage() {
  const { layout, games, status, connected, frame, send, notice } = usePlaySocket();
  /** The buttons held down now, by id ('main': the big button). */
  const [pressed, setPressed] = useState<ReadonlySet<string>>(new Set());
  // The line for the lights: with someone else's turn, this phone watches.
  const line = status?.line;
  const lined = !!line?.enabled;
  const canPlay = status?.canPlay !== false;
  const playing = !!status?.game && canPlay;
  const watching = !!status?.game && !canPlay;
  const offer = line?.offer ?? null;
  // Picking a game joins the line when the lights are busy (your own scene becomes a game at
  // once, unless others wait).
  const joins = lined && !!line && !line.free && !(line.now?.you && (line.now.kind === 'game' || !line.waiting));
  /** The game picked on the public page, waiting for a tap here when the lights are busy. */
  const [suggested, setSuggested] = useState<string | null>(null);
  const [shownNotice, setShownNotice] = useState<string | null>(null);
  useEffect(() => {
    if (!notice) return;
    setShownNotice(notice.text);
    const t = setTimeout(() => setShownNotice(null), 5000);
    return () => clearTimeout(t);
  }, [notice]);
  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.session, retry: false });
  const isAdmin = !!session?.user;
  const [debugOpen, setDebugOpen] = useState(false);
  const realLights = status?.realLights ?? [];

  useEffect(() => {
    document.title = 'Play';
  }, []);

  // Opened from a game on the public page (/play?game=cascade): start it when the lights are free.
  // When they are busy, it is only pointed out: joining the line is the visitor's own tap.
  const wanted = useRef(new URLSearchParams(location.search).get('game'));
  useEffect(() => {
    const id = wanted.current;
    if (!id || !connected || !status || !games.length) return;
    wanted.current = null;
    history.replaceState(null, '', location.pathname);
    if (!games.some((g) => g.id === id) || (status.game && status.canPlay !== false)) return;
    if (joins && !isAdmin) setSuggested(id);
    else send({ type: 'start', game: id });
  }, [connected, status, games, send, joins, isAdmin]);

  // Each button is held for as long as its finger (or key) is down: some games pour while you
  // hold. Several can be down at once (one finger per button).
  const held = useRef(new Set<string>());
  const press = useCallback(
    (id = 'main') => {
      if (held.current.has(id)) return;
      held.current.add(id);
      send({ type: 'input', action: 'press', ...(id === 'main' ? {} : { button: id }) });
      navigator.vibrate?.(15);
      setPressed(new Set(held.current));
    },
    [send]
  );
  const release = useCallback(
    (id = 'main') => {
      if (!held.current.delete(id)) return;
      send({ type: 'input', action: 'release', ...(id === 'main' ? {} : { button: id }) });
      setPressed(new Set(held.current));
    },
    [send]
  );
  const releaseAll = useCallback(() => {
    for (const id of [...held.current]) release(id);
  }, [release]);

  const controls = playing ? status?.controls : undefined;
  // A button that goes away (the game moved on to its game-over screen) lets go.
  const controlIds = controls?.map((c) => c.id).join() ?? 'main';
  useEffect(() => {
    const ids = new Set(controlIds.split(','));
    for (const id of [...held.current]) if (!ids.has(id)) release(id);
  }, [controlIds, release]);

  // On a computer: the space bar or Enter is the big button; a row of buttons has its own keys.
  const keyMap = useRef(new Map<string, string>());
  // While initials are typed, the keys are for the letters.
  const entering = playing && !!status?.enterInitials;
  keyMap.current = entering ? new Map() : new Map(controls ? controls.flatMap((c) => (c.keys ?? []).map((k) => [k, c.id] as const)) : [['Space', 'main'], ['Enter', 'main']]);
  useEffect(() => {
    if (!playing) return;
    const down = (e: KeyboardEvent) => {
      const id = keyMap.current.get(e.code);
      if (!id) return;
      e.preventDefault();
      if (!e.repeat) press(id);
    };
    const up = (e: KeyboardEvent) => {
      const id = keyMap.current.get(e.code);
      if (!id) return;
      e.preventDefault();
      release(id);
    };
    // A finger that leaves the page (a notification, switching apps) lets go.
    window.addEventListener('keydown', down);
    window.addEventListener('keyup', up);
    window.addEventListener('blur', releaseAll);
    return () => {
      window.removeEventListener('keydown', down);
      window.removeEventListener('keyup', up);
      window.removeEventListener('blur', releaseAll);
    };
  }, [playing, press, release, releaseAll]);

  const phase = status?.phase ?? '';
  const buttonLabel = status?.button ?? (phase === 'ready' || phase === 'over' || phase === 'won' ? 'GO!' : 'STOP!');
  const tone: ButtonTone = status?.tone ?? (phase === 'miss' || phase === 'over' ? 'bad' : phase === 'hit' || phase === 'won' ? 'good' : 'go');
  const you = status?.you ?? null;
  const arcade = status?.arcade ?? null;
  // On your team's turn, the button is in your team's color.
  const teamButton = you && tone === 'go';

  return (
    <div
      className="dark min-h-dvh bg-[radial-gradient(ellipse_at_top,var(--play-glow)_0%,#0c0a09_60%)] text-white transition-[background] duration-700"
      style={{ '--play-glow': you ? `color-mix(in srgb, ${you.color} 35%, #0c0a09)` : '#1e1b4b' } as React.CSSProperties}
    >
      {/* Playing, the game fits on one screen: the game window takes all the room the controls leave. The high scores are below it. */}
      <div
        className={cn(
          'mx-auto flex flex-col',
          playing
            ? 'min-h-dvh max-w-6xl px-2 pt-[max(0.25rem,env(safe-area-inset-top))] pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:px-6'
            : 'min-h-dvh max-w-4xl px-4 pt-[max(1rem,env(safe-area-inset-top))] pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:px-6'
        )}
      >
        <header className={cn('flex shrink-0 items-center justify-between', playing ? 'py-0.5' : 'py-2')}>
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
          {playing && (!lined || line?.now?.you) ? (
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
              <p className="mb-3 inline-flex shrink-0 items-center gap-2 self-center rounded-full bg-red-500/15 px-3 py-1 text-sm text-red-300">
                <WifiOff className="size-4" /> Reconnecting…
              </p>
            ) : null}

            {layout && playing && status ? (
              <div className="flex min-h-52 flex-1 flex-col">
                {arcade ? (
                  <ArcadeWindow hud={arcade} health={status.progress}>
                    <GameScreen layout={layout} getFrame={() => frame.current} />
                  </ArcadeWindow>
                ) : (
                  <GameWindow status={status}>
                    <GameScreen layout={layout} getFrame={() => frame.current} />
                  </GameWindow>
                )}
              </div>
            ) : layout ? (
              <YardView layout={layout} getFrame={() => frame.current} maxHeight="60dvh" className="shadow-2xl shadow-black/60" />
            ) : null}

            {shownNotice ? <p className="mt-3 shrink-0 self-center rounded-full bg-amber-400/15 px-4 py-1.5 text-sm text-amber-200">{shownNotice}</p> : null}

            {offer ? (
              <OfferCard offer={offer} onPlay={() => send({ type: 'accept' })} onPass={() => send({ type: 'leaveLine' })} />
            ) : playing ? (
              <section className="flex shrink-0 flex-col items-center justify-center gap-2 pt-2">
                {line ? <TurnBanner line={line} /> : null}
                {you ? (
                  <p className="-mb-2 rounded-full px-4 py-1 text-sm font-bold tracking-widest uppercase" style={{ backgroundColor: `color-mix(in srgb, ${you.color} 25%, transparent)`, color: you.color }}>
                    You're {you.name}
                  </p>
                ) : null}
                {/* Room for two lines kept while playing, so the game window does not jump when a message comes and goes. */}
                <p className="grid min-h-14 place-items-center text-center text-lg leading-snug font-bold tracking-tight text-balance sm:text-2xl" aria-live="polite">
                  {status?.message}
                </p>
                {status?.enterInitials ? <InitialsEntry entry={status.enterInitials} onSave={(initials) => send({ type: 'initials', id: status.enterInitials!.id, initials })} /> : null}
                {status?.settings?.length ? <Settings settings={status.settings} onPick={(id, value) => send({ type: 'setting', id, value })} /> : null}
                {controls?.length ? (
                  <ControlRow controls={controls} pressed={pressed} tone={tone} disabled={phase === 'setup'} onPress={press} onRelease={release} />
                ) : (
                  <button
                    type="button"
                    onPointerDown={(e) => {
                      e.preventDefault();
                      // Keep getting this finger's events even if it slides off the button.
                      e.currentTarget.setPointerCapture?.(e.pointerId);
                      press();
                    }}
                    onPointerUp={() => release()}
                    onPointerCancel={() => release()}
                    onLostPointerCapture={() => release()}
                    onContextMenu={(e) => e.preventDefault()}
                    onKeyDown={(e) => e.key === ' ' && e.preventDefault()}
                    disabled={phase === 'setup'}
                    style={teamButton ? { backgroundImage: `linear-gradient(to bottom, color-mix(in srgb, ${you.color} 70%, white), ${you.color})`, boxShadow: `0 25px 50px -12px ${you.color}` } : undefined}
                    className={cn(
                      // A finger-sized round button on a touch screen; a regular button for a mouse.
                      'grid size-28 touch-manipulation place-items-center rounded-full bg-gradient-to-b px-3 text-center font-black tracking-wider text-white shadow-2xl ring-4 ring-white/20 transition select-none [-webkit-touch-callout:none]',
                      'pointer-fine:h-12 pointer-fine:w-auto pointer-fine:min-w-40 pointer-fine:px-8 pointer-fine:text-xl pointer-fine:shadow-lg pointer-fine:ring-2',
                      buttonLabel.length <= 4 ? 'text-3xl' : buttonLabel.length <= 6 ? 'text-xl' : 'text-lg',
                      TONES[tone],
                      pressed.has('main') ? 'scale-90 brightness-125' : 'hover:scale-[1.03]',
                      'disabled:opacity-40'
                    )}
                  >
                    {buttonLabel}
                  </button>
                )}
                <p className="hidden text-sm text-white/40 pointer-fine:block">
                  {controls?.length ? status?.keysHint : `or press the space bar${status?.button === 'HOLD' || status?.button === 'LET GO' ? ' (hold it down)' : ''}`}
                </p>
              </section>
            ) : (
              <section className="flex-1 py-6">
                {watching ? (
                  <p className="mb-4 text-center text-lg text-white/80">
                    Watching <b className="text-white">{games.find((g) => g.id === status?.game)?.name ?? 'the game'}</b>
                    {status?.score ? <span className="text-white/60 tabular-nums"> · score {status.score}</span> : null}
                  </p>
                ) : null}
                {line ? <LineCard line={line} onLeave={() => send({ type: 'leaveLine' })} className="mb-6" /> : null}
                <h1 className="mb-1 text-2xl font-bold tracking-tight">{joins ? 'Join the line' : 'Pick a game'}</h1>
                <p className="mb-5 text-white/60">{joins ? 'The lights are busy. Pick a game to wait for your turn.' : 'The lights on the house become the game.'}</p>
                <div className="grid gap-3 sm:grid-cols-2">
                  {games.map((g) => {
                    const look = gameLook(g.id);
                    const Icon = look.icon;
                    return (
                      <button
                        key={g.id}
                        type="button"
                        onClick={() => {
                          setSuggested(null);
                          send({ type: 'start', game: g.id });
                        }}
                        aria-pressed={line?.you?.kind === 'game' && line.you.label === g.name}
                        className={cn(
                          'group flex items-start gap-4 rounded-2xl bg-white/5 p-5 text-left ring-1 ring-white/10 transition hover:bg-white/10 active:scale-[0.98]',
                          suggested === g.id && !line?.you && 'ring-2 ring-amber-300/70'
                        )}
                      >
                        <span className={cn('grid size-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br text-white shadow-lg', look.className)}>
                          <Icon className="size-6" />
                        </span>
                        <span>
                          <span className="flex flex-wrap items-center gap-2 text-lg font-semibold">
                            {g.name}
                            {line?.you?.kind === 'game' && line.you.label === g.name ? (
                              <span className="rounded-full bg-amber-300/15 px-2 py-0.5 text-xs font-semibold text-amber-200">In line · {line.you.place}</span>
                            ) : joins ? (
                              <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs font-medium text-white/60">Join the line</span>
                            ) : null}
                          </span>
                          <span className="mt-0.5 block text-sm text-white/60">{g.description}</span>
                          {g.players ? (
                            <span className="mt-2 inline-flex items-center gap-1 text-xs text-white/45">
                              <Users className="size-3.5" /> {g.players}
                            </span>
                          ) : null}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </section>
            )}
          </>
        )}
      </div>
      {playing && !offer && status?.scoreboard ? (
        <div className="mx-auto flex max-w-4xl justify-center px-4 pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:px-6">
          <Scoreboard board={status.scoreboard} onRemove={isAdmin ? (id) => void api.removeScore(id).catch(() => {}) : undefined} />
        </div>
      ) : null}
    </div>
  );
}

const TONES: Record<ButtonTone, string> = {
  go: 'from-amber-300 to-orange-500 shadow-orange-500/40',
  good: 'from-emerald-400 to-green-600 shadow-emerald-500/40',
  bad: 'from-rose-500 to-red-600 shadow-red-500/40',
  calm: 'from-sky-400 to-indigo-600 shadow-sky-500/40',
  wait: 'from-slate-500 to-slate-700 shadow-black/40'
};


/** Choices for the next game: each setting as a row of pills, the chosen one lit. */
function Settings({ settings, onPick }: { settings: GameSetting[]; onPick: (id: string, value: string) => void }) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2">
      {settings.map((s) => (
        <div key={s.id} role="radiogroup" aria-label={s.label} className="flex flex-wrap items-center justify-center gap-2">
          <span className="text-sm text-white/60">{s.label}</span>
          <div className="inline-flex rounded-full bg-white/10 p-1">
            {s.choices.map((c) => (
              <button
                key={c.value}
                type="button"
                role="radio"
                aria-checked={c.value === s.value}
                onClick={() => onPick(s.id, c.value)}
                className={cn('rounded-full px-3.5 py-1 text-sm font-semibold transition', c.value === s.value ? 'bg-white text-slate-900 shadow' : 'text-white/70 hover:text-white')}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * A row of buttons for games with more than one (change color, fire…), one finger each. On a
 * phone they sit side by side, the big one in the middle; each one in the color it stands for.
 */
function ControlRow({
  controls,
  pressed,
  tone,
  disabled,
  onPress,
  onRelease
}: {
  controls: GameControl[];
  pressed: ReadonlySet<string>;
  tone: ButtonTone;
  disabled: boolean;
  onPress: (id: string) => void;
  onRelease: (id: string) => void;
}) {
  const many = controls.length > 3;
  return (
    <div className={cn('flex w-full max-w-xl items-center justify-center', many ? 'gap-2.5 pointer-fine:gap-3' : 'gap-4 pointer-fine:gap-3')}>
      {controls.map((c) => {
        const down = pressed.has(c.id);
        return (
          <button
            key={c.id}
            type="button"
            aria-label={c.label}
            onPointerDown={(e) => {
              e.preventDefault();
              e.currentTarget.setPointerCapture?.(e.pointerId);
              onPress(c.id);
            }}
            onPointerUp={() => onRelease(c.id)}
            onPointerCancel={() => onRelease(c.id)}
            onLostPointerCapture={() => onRelease(c.id)}
            onContextMenu={(e) => e.preventDefault()}
            onKeyDown={(e) => e.key === ' ' && e.preventDefault()}
            disabled={disabled}
            style={c.color ? { backgroundImage: `linear-gradient(to bottom, color-mix(in srgb, ${c.color} 65%, white), ${c.color})`, boxShadow: `0 20px 40px -12px ${c.color}` } : undefined}
            className={cn(
              'grid aspect-square min-w-0 touch-manipulation place-items-center rounded-full bg-gradient-to-b px-2 text-center font-black tracking-wider text-white shadow-2xl ring-4 ring-white/20 transition select-none [-webkit-touch-callout:none] [text-shadow:0_1px_6px_rgba(0,0,0,0.55)]',
              // Finger-sized on a touch screen (about 2 cm); a regular round button for a mouse.
              many ? 'max-w-20 flex-1 text-3xl' : c.big ? 'w-28 text-2xl' : 'w-20 text-3xl',
              many || !c.big ? 'pointer-fine:w-14 pointer-fine:flex-none pointer-fine:text-xl' : 'pointer-fine:w-20 pointer-fine:text-lg',
              'pointer-fine:shadow-lg pointer-fine:ring-2',
              !c.color && TONES[tone],
              down ? 'scale-90 brightness-125' : 'hover:scale-[1.03]',
              'disabled:opacity-40'
            )}
          >
            {c.label}
          </button>
        );
      })}
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
          <p className="mt-1 text-white/60">
            To keep games off lights that cannot be seen, go to{' '}
            <a href="/admin/games" className="underline">
              Admin → Games
            </a>
            .
          </p>
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
