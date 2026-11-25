import { useEffect } from 'react';
import { Clock, Gamepad2, Hourglass, Sparkles, Users } from 'lucide-react';
import { clock, ordinal, type LineView } from '../../../shared/line.ts';
import { useCountdown } from '../lib/useCountdown.ts';
import { cn } from '../lib/utils.ts';

// The line for the lights on the Play page: whose turn it is, your place, and "You're up!".

/** For the player with the turn: how long it has left, and who waits (then it ends after this game). */
export function TurnBanner({ line }: { line: LineView }) {
  const left = useCountdown(line.endsIn);
  if (!line.enabled || !line.now?.you) return null;
  return (
    <p className="inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1 self-center rounded-full bg-sky-500/15 px-4 py-1.5 text-center text-sm text-sky-200 tabular-nums">
      {line.waiting ? <Users className="size-4" /> : <Clock className="size-4" />}
      {line.waiting
        ? `${waitingText(line.waiting)}: your turn ends after this game${left != null ? ` or in ${clock(left)}` : ''}.`
        : left != null
          ? `Your turn: ${clock(left)} left.`
          : "Time's up, but nobody's waiting: play on!"}
    </p>
  );
}

const waitingText = (n: number) => (n === 1 ? '1 person in line' : `${n} people in line`);

/** For a page that watches a game: whose it is (the line card below has its clock and the line). */
export function WatchBanner({ game, score, elsewhere }: { game: string; score?: number; elsewhere?: boolean }) {
  return (
    <p className="mb-4 text-center text-lg text-white/80">
      {elsewhere ? 'You play ' : 'Watching '}
      <b className="text-white">{game}</b>
      {elsewhere ? ' on another tab or phone' : ''}
      {score ? <span className="text-white/60 tabular-nums"> · score {score}</span> : null}
    </p>
  );
}

/** The first places in line: what each is for and when it starts at the latest; yours lit up. */
export function QueueList({ line }: { line: LineView }) {
  const ahead = line.ahead ?? [];
  if (!ahead.length) return null;
  const total = line.waiting + (line.calling || line.offer ? 1 : 0);
  return (
    <div className="mt-3">
      <p className="mb-1.5 text-xs font-semibold tracking-wider text-white/45 uppercase">Up next</p>
      <ol className="grid gap-1">
        {ahead.map((e, i) => (
          <li key={i} className={cn('flex items-center gap-2 rounded-lg px-2.5 py-1.5', e.you ? 'bg-amber-300/15 text-amber-100 ring-1 ring-amber-300/30' : 'bg-white/5 text-white/75')}>
            <span className="w-6 text-right text-white/40 tabular-nums">{i + 1}.</span>
            {e.kind === 'game' ? <Gamepad2 className="size-3.5 shrink-0 text-white/45" /> : <Sparkles className="size-3.5 shrink-0 text-white/45" />}
            <span className="min-w-0 flex-1 truncate">
              {e.label}
              {e.you ? <b className="ml-1.5 text-amber-200">(you)</b> : null}
            </span>
            <span className="text-white/45 tabular-nums">{i === 0 && (line.calling || line.offer) ? 'now' : <StartsIn ms={e.startsIn} />}</span>
          </li>
        ))}
      </ol>
      {total > ahead.length ? <p className="mt-1.5 text-xs text-white/45">and {total - ahead.length} more</p> : null}
    </div>
  );
}

function StartsIn({ ms }: { ms: number }) {
  const left = useCountdown(ms);
  return <>{left ? `by ${clock(left)}` : 'any moment'}</>;
}

/** It is your turn: tap Play within the time, or the line moves on. */
export function OfferCard({ offer, onPlay, onPass }: { offer: NonNullable<LineView['offer']>; onPlay: () => void; onPass: () => void }) {
  const left = useCountdown(offer.endsIn) ?? 0;
  useEffect(() => {
    navigator.vibrate?.([200, 100, 200]);
    const title = document.title;
    document.title = "You're up!";
    return () => void (document.title = title);
  }, []);
  return (
    <section aria-live="assertive" className="mx-auto mt-6 w-full max-w-md rounded-3xl bg-gradient-to-b from-amber-300/20 to-orange-500/10 p-6 text-center ring-2 ring-amber-300/60 shadow-[0_0_60px_rgba(252,211,77,0.25)]">
      <p className="text-sm font-semibold tracking-widest text-amber-200 uppercase">Your turn!</p>
      <h2 className="mt-1 text-3xl font-black tracking-tight">{offer.label}</h2>
      <button
        type="button"
        onClick={onPlay}
        className="mt-5 w-full rounded-full bg-gradient-to-b from-amber-300 to-orange-500 px-8 py-4 text-2xl font-black tracking-wider text-white shadow-lg shadow-orange-500/40 transition active:scale-95"
      >
        PLAY
      </button>
      <p className="mt-3 text-sm text-white/70 tabular-nums">
        Tap within <b className="text-white">{clock(left)}</b>, or the next person goes.
      </p>
      <button type="button" onClick={onPass} className="mt-2 text-sm text-white/50 underline-offset-2 hover:text-white hover:underline">
        Not now (leave the line)
      </button>
    </section>
  );
}

/** Who has the lights now, and your place in line. Nothing when the lights are free and you do not wait. */
export function LineCard({ line, onLeave, className }: { line: LineView; onLeave: () => void; className?: string }) {
  const left = useCountdown(line.endsIn);
  const mine = useCountdown(line.you?.startsIn ?? null);
  if (!line.enabled || (line.free && !line.you)) return null;
  const now = line.now;
  return (
    <section className={cn('rounded-2xl bg-white/5 p-4 text-sm ring-1 ring-white/10', className)}>
      {now && !now.you ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-white/80">
          {now.kind === 'game' ? <Gamepad2 className="size-4 text-amber-300" /> : <Sparkles className="size-4 text-amber-300" />}
          <span>
            {now.kind === 'game' ? 'Someone is playing ' : 'On the lights: '}
            <b className="text-white">{now.label}</b>
          </span>
          {left != null ? (
            <span className="inline-flex items-center gap-1 text-white/50 tabular-nums">
              <Clock className="size-3.5" /> {now.kind === 'game' ? (line.waiting ? `ends after this game or in ${clock(left)}` : `${clock(left)} left`) : `next in ${clock(left)}`}
            </span>
          ) : null}
          <span className="inline-flex items-center gap-1 text-white/50">
            <Users className="size-3.5" /> {line.waiting ? waitingText(line.waiting) : 'Nobody in line'}
          </span>
        </p>
      ) : line.calling ? (
        <p className="flex items-center gap-2 text-white/80">
          <Hourglass className="size-4 text-amber-300" /> Waiting for the next player to tap Play…
        </p>
      ) : null}
      {line.you ? (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-amber-300/10 px-3 py-2 ring-1 ring-amber-300/30">
          <p>
            <b className="text-amber-200">You're {ordinal(line.you.place)} in line</b> for {line.you.label}.{' '}
            {mine != null ? (
              <b className="inline-flex items-center gap-1 text-white tabular-nums">
                <Clock className="size-3.5" /> Your turn {mine ? `within ${clock(mine)}` : 'any moment'}.
              </b>
            ) : null}{' '}
            <span className="text-white/60">{line.you.kind === 'game' ? 'Keep this page open: your game starts on its own when your turn comes.' : 'It plays on its own when your turn comes.'}</span>
          </p>
          <button type="button" onClick={onLeave} className="rounded-full px-3 py-1 text-white/60 ring-1 ring-white/15 hover:bg-white/10 hover:text-white">
            Leave the line
          </button>
        </div>
      ) : (
        <p className="mt-2 text-white/50">Pick a game to join the line.</p>
      )}
      <QueueList line={line} />
    </section>
  );
}
