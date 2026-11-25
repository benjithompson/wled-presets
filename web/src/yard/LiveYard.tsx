import { lazy, Suspense, useEffect, useRef, useState, type ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import type { Layout } from '../../../shared/layout.ts';
import { YardView } from './YardView.tsx';
import type { ViewSide } from './views.ts';
import { cn } from '../lib/utils.ts';

const Scene3D = lazy(() => import('./Scene3D.tsx').then((m) => ({ default: m.Scene3D })));

type View = ViewSide | '3d';
const VIEWS: { id: View; label: string }[] = [
  { id: 'front', label: 'Front' },
  { id: 'top', label: 'Top' },
  { id: 'side', label: 'Side' },
  { id: '3d', label: '3D' }
];
const VIEW_KEY = 'yard-live-view';

/**
 * The whole yard as the lights show it now, LED by LED: what plays on every object, also the ones
 * out of sight of the street. Nothing here edits the layout or the lights. `src`: the stream
 * (/api/admin/yard for an admin, /api/yard for everyone). `embedded`: a box on the home page (a
 * fixed height); otherwise it fills its parent.
 */
export function LiveYard({ src, embedded, actions }: { src: string; embedded?: boolean; actions?: ReactNode }) {
  const { layout, frame, state } = useYardStream(src);
  const [view, setView] = useState<View>(() => {
    try {
      const v = localStorage.getItem(VIEW_KEY);
      return VIEWS.some((x) => x.id === v) ? (v as View) : 'front';
    } catch {
      return 'front';
    }
  });
  const pick = (v: View) => {
    setView(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      /* private mode: the choice lasts this visit */
    }
  };
  const getFrame = () => frame.current;
  const height = embedded ? 'min(62dvh, 40rem)' : '100%';

  return (
    <div className={cn('flex flex-col bg-stone-950 text-stone-100', embedded ? 'overflow-hidden rounded-2xl shadow-xl ring-1 ring-white/10' : 'min-h-0 flex-1')}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5">
        <span className={cn('inline-flex items-center gap-1.5 text-xs', state === 'live' ? 'text-emerald-400' : 'text-stone-500')}>
          <span className={cn('size-1.5 rounded-full', state === 'live' ? 'animate-pulse bg-emerald-400' : 'bg-stone-500')} />
          {state === 'live' ? 'Live' : state === 'busy' ? 'Too many people are watching right now' : 'Connecting…'}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <div role="tablist" aria-label="View" className="flex rounded-full bg-white/5 p-0.5 ring-1 ring-white/10">
            {VIEWS.map((v) => (
              <button
                key={v.id}
                type="button"
                role="tab"
                aria-selected={view === v.id}
                onClick={() => pick(v.id)}
                className={cn('rounded-full px-3 py-1 text-sm transition', view === v.id ? 'bg-white text-stone-950' : 'text-stone-300 hover:bg-white/10')}
              >
                {v.label}
              </button>
            ))}
          </div>
          {actions}
        </div>
      </div>

      <div className="relative min-h-0 flex-1 px-2 pb-2" style={embedded ? { height } : undefined}>
        {state === 'busy' && !layout ? (
          <p className="grid h-full min-h-40 place-items-center px-6 text-center text-sm text-stone-400">Lots of people are watching the lights right now. Try again in a few minutes, or look at the house!</p>
        ) : !layout ? (
          <Spinner />
        ) : layout.fixtures.length === 0 ? (
          <p className="grid h-full place-items-center text-stone-500">No objects in the layout yet.</p>
        ) : view === '3d' ? (
          <Suspense fallback={<Spinner />}>
            <div className="absolute inset-0 px-2 pb-2">
              <div className="relative h-full overflow-hidden rounded-xl">
                <Scene3D layout={layout} getFrame={getFrame} selected={null} onSelect={() => {}} fill viewOnly />
              </div>
            </div>
          </Suspense>
        ) : (
          <div className="grid h-full place-items-center">
            <YardView key={view} layout={layout} getFrame={getFrame} side={view} maxHeight={embedded ? `calc(${height} - 0.5rem)` : 'calc(100dvh - 8rem)'} className="w-full rounded-xl shadow-2xl shadow-black/60" />
          </div>
        )}
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <div className="grid h-full min-h-40 place-items-center">
      <Loader2 className="size-6 animate-spin text-stone-500" />
    </div>
  );
}

/**
 * The yard stream: the layout the server lights, then RGB bytes for each of its LEDs in stage
 * order, 10 to 20 times a second. It closes while the tab is hidden.
 */
function useYardStream(src: string) {
  const [layout, setLayout] = useState<Layout | null>(null);
  const [state, setState] = useState<'connecting' | 'live' | 'busy'>('connecting');
  const frame = useRef<Uint8Array | null>(null);

  useEffect(() => {
    let es: EventSource | null = null;
    const open = () => {
      if (es) return;
      es = new EventSource(src);
      es.addEventListener('geometry', (e) => {
        const g = JSON.parse((e as MessageEvent).data) as { cells: number; layout?: Layout };
        frame.current = new Uint8Array(g.cells * 3);
        if (g.layout) setLayout(g.layout);
        setState('live');
      });
      es.addEventListener('frame', (e) => {
        const bin = atob((e as MessageEvent).data);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        frame.current = bytes;
      });
      es.addEventListener('busy', () => {
        setState('busy');
        close();
      });
      es.onerror = () => setState((s) => (s === 'busy' ? s : 'connecting'));
    };
    const close = () => {
      es?.close();
      es = null;
    };
    const onVisible = () => (document.hidden ? close() : open());
    open();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      close();
    };
  }, [src]);

  return { layout, frame, state };
}
