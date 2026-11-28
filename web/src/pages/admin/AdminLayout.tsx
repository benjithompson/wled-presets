import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, Outlet, useLocation } from 'react-router';
import { Loader2 } from 'lucide-react';
import { api } from '../../lib/api.ts';
import { useEvents } from '../../lib/useEvents.ts';
import { LIGHTS } from '../../components/LightControls.tsx';
import { cn } from '../../lib/utils.ts';
import { AdminHeader } from './AdminHeader.tsx';

export const OVERVIEW = ['admin', 'overview'];
export const LOGS = ['admin', 'logs'];

/** `refetchInterval`: ms between reads, for a page that shows what changes on its own (a device's frame rate). */
export function useOverview(refetchInterval?: number) {
  return useQuery({ queryKey: OVERVIEW, queryFn: api.overview, refetchInterval });
}

export function AdminLayout() {
  const qc = useQueryClient();
  const location = useLocation();
  const { data: session, isLoading } = useQuery({ queryKey: ['session'], queryFn: api.session });
  const signedIn = !!session?.user;

  useEvents(
    '/api/admin/events',
    {
      log: () => void qc.invalidateQueries({ queryKey: LOGS }),
      // The switches follow the lights, also when they are changed in WLED's own app.
      devices: () => (void qc.invalidateQueries({ queryKey: OVERVIEW }), void qc.invalidateQueries({ queryKey: LIGHTS })),
      state: () => (void qc.invalidateQueries({ queryKey: OVERVIEW }), void qc.invalidateQueries({ queryKey: LIGHTS }))
    },
    signedIn
  );

  if (isLoading) {
    return (
      <div className="grid min-h-dvh place-items-center">
        <Loader2 className="size-6 animate-spin text-stone-400" />
      </div>
    );
  }
  if (!signedIn) return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname + location.search)}`} replace />;

  // The layout and sequence editors are workspaces: they fill the window below the header, like
  // apps.
  const workspace = /^\/admin\/(layout|sequences)\/?$/.test(location.pathname);
  // Below a laptop's width the layout editor has no header, so the views get its height: the
  // menu at the start of its command bar (PageMenu) has what the header would.
  const ownMenu = /^\/admin\/layout\/?$/.test(location.pathname);

  return (
    <div className={cn('touch-ui min-h-dvh', workspace && 'flex h-dvh min-h-0 flex-col overflow-hidden')}>
      <AdminHeader className={cn(ownMenu && 'max-lg:hidden')} />
      <main className={workspace ? 'min-h-0 flex-1' : 'mx-auto max-w-6xl px-4 pt-5 pb-[calc(2rem+env(safe-area-inset-bottom,0px))] sm:px-6 sm:py-10'}>
        <Outlet />
      </main>
    </div>
  );
}
