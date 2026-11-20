import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import { Activity, ChevronDown, Clapperboard, ExternalLink, Gamepad2, Layers, Lightbulb, Loader2, LogOut, Map as MapIcon, Router, Settings as SettingsIcon, UserRound } from 'lucide-react';
import { ThemeSwitcher } from '../../components/ThemeToggle.tsx';
import { api } from '../../lib/api.ts';
import { useEvents } from '../../lib/useEvents.ts';
import { cn } from '../../lib/utils.ts';

export const OVERVIEW = ['admin', 'overview'];
export const LOGS = ['admin', 'logs'];

export function useOverview() {
  return useQuery({ queryKey: OVERVIEW, queryFn: api.overview });
}

const NAV = [
  { to: 'scenes', label: 'Scenes', icon: Layers },
  { to: 'devices', label: 'Devices', icon: Router },
  { to: 'layout', label: 'Layout', icon: MapIcon },
  { to: 'sequences', label: 'Sequences', icon: Clapperboard },
  { to: 'games', label: 'Games', icon: Gamepad2 },
  { to: 'activity', label: 'Activity', icon: Activity },
  { to: 'settings', label: 'Settings', icon: SettingsIcon }
];

export function AdminLayout() {
  const qc = useQueryClient();
  const location = useLocation();
  const { data: session, isLoading } = useQuery({ queryKey: ['session'], queryFn: api.session });
  const signedIn = !!session?.user;

  useEvents(
    '/api/admin/events',
    {
      log: () => void qc.invalidateQueries({ queryKey: LOGS }),
      devices: () => void qc.invalidateQueries({ queryKey: OVERVIEW }),
      state: () => void qc.invalidateQueries({ queryKey: OVERVIEW })
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
  if (!signedIn) return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}`} replace />;

  // The layout and sequence editors are workspaces: on wide screens they fill the window below the header.
  const workspace = /^\/admin\/(layout|sequences)\/?$/.test(location.pathname);
  // The layout editor fills the window on phones too, like an app: a slim header, with the
  // sections in a menu instead of a second row of tabs.
  const app = /^\/admin\/layout\/?$/.test(location.pathname);

  return (
    <div className={cn('min-h-dvh', workspace && 'lg:flex lg:h-dvh lg:min-h-0 lg:flex-col', app && 'flex h-dvh min-h-0 flex-col overflow-hidden')}>
      <header className="sticky top-0 z-30 shrink-0 border-b border-stone-200/80 bg-stone-50/80 backdrop-blur-lg dark:border-stone-800/80 dark:bg-stone-950/80">
        <div className={cn('mx-auto flex items-center', app ? 'h-12 gap-2 px-2 md:h-16 md:gap-4 md:px-6' : 'h-16 gap-4 px-4 sm:px-6', !workspace && 'max-w-6xl')}>
          <NavLink to="/admin" className="flex items-center gap-2.5 font-semibold tracking-tight">
            <span className="grid size-8 place-items-center rounded-xl bg-stone-900 text-accent-400 dark:bg-accent-400 dark:text-stone-950">
              <Lightbulb className="size-[18px]" />
            </span>
            <span className="hidden sm:inline">WLED Presets</span>
          </NavLink>
          {app ? <NavMenu /> : null}
          <nav className="hidden items-center gap-1 md:flex">
            {NAV.map((n) => (
              <NavItem key={n.to} {...n} />
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <a
              href="/"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-xl px-3 py-2 text-sm font-medium text-stone-600 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white"
            >
              <span className={cn(app && 'max-sm:hidden')}>Public page</span> <ExternalLink className="size-3.5" />
            </a>
            <UserMenu username={session!.user!.username} />
          </div>
        </div>
        <nav className={cn('flex gap-1 overflow-x-auto px-3 pb-2 md:hidden', app && 'hidden')}>
          {NAV.map((n) => (
            <NavItem key={n.to} {...n} />
          ))}
        </nav>
      </header>
      <main className={app ? 'min-h-0 flex-1' : workspace ? 'lg:min-h-0 lg:flex-1' : 'mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-10'}>
        <Outlet />
      </main>
    </div>
  );
}

function NavItem({ to, label, icon: Icon }: (typeof NAV)[number]) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          'inline-flex shrink-0 items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium transition',
          isActive
            ? 'bg-white text-stone-900 shadow-sm ring-1 ring-stone-200 dark:bg-stone-800 dark:text-white dark:ring-stone-700'
            : 'text-stone-500 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800/70 dark:hover:text-white'
        )
      }
    >
      <Icon className="size-4" />
      {label}
    </NavLink>
  );
}

/** On a phone, in a workspace: the sections of the admin pages, in a menu under the current one. */
function NavMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const current = NAV.find((n) => location.pathname.startsWith(`/admin/${n.to}`)) ?? NAV[0];
  useEffect(() => {
    if (!open) return;
    const close = (e: PointerEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('pointerdown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);
  const Icon = current.icon;
  return (
    <div ref={ref} className="relative md:hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="inline-flex h-9 items-center gap-1.5 rounded-xl bg-white px-3 text-sm font-medium shadow-sm ring-1 ring-stone-200 dark:bg-stone-800 dark:ring-stone-700"
      >
        <Icon className="size-4" />
        {current.label}
        <ChevronDown className="size-3.5 text-stone-500" />
      </button>
      {open ? (
        <div role="menu" className="absolute left-0 mt-2 w-56 rounded-2xl bg-white p-1.5 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              role="menuitem"
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 rounded-xl px-3 py-2.5 text-sm font-medium',
                  isActive ? 'bg-stone-100 text-stone-900 dark:bg-stone-800 dark:text-white' : 'text-stone-600 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800'
                )
              }
            >
              <n.icon className="size-4" />
              {n.label}
            </NavLink>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function UserMenu({ username }: { username: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const qc = useQueryClient();
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);

  async function signOut() {
    await api.logout();
    qc.clear();
    navigate('/login', { replace: true });
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="grid size-9 place-items-center rounded-full bg-stone-200/70 text-stone-700 transition hover:bg-stone-200 dark:bg-stone-800 dark:text-stone-200 dark:hover:bg-stone-700"
      >
        <UserRound className="size-[18px]" />
      </button>
      {open ? (
        <div role="menu" className="absolute right-0 mt-2 w-64 rounded-2xl bg-white p-2 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
          <div className="px-3 pt-2 pb-3">
            <p className="text-xs text-stone-500">Signed in as</p>
            <p className="truncate font-medium">{username}</p>
          </div>
          <div className="px-3 pb-3">
            <p className="mb-2 text-xs text-stone-500">Theme</p>
            <ThemeSwitcher />
          </div>
          <div className="my-1 h-px bg-stone-100 dark:bg-stone-800" />
          <button
            role="menuitem"
            type="button"
            onClick={signOut}
            className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-sm text-stone-700 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800"
          >
            <LogOut className="size-4" /> Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}
