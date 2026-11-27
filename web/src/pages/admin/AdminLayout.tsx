import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import { Activity, ChevronDown, Clapperboard, ExternalLink, Gamepad2, Layers, Lightbulb, Loader2, LogOut, Map as MapIcon, Menu, Router, Settings as SettingsIcon, UserRound } from 'lucide-react';
import { ThemeSwitcher } from '../../components/ThemeToggle.tsx';
import { api } from '../../lib/api.ts';
import { useEvents } from '../../lib/useEvents.ts';
import { LIGHTS } from '../../components/LightControls.tsx';
import { cn } from '../../lib/utils.ts';

export const OVERVIEW = ['admin', 'overview'];
export const LOGS = ['admin', 'logs'];

/** `refetchInterval`: ms between reads, for a page that shows what changes on its own (a device's frame rate). */
export function useOverview(refetchInterval?: number) {
  return useQuery({ queryKey: OVERVIEW, queryFn: api.overview, refetchInterval });
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
  if (!signedIn) return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}`} replace />;

  // The layout and sequence editors are workspaces: they fill the window below the header, like
  // apps. Below a laptop's width every page has a slim header, with the sections in a menu instead of tabs.
  const workspace = /^\/admin\/(layout|sequences)\/?$/.test(location.pathname);
  // Below a laptop's width the layout editor has no header, so the views get its height: the
  // menu at the start of its command bar (PageMenu) has what the header would.
  const ownMenu = /^\/admin\/layout\/?$/.test(location.pathname);

  return (
    <div className={cn('touch-ui min-h-dvh', workspace && 'flex h-dvh min-h-0 flex-col overflow-hidden')}>
      <header
        className={cn('sticky top-0 z-30 shrink-0 border-b border-stone-200/80 bg-stone-50/80 backdrop-blur-lg dark:border-stone-800/80 dark:bg-stone-950/80', ownMenu && 'max-lg:hidden')}
        style={{ paddingTop: 'env(safe-area-inset-top, 0px)' }}
      >
        <div className={cn('mx-auto flex h-11 items-center gap-2 px-3 sm:px-4 md:px-6 lg:h-16 lg:gap-4', !workspace && 'max-w-6xl')}>
          <NavLink to="/admin" aria-label="WLED Presets" className="flex items-center gap-2.5 font-semibold tracking-tight">
            <span className="grid size-8 place-items-center rounded-xl bg-stone-900 text-accent-400 dark:bg-accent-400 dark:text-stone-950">
              <Lightbulb className="size-[18px]" />
            </span>
            <span className="hidden sm:inline">WLED Presets</span>
          </NavLink>
          <NavMenu />
          <nav className="hidden items-center gap-1 lg:flex">
            {NAV.map((n) => (
              <NavItem key={n.to} {...n} />
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <a
              href="/"
              target="_blank"
              rel="noreferrer"
              aria-label="Public page"
              className="inline-flex h-9 items-center gap-1.5 rounded-xl px-3 text-sm font-medium text-stone-600 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white"
            >
              <span className="max-sm:hidden">Public page</span> <ExternalLink className="size-3.5 max-sm:size-[18px]" />
            </a>
            <UserMenu username={session!.user!.username} />
          </div>
        </div>
      </header>
      <main className={workspace ? 'min-h-0 flex-1' : 'mx-auto max-w-6xl px-4 pt-5 pb-[calc(2rem+env(safe-area-inset-bottom,0px))] sm:px-6 sm:py-10'}>
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

function useSignOut() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return async () => {
    await api.logout();
    qc.clear();
    navigate('/login', { replace: true });
  };
}

/** Closes a menu when a finger or the mouse goes down outside it, or on Escape. */
function useCloseOutside(open: boolean, setOpen: (open: boolean) => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const handle = (e: PointerEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', handle);
    document.addEventListener('keydown', handle);
    return () => {
      document.removeEventListener('pointerdown', handle);
      document.removeEventListener('keydown', handle);
    };
  }, [open, setOpen]);
  return ref;
}

const menuRow = 'flex items-center gap-2.5 rounded-xl px-3 py-2.5 text-sm font-medium';
const menuRowIdle = 'text-stone-600 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800';

/**
 * For a page with no header on a phone or a tablet (the layout editor): one button with what the
 * header has, the admin pages, the public page, the theme and Sign out.
 */
export function PageMenu({ className }: { className?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useCloseOutside(open, setOpen);
  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.session });
  const signOut = useSignOut();
  return (
    <div ref={ref} className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="menu" aria-label="Menu: pages, theme, sign out" className={className}>
        <Menu />
      </button>
      {open ? (
        <div role="menu" className="absolute top-full left-0 z-40 mt-1 max-h-[80dvh] w-64 overflow-y-auto rounded-2xl bg-white p-1.5 text-stone-900 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:text-stone-100 dark:ring-stone-800">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={`/admin/${n.to}`}
              role="menuitem"
              onClick={() => setOpen(false)}
              className={({ isActive }) => cn(menuRow, isActive ? 'bg-stone-100 text-stone-900 dark:bg-stone-800 dark:text-white' : menuRowIdle)}
            >
              <n.icon className="size-4" />
              {n.label}
            </NavLink>
          ))}
          <div className="my-1 h-px bg-stone-100 dark:bg-stone-800" />
          <a href="/" target="_blank" rel="noreferrer" role="menuitem" onClick={() => setOpen(false)} className={cn(menuRow, menuRowIdle)}>
            <ExternalLink className="size-4" />
            Public page
          </a>
          <div className="px-3 pt-2 pb-2">
            <p className="mb-2 text-xs text-stone-500">Theme</p>
            <ThemeSwitcher />
          </div>
          <div className="my-1 h-px bg-stone-100 dark:bg-stone-800" />
          <button role="menuitem" type="button" onClick={signOut} className={cn(menuRow, menuRowIdle, 'w-full text-left')}>
            <LogOut className="size-4" />
            <span className="min-w-0 flex-1 truncate">Sign out{session?.user ? ` (${session.user.username})` : ''}</span>
          </button>
        </div>
      ) : null}
    </div>
  );
}

/** On a phone or a tablet: the sections of the admin pages, in a menu under the current one. */
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
    <div ref={ref} className="relative lg:hidden">
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
  const signOut = useSignOut();

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
