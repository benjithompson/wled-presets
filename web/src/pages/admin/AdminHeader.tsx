import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { NavLink, useLocation, useNavigate } from 'react-router';
import { Activity, CalendarClock, ChevronDown, Clapperboard, Gamepad2, Globe, KeyRound, Layers, Lightbulb, LogOut, Map as MapIcon, Menu, Router, Settings as SettingsIcon, UserRound } from 'lucide-react';
import { ThemeSwitcher } from '../../components/ThemeToggle.tsx';
import { api } from '../../lib/api.ts';
import { cn } from '../../lib/utils.ts';

const NAV = [
  { to: '/admin/scenes', label: 'Scenes', icon: Layers },
  { to: '/admin/schedule', label: 'Schedule', icon: CalendarClock },
  { to: '/admin/devices', label: 'Devices', icon: Router },
  { to: '/admin/layout', label: 'Layout', icon: MapIcon },
  { to: '/admin/sequences', label: 'Sequences', icon: Clapperboard },
  { to: '/admin/games', label: 'Games', icon: Gamepad2 },
  { to: '/admin/activity', label: 'Activity', icon: Activity },
  { to: '/admin/settings', label: 'Settings', icon: SettingsIcon }
];
/** What visitors see: the home page (and, from it, the play and live pages). */
const PUBLIC = { to: '/', label: 'Public page', icon: Globe };

/**
 * The header of every page a signed-in admin sees: the admin pages, and the public pages (home,
 * play, live) too, so the way around is the same everywhere. On a laptop and wider: a tab for each
 * page; narrower: the current page, with the others in a menu. The account menu (theme, Sign out)
 * is at the end. It spans the window on every page, so nothing in it moves from page to page.
 */
export function AdminHeader({ className }: { className?: string }) {
  const { data: session } = useQuery({ queryKey: ['session'], queryFn: api.session });
  return (
    <header
      className={cn(
        'sticky top-0 z-30 shrink-0 border-b border-stone-200/80 bg-stone-50/80 text-stone-900 backdrop-blur-lg select-none dark:border-stone-800/80 dark:bg-stone-950/80 dark:text-stone-100',
        className
      )}
      style={{ paddingTop: 'env(safe-area-inset-top, 0px)' }}
    >
      <div className="flex h-11 items-center gap-2 px-3 sm:px-4 md:px-6 lg:h-16 lg:gap-4">
        <NavLink to="/admin" aria-label="WLED Presets: admin" className="flex items-center gap-2.5 font-semibold tracking-tight">
          <span className="grid size-8 place-items-center rounded-xl bg-stone-900 text-accent-400 dark:bg-accent-400 dark:text-stone-950">
            <Lightbulb className="size-[18px]" />
          </span>
          <span className="hidden whitespace-nowrap sm:inline lg:hidden xl:inline">WLED Presets</span>
        </NavLink>
        <NavMenu />
        <nav className="hidden items-center gap-0.5 lg:flex xl:gap-1">
          {/* Only the public page's icon until the bar has room for every page and its name. */}
          <NavItem {...PUBLIC} end short />
          <span aria-hidden className="mx-1 h-5 w-px bg-stone-200 dark:bg-stone-800" />
          {NAV.map((n) => (
            <NavItem key={n.to} {...n} />
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2">{session?.user ? <UserMenu username={session.user.username} /> : null}</div>
      </div>
    </header>
  );
}

function NavItem({ to, label, icon: Icon, end, short }: (typeof NAV)[number] & { end?: boolean; short?: boolean }) {
  return (
    <NavLink
      to={to}
      end={end}
      title={short ? label : undefined}
      className={({ isActive }) =>
        cn(
          'inline-flex shrink-0 items-center gap-2 rounded-xl px-2.5 py-2 text-sm font-medium transition xl:px-3',
          isActive
            ? 'bg-white text-stone-900 shadow-sm ring-1 ring-stone-200 dark:bg-stone-800 dark:text-white dark:ring-stone-700'
            : 'text-stone-500 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800/70 dark:hover:text-white'
        )
      }
    >
      <Icon className="size-4" />
      <span className={cn(short && 'max-2xl:sr-only')}>{label}</span>
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
const menuBox = 'rounded-2xl bg-white p-1.5 text-stone-900 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:text-stone-100 dark:ring-stone-800';

/** The public page and the admin pages, as rows of a menu. */
function PageLinks({ onPick }: { onPick: () => void }) {
  const row = ({ isActive }: { isActive: boolean }) => cn(menuRow, isActive ? 'bg-stone-100 text-stone-900 dark:bg-stone-800 dark:text-white' : menuRowIdle);
  return (
    <>
      <NavLink to={PUBLIC.to} end role="menuitem" onClick={onPick} className={row}>
        <PUBLIC.icon className="size-4" />
        {PUBLIC.label}
      </NavLink>
      <div className="my-1 h-px bg-stone-100 dark:bg-stone-800" />
      {NAV.map((n) => (
        <NavLink key={n.to} to={n.to} role="menuitem" onClick={onPick} className={row}>
          <n.icon className="size-4" />
          {n.label}
        </NavLink>
      ))}
    </>
  );
}

/**
 * For a page with no header on a phone or a tablet (the layout editor): one button with what the
 * header has, the pages, the theme and Sign out.
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
        <div role="menu" className={cn(menuBox, 'absolute top-full left-0 z-40 mt-1 max-h-[80dvh] w-64 overflow-y-auto')}>
          <PageLinks onPick={() => setOpen(false)} />
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

/** On a phone or a tablet: the current page, with the others in a menu under it. */
function NavMenu() {
  const [open, setOpen] = useState(false);
  const ref = useCloseOutside(open, setOpen);
  const location = useLocation();
  const current = location.pathname.startsWith('/admin') ? (NAV.find((n) => location.pathname.startsWith(n.to)) ?? NAV[0]) : PUBLIC;
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
        <div role="menu" className={cn(menuBox, 'absolute left-0 z-40 mt-2 max-h-[80dvh] w-56 overflow-y-auto')}>
          <PageLinks onPick={() => setOpen(false)} />
        </div>
      ) : null}
    </div>
  );
}

function UserMenu({ username }: { username: string }) {
  const [open, setOpen] = useState(false);
  const ref = useCloseOutside(open, setOpen);
  const signOut = useSignOut();
  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label="Account: theme, sign out"
        className="grid size-9 place-items-center rounded-full bg-stone-200/70 text-stone-700 transition hover:bg-stone-200 dark:bg-stone-800 dark:text-stone-200 dark:hover:bg-stone-700"
      >
        <UserRound className="size-[18px]" />
      </button>
      {open ? (
        <div role="menu" className={cn(menuBox, 'absolute right-0 z-40 mt-2 w-64 p-2')}>
          <div className="px-3 pt-2 pb-3">
            <p className="text-xs text-stone-500">Signed in as</p>
            <p className="truncate font-medium">{username}</p>
          </div>
          <div className="px-3 pb-3">
            <p className="mb-2 text-xs text-stone-500">Theme</p>
            <ThemeSwitcher />
          </div>
          <div className="my-1 h-px bg-stone-100 dark:bg-stone-800" />
          <NavLink to="/admin/settings?tab=account" role="menuitem" onClick={() => setOpen(false)} className={cn(menuRow, menuRowIdle, 'py-2')}>
            <KeyRound className="size-4" /> Password and passkeys
          </NavLink>
          <button role="menuitem" type="button" onClick={signOut} className={cn(menuRow, menuRowIdle, 'w-full py-2 text-left')}>
            <LogOut className="size-4" /> Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}
