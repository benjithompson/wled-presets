import { createBrowserRouter, Navigate, RouterProvider } from 'react-router';
import { Toaster } from 'sonner';
import { useTheme } from './lib/theme.ts';
import { PublicPage } from './pages/PublicPage.tsx';
import { LoginPage } from './pages/LoginPage.tsx';
import { AdminLayout } from './pages/admin/AdminLayout.tsx';
import { ScenesPage } from './pages/admin/ScenesPage.tsx';
import { DevicesPage } from './pages/admin/DevicesPage.tsx';
import { ActivityPage } from './pages/admin/ActivityPage.tsx';
import { SettingsPage } from './pages/admin/SettingsPage.tsx';
import { LayoutPage } from './pages/admin/LayoutPage.tsx';
import { GamesPage } from './pages/admin/GamesPage.tsx';
import { PlayPage } from './pages/PlayPage.tsx';
import { YardLivePage } from './pages/YardLivePage.tsx';
import { SequencePage } from './pages/admin/sequence/SequencePage.tsx';

const router = createBrowserRouter([
  { path: '/', element: <PublicPage /> },
  // A link to one scene: it plays (or joins the line) when the page opens.
  { path: '/scene/:scene', element: <PublicPage /> },
  { path: '/login', element: <LoginPage /> },
  // /play/<game>: a link to one game, which starts when the lights are free (see PlayPage). One
  // route, so the page (and its connection) stays when the address follows the game.
  { path: '/play/:game?', element: <PlayPage /> },
  { path: '/yard', element: <YardLivePage /> },
  {
    path: '/admin',
    element: <AdminLayout />,
    children: [
      { index: true, element: <Navigate to="scenes" replace /> },
      { path: 'scenes', element: <ScenesPage /> },
      { path: 'devices', element: <DevicesPage /> },
      { path: 'layout', element: <LayoutPage /> },
      { path: 'sequences', element: <SequencePage /> },
      { path: 'games', element: <GamesPage /> },
      { path: 'activity', element: <ActivityPage /> },
      { path: 'settings', element: <SettingsPage /> }
    ]
  },
  { path: '*', element: <Navigate to="/" replace /> }
]);

export function App() {
  const theme = useTheme();
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  return (
    <>
      <RouterProvider router={router} />
      <Toaster theme={dark ? 'dark' : 'light'} position="bottom-center" richColors closeButton />
    </>
  );
}
