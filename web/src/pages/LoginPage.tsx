import { useState, type FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, useNavigate, useSearchParams } from 'react-router';
import { Lightbulb, Loader2 } from 'lucide-react';
import { Button, Card, Field, Input } from '../components/ui.tsx';
import { ThemeCycleButton } from '../components/ThemeToggle.tsx';
import { api } from '../lib/api.ts';
import { errorText } from '../lib/utils.ts';

export function LoginPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const redirect = params.get('redirect')?.startsWith('/admin') ? params.get('redirect')! : '/admin';
  const { data: session, isLoading } = useQuery({ queryKey: ['session'], queryFn: api.session });
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (isLoading) {
    return (
      <div className="grid min-h-dvh place-items-center">
        <Loader2 className="size-6 animate-spin text-stone-400" />
      </div>
    );
  }
  if (session?.user) return <Navigate to={redirect} replace />;
  const bootstrap = session?.needsBootstrap ?? false;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await (bootstrap ? api.bootstrap(username, password) : api.login(username, password));
      await qc.invalidateQueries({ queryKey: ['session'] });
      navigate(redirect, { replace: true });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative grid min-h-dvh place-items-center px-4 py-10">
      <ThemeCycleButton className="absolute top-5 right-5" />
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 grid size-12 place-items-center rounded-2xl bg-stone-900 text-accent-400 shadow-lg dark:bg-accent-400 dark:text-stone-950">
            <Lightbulb className="size-6" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">{bootstrap ? 'Create the admin account' : 'Sign in to admin'}</h1>
          <p className="mt-1 text-sm text-stone-500 dark:text-stone-400">
            {bootstrap ? 'No admin exists yet. This works only from the server itself.' : 'Manage scenes, devices and settings.'}
          </p>
        </div>
        <Card className="p-6">
          <form onSubmit={submit} className="space-y-4">
            <Field label="Username">
              {(id) => <Input id={id} autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />}
            </Field>
            <Field label="Password" hint={bootstrap ? 'At least 12 characters.' : undefined}>
              {(id) => (
                <Input
                  id={id}
                  type="password"
                  autoComplete={bootstrap ? 'new-password' : 'current-password'}
                  required
                  minLength={bootstrap ? 12 : undefined}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              )}
            </Field>
            {error ? <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-500/10 dark:text-red-400">{error}</p> : null}
            <Button type="submit" variant="primary" className="w-full justify-center" loading={busy}>
              {bootstrap ? 'Create account' : 'Sign in'}
            </Button>
          </form>
        </Card>
        <p className="mt-6 text-center text-sm">
          <a href="/" className="text-stone-500 hover:text-stone-900 dark:text-stone-400 dark:hover:text-white">
            ← Back to the lights
          </a>
        </p>
      </div>
    </div>
  );
}
