import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Loader2, Settings2 } from 'lucide-react';
import { api } from '../lib/api.ts';
import { LiveYard } from '../yard/LiveYard.tsx';

/**
 * The whole yard as the lights show it now, full screen (the home page's Live tab, bigger). An
 * admin watches the admins' stream; anyone else the public one.
 */
export function YardLivePage() {
  const { data: session, isLoading } = useQuery({ queryKey: ['session'], queryFn: api.session, retry: false });
  const admin = !!session?.user;
  return (
    <div className="flex h-dvh flex-col bg-stone-950 text-stone-100">
      <header className="flex flex-wrap items-center gap-3 px-4 pt-[max(0.75rem,env(safe-area-inset-top))] pb-1 sm:px-6">
        <a href="/" className="inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-sm text-stone-300 ring-1 ring-white/10 hover:bg-white/10">
          <ArrowLeft className="size-4" /> Home
        </a>
        <h1 className="text-lg font-semibold tracking-tight">Live</h1>
        {admin ? (
          <a href="/admin/layout" className="ml-auto hidden items-center gap-1.5 rounded-full px-3 py-1.5 text-sm text-stone-300 ring-1 ring-white/10 hover:bg-white/10 sm:inline-flex" title="Edit the layout in the admin console">
            <Settings2 className="size-4" /> Edit
          </a>
        ) : null}
      </header>
      <main className="flex min-h-0 flex-1 flex-col px-2 pb-[max(0.5rem,env(safe-area-inset-bottom))] sm:px-4">
        {isLoading ? (
          <div className="grid flex-1 place-items-center">
            <Loader2 className="size-6 animate-spin text-stone-500" />
          </div>
        ) : (
          <LiveYard src={admin ? '/api/admin/yard' : '/api/yard'} />
        )}
      </main>
    </div>
  );
}
