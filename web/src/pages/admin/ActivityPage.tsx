import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, CircleAlert, Info, ScrollText } from 'lucide-react';
import type { LogEntry } from '../../../../shared/types.ts';
import { Card, Empty, PageHeader, Spinner } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { cn, relativeTime } from '../../lib/utils.ts';
import { LOGS } from './AdminLayout.tsx';

const FILTERS: { value: string | null; label: string }[] = [
  { value: null, label: 'All' },
  { value: 'visitor', label: 'Visitors' },
  { value: 'applied', label: 'Applied' },
  { value: 'game', label: 'Games' },
  { value: 'auto_revert', label: 'Auto-revert' },
  { value: 'config', label: 'Config' },
  { value: 'settings', label: 'Settings' },
  { value: 'import', label: 'Import' },
  { value: 'discovery', label: 'Discovery' },
  { value: 'admin', label: 'Sign-in' },
  { value: 'startup', label: 'Startup' },
  { value: 'error', label: 'Errors' }
];

const LEVEL = {
  info: { icon: Info, cls: 'text-sky-500' },
  warn: { icon: AlertTriangle, cls: 'text-amber-500' },
  error: { icon: CircleAlert, cls: 'text-red-500' }
} as const;

export function ActivityPage() {
  const [filter, setFilter] = useState<string | null>(null);
  const { data, isLoading } = useQuery({ queryKey: [...LOGS, filter], queryFn: () => api.logs(filter) });
  const [open, setOpen] = useState<number | null>(null);
  const logs = data?.logs ?? [];

  return (
    <>
      <PageHeader title="Activity" description="What happened, newest first. New entries appear live." />
      <div className="-mx-4 mb-4 flex gap-1.5 overflow-x-auto px-4 pb-1 sm:mx-0 sm:px-0">
        {FILTERS.map((f) => (
          <button
            key={f.label}
            type="button"
            onClick={() => setFilter(f.value)}
            className={cn(
              'shrink-0 rounded-full px-3 py-1.5 text-[13px] font-medium transition',
              filter === f.value
                ? 'bg-stone-900 text-white dark:bg-white dark:text-stone-900'
                : 'bg-white text-stone-600 ring-1 ring-stone-200 hover:bg-stone-50 dark:bg-stone-900 dark:text-stone-400 dark:ring-stone-800 dark:hover:bg-stone-800'
            )}
          >
            {f.label}
          </button>
        ))}
      </div>
      <Card>
        {isLoading ? (
          <div className="grid place-items-center py-16">
            <Spinner />
          </div>
        ) : !logs.length ? (
          <Empty icon={<ScrollText />} title="Nothing here yet">
            Entries appear when someone picks a scene or an admin changes something.
          </Empty>
        ) : (
          <ul className="divide-y divide-stone-100 dark:divide-stone-800">
            {logs.map((l) => (
              <Row key={l.id} log={l} open={open === l.id} onToggle={() => setOpen(open === l.id ? null : l.id)} />
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

function Row({ log, open, onToggle }: { log: LogEntry; open: boolean; onToggle: () => void }) {
  const { icon: Icon, cls } = LEVEL[log.level] ?? LEVEL.info;
  const who = log.clientIp && log.clientIp !== 'server' ? log.clientIp : null;
  return (
    <li>
      <button type="button" onClick={onToggle} className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-stone-50 sm:px-5 dark:hover:bg-stone-900">
        <Icon className={cn('mt-0.5 size-4 shrink-0', cls)} />
        <div className="min-w-0 flex-1">
          <p className="text-sm">{log.message}</p>
          <p className="mt-0.5 text-xs text-stone-500">
            <span className="font-medium text-stone-600 dark:text-stone-400">{log.action.replace('_', ' ')}</span>
            {who ? <> · {who}</> : null}
          </p>
        </div>
        <time dateTime={log.timestamp} title={new Date(log.timestamp).toLocaleString()} className="shrink-0 text-xs text-stone-400 tabular-nums">
          {relativeTime(log.timestamp)}
        </time>
      </button>
      {open ? (
        <div className="space-y-2 px-4 pb-4 pl-11 text-xs sm:px-5 sm:pl-12">
          <p className="text-stone-500">{new Date(log.timestamp).toLocaleString()}</p>
          {log.userAgent && log.userAgent !== 'system' ? <p className="break-all text-stone-500">{log.userAgent}</p> : null}
          {log.details ? (
            <pre className="overflow-x-auto rounded-lg bg-stone-100 p-3 font-mono text-[11px] leading-relaxed text-stone-700 dark:bg-stone-950 dark:text-stone-300">
              {JSON.stringify(log.details, null, 2)}
            </pre>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
