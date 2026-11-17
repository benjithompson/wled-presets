import { useEffect, useRef } from 'react';

/** Subscribes to a server-sent event stream. The browser reconnects on its own after a drop. */
export function useEvents(url: string, handlers: Record<string, (data: string) => void>, enabled = true) {
  const ref = useRef(handlers);
  ref.current = handlers;
  useEffect(() => {
    if (!enabled) return;
    const es = new EventSource(url);
    const names = Object.keys(ref.current);
    const listeners = names.map((name) => {
      const fn = (e: MessageEvent) => ref.current[name]?.(e.data);
      es.addEventListener(name, fn);
      return [name, fn] as const;
    });
    return () => {
      for (const [n, fn] of listeners) es.removeEventListener(n, fn);
      es.close();
    };
  }, [url, enabled]);
}
