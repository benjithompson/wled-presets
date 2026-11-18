import { useEffect, useState } from 'react';

/**
 * Milliseconds left of a time the server gave as "this long from now": it counts down on its
 * own between the server's updates. Null stays null.
 */
export function useCountdown(ms: number | null | undefined): number | null {
  const [base, setBase] = useState(() => ({ ms, at: Date.now() }));
  const [, tick] = useState(0);
  if (base.ms !== ms) setBase({ ms, at: Date.now() });
  useEffect(() => {
    if (ms == null) return;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [ms]);
  if (base.ms == null) return null;
  return Math.max(0, base.ms - (Date.now() - base.at));
}
