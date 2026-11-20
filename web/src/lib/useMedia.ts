import { useCallback, useSyncExternalStore } from 'react';

/** Whether a CSS media query matches now, kept up to date (a phone turned on its side, a window made wider). */
export function useMedia(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      const m = matchMedia(query);
      m.addEventListener('change', onChange);
      return () => m.removeEventListener('change', onChange);
    },
    [query]
  );
  return useSyncExternalStore(subscribe, () => matchMedia(query).matches);
}
