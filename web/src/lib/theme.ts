import { useEffect, useSyncExternalStore } from 'react';

export type Theme = 'light' | 'dark' | 'system';
const listeners = new Set<() => void>();
const media = matchMedia('(prefers-color-scheme: dark)');

function read(): Theme {
  try {
    const t = localStorage.getItem('theme');
    return t === 'light' || t === 'dark' ? t : 'system';
  } catch {
    return 'system';
  }
}

function apply(t: Theme) {
  const dark = t === 'dark' || (t === 'system' && media.matches);
  document.documentElement.classList.toggle('dark', dark);
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0c0a09' : '#fafaf9');
}

export function setTheme(t: Theme) {
  try {
    localStorage.setItem('theme', t);
  } catch {
    /* private mode */
  }
  apply(t);
  listeners.forEach((l) => l());
}

export function useTheme(): Theme {
  const theme = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    read
  );
  useEffect(() => {
    const onChange = () => apply(read());
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);
  return theme;
}
