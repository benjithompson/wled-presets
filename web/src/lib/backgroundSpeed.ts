import { useSyncExternalStore } from 'react';
import { DEFAULT_SPEED, MAX_SPEED, MIN_SPEED } from '../lightfield/engine.ts';

// How fast the public page background moves. A per-browser preference, like the theme.
const KEY = 'backgroundSpeed';
const listeners = new Set<() => void>();

function read(): number {
  try {
    const n = Number(localStorage.getItem(KEY));
    return Number.isFinite(n) && n >= MIN_SPEED && n <= MAX_SPEED ? n : DEFAULT_SPEED;
  } catch {
    return DEFAULT_SPEED;
  }
}

export function setBackgroundSpeed(v: number) {
  try {
    localStorage.setItem(KEY, String(v));
  } catch {
    /* private mode: keep it for this page only */
  }
  listeners.forEach((l) => l());
}

export function useBackgroundSpeed(): number {
  return useSyncExternalStore((cb) => {
    listeners.add(cb);
    return () => listeners.delete(cb);
  }, read);
}

// The slider uses a log scale: each step multiplies the speed, which matches how speed is perceived.
export const toSlider = (v: number) => Math.round((Math.log(v / MIN_SPEED) / Math.log(MAX_SPEED / MIN_SPEED)) * 100);
export const fromSlider = (p: number) => Math.round(MIN_SPEED * Math.pow(MAX_SPEED / MIN_SPEED, p / 100) * 1000) / 1000;

export function speedLabel(v: number): string {
  if (v <= 0.05) return 'Very slow';
  if (v <= 0.1) return 'Slow';
  if (v <= 0.2) return 'Calm';
  if (v <= 0.45) return 'Lively';
  return 'Fast';
}
