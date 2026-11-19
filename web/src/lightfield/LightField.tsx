import { useEffect, useRef, useState } from 'react';
import { DEFAULT_LOOK, DEFAULT_SPEED, LightFieldEngine, type Look } from './engine.ts';

// One engine per page. Other components reach it through these helpers.
let engine: LightFieldEngine | null = null;

/** Radial burst of colors from the centre of an element. */
export function fieldBurst(el: Element, colors?: string[]) {
  const r = el.getBoundingClientRect();
  engine?.burst(r.left + r.width / 2, r.top + r.height / 2, colors, 1);
}

/** The roofline's colors now, one RGB triple per cell in strip order (see LightFieldEngine.setRoof). Null: none. */
export function fieldRoof(rgb: Uint8Array | null) {
  engine?.setRoof(rgb);
}

/** Shows a scene's colors while the pointer rests on it. Null ends the preview. */
export function fieldPreview(look: Look | null) {
  engine?.setPreview(look);
}

function prefersReducedMotion() {
  return matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * The animated background of the public page: a fluid simulation of light in the
 * colors of what is playing. Falls back to a still gradient when motion is reduced
 * or WebGL 2 is not available.
 */
export function LightField({ look, dark, speed = DEFAULT_SPEED }: { look: Look; dark: boolean; speed?: number }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [fallback, setFallback] = useState(() => prefersReducedMotion());

  useEffect(() => {
    if (fallback || !canvas.current) return;
    const small = Math.min(screen.width, screen.height) < 500;
    const e = LightFieldEngine.create(canvas.current, { dark, reducedQuality: small && (navigator.hardwareConcurrency ?? 8) <= 4 });
    if (!e) {
      setFallback(true);
      return;
    }
    engine = e;
    e.setLook(look, true);
    e.setSpeed(speed);
    e.start();
    return () => {
      e.dispose();
      if (engine === e) engine = null;
    };
    // The engine is created once; look and theme changes go through the effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fallback]);

  useEffect(() => {
    engine?.setLook(look);
  }, [look]);

  useEffect(() => {
    engine?.setTheme(dark);
  }, [dark]);

  useEffect(() => {
    engine?.setSpeed(speed);
  }, [speed]);

  useEffect(() => {
    const m = matchMedia('(prefers-reduced-motion: reduce)');
    const on = () => setFallback(m.matches || fallback);
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, [fallback]);

  if (fallback) {
    const colors = look.colors.length ? look.colors : DEFAULT_LOOK.colors;
    const at = ['20% 15%', '85% 25%', '70% 85%', '10% 80%', '50% 50%', '35% 40%'];
    const background = colors
      .map((c, i) => `radial-gradient(40rem 30rem at ${at[i % at.length]}, ${c}${dark ? '55' : '33'}, transparent 70%)`)
      .join(', ');
    return <div aria-hidden className="fixed inset-0 -z-10 transition-[background] duration-1000" style={{ background }} />;
  }
  return <canvas ref={canvas} aria-hidden className="fixed inset-0 -z-10 block h-lvh w-full touch-none" />;
}
