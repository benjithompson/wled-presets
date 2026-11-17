import { createRoot } from 'react-dom/client';

const PALETTE = ['#fbbf24', '#f87171', '#34d399', '#60a5fa', '#f472b6', '#fde047', '#a78bfa', '#22d3ee'];

/** Short particle burst from the centre of an element. Purely decorative. */
export function burst(el: Element, color?: string) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const r = el.getBoundingClientRect();
  const host = document.createElement('div');
  host.setAttribute('aria-hidden', 'true');
  Object.assign(host.style, { position: 'fixed', left: `${r.left + r.width / 2}px`, top: `${r.top + r.height / 2}px`, pointerEvents: 'none', zIndex: '50' });
  document.body.append(host);
  const n = 22;
  const reach = Math.max(70, Math.min(r.width, 220) * 0.75);
  const root = createRoot(host);
  root.render(
    <>
      {Array.from({ length: n }, (_, i) => {
        const a = (i / n) * Math.PI * 2 + Math.random() * 0.3;
        const d = reach * (0.55 + Math.random() * 0.6);
        const s = 4 + Math.random() * 5;
        return (
          <span
            key={i}
            className="absolute rounded-full animate-burst"
            style={{
              width: s,
              height: s,
              background: color ?? PALETTE[i % PALETTE.length],
              boxShadow: `0 0 8px ${color ?? PALETTE[i % PALETTE.length]}`,
              ['--dx' as string]: `${Math.cos(a) * d}px`,
              ['--dy' as string]: `${Math.sin(a) * d}px`,
              animationDelay: `${Math.random() * 60}ms`
            }}
          />
        );
      })}
    </>
  );
  setTimeout(() => {
    root.unmount();
    host.remove();
  }, 1100);
}
