import type { CSSProperties } from 'react';

/**
 * The ring that fills around a finger held still on a touch screen, until the hold selects (it
 * shows after 150 ms, so a quick pan does not flash it). `x`, `y`: in the positioned parent.
 */
export function HoldRing({ x, y, ms }: { x: number; y: number; ms: number }) {
  return (
    <svg aria-hidden viewBox="0 0 64 64" className="pointer-events-none absolute size-16 -translate-x-1/2 -translate-y-1/2" style={{ left: x, top: y }}>
      <circle cx={32} cy={32} r={26} fill="rgba(12,10,9,0.35)" stroke="rgba(255,255,255,0.25)" strokeWidth={5} className="hold-ring" style={{ strokeDasharray: 'none' }} />
      <circle
        cx={32}
        cy={32}
        r={26}
        fill="none"
        stroke="rgb(40,170,255)"
        strokeWidth={5}
        strokeLinecap="round"
        pathLength={100}
        strokeDasharray="100 100"
        transform="rotate(-90 32 32)"
        className="hold-ring"
        style={{ '--hold': `${ms - 150}ms` } as CSSProperties}
      />
    </svg>
  );
}
