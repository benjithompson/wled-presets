import { useRef, type KeyboardEvent, type PointerEvent } from 'react';
import { fromHex, hex, hsv } from '../../../shared/color.ts';
import { cn } from '../lib/utils.ts';

export const SWATCHES: { hex: string; name: string }[] = [
  { hex: '#ffa757', name: 'Warm white' },
  { hex: '#ffffff', name: 'White' },
  { hex: '#ff0000', name: 'Red' },
  { hex: '#ff6a00', name: 'Orange' },
  { hex: '#ffd000', name: 'Yellow' },
  { hex: '#00ff2a', name: 'Green' },
  { hex: '#00e5ff', name: 'Cyan' },
  { hex: '#0040ff', name: 'Blue' },
  { hex: '#8a00ff', name: 'Purple' },
  { hex: '#ff00b4', name: 'Pink' }
];

/** The color of a hue on the ring, in degrees. */
const hueColor = (deg: number) => hex(hsv(deg / 360));

function hexToHue(value: string): number | null {
  const [r, g, b] = fromHex(value);
  const max = Math.max(r, g, b);
  const d = max - Math.min(r, g, b);
  if (d < 0.25) return null; // near white or grey: no hue marker
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return (h * 60 + 360) % 360;
}

export function ColorPicker({
  value,
  disabled,
  onPick
}: {
  value: string | null;
  disabled?: boolean;
  onPick: (hex: string, el: Element) => void;
}) {
  const ring = useRef<HTMLDivElement>(null);
  const hue = value ? hexToHue(value) : null;

  function pickAt(e: PointerEvent<HTMLDivElement>) {
    if (disabled || !ring.current) return;
    const r = ring.current.getBoundingClientRect();
    const dx = e.clientX - (r.left + r.width / 2);
    const dy = e.clientY - (r.top + r.height / 2);
    const dist = Math.hypot(dx, dy) / (r.width / 2);
    if (dist < 0.6 || dist > 1.02) return;
    const deg = ((Math.atan2(dx, -dy) * 180) / Math.PI + 360) % 360;
    onPick(hueColor(deg), ring.current);
  }

  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    if (disabled || !ring.current) return;
    const step = e.shiftKey ? 30 : 10;
    const cur = hue ?? 0;
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') onPick(hueColor((cur + step) % 360), ring.current);
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') onPick(hueColor((cur - step + 360) % 360), ring.current);
    else return;
    e.preventDefault();
  }

  const markerAngle = hue == null ? null : (hue * Math.PI) / 180;

  return (
    <div className={cn('flex flex-col items-center gap-6', disabled && 'pointer-events-none opacity-40 grayscale')}>
      <div
        ref={ring}
        role="slider"
        tabIndex={disabled ? -1 : 0}
        aria-label="Color hue"
        aria-valuemin={0}
        aria-valuemax={359}
        aria-valuenow={Math.round(hue ?? 0)}
        aria-disabled={disabled}
        onPointerDown={pickAt}
        onKeyDown={onKey}
        className="relative aspect-square w-full max-w-[17rem] cursor-pointer touch-manipulation rounded-full"
      >
        <div
          className="absolute inset-0 rounded-full shadow-[0_10px_40px_-10px_rgba(0,0,0,0.4)]"
          style={{
            background: 'conic-gradient(from 0deg, #f00, #ff0, #0f0, #0ff, #00f, #f0f, #f00)',
            mask: 'radial-gradient(circle, transparent 59%, #000 60%)',
            WebkitMask: 'radial-gradient(circle, transparent 59%, #000 60%)'
          }}
        />
        <div
          className="absolute inset-[24%] grid place-items-center rounded-full ring-1 ring-black/5 transition-colors duration-500 dark:ring-white/10"
          style={{
            background: value ?? 'transparent',
            boxShadow: value ? `0 0 50px -6px ${value}, inset 0 0 0 6px rgba(255,255,255,0.15)` : undefined
          }}
        >
          {!value ? <span className="text-xs font-medium tracking-wide text-stone-400 uppercase">Pick a color</span> : null}
        </div>
        {markerAngle != null ? (
          <span
            className="pointer-events-none absolute size-6 -translate-x-1/2 -translate-y-1/2 rounded-full border-[3px] border-white shadow-md transition-all duration-300"
            style={{
              left: `${50 + Math.sin(markerAngle) * 40}%`,
              top: `${50 - Math.cos(markerAngle) * 40}%`,
              background: value ?? undefined
            }}
          />
        ) : null}
      </div>

      <div className="grid grid-cols-5 gap-2.5">
        {SWATCHES.map((s) => {
          const active = value?.toLowerCase() === s.hex;
          return (
            <button
              key={s.hex}
              type="button"
              title={s.name}
              aria-label={s.name}
              aria-pressed={active}
              disabled={disabled}
              onClick={(e) => onPick(s.hex, e.currentTarget)}
              className={cn(
                'size-9 rounded-full ring-1 ring-black/10 transition hover:scale-110 active:scale-95 dark:ring-white/15',
                active && 'outline-2 outline-offset-2 outline-stone-900 dark:outline-white'
              )}
              style={{ background: s.hex }}
            />
          );
        })}
      </div>
    </div>
  );
}
