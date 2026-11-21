// The handles on the selected object in the front and top views, as in 3D and CAD programs:
// arrows to move it along one axis (X across, Y up and down, Z toward the street), a square to
// move it freely, a ring to turn it, and handles on its box to resize it. Axis colors are the
// usual ones: X red, Y green, Z blue; a ring has the color of the axis it turns about.
import type { PointerEvent as RPointerEvent } from 'react';
import type { ViewSide } from '../../yard/YardView.tsx';

type UV = { u: number; v: number };

/** What a handle does: move (along an axis, or freely), turn, or resize. */
export type GizmoPart = { kind: 'move'; axis: 'u' | 'v' | null } | { kind: 'rotate' } | { kind: 'width' } | { kind: 'height' } | { kind: 'scale' };

export const AXIS_RGB = { x: '#ef4444', y: '#22c55e', z: '#3b82f6' } as const;

/** The angle (degrees, clockwise on the screen from the right) of a point around a center. */
export const screenAngle = (c: UV, p: UV) => (Math.atan2(p.v - c.v, p.u - c.u) * 180) / Math.PI;

/** Degrees in (-180, 180]. */
export const wrapAngle = (d: number) => {
  const w = ((((d + 180) % 360) + 360) % 360) - 180;
  return w === -180 ? 180 : w;
};

/**
 * Draws the handles. `anchor`: the point the object turns about and the arrows start from;
 * `box`: what the object covers in the view. `turn`: the object's angle in the view (the ring's
 * knob sits there), or null when it cannot turn in this view. `width`, `height`, `scale`:
 * which resize handles it has. `active`: the part being dragged, and its label (an angle, a
 * size) shown by it.
 */
export function Gizmo({
  side,
  anchor,
  box,
  k,
  turn,
  width,
  height,
  scale,
  active,
  onStart
}: {
  side: ViewSide;
  anchor: UV;
  box: { x: number; y: number; w: number; h: number };
  k: number;
  turn: number | null;
  width: boolean;
  height: boolean;
  scale: boolean;
  active: { part: GizmoPart['kind']; label: string | null } | null;
  onStart: (e: RPointerEvent, part: GizmoPart) => void;
}) {
  const front = side === 'front';
  const len = 64 * k;
  const head = 11 * k;
  const down = (part: GizmoPart) => (e: RPointerEvent) => {
    if (e.button !== 0) return;
    onStart(e, part);
  };
  /** An arrow from the anchor: dir is the screen direction (1, 0) right, (0, -1) up, (0, 1) down. */
  const arrow = (key: string, dir: UV, color: string, label: string, title: string, axis: 'u' | 'v') => {
    const a = { u: anchor.u + dir.u * 14 * k, v: anchor.v + dir.v * 14 * k };
    const b = { u: anchor.u + dir.u * len, v: anchor.v + dir.v * len };
    const n = { u: -dir.v, v: dir.u };
    const tip = { u: b.u + dir.u * head, v: b.v + dir.v * head };
    const on = active?.part === 'move';
    return (
      <g key={key} className={axis === 'u' ? 'cursor-ew-resize' : 'cursor-ns-resize'} onPointerDown={down({ kind: 'move', axis })}>
        <title>{title}</title>
        <line x1={a.u} y1={a.v} x2={tip.u} y2={tip.v} stroke="transparent" strokeWidth={18 * k} />
        <line x1={a.u} y1={a.v} x2={b.u} y2={b.v} stroke={color} strokeWidth={(on ? 3.5 : 2.5) * k} strokeLinecap="round" />
        <polygon points={`${tip.u},${tip.v} ${b.u + n.u * head * 0.55},${b.v + n.v * head * 0.55} ${b.u - n.u * head * 0.55},${b.v - n.v * head * 0.55}`} fill={color} stroke="#0c0a09" strokeWidth={1 * k} />
        <text x={tip.u + dir.u * 9 * k + (dir.u ? 0 : 9 * k)} y={tip.v + dir.v * 9 * k + 4 * k} fontSize={12 * k} fontWeight={800} fill={color} stroke="#0c0a09" strokeWidth={3 * k} paintOrder="stroke" pointerEvents="none">
          {label}
        </text>
      </g>
    );
  };
  // The ring: around the anchor, just outside everything the object covers.
  const corners = [
    [box.x, box.y],
    [box.x + box.w, box.y],
    [box.x, box.y + box.h],
    [box.x + box.w, box.y + box.h]
  ];
  const R = Math.max(len + head + 22 * k, ...corners.map(([u, v]) => Math.hypot(u - anchor.u, v - anchor.v) + 16 * k));
  // The ring turns about the axis that points out of the view.
  const ringColor = front ? AXIS_RGB.z : side === 'top' ? AXIS_RGB.y : AXIS_RGB.x;
  const knob = turn == null ? null : { u: anchor.u + Math.cos((turn * Math.PI) / 180) * R, v: anchor.v + Math.sin((turn * Math.PI) / 180) * R };
  const square = (key: string, at: UV, cursor: string, part: GizmoPart, title: string) => (
    <g key={key} className={cursor} onPointerDown={down(part)}>
      <title>{title}</title>
      <rect x={at.u - 11 * k} y={at.v - 11 * k} width={22 * k} height={22 * k} fill="transparent" />
      <rect x={at.u - 5.5 * k} y={at.v - 5.5 * k} width={11 * k} height={11 * k} rx={1.5 * k} fill={active?.part === part.kind ? '#fde68a' : '#fbbf24'} stroke="#0c0a09" strokeWidth={1.5 * k} />
    </g>
  );
  const label = active?.label;
  const labelAt =
    active?.part === 'rotate' && knob
      ? { u: knob.u, v: knob.v - 16 * k }
      : active?.part === 'width'
        ? { u: box.x + box.w + 14 * k, v: anchor.v - 12 * k }
        : active?.part === 'height' || active?.part === 'scale'
          ? { u: box.x + box.w + 14 * k, v: box.y - 10 * k }
          : { u: anchor.u + 14 * k, v: anchor.v + 26 * k };
  return (
    <g>
      {/* The box it covers. */}
      {width || height || scale ? (
        <rect x={box.x} y={box.y} width={box.w} height={box.h} fill="none" stroke="#fbbf24" strokeOpacity={0.5} strokeWidth={1 * k} strokeDasharray={`${4 * k} ${4 * k}`} pointerEvents="none" />
      ) : null}
      {turn != null && knob ? (
        <g className="cursor-grab" onPointerDown={down({ kind: 'rotate' })}>
          <title>
            {front
              ? 'Turn or tilt it left and right, as seen from the front (Shift: 15° steps)'
              : side === 'top'
                ? 'Turn which way it faces, as seen from above (Shift: 15° steps)'
                : 'Tilt it toward the street or the house, as seen from the side (Shift: 15° steps)'}
          </title>
          <circle cx={anchor.u} cy={anchor.v} r={R} fill="none" stroke="transparent" strokeWidth={14 * k} />
          <circle cx={anchor.u} cy={anchor.v} r={R} fill="none" stroke={ringColor} strokeOpacity={active?.part === 'rotate' ? 0.95 : 0.6} strokeWidth={(active?.part === 'rotate' ? 3 : 2) * k} />
          <line x1={anchor.u} y1={anchor.v} x2={knob.u} y2={knob.v} stroke={ringColor} strokeOpacity={0.35} strokeWidth={1.5 * k} strokeDasharray={`${4 * k} ${4 * k}`} pointerEvents="none" />
          <circle cx={knob.u} cy={knob.v} r={8 * k} fill={ringColor} stroke="#0c0a09" strokeWidth={2 * k} />
          <path
            d={`M ${knob.u - 3.5 * k} ${knob.v - 1 * k} a ${3.5 * k} ${3.5 * k} 0 1 1 ${3.5 * k} ${4.5 * k}`}
            fill="none"
            stroke="#fff"
            strokeWidth={1.6 * k}
            strokeLinecap="round"
            pointerEvents="none"
          />
        </g>
      ) : null}
      {side === 'side'
        ? arrow('z', { u: 1, v: 0 }, AXIS_RGB.z, 'Z', 'Move toward the street or the house (Z). Drag the square to move it freely.', 'u')
        : arrow('x', { u: 1, v: 0 }, AXIS_RGB.x, 'X', 'Move across (X). Drag the square to move it freely.', 'u')}
      {side === 'top'
        ? arrow('z', { u: 0, v: 1 }, AXIS_RGB.z, 'Z', 'Move toward the street or the house (Z)', 'v')
        : arrow('y', { u: 0, v: -1 }, AXIS_RGB.y, 'Y', 'Move up and down (Y)', 'v')}
      <g className="cursor-move" onPointerDown={down({ kind: 'move', axis: null })}>
        <title>Move it freely</title>
        <rect x={anchor.u - 12 * k} y={anchor.v - 12 * k} width={24 * k} height={24 * k} fill="transparent" />
        <rect x={anchor.u - 6.5 * k} y={anchor.v - 6.5 * k} width={13 * k} height={13 * k} rx={2 * k} fill="#f8fafc" fillOpacity={0.9} stroke="#0c0a09" strokeWidth={1.5 * k} />
      </g>
      {width ? square('w', { u: box.x + box.w, v: box.y + box.h / 2 }, 'cursor-ew-resize', { kind: 'width' }, 'Width') : null}
      {height ? square('h', { u: box.x + box.w / 2, v: box.y }, 'cursor-ns-resize', { kind: 'height' }, 'Height') : null}
      {scale ? square('s', { u: box.x + box.w, v: box.y }, 'cursor-nesw-resize', { kind: 'scale' }, 'Size: width and height together') : null}
      {label ? (
        <text x={labelAt.u} y={labelAt.v} fontSize={13 * k} fontWeight={700} fill="#fff" stroke="#0c0a09" strokeWidth={4 * k} paintOrder="stroke" pointerEvents="none" className="tabular-nums">
          {label}
        </text>
      ) : null}
    </g>
  );
}
