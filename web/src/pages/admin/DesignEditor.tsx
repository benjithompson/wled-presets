// The object designer: draw how a light string is laid out on your own object (a star, a
// wreath, an arch…), see where every LED lands, and save it to the library to place it in the
// yard as many times as you like. Designs are in meters, as seen from the front, y up.
import { useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent } from 'react';
import { ArrowLeftRight, Camera, Crosshair, Maximize, MousePointer2, PenTool, Redo2, Trash2, Undo2 } from 'lucide-react';
import { designCounts, designLeds, designLength, FEET_PER_METER, type Design, type DesignPoint, type DesignStroke, type Layout } from '../../../../shared/layout.ts';
import { allLights, ledsForLength, lightsOf, lightSummary, spacingText, strandStarts, strandText } from '../../../../shared/lights.ts';
import { Button, Dialog } from '../../components/ui.tsx';
import { cn } from '../../lib/utils.ts';
import { PhotoTrace } from './PhotoTrace.tsx';
import { PropButton, PropNote, PropNumber, PropRow, PropSection, PropSelect, PropText } from './props.tsx';

type P = { x: number; y: number };
type Pick = { s: number; i: number };
type Tool = 'select' | 'draw';

const r3 = (v: number) => Math.round(v * 1000) / 1000;

// ---------- Templates ----------

const ring = (n: number, f: (t: number) => P): P[] => Array.from({ length: n }, (_, i) => f((i / n) * Math.PI * 2));

export const DESIGN_TEMPLATES: { id: string; name: string; strokes: () => DesignStroke[] }[] = [
  {
    id: 'star',
    name: 'Star',
    strokes: () => [{ closed: true, points: Array.from({ length: 10 }, (_, i) => ({ x: r3(Math.sin((i * Math.PI) / 5) * (i % 2 ? 0.19 : 0.46)), y: r3(Math.cos((i * Math.PI) / 5) * (i % 2 ? 0.19 : 0.46)) })) }]
  },
  { id: 'wreath', name: 'Wreath', strokes: () => [{ closed: true, points: ring(36, (a) => ({ x: r3(Math.sin(a) * 0.45), y: r3(Math.cos(a) * 0.45) })) }] },
  {
    id: 'heart',
    name: 'Heart',
    strokes: () => [
      {
        closed: true,
        points: ring(40, (a) => ({ x: r3(((16 * Math.sin(a) ** 3) / 17) * 0.45), y: r3(((13 * Math.cos(a) - 5 * Math.cos(2 * a) - 2 * Math.cos(3 * a) - Math.cos(4 * a)) / 17) * 0.45 + 0.03) }))
      }
    ]
  },
  { id: 'arch', name: 'Arch', strokes: () => [{ points: Array.from({ length: 25 }, (_, i) => ({ x: r3(-Math.cos((i / 24) * Math.PI) * 1), y: r3(Math.sin((i / 24) * Math.PI) * 1) })) }] },
  {
    id: 'window',
    name: 'Window',
    strokes: () => [
      {
        closed: true,
        points: [
          { x: -0.6, y: -0.6 },
          { x: -0.6, y: 0.6 },
          { x: 0.6, y: 0.6 },
          { x: 0.6, y: -0.6 }
        ]
      }
    ]
  },
  {
    id: 'cane',
    name: 'Candy cane',
    strokes: () => [
      {
        points: [
          { x: 0.15, y: -0.6 },
          { x: 0.15, y: 0.3 },
          ...Array.from({ length: 9 }, (_, i) => ({ x: r3(Math.cos((i / 8) * Math.PI) * 0.15), y: r3(0.3 + Math.sin((i / 8) * Math.PI) * 0.15) })).slice(1),
          { x: -0.15, y: 0.18 }
        ]
      }
    ]
  },
  {
    id: 'tree',
    name: 'Flat tree',
    strokes: () => [
      {
        closed: true,
        points: [
          { x: 0, y: 0.9 },
          { x: 0.3, y: 0.45 },
          { x: 0.15, y: 0.45 },
          { x: 0.45, y: 0 },
          { x: 0.25, y: 0 },
          { x: 0.6, y: -0.5 },
          { x: -0.6, y: -0.5 },
          { x: -0.25, y: 0 },
          { x: -0.45, y: 0 },
          { x: -0.15, y: 0.45 },
          { x: -0.3, y: 0.45 }
        ]
      }
    ]
  },
  {
    id: 'snowflake',
    name: 'Snowflake',
    strokes: () => {
      const out: DesignStroke[] = [];
      for (let k = 0; k < 6; k++) {
        const a = (k * Math.PI) / 3;
        const at = (d: number, side: number): P => ({ x: r3(Math.sin(a) * d + Math.cos(a) * side), y: r3(Math.cos(a) * d - Math.sin(a) * side) });
        out.push({ points: [at(0.06, 0), at(0.5, 0)] }, { points: [at(0.22, -0.12), at(0.32, 0), at(0.22, 0.12)] });
      }
      return out;
    }
  },
  { id: 'spiral', name: 'Spiral', strokes: () => [{ points: Array.from({ length: 60 }, (_, i) => ({ x: r3(Math.sin((i / 59) * Math.PI * 6) * 0.05 + Math.sin((i / 59) * Math.PI * 6) * (i / 59) * 0.4), y: r3(Math.cos((i / 59) * Math.PI * 6) * (0.05 + (i / 59) * 0.4)) })) }] },
  {
    id: 'zigzag',
    name: 'Zigzag',
    strokes: () => [{ points: Array.from({ length: 9 }, (_, i) => ({ x: r3(-0.8 + i * 0.2), y: i % 2 ? 0.25 : -0.25 })) }]
  }
];

// ---------- Small helpers ----------

function bounds(strokes: DesignStroke[]) {
  let x0 = Infinity;
  let y0 = Infinity;
  let x1 = -Infinity;
  let y1 = -Infinity;
  for (const s of strokes)
    for (const p of s.points) {
      x0 = Math.min(x0, p.x);
      y0 = Math.min(y0, p.y);
      x1 = Math.max(x1, p.x);
      y1 = Math.max(y1, p.y);
    }
  return Number.isFinite(x0) ? { x0, y0, x1, y1 } : null;
}

/** Each point moved by f; a 3D point keeps its depth unless f sets it. */
const mapPoints = (strokes: DesignStroke[], f: (p: DesignPoint) => DesignPoint) => strokes.map((s) => ({ ...s, points: s.points.map((p) => ({ ...p, ...f(p) })) }));

function distToSegment(p: P, a: P, b: P) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const l = dx * dx + dy * dy;
  const t = l ? Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / l)) : 0;
  return { d: Math.hypot(p.x - a.x - dx * t, p.y - a.y - dy * t), t };
}

/** A small picture of a design, for the library. */
export function DesignThumb({ strokes, pixels, className }: { strokes: DesignStroke[]; pixels: number; className?: string }) {
  const b = bounds(strokes) ?? { x0: -0.5, y0: -0.5, x1: 0.5, y1: 0.5 };
  const size = Math.max(b.x1 - b.x0, b.y1 - b.y0, 0.1);
  const pad = size * 0.12;
  const leds = designLeds(strokes, Math.min(pixels, 400));
  return (
    <svg viewBox={`${b.x0 - pad} ${-b.y1 - pad} ${b.x1 - b.x0 + 2 * pad} ${b.y1 - b.y0 + 2 * pad}`} className={className} aria-hidden>
      {strokes.map((s, i) => (
        <polyline key={i} points={[...s.points, ...(s.closed && s.points.length > 2 ? [s.points[0]] : [])].map((p) => `${p.x},${-p.y}`).join(' ')} fill="none" stroke="currentColor" strokeOpacity={leds.length ? 0.25 : 0.9} strokeWidth={size * (leds.length ? 0.015 : 0.04)} strokeLinejoin="round" />
      ))}
      {leds.map((p, i) => (
        <circle key={i} cx={p.x} cy={-p.y} r={size * 0.018} fill="#fbbf24" />
      ))}
    </svg>
  );
}

// ---------- The designer ----------

export function DesignEditor({
  open,
  initial,
  layout,
  usedBy,
  onSave,
  onLights,
  onClose
}: {
  open: boolean;
  initial: Design;
  layout: Layout;
  /** How many objects in the yard use this design (they all change). */
  usedBy: number;
  onSave: (d: Design) => void;
  /** True while the photo tracer lights the object for its photo. */
  onLights?: (on: boolean) => void;
  onClose: () => void;
}) {
  const units = layout.units ?? 'ft';
  const perUnit = units === 'm' ? 1 : 1 / FEET_PER_METER;
  const show = (m: number) => Math.round((m / perUnit) * 100) / 100;
  const text = (m: number) => `${show(m)} ${units}`;

  const [name, setName] = useState(initial.name);
  const [lights, setLights] = useState(initial.lights ?? layout.lights ?? '');
  const [pixels, setPixels] = useState(initial.pixels);
  const [strokes, setStrokes] = useState<DesignStroke[]>(initial.strokes);
  const [tool, setTool] = useState<Tool>(initial.strokes.length ? 'select' : 'draw');
  const [pick, setPick] = useState<Pick | null>(null);
  const [stroke, setStroke] = useState<number | null>(null);
  const [draft, setDraft] = useState<P[]>([]);
  const [hover, setHover] = useState<P | null>(null);
  const [photo, setPhoto] = useState(false);
  const past = useRef<DesignStroke[][]>([]);
  const future = useRef<DesignStroke[][]>([]);
  const [, tick] = useState(0);

  // Start again whenever it opens on another design.
  useEffect(() => {
    if (!open) return;
    setName(initial.name);
    setLights(initial.lights ?? layout.lights ?? '');
    setPixels(initial.pixels);
    setStrokes(initial.strokes);
    setTool(initial.strokes.length ? 'select' : 'draw');
    setPick(null);
    setStroke(null);
    setDraft([]);
    past.current = [];
    future.current = [];
    setView(null);
  }, [open, initial, layout.lights]);

  const lt = lightsOf(layout, lights);
  const length = designLength(strokes);
  const leds = useMemo(() => designLeds(strokes, pixels), [strokes, pixels]);
  const fit = lt ? fitLeds(strokes, lt.spacing) : null;
  const box = bounds(strokes);

  /** Changes the strokes; Undo goes back to before. */
  const commit = (next: DesignStroke[]) => {
    // While the LEDs fit the wire, they keep fitting it as the wire changes.
    if (lt && strokes.length && pixels === fitLeds(strokes, lt.spacing)) setPixels(fitLeds(next, lt.spacing));
    past.current.push(strokes);
    if (past.current.length > 100) past.current.shift();
    future.current = [];
    setStrokes(next);
  };
  const undo = () => {
    const prev = past.current.pop();
    if (!prev) return;
    future.current.push(strokes);
    setStrokes(prev);
    setPick(null);
    tick((n) => n + 1);
  };
  const redo = () => {
    const next = future.current.pop();
    if (!next) return;
    past.current.push(strokes);
    setStrokes(next);
    tick((n) => n + 1);
  };

  // ----- The view: meters to screen pixels -----
  const wrap = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 600, h: 440 });
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: Math.max(200, e.contentRect.width), h: Math.max(200, e.contentRect.height) }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [open]);
  const [view, setView] = useState<{ cx: number; cy: number; ppm: number } | null>(null);
  const fitView = (st = strokes) => {
    const b = bounds(st) ?? { x0: -0.6, y0: -0.6, x1: 0.6, y1: 0.6 };
    const w = Math.max(0.6, b.x1 - b.x0);
    const h = Math.max(0.6, b.y1 - b.y0);
    return { cx: (b.x0 + b.x1) / 2, cy: (b.y0 + b.y1) / 2, ppm: Math.min(size.w / (w * 1.35), size.h / (h * 1.35)) };
  };
  const v = view ?? fitView();
  const S = (p: P) => ({ X: size.w / 2 + (p.x - v.cx) * v.ppm, Y: size.h / 2 - (p.y - v.cy) * v.ppm });
  const W = (X: number, Y: number): P => ({ x: v.cx + (X - size.w / 2) / v.ppm, y: v.cy - (Y - size.h / 2) / v.ppm });

  // Grid: 3 in (major: 1 ft), or 5 cm (major: 50 cm). Points snap to it.
  const minor = units === 'm' ? 0.05 : 0.0762;
  const major = units === 'm' ? 0.5 : 0.3048;
  const snap = (p: P, free: boolean): P => (free ? { x: r3(p.x), y: r3(p.y) } : { x: r3(Math.round(p.x / minor) * minor), y: r3(Math.round(p.y / minor) * minor) });

  const svgPoint = (e: { clientX: number; clientY: number }) => {
    const r = wrap.current!.getBoundingClientRect();
    return { X: e.clientX - r.left, Y: e.clientY - r.top };
  };
  const hitPoint = (X: number, Y: number): Pick | null => {
    let best: Pick | null = null;
    let bd = 9;
    strokes.forEach((s, si) =>
      s.points.forEach((p, i) => {
        const q = S(p);
        const d = Math.hypot(q.X - X, q.Y - Y);
        if (d < bd) {
          bd = d;
          best = { s: si, i };
        }
      })
    );
    return best;
  };
  const hitEdge = (X: number, Y: number): { s: number; i: number; t: number } | null => {
    const p = W(X, Y);
    let best: { s: number; i: number; t: number } | null = null;
    let bd = 7 / v.ppm;
    strokes.forEach((s, si) => {
      const pts = s.closed && s.points.length > 2 ? [...s.points, s.points[0]] : s.points;
      for (let i = 0; i < pts.length - 1; i++) {
        const { d, t } = distToSegment(p, pts[i], pts[i + 1]);
        if (d < bd) {
          bd = d;
          best = { s: si, i, t };
        }
      }
    });
    return best;
  };

  const drag = useRef<{ kind: 'point'; pick: Pick; start: DesignStroke[]; moved: boolean } | { kind: 'pan'; X: number; Y: number; cx: number; cy: number } | null>(null);

  const finishDraft = (closed = false) => {
    if (draft.length >= 2 || (draft.length === 1 && !closed)) {
      const next = [...strokes, { points: draft, ...(closed && draft.length > 2 ? { closed: true } : {}) }];
      commit(next);
      setStroke(next.length - 1);
      // A first stroke: fit the LEDs to it.
      if (!strokes.length && lt) setPixels(fitLeds(next, lt.spacing));
    }
    setDraft([]);
  };

  const onDown = (e: RPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 && e.button !== 1) return;
    const { X, Y } = svgPoint(e);
    (e.currentTarget as HTMLDivElement).setPointerCapture(e.pointerId);
    if (e.button === 1 || e.shiftKey && tool === 'select' && !hitPoint(X, Y)) {
      drag.current = { kind: 'pan', X, Y, cx: v.cx, cy: v.cy };
      return;
    }
    if (tool === 'draw') {
      const p = snap(W(X, Y), e.altKey);
      // Clicking the first point closes the shape.
      if (draft.length >= 3) {
        const q = S(draft[0]);
        if (Math.hypot(q.X - X, q.Y - Y) < 10) return finishDraft(true);
      }
      setDraft((d) => (d.length && Math.hypot(d.at(-1)!.x - p.x, d.at(-1)!.y - p.y) < 1e-6 ? d : [...d, p]));
      return;
    }
    const hp = hitPoint(X, Y);
    if (hp) {
      setPick(hp);
      setStroke(hp.s);
      drag.current = { kind: 'point', pick: hp, start: strokes, moved: false };
      return;
    }
    const he = hitEdge(X, Y);
    if (he) {
      setStroke(he.s);
      setPick(null);
      return;
    }
    setPick(null);
    setStroke(null);
    drag.current = { kind: 'pan', X, Y, cx: v.cx, cy: v.cy };
  };
  const onMove = (e: RPointerEvent<HTMLDivElement>) => {
    const { X, Y } = svgPoint(e);
    setHover(tool === 'draw' ? snap(W(X, Y), e.altKey) : null);
    const d = drag.current;
    if (!d) return;
    if (d.kind === 'pan') {
      setView({ ...v, cx: d.cx - (X - d.X) / v.ppm, cy: d.cy + (Y - d.Y) / v.ppm });
      return;
    }
    const p = snap(W(X, Y), e.altKey);
    d.moved = true;
    setStrokes(d.start.map((s, si) => (si === d.pick.s ? { ...s, points: s.points.map((q, i) => (i === d.pick.i ? { ...q, ...p } : q)) } : s)));
  };
  const onUp = () => {
    const d = drag.current;
    drag.current = null;
    if (d?.kind === 'point' && d.moved) {
      past.current.push(d.start);
      future.current = [];
      if (lt && pixels === fitLeds(d.start, lt.spacing)) setPixels(fitLeds(strokes, lt.spacing));
    }
  };
  const onDouble = (e: React.MouseEvent) => {
    const { X, Y } = svgPoint(e);
    if (tool === 'draw') return finishDraft();
    // Double-click a point to delete it, or the wire to add a point there.
    const hp = hitPoint(X, Y);
    if (hp) return deletePoint(hp);
    const he = hitEdge(X, Y);
    if (he) {
      const p = snap(W(X, Y), e.altKey);
      commit(strokes.map((s, si) => (si === he.s ? { ...s, points: [...s.points.slice(0, he.i + 1), p, ...s.points.slice(he.i + 1)] } : s)));
      setPick({ s: he.s, i: he.i + 1 });
    }
  };
  const onWheel = (e: React.WheelEvent) => {
    const { X, Y } = svgPoint(e);
    const at = W(X, Y);
    const ppm = Math.min(5000, Math.max(20, v.ppm * Math.exp(-e.deltaY * 0.0015)));
    setView({ ppm, cx: at.x - (X - size.w / 2) / ppm, cy: at.y + (Y - size.h / 2) / ppm });
  };

  const deletePoint = (p: Pick) => {
    const next = strokes.map((s, si) => (si === p.s ? { ...s, points: s.points.filter((_, i) => i !== p.i) } : s)).filter((s) => s.points.length > 0);
    commit(next);
    setPick(null);
    setStroke(null);
  };
  const deleteStroke = (k: number) => {
    commit(strokes.filter((_, i) => i !== k));
    setStroke(null);
    setPick(null);
  };

  // Keys: V select, P draw, Enter/Esc finish, Backspace/Delete remove, Ctrl/⌘+Z undo.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.closest('input, select, textarea')) return;
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === 'z') {
        e.preventDefault();
        return e.shiftKey ? redo() : undo();
      }
      if (draft.length) {
        if (e.key === 'Enter') return finishDraft();
        if (e.key === 'Escape') {
          e.preventDefault();
          return setDraft([]);
        }
        if (e.key === 'Backspace') return setDraft((d) => d.slice(0, -1));
      }
      if (e.key === 'v' || e.key === 'V') setTool('select');
      if (e.key === 'p' || e.key === 'P') setTool('draw');
      if (e.key === 'Delete' || e.key === 'Backspace') {
        if (pick) deletePoint(pick);
        else if (stroke != null) deleteStroke(stroke);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const apply = (next: DesignStroke[], refit = false) => {
    commit(next);
    if (refit && lt) setPixels(fitLeds(next, lt.spacing));
  };
  const useTemplate = (id: string) => {
    const t = DESIGN_TEMPLATES.find((x) => x.id === id);
    if (!t) return;
    const next = t.strokes();
    commit(next);
    if (!name.trim() || name === 'My object' || DESIGN_TEMPLATES.some((x) => x.name === name)) setName(t.name);
    setPixels(lt ? fitLeds(next, lt.spacing) : 50);
    setPick(null);
    setStroke(null);
    setView(fitView(next));
    setTool('select');
  };

  const starts = new Set(strandStarts(pixels, lt?.perStrand ?? null));
  const strokeStarts = new Set<number>();
  {
    // The first LED of each stroke, for its label.
    let acc = 0;
    const counts = designCounts(strokes, pixels);
    for (const c of counts) {
      if (c) strokeStarts.add(acc);
      acc += c;
    }
  }
  const dot = Math.max(2.2, Math.min(6, (lt?.spacing ?? 0.08) * v.ppm * 0.32));

  // Grid lines in view.
  const grid: { a: number; vertical: boolean; major: boolean }[] = [];
  {
    const lo = W(0, size.h);
    const hi = W(size.w, 0);
    for (const [step, isMajor] of [
      [minor, false],
      [major, true]
    ] as const) {
      if (step * v.ppm < 7) continue;
      for (let x = Math.ceil(lo.x / step) * step; x <= hi.x; x += step) grid.push({ a: x, vertical: true, major: isMajor });
      for (let y = Math.ceil(lo.y / step) * step; y <= hi.y; y += step) grid.push({ a: y, vertical: false, major: isMajor });
    }
  }

  const sel = pick ? strokes[pick.s]?.points[pick.i] : null;
  const toolBtn = (t: Tool, label: string, key: string, Icon: typeof PenTool) => (
    <button
      type="button"
      onClick={() => (setTool(t), setDraft([]))}
      title={`${label} (${key})`}
      aria-pressed={tool === t}
      className={cn('flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-medium transition [&_svg]:size-4', tool === t ? 'bg-sky-600 text-white' : 'text-stone-700 hover:bg-stone-200/70 dark:text-stone-300 dark:hover:bg-stone-800')}
    >
      <Icon /> {label}
    </button>
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="xl"
      title={initial.strokes.length ? `Design: ${initial.name}` : 'New custom object'}
      description="Draw how the light string runs over the object. The LEDs spread along the wire at one spacing; between strokes the wire jumps without LEDs."
      footer={
        <>
          {usedBy ? <span className="mr-auto self-center text-xs text-stone-500">Saving changes {usedBy} object{usedBy === 1 ? '' : 's'} in the yard.</span> : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!strokes.length || !name.trim()}
            onClick={() => onSave({ ...initial, name: name.trim(), strokes, pixels: Math.max(1, Math.round(pixels)), ...(lights ? { lights } : { lights: undefined }) })}
          >
            {usedBy ? 'Save design' : 'Save to library'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2 lg:flex-row">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-1">
            {toolBtn('select', 'Select', 'V', MousePointer2)}
            {toolBtn('draw', 'Draw wire', 'P', PenTool)}
            {/* Also under the drawing (Start from), which a phone has to scroll to. */}
            <button
              type="button"
              onClick={() => setPhoto(true)}
              title="Light the object up, take a picture or scan it, and its LEDs become the shape"
              className="flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-medium text-sky-700 transition hover:bg-sky-50 dark:text-sky-300 dark:hover:bg-sky-500/10 [&_svg]:size-4"
            >
              <Camera /> Photo or scan
            </button>
            <span className="mx-1 h-5 w-px bg-stone-200 dark:bg-stone-700" />
            <Button size="sm" variant="ghost" onClick={undo} disabled={!past.current.length} title="Undo (Ctrl/⌘+Z)" aria-label="Undo" className="px-2">
              <Undo2 />
            </Button>
            <Button size="sm" variant="ghost" onClick={redo} disabled={!future.current.length} title="Redo (Ctrl/⌘+Shift+Z)" aria-label="Redo" className="px-2">
              <Redo2 />
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setView(null)} title="Zoom to fit" aria-label="Zoom to fit" className="px-2">
              <Maximize />
            </Button>
            <span className="ml-auto text-[11px] text-stone-500 tabular-nums">
              {box ? `${text(box.x1 - box.x0)} × ${text(box.y1 - box.y0)} · ` : ''}
              {text(length)} of wire · {pixels} LEDs
            </span>
          </div>
          <div
            ref={wrap}
            className={cn('relative h-[40dvh] min-h-64 touch-none sm:h-[52dvh] sm:min-h-72 overflow-hidden rounded-xl bg-[#05070f] select-none', tool === 'draw' ? 'cursor-crosshair' : 'cursor-default')}
            onPointerDown={onDown}
            onPointerMove={onMove}
            onPointerUp={onUp}
            onPointerLeave={() => setHover(null)}
            onDoubleClick={onDouble}
            onWheel={onWheel}
          >
            <svg width={size.w} height={size.h} className="absolute inset-0">
              {grid.map((g, i) =>
                g.vertical ? (
                  <line key={i} x1={S({ x: g.a, y: 0 }).X} x2={S({ x: g.a, y: 0 }).X} y1={0} y2={size.h} stroke="#fff" strokeOpacity={g.major ? 0.1 : 0.04} />
                ) : (
                  <line key={i} y1={S({ x: 0, y: g.a }).Y} y2={S({ x: 0, y: g.a }).Y} x1={0} x2={size.w} stroke="#fff" strokeOpacity={g.major ? 0.1 : 0.04} />
                )
              )}
              {/* The anchor: the point you place in the yard. */}
              <g stroke="#fbbf24" strokeOpacity={0.6}>
                <line x1={S({ x: 0, y: 0 }).X - 10} x2={S({ x: 0, y: 0 }).X + 10} y1={S({ x: 0, y: 0 }).Y} y2={S({ x: 0, y: 0 }).Y} />
                <line y1={S({ x: 0, y: 0 }).Y - 10} y2={S({ x: 0, y: 0 }).Y + 10} x1={S({ x: 0, y: 0 }).X} x2={S({ x: 0, y: 0 }).X} />
              </g>
              {strokes.map((s, si) => {
                const pts = s.closed && s.points.length > 2 ? [...s.points, s.points[0]] : s.points;
                return (
                  <polyline
                    key={si}
                    points={pts.map((p) => `${S(p).X},${S(p).Y}`).join(' ')}
                    fill="none"
                    stroke={stroke === si ? 'rgb(40,170,255)' : '#fff'}
                    strokeOpacity={stroke === si ? 0.9 : 0.28}
                    strokeWidth={stroke === si ? 2.5 : 1.5}
                    strokeLinejoin="round"
                  />
                );
              })}
              {/* Wire jumps between strokes: no LEDs. */}
              {strokes.slice(1).map((s, si) => {
                const prev = strokes[si];
                const a = prev.closed && prev.points.length > 2 ? prev.points[0] : prev.points.at(-1);
                const b = s.points[0];
                if (!a || !b) return null;
                return <line key={`j${si}`} x1={S(a).X} y1={S(a).Y} x2={S(b).X} y2={S(b).Y} stroke="#fff" strokeOpacity={0.15} strokeDasharray="3 5" />;
              })}
              {leds.map((p, i) => {
                const q = S(p);
                const first = i === 0;
                const last = i === leds.length - 1;
                return (
                  <g key={i}>
                    <circle cx={q.X} cy={q.Y} r={dot} fill={starts.has(i) ? '#fb923c' : '#fde68a'} />
                    {first || last ? <circle cx={q.X} cy={q.Y} r={dot + 4} fill="none" stroke={first ? '#22c55e' : '#ef4444'} strokeWidth={2} /> : null}
                    {strokeStarts.has(i) || starts.has(i) ? (
                      <text x={q.X + dot + 4} y={q.Y - dot - 3} fontSize={10} fill={starts.has(i) ? '#fb923c' : '#fde68a'} stroke="#05070f" strokeWidth={3} paintOrder="stroke" className="tabular-nums">
                        {starts.has(i) ? `strand ${Math.round(i / (lt?.perStrand ?? 1)) + 1}` : `LED ${i}`}
                      </text>
                    ) : null}
                  </g>
                );
              })}
              {tool === 'select'
                ? strokes.flatMap((s, si) =>
                    s.points.map((p, i) => (
                      <rect
                        key={`${si}-${i}`}
                        x={S(p).X - 4}
                        y={S(p).Y - 4}
                        width={8}
                        height={8}
                        fill={pick?.s === si && pick.i === i ? 'rgb(40,170,255)' : '#05070f'}
                        stroke={stroke === si ? 'rgb(40,170,255)' : '#fff'}
                        strokeOpacity={0.8}
                      />
                    ))
                  )
                : null}
              {draft.length ? (
                <polyline points={[...draft, ...(hover ? [hover] : [])].map((p) => `${S(p).X},${S(p).Y}`).join(' ')} fill="none" stroke="#fde68a" strokeWidth={2} strokeDasharray="6 4" />
              ) : null}
              {draft.map((p, i) => (
                <circle key={i} cx={S(p).X} cy={S(p).Y} r={i === 0 && draft.length >= 3 ? 7 : 3.5} fill={i === 0 ? '#22c55e' : '#fde68a'} fillOpacity={0.9} />
              ))}
              {hover && tool === 'draw' ? <circle cx={S(hover).X} cy={S(hover).Y} r={3} fill="#fff" /> : null}
            </svg>
            <p className="pointer-events-none absolute inset-x-3 bottom-2 text-[11px] text-white/60">
              {tool === 'draw'
                ? draft.length
                  ? 'Click the next point. Click the green first point to close the shape. Enter or double-click: done. Backspace: undo a point. Alt: no snapping.'
                  : 'Click where the wire starts (LED 0), then each corner. Points snap to the grid.'
                : 'Drag a point to move it. Double-click the wire to add a point, a point to delete it. Drag the background to pan, wheel to zoom.'}
            </p>
          </div>
          <div className="mt-2 flex flex-wrap gap-1">
            <span className="self-center pr-1 text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Start from</span>
            <button
              type="button"
              onClick={() => setPhoto(true)}
              title="Light the object up, take a picture, and its LEDs become the shape"
              className="flex items-center gap-1.5 rounded-lg bg-sky-50 px-2 py-1 text-xs font-medium text-sky-700 transition hover:bg-sky-100 dark:bg-sky-500/10 dark:text-sky-300 dark:hover:bg-sky-500/20 [&_svg]:size-4"
            >
              <Camera /> A photo
            </button>
            {DESIGN_TEMPLATES.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => useTemplate(t.id)}
                className="flex items-center gap-1.5 rounded-lg bg-stone-100 px-2 py-1 text-xs text-stone-700 transition hover:bg-stone-200 dark:bg-stone-800 dark:text-stone-200 dark:hover:bg-stone-700"
              >
                <DesignThumb strokes={t.strokes()} pixels={0} className="size-5 text-stone-500" /> {t.name}
              </button>
            ))}
          </div>
        </div>

        <div className="w-full shrink-0 rounded-xl ring-1 ring-stone-200 lg:w-72 dark:ring-stone-800">
          <PropSection id="design-object" title="Object">
            <PropText label="Name" value={name} maxLength={60} onChange={setName} />
            <PropSelect
              label="Made of"
              value={lights}
              options={[['', 'Not set'], ...allLights(layout).map((l): [string, string] => [l.id, l.name])]}
              onChange={(id) => {
                setLights(id);
                const n = lightsOf(layout, id);
                if (n && strokes.length) setPixels(fitLeds(strokes, n.spacing));
              }}
            />
            {lt ? <PropNote>{lightSummary(lt, units)}</PropNote> : <PropNote>Pick the light string to space the LEDs as they are on the real wire.</PropNote>}
            <PropNumber label="LEDs" value={pixels} min={1} max={2000} steppers onChange={(n) => setPixels(Math.round(n))} />
            {lt && fit != null && fit !== pixels ? (
              <PropRow label="">
                <PropButton onClick={() => setPixels(fit)} title={`The wire is ${text(length)}: at ${spacingText(lt.spacing, units)} apart that is ${fit} LEDs`}>
                  Fit to the wire: {fit} LEDs
                </PropButton>
              </PropRow>
            ) : null}
            {lt && fit === pixels ? <PropNote>The LEDs fit the wire, and keep fitting it as you change the drawing.</PropNote> : null}
            {strokes.some((s) => s.points.some((p) => p.z)) ? <PropNote>A 3D shape: you see it from the front here, and dragging a point keeps its depth. The 3D view of the layout shows it all round.</PropNote> : null}
            {lt?.perStrand ? <PropNote>{strandText(pixels, lt.perStrand)}. Orange dots: where a new strand starts.</PropNote> : null}
            {lt && strokes.length ? (
              <PropNote>
                {text(length)} of wire for {pixels} LEDs: one every {spacingText(length / Math.max(1, gapsOf(strokes, pixels)), units)}
                {Math.abs(length / Math.max(1, gapsOf(strokes, pixels)) - lt.spacing) > lt.spacing * 0.15 ? ` (the string has ${spacingText(lt.spacing, units)})` : ''}.
              </PropNote>
            ) : null}
          </PropSection>

          {stroke != null && strokes[stroke] ? (
            <PropSection id="design-stroke" title={`Stroke ${stroke + 1} of ${strokes.length}`}>
              <PropRow label="Closed" hint="The wire goes back to its first point">
                <input
                  type="checkbox"
                  className="accent-sky-600"
                  checked={!!strokes[stroke].closed}
                  disabled={strokes[stroke].points.length < 3}
                  onChange={(e) => commit(strokes.map((s, i) => (i === stroke ? { ...s, closed: e.target.checked || undefined } : s)))}
                />
              </PropRow>
              {strokes[stroke].exact ? (
                <PropRow label="An LED per point" hint="From a scan: each point is where an LED really is. Off: the LEDs spread evenly along the wire.">
                  <input type="checkbox" className="accent-sky-600" checked onChange={() => commit(strokes.map((s, i) => (i === stroke ? { ...s, exact: undefined } : s)))} />
                </PropRow>
              ) : null}
              {sel && pick ? (
                <>
                  <PropNumber label="Point x" decimal step={0.1} min={-300} max={300} unit={units} value={show(sel.x)} onChange={(n) => commit(movePoint(strokes, pick, { x: r3(n * perUnit), y: sel.y }))} />
                  <PropNumber label="Point y" decimal step={0.1} min={-300} max={300} unit={units} value={show(sel.y)} onChange={(n) => commit(movePoint(strokes, pick, { x: sel.x, y: r3(n * perUnit) }))} />
                  <PropNumber
                    label="Point depth"
                    hint="Toward the front of the object (minus: toward its back)"
                    decimal
                    step={0.1}
                    min={-300}
                    max={300}
                    unit={units}
                    value={show(sel.z ?? 0)}
                    onChange={(n) => commit(movePoint(strokes, pick, { x: sel.x, y: sel.y, z: r3(n * perUnit) }))}
                  />
                </>
              ) : null}
              <div className="flex flex-wrap gap-1.5 pt-1">
                <PropButton onClick={() => commit(strokes.map((s, i) => (i === stroke ? { ...s, points: [...s.points].reverse() } : s)))} title="The LEDs on this stroke run the other way">
                  <ArrowLeftRight /> Reverse
                </PropButton>
                <PropButton
                  disabled={stroke === 0}
                  onClick={() => {
                    const next = [...strokes];
                    [next[stroke - 1], next[stroke]] = [next[stroke], next[stroke - 1]];
                    commit(next);
                    setStroke(stroke - 1);
                  }}
                  title="Its LEDs come earlier on the string"
                >
                  Earlier
                </PropButton>
                <PropButton
                  disabled={stroke === strokes.length - 1}
                  onClick={() => {
                    const next = [...strokes];
                    [next[stroke + 1], next[stroke]] = [next[stroke], next[stroke + 1]];
                    commit(next);
                    setStroke(stroke + 1);
                  }}
                  title="Its LEDs come later on the string"
                >
                  Later
                </PropButton>
                <PropButton danger onClick={() => deleteStroke(stroke)}>
                  <Trash2 /> Delete
                </PropButton>
              </div>
            </PropSection>
          ) : null}

          <PropSection id="design-size" title="Size and order">
            <PropNumber
              label="Width"
              decimal
              step={0.1}
              min={0.01}
              max={300}
              unit={units}
              value={box ? show(box.x1 - box.x0) : null}
              placeholder="—"
              onChange={(n) => {
                if (!box || box.x1 - box.x0 < 1e-6) return;
                const k = (n * perUnit) / (box.x1 - box.x0);
                apply(mapPoints(strokes, (p) => ({ x: r3(p.x * k), y: r3(p.y * k), ...(p.z != null ? { z: r3(p.z * k) } : {}) })), true);
              }}
            />
            <PropNumber
              label="Height"
              decimal
              step={0.1}
              min={0.01}
              max={300}
              unit={units}
              value={box ? show(box.y1 - box.y0) : null}
              placeholder="—"
              onChange={(n) => {
                if (!box || box.y1 - box.y0 < 1e-6) return;
                const k = (n * perUnit) / (box.y1 - box.y0);
                apply(mapPoints(strokes, (p) => ({ x: r3(p.x * k), y: r3(p.y * k), ...(p.z != null ? { z: r3(p.z * k) } : {}) })), true);
              }}
            />
            <PropNote>Width and height keep the shape; the LEDs are fitted again when a light string is set.</PropNote>
            <div className="flex flex-wrap gap-1.5 pt-1">
              <PropButton
                disabled={!box}
                onClick={() => box && commit(mapPoints(strokes, (p) => ({ x: r3(p.x - (box.x0 + box.x1) / 2), y: r3(p.y - (box.y0 + box.y1) / 2) })))}
                title="Puts the anchor (the point you place in the yard) in the middle"
              >
                <Crosshair /> Anchor in the middle
              </PropButton>
              <PropButton
                disabled={!box}
                onClick={() => box && commit(mapPoints(strokes, (p) => ({ x: r3(p.x - (box.x0 + box.x1) / 2), y: r3(p.y - box.y0) })))}
                title="Puts the anchor at the bottom, for objects that stand on the ground"
              >
                Anchor at the bottom
              </PropButton>
              <PropButton
                disabled={!strokes.length}
                onClick={() => commit([...strokes].reverse().map((s) => ({ ...s, points: [...s.points].reverse() })))}
                title="LED 0 moves to the other end of the string"
              >
                <ArrowLeftRight /> Flip LED order
              </PropButton>
            </div>
          </PropSection>
        </div>
      </div>
      <PhotoTrace
        open={photo}
        layout={layout}
        designId={initial.id}
        pixels={pixels}
        spacing={lt?.spacing ?? null}
        onLights={(on) => onLights?.(on)}
        onClose={() => setPhoto(false)}
        onUse={(next, n) => {
          commit(next);
          setPixels(n ?? (lt ? fitLeds(next, lt.spacing) : pixels));
          setPick(null);
          setStroke(null);
          setDraft([]);
          setView(fitView(next));
          setTool('select');
          setPhoto(false);
        }}
      />
    </Dialog>
  );
}

function movePoint(strokes: DesignStroke[], pick: Pick, p: DesignPoint) {
  return strokes.map((s, si) => (si === pick.s ? { ...s, points: s.points.map((q, i) => (i === pick.i ? { ...q, ...p } : q)) } : s));
}

const isClosed = (s: DesignStroke) => !!s.closed && s.points.length > 2;

/** LED-to-LED gaps along the wire: one less than the LEDs on an open stroke. */
function gapsOf(strokes: DesignStroke[], pixels: number) {
  return pixels - strokes.filter((s) => s.points.length && !isClosed(s)).length;
}

/** How many LEDs a design's wire holds at this spacing. */
export function fitLeds(strokes: DesignStroke[], spacing: number): number {
  let n = 0;
  for (const s of strokes) {
    if (!s.points.length) continue;
    // A scanned stroke: an LED at each point.
    if (s.exact) {
      n += s.points.length;
      continue;
    }
    const pts = isClosed(s) ? [...s.points, s.points[0]] : s.points;
    const len = pts.slice(1).reduce((a, p, i) => a + Math.hypot(p.x - pts[i].x, p.y - pts[i].y, (p.z ?? 0) - (pts[i].z ?? 0)), 0);
    n += isClosed(s) ? Math.max(1, ledsForLength(len, spacing, false)) : ledsForLength(len, spacing, true);
  }
  return Math.max(1, Math.min(2000, n));
}
