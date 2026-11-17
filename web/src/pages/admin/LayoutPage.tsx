import { lazy, Suspense, useEffect, useMemo, useRef, useState, type MouseEvent as RMouseEvent, type PointerEvent as RPointerEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeftRight,
  Box,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Circle,
  House,
  ImagePlus,
  Lightbulb,
  LightbulbOff,
  MousePointer2,
  Pin,
  PinOff,
  RotateCcw,
  Ruler,
  Save,
  Scissors,
  Spline,
  Trash2,
  TreePine,
  X
} from 'lucide-react';
import { toast } from 'sonner';
import {
  buildStage,
  deviceLed,
  FEET_PER_METER,
  FIXTURE_HUES,
  hsvBytes,
  editorPulse,
  fixturePixels,
  isLine,
  layoutGround,
  layoutScale,
  paintEditor,
  clampPointLed,
  segmentLeds,
  setPointLed,
  skipAfterInsert,
  skipAfterRemove,
  deviceRuns,
  fromLedRange,
  isPinned,
  LAYOUT_WIDTH,
  ledRange,
  MAX_FIXTURE_PIXELS,
  pointOffsets,
  type Fixture,
  type FixtureKind,
  type Layout,
  type Point,
  type Units
} from '../../../../shared/layout.ts';
import { Badge, Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Switch } from '../../components/ui.tsx';
import { toView, YardView, type ViewSide } from '../../yard/YardView.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { useOverview } from './AdminLayout.tsx';

// three.js is large: load the 3D view only when it is opened.
const Scene3D = lazy(() => import('../../yard/Scene3D.tsx').then((m) => ({ default: m.Scene3D })));

type Tool = 'select' | 'roof' | 'line' | 'bush' | 'tree' | 'measure';
/** A position in one view, in layout units: u to the right, v down. */
type UV = { u: number; v: number };
type Drag =
  | { kind: 'vertex'; side: ViewSide; id: string; index: number }
  | { kind: 'move'; side: ViewSide; id: string; from: UV; original: Point[] }
  | { kind: 'radius'; side: ViewSide; id: string }
  | { kind: 'treeHeight'; id: string }
  | { kind: 'ground' }
  | { kind: 'newBush'; side: ViewSide; center: UV; radius: number }
  | { kind: 'newTree'; side: ViewSide; base: UV; size: number };
type ViewName = ViewSide | '3d';

const LAYOUT_KEY = ['layout'];
const HUES = FIXTURE_HUES;
const SHOW_KEY = 'layout.showOnLights';
const VIEWS_KEY = 'layout.views';
const VIEW_LABELS: Record<ViewName, string> = { front: 'Front', top: 'Top', '3d': '3D' };
const KIND_LABELS: Record<FixtureKind, string> = { roof: 'Roofline', line: 'Line of lights', bush: 'Bush', tree: 'Tree' };

function readShowOnLights() {
  try {
    return localStorage.getItem(SHOW_KEY) !== 'off';
  } catch {
    return true;
  }
}

function readViews(): ViewName[] {
  try {
    const v = JSON.parse(localStorage.getItem(VIEWS_KEY) ?? '') as ViewName[];
    const ok = v.filter((x) => x in VIEW_LABELS);
    if (ok.length) return ok;
  } catch {}
  return ['front', 'top'];
}

/**
 * A number field. A typed number applies 0.7 s after the last key, or at once with Enter or
 * when the field loses focus; Escape puts the old number back. The arrow keys step the number
 * by `step` (Shift: 10 steps) and apply at once. `decimal` allows a sign and a decimal point.
 */
function NumberInput({
  id,
  value,
  min = 0,
  max = 100_000,
  step = 1,
  decimal = false,
  onCommit,
  placeholder,
  className
}: {
  id?: string;
  value: number | null;
  min?: number;
  max?: number;
  step?: number;
  decimal?: boolean;
  onCommit: (n: number) => void;
  placeholder?: string;
  className?: string;
}) {
  const [text, setText] = useState(value == null ? '' : String(value));
  /** True while you are typing a number that is not applied yet. */
  const typing = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Show the applied value (it can be limited, for example so segments do not cross),
  // except while you are in the middle of typing.
  useEffect(() => {
    if (!typing.current) setText(value == null ? '' : String(value));
  }, [value]);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);
  const clamp = (n: number) => Math.min(max, Math.max(min, n));
  const parse = (t: string) => (t === '' || t === '-' || t === '.' || t === '-.' ? NaN : Number(t));
  const commit = (t = text) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    typing.current = false;
    const n = parse(t);
    if (Number.isFinite(n) && clamp(n) !== value) onCommit(clamp(n));
    else setText(value == null ? '' : String(value));
  };
  return (
    <Input
      id={id}
      inputMode={decimal ? 'decimal' : 'numeric'}
      value={text}
      placeholder={placeholder}
      className={className}
      onBlur={() => commit()}
      onKeyDown={(e) => {
        if (e.key === 'Enter') commit();
        if (e.key === 'Escape') {
          typing.current = false;
          if (timer.current) clearTimeout(timer.current);
          setText(value == null ? '' : String(value));
        }
        if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
          e.preventDefault();
          const base = Number.isFinite(parse(text)) ? parse(text) : (value ?? 0);
          const next = base + (e.key === 'ArrowUp' ? 1 : -1) * step * (e.shiftKey ? 10 : 1);
          commit(String(clamp(Math.round(next * 1000) / 1000)));
        }
      }}
      onChange={(e) => {
        // A typed number applies when you stop typing for a moment, or press Enter. Half-typed
        // numbers (and an empty field) are never applied, so they cannot upset other segments.
        const t = decimal ? e.target.value.replace(/[^\d.-]/g, '') : e.target.value.replace(/\D/g, '');
        setText(t);
        typing.current = true;
        if (timer.current) clearTimeout(timer.current);
        if (Number.isFinite(parse(t))) timer.current = setTimeout(() => commit(t), 700);
      }}
    />
  );
}

/** A number field with large step buttons, for adjusting while you look at the lights. */
function StepField({ label, value, min = 0, max = 100_000, onChange, tone }: { label: string; value: number; min?: number; max?: number; onChange: (n: number) => void; tone?: 'green' | 'red' }) {
  const step = (d: number) => onChange(Math.min(max, Math.max(min, value + d)));
  const btn =
    'h-8 flex-1 rounded-lg bg-stone-100 text-xs font-semibold tabular-nums text-stone-700 transition hover:bg-stone-200 active:scale-95 dark:bg-stone-800 dark:text-stone-200 dark:hover:bg-stone-700';
  return (
    <Field label={label}>
      {(id) => (
        <div className="space-y-1.5">
          <div className="relative">
            {tone ? <span className={cn('absolute top-1/2 left-3 size-2.5 -translate-y-1/2 rounded-full', tone === 'green' ? 'bg-green-500' : 'bg-red-500')} /> : null}
            <div className={tone ? '[&_input]:pl-8' : ''}>
              <NumberInput id={id} value={value} min={min} max={max} onCommit={onChange} />
            </div>
          </div>
          <div className="flex gap-1">
            {[-10, -1, 1, 10].map((d) => (
              <button key={d} type="button" className={btn} onClick={() => step(d)} aria-label={`${label} ${d > 0 ? 'plus' : 'minus'} ${Math.abs(d)}`}>
                {d > 0 ? `+${d}` : `−${-d}`}
              </button>
            ))}
          </div>
        </div>
      )}
    </Field>
  );
}

/** Real distances in the editor: layout units shown in feet or meters. */
interface Measure {
  units: Units;
  /** Layout units per shown unit (per foot or per meter). */
  per: number;
  /** Shown units, rounded for display. */
  show: (layoutUnits: number) => number;
  text: (layoutUnits: number) => string;
}

function measureOf(layout: Layout): Measure {
  const units = layout.units ?? 'ft';
  const per = units === 'm' ? layoutScale(layout) : layoutScale(layout) / FEET_PER_METER;
  const dp = units === 'm' ? 100 : 10;
  const show = (lu: number) => Math.round((lu / per) * dp) / dp;
  return { units, per, show, text: (lu) => `${show(lu)} ${units}` };
}

/**
 * A distance field in feet or meters, with − and + buttons (0.5 ft or 0.1 m; Shift-click: 10
 * times that). `value` and `onChange` use layout units.
 */
function DistanceField({ label, value, m, onChange, min = -100_000 }: { label: string; value: number | null; m: Measure; onChange: (layoutUnits: number) => void; min?: number }) {
  const step = m.units === 'm' ? 0.1 : 0.5;
  const btn = 'h-7 flex-1 rounded-md bg-stone-100 text-sm font-semibold text-stone-700 transition hover:bg-stone-200 active:scale-95 dark:bg-stone-800 dark:text-stone-200 dark:hover:bg-stone-700';
  const shown = value == null ? null : m.show(value);
  const bump = (d: number, big: boolean) => shown != null && onChange((Math.round((shown + d * step * (big ? 10 : 1)) * 100) / 100) * m.per);
  return (
    <Field label={`${label} (${m.units})`}>
      {(id) => (
        <div className="space-y-1">
          <NumberInput id={id} decimal value={shown} min={min} step={step} placeholder="varies" onCommit={(n) => onChange(n * m.per)} className="h-9 px-2 tabular-nums" />
          <div className="flex gap-1">
            <button
              type="button"
              className={btn}
              disabled={shown == null}
              onClick={(e) => bump(-1, e.shiftKey)}
              aria-label={`${label} minus ${step} ${m.units}`}
              title={`−${step} ${m.units} (Shift: −${step * 10})`}
            >
              −
            </button>
            <button
              type="button"
              className={btn}
              disabled={shown == null}
              onClick={(e) => bump(1, e.shiftKey)}
              aria-label={`${label} plus ${step} ${m.units}`}
              title={`+${step} ${m.units} (Shift: +${step * 10})`}
            >
              +
            </button>
          </div>
        </div>
      )}
    </Field>
  );
}

const uid = () => (crypto.randomUUID?.() ?? String(Math.random())).slice(0, 8);

export function LayoutPage() {
  const qc = useQueryClient();
  const { data: saved, isLoading } = useQuery({
    queryKey: LAYOUT_KEY,
    queryFn: api.layout
  });
  const { data: overview } = useOverview();
  const [layout, setLayout] = useState<Layout | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  /** Index of the selected point of the selected line (0 and the last point are its ends). */
  const [corner, setCorner] = useState<number | null>(null);
  /** Index of the selected segment (between point k and point k + 1) of the selected line. */
  const [segment, setSegment] = useState<number | null>(null);
  /** Set when a click selects an object and one of its segments at once. */
  const keepPart = useRef(false);
  const [tool, setTool] = useState<Tool>('select');
  /** The line being drawn, in the view it is drawn in. */
  const [draft, setDraft] = useState<{ side: ViewSide; pts: UV[] }>({ side: 'front', pts: [] });
  const [cursor, setCursor] = useState<(UV & { side: ViewSide }) | null>(null);
  const [drag, setDrag] = useState<Drag | null>(null);
  /** Measure tool: two points in one view. */
  const [tape, setTape] = useState<{ side: ViewSide; a: UV; b?: UV } | null>(null);
  const [busy, setBusy] = useState(false);
  const [views, setViews] = useState<ViewName[]>(readViews);
  const svgs = useRef<Partial<Record<ViewSide, SVGSVGElement | null>>>({});
  const fileInput = useRef<HTMLInputElement>(null);
  const pane = useRef<HTMLDivElement>(null);
  const propsCard = useRef<HTMLDivElement>(null);

  const toggleView = (v: ViewName) =>
    setViews((cur) => {
      const next = cur.includes(v) ? cur.filter((x) => x !== v) : (['front', 'top', '3d'] as ViewName[]).filter((x) => x === v || cur.includes(x));
      if (!next.length) return cur;
      try {
        localStorage.setItem(VIEWS_KEY, JSON.stringify(next));
      } catch {}
      return next;
    });

  // A new selection scrolls only the side panel (never the page) to show the object's panel.
  useEffect(() => {
    const p = pane.current;
    const c = propsCard.current;
    if (!p || !c || p.scrollHeight <= p.clientHeight) return;
    const top = c.offsetTop - p.offsetTop;
    if (top < p.scrollTop || top > p.scrollTop + p.clientHeight - 120) p.scrollTo({ top, behavior: 'smooth' });
  }, [selected, segment, corner]);

  useEffect(() => {
    if (saved && !layout) setLayout(saved);
  }, [saved, layout]);

  const dirty = !!layout && !!saved && JSON.stringify(layout) !== JSON.stringify(saved);
  const stage = useMemo(() => (layout ? buildStage(layout) : null), [layout]);
  const sel = layout?.fixtures.find((f) => f.id === selected) ?? null;
  const runs = useMemo(() => (layout ? deviceRuns(layout) : new Map()), [layout]);
  const overlapCount = [...runs.values()].reduce((n, r) => n + r.overlaps.length, 0);

  // The depths the top view shows: at least 4 m behind and 5 m in front of the house front, and
  // 1.5 m more than the objects. It stays the same while you drag, so the view does not jump.
  const zRangeRef = useRef<[number, number]>([-480, 480]);
  const dragging = drag != null;
  const zRange = useMemo((): [number, number] => {
    if (!layout || !stage || dragging) return zRangeRef.current;
    const s = layoutScale(layout);
    let lo = -4 * s;
    let hi = 5 * s;
    for (let i = 0; i < stage.pixelCount; i++) {
      const z = stage.positions3[i * 3 + 2];
      lo = Math.min(lo, z - 1.5 * s);
      hi = Math.max(hi, z + 1.5 * s);
    }
    for (const f of layout.fixtures)
      for (const p of f.points) {
        const r = isLine(f) ? 0 : (f.radius ?? 60);
        lo = Math.min(lo, (p.z ?? 0) - r - 1.5 * s);
        hi = Math.max(hi, (p.z ?? 0) + r + 1.5 * s);
      }
    zRangeRef.current = [Math.floor(lo / s) * s, Math.ceil(hi / s) * s];
    return zRangeRef.current;
  }, [layout, stage, dragging]);
  const zMin = zRange[0];

  useEffect(() => {
    if (keepPart.current) {
      keepPart.current = false;
      return;
    }
    setCorner(null);
    setSegment(null);
  }, [selected]);

  /** Selects one segment of a line (and the line itself). */
  const selectSegment = (id: string, k: number | null) => {
    if (id !== selected) keepPart.current = true;
    setSelected(id);
    setSegment(k);
    setCorner(null);
  };

  // Warn before leaving with unsaved changes.
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  const update = (id: string, patch: Partial<Fixture>) =>
    setLayout((l) =>
      l
        ? {
            ...l,
            fixtures: l.fixtures.map((f) => (f.id === id ? { ...f, ...patch } : f))
          }
        : l
    );
  const updateLayout = (patch: Partial<Layout>) => setLayout((l) => (l ? { ...l, ...patch } : l));

  /** Sets the device LED numbers at the first and the last point. */
  const setRange = (f: Fixture, first: number, last: number) => {
    // One end changed on a line: move only that end; the corners keep their LED numbers.
    const cur = ledRange(f);
    if (isLine(f) && f.points.length > 2 && (first === cur.first) !== (last === cur.last)) {
      const lastPoint = f.points.length - 1;
      update(f.id, first !== cur.first ? setPointLed(f, 0, clampPointLed(f, 0, first), allPoints(f)) : setPointLed(f, lastPoint, clampPointLed(f, lastPoint, last), allPoints(f)));
      return;
    }
    const next = fromLedRange(first, last);
    update(f.id, {
      ...next,
      pixels: Math.min(MAX_FIXTURE_PIXELS, next.pixels)
    });
  };

  /** Pins the corner to a device LED number, or clears the pin with null. */
  const pinCorner = (f: Fixture, index: number, led: number | null) => {
    if (led != null) {
      // Only this corner moves: every other corner keeps its LED number.
      update(f.id, setPointLed(f, index, clampPointLed(f, index, led), allPoints(f)));
      return;
    }
    const pins = f.points.map((_, i) => f.pointLeds?.[i] ?? null);
    pins[index] = null;
    update(f.id, { pointLeds: tidyPins(pins) });
  };

  /** Cuts a line in two at a corner. The second part starts at the next LED; raise its first LED to leave a gap. */
  const splitAt = (f: Fixture, k: number) => {
    const off = pointOffsets(f)[k];
    if (off < 1 || off >= f.pixels - 1) {
      toast.error('Each part needs at least one LED. Move the corner or add LEDs first.');
      return;
    }
    const pins = f.points.map((_, i) => f.pointLeds?.[i] ?? null);
    const a: Fixture = {
      ...f,
      points: f.points.slice(0, k + 1),
      ...fromLedRange(deviceLed(f, 0), deviceLed(f, off)),
      pointLeds: tidyPins(pins.slice(0, k + 1)),
      skip: nonEmpty(f.skip?.filter((x) => x < k))
    };
    const b: Fixture = {
      ...f,
      id: uid(),
      name: `${f.name} (part 2)`,
      points: f.points.slice(k),
      ...fromLedRange(deviceLed(f, off + 1), deviceLed(f, f.pixels - 1)),
      pointLeds: tidyPins(pins.slice(k).map((p) => (p == null ? null : p - off - 1))),
      skip: nonEmpty(f.skip?.filter((x) => x >= k).map((x) => x - k))
    };
    setLayout((l) =>
      l
        ? {
            ...l,
            fixtures: l.fixtures.flatMap((x) => (x.id === f.id ? [a, b] : [x]))
          }
        : l
    );
    setSelected(b.id);
    toast.success(`Split into ${a.name} and ${b.name}. Set the first LED of ${b.name} to leave a gap.`);
  };

  const remove = (id: string) => {
    setLayout((l) => (l ? { ...l, fixtures: l.fixtures.filter((f) => f.id !== id) } : l));
    setSelected(null);
  };
  const addFixture = (f: Fixture) => {
    setLayout((l) => (l ? { ...l, fixtures: [...l.fixtures, f] } : l));
    setSelected(f.id);
    setTool('select');
  };

  /** The first LED after every object on the device. */
  const nextFree = (deviceId: string | null) => (deviceId ? Math.max(0, ...(layout?.fixtures ?? []).filter((f) => f.deviceId === deviceId).map((f) => f.startPixel + f.pixels)) : 0);

  /** A point from a position in one view. The coordinate that the view does not show comes from `base`. */
  const fromView = (side: ViewSide, p: UV, base: Point): Point => (side === 'front' ? { ...base, x: p.u, y: p.v } : { ...base, x: p.u, z: Math.round(p.v + zMin) });

  function finishLine(kind: 'roof' | 'line', d = draft) {
    // A double-click adds the same point twice; drop near-duplicates.
    const uv = d.pts.filter((p, i) => i === 0 || Math.hypot(p.u - d.pts[i - 1].u, p.v - d.pts[i - 1].v) > 4);
    setDraft({ side: d.side, pts: [] });
    if (!layout || uv.length < 2) {
      setTool('select');
      return;
    }
    const lines = layout.fixtures.filter((f) => f.kind === kind);
    const roofs = layout.fixtures.filter((f) => f.kind === 'roof');
    // Drawn from above: a line lies on the ground; a roofline at the height of the other rooflines.
    const roofY = roofs.length ? roofs.flatMap((f) => f.points).reduce((a, p) => a + p.y, 0) / roofs.flatMap((f) => f.points).length : layout.height * 0.45;
    const base: Point = d.side === 'front' ? { x: 0, y: 0, z: 0 } : { x: 0, y: Math.round(kind === 'roof' ? roofY : layoutGround(layout)), z: 0 };
    // A new line continues after the last line on the same device.
    const prev = layout.fixtures.filter(isLine).at(-1);
    const deviceId = prev?.deviceId ?? null;
    addFixture({
      id: uid(),
      name: lines.length ? `${KIND_LABELS[kind]} ${lines.length + 1}` : KIND_LABELS[kind],
      kind,
      points: uv.map((p) => fromView(d.side, p, base)),
      pixels: kind === 'roof' && !roofs.length ? 450 : 100,
      deviceId,
      startPixel: nextFree(deviceId),
      reversed: false
    });
  }

  // Keyboard: Enter finishes a line, Escape cancels, Delete removes the selected object.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.closest('input, select, textarea');
      if (typing) return;
      if (e.key === 'Escape') {
        if (segment != null || corner != null) {
          setSegment(null);
          setCorner(null);
          return;
        }
        setDraft((d) => ({ ...d, pts: [] }));
        setTape(null);
        setTool('select');
        setDrag(null);
      } else if (e.key === 'Enter' && (tool === 'roof' || tool === 'line')) finishLine(tool);
      else if ((e.key === 'Delete' || e.key === 'Backspace') && selected) remove(selected);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  // Show the layout being edited on the real lights: the selected object lights up, with its
  // first LED blinking green and its last LED blinking red. The devices go back to normal by
  // themselves about 2 seconds after the editor stops asking.
  const [showOnLights, setShowOnLights] = useState(readShowOnLights);
  // The object's settings fold away, so the segment editor and the drawing fit on screen together.
  const [settingsOpen, setSettingsOpen] = useState(() => {
    try {
      return localStorage.getItem('layout.settingsOpen') !== 'closed';
    } catch {
      return true;
    }
  });
  const toggleSettings = () =>
    setSettingsOpen((v) => {
      try {
        localStorage.setItem('layout.settingsOpen', v ? 'closed' : 'open');
      } catch {}
      return !v;
    });
  const [previewDevices, setPreviewDevices] = useState<string[]>([]);
  const mapped = !!layout?.fixtures.some((f) => f.deviceId);
  // Only while this window has focus: a layout editor left open behind other windows or in a
  // background tab must not take the real lights from a game or from the public page's colors.
  // (A window behind others can still count as "visible", and its timers still run now and then.)
  const [inFront, setInFront] = useState(() => document.visibilityState === 'visible' && document.hasFocus());
  useEffect(() => {
    const on = () => setInFront(document.visibilityState === 'visible' && document.hasFocus());
    document.addEventListener('visibilitychange', on);
    window.addEventListener('focus', on);
    window.addEventListener('blur', on);
    return () => {
      document.removeEventListener('visibilitychange', on);
      window.removeEventListener('focus', on);
      window.removeEventListener('blur', on);
    };
  }, []);
  const previewing = showOnLights && mapped && inFront;
  const previewBody = previewing && layout ? JSON.stringify({ active: true, layout, selected, corner, segment }) : null;
  useEffect(() => {
    if (!previewBody) return;
    let alive = true;
    const send = () =>
      api
        .previewLayout(previewBody)
        .then((r) => alive && setPreviewDevices(r.devices))
        .catch(() => alive && setPreviewDevices([]));
    const t = setTimeout(send, 40);
    const keep = setInterval(send, 5000);
    return () => {
      alive = false;
      clearTimeout(t);
      clearInterval(keep);
    };
  }, [previewBody]);
  useEffect(() => {
    if (!previewing) return;
    const stop = () => void api.stopLayoutPreview().catch(() => {});
    window.addEventListener('pagehide', stop);
    return () => {
      window.removeEventListener('pagehide', stop);
      stop();
    };
  }, [previewing]);
  const toggleShow = () => {
    setShowOnLights((v) => {
      try {
        localStorage.setItem(SHOW_KEY, v ? 'off' : 'on');
      } catch {}
      return !v;
    });
  };

  // Simulator: the same view as the real lights get (see paintEditor).
  const getFrame = () => {
    if (!stage || !layout) return null;
    const out = new Uint8Array(stage.pixelCount * 3);
    // Same clock as the server, so the drawing pulses together with the real lights.
    const pulse = editorPulse(Date.now());
    paintEditor(layout, selected, corner, segment, pulse, (fi, i, rgb) => {
      const sf = stage.fixtures[fi];
      if (i >= 0 && i < sf.count) out.set(rgb, (sf.offset + i) * 3);
    });
    return out;
  };

  /** The pointer position in one view, in layout units. */
  function viewPoint(e: { clientX: number; clientY: number }, side: ViewSide): UV {
    const ctm = svgs.current[side]?.getScreenCTM();
    if (!ctm) return { u: 0, v: 0 };
    const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
    return { u: Math.round(p.x), v: Math.round(p.y) };
  }

  function onPointerDown(e: RPointerEvent<SVGSVGElement>, side: ViewSide) {
    const p = viewPoint(e, side);
    if (tool === 'roof' || tool === 'line') {
      // A line is drawn in one view; a click in the other view starts again there.
      setDraft((d) => ({ side, pts: d.side === side ? [...d.pts, p] : [p] }));
      return;
    }
    if (tool === 'bush' || tool === 'tree') {
      svgs.current[side]?.setPointerCapture(e.pointerId);
      setDrag(tool === 'bush' ? { kind: 'newBush', side, center: p, radius: 0 } : { kind: 'newTree', side, base: p, size: 0 });
      return;
    }
    if (tool === 'measure') {
      setTape((t) => (!t || t.b || t.side !== side ? { side, a: p } : { ...t, b: p }));
      return;
    }
    // Select tool: a press on empty space clears the selection.
    if (e.target === e.currentTarget) setSelected(null);
  }

  function startDrag(e: RPointerEvent, d: Drag, id: string | null, side: ViewSide) {
    if (tool !== 'select') return;
    e.stopPropagation();
    if (id) setSelected(id);
    svgs.current[side]?.setPointerCapture(e.pointerId);
    setDrag(d);
  }

  function onPointerMove(e: RPointerEvent<SVGSVGElement>, side: ViewSide) {
    const p = viewPoint(e, side);
    setCursor({ ...p, side });
    if (!drag || !layout) return;
    const f = 'id' in drag ? layout.fixtures.find((x) => x.id === drag.id) : undefined;
    if (drag.kind === 'vertex' && f) {
      update(drag.id, { points: f.points.map((q, i) => (i === drag.index ? fromView(side, p, q) : q)) });
    } else if (drag.kind === 'move') {
      const du = p.u - drag.from.u;
      const dv = p.v - drag.from.v;
      update(drag.id, {
        points: drag.original.map((q) => (side === 'front' ? { ...q, x: q.x + du, y: q.y + dv } : { ...q, x: q.x + du, z: (q.z ?? 0) + dv }))
      });
    } else if (drag.kind === 'radius' && f) {
      update(drag.id, { radius: Math.max(15, Math.round(Math.abs(p.u - f.points[0].x))) });
    } else if (drag.kind === 'treeHeight' && f) {
      update(drag.id, { height: Math.max(20, Math.round(f.points[0].y - p.v)) });
    } else if (drag.kind === 'ground') {
      updateLayout({ groundY: Math.max(0, Math.min(layout.height, p.v)) });
    } else if (drag.kind === 'newBush') {
      setDrag({ ...drag, radius: Math.round(Math.hypot(p.u - drag.center.u, (p.v - drag.center.v) / (side === 'front' ? 0.72 : 1))) });
    } else if (drag.kind === 'newTree') {
      setDrag({ ...drag, size: Math.round(side === 'front' ? Math.max(0, drag.base.v - p.v) : Math.hypot(p.u - drag.base.u, p.v - drag.base.v)) });
    }
  }

  function onPointerUp() {
    if (layout && (drag?.kind === 'newBush' || drag?.kind === 'newTree')) {
      const s = layoutScale(layout);
      const ground = layoutGround(layout);
      const count = layout.fixtures.filter((f) => f.kind === (drag.kind === 'newBush' ? 'bush' : 'tree')).length;
      if (drag.kind === 'newBush') {
        const r = Math.max(30, drag.radius || 70);
        const c = drag.center;
        // From the front: the bush touches the front wall. From above: it sits on the ground.
        const center: Point = drag.side === 'front' ? { x: c.u, y: c.v, z: r } : { x: c.u, y: Math.round(ground - r * 0.72), z: Math.round(c.v + zMin) };
        addFixture({ id: uid(), name: `Bush ${count + 1}`, kind: 'bush', points: [center], radius: r, pattern: 'fill', pixels: 60, deviceId: null, startPixel: 0, reversed: false });
      } else {
        const b = drag.base;
        // From the front you drag the height; from above, the radius of the base.
        const height = drag.side === 'front' ? Math.max(40, drag.size || 2.5 * s) : Math.max(40, (drag.size || 0.6 * s) * 3);
        const r = Math.round(drag.side === 'front' ? height * 0.33 : Math.max(15, drag.size || 0.6 * s));
        const base: Point = drag.side === 'front' ? { x: b.u, y: b.v, z: Math.round(r + 0.5 * s) } : { x: b.u, y: Math.round(ground), z: Math.round(b.v + zMin) };
        addFixture({
          id: uid(),
          name: `Tree ${count + 1}`,
          kind: 'tree',
          points: [base],
          radius: r,
          height: Math.round(height),
          pattern: 'spiral',
          turns: 8,
          pixels: 200,
          deviceId: null,
          startPixel: 0,
          reversed: false
        });
      }
    }
    setDrag(null);
  }

  function insertVertex(f: Fixture, e: RMouseEvent, side: ViewSide) {
    // Double-click on a line adds a corner on the nearest segment. The coordinate that this
    // view does not show is taken from the line, between the two points.
    const p = viewPoint(e, side);
    const V = (q: Point) => toView(q, side, zMin);
    let best = 0;
    let bestT = 0;
    let bestD = Infinity;
    for (let i = 0; i < f.points.length - 1; i++) {
      const a = V(f.points[i]);
      const b = V(f.points[i + 1]);
      const l2 = (b.u - a.u) ** 2 + (b.v - a.v) ** 2 || 1;
      const t = Math.max(0, Math.min(1, ((p.u - a.u) * (b.u - a.u) + (p.v - a.v) * (b.v - a.v)) / l2));
      const d = Math.hypot(p.u - (a.u + t * (b.u - a.u)), p.v - (a.v + t * (b.v - a.v)));
      if (d < bestD) {
        bestD = d;
        best = i;
        bestT = t;
      }
    }
    const a = f.points[best];
    const b = f.points[best + 1];
    const mid: Point = { x: a.x + (b.x - a.x) * bestT, y: Math.round(a.y + (b.y - a.y) * bestT), z: Math.round((a.z ?? 0) + ((b.z ?? 0) - (a.z ?? 0)) * bestT) };
    const pts = [...f.points];
    pts.splice(best + 1, 0, fromView(side, p, mid));
    const pins = f.pointLeds ? [...f.pointLeds] : undefined;
    pins?.splice(best + 1, 0, null);
    update(f.id, {
      points: pts,
      pointLeds: pins,
      skip: skipAfterInsert(f.skip, best)
    });
  }

  async function save() {
    if (!layout) return;
    setBusy(true);
    try {
      const out = await api.saveLayout(layout);
      qc.setQueryData(LAYOUT_KEY, out);
      setLayout(out);
      toast.success('Layout saved. Games use it now.');
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function upload(file: File | undefined) {
    if (!file || !layout) return;
    setBusy(true);
    try {
      const withBg = await api.uploadBackground(file);
      // Match the layout's height to the picture's shape, then keep the objects drawn so far.
      const img = new Image();
      img.src = withBg.background!;
      await img.decode();
      const height = Math.round((LAYOUT_WIDTH * img.naturalHeight) / img.naturalWidth);
      const next = {
        ...layout,
        background: withBg.background,
        height: Math.min(4000, Math.max(200, height))
      };
      const out = await api.saveLayout(next);
      qc.setQueryData(LAYOUT_KEY, out);
      setLayout(out);
      toast.success('Picture added. Trace the roofline and bushes over it.');
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeBg() {
    setBusy(true);
    try {
      const out = await api.removeBackground();
      qc.setQueryData(LAYOUT_KEY, out);
      setLayout((l) => (l ? { ...l, background: null } : out));
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (isLoading || !layout) {
    return (
      <div className="grid place-items-center py-24">
        <Spinner />
      </div>
    );
  }

  const devices = overview?.devices ?? [];
  const totals = layout.fixtures.reduce((n, f) => n + f.pixels, 0);
  const m = measureOf(layout);
  const ground = layoutGround(layout);
  const has2d = views.includes('front') || views.includes('top');

  const toolButton = (t: Tool, label: string, Icon: typeof House) => (
    <button
      type="button"
      onClick={() => {
        setTool(t);
        setDraft((d) => ({ ...d, pts: [] }));
        setTape(null);
      }}
      aria-pressed={tool === t}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition',
        tool === t ? 'bg-stone-900 text-white dark:bg-white dark:text-stone-900' : 'text-stone-600 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800'
      )}
    >
      <Icon className="size-4" /> {label}
    </button>
  );

  const hint = !has2d
    ? 'Open the front or the top view to draw and move objects. In the 3D view, click an LED to select its object.'
    : tool === 'roof' || tool === 'line'
      ? draft.pts.length
        ? 'Click to add each corner. Double-click, or press Enter, on the last point to finish.'
        : `Click where the first LED of the ${tool === 'roof' ? 'roofline' : 'line'} is. In the front view the line starts on the front wall; in the top view it starts ${tool === 'roof' ? 'at roof height' : 'on the ground'}.`
      : tool === 'bush'
        ? 'Press on the middle of a bush and drag out to its edge.'
        : tool === 'tree'
          ? 'Front view: press at the base of the tree and drag up to its top. Top view: press at the middle and drag out to the edge of the base.'
          : tool === 'measure'
            ? 'Click two points in the front or the top view to measure the distance between them. Type the real distance to set the scale.'
            : 'Click a straight segment of a line to light up only that segment. Drag points to move them: the front view moves them across and up, the top view across and toward the street. Double-click a line to add a corner; double-click a corner to remove it. Drag the dashed ground line to the bottom of the front wall.';

  const tapeLength = tape?.b ? Math.hypot(tape.b.u - tape.a.u, tape.b.v - tape.a.v) : null;

  /** One editable view: the drawing (YardView) and the handles over it. */
  const renderView = (side: ViewSide) => {
    const V = (p: Point) => toView(p, side, zMin);
    const front = side === 'front';
    const size = { w: layout.width, h: front ? layout.height : zRange[1] - zRange[0] };
    const handle = (key: string | number, at: UV, className: string, onDown: (e: RPointerEvent<SVGCircleElement>) => void, onDouble?: (e: RMouseEvent) => void) => (
      <circle key={key} cx={at.u} cy={at.v} r={9} className={cn('stroke-stone-950', className)} strokeWidth={3} onPointerDown={onDown} onDoubleClick={onDouble} />
    );
    return (
      <div key={side} className="space-y-1">
        <p className="flex items-baseline justify-between gap-2 text-xs font-medium tracking-wide text-stone-500 uppercase dark:text-stone-400">
          <span>{front ? 'Front view: as seen from the street' : 'Top view: from above, the street at the bottom'}</span>
          {!front ? <span className="normal-case">Grid: {m.units === 'm' ? '1 m' : '5 ft'}</span> : null}
        </p>
        <YardView layout={layout} side={side} zRange={zRange} getFrame={getFrame} highlight={segment != null ? null : selected}>
          <svg
            ref={(el) => void (svgs.current[side] = el)}
            viewBox={`0 0 ${size.w} ${size.h}`}
            preserveAspectRatio="none"
            className={cn('absolute inset-0 h-full w-full touch-none select-none', tool !== 'select' ? 'cursor-crosshair' : '')}
            onPointerDown={(e) => onPointerDown(e, side)}
            onPointerMove={(e) => onPointerMove(e, side)}
            onPointerUp={onPointerUp}
            onPointerLeave={() => setCursor(null)}
            onDoubleClick={() => (tool === 'roof' || tool === 'line') && draft.side === side && finishLine(tool)}
          >
            {!front ? (
              <>
                <text x={12} y={-zMin - 10} fontSize={20} fill="rgba(251,191,36,0.7)" pointerEvents="none">
                  Front wall of the house
                </text>
                <text x={12} y={size.h - 12} fontSize={20} fill="rgba(255,255,255,0.4)" pointerEvents="none">
                  ↓ Street
                </text>
              </>
            ) : null}

            {/* The ground: drag it to the bottom of the front wall. Heights count from here. */}
            {front ? (
              <g>
                <line x1={0} x2={size.w} y1={ground} y2={ground} stroke="rgba(52,211,153,0.6)" strokeWidth={2} strokeDasharray="12 10" pointerEvents="none" />
                <g className={tool === 'select' ? 'cursor-ns-resize' : ''} onPointerDown={(e) => startDrag(e, { kind: 'ground' }, null, side)}>
                  <rect x={8} y={ground - 36} width={92} height={30} rx={8} fill="rgba(6,78,59,0.85)" stroke="rgba(52,211,153,0.8)" strokeWidth={2} />
                  <text x={54} y={ground - 14} textAnchor="middle" fontSize={18} fontWeight={600} fill="#a7f3d0" pointerEvents="none">
                    Ground
                  </text>
                </g>
              </g>
            ) : null}

            {layout.fixtures.map((f) => {
              const isSel = selected === f.id;
              if (isLine(f)) {
                const pts = f.points.map(V);
                return (
                  <g key={f.id}>
                    {/* The selected segment, drawn wide so it is easy to see. */}
                    {isSel && segment != null && pts[segment + 1] ? (
                      <line
                        x1={pts[segment].u}
                        y1={pts[segment].v}
                        x2={pts[segment + 1].u}
                        y2={pts[segment + 1].v}
                        stroke="rgb(40,170,255)"
                        strokeOpacity={0.45}
                        strokeWidth={14}
                        strokeLinecap="round"
                        pointerEvents="none"
                      />
                    ) : null}
                    {/* Skipped segments: a dashed line, so they show as "off". */}
                    {f.skip?.map((k) =>
                      pts[k + 1] ? (
                        <line
                          key={`skip${k}`}
                          x1={pts[k].u}
                          y1={pts[k].v}
                          x2={pts[k + 1].u}
                          y2={pts[k + 1].v}
                          stroke="rgba(255,255,255,0.45)"
                          strokeWidth={3}
                          strokeDasharray="6 9"
                          pointerEvents="none"
                        />
                      ) : null
                    )}
                    {/* One hit area per segment: a click selects that segment. */}
                    {pts.slice(1).map((b, k) => {
                      const a = pts[k];
                      return (
                        <line
                          key={k}
                          x1={a.u}
                          y1={a.v}
                          x2={b.u}
                          y2={b.v}
                          stroke="transparent"
                          strokeWidth={26}
                          strokeLinecap="round"
                          className={tool === 'select' ? 'cursor-pointer' : ''}
                          onPointerDown={(e) => {
                            if (tool !== 'select') return;
                            startDrag(e, { kind: 'move', side, id: f.id, from: viewPoint(e, side), original: f.points }, f.id, side);
                            selectSegment(f.id, k);
                          }}
                          onDoubleClick={(e) => {
                            e.stopPropagation();
                            if (tool === 'select') insertVertex(f, e, side);
                          }}
                        />
                      );
                    })}
                    {isSel
                      ? pts.map((p, i) =>
                          handle(
                            i,
                            p,
                            cn(
                              'cursor-grab',
                              i === (segment ?? 0) ? 'fill-green-500' : i === (segment != null ? segment + 1 : f.points.length - 1) ? 'fill-red-500' : 'fill-amber-400',
                              corner === i && 'stroke-white'
                            ),
                            (e) => {
                              startDrag(e, { kind: 'vertex', side, id: f.id, index: i }, f.id, side);
                              if (tool === 'select') {
                                setCorner(i);
                                setSegment(null);
                              }
                            },
                            (e) => {
                              e.stopPropagation();
                              if (f.points.length > 2) {
                                update(f.id, {
                                  points: f.points.filter((_, j) => j !== i),
                                  pointLeds: tidyPins(f.pointLeds?.filter((_, j) => j !== i)),
                                  skip: i > 0 && i < f.points.length - 1 ? skipAfterRemove(f.skip, i) : undefined
                                });
                                setSegment(null);
                                setCorner(null);
                              }
                            }
                          )
                        )
                      : null}
                    {isSel ? <LedLabels f={f} corner={corner} segment={segment} V={V} side={side} /> : null}
                    {isSel ? (
                      segment != null && f.points[segment + 1] ? (
                        <EndMarkers a={fixturePixels(f)[segmentLeds(f, segment).lo]} b={fixturePixels(f)[segmentLeds(f, segment).hi]} V={V} />
                      ) : (
                        <EndMarkers a={f.points[0]} b={f.points[f.points.length - 1]} V={V} />
                      )
                    ) : null}
                  </g>
                );
              }
              // Bush or tree.
              const c = V(f.points[0]);
              const r = f.radius ?? 60;
              const h = f.height ?? 240;
              const move = (e: RPointerEvent) => startDrag(e, { kind: 'move', side, id: f.id, from: viewPoint(e, side), original: f.points }, f.id, side);
              const hitClass = tool === 'select' ? 'cursor-move' : '';
              return (
                <g key={f.id}>
                  {f.kind === 'tree' && front ? (
                    <polygon points={`${c.u - r},${c.v} ${c.u},${c.v - h} ${c.u + r},${c.v}`} fill="transparent" className={hitClass} onPointerDown={move} />
                  ) : (
                    <ellipse cx={c.u} cy={c.v} rx={r} ry={front ? r * 0.72 : r} fill="transparent" className={hitClass} onPointerDown={move} />
                  )}
                  {isSel ? <LedLabels f={f} corner={null} segment={null} V={V} side={side} /> : null}
                  {isSel ? <EndMarkers a={fixturePixels(f)[0]} b={fixturePixels(f).at(-1)} V={V} /> : null}
                  {isSel ? handle('r', { u: c.u + r, v: c.v }, 'cursor-ew-resize fill-amber-400', (e) => startDrag(e, { kind: 'radius', side, id: f.id }, f.id, side)) : null}
                  {isSel && f.kind === 'tree' && front
                    ? handle('h', { u: c.u, v: c.v - h }, 'cursor-ns-resize fill-amber-400', (e) => startDrag(e, { kind: 'treeHeight', id: f.id }, f.id, side))
                    : null}
                </g>
              );
            })}

            {/* Line being drawn */}
            {(tool === 'roof' || tool === 'line') && draft.side === side && draft.pts.length ? (
              <>
                <polyline
                  points={[...draft.pts, ...(cursor?.side === side ? [cursor] : [])].map((p) => `${p.u},${p.v}`).join(' ')}
                  fill="none"
                  stroke="#fbbf24"
                  strokeWidth={3}
                  strokeDasharray="10 8"
                  pointerEvents="none"
                />
                {draft.pts.map((p, i) => (
                  <circle key={i} cx={p.u} cy={p.v} r={7} fill="#fbbf24" pointerEvents="none" />
                ))}
              </>
            ) : null}

            {/* Bush or tree being drawn */}
            {drag?.kind === 'newBush' && drag.side === side ? (
              <ellipse
                cx={drag.center.u}
                cy={drag.center.v}
                rx={drag.radius}
                ry={drag.radius * (front ? 0.72 : 1)}
                fill="rgba(52,211,153,0.15)"
                stroke="#34d399"
                strokeWidth={3}
                strokeDasharray="8 6"
                pointerEvents="none"
              />
            ) : null}
            {drag?.kind === 'newTree' && drag.side === side ? (
              front ? (
                <polygon
                  points={`${drag.base.u - drag.size * 0.33},${drag.base.v} ${drag.base.u},${drag.base.v - drag.size} ${drag.base.u + drag.size * 0.33},${drag.base.v}`}
                  fill="rgba(52,211,153,0.15)"
                  stroke="#34d399"
                  strokeWidth={3}
                  strokeDasharray="8 6"
                  pointerEvents="none"
                />
              ) : (
                <circle cx={drag.base.u} cy={drag.base.v} r={drag.size} fill="rgba(52,211,153,0.15)" stroke="#34d399" strokeWidth={3} strokeDasharray="8 6" pointerEvents="none" />
              )
            ) : null}

            {/* Measuring tape */}
            {tool === 'measure' && tape?.side === side ? (
              <g pointerEvents="none">
                {(() => {
                  const b = tape.b ?? (cursor?.side === side ? cursor : null);
                  return b ? (
                    <>
                      <line x1={tape.a.u} y1={tape.a.v} x2={b.u} y2={b.v} stroke="#f0abfc" strokeWidth={3} />
                      <text
                        x={(tape.a.u + b.u) / 2}
                        y={(tape.a.v + b.v) / 2 - 14}
                        textAnchor="middle"
                        fontSize={24}
                        fontWeight={700}
                        fill="#f5d0fe"
                        stroke="#0c0a09"
                        strokeWidth={5}
                        paintOrder="stroke"
                      >
                        {m.text(Math.hypot(b.u - tape.a.u, b.v - tape.a.v))}
                      </text>
                    </>
                  ) : null;
                })()}
                <circle cx={tape.a.u} cy={tape.a.v} r={7} fill="#f0abfc" />
                {tape.b ? <circle cx={tape.b.u} cy={tape.b.v} r={7} fill="#f0abfc" /> : null}
              </g>
            ) : null}
          </svg>
        </YardView>
      </div>
    );
  };

  return (
    <>
      <PageHeader
        title="Yard layout"
        description="Place every light object where it really is: the front view moves objects across and up, the top view across and toward the street, and the 3D view shows the whole yard. Give each object its first and last LED number on the device. Select an object to edit it: it glows blue here and on the real lights, with its first LED green, its last LED red and its corners amber."
        actions={
          <>
            {overlapCount ? <Badge tone="red">Objects share LEDs</Badge> : dirty ? <Badge tone="amber">Unsaved changes</Badge> : null}
            <Button onClick={() => (setLayout(saved!), setSelected(null))} disabled={!dirty || busy}>
              <RotateCcw /> Revert
            </Button>
            <Button variant="primary" onClick={save} disabled={!dirty || overlapCount > 0} loading={busy}>
              <Save /> Save layout
            </Button>
          </>
        }
      />

      {/* Two panes on wide screens: the drawing stays put, and the side panel scrolls on its own.
          The page height then stays the same when the side panel changes, so the page never jumps.
          overflow-anchor: none stops the browser from scrolling to keep its place. */}
      <div className="grid gap-6 [overflow-anchor:none] lg:grid-cols-[1fr_20rem]">
        <div className="space-y-3 lg:sticky lg:top-20 lg:self-start">
          <div className="flex flex-wrap items-center gap-2 rounded-xl bg-white p-1.5 ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
            {toolButton('select', 'Select', MousePointer2)}
            {toolButton('roof', 'Roofline', House)}
            {toolButton('line', 'Line', Spline)}
            {toolButton('bush', 'Bush', Circle)}
            {toolButton('tree', 'Tree', TreePine)}
            {toolButton('measure', 'Measure', Ruler)}
            {(tool === 'roof' || tool === 'line') && draft.pts.length >= 2 ? (
              <Button size="sm" variant="primary" onClick={() => finishLine(tool)}>
                Finish line
              </Button>
            ) : null}
            <span className="mx-1 hidden h-5 w-px bg-stone-200 sm:block dark:bg-stone-700" />
            <Button
              size="sm"
              variant="ghost"
              onClick={toggleShow}
              aria-pressed={showOnLights}
              title={mapped ? 'Light the objects on their WLED devices while you edit' : 'Choose a WLED device for an object first'}
              className={cn(previewing && previewDevices.length && 'text-emerald-700 dark:text-emerald-400')}
            >
              {showOnLights ? <Lightbulb /> : <LightbulbOff />}
              {!showOnLights
                ? 'Show on lights: off'
                : !mapped
                  ? 'Show on lights (no device chosen)'
                  : !inFront
                    ? 'Show on lights (paused: window not in front)'
                    : previewDevices.length
                      ? `On the lights: ${previewDevices.join(', ')}`
                      : 'Show on lights'}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => fileInput.current?.click()} disabled={busy}>
              <ImagePlus /> {layout.background ? 'Change picture' : 'Add house picture'}
            </Button>
            {layout.background ? (
              <Button size="sm" variant="ghost" onClick={removeBg} disabled={busy}>
                <X /> Remove picture
              </Button>
            ) : null}
            <input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => (upload(e.target.files?.[0]), (e.target.value = ''))} />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-stone-500">Views</span>
            <div className="inline-flex rounded-lg bg-white p-1 ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
              {(['front', 'top', '3d'] as ViewName[]).map((v) => (
                <button
                  key={v}
                  type="button"
                  aria-pressed={views.includes(v)}
                  onClick={() => toggleView(v)}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-sm font-medium transition',
                    views.includes(v) ? 'bg-stone-900 text-white dark:bg-white dark:text-stone-900' : 'text-stone-600 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800'
                  )}
                >
                  {v === '3d' ? <Box className="size-3.5" /> : null}
                  {VIEW_LABELS[v]}
                </button>
              ))}
            </div>
            {tool === 'measure' && tapeLength != null ? (
              <MeasureBar
                length={tapeLength}
                m={m}
                onScale={(meters) => {
                  updateLayout({ scale: Math.round((tapeLength / meters) * 1000) / 1000 });
                  setTape(null);
                  toast.success(`Scale set: ${m.text(tapeLength)} is now ${meters * (m.units === 'm' ? 1 : FEET_PER_METER)} ${m.units}.`);
                }}
              />
            ) : null}
          </div>

          {/* All views share one width, so x lines up between them, and together they fit on the screen. */}
          <div
            className="mx-auto space-y-3"
            style={{
              maxWidth: `max(32rem, calc((100dvh - ${16 + views.length * 1.5}rem) * ${
                layout.width / ((views.includes('front') ? layout.height : 0) + (views.includes('top') ? zRange[1] - zRange[0] : 0) + (views.includes('3d') ? (layout.width * 9) / 16 : 0))
              }))`
            }}
          >
            {views.includes('front') ? renderView('front') : null}
            {views.includes('top') ? renderView('top') : null}
            {views.includes('3d') ? (
              <Suspense
                fallback={
                  <div className="grid aspect-video place-items-center rounded-2xl bg-[#05070f]">
                    <Spinner />
                  </div>
                }
              >
                <Scene3D
                  layout={layout}
                  getFrame={getFrame}
                  selected={selected}
                  onSelect={(id) => {
                    setSelected(id);
                    setTool('select');
                  }}
                />
              </Suspense>
            ) : null}
          </div>
          <p className="text-sm text-stone-500 dark:text-stone-400">{hint}</p>
        </div>

        <div ref={pane} className="space-y-4 lg:sticky lg:top-20 lg:max-h-[calc(100dvh-6rem)] lg:self-start lg:overflow-y-auto lg:overscroll-contain lg:pr-1">
          {sel ? (
            <div ref={propsCard}>
              <Card>
                <CardHeader
                  title={KIND_LABELS[sel.kind]}
                  actions={
                    <Button size="sm" variant="ghost" onClick={() => remove(sel.id)} className="hover:text-red-600">
                      <Trash2 /> Delete
                    </Button>
                  }
                />
                <div className="space-y-4 p-5">
                  {isLine(sel) && segment != null && segment < sel.points.length - 1 ? (
                    <SegmentPanel
                      f={sel}
                      index={segment}
                      onPoint={(point, led) => update(sel.id, setPointLed(sel, point, led, allPoints(sel)))}
                      onGo={(k) => setSegment(k)}
                      onToggle={(on) =>
                        update(sel.id, {
                          skip: nonEmpty(on ? sel.skip?.filter((x) => x !== segment) : [...(sel.skip ?? []), segment].sort((a, b) => a - b))
                        })
                      }
                      onClose={() => setSegment(null)}
                    />
                  ) : isLine(sel) && corner != null && corner > 0 && corner < sel.points.length - 1 ? (
                    <CornerPanel f={sel} index={corner} onPin={(led) => pinCorner(sel, corner, led)} onSplit={() => splitAt(sel, corner)} />
                  ) : isLine(sel) && sel.points.length > 2 ? (
                    <p className="text-xs text-stone-500">
                      Click one straight segment of the line to light up only that segment and set its first and last LED. Click a corner to pin it, or to split the line there and leave a gap.
                    </p>
                  ) : null}

                  <PositionPanel f={sel} point={corner} m={m} ground={ground} onChange={(patch) => update(sel.id, patch)} />

                  <button
                    type="button"
                    onClick={toggleSettings}
                    aria-expanded={settingsOpen}
                    className="flex w-full items-center justify-between gap-2 rounded-lg py-1 text-left text-sm font-medium text-stone-700 hover:text-stone-950 dark:text-stone-300 dark:hover:text-white"
                  >
                    <span>
                      {isLine(sel) ? 'Line settings' : `${KIND_LABELS[sel.kind]} settings`}
                      {!settingsOpen ? (
                        <span className="ml-2 font-normal text-stone-500 tabular-nums">
                          {devices.find((d) => d.id === sel.deviceId)?.name ?? 'Simulation only'} · LEDs {ledRange(sel).first}–{ledRange(sel).last}
                        </span>
                      ) : null}
                    </span>
                    <ChevronDown className={cn('size-4 shrink-0 transition', settingsOpen && 'rotate-180')} />
                  </button>
                  {settingsOpen ? (
                    <>
                      <Field label="Name">{(id) => <Input id={id} value={sel.name} maxLength={60} onChange={(e) => update(sel.id, { name: e.target.value })} />}</Field>
                      {isLine(sel) ? (
                        <Field label="Kind" hint="Games run along the roofline. Other lines (windows, doors, a fence, a path) are for animations.">
                          {(id) => (
                            <Select id={id} value={sel.kind} onChange={(e) => update(sel.id, { kind: e.target.value as FixtureKind })}>
                              <option value="roof">Roofline</option>
                              <option value="line">Other line of lights</option>
                            </Select>
                          )}
                        </Field>
                      ) : null}
                      <Field label="WLED device" hint="The device that drives these LEDs. Games show on it in debug mode (Play → Debug).">
                        {(id) => (
                          <Select id={id} value={sel.deviceId ?? ''} onChange={(e) => update(sel.id, { deviceId: e.target.value || null })}>
                            <option value="">Simulation only</option>
                            {devices.map((d) => (
                              <option key={d.id} value={d.id}>
                                {d.name}
                                {d.info?.leds?.count ? ` (${d.info.leds.count} LEDs)` : ''}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Field>
                      <LedRangeFields f={sel} onRange={(a, b) => setRange(sel, a, b)} />
                      {sel.kind === 'bush' ? (
                        <Field label="How the LEDs sit">
                          {(id) => (
                            <Select id={id} value={sel.pattern ?? 'fill'} onChange={(e) => update(sel.id, { pattern: e.target.value as Fixture['pattern'] })}>
                              <option value="fill">Net over the whole bush</option>
                              <option value="ring">Ring around the edge</option>
                              <option value="spiral">Spiral from the middle</option>
                            </Select>
                          )}
                        </Field>
                      ) : null}
                      {sel.kind === 'tree' ? (
                        <>
                          <Field
                            label="How the LEDs sit"
                            hint={
                              sel.pattern === 'strands'
                                ? 'Strands run from the base to the top. They zigzag: LED 0 is at the base of the front strand, which goes up; the next strand comes down.'
                                : 'LED 0 is at the base, at the front; the spiral goes up to the top.'
                            }
                          >
                            {(id) => (
                              <Select id={id} value={sel.pattern === 'strands' ? 'strands' : 'spiral'} onChange={(e) => update(sel.id, { pattern: e.target.value as Fixture['pattern'] })}>
                                <option value="spiral">Spiral around the tree</option>
                                <option value="strands">Strands from base to top</option>
                              </Select>
                            )}
                          </Field>
                          {sel.pattern === 'strands' ? (
                            <Field label="Strands">{(id) => <NumberInput id={id} value={sel.strands ?? 12} min={1} max={64} onCommit={(n) => update(sel.id, { strands: n })} />}</Field>
                          ) : (
                            <Field label="Turns from base to top">
                              {(id) => <NumberInput id={id} decimal value={sel.turns ?? 8} min={0.5} max={100} step={0.5} onCommit={(n) => update(sel.id, { turns: n })} />}
                            </Field>
                          )}
                        </>
                      ) : null}
                    </>
                  ) : null}
                </div>
              </Card>
            </div>
          ) : null}

          <Card>
            <CardHeader title="Objects" description={`${layout.fixtures.length} object(s), ${totals} LED(s)`} />
            {layout.fixtures.length ? (
              <ul className="divide-y divide-stone-100 dark:divide-stone-800">
                {layout.fixtures.map((f, i) => (
                  <li key={f.id}>
                    <button
                      type="button"
                      onClick={() => {
                        setSelected(f.id);
                        setTool('select');
                      }}
                      className={cn(
                        'flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm hover:bg-stone-50 dark:hover:bg-stone-800/60',
                        selected === f.id && 'bg-amber-50 dark:bg-amber-400/10'
                      )}
                    >
                      <span
                        className="size-2.5 shrink-0 rounded-full"
                        style={{
                          background: `rgb(${hsvBytes(HUES[i % HUES.length], 1).join(',')})`
                        }}
                      />
                      <span className="min-w-0 flex-1 truncate font-medium">{f.name}</span>
                      <span className="text-xs text-stone-500 tabular-nums">
                        {ledRange(f).first}–{ledRange(f).last}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-5 py-6 text-sm text-stone-500">Nothing yet. Draw the roofline first.</p>
            )}
          </Card>

          <YardCard layout={layout} m={m} onChange={updateLayout} onMeasure={() => (setTool('measure'), setTape(null))} />

          {runs.size ? (
            <Card>
              <CardHeader title="LEDs per device" description="Which LEDs each object uses. Gaps are LEDs that stay off." />
              <div className="space-y-5 p-5">
                {[...runs.entries()].map(([deviceId, r]) => (
                  <StripMap
                    key={deviceId}
                    name={devices.find((d) => d.id === deviceId)?.name ?? 'Unknown device'}
                    count={devices.find((d) => d.id === deviceId)?.info?.leds?.count ?? null}
                    runs={r.runs}
                    overlaps={r.overlaps}
                    fixtures={layout.fixtures}
                    selected={selected}
                    onSelect={setSelected}
                  />
                ))}
              </div>
            </Card>
          ) : null}
        </div>
      </div>
    </>
  );
}

/** After two points are measured: type the real distance between them to set the scale. */
function MeasureBar({ length, m, onScale }: { length: number; m: Measure; onScale: (meters: number) => void }) {
  const [real, setReal] = useState('');
  const n = Number(real);
  const ok = real !== '' && Number.isFinite(n) && n > 0;
  return (
    <form
      className="flex flex-wrap items-center gap-2 rounded-lg bg-fuchsia-50 px-3 py-1.5 text-sm ring-1 ring-fuchsia-200 dark:bg-fuchsia-400/10 dark:ring-fuchsia-400/30"
      onSubmit={(e) => {
        e.preventDefault();
        if (ok) onScale(m.units === 'm' ? n : n / FEET_PER_METER);
      }}
    >
      <span>
        Measured: <span className="font-semibold tabular-nums">{m.text(length)}</span>. Real distance:
      </span>
      <Input inputMode="decimal" value={real} onChange={(e) => setReal(e.target.value.replace(/[^\d.]/g, ''))} className="h-8 w-20 px-2" aria-label={`Real distance in ${m.units}`} />
      <span>{m.units}</span>
      <Button size="sm" type="submit" variant="primary" disabled={!ok}>
        Set scale
      </Button>
    </form>
  );
}

/** Units, scale and ground for the whole yard. */
function YardCard({ layout, m, onChange, onMeasure }: { layout: Layout; m: Measure; onChange: (patch: Partial<Layout>) => void; onMeasure: () => void }) {
  return (
    <Card>
      <CardHeader title="Yard size" description="Real distances make the top and 3D views true to life, and let animations move at real speeds." />
      <div className="space-y-4 p-5">
        <Field label="Units">
          {(id) => (
            <Select id={id} value={m.units} onChange={(e) => onChange({ units: e.target.value as Units })}>
              <option value="ft">Feet</option>
              <option value="m">Meters</option>
            </Select>
          )}
        </Field>
        <DistanceField
          label="Width of the front view"
          value={layout.width}
          m={m}
          min={0.1}
          onChange={(lu) => onChange({ scale: Math.round(((layoutScale(layout) * layout.width) / lu) * 1000) / 1000 })}
        />
        <Button size="sm" onClick={onMeasure}>
          <Ruler /> Measure to set the scale
        </Button>
        <p className="text-xs text-stone-500">
          For the best scale, measure something you know in the front view, at the front wall: for example, a garage door. Then drag the dashed ground line in the front view to the bottom of the front
          wall: heights count from there.
        </p>
      </div>
    </Card>
  );
}

/**
 * Where the selected point or object is, in feet or meters. X counts from the left edge of
 * the front view, height from the ground line, depth from the front wall (toward the street).
 */
function PositionPanel({ f, point, m, ground, onChange }: { f: Fixture; point: number | null; m: Measure; ground: number; onChange: (patch: Partial<Fixture>) => void }) {
  const setPoint = (i: number, patch: Partial<Point>) => onChange({ points: f.points.map((p, j) => (j === i ? { ...p, ...patch } : p)) });
  const xyz = (i: number, labels: [string, string, string]) => {
    const p = f.points[i];
    return (
      <div className="grid grid-cols-3 items-end gap-2">
        <DistanceField label={labels[0]} value={p.x} m={m} onChange={(lu) => setPoint(i, { x: Math.round(lu) })} />
        <DistanceField label={labels[1]} value={ground - p.y} m={m} onChange={(lu) => setPoint(i, { y: Math.round(ground - lu) })} />
        <DistanceField label={labels[2]} value={p.z ?? 0} m={m} onChange={(lu) => setPoint(i, { z: Math.round(lu) })} />
      </div>
    );
  };
  const box = 'space-y-3 rounded-xl bg-stone-50 p-3 ring-1 ring-stone-200 dark:bg-stone-950 dark:ring-stone-800';
  if (isLine(f)) {
    if (point != null && f.points[point]) {
      const z = f.points[point].z ?? 0;
      return (
        <div className={box}>
          <p className="text-sm font-medium">Position of {point === 0 ? 'the first point' : point === f.points.length - 1 ? 'the last point' : `corner ${point}`}</p>
          {xyz(point, ['Across', 'Height', 'Depth'])}
          <Button size="sm" onClick={() => onChange({ points: f.points.map((p) => ({ ...p, z })) })} disabled={f.points.every((p) => (p.z ?? 0) === z)}>
            Use this depth for every point
          </Button>
        </div>
      );
    }
    const depths = f.points.map((p) => p.z ?? 0);
    const same = depths.every((d) => d === depths[0]);
    return (
      <div className={box}>
        <p className="text-sm font-medium">Position</p>
        <div className="grid grid-cols-2 gap-2">
          <DistanceField label="Depth of every point" value={same ? depths[0] : null} m={m} onChange={(lu) => onChange({ points: f.points.map((p) => ({ ...p, z: Math.round(lu) })) })} />
        </div>
        <p className="text-xs text-stone-500">
          Depth 0 is the front wall; plus is toward the street. Click a point to place it exactly. A roofline along the side of the house runs back: give its far points a minus depth in the top view.
        </p>
      </div>
    );
  }
  const r = f.radius ?? 60;
  return (
    <div className={box}>
      <p className="text-sm font-medium">Position and size</p>
      {xyz(0, f.kind === 'tree' ? ['Across', 'Base height', 'Depth'] : ['Across', 'Height', 'Depth'])}
      <div className="grid grid-cols-3 items-end gap-2">
        <DistanceField label="Width" value={r * 2} m={m} min={0.1} onChange={(lu) => onChange({ radius: Math.max(5, Math.round(lu / 2)) })} />
        {f.kind === 'tree' ? <DistanceField label="Tree height" value={f.height ?? 240} m={m} min={0.1} onChange={(lu) => onChange({ height: Math.max(5, Math.round(lu)) })} /> : null}
      </div>
      <p className="text-xs text-stone-500">
        {f.kind === 'tree' ? 'The point is the middle of the base.' : 'The point is the middle of the bush, as seen from the front.'} Depth 0 is the front wall; plus is toward the street.
      </p>
    </div>
  );
}

/** Every point of a line, so an edit to one point leaves all the others where they are. */
const allPoints = (f: Fixture) => f.points.map((_, i) => i);

const nonEmpty = <T,>(a: T[] | undefined) => (a?.length ? a : undefined);

/** Drops a pin list that has no pins left. */
function tidyPins(pins: (number | null)[] | undefined) {
  // The ends are never pinned (their LEDs are the object's first and last); drop bad numbers too.
  const out = pins?.map((p, i) => (i === 0 || i === pins.length - 1 || p == null || p < 0 ? null : p));
  return out?.some((p) => p != null) ? out : undefined;
}

function LedRangeFields({ f, onRange }: { f: Fixture; onRange: (first: number, last: number) => void }) {
  const { first, last } = ledRange(f);
  const firstLabel = 'First LED';
  const lastLabel = 'Last LED';
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-3">
        <StepField label={firstLabel} tone="green" value={first} onChange={(n) => onRange(n, last)} />
        <StepField label={lastLabel} tone="red" value={last} onChange={(n) => onRange(first, n)} />
      </div>
      <div className="grid grid-cols-2 items-end gap-3">
        <Field label="Number of LEDs">
          {(id) => <NumberInput id={id} value={f.pixels} min={1} max={MAX_FIXTURE_PIXELS} onCommit={(n) => onRange(first, last >= first ? first + n - 1 : Math.max(0, first - n + 1))} />}
        </Field>
        <Button size="sm" onClick={() => onRange(last, first)} disabled={f.pixels < 2} className="mb-0.5">
          <ArrowLeftRight /> Flip direction
        </Button>
      </div>
      <p className="text-xs text-stone-500">
        {isLine(f) ? 'The first LED sits at the first point you drew. ' : ''}
        {f.pixels === 1 ? 'One LED. ' : last >= first ? 'The numbers count up along the line. ' : 'The numbers count down along the line. '}
        On the lights, the selected object glows blue, its first LED is green and its last LED is red. Each change shows at once. Use the LED numbers from the WLED app; LEDs that no object uses stay
        off.
      </p>
    </div>
  );
}

function CornerPanel({ f, index, onPin, onSplit }: { f: Fixture; index: number; onPin: (led: number | null) => void; onSplit: () => void }) {
  const led = deviceLed(f, pointOffsets(f)[index]);
  const pinned = isPinned(f, index);
  const ignored = f.pointLeds?.[index] != null && !pinned;
  return (
    <div className="space-y-3 rounded-xl bg-stone-50 p-3 ring-1 ring-stone-200 dark:bg-stone-950 dark:ring-stone-800">
      <p className="text-sm font-medium">Corner {index}</p>
      <Field label="First LED after this corner" hint={`The segment before it ends on the LED just before. ${pinned ? 'Pinned.' : 'Estimated from the line length; type the real number to pin it.'}`}>
        {(id) => <NumberInput id={id} value={led} onCommit={(n) => onPin(n)} />}
      </Field>
      {ignored ? <p className="text-xs text-red-600">The pinned number is not between the numbers of the points on each side, so it is not used.</p> : null}
      <div className="flex flex-wrap gap-2">
        {pinned || ignored ? (
          <Button size="sm" onClick={() => onPin(null)}>
            <PinOff /> Unpin
          </Button>
        ) : (
          <Button size="sm" onClick={() => onPin(led)}>
            <Pin /> Pin here
          </Button>
        )}
        <Button size="sm" onClick={onSplit}>
          <Scissors /> Split line here
        </Button>
      </div>
    </div>
  );
}

/** Device LED numbers at the points of the selected object, drawn on the map. */
function LedLabels({ f, corner, segment, V, side }: { f: Fixture; corner: number | null; segment: number | null; V: (p: Point) => { u: number; v: number }; side: ViewSide }) {
  const label = (x: number, y: number, text: string, strong: boolean, key: string | number) => (
    <text
      key={key}
      x={x}
      y={y - 18}
      textAnchor="middle"
      fontSize={22}
      fontWeight={strong ? 700 : 500}
      fill={strong ? '#fbbf24' : '#fff'}
      stroke="#0c0a09"
      strokeWidth={5}
      paintOrder="stroke"
      pointerEvents="none"
      className="tabular-nums"
    >
      {text}
    </text>
  );
  if (!isLine(f)) {
    const c = V(f.points[0]);
    const r = f.radius ?? 60;
    const { first, last } = ledRange(f);
    const above = side === 'top' ? r : f.kind === 'tree' ? (f.height ?? 240) : r * 0.72;
    return label(c.u, c.v - above, `LEDs ${first}–${last}`, true, 'b');
  }
  const offs = pointOffsets(f);
  return (
    <>
      {f.points.map((p, i) =>
        label(
          V(p).u,
          V(p).v,
          `${isPinned(f, i) ? '◆ ' : ''}${i > 0 && i < f.points.length - 1 ? `#${deviceLed(f, offs[i] - 1)} | ` : ''}#${deviceLed(f, offs[i])}`,
          segment != null ? i === segment || i === segment + 1 : i === corner || i === 0,
          i
        )
      )}
    </>
  );
}

function StripMap({
  name,
  count,
  runs,
  overlaps,
  fixtures,
  selected,
  onSelect
}: {
  name: string;
  count: number | null;
  runs: { fixtureId: string; lo: number; hi: number }[];
  overlaps: [{ fixtureId: string; lo: number; hi: number }, { fixtureId: string; lo: number; hi: number }][];
  fixtures: Fixture[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const used = Math.max(...runs.map((r) => r.hi + 1));
  const total = Math.max(used, count ?? 0);
  const fx = (id: string) => fixtures.find((f) => f.id === id);
  const hue = (id: string) => HUES[fixtures.findIndex((f) => f.id === id) % HUES.length];
  // Gaps: LEDs between runs (and before the first run) that no object uses.
  const gaps: { lo: number; hi: number }[] = [];
  let next = 0;
  for (const r of runs) {
    if (r.lo > next) gaps.push({ lo: next, hi: r.lo - 1 });
    next = Math.max(next, r.hi + 1);
  }
  if (count != null && count > next) gaps.push({ lo: next, hi: count - 1 });
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2 text-sm">
        <span className="truncate font-medium">{name}</span>
        {count != null && used > count ? (
          <Badge tone="red">
            needs {used} of {count}
          </Badge>
        ) : (
          <span className="text-xs text-stone-500 tabular-nums">{count != null ? `${count} LEDs` : `uses up to ${used}`}</span>
        )}
      </div>
      <div className="relative h-5 overflow-hidden rounded-md bg-stone-100 ring-1 ring-stone-200 dark:bg-stone-800 dark:ring-stone-700">
        {runs.map((r) => (
          <button
            key={r.fixtureId}
            type="button"
            title={`${fx(r.fixtureId)?.name}: LEDs ${r.lo}–${r.hi}`}
            onClick={() => onSelect(r.fixtureId)}
            className={cn('absolute inset-y-0 opacity-80 hover:opacity-100', selected === r.fixtureId && 'opacity-100 ring-2 ring-stone-900 ring-inset dark:ring-white')}
            style={{
              left: `${(r.lo / total) * 100}%`,
              width: `max(3px, ${((r.hi - r.lo + 1) / total) * 100}%)`,
              background: `rgb(${hsvBytes(hue(r.fixtureId), 1).join(',')})`
            }}
          />
        ))}
        {overlaps.map(([a, b], i) => (
          <span
            key={i}
            className="absolute inset-y-0 bg-red-600"
            style={{
              left: `${(b.lo / total) * 100}%`,
              width: `max(3px, ${((Math.min(a.hi, b.hi) - b.lo + 1) / total) * 100}%)`
            }}
          />
        ))}
      </div>
      <ul className="mt-2 space-y-0.5 text-xs text-stone-500 tabular-nums">
        {[...runs.map((r) => ({ ...r, kind: 'run' as const })), ...gaps.map((g) => ({ ...g, kind: 'gap' as const, fixtureId: '' }))]
          .sort((a, b) => a.lo - b.lo)
          .map((r) =>
            r.kind === 'run' ? (
              <li key={`r${r.fixtureId}`} className="flex justify-between gap-2">
                <span className="truncate text-stone-700 dark:text-stone-300">{fx(r.fixtureId)?.name}</span>
                <span>
                  {r.lo}–{r.hi}
                </span>
              </li>
            ) : (
              <li key={`g${r.lo}`} className="flex justify-between gap-2 italic">
                <span>Off (gap)</span>
                <span>
                  {r.lo}–{r.hi} ({r.hi - r.lo + 1})
                </span>
              </li>
            )
          )}
        {overlaps.map(([a, b], i) => (
          <li key={`o${i}`} className="text-red-600">
            {fx(a.fixtureId)?.name} and {fx(b.fixtureId)?.name} share LEDs {b.lo}–{Math.min(a.hi, b.hi)}.
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Edits one straight segment of a roof line: only it glows on the lights, with green and red ends. */
function SegmentPanel({
  f,
  index,
  onPoint,
  onGo,
  onToggle,
  onClose
}: {
  f: Fixture;
  index: number;
  onPoint: (point: number, led: number) => void;
  onGo: (k: number) => void;
  onToggle: (on: boolean) => void;
  onClose: () => void;
}) {
  const on = !f.skip?.includes(index);
  const count = f.points.length - 1;
  // Segments do not share LEDs: this one ends on the LED just before the next one starts.
  const leds = segmentLeds(f, index);
  const start = deviceLed(f, leds.lo);
  const end = deviceLed(f, leds.hi);
  const isLast = index === count - 1;
  const dir = f.reversed ? -1 : 1;
  // Inner points cannot pass their neighbours; the line's own ends can move freely.
  const limit = (point: number, led: number) => clampPointLed(f, point, led);

  return (
    <div className="space-y-3 rounded-xl bg-sky-50 p-3 ring-1 ring-sky-200 dark:bg-sky-400/10 dark:ring-sky-400/30">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium">
          Segment {index + 1} of {count}
        </p>
        <div className="flex gap-1">
          <Button size="sm" variant="ghost" onClick={() => onGo(index - 1)} disabled={index === 0} aria-label="Previous segment">
            <ChevronLeft />
          </Button>
          <Button size="sm" variant="ghost" onClick={() => onGo(index + 1)} disabled={index >= count - 1} aria-label="Next segment">
            <ChevronRight />
          </Button>
        </div>
      </div>
      <label className="flex items-center justify-between gap-3 rounded-lg bg-white/70 px-3 py-2 dark:bg-stone-900/60">
        <span>
          <span className="block text-sm font-medium">{on ? 'Segment on' : 'Segment off (skipped)'}</span>
          <span className="block text-xs text-stone-500">Turn off a stretch that only links two lit segments. Its LEDs stay dark, and games skip it.</span>
        </span>
        <Switch label="Segment on" checked={on} onChange={onToggle} />
      </label>
      <div className="grid grid-cols-2 gap-3">
        <StepField label="Segment start" tone="green" value={start} onChange={(n) => onPoint(index, limit(index, n))} />
        <StepField label="Segment end" tone="red" value={end} onChange={(n) => (isLast ? onPoint(index + 1, limit(index + 1, n)) : onPoint(index + 1, limit(index + 1, n + dir)))} />
      </div>
      <p className="text-xs text-stone-500">
        {Math.abs(end - start) + 1} LEDs{on ? '' : ', off'}.{!isLast ? ` The next segment starts at LED ${end + dir}.` : ''} Only this segment glows on the lights
        {on ? '' : ' (dimmer, because it is off)'}. Move its ends until the green and red LEDs sit at the real corners; the numbers you set here stay fixed when you edit other segments.
      </p>
      <Button size="sm" variant="ghost" onClick={onClose}>
        Show the whole line
      </Button>
    </div>
  );
}

/**
 * Green and red rings on the first and last LED of the selection. They pulse on the same clock
 * as the real lights (see editorPulse), so the drawing and the house blink together.
 */
function EndMarkers({ a, b, V }: { a?: Point; b?: Point; V: (p: Point) => { u: number; v: number } }) {
  const delay = { animationDelay: `-${Date.now() % 1000}ms` };
  const ring = (p: Point | undefined, color: string, key: string) =>
    p ? <circle key={key} cx={V(p).u} cy={V(p).v} r={20} fill="none" stroke={color} strokeWidth={8} className="led-pulse" style={delay} pointerEvents="none" /> : null;
  return (
    <>
      {ring(a, '#22c55e', 'a')}
      {ring(b, '#ef4444', 'b')}
    </>
  );
}
