import { useEffect, useMemo, useRef, useState, type MouseEvent as RMouseEvent, type PointerEvent as RPointerEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeftRight,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Circle,
  ImagePlus,
  Lightbulb,
  LightbulbOff,
  MousePointer2,
  Pencil,
  Pin,
  PinOff,
  RotateCcw,
  Save,
  Scissors,
  Trash2,
  X
} from 'lucide-react';
import { toast } from 'sonner';
import {
  buildStage,
  deviceLed,
  FIXTURE_HUES,
  hsvBytes,
  editorPulse,
  fixturePixels,
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
  type Layout,
  type Point
} from '../../../../shared/layout.ts';
import { Badge, Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Switch } from '../../components/ui.tsx';
import { YardView } from '../../yard/YardView.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { useOverview } from './AdminLayout.tsx';

type Tool = 'select' | 'roof' | 'bush';
type Drag =
  { kind: 'vertex'; id: string; index: number } | { kind: 'move'; id: string; from: Point; original: Point[] } | { kind: 'radius'; id: string } | { kind: 'newBush'; center: Point; radius: number };

const LAYOUT_KEY = ['layout'];
const HUES = FIXTURE_HUES;
const SHOW_KEY = 'layout.showOnLights';

function readShowOnLights() {
  try {
    return localStorage.getItem(SHOW_KEY) !== 'off';
  } catch {
    return true;
  }
}

/**
 * A number field for LED numbers. A typed number applies 0.7 s after the last key, or at once
 * with Enter or when the field loses focus; Escape puts the old number back. The arrow keys
 * step the number by 1 (Shift: 10) and apply at once.
 */
function NumberInput({
  id,
  value,
  min = 0,
  max = 100_000,
  onCommit,
  placeholder
}: {
  id?: string;
  value: number | null;
  min?: number;
  max?: number;
  onCommit: (n: number) => void;
  placeholder?: string;
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
  const commit = (t = text) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    typing.current = false;
    if (t !== '' && clamp(Number(t)) !== value) onCommit(clamp(Number(t)));
    else setText(value == null ? '' : String(value));
  };
  return (
    <Input
      id={id}
      inputMode="numeric"
      value={text}
      placeholder={placeholder}
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
          const base = text === '' ? (value ?? 0) : Number(text);
          commit(String(clamp(base + (e.key === 'ArrowUp' ? 1 : -1) * (e.shiftKey ? 10 : 1))));
        }
      }}
      onChange={(e) => {
        // A typed number applies when you stop typing for a moment, or press Enter. Half-typed
        // numbers (and an empty field) are never applied, so they cannot upset other segments.
        const t = e.target.value.replace(/\D/g, '');
        setText(t);
        typing.current = true;
        if (timer.current) clearTimeout(timer.current);
        if (t !== '') timer.current = setTimeout(() => commit(t), 700);
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
  /** Index of the selected corner of the selected roof line. */
  const [corner, setCorner] = useState<number | null>(null);
  /** Index of the selected segment (between point k and point k + 1) of the selected roof line. */
  const [segment, setSegment] = useState<number | null>(null);
  /** Set when a click selects an object and one of its segments at once. */
  const keepPart = useRef(false);
  const [tool, setTool] = useState<Tool>('select');
  const [draft, setDraft] = useState<Point[]>([]);
  const [cursor, setCursor] = useState<Point | null>(null);
  const [drag, setDrag] = useState<Drag | null>(null);
  const [busy, setBusy] = useState(false);
  const svg = useRef<SVGSVGElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const pane = useRef<HTMLDivElement>(null);
  const propsCard = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    if (keepPart.current) {
      keepPart.current = false;
      return;
    }
    setCorner(null);
    setSegment(null);
  }, [selected]);

  /** Selects one segment of a roof line (and the line itself). */
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
  /** Sets the device LED numbers at the first and the last point. */
  const setRange = (f: Fixture, first: number, last: number) => {
    // One end changed on a roof line: move only that end; the corners keep their LED numbers.
    const cur = ledRange(f);
    if (f.kind === 'roof' && f.points.length > 2 && (first === cur.first) !== (last === cur.last)) {
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

  /** Cuts a roof line in two at a corner. The second part starts at the next LED; raise its first LED to leave a gap. */
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

  function finishRoof(points = draft) {
    // A double-click adds the same point twice; drop near-duplicates.
    const pts = points.filter((p, i) => i === 0 || Math.hypot(p.x - points[i - 1].x, p.y - points[i - 1].y) > 4);
    setDraft([]);
    if (pts.length < 2) {
      setTool('select');
      return;
    }
    const roofs = layout?.fixtures.filter((f) => f.kind === 'roof') ?? [];
    // A new roof part continues after the last roof part, on the same device.
    const prev = roofs.at(-1);
    addFixture({
      id: uid(),
      name: roofs.length ? `Roofline ${roofs.length + 1}` : 'Roofline',
      kind: 'roof',
      points: pts,
      pixels: roofs.length ? 100 : 450,
      deviceId: prev?.deviceId ?? null,
      startPixel: prev ? prev.startPixel + prev.pixels : 0,
      reversed: false
    });
  }

  // Keyboard: Enter finishes a roofline, Escape cancels, Delete removes the selected object.
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
        setDraft([]);
        setTool('select');
        setDrag(null);
      } else if (e.key === 'Enter' && tool === 'roof') finishRoof();
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
  const getFrame = (t: number) => {
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

  function toPoint(e: { clientX: number; clientY: number }): Point {
    const el = svg.current!;
    const ctm = el.getScreenCTM();
    if (!ctm) return { x: 0, y: 0 };
    const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
    return { x: Math.round(p.x), y: Math.round(p.y) };
  }

  function onPointerDown(e: RPointerEvent<SVGSVGElement>) {
    const p = toPoint(e);
    if (tool === 'roof') {
      setDraft((d) => [...d, p]);
      return;
    }
    if (tool === 'bush') {
      svg.current?.setPointerCapture(e.pointerId);
      setDrag({ kind: 'newBush', center: p, radius: 0 });
      return;
    }
    // Select tool: a press on empty space clears the selection.
    if (e.target === svg.current) setSelected(null);
  }

  function startDrag(e: RPointerEvent, d: Drag, id: string) {
    if (tool !== 'select') return;
    e.stopPropagation();
    setSelected(id);
    svg.current?.setPointerCapture(e.pointerId);
    setDrag(d);
  }

  function onPointerMove(e: RPointerEvent<SVGSVGElement>) {
    const p = toPoint(e);
    setCursor(p);
    if (!drag || !layout) return;
    if (drag.kind === 'vertex') {
      const f = layout.fixtures.find((x) => x.id === drag.id);
      if (f)
        update(drag.id, {
          points: f.points.map((q, i) => (i === drag.index ? p : q))
        });
    } else if (drag.kind === 'move') {
      const dx = p.x - drag.from.x;
      const dy = p.y - drag.from.y;
      update(drag.id, {
        points: drag.original.map((q) => ({ x: q.x + dx, y: q.y + dy }))
      });
    } else if (drag.kind === 'radius') {
      const f = layout.fixtures.find((x) => x.id === drag.id);
      if (f)
        update(drag.id, {
          radius: Math.max(15, Math.round(Math.abs(p.x - f.points[0].x)))
        });
    } else if (drag.kind === 'newBush') {
      setDrag({
        ...drag,
        radius: Math.round(Math.hypot(p.x - drag.center.x, (p.y - drag.center.y) / 0.72))
      });
    }
  }

  function onPointerUp() {
    if (drag?.kind === 'newBush') {
      const bushes = layout?.fixtures.filter((f) => f.kind === 'bush').length ?? 0;
      addFixture({
        id: uid(),
        name: `Bush ${bushes + 1}`,
        kind: 'bush',
        points: [drag.center],
        radius: Math.max(30, drag.radius || 70),
        pattern: 'fill',
        pixels: 60,
        deviceId: null,
        startPixel: 0,
        reversed: false
      });
    }
    setDrag(null);
  }

  function insertVertex(f: Fixture, e: RMouseEvent) {
    // Double-click on a roof line adds a corner on the nearest segment.
    const p = toPoint(e);
    let best = 0;
    let bestD = Infinity;
    for (let i = 0; i < f.points.length - 1; i++) {
      const a = f.points[i];
      const b = f.points[i + 1];
      const l2 = (b.x - a.x) ** 2 + (b.y - a.y) ** 2 || 1;
      const t = Math.max(0, Math.min(1, ((p.x - a.x) * (b.x - a.x) + (p.y - a.y) * (b.y - a.y)) / l2));
      const d = Math.hypot(p.x - (a.x + t * (b.x - a.x)), p.y - (a.y + t * (b.y - a.y)));
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    }
    const pts = [...f.points];
    pts.splice(best + 1, 0, p);
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

  const toolButton = (t: Tool, label: string, Icon: typeof Pencil) => (
    <button
      type="button"
      onClick={() => {
        setTool(t);
        setDraft([]);
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

  const hint =
    tool === 'roof'
      ? draft.length
        ? 'Click to add each corner. Double-click, or press Enter, on the last point to finish.'
        : 'Click where the first LED of the roofline is.'
      : tool === 'bush'
        ? 'Press on the middle of a bush and drag out to its edge.'
        : 'Click a straight segment of a roof line to light up only that segment. Drag points to move them. Double-click a roof line to add a corner; double-click a corner to remove it. Click a corner to pin it or split the line there.';

  return (
    <>
      <PageHeader
        title="Yard layout"
        description="Draw where the lights are, and give each object its first and last LED number on the device. Games use this map. Select an object to edit it: it glows blue here and on the real lights, with its first LED green, its last LED red and its corners amber. Changes show on the lights as you make them."
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
            {toolButton('roof', 'Draw roofline', Pencil)}
            {toolButton('bush', 'Add bush', Circle)}
            {tool === 'roof' && draft.length >= 2 ? (
              <Button size="sm" variant="primary" onClick={() => finishRoof()}>
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

          <YardView layout={layout} getFrame={getFrame} highlight={segment != null ? null : selected}>
            <svg
              ref={svg}
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              preserveAspectRatio="none"
              className={cn('absolute inset-0 h-full w-full touch-none select-none', tool !== 'select' ? 'cursor-crosshair' : '')}
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerLeave={() => setCursor(null)}
              onDoubleClick={() => tool === 'roof' && finishRoof(draft)}
            >
              {layout.fixtures.map((f) =>
                f.kind === 'roof' ? (
                  <g key={f.id}>
                    {/* The selected segment, drawn wide so it is easy to see. */}
                    {selected === f.id && segment != null && f.points[segment + 1] ? (
                      <line
                        x1={f.points[segment].x}
                        y1={f.points[segment].y}
                        x2={f.points[segment + 1].x}
                        y2={f.points[segment + 1].y}
                        stroke="rgb(40,170,255)"
                        strokeOpacity={0.45}
                        strokeWidth={14}
                        strokeLinecap="round"
                        pointerEvents="none"
                      />
                    ) : null}
                    {/* Skipped segments: a dashed line, so they show as "off". */}
                    {f.skip?.map((k) =>
                      f.points[k + 1] ? (
                        <line
                          key={`skip${k}`}
                          x1={f.points[k].x}
                          y1={f.points[k].y}
                          x2={f.points[k + 1].x}
                          y2={f.points[k + 1].y}
                          stroke="rgba(255,255,255,0.45)"
                          strokeWidth={3}
                          strokeDasharray="6 9"
                          pointerEvents="none"
                        />
                      ) : null
                    )}
                    {/* One hit area per segment: a click selects that segment. */}
                    {f.points.slice(1).map((b, k) => {
                      const a = f.points[k];
                      return (
                        <line
                          key={k}
                          x1={a.x}
                          y1={a.y}
                          x2={b.x}
                          y2={b.y}
                          stroke="transparent"
                          strokeWidth={26}
                          strokeLinecap="round"
                          className={tool === 'select' ? 'cursor-pointer' : ''}
                          onPointerDown={(e) => {
                            if (tool !== 'select') return;
                            startDrag(
                              e,
                              {
                                kind: 'move',
                                id: f.id,
                                from: toPoint(e),
                                original: f.points
                              },
                              f.id
                            );
                            selectSegment(f.id, k);
                          }}
                          onDoubleClick={(e) => {
                            e.stopPropagation();
                            if (tool === 'select') insertVertex(f, e);
                          }}
                        />
                      );
                    })}
                    {selected === f.id
                      ? f.points.map((p, i) => (
                          <circle
                            key={i}
                            cx={p.x}
                            cy={p.y}
                            r={9}
                            className={cn(
                              'cursor-grab stroke-stone-950',
                              i === (segment ?? 0) ? 'fill-green-500' : i === (segment != null ? segment + 1 : f.points.length - 1) ? 'fill-red-500' : 'fill-amber-400'
                            )}
                            strokeWidth={3}
                            onPointerDown={(e) => {
                              startDrag(e, { kind: 'vertex', id: f.id, index: i }, f.id);
                              if (tool === 'select') {
                                setCorner(i);
                                setSegment(null);
                              }
                            }}
                            onDoubleClick={(e) => {
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
                            }}
                          />
                        ))
                      : null}
                    {selected === f.id ? <LedLabels f={f} corner={corner} segment={segment} /> : null}
                    {selected === f.id ? (
                      segment != null && f.points[segment + 1] ? (
                        <EndMarkers a={fixturePixels(f)[segmentLeds(f, segment).lo]} b={fixturePixels(f)[segmentLeds(f, segment).hi]} />
                      ) : (
                        <EndMarkers a={f.points[0]} b={f.points[f.points.length - 1]} />
                      )
                    ) : null}
                  </g>
                ) : (
                  <g key={f.id}>
                    <ellipse
                      cx={f.points[0].x}
                      cy={f.points[0].y}
                      rx={f.radius ?? 60}
                      ry={(f.radius ?? 60) * 0.72}
                      fill="transparent"
                      className={tool === 'select' ? 'cursor-move' : ''}
                      onPointerDown={(e) =>
                        startDrag(
                          e,
                          {
                            kind: 'move',
                            id: f.id,
                            from: toPoint(e),
                            original: f.points
                          },
                          f.id
                        )
                      }
                    />
                    {selected === f.id ? <LedLabels f={f} corner={null} segment={null} /> : null}
                    {selected === f.id ? <EndMarkers a={fixturePixels(f)[0]} b={fixturePixels(f).at(-1)} /> : null}
                    {selected === f.id ? (
                      <circle
                        cx={f.points[0].x + (f.radius ?? 60)}
                        cy={f.points[0].y}
                        r={9}
                        className="cursor-ew-resize fill-amber-400 stroke-stone-950"
                        strokeWidth={3}
                        onPointerDown={(e) => startDrag(e, { kind: 'radius', id: f.id }, f.id)}
                      />
                    ) : null}
                  </g>
                )
              )}

              {/* Roofline being drawn */}
              {tool === 'roof' && draft.length ? (
                <>
                  <polyline
                    points={[...draft, ...(cursor ? [cursor] : [])].map((p) => `${p.x},${p.y}`).join(' ')}
                    fill="none"
                    stroke="#fbbf24"
                    strokeWidth={3}
                    strokeDasharray="10 8"
                    pointerEvents="none"
                  />
                  {draft.map((p, i) => (
                    <circle key={i} cx={p.x} cy={p.y} r={7} fill="#fbbf24" pointerEvents="none" />
                  ))}
                </>
              ) : null}

              {/* Bush being drawn */}
              {drag?.kind === 'newBush' ? (
                <ellipse
                  cx={drag.center.x}
                  cy={drag.center.y}
                  rx={drag.radius}
                  ry={drag.radius * 0.72}
                  fill="rgba(52,211,153,0.15)"
                  stroke="#34d399"
                  strokeWidth={3}
                  strokeDasharray="8 6"
                  pointerEvents="none"
                />
              ) : null}
            </svg>
          </YardView>
          <p className="text-sm text-stone-500 dark:text-stone-400">{hint}</p>
        </div>

        <div ref={pane} className="space-y-4 lg:sticky lg:top-20 lg:max-h-[calc(100dvh-6rem)] lg:self-start lg:overflow-y-auto lg:overscroll-contain lg:pr-1">
          {sel ? (
            <div ref={propsCard}>
              <Card>
                <CardHeader
                  title={sel.kind === 'roof' ? 'Roofline' : 'Bush'}
                  actions={
                    <Button size="sm" variant="ghost" onClick={() => remove(sel.id)} className="hover:text-red-600">
                      <Trash2 /> Delete
                    </Button>
                  }
                />
                <div className="space-y-4 p-5">
                  {sel.kind === 'roof' && segment != null && segment < sel.points.length - 1 ? (
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
                  ) : sel.kind === 'roof' && corner != null && corner > 0 && corner < sel.points.length - 1 ? (
                    <CornerPanel f={sel} index={corner} onPin={(led) => pinCorner(sel, corner, led)} onSplit={() => splitAt(sel, corner)} />
                  ) : sel.kind === 'roof' && sel.points.length > 2 ? (
                    <p className="text-xs text-stone-500">
                      Click one straight segment of the line to light up only that segment and set its first and last LED. Click a corner to pin it, or to split the line there and leave a gap.
                    </p>
                  ) : null}
                  <button
                    type="button"
                    onClick={toggleSettings}
                    aria-expanded={settingsOpen}
                    className="flex w-full items-center justify-between gap-2 rounded-lg py-1 text-left text-sm font-medium text-stone-700 hover:text-stone-950 dark:text-stone-300 dark:hover:text-white"
                  >
                    <span>
                      {sel.kind === 'roof' ? 'Line settings' : 'Bush settings'}
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
                            <Select
                              id={id}
                              value={sel.pattern ?? 'fill'}
                              onChange={(e) =>
                                update(sel.id, {
                                  pattern: e.target.value as Fixture['pattern']
                                })
                              }
                            >
                              <option value="fill">Net over the whole bush</option>
                              <option value="ring">Ring around the edge</option>
                              <option value="spiral">Spiral from the middle</option>
                            </Select>
                          )}
                        </Field>
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
        {f.kind === 'roof' ? 'The first LED sits at the first point you drew. ' : ''}
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
function LedLabels({ f, corner, segment }: { f: Fixture; corner: number | null; segment: number | null }) {
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
  if (f.kind === 'bush') {
    const c = f.points[0];
    const { first, last } = ledRange(f);
    return label(c.x, c.y - (f.radius ?? 60) * 0.72, `LEDs ${first}–${last}`, true, 'b');
  }
  const offs = pointOffsets(f);
  return <>{f.points.map((p, i) => label(p.x, p.y, `${isPinned(f, i) ? '◆ ' : ''}${i > 0 && i < f.points.length - 1 ? `#${deviceLed(f, offs[i] - 1)} | ` : ''}#${deviceLed(f, offs[i])}`, segment != null ? i === segment || i === segment + 1 : i === corner || i === 0, i))}</>;
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
        {Math.abs(end - start) + 1} LEDs{on ? '' : ', off'}.{!isLast ? ` The next segment starts at LED ${end + dir}.` : ''} Only this segment glows on the lights{on ? '' : ' (dimmer, because it is off)'}. Move its ends until the green and red LEDs sit at the real
        corners; the numbers you set here stay fixed when you edit other segments.
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
function EndMarkers({ a, b }: { a?: Point; b?: Point }) {
  const delay = { animationDelay: `-${Date.now() % 1000}ms` };
  const ring = (p: Point | undefined, color: string, key: string) =>
    p ? <circle key={key} cx={p.x} cy={p.y} r={20} fill="none" stroke={color} strokeWidth={8} className="led-pulse" style={delay} pointerEvents="none" /> : null;
  return (
    <>
      {ring(a, '#22c55e', 'a')}
      {ring(b, '#ef4444', 'b')}
    </>
  );
}
