import { lazy, Suspense, useEffect, useMemo, useRef, useState, type ReactNode, type MouseEvent as RMouseEvent, type PointerEvent as RPointerEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router';
import {
  ArrowLeftRight,
  ChevronDown,
  Clapperboard,
  Pause,
  Play,
  ChevronLeft,
  ChevronRight,
  Circle,
  Columns2,
  Hand,
  House,
  ImagePlus,
  Images,
  Move,
  LayoutPanelLeft,
  Lightbulb,
  LightbulbOff,
  Maximize2,
  Minimize2,
  MousePointer2,
  PenTool,
  Redo2,
  Pin,
  PinOff,
  Plus,
  RotateCcw,
  Rows2,
  Ruler,
  Save,
  Scan,
  Scissors,
  Shapes,
  Spline,
  Square,
  Trash2,
  TreePine,
  Undo2,
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
  skipAfterRemove,
  mapSegmentEffects,
  segmentsAfterRemove,
  deviceRuns,
  extendLine,
  insertPoint,
  pointOnSegment,
  fromLedRange,
  isPinned,
  LAYOUT_WIDTH,
  ledRange,
  MAX_FIXTURE_PIXELS,
  pointOffsets,
  designPaths,
  designReach,
  lineLengths,
  resizeSegment,
  AERIAL_OPACITY,
  aerialCorners,
  alignAerial,
  placeAerial,
  scaleAerial,
  type AerialPicture,
  type Design,
  type Fixture,
  type FixtureKind,
  type Layout,
  type Point,
  type Units
} from '../../../../shared/layout.ts';
import { EFFECTS, EffectScene, effectKey, effectTarget, layoutEffects, toBytes, withEffects, YARD, type EffectId, type EffectSettings } from '../../../../shared/effects.ts';
import type { Stage } from '../../../../shared/layout.ts';
import type { Scene } from '../../../../shared/types.ts';
import { Badge, Button, Dialog, Field, Input, Spinner, Switch } from '../../components/ui.tsx';
import { EffectProps } from './effectProps.tsx';
import { DesignEditor } from './DesignEditor.tsx';
import { CustomProps, LibraryList, LightSelect, LightsProps, LightTypeDialog } from './lightsProps.tsx';
import { ledsForLength, lightsOf, spacingText, strandStarts, type LightType } from '../../../../shared/lights.ts';
import { toView, YardView, type ViewSide } from '../../yard/YardView.tsx';
import { fitCam, panBy, viewBoxOf, wheelFactor, zoomAt, type Box, type Cam, type PaneSize } from '../../yard/camera.ts';
import { NumberInput, PropButton, PropNote, PropNumber, PropRow, PropSection, PropSelect, PropSlider, PropText } from './props.tsx';
import { closestOnSegment, emptyTargets, snapPoint, type Snapped, type SnapTargets } from '../../yard/snap.ts';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';

// three.js is large: load the 3D view only when it is opened.
const Scene3D = lazy(() => import('../../yard/Scene3D.tsx').then((m) => ({ default: m.Scene3D })));

/** align: lines the picture from above up with the yard (no button: the Pictures menu starts it). */
type Tool = 'select' | 'edit' | 'split' | 'pan' | 'roof' | 'line' | 'bush' | 'tree' | 'measure' | 'align';
type LineTool = 'roof' | 'line';
const isLineTool = (t: Tool): t is LineTool => t === 'roof' || t === 'line';
/** One-key shortcuts, as in most drawing programs. */
const TOOL_KEYS: Record<string, Tool> = { v: 'select', a: 'edit', c: 'split', h: 'pan', r: 'roof', l: 'line', b: 'bush', t: 'tree', m: 'measure' };
/** A line being drawn. `cont`: it continues an existing line from one of its ends. */
type Draft = { side: ViewSide; pts: UV[]; cont?: { id: string; at: 'first' | 'last' } };
type MenuItem = { label: string; keys?: string; danger?: boolean; run: () => void };
/** How far back Undo goes. */
const UNDO_STEPS = 100;
/** Changes closer together than this are one step for Undo (for example, one drag). */
const UNDO_GROUP_MS = 600;
/** A position in one view, in layout units: u to the right, v down. */
type UV = { u: number; v: number };
type Drag =
  | { kind: 'vertex'; side: ViewSide; id: string; index: number }
  | { kind: 'move'; side: ViewSide; id: string; from: UV; original: Point[] }
  | { kind: 'radius'; side: ViewSide; id: string }
  | { kind: 'treeHeight'; id: string }
  | { kind: 'ground' }
  | { kind: 'newBush'; side: ViewSide; center: UV; radius: number }
  | { kind: 'newTree'; side: ViewSide; base: UV; size: number }
  | { kind: 'pan'; side: ViewSide; x: number; y: number; cam: Cam };
type ViewName = ViewSide | '3d';
/** How the viewports share the space, as in CAD programs. */
type VpMode = 'single' | 'columns' | 'rows' | 'three';
const VP_COUNT: Record<VpMode, number> = { single: 1, columns: 2, rows: 2, three: 3 };
const VP_MODES: { mode: VpMode; label: string; icon: typeof House }[] = [
  { mode: 'single', label: 'One view', icon: Square },
  { mode: 'columns', label: 'Two views, side by side', icon: Columns2 },
  { mode: 'rows', label: 'Two views, one above the other', icon: Rows2 },
  { mode: 'three', label: 'Three views', icon: LayoutPanelLeft }
];
/** Snapping, the 90° lock and the grid: switches in the status bar. */
type Drafting = { snap: boolean; ortho: boolean; grid: boolean };

const LAYOUT_KEY = ['layout'];
const HUES = FIXTURE_HUES;
const SHOW_KEY = 'layout.showOnLights';
const VIEWPORT_KEY = 'layout.viewport';
const DRAFTING_KEY = 'layout.drafting';
const VIEW_LABELS: Record<ViewName, string> = { front: 'Front', top: 'Top', '3d': '3D' };
const VIEW_NOTES: Record<ViewName, string> = { front: 'as seen from the street', top: 'from above, the street at the bottom', '3d': 'drag to turn, right-drag to pan' };
const TOOL_LABELS: Record<Tool, string> = { select: 'Select', edit: 'Edit points', split: 'Split', pan: 'Pan', roof: 'Roofline', line: 'Line', bush: 'Bush', tree: 'Tree', measure: 'Measure', align: 'Align picture' };
const KIND_ICONS: Record<FixtureKind, typeof House> = { roof: House, line: Spline, bush: Circle, tree: TreePine, custom: Shapes };
/** The size of handles and labels was set for about 1.6 layout units per pixel; this keeps them the same size on the screen at every zoom. */
const BASE_K = 1.6;
const KIND_LABELS: Record<FixtureKind, string> = { roof: 'Roofline', line: 'Line of lights', bush: 'Bush', tree: 'Tree', custom: 'Custom object' };

function readShowOnLights() {
  try {
    return localStorage.getItem(SHOW_KEY) !== 'off';
  } catch {
    return true;
  }
}

function readViewport(): { mode: VpMode; panes: ViewName[] } {
  try {
    const v = JSON.parse(localStorage.getItem(VIEWPORT_KEY) ?? '') as { mode: VpMode; panes: ViewName[] };
    const all: ViewName[] = ['front', 'top', '3d'];
    if (v.mode in VP_COUNT && v.panes.length === 3 && all.every((x) => v.panes.includes(x))) return v;
  } catch {}
  return { mode: 'three', panes: ['front', 'top', '3d'] };
}

function readDrafting(): Drafting {
  try {
    return { snap: true, ortho: false, grid: true, ...(JSON.parse(localStorage.getItem(DRAFTING_KEY) ?? '{}') as Partial<Drafting>) };
  } catch {
    return { snap: true, ortho: false, grid: true };
  }
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

/** A distance property in feet or meters. Arrow keys and dragging the label step 0.5 ft or 0.1 m. `value` and `onChange` use layout units. */
function PropDistance({ label, value, m, onChange, min = -100_000, hint }: { label: string; value: number | null; m: Measure; onChange: (layoutUnits: number) => void; min?: number; hint?: string }) {
  return (
    <PropNumber label={label} hint={hint} decimal value={value == null ? null : m.show(value)} min={min} step={m.units === 'm' ? 0.1 : 0.5} unit={m.units} onChange={(n) => onChange(n * m.per)} />
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
  const [draft, setDraft] = useState<Draft>({ side: 'front', pts: [] });
  /** What the pointer snaps to now, shown as a marker and guides. */
  const [snapHint, setSnapHint] = useState<(Snapped & { side: ViewSide; label?: string }) | null>(null);
  /** The right-click menu. */
  const [menu, setMenu] = useState<{ x: number; y: number; title: string; items: MenuItem[] } | null>(null);
  /** Set when Ctrl-click started a line, so the context menu that a Mac also opens is skipped. */
  const suppressMenu = useRef(false);
  // Undo and redo: whole layouts. Changes in quick succession (a drag) are one step.
  const layoutRef = useRef<Layout | null>(null);
  layoutRef.current = layout;
  const past = useRef<Layout[]>([]);
  const future = useRef<Layout[]>([]);
  const lastEdit = useRef(0);
  const [, setHistoryTick] = useState(0);
  const [cursor, setCursor] = useState<(UV & { side: ViewSide }) | null>(null);
  const [drag, setDrag] = useState<Drag | null>(null);
  /** Measure tool: two points in one view. */
  const [tape, setTape] = useState<{ side: ViewSide; a: UV; b?: UV } | null>(null);
  const [busy, setBusy] = useState(false);
  const svgs = useRef<Partial<Record<ViewSide, SVGSVGElement | null>>>({});
  const fileInput = useRef<HTMLInputElement>(null);
  const aerialInput = useRef<HTMLInputElement>(null);
  /** Align tool: a spot on the picture from above, where it goes, then a second spot and where it goes (top view). */
  const [alignPts, setAlignPts] = useState<UV[]>([]);

  // Viewports: how they share the space, which view each one shows, and one view made big.
  const [viewport, setViewportState] = useState(readViewport);
  const [maximized, setMaximized] = useState<ViewName | null>(null);
  const setViewport = (next: { mode: VpMode; panes: ViewName[] }) => {
    setViewportState(next);
    try {
      localStorage.setItem(VIEWPORT_KEY, JSON.stringify(next));
    } catch {}
  };
  /** Shows view `v` in viewport `i`. A view shows in one viewport only: the two viewports swap views. */
  const setPaneView = (i: number, v: ViewName) => {
    const panes = [...viewport.panes];
    const j = panes.indexOf(v);
    [panes[i], panes[j]] = [v, panes[i]];
    setViewport({ ...viewport, panes });
    if (maximized === panes[j]) setMaximized(null);
  };
  const visible = viewport.panes.slice(0, VP_COUNT[viewport.mode]);
  const shown = maximized && visible.includes(maximized) ? [maximized] : visible;

  // The camera of each 2D view. No camera: the view shows the whole yard (zoom to fit).
  const [cams, setCams] = useState<Partial<Record<ViewSide, Cam>>>({});
  const [paneSize, setPaneSize] = useState<Partial<Record<ViewSide, PaneSize>>>({});
  const [spaceDown, setSpaceDown] = useState(false);
  const panMode = tool === 'pan' || spaceDown;

  const [drafting, setDraftingState] = useState(readDrafting);
  const setDrafting = (patch: Partial<Drafting>) =>
    setDraftingState((d) => {
      const next = { ...d, ...patch };
      try {
        localStorage.setItem(DRAFTING_KEY, JSON.stringify(next));
      } catch {}
      return next;
    });
  /** The object being renamed in the object list. */
  const [renaming, setRenaming] = useState<string | null>(null);
  /** The design open in the object designer, and the library dialog. */
  const [designing, setDesigning] = useState<Design | null>(null);
  const [library, setLibrary] = useState(false);
  /** The light type being made or changed; `forObject`: give it to that object when saved. */
  const [lightEdit, setLightEdit] = useState<{ type: LightType | null; forObject?: string } | null>(null);

  useEffect(() => {
    if (saved && !layout) setLayout(saved);
  }, [saved, layout]);

  const dirty = !!layout && !!saved && JSON.stringify(layout) !== JSON.stringify(saved);
  const stage = useMemo(() => (layout ? buildStage(layout) : null), [layout]);
  const sel = layout?.fixtures.find((f) => f.id === selected) ?? null;
  const runs = useMemo(() => (layout ? deviceRuns(layout) : new Map()), [layout]);
  const overlapCount = [...runs.values()].reduce((n, r) => n + r.overlaps.length, 0);

  // Effects: each object's effect is part of the layout (the working copy); "Play" animates
  // them in the views (and on the real lights while Lights is on). A scene saved from here
  // keeps its own copy, and can be loaded back to change it.
  const effects = useMemo(() => (layout ? layoutEffects(layout) : {}), [layout]);
  const fxCount = Object.keys(effects).length;
  const [playing, setPlaying] = useState(false);
  /** The scene the effects were loaded from or last saved to. */
  const [sceneRef, setSceneRef] = useState<{ id: string; name: string } | null>(null);
  const [newScene, setNewScene] = useState<string | null>(null);
  const fxRef = useRef<{ scene: EffectScene; stage: Stage; data: Float32Array; bytes: Uint8Array; last: number } | null>(null);
  useEffect(() => {
    if (!playing || !stage || !layout) {
      fxRef.current = null;
      return;
    }
    const cur = fxRef.current;
    if (!cur) {
      fxRef.current = { scene: new EffectScene(stage, layout, effects), stage, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3), last: performance.now() };
      return;
    }
    // Objects whose effect and LED count stay the same keep running smoothly.
    cur.scene.setStage(stage, layout);
    cur.scene.setEffects(effects);
    if (cur.stage !== stage) fxRef.current = { ...cur, stage, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3) };
  }, [playing, stage, layout, effects]);
  // Nothing to play: stop.
  useEffect(() => {
    if (!fxCount) setPlaying(false);
  }, [fxCount]);

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
        const r = isLine(f) ? 0 : f.kind === 'custom' ? designReach(f, s) : (f.radius ?? 60);
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

  // Multi-selection, to give several objects and segments one effect: Ctrl/⌘-click adds or
  // removes (in the views, the object list and the 3D view), Shift-click in the list picks a
  // range, Esc clears. Items are effect keys: an object id, or "<id>#<segment>".
  const [multi, setMulti] = useState<string[]>([]);
  /** Where a Shift-click range in the object list starts. */
  const listAnchor = useRef<string | null>(null);
  /** Selects these items: one is a normal selection; two or more, a multi-selection. */
  const pickTargets = (keys: string[]) => {
    const list = [...new Set(keys)];
    if (list.length >= 2) {
      setMulti(list);
      setSelected(null);
      return;
    }
    setMulti([]);
    const t = list[0] ? effectTarget(list[0]) : null;
    if (!t) setSelected(null);
    else if (t.segment == null) setSelected(t.id);
    else selectSegment(t.id, t.segment);
  };
  const toggleTarget = (key: string) => {
    const base = multi.length ? multi : selected ? [effectKey(selected, segment)] : [];
    pickTargets(base.includes(key) ? base.filter((x) => x !== key) : [...base, key]);
  };
  // A normal selection ends the multi-selection.
  useEffect(() => {
    if (selected) setMulti([]);
  }, [selected]);
  /** On a Mac, Ctrl-click also opens the context menu; skip that one. */
  const skipMenu = (e: { ctrlKey: boolean }) => {
    suppressMenu.current = e.ctrlKey;
    setTimeout(() => (suppressMenu.current = false), 600);
  };

  // Warn before leaving with unsaved changes.
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  /** Changes the layout, and keeps the state before it for Undo. */
  const edit = (fn: (l: Layout) => Layout) => {
    const cur = layoutRef.current;
    if (!cur) return;
    const now = Date.now();
    if (now - lastEdit.current > UNDO_GROUP_MS) {
      past.current = [...past.current.slice(1 - UNDO_STEPS), cur];
      future.current = [];
      setHistoryTick((n) => n + 1);
    }
    lastEdit.current = now;
    setLayout((l) => (l ? fn(l) : l));
  };
  const undo = () => {
    const prev = past.current.pop();
    if (!prev || !layoutRef.current) return;
    future.current.push(layoutRef.current);
    lastEdit.current = 0;
    setLayout(prev);
    setHistoryTick((n) => n + 1);
  };
  const redo = () => {
    const next = future.current.pop();
    if (!next || !layoutRef.current) return;
    past.current.push(layoutRef.current);
    lastEdit.current = 0;
    setLayout(next);
    setHistoryTick((n) => n + 1);
  };
  const update = (id: string, patch: Partial<Fixture>) => edit((l) => ({ ...l, fixtures: l.fixtures.map((f) => (f.id === id ? { ...f, ...patch } : f)) }));
  const updateLayout = (patch: Partial<Layout>) => edit((l) => ({ ...l, ...patch }));

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
      skip: nonEmpty(f.skip?.filter((x) => x < k)),
      segmentEffects: mapSegmentEffects(f.segmentEffects, (x) => (x < k ? [x] : []))
    };
    const b: Fixture = {
      ...f,
      id: uid(),
      name: `${f.name} (part 2)`,
      points: f.points.slice(k),
      ...fromLedRange(deviceLed(f, off + 1), deviceLed(f, f.pixels - 1)),
      pointLeds: tidyPins(pins.slice(k).map((p) => (p == null ? null : p - off - 1))),
      skip: nonEmpty(f.skip?.filter((x) => x >= k).map((x) => x - k)),
      segmentEffects: mapSegmentEffects(f.segmentEffects, (x) => (x >= k ? [x - k] : []))
    };
    edit((l) => ({ ...l, fixtures: l.fixtures.flatMap((x) => (x.id === f.id ? [a, b] : [x])) }));
    setSelected(b.id);
    toast.success(`Split into ${a.name} and ${b.name}. Set the first LED of ${b.name} to leave a gap.`);
  };

  const remove = (id: string) => {
    edit((l) => ({ ...l, fixtures: l.fixtures.filter((f) => f.id !== id) }));
    setSelected(null);
  };
  /** Adds an object and selects it. Bushes and trees go back to the Select tool; line tools stay on, as in CAD programs. */
  const addFixture = (f: Fixture) => {
    edit((l) => ({ ...l, fixtures: [...l.fixtures, f] }));
    setSelected(f.id);
    if (!isLine(f)) setTool('select');
  };
  /** Removes one point of a line (a line keeps at least two). */
  const deletePoint = (f: Fixture, i: number) => {
    if (f.points.length <= 2) {
      toast.error('A line needs at least two points. Delete the whole line instead.');
      return;
    }
    const last = f.points.length - 1;
    const offs = pointOffsets(f);
    const pins = f.points.map((_, j) => f.pointLeds?.[j] ?? null);
    if (i === 0) {
      // The first segment goes, with its LEDs: the line now starts at the LED of point 1.
      const off = offs[1];
      update(f.id, {
        points: f.points.slice(1),
        ...fromLedRange(deviceLed(f, off), deviceLed(f, f.pixels - 1)),
        pointLeds: tidyPins(pins.slice(1).map((p) => (p == null ? null : p - off))),
        skip: nonEmpty(f.skip?.filter((k) => k > 0).map((k) => k - 1)),
        segmentEffects: mapSegmentEffects(f.segmentEffects, (k) => (k > 0 ? [k - 1] : []))
      });
    } else if (i === last) {
      // The last segment goes, with its LEDs: the line now ends at the LED of the point before.
      update(f.id, {
        points: f.points.slice(0, last),
        ...fromLedRange(deviceLed(f, 0), deviceLed(f, offs[last - 1])),
        pointLeds: tidyPins(pins.slice(0, last)),
        skip: nonEmpty(f.skip?.filter((k) => k < last - 1)),
        segmentEffects: mapSegmentEffects(f.segmentEffects, (k) => (k < last - 1 ? [k] : []))
      });
    } else {
      update(f.id, {
        points: f.points.filter((_, j) => j !== i),
        pointLeds: tidyPins(pins.filter((_, j) => j !== i)),
        skip: skipAfterRemove(f.skip, i),
        segmentEffects: mapSegmentEffects(f.segmentEffects, segmentsAfterRemove(i))
      });
    }
    setSegment(null);
    setCorner(null);
  };

  /** The first LED after every object on the device. */
  const nextFree = (deviceId: string | null) => (deviceId ? Math.max(0, ...(layout?.fixtures ?? []).filter((f) => f.deviceId === deviceId).map((f) => f.startPixel + f.pixels)) : 0);

  // ----- Custom objects and their library -----

  /** Opens the designer on a new, empty design. */
  const newDesign = () => setDesigning({ id: uid(), name: 'My object', strokes: [], pixels: 50, lights: layout?.lights });
  /** Saves a design to the library; every object placed from it changes with it. */
  const saveDesign = (d: Design) => {
    const isNew = !layout?.designs?.some((x) => x.id === d.id);
    edit((l) => ({
      ...l,
      designs: isNew ? [...(l.designs ?? []), d] : (l.designs ?? []).map((x) => (x.id === d.id ? d : x)),
      fixtures: l.fixtures.map((f) => (f.designId === d.id ? { ...f, design: d.strokes, pixels: d.pixels, lights: d.lights } : f))
    }));
    setDesigning(null);
    if (isNew) {
      placeDesign(d, true);
      toast.success(`${d.name} is in the library, and one is placed in the yard. Drag it into place.`);
    }
  };
  /** Places a copy of a design in the yard: in the middle, standing on the ground. */
  const placeDesign = (d: Design, withDesign = false) => {
    if (!layout) return;
    const s = layoutScale(layout);
    const low = Math.min(0, ...d.strokes.flatMap((st) => st.points.map((p) => p.y)));
    const count = layout.fixtures.filter((f) => f.designId === d.id).length;
    const prev = layout.fixtures.at(-1);
    const deviceId = prev?.deviceId ?? null;
    const f: Fixture = {
      id: uid(),
      name: count ? `${d.name} ${count + 1}` : d.name,
      kind: 'custom',
      points: [{ x: Math.round(layout.width / 2), y: Math.round(layoutGround(layout) + low * s), z: Math.round(0.3 * s) }],
      design: d.strokes,
      designId: d.id,
      pixels: d.pixels,
      ...(d.lights ? { lights: d.lights } : {}),
      deviceId,
      startPixel: nextFree(deviceId),
      reversed: false
    };
    // Saving a new design adds it to the library in the same step.
    edit((l) => ({ ...l, designs: withDesign && !l.designs?.some((x) => x.id === d.id) ? [...(l.designs ?? []), d] : l.designs, fixtures: [...l.fixtures, f] }));
    setSelected(f.id);
    setTool('select');
    setLibrary(false);
  };
  const duplicateDesign = (d: Design) => {
    const copy = { ...d, id: uid(), name: `${d.name} copy` };
    edit((l) => ({ ...l, designs: [...(l.designs ?? []), copy] }));
    setDesigning(copy);
  };
  const deleteDesign = (d: Design) => edit((l) => ({ ...l, designs: (l.designs ?? []).filter((x) => x.id !== d.id) }));

  // ----- What the lights are made of -----

  /** Gives an object a light type; the first one picked is also used for new objects. */
  const pickLights = (id: string, lights: string | undefined) =>
    edit((l) => ({ ...l, lights: l.lights ?? lights, fixtures: l.fixtures.map((f) => (f.id === id ? { ...f, lights } : f)) }));
  const saveLightType = (lt: LightType, forObject?: string) => {
    edit((l) => {
      const mine = l.lightTypes ?? [];
      const lightTypes = mine.some((x) => x.id === lt.id) ? mine.map((x) => (x.id === lt.id ? lt : x)) : [...mine, lt];
      return { ...l, lightTypes, lights: l.lights ?? (forObject ? lt.id : undefined), fixtures: forObject ? l.fixtures.map((f) => (f.id === forObject ? { ...f, lights: lt.id } : f)) : l.fixtures };
    });
    setLightEdit(null);
  };
  const deleteLightType = (id: string) => {
    edit((l) => ({
      ...l,
      lightTypes: (l.lightTypes ?? []).filter((x) => x.id !== id),
      lights: l.lights === id ? undefined : l.lights,
      designs: l.designs?.map((d) => (d.lights === id ? { ...d, lights: undefined } : d)),
      fixtures: l.fixtures.map((f) => (f.lights === id ? { ...f, lights: undefined } : f))
    }));
    setLightEdit(null);
  };

  /** A point from a position in one view. The coordinate that the view does not show comes from `base`. */
  const fromView = (side: ViewSide, p: UV, base: Point): Point => (side === 'front' ? { ...base, x: p.u, y: p.v } : { ...base, x: p.u, z: Math.round(p.v + zMin) });

  /** The 3D point of a line that sits at this spot in a view, if any. */
  const pointAtView = (side: ViewSide, at: UV, exclude?: { id: string; index: number }): Point | undefined => {
    for (const f of layout?.fixtures ?? []) {
      if (!isLine(f)) continue;
      for (let i = 0; i < f.points.length; i++) {
        if (exclude?.id === f.id && exclude.index === i) continue;
        const q = toView(f.points[i], side, zMin);
        if (Math.abs(q.u - at.u) < 1 && Math.abs(q.v - at.v) < 1) return f.points[i];
      }
    }
    return undefined;
  };

  function finishLine(kind: LineTool, d = draft) {
    // A double-click adds the same point twice; drop near-duplicates.
    const uv = d.pts.filter((p, i) => i === 0 || Math.hypot(p.u - d.pts[i - 1].u, p.v - d.pts[i - 1].v) > 4);
    setDraft({ side: d.side, pts: [] });
    setSnapHint(null);
    if (!layout || uv.length < 2) return;
    // Each point takes the coordinate that this view does not show from the point it snapped
    // onto; otherwise from the point before it. So a line drawn from the end of a side roofline
    // stays at that roofline's depth.
    const to3d = (start: Point) => {
      let prev = start;
      return uv.map((p) => {
        const hit = pointAtView(d.side, p);
        prev = hit ? { ...hit } : fromView(d.side, p, prev);
        return prev;
      });
    };
    const cont = d.cont && layout.fixtures.find((x) => x.id === d.cont!.id);
    if (d.cont && cont) {
      const join = d.cont.at === 'last' ? cont.points[cont.points.length - 1] : cont.points[0];
      const { patch, shifted } = extendLine(cont, d.cont.at, to3d(join).slice(1));
      update(cont.id, patch);
      setSelected(cont.id);
      toast.success(
        `${cont.name}: ${uv.length - 1} segment(s) and ${patch.pixels - cont.pixels} LEDs added, at the same spacing.${shifted ? ' The LED numbers now start at 0: check the first and last LED.' : ''}`
      );
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
      points: to3d(base),
      // With a light string set, as many LEDs as fit the line; else a guess to adjust.
      ...(() => {
        const lt = lightsOf(layout, layout.lights);
        const pts = to3d(base);
        const len = lineLengths({ points: pts }).reduce((a, b) => a + b, 0);
        return { pixels: lt ? Math.min(MAX_FIXTURE_PIXELS, ledsForLength(len / layoutScale(layout), lt.spacing)) : kind === 'roof' && !roofs.length ? 450 : 100, ...(lt ? { lights: lt.id } : {}) };
      })(),
      deviceId,
      startPixel: nextFree(deviceId),
      reversed: false
    });
  }

  const chooseTool = (t: Tool) => {
    setTool(t);
    setDraft((d) => ({ side: d.side, pts: [] }));
    setTape(null);
    setAlignPts([]);
    setSnapHint(null);
    setMenu(null);
  };

  /** Starts drawing from one end of a line: the new points are added to that line. */
  const startContinue = (f: Fixture, at: 'first' | 'last', side: ViewSide) => {
    const end = f.points[at === 'first' ? 0 : f.points.length - 1];
    setTool(f.kind === 'roof' ? 'roof' : 'line');
    setTape(null);
    setMenu(null);
    setSelected(f.id);
    setDraft({ side, pts: [toView(end, side, zMin)], cont: { id: f.id, at } });
  };

  // Keyboard, as in CAD and drawing programs. V A C R L B T M: tools. Enter, Esc or a
  // double-click: finish the line. Backspace while drawing: remove the last point. Delete: the
  // selected point, or else the selected object. Ctrl/⌘+Z: undo; Ctrl/⌘+Shift+Z or Ctrl+Y: redo.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.closest('input, select, textarea');
      // A dialog (the object designer) has its own keys.
      if (typing || document.querySelector('dialog[open]')) return;
      const mod = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (mod && key === 'z') {
        e.preventDefault();
        if (e.shiftKey) redo();
        else undo();
        return;
      }
      if (mod && key === 'y') {
        e.preventDefault();
        redo();
        return;
      }
      if (mod && key === 's') {
        e.preventDefault();
        if (dirty && !overlapCount && !busy) void save();
        return;
      }
      if (e.key === ' ') {
        // Hold Space and drag to pan, as in drawing programs.
        e.preventDefault();
        setSpaceDown(true);
        return;
      }
      if (mod || e.altKey) return;
      const drawing = isLineTool(tool) && draft.pts.length > 0;
      if (e.key === 'Escape') {
        if (menu) return setMenu(null);
        if (multi.length) return setMulti([]);
        if (drawing) {
          // As in CAD: Esc ends the line and keeps the segments drawn so far.
          if (isLineTool(tool)) finishLine(tool);
          return;
        }
        if (tape) return setTape(null);
        if (segment != null || corner != null) {
          setSegment(null);
          setCorner(null);
          return;
        }
        chooseTool('select');
        setDrag(null);
      } else if (e.key === 'Enter' && drawing && isLineTool(tool)) {
        finishLine(tool);
      } else if (e.key === 'Enter' && tool === 'align' && alignPts.length === 2) {
        finishAlign(alignPts);
      } else if (e.key === 'Backspace' && tool === 'align' && alignPts.length) {
        e.preventDefault();
        setAlignPts((a) => a.slice(0, -1));
      } else if (e.key === 'Backspace' && drawing) {
        e.preventDefault();
        setDraft((d) => ({ ...d, pts: d.pts.slice(0, -1) }));
      } else if (e.key === 'Delete' || e.key === 'Backspace') {
        if (multi.length) {
          // The whole objects in the selection go; segments stay (delete a segment's points instead).
          const ids = new Set(multi.filter((x) => effectTarget(x).segment == null));
          if (!ids.size) return void toast.error('Only segments are selected. To delete a segment, delete its points.');
          edit((l) => ({ ...l, fixtures: l.fixtures.filter((f) => !ids.has(f.id)) }));
          setMulti([]);
          toast.success(`${ids.size} object(s) deleted. Ctrl/⌘+Z brings them back.`);
        } else if (sel && isLine(sel) && corner != null && sel.points[corner]) deletePoint(sel, corner);
        else if (selected) remove(selected);
      } else if (e.key === 'F2' && selected) {
        e.preventDefault();
        setRenaming(selected);
      } else if (key === 'f' && !e.shiftKey) {
        frameSelection();
      } else if (key === 'p' && !e.shiftKey) {
        if (fxCount) setPlaying((v) => !v);
      } else if (e.key === 'Home') {
        setCams({});
      } else if (e.key === '+' || e.key === '=' || e.key === '-' || e.key === '_') {
        zoomViews(e.key === '+' || e.key === '=' ? 1.25 : 0.8);
      } else if (key === 'o' && !e.shiftKey) {
        setLibrary(true);
      } else if (!e.shiftKey && TOOL_KEYS[key]) {
        chooseTool(TOOL_KEYS[key]);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });
  useEffect(() => {
    const up = (e: KeyboardEvent) => e.key === ' ' && setSpaceDown(false);
    const off = () => setSpaceDown(false);
    window.addEventListener('keyup', up);
    window.addEventListener('blur', off);
    return () => {
      window.removeEventListener('keyup', up);
      window.removeEventListener('blur', off);
    };
  }, []);

  // The right-click menu closes on a click elsewhere, or when the page scrolls.
  useEffect(() => {
    if (!menu) return;
    const close = (e: Event) => {
      if (!(e.target as HTMLElement)?.closest?.('[data-layout-menu]')) setMenu(null);
    };
    window.addEventListener('pointerdown', close);
    window.addEventListener('scroll', close, true);
    window.addEventListener('blur', close);
    return () => {
      window.removeEventListener('pointerdown', close);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('blur', close);
    };
  }, [menu]);

  // Show the layout being edited on the real lights: the selected object lights up, with its
  // first LED blinking green and its last LED blinking red. The devices go back to normal by
  // themselves about 2 seconds after the editor stops asking.
  const [showOnLights, setShowOnLights] = useState(readShowOnLights);
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
  const previewBody = previewing && layout ? JSON.stringify({ active: true, layout, selected, corner, segment, play: playing && fxCount > 0 }) : null;
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
    const fx = fxRef.current;
    if (playing && fx && fx.stage === stage) {
      // Every view asks on each animation frame: draw once per frame.
      const now = performance.now();
      if (now - fx.last > 4) {
        fx.scene.update(Math.min(0.1, (now - fx.last) / 1000), fx.data);
        fx.last = now;
        toBytes(fx.data, fx.bytes);
      }
      return fx.bytes;
    }
    const out = new Uint8Array(stage.pixelCount * 3);
    // Same clock as the server, so the drawing pulses together with the real lights.
    const pulse = editorPulse(Date.now());
    paintEditor(layout, selected, corner, segment, pulse, (fi, i, rgb) => {
      const sf = stage.fixtures[fi];
      if (i >= 0 && i < sf.count) out.set(rgb, (sf.offset + i) * 3);
    });
    return out;
  };

  /** v minus the world coordinate in a view: the top view counts v from the back edge (zMin). */
  const offOf = (side: ViewSide) => (side === 'top' ? -zMin : 0);
  /** Everything a view shows when it is zoomed to fit, in view units. */
  const contentBox = (side: ViewSide): Box => {
    // The picture (or the depth range), and every object, as "zoom extents" does in CAD programs.
    let x0 = 0;
    let y0 = 0;
    let x1 = layout?.width ?? LAYOUT_WIDTH;
    let y1 = side === 'front' ? (layout?.height ?? 900) : zRange[1] - zRange[0];
    for (const f of layout?.fixtures ?? []) {
      const b = boxOf(f, side);
      x0 = Math.min(x0, b.x);
      y0 = Math.min(y0, b.y);
      x1 = Math.max(x1, b.x + b.w);
      y1 = Math.max(y1, b.y + b.h);
    }
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  };
  const sizeOf = (side: ViewSide): PaneSize => paneSize[side] ?? { w: 1000, h: 600 };
  function camFor(side: ViewSide): Cam {
    return cams[side] ?? fitCam(contentBox(side), sizeOf(side), offOf(side));
  }
  const viewBoxFor = (side: ViewSide) => viewBoxOf(camFor(side), sizeOf(side), offOf(side));

  /** The box around an object in a view, in view units. */
  const boxOf = (f: Fixture, side: ViewSide): Box => {
    const V = (p: Point) => toView(p, side, zMin);
    if (isLine(f) || f.kind === 'custom') {
      const pts = isLine(f) ? f.points : designPaths(f, layout ? layoutScale(layout) : undefined).flat();
      if (!pts.length) pts.push(f.points[0]);
      const us = pts.map((p) => V(p).u);
      const vs = pts.map((p) => V(p).v);
      return { x: Math.min(...us), y: Math.min(...vs), w: Math.max(...us) - Math.min(...us), h: Math.max(...vs) - Math.min(...vs) };
    }
    const c = V(f.points[0]);
    const r = f.radius ?? 60;
    if (side === 'top') return { x: c.u - r, y: c.v - r, w: 2 * r, h: 2 * r };
    const h = f.kind === 'tree' ? (f.height ?? 240) : r * 0.72;
    return { x: c.u - r, y: c.v - h, w: 2 * r, h: f.kind === 'tree' ? h : 2 * h };
  };
  /** F: zoom every 2D view to the selected object, or to the whole yard when nothing is selected. */
  function frameSelection(id = selected) {
    const f = layout?.fixtures.find((x) => x.id === id);
    if (!f || !layout) return setCams({});
    const pad = layoutScale(layout) * 0.75;
    const next: Partial<Record<ViewSide, Cam>> = {};
    for (const side of ['front', 'top'] as ViewSide[]) {
      const b = boxOf(f, side);
      next[side] = fitCam({ x: b.x - pad, y: b.y - pad, w: b.w + 2 * pad, h: b.h + 2 * pad }, sizeOf(side), offOf(side), 1);
    }
    setCams(next);
  }
  /** + and −: zoom the view under the pointer (or every 2D view) about its middle. */
  function zoomViews(factor: number) {
    const sides = cursor ? [cursor.side] : (['front', 'top'] as ViewSide[]);
    setCams((c) => {
      const next = { ...c };
      for (const side of sides) next[side] = zoomAt(c[side] ?? camFor(side), sizeOf(side), { x: sizeOf(side).w / 2, y: sizeOf(side).h / 2 }, factor);
      return next;
    });
  }
  /** The wheel zooms at the pointer (as in CAD programs); a pinch on a trackpad too. A sideways swipe pans. */
  function onWheel(side: ViewSide, e: WheelEvent, rect: DOMRect) {
    setCams((c) => {
      const cam = c[side] ?? camFor(side);
      if (!e.ctrlKey && Math.abs(e.deltaX) > Math.abs(e.deltaY)) return { ...c, [side]: panBy(cam, -e.deltaX, 0) };
      return { ...c, [side]: zoomAt(cam, sizeOf(side), { x: e.clientX - rect.left, y: e.clientY - rect.top }, wheelFactor(e)) };
    });
  }

  /** The pointer position in one view, in layout units. */
  function viewPoint(e: { clientX: number; clientY: number }, side: ViewSide): UV {
    const ctm = svgs.current[side]?.getScreenCTM();
    if (!ctm) return { u: 0, v: 0 };
    const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
    return { u: Math.round(p.x), v: Math.round(p.y) };
  }

  /** The snap distance: 10 screen pixels, in layout units. */
  const tolFor = (side: ViewSide) => {
    const ctm = svgs.current[side]?.getScreenCTM();
    return ctm?.a ? 10 / ctm.a : 10;
  };

  /** What can be snapped to in a view. `exclude`: a point being dragged, and its two segments. */
  const targetsFor = (side: ViewSide, exclude?: { id: string; index: number }, linesOnly = false): SnapTargets => {
    const t = emptyTargets();
    for (const f of layout?.fixtures ?? []) {
      const pts = f.points.map((p) => toView(p, side, zMin));
      if (!isLine(f)) {
        if (!linesOnly) t.centers.push(pts[0]);
        continue;
      }
      pts.forEach((p, i) => !(exclude?.id === f.id && exclude.index === i) && t.points.push(p));
      for (let k = 0; k < pts.length - 1; k++) if (!(exclude?.id === f.id && (exclude.index === k || exclude.index === k + 1))) t.segments.push([pts[k], pts[k + 1]]);
    }
    if (!linesOnly && draft.side === side) {
      t.points.push(...draft.pts);
      for (let k = 0; k < draft.pts.length - 1; k++) t.segments.push([draft.pts[k], draft.pts[k + 1]]);
    }
    return t;
  };

  /** The pointer position, snapped. Shift: 45° steps from `from`; Ortho: 90° steps. Alt turns snapping off (or on, when Snap is off). */
  const snapAt = (e: { clientX: number; clientY: number; shiftKey: boolean; altKey: boolean }, side: ViewSide, from?: UV | null, exclude?: { id: string; index: number }) =>
    snapPoint(viewPoint(e, side), targetsFor(side, exclude), tolFor(side), { from, angle: e.shiftKey ? 45 : drafting.ortho ? 90 : false, snap: drafting.snap !== e.altKey });

  /** The end of a line near this spot, for continuing that line. */
  const lineEndAt = (side: ViewSide, at: UV): { f: Fixture; at: 'first' | 'last' } | null => {
    let best: { f: Fixture; at: 'first' | 'last' } | null = null;
    let bestD = tolFor(side);
    for (const f of layout?.fixtures ?? []) {
      if (!isLine(f)) continue;
      for (const end of ['first', 'last'] as const) {
        const q = toView(f.points[end === 'first' ? 0 : f.points.length - 1], side, zMin);
        const d = Math.hypot(q.u - at.u, q.v - at.v);
        if (d <= bestD) {
          best = { f, at: end };
          bestD = d;
        }
      }
    }
    return best;
  };

  /** The 3D point on segment k of a line nearest to a spot in a view. */
  const pointOnLine = (f: Fixture, k: number, raw: UV, side: ViewSide): Point => {
    const V = (q: Point) => toView(q, side, zMin);
    const { at, t } = closestOnSegment(raw, V(f.points[k]), V(f.points[k + 1]));
    return fromView(side, { u: Math.round(at.u), v: Math.round(at.v) }, pointOnSegment(f, k, t));
  };

  /** Adds a point on segment k and selects it; with `drag`, the pointer then moves it. */
  const addPointOn = (f: Fixture, k: number, raw: UV, side: ViewSide, drag?: RPointerEvent) => {
    update(f.id, insertPoint(f, k, pointOnLine(f, k, raw, side)));
    if (f.id !== selected) keepPart.current = true;
    setSelected(f.id);
    setCorner(k + 1);
    setSegment(null);
    if (drag) {
      drag.stopPropagation();
      svgs.current[side]?.setPointerCapture(drag.pointerId);
      setDrag({ kind: 'vertex', side, id: f.id, index: k + 1 });
    }
  };

  /** Cuts a line in two at a spot on segment k. */
  const splitOn = (f: Fixture, k: number, raw: UV, side: ViewSide) => {
    const g = { ...f, ...insertPoint(f, k, pointOnLine(f, k, raw, side)) };
    splitAt(g, k + 1);
  };

  const openMenu = (e: RMouseEvent, title: string, items: MenuItem[]) => {
    e.preventDefault();
    e.stopPropagation();
    if (suppressMenu.current) {
      suppressMenu.current = false;
      return;
    }
    setDrag(null);
    setMenu({ x: e.clientX, y: e.clientY, title, items });
  };

  const pointMenu = (e: RMouseEvent, f: Fixture, i: number, side: ViewSide) => {
    const end = i === 0 ? 'first' : i === f.points.length - 1 ? 'last' : null;
    const name = end ? `${end === 'first' ? 'First' : 'Last'} point of ${f.name}` : `Corner ${i} of ${f.name}`;
    openMenu(e, name, [
      ...(end ? [{ label: 'Continue the line from here', keys: 'Ctrl-click', run: () => startContinue(f, end, side) }] : [{ label: 'Split the line here', keys: 'C', run: () => splitAt(f, i) }]),
      { label: 'Select this point', run: () => (f.id !== selected && (keepPart.current = true), setSelected(f.id), setCorner(i), setSegment(null)) },
      { label: 'Delete this point', keys: 'Delete', danger: true, run: () => deletePoint(f, i) }
    ]);
  };

  const objectMenu = (e: RMouseEvent, f: Fixture) =>
    openMenu(e, f.name, [
      { label: 'Select', run: () => setSelected(f.id) },
      { label: 'Zoom to this object', keys: 'F', run: () => (setSelected(f.id), frameSelection(f.id)) },
      { label: 'Rename', keys: 'F2', run: () => (setSelected(f.id), setRenaming(f.id)) },
      { label: `Delete ${f.name}`, keys: 'Delete', danger: true, run: () => remove(f.id) }
    ]);

  const segmentMenu = (e: RMouseEvent, f: Fixture, k: number, side: ViewSide) => {
    const raw = viewPoint(e, side);
    const off = f.skip?.includes(k);
    openMenu(e, `Segment ${k + 1} of ${f.name}`, [
      { label: 'Add a point here', keys: 'A, click', run: () => addPointOn(f, k, raw, side) },
      { label: 'Split the line here', keys: 'C, click', run: () => splitOn(f, k, raw, side) },
      { label: 'Edit this segment', run: () => selectSegment(f.id, k) },
      {
        label: off ? 'Turn this segment on' : 'Turn this segment off (skip)',
        run: () => update(f.id, { skip: nonEmpty(off ? f.skip?.filter((x) => x !== k) : [...(f.skip ?? []), k].sort((a, b) => a - b)) })
      },
      { label: `Delete ${f.name}`, danger: true, run: () => remove(f.id) }
    ]);
  };

  function onPointerDown(e: RPointerEvent<SVGSVGElement>, side: ViewSide) {
    // Pan: the middle button, Space-drag, or the Hand tool.
    if (e.button === 1 || (e.button === 0 && panMode)) {
      e.preventDefault();
      svgs.current[side]?.setPointerCapture(e.pointerId);
      setDrag({ kind: 'pan', side, x: e.clientX, y: e.clientY, cam: camFor(side) });
      return;
    }
    if (e.button !== 0) return;
    if (isLineTool(tool)) {
      const drawingHere = draft.side === side && draft.pts.length > 0;
      // The first click on the end of a line continues that line (Alt: start a new line there).
      if (!drawingHere && !e.altKey) {
        const end = lineEndAt(side, viewPoint(e, side));
        if (end) return startContinue(end.f, end.at, side);
      }
      // A line is drawn in one view; a click in the other view starts again there.
      const s = snapAt(e, side, drawingHere ? draft.pts[draft.pts.length - 1] : null);
      setDraft((d) => (d.side === side && d.pts.length ? { ...d, pts: [...d.pts, s.at] } : { side, pts: [s.at] }));
      return;
    }
    if (tool === 'bush' || tool === 'tree') {
      const p = snapAt(e, side).at;
      svgs.current[side]?.setPointerCapture(e.pointerId);
      setDrag(tool === 'bush' ? { kind: 'newBush', side, center: p, radius: 0 } : { kind: 'newTree', side, base: p, size: 0 });
      return;
    }
    if (tool === 'align') {
      if (side !== 'top') return void toast('Line the picture up in the top view.');
      // A spot on the picture is where you click; where it goes snaps to the objects.
      const p = alignPts.length % 2 ? snapAt(e, side, alignPts[alignPts.length - 1]).at : viewPoint(e, side);
      const next = [...alignPts, p];
      if (next.length === 4) finishAlign(next);
      else setAlignPts(next);
      return;
    }
    if (tool === 'measure') {
      const open = tape && !tape.b && tape.side === side;
      const p = snapAt(e, side, open ? tape.a : null).at;
      setTape((t) => (!t || t.b || t.side !== side ? { side, a: p } : { ...t, b: p }));
      return;
    }
    // Select, edit and split: a press on empty space clears the selection (not with Ctrl/⌘: that adds to it).
    if (e.target === e.currentTarget && !e.ctrlKey && !e.metaKey) {
      setSelected(null);
      setMulti([]);
    }
  }

  function startDrag(e: RPointerEvent, d: Drag, id: string | null, side: ViewSide) {
    if ((tool !== 'select' && tool !== 'edit') || panMode || e.button !== 0) return;
    e.stopPropagation();
    if (id) setSelected(id);
    svgs.current[side]?.setPointerCapture(e.pointerId);
    // A new drag is a new step for Undo.
    lastEdit.current = 0;
    setDrag(d);
  }

  function onPointerMove(e: RPointerEvent<SVGSVGElement>, side: ViewSide) {
    if (drag?.kind === 'pan') {
      setCams((c) => ({ ...c, [drag.side]: panBy(drag.cam, e.clientX - drag.x, e.clientY - drag.y) }));
      return;
    }
    const p = viewPoint(e, side);
    if (!drag || !layout) {
      if (panMode) {
        setSnapHint(null);
        setCursor({ ...p, side });
        return;
      }
      // Show what a click would snap to.
      let hint: (Snapped & { label?: string }) | null = null;
      if (isLineTool(tool)) {
        const from = draft.side === side && draft.pts.length ? draft.pts[draft.pts.length - 1] : null;
        hint = snapAt(e, side, from);
        if (!from && !e.altKey && lineEndAt(side, p)) hint = { ...hint, label: 'Click to continue this line' };
      } else if (tool === 'measure') {
        hint = snapAt(e, side, tape && !tape.b && tape.side === side ? tape.a : null);
      } else if (tool === 'align' && side === 'top' && alignPts.length % 2) {
        hint = snapAt(e, side, alignPts[alignPts.length - 1]);
      } else if (tool === 'bush' || tool === 'tree') {
        hint = snapAt(e, side);
      } else if (tool === 'edit' || tool === 'split') {
        const s = snapPoint(p, targetsFor(side, undefined, true), tolFor(side), { snap: drafting.snap !== e.altKey });
        hint = s.kind === 'point' || s.kind === 'mid' || s.kind === 'on' ? { ...s, label: tool === 'split' ? 'Click to split here' : s.kind === 'point' ? undefined : 'Click to add a point' } : null;
      }
      setSnapHint(hint ? { ...hint, side } : null);
      setCursor(hint ? { ...hint.at, side } : { ...p, side });
      return;
    }
    setCursor({ ...p, side });
    const f = 'id' in drag ? layout.fixtures.find((x) => x.id === drag.id) : undefined;
    if (drag.kind === 'vertex' && f) {
      const i = drag.index;
      const V = (q: Point) => toView(q, side, zMin);
      // Shift keeps the segment to the point before (or after, for the first point) at 45° steps.
      const neighbour = f.points[i - 1] ?? f.points[i + 1];
      const s = snapAt(e, side, neighbour ? V(neighbour) : null, { id: f.id, index: i });
      setSnapHint({ ...s, side });
      // On another point: take that point's position in 3D, so the two points join.
      const hit = s.kind === 'point' ? pointAtView(side, s.at, { id: f.id, index: i }) : undefined;
      update(drag.id, { points: f.points.map((q, j) => (j === i ? (hit ? { ...hit } : fromView(side, s.at, q)) : q)) });
    } else if (drag.kind === 'move') {
      let du = p.u - drag.from.u;
      let dv = p.v - drag.from.v;
      // Shift: move straight across, or straight up and down (toward the street in the top view).
      if (e.shiftKey) {
        if (Math.abs(du) >= Math.abs(dv)) dv = 0;
        else du = 0;
      }
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
    setSnapHint(null);
    if (layout && (drag?.kind === 'newBush' || drag?.kind === 'newTree')) {
      const s = layoutScale(layout);
      const ground = layoutGround(layout);
      const count = layout.fixtures.filter((f) => f.kind === (drag.kind === 'newBush' ? 'bush' : 'tree')).length;
      if (drag.kind === 'newBush') {
        const r = Math.max(30, drag.radius || 70);
        const c = drag.center;
        // From the front: the bush touches the front wall. From above: it sits on the ground.
        const center: Point = drag.side === 'front' ? { x: c.u, y: c.v, z: r } : { x: c.u, y: Math.round(ground - r * 0.72), z: Math.round(c.v + zMin) };
        const lt = lightsOf(layout, layout.lights);
        // One strand of lights per bush, when the strands are known.
        addFixture({ id: uid(), name: `Bush ${count + 1}`, kind: 'bush', points: [center], radius: r, pattern: 'fill', pixels: lt?.perStrand ?? 60, ...(lt ? { lights: lt.id } : {}), deviceId: null, startPixel: 0, reversed: false });
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
          pixels: lightsOf(layout, layout.lights)?.perStrand ? lightsOf(layout, layout.lights)!.perStrand! * 4 : 200,
          ...(layout.lights && lightsOf(layout, layout.lights) ? { lights: layout.lights } : {}),
          deviceId: null,
          startPixel: 0,
          reversed: false
        });
      }
    }
    setDrag(null);
  }

  /** Double-click on a line (Select tool): adds a point on the nearest segment. */
  function insertVertex(f: Fixture, k: number, e: RMouseEvent, side: ViewSide) {
    update(f.id, insertPoint(f, k, pointOnLine(f, k, viewPoint(e, side), side)));
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

  // ---------- Scenes ----------

  /** Puts a scene's effects on the objects (an undoable edit), and plays them. */
  function loadScene(sc: Scene) {
    const yard = sc.effects?.[YARD];
    edit((l) => {
      const { effect: _e, ...rest } = l;
      return { ...rest, ...(yard ? { effect: yard } : {}), fixtures: l.fixtures.map((f) => withEffects(f, sc.effects)) };
    });
    setSceneRef({ id: sc.id, name: sc.name });
    setPlaying(true);
    const n = layout ? Object.keys(layoutEffects({ effect: yard, fixtures: layout.fixtures.map((f) => withEffects(f, sc.effects)) })).length : 0;
    toast.success(`Editing "${sc.name}": ${n} effect(s). Save the scene when you are done.`);
  }

  // Opened from the Scenes page to edit a scene: /admin/layout?scene=<id>
  const [params, setParams] = useSearchParams();
  const openScene = params.get('scene');
  useEffect(() => {
    if (!openScene || !layout || !overview) return;
    setParams({}, { replace: true });
    const sc = overview.scenes.find((x) => x.id === openScene);
    if (sc) loadScene(sc);
  }, [openScene, !!layout, !!overview]);

  /** Saves the objects' effects as a scene: a new one (name), or the one being edited. */
  async function saveScene(target: { name: string } | { id: string }) {
    if (!layout) return;
    if (!fxCount) return void toast.error('Give at least one object an effect first.');
    if (overlapCount) return void toast.error('Two objects use the same LEDs. Fix that first.');
    setBusy(true);
    try {
      // A scene names the objects by id: save the layout too, so the server has them.
      if (dirty) {
        const out = await api.saveLayout(layout);
        qc.setQueryData(LAYOUT_KEY, out);
        setLayout(out);
      }
      const fx = layoutEffects(layout);
      const prev = 'id' in target ? overview?.scenes.find((x) => x.id === target.id) : null;
      const sc = prev
        ? await api.updateScene(prev.id, { name: prev.name, devicePresets: prev.devicePresets, effects: fx })
        : await api.createScene({ name: 'name' in target ? target.name : 'Effects', devicePresets: {}, effects: fx });
      setSceneRef({ id: sc.id, name: sc.name });
      setNewScene(null);
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      toast.success(prev ? `Scene "${sc.name}" saved${dirty ? ', with the layout' : ''}.` : `Scene "${sc.name}" created. It is on the public page now.`);
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const effectScenes = (overview?.scenes ?? []).filter((x) => x.effects && Object.keys(x.effects).length);
  const editingScene = sceneRef && overview?.scenes.some((x) => x.id === sceneRef.id) ? sceneRef : null;
  function scenesMenu(e: RMouseEvent<HTMLElement>) {
    const r = e.currentTarget.getBoundingClientRect();
    const items: MenuItem[] = [];
    if (editingScene) items.push({ label: `Save "${editingScene.name}"`, run: () => void saveScene({ id: editingScene.id }) });
    items.push({ label: 'Save as a new scene…', run: () => setNewScene(editingScene ? `${editingScene.name} 2` : '') });
    for (const sc of effectScenes) items.push({ label: `Open "${sc.name}"`, run: () => loadScene(sc) });
    if (fxCount) items.push({ label: 'Remove every effect', danger: true, run: () => (edit((l) => ({ ...l, fixtures: l.fixtures.map((f) => withEffects(f, {})) })), setSceneRef(null)) });
    setMenu({ x: r.left, y: r.bottom + 4, title: editingScene ? `Scene: ${editingScene.name}` : 'Scenes with effects', items });
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

  /** The view position in the top view as a spot seen from above. */
  const toXZ = (p: UV) => ({ x: p.u, z: p.v + zMin });
  /** Applies the Align tool: two pairs move, turn and size the picture; one pair only moves it. */
  function finishAlign(pts: UV[]) {
    const a = layout?.aerial;
    chooseTool('select');
    if (!a || pts.length < 2) return;
    const [f1, t1, f2, t2] = pts.map(toXZ);
    const next = alignAerial(a, f1, t1, f2, t2);
    updateLayout({ aerial: next });
    toast.success(f2 ? `Picture lined up: ${m.text(next.width)} wide, turned ${Math.round(next.rotation * 10) / 10}°.` : 'Picture moved.');
  }
  const startAlign = (a: AerialPicture | null | undefined = layoutRef.current?.aerial) => {
    chooseTool('align');
    // The top view must be on the screen, zoomed out to show the whole picture and the yard.
    if (!shown.includes('top')) {
      setMaximized(null);
      if (!visible.includes('top')) setPaneView(0, 'top');
    }
    if (a) {
      const c = contentBox('top');
      const us = [c.x, c.x + c.w, ...aerialCorners(a).map((q) => q.x)];
      const vs = [c.y, c.y + c.h, ...aerialCorners(a).map((q) => q.z - zMin)];
      const box = { x: Math.min(...us), y: Math.min(...vs), w: Math.max(...us) - Math.min(...us), h: Math.max(...vs) - Math.min(...vs) };
      setCams((cs) => ({ ...cs, top: fitCam(box, sizeOf('top'), offOf('top')) }));
    }
  };

  async function uploadAerial(file: File | undefined) {
    if (!file || !layout) return;
    setBusy(true);
    try {
      const { url } = await api.uploadAerial(file);
      const img = new Image();
      img.src = url;
      await img.decode();
      const first = !layout.aerial;
      const next = { ...layout, aerial: placeAerial(layout, url, img.naturalHeight / img.naturalWidth, layout.aerial) };
      const out = await api.saveLayout(next);
      qc.setQueryData(LAYOUT_KEY, out);
      setLayout(out);
      if (first) {
        toast.success('Picture added under the top view. Now line it up: click a corner of the house on the picture, then where that corner is in the yard; then a second corner.');
        startAlign(out.aerial);
      } else toast.success('Picture replaced. It keeps the place of the old one.');
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeAerial() {
    setBusy(true);
    try {
      const out = await api.removeAerial();
      qc.setQueryData(LAYOUT_KEY, out);
      setLayout((l) => (l ? { ...l, aerial: null } : out));
      if (tool === 'align') chooseTool('select');
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  /** The Pictures menu: the front of the house, and the yard from above. */
  function picturesMenu(e: RMouseEvent<HTMLElement>) {
    if (!layout) return;
    const r = e.currentTarget.getBoundingClientRect();
    const items: MenuItem[] = [
      { label: layout.background ? 'Change the house picture (front view)…' : 'Add a house picture (front view)…', run: () => fileInput.current?.click() },
      { label: layout.aerial ? 'Change the picture from above (top view)…' : 'Add a picture from above (top view)…', run: () => aerialInput.current?.click() }
    ];
    if (layout.aerial) items.push({ label: 'Line up the picture from above', run: () => startAlign() });
    if (layout.background) items.push({ label: 'Remove the house picture', danger: true, run: () => void removeBg() });
    if (layout.aerial) items.push({ label: 'Remove the picture from above', danger: true, run: () => void removeAerial() });
    setMenu({ x: r.left, y: r.bottom + 4, title: 'Pictures to trace over', items });
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
  const scale = layoutScale(layout);
  /** The light string new objects are made of. */
  const newLights = lightsOf(layout, layout.lights);
  const ground = layoutGround(layout);
  const has2d = shown.some((v) => v !== '3d');
  const drawing = isLineTool(tool) && draft.pts.length > 0;

  const toolKey = (t: Tool) =>
    Object.keys(TOOL_KEYS)
      .find((k) => TOOL_KEYS[k] === t)!
      .toUpperCase();
  const toolButton = (t: Tool, Icon: typeof House) => (
    <button
      type="button"
      onClick={() => chooseTool(t)}
      title={`${TOOL_LABELS[t]} (${toolKey(t)})`}
      aria-label={TOOL_LABELS[t]}
      aria-keyshortcuts={toolKey(t)}
      aria-pressed={tool === t}
      className={cn(
        'relative grid size-9 shrink-0 place-items-center rounded-lg transition [&_svg]:size-[18px]',
        tool === t ? 'bg-sky-600 text-white shadow-sm' : 'text-stone-600 hover:bg-stone-200/70 hover:text-stone-950 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white'
      )}
    >
      <Icon />
      <kbd className="pointer-events-none absolute right-0.5 bottom-0 font-sans text-[9px] leading-none font-semibold opacity-60">{toolKey(t)}</kbd>
    </button>
  );
  const toolSep = <span className="h-6 w-px shrink-0 bg-stone-200 lg:h-px lg:w-6 dark:bg-stone-700" />;
  const barSep = <span className="mx-1 h-5 w-px shrink-0 bg-stone-200 dark:bg-stone-700" />;

  const hint = !has2d
    ? 'Show the front or the top view to draw and move objects. In the 3D view, click an LED to select its object.'
    : panMode
      ? 'Drag to pan the view. Wheel: zoom at the pointer. Home: zoom to fit.'
      : isLineTool(tool)
        ? draft.pts.length
          ? 'Click the next corner. Enter, Esc or a double-click finishes the line. Backspace removes the last point. Shift: 45° steps. Alt: no snapping.'
          : `Click the first point of the ${tool === 'roof' ? 'roofline' : 'line'}, or click the end of a line to continue it (Alt-click: a new line from there).`
        : tool === 'edit'
          ? 'Click a line to add a point, then drag it into place. Drag a point to move it. Delete removes the selected point. Ctrl-click (⌘-click) an end to continue the line.'
          : tool === 'split'
            ? 'Click a corner, or a spot on a line, to cut the line in two there.'
            : tool === 'bush'
              ? 'Press on the middle of the bush and drag out to its edge.'
              : tool === 'tree'
                ? 'Front view: drag from the base up to the top. Top view: drag from the middle out to the edge of the base.'
                : tool === 'measure'
                  ? 'Click two points to measure the distance between them. Then type the real distance to set the scale (or, in the top view, the scale of the picture from above).'
                  : tool === 'align'
                    ? ALIGN_STEPS[alignPts.length]
                  : 'Click to select; drag to move (Shift: straight). Right-click for actions. Wheel: zoom. Middle-drag or Space-drag: pan. F: zoom to the selection.';

  const tapeLength = tape?.b ? Math.hypot(tape.b.u - tape.a.u, tape.b.v - tape.a.v) : null;
  const coords: [string, string][] | null = cursor
    ? cursor.side === 'front'
      ? [
          ['X', m.text(cursor.u)],
          ['Height', m.text(ground - cursor.v)]
        ]
      : [
          ['X', m.text(cursor.u)],
          ['Depth', m.text(cursor.v + zMin)]
        ]
    : null;

  /** One editable view: the drawing (YardView) and the handles over it, seen through the view's camera. */
  const renderView = (side: ViewSide) => {
    const V = (p: Point) => toView(p, side, zMin);
    const front = side === 'front';
    const vb = viewBoxFor(side);
    // Handles and labels keep the same size on the screen at every zoom.
    const k = camFor(side).k / BASE_K;
    const dash = (a: number, b: number) => `${a * k} ${b * k}`;
    const handle = (key: string | number, at: UV, className: string, onDown: (e: RPointerEvent<SVGCircleElement>) => void, onDouble?: (e: RMouseEvent) => void) => (
      <circle key={key} cx={at.u} cy={at.v} r={9 * k} className={cn('stroke-stone-950', className)} strokeWidth={3 * k} onPointerDown={onDown} onDoubleClick={onDouble} />
    );
    return (
      <YardView layout={layout} side={side} zRange={zRange} getFrame={getFrame} highlight={segment != null || playing ? null : selected} fill viewBox={vb} grid={drafting.grid}>
        <svg
          ref={(el) => void (svgs.current[side] = el)}
          viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
          preserveAspectRatio="none"
          className={cn(
            'absolute inset-0 h-full w-full touch-none select-none',
            drag?.kind === 'pan' ? 'cursor-grabbing' : panMode ? 'cursor-grab' : tool !== 'select' && tool !== 'edit' ? 'cursor-crosshair' : ''
          )}
          onPointerDown={(e) => onPointerDown(e, side)}
          onPointerMove={(e) => onPointerMove(e, side)}
          onPointerUp={onPointerUp}
          onPointerLeave={() => (setCursor(null), drag == null && setSnapHint(null))}
          onMouseDown={(e) => e.button === 1 && e.preventDefault()}
          onDoubleClick={() => isLineTool(tool) && draft.side === side && finishLine(tool)}
        >
          {!front ? (
            <>
              <text x={vb.x + 12 * k} y={-zMin - 10 * k} fontSize={14 * k} fill="rgba(251,191,36,0.7)" pointerEvents="none">
                Front wall of the house
              </text>
              <text x={vb.x + 12 * k} y={vb.y + vb.h - 12 * k} fontSize={14 * k} fill="rgba(255,255,255,0.4)" pointerEvents="none">
                ↓ Street
              </text>
            </>
          ) : null}

          {/* The ground: drag it to the bottom of the front wall. Heights count from here. */}
          {front ? (
            <g>
              <line x1={vb.x} x2={vb.x + vb.w} y1={ground} y2={ground} stroke="rgba(52,211,153,0.6)" strokeWidth={2 * k} strokeDasharray={dash(12, 10)} pointerEvents="none" />
              <g className={tool === 'select' && !panMode ? 'cursor-ns-resize' : ''} onPointerDown={(e) => startDrag(e, { kind: 'ground' }, null, side)}>
                <rect x={vb.x + 8 * k} y={ground - 30 * k} width={70 * k} height={24 * k} rx={6 * k} fill="rgba(6,78,59,0.85)" stroke="rgba(52,211,153,0.8)" strokeWidth={1.5 * k} />
                <text x={vb.x + 43 * k} y={ground - 13 * k} textAnchor="middle" fontSize={14 * k} fontWeight={600} fill="#a7f3d0" pointerEvents="none">
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
                  {/* Segments in the multi-selection (all of them when the whole line is in it). */}
                  {multi.length
                    ? pts.slice(1).map((b, s) =>
                        multi.includes(f.id) || multi.includes(effectKey(f.id, s)) ? (
                          <line
                            key={`multi${s}`}
                            x1={pts[s].u}
                            y1={pts[s].v}
                            x2={b.u}
                            y2={b.v}
                            stroke="rgb(40,170,255)"
                            strokeOpacity={playing ? 0.18 : 0.45}
                            strokeWidth={14 * k}
                            strokeLinecap="round"
                            pointerEvents="none"
                          />
                        ) : null
                      )
                    : null}
                  {/* The selected segment, drawn wide so it is easy to see (faint while effects play, so they show through). */}
                  {isSel && segment != null && pts[segment + 1] ? (
                    <line
                      x1={pts[segment].u}
                      y1={pts[segment].v}
                      x2={pts[segment + 1].u}
                      y2={pts[segment + 1].v}
                      stroke="rgb(40,170,255)"
                      strokeOpacity={playing ? 0.14 : 0.45}
                      strokeWidth={14 * k}
                      strokeLinecap="round"
                      pointerEvents="none"
                    />
                  ) : null}
                  {/* Skipped segments: a dashed line, so they show as "off". */}
                  {f.skip?.map((s) =>
                    pts[s + 1] ? (
                      <line
                        key={`skip${s}`}
                        x1={pts[s].u}
                        y1={pts[s].v}
                        x2={pts[s + 1].u}
                        y2={pts[s + 1].v}
                        stroke="rgba(255,255,255,0.45)"
                        strokeWidth={3 * k}
                        strokeDasharray={dash(6, 9)}
                        pointerEvents="none"
                      />
                    ) : null
                  )}
                  {/* One hit area per segment: a click selects that segment. */}
                  {pts.slice(1).map((b, s) => {
                    const a = pts[s];
                    return (
                      <line
                        key={s}
                        x1={a.u}
                        y1={a.v}
                        x2={b.u}
                        y2={b.v}
                        stroke="transparent"
                        strokeWidth={26 * k}
                        strokeLinecap="round"
                        className={panMode ? '' : tool === 'select' ? 'cursor-pointer' : tool === 'edit' ? 'cursor-copy' : ''}
                        onPointerDown={(e) => {
                          if (e.button !== 0 || panMode) return;
                          if (tool === 'select' && (e.ctrlKey || e.metaKey)) {
                            e.stopPropagation();
                            skipMenu(e);
                            toggleTarget(effectKey(f.id, s));
                            return;
                          }
                          if (tool === 'select') {
                            startDrag(e, { kind: 'move', side, id: f.id, from: viewPoint(e, side), original: f.points }, f.id, side);
                            selectSegment(f.id, s);
                          } else if (tool === 'edit') {
                            lastEdit.current = 0;
                            addPointOn(f, s, snapHint?.side === side && drafting.snap !== e.altKey ? snapHint.at : viewPoint(e, side), side, e);
                          } else if (tool === 'split') {
                            e.stopPropagation();
                            splitOn(f, s, snapHint?.side === side && drafting.snap !== e.altKey ? snapHint.at : viewPoint(e, side), side);
                          }
                        }}
                        onContextMenu={(e) => segmentMenu(e, f, s, side)}
                        onDoubleClick={(e) => {
                          e.stopPropagation();
                          if (tool === 'select') insertVertex(f, s, e, side);
                        }}
                      />
                    );
                  })}
                  {isSel || tool === 'edit' || tool === 'split'
                    ? pts.map((p, i) => {
                        const end = i === 0 ? 'first' : i === f.points.length - 1 ? 'last' : null;
                        return (
                          <circle
                            key={i}
                            cx={p.u}
                            cy={p.v}
                            r={(isSel ? 9 : 7) * k}
                            strokeWidth={3 * k}
                            className={cn(
                              'stroke-stone-950',
                              panMode ? '' : tool === 'split' ? (end ? '' : 'cursor-crosshair') : 'cursor-grab',
                              tool === 'split' && (end ? 'fill-stone-500' : 'fill-rose-400'),
                              tool !== 'split' &&
                                (!isSel
                                  ? 'fill-amber-400/80'
                                  : i === (segment ?? 0)
                                    ? 'fill-green-500'
                                    : i === (segment != null ? segment + 1 : f.points.length - 1)
                                      ? 'fill-red-500'
                                      : 'fill-amber-400'),
                              isSel && corner === i && 'stroke-white'
                            )}
                            onPointerDown={(e) => {
                              if (e.button !== 0 || panMode) return;
                              // Ctrl-click (⌘-click) on an end: draw on from there.
                              if ((e.ctrlKey || e.metaKey) && end && (tool === 'select' || tool === 'edit')) {
                                e.stopPropagation();
                                // On a Mac, Ctrl-click also opens the context menu; skip that one.
                                suppressMenu.current = e.ctrlKey;
                                setTimeout(() => (suppressMenu.current = false), 600);
                                return startContinue(f, end, side);
                              }
                              if (tool === 'split') {
                                e.stopPropagation();
                                if (end) toast.error('Pick a corner or a spot on the line to split it. To shorten the line, delete its end point.');
                                else splitAt(f, i);
                                return;
                              }
                              startDrag(e, { kind: 'vertex', side, id: f.id, index: i }, f.id, side);
                              if (tool === 'select' || tool === 'edit') {
                                if (f.id !== selected) keepPart.current = true;
                                setCorner(i);
                                setSegment(null);
                              }
                            }}
                            onContextMenu={(e) => pointMenu(e, f, i, side)}
                            onDoubleClick={(e) => {
                              e.stopPropagation();
                              if (tool === 'select' || tool === 'edit') deletePoint(f, i);
                            }}
                          />
                        );
                      })
                    : null}
                  {isSel ? <LedLabels f={f} corner={corner} segment={segment} V={V} side={side} k={k} scale={scale} /> : null}
                  {isSel ? (
                    segment != null && f.points[segment + 1] ? (
                      <EndMarkers a={fixturePixels(f, scale)[segmentLeds(f, segment).lo]} b={fixturePixels(f, scale)[segmentLeds(f, segment).hi]} V={V} k={k} />
                    ) : (
                      <EndMarkers a={f.points[0]} b={f.points[f.points.length - 1]} V={V} k={k} />
                    )
                  ) : null}
                </g>
              );
            }
            // Bush or tree.
            const c = V(f.points[0]);
            const r = f.radius ?? 60;
            const h = f.kind === 'tree' ? (f.height ?? 240) : 0;
            const move = (e: RPointerEvent) => {
              if (tool === 'select' && !panMode && e.button === 0 && (e.ctrlKey || e.metaKey)) {
                e.stopPropagation();
                skipMenu(e);
                return toggleTarget(f.id);
              }
              startDrag(e, { kind: 'move', side, id: f.id, from: viewPoint(e, side), original: f.points }, f.id, side);
            };
            const hitClass = tool === 'select' && !panMode ? 'cursor-move' : '';
            if (f.kind === 'custom') {
              const paths = designPaths(f, scale).map((path) => path.map(V));
              const b = boxOf(f, side);
              const pad = 10 * k;
              return (
                <g key={f.id}>
                  <rect x={b.x - pad} y={b.y - pad} width={b.w + 2 * pad} height={b.h + 2 * pad} fill="transparent" className={hitClass} onPointerDown={move} onContextMenu={(e) => objectMenu(e, f)} />
                  {isSel || multi.includes(f.id)
                    ? paths.map((path, j) => (
                        <polyline key={j} points={path.map((q) => `${q.u},${q.v}`).join(' ')} fill="none" stroke="rgb(40,170,255)" strokeOpacity={0.85} strokeWidth={2.5 * k} strokeLinejoin="round" pointerEvents="none" />
                      ))
                    : null}
                  {isSel || multi.includes(f.id) ? (
                    <rect x={b.x - pad} y={b.y - pad} width={b.w + 2 * pad} height={b.h + 2 * pad} fill={multi.includes(f.id) ? 'rgba(40,170,255,0.08)' : 'none'} stroke="rgb(40,170,255)" strokeOpacity={0.6} strokeWidth={1.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
                  ) : null}
                  {isSel ? <LedLabels f={f} corner={null} segment={null} V={V} side={side} k={k} scale={scale} /> : null}
                  {isSel ? <EndMarkers a={fixturePixels(f, scale)[0]} b={fixturePixels(f, scale).at(-1)} V={V} k={k} /> : null}
                </g>
              );
            }
            return (
              <g key={f.id}>
                {f.kind === 'tree' && front ? (
                  <polygon points={`${c.u - r},${c.v} ${c.u},${c.v - h} ${c.u + r},${c.v}`} fill="transparent" className={hitClass} onPointerDown={move} onContextMenu={(e) => objectMenu(e, f)} />
                ) : (
                  <ellipse cx={c.u} cy={c.v} rx={r} ry={front ? r * 0.72 : r} fill="transparent" className={hitClass} onPointerDown={move} onContextMenu={(e) => objectMenu(e, f)} />
                )}
                {multi.includes(f.id) ? (
                  f.kind === 'tree' && front ? (
                    <polygon points={`${c.u - r},${c.v} ${c.u},${c.v - h} ${c.u + r},${c.v}`} fill="rgba(40,170,255,0.08)" stroke="rgb(40,170,255)" strokeWidth={2.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
                  ) : (
                    <ellipse cx={c.u} cy={c.v} rx={r + 6 * k} ry={(front ? r * 0.72 : r) + 6 * k} fill="rgba(40,170,255,0.08)" stroke="rgb(40,170,255)" strokeWidth={2.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
                  )
                ) : null}
                {isSel ? <LedLabels f={f} corner={null} segment={null} V={V} side={side} k={k} scale={scale} /> : null}
                {isSel ? <EndMarkers a={fixturePixels(f, scale)[0]} b={fixturePixels(f, scale).at(-1)} V={V} k={k} /> : null}
                {isSel ? handle('r', { u: c.u + r, v: c.v }, 'cursor-ew-resize fill-amber-400', (e) => startDrag(e, { kind: 'radius', side, id: f.id }, f.id, side)) : null}
                {isSel && f.kind === 'tree' && front ? handle('h', { u: c.u, v: c.v - h }, 'cursor-ns-resize fill-amber-400', (e) => startDrag(e, { kind: 'treeHeight', id: f.id }, f.id, side)) : null}
              </g>
            );
          })}

          {/* Where each new strand of the selected object starts */}
          {sel && !playing ? <StrandMarks f={sel} perStrand={lightsOf(layout, sel.lights)?.perStrand ?? null} scale={scale} V={V} k={k} labels={front} /> : null}

          {/* Line being drawn, with the length of the segment under the pointer */}
          {isLineTool(tool) && draft.side === side && draft.pts.length ? (
            <>
              {cursor?.side === side
                ? (() => {
                    const a = draft.pts[draft.pts.length - 1];
                    const len = Math.hypot(cursor.u - a.u, cursor.v - a.v);
                    return len > 20 * k ? (
                      <text
                        x={(a.u + cursor.u) / 2}
                        y={(a.v + cursor.v) / 2 - 12 * k}
                        textAnchor="middle"
                        fontSize={15 * k}
                        fontWeight={700}
                        fill="#fde68a"
                        stroke="#0c0a09"
                        strokeWidth={4 * k}
                        paintOrder="stroke"
                        pointerEvents="none"
                      >
                        {m.text(len)}
                        {newLights ? ` · ${ledsForLength(len / scale, newLights.spacing, false)} LEDs` : ''}
                      </text>
                    ) : null;
                  })()
                : null}
              <polyline
                points={[...draft.pts, ...(cursor?.side === side ? [cursor] : [])].map((p) => `${p.u},${p.v}`).join(' ')}
                fill="none"
                stroke="#fbbf24"
                strokeWidth={2.5 * k}
                strokeDasharray={dash(10, 8)}
                pointerEvents="none"
              />
              {draft.pts.map((p, i) => (
                <circle key={i} cx={p.u} cy={p.v} r={6 * k} fill="#fbbf24" pointerEvents="none" />
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
              strokeWidth={2.5 * k}
              strokeDasharray={dash(8, 6)}
              pointerEvents="none"
            />
          ) : null}
          {drag?.kind === 'newTree' && drag.side === side ? (
            front ? (
              <polygon
                points={`${drag.base.u - drag.size * 0.33},${drag.base.v} ${drag.base.u},${drag.base.v - drag.size} ${drag.base.u + drag.size * 0.33},${drag.base.v}`}
                fill="rgba(52,211,153,0.15)"
                stroke="#34d399"
                strokeWidth={2.5 * k}
                strokeDasharray={dash(8, 6)}
                pointerEvents="none"
              />
            ) : (
              <circle cx={drag.base.u} cy={drag.base.v} r={drag.size} fill="rgba(52,211,153,0.15)" stroke="#34d399" strokeWidth={2.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
            )
          ) : null}

          {snapHint?.side === side ? <SnapMarker s={snapHint} k={k} /> : null}

          {/* Measuring tape */}
          {tool === 'measure' && tape?.side === side ? (
            <g pointerEvents="none">
              {(() => {
                const b = tape.b ?? (cursor?.side === side ? cursor : null);
                return b ? (
                  <>
                    <line x1={tape.a.u} y1={tape.a.v} x2={b.u} y2={b.v} stroke="#f0abfc" strokeWidth={2.5 * k} />
                    <text
                      x={(tape.a.u + b.u) / 2}
                      y={(tape.a.v + b.v) / 2 - 12 * k}
                      textAnchor="middle"
                      fontSize={16 * k}
                      fontWeight={700}
                      fill="#f5d0fe"
                      stroke="#0c0a09"
                      strokeWidth={4 * k}
                      paintOrder="stroke"
                    >
                      {m.text(Math.hypot(b.u - tape.a.u, b.v - tape.a.v))}
                    </text>
                  </>
                ) : null;
              })()}
              <circle cx={tape.a.u} cy={tape.a.v} r={6 * k} fill="#f0abfc" />
              {tape.b ? <circle cx={tape.b.u} cy={tape.b.v} r={6 * k} fill="#f0abfc" /> : null}
            </g>
          ) : null}

          {/* Align tool: the edge of the picture, and each spot with an arrow to where it goes. */}
          {!front && tool === 'align' && layout.aerial ? (
            <g pointerEvents="none">
              <polygon points={aerialCorners(layout.aerial).map((q) => `${q.x},${q.z - zMin}`).join(' ')} fill="none" stroke="#5eead4" strokeWidth={1.5 * k} strokeDasharray={dash(8, 6)} />
              {[0, 2].map((i) => {
                const a = alignPts[i];
                if (!a) return null;
                const b = alignPts[i + 1] ?? (i + 1 === alignPts.length && cursor?.side === side ? cursor : null);
                return (
                  <g key={i}>
                    {b ? <line x1={a.u} y1={a.v} x2={b.u} y2={b.v} stroke="#5eead4" strokeWidth={2.5 * k} strokeDasharray={alignPts[i + 1] ? undefined : dash(6, 4)} /> : null}
                    <circle cx={a.u} cy={a.v} r={6 * k} fill="none" stroke="#5eead4" strokeWidth={2.5 * k} />
                    {alignPts[i + 1] ? <circle cx={alignPts[i + 1].u} cy={alignPts[i + 1].v} r={6 * k} fill="#5eead4" /> : null}
                    <text x={a.u + 10 * k} y={a.v - 10 * k} fontSize={14 * k} fontWeight={700} fill="#99f6e4" stroke="#0c0a09" strokeWidth={4 * k} paintOrder="stroke">
                      {i / 2 + 1}
                    </text>
                  </g>
                );
              })}
            </g>
          ) : null}
        </svg>
      </YardView>
    );
  };

  /** The title bar of a viewport: which view it shows, the zoom, zoom to fit, and make big. */
  const paneHeader = (v: ViewName) => {
    const i = viewport.panes.indexOf(v);
    const big = maximized === v;
    const side = v === '3d' ? null : v;
    const zoom = side ? Math.round((fitCam(contentBox(side), sizeOf(side), offOf(side)).k / camFor(side).k) * 100) : null;
    return (
      <div
        className="flex h-7 shrink-0 items-center gap-2 border-b border-white/10 bg-stone-900 px-1.5 text-[11px] text-white/55 select-none"
        onDoubleClick={(e) => e.target === e.currentTarget && setMaximized(big ? null : v)}
      >
        <select
          value={v}
          onChange={(e) => setPaneView(i, e.target.value as ViewName)}
          aria-label="View shown in this viewport"
          className="h-5 cursor-pointer appearance-none rounded bg-white/10 pr-5 pl-1.5 text-[11px] font-semibold text-white hover:bg-white/15 focus:ring-1 focus:ring-sky-400 focus:outline-none"
          style={{
            colorScheme: 'dark',
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d6d3d1' stroke-width='2.5'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`,
            backgroundRepeat: 'no-repeat',
            backgroundPosition: 'right 0.25rem center',
            backgroundSize: '12px'
          }}
        >
          {(['front', 'top', '3d'] as ViewName[]).map((x) => (
            <option key={x} value={x}>
              {VIEW_LABELS[x]}
            </option>
          ))}
        </select>
        <span className="pointer-events-none truncate">
          {VIEW_NOTES[v]}
          {v === 'top' ? ` · grid ${m.units === 'm' ? '1 m' : '5 ft'}` : ''}
        </span>
        <span className="ml-auto" />
        {side ? (
          <>
            <span className="tabular-nums" title="Zoom: 100% shows the whole yard">
              {zoom}%
            </span>
            <button
              type="button"
              title="Zoom to fit (Home)"
              aria-label="Zoom to fit"
              onClick={() =>
                setCams((c) => {
                  const next = { ...c };
                  delete next[side];
                  return next;
                })
              }
              className="grid size-5 place-items-center rounded hover:bg-white/15 hover:text-white [&_svg]:size-3.5"
            >
              <Scan />
            </button>
          </>
        ) : null}
        <button
          type="button"
          title={big ? 'Show all views' : 'Make this view big (double-click the title bar)'}
          aria-label={big ? 'Show all views' : 'Make this view big'}
          onClick={() => setMaximized(big ? null : v)}
          className="grid size-5 place-items-center rounded hover:bg-white/15 hover:text-white [&_svg]:size-3.5"
        >
          {big ? <Minimize2 /> : <Maximize2 />}
        </button>
      </div>
    );
  };

  const single = shown.length === 1;
  const gridClass = single
    ? 'lg:grid-cols-1 lg:grid-rows-1'
    : viewport.mode === 'columns'
      ? 'lg:grid-cols-2 lg:grid-rows-1'
      : viewport.mode === 'rows'
        ? 'lg:grid-cols-1 lg:grid-rows-2'
        : 'lg:grid-cols-[3fr_2fr] lg:grid-rows-2';

  const lightsLabel = !showOnLights ? 'Lights: off' : !mapped ? 'Lights: no device' : !inFront ? 'Lights: paused' : previewDevices.length ? `Lights: ${previewDevices.join(', ')}` : 'Lights: on';
  const lightsTitle = !showOnLights
    ? 'Show the layout on the real lights while you edit'
    : !mapped
      ? 'Choose a WLED device for an object first'
      : !inFront
        ? 'Paused while this window is not in front'
        : 'The selected object glows on its WLED device. Click to stop.';

  const SelIcon = sel ? KIND_ICONS[sel.kind] : null;

  // The multi-selection's items that still exist, with their names and effects.
  const multiItems = multi.flatMap((key) => {
    const t = effectTarget(key);
    const f = layout.fixtures.find((x) => x.id === t.id);
    if (!f) return [];
    if (t.segment == null) return [{ key, name: f.name, effect: f.effect }];
    if (!isLine(f) || t.segment >= f.points.length - 1) return [];
    return [{ key, name: `${f.name} · segment ${t.segment + 1}`, effect: f.segmentEffects?.[t.segment] }];
  });
  const multiShown = multiItems.find((it) => it.effect)?.effect;
  const multiMixed = new Set(multiItems.map((it) => JSON.stringify(it.effect ?? null))).size > 1;
  /**
   * Changes the effect of every item in the multi-selection. A new effect (or none) replaces
   * them all; a changed setting goes to each item, which keeps its other settings.
   */
  function setMultiEffect(next: EffectSettings | undefined, prev: EffectSettings | undefined) {
    let fn: (cur: EffectSettings | undefined) => EffectSettings | undefined;
    if (!next) fn = () => undefined;
    else if (!prev || next.effect !== prev.effect) fn = () => next;
    else {
      const keys = new Set([...Object.keys(next), ...Object.keys(prev)] as (keyof EffectSettings)[]);
      const changed: Partial<EffectSettings> = {};
      for (const k of keys) if (JSON.stringify(next[k]) !== JSON.stringify(prev[k])) (changed as Record<string, unknown>)[k] = next[k];
      fn = (cur) => (cur ? { ...cur, ...changed } : next);
    }
    const keys = new Set(multiItems.map((it) => it.key));
    edit((l) => ({
      ...l,
      fixtures: l.fixtures.map((f) => {
        let g = f;
        if (keys.has(f.id)) g = { ...g, effect: fn(g.effect) };
        if (isLine(f))
          for (let k = 0; k < f.points.length - 1; k++)
            if (keys.has(effectKey(f.id, k))) g = { ...g, segmentEffects: setSegmentEffect(g.segmentEffects, k, fn(g.segmentEffects?.[k])) };
        return g;
      })
    }));
  }

  return (
    <div className="flex flex-col bg-stone-100 lg:h-full dark:bg-stone-950">
      {/* The command bar: history, viewports, the real lights, the picture, and saving. */}
      <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-stone-200 bg-stone-50 px-2 py-1 dark:border-stone-800 dark:bg-stone-900">
        <h1 className="px-1.5 text-sm font-semibold tracking-tight">Yard layout</h1>
        {overlapCount ? <Badge tone="red">Objects share LEDs</Badge> : dirty ? <Badge tone="amber">Unsaved changes</Badge> : null}
        {barSep}
        <Button size="sm" variant="ghost" onClick={undo} disabled={!past.current.length} title="Undo (Ctrl/⌘+Z)" aria-label="Undo" className="px-2">
          <Undo2 />
        </Button>
        <Button size="sm" variant="ghost" onClick={redo} disabled={!future.current.length} title="Redo (Ctrl/⌘+Shift+Z)" aria-label="Redo" className="px-2">
          <Redo2 />
        </Button>
        {barSep}
        <div className="inline-flex rounded-lg bg-white p-0.5 ring-1 ring-stone-200 dark:bg-stone-950 dark:ring-stone-800" role="group" aria-label="Viewports">
          {VP_MODES.map(({ mode, label, icon: Icon }) => (
            <button
              key={mode}
              type="button"
              title={label}
              aria-label={label}
              aria-pressed={viewport.mode === mode && !maximized}
              onClick={() => (setViewport({ ...viewport, mode }), setMaximized(null))}
              className={cn(
                'grid h-7 w-8 place-items-center rounded-md transition [&_svg]:size-4',
                viewport.mode === mode && !maximized
                  ? 'bg-stone-900 text-white dark:bg-white dark:text-stone-900'
                  : 'text-stone-500 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white'
              )}
            >
              <Icon />
            </button>
          ))}
        </div>
        {barSep}
        <Button
          size="sm"
          variant="ghost"
          onClick={toggleShow}
          aria-pressed={showOnLights}
          title={lightsTitle}
          className={cn(previewing && previewDevices.length && 'text-emerald-700 dark:text-emerald-400')}
        >
          {showOnLights ? <Lightbulb /> : <LightbulbOff />}
          <span className="max-w-48 truncate">{lightsLabel}</span>
        </Button>
        {barSep}
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setPlaying((v) => !v)}
          disabled={!fxCount}
          aria-pressed={playing}
          title={fxCount ? `${playing ? 'Stop' : 'Play'} the effects (P)` : 'Select an object and pick an effect for it first'}
          className={cn(playing && 'text-sky-700 dark:text-sky-300')}
        >
          {playing ? <Pause /> : <Play />} {playing ? 'Stop effects' : 'Play effects'}
        </Button>
        <Button size="sm" variant="ghost" onClick={scenesMenu} disabled={busy} title="Save the effects as a scene for the public page, or open a scene to change it">
          <Clapperboard />
          <span className="max-w-40 truncate">{editingScene ? editingScene.name : 'Scenes'}</span>
          <ChevronDown />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={picturesMenu}
          disabled={busy}
          title="Pictures to trace over: the front of the house (a photo or a Street View screenshot), and the yard from above (a satellite view screenshot)"
        >
          {layout.background || layout.aerial ? <Images /> : <ImagePlus />} Pictures
          <ChevronDown />
        </Button>
        <input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => (upload(e.target.files?.[0]), (e.target.value = ''))} />
        <input ref={aerialInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => (uploadAerial(e.target.files?.[0]), (e.target.value = ''))} />
        <span className="ml-auto" />
        <Button size="sm" variant="ghost" onClick={() => (edit(() => saved!), setSelected(null))} disabled={!dirty || busy} title="Go back to the saved layout">
          <RotateCcw /> Revert
        </Button>
        <Button size="sm" variant="primary" onClick={save} disabled={!dirty || overlapCount > 0} loading={busy} title="Save the layout (Ctrl/⌘+S)">
          <Save /> Save
        </Button>
      </div>

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        {/* Tools */}
        <div
          role="toolbar"
          aria-label="Tools"
          className="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-stone-200 bg-stone-50 p-1 lg:flex-col lg:overflow-visible lg:border-r lg:border-b-0 dark:border-stone-800 dark:bg-stone-900"
        >
          {toolButton('select', MousePointer2)}
          {toolButton('edit', PenTool)}
          {toolButton('split', Scissors)}
          {toolButton('pan', Hand)}
          {toolSep}
          {toolButton('roof', House)}
          {toolButton('line', Spline)}
          {toolButton('bush', Circle)}
          {toolButton('tree', TreePine)}
          <button
            type="button"
            onClick={() => setLibrary(true)}
            title="Custom object: a star, a wreath, an arch… (O)"
            aria-label="Custom object"
            aria-keyshortcuts="O"
            className="relative grid size-9 shrink-0 place-items-center rounded-lg text-stone-600 transition hover:bg-stone-200/70 hover:text-stone-950 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white [&_svg]:size-[18px]"
          >
            <Shapes />
            <kbd className="pointer-events-none absolute right-0.5 bottom-0 font-sans text-[9px] leading-none font-semibold opacity-60">O</kbd>
          </button>
          {toolSep}
          {toolButton('measure', Ruler)}
          {toolSep}
          <button
            type="button"
            onClick={() => frameSelection()}
            title={sel ? `Zoom to ${sel.name} (F)` : 'Zoom to fit (F or Home)'}
            aria-label="Zoom to fit"
            className="relative grid size-9 shrink-0 place-items-center rounded-lg text-stone-600 transition hover:bg-stone-200/70 hover:text-stone-950 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white [&_svg]:size-[18px]"
          >
            <Scan />
            <kbd className="pointer-events-none absolute right-0.5 bottom-0 font-sans text-[9px] leading-none font-semibold opacity-60">F</kbd>
          </button>
        </div>

        {/* Viewports */}
        <div className="relative min-h-0 min-w-0 flex-1">
          <div className={cn('grid gap-px bg-stone-300 lg:h-full dark:bg-stone-800', gridClass)}>
            {shown.map((v, i) => (
              <div key={v} className={cn('flex h-[55dvh] min-h-0 min-w-0 flex-col bg-[#05070f] lg:h-auto', viewport.mode === 'three' && !single && i === 0 && 'lg:row-span-2')}>
                {paneHeader(v)}
                {v === '3d' ? (
                  <div className="relative min-h-0 flex-1">
                    <Suspense
                      fallback={
                        <div className="absolute inset-0 grid place-items-center bg-[#05070f]">
                          <Spinner />
                        </div>
                      }
                    >
                      <Scene3D
                        fill
                        layout={layout}
                        getFrame={getFrame}
                        selected={playing ? null : selected}
                        onSelect={(id, add) => {
                          setTool('select');
                          if (add) return void (id && toggleTarget(id));
                          setSelected(id);
                        }}
                      />
                    </Suspense>
                  </div>
                ) : (
                  <PaneBody onSize={(w, h) => setPaneSize((p) => (p[v]?.w === w && p[v]?.h === h ? p : { ...p, [v]: { w, h } }))} onWheel={(e, r) => onWheel(v, e, r)}>
                    {renderView(v)}
                  </PaneBody>
                )}
              </div>
            ))}
          </div>

          {/* The command line: what the line tool or the measure tool needs next. */}
          {drawing || (tool === 'measure' && tapeLength != null) || tool === 'align' ? (
            <div className="pointer-events-none absolute inset-x-0 bottom-3 z-10 flex justify-center px-3">
              <div className="pointer-events-auto">
                {drawing && isLineTool(tool) ? (
                  <div className="flex flex-wrap items-center gap-2 rounded-xl bg-stone-900/90 px-3 py-1.5 text-xs text-white shadow-lg ring-1 ring-white/10 backdrop-blur">
                    <span>
                      {draft.cont ? `Adding to ${layout.fixtures.find((f) => f.id === draft.cont!.id)?.name ?? 'the line'}` : `New ${TOOL_LABELS[tool].toLowerCase()}`}:{' '}
                      <span className="tabular-nums">{draft.pts.length}</span> point(s)
                    </span>
                    <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10" onClick={() => setDraft((d) => ({ ...d, pts: d.pts.slice(0, -1) }))} title="Backspace">
                      Remove last point
                    </button>
                    <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10" onClick={() => setDraft((d) => ({ side: d.side, pts: [] }))}>
                      Cancel
                    </button>
                    {draft.pts.length >= 2 ? (
                      <button type="button" className="rounded-md bg-sky-600 px-2.5 py-1 font-semibold hover:bg-sky-500" onClick={() => finishLine(tool)} title="Enter">
                        Finish line
                      </button>
                    ) : null}
                  </div>
                ) : tool === 'align' ? (
                  <div className="flex flex-wrap items-center gap-2 rounded-xl bg-stone-900/90 px-3 py-1.5 text-xs text-white shadow-lg ring-1 ring-white/10 backdrop-blur">
                    <span className="max-w-[34rem]">{layout.aerial ? ALIGN_STEPS[alignPts.length] : 'Add a picture from above first (Pictures menu).'}</span>
                    {alignPts.length ? (
                      <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10" onClick={() => setAlignPts((a) => a.slice(0, -1))} title="Backspace">
                        Undo last click
                      </button>
                    ) : null}
                    {alignPts.length === 2 ? (
                      <button type="button" className="rounded-md bg-teal-600 px-2.5 py-1 font-semibold hover:bg-teal-500" onClick={() => finishAlign(alignPts)} title="Enter">
                        Just move it
                      </button>
                    ) : null}
                    <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10" onClick={() => chooseTool('select')} title="Esc">
                      Done
                    </button>
                  </div>
                ) : tapeLength != null ? (
                  <MeasureBar
                    length={tapeLength}
                    m={m}
                    onPicture={
                      tape?.side === 'top' && layout.aerial
                        ? (meters) => {
                            const a = layout.aerial!;
                            updateLayout({ aerial: scaleAerial(a, toXZ(tape.a), (meters * scale) / tapeLength) });
                            setTape(null);
                            toast.success(`Picture scaled: what you measured is now ${meters * (m.units === 'm' ? 1 : FEET_PER_METER)} ${m.units}.`);
                          }
                        : undefined
                    }
                    onScale={(meters) => {
                      updateLayout({ scale: Math.round((tapeLength / meters) * 1000) / 1000 });
                      setTape(null);
                      toast.success(`Scale set: ${m.text(tapeLength)} is now ${meters * (m.units === 'm' ? 1 : FEET_PER_METER)} ${m.units}.`);
                    }}
                  />
                ) : null}
              </div>
            </div>
          ) : null}
        </div>

        {/* The side panel: the object list, and the properties of the selection. */}
        <aside className="flex shrink-0 flex-col border-stone-200 bg-white text-sm lg:w-80 lg:border-l dark:border-stone-800 dark:bg-stone-900">
          <div className="flex flex-col border-b border-stone-200 lg:max-h-[40%] lg:min-h-32 dark:border-stone-800">
            <div className="flex h-8 shrink-0 items-center justify-between gap-2 border-b border-stone-100 px-3 dark:border-stone-800">
              <span className="text-[11px] font-semibold tracking-wide text-stone-600 uppercase dark:text-stone-400">Objects</span>
              <span className="text-[11px] text-stone-500 tabular-nums">
                {layout.fixtures.length} · {totals} LEDs
              </span>
            </div>
            {layout.fixtures.length ? (
              <ul role="listbox" aria-label="Objects" className="min-h-0 flex-1 overflow-y-auto py-1">
                {layout.fixtures.map((f, i) => {
                  const Icon = KIND_ICONS[f.kind];
                  const on = selected === f.id || multi.includes(f.id);
                  const partly = !on && multi.some((x) => effectTarget(x).id === f.id);
                  return (
                    <li
                      key={f.id}
                      role="option"
                      aria-selected={on}
                      title={partly ? 'Some of its segments are selected' : undefined}
                      onClick={(e) => {
                        if (tool !== 'select') chooseTool('select');
                        if (e.ctrlKey || e.metaKey) {
                          toggleTarget(f.id);
                        } else if (e.shiftKey && listAnchor.current) {
                          // A range, from the item clicked before to this one.
                          const ids = layout.fixtures.map((x) => x.id);
                          const a = ids.indexOf(listAnchor.current);
                          const b = ids.indexOf(f.id);
                          if (a >= 0) return pickTargets(ids.slice(Math.min(a, b), Math.max(a, b) + 1));
                          setSelected(f.id);
                        } else setSelected(f.id);
                        listAnchor.current = f.id;
                      }}
                      onMouseDown={(e) => e.shiftKey && e.preventDefault()}
                      onDoubleClick={() => setRenaming(f.id)}
                      onContextMenu={(e) => objectMenu(e, f)}
                      className={cn(
                        'mx-1 flex h-7 cursor-default items-center gap-2 rounded-md px-2 text-[13px]',
                        on
                          ? 'bg-sky-600 text-white'
                          : partly
                            ? 'bg-sky-600/15 text-stone-900 dark:text-white'
                            : 'text-stone-800 hover:bg-stone-100 dark:text-stone-200 dark:hover:bg-stone-800'
                      )}
                    >
                      <Icon className="size-3.5 shrink-0" style={{ color: on ? undefined : `rgb(${hsvBytes(HUES[i % HUES.length], 1).join(',')})` }} />
                      {renaming === f.id ? (
                        <RenameInput value={f.name} onDone={(name) => (setRenaming(null), name != null && name.trim() && update(f.id, { name: name.trim() }))} />
                      ) : (
                        <span className="min-w-0 flex-1 truncate">{f.name}</span>
                      )}
                      <span className={cn('text-[11px] tabular-nums', on ? 'text-white/80' : 'text-stone-500')}>
                        {ledRange(f).first}–{ledRange(f).last}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="px-3 py-4 text-xs text-stone-500">Nothing yet. Draw the roofline first: press R, then click along the roof.</p>
            )}
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            {sel && SelIcon ? (
              <>
                <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-stone-200 bg-white px-3 py-2 dark:border-stone-800 dark:bg-stone-900">
                  <SelIcon className="size-4 shrink-0 text-stone-500" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[13px] font-semibold">{sel.name}</p>
                    <p className="truncate text-[11px] text-stone-500">
                      {KIND_LABELS[sel.kind]}
                      {isLine(sel) && segment != null ? ` · segment ${segment + 1} of ${sel.points.length - 1}` : ''}
                      {isLine(sel) && segment == null && corner != null ? ` · ${pointName(sel, corner)}` : ''}
                    </p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => frameSelection()} title="Zoom to this object (F)" aria-label="Zoom to this object" className="px-2">
                    <Scan />
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => remove(sel.id)} title="Delete this object (Delete)" aria-label="Delete this object" className="px-2 hover:text-red-600">
                    <Trash2 />
                  </Button>
                </div>

                {isLine(sel) && segment != null && segment < sel.points.length - 1 ? (
                  <PropSection
                    key="segment"
                    id="segment"
                    title={`Segment ${segment + 1}`}
                    actions={
                      <div className="flex">
                        <button
                          type="button"
                          className="grid size-6 place-items-center rounded text-stone-500 hover:bg-stone-100 disabled:opacity-30 dark:hover:bg-stone-800 [&_svg]:size-3.5"
                          onClick={() => setSegment(segment - 1)}
                          disabled={segment === 0}
                          aria-label="Previous segment"
                          title="Previous segment"
                        >
                          <ChevronLeft />
                        </button>
                        <button
                          type="button"
                          className="grid size-6 place-items-center rounded text-stone-500 hover:bg-stone-100 disabled:opacity-30 dark:hover:bg-stone-800 [&_svg]:size-3.5"
                          onClick={() => setSegment(segment + 1)}
                          disabled={segment >= sel.points.length - 2}
                          aria-label="Next segment"
                          title="Next segment"
                        >
                          <ChevronRight />
                        </button>
                      </div>
                    }
                  >
                    <SegmentProps
                      f={sel}
                      index={segment}
                      onPoint={(point, led) => update(sel.id, setPointLed(sel, point, led, allPoints(sel)))}
                      onToggle={(on) =>
                        update(sel.id, {
                          skip: nonEmpty(on ? sel.skip?.filter((x) => x !== segment) : [...(sel.skip ?? []), segment].sort((a, b) => a - b))
                        })
                      }
                      onClose={() => setSegment(null)}
                      lights={lightsOf(layout, sel.lights)}
                      length={lineLengths(sel)[segment] ?? 0}
                      scale={scale}
                      m={m}
                      onResize={(count) => update(sel.id, resizeSegment(sel, segment, count))}
                    />
                  </PropSection>
                ) : null}

                {isLine(sel) && segment != null && segment < sel.points.length - 1 ? (
                  <PropSection
                    key="segment-effect"
                    id="segment-effect"
                    title={sel.segmentEffects?.[segment] ? `Segment ${segment + 1} effect · ${EFFECT_NAMES[sel.segmentEffects[segment].effect]}` : `Segment ${segment + 1} effect`}
                  >
                    <EffectProps
                      effect={sel.segmentEffects?.[segment]}
                      objectCount={sel.points.length - 1}
                      noneLabel={sel.effect ? `Same as the line (${EFFECT_NAMES[sel.effect.effect]})` : 'Same as the line (dark)'}
                      copyLabel="Use on every segment"
                      copyTitle="Every segment of this line plays this effect on its own"
                      emptyNote={
                        sel.skip?.includes(segment)
                          ? 'This segment is off (skipped): it stays dark, whatever its effect.'
                          : 'This segment plays the whole line’s effect. Pick an effect to give it its own: it runs from the segment’s first LED to its last, and the line’s effect fills the rest.'
                      }
                      onChange={(effect) => {
                        update(sel.id, { segmentEffects: setSegmentEffect(sel.segmentEffects, segment, effect) });
                        if (effect && !sel.segmentEffects?.[segment]) setPlaying(true);
                      }}
                      onCopyToAll={() => {
                        const fx = sel.segmentEffects?.[segment];
                        update(sel.id, { segmentEffects: fx ? Object.fromEntries(sel.points.slice(1).map((_, k) => [k, fx])) : undefined });
                        setPlaying(true);
                      }}
                    />
                  </PropSection>
                ) : null}

                {isLine(sel) && segment == null && corner != null && corner > 0 && corner < sel.points.length - 1 ? (
                  <PropSection key="corner" id="corner" title={`Corner ${corner}`}>
                    <CornerProps f={sel} index={corner} onPin={(led) => pinCorner(sel, corner, led)} onSplit={() => splitAt(sel, corner)} />
                  </PropSection>
                ) : null}

                <PropSection key="object" id="object" title="Object">
                  <PropText label="Name" value={sel.name} maxLength={60} onChange={(name) => update(sel.id, { name })} />
                  {isLine(sel) ? (
                    <PropSelect<FixtureKind>
                      label="Kind"
                      hint="Games run along the roofline. Other lines (windows, doors, a fence, a path) are for animations."
                      value={sel.kind}
                      options={[
                        ['roof', 'Roofline'],
                        ['line', 'Other line of lights']
                      ]}
                      onChange={(kind) => update(sel.id, { kind })}
                    />
                  ) : null}
                  <PropSelect
                    label="WLED device"
                    hint="The device that drives these LEDs."
                    value={sel.deviceId ?? ''}
                    options={[['', 'Simulation only'], ...devices.map((d): [string, string] => [d.id, `${d.name}${d.info?.leds?.count ? ` (${d.info.leds.count} LEDs)` : ''}`])]}
                    onChange={(id) => update(sel.id, { deviceId: id || null })}
                  />
                  {isLine(sel) && sel.points.length > 2 && segment == null && corner == null ? (
                    <PropNote>Click one segment of the line to set its first and last LED. Click a corner to pin it, or to split the line there.</PropNote>
                  ) : null}
                </PropSection>

                <PropSection
                  key="effect"
                  id="effect"
                  title={`${isLine(sel) && segment != null ? 'Whole line effect' : 'Effect'}${sel.effect ? ` · ${EFFECT_NAMES[sel.effect.effect]}` : ''}`}
                >
                  <EffectProps
                    effect={sel.effect}
                    objectCount={layout.fixtures.length}
                    onChange={(effect) => {
                      update(sel.id, { effect });
                      if (effect && !sel.effect) setPlaying(true);
                    }}
                    onCopyToAll={() => {
                      const fx = sel.effect;
                      edit((l) => ({ ...l, fixtures: l.fixtures.map((f) => ({ ...f, effect: fx })) }));
                      setPlaying(true);
                    }}
                  />
                </PropSection>

                {sel.kind === 'custom' ? (
                  <PropSection key="design" id="design" title="Design">
                    <CustomProps
                      layout={layout}
                      f={sel}
                      lenText={m.text}
                      onChange={(patch) => update(sel.id, patch)}
                      onEditDesign={() => {
                        const d = layout.designs?.find((x) => x.id === sel.designId);
                        setDesigning(d ?? { id: uid(), name: sel.name, strokes: sel.design ?? [], pixels: sel.pixels, lights: sel.lights });
                      }}
                    />
                  </PropSection>
                ) : null}

                <PropSection key="lights" id="lights" title={`Made of${lightsOf(layout, sel.lights) ? ` · ${lightsOf(layout, sel.lights)!.name}` : ''}`}>
                  <LightsProps
                    layout={layout}
                    f={sel}
                    lenText={m.text}
                    onPick={(id) => pickLights(sel.id, id)}
                    onNew={() => setLightEdit({ type: null, forObject: sel.id })}
                    onEdit={(lt) => setLightEdit({ type: lt })}
                    onFit={(pixels) => update(sel.id, { pixels, pointLeds: undefined })}
                  />
                </PropSection>

                <PropSection key="leds" id="leds" title="LEDs">
                  <LedProps f={sel} onRange={(a, b) => setRange(sel, a, b)} />
                </PropSection>

                <PropSection key="position" id="position" title={isLine(sel) && corner != null && sel.points[corner] ? `Position of ${pointName(sel, corner)}` : 'Position'}>
                  <PositionProps f={sel} point={corner} m={m} ground={ground} onChange={(patch) => update(sel.id, patch)} />
                </PropSection>

                {!isLine(sel) && sel.kind !== 'custom' ? (
                  <PropSection key="shape" id="shape" title="Shape">
                    <PropDistance label="Width" value={(sel.radius ?? 60) * 2} m={m} min={0.1} onChange={(lu) => update(sel.id, { radius: Math.max(5, Math.round(lu / 2)) })} />
                    {sel.kind === 'tree' ? <PropDistance label="Height" value={sel.height ?? 240} m={m} min={0.1} onChange={(lu) => update(sel.id, { height: Math.max(5, Math.round(lu)) })} /> : null}
                    {sel.kind === 'bush' ? (
                      <PropSelect<NonNullable<Fixture['pattern']>>
                        label="LED pattern"
                        value={sel.pattern ?? 'fill'}
                        options={[
                          ['fill', 'Net over the bush'],
                          ['ring', 'Ring around the edge'],
                          ['spiral', 'Spiral from the middle']
                        ]}
                        onChange={(pattern) => update(sel.id, { pattern })}
                      />
                    ) : (
                      <>
                        <PropSelect<NonNullable<Fixture['pattern']>>
                          label="LED pattern"
                          hint={
                            sel.pattern === 'strands'
                              ? 'Strands run from the base to the top. They zigzag: LED 0 is at the base of the front strand, which goes up; the next strand comes down.'
                              : 'LED 0 is at the base, at the front; the spiral goes up to the top.'
                          }
                          value={sel.pattern === 'strands' ? 'strands' : 'spiral'}
                          options={[
                            ['spiral', 'Spiral around the tree'],
                            ['strands', 'Strands, base to top']
                          ]}
                          onChange={(pattern) => update(sel.id, { pattern })}
                        />
                        {sel.pattern === 'strands' ? (
                          <PropNumber label="Strands" value={sel.strands ?? 12} min={1} max={64} onChange={(n) => update(sel.id, { strands: Math.round(n) })} />
                        ) : (
                          <PropNumber
                            label="Turns"
                            hint="Turns of the spiral from the base to the top"
                            decimal
                            value={sel.turns ?? 8}
                            min={0.5}
                            max={100}
                            step={0.5}
                            onChange={(n) => update(sel.id, { turns: n })}
                          />
                        )}
                      </>
                    )}
                    <PropNote>{sel.kind === 'tree' ? 'The point is the middle of the base.' : 'The point is the middle of the bush, as seen from the front.'}</PropNote>
                  </PropSection>
                ) : null}
              </>
            ) : multiItems.length >= 2 ? (
              <>
                <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-stone-200 bg-white px-3 py-2 dark:border-stone-800 dark:bg-stone-900">
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-semibold">{multiItems.length} selected</p>
                    <p className="truncate text-[11px] text-stone-500">Ctrl/⌘-click to add or remove. Esc to clear.</p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => setMulti([])} title="Clear the selection (Esc)" aria-label="Clear the selection" className="px-2">
                    <X />
                  </Button>
                </div>
                <PropSection key="multi-items" id="multi-items" title="Selection">
                  <ul className="space-y-0.5">
                    {multiItems.map((it) => (
                      <li key={it.key} className="group flex items-center gap-2 rounded px-1 py-0.5 text-xs hover:bg-stone-100 dark:hover:bg-stone-800">
                        <button type="button" className="min-w-0 flex-1 truncate text-left" title="Select only this" onClick={() => pickTargets([it.key])}>
                          {it.name}
                        </button>
                        <span className="text-stone-500">{it.effect ? EFFECT_NAMES[it.effect.effect] : '—'}</span>
                        <button
                          type="button"
                          aria-label={`Remove ${it.name} from the selection`}
                          title="Remove from the selection"
                          onClick={() => toggleTarget(it.key)}
                          className="grid size-5 place-items-center rounded text-stone-400 opacity-0 group-hover:opacity-100 hover:text-stone-900 dark:hover:text-white [&_svg]:size-3"
                        >
                          <X />
                        </button>
                      </li>
                    ))}
                  </ul>
                </PropSection>
                <PropSection key="multi-effect" id="multi-effect" title={`Effect${multiShown ? ` · ${EFFECT_NAMES[multiShown.effect]}` : ''}`}>
                  {multiMixed ? (
                    <PropNote>They play different effects now. The settings below are the first one’s. A setting you change goes to each of them; a new effect replaces them all.</PropNote>
                  ) : null}
                  <EffectProps
                    effect={multiShown}
                    objectCount={multiItems.length}
                    noneLabel="None"
                    emptyNote="Pick an effect: every selected object and segment gets it. A segment plays its own copy; the rest of its line keeps the line’s effect."
                    onChange={(next) => {
                      setMultiEffect(next, multiShown);
                      if (next) setPlaying(true);
                    }}
                  />
                </PropSection>
              </>
            ) : (
              <>
                <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-stone-200 bg-white px-3 py-2 dark:border-stone-800 dark:bg-stone-900">
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-semibold">Yard</p>
                    <p className="text-[11px] text-stone-500">Nothing selected. Click an object to see its properties.</p>
                  </div>
                </div>
                <PropSection key="yardfx" id="yardfx" title="Whole yard effect">
                  <EffectProps
                    effect={layout.effect}
                    objectCount={0}
                    noneLabel="None"
                    emptyNote="An effect for every object at once. A 3-D effect plays over the whole yard as one picture; a 1-D effect runs along each object. Objects and segments with their own effect play theirs instead."
                    onChange={(effect) => {
                      updateLayout({ effect });
                      if (effect) setPlaying(true);
                    }}
                  />
                </PropSection>
                <PropSection key="scene" id="scene" title="Effects and scenes">
                  {fxCount ? (
                    <ul className="space-y-0.5">
                      {layout.effect ? (
                        <li className="flex items-center gap-2 px-1 py-0.5 text-xs">
                          <span className="min-w-0 flex-1 truncate font-medium">Whole yard</span>
                          <span className="text-stone-500">{EFFECT_NAMES[layout.effect.effect]}</span>
                        </li>
                      ) : null}
                      {layout.fixtures.flatMap((f) => {
                        const rows: { key: string; name: string; fx: EffectSettings; seg: number | null }[] = [];
                        if (f.effect) rows.push({ key: f.id, name: f.name, fx: f.effect, seg: null });
                        if (isLine(f))
                          for (const [k, fx] of Object.entries(f.segmentEffects ?? {}).sort(([a], [b]) => Number(a) - Number(b)))
                            if (Number(k) < f.points.length - 1) rows.push({ key: `${f.id}#${k}`, name: `${f.name} · segment ${Number(k) + 1}`, fx, seg: Number(k) });
                        return rows.map((r) => (
                          <li key={r.key}>
                            <button
                              type="button"
                              onClick={(e) => (e.ctrlKey || e.metaKey ? toggleTarget(r.key) : r.seg == null ? setSelected(f.id) : selectSegment(f.id, r.seg))}
                              className={cn('flex w-full items-center gap-2 rounded px-1 py-0.5 text-left text-xs hover:bg-stone-100 dark:hover:bg-stone-800', r.seg != null && 'pl-4')}
                            >
                              <span className="min-w-0 flex-1 truncate">{r.name}</span>
                              <span className="text-stone-500">{EFFECT_NAMES[r.fx.effect]}</span>
                            </button>
                          </li>
                        ));
                      })}
                    </ul>
                  ) : (
                    <PropNote>No object has an effect yet. Select an object, then pick an effect in its Effect section.</PropNote>
                  )}
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    <PropButton onClick={() => setPlaying((v) => !v)} disabled={!fxCount}>
                      {playing ? <Pause /> : <Play />} {playing ? 'Stop' : 'Play'}
                    </PropButton>
                    {editingScene ? (
                      <PropButton onClick={() => void saveScene({ id: editingScene.id })} disabled={!fxCount || busy}>
                        <Save /> Save “{editingScene.name}”
                      </PropButton>
                    ) : null}
                    <PropButton onClick={() => setNewScene('')} disabled={!fxCount || busy}>
                      <Clapperboard /> Save as a new scene
                    </PropButton>
                  </div>
                  <PropNote>A scene plays these effects on the real lights when it is picked on the public page, until another scene or color is chosen.</PropNote>
                </PropSection>
                <YardProps layout={layout} m={m} onChange={updateLayout} onMeasure={() => (chooseTool('measure'), setTape(null))} />
                {layout.aerial ? (
                  <AerialProps
                    aerial={layout.aerial}
                    m={m}
                    onChange={(patch) => updateLayout({ aerial: { ...layout.aerial!, ...patch } })}
                    onAlign={() => startAlign()}
                    onMeasure={() => (chooseTool('measure'), setTape(null))}
                    onRemove={() => void removeAerial()}
                  />
                ) : null}
                <PropSection key="lightstrings" id="lightstrings" title="Light strings">
                  <LightSelect
                    layout={layout}
                    label="New objects"
                    value={layout.lights}
                    hint="What new lines, bushes, trees and custom objects are made of"
                    onChange={(lights) => updateLayout({ lights })}
                    onNew={() => setLightEdit({ type: null })}
                  />
                  {newLights ? (
                    <PropNote>
                      New lines get as many LEDs as fit at {spacingText(newLights.spacing, m.units)} apart; while you draw, each segment shows its length and LEDs.
                    </PropNote>
                  ) : (
                    <PropNote>Pick the light string you use most. New objects are made of it, and lines you draw get the right number of LEDs.</PropNote>
                  )}
                  {layout.lightTypes?.length ? (
                    <ul className="space-y-0.5 pt-1">
                      {layout.lightTypes.map((lt) => (
                        <li key={lt.id}>
                          <button type="button" onClick={() => setLightEdit({ type: lt })} className="flex w-full items-center gap-2 rounded px-1 py-0.5 text-left text-xs hover:bg-stone-100 dark:hover:bg-stone-800">
                            <span className="min-w-0 flex-1 truncate">{lt.name}</span>
                            <span className="text-stone-500">{layout.fixtures.filter((f) => f.lights === lt.id).length} objects</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  <div className="pt-1">
                    <PropButton onClick={() => setLightEdit({ type: null })}>
                      <Plus /> New light type
                    </PropButton>
                  </div>
                </PropSection>
                <PropSection key="library" id="library" title="Custom objects">
                  <LibraryList layout={layout} onPlace={(d) => placeDesign(d)} onEdit={setDesigning} onDuplicate={duplicateDesign} onDelete={deleteDesign} />
                  <div className="pt-1">
                    <PropButton onClick={newDesign}>
                      <Plus /> New custom object
                    </PropButton>
                  </div>
                </PropSection>
                {runs.size ? (
                  <PropSection key="devices" id="devices" title="LEDs per device">
                    <div className="space-y-4">
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
                  </PropSection>
                ) : null}
                <PropSection key="keys" id="keys" title="Keyboard and mouse" defaultOpen={false}>
                  <Shortcuts />
                </PropSection>
              </>
            )}
          </div>
        </aside>
      </div>

      {/* The status bar: the tool and what it needs, the pointer position, and the drafting switches. */}
      <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-t border-stone-200 bg-stone-50 px-3 py-1 text-[11px] text-stone-500 lg:h-7 lg:flex-nowrap lg:py-0 dark:border-stone-800 dark:bg-stone-900 dark:text-stone-400">
        <span className="font-semibold text-stone-700 dark:text-stone-200">{TOOL_LABELS[tool]}</span>
        <span className="min-w-0 flex-1 lg:truncate" title={hint}>
          {hint}
        </span>
        <span className="flex w-52 shrink-0 gap-3 tabular-nums" aria-live="off">
          {coords ? coords.map(([l, v]) => <span key={l}>{`${l} ${v}`}</span>) : <span className="opacity-60">Pointer outside the views</span>}
        </span>
        <span className="flex shrink-0 items-center gap-1">
          {(
            [
              ['snap', 'Snap', 'Snap to points, midpoints, lines and alignments (Alt: the other way)'],
              ['ortho', 'Ortho', 'Keep lines level or upright (Shift: 45° steps)'],
              ['grid', 'Grid', 'Show the grid']
            ] as [keyof Drafting, string, string][]
          ).map(([key, label, title]) => (
            <button
              key={key}
              type="button"
              title={title}
              aria-pressed={drafting[key]}
              onClick={() => setDrafting({ [key]: !drafting[key] })}
              className={cn(
                'rounded px-1.5 py-0.5 font-semibold tracking-wide uppercase transition',
                drafting[key] ? 'bg-sky-600/15 text-sky-700 dark:bg-sky-400/15 dark:text-sky-300' : 'text-stone-400 hover:text-stone-700 dark:text-stone-600 dark:hover:text-stone-300'
              )}
            >
              {label}
            </button>
          ))}
        </span>
      </div>
      {menu ? <ContextMenu menu={menu} onClose={() => setMenu(null)} /> : null}
      <Dialog
        open={library}
        onClose={() => setLibrary(false)}
        title="Custom objects"
        description="Your own shapes, laid out the way the light string really runs. Place one in the yard as often as you like; changing a design changes every copy."
        footer={
          <>
            <Button onClick={() => setLibrary(false)}>Close</Button>
            <Button variant="primary" onClick={() => (setLibrary(false), newDesign())}>
              <Plus /> New custom object
            </Button>
          </>
        }
      >
        <div className="pb-2">
          <LibraryList
            layout={layout}
            onPlace={(d) => placeDesign(d)}
            onEdit={(d) => (setLibrary(false), setDesigning(d))}
            onDuplicate={(d) => (setLibrary(false), duplicateDesign(d))}
            onDelete={deleteDesign}
          />
        </div>
      </Dialog>
      {designing ? (
        <DesignEditor
          open
          initial={designing}
          layout={layout}
          usedBy={layout.fixtures.filter((f) => f.designId === designing.id).length}
          onSave={saveDesign}
          onClose={() => setDesigning(null)}
        />
      ) : null}
      <LightTypeDialog
        open={lightEdit != null}
        initial={lightEdit?.type ?? null}
        units={m.units}
        usedBy={lightEdit?.type ? layout.fixtures.filter((f) => f.lights === lightEdit.type!.id).length : 0}
        onSave={(lt) => saveLightType(lt, lightEdit?.forObject)}
        onDelete={deleteLightType}
        onClose={() => setLightEdit(null)}
      />
      <Dialog
        open={newScene != null}
        onClose={() => setNewScene(null)}
        size="sm"
        title="Save as a new scene"
        description={`These ${fxCount} effect(s) become a scene: a button on the public page.${dirty ? ' The layout is saved too.' : ''}`}
        footer={
          <>
            <Button onClick={() => setNewScene(null)}>Cancel</Button>
            <Button variant="primary" loading={busy} disabled={!newScene?.trim()} onClick={() => newScene?.trim() && void saveScene({ name: newScene.trim() })}>
              Create scene
            </Button>
          </>
        }
      >
        <form
          className="pb-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (newScene?.trim()) void saveScene({ name: newScene.trim() });
          }}
        >
          <Field label="Name" hint="Shown on the public page.">
            {(id) => <Input id={id} value={newScene ?? ''} onChange={(e) => setNewScene(e.target.value)} placeholder="For example: Winter Wonderland" autoFocus maxLength={100} />}
          </Field>
        </form>
      </Dialog>
    </div>
  );
}

/** Sets or clears the effect of segment k. */
function setSegmentEffect(fx: Fixture['segmentEffects'], k: number, effect: EffectSettings | undefined): Fixture['segmentEffects'] {
  const next = { ...fx };
  if (effect) next[k] = effect;
  else delete next[k];
  return Object.keys(next).length ? next : undefined;
}

const EFFECT_NAMES = Object.fromEntries(EFFECTS.map((e) => [e.id, e.name])) as Record<EffectId, string>;

/** After two points are measured: type the real distance between them to set the scale. */
function MeasureBar({ length, m, onScale, onPicture }: { length: number; m: Measure; onScale: (meters: number) => void; onPicture?: (meters: number) => void }) {
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
      {/* Input is full width and 2.5rem high: the wrapper and the style size it. */}
      <div className="w-20 shrink-0">
        <Input inputMode="decimal" value={real} onChange={(e) => setReal(e.target.value.replace(/[^\d.]/g, ''))} style={{ height: '2rem' }} className="px-2" aria-label={`Real distance in ${m.units}`} />
      </div>
      <span>{m.units}</span>
      <Button size="sm" type="submit" variant="primary" disabled={!ok} title="Make the whole yard this size">
        Set scale
      </Button>
      {onPicture ? (
        <Button size="sm" type="button" disabled={!ok} onClick={() => onPicture(m.units === 'm' ? n : n / FEET_PER_METER)} title="Scale only the picture from above, about the first point">
          Scale the picture
        </Button>
      ) : null}
    </form>
  );
}

/** What the Align tool needs next, by the number of clicks so far. */
const ALIGN_STEPS = [
  'Step 1 of 4: click a spot on the picture, for example a front corner of the house.',
  'Step 2 of 4: click where that spot really is in the yard, for example the end of the roofline. Snapping helps.',
  'Step 3 of 4: click a second spot on the picture, far from the first: the other front corner. Or press Enter to just move it.',
  'Step 4 of 4: click where that second spot really is. The picture moves, turns and resizes to fit both.'
];

/** The picture from above: where it lies, how big, turned how far, and how strong. */
function AerialProps({
  aerial,
  m,
  onChange,
  onAlign,
  onMeasure,
  onRemove
}: {
  aerial: AerialPicture;
  m: Measure;
  onChange: (patch: Partial<AerialPicture>) => void;
  onAlign: () => void;
  onMeasure: () => void;
  onRemove: () => void;
}) {
  return (
    <PropSection key="aerial" id="aerial" title="Picture from above">
      <PropRow label="Line up">
        <div className="flex flex-wrap gap-1.5">
          <PropButton onClick={onAlign} title="Click two spots on the picture and where each one really is">
            <Move /> Align
          </PropButton>
          <PropButton onClick={onMeasure} title="Measure something on the picture in the top view, then type its real size">
            <Ruler /> Measure
          </PropButton>
        </div>
      </PropRow>
      <PropSlider label="Strength" value={aerial.opacity ?? AERIAL_OPACITY} onChange={(opacity) => onChange({ opacity: Math.round(opacity * 100) / 100 })} hint="0 hides it" />
      <PropDistance label="Width" value={aerial.width} m={m} min={0.1} onChange={(width) => onChange({ width: Math.max(10, Math.round(width * 100) / 100) })} />
      <PropNumber label="Turned" value={aerial.rotation} decimal min={-360} max={360} step={0.5} unit="°" onChange={(rotation) => onChange({ rotation })} hint="Clockwise, seen from above" />
      <PropDistance label="Middle, across" value={aerial.x} m={m} onChange={(x) => onChange({ x: Math.round(x * 100) / 100 })} />
      <PropDistance label="Middle, depth" value={aerial.z} m={m} onChange={(z) => onChange({ z: Math.round(z * 100) / 100 })} hint="From the front wall; toward the street is more" />
      <PropRow label="">
        <PropButton danger onClick={onRemove}>
          <Trash2 /> Remove picture
        </PropButton>
      </PropRow>
      <PropNote>
        A satellite view screenshot works well (Google Maps: Satellite, zoomed in, the street at the bottom). Align it to the roofline: a front corner of the house on the picture, then the end of the
        roofline in the top view, and the same for the other corner.
      </PropNote>
    </PropSection>
  );
}

/** Units, scale and ground for the whole yard: the properties when nothing is selected. */
function YardProps({ layout, m, onChange, onMeasure }: { layout: Layout; m: Measure; onChange: (patch: Partial<Layout>) => void; onMeasure: () => void }) {
  return (
    <PropSection key="yard" id="yard" title="Yard size">
      <PropSelect<Units>
        label="Units"
        value={m.units}
        options={[
          ['ft', 'Feet'],
          ['m', 'Meters']
        ]}
        onChange={(units) => onChange({ units })}
      />
      <PropDistance
        label="Front view width"
        hint="The real width of the front view. It sets the scale."
        value={layout.width}
        m={m}
        min={0.1}
        onChange={(lu) => onChange({ scale: Math.round(((layoutScale(layout) * layout.width) / lu) * 1000) / 1000 })}
      />
      <PropRow label="Scale">
        <PropButton onClick={onMeasure} title="Measure something you know, then type its real size (M)">
          <Ruler /> Measure
        </PropButton>
      </PropRow>
      <PropNote>
        Real distances make the top and 3D views true to life, and let animations move at real speeds. For the best scale, measure something you know at the front wall, for example a garage door. Then
        drag the dashed ground line in the front view to the bottom of the front wall: heights count from there.
      </PropNote>
    </PropSection>
  );
}

/** The name of a point of a line. */
const pointName = (f: Fixture, i: number) => (i === 0 ? 'first point' : i === f.points.length - 1 ? 'last point' : `corner ${i}`);

/**
 * Where the selected point or object is, in feet or meters. X counts from the left edge of
 * the front view, height from the ground line, depth from the front wall (toward the street).
 */
function PositionProps({ f, point, m, ground, onChange }: { f: Fixture; point: number | null; m: Measure; ground: number; onChange: (patch: Partial<Fixture>) => void }) {
  const setPoint = (i: number, patch: Partial<Point>) => onChange({ points: f.points.map((p, j) => (j === i ? { ...p, ...patch } : p)) });
  const depthHint = 'Depth 0 is the front wall; plus is toward the street.';
  const xyz = (i: number, heightLabel: string) => {
    const p = f.points[i];
    return (
      <>
        <PropDistance label="X (across)" hint="From the left edge of the front view" value={p.x} m={m} onChange={(lu) => setPoint(i, { x: Math.round(lu) })} />
        <PropDistance label={heightLabel} hint="From the ground line" value={ground - p.y} m={m} onChange={(lu) => setPoint(i, { y: Math.round(ground - lu) })} />
        <PropDistance label="Depth" hint={depthHint} value={p.z ?? 0} m={m} onChange={(lu) => setPoint(i, { z: Math.round(lu) })} />
      </>
    );
  };
  if (isLine(f)) {
    if (point != null && f.points[point]) {
      const z = f.points[point].z ?? 0;
      return (
        <>
          {xyz(point, 'Height')}
          <PropRow label="">
            <PropButton onClick={() => onChange({ points: f.points.map((p) => ({ ...p, z })) })} disabled={f.points.every((p) => (p.z ?? 0) === z)}>
              Use this depth for every point
            </PropButton>
          </PropRow>
        </>
      );
    }
    const depths = f.points.map((p) => p.z ?? 0);
    const same = depths.every((d) => d === depths[0]);
    return (
      <>
        <PropDistance label="Depth (all points)" hint={depthHint} value={same ? depths[0] : null} m={m} onChange={(lu) => onChange({ points: f.points.map((p) => ({ ...p, z: Math.round(lu) })) })} />
        <PropNote>Click a point to place it exactly. A roofline along the side of the house runs back: give its far points a minus depth in the top view. {depthHint}</PropNote>
      </>
    );
  }
  return xyz(0, f.kind === 'tree' ? 'Base height' : 'Height');
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

function LedProps({ f, onRange }: { f: Fixture; onRange: (first: number, last: number) => void }) {
  const { first, last } = ledRange(f);
  // A custom object has as many LEDs as its design: moving the first LED moves them all.
  const fixed = f.kind === 'custom';
  return (
    <>
      <PropNumber
        label="First LED"
        tone="green"
        steppers
        value={first}
        onChange={(n) => (fixed ? onRange(Math.round(n), Math.max(0, Math.round(n) + last - first)) : onRange(Math.round(n), last))}
        hint="The device LED number at the start (the first point you drew)"
      />
      {fixed ? (
        <PropRow label="Last LED">
          <span className="block text-xs tabular-nums">
            {last} ({f.pixels} LEDs, set in the design)
          </span>
        </PropRow>
      ) : (
        <>
          <PropNumber label="Last LED" tone="red" steppers value={last} onChange={(n) => onRange(first, Math.round(n))} hint="The device LED number at the end" />
          <PropNumber
            label="Number of LEDs"
            value={f.pixels}
            min={1}
            max={MAX_FIXTURE_PIXELS}
            onChange={(n) => onRange(first, last >= first ? first + Math.round(n) - 1 : Math.max(0, first - Math.round(n) + 1))}
          />
        </>
      )}
      <PropRow label="Direction">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-xs">{f.pixels === 1 ? 'One LED' : last >= first ? 'Counts up' : 'Counts down'}</span>
          <PropButton onClick={() => onRange(last, first)} disabled={f.pixels < 2}>
            <ArrowLeftRight /> Flip
          </PropButton>
        </div>
      </PropRow>
      <PropNote>Use the LED numbers from the WLED app. On the lights, the selected object glows blue, its first LED is green and its last LED is red. LEDs that no object uses stay off.</PropNote>
    </>
  );
}

function CornerProps({ f, index, onPin, onSplit }: { f: Fixture; index: number; onPin: (led: number | null) => void; onSplit: () => void }) {
  const led = deviceLed(f, pointOffsets(f)[index]);
  const pinned = isPinned(f, index);
  const ignored = f.pointLeds?.[index] != null && !pinned;
  return (
    <>
      <PropNumber label="LED after it" steppers value={led} onChange={(n) => onPin(Math.round(n))} hint="The first LED after this corner. The segment before it ends on the LED just before." />
      <PropRow label="">
        <div className="flex flex-wrap gap-1">
          {pinned || ignored ? (
            <PropButton onClick={() => onPin(null)}>
              <PinOff /> Unpin
            </PropButton>
          ) : (
            <PropButton onClick={() => onPin(led)}>
              <Pin /> Pin here
            </PropButton>
          )}
          <PropButton onClick={onSplit}>
            <Scissors /> Split here
          </PropButton>
        </div>
      </PropRow>
      <PropNote>{pinned ? 'Pinned: this number stays when you edit other segments.' : 'Estimated from the line length. Type the real number to pin it.'}</PropNote>
      {ignored ? <PropNote tone="red">The pinned number is not between the numbers of the points on each side, so it is not used.</PropNote> : null}
    </>
  );
}

/** Device LED numbers at the points of the selected object, drawn on the map. */
function LedLabels({ f, corner, segment, V, side, k, scale }: { f: Fixture; corner: number | null; segment: number | null; V: (p: Point) => { u: number; v: number }; side: ViewSide; k: number; scale: number }) {
  const label = (x: number, y: number, text: string, strong: boolean, key: string | number) => (
    <text
      key={key}
      x={x}
      y={y - 14 * k}
      textAnchor="middle"
      fontSize={14 * k}
      fontWeight={strong ? 700 : 500}
      fill={strong ? '#fbbf24' : '#fff'}
      stroke="#0c0a09"
      strokeWidth={4 * k}
      paintOrder="stroke"
      pointerEvents="none"
      className="tabular-nums"
    >
      {text}
    </text>
  );
  if (f.kind === 'custom') {
    const pts = designPaths(f, scale).flat().map(V);
    const { first, last } = ledRange(f);
    if (!pts.length) return null;
    const u = (Math.min(...pts.map((q) => q.u)) + Math.max(...pts.map((q) => q.u))) / 2;
    return label(u, Math.min(...pts.map((q) => q.v)) - 10 * k, `LEDs ${first}–${last}`, true, 'c');
  }
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

/** Edits one straight segment of a line: only it glows on the lights, with green and red ends. */
function SegmentProps({
  f,
  index,
  onPoint,
  onToggle,
  onClose,
  lights,
  length,
  scale,
  m,
  onResize
}: {
  f: Fixture;
  index: number;
  onPoint: (point: number, led: number) => void;
  onToggle: (on: boolean) => void;
  onClose: () => void;
  /** What the line is made of, if known. */
  lights: LightType | null;
  /** The segment's drawn length, in layout units. */
  length: number;
  scale: number;
  m: Measure;
  /** Gives the segment this many LEDs; the LEDs after it move along. */
  onResize: (count: number) => void;
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
    <>
      <PropRow label="Lit" hint="Turn off a stretch that only links two lit segments. Its LEDs stay dark, and games skip it.">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs">{on ? 'On' : 'Off (skipped)'}</span>
          <Switch label="Segment on" checked={on} onChange={onToggle} />
        </div>
      </PropRow>
      <PropNumber label="Start LED" tone="green" steppers value={start} onChange={(n) => onPoint(index, limit(index, Math.round(n)))} />
      <PropNumber
        label="End LED"
        tone="red"
        steppers
        value={end}
        onChange={(n) => (isLast ? onPoint(index + 1, limit(index + 1, Math.round(n))) : onPoint(index + 1, limit(index + 1, Math.round(n) + dir)))}
      />
      <PropNote>
        {Math.abs(end - start) + 1} LEDs{on ? '' : ', off'}.{!isLast ? ` The next segment starts at LED ${end + dir}.` : ''} Only this segment glows on the lights. Move its ends until the green and
        red LEDs sit at the real corners; these numbers stay fixed when you edit other segments.
      </PropNote>
      <PropRow label="Length">
        <span className="block text-xs tabular-nums">
          {m.text(length)}
          {lights ? ` · one LED every ${spacingText(length / scale / Math.max(1, Math.abs(end - start) + (isLast ? 0 : 1)), m.units)}` : ''}
        </span>
      </PropRow>
      {lights
        ? (() => {
            // A segment ends where the next begins; the last one has an LED at each end.
            const fit = ledsForLength(length / scale, lights.spacing, isLast);
            const now = Math.abs(end - start) + 1;
            return fit !== now ? (
              <>
                <PropNote>
                  Made of {lights.name}: {spacingText(lights.spacing, m.units)} apart, this segment holds {fit} LEDs; it has {now}.
                </PropNote>
                <PropRow label="">
                  <PropButton onClick={() => onResize(fit)} title="The LEDs after this segment move along; the other segments keep their LEDs">
                    Use {fit} LEDs here
                  </PropButton>
                </PropRow>
              </>
            ) : (
              <PropNote>Made of {lights.name}: {now} LEDs fit this segment as drawn.</PropNote>
            );
          })()
        : null}
      <PropRow label="">
        <PropButton onClick={onClose}>Show the whole line</PropButton>
      </PropRow>
    </>
  );
}

/** Orange marks where each new strand of lights starts on the selected object, with the device LED number there. */
function StrandMarks({ f, perStrand, scale, V, k, labels }: { f: Fixture; perStrand: number | null; scale: number; V: (p: Point) => { u: number; v: number }; k: number; labels: boolean }) {
  const starts = strandStarts(f.pixels, perStrand);
  if (!starts.length) return null;
  const px = fixturePixels(f, scale);
  return (
    <g pointerEvents="none">
      {starts.map((i, n) => {
        const p = px[i];
        if (!p) return null;
        const q = V(p);
        return (
          <g key={i}>
            <rect x={q.u - 6 * k} y={q.v - 6 * k} width={12 * k} height={12 * k} transform={`rotate(45 ${q.u} ${q.v})`} fill="#fb923c" stroke="#0c0a09" strokeWidth={2 * k} />
            {labels ? (
              <text x={q.u} y={q.v + 24 * k} textAnchor="middle" fontSize={12 * k} fontWeight={600} fill="#fdba74" stroke="#0c0a09" strokeWidth={3.5 * k} paintOrder="stroke" className="tabular-nums">
                strand {n + 2} · #{deviceLed(f, i)}
              </text>
            ) : null}
          </g>
        );
      })}
    </g>
  );
}

/**
 * Green and red rings on the first and last LED of the selection. They pulse on the same clock
 * as the real lights (see editorPulse), so the drawing and the house blink together.
 */
function EndMarkers({ a, b, V, k }: { a?: Point; b?: Point; V: (p: Point) => { u: number; v: number }; k: number }) {
  const delay = { animationDelay: `-${Date.now() % 1000}ms` };
  const ring = (p: Point | undefined, color: string, key: string) =>
    p ? <circle key={key} cx={V(p).u} cy={V(p).v} r={16 * k} fill="none" stroke={color} strokeWidth={5 * k} className="led-pulse" style={delay} pointerEvents="none" /> : null;
  return (
    <>
      {ring(a, '#22c55e', 'a')}
      {ring(b, '#ef4444', 'b')}
    </>
  );
}

const SNAP_LABELS: Record<Snapped['kind'], string> = { point: 'Point', center: 'Center', mid: 'Midpoint', on: 'On line', align: 'Aligned', angle: '', free: '' };

/** Where the pointer snaps: a marker in the CAD style (square: point, triangle: midpoint, cross: on a line), dashed guides, and a label. */
function SnapMarker({ s, k }: { s: Snapped & { label?: string }; k: number }) {
  if (s.kind === 'free' && !s.label) return null;
  const { u, v } = s.at;
  const color = '#22d3ee';
  const common = { fill: 'none', stroke: color, strokeWidth: 2 * k };
  const d = 8 * k;
  let label = s.label ?? SNAP_LABELS[s.kind];
  if (!s.label && s.kind === 'angle' && s.guides[0]) {
    const [a, b] = s.guides[0];
    const deg = Math.round((Math.atan2(-(b.v - a.v), b.u - a.u) * 180) / Math.PI);
    label = `${(deg + 360) % 180 === 0 ? 'Level' : Math.abs(deg) === 90 ? 'Upright' : '45°'}`;
  }
  return (
    <g pointerEvents="none">
      {s.guides.map(([a, b], i) => (
        <line key={i} x1={a.u} y1={a.v} x2={b.u} y2={b.v} stroke={color} strokeOpacity={0.7} strokeWidth={1.25 * k} strokeDasharray={`${6 * k} ${6 * k}`} />
      ))}
      {s.kind === 'point' ? <rect x={u - d} y={v - d} width={2 * d} height={2 * d} {...common} /> : null}
      {s.kind === 'center' ? <circle cx={u} cy={v} r={d} {...common} /> : null}
      {s.kind === 'mid' ? <polygon points={`${u},${v - d * 1.1} ${u + d},${v + d * 0.75} ${u - d},${v + d * 0.75}`} {...common} /> : null}
      {s.kind === 'on' ? <path d={`M${u - d},${v - d}L${u + d},${v + d}M${u + d},${v - d}L${u - d},${v + d}`} {...common} /> : null}
      {s.kind === 'align' || s.kind === 'angle' ? <circle cx={u} cy={v} r={4 * k} fill={color} /> : null}
      {label ? (
        <text x={u + 12 * k} y={v - 12 * k} fontSize={13 * k} fontWeight={600} fill="#a5f3fc" stroke="#0c0a09" strokeWidth={3.5 * k} paintOrder="stroke">
          {label}
        </text>
      ) : null}
    </g>
  );
}

/** The right-click menu: actions for the point, segment or object under the pointer. */
function ContextMenu({ menu, onClose }: { menu: { x: number; y: number; title: string; items: MenuItem[] }; onClose: () => void }) {
  // Keep it on screen.
  const x = Math.min(menu.x, window.innerWidth - 260);
  const y = Math.min(menu.y, window.innerHeight - 48 - menu.items.length * 36);
  return (
    <div
      data-layout-menu
      role="menu"
      className="fixed z-50 w-60 rounded-xl bg-white p-1.5 text-sm shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-700"
      style={{ left: x, top: y }}
      onContextMenu={(e) => e.preventDefault()}
    >
      <p className="truncate px-2.5 pt-1 pb-1.5 text-xs font-medium text-stone-500">{menu.title}</p>
      {menu.items.map((it) => (
        <button
          key={it.label}
          type="button"
          role="menuitem"
          onClick={() => {
            onClose();
            it.run();
          }}
          className={cn(
            'flex w-full items-center justify-between gap-3 rounded-lg px-2.5 py-1.5 text-left hover:bg-stone-100 dark:hover:bg-stone-800',
            it.danger ? 'text-red-600 dark:text-red-400' : 'text-stone-800 dark:text-stone-200'
          )}
        >
          <span>{it.label}</span>
          {it.keys ? <kbd className="shrink-0 font-sans text-xs text-stone-400">{it.keys}</kbd> : null}
        </button>
      ))}
    </div>
  );
}

/** The drawing area of a 2D viewport: reports its size, and passes wheel events (which must not scroll the page) to the camera. */
function PaneBody({ onSize, onWheel, children }: { onSize: (w: number, h: number) => void; onWheel: (e: WheelEvent, rect: DOMRect) => void; children: ReactNode }) {
  const el = useRef<HTMLDivElement>(null);
  const sizeRef = useRef(onSize);
  sizeRef.current = onSize;
  const wheelRef = useRef(onWheel);
  wheelRef.current = onWheel;
  useEffect(() => {
    const d = el.current;
    if (!d) return;
    const ro = new ResizeObserver(() => sizeRef.current(d.clientWidth, d.clientHeight));
    ro.observe(d);
    const wheel = (e: WheelEvent) => {
      e.preventDefault();
      wheelRef.current(e, d.getBoundingClientRect());
    };
    d.addEventListener('wheel', wheel, { passive: false });
    return () => {
      ro.disconnect();
      d.removeEventListener('wheel', wheel);
    };
  }, []);
  return (
    <div ref={el} className="relative min-h-0 flex-1 overflow-hidden">
      {children}
    </div>
  );
}

/** Renames an object in the object list. Enter or a click elsewhere keeps the name; Esc cancels. */
function RenameInput({ value, onDone }: { value: string; onDone: (name: string | null) => void }) {
  const [text, setText] = useState(value);
  const done = useRef(false);
  const finish = (name: string | null) => {
    if (done.current) return;
    done.current = true;
    onDone(name);
  };
  return (
    <input
      autoFocus
      value={text}
      maxLength={60}
      onFocus={(e) => e.target.select()}
      onChange={(e) => setText(e.target.value)}
      onClick={(e) => e.stopPropagation()}
      onBlur={() => finish(text)}
      onKeyDown={(e) => {
        if (e.key === 'Enter') finish(text);
        if (e.key === 'Escape') finish(null);
      }}
      className="h-6 min-w-0 flex-1 rounded bg-white px-1.5 text-[13px] text-stone-900 ring-2 ring-sky-400 outline-none"
    />
  );
}

const SHORTCUTS: [string, string][] = [
  ['V  A  C  H', 'Select, edit points, split, pan'],
  ['R  L  B  T', 'Roofline, line, bush, tree'],
  ['M', 'Measure'],
  ['P', 'Play or stop the effects'],
  ['Wheel, pinch', 'Zoom at the pointer'],
  ['Middle-drag, Space-drag', 'Pan'],
  ['F', 'Zoom to the selection'],
  ['Home', 'Zoom to fit'],
  ['+  −', 'Zoom in, zoom out'],
  ['Shift', '45° steps; move straight'],
  ['Alt (Option)', 'Snapping the other way'],
  ['Enter, Esc', 'Finish the line'],
  ['Backspace', 'Remove the last point drawn'],
  ['Delete', 'Delete the point or object'],
  ['F2', 'Rename the object'],
  ['Ctrl/⌘-click an end', 'Continue the line'],
  ['Ctrl/⌘-click', 'Add to or remove from the selection'],
  ['Shift-click in the list', 'Select a range of objects'],
  ['Esc', 'Clear a multi-selection'],
  ['Right-click', 'Actions'],
  ['Ctrl/⌘+Z, Shift+Z', 'Undo, redo'],
  ['Ctrl/⌘+S', 'Save']
];

function Shortcuts() {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
      {SHORTCUTS.map(([keys, what]) => (
        <div key={keys} className="contents">
          <dt className="font-medium whitespace-nowrap text-stone-700 dark:text-stone-300">{keys}</dt>
          <dd className="text-stone-500">{what}</dd>
        </div>
      ))}
    </dl>
  );
}
