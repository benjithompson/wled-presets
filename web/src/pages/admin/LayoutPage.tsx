import { lazy, Suspense, useEffect, useMemo, useRef, useState, type ReactNode, type MouseEvent as RMouseEvent, type PointerEvent as RPointerEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router';
import {
  ArrowLeftRight,
  ChevronDown,
  Ellipsis,
  Magnet,
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
  FolderOpen,
  Move,
  LayoutPanelLeft,
  Lightbulb,
  LightbulbOff,
  Lock,
  LockOpen,
  List,
  LocateFixed,
  Maximize2,
  Minimize2,
  MousePointer2,
  PenTool,
  Redo2,
  Pin,
  PinOff,
  Plus,
  Rainbow,
  RotateCcw,
  Rows2,
  Ruler,
  Save,
  Scan,
  ScanLine,
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
  BUSH_TALL,
  drawnByPaths,
  BUSH_TURNS,
  radiusOf,
  semicircleSize,
  treeSize,
  deviceLed,
  markedTree,
  takesMarks,
  validMarks,
  FEET_PER_METER,
  FIXTURE_HUES,
  editorPulse,
  fixturePixels,
  isLine,
  layoutGround,
  layoutScale,
  clampPointLed,
  pinPoint,
  removePoint,
  setSkipped,
  splitLine,
  unpinPoint,
  segmentLeds,
  deviceRuns,
  extendLine,
  insertPoint,
  fromLedRange,
  isPinned,
  LAYOUT_WIDTH,
  ledRange,
  matchPoint,
  matchRange,
  MAX_FIXTURE_PIXELS,
  pointOffsets,
  designReach,
  objectPaths,
  treeOutline,
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
  type FrontView,
  MAX_PITCH,
  MAX_YAW,
  type Layout,
  type MatchProbe,
  type Point,
  type Spin,
  type TreeShape,
  type Units,
  type Zigzag,
  type Side,
  wavePasses,
  WAVE_SWEEP,
  capFloor,
  litFloor,
  treeSurfaceLength,
  keepLocked,
  changeKind,
  isShapeKind,
  SHAPE_KINDS,
  type ShapeKind
} from '../../../../shared/layout.ts';
import { hsvBytes } from '../../../../shared/color.ts';
import { deviceEffects, EFFECTS, keyDevice, effectKey, effectTarget, LayoutEffects, layoutEffects, withEffects, YARD, type EffectId, type EffectSettings } from '../../../../shared/effects.ts';
import { framePut, paintEditorView } from '../../../../shared/editorView.ts';
import type { Scene } from '../../../../shared/types.ts';
import { Badge, Button, ConfirmDialog, Dialog, Field, Input, Spinner, Switch } from '../../components/ui.tsx';
import { EffectProps } from './effectProps.tsx';
import { DesignEditor } from './DesignEditor.tsx';
import { Gizmo, screenAngle, wrapAngle, type GizmoPart } from './gizmo.tsx';
import { CheckBar, CheckOverlay, ObjectCheckProps, toLayoutCheck, YardCheckProps, type EditorCheck } from './checkProps.tsx';
import { pictureBlocks, validCheck } from '../../../../shared/check.ts';
import { freeSetting, keepStrings, stringGap } from '../../../../shared/stringFit.ts';
import { autoScale, keepScale, roofScale } from '../../../../shared/yardScale.ts';
import { CustomProps, LibraryList, LightSelect, LightsProps, LightTypeDialog } from './lightsProps.tsx';
import { markAt, moveMark, raiseMark, ShapeWizard } from './shapeWizard.tsx';
import { ledsForLength, lightsOf, spacingText, strandStarts, stringStarts, wholeStrands, type LightType } from '../../../../shared/lights.ts';
import { YardView } from '../../yard/YardView.tsx';
import { fromView, LayoutInView, toView, viewPositions, type PointRef, type ViewSide } from '../../yard/views.ts';
import { ellipsePolygon, pickAt, type Picked, type PickShape } from '../../yard/pick.ts';
import { acrossOf, frontCamera } from '../../yard/frontCamera.ts';
import { draftOutline, draftSize, shapeFrom, type ShapeDraft } from './newShapes.ts';
import { fitCam, frameCam, lerpCam, panBy, pinch, viewBoxOf, wheelFactor, zoomAt, type Box, type Cam, type Pair, type PaneSize } from '../../yard/camera.ts';
import { NumberInput, PropAccordion, PropAdvanced, PropButton, PropNote, PropNumber, PropRow, PropSection, PropSelect, PropSlider, PropText } from './props.tsx';
import { onGrid, snapPoint, type SnapGrid, type Snapped, type SnapTargets } from '../../yard/snap.ts';
import { api } from '../../lib/api.ts';
import { KIND_ICONS, KIND_LABELS } from '../../lib/kinds.ts';
import { EditHistory } from './editHistory.ts';
import { cn, downloadJson, errorText } from '../../lib/utils.ts';
import { useInFront } from '../../lib/useInFront.ts';
import { useLightsPreview } from '../../lib/useLightsPreview.ts';
import { useMedia } from '../../lib/useMedia.ts';
import { ActionSheet, BottomSheet, type SheetSize } from '../../components/mobile.tsx';
import { HoldRing } from '../../components/HoldRing.tsx';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';

// three.js is large: load the 3D view only when it is opened.
const Scene3D = lazy(() => import('../../yard/Scene3D.tsx').then((m) => ({ default: m.Scene3D })));

/** align: lines the picture from above up with the yard (no button: the Pictures menu starts it). */
type Tool = 'select' | 'edit' | 'split' | 'pan' | 'roof' | 'line' | 'bush' | 'tree' | 'semicircle' | 'measure' | 'align';
type LineTool = 'roof' | 'line';
const isLineTool = (t: Tool): t is LineTool => t === 'roof' || t === 'line';
/** One-key shortcuts, as in most drawing programs. */
const TOOL_KEYS: Record<string, Tool> = { v: 'select', a: 'edit', c: 'split', h: 'pan', r: 'roof', l: 'line', b: 'bush', t: 'tree', u: 'semicircle', m: 'measure' };
/** A line being drawn. `cont`: it continues an existing line from one of its ends. */
type Draft = { side: ViewSide; pts: UV[]; cont?: { id: string; at: 'first' | 'last' } };
type MenuItem = { label: string; keys?: string; danger?: boolean; run: () => void };
/** Where a menu opens: on the screen, in pixels. */
type Anchor = { x: number; y: number };
/** Under a button. */
const below = (e: RMouseEvent<HTMLElement>): Anchor => {
  const r = e.currentTarget.getBoundingClientRect();
  return { x: r.left, y: r.bottom + 4 };
};
/** A position in one view, in layout units: u to the right, v down. */
type UV = { u: number; v: number };
type Drag =
  | { kind: 'vertex'; side: ViewSide; id: string; index: number; start: UV }
  /** `axis`: only across (u) or only up and down / toward the street (v), from the arrows. */
  | { kind: 'move'; side: ViewSide; id: string; from: UV; original: Point[]; axis?: 'u' | 'v' | null }
  /** Turning with the ring: `prop` is the front view's rotation or the top view's facing. */
  | { kind: 'rotate'; side: ViewSide; id: string; prop: 'rotation' | 'facing' | 'tilt'; center: UV; start: number; original: number }
  /** Resizing width and height together, about the anchor. */
  | { kind: 'scale'; side: ViewSide; id: string; center: UV; start: number; original: Pick<Fixture, 'radius' | 'height' | 'size'> }
  | { kind: 'radius'; side: ViewSide; id: string }
  | { kind: 'treeHeight'; side: ViewSide; id: string }
  /** A press on a locked object: it stays put; moving the pointer says why. */
  | { kind: 'locked'; id: string; from: UV; warned: boolean }
  | { kind: 'ground' }
  | ({ kind: 'newShape' } & ShapeDraft)
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
/** Units the grid can be set in, whatever the units of the layout. */
type GridUnit = 'ft' | 'in' | 'm' | 'cm';
const GRID_UNITS: { unit: GridUnit; label: string; meters: number }[] = [
  { unit: 'ft', label: 'feet', meters: 1 / FEET_PER_METER },
  { unit: 'in', label: 'inches', meters: 1 / (12 * FEET_PER_METER) },
  { unit: 'm', label: 'meters', meters: 1 },
  { unit: 'cm', label: 'centimeters', meters: 0.01 }
];
/**
 * Snapping, the 90° lock and the grid: switches in the status bar. `gridSize` in `gridUnit`
 * (null: 5 ft, or 1 m, in the units of the layout); every `gridMajor`th grid line is brighter.
 */
type Drafting = { snap: boolean; ortho: boolean; grid: boolean; gridSnap: boolean; gridSize: number | null; gridUnit: GridUnit | null; gridMajor: number };
type DraftSwitch = 'snap' | 'ortho' | 'grid' | 'gridSnap';
const DRAFTING_DEFAULTS: Drafting = { snap: true, ortho: false, grid: true, gridSnap: false, gridSize: null, gridUnit: null, gridMajor: 5 };

/** The grid as set (or the default for the layout's units): its size, its unit, and its step in layout units. */
function gridOf(d: Drafting, layout: Layout) {
  const unit: GridUnit = d.gridUnit ?? (layout.units === 'm' ? 'm' : 'ft');
  const size = d.gridSize && d.gridSize > 0 ? d.gridSize : unit === 'm' ? 1 : unit === 'ft' ? 5 : unit === 'in' ? 6 : 10;
  const meters = GRID_UNITS.find((g) => g.unit === unit)!.meters;
  return { unit, size, step: size * meters * layoutScale(layout), text: `${size} ${unit}` };
}

const LAYOUT_KEY = ['layout'];
const HUES = FIXTURE_HUES;
const SHOW_KEY = 'layout.showOnLights';
const VIEWPORT_KEY = 'layout.viewport';
/** The one view a phone shows. */
const PHONE_VIEW_KEY = 'layout.phoneView';
const DRAFTING_KEY = 'layout.drafting';
const VIEW_LABELS: Record<ViewName, string> = { front: 'Front', top: 'Top', side: 'Side', '3d': '3D' };
const VIEW_NOTES: Record<ViewName, string> = {
  front: 'as seen from the street',
  top: 'from above, the street at the bottom',
  side: 'from the left, the street on the right',
  '3d': 'drag to turn, right-drag to pan'
};
/** The 2D views. */
const SIDES: ViewSide[] = ['front', 'top', 'side'];
const TOOL_LABELS: Record<Tool, string> = { select: 'Select', edit: 'Edit points', split: 'Split', pan: 'Pan', roof: 'Roofline', line: 'Line', bush: 'Bush', tree: 'Tree', semicircle: 'Semicircle', measure: 'Measure', align: 'Align picture' };
/** The size of handles and labels was set for about 1.6 layout units per pixel; this keeps them the same size on the screen at every zoom. */
const BASE_K = 1.6;

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
    const all: ViewName[] = ['front', 'top', 'side', '3d'];
    // Saved before the side view: it comes last.
    if (v.panes.length === 3 && !v.panes.includes('side')) v.panes = [...v.panes, 'side'];
    if (v.mode in VP_COUNT && v.panes.length === 4 && all.every((x) => v.panes.includes(x))) return v;
  } catch {}
  return { mode: 'three', panes: ['front', 'top', '3d', 'side'] };
}

function readPhoneView(): ViewName {
  try {
    const v = localStorage.getItem(PHONE_VIEW_KEY);
    if (v === 'front' || v === 'top' || v === 'side' || v === '3d') return v;
  } catch {}
  return 'front';
}

function readDrafting(): Drafting {
  try {
    return { ...DRAFTING_DEFAULTS, ...(JSON.parse(localStorage.getItem(DRAFTING_KEY) ?? '{}') as Partial<Drafting>) };
  } catch {
    return { ...DRAFTING_DEFAULTS };
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

/** How far one press of − or + moves a mark of Shape to the lights up or down: 3 in, or 5 cm. */
const shapeStep = (layout: Layout) => (layout.units === 'm' ? 0.05 : 0.0762) * layoutScale(layout);

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

/** Which way an object faces, as seen from above (see Fixture.facing). */
function FacingProp({ f, hint, onChange }: { f: Fixture; hint: string; onChange: (patch: Partial<Fixture>) => void }) {
  return <PropNumber label="Faces" unit="°" decimal value={f.facing ?? 0} min={-360} max={360} step={15} onChange={(n) => onChange({ facing: n || undefined })} hint={hint} />;
}

/** Shown with where an object sits, while it is locked. */
function LockedNote({ onUnlock }: { onUnlock: () => void }) {
  return (
    <div className="flex items-center gap-2 rounded-md bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-800 ring-1 ring-amber-500/30 ring-inset dark:text-amber-300">
      <Lock className="size-3.5 shrink-0" />
      <span className="min-w-0 flex-1">Locked in place: it cannot be moved, resized or deleted. Its LEDs, wiring and effect can still change.</span>
      <PropButton onClick={onUnlock}>
        <LockOpen /> Unlock
      </PropButton>
    </div>
  );
}

/** An angle an object leans by (0: upright). */
function TiltProp({ label, value, hint, onChange }: { label: string; value: number | undefined; hint: string; onChange: (deg: number | undefined) => void }) {
  return <PropNumber label={label} unit="°" decimal value={value ?? 0} min={-180} max={180} step={5} onChange={(n) => onChange(n || undefined)} hint={hint} />;
}

/** The shape of a bush, a tree or a semicircle, and how its LEDs run over it. */
/** The height a shape's size handles show: a tree's, or a semicircle's (its radius unless set). */
const sizeHeight = (f: Fixture) => (f.kind === 'tree' ? treeSize(f).h : semicircleSize(f).h);

function ShapeProps({ f, m, locked, strung, onChange }: { f: Fixture; m: Measure; locked: boolean; strung: boolean; onChange: (patch: Partial<Fixture>) => void }) {
  /** Its size and turn: a locked object keeps them (its pattern and wiring can still change). */
  const place = (el: ReactNode) => (
    <fieldset disabled={locked} className="contents">
      {el}
    </fieldset>
  );
  /** The setting that follows from its light string (see freeSetting): it cannot be set by hand. */
  const free = strung ? freeSetting(f) : null;
  const fromString = (el: ReactNode) =>
    free ? (
      <fieldset disabled className="contents">
        {el}
      </fieldset>
    ) : (
      el
    );
  const stringNote = free ? (
    <PropNote>
      {free === 'radius' ? 'Its size' : free === 'turns' ? 'Its turns' : free === 'strands' ? 'Its strands' : free === 'rows' ? 'Its rows' : 'Its passes'} follow from the light string, so the LEDs sit as far apart as on the real string. More LEDs
      {free === 'radius' ? ' make it bigger' : `, or a ${f.kind === 'tree' ? 'smaller tree' : 'smaller shape'}, give it more`}.
    </PropNote>
  ) : null;
  const width = place(<PropDistance label="Width" value={radiusOf(f) * 2} m={m} min={0.1} onChange={(lu) => onChange({ radius: Math.max(5, Math.round(lu / 2)) })} />);
  if (f.kind === 'bush') {
    return (
      <>
        {free === 'radius' ? fromString(width) : width}
        <PropSelect<NonNullable<Fixture['pattern']>>
          label="LED pattern"
          value={f.pattern ?? 'fill'}
          options={[
            ['fill', 'Net over the bush'],
            ['ring', 'Ring around the edge'],
            ['spiral', 'Spiral from the middle']
          ]}
          onChange={(pattern) => onChange({ pattern })}
        />
        {free === 'turns' ? <PropNote>The spiral goes round {f.turns ?? BUSH_TURNS} times from the middle out.</PropNote> : null}
        {stringNote}
        <PropNote>The point is the middle of the bush, as seen from the front.</PropNote>
      </>
    );
  }
  if (f.kind === 'semicircle') {
    const way = f.zigzag ?? 'down';
    const across = way === 'down' || way === 'up';
    return (
      <>
        {width}
        {place(
          <PropDistance
            label="Height"
            hint="From the straight edge to the top of the round. Half the width: a true half circle."
            value={semicircleSize(f).h}
            m={m}
            min={0.1}
            onChange={(lu) => onChange({ height: Math.max(5, Math.round(lu)) })}
          />
        )}
        <PropSelect<Zigzag>
          label="Zigzag"
          hint={
            across
              ? `The wire runs across and back, row by row. LED 0 is at the left end of the ${way === 'down' ? 'top' : 'bottom'} row.`
              : `The wire runs up and down, column by column. LED 0 is at the foot of the ${way === 'right' ? 'left' : 'right'}-most column.`
          }
          value={way}
          options={[
            ['down', 'From the top down'],
            ['up', 'From the bottom up'],
            ['right', 'From the left to the right'],
            ['left', 'From the right to the left']
          ]}
          onChange={(zigzag) => onChange({ zigzag })}
        />
        {fromString(<PropNumber label={across ? 'Rows' : 'Columns'} hint="How many times the wire crosses the semicircle" value={f.strands ?? 8} min={1} max={64} onChange={(n) => onChange({ strands: Math.round(n) })} />)}
        {stringNote}
        {place(
          <PropNumber
            label="Turn"
            unit="°"
            decimal
            value={f.rotation ?? 0}
            min={-360}
            max={360}
            step={15}
            onChange={(n) => onChange({ rotation: n || undefined })}
            hint="Clockwise, as seen from the front: 90 puts the round side to the right, 180 turns it upside down"
          />
        )}
        {place(<FacingProp f={f} onChange={onChange} hint="Turned as seen from above: 0 faces the street, 90 faces right (as seen from the street), -90 left" />)}
        {place(<TiltProp label="Tilt" value={f.tilt} onChange={(tilt) => onChange({ tilt })} hint="Tilted toward the street (more) or the house (less), as seen from the side view" />)}
        <PropNote>The point is the middle of the straight edge.</PropNote>
      </>
    );
  }
  const pattern = f.pattern === 'strands' || f.pattern === 'wave' ? f.pattern : 'spiral';
  const spiral = pattern === 'spiral';
  const wave = pattern === 'wave';
  const fromTop = (spiral || wave) && f.start === 'top';
  const passes = wave ? wavePasses(f) : null;
  // A wave shaped to the lights: its rows make its shape, each as wide as its LEDs (see waveRows).
  const rows = wave && markedTree(f) ? validMarks(f).filter((x) => x.led > 0 && x.led < f.pixels - 1).length + 1 : null;
  const ball = f.shape === 'sphere';
  /** The height its LEDs climb: a ball's cap, when only its top has LEDs. */
  const climb = treeSize(f).h * (1 - capFloor(f));
  return (
    <>
      {rows ? (
        <PropNote>
          Shaped to the lights: {rows} row{rows === 1 ? '' : 's'}, each as wide as its LEDs go round, the widest as wide as the tree. Its width comes from the light string when the marks change;
          Width and Height then stretch it, and the rows sit evenly apart up its height unless a turn’s height is set.
        </PropNote>
      ) : (
        <PropSelect<TreeShape>
          label="Shape"
          hint="How wide it is going up. A sphere fits in its width and height: make them the same for a round ball."
          value={f.shape ?? 'cone'}
          options={[
            ['cone', 'Cone (a tree)'],
            ['cylinder', 'Cylinder (a post, a column)'],
            ['sphere', 'Sphere (a ball)']
          ]}
          onChange={(shape) => onChange({ shape: shape === 'cone' ? undefined : shape })}
        />
      )}
      {width}
      {place(<PropDistance label="Height" value={treeSize(f).h} m={m} min={0.1} onChange={(lu) => onChange({ height: Math.max(5, Math.round(lu)) })} />)}
      {ball && !rows ? (
        <>
          {place(
            <PropNumber
              label="Roundness"
              unit="%"
              hint="Its height as a share of its width: 100 is a round ball, less is flatter (a squashed ball, a low dome), more is taller."
              value={Math.round((treeSize(f).h / (2 * treeSize(f).r)) * 100)}
              min={5}
              max={400}
              step={5}
              onChange={(n) => onChange({ height: Math.max(5, Math.round((2 * treeSize(f).r * n) / 100)) })}
            />
          )}
          <PropNumber
            label="LEDs cover"
            unit="°"
            hint="How much of the ball has LEDs, from the top down: 180 all of it, 90 its top half (an upside-down bowl, like the crown of a Japanese maple), less a flatter cap."
            value={f.cover ?? 180}
            min={10}
            max={180}
            step={5}
            onChange={(n) => onChange({ cover: Math.round(n) >= 180 ? undefined : Math.round(n) })}
          />
        </>
      ) : null}
      <PropSelect<NonNullable<Fixture['pattern']>>
        label="LED pattern"
        hint={
          spiral
            ? ball
              ? `Seen from above, the spiral winds ${fromTop ? 'out from the middle (the top) to the edge' : 'in from the edge to the middle (the top)'}. LED 0 is at the front.`
              : `LED 0 is at the ${fromTop ? 'top' : 'base'}, at the front; the spiral goes ${fromTop ? 'down to the base' : 'up to the top'}.`
            : wave
              ? 'The wire winds back and forth over the front of the tree, like a river, turning in smooth bends instead of going all the way round.'
              : 'Strands run from the base to the top. They zigzag: LED 0 is at the base of the front strand, which goes up; the next strand comes down.'
        }
        value={pattern}
        options={[
          ['spiral', 'Spiral around it'],
          ['wave', 'Back and forth (winding)'],
          ['strands', 'Strands, base to top']
        ]}
        onChange={(pattern) => onChange({ pattern })}
      />
      {spiral || wave ? (
        <>
          {spiral ? (
            <>
              {fromString(<PropNumber label="Turns" hint="Turns of the spiral from the base to the top" decimal value={f.turns ?? 8} min={0.5} max={100} step={0.5} onChange={(n) => onChange({ turns: n })} />)}
              {fromString(<PropDistance
                label="Loops apart"
                hint={`How far one loop is from the next, measured over the ${ball ? 'ball' : 'tree'} from the ${ball ? 'edge to the middle' : 'base to the top'} (on average, when they bunch). Sets the turns.`}
                value={treeSurfaceLength(f) / (f.turns ?? 8)}
                m={m}
                min={0.01}
                onChange={(lu) => onChange({ turns: Math.max(0.5, Math.min(100, Math.round((treeSurfaceLength(f) / Math.max(1, lu)) * 10) / 10)) })}
              />)}
              <PropNumber
                label="Loops bunch"
                unit="%"
                hint={`0: evenly apart. More: closer together toward the ${ball ? 'middle (top)' : 'top'}. Less: closer together toward the ${ball ? 'outside edge' : 'base'}.`}
                value={Math.round((f.bias ?? 0) * 100)}
                min={-100}
                max={100}
                step={10}
                onChange={(n) => onChange({ bias: Math.round(n) ? Math.max(-1, Math.min(1, n / 100)) : undefined })}
              />
            </>
          ) : null}
          <PropSelect<'base' | 'top'>
            label="Starts"
            hint={ball && spiral ? 'Where LED 0 is: on the outside edge of the LEDs, or in the middle (the top of the ball). The spiral ends at the other.' : undefined}
            value={f.start ?? 'base'}
            options={
              ball && spiral
                ? [
                    ['base', 'On the outside edge'],
                    ['top', 'In the middle (top)']
                  ]
                : [
                    ['base', 'At the base'],
                    ['top', 'At the top']
                  ]
            }
            onChange={(start) => onChange({ start: start === 'base' ? undefined : start })}
          />
        </>
      ) : (
        fromString(<PropNumber label="Strands" value={f.strands ?? 12} min={1} max={64} onChange={(n) => onChange({ strands: Math.round(n) })} />)
      )}
      {wave && passes && !rows ? (
        <>
          <PropNumber
            label="Goes around"
            unit="°"
            hint="How far around the tree each pass goes, centered on its front (Faces): 180 covers the front half, 360 goes all the way round and back."
            value={f.sweep ?? WAVE_SWEEP}
            min={10}
            max={360}
            step={15}
            onChange={(n) => onChange({ sweep: Math.round(n) === WAVE_SWEEP ? undefined : Math.round(n) })}
          />
          {fromString(
            <PropDistance
              label="Rows apart"
              hint="The height from one pass to the next. The passes fit the tree's height, as close to this as they can."
              value={f.spacing ?? climb / (passes.passes - 1)}
              m={m}
              min={0.05}
              onChange={(lu) => onChange({ spacing: Math.max(1, Math.round(lu * 10) / 10) })}
            />
          )}
          <PropSelect<Side>
            label="First LED on"
            hint="The side of the tree its first pass starts on, as seen from its front"
            value={passes.startSide}
            options={[
              ['left', 'The left'],
              ['right', 'The right']
            ]}
            onChange={(x) => onChange({ startSide: x === 'left' ? undefined : x })}
          />
          <PropSelect<Side>
            label="Last LED on"
            hint="The side its last pass ends on. One pass more or less makes it end there."
            value={passes.endSide}
            options={[
              ['left', 'The left'],
              ['right', 'The right']
            ]}
            onChange={(x) => onChange({ endSide: x })}
          />
          <PropNote>
            {passes.passes} passes, {m.text(climb / (passes.passes - 1))} apart, from the {passes.startSide} {fromTop ? 'at the top' : 'at the base'} to the {passes.endSide}{' '}
            {fromTop ? 'at the base' : 'at the top'}.
          </PropNote>
        </>
      ) : (
        <PropSelect<Spin>
          label={spiral ? 'Winds' : 'Goes round'}
          hint={spiral ? 'As seen from above, following the wire from LED 0' : 'Which way the strands go round from the first, as seen from above'}
          value={f.spin ?? 'ccw'}
          options={[
            ['ccw', 'Counterclockwise'],
            ['cw', 'Clockwise']
          ]}
          onChange={(spin) => onChange({ spin: spin === 'ccw' ? undefined : spin })}
        />
      )}
      {place(
        <FacingProp
          f={f}
          onChange={onChange}
          hint={`Turned as seen from above: ${wave ? 'the middle of the passes' : `where ${spiral ? 'the spiral' : 'the first strand'} starts`}. 0: the front (toward the street), 90: the right, -90: the left, 180: the back.`}
        />
      )}
      {stringNote}
      {place(<TiltProp label="Leans right" value={f.rotation} onChange={(rotation) => onChange({ rotation })} hint="Tilted about its base, as seen from the front: more leans it to the right, less to the left" />)}
      {place(<TiltProp label="Leans to street" value={f.tilt} onChange={(tilt) => onChange({ tilt })} hint="Tilted about its base, as seen from the side view: more leans it toward the street, less toward the house" />)}
      <PropNote>{ball ? 'The point is the bottom of the ball, under the middle (below the LEDs when they cover only its top).' : 'The point is the middle of the base.'}</PropNote>
    </>
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
  /**
   * The "match to the lights" wizard on a line: it walks its points (the selected point is the
   * one being matched), and one LED blinks red on the house until you move it to the real spot.
   * `offset` is that LED for `point`; another selected point starts from its own LED.
   */
  const [match, setMatch] = useState<{ id: string; point: number; offset: number } | null>(null);
  /** Shape to the lights: the tree being shaped, and its blinking LED (counted from its LED 0). */
  const [shaping, setShaping] = useState<{ id: string; led: number } | null>(null);
  /**
   * A check of the drawing against the yard, on the lights and in the views (see shared/check.ts):
   * a slice or a ruler over the whole yard, or the selected object's color test or chase.
   */
  const [check, setCheck] = useState<EditorCheck | null>(null);
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
  const [history] = useState(() => new EditHistory<Layout>());
  const [, setHistoryTick] = useState(0);
  const [cursor, setCursor] = useState<(UV & { side: ViewSide }) | null>(null);
  const [drag, setDrag] = useState<Drag | null>(null);
  /** Measure tool: two points in one view. */
  const [tape, setTape] = useState<{ side: ViewSide; a: UV; b?: UV } | null>(null);
  const [busy, setBusy] = useState(false);
  const svgs = useRef<Partial<Record<ViewSide, SVGSVGElement | null>>>({});
  const fileInput = useRef<HTMLInputElement>(null);
  const layoutFileInput = useRef<HTMLInputElement>(null);
  /** A layout file read from disk, waiting for Import to be confirmed. */
  const [importing, setImporting] = useState<{ data: unknown; name: string; objects: number; pictures: number } | null>(null);
  const aerialInput = useRef<HTMLInputElement>(null);
  /** Align tool: a spot on the picture from above, where it goes, then a second spot and where it goes (top view). */
  const [alignPts, setAlignPts] = useState<UV[]>([]);

  // A phone (or a narrow window) is laid out like a mobile app: one view at a time, switched
  // with buttons, and the object list and the inspector in a bottom sheet that expands and
  // collapses. Wide screens get the CAD layout: viewports side by side and a side panel.
  const wide = useMedia('(min-width: 1024px)');
  const phone = !wide;
  /** Touch: the hints talk about taps, long presses and pinches instead of clicks and keys. */
  const coarse = useMedia('(pointer: coarse)');
  const [phoneView, setPhoneViewState] = useState(readPhoneView);
  const setPhoneView = (v: ViewName) => {
    setPhoneViewState(v);
    try {
      localStorage.setItem(PHONE_VIEW_KEY, v);
    } catch {}
  };
  /** The bottom sheet on a phone: just its tabs, half the screen, or all of it. */
  const [sheet, setSheet] = useState<SheetSize>('peek');
  const [sheetTab, setSheetTab] = useState<'objects' | 'details'>('details');
  /** On a phone, the inspector shows one section at a time: the open one, for objects, a multi-selection and the yard. */
  const [accOpen, setAccOpen] = useState<Record<'object' | 'multi' | 'yard', string | null>>({ object: 'object', multi: 'multi-effect', yard: 'yardfx' });
  /** The drawer of tools that add objects (phone toolbar). */
  const [addOpen, setAddOpen] = useState(false);
  /** The phone's one-line hint, opened to show all of it. */
  const [hintOpen, setHintOpen] = useState(false);

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
  const shown = phone ? [phoneView] : maximized && visible.includes(maximized) ? [maximized] : visible;

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
  // The roofline sets the scale (see keepScale): a layout saved before it did takes it when it opens.
  const scaleChecked = useRef(false);
  useEffect(() => {
    if (!layout || scaleChecked.current) return;
    scaleChecked.current = true;
    const r = autoScale(layout);
    if (!r || r.scale === layoutScale(layout)) return;
    edit((l) => l);
    toast(`The roofline sets the scale now: its strings make the front view ${measureOf({ ...layout, scale: r.scale }).text(layout.width)} wide. Objects keep their size. Save to keep it.`, { id: 'scale' });
  }, [layout]);

  const dirty = !!layout && !!saved && JSON.stringify(layout) !== JSON.stringify(saved);
  const stage = useMemo(() => (layout ? buildStage(layout) : null), [layout]);
  const sel = layout?.fixtures.find((f) => f.id === selected) ?? null;
  // The wizard runs while its line is selected with one of its points, and no segment.
  const matching = match && sel && sel.id === match.id && isLine(sel) && segment == null && corner != null && corner < sel.points.length ? sel : null;
  // Shape to the lights runs while its tree is selected (and still takes marks).
  const shapeSel = shaping && sel && sel.id === shaping.id && takesMarks(sel) && !matching ? sel : null;
  const probe: MatchProbe | null =
    matching && corner != null
      ? { point: corner, offset: match!.point === corner ? match!.offset : pointOffsets(matching)[corner] }
      : shapeSel
        ? { point: 0, offset: Math.max(0, Math.min(Math.floor(shapeSel.pixels) - 1, shaping!.led)) }
        : null;
  useEffect(() => {
    if (match && !matching) setMatch(null);
  }, [match, matching]);
  useEffect(() => {
    if (shaping && !shapeSel) setShaping(null);
  }, [shaping, shapeSel]);
  // An object's check ends when no object is selected; another selected object takes it over.
  useEffect(() => {
    if (!selected && (check?.kind === 'picture' || check?.kind === 'chase')) setCheck(null);
  }, [selected, check]);
  /** The check to show now: the wizard's blinking LED wins over it. */
  const layoutCheck = layout && !probe ? validCheck(toLayoutCheck(check, selected), layout) : null;
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
  const fxRef = useRef<{ effects: LayoutEffects; last: number } | null>(null);
  useEffect(() => {
    if (!playing || !stage || !layout) {
      fxRef.current = null;
      return;
    }
    // Objects whose effect and LED count stay the same keep running smoothly.
    if (fxRef.current) fxRef.current.effects.sync(stage, layout);
    else fxRef.current = { effects: new LayoutEffects(stage, layout), last: performance.now() };
  }, [playing, stage, layout]);
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
        const r = isLine(f) ? 0 : f.kind === 'custom' ? designReach(f, s) : radiusOf(f);
        lo = Math.min(lo, (p.z ?? 0) - r - 1.5 * s);
        hi = Math.max(hi, (p.z ?? 0) + r + 1.5 * s);
      }
    zRangeRef.current = [Math.floor(lo / s) * s, Math.ceil(hi / s) * s];
    return zRangeRef.current;
  }, [layout, stage, dragging]);
  const zMin = zRange[0];
  /** The front view's camera, when it is turned to where the picture was taken from (see frontCamera). */
  const frontCam = frontCamera(layout);

  useEffect(() => {
    if (keepPart.current) {
      keepPart.current = false;
      return;
    }
    setCorner(null);
    setSegment(null);
  }, [selected]);
  // On a phone, a selection (in the views or the list) shows its properties in the bottom sheet.
  useEffect(() => {
    if (selected) setSheetTab('details');
  }, [selected]);
  // A segment or a point picked in a view opens its own section of the phone's inspector.
  useEffect(() => {
    const f = layoutRef.current?.fixtures.find((x) => x.id === selected);
    if (!f || !isLine(f)) return;
    const part = segment != null ? 'segment' : corner == null ? null : corner > 0 && corner < f.points.length - 1 ? 'corner' : 'position';
    if (part) setAccOpen((a) => ({ ...a, object: part }));
  }, [selected, segment, corner]);

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
  /** The side panel, which scrolls (on wide screens) through the object list and the selected object's properties. */
  const sidePanel = useRef<HTMLElement>(null);
  // A newly selected object (in the views, too) scrolls to the top of the side panel, so its
  // properties are in sight, unless its row is already near the top.
  useEffect(() => {
    const panel = sidePanel.current;
    if (!selected || !panel || panel.scrollHeight <= panel.clientHeight) return;
    const row = panel.querySelector<HTMLElement>(`[data-object-row="${CSS.escape(selected)}"]`);
    if (!row) return;
    const top = row.getBoundingClientRect().top - panel.getBoundingClientRect().top;
    if (top < 0 || top > panel.clientHeight * 0.35) panel.scrollTo({ top: panel.scrollTop + top - 4, behavior: 'smooth' });
  }, [selected]);
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

  /**
   * Changes the layout, and keeps the state before it for Undo. Locked objects stay where they
   * are (see keepLocked), unless `force` (Revert).
   */
  const edit = (fn: (l: Layout) => Layout, force = false) => {
    const cur = layoutRef.current;
    if (!cur) return;
    if (history.record(cur)) setHistoryTick((n) => n + 1);
    setLayout((l) => {
      if (!l) return l;
      const next = fn(l);
      if (force) return next;
      // The roofline sets the scale (see keepScale), wires stay within their strings (see
      // keepStrings), then locked objects stay put.
      const settle = (want: Layout) => {
        const scaled = keepScale(l, want);
        const strung = keepStrings(scaled.prev, scaled.layout);
        return { strung, kept: keepLocked(scaled.prev, strung.layout) };
      };
      let { strung, kept } = settle(next);
      // A locked roof that did not move: the scale is the one it gives as it is.
      const r = kept.blocked.length ? autoScale(kept.layout) : null;
      if (r && r.scale !== kept.layout.scale) ({ strung, kept } = settle(kept.layout));
      if (strung.limited.length) stringNote(strung.limited, strung.layout);
      if (kept.blocked.length) lockedNote(kept.blocked);
      return kept.layout;
    });
  };
  /** Says (one toast at a time) why an object did not stretch any farther. */
  const stringNote = (names: string[], l: Layout) => {
    const f = l.fixtures.find((x) => x.name === names[0]);
    const lt = f ? lightsOf(l, f.lights) : null;
    const reach = f && lt ? ` (${f.pixels} LEDs, ${spacingText(lt.spacing, l.units ?? 'ft')} apart)` : '';
    toast(`${names.length > 1 ? `${names.length} objects reach` : `${names[0]} reaches`} as far as ${names.length > 1 ? 'their strings go' : `its string goes${reach}`}. Give it more LEDs (another string) to make it bigger.`, { id: 'string' });
  };
  /** Says (one toast at a time) why a locked object did not move. */
  const lockedNote = (names: string[]) =>
    toast.error(`${names.length > 1 ? `${names.length} objects are` : `${names[0]} is`} locked in place. Unlock ${names.length > 1 ? 'them' : 'it'} to move, reshape or delete ${names.length > 1 ? 'them' : 'it'}.`, { id: 'locked' });
  /** Makes objects another kind of shape (a bush a tree, say), keeping the rest (see changeKind). Locked ones stay as they are. */
  const setKind = (ids: string[], kind: ShapeKind) => {
    const fs = layoutRef.current?.fixtures.filter((f) => ids.includes(f.id) && isShapeKind(f.kind) && f.kind !== kind) ?? [];
    const locked = fs.filter((f) => f.locked);
    if (locked.length) lockedNote(locked.map((f) => f.name));
    const go = new Set(fs.filter((f) => !f.locked).map((f) => f.id));
    if (go.size) edit((l) => ({ ...l, fixtures: l.fixtures.map((f) => (go.has(f.id) ? changeKind(f, kind) : f)) }));
  };
  const setLocked = (ids: string[], locked: boolean) =>
    edit((l) => ({ ...l, fixtures: l.fixtures.map((f) => (ids.includes(f.id) ? { ...f, locked: locked || undefined } : f)) }));
  const undo = () => {
    const prev = layoutRef.current && history.undo(layoutRef.current);
    if (!prev) return;
    setLayout(prev);
    setHistoryTick((n) => n + 1);
  };
  const redo = () => {
    const next = layoutRef.current && history.redo(layoutRef.current);
    if (!next) return;
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
      update(f.id, first !== cur.first ? pinPoint(f, 0, clampPointLed(f, 0, first)) : pinPoint(f, lastPoint, clampPointLed(f, lastPoint, last)));
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
      update(f.id, pinPoint(f, index, clampPointLed(f, index, led)));
      return;
    }
    update(f.id, unpinPoint(f, index));
  };

  /** Starts Shape to the lights on a tree, at its last mark (or its first LED). */
  const startShape = (f: Fixture) => {
    if (!showOnLights) toggleShow();
    setPlaying(false);
    setSelected(f.id);
    setSegment(null);
    setCorner(null);
    setMatch(null);
    setShaping({ id: f.id, led: validMarks(f).at(-1)?.led ?? 0 });
  };
  const setShapeLed = (led: number) => shapeSel && setShaping({ id: shapeSel.id, led: Math.max(0, Math.min(Math.floor(shapeSel.pixels) - 1, Math.round(led))) });
  /** Moves the tree's blinking LED to the first LED of the next (1) or the previous (-1) strand, counted from device LED 0. */
  const shapeStrand = (dir: 1 | -1) => {
    const per = shapeSel ? lightsOf(layout ?? undefined, shapeSel.lights)?.perStrand : null;
    if (!shapeSel || !probe || !per) return;
    const led = deviceLed(shapeSel, probe.offset);
    const target = dir > 0 ? (Math.floor(led / per) + 1) * per : led % per ? Math.floor(led / per) * per : led - per;
    setShapeLed(probe.offset + (shapeSel.reversed ? led - target : target - led));
  };
  /** Marks the blinking LED at this angle round the tree, as seen from the street (its height: where it is now, or as marked). */
  const shapeMark = (streetAngle: number) => shapeSel && probe && update(shapeSel.id, { marks: markAt(shapeSel, probe.offset, streetAngle) });
  /** Moves the blinking LED's mark by steps, as seen from the street: right, up, toward the street. */
  const shapeMove = (x: number, y: number, z: number) => {
    if (!shapeSel || !probe || !layout) return;
    const d = shapeStep(layout);
    update(shapeSel.id, { marks: moveMark(shapeSel, probe.offset, { x: x * d, y: y * d, z: z * d }) });
  };
  /** Moves the blinking LED's mark up (1) or down (-1) by one step. */
  const shapeNudge = (dir: 1 | -1) => {
    if (!shapeSel || !probe || !layout) return;
    if (!validMarks(shapeSel).some((m) => m.led === probe.offset)) return;
    const lit = Math.max(1e-6, treeSize(shapeSel).h * (1 - litFloor(shapeSel)));
    update(shapeSel.id, { marks: raiseMark(shapeSel, probe.offset, (dir * shapeStep(layout)) / lit) });
  };

  /** Starts the wizard on a line at one of its points (default: the start). */
  const startMatch = (f: Fixture, point = 0) => {
    if (!showOnLights) toggleShow();
    setPlaying(false);
    setSelected(f.id);
    setSegment(null);
    setCorner(point);
    setMatch({ id: f.id, point, offset: pointOffsets(f)[point] });
  };
  /** Moves the wizard to another point of its line, starting from that point's LED. */
  const matchGo = (point: number, f: Fixture | null = matching) => {
    if (!f || point < 0 || point >= f.points.length) return;
    setCorner(point);
    setMatch({ id: f.id, point, offset: pointOffsets(f)[point] });
  };
  /** The LEDs the device has, as set in WLED (null: not known yet). */
  const ledCountOf = (f: Fixture) => overview?.devices.find((d) => d.id === f.deviceId)?.info?.leds?.count || null;
  const setProbe = (offset: number) => {
    if (!matching || !probe) return;
    const { lo, hi } = matchRange(matching, probe.point, ledCountOf(matching));
    setMatch({ id: matching.id, point: probe.point, offset: Math.min(hi, Math.max(lo, Math.round(offset))) });
  };
  const moveProbe = (delta: number) => setProbe((probe?.offset ?? 0) + delta);
  /** Moves the blinking LED to the first LED of the next (1) or the previous (-1) strand, counted from device LED 0. */
  const strandJump = (f: Fixture, dir: 1 | -1) => {
    const per = lightsOf(layout ?? undefined, f.lights)?.perStrand;
    if (!probe || !per) return;
    const led = deviceLed(f, probe.offset);
    const target = dir > 0 ? (Math.floor(led / per) + 1) * per : led % per ? Math.floor(led / per) * per : led - per;
    // Device numbers run against the offsets on a line that counts down.
    setProbe(probe.offset + (f.reversed ? led - target : target - led));
  };
  /** The blinking LED is at the real spot: the point takes it, and the wizard goes on to the next point. */
  const matchFound = () => {
    if (!matching || !probe) return;
    const patch = matchPoint(matching, probe.point, probe.offset, ledCountOf(matching));
    update(matching.id, patch);
    const g = { ...matching, ...patch };
    if (probe.point >= g.points.length - 1) {
      setMatch(null);
      setCorner(null);
      toast.success(`${g.name} matches the lights: LEDs ${ledRange(g).first}–${ledRange(g).last}.`);
    } else matchGo(probe.point + 1, g);
  };

  /** Cuts a line in two at a corner. The second part starts at the next LED; raise its first LED to leave a gap. */
  const splitAt = (f: Fixture, k: number) => {
    const parts = splitLine(f, k, uid());
    if (!parts) {
      toast.error('Each part needs at least one LED. Move the corner or add LEDs first.');
      return;
    }
    const [a, b] = parts;
    edit((l) => ({ ...l, fixtures: l.fixtures.flatMap((x) => (x.id === f.id ? [a, b] : [x])) }));
    setSelected(b.id);
    toast.success(`Split into ${a.name} and ${b.name}. Set the first LED of ${b.name} to leave a gap.`);
  };

  const remove = (id: string) => {
    const f = layout?.fixtures.find((x) => x.id === id);
    if (f?.locked) return lockedNote([f.name]);
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
    const patch = removePoint(f, i);
    if (!patch) {
      toast.error('A line needs at least two points. Delete the whole line instead.');
      return;
    }
    update(f.id, patch);
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

  /** The layout as one view shows it (see LayoutInView). */
  const inView = (side: ViewSide) => new LayoutInView(layout, side, zMin);

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
        const hit = inView(d.side).pointAt(p);
        prev = hit ? { ...hit } : fromView(p, d.side, zMin, prev, frontCam);
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
        // Whole strings, enough to reach along the line.
        const fits = lt ? wholeStrands(ledsForLength(len / layoutScale(layout), lt.spacing), lt.perStrand) : 0;
        return { pixels: lt ? Math.min(lt.perStrand ? Math.floor(MAX_FIXTURE_PIXELS / lt.perStrand) * lt.perStrand : MAX_FIXTURE_PIXELS, fits) : kind === 'roof' && !roofs.length ? 450 : 100, ...(lt ? { lights: lt.id } : {}) };
      })(),
      deviceId,
      startPixel: nextFree(deviceId),
      reversed: false
    });
  }

  const chooseTool = (t: Tool) => {
    setTool(t);
    setAddOpen(false);
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
    setDraft({ side, pts: [toView(end, side, zMin, frontCam)], cont: { id: f.id, at } });
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
      if (probe && shapeSel) {
        // Shape to the lights: arrows move the blinking LED, letters mark where it is.
        const step = e.shiftKey ? 10 : 1;
        const k = e.key.toLowerCase();
        const wave = shapeSel.pattern === 'wave';
        if (e.altKey && e.key.startsWith('Arrow')) shapeMove(e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0, e.key === 'ArrowUp' ? 1 : e.key === 'ArrowDown' ? -1 : 0, 0);
        else if (e.altKey && (e.key === 'PageUp' || e.key === 'PageDown')) shapeMove(0, 0, e.key === 'PageDown' ? 1 : -1);
        else if (e.key === 'ArrowRight' || e.key === 'ArrowUp') setShapeLed(probe.offset + step);
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') setShapeLed(probe.offset - step);
        else if (e.key === 'Home') setShapeLed(0);
        else if (e.key === 'End') setShapeLed(shapeSel.pixels - 1);
        else if (e.key === 'PageUp' || e.key === 'PageDown') shapeStrand(e.key === 'PageDown' ? 1 : -1);
        else if (k === 'f') shapeMark(0);
        else if (k === 'r') shapeMark(90);
        else if (k === 'l') shapeMark(-90);
        else if (k === 'b' && !wave) shapeMark(180);
        else if (e.key === '[' || e.key === ']') shapeNudge(e.key === ']' ? 1 : -1);
        else if (e.key === 'Delete' || e.key === 'Backspace') {
          const rest = validMarks(shapeSel).filter((m) => m.led !== probe.offset);
          update(shapeSel.id, { marks: rest.length ? rest : undefined });
        } else if (e.key === 'Escape' || e.key === 'Enter') setShaping(null);
        else return;
        e.preventDefault();
        return;
      }
      if (probe && matching) {
        // The wizard: arrows move the blinking LED along the line, Enter takes it.
        const step = e.shiftKey ? 10 : 1;
        if (e.key === 'ArrowRight' || e.key === 'ArrowUp') moveProbe(step);
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') moveProbe(-step);
        else if (e.key === 'PageUp' || e.key === 'PageDown') strandJump(matching, e.key === 'PageDown' ? 1 : -1);
        else if (e.key === 'Enter') matchFound();
        else if (e.key === 'Escape') setMatch(null);
        else if (e.key === 'Backspace') matchGo(probe.point - 1);
        else return;
        e.preventDefault();
        return;
      }
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
          const whole = multi.filter((x) => effectTarget(x).segment == null);
          if (!whole.length) return void toast.error('Only segments are selected. To delete a segment, delete its points.');
          const ids = new Set(whole.filter((id) => !layout?.fixtures.find((f) => f.id === id)?.locked));
          if (!ids.size) return void lockedNote(whole.map((id) => layout?.fixtures.find((f) => f.id === id)?.name ?? id));
          edit((l) => ({ ...l, fixtures: l.fixtures.filter((f) => !ids.has(f.id)) }));
          setMulti([]);
          const kept = whole.length - ids.size;
          toast.success(`${ids.size} object(s) deleted${kept ? `; ${kept} locked one(s) kept` : ''}. Ctrl/⌘+Z brings them back.`);
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
  // Only while this window has focus (see useInFront).
  const inFront = useInFront();
  /** The object designer lights an object for its photo: this preview waits meanwhile. */
  const [photoLights, setPhotoLights] = useState(false);
  const previewing = showOnLights && mapped && inFront && !photoLights;
  useLightsPreview(previewing && layout ? { layout, selected, corner, segment, play: playing && fxCount > 0 && !probe && !layoutCheck, probe, check: layoutCheck } : null, {
    active: previewing,
    onDevices: setPreviewDevices,
    onError: () => setPreviewDevices([])
  });
  const toggleShow = () => {
    setShowOnLights((v) => {
      try {
        localStorage.setItem(SHOW_KEY, v ? 'off' : 'on');
      } catch {}
      return !v;
    });
  };

  // Simulator: the same picture as the real lights get (see editorFrame on the server).
  const getFrame = () => {
    if (!stage || !layout) return null;
    const fx = fxRef.current;
    // The effects, while they play; the wizard and a check show what they test instead.
    if (playing && fx && fx.effects.stage === stage && !(probe && selected) && !layoutCheck) {
      // Every view asks on each animation frame: draw once per frame.
      const now = performance.now();
      if (now - fx.last > 4) {
        fx.effects.frame(Math.min(0.1, (now - fx.last) / 1000));
        fx.last = now;
      }
      return fx.effects.bytes;
    }
    const out = new Uint8Array(stage.pixelCount * 3);
    // Same clock as the server, so the drawing pulses (and a check moves) together with the real lights.
    const now = Date.now();
    paintEditorView(layout, stage, { selected, corner, segment, probe, check: layoutCheck }, now, editorPulse(now), framePut(stage, out), out);
    return out;
  };


  /** v minus the world coordinate in a view: the top view counts v from the back edge (zMin). */
  const offOf = (side: ViewSide) => (side === 'top' ? -zMin : 0);
  /** Everything a view shows when it is zoomed to fit, in view units. */
  const contentBox = (side: ViewSide): Box => {
    // The picture (or the depth range), and every object, as "zoom extents" does in CAD programs.
    let x0 = side === 'side' ? zRange[0] : 0;
    let y0 = 0;
    let x1 = side === 'side' ? zRange[1] : (layout?.width ?? LAYOUT_WIDTH);
    let y1 = side === 'top' ? zRange[1] - zRange[0] : (layout?.height ?? 900);
    for (const f of layout?.fixtures ?? []) {
      const b = inView(side).box(f);
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

  // A camera change that glides (framing an object), stopped by anything that moves a camera by hand.
  const glide = useRef(0);
  const stopGlide = () => cancelAnimationFrame(glide.current);
  useEffect(() => stopGlide, []);
  function glideTo(next: Partial<Record<ViewSide, Cam>>) {
    stopGlide();
    let still = false;
    try {
      still = matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {}
    const from: Partial<Record<ViewSide, Cam>> = {};
    for (const side of SIDES) from[side] = camFor(side);
    if (still) return setCams(next);
    const t0 = performance.now();
    const step = () => {
      const t = Math.min(1, (performance.now() - t0) / 320);
      const e = 1 - (1 - t) ** 3;
      const c: Partial<Record<ViewSide, Cam>> = {};
      for (const side of SIDES) c[side] = next[side] && from[side] ? lerpCam(from[side], next[side], e) : next[side];
      setCams(c);
      if (t < 1) glide.current = requestAnimationFrame(step);
    };
    glide.current = requestAnimationFrame(step);
  }

  /**
   * F: zoom every 2D view to the selected object (centered, filling the view, with room for its
   * handles), or to the whole yard when nothing is selected.
   */
  function frameSelection(id = selected) {
    const f = layout?.fixtures.find((x) => x.id === id);
    if (!f || !layout) return (stopGlide(), setCams({}));
    const next: Partial<Record<ViewSide, Cam>> = {};
    for (const side of SIDES) next[side] = frameCam(inView(side).box(f), sizeOf(side), offOf(side), coarse ? 64 : 48, layoutScale(layout));
    glideTo(next);
    setFocus3d((n) => ({ id: f.id, n: (n?.n ?? 0) + 1 }));
  }
  /** + and −: zoom the view under the pointer (or every 2D view) about its middle. */
  function zoomViews(factor: number) {
    stopGlide();
    const sides = cursor ? [cursor.side] : SIDES;
    setCams((c) => {
      const next = { ...c };
      for (const side of sides) next[side] = zoomAt(c[side] ?? camFor(side), sizeOf(side), { x: sizeOf(side).w / 2, y: sizeOf(side).h / 2 }, factor);
      return next;
    });
  }
  /** The wheel zooms at the pointer (as in CAD programs); a pinch on a trackpad too. A sideways swipe pans. */
  function onWheel(side: ViewSide, e: WheelEvent, rect: DOMRect) {
    stopGlide();
    setCams((c) => {
      const cam = c[side] ?? camFor(side);
      if (!e.ctrlKey && Math.abs(e.deltaX) > Math.abs(e.deltaY)) return { ...c, [side]: panBy(cam, -e.deltaX, 0) };
      return { ...c, [side]: zoomAt(cam, sizeOf(side), { x: e.clientX - rect.left, y: e.clientY - rect.top }, wheelFactor(e)) };
    });
  }

  // Touch: two fingers pan and zoom a 2D view (a pinch), as in maps and drawing apps. The first
  // finger of a pinch has already reached the view as a tap (a point drawn, a drag begun, the
  // selection cleared), so when the second finger follows quickly, what the first one did is
  // taken back.
  const touchStart = useRef<{
    at: number;
    layout: Layout | null;
    past: number;
    draft: Draft;
    tape: typeof tape;
    alignPts: UV[];
    selected: string | null;
    corner: number | null;
    segment: number | null;
    multi: string[];
    tool: Tool;
  } | null>(null);
  const pinchCam = useRef<Cam | null>(null);
  const onTouchFirst = () => {
    touchStart.current = { at: performance.now(), layout: layoutRef.current, past: history.mark(), draft, tape, alignPts, selected, corner, segment, multi, tool };
  };
  const onPinchStart = (side: ViewSide) => {
    const s = touchStart.current;
    setDrag(null);
    setSnapHint(null);
    setCursor(null);
    if (s && performance.now() - s.at < 600) {
      if (s.layout && layoutRef.current !== s.layout) {
        history.rollback(s.past);
        setLayout(s.layout);
        setHistoryTick((n) => n + 1);
      }
      if (s.selected !== selected) {
        keepPart.current = true;
        setSelected(s.selected);
      }
      setCorner(s.corner);
      setSegment(s.segment);
      setMulti(s.multi);
      setTool(s.tool);
      setDraft(s.draft);
      setTape(s.tape);
      setAlignPts(s.alignPts);
    }
    stopGlide();
    pinchCam.current = camFor(side);
  };
  const onPinch = (side: ViewSide, from: Pair, to: Pair) => {
    const start = pinchCam.current;
    if (start) setCams((c) => ({ ...c, [side]: pinch(start, sizeOf(side), from, to) }));
  };
  // One finger pans (with the Select tool, away from the handles), as in maps.
  const onTouchPanStart = (side: ViewSide) => {
    stopGlide();
    pinchCam.current = camFor(side);
  };
  const onTouchPan = (side: ViewSide, dx: number, dy: number) => {
    const start = pinchCam.current;
    if (start) setCams((c) => ({ ...c, [side]: panBy(start, dx, dy) }));
  };

  /** The pointer position in one view, in layout units. */
  function viewPoint(e: { clientX: number; clientY: number }, side: ViewSide): UV {
    const ctm = svgs.current[side]?.getScreenCTM();
    if (!ctm) return { u: 0, v: 0 };
    const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
    return { u: Math.round(p.x), v: Math.round(p.y) };
  }

  // Picking: what a click, a tap or a hold in a view selects. The object nearest the pointer
  // (its wire or its LEDs), else the smallest one it is inside (see yard/pick.ts).
  const pickCache = useRef<{ stage: unknown; zMin: number; sides: Partial<Record<ViewSide, PickShape[]>> } | null>(null);
  const pickShapes = (side: ViewSide): PickShape[] => {
    if (!layout || !stage) return [];
    if (pickCache.current?.stage !== stage || pickCache.current.zMin !== zMin) pickCache.current = { stage, zMin, sides: {} };
    const cached = pickCache.current.sides[side];
    if (cached) return cached;
    const view = inView(side);
    const V = (p: Point) => view.at(p);
    const pos = viewPositions(stage.positions3, side, zMin, view.cam);
    const leds = new Map(stage.fixtures.map((x) => [x.id, pos.subarray(x.offset * 2, (x.offset + x.count) * 2)]));
    const upright = side !== 'top';
    const shapes = layout.fixtures.map((f): PickShape => {
      if (isLine(f)) return { id: f.id, line: true, wire: [f.points.map(V)] };
      let area: UV[];
      if (f.kind === 'custom' || f.kind === 'semicircle') {
        const b = view.box(f);
        area = [{ u: b.x, v: b.y }, { u: b.x + b.w, v: b.y }, { u: b.x + b.w, v: b.y + b.h }, { u: b.x, v: b.y + b.h }];
      } else if (f.kind === 'tree' && upright) area = treeOutline(f, side === 'side' ? 'side' : view.cam ? acrossOf(view.cam) : 'front').map(V);
      else area = ellipsePolygon(V(f.points[0]), radiusOf(f), upright ? radiusOf(f) * BUSH_TALL : radiusOf(f));
      return { id: f.id, wire: drawnByPaths(f) ? objectPaths(f, layoutScale(layout)).map((path) => path.map(V)) : [], leds: leds.get(f.id), area };
    });
    pickCache.current.sides[side] = shapes;
    return shapes;
  };
  /** How near (screen pixels) the pointer must be to an object to pick it: a finger is less exact than a mouse. */
  const PICK_PX = { mouse: 12, touch: 24 };
  /** The object at a spot in a view; `only` limits what can be picked. */
  const pickIn = (side: ViewSide, e: { clientX: number; clientY: number }, px: number, only?: (f: Fixture) => boolean): (Picked & { f: Fixture }) | null => {
    const ctm = svgs.current[side]?.getScreenCTM();
    if (!ctm || !layout) return null;
    const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
    const byId = new Map(layout.fixtures.map((f) => [f.id, f]));
    const shapes = only ? pickShapes(side).filter((s) => only(byId.get(s.id)!)) : pickShapes(side);
    const hit = pickAt(shapes, { u: p.x, v: p.y }, px / (ctm.a || 1));
    const f = hit && byId.get(hit.id);
    return f ? { ...hit, f } : null;
  };
  /** The object under the mouse (Select and Edit tools): outlined, so you see what a click picks. */
  const [hover, setHover] = useState<{ side: ViewSide; id: string } | null>(null);

  // Picking an object (in a view, the list or the 3D view) frames it in the views: centered and
  // filling them. Not while it is being dragged (the view would move under the pointer), and not
  // when the drag moved it; nor for objects selected in other ways (one just drawn, an undo).
  const framePending = useRef<string | null>(null);
  const dragFrom = useRef<Layout | null>(null);
  /** The 3D view flies to this object (n: each time). */
  const [focus3d, setFocus3d] = useState<{ id: string; n: number } | null>(null);
  const choose = (id: string | null) => {
    if (id && id !== selected) framePending.current = id;
    setSelected(id);
  };
  /** A click in a view frames a moment later, so the second click of a double-click (which adds a point) lands where it was aimed: it calls the framing off. */
  const frameTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const frameLater = useRef(false);
  useEffect(() => {
    const id = framePending.current;
    if (!id || drag) return;
    framePending.current = null;
    if (id !== selected) return;
    clearTimeout(frameTimer.current);
    if (frameLater.current) frameTimer.current = setTimeout(() => frameSelection(id), 300);
    else frameSelection(id);
    frameLater.current = false;
  }, [selected, drag]);
  useEffect(() => () => clearTimeout(frameTimer.current), []);

  // Touch: one finger pans the view, and holding it still on an object selects that object (on
  // the selected one, it opens its menu). A tap selects nothing, so panning never picks by mistake.
  /** Whether one finger on this element pans: with the Select tool everywhere but the handles; with Edit and Split, away from the lines too. */
  const touchPans = (target: Element) =>
    !panMode && (tool === 'select' ? !target.closest('[data-handle]') : (tool === 'edit' || tool === 'split') && !target.closest('[data-handle],[data-hit]'));
  const fingerPick = (side: ViewSide, x: number, y: number) => pickIn(side, { clientX: x, clientY: y }, PICK_PX.touch);
  const onHold = (side: ViewSide, x: number, y: number): HoldResult => {
    const hit = fingerPick(side, x, y);
    if (!hit) return null;
    if (!multi.length && hit.f.id === selected && (!isLine(hit.f) || hit.seg === segment)) return 'menu';
    if (tool !== 'select') setTool('select');
    setMulti([]);
    choose(hit.f.id);
    if (isLine(hit.f)) selectSegment(hit.f.id, hit.seg);
    return 'selected';
  };
  const onTap = (side: ViewSide, x: number, y: number) => {
    const hit = fingerPick(side, x, y);
    if (!hit) {
      setSelected(null);
      setMulti([]);
    } else if (hit.f.id === selected) {
      if (isLine(hit.f) && tool === 'select') selectSegment(hit.f.id, hit.seg);
    } else toast(`Hold your finger on ${hit.f.name} to select it.`, { id: 'hold-to-select' });
  };

  /** The snap distance: 10 screen pixels, in layout units. */
  const tolFor = (side: ViewSide) => {
    const ctm = svgs.current[side]?.getScreenCTM();
    return ctm?.a ? 10 / ctm.a : 10;
  };

  /** What can be snapped to in a view. `exclude`: a point being dragged, and its two segments. */
  const targetsFor = (side: ViewSide, exclude?: PointRef, linesOnly = false): SnapTargets => {
    const t = inView(side).targets(exclude, linesOnly);
    if (!linesOnly && draft.side === side) {
      t.points.push(...draft.pts);
      for (let k = 0; k < draft.pts.length - 1; k++) t.segments.push([draft.pts[k], draft.pts[k + 1]]);
    }
    return t;
  };

  /** The snapping grid of a view, when Grid snap is on (Alt: off for now). It counts from the left edge, and from the ground (front) or the front wall (top), as drawn. */
  const gridFor = (side: ViewSide, e: { altKey: boolean }): SnapGrid | null =>
    layout && drafting.gridSnap && !e.altKey ? { step: gridOf(drafting, layout).step, origin: { u: 0, v: side === 'top' ? -zMin : layoutGround(layout) } } : null;

  /**
   * The pointer position, snapped. Shift: 45° steps from `from`; Ortho: 90° steps (`angle`
   * overrides both). Alt turns snapping off (or on, when Snap is off), and grid snapping off.
   */
  const snapAt = (
    e: { clientX: number; clientY: number; shiftKey: boolean; altKey: boolean },
    side: ViewSide,
    from?: UV | null,
    exclude?: { id: string; index: number },
    angle?: number
  ) =>
    snapPoint(viewPoint(e, side), targetsFor(side, exclude), tolFor(side), {
      from,
      angle: angle ?? (e.shiftKey ? 45 : drafting.ortho ? 90 : false),
      snap: drafting.snap !== e.altKey,
      grid: gridFor(side, e)
    });

  /** The end of a line near this spot, for continuing that line. */
  const lineEndAt = (side: ViewSide, at: UV) => inView(side).lineEndAt(at, tolFor(side));

  /** The 3D point on segment k of a line nearest to a spot in a view. */
  const pointOnLine = (f: Fixture, k: number, raw: UV, side: ViewSide): Point => inView(side).pointOnLine(f, k, raw);

  /** Adds a point on segment k and selects it; with `drag`, the pointer then moves it. */
  const addPointOn = (f: Fixture, k: number, raw: UV, side: ViewSide, drag?: RPointerEvent) => {
    if (f.locked) return void (drag?.stopPropagation(), setSelected(f.id), lockedNote([f.name]));
    update(f.id, insertPoint(f, k, pointOnLine(f, k, raw, side)));
    if (f.id !== selected) keepPart.current = true;
    setSelected(f.id);
    setCorner(k + 1);
    setSegment(null);
    if (drag) {
      drag.stopPropagation();
      svgs.current[side]?.setPointerCapture(drag.pointerId);
      setDrag({ kind: 'vertex', side, id: f.id, index: k + 1, start: toView(pointOnLine(f, k, raw, side), side, zMin, frontCam) });
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
      ...(isShapeKind(f.kind)
        ? SHAPE_KINDS.filter((k) => k !== f.kind).map((k) => ({ label: `Make it a ${KIND_LABELS[k].toLowerCase()}`, run: () => setKind([f.id], k) }))
        : []),
      { label: f.locked ? 'Unlock' : 'Lock in place', run: () => setLocked([f.id], !f.locked) },
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
        run: () => update(f.id, setSkipped(f, k, !off))
      },
      { label: `Delete ${f.name}`, danger: true, run: () => remove(f.id) }
    ]);
  };

  function onPointerDown(e: RPointerEvent<SVGSVGElement>, side: ViewSide) {
    clearTimeout(frameTimer.current);
    // Pan: the middle button, Space-drag, or the Hand tool.
    if (e.button === 1 || (e.button === 0 && panMode)) {
      e.preventDefault();
      stopGlide();
      svgs.current[side]?.setPointerCapture(e.pointerId);
      setDrag({ kind: 'pan', side, x: e.clientX, y: e.clientY, cam: camFor(side) });
      return;
    }
    if (e.button !== 0) return;
    if (side === 'side' && (isLineTool(tool) || tool === 'bush' || tool === 'tree' || tool === 'semicircle')) {
      return void toast('Draw new objects in the front or top view. The side view moves, turns and tilts them.', { id: 'side-draw' });
    }
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
    if (tool === 'bush' || tool === 'tree' || tool === 'semicircle') {
      const p = snapAt(e, side).at;
      svgs.current[side]?.setPointerCapture(e.pointerId);
      setDrag({ kind: 'newShape', shape: tool, side, at: p, size: 0 });
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
    // Select (and Edit, for objects that are not lines): what is nearest the pointer. A press
    // picks it and starts moving it; Ctrl/⌘ adds it to the selection or takes it out.
    if ((tool === 'select' || tool === 'edit') && !panMode) {
      const hit = pickIn(side, e, e.pointerType === 'touch' ? PICK_PX.touch : PICK_PX.mouse, tool === 'edit' ? (f) => !isLine(f) : undefined);
      if (hit) {
        const { f } = hit;
        if (tool === 'select' && (e.ctrlKey || e.metaKey)) {
          skipMenu(e);
          return toggleTarget(isLine(f) ? effectKey(f.id, hit.seg) : f.id);
        }
        if (f.id !== selected) {
          framePending.current = f.id;
          frameLater.current = e.pointerType !== 'touch';
        }
        startDrag(e, { kind: 'move', side, id: f.id, from: viewPoint(e, side), original: f.points }, f.id, side);
        if (isLine(f) && tool === 'select') selectSegment(f.id, hit.seg);
        return;
      }
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
    stopGlide();
    clearTimeout(frameTimer.current);
    dragFrom.current = layoutRef.current;
    // A locked object is selected, but stays where it is.
    const target = 'id' in d ? d.id : null;
    if (target && layout?.fixtures.find((f) => f.id === target)?.locked) d = { kind: 'locked', id: target, from: viewPoint(e, side), warned: false };
    svgs.current[side]?.setPointerCapture(e.pointerId);
    // A new drag is a new step for Undo.
    history.newStep();
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
        setHover(null);
        setCursor({ ...p, side });
        return;
      }
      // Outline what a click would pick.
      if ((tool === 'select' || tool === 'edit') && e.pointerType !== 'touch') {
        const h = pickIn(side, e, PICK_PX.mouse, tool === 'edit' ? (f) => !isLine(f) : undefined);
        setHover((o) => (!h ? null : o?.id === h.f.id && o.side === side ? o : { side, id: h.f.id }));
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
      } else if (tool === 'bush' || tool === 'tree' || tool === 'semicircle') {
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
    if (drag.kind === 'locked') {
      // Past a small wobble of the pointer: say why it does not move.
      if (!drag.warned && f && Math.hypot(p.u - drag.from.u, p.v - drag.from.v) > tolFor(side)) {
        lockedNote([f.name]);
        setDrag({ ...drag, warned: true });
      }
    } else if (drag.kind === 'vertex' && f) {
      const i = drag.index;
      const V = (q: Point) => toView(q, side, zMin, frontCam);
      // Shift: move the point straight across or straight up and down from where it was (to
      // raise the middle of a roofline into a peak, say). Ortho: keep the segment to the point
      // before (or after, for the first point) level or upright.
      const neighbour = f.points[i - 1] ?? f.points[i + 1];
      const s = e.shiftKey ? snapAt(e, side, drag.start, { id: f.id, index: i }, 90) : snapAt(e, side, neighbour ? V(neighbour) : null, { id: f.id, index: i });
      setSnapHint({ ...s, side });
      // On another point: take that point's position in 3D, so the two points join.
      const hit = s.kind === 'point' ? inView(side).pointAt(s.at, { id: f.id, index: i }) : undefined;
      update(drag.id, { points: f.points.map((q, j) => (j === i ? (hit ? { ...hit } : fromView(s.at, side, zMin, q, frontCam)) : q)) });
    } else if (drag.kind === 'move') {
      let du = p.u - drag.from.u;
      let dv = p.v - drag.from.v;
      // An arrow: along its axis only. Shift: straight across, or straight up and down (toward
      // the street in the top view), whichever the pointer is closer to.
      const axis = drag.axis ?? (e.shiftKey ? (Math.abs(du) >= Math.abs(dv) ? 'u' : 'v') : null);
      if (axis === 'u') dv = 0;
      if (axis === 'v') du = 0;
      // Grid snap: the first point of the object (the middle of a bush, the base of a tree) goes to the grid.
      const grid = gridFor(side, e);
      if (grid && drag.original[0]) {
        const a = toView(drag.original[0], side, zMin, frontCam);
        if (axis !== 'v') du = onGrid(a.u + du, grid, 'u') - a.u;
        if (axis !== 'u') dv = onGrid(a.v + dv, grid, 'v') - a.v;
      }
      update(drag.id, { points: inView(side).moved(drag.original, du, dv) });
    } else if (drag.kind === 'rotate' && f) {
      // The front view's rotation turns clockwise on the screen; facing, seen from above, the other way.
      const d = screenAngle(drag.center, p) - drag.start;
      const raw = drag.original + (drag.prop === 'facing' ? -d : d);
      const val = wrapAngle(e.shiftKey ? Math.round(raw / 15) * 15 : Math.round(raw));
      update(drag.id, { [drag.prop]: val || undefined });
    } else if (drag.kind === 'scale' && f) {
      const t = Math.max(0.05, Math.hypot(p.u - drag.center.u, p.v - drag.center.v) / Math.max(1, drag.start));
      const o = drag.original;
      update(drag.id, {
        ...(o.radius != null ? { radius: Math.max(5, Math.round(o.radius * t)) } : {}),
        ...(o.height != null ? { height: Math.max(5, Math.round(o.height * t)) } : {}),
        ...(o.size != null ? { size: Math.max(0.01, Math.round(o.size * t * 100) / 100) } : {})
      });
    } else if (drag.kind === 'radius' && f) {
      update(drag.id, { radius: Math.max(15, Math.round(Math.abs(p.u - toView(f.points[0], side, zMin, frontCam).u))) });
    } else if (drag.kind === 'treeHeight' && f) {
      update(drag.id, { height: Math.max(20, Math.round(toView(f.points[0], side, zMin, frontCam).v - p.v)) });
    } else if (drag.kind === 'ground') {
      updateLayout({ groundY: Math.max(0, Math.min(layout.height, p.v)) });
    } else if (drag.kind === 'newShape') {
      setDrag({ ...drag, size: draftSize(drag, p) });
    }
  }

  function onPointerUp() {
    setSnapHint(null);
    // Picked and moved: it stays where it was put, in the same view.
    if (drag && layoutRef.current !== dragFrom.current) framePending.current = null;
    if (layout && drag?.kind === 'newShape') addFixture(shapeFrom(drag, layout, zMin, uid(), drag.side === 'front' ? frontCam : null));
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
        ? // Effects picked for whole devices in the scene dialog stay.
          await api.updateScene(prev.id, { name: prev.name, devicePresets: prev.devicePresets, effects: { ...deviceEffects(prev.effects), ...fx } })
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

  // Scenes with effects on objects (effects on whole devices are picked in the scene dialog).
  const effectScenes = (overview?.scenes ?? []).filter((x) => Object.keys(x.effects ?? {}).some((k) => keyDevice(k) == null));
  const editingScene = sceneRef && overview?.scenes.some((x) => x.id === sceneRef.id) ? sceneRef : null;
  function scenesMenu(at: Anchor) {
    const items: MenuItem[] = [];
    if (editingScene) items.push({ label: `Save "${editingScene.name}"`, run: () => void saveScene({ id: editingScene.id }) });
    items.push({ label: 'Save as a new scene…', run: () => setNewScene(editingScene ? `${editingScene.name} 2` : '') });
    for (const sc of effectScenes) items.push({ label: `Open "${sc.name}"`, run: () => loadScene(sc) });
    if (fxCount) items.push({ label: 'Remove every effect', danger: true, run: () => (edit((l) => ({ ...l, fixtures: l.fixtures.map((f) => withEffects(f, {})) })), setSceneRef(null)) });
    setMenu({ ...at, title: editingScene ? `Scene: ${editingScene.name}` : 'Scenes with effects', items });
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
    if (phone) setPhoneView('top');
    else if (!shown.includes('top')) {
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

  /** The File menu: the layout to a file, and a layout from a file. */
  function fileMenu(at: Anchor) {
    setMenu({
      ...at,
      title: 'Layout file',
      items: [
        { label: 'Export the layout…', run: () => void exportLayout() },
        { label: 'Import a layout…', run: () => layoutFileInput.current?.click() }
      ]
    });
  }

  /** Downloads the layout as it is in the editor (unsaved changes too), with its pictures, devices and game area. */
  async function exportLayout() {
    if (!layout) return;
    setBusy(true);
    try {
      const file = await api.exportLayout();
      downloadJson({ ...file, layout }, `wled-layout-${new Date().toISOString().slice(0, 10)}.json`);
      toast.success(dirty ? 'Layout exported, with your unsaved changes.' : 'Layout exported.');
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  /** Reads a layout file, then asks before it replaces the layout. */
  async function pickLayoutFile(file: File | undefined) {
    if (!file) return;
    try {
      const data = JSON.parse(await file.text()) as { layout?: { fixtures?: unknown }; fixtures?: unknown; pictures?: Record<string, unknown> };
      const fixtures = (data?.layout ?? data)?.fixtures;
      if (!Array.isArray(fixtures)) throw new Error('bad');
      const pictures = Object.values(data.pictures ?? {}).filter(Boolean).length;
      setImporting({ data, name: file.name, objects: fixtures.length, pictures });
    } catch {
      toast.error(`${file.name} is not a layout file. Use a file from Export the layout.`);
    }
  }

  async function confirmImport() {
    if (!importing) return;
    setBusy(true);
    try {
      const out = await api.importLayout(importing.data);
      qc.setQueryData(LAYOUT_KEY, out.layout);
      void qc.invalidateQueries({ queryKey: ['admin', 'game-area'] });
      // A new layout: start over, with nothing selected, no undo history, and the views zoomed to fit.
      history.clear();
      setHistoryTick((n) => n + 1);
      setLayout(out.layout);
      scaleChecked.current = false;
      setSelected(null);
      setMulti([]);
      setCorner(null);
      setSegment(null);
      setMatch(null);
      setTape(null);
      setDraft((d) => ({ ...d, pts: [] }));
      setCams({});
      setImporting(null);
      toast.success(`Layout imported: ${out.layout.fixtures.length} object(s).`);
      if (out.unmatched) toast.warning(`${out.unmatched} object(s) had a device that is not here. Choose their WLED device again.`);
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  /** The Pictures menu: the front of the house, and the yard from above. */
  function picturesMenu(at: Anchor) {
    if (!layout) return;
    const items: MenuItem[] = [
      { label: layout.background ? 'Change the house picture (front view)…' : 'Add a house picture (front view)…', run: () => fileInput.current?.click() },
      { label: layout.aerial ? 'Change the picture from above (top view)…' : 'Add a picture from above (top view)…', run: () => aerialInput.current?.click() }
    ];
    if (layout.aerial) items.push({ label: 'Line up the picture from above', run: () => startAlign() });
    if (layout.background) items.push({ label: 'Remove the house picture', danger: true, run: () => void removeBg() });
    if (layout.aerial) items.push({ label: 'Remove the picture from above', danger: true, run: () => void removeAerial() });
    setMenu({ ...at, title: 'Pictures to trace over', items });
  }

  /** The phone's command bar keeps the menus of the wide one under ⋯: scenes, pictures, the layout file, Revert. */
  function moreMenu(at: Anchor) {
    const items: MenuItem[] = [
      { label: editingScene ? `Scene: ${editingScene.name}…` : 'Scenes…', run: () => scenesMenu(at) },
      { label: 'Pictures to trace over…', run: () => picturesMenu(at) },
      { label: 'Layout file…', run: () => fileMenu(at) },
      { label: 'Custom objects…', run: () => setLibrary(true) }
    ];
    if (dirty) items.push({ label: 'Revert to the saved layout', danger: true, run: () => (edit(() => saved!, true), setSelected(null)) });
    setMenu({ ...at, title: 'Layout', items });
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
        'relative grid shrink-0 place-items-center rounded-lg transition [&_svg]:size-[18px]',
        phone ? 'size-10' : 'size-9',
        tool === t ? 'bg-sky-600 text-white shadow-sm' : 'text-stone-600 hover:bg-stone-200/70 hover:text-stone-950 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white'
      )}
    >
      <Icon />
      {phone ? null : <kbd className="pointer-events-none absolute right-0.5 bottom-0 font-sans text-[9px] leading-none font-semibold opacity-60">{toolKey(t)}</kbd>}
    </button>
  );
  const toolSep = <span className="h-6 w-px shrink-0 bg-stone-200 lg:h-px lg:w-6 dark:bg-stone-700" />;
  const barSep = <span className="mx-1 h-5 w-px shrink-0 bg-stone-200 dark:bg-stone-700" />;

  /** What the tool needs next, for a finger. */
  const touchHint = !has2d
    ? 'Switch to the front or the top view to draw and move objects. In the 3D view, hold your finger on an LED to select its object.'
    : panMode
      ? 'Drag to pan the view. Pinch to zoom.'
      : isLineTool(tool)
        ? draft.pts.length
          ? 'Tap the next corner. Tap Finish line (or double-tap) when it is done. Pinch to zoom.'
          : `Tap the first point of the ${tool === 'roof' ? 'roofline' : 'line'}, or tap the end of a line to continue it.`
        : tool === 'edit'
          ? 'Tap a line to add a point, then drag it into place. Drag a point to move it. Long-press a point to delete it. Drag anywhere else to pan.'
          : tool === 'split'
            ? 'Tap a corner, or a spot on a line, to cut the line in two there.'
            : tool === 'bush'
              ? 'Press on the middle of the bush and drag out to its edge.'
              : tool === 'tree'
                ? 'Front view: drag from the base up to the top. Top view: drag from the middle out to the edge of the base.'
                : tool === 'semicircle'
                  ? 'Press on the middle of its straight (bottom) edge and drag out to one end.'
                : tool === 'measure'
                  ? 'Tap two points to measure the distance between them. Then type the real distance to set the scale.'
                  : tool === 'align'
                    ? ALIGN_STEPS[alignPts.length]
                    : 'Hold your finger on an object for a second to select it (hold again for its actions). Drag to pan, pinch to zoom. On the selected object, drag the white square to move it, the arrows to move it along one axis, the ring to turn it and the yellow squares to resize it.';
  const deskHint = !has2d
    ? 'Show the front or the top view to draw and move objects. In the 3D view, click an LED to select its object.'
    : panMode
      ? 'Drag to pan the view. Wheel: zoom at the pointer. Home: zoom to fit.'
      : isLineTool(tool)
        ? draft.pts.length
          ? 'Click the next corner. Enter, Esc or a double-click finishes the line. Backspace removes the last point. Shift: 45° steps. Alt: no snapping.'
          : `Click the first point of the ${tool === 'roof' ? 'roofline' : 'line'}, or click the end of a line to continue it (Alt-click: a new line from there).`
        : tool === 'edit'
          ? 'Click a line to add a point, then drag it into place. Drag a point to move it (Shift: straight across or straight up). Delete removes the selected point. Ctrl-click (⌘-click) an end to continue the line.'
          : tool === 'split'
            ? 'Click a corner, or a spot on a line, to cut the line in two there.'
            : tool === 'bush'
              ? 'Press on the middle of the bush and drag out to its edge.'
              : tool === 'tree'
                ? 'Front view: drag from the base up to the top. Top view: drag from the middle out to the edge of the base.'
                : tool === 'semicircle'
                  ? 'Press on the middle of its straight (bottom) edge and drag out to one end.'
                : tool === 'measure'
                  ? 'Click two points to measure the distance between them. Then type the real distance to set the scale (or, in the top view, the scale of the picture from above).'
                  : tool === 'align'
                    ? ALIGN_STEPS[alignPts.length]
                  : 'Click to select; drag an object or a point to move it (Shift: straight across or straight up). On the selected object, the arrows move it along one axis, the ring turns it (Shift: 15° steps) and the yellow squares resize it. Right-click for actions. Wheel: zoom. Middle-drag or Space-drag: pan. F: zoom to the selection.';
  const hint = coarse ? touchHint : deskHint;

  const tapeLength = tape?.b ? Math.hypot(tape.b.u - tape.a.u, tape.b.v - tape.a.v) : null;
  const coords: [string, string][] | null = cursor
    ? cursor.side === 'side'
      ? [
          ['Depth', m.text(cursor.u)],
          ['Height', m.text(ground - cursor.v)]
        ]
      : cursor.side === 'front'
      ? [
          ['X', m.text(cursor.u)],
          ['Height', m.text(ground - cursor.v)]
        ]
      : [
          ['X', m.text(cursor.u)],
          ['Depth', m.text(cursor.v + zMin)]
        ]
    : null;

  /**
   * The move, turn and resize handles of the selected object in one view (see Gizmo): not for a
   * locked object, nor while a line's point or segment is being edited.
   */
  const gizmoFor = (side: ViewSide, V: (p: Point) => UV, k: number) => {
    const f = sel;
    if (!f || f.locked || tool !== 'select' || panMode || probe || drawing || multi.length > 1) return null;
    if (isLine(f) && (corner != null || segment != null)) return null;
    const front = side === 'front';
    const box = inView(side).box(f);
    const anchor = isLine(f) ? { u: box.x + box.w / 2, v: box.y + box.h / 2 } : V(f.points[0]);
    const shaped = f.kind === 'tree' || f.kind === 'semicircle' || f.kind === 'custom';
    // What the ring turns in this view: left and right from the front, which way it faces from
    // above, toward the street or the house from the side.
    const prop: 'rotation' | 'facing' | 'tilt' = front ? 'rotation' : side === 'top' ? 'facing' : 'tilt';
    // The knob: the top of the ring at no turn (front and side), or where it faces (top: the street is down).
    const turn = !shaped ? null : prop === 'facing' ? 90 - (f.facing ?? 0) : (f[prop] ?? 0) - 90;
    // Width and height handles only while it stands straight (a semicircle: not turned either).
    const straight = !f.tilt && !(f.kind === 'tree' && f.rotation);
    const upright = f.kind === 'semicircle' && !f.rotation && !f.facing && straight;
    const width = f.kind === 'bush' || (f.kind === 'tree' && straight) || (upright && side !== 'side');
    const height = side !== 'top' && ((f.kind === 'tree' && straight) || upright);
    const scalable = f.kind === 'tree' || f.kind === 'semicircle' || f.kind === 'custom';
    // The part being dragged, in the view it is dragged in (the height handle is the front view's).
    const d = drag && 'id' in drag && drag.id === f.id && 'side' in drag && drag.side === side ? drag : null;
    const part: GizmoPart['kind'] | null = !d ? null : d.kind === 'radius' ? 'width' : d.kind === 'treeHeight' ? 'height' : d.kind === 'rotate' || d.kind === 'scale' || d.kind === 'move' ? d.kind : null;
    const label =
      part === 'rotate' && d?.kind === 'rotate'
        ? `${f[d.prop] ?? 0}°`
        : part === 'width'
          ? m.text(radiusOf(f) * 2)
          : part === 'height'
            ? m.text(sizeHeight(f))
            : part === 'scale'
              ? f.kind === 'custom'
                ? `× ${f.size ?? 1}`
                : `${m.text(radiusOf(f) * 2)} × ${m.text(sizeHeight(f))}`
              : null;
    const start = (e: RPointerEvent, g: GizmoPart) => {
      const at = viewPoint(e, side);
      const d: Drag =
        g.kind === 'move'
          ? { kind: 'move', side, id: f.id, from: at, original: f.points, axis: g.axis }
          : g.kind === 'rotate'
            ? { kind: 'rotate', side, id: f.id, prop, center: anchor, start: screenAngle(anchor, at), original: f[prop] ?? 0 }
            : g.kind === 'scale'
              ? {
                  kind: 'scale',
                  side,
                  id: f.id,
                  center: anchor,
                  start: Math.hypot(at.u - anchor.u, at.v - anchor.v),
                  original: f.kind === 'custom' ? { size: f.size ?? 1 } : { radius: radiusOf(f), height: sizeHeight(f) }
                }
              : g.kind === 'width'
                ? { kind: 'radius', side, id: f.id }
                : { kind: 'treeHeight', side, id: f.id };
      startDrag(e, d, f.id, side);
    };
    return <Gizmo side={side} anchor={anchor} box={box} k={k} turn={turn} width={width} height={height} scale={scalable} active={part ? { part, label } : null} touch={coarse} onStart={start} />;
  };

  /** One editable view: the drawing (YardView) and the handles over it, seen through the view's camera. */
  const renderView = (side: ViewSide) => {
    const V = (p: Point) => toView(p, side, zMin, frontCam);
    const front = side === 'front';
    const vb = viewBoxFor(side);
    // Handles and labels keep the same size on the screen at every zoom.
    const k = camFor(side).k / BASE_K;
    const dash = (a: number, b: number) => `${a * k} ${b * k}`;
    const hovered = hover?.side === side && !drag ? (layout.fixtures.find((f) => f.id === hover.id) ?? null) : null;
    const handle = (key: string | number, at: UV, className: string, onDown: (e: RPointerEvent<SVGCircleElement>) => void, onDouble?: (e: RMouseEvent) => void) => (
      <circle key={key} cx={at.u} cy={at.v} r={9 * k} className={cn('stroke-stone-950', className)} strokeWidth={3 * k} onPointerDown={onDown} onDoubleClick={onDouble} />
    );
    return (
      <YardView layout={layout} side={side} zRange={zRange} getFrame={getFrame} highlight={segment != null || playing || probe || layoutCheck ? null : selected} fill viewBox={vb} grid={drafting.grid} gridStep={gridOf(drafting, layout).step} gridMajor={drafting.gridMajor}>
        <svg
          ref={(el) => void (svgs.current[side] = el)}
          viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
          preserveAspectRatio="none"
          className={cn(
            'absolute inset-0 h-full w-full touch-none select-none',
            drag?.kind === 'pan'
              ? 'cursor-grabbing'
              : panMode
                ? 'cursor-grab'
                : tool !== 'select' && tool !== 'edit'
                  ? 'cursor-crosshair'
                  : hovered
                    ? hovered.locked
                      ? 'cursor-pointer'
                      : 'cursor-move'
                    : ''
          )}
          onPointerDown={(e) => onPointerDown(e, side)}
          onPointerMove={(e) => onPointerMove(e, side)}
          onPointerUp={onPointerUp}
          onPointerLeave={() => (setCursor(null), setHover(null), drag == null && setSnapHint(null))}
          onMouseDown={(e) => e.button === 1 && e.preventDefault()}
          onDoubleClick={(e) => {
            if (isLineTool(tool)) return void (draft.side === side && finishLine(tool));
            // Select: a double-click on a line adds a point there.
            const hit = tool === 'select' && !panMode ? pickIn(side, e, PICK_PX.mouse, isLine) : null;
            if (hit) insertVertex(hit.f, hit.seg ?? 0, e, side);
          }}
          // The right-click menu (a hold, on a touch screen) of the object there. The handles have their own.
          onContextMenu={(e) => {
            if (e.target instanceof Element && e.target.closest('[data-gizmo]')) return;
            const hit = pickIn(side, e, e.nativeEvent.isTrusted ? PICK_PX.mouse : PICK_PX.touch);
            if (!hit) return;
            if (isLine(hit.f)) segmentMenu(e, hit.f, hit.seg ?? 0, side);
            else objectMenu(e, hit.f);
          }}
        >
          {side === 'side' ? (
            <>
              <text x={-10 * k} y={vb.y + 20 * k} textAnchor="end" fontSize={14 * k} fill="rgba(251,191,36,0.7)" pointerEvents="none">
                House · front wall
              </text>
              <text x={vb.x + vb.w - 12 * k} y={vb.y + vb.h - 12 * k} textAnchor="end" fontSize={14 * k} fill="rgba(255,255,255,0.4)" pointerEvents="none">
                Street →
              </text>
            </>
          ) : null}
          {side === 'top' ? (
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
              <g data-handle className={tool === 'select' && !panMode ? 'cursor-ns-resize' : ''} onPointerDown={(e) => startDrag(e, { kind: 'ground' }, null, side)}>
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
                  {/* Edit and Split: one hit area per segment, to add a point or cut the line there. (Select picks by distance: see pickIn.) */}
                  {(tool === 'edit' || tool === 'split') && !panMode
                    ? pts.slice(1).map((b, s) => {
                        const a = pts[s];
                        return (
                          <line
                            key={s}
                            data-hit
                            x1={a.u}
                            y1={a.v}
                            x2={b.u}
                            y2={b.v}
                            stroke="transparent"
                            strokeWidth={(coarse ? 44 : 26) * k}
                            strokeLinecap="round"
                            className={tool === 'edit' ? 'cursor-copy' : ''}
                            onPointerDown={(e) => {
                              if (e.button !== 0) return;
                              const at = snapHint?.side === side && drafting.snap !== e.altKey ? snapHint.at : viewPoint(e, side);
                              if (tool === 'edit') {
                                history.newStep();
                                addPointOn(f, s, at, side, e);
                              } else {
                                e.stopPropagation();
                                splitOn(f, s, at, side);
                              }
                            }}
                            onContextMenu={(e) => segmentMenu(e, f, s, side)}
                          />
                        );
                      })
                    : null}
                  {isSel || tool === 'edit' || tool === 'split'
                    ? pts.map((p, i) => {
                        const end = i === 0 ? 'first' : i === f.points.length - 1 ? 'last' : null;
                        return (
                          <g
                            key={i}
                            data-handle
                            className={panMode ? '' : tool === 'split' ? (end ? '' : 'cursor-crosshair') : 'cursor-grab'}
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
                              startDrag(e, { kind: 'vertex', side, id: f.id, index: i, start: toView(f.points[i], side, zMin, frontCam) }, f.id, side);
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
                          >
                          {/* A finger needs a bigger target than the dot. */}
                          <circle cx={p.u} cy={p.v} r={(coarse ? 22 : 11) * k} fill="transparent" />
                          <circle
                            cx={p.u}
                            cy={p.v}
                            r={(isSel ? 9 : 7) * (coarse ? 1.35 : 1) * k}
                            strokeWidth={3 * k}
                            className={cn(
                              'stroke-stone-950',
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
                            pointerEvents="none"
                          />
                          </g>
                        );
                      })
                    : null}
                  {isSel && probe ? (
                    <ProbeMarker f={f} probe={probe} V={V} k={k} scale={scale} />
                  ) : isSel ? (
                    <LedLabels f={f} corner={corner} segment={segment} V={V} side={side} k={k} scale={scale} />
                  ) : null}
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
            // Bush, tree, custom object or semicircle. (No hit areas: Select picks by distance, see pickIn.)
            const c = V(f.points[0]);
            const r = radiusOf(f);
            if (f.kind === 'custom' || f.kind === 'semicircle') {
              const paths = objectPaths(f, scale).map((path) => path.map(V));
              const b = inView(side).box(f);
              const pad = 10 * k;
              return (
                <g key={f.id}>
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
            const upright = side !== 'top';
            const outline = f.kind === 'tree' && upright ? treeOutline(f, side === 'side' ? 'side' : side === 'front' && frontCam ? acrossOf(frontCam) : 'front').map((p) => `${V(p).u},${V(p).v}`).join(' ') : '';
            return (
              <g key={f.id}>
                {multi.includes(f.id) ? (
                  f.kind === 'tree' && upright ? (
                    <polygon points={outline} fill="rgba(40,170,255,0.08)" stroke="rgb(40,170,255)" strokeWidth={2.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
                  ) : (
                    <ellipse cx={c.u} cy={c.v} rx={r + 6 * k} ry={(upright ? r * BUSH_TALL : r) + 6 * k} fill="rgba(40,170,255,0.08)" stroke="rgb(40,170,255)" strokeWidth={2.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
                  )
                ) : null}
                {isSel ? <LedLabels f={f} corner={null} segment={null} V={V} side={side} k={k} scale={scale} /> : null}
                {isSel ? <EndMarkers a={fixturePixels(f, scale)[0]} b={fixturePixels(f, scale).at(-1)} V={V} k={k} /> : null}
              </g>
            );
          })}

          {/* What a click would pick, outlined. */}
          {hovered && hovered.id !== selected && !multi.includes(hovered.id)
            ? (() => {
                const h = pickShapes(side).find((x) => x.id === hovered.id);
                if (!h) return null;
                const paths = h.wire.length ? h.wire : h.area ? [[...h.area, h.area[0]]] : [];
                return (
                  <g pointerEvents="none">
                    {paths.map((path, j) => (
                      <polyline key={j} points={path.map((q) => `${q.u},${q.v}`).join(' ')} fill="none" stroke="rgb(40,170,255)" strokeOpacity={0.55} strokeWidth={2 * k} strokeLinejoin="round" strokeLinecap="round" />
                    ))}
                  </g>
                );
              })()
            : null}

          {/* Where each new strand of the selected object starts */}
          {sel && !playing ? <StrandMarks f={sel} perStrand={lightsOf(layout, sel.lights)?.perStrand ?? null} scale={scale} V={V} k={k} labels={front} /> : null}

          {/* Move, turn and resize handles on the selected object. */}
          {gizmoFor(side, V, k)}

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

          {/* A bush, tree or semicircle being drawn */}
          {drag?.kind === 'newShape' && drag.side === side ? (
            <path d={draftOutline(drag)} fill="rgba(52,211,153,0.15)" stroke="#34d399" strokeWidth={2.5 * k} strokeDasharray={dash(8, 6)} pointerEvents="none" />
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

          {/* A check's slice (drag it) or the ruler's band edges. */}
          {layoutCheck && stage && !(front && frontCam) ? (
            <CheckOverlay
              check={layoutCheck}
              stage={stage}
              layout={layout}
              side={side}
              zMin={zMin}
              vb={vb}
              k={k}
              m={m}
              toWorld={(e, axis) => {
                const p = viewPoint(e, side);
                return side === 'side' ? (axis === 'z' ? p.u : p.v) : axis === 'x' ? p.u : side === 'top' ? p.v + zMin : p.v;
              }}
              onMove={(at) => setCheck((c) => (c?.kind === 'slice' ? { ...c, at } : c))}
            />
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
    if (phone)
      return (
        <div className="flex h-11 shrink-0 items-center gap-2 border-b border-white/10 bg-stone-900 px-1.5 text-xs text-white/55 select-none">
          <div role="group" aria-label="View" className="inline-flex rounded-lg bg-white/10 p-0.5">
            {(['front', 'top', 'side', '3d'] as ViewName[]).map((x) => (
              <button
                key={x}
                type="button"
                aria-pressed={x === v}
                onClick={() => setPhoneView(x)}
                className={cn('h-8 rounded-md px-3.5 text-xs font-semibold transition', x === v ? 'bg-white text-stone-900 shadow-sm' : 'text-white/70 active:bg-white/15')}
              >
                {VIEW_LABELS[x]}
              </button>
            ))}
          </div>
          <span className="ml-auto" />
          {side ? (
            <>
              <span className="tabular-nums">{zoom}%</span>
              <button
                type="button"
                aria-label="Zoom to fit"
                onClick={() =>
                  setCams((c) => {
                    const next = { ...c };
                    delete next[side];
                    return next;
                  })
                }
                className="grid size-9 place-items-center rounded-lg text-white/80 active:bg-white/15 [&_svg]:size-4"
              >
                <Scan />
              </button>
            </>
          ) : null}
        </div>
      );
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
          {(['front', 'top', 'side', '3d'] as ViewName[]).map((x) => (
            <option key={x} value={x}>
              {VIEW_LABELS[x]}
            </option>
          ))}
        </select>
        {v === 'front' ? (
          <label className="flex shrink-0 items-center gap-1" title="Turn the yard to where the picture was taken from (more in the properties, with nothing selected: Front view angle)">
            <input
              type="range"
              aria-label="Front view turned"
              min={-MAX_YAW}
              max={MAX_YAW}
              step={1}
              value={layout.frontView?.yaw ?? 0}
              onPointerDown={() => history.newStep()}
              onChange={(e) => updateLayout({ frontView: tidyFrontView({ ...layout.frontView, yaw: Number(e.target.value) }) })}
              onDoubleClick={() => updateLayout({ frontView: tidyFrontView({ ...layout.frontView, yaw: 0 }) })}
              className="h-3 w-20 cursor-pointer accent-sky-400"
            />
            <span className="w-7 text-right tabular-nums">{layout.frontView?.yaw ?? 0}°</span>
          </label>
        ) : null}
        <span className="pointer-events-none truncate">
          {VIEW_NOTES[v]}
          {side && (drafting.grid || drafting.gridSnap) ? ` · grid ${gridOf(drafting, layout).text}${drafting.gridSnap ? ', snap' : ''}` : ''}
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

  /** Why a check shows in the drawing only, if it does. */
  const checkLights = !mapped
    ? 'No object has a WLED device yet: the check shows in the drawing only.'
    : !showOnLights
      ? 'Lights are off: turn them on in the toolbar to see the check on the house.'
      : !inFront
        ? 'Paused while this window is not in front.'
        : null;
  const lightsLabel = !showOnLights ? 'Lights: off' : !mapped ? 'Lights: no device' : !inFront ? 'Lights: paused' : previewDevices.length ? `Lights: ${previewDevices.join(', ')}` : 'Lights: on';
  const lightsTitle = !showOnLights
    ? 'Show the layout on the real lights while you edit'
    : !mapped
      ? 'Choose a WLED device for an object first'
      : !inFront
        ? 'Paused while this window is not in front'
        : 'The selected object glows on its WLED device. Click to stop.';


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

  /** The properties of the selected object, shown in the object list right under it. */
  const selPanel = () =>
    sel ? (
      <>
        {matching && probe ? (
          <PropSection key="match" id="match" title="Match to the lights">
            <MatchWizard
              f={matching}
              probe={probe}
              ledCount={ledCountOf(matching)}
              device={devices.find((d) => d.id === matching.deviceId)?.name ?? null}
              perStrand={lightsOf(layout, matching.lights)?.perStrand ?? null}
              lights={!showOnLights ? 'Lights are off: turn them on in the toolbar to see the blinking LED.' : !inFront ? 'Paused while this window is not in front.' : previewDevices.length ? null : 'Waiting for the device to answer…'}
              onSet={setProbe}
              onMove={moveProbe}
              onStrand={(dir) => strandJump(matching, dir)}
              onGo={(point) => matchGo(point)}
              onFound={matchFound}
              onStop={() => setMatch(null)}
            />
          </PropSection>
        ) : shapeSel && probe ? (
          <PropSection key="shape" id="shape" title="Shape to the lights">
            <ShapeWizard
              f={shapeSel}
              led={probe.offset}
              perStrand={lightsOf(layout, shapeSel.lights)?.perStrand ?? null}
              ledCount={ledCountOf(shapeSel)}
              device={devices.find((d) => d.id === shapeSel.deviceId)?.name ?? null}
              lights={!showOnLights ? 'Lights are off: turn them on in the toolbar to see the blinking LED.' : !inFront ? 'Paused while this window is not in front.' : previewDevices.length ? null : 'Waiting for the device to answer…'}
              lenText={m.text}
              stepLu={shapeStep(layout)}
              onSet={setShapeLed}
              onStrand={shapeStrand}
              onMarks={(marks) => update(shapeSel.id, { marks })}
              onStop={() => setShaping(null)}
            />
          </PropSection>
        ) : (
          <>
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
                onPoint={(point, led) => update(sel.id, pinPoint(sel, point, led))}
                onToggle={(on) => update(sel.id, setSkipped(sel, segment, !on))}
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
              <CornerProps f={sel} index={corner} onPin={(led) => pinCorner(sel, corner, led)} onSplit={() => splitAt(sel, corner)} onFind={sel.deviceId ? () => startMatch(sel, corner) : undefined} />
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
            ) : isShapeKind(sel.kind) ? (
              <fieldset disabled={!!sel.locked} className="contents">
                <PropSelect<ShapeKind>
                  label="Kind"
                  hint={
                    sel.locked
                      ? 'Locked in place: unlock it to change its kind.'
                      : 'Make it another kind of shape. It keeps its name, LEDs, effect and the part of the yard it covers; the new kind’s shape settings start fresh.'
                  }
                  value={sel.kind}
                  options={[
                    ['bush', 'Bush'],
                    ['tree', 'Tree (cone, cylinder or ball)'],
                    ['semicircle', 'Semicircle']
                  ]}
                  onChange={(kind) => setKind([sel.id], kind)}
                />
              </fieldset>
            ) : null}
            <PropSelect
              label="WLED device"
              hint="The device that drives these LEDs."
              value={sel.deviceId ?? ''}
              options={[['', 'Simulation only'], ...devices.map((d): [string, string] => [d.id, `${d.name}${d.info?.leds?.count ? ` (${d.info.leds.count} LEDs)` : ''}`])]}
              onChange={(id) => update(sel.id, { deviceId: id || null })}
            />
            {isLine(sel) && sel.points.length > 2 && segment == null && corner == null ? (
              <PropNote>Click a segment of the line to turn it off or give it its own effect, or a corner to split the line there.</PropNote>
            ) : null}
          </PropSection>

          <PropSection key="leds" id="leds" title="LEDs">
            <LedProps f={sel} onRange={(a, b) => setRange(sel, a, b)} onMatch={isLine(sel) ? () => startMatch(sel) : undefined} onShape={takesMarks(sel) ? () => startShape(sel) : undefined} onClearMarks={() => update(sel.id, { marks: undefined })} />
          </PropSection>

          <ObjectCheckProps
            f={sel}
            check={check}
            onChange={setCheck}
            onPatch={(patch) => update(sel.id, patch)}
            blocks={stage ? pictureBlocks(stage, sel.id) : null}
            lights={checkLights}
            scale={scale}
            perStrand={lightsOf(layout, sel.lights)?.perStrand ?? null}
          />

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
              onStrings={(patch) => update(sel.id, patch)}
            />
          </PropSection>

          <PropSection key="position" id="position" title={isLine(sel) && corner != null && sel.points[corner] ? `Position of ${pointName(sel, corner)}` : 'Position'}>
            {sel.locked ? <LockedNote onUnlock={() => setLocked([sel.id], false)} /> : null}
            <fieldset disabled={!!sel.locked} className="contents">
              <PositionProps f={sel} point={corner} m={m} ground={ground} onChange={(patch) => update(sel.id, patch)} />
            </fieldset>
          </PropSection>

          {!isLine(sel) && sel.kind !== 'custom' ? (
            <PropSection key="shape" id="shape" title="Shape">
              <ShapeProps f={sel} m={m} locked={!!sel.locked} strung={stringGap(sel, layout) != null} onChange={(patch) => update(sel.id, patch)} />
            </PropSection>
          ) : null}
          </>
        )}
      </>
    ) : null;

  /** The object list. In the side panel (`inline`), the selected object opens in it, with its properties right under it. */
  const objectList = (inline: boolean) => (
    <div className="flex shrink-0 flex-col border-b border-stone-200 dark:border-stone-800">
      <div className="flex h-8 shrink-0 items-center justify-between gap-2 border-b border-stone-100 px-3 dark:border-stone-800">
        <span className="text-[11px] font-semibold tracking-wide text-stone-600 uppercase dark:text-stone-400">Objects</span>
        <span className="text-[11px] text-stone-500 tabular-nums">
          {layout.fixtures.length} · {totals} LEDs
        </span>
      </div>
      {layout.fixtures.length ? (
        <ul aria-label="Objects" className="py-1">
          {layout.fixtures.map((f, i) => {
            const Icon = KIND_ICONS[f.kind];
            const on = selected === f.id || multi.includes(f.id);
            const partly = !on && multi.some((x) => effectTarget(x).id === f.id);
            /** The selected object opens: its row stays at the top while you scroll through its properties. */
            const open = inline && sel?.id === f.id;
            return (
              <li key={f.id} className={cn(open && 'my-1')}>
                <div
                  data-object-row={f.id}
                  aria-current={on ? 'true' : undefined}
                  aria-expanded={open}
                  title={partly ? 'Some of its segments are selected' : open ? 'Click to close it (nothing selected)' : undefined}
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
                    } else if (open && !multi.length) {
                      // A click on the open object's header closes it: nothing is selected.
                      setSelected(null);
                      return;
                    } else choose(f.id);
                    listAnchor.current = f.id;
                    // On a phone, the list hands over to the object's properties.
                    if (!inline) setSheetTab('details');
                  }}
                  onMouseDown={(e) => e.shiftKey && e.preventDefault()}
                  onDoubleClick={() => setRenaming(f.id)}
                  onContextMenu={(e) => objectMenu(e, f)}
                  className={cn(
                    'mx-1 flex cursor-default items-center gap-2 rounded-md px-2',
                    inline ? 'text-[13px]' : 'text-sm',
                    open ? 'sticky top-0 z-10 min-h-11 rounded-b-none py-1.5 shadow-sm' : inline ? 'h-7' : 'h-11',
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
                  ) : open ? (
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-semibold">{f.name}</span>
                      <span className="block truncate text-[11px] text-white/75">
                        {KIND_LABELS[f.kind]}
                        {isLine(f) && segment != null ? ` · segment ${segment + 1} of ${f.points.length - 1}` : ''}
                        {isLine(f) && segment == null && corner != null ? ` · ${pointName(f, corner)}` : ''}
                        {` · LEDs ${ledRange(f).first}–${ledRange(f).last}`}
                      </span>
                    </span>
                  ) : (
                    <span className="min-w-0 flex-1 truncate">{f.name}</span>
                  )}
                  {open ? (
                    <span className="flex shrink-0" onClick={(e) => e.stopPropagation()} onDoubleClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => setLocked([f.id], !f.locked)}
                        aria-pressed={!!f.locked}
                        title={f.locked ? 'Locked in place: click to unlock' : 'Lock in place, so it cannot be moved, reshaped or deleted by mistake'}
                        aria-label={f.locked ? 'Unlock this object' : 'Lock this object in place'}
                        className={cn('grid size-7 place-items-center rounded-md hover:bg-white/15 [&_svg]:size-4', f.locked && 'bg-white/20')}
                      >
                        {f.locked ? <Lock /> : <LockOpen />}
                      </button>
                      <button type="button" onClick={() => frameSelection()} title="Zoom to this object (F)" aria-label="Zoom to this object" className="grid size-7 place-items-center rounded-md hover:bg-white/15 [&_svg]:size-4">
                        <Scan />
                      </button>
                      <button type="button" onClick={() => remove(f.id)} title="Delete this object (Delete)" aria-label="Delete this object" className="grid size-7 place-items-center rounded-md hover:bg-red-500/80 [&_svg]:size-4">
                        <Trash2 />
                      </button>
                    </span>
                  ) : (
                    <>
                      {f.locked ? <Lock aria-label="Locked in place" className={cn('size-3 shrink-0', on ? 'text-white/80' : 'text-stone-500')} /> : null}
                      <span className={cn('text-[11px] tabular-nums', on ? 'text-white/80' : 'text-stone-500')}>
                        {ledRange(f).first}–{ledRange(f).last}
                      </span>
                    </>
                  )}
                </div>
                {open ? (
                  <div className="mx-1 rounded-b-md border border-t-0 border-sky-600/50 bg-stone-50/70 dark:border-sky-400/40 dark:bg-stone-950/40 [&>section:last-child]:border-b-0">{selPanel()}</div>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="px-3 py-4 text-xs text-stone-500">
          {coarse ? 'Nothing yet. Draw the roofline first: tap + in the toolbar, pick Roofline, then tap along the roof.' : 'Nothing yet. Draw the roofline first: press R, then click along the roof.'}
        </p>
      )}
    </div>
  );

  /** The inspector when no one object is selected: the multi-selection, or the whole yard. */
  const restPanel = () =>
    multiItems.length >= 2 ? (
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
          {(() => {
            const ids = multiItems.map((it) => effectTarget(it.key).id);
            const locked = layout.fixtures.filter((f) => ids.includes(f.id) && f.locked).length;
            return (
              <div className="flex flex-wrap gap-1.5 pt-1">
                <PropButton onClick={() => setLocked(ids, true)} disabled={locked === new Set(ids).size} title="Lock them in place, so they cannot be moved, reshaped or deleted by mistake">
                  <Lock /> Lock all
                </PropButton>
                <PropButton onClick={() => setLocked(ids, false)} disabled={!locked}>
                  <LockOpen /> Unlock all
                </PropButton>
              </div>
            );
          })()}
          {(() => {
            const shapes = layout.fixtures.filter((f) => multiItems.some((it) => it.key === f.id) && isShapeKind(f.kind));
            if (!shapes.length) return null;
            const kinds = new Set(shapes.map((f) => f.kind));
            return (
              <PropSelect<ShapeKind | ''>
                label="Make them"
                hint="Bushes, trees and semicircles in the selection become this kind of shape. Each keeps its name, LEDs, effect and the part of the yard it covers. Locked ones stay as they are."
                value={kinds.size === 1 ? (shapes[0].kind as ShapeKind) : ''}
                options={[
                  ...(kinds.size === 1 ? [] : ([['', 'Mixed kinds']] as [ShapeKind | '', string][])),
                  ['bush', 'Bushes'],
                  ['tree', 'Trees'],
                  ['semicircle', 'Semicircles']
                ]}
                onChange={(k) => k && setKind(shapes.map((f) => f.id), k)}
              />
            );
          })()}
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
            <p className="text-[11px] text-stone-500">Nothing selected. {coarse ? 'Tap' : 'Click'} an object to see its properties.</p>
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
                      onClick={(e) => (e.ctrlKey || e.metaKey ? toggleTarget(r.key) : r.seg == null ? choose(f.id) : (choose(f.id), selectSegment(f.id, r.seg)))}
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
        <FrontViewProps layout={layout} m={m} onChange={(frontView) => updateLayout({ frontView })} />
        <YardCheckProps check={check} onChange={setCheck} layout={layout} stage={stage} m={m} lights={checkLights} />
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
              New lines get as many LEDs as fit at {spacingText(newLights.spacing, m.units)} apart{newLights.perStrand ? `, in whole strings of ${newLights.perStrand}` : ''}; while you draw, each segment shows its length and LEDs.
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
                  onSelect={choose}
                />
              ))}
            </div>
          </PropSection>
        ) : null}
        {coarse ? null : (
          <PropSection key="keys" id="keys" title="Keyboard and mouse" defaultOpen={false}>
            <Shortcuts />
          </PropSection>
        )}
      </>
    );

  const iconButton =
    'grid size-10 shrink-0 place-items-center rounded-lg text-stone-600 transition hover:bg-stone-200/70 active:bg-stone-200 disabled:opacity-35 dark:text-stone-300 dark:hover:bg-stone-800 dark:active:bg-stone-700 [&_svg]:size-[18px]';

  /** The phone's command bar: one row, the menus under ⋯. */
  const phoneBar = (
    <div className="flex shrink-0 items-center gap-0.5 border-b border-stone-200 bg-stone-50 px-1.5 py-1 dark:border-stone-800 dark:bg-stone-900">
      <button type="button" onClick={undo} disabled={!history.canUndo} aria-label="Undo" className={iconButton}>
        <Undo2 />
      </button>
      <button type="button" onClick={redo} disabled={!history.canRedo} aria-label="Redo" className={iconButton}>
        <Redo2 />
      </button>
      {barSep}
      <button
        type="button"
        onClick={toggleShow}
        aria-pressed={showOnLights}
        aria-label={lightsLabel}
        title={lightsTitle}
        className={cn(iconButton, showOnLights && 'text-stone-900 dark:text-white', previewing && previewDevices.length && 'text-emerald-600 dark:text-emerald-400')}
      >
        {showOnLights ? <Lightbulb /> : <LightbulbOff />}
      </button>
      <button
        type="button"
        onClick={() => setPlaying((v) => !v)}
        disabled={!fxCount}
        aria-pressed={playing}
        aria-label={playing ? 'Stop the effects' : 'Play the effects'}
        className={cn(iconButton, playing && 'text-sky-600 dark:text-sky-300')}
      >
        {playing ? <Pause /> : <Play />}
      </button>
      {overlapCount ? <Badge tone="red">LEDs overlap</Badge> : null}
      <span className="ml-auto" />
      <button type="button" onClick={(e) => moreMenu(below(e))} disabled={busy} aria-label="More: scenes, pictures, file" aria-haspopup="menu" className={iconButton}>
        <Ellipsis />
      </button>
      <Button size="sm" variant="primary" onClick={save} disabled={!dirty || overlapCount > 0} loading={busy} className="h-10">
        <Save /> Save
      </Button>
    </div>
  );

  /** The tools that add an object, in a drawer on a phone. */
  const addTools: [Tool | 'custom', typeof House, string][] = [
    ['roof', House, 'Roofline'],
    ['line', Spline, 'Line'],
    ['bush', Circle, 'Bush'],
    ['tree', TreePine, 'Tree'],
    ['semicircle', Rainbow, 'Semicircle'],
    ['custom', Shapes, 'Custom']
  ];
  const addTool = addTools.find(([t]) => t === tool);
  const AddIcon = addTool ? addTool[1] : Plus;
  /** The phone's toolbar: select, edit and split; a drawer of objects to add; measure; snapping. Two fingers pan, so no Pan tool. */
  const phoneTools = (
    <div role="toolbar" aria-label="Tools" className="relative z-20 flex shrink-0 items-center gap-1 border-b border-stone-200 bg-stone-50 px-1.5 py-1 dark:border-stone-800 dark:bg-stone-900">
      {toolButton('select', MousePointer2)}
      {toolButton('edit', PenTool)}
      {toolButton('split', Scissors)}
      {toolSep}
      <button
        type="button"
        onClick={() => setAddOpen((v) => !v)}
        aria-expanded={addOpen}
        aria-label={addTool ? `Add: ${TOOL_LABELS[addTool[0] as Tool]}` : 'Add an object'}
        className={cn(
          'flex h-10 shrink-0 items-center gap-0.5 rounded-lg px-2 transition [&_svg]:size-[18px]',
          addTool ? 'bg-sky-600 text-white shadow-sm' : addOpen ? 'bg-stone-200 text-stone-950 dark:bg-stone-800 dark:text-white' : 'text-stone-600 active:bg-stone-200 dark:text-stone-300 dark:active:bg-stone-800'
        )}
      >
        <AddIcon />
        <ChevronDown className={cn('size-3.5! transition', addOpen && 'rotate-180')} />
      </button>
      {toolButton('measure', Ruler)}
      <span className="ml-auto" />
      <DraftingMenu drafting={drafting} layout={layout} onChange={setDrafting} />
      {addOpen ? (
        <div className="absolute inset-x-0 top-full grid grid-cols-6 gap-1 border-b border-stone-200 bg-stone-50 p-1.5 shadow-lg dark:border-stone-800 dark:bg-stone-900">
          {addTools.map(([t, Icon, label]) => (
            <button
              key={t}
              type="button"
              aria-pressed={tool === t}
              onClick={() => (t === 'custom' ? (setAddOpen(false), setLibrary(true)) : chooseTool(t))}
              className={cn(
                'flex flex-col items-center gap-1 rounded-lg py-2 text-[11px] font-medium transition [&_svg]:size-5',
                tool === t ? 'bg-sky-600 text-white' : 'text-stone-700 active:bg-stone-200 dark:text-stone-200 dark:active:bg-stone-800'
              )}
            >
              <Icon />
              {label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );

  /** The phone's status line: the tool and what it needs next. Tap it to read all of it. */
  const phoneStatus = (
    <button
      type="button"
      onClick={() => setHintOpen((v) => !v)}
      aria-expanded={hintOpen}
      className="flex shrink-0 items-start gap-2 border-t border-stone-200 bg-stone-50 px-3 py-1.5 text-left text-[11px] text-stone-500 dark:border-stone-800 dark:bg-stone-900 dark:text-stone-400"
    >
      <span className="font-semibold text-stone-700 dark:text-stone-200">{TOOL_LABELS[tool]}</span>
      <span className={cn('min-w-0 flex-1', !hintOpen && 'truncate')}>{hint}</span>
      <ChevronDown className={cn('mt-px size-3.5 shrink-0 transition', hintOpen && 'rotate-180')} />
    </button>
  );

  /** The phone's inspector: the selected object, the multi-selection or the yard, one section open at a time. */
  const phoneDetails = () => {
    const key = sel ? 'object' : multiItems.length >= 2 ? 'multi' : 'yard';
    const i = sel ? layout.fixtures.indexOf(sel) : -1;
    const Icon = sel ? KIND_ICONS[sel.kind] : null;
    const body =
      sel && Icon ? (
        <>
          <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-stone-200 bg-white py-1.5 pr-1 pl-3 dark:border-stone-800 dark:bg-stone-900">
            <Icon className="size-4 shrink-0" style={{ color: `rgb(${hsvBytes(HUES[i % HUES.length], 1).join(',')})` }} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold">{sel.name}</p>
              <p className="truncate text-[11px] text-stone-500">
                {KIND_LABELS[sel.kind]}
                {isLine(sel) && segment != null ? ` · segment ${segment + 1} of ${sel.points.length - 1}` : ''}
                {isLine(sel) && segment == null && corner != null ? ` · ${pointName(sel, corner)}` : ''}
                {` · LEDs ${ledRange(sel).first}–${ledRange(sel).last}`}
              </p>
            </div>
            <button type="button" onClick={() => frameSelection()} aria-label="Zoom to this object" className={iconButton}>
              <Scan />
            </button>
            <button type="button" onClick={() => remove(sel.id)} aria-label="Delete this object" className={cn(iconButton, 'text-red-600 dark:text-red-400')}>
              <Trash2 />
            </button>
            <button type="button" onClick={() => setSelected(null)} aria-label="Done: select nothing" className={iconButton}>
              <X />
            </button>
          </div>
          {selPanel()}
        </>
      ) : (
        restPanel()
      );
    // The wizard that matches a line to the lights is one section, always open.
    if (sel && (matching || shapeSel) && probe) return body;
    return <PropAccordion.Provider value={{ open: accOpen[key], set: (id) => setAccOpen((a) => ({ ...a, [key]: id })) }}>{body}</PropAccordion.Provider>;
  };

  const SelIcon = sel ? KIND_ICONS[sel.kind] : null;
  /** The phone's bottom sheet: the object list and the inspector, in two tabs. */
  const phoneSheet = (
    <BottomSheet
      label="Objects and properties"
      size={sheet}
      onSize={setSheet}
      tab={sheetTab}
      onTab={setSheetTab}
      tabs={[
        {
          id: 'objects',
          content: (
            <>
              <List /> Objects <span className="text-stone-500 tabular-nums">{layout.fixtures.length}</span>
            </>
          )
        },
        {
          id: 'details',
          content: (
            <>
              {SelIcon ? <SelIcon /> : null}
              <span className="truncate">{sel ? sel.name : multiItems.length >= 2 ? `${multiItems.length} selected` : 'Yard'}</span>
            </>
          )
        }
      ]}
    >
      {sheetTab === 'objects' ? objectList(false) : phoneDetails()}
    </BottomSheet>
  );

  return (
    <div className="touch-ui flex h-full flex-col bg-stone-100 dark:bg-stone-950">
      {phone ? (
        phoneBar
      ) : (
        <>
          {/* The command bar: history, viewports, the real lights, the picture, and saving. */}
          <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-stone-200 bg-stone-50 px-2 py-1 dark:border-stone-800 dark:bg-stone-900">
            <h1 className="px-1.5 text-sm font-semibold tracking-tight">Yard layout</h1>
            {overlapCount ? <Badge tone="red">Objects share LEDs</Badge> : dirty ? <Badge tone="amber">Unsaved changes</Badge> : null}
            {barSep}
            <Button size="sm" variant="ghost" onClick={undo} disabled={!history.canUndo} title="Undo (Ctrl/⌘+Z)" aria-label="Undo" className="px-2">
              <Undo2 />
            </Button>
            <Button size="sm" variant="ghost" onClick={redo} disabled={!history.canRedo} title="Redo (Ctrl/⌘+Shift+Z)" aria-label="Redo" className="px-2">
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
            <Button size="sm" variant="ghost" onClick={(e) => scenesMenu(below(e))} disabled={busy} title="Save the effects as a scene for the public page, or open a scene to change it">
              <Clapperboard />
              <span className="max-w-40 truncate">{editingScene ? editingScene.name : 'Scenes'}</span>
              <ChevronDown />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={(e) => picturesMenu(below(e))}
              disabled={busy}
              title="Pictures to trace over: the front of the house (a photo or a Street View screenshot), and the yard from above (a satellite view screenshot)"
            >
              {layout.background || layout.aerial ? <Images /> : <ImagePlus />} Pictures
              <ChevronDown />
            </Button>
            <Button size="sm" variant="ghost" onClick={(e) => fileMenu(below(e))} disabled={busy} title="Export the layout to a file, or import a layout from a file">
              <FolderOpen /> File
              <ChevronDown />
            </Button>
            <span className="ml-auto" />
            <Button size="sm" variant="ghost" onClick={() => (edit(() => saved!, true), setSelected(null))} disabled={!dirty || busy} title="Go back to the saved layout">
              <RotateCcw /> Revert
            </Button>
            <Button size="sm" variant="primary" onClick={save} disabled={!dirty || overlapCount > 0} loading={busy} title="Save the layout (Ctrl/⌘+S)">
              <Save /> Save
            </Button>
          </div>
        </>
      )}
      <input ref={layoutFileInput} type="file" accept="application/json,.json" hidden onChange={(e) => (void pickLayoutFile(e.target.files?.[0]), (e.target.value = ''))} />
      <input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => (upload(e.target.files?.[0]), (e.target.value = ''))} />
      <input ref={aerialInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => (uploadAerial(e.target.files?.[0]), (e.target.value = ''))} />
      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        {phone ? (
          sheet === 'full' ? null : phoneTools
        ) : (
          <>
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
              {toolButton('semicircle', Rainbow)}
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
              <button
                type="button"
                onClick={() => setCheck((c) => (c?.kind === 'slice' || c?.kind === 'bands' ? null : { kind: 'slice', axis: 'x', at: null }))}
                aria-pressed={check?.kind === 'slice' || check?.kind === 'bands'}
                title="Check alignment: a slice of white light sweeps across the yard, on the house and in the drawing. Settings: Check alignment, with nothing selected."
                aria-label="Check alignment"
                className={cn(
                  'relative grid size-9 shrink-0 place-items-center rounded-lg text-stone-600 transition hover:bg-stone-200/70 hover:text-stone-950 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white [&_svg]:size-[18px]',
                  (check?.kind === 'slice' || check?.kind === 'bands') && 'bg-sky-600 text-white hover:bg-sky-600 hover:text-white dark:text-white dark:hover:bg-sky-600'
                )}
              >
                <ScanLine />
              </button>
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
          </>
        )}

        {/* Viewports */}
        <div className={cn('relative flex min-h-0 min-w-0 flex-1 flex-col', phone && sheet === 'full' && 'hidden')}>
          {check && layoutCheck ? <CheckBar check={check} objectName={sel?.name ?? null} layout={layout} m={m} onChange={setCheck} /> : null}
          <div className={cn('grid min-h-0 flex-1 gap-px bg-stone-300 dark:bg-stone-800', phone ? 'grid-cols-1 grid-rows-1' : gridClass)}>
            {shown.map((v, i) => (
              <div key={v} className={cn('flex min-h-0 min-w-0 flex-col bg-[#05070f]', viewport.mode === 'three' && !single && i === 0 && 'lg:row-span-2')}>
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
                        selected={playing || probe || layoutCheck ? null : selected}
                        focus={focus3d}
                        onSelect={(id, add) => {
                          setTool('select');
                          if (add) return void (id && toggleTarget(id));
                          choose(id);
                        }}
                      />
                    </Suspense>
                  </div>
                ) : (
                  <PaneBody
                    onSize={(w, h) => setPaneSize((p) => (p[v]?.w === w && p[v]?.h === h ? p : { ...p, [v]: { w, h } }))}
                    onWheel={(e, r) => onWheel(v, e, r)}
                    onTouchFirst={onTouchFirst}
                    onPinchStart={() => onPinchStart(v)}
                    onPinch={(from, to) => onPinch(v, from, to)}
                    touchPans={touchPans}
                    canHold={(x, y) => fingerPick(v, x, y) != null}
                    onHold={(x, y) => onHold(v, x, y)}
                    onTap={(x, y) => onTap(v, x, y)}
                    onPanStart={() => onTouchPanStart(v)}
                    onPan={(dx, dy) => onTouchPan(v, dx, dy)}
                  >
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
                  <div className="flex flex-wrap items-center gap-2 rounded-xl bg-stone-900/90 px-3 py-1.5 text-xs text-white shadow-lg ring-1 ring-white/10 backdrop-blur max-lg:text-sm">
                    <span>
                      {draft.cont ? `Adding to ${layout.fixtures.find((f) => f.id === draft.cont!.id)?.name ?? 'the line'}` : `New ${TOOL_LABELS[tool].toLowerCase()}`}:{' '}
                      <span className="tabular-nums">{draft.pts.length}</span> point(s)
                    </span>
                    <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10 max-lg:px-3 max-lg:py-2" onClick={() => setDraft((d) => ({ ...d, pts: d.pts.slice(0, -1) }))} title="Backspace">
                      Remove last point
                    </button>
                    <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10 max-lg:px-3 max-lg:py-2" onClick={() => setDraft((d) => ({ side: d.side, pts: [] }))}>
                      Cancel
                    </button>
                    {draft.pts.length >= 2 ? (
                      <button type="button" className="rounded-md bg-sky-600 px-2.5 py-1 font-semibold hover:bg-sky-500 max-lg:px-3 max-lg:py-2" onClick={() => finishLine(tool)} title="Enter">
                        Finish line
                      </button>
                    ) : null}
                  </div>
                ) : tool === 'align' ? (
                  <div className="flex flex-wrap items-center gap-2 rounded-xl bg-stone-900/90 px-3 py-1.5 text-xs text-white shadow-lg ring-1 ring-white/10 backdrop-blur">
                    <span className="max-w-[34rem]">{layout.aerial ? ALIGN_STEPS[alignPts.length] : 'Add a picture from above first (Pictures menu).'}</span>
                    {alignPts.length ? (
                      <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10 max-lg:px-3 max-lg:py-2" onClick={() => setAlignPts((a) => a.slice(0, -1))} title="Backspace">
                        Undo last click
                      </button>
                    ) : null}
                    {alignPts.length === 2 ? (
                      <button type="button" className="rounded-md bg-teal-600 px-2.5 py-1 font-semibold hover:bg-teal-500 max-lg:px-3 max-lg:py-2" onClick={() => finishAlign(alignPts)} title="Enter">
                        Just move it
                      </button>
                    ) : null}
                    <button type="button" className="rounded-md px-2 py-1 hover:bg-white/10 max-lg:px-3 max-lg:py-2" onClick={() => chooseTool('select')} title="Esc">
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
                      updateLayout({ scale: Math.round((tapeLength / meters) * 1000) / 1000, scaleBy: 'hand' });
                      setTape(null);
                      toast.success(
                        `Scale set: ${m.text(tapeLength)} is now ${meters * (m.units === 'm' ? 1 : FEET_PER_METER)} ${m.units}.${roofScale(layout) ? ' It is set by hand now, not by the roofline (Yard size: Use the roofline).' : ''}`
                      );
                    }}
                  />
                ) : null}
              </div>
            </div>
          ) : null}
        </div>

        {phone ? (
          <>
            {sheet === 'full' ? null : phoneStatus}
            {phoneSheet}
          </>
        ) : (
          <>
            {/* The side panel: the object list. The selected object opens in the list, with its properties right under it. */}
            <aside ref={sidePanel} className="flex shrink-0 flex-col border-stone-200 bg-white text-sm lg:w-80 lg:overflow-y-auto lg:border-l dark:border-stone-800 dark:bg-stone-900">
              {objectList(true)}
              <div>{sel ? null : restPanel()}</div>
            </aside>
          </>
        )}
      </div>

      {phone ? null : (
        <>
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
                  ['grid', 'Grid', 'Show the grid'],
                  ['gridSnap', 'Grid snap', 'Snap to the grid where no point or line is near (Alt: not now)']
                ] as [DraftSwitch, string, string][]
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
              <GridSettings drafting={drafting} layout={layout} onChange={setDrafting} />
            </span>
          </div>
        </>
      )}
      {menu ? <ContextMenu menu={menu} sheet={phone} onClose={() => setMenu(null)} /> : null}
      <ConfirmDialog
        open={importing != null}
        title="Import this layout?"
        confirmLabel="Import and replace"
        danger
        loading={busy}
        onConfirm={() => void confirmImport()}
        onClose={() => !busy && setImporting(null)}
      >
        <div className="space-y-2">
          <p>
            <span className="font-medium">{importing?.name}</span> has {importing?.objects} object(s)
            {importing?.pictures ? ` and ${importing.pictures} picture(s)` : ' and no pictures'}. It replaces the saved layout, its pictures and its game area
            {dirty ? ', and your unsaved changes are lost' : ''}. Objects keep their WLED device when it is here (the same address or name).
          </p>
          <p>
            To keep a copy of the layout you have now,{' '}
            <button type="button" className="font-medium text-sky-700 underline hover:no-underline dark:text-sky-300" disabled={busy} onClick={() => void exportLayout()}>
              export it first
            </button>
            .
          </p>
        </div>
      </ConfirmDialog>
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
          onLights={setPhotoLights}
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
  // The roofline's LEDs are a known distance apart: they set the scale unless it is set by hand.
  const roof = roofScale(layout);
  const byRoof = !!roof && layout.scaleBy !== 'hand';
  // Real meters as text in the editor's units, whatever the scale is now.
  const metersText = (meters: number) => m.text(meters * layoutScale(layout));
  const roofs = roof ? layout.fixtures.filter((f) => roof.roofs.includes(f.id)) : [];
  const leds = roofs.reduce((a, f) => a + Math.floor(f.pixels), 0);
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
        hint={byRoof ? 'The real width of the front view, from the roofline. Typing a width sets the scale by hand instead.' : 'The real width of the front view. It sets the scale.'}
        value={layout.width}
        m={m}
        min={0.1}
        onChange={(lu) => onChange({ scale: Math.round(((layoutScale(layout) * layout.width) / lu) * 1000) / 1000, scaleBy: 'hand' })}
      />
      <PropRow label="Scale">
        <div className="flex flex-wrap gap-1.5">
          {roof && !byRoof ? (
            <PropButton onClick={() => onChange({ scaleBy: undefined })} title={`The roofline’s strings make the front view ${metersText(layout.width / roof.scale)} wide`}>
              <Ruler /> Use the roofline
            </PropButton>
          ) : null}
          <PropButton onClick={onMeasure} title={byRoof ? 'Measure something you know, then type its real size: the scale is then set by hand (M)' : 'Measure something you know, then type its real size (M)'}>
            <Ruler /> Measure
          </PropButton>
        </div>
      </PropRow>
      {byRoof ? (
        <PropNote>
          Set by the roofline: {roofs.length > 1 ? `${roofs.length} roofs, ` : ''}
          {leds} LEDs, {metersText(roof.meters)} of string from corner to corner{roofs.some((f) => f.skip?.length) ? ' (skipped segments left out)' : ''}. Match the roof to the lights (each corner gets its LED) and give it its
          real number of strings: the scale follows, and so do the top and 3D views and the picture from above. Objects keep the size they are drawn at.
        </PropNote>
      ) : roof ? (
        <PropNote>
          Set by hand. The roofline’s strings would make the front view {metersText(layout.width / roof.scale)} wide.
        </PropNote>
      ) : (
        <PropNote>
          Real distances make the top and 3D views true to life, and let animations move at real speeds. Give the roofline its light string and the scale is set from it: its LEDs are a known distance
          apart. Or measure something you know at the front wall, for example a garage door.
        </PropNote>
      )}
      <PropNote>Drag the dashed ground line in the front view to the bottom of the front wall: heights count from there.</PropNote>
    </PropSection>
  );
}

/** A turn in degrees, set with a slider. */
function AngleSlider({ label, value, min, max, hint, onChange }: { label: string; value: number; min: number; max: number; hint?: string; onChange: (deg: number) => void }) {
  return (
    <PropRow label={label} hint={hint}>
      <div className="flex items-center gap-2">
        <input
          type="range"
          aria-label={label}
          min={min}
          max={max}
          step={1}
          value={value}
          onChange={(e) => onChange(Number(e.target.value))}
          className="h-7 min-w-0 flex-1 cursor-pointer accent-sky-600 dark:accent-sky-400"
        />
        <span className="w-8 shrink-0 text-right text-[11px] text-stone-500 tabular-nums">{value}°</span>
      </div>
    </PropRow>
  );
}

/** A front view angle with its unset settings left out, or undefined for straight on from far away. */
function tidyFrontView(v: FrontView): FrontView | undefined {
  const out: FrontView = {};
  if (v.yaw) out.yaw = Math.max(-MAX_YAW, Math.min(MAX_YAW, Math.round(v.yaw)));
  if (v.pitch) out.pitch = Math.max(0, Math.min(MAX_PITCH, Math.round(v.pitch)));
  if (v.distance && v.distance >= 10) out.distance = Math.round(v.distance);
  return Object.keys(out).length ? out : undefined;
}

/**
 * Where the front view looks at the yard from: the place the picture of the house was taken
 * from. The yard turns under the picture, so the objects line up with it.
 */
function FrontViewProps({ layout, m, onChange }: { layout: Layout; m: Measure; onChange: (v: FrontView | undefined) => void }) {
  const v = layout.frontView ?? {};
  const set = (patch: Partial<FrontView>) => onChange(tidyFrontView({ ...v, ...patch }));
  return (
    <PropSection key="frontview" id="frontview" title="Front view angle">
      <AngleSlider label="Turned" value={v.yaw ?? 0} min={-MAX_YAW} max={MAX_YAW} onChange={(yaw) => set({ yaw })} hint="Seen from farther to the right (more) or the left (less), as from the street" />
      <AngleSlider label="From above" value={v.pitch ?? 0} min={0} max={MAX_PITCH} onChange={(pitch) => set({ pitch })} hint="Looking down on the yard, as from a window upstairs or a ladder" />
      <PropNumber
        label="Distance"
        hint="How far from the front wall the picture was taken: closer makes what is nearer look bigger. Empty or 0: far away (no perspective)."
        decimal
        value={v.distance ? m.show(v.distance) : null}
        placeholder="far away"
        min={0}
        step={m.units === 'm' ? 0.5 : 1}
        unit={m.units}
        onChange={(n) => set({ distance: n > 0 ? n * m.per : undefined })}
      />
      <PropRow label="">
        <PropButton onClick={() => onChange(undefined)} disabled={!layout.frontView}>
          <RotateCcw /> Straight on
        </PropButton>
      </PropRow>
      <PropNote>
        Set where the picture of the house was taken from, and the whole yard turns under it so the objects line up with the picture: a roofline down the side of the house, the trees in front of it. The
        yard turns about the middle of the front wall at the ground. It only changes how the front view (and the yard on the public page) looks: effects and games are the same.
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
  return xyz(0, f.kind === 'tree' || f.kind === 'semicircle' ? 'Base height' : 'Height');
}


/**
 * The LED numbers of an object on its device. A line is matched to the real lights with the
 * wizard (`onMatch`); typing the numbers is folded away under Advanced. Other objects have
 * only the numbers.
 */
function LedProps({
  f,
  onRange,
  onMatch,
  onShape,
  onClearMarks
}: {
  f: Fixture;
  onRange: (first: number, last: number) => void;
  onMatch?: () => void;
  /** A tree: Shape to the lights. */
  onShape?: () => void;
  onClearMarks?: () => void;
}) {
  const { first, last } = ledRange(f);
  const fields = <LedFields f={f} onRange={onRange} />;
  if (onShape) {
    const marks = validMarks(f).length;
    return (
      <>
        {fields}
        <PropRow
          label="Shape"
          hint="One LED blinks red on the tree. Move it along the string and mark where you see it: its start and end, and where it passes the front, the right, the back or the left. The drawing follows."
        >
          <div className="flex flex-wrap gap-1">
            <PropButton onClick={onShape} disabled={!f.deviceId} title={f.deviceId ? 'Mark where the real LEDs are on the tree' : 'Pick the WLED device first'}>
              <LocateFixed /> Shape to the lights
            </PropButton>
            {marks && onClearMarks ? (
              <PropButton onClick={onClearMarks} title="Every LED goes back to where the pattern puts it">
                Clear {marks} mark{marks === 1 ? '' : 's'}
              </PropButton>
            ) : null}
          </div>
        </PropRow>
        {!f.deviceId ? <PropNote>Pick its WLED device (in Object) to shape it to the real lights.</PropNote> : null}
      </>
    );
  }
  if (!onMatch) return fields;
  return (
    <>
      <PropRow label="LEDs">
        <span className="block text-xs tabular-nums">
          {first}–{last} ({f.pixels})
        </span>
      </PropRow>
      <PropRow label="" hint="One LED blinks red on the house. Move it to the start, to each corner and to the end of the real line, and the drawing takes those LEDs.">
        <PropButton onClick={onMatch} disabled={!f.deviceId} title={f.deviceId ? 'Step through the start, each corner and the end on the real lights' : 'Pick the WLED device first'}>
          <LocateFixed /> Match to the lights
        </PropButton>
      </PropRow>
      {!f.deviceId ? <PropNote>Pick its WLED device (in Object) to match it to the real lights.</PropNote> : null}
      <PropAdvanced id="leds" label="Advanced: type the LED numbers">
        {fields}
      </PropAdvanced>
    </>
  );
}

function LedFields({ f, onRange }: { f: Fixture; onRange: (first: number, last: number) => void }) {
  const { first, last } = ledRange(f);
  // A custom object has as many LEDs as its design: moving the first LED moves them all.
  const fixed = f.kind === 'custom';
  return (
    <>
      <PropNumber
        label="First LED"
        tone="green"
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
          <PropNumber label="Last LED" tone="red" value={last} onChange={(n) => onRange(first, Math.round(n))} hint="The device LED number at the end" />
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

/**
 * The "match to the lights" wizard, one point at a time: one LED blinks red on the house, the
 * buttons, the slider or the arrow keys move it along the line, and "Found it" gives the point
 * that LED. The start and the end can move past the line's LEDs; corners stay in order.
 */
function MatchWizard({
  f,
  probe,
  ledCount,
  device,
  perStrand,
  lights,
  onStrand,
  onSet,
  onMove,
  onGo,
  onFound,
  onStop
}: {
  f: Fixture;
  probe: MatchProbe;
  /** The LEDs on the device, as set in WLED (null: not known). */
  ledCount: number | null;
  device: string | null;
  /** LEDs in one strand of the line's lights (null: not known, or a strip). */
  perStrand: number | null;
  /** Jumps to the start of the next (1) or the previous (-1) strand. */
  onStrand: (dir: 1 | -1) => void;
  /** Why the lights do not show the blinking LED, if they do not. */
  lights: string | null;
  onSet: (offset: number) => void;
  onMove: (delta: number) => void;
  onGo: (point: number) => void;
  onFound: () => void;
  onStop: () => void;
}) {
  const L = f.points.length - 1;
  const n = Math.max(1, Math.floor(f.pixels));
  const { point, offset } = probe;
  const { lo, hi } = matchRange(f, point, ledCount);
  const offs = pointOffsets(f);
  // The slider spans the room the point has, or a little past the line for the ends.
  const room = Math.max(10, Math.round(n * 0.2));
  const sMin = Math.min(offset, point === 0 ? Math.max(lo, -room) : lo);
  const sMax = Math.max(offset, point === L ? Math.min(hi, n - 1 + room) : hi);
  const led = deviceLed(f, offset);
  const name = point === 0 ? 'The start' : point === L ? 'The end' : `Corner ${point}`;
  const since = point > 0 ? offset - offs[point - 1] : null;
  // Strands count from device LED 0: the chain on the device is made of whole strands.
  const strand = perStrand ? { at: Math.floor(led / perStrand) + 1, bulb: (led % perStrand) + 1, of: ledCount ? Math.ceil(ledCount / perStrand) : null } : null;
  // The device's last LED, where a line that ends the chain ends.
  const lastLed = ledCount ? ledCount - 1 : null;
  const lastOffset = lastLed != null ? (f.reversed ? f.startPixel + n - 1 - lastLed : lastLed - f.startPixel) : null;
  const towardLast = lastOffset != null && lastOffset >= lo && lastOffset <= hi;
  const steps: [number, string][] = [
    [-10, '−10'],
    [-1, '−1'],
    [1, '+1'],
    [10, '+10']
  ];
  return (
    <>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-sm font-semibold">{name}</span>
        <span className="text-[11px] text-stone-500 tabular-nums">
          step {point + 1} of {L + 1}
        </span>
      </div>
      <p className="text-xs text-stone-600 dark:text-stone-400">
        {point === 0
          ? 'Move the blinking red LED to the first LED of this line on the house.'
          : point === L
            ? 'Move the blinking red LED to the last LED of this line.'
            : 'Move the blinking red LED to the first LED after this corner.'}{' '}
        The drawing shows where it is now.
      </p>
      <div className="flex items-center justify-between gap-2 rounded-md bg-stone-100 px-2.5 py-2 dark:bg-stone-800">
        <span className="text-lg font-semibold text-red-600 tabular-nums dark:text-red-400">LED {led}</span>
        <span className="text-right text-[11px] text-stone-500 tabular-nums">
          {strand ? (
            <>
              strand {strand.at}
              {strand.of ? ` of ${strand.of}` : ''}, bulb {strand.bulb} of {perStrand}
              <br />
            </>
          ) : null}
          {since != null ? `${since} LEDs after the ${point === 1 ? 'start' : `corner ${point - 1}`}` : `${n} LEDs in the line`}
        </span>
      </div>
      {ledCount ? (
        <p className="text-[11px] text-stone-500 tabular-nums">
          {device ?? 'The device'} has {ledCount} LEDs in WLED (0–{ledCount - 1}){perStrand ? `: ${ledCount % perStrand ? `${(ledCount / perStrand).toFixed(1)}` : ledCount / perStrand} strands of ${perStrand}` : ''}. The red LED stays within them.
        </p>
      ) : null}
      <div className="grid grid-cols-4 gap-1">
        {steps.map(([d, label]) => (
          <PropButton key={d} onClick={() => onMove(d)} disabled={d < 0 ? offset <= lo : offset >= hi} title={`${d < 0 ? 'Back toward the start' : 'On toward the end'} by ${Math.abs(d)}`}>
            <span className="w-full text-center tabular-nums">{label}</span>
          </PropButton>
        ))}
      </div>
      {perStrand || (point === f.points.length - 1 && towardLast) ? (
        <div className="flex flex-wrap gap-1">
          {perStrand ? (
            <>
              <PropButton onClick={() => onStrand(-1)} title="To the first bulb of this strand, or of the one before (Page Up)">
                <ChevronLeft /> Strand
              </PropButton>
              <PropButton onClick={() => onStrand(1)} title="To the first bulb of the next strand (Page Down)">
                Strand <ChevronRight />
              </PropButton>
            </>
          ) : null}
          {point === f.points.length - 1 && towardLast && lastOffset !== offset ? (
            <PropButton onClick={() => onSet(lastOffset!)} title="This line ends the chain: its last LED is the device's last">
              Last LED in WLED ({lastLed})
            </PropButton>
          ) : null}
        </div>
      ) : null}
      <input
        type="range"
        aria-label="Blinking LED"
        min={sMin}
        max={sMax}
        step={1}
        value={offset}
        onChange={(e) => onSet(Number(e.target.value))}
        className="h-7 w-full cursor-pointer accent-red-600 dark:accent-red-400"
      />
      <div className="flex items-center gap-1">
        <PropButton onClick={() => onGo(point - 1)} disabled={point === 0} title="The point before (Backspace)">
          <ChevronLeft /> Back
        </PropButton>
        <PropButton onClick={() => onGo(point + 1)} disabled={point === L} title="Keep this point as it is">
          Skip
        </PropButton>
        <span className="flex-1" />
        <Button size="sm" variant="primary" onClick={onFound} title="This LED is the spot (Enter)">
          {point === L ? 'Found it, done' : 'Found it'}
        </Button>
      </div>
      <div className="flex flex-wrap gap-1 pt-1" aria-label="Points">
        {f.points.map((_, i) => (
          <button
            key={i}
            type="button"
            onClick={() => onGo(i)}
            title={i === 0 ? 'The start' : i === L ? 'The end' : `Corner ${i}`}
            aria-current={i === point}
            className={cn(
              'size-2.5 rounded-full ring-1 ring-stone-400 dark:ring-stone-500',
              i < point && 'bg-emerald-500 ring-emerald-500',
              i === point && 'bg-red-500 ring-2 ring-red-500',
              isPinned(f, i) && i > point && 'bg-amber-400 ring-amber-400'
            )}
          />
        ))}
      </div>
      {lights ? <PropNote tone="red">{lights}</PropNote> : null}
      <PropNote>
        Arrow keys move the LED (Shift: 10 at a time{perStrand ? '; Page Up and Page Down: a strand' : ''}), Enter takes it, Backspace goes back, Esc stops.
      </PropNote>
      <PropRow label="">
        <PropButton onClick={onStop}>
          <X /> Stop
        </PropButton>
      </PropRow>
    </>
  );
}

function CornerProps({ f, index, onPin, onSplit, onFind }: { f: Fixture; index: number; onPin: (led: number | null) => void; onSplit: () => void; onFind?: () => void }) {
  const led = deviceLed(f, pointOffsets(f)[index]);
  const pinned = isPinned(f, index);
  const ignored = f.pointLeds?.[index] != null && !pinned;
  return (
    <>
      <PropRow label="LED after it" hint="The first LED after this corner. The segment before it ends on the LED just before.">
        <span className="block text-xs tabular-nums">
          {led} {pinned ? '(pinned)' : '(estimated from the line length)'}
        </span>
      </PropRow>
      <PropRow label="">
        <div className="flex flex-wrap gap-1">
          {onFind ? (
            <PropButton onClick={onFind} title="Blink an LED on the house and move it to this corner">
              <LocateFixed /> Find on the lights
            </PropButton>
          ) : null}
          <PropButton onClick={onSplit}>
            <Scissors /> Split here
          </PropButton>
        </div>
      </PropRow>
      {ignored ? <PropNote tone="red">The pinned number is not between the numbers of the points on each side, so it is not used.</PropNote> : null}
      <PropAdvanced id="corner" label="Advanced: type the LED number">
        <PropNumber label="LED after it" value={led} onChange={(n) => onPin(Math.round(n))} />
        <PropRow label="">
          {pinned || ignored ? (
            <PropButton onClick={() => onPin(null)}>
              <PinOff /> Unpin
            </PropButton>
          ) : (
            <PropButton onClick={() => onPin(led)}>
              <Pin /> Pin here
            </PropButton>
          )}
        </PropRow>
        <PropNote>{pinned ? 'Pinned: this number stays when you edit other segments.' : 'Type the real number to pin it.'}</PropNote>
      </PropAdvanced>
    </>
  );
}

/** The wizard's blinking LED on the drawing: where the line puts it now, with its device LED number. */
function ProbeMarker({ f, probe, V, k, scale }: { f: Fixture; probe: MatchProbe; V: (p: Point) => { u: number; v: number }; k: number; scale: number }) {
  const px = fixturePixels(f, scale);
  if (!px.length) return null;
  // Past either end of the line, it shows at that end.
  const at = V(px[Math.min(px.length - 1, Math.max(0, probe.offset))]);
  const point = V(f.points[probe.point]);
  // A line: the point being matched. A tree being shaped: its marks, amber.
  const marks = isLine(f) ? [] : validMarks(f);
  return (
    <g pointerEvents="none">
      {isLine(f) ? <circle cx={point.u} cy={point.v} r={11 * k} fill="none" stroke="#fff" strokeWidth={2 * k} strokeDasharray={`${3 * k} ${3 * k}`} /> : null}
      {marks.map((m) => {
        const q = V(px[m.led]);
        return <circle key={m.led} cx={q.u} cy={q.v} r={5 * k} fill="#f59e0b" stroke="#0c0a09" strokeWidth={1.5 * k} />;
      })}
      <circle cx={at.u} cy={at.v} r={8 * k} fill="none" stroke="#ef4444" strokeWidth={3 * k} className="animate-pulse" />
      <text
        x={at.u}
        y={at.v - 16 * k}
        textAnchor="middle"
        fontSize={14 * k}
        fontWeight={700}
        fill="#f87171"
        stroke="#0c0a09"
        strokeWidth={4 * k}
        paintOrder="stroke"
        className="tabular-nums"
      >
        LED {deviceLed(f, probe.offset)}
      </text>
    </g>
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
  if (f.kind === 'custom' || f.kind === 'semicircle') {
    const pts = objectPaths(f, scale).flat().map(V);
    const { first, last } = ledRange(f);
    if (!pts.length) return null;
    const u = (Math.min(...pts.map((q) => q.u)) + Math.max(...pts.map((q) => q.u))) / 2;
    return label(u, Math.min(...pts.map((q) => q.v)) - 10 * k, `LEDs ${first}–${last}`, true, 'c');
  }
  if (!isLine(f)) {
    const c = V(f.points[0]);
    const r = radiusOf(f);
    const { first, last } = ledRange(f);
    const above = side === 'top' ? r : f.kind === 'tree' ? treeSize(f).h : r * BUSH_TALL;
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
      <PropRow label="LEDs">
        <span className="block text-xs tabular-nums">
          {start}–{end} ({Math.abs(end - start) + 1}
          {on ? '' : ', off'})
        </span>
      </PropRow>
      <PropNote>Only this segment glows on the lights: green at its start, red at its end. To move its ends, match the line to the lights (in LEDs).</PropNote>
      <PropAdvanced id="segment" label="Advanced: type the LED numbers">
        <PropNumber label="Start LED" tone="green" value={start} onChange={(n) => onPoint(index, limit(index, Math.round(n)))} />
        <PropNumber
          label="End LED"
          tone="red"
          value={end}
          onChange={(n) => (isLast ? onPoint(index + 1, limit(index + 1, Math.round(n))) : onPoint(index + 1, limit(index + 1, Math.round(n) + dir)))}
        />
        <PropNote>
          {!isLast ? `The next segment starts at LED ${end + dir}. ` : ''}Move its ends until the green and red LEDs sit at the real corners; these numbers stay fixed when you edit
          other segments.
        </PropNote>
      </PropAdvanced>
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
  // Strings run in the order of the device's LEDs (see stringStarts).
  const count = Math.floor(f.pixels);
  const starts = stringStarts(count, perStrand, f.stringBreaks);
  if (!starts.length) return null;
  const px = fixturePixels(f, scale);
  return (
    <g pointerEvents="none">
      {starts.map((d, n) => {
        const i = f.reversed ? count - 1 - d : d;
        const p = px[i];
        if (!p) return null;
        const q = V(p);
        return (
          <g key={i}>
            <rect x={q.u - 6 * k} y={q.v - 6 * k} width={12 * k} height={12 * k} transform={`rotate(45 ${q.u} ${q.v})`} fill="#fb923c" stroke="#0c0a09" strokeWidth={2 * k} />
            {labels ? (
              <text x={q.u} y={q.v + 24 * k} textAnchor="middle" fontSize={12 * k} fontWeight={600} fill="#fdba74" stroke="#0c0a09" strokeWidth={3.5 * k} paintOrder="stroke" className="tabular-nums">
                string {n + 2} · #{f.startPixel + d}
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

const SNAP_LABELS: Record<Snapped['kind'], string> = { point: 'Point', center: 'Center', mid: 'Midpoint', on: 'On line', align: 'Aligned', grid: 'Grid', angle: '', free: '' };

/** Where the pointer snaps: a marker in the CAD style (square: point, triangle: midpoint, cross: on a line, plus: the grid), dashed guides, and a label. */
function SnapMarker({ s, k }: { s: Snapped & { label?: string }; k: number }) {
  if (s.kind === 'free' && !s.label) return null;
  const { u, v } = s.at;
  const color = '#22d3ee';
  const common = { fill: 'none', stroke: color, strokeWidth: 2 * k };
  const d = 8 * k;
  let label = s.label ?? SNAP_LABELS[s.kind];
  if (!s.label && (s.kind === 'angle' || s.kind === 'grid') && s.guides[0]) {
    const [a, b] = s.guides[0];
    const deg = Math.round((Math.atan2(-(b.v - a.v), b.u - a.u) * 180) / Math.PI);
    const dir = (deg + 360) % 180 === 0 ? 'Level' : Math.abs(deg) === 90 ? 'Upright' : '45°';
    label = s.kind === 'grid' ? `${dir} · Grid` : dir;
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
      {s.kind === 'grid' ? <path d={`M${u - d},${v}L${u + d},${v}M${u},${v - d}L${u},${v + d}`} {...common} /> : null}
      {label ? (
        <text x={u + 12 * k} y={v - 12 * k} fontSize={13 * k} fontWeight={600} fill="#a5f3fc" stroke="#0c0a09" strokeWidth={3.5 * k} paintOrder="stroke">
          {label}
        </text>
      ) : null}
    </g>
  );
}

/** The right-click menu: actions for the point, segment or object under the pointer. */
/** Quick grid sizes, for layouts in feet and in meters. */
const GRID_PRESETS: Record<Units, [number, GridUnit][]> = {
  ft: [
    [3, 'in'],
    [6, 'in'],
    [1, 'ft'],
    [2, 'ft'],
    [5, 'ft']
  ],
  m: [
    [5, 'cm'],
    [10, 'cm'],
    [25, 'cm'],
    [50, 'cm'],
    [1, 'm']
  ]
};

/** The grid size in the status bar; a click opens the grid settings: size, units, brighter lines, show and snap. */
/** The grid's settings: shown, snapped to, its size and units, and its bright lines. */
function GridFields({ drafting, layout, onChange }: { drafting: Drafting; layout: Layout; onChange: (patch: Partial<Drafting>) => void }) {
  const g = gridOf(drafting, layout);
  /** Another unit keeps about the same size, rounded to two figures (5 ft is 1.5 m). */
  const setUnit = (unit: GridUnit) => {
    const from = GRID_UNITS.find((x) => x.unit === g.unit)!.meters;
    const to = GRID_UNITS.find((x) => x.unit === unit)!.meters;
    onChange({ gridUnit: unit, gridSize: Number(((g.size * from) / to).toPrecision(2)) });
  };
  const row = 'flex items-center justify-between gap-3';
  return (
    <>
      <p className="text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Grid</p>
      <label className={row}>
        <span>Show the grid</span>
        <Switch checked={drafting.grid} onChange={(v) => onChange({ grid: v })} label="Show the grid" />
      </label>
      <label className={row}>
        <span>Snap to the grid</span>
        <Switch checked={drafting.gridSnap} onChange={(v) => onChange({ gridSnap: v })} label="Snap to the grid" />
      </label>
      <div className={row}>
        <span>Size</span>
        <span className="flex w-36 gap-1">
          <NumberInput compact decimal value={g.size} min={0.01} max={1000} step={g.unit === 'cm' || g.unit === 'in' ? 1 : 0.5} onCommit={(n) => onChange({ gridSize: n, gridUnit: g.unit })} className="w-16" />
          <select
            value={g.unit}
            onChange={(e) => setUnit(e.target.value as GridUnit)}
            aria-label="Grid units"
            className="h-7 w-16 shrink-0 rounded-md bg-white px-1.5 text-xs ring-1 ring-stone-200 ring-inset focus:ring-2 focus:ring-sky-500 focus:outline-none dark:bg-stone-950 dark:ring-stone-700"
          >
            {GRID_UNITS.map((x) => (
              <option key={x.unit} value={x.unit}>
                {x.label}
              </option>
            ))}
          </select>
        </span>
      </div>
      <div className="flex flex-wrap gap-1">
        {GRID_PRESETS[layout.units ?? 'ft'].map(([size, unit]) => (
          <button
            key={`${size}${unit}`}
            type="button"
            onClick={() => onChange({ gridSize: size, gridUnit: unit })}
            className={cn(
              'rounded-md px-2 py-0.5 tabular-nums ring-1 ring-stone-200 transition hover:bg-stone-100 dark:ring-stone-700 dark:hover:bg-stone-800',
              g.size === size && g.unit === unit && 'bg-sky-600/15 text-sky-700 ring-sky-600/30 dark:text-sky-300'
            )}
          >
            {size} {unit}
          </button>
        ))}
      </div>
      <div className={row}>
        <span title="Every this many lines, one is brighter">Bright line every</span>
        <span className="flex w-36 items-center gap-1.5">
          <NumberInput compact value={drafting.gridMajor} min={1} max={50} onCommit={(n) => onChange({ gridMajor: Math.round(n) })} className="w-16" />
          <span className="text-stone-500">lines</span>
        </span>
      </div>
      <p className="text-[11px] leading-snug text-stone-500">
        The grid counts from the left edge, and from the ground (front view) or the front wall (top view). Alt (Option) turns grid snap off while you hold it. Lines closer than a few pixels are not drawn: zoom in to see them.
      </p>
    </>
  );
}

/**
 * The phone's drafting menu: snapping, ortho and the grid, which the wide screen keeps in its
 * status bar.
 */
function DraftingMenu({ drafting, layout, onChange }: { drafting: Drafting; layout: Layout; onChange: (patch: Partial<Drafting>) => void }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener('pointerdown', away);
    return () => document.removeEventListener('pointerdown', away);
  }, [open]);
  const on = drafting.snap || drafting.ortho || drafting.gridSnap;
  const row = 'flex items-center justify-between gap-3';
  return (
    <div ref={box} className="relative">
      <button
        type="button"
        aria-label="Snapping and grid"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={cn(
          'grid size-10 shrink-0 place-items-center rounded-lg transition [&_svg]:size-[18px]',
          open && 'bg-stone-200 dark:bg-stone-800',
          on ? 'text-sky-700 dark:text-sky-300' : 'text-stone-500 dark:text-stone-400'
        )}
      >
        <Magnet />
      </button>
      {open ? (
        <div
          role="dialog"
          aria-label="Snapping and grid"
          className="absolute top-full right-0 z-30 mt-1 max-h-[70dvh] w-72 max-w-[calc(100vw-1rem)] space-y-3 overflow-y-auto rounded-xl bg-white p-3 text-sm text-stone-700 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:text-stone-200 dark:ring-stone-700"
        >
          <p className="text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Snapping</p>
          <label className={row}>
            <span>Snap to points and lines</span>
            <Switch checked={drafting.snap} onChange={(v) => onChange({ snap: v })} label="Snap to points and lines" />
          </label>
          <label className={row}>
            <span>Keep lines level or upright</span>
            <Switch checked={drafting.ortho} onChange={(v) => onChange({ ortho: v })} label="Keep lines level or upright (ortho)" />
          </label>
          <GridFields drafting={drafting} layout={layout} onChange={onChange} />
        </div>
      ) : null}
    </div>
  );
}

function GridSettings({ drafting, layout, onChange }: { drafting: Drafting; layout: Layout; onChange: (patch: Partial<Drafting>) => void }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLSpanElement>(null);
  const g = gridOf(drafting, layout);
  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && (e.stopPropagation(), setOpen(false));
    document.addEventListener('pointerdown', away);
    window.addEventListener('keydown', esc, true);
    return () => {
      document.removeEventListener('pointerdown', away);
      window.removeEventListener('keydown', esc, true);
    };
  }, [open]);
  return (
    <span ref={box} className="relative">
      <button
        type="button"
        title="Grid settings: size, units and snapping"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-0.5 rounded px-1.5 py-0.5 font-semibold tabular-nums transition hover:bg-stone-200/70 hover:text-stone-800 dark:hover:bg-stone-800 dark:hover:text-stone-200"
      >
        {g.text}
        <ChevronDown className="size-3" />
      </button>
      {open ? (
        <div
          role="dialog"
          aria-label="Grid settings"
          className="absolute right-0 bottom-full z-50 mb-2 w-64 space-y-2.5 rounded-xl bg-white p-3 text-xs text-stone-700 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:text-stone-200 dark:ring-stone-700"
        >
          <GridFields drafting={drafting} layout={layout} onChange={onChange} />
        </div>
      ) : null}
    </span>
  );
}

function ContextMenu({ menu, sheet, onClose }: { menu: { x: number; y: number; title: string; items: MenuItem[] }; sheet?: boolean; onClose: () => void }) {
  // On a phone, an action sheet that rises from the bottom, with big rows, as phone apps do.
  if (sheet) return <ActionSheet data-layout-menu title={menu.title} items={menu.items} onClose={onClose} />;
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

/** How long a finger holds still on a handle for its right-click menu (a point's), in ms. */
const LONG_PRESS_MS = 500;
/** How long a finger holds still on an object to select it (or, on the selected one, for its menu), in ms. */
const HOLD_SELECT_MS = 1000;
/** How far a finger moves before a touch is a pan, not a tap or a hold, in pixels. */
const PAN_SLOP = 8;

/** What a hold did: selected what was under the finger, or asks for its menu. */
type HoldResult = 'selected' | 'menu' | null;

/**
 * The drawing area of a 2D viewport: reports its size, and passes wheel events (which must not
 * scroll the page) to the camera. On a touch screen it also takes the gestures the drawing never
 * sees: one finger pans (where `touchPans` says so: everywhere but the handles, with the Select
 * tool), holding still on an object selects it, two fingers pinch to zoom and drag to pan, and
 * a long press on a handle opens its right-click menu.
 */
function PaneBody({
  onSize,
  onWheel,
  onTouchFirst,
  onPinchStart,
  onPinch,
  touchPans,
  canHold,
  onHold,
  onTap,
  onPanStart,
  onPan,
  children
}: {
  onSize: (w: number, h: number) => void;
  onWheel: (e: WheelEvent, rect: DOMRect) => void;
  /** A first finger comes down (before the drawing sees it). */
  onTouchFirst: () => void;
  /** A second finger came down: a pinch starts. */
  onPinchStart: () => void;
  /** The two fingers moved: from where they came down, to where they are (pixels in the pane). */
  onPinch: (from: Pair, to: Pair) => void;
  /** Whether one finger coming down on this element pans the view (and holds to select) instead of reaching the drawing. */
  touchPans: (target: Element) => boolean;
  /** Whether a hold here would select something (a ring then fills around the finger). */
  canHold: (clientX: number, clientY: number) => boolean;
  onHold: (clientX: number, clientY: number) => HoldResult;
  /** A finger came down and lifted without moving, before the hold. */
  onTap: (clientX: number, clientY: number) => void;
  onPanStart: () => void;
  /** One finger moved by (dx, dy) pixels since the pan started. */
  onPan: (dx: number, dy: number) => void;
  children: ReactNode;
}) {
  const el = useRef<HTMLDivElement>(null);
  const cb = useRef({ onSize, onWheel, onTouchFirst, onPinchStart, onPinch, touchPans, canHold, onHold, onTap, onPanStart, onPan });
  cb.current = { onSize, onWheel, onTouchFirst, onPinchStart, onPinch, touchPans, canHold, onHold, onTap, onPanStart, onPan };
  /** The ring that fills while a finger holds still, in pane pixels. */
  const [ring, setRing] = useState<{ x: number; y: number; n: number } | null>(null);
  useEffect(() => {
    const d = el.current;
    if (!d) return;
    const ro = new ResizeObserver(() => cb.current.onSize(d.clientWidth, d.clientHeight));
    ro.observe(d);
    const wheel = (e: WheelEvent) => {
      e.preventDefault();
      cb.current.onWheel(e, d.getBoundingClientRect());
    };

    // Touch. These listen in the capture phase, so they see every finger before the drawing does.
    const fingers = new Map<number, { x: number; y: number }>();
    let pair: { ids: [number, number]; from: Pair } | null = null;
    /** After a pinch, a hold or a long press, the fingers left down do nothing until all of them lift. */
    let locked = false;
    let press: { id: number; x: number; y: number; timer: ReturnType<typeof setTimeout> } | null = null;
    /** One finger that pans, taps or holds (it never reaches the drawing). */
    let grab: { id: number; x: number; y: number; panning: boolean; timer: ReturnType<typeof setTimeout> } | null = null;
    /** Until when the browser's own menu (a long press on Android) is kept away. */
    let touchUntil = 0;
    /** Until when the click a browser sends after a finger lifts is dropped (after a hold, it would close the menu it opened). */
    let clickUntil = 0;
    let rings = 0;
    const at = (e: PointerEvent) => {
      const r = d.getBoundingClientRect();
      return { x: e.clientX - r.left, y: e.clientY - r.top };
    };
    const pairOf = (ids: [number, number]): Pair | null => {
      const a = fingers.get(ids[0]);
      const b = fingers.get(ids[1]);
      return a && b ? [{ ...a }, { ...b }] : null;
    };
    const endPress = () => {
      if (press) clearTimeout(press.timer);
      press = null;
    };
    const endGrab = () => {
      if (grab) clearTimeout(grab.timer);
      grab = null;
      setRing(null);
    };
    /** Opens the right-click menu of what is at (x, y); true when something opened one. */
    const menuAt = (x: number, y: number) => {
      const target = document.elementFromPoint(x, y);
      if (!target || !d.contains(target)) return false;
      const menu = new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: x, clientY: y, button: 2 });
      target.dispatchEvent(menu);
      return menu.defaultPrevented;
    };
    const down = (e: PointerEvent) => {
      if (e.pointerType !== 'touch') return;
      fingers.set(e.pointerId, at(e));
      touchUntil = Infinity;
      if (fingers.size === 1) {
        locked = false;
        cb.current.onTouchFirst();
        const { clientX: x, clientY: y } = e;
        endPress();
        endGrab();
        const target = e.target instanceof Element ? e.target : null;
        if (target && cb.current.touchPans(target)) {
          // The drawing never sees this finger: it pans the view, taps, or holds to select.
          e.stopPropagation();
          grab = {
            id: e.pointerId,
            x,
            y,
            panning: false,
            timer: setTimeout(() => {
              const g = grab;
              grab = null;
              setRing(null);
              if (!g) return;
              const did = cb.current.onHold(x, y);
              if (did === 'menu' ? menuAt(x, y) : did === 'selected') {
                locked = true;
                navigator.vibrate?.(15);
              }
            }, HOLD_SELECT_MS)
          };
          if (cb.current.canHold(x, y)) {
            const p = at(e);
            setRing({ ...p, n: ++rings });
          }
          return;
        }
        // A handle: the drawing takes the finger; holding still on it opens its menu (a point's).
        if (target?.closest('[data-gizmo]')) return;
        press = {
          id: e.pointerId,
          x,
          y,
          timer: setTimeout(() => {
            press = null;
            // Something opened a menu: this finger is done.
            if (menuAt(x, y)) {
              locked = true;
              navigator.vibrate?.(15);
            }
          }, LONG_PRESS_MS)
        };
        return;
      }
      // A second finger neither draws nor selects.
      endPress();
      endGrab();
      e.stopPropagation();
      d.setPointerCapture(e.pointerId);
      if (fingers.size === 2 && !pair) {
        const ids = [...fingers.keys()] as [number, number];
        pair = { ids, from: pairOf(ids)! };
        locked = true;
        cb.current.onPinchStart();
      }
    };
    const move = (e: PointerEvent) => {
      if (e.pointerType !== 'touch' || !fingers.has(e.pointerId)) return;
      fingers.set(e.pointerId, at(e));
      if (press?.id === e.pointerId && Math.hypot(e.clientX - press.x, e.clientY - press.y) > 10) endPress();
      if (grab?.id === e.pointerId) {
        const dx = e.clientX - grab.x;
        const dy = e.clientY - grab.y;
        if (!grab.panning && Math.hypot(dx, dy) > PAN_SLOP) {
          clearTimeout(grab.timer);
          setRing(null);
          grab.panning = true;
          cb.current.onPanStart();
        }
        if (grab.panning) cb.current.onPan(dx, dy);
        e.stopPropagation();
        return;
      }
      if (pair) {
        const to = pairOf(pair.ids);
        if (to) cb.current.onPinch(pair.from, to);
      }
      if (locked) e.stopPropagation();
    };
    const up = (e: PointerEvent) => {
      if (e.pointerType !== 'touch' || !fingers.has(e.pointerId)) return;
      fingers.delete(e.pointerId);
      if (press?.id === e.pointerId) endPress();
      if (grab?.id === e.pointerId) {
        const tap = !grab.panning && e.type === 'pointerup';
        endGrab();
        e.stopPropagation();
        if (tap && !locked) cb.current.onTap(e.clientX, e.clientY);
      }
      if (pair?.ids.includes(e.pointerId)) pair = null;
      if (!fingers.size) {
        if (locked) clickUntil = performance.now() + 500;
        locked = false;
        touchUntil = performance.now() + 800;
      }
    };
    const click = (e: MouseEvent) => {
      if (performance.now() >= clickUntil) return;
      clickUntil = 0;
      e.preventDefault();
      e.stopPropagation();
    };
    const nativeMenu = (e: MouseEvent) => {
      // The browser's own long-press menu: the holds above open ours instead.
      if (e.isTrusted && (fingers.size || performance.now() < touchUntil)) {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    // Safari's own pinch would zoom the whole page.
    const gesture = (e: Event) => e.preventDefault();
    const opts = { capture: true };
    d.addEventListener('wheel', wheel, { passive: false });
    d.addEventListener('pointerdown', down, opts);
    d.addEventListener('pointermove', move, opts);
    d.addEventListener('pointerup', up, opts);
    d.addEventListener('pointercancel', up, opts);
    d.addEventListener('contextmenu', nativeMenu, opts);
    d.addEventListener('gesturestart', gesture);
    d.addEventListener('gesturechange', gesture);
    // On the window: the menu that click would close is on the body.
    window.addEventListener('click', click, opts);
    return () => {
      window.removeEventListener('click', click, opts);
      ro.disconnect();
      endPress();
      endGrab();
      d.removeEventListener('wheel', wheel);
      d.removeEventListener('pointerdown', down, opts);
      d.removeEventListener('pointermove', move, opts);
      d.removeEventListener('pointerup', up, opts);
      d.removeEventListener('pointercancel', up, opts);
      d.removeEventListener('contextmenu', nativeMenu, opts);
      d.removeEventListener('gesturestart', gesture);
      d.removeEventListener('gesturechange', gesture);
    };
  }, []);
  return (
    <div ref={el} className="relative min-h-0 flex-1 overflow-hidden [-webkit-touch-callout:none]">
      {children}
      {ring ? (
        <HoldRing key={ring.n} x={ring.x} y={ring.y} ms={HOLD_SELECT_MS} />
      ) : null}
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
  ['R  L  B  T  U', 'Roofline, line, bush, tree, semicircle'],
  ['M', 'Measure'],
  ['P', 'Play or stop the effects'],
  ['Wheel, pinch', 'Zoom at the pointer'],
  ['Middle-drag, Space-drag', 'Pan'],
  ['F', 'Zoom to the selection'],
  ['Home', 'Zoom to fit'],
  ['+  −', 'Zoom in, zoom out'],
  ['Shift while drawing', '45° steps'],
  ['Shift-drag', 'Move a point or object straight across or straight up'],
  ['Alt (Option)', 'Snapping the other way; no grid snap'],
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
