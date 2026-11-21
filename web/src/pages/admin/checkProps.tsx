// The layout editor's checks (see shared/check.ts): the inspector sections that start them, the
// slice or ruler drawn over the views, and the bar that shows while a check runs.
import { useEffect, useMemo, useRef, type PointerEvent as RPointerEvent } from 'react';
import { ChevronLeft, ChevronRight, Pause, Play, X } from 'lucide-react';
import {
  axisRange,
  bandOf,
  bandOrigin,
  BAND_RGB,
  currentGuess,
  PICTURE_RGB,
  slicePosition,
  SLICE_HALF_M,
  SLICE_HIGH_RGB,
  SLICE_LOW_RGB,
  wiringGuesses,
  type CheckAxis,
  type LayoutCheck
} from '../../../../shared/check.ts';
import { layoutGround, type Fixture, type Layout, type Stage, type Units } from '../../../../shared/layout.ts';
import { cn } from '../../lib/utils.ts';
import type { ViewSide } from '../../yard/YardView.tsx';
import { PropButton, PropNote, PropNumber, PropRow, PropSection, PropSelect } from './props.tsx';

/** The check the editor runs. An object's check is of the selected object. */
export type EditorCheck = { kind: 'slice'; axis: CheckAxis; at: number | null } | { kind: 'bands'; axis: CheckAxis; step: number } | { kind: 'picture' } | { kind: 'chase' };

/** The check to paint, for the selected object (none: an object's check shows nothing). */
export const toLayoutCheck = (c: EditorCheck | null, selected: string | null): LayoutCheck | null =>
  !c ? null : c.kind === 'slice' || c.kind === 'bands' ? c : selected ? { kind: c.kind, id: selected } : null;

interface Measure {
  units: Units;
  per: number;
  show: (layoutUnits: number) => number;
  text: (layoutUnits: number) => string;
}

const AXIS_LABELS: Record<CheckAxis, string> = { x: 'Across (left to right)', y: 'Height', z: 'Depth (house to street)' };
/** The low and the high side of a slice, in words. */
const SIDES: Record<CheckAxis, [string, string]> = { x: ['left of it', 'right of it'], y: ['above it', 'below it'], z: ['behind it (toward the house)', 'in front of it (toward the street)'] };
const LINE_UP: Record<CheckAxis, string> = { x: 'straight up and down', y: 'level', z: 'at one depth' };
const FROM: Record<CheckAxis, string> = { x: 'the left edge of the front view', y: 'the ground', z: 'the front wall' };
const BAND_NAMES = ['red', 'green', 'blue', 'yellow'];

const css = (c: readonly number[]) => `rgb(${c.join(',')})`;
/** A color as it looks on an LED: dim colors are made brighter for the screen. */
const shown = (c: readonly number[]) => {
  const k = 255 / Math.max(1, ...c);
  return css(c.map((v) => Math.round(v * k)));
};

/** The axis's value as the editor shows it (from the left edge, the height, the depth), in shown units. */
const showAt = (layout: Layout, m: Measure, axis: CheckAxis, at: number) => m.show(axis === 'y' ? layoutGround(layout) - at : at);
const fromShown = (layout: Layout, m: Measure, axis: CheckAxis, n: number) => (axis === 'y' ? layoutGround(layout) - n * m.per : n * m.per);

/** Band widths to pick from, in shown units. */
const BAND_STEPS: Record<Units, number[]> = { ft: [1, 2, 5, 10], m: [0.5, 1, 2, 3] };
export const defaultBandStep = (m: Measure) => (m.units === 'm' ? 1 : 2) * m.per;

function Choice<T extends string>({ value, options, onChange, label }: { value: T; options: [T, string][]; onChange: (v: T) => void; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="grid auto-cols-fr grid-flow-col gap-0.5 rounded-md bg-stone-100 p-0.5 dark:bg-stone-800">
      {options.map(([v, l]) => (
        <button
          key={v}
          type="button"
          role="radio"
          aria-checked={value === v}
          onClick={() => onChange(v)}
          className={cn(
            'h-7 truncate rounded px-1.5 text-xs font-medium transition',
            value === v ? 'bg-white text-stone-950 shadow-sm dark:bg-stone-600 dark:text-white' : 'text-stone-600 hover:text-stone-950 dark:text-stone-300 dark:hover:text-white'
          )}
        >
          {l}
        </button>
      ))}
    </div>
  );
}

const Swatch = ({ c, children }: { c: readonly number[]; children: string }) => (
  <span className="inline-flex items-center gap-1.5 text-[11px] text-stone-600 dark:text-stone-300">
    <span className="size-3 shrink-0 rounded-full ring-1 ring-black/10" style={{ background: shown(c) }} />
    {children}
  </span>
);

/** The whole yard's checks: a slice or a ruler along one axis. */
export function YardCheckProps({ check, onChange, layout, stage, m, lights }: { check: EditorCheck | null; onChange: (c: EditorCheck | null) => void; layout: Layout; stage: Stage | null; m: Measure; lights: string | null }) {
  const yard = check && (check.kind === 'slice' || check.kind === 'bands') ? check : null;
  const axis = yard?.axis ?? 'x';
  const middle = (a: CheckAxis) => {
    if (!stage) return 0;
    const [lo, hi] = axisRange(stage, a);
    return Math.round((lo + hi) / 2);
  };
  return (
    <PropSection key="check" id="check" title="Check alignment">
      <Choice<'off' | 'slice' | 'bands'>
        label="Check"
        value={yard?.kind ?? 'off'}
        options={[
          ['off', 'Off'],
          ['slice', 'Slice'],
          ['bands', 'Ruler']
        ]}
        onChange={(k) => onChange(k === 'off' ? null : k === 'slice' ? { kind: 'slice', axis, at: null } : { kind: 'bands', axis, step: defaultBandStep(m) })}
      />
      {yard ? (
        <>
          <PropSelect<CheckAxis>
            label="Along"
            value={axis}
            options={(['x', 'y', 'z'] as const).map((a) => [a, AXIS_LABELS[a]])}
            onChange={(a) => onChange(yard.kind === 'slice' ? { ...yard, axis: a, at: yard.at == null ? null : middle(a) } : { ...yard, axis: a })}
          />
          {yard.kind === 'slice' ? (
            <>
              <PropRow label="Moves">
                <div className="flex gap-1.5">
                  <PropButton onClick={() => onChange({ ...yard, at: yard.at == null ? Math.round(stage ? slicePosition(stage, yard, Date.now()) : 0) : null })}>
                    {yard.at == null ? <Pause /> : <Play />} {yard.at == null ? 'Hold it here' : 'Sweep'}
                  </PropButton>
                </div>
              </PropRow>
              <PropNumber
                label={axis === 'x' ? 'From the left' : axis === 'y' ? 'Height' : 'Depth'}
                hint={`Where the slice is, from ${FROM[axis]}`}
                decimal
                value={yard.at == null ? null : showAt(layout, m, axis, yard.at)}
                placeholder="sweeping"
                min={-1000}
                max={1000}
                step={m.units === 'm' ? 0.05 : 0.25}
                unit={m.units}
                steppers
                onChange={(n) => onChange({ ...yard, at: Math.round(fromShown(layout, m, axis, n) * 10) / 10 })}
              />
              <div className="flex flex-wrap gap-x-3 gap-y-1 pt-0.5">
                <Swatch c={[255, 255, 255]}>in the slice</Swatch>
                <Swatch c={SLICE_LOW_RGB}>{SIDES[axis][0]}</Swatch>
                <Swatch c={SLICE_HIGH_RGB}>{SIDES[axis][1]}</Swatch>
              </div>
              <PropNote>
                A thin plane of white light crosses the whole yard. Where the drawing puts an LED in it, that LED lights white on the house too, so on every object the white should line up {LINE_UP[axis]}, where it
                does in the drawing. An object that lights white too early or too late is drawn too far {axis === 'x' ? 'left or right' : axis === 'y' ? 'up or down' : 'forward or back'}, or is the wrong size.{' '}
                {axis === 'z' ? 'Drag the line in the top view to move it.' : axis === 'y' ? 'Drag the line in the front view to move it.' : 'Drag the line in the front or top view to move it.'}
              </PropNote>
            </>
          ) : (
            <>
              <PropSelect
                label="Bands every"
                value={String(Math.round((yard.step / m.per) * 100) / 100)}
                options={BAND_STEPS[m.units].map((s): [string, string] => [String(s), `${s} ${m.units}`])}
                onChange={(s) => onChange({ ...yard, step: Number(s) * m.per })}
              />
              <div className="flex flex-wrap gap-x-3 gap-y-1 pt-0.5">
                {BAND_RGB.map((c, i) => (
                  <Swatch key={i} c={c}>
                    {BAND_NAMES[i]}
                  </Swatch>
                ))}
              </div>
              <PropNote>
                The yard in bands of color, {m.text(yard.step)} wide, from {FROM[axis]}: red, green, blue, yellow, then red again. Every object on the house should show the same colors in the same places as in the
                drawing. Measure a real object against a band edge, or find the one whose colors are off by a band.
              </PropNote>
            </>
          )}
          {lights ? <PropNote>{lights}</PropNote> : null}
        </>
      ) : (
        <PropNote>
          Shows, on the real lights, where the drawing puts each LED: a slice of white light you move across the yard, or colored bands like a ruler. Turn on Lights in the toolbar to see it on the house.
        </PropNote>
      )}
    </PropSection>
  );
}

/** One object's checks: the color test and the chase, and the ways its string can run. */
export function ObjectCheckProps({
  f,
  check,
  onChange,
  onPatch,
  blocks,
  lights,
  scale
}: {
  f: Fixture;
  scale: number;
  check: EditorCheck | null;
  onChange: (c: EditorCheck | null) => void;
  onPatch: (patch: Partial<Fixture>) => void;
  blocks: { across: boolean; up: boolean } | null;
  lights: string | null;
}) {
  const mode = check?.kind === 'picture' || check?.kind === 'chase' ? check.kind : 'off';
  const on = mode !== 'off';
  const guesses = useMemo(() => (on ? wiringGuesses(f, scale) : []), [on, f, scale]);
  const cur = useMemo(() => (on ? currentGuess(f, guesses, scale) : -1), [on, f, guesses, scale]);
  /** The next (d = 1) or the one before (d = -1); from none, the first or the last. */
  const go = (d: number) => {
    const from = cur >= 0 ? cur : d > 0 ? -1 : 0;
    onPatch(guesses[(from + d + guesses.length) % guesses.length].patch);
  };
  const tree = f.kind === 'tree';
  return (
    <PropSection key="wiring" id="wiring" title="Check the wiring">
      <Choice<'off' | 'picture' | 'chase'>
        label="Check"
        value={mode}
        options={[
          ['off', 'Off'],
          ['picture', 'Color test'],
          ['chase', 'Chase']
        ]}
        onChange={(k) => onChange(k === 'off' ? null : { kind: k })}
      />
      {mode === 'off' ? (
        <PropNote>Lights this object on the house by where the drawing puts each LED, to see if its shape and the way its string runs are right. Turn on Lights in the toolbar to see it on the house.</PropNote>
      ) : (
        <>
          {mode === 'picture' && blocks ? (
            <div className={cn('grid gap-x-3 gap-y-1 pt-0.5', blocks.across ? 'grid-cols-2' : 'grid-cols-1')}>
              <Swatch c={PICTURE_RGB.topLeft}>{blocks.across ? (blocks.up ? 'top left' : 'left') : blocks.up ? 'top' : 'all of it'}</Swatch>
              {blocks.across ? <Swatch c={PICTURE_RGB.topRight}>{blocks.up ? 'top right' : 'right'}</Swatch> : null}
              {blocks.up ? <Swatch c={PICTURE_RGB.bottomLeft}>{blocks.across ? 'bottom left' : 'bottom'}</Swatch> : null}
              {blocks.up && blocks.across ? <Swatch c={PICTURE_RGB.bottomRight}>bottom right</Swatch> : null}
            </div>
          ) : null}
          <PropNote>
            {mode === 'picture'
              ? 'Each LED is colored by where the drawing puts it, as seen from the street, and LED 0 blinks white. The drawing always shows clean blocks; when it is right, the house shows the same. Swapped or mixed-up colors on the house: the string runs another way. Try the next way below until the house matches.'
              : 'A light runs along the wire from LED 0 to the last LED, in the drawing and on the house at the same time. Where it starts and which way it goes on the house should match the drawing. If not, try the next way below.'}
          </PropNote>
          {guesses.length > 1 ? (
            <div className="flex items-center gap-1 rounded-md bg-stone-100 p-1 dark:bg-stone-800">
              <button type="button" onClick={() => go(-1)} aria-label="The way before" title="The way before" className="grid size-7 shrink-0 place-items-center rounded hover:bg-white dark:hover:bg-stone-700 [&_svg]:size-4">
                <ChevronLeft />
              </button>
              <div className="min-w-0 flex-1 text-center">
                <p className="text-[11px] text-stone-500 tabular-nums">{cur < 0 ? `${guesses.length} ways to try` : `Way ${cur + 1} of ${guesses.length}`}</p>
                <p className="truncate text-xs font-medium" title={cur < 0 ? undefined : guesses[cur].label}>
                  {cur < 0 ? 'Set by hand' : guesses[cur].label}
                </p>
              </div>
              <button type="button" onClick={() => go(1)} aria-label="Try the next way" title="Try the next way" className="grid size-7 shrink-0 place-items-center rounded hover:bg-white dark:hover:bg-stone-700 [&_svg]:size-4">
                <ChevronRight />
              </button>
            </div>
          ) : null}
          {tree ? (
            <PropNote>
              A color wound around the tree instead of on one side: turn it with Faces (in Shape) until the blocks sit side by side. Thin stripes of every color: the number of {f.pattern === 'strands' ? 'strands' : f.pattern === 'wave' ? 'passes' : 'turns'} or of
              LEDs is off.
            </PropNote>
          ) : f.kind === 'roof' || f.kind === 'line' ? (
            <PropNote>The colors change at the middle of the line. If they change somewhere else on the house, a corner sits at the wrong LED: Match to the lights (in LEDs) fixes it.</PropNote>
          ) : null}
          {lights ? <PropNote>{lights}</PropNote> : null}
        </>
      )}
    </PropSection>
  );
}

/**
 * The slice (a line across the view, that can be dragged) or the ruler's band edges, over a
 * view. The sweeping slice moves on every animation frame, by itself: the page does not draw again.
 */
export function CheckOverlay({
  check,
  stage,
  layout,
  side,
  zMin,
  vb,
  k,
  m,
  toWorld,
  onMove
}: {
  check: LayoutCheck;
  stage: Stage;
  layout: Layout;
  side: ViewSide;
  zMin: number;
  vb: { x: number; y: number; w: number; h: number };
  k: number;
  m: Measure;
  /** The pointer's place along the axis, in layout units. */
  toWorld: (e: RPointerEvent, axis: CheckAxis) => number;
  onMove: (at: number) => void;
}) {
  if (check.kind !== 'slice' && check.kind !== 'bands') return null;
  const axis = check.axis;
  // The front view shows across and height; the top view across and depth.
  if ((side === 'front' && axis === 'z') || (side === 'top' && axis === 'y')) return null;
  const across = axis === 'x';
  /** From the axis's layout units to the view's u (across) or v (up and down). */
  const toView = (w: number) => (across ? w : side === 'top' ? w - zMin : w);
  if (check.kind === 'bands') {
    const origin = bandOrigin(layout, axis);
    const lo = across ? vb.x : side === 'top' ? vb.y + zMin : vb.y;
    const hi = across ? vb.x + vb.w : side === 'top' ? vb.y + vb.h + zMin : vb.y + vb.h;
    const sign = axis === 'y' ? -1 : 1;
    // Band edges from the origin: up for heights (y counts down), right and toward the street otherwise.
    const b0 = Math.min(bandOf(layout, axis, check.step, lo), bandOf(layout, axis, check.step, hi));
    const b1 = Math.max(bandOf(layout, axis, check.step, lo), bandOf(layout, axis, check.step, hi)) + 1;
    if (b1 - b0 > 400) return null;
    const edges = Array.from({ length: b1 - b0 + 1 }, (_, i) => b0 + i);
    return (
      <g pointerEvents="none">
        {edges.map((b) => {
          const w = toView(origin + sign * b * check.step);
          const c = BAND_RGB[((b % BAND_RGB.length) + BAND_RGB.length) % BAND_RGB.length];
          const label = m.text(b * check.step);
          return (
            <g key={b}>
              {across ? (
                <line x1={w} y1={vb.y} x2={w} y2={vb.y + vb.h} stroke={shown(c)} strokeOpacity={0.55} strokeWidth={1.5 * k} strokeDasharray={`${6 * k} ${5 * k}`} />
              ) : (
                <line x1={vb.x} y1={w} x2={vb.x + vb.w} y2={w} stroke={shown(c)} strokeOpacity={0.55} strokeWidth={1.5 * k} strokeDasharray={`${6 * k} ${5 * k}`} />
              )}
              <text
                x={across ? w + 4 * k : vb.x + 6 * k}
                y={across ? vb.y + 16 * k : w - 4 * k}
                fontSize={11 * k}
                fontWeight={600}
                fill={shown(c)}
                stroke="#0c0a09"
                strokeWidth={3 * k}
                paintOrder="stroke"
                className="tabular-nums"
              >
                {label}
              </text>
            </g>
          );
        })}
      </g>
    );
  }
  return <SliceLine check={check} stage={stage} layout={layout} across={across} toView={toView} vb={vb} k={k} m={m} toWorld={(e) => toWorld(e, axis)} onMove={onMove} />;
}

function SliceLine({
  check,
  stage,
  layout,
  across,
  toView,
  vb,
  k,
  m,
  toWorld,
  onMove
}: {
  check: { kind: 'slice'; axis: CheckAxis; at: number | null };
  stage: Stage;
  layout: Layout;
  across: boolean;
  toView: (w: number) => number;
  vb: { x: number; y: number; w: number; h: number };
  k: number;
  m: Measure;
  toWorld: (e: RPointerEvent) => number;
  onMove: (at: number) => void;
}) {
  const g = useRef<SVGGElement>(null);
  const label = useRef<SVGTextElement>(null);
  const dragging = useRef(false);
  const half = SLICE_HALF_M * stage.scale;
  const place = (at: number) => {
    const w = toView(at);
    g.current?.setAttribute('transform', across ? `translate(${w} 0)` : `translate(0 ${w})`);
    if (label.current) label.current.textContent = `${m.text(check.axis === 'y' ? layoutGround(layout) - at : at)}`;
  };
  const placeRef = useRef(place);
  placeRef.current = place;
  useEffect(() => {
    if (check.at != null) return placeRef.current(check.at);
    let raf = 0;
    const loop = () => {
      placeRef.current(slicePosition(stage, check, Date.now()));
      raf = requestAnimationFrame(loop);
    };
    loop();
    return () => cancelAnimationFrame(raf);
  }, [check, stage]);
  useEffect(() => {
    if (check.at != null) place(check.at);
  });
  const line = (w: number, props: Record<string, unknown>) =>
    across ? <line x1={w} y1={vb.y} x2={w} y2={vb.y + vb.h} {...props} /> : <line x1={vb.x} y1={w} x2={vb.x + vb.w} y2={w} {...props} />;
  return (
    <g ref={g}>
      {/* The slice's thickness, then its middle, and a wide grip to drag it by. */}
      {line(0, { stroke: '#fff', strokeOpacity: 0.12, strokeWidth: half * 2, pointerEvents: 'none' })}
      {line(0, { stroke: '#fff', strokeOpacity: 0.9, strokeWidth: 1.5 * k, pointerEvents: 'none' })}
      {line(0, {
        stroke: 'transparent',
        strokeWidth: 16 * k,
        className: across ? 'cursor-ew-resize' : 'cursor-ns-resize',
        onPointerDown: (e: RPointerEvent<SVGLineElement>) => {
          if (e.button !== 0) return;
          e.stopPropagation();
          e.currentTarget.setPointerCapture(e.pointerId);
          dragging.current = true;
          onMove(Math.round(toWorld(e)));
        },
        onPointerMove: (e: RPointerEvent<SVGLineElement>) => {
          if (!dragging.current) return;
          e.stopPropagation();
          onMove(Math.round(toWorld(e)));
        },
        onPointerUp: () => (dragging.current = false),
        onPointerCancel: () => (dragging.current = false)
      })}
      <text
        ref={label}
        x={across ? 6 * k : vb.x + 8 * k}
        y={across ? vb.y + 18 * k : -8 * k}
        fontSize={13 * k}
        fontWeight={700}
        fill="#fff"
        stroke="#0c0a09"
        strokeWidth={4 * k}
        paintOrder="stroke"
        pointerEvents="none"
        className="tabular-nums"
      />
    </g>
  );
}

/** The bar over the views while a check runs: what it is, and a button to stop it. */
export function CheckBar({ check, objectName, layout, m, onChange }: { check: EditorCheck; objectName: string | null; layout: Layout; m: Measure; onChange: (c: EditorCheck | null) => void }) {
  const text =
    check.kind === 'slice'
      ? `Slice · ${AXIS_LABELS[check.axis].split(' (')[0]}${check.at == null ? ' · sweeping' : ` · ${showAt(layout, m, check.axis, check.at)} ${m.units}`}`
      : check.kind === 'bands'
        ? `Ruler · ${AXIS_LABELS[check.axis].split(' (')[0]} · every ${m.text(check.step)}`
        : `${check.kind === 'picture' ? 'Color test' : 'Chase'} · ${objectName ?? 'select an object'}`;
  return (
    <div className="pointer-events-none absolute inset-x-0 bottom-3 z-20 flex justify-center px-3">
      <div className="pointer-events-auto flex max-w-full items-center gap-1 rounded-full bg-stone-900/90 py-1 pr-1 pl-3 text-xs font-medium text-white shadow-lg ring-1 ring-white/10 backdrop-blur">
        <span className="truncate">{text}</span>
        {check.kind === 'slice' ? (
          <button
            type="button"
            onClick={() => onChange({ ...check, at: null })}
            disabled={check.at == null}
            title="Sweep across the yard"
            aria-label="Sweep across the yard"
            className="grid size-7 shrink-0 place-items-center rounded-full hover:bg-white/15 disabled:hidden [&_svg]:size-3.5"
          >
            <Play />
          </button>
        ) : null}
        <button type="button" onClick={() => onChange(null)} title="Stop the check" aria-label="Stop the check" className="grid size-7 shrink-0 place-items-center rounded-full hover:bg-white/15 [&_svg]:size-3.5">
          <X />
        </button>
      </div>
    </div>
  );
}
