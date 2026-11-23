// "Shape to the lights": the wizard that places a tree's LEDs where they really are. One LED
// blinks red on the house; you move it along the string and say where you see it on the tree
// (its start, where it passes the front, the right, the back or the left, its end), and how
// high. The tree's pattern, bent to go through those marks, places the rest (see
// Fixture.marks, shared/layout.ts).

import { useState } from 'react';
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, ChevronLeft, ChevronRight, Minus, Plus, RotateCcw, Trash2, X } from 'lucide-react';
import { deviceLed, litFloor, shapePlaces, treeSize, validMarks, type Fixture, type Offset3, type ShapeMark } from '../../../../shared/layout.ts';
import { Button } from '../../components/ui.tsx';
import { cn } from '../../lib/utils.ts';
import { PropAdvanced, PropButton, PropNote, PropNumber, PropRow } from './props.tsx';

/** Degrees in (-180, 180]. */
export const wrapDeg = (d: number) => {
  const w = ((((d + 180) % 360) + 360) % 360) - 180;
  return Math.round((w === -180 ? 180 : w) * 10) / 10;
};

/** Where on the tree, as seen from the street: the eight ways round, by their angle from the front. */
const WAYS: [number, string][] = [
  [0, 'Front'],
  [45, 'Front right'],
  [90, 'Right'],
  [135, 'Back right'],
  [180, 'Back'],
  [-135, 'Back left'],
  [-90, 'Left'],
  [-45, 'Front left']
];

/** "Right", or "Right 80°" when it is off the way by more than a little. */
export function wayText(angle: number): string {
  const a = wrapDeg(angle);
  const [deg, name] = WAYS.reduce((best, w) => (Math.abs(wrapDeg(a - w[0])) < Math.abs(wrapDeg(a - best[0])) ? w : best));
  return Math.abs(wrapDeg(a - deg)) < 3 ? name : `${name} (${Math.round(a)}°)`;
}

/** The marks with this one put in (in place of one on the same LED). A move of nothing is not kept. */
export function setMark(f: Fixture, mark: ShapeMark): ShapeMark[] {
  const { offset, ...rest } = mark;
  const moved = offset && (offset.x || offset.y || offset.z) ? { ...rest, offset } : rest;
  return [...validMarks(f).filter((m) => m.led !== mark.led), moved].sort((a, b) => a.led - b.led);
}

const r2 = (x: number) => Math.round(x * 100) / 100 || 0;

/** A move as seen from the street (x right, y up, z toward the street) as the tree has it (turned the way it faces), and back. */
function turned(d: Offset3, facing: number, back = false): Offset3 {
  const t = ((back ? -facing : facing) * Math.PI) / 180;
  const c = Math.cos(t);
  const s = Math.sin(t);
  return { x: r2(d.x * c - d.z * s), y: r2(d.y), z: r2(d.x * s + d.z * c) };
}
const toTree = (d: Offset3, facing: number) => turned(d, facing);
const toStreet = (d: Offset3, facing: number) => turned(d, facing, true);

/** The LED's mark, or a new one where the LED is drawn now (on the shape, and moved as its neighbours are). */
function markOf(f: Fixture, led: number): ShapeMark {
  const here = validMarks(f).find((m) => m.led === led);
  if (here) return here;
  const p = shapePlaces(f)[led] ?? { height: 0, angle: 0, offset: { x: 0, y: 0, z: 0 } };
  // A wave's turns sit evenly up the tree until a height is set.
  return { led, angle: p.angle, height: f.pattern === 'wave' ? undefined : p.height, offset: p.offset };
}

/** Moves the LED's mark (made where the LED is now, if it has none) up or down its shape by `du` (a share of its lit height). */
export function raiseMark(f: Fixture, led: number, du: number): ShapeMark[] {
  const m = markOf(f, led);
  const now = m.height ?? shapePlaces(f)[led]?.height ?? 0;
  return setMark(f, { ...m, height: Math.max(0, Math.min(1, Math.round((now + du) * 1000) / 1000)) });
}

/**
 * Marks the LED at this angle round the tree, as seen from the street. A new mark sits on the
 * shape at the height the LED is drawn at; a mark it had keeps its height and its move.
 */
export function markAt(f: Fixture, led: number, streetAngle: number): ShapeMark[] {
  const had = validMarks(f).some((m) => m.led === led);
  const m = markOf(f, led);
  return setMark(f, { ...m, angle: wrapDeg(streetAngle - (f.facing ?? 0)), offset: had ? m.offset : undefined });
}

/** Moves the LED's mark (made where the LED is now, if it has none) by `d`, as seen from the street, in layout units. */
export function moveMark(f: Fixture, led: number, d: Offset3): ShapeMark[] {
  const m = markOf(f, led);
  const by = toTree(d, f.facing ?? 0);
  const o = m.offset ?? { x: 0, y: 0, z: 0 };
  return setMark(f, { ...m, offset: { x: r2(o.x + by.x), y: r2(o.y + by.y), z: r2(o.z + by.z) } });
}

export function ShapeWizard({
  f,
  led,
  perStrand,
  ledCount,
  device,
  lights,
  lenText,
  stepLu,
  onSet,
  onStrand,
  onMarks,
  onStop,
  phone = false
}: {
  f: Fixture;
  /** The blinking LED, counted from the object's LED 0. */
  led: number;
  perStrand: number | null;
  ledCount: number | null;
  device: string | null;
  /** Why the lights do not show the blinking LED, if they do not. */
  lights: string | null;
  /** Layout units as text in the editor's units. */
  lenText: (lu: number) => string;
  /** How far one press of − or + moves a mark up or down, in layout units. */
  stepLu: number;
  onSet: (led: number) => void;
  onStrand: (dir: 1 | -1) => void;
  onMarks: (marks: ShapeMark[] | undefined) => void;
  onStop: () => void;
  /**
   * A phone: the blinking LED stays on top and the rest is in tabs (mark it, move it, the marks),
   * so the panel stays short and the tree shows above it. The help is folded away and the keys are left out.
   */
  phone?: boolean;
}) {
  const [tab, setTab] = useState<'mark' | 'move' | 'marks'>('mark');
  const n = Math.max(1, Math.floor(f.pixels));
  const wave = f.pattern === 'wave';
  const facing = f.facing ?? 0;
  const marks = validMarks(f);
  const here = marks.find((m) => m.led === led) ?? null;
  const places = shapePlaces(f);
  const place = places[led] ?? { height: 0, angle: 0 };
  /** A mark's height as drawn (a wave's, worked out, when not set). */
  const heightOf = (m: ShapeMark) => m.height ?? places[m.led]?.height ?? 0;
  // Heights in real units, above the base (a ball's cap starts part way up).
  const { h } = treeSize(f);
  const u0 = litFloor(f);
  const lit = Math.max(1e-6, h * (1 - u0));
  const heightText = (u: number) => lenText((u0 + (1 - u0) * u) * h);
  const du = stepLu / lit;
  const street = (m: Pick<ShapeMark, 'angle'>) => wrapDeg(m.angle + facing);
  const mark = (streetAngle: number) => onMarks(markAt(f, led, streetAngle));
  const move = (x: number, y: number, z: number) => onMarks(moveMark(f, led, { x: x * stepLu, y: y * stepLu, z: z * stepLu }));
  // The move by hand, as seen from the street.
  const moved = here?.offset ? toStreet(here.offset, facing) : null;
  const movedText = (o: Offset3) =>
    [
      o.x ? `${lenText(Math.abs(o.x))} ${o.x > 0 ? 'right' : 'left'}` : '',
      o.y ? `${lenText(Math.abs(o.y))} ${o.y > 0 ? 'up' : 'down'}` : '',
      o.z ? `${lenText(Math.abs(o.z))} toward the ${o.z > 0 ? 'street' : 'house'}` : ''
    ]
      .filter(Boolean)
      .join(', ');
  const pad = 'grid h-8 pointer-coarse:h-12 place-items-center rounded-md bg-stone-100 text-stone-700 transition hover:bg-stone-200 active:scale-95 disabled:opacity-40 dark:bg-stone-800 dark:text-stone-200 dark:hover:bg-stone-700 [&_svg]:size-4';
  const nudge = (m: ShapeMark, dir: 1 | -1) => onMarks(raiseMark(f, m.led, dir * du));
  const remove = (m: ShapeMark) => {
    const rest = marks.filter((x) => x.led !== m.led);
    onMarks(rest.length ? rest : undefined);
  };
  // The start and the end take any angle; the LEDs between, a quarter (a wave: a side and how far).
  const end = led === 0 || led === n - 1;
  const before = marks.filter((m) => m.led < led).at(-1);
  const dev = deviceLed(f, led);
  const strand = perStrand ? { at: Math.floor(dev / perStrand) + 1, bulb: (dev % perStrand) + 1, of: ledCount ? Math.ceil(ledCount / perStrand) : null } : null;
  const steps: [number, string][] = [
    [-10, '−10'],
    [-1, '−1'],
    [1, '+1'],
    [10, '+10']
  ];
  const on = (a: number) => here != null && Math.abs(wrapDeg(street(here) - a)) < 0.5;
  const wayButton = (a: number, label: string, key?: string) => (
    <PropButton key={a} onClick={() => mark(a)} title={`LED ${dev} is at the ${label.toLowerCase()} of the tree, as seen from the street${key ? ` (${key})` : ''}`}>
      <span className={cn('w-full text-center', on(a) && 'font-semibold text-amber-600 dark:text-amber-400')}>{label}</span>
    </PropButton>
  );
  const intro = (
      <p className="text-xs text-stone-600 dark:text-stone-400">
        {wave
          ? 'Move the blinking red LED along the string. Mark its first LED, each LED where the string turns at the left or the right side of the tree, and its last LED. Each row is as wide as its LEDs go (fewer LEDs: a narrower row), and the rows sit evenly apart up the tree: set the tree’s width and height after, or a turn’s height here.'
          : 'Move the blinking red LED along the string. Mark where it starts and ends, and each LED where it passes the front, the right, the back or the left of the tree (as seen from the street). Then set how high each mark is. The pattern, bent to go through the marks, places the LEDs in between.'}
      </p>
  );
  const ledCountNote = ledCount ? (
    <p className="text-[11px] text-stone-500 tabular-nums">
      {device ?? 'The device'} has {ledCount} LEDs in WLED (0–{ledCount - 1}).
    </p>
  ) : null;
  const stepButtons = steps.map(([d, label]) => (
    <PropButton key={d} tight={phone} onClick={() => onSet(led + d)} disabled={d < 0 ? led <= 0 : led >= n - 1} title={`${d < 0 ? 'Back toward the start' : 'On toward the end'} by ${Math.abs(d)}`}>
      <span className="w-full text-center tabular-nums">{label}</span>
    </PropButton>
  ));
  const startButton = (
    <PropButton tight={phone} onClick={() => onSet(0)} disabled={led === 0} title="The first LED of the tree (Home)">
      <span className="w-full text-center">Start</span>
    </PropButton>
  );
  const endButton = (
    <PropButton tight={phone} onClick={() => onSet(n - 1)} disabled={led === n - 1} title="The last LED of the tree (End)">
      <span className="w-full text-center">End</span>
    </PropButton>
  );
  const ledBlock = (
    <>
      <div className="flex items-center justify-between gap-2 rounded-md bg-stone-100 px-2.5 py-2 dark:bg-stone-800">
        <span className="text-lg font-semibold text-red-600 tabular-nums dark:text-red-400">LED {dev}</span>
        <span className="text-right text-[11px] text-stone-500 tabular-nums">
          {strand ? (
            <>
              strand {strand.at}
              {strand.of ? ` of ${strand.of}` : ''}, bulb {strand.bulb} of {perStrand}
              <br />
            </>
          ) : null}
          {led === 0 ? 'the start' : led === n - 1 ? 'the end' : before ? `${led - before.led} LEDs after the last mark` : `${led} LEDs after the start`}
        </span>
      </div>
      {phone ? null : ledCountNote}
      {phone ? (
        // One row on a phone: the first LED, the steps back and on, the last LED.
        <div className="grid grid-cols-6 gap-1">
          {startButton}
          {stepButtons}
          {endButton}
        </div>
      ) : (
        <div className="grid grid-cols-4 gap-1">{stepButtons}</div>
      )}
      <div className={cn('flex flex-wrap gap-1', phone && !perStrand && 'hidden')}>
        {phone ? null : startButton}
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
        {phone ? null : endButton}
      </div>
      <input
        type="range"
        aria-label="Blinking LED"
        min={0}
        max={n - 1}
        step={1}
        value={led}
        onChange={(e) => onSet(Number(e.target.value))}
        className="h-7 w-full cursor-pointer accent-red-600 pointer-coarse:h-11 dark:accent-red-400"
      />
    </>
  );
  const markBlock = (
    <>
      <div className="text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Where is it on the tree?</div>
      {wave ? (
        <div className="grid grid-cols-3 gap-1">
          {wayButton(-90, 'Left', 'L')}
          {wayButton(0, 'Front', 'F')}
          {wayButton(90, 'Right', 'R')}
        </div>
      ) : (
        // As seen from above, the street at the bottom.
        <div className="grid grid-cols-3 gap-1">
          {end ? wayButton(-135, 'Back left') : <span />}
          {wayButton(180, 'Back', 'B')}
          {end ? wayButton(135, 'Back right') : <span />}
          {wayButton(-90, 'Left', 'L')}
          <span className="grid place-items-center text-[10px] text-stone-400">from above</span>
          {wayButton(90, 'Right', 'R')}
          {end ? wayButton(-45, 'Front left') : <span />}
          {wayButton(0, 'Front', 'F')}
          {end ? wayButton(45, 'Front right') : <span />}
        </div>
      )}
      {here ? (
        <div className="space-y-1 rounded-md bg-amber-50 px-2 py-1.5 dark:bg-amber-950/40">
          <div className="text-xs font-semibold text-amber-700 dark:text-amber-300">Marked: {wayText(street(here))}</div>
          {end || wave ? (
            <PropNumber
              label="Round"
              hint="Degrees from the front as seen from the street: right is more, left is less (90 the right side, -90 the left, 180 the back)"
              value={street(here)}
              min={-180}
              max={180}
              step={wave ? 5 : 15}
              decimal
              unit="°"
              onChange={(a) => mark(a)}
            />
          ) : null}
          <PropRow
            label="Height"
            hint={
              wave
                ? 'How high this turn is, above the base of the tree. Not set: the rows sit evenly apart up the tree (change the tree’s height to stretch them). − and + (or [ and ]) set it.'
                : 'How high this LED is, above the base of the tree. − and + (or [ and ]) pull the string down or up.'
            }
          >
            <div className="flex items-center gap-1">
              <PropButton onClick={() => nudge(here, -1)} disabled={heightOf(here) <= 0} title="Lower ([)">
                <Minus />
              </PropButton>
              <span className="min-w-16 text-center text-xs tabular-nums">
                {heightText(heightOf(here))}
                {here.height == null ? ' (auto)' : ''}
              </span>
              <PropButton onClick={() => nudge(here, 1)} disabled={heightOf(here) >= 1} title="Higher (])">
                <Plus />
              </PropButton>
              {wave && here.height != null ? (
                <PropButton onClick={() => onMarks(setMark(f, { ...here, height: undefined }))} title="The rows evenly apart up the tree again">
                  Auto
                </PropButton>
              ) : null}
            </div>
          </PropRow>
          <PropRow label="">
            <PropButton onClick={() => remove(here)} title="This LED goes back to where the pattern puts it (Delete)">
              <Trash2 /> Remove mark
            </PropButton>
          </PropRow>
        </div>
      ) : (
        <PropNote>
          The drawing has it {wayText(wrapDeg(place.angle + facing)).toLowerCase()}, {heightText(place.height)} up. Mark it where you really see it.
        </PropNote>
      )}
    </>
  );
  const moveBlock = (
    <>
      <div className="text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Move it</div>
      <div className="flex items-start gap-2">
        {/* As seen from the street: left, right, up, down; then nearer or farther. */}
        <div className="grid w-32 shrink-0 grid-cols-3 gap-1">
          <span />
          <button type="button" className={pad} onClick={() => move(0, 1, 0)} title="Up (Alt+↑)" aria-label="Up">
            <ArrowUp />
          </button>
          <span />
          <button type="button" className={pad} onClick={() => move(-1, 0, 0)} title="Left, as seen from the street (Alt+←)" aria-label="Left">
            <ArrowLeft />
          </button>
          <button type="button" className={pad} onClick={() => here && onMarks(setMark(f, { ...here, offset: undefined }))} disabled={!moved} title="Back onto the shape" aria-label="Undo the move">
            <RotateCcw />
          </button>
          <button type="button" className={pad} onClick={() => move(1, 0, 0)} title="Right, as seen from the street (Alt+→)" aria-label="Right">
            <ArrowRight />
          </button>
          <span />
          <button type="button" className={pad} onClick={() => move(0, -1, 0)} title="Down (Alt+↓)" aria-label="Down">
            <ArrowDown />
          </button>
          <span />
        </div>
        <div className="grid flex-1 gap-1">
          <button type="button" className={cn(pad, 'px-2 text-xs')} onClick={() => move(0, 0, 1)} title="Toward the street (Alt+Page Down)">
            Toward the street
          </button>
          <button type="button" className={cn(pad, 'px-2 text-xs')} onClick={() => move(0, 0, -1)} title="Toward the house (Alt+Page Up)">
            Toward the house
          </button>
        </div>
      </div>
      <p className="text-[11px] text-stone-500">
        {moved ? `Moved ${movedText(moved)} from the shape. ` : ''}Each press moves it {lenText(stepLu)}; the LEDs between it and the marks on either side move along. A move marks the LED where it is,
        if it has no mark yet.
      </p>
    </>
  );
  const marksBlock = marks.length ? (
        <div className="space-y-0.5">
          <div className="text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Marks ({marks.length})</div>
          <div className={cn('overflow-y-auto', !phone && 'max-h-48')}>
            {marks.map((m) => (
              <div key={m.led} className={cn('flex items-center gap-1 rounded px-1 text-xs tabular-nums pointer-coarse:text-sm', m.led === led && 'bg-red-50 dark:bg-red-950/40')}>
                <button type="button" className="min-w-0 flex-1 truncate py-0.5 text-left hover:underline pointer-coarse:py-3" onClick={() => onSet(m.led)} title="Blink this LED">
                  LED {deviceLed(f, m.led)} · {wayText(street(m))} · {heightText(heightOf(m))}
                  {m.offset ? ' · moved' : ''}
                </button>
                <button type="button" className="grid size-6 place-items-center rounded pointer-coarse:size-11 hover:bg-stone-200 dark:hover:bg-stone-700 [&_svg]:size-3.5" onClick={() => nudge(m, -1)} aria-label="Lower" title="Lower">
                  <Minus />
                </button>
                <button type="button" className="grid size-6 place-items-center rounded pointer-coarse:size-11 hover:bg-stone-200 dark:hover:bg-stone-700 [&_svg]:size-3.5" onClick={() => nudge(m, 1)} aria-label="Higher" title="Higher">
                  <Plus />
                </button>
                <button type="button" className="grid size-6 place-items-center rounded pointer-coarse:size-11 hover:bg-stone-200 dark:hover:bg-stone-700 [&_svg]:size-3.5" onClick={() => remove(m)} aria-label="Remove" title="Remove this mark">
                  <X />
                </button>
              </div>
            ))}
          </div>
        </div>
  ) : null;
  const keys = (
      <PropNote>
        Arrow keys move the LED (Shift: 10 at a time{perStrand ? '; Page Up and Page Down: a strand' : ''}; Home, End). {wave ? 'L, F, R' : 'F, R, B, L'} mark it; [ and ] lower or raise its
        mark on the shape; Alt and the arrows (Page Up, Page Down: nearer the house or the street) move it; Delete removes it; Esc stops.
      </PropNote>
  );
  const footer = (
      <div className="flex items-center gap-1">
        <PropButton onClick={() => onMarks(undefined)} disabled={!marks.length} danger title="Every LED goes back to where the pattern puts it">
          <Trash2 /> Clear marks
        </PropButton>
        <span className="flex-1" />
        <Button size="sm" variant="primary" onClick={onStop} className="pointer-coarse:h-11 pointer-coarse:px-5">
          Done
        </Button>
      </div>
  );
  const lightsNote = lights ? <PropNote tone="red">{lights}</PropNote> : null;
  if (phone) {
    const tabs: ['mark' | 'move' | 'marks', string][] = [
      ['mark', 'Mark it'],
      ['move', 'Move it'],
      ['marks', `Marks${marks.length ? ` (${marks.length})` : ''}`]
    ];
    return (
      <>
        {lightsNote}
        {ledBlock}
        <div role="tablist" aria-label="Shape to the lights" className="grid grid-cols-3 gap-0.5 rounded-md bg-stone-100 p-0.5 dark:bg-stone-800">
          {tabs.map(([k, label]) => (
            <button
              key={k}
              type="button"
              role="tab"
              aria-selected={tab === k}
              onClick={() => setTab(k)}
              className={cn(
                'h-11 truncate rounded px-1.5 text-sm font-medium transition',
                tab === k ? 'bg-white text-stone-950 shadow-sm dark:bg-stone-600 dark:text-white' : 'text-stone-600 dark:text-stone-300'
              )}
            >
              {label}
            </button>
          ))}
        </div>
        {tab === 'mark' ? markBlock : tab === 'move' ? moveBlock : (marksBlock ?? <PropNote>No marks yet. Mark the blinking LED where you see it on the tree (Mark it).</PropNote>)}
        {footer}
        <PropAdvanced id="shape-help" label="How it works">
          {intro}
          {ledCountNote}
        </PropAdvanced>
      </>
    );
  }
  return (
    <>
      {intro}
      {ledBlock}
      {markBlock}
      {moveBlock}
      {marksBlock}
      {lightsNote}
      {keys}
      {footer}
    </>
  );
}
