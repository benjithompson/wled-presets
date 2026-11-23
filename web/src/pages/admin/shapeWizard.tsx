// "Shape to the lights": the wizard that places a tree's LEDs where they really are. One LED
// blinks red on the house; you move it along the string and say where you see it on the tree
// (its start, where it passes the front, the right, the back or the left, its end), and how
// high. The tree's pattern, bent to go through those marks, places the rest (see
// Fixture.marks, shared/layout.ts).

import { ChevronLeft, ChevronRight, Minus, Plus, Trash2, X } from 'lucide-react';
import { capFloor, deviceLed, shapePlaces, treeSize, validMarks, type Fixture, type ShapeMark } from '../../../../shared/layout.ts';
import { Button } from '../../components/ui.tsx';
import { cn } from '../../lib/utils.ts';
import { PropButton, PropNote, PropNumber, PropRow } from './props.tsx';

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

/** The marks as the page changes them: the tree's angle is the street's less its facing. */
export function setMark(f: Fixture, mark: ShapeMark): ShapeMark[] {
  return [...validMarks(f).filter((m) => m.led !== mark.led), mark].sort((a, b) => a.led - b.led);
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
  onStop
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
}) {
  const n = Math.max(1, Math.floor(f.pixels));
  const wave = f.pattern === 'wave';
  const facing = f.facing ?? 0;
  const marks = validMarks(f);
  const here = marks.find((m) => m.led === led) ?? null;
  const place = shapePlaces(f)[led] ?? { height: 0, angle: 0 };
  // Heights in real units, above the base (a ball's cap starts part way up).
  const { h } = treeSize(f);
  const u0 = capFloor(f);
  const lit = Math.max(1e-6, h * (1 - u0));
  const heightText = (u: number) => lenText((u0 + (1 - u0) * u) * h);
  const du = stepLu / lit;
  const street = (m: Pick<ShapeMark, 'angle'>) => wrapDeg(m.angle + facing);
  const mark = (streetAngle: number, m: Partial<ShapeMark> = {}) =>
    onMarks(setMark(f, { led, angle: wrapDeg(streetAngle - facing), height: here?.height ?? place.height, ...m }));
  const nudge = (m: ShapeMark, dir: 1 | -1) => onMarks(setMark(f, { ...m, height: Math.max(0, Math.min(1, Math.round((m.height + dir * du) * 1000) / 1000)) }));
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
  return (
    <>
      <p className="text-xs text-stone-600 dark:text-stone-400">
        {wave
          ? 'Move the blinking red LED along the string. Mark where it starts and ends, and each LED where the string turns at the left or the right side of the tree, with how far round it is.'
          : 'Move the blinking red LED along the string. Mark where it starts and ends, and each LED where it passes the front, the right, the back or the left of the tree (as seen from the street).'}{' '}
        Then set how high each mark is. The pattern, bent to go through the marks, places the LEDs in between.
      </p>
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
      {ledCount ? (
        <p className="text-[11px] text-stone-500 tabular-nums">
          {device ?? 'The device'} has {ledCount} LEDs in WLED (0–{ledCount - 1}).
        </p>
      ) : null}
      <div className="grid grid-cols-4 gap-1">
        {steps.map(([d, label]) => (
          <PropButton key={d} onClick={() => onSet(led + d)} disabled={d < 0 ? led <= 0 : led >= n - 1} title={`${d < 0 ? 'Back toward the start' : 'On toward the end'} by ${Math.abs(d)}`}>
            <span className="w-full text-center tabular-nums">{label}</span>
          </PropButton>
        ))}
      </div>
      <div className="flex flex-wrap gap-1">
        <PropButton onClick={() => onSet(0)} disabled={led === 0} title="The first LED of the tree (Home)">
          Start
        </PropButton>
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
        <PropButton onClick={() => onSet(n - 1)} disabled={led === n - 1} title="The last LED of the tree (End)">
          End
        </PropButton>
      </div>
      <input
        type="range"
        aria-label="Blinking LED"
        min={0}
        max={n - 1}
        step={1}
        value={led}
        onChange={(e) => onSet(Number(e.target.value))}
        className="h-7 w-full cursor-pointer accent-red-600 dark:accent-red-400"
      />

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
              steppers
              unit="°"
              onChange={(a) => mark(a)}
            />
          ) : null}
          <PropRow label="Height" hint="How high this LED is, above the base of the tree. − and + (or [ and ]) pull the string down or up.">
            <div className="flex items-center gap-1">
              <PropButton onClick={() => nudge(here, -1)} disabled={here.height <= 0} title="Lower ([)">
                <Minus />
              </PropButton>
              <span className="min-w-16 text-center text-xs tabular-nums">{heightText(here.height)}</span>
              <PropButton onClick={() => nudge(here, 1)} disabled={here.height >= 1} title="Higher (])">
                <Plus />
              </PropButton>
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

      {marks.length ? (
        <div className="space-y-0.5">
          <div className="text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Marks ({marks.length})</div>
          <div className="max-h-48 overflow-y-auto">
            {marks.map((m) => (
              <div key={m.led} className={cn('flex items-center gap-1 rounded px-1 text-xs tabular-nums', m.led === led && 'bg-red-50 dark:bg-red-950/40')}>
                <button type="button" className="min-w-0 flex-1 truncate py-0.5 text-left hover:underline" onClick={() => onSet(m.led)} title="Blink this LED">
                  LED {deviceLed(f, m.led)} · {wayText(street(m))} · {heightText(m.height)}
                </button>
                <button type="button" className="grid size-6 place-items-center rounded hover:bg-stone-200 dark:hover:bg-stone-700 [&_svg]:size-3.5" onClick={() => nudge(m, -1)} aria-label="Lower" title="Lower">
                  <Minus />
                </button>
                <button type="button" className="grid size-6 place-items-center rounded hover:bg-stone-200 dark:hover:bg-stone-700 [&_svg]:size-3.5" onClick={() => nudge(m, 1)} aria-label="Higher" title="Higher">
                  <Plus />
                </button>
                <button type="button" className="grid size-6 place-items-center rounded hover:bg-stone-200 dark:hover:bg-stone-700 [&_svg]:size-3.5" onClick={() => remove(m)} aria-label="Remove" title="Remove this mark">
                  <X />
                </button>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {lights ? <PropNote tone="red">{lights}</PropNote> : null}
      <PropNote>
        Arrow keys move the LED (Shift: 10 at a time{perStrand ? '; Page Up and Page Down: a strand' : ''}; Home, End). {wave ? 'L, F, R' : 'F, R, B, L'} mark it; [ and ] lower or raise its
        mark; Delete removes it; Esc stops.
      </PropNote>
      <div className="flex items-center gap-1">
        <PropButton onClick={() => onMarks(undefined)} disabled={!marks.length} danger title="Every LED goes back to where the pattern puts it">
          <Trash2 /> Clear marks
        </PropButton>
        <span className="flex-1" />
        <Button size="sm" variant="primary" onClick={onStop}>
          Done
        </Button>
      </div>
    </>
  );
}
