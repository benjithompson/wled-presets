// The layout editor's panels for what the lights are made of (light string types), and for
// custom objects and their library.
import { useEffect, useState, type ReactNode } from 'react';
import { Copy, Pencil, Plus, Trash2 } from 'lucide-react';
import { designLength, isLine, layoutScale, ledGap, MAX_FIXTURE_PIXELS, lineLengths, zigzagPath, type Design, type Fixture, type Layout } from '../../../../shared/layout.ts';
import { fitsString, freeSetting } from '../../../../shared/stringFit.ts';
import { setsScale } from '../../../../shared/yardScale.ts';
import {
  BUILT_IN_LIGHTS,
  isBuiltInLight,
  LED_CHIPS,
  LIGHT_STYLES,
  ledsForLength,
  lightsOf,
  lightSummary,
  maxAmps,
  spacingText,
  setStringCount,
  strandText,
  stringLength,
  stringRanges,
  wholeStrands,
  type LightStyle,
  type LightType
} from '../../../../shared/lights.ts';
import { Button, Dialog, Field, Input, Select } from '../../components/ui.tsx';
import { DesignThumb } from './DesignEditor.tsx';
import { NumberInput, PropButton, PropNote, PropNumber, PropRow, PropSelect } from './props.tsx';

const NEW = '__new';

/** The light type menu: yours, then the common ones, then "New light type…". */
export function LightSelect({ layout, value, onChange, onNew, label = 'Made of', none = 'Not set', hint }: { layout: Layout; value: string | undefined; onChange: (id: string | undefined) => void; onNew: () => void; label?: string; none?: string; hint?: string }) {
  const mine = layout.lightTypes ?? [];
  return (
    <PropSelect
      label={label}
      hint={hint}
      value={value && lightsOf(layout, value) ? value : ''}
      options={[['', none]]}
      groups={[
        ...(mine.length ? [{ label: 'My light types', options: mine.map((l): [string, string] => [l.id, l.name]) }] : []),
        { label: 'Common light strings', options: BUILT_IN_LIGHTS.map((l): [string, string] => [l.id, l.name]) },
        { label: 'More', options: [[NEW, 'New light type…']] }
      ]}
      onChange={(id) => (id === NEW ? onNew() : onChange(id || undefined))}
    />
  );
}

/**
 * What the selected object is made of, and what follows from it: how many LEDs fit the line
 * you drew, how much string that is, the strands, and the current.
 */
export function LightsProps({
  layout,
  f,
  lenText,
  onPick,
  onNew,
  onEdit,
  onFit,
  onStrings
}: {
  layout: Layout;
  f: Fixture;
  /** Layout units as text in the editor's units. */
  lenText: (layoutUnits: number) => string;
  onPick: (id: string | undefined) => void;
  onNew: () => void;
  onEdit: (l: LightType) => void;
  /** Sets the LED count of a line to fit its drawn length. */
  onFit: (pixels: number) => void;
  /** Sets the number of strings: the LED count, and where strings whose ends are set start. */
  onStrings: (patch: Pick<Fixture, 'pixels' | 'stringBreaks'>) => void;
}) {
  const units = layout.units ?? 'ft';
  const scale = layoutScale(layout);
  const lt = lightsOf(layout, f.lights);
  const custom = f.kind === 'custom';
  // A semicircle's zigzag is drawn for you: its length is known, so the LEDs that fit it are too.
  const zigzag = f.kind === 'semicircle';
  const drawn = isLine(f) ? lineLengths(f).reduce((a, b) => a + b, 0) : custom ? designLength(f.design ?? []) * scale * (f.size ?? 1) : zigzag ? designLength([{ points: zigzagPath(f) }]) : 0;
  // The LEDs that fit the drawing, as whole strings when the lights come in strings.
  const fitLeds = lt && (isLine(f) || zigzag) ? Math.min(MAX_FIXTURE_PIXELS, ledsForLength(drawn / scale, lt.spacing)) : null;
  const per = lt?.perStrand && lt.perStrand > 0 ? lt.perStrand : null;
  const fit = fitLeds != null && per ? Math.min(Math.floor(MAX_FIXTURE_PIXELS / per) * per, wholeStrands(fitLeds, per)) : fitLeds;
  // Strings whose start and end are set are whole strings, whatever their length.
  const setByHand = !!f.stringBreaks?.length;
  const strings = per ? (setByHand ? stringRanges(f.pixels, per, f.stringBreaks).length : f.pixels / per) : null;
  const whole = strings != null && (setByHand || Number.isInteger(strings));
  const setCount = (n: number) => {
    const next = setStringCount(f.pixels, per!, f.stringBreaks, Math.min(n, Math.floor(MAX_FIXTURE_PIXELS / per!)));
    onStrings({ pixels: Math.min(MAX_FIXTURE_PIXELS, next.pixels), stringBreaks: next.stringBreaks });
  };
  const pins = f.pointLeds?.filter((p) => p != null).length ?? 0;
  // How far apart the LEDs are on the drawing, along its wire (none for a net over a bush).
  const gap = lt ? ledGap(f, scale) : null;
  // A roof that sets the scale is as long as its string: the drawing is the measure.
  const scales = setsScale(f, layout);
  const tooLong = lt && !scales ? !fitsString(f, layout) : false;
  return (
    <>
      {custom ? (
        <PropRow label="Made of">
          <span className="block truncate text-xs">{lt?.name ?? 'Not set'}</span>
        </PropRow>
      ) : (
        <LightSelect layout={layout} value={f.lights} onChange={onPick} onNew={onNew} hint="The light string or strip of this object: it knows how far apart the LEDs are" />
      )}
      {lt ? (
        <>
          <PropNote>
            {lightSummary(lt, units)}
            {!isBuiltInLight(lt.id) ? (
              <>
                {' · '}
                <button type="button" className="underline underline-offset-2 hover:text-stone-900 dark:hover:text-white" onClick={() => onEdit(lt)}>
                  edit
                </button>
              </>
            ) : null}
          </PropNote>
          {isLine(f) || custom || zigzag ? (
            <PropRow label="Length">
              <span className="block text-xs tabular-nums">
                {lenText(drawn)} drawn · {lenText(stringLength(f.pixels, lt.spacing) * scale)} of string
              </span>
            </PropRow>
          ) : null}
          {gap != null ? (
            <PropRow label="Spacing" hint="How far apart the LEDs are along the wire as drawn, and on the string. The wire cannot be drawn longer than the string.">
              <span className={tooLong ? 'block text-xs text-red-600 tabular-nums dark:text-red-400' : 'block text-xs tabular-nums'}>
                {spacingText(gap / scale, units)} drawn · {spacingText(lt.spacing, units)} on the string
              </span>
            </PropRow>
          ) : null}
          {tooLong && fit == null ? (
            <PropNote>
              The wire as drawn is longer than the string: {f.pixels} LEDs {spacingText(lt.spacing, units)} apart do not reach that far. {custom ? 'Make it smaller, or give its design more LEDs.' : freeSetting(f) ? 'Give it more LEDs, or make it smaller.' : 'Give it more LEDs.'}
            </PropNote>
          ) : null}
          {scales ? (
            <PropNote>
              Its LEDs set the yard’s scale: from corner to corner the roofline is as long as its string. More strings, or a corner’s LED moved, change the scale; the objects keep their size.
            </PropNote>
          ) : null}
          {fit != null && fit !== f.pixels && !scales ? (
            <>
              <PropNote>
                At {spacingText(lt.spacing, units)} apart, {fitLeds} LEDs fit the line as drawn{per ? ` (${fit / per} string${fit === per ? '' : 's'} of ${per})` : ''}; it has {f.pixels}.{' '}
                {fit < f.pixels ? 'The string is longer than the line: check the drawing, or the extra LEDs hang somewhere.' : 'The string is shorter than the line.'}
              </PropNote>
              <PropRow label="">
                <PropButton onClick={() => onFit(fit)} title={pins ? `Unpins ${pins} corner(s): the LEDs spread evenly again` : 'The LEDs spread evenly along the line'}>
                  {per ? `Use ${fit / per} string${fit === per ? '' : 's'}` : `Use ${fit} LEDs`}
                </PropButton>
              </PropRow>
            </>
          ) : null}
          {custom ? <PropNote>Set in the object’s design: Edit design, above.</PropNote> : null}
          {per && custom ? (
            <PropRow label="Strings">
              <span className="block text-xs">{strandText(f.pixels, per)}</span>
            </PropRow>
          ) : per ? (
            <>
              <PropNumber
                label="Strings"
                hint={`How many strings of ${per} LEDs make up this object, one after the other. Sets its number of LEDs. Where each one starts and ends: Check the wiring, Strings.`}
                decimal={!whole}
                value={whole ? strings : Math.round(strings! * 100) / 100}
                min={1}
                max={Math.floor(MAX_FIXTURE_PIXELS / per)}
                onChange={(n) => setCount(Math.max(1, Math.round(n)))}
              />
              {!whole ? (
                <>
                  <PropNote>
                    {f.pixels} LEDs is {Math.floor(strings!) ? `${Math.floor(strings!)} string${Math.floor(strings!) === 1 ? '' : 's'} of ${per} and ` : ''}
                    {f.pixels % per} LED{f.pixels % per === 1 ? '' : 's'}{Math.floor(strings!) ? ' more' : ` of a string of ${per}`}: an object is made of whole strings.
                  </PropNote>
                  <PropRow label="">
                    <PropButton onClick={() => onStrings({ pixels: Math.min(Math.floor(MAX_FIXTURE_PIXELS / per) * per, wholeStrands(f.pixels, per)), stringBreaks: undefined })}>
                      Use {Math.ceil(strings! - 1e-9)} strings
                    </PropButton>
                  </PropRow>
                </>
              ) : null}
            </>
          ) : null}
          <PropRow label="Power" hint="All LEDs white at full brightness. WLED's brightness limiter keeps it lower.">
            <span className="block text-xs tabular-nums">
              up to {maxAmps(f.pixels, lt).toFixed(1)} A at {lt.volts} V ({Math.round(maxAmps(f.pixels, lt) * lt.volts)} W)
            </span>
          </PropRow>
          {lt.perStrand ? <PropNote>Orange marks on the drawing: where each new strand starts.</PropNote> : null}
        </>
      ) : (
        <PropNote>Pick the light string this object is made of. The editor then knows how far apart the LEDs are: how many fit a line you draw, where each strand starts, and the power the lights need.</PropNote>
      )}
    </>
  );
}

/** Your own light type: a string or strip that is not in the list. */
export function LightTypeDialog({
  open,
  initial,
  units,
  usedBy,
  onSave,
  onDelete,
  onClose
}: {
  open: boolean;
  /** Null: a new light type. */
  initial: LightType | null;
  units: 'ft' | 'm';
  usedBy: number;
  onSave: (l: LightType) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}) {
  const per = units === 'm' ? 0.01 : 0.0254;
  const blank: LightType = { id: '', name: '', chip: 'WS2811', volts: 12, style: 'bullet', spacing: 4 * 0.0254, perStrand: 50, milliamps: 25 };
  const [l, setL] = useState<LightType>(initial ?? blank);
  useEffect(() => {
    if (open) setL(initial ?? blank);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initial]);
  const set = (patch: Partial<LightType>) => setL((x) => ({ ...x, ...patch }));
  const valid = l.name.trim() && l.spacing > 0 && l.volts > 0;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={initial ? `Light type: ${initial.name}` : 'New light type'}
      description="A light string or strip of your own. The spacing is from the middle of one LED to the middle of the next."
      footer={
        <>
          {initial ? (
            <Button variant="ghost" className="mr-auto text-red-600" onClick={() => onDelete(initial.id)} title={usedBy ? `${usedBy} object(s) use it: they become “not set”` : undefined}>
              <Trash2 /> Delete
            </Button>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!valid} onClick={() => onSave({ ...l, name: l.name.trim(), id: l.id || `lights-${Math.random().toString(36).slice(2, 10)}` })}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3 pb-2">
        <div className="col-span-2">
          <Field label="Name">{(id) => <Input id={id} value={l.name} maxLength={80} autoFocus placeholder="For example: 12 V bullet pixels from the garage" onChange={(e) => set({ name: e.target.value })} />}</Field>
        </div>
        <Field label="Chip">
          {(id) => (
            <Select id={id} value={LED_CHIPS.includes(l.chip) ? l.chip : 'Other'} onChange={(e) => set({ chip: e.target.value })}>
              {LED_CHIPS.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Kind">
          {(id) => (
            <Select id={id} value={l.style} onChange={(e) => set({ style: e.target.value as LightStyle })}>
              {Object.entries(LIGHT_STYLES).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Volts">{(id) => <NumberInput id={id} decimal value={l.volts} min={1} max={60} onCommit={(volts) => set({ volts })} />}</Field>
        <Field label={`Spacing (${units === 'm' ? 'cm' : 'in'})`} hint="From one LED to the next">
          {(id) => <NumberInput id={id} decimal value={Math.round((l.spacing / per) * 100) / 100} min={0.1} max={1000} onCommit={(n) => set({ spacing: n * per })} />}
        </Field>
        <Field label="LEDs per strand" hint="Empty: a strip you cut to length">
          {(id) => (
            <Input
              id={id}
              inputMode="numeric"
              value={l.perStrand ?? ''}
              placeholder="cut to length"
              onChange={(e) => {
                const n = parseInt(e.target.value.replace(/\D/g, ''), 10);
                set({ perStrand: Number.isFinite(n) && n > 0 ? Math.min(MAX_FIXTURE_PIXELS, n) : null });
              }}
            />
          )}
        </Field>
        <Field label="Current per LED (mA)" hint="Full white; for the power estimate">
          {(id) => <NumberInput id={id} decimal value={l.milliamps} min={0} max={1000} onCommit={(milliamps) => set({ milliamps })} />}
        </Field>
      </div>
      {usedBy ? <p className="pb-2 text-xs text-stone-500">{usedBy} object(s) are made of it.</p> : null}
    </Dialog>
  );
}

/** The library of custom objects: place one, or change a design (every copy changes). */
export function LibraryList({
  layout,
  onPlace,
  onEdit,
  onDuplicate,
  onDelete
}: {
  layout: Layout;
  onPlace: (d: Design) => void;
  onEdit: (d: Design) => void;
  onDuplicate: (d: Design) => void;
  onDelete: (d: Design) => void;
}) {
  const designs = layout.designs ?? [];
  if (!designs.length) return <PropNote>No custom objects yet. Make one: a star, a wreath, an arch, or any shape your lights are laid out in.</PropNote>;
  return (
    <ul className="space-y-1">
      {designs.map((d) => {
        const used = layout.fixtures.filter((f) => f.designId === d.id).length;
        const lt = lightsOf(layout, d.lights);
        return (
          <li key={d.id} className="group flex items-center gap-2 rounded-lg p-1 ring-1 ring-stone-200 dark:ring-stone-800">
            <DesignThumb strokes={d.strokes} pixels={d.pixels} className="size-11 shrink-0 rounded-md bg-[#05070f] text-white" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium">{d.name}</p>
              <p className="truncate text-[11px] text-stone-500">
                {d.pixels} LEDs{lt ? ` · ${lt.name}` : ''}
                {used ? ` · ${used} in the yard` : ''}
              </p>
            </div>
            <div className="flex shrink-0 gap-0.5">
              <IconButton title="Place one in the yard" onClick={() => onPlace(d)}>
                <Plus />
              </IconButton>
              <IconButton title={used ? `Change the design (all ${used} change)` : 'Change the design'} onClick={() => onEdit(d)}>
                <Pencil />
              </IconButton>
              <IconButton title="Make a copy to change" onClick={() => onDuplicate(d)}>
                <Copy />
              </IconButton>
              <IconButton title={used ? `Used by ${used} object(s): delete those first` : 'Delete'} disabled={used > 0} onClick={() => onDelete(d)}>
                <Trash2 />
              </IconButton>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function IconButton({ title, onClick, disabled, children }: { title: string; onClick: () => void; disabled?: boolean; children: ReactNode }) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={onClick}
      className="grid size-7 place-items-center rounded-md text-stone-600 transition pointer-coarse:size-11 hover:bg-stone-100 hover:text-stone-950 disabled:opacity-30 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white [&_svg]:size-3.5"
    >
      {children}
    </button>
  );
}

/** A placed custom object: its design, size and turn. */
export function CustomProps({ layout, f, lenText, onChange, onEditDesign }: { layout: Layout; f: Fixture; lenText: (lu: number) => string; onChange: (patch: Partial<Fixture>) => void; onEditDesign: () => void }) {
  const d = layout.designs?.find((x) => x.id === f.designId);
  const scale = layoutScale(layout);
  let w = 0;
  let h = 0;
  {
    let x0 = Infinity;
    let x1 = -Infinity;
    let y0 = Infinity;
    let y1 = -Infinity;
    for (const s of f.design ?? [])
      for (const p of s.points) {
        x0 = Math.min(x0, p.x);
        x1 = Math.max(x1, p.x);
        y0 = Math.min(y0, p.y);
        y1 = Math.max(y1, p.y);
      }
    if (Number.isFinite(x0)) {
      w = (x1 - x0) * scale * (f.size ?? 1);
      h = (y1 - y0) * scale * (f.size ?? 1);
    }
  }
  return (
    <>
      <PropRow label="Design">
        <div className="flex items-center gap-2">
          <DesignThumb strokes={f.design ?? []} pixels={f.pixels} className="size-9 shrink-0 rounded bg-[#05070f] text-white" />
          <span className="min-w-0 flex-1 truncate text-xs">{d?.name ?? 'Not in the library'}</span>
        </div>
      </PropRow>
      <PropRow label="">
        <PropButton onClick={onEditDesign} title="Change how the string runs; every copy of this design changes">
          <Pencil /> Edit design
        </PropButton>
      </PropRow>
      <PropRow label="Size">
        <span className="block text-xs tabular-nums">
          {lenText(w)} × {lenText(h)}
        </span>
      </PropRow>
      <PropNumber label="Scale" unit="%" value={Math.round((f.size ?? 1) * 100)} min={5} max={1000} step={5} onChange={(n) => onChange({ size: n === 100 ? undefined : n / 100 })} hint="100%: as designed. The LEDs stay the same; they spread over the new size." />
      <PropNumber label="Turn" unit="°" decimal value={f.rotation ?? 0} min={-360} max={360} step={5} onChange={(n) => onChange({ rotation: n || undefined })} hint="Clockwise, as seen from the front" />
      <PropNumber
        label="Faces"
        unit="°"
        decimal
        value={f.facing ?? 0}
        min={-360}
        max={360}
        step={15}
        onChange={(n) => onChange({ facing: n || undefined })}
        hint="Turned as seen from above: 0 faces the street, 90 faces right (as seen from the street), -90 left"
      />
      <PropNumber
        label="Tilt"
        unit="°"
        decimal
        value={f.tilt ?? 0}
        min={-180}
        max={180}
        step={5}
        onChange={(n) => onChange({ tilt: n || undefined })}
        hint="Tilted toward the street (more) or the house (less), as seen from the side view"
      />
      {d && (d.pixels !== f.pixels || JSON.stringify(d.strokes) !== JSON.stringify(f.design)) ? <PropNote tone="red">The design changed since this object was placed.</PropNote> : null}
    </>
  );
}

