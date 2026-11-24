// A device's own WLED settings, changed from the console instead of WLED's app: its LED
// outputs and brightness limiter, what it does at power-up, how it takes real-time frames, its
// name and Wi-Fi radio, and everything else as JSON. The form edits a copy; Save sends the
// device only what changed (see shared/wledConfig.ts).
import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Plus, RotateCw, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { DevicePreset, DeviceWithStatus } from '../../../../shared/types.ts';
import {
  COLOR_ORDERS,
  configPatch,
  gammaOf,
  getPath,
  limiterOf,
  MIN_LIMIT_MA,
  newOutput,
  outputProblems,
  outputsOf,
  protectedSection,
  setGamma,
  setLimiter,
  setOutputLength,
  setOutputType,
  setPath,
  totalLeds,
  withOutputs,
  type LedType,
  type LimiterMode,
  type WledConfig,
  type WledOutput,
  type WledSettings
} from '../../../../shared/wledConfig.ts';
import { Button, ConfirmDialog, Dialog, Field, Input, Select, Spinner, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { OVERVIEW } from './AdminLayout.tsx';
import { NumberInput } from './props.tsx';

type Tab = 'leds' | 'power' | 'realtime' | 'device' | 'json';
const TABS: [Tab, string][] = [
  ['leds', 'LEDs'],
  ['power', 'Startup'],
  ['realtime', 'Live'],
  ['device', 'Device'],
  ['json', 'JSON']
];

/** Changes one setting of the copy being edited, at a dotted path ("if.live.en"). */
type SetValue = (path: string, value: unknown) => void;

export function WledSettingsDialog({ device, presets, onClose }: { device: DeviceWithStatus; presets: DevicePreset[]; onClose: () => void }) {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ['wled-settings', device.id], queryFn: () => api.wledSettings(device.id), staleTime: Infinity, gcTime: 0, retry: false, refetchOnWindowFocus: false });
  const [base, setBase] = useState<WledConfig | null>(null);
  const [draft, setDraft] = useState<WledConfig | null>(null);
  const [tab, setTab] = useState<Tab>('leds');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [leaving, setLeaving] = useState(false);
  const [restarting, setRestarting] = useState(false);

  // The device's settings as loaded (again after a reload) are the ones to compare with.
  useEffect(() => {
    if (!query.data) return;
    setBase(query.data.config);
    setDraft(query.data.config);
    setJsonError(null);
  }, [query.data]);

  const patch = useMemo(() => (base && draft ? (configPatch(base, draft) as WledConfig | undefined) : undefined), [base, draft]);
  const settings = query.data;
  const problems = useMemo(() => {
    if (!draft || !settings) return [];
    const list = outputProblems(outputsOf(draft), settings.ledTypes, settings.gpio);
    const blocked = patch ? protectedSection(patch) : null;
    if (blocked) list.push(`Settings for ${blocked} are not changed from here. Put them back as they were, or use WLED's own page.`);
    if (jsonError) list.push(`The JSON is not valid: ${jsonError}`);
    return list;
  }, [draft, settings, patch, jsonError]);

  const set: SetValue = (path, value) => setDraft((d) => (d ? setPath(d, path, value) : d));

  const save = useMutation({
    mutationFn: () => api.saveWledSettings(device.id, patch!),
    onSuccess: (r) => {
      const now = r.config ?? draft;
      setBase(now);
      setDraft(now);
      if (r.unapplied.length) toast.warning(`Saved, but ${device.name} did not take ${describePaths(r.unapplied)}. The form shows what it has now.`);
      else toast.success(`Saved to ${device.name}`);
      qc.invalidateQueries({ queryKey: OVERVIEW });
    },
    onError: (e) => toast.error(errorText(e))
  });
  const restart = useMutation({
    mutationFn: () => api.restartWled(device.id),
    onSuccess: () => {
      setRestarting(false);
      toast.success(`${device.name} is restarting. It is back in a few seconds.`);
    },
    onError: (e) => toast.error(errorText(e))
  });

  const close = () => (patch ? setLeaving(true) : onClose());
  const info = settings?.info;

  return (
    <>
      <Dialog
        open
        onClose={close}
        size="lg"
        title="WLED settings"
        description={
          <>
            {device.name}
            {info?.ver ? ` · WLED ${info.ver}` : ''}
            {info?.arch ? ` on ${info.arch.toUpperCase()}` : ''}. Saved to the device itself.
          </>
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setRestarting(true)} disabled={!settings} className="sm:mr-auto">
              <RotateCw /> Restart
            </Button>
            <Button onClick={close}>{patch ? 'Cancel' : 'Close'}</Button>
            <Button variant="primary" loading={save.isPending} disabled={!patch || problems.length > 0} onClick={() => save.mutate()}>
              Save changes
            </Button>
          </>
        }
      >
        {query.isLoading ? (
          <div className="flex items-center gap-3 py-10 text-sm text-stone-500">
            <Spinner /> Reading the settings from {device.name}…
          </div>
        ) : query.error ? (
          <div className="space-y-3 py-6">
            <p className="text-sm text-red-600 dark:text-red-400">{errorText(query.error)}</p>
            <Button size="sm" onClick={() => query.refetch()}>
              Try again
            </Button>
          </div>
        ) : settings && draft ? (
          <div className="pb-3 sm:min-h-[min(36rem,60dvh)]">
            {/* -top-2: over the scroll area's own padding, so nothing shows above the tabs. */}
            <div className="sticky -top-2 z-10 -mx-1 -mt-2 bg-white px-1 pt-3 pb-3 dark:bg-stone-900">
              <div role="tablist" aria-label="Settings" className="flex rounded-lg bg-stone-100 p-0.5 dark:bg-stone-800">
                {TABS.map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    role="tab"
                    aria-selected={tab === id}
                    onClick={() => setTab(id)}
                    className={cn(
                      'h-9 min-w-0 flex-1 truncate rounded-md px-1.5 text-[13px] font-medium transition',
                      tab === id ? 'bg-white text-stone-900 shadow-sm dark:bg-stone-950 dark:text-white' : 'text-stone-600 dark:text-stone-300'
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            {problems.length ? (
              <div className="mb-4 flex gap-2 rounded-xl bg-amber-50 px-3 py-2.5 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <ul className="space-y-0.5">
                  {problems.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {tab === 'leds' ? <LedsTab draft={draft} setDraft={(d) => setDraft(d)} set={set} settings={settings} /> : null}
            {tab === 'power' ? <PowerTab draft={draft} setDraft={(d) => setDraft(d)} set={set} presets={presets} /> : null}
            {tab === 'realtime' ? <RealtimeTab draft={draft} set={set} /> : null}
            {tab === 'device' ? <DeviceTab draft={draft} set={set} settings={settings} /> : null}
            {tab === 'json' ? <JsonTab draft={draft} onDraft={setDraft} onError={setJsonError} /> : null}
          </div>
        ) : null}
      </Dialog>

      <ConfirmDialog
        open={leaving}
        title="Leave without saving?"
        confirmLabel="Leave"
        danger
        onConfirm={() => (setLeaving(false), onClose())}
        onClose={() => setLeaving(false)}
      >
        The changes you made are not on {device.name}. They are lost if you leave.
      </ConfirmDialog>
      <ConfirmDialog
        open={restarting}
        title={`Restart ${device.name}?`}
        confirmLabel="Restart"
        loading={restart.isPending}
        onConfirm={() => restart.mutate()}
        onClose={() => setRestarting(false)}
      >
        Its lights go dark for a few seconds while it starts again. {patch ? 'Changes that are not saved stay here, not on the device.' : ''}
      </ConfirmDialog>
    </>
  );
}

/** The settings a device did not take, for people. */
function describePaths(paths: string[]): string {
  const names = new Set(
    paths.map((p) => {
      if (p.startsWith('hw.led.ins')) return 'all of the LED outputs';
      if (p.startsWith('light.gc')) return 'the gamma';
      return p;
    })
  );
  return [...names].join(', ');
}

// ---------- Rows and fields ----------

function Group({ title, note, children }: { title: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className="text-xs font-semibold tracking-wide text-stone-500 uppercase dark:text-stone-400">{title}</h3>
      {note ? <p className="mt-1 text-sm text-stone-500 dark:text-stone-400">{note}</p> : null}
      <div className="mt-1 divide-y divide-stone-100 dark:divide-stone-800">{children}</div>
    </section>
  );
}

/** A setting: what it is on the left, its control on the right (under it on a phone, when wide). */
function Row({ label, hint, children, wide }: { label: string; hint?: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <div className={cn('flex gap-x-4 gap-y-2 py-3', wide ? 'flex-col sm:flex-row sm:items-center' : 'items-center')}>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{label}</div>
        {hint ? <p className="mt-0.5 text-xs text-stone-500 dark:text-stone-400">{hint}</p> : null}
      </div>
      <div className={cn('shrink-0', wide && 'sm:w-56')}>{children}</div>
    </div>
  );
}

function Toggle({ label, hint, value, onChange }: { label: string; hint?: ReactNode; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <Row label={label} hint={hint}>
      <Switch label={label} checked={value} onChange={onChange} />
    </Row>
  );
}

/** A number with − and + beside it. */
function Stepper({
  id,
  label,
  value,
  onChange,
  min = 0,
  max = 100_000,
  step = 1,
  decimal,
  unit,
  placeholder,
  disabled
}: {
  id?: string;
  label: string;
  value: number | null;
  onChange: (n: number) => void;
  min?: number;
  max?: number;
  step?: number;
  decimal?: boolean;
  unit?: string;
  placeholder?: string;
  disabled?: boolean;
}) {
  const clamp = (n: number) => Math.min(max, Math.max(min, Math.round(n * 1000) / 1000));
  const bump = (d: number) => onChange(clamp((value ?? (d > 0 ? min - step : min)) + d * step));
  const btn =
    'grid h-10 w-9 shrink-0 place-items-center rounded-lg bg-stone-100 text-base font-semibold text-stone-600 transition hover:bg-stone-200 active:scale-95 disabled:opacity-40 dark:bg-stone-800 dark:text-stone-300 dark:hover:bg-stone-700';
  return (
    <fieldset disabled={disabled} className="flex min-w-0 items-center gap-1">
      <div className="relative min-w-0 flex-1">
        <NumberInput id={id} value={value} min={min} max={max} step={step} decimal={decimal} placeholder={placeholder} onCommit={onChange} className={cn('tabular-nums', unit && 'pr-9')} />
        {unit ? <span className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 text-xs text-stone-400">{unit}</span> : null}
      </div>
      <button type="button" className={btn} onClick={() => bump(-1)} aria-label={`Lower ${label}`}>
        −
      </button>
      <button type="button" className={btn} onClick={() => bump(1)} aria-label={`Raise ${label}`}>
        +
      </button>
    </fieldset>
  );
}

function NumberRow({ label, hint, ...rest }: Parameters<typeof Stepper>[0] & { hint?: ReactNode }) {
  return (
    <Row label={label} hint={hint} wide>
      <Stepper label={label} {...rest} />
    </Row>
  );
}

function SelectRow<T extends string | number>({ label, hint, value, onChange, options }: { label: string; hint?: ReactNode; value: T; onChange: (v: T) => void; options: [T, string][] }) {
  const id = useId();
  const known = options.some(([v]) => v === value);
  return (
    <Row label={label} hint={hint} wide>
      <Select id={id} aria-label={label} value={String(value)} onChange={(e) => onChange((typeof value === 'number' ? Number(e.target.value) : e.target.value) as T)}>
        {known ? null : <option value={String(value)}>{String(value)}</option>}
        {options.map(([v, l]) => (
          <option key={String(v)} value={String(v)}>
            {l}
          </option>
        ))}
      </Select>
    </Row>
  );
}

// ---------- LEDs ----------

const LED_CURRENT: [number, string][] = [
  [55, '5 V strip (55 mA)'],
  [35, '5 V efficient (35 mA)'],
  [30, '12 V strip (30 mA)'],
  [255, 'WS2815 (12 mA)']
];
const AUTO_WHITE: [number, string][] = [
  [0, 'None'],
  [1, 'Brighter'],
  [2, 'Accurate'],
  [3, 'Dual'],
  [4, 'Max']
];
const WHITE_SWAP = ['As wired', 'Swap white and blue', 'Swap white and green', 'Swap white and red'];
const KIND_GROUPS: [LedType['kind'], string][] = [
  ['digital', 'Digital, one data wire'],
  ['spi', 'Digital, data and clock'],
  ['pwm', 'PWM (analog)'],
  ['onoff', 'Relay'],
  ['network', 'Network']
];

function pinLabels(type: LedType | undefined, count: number): string[] {
  if (type?.kind === 'spi') return ['Data GPIO', 'Clock GPIO'];
  if (type?.kind === 'pwm') return ({ 1: ['White GPIO'], 2: ['Warm GPIO', 'Cold GPIO'], 3: ['Red GPIO', 'Green GPIO', 'Blue GPIO'], 4: ['Red GPIO', 'Green GPIO', 'Blue GPIO', 'White GPIO'] } as Record<number, string[]>)[count] ?? Array.from({ length: count }, (_, i) => `GPIO ${i + 1}`);
  return Array.from({ length: count }, (_, i) => (count > 1 ? `GPIO ${i + 1}` : 'GPIO'));
}

function LedsTab({ draft, setDraft, set, settings }: { draft: WledConfig; setDraft: (d: WledConfig) => void; set: SetValue; settings: WledSettings }) {
  const outputs = outputsOf(draft);
  const limiter = limiterOf(draft);
  const types = settings.ledTypes;
  const setOutputs = (o: WledOutput[]) => setDraft(withOutputs(draft, o));
  const update = (i: number, change: Partial<WledOutput>) => setOutputs(outputs.map((o, k) => (k === i ? { ...o, ...change } : o)));
  const total = totalLeds(outputs);
  const fps = Number(getPath(draft, 'hw.led.fps'));

  return (
    <>
      <Group
        title={`Outputs · ${total} LED${total === 1 ? '' : 's'}`}
        note="Each output is one strip wired to the controller. The layout's objects use this device's LED numbers: after changing the counts or their order, check the objects in Layout."
      >
        <div className="space-y-3 border-none pt-2">
          {outputs.map((o, i) => (
            <OutputCard
              key={i}
              index={i}
              output={o}
              types={types}
              limiter={limiter.mode}
              canRemove={outputs.length > 1}
              onChange={(change) => update(i, change)}
              onLength={(len) => setOutputs(setOutputLength(outputs, i, len))}
              onType={(t) => setOutputs(outputs.map((x, k) => (k === i ? setOutputType(x, t) : x)))}
              onRemove={() => setOutputs(outputs.filter((_, k) => k !== i))}
            />
          ))}
          <Button size="sm" onClick={() => setOutputs([...outputs, newOutput(outputs, types)])}>
            <Plus /> Add output
          </Button>
        </div>
      </Group>

      <Group title="Brightness limiter" note="Keeps the current the LEDs draw within what the power supply and wires can carry, by dimming when needed.">
        <SelectRow<LimiterMode>
          label="Limit"
          value={limiter.mode}
          onChange={(m) => setDraft(setLimiter(draft, m))}
          options={[
            ['off', 'Off'],
            ['device', 'One limit for the device'],
            ['output', 'A limit on each output']
          ]}
        />
        {limiter.mode === 'device' ? (
          <NumberRow label="Power supply" hint="The most current the whole device may draw." value={limiter.ma} min={MIN_LIMIT_MA} max={65000} step={100} unit="mA" onChange={(n) => setDraft(setLimiter(draft, 'device', n))} />
        ) : null}
        {limiter.mode === 'output' ? <Row label="Per output" hint="Set each output's maximum current above.">{`${limiter.ma} mA in all`}</Row> : null}
      </Group>

      <Group title="Drawing">
        <NumberRow
          label="Frame rate"
          hint="How often WLED draws its own effects. 0: as fast as it can."
          value={Number.isFinite(fps) ? fps : null}
          min={0}
          max={250}
          unit="fps"
          onChange={(n) => set('hw.led.fps', n)}
        />
      </Group>
    </>
  );
}

function OutputCard({
  index,
  output: o,
  types,
  limiter,
  canRemove,
  onChange,
  onLength,
  onType,
  onRemove
}: {
  index: number;
  output: WledOutput;
  types: LedType[];
  limiter: LimiterMode;
  canRemove: boolean;
  onChange: (change: Partial<WledOutput>) => void;
  onLength: (len: number) => void;
  onType: (t: LedType) => void;
  onRemove: () => void;
}) {
  const type = types.find((t) => t.id === o.type);
  const pins = o.pin ?? [];
  const wired = type?.kind === 'digital' || type?.kind === 'spi' || !type;
  const ma = o.ledma ?? 55;
  const knownMa = LED_CURRENT.some(([v]) => v === ma);
  const end = o.start + o.len - 1;

  return (
    <div className="rounded-xl bg-stone-50 p-3 ring-1 ring-stone-200 sm:p-4 dark:bg-stone-950/40 dark:ring-stone-800">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="min-w-0">
          <span className="font-medium">Output {index + 1}</span>
          <span className="ml-2 text-xs text-stone-500 tabular-nums">{o.len > 0 ? `LEDs ${o.start}–${end}` : 'No LEDs'}</span>
        </div>
        {canRemove ? (
          <Button size="sm" variant="ghost" onClick={onRemove} aria-label={`Remove output ${index + 1}`} className="hover:text-red-600 dark:hover:text-red-400">
            <Trash2 /> Remove
          </Button>
        ) : null}
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="col-span-2 sm:col-span-3">
          <Field label="LED type">
            {(id) => (
              <Select
                id={id}
                value={String(o.type)}
                onChange={(e) => {
                  const t = types.find((x) => x.id === Number(e.target.value));
                  if (t) onType(t);
                }}
              >
                {type ? null : <option value={String(o.type)}>Type {o.type}</option>}
                {KIND_GROUPS.map(([kind, label]) => {
                  const list = types.filter((t) => t.kind === kind);
                  return list.length ? (
                    <optgroup key={kind} label={label}>
                      {list.map((t) => (
                        <option key={t.id} value={String(t.id)}>
                          {t.name}
                        </option>
                      ))}
                    </optgroup>
                  ) : null;
                })}
              </Select>
            )}
          </Field>
        </div>

        {type?.kind === 'network' ? (
          <div className="col-span-2">
            <Field label="IP address" hint="Where this output sends its LEDs.">
              {(id) => <IpInput id={id} value={pins} onChange={(pin) => onChange({ pin })} />}
            </Field>
          </div>
        ) : (
          pinLabels(type, pins.length).map((label, k) => (
            <Field key={k} label={label}>
              {(id) => (
                <Stepper
                  id={id}
                  label={`output ${index + 1} ${label}`}
                  value={pins[k] >= 0 ? pins[k] : null}
                  placeholder="None"
                  min={0}
                  max={60}
                  onChange={(n) => onChange({ pin: pins.map((p, j) => (j === k ? n : p)) })}
                />
              )}
            </Field>
          ))
        )}

        <Field label="First LED">{(id) => <Stepper id={id} label={`output ${index + 1} first LED`} value={o.start} min={0} max={8191} onChange={(n) => onChange({ start: n })} />}</Field>
        <Field label="LEDs">{(id) => <Stepper id={id} label={`output ${index + 1} LEDs`} value={o.len} min={1} max={8192} onChange={onLength} />}</Field>

        {wired ? (
          <Field label="Color order">
            {(id) => (
              <Select id={id} value={String(o.order & 0x0f)} onChange={(e) => onChange({ order: (o.order & 0xf0) | Number(e.target.value) })}>
                {COLOR_ORDERS.map((name, v) => (
                  <option key={name} value={String(v)}>
                    {name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : null}
        {wired && type?.white ? (
          <Field label="White channel">
            {(id) => (
              <Select id={id} value={String(o.order >> 4)} onChange={(e) => onChange({ order: (o.order & 0x0f) | (Number(e.target.value) << 4) })}>
                {WHITE_SWAP.map((name, v) => (
                  <option key={name} value={String(v)}>
                    {name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : null}
        {type?.white ? (
          <Field label="Auto white">
            {(id) => (
              <Select id={id} value={String(o.rgbwm ?? 0)} onChange={(e) => onChange({ rgbwm: Number(e.target.value) })}>
                {AUTO_WHITE.map(([v, name]) => (
                  <option key={v} value={String(v)}>
                    {name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : null}
        {wired ? (
          <Field label="Skip first LEDs">
            {(id) => <Stepper id={id} label={`output ${index + 1} skipped LEDs`} value={o.skip ?? 0} min={0} max={255} onChange={(n) => onChange({ skip: n })} />}
          </Field>
        ) : null}

        {wired && limiter !== 'off' ? (
          <>
            <Field label="Current per LED">
              {(id) => (
                <Select id={id} value={knownMa ? String(ma) : 'custom'} onChange={(e) => onChange({ ledma: e.target.value === 'custom' ? 40 : Number(e.target.value) })}>
                  {LED_CURRENT.map(([v, name]) => (
                    <option key={v} value={String(v)}>
                      {name}
                    </option>
                  ))}
                  <option value="custom">Other</option>
                </Select>
              )}
            </Field>
            {knownMa ? null : (
              <Field label="mA per LED">{(id) => <Stepper id={id} label={`output ${index + 1} mA per LED`} value={ma} min={1} max={254} unit="mA" onChange={(n) => onChange({ ledma: n })} />}</Field>
            )}
          </>
        ) : null}
        {wired && limiter === 'output' ? (
          <Field label="Maximum current">
            {(id) => <Stepper id={id} label={`output ${index + 1} maximum current`} value={o.maxpwr ?? 0} min={MIN_LIMIT_MA} max={65000} step={100} unit="mA" onChange={(n) => onChange({ maxpwr: n })} />}
          </Field>
        ) : null}
      </div>
      <label className="mt-3 flex items-center justify-between gap-3">
        <span className="text-sm">
          Reversed <span className="text-xs text-stone-500">(LED numbers run from the far end)</span>
        </span>
        <Switch label={`Output ${index + 1} reversed`} checked={!!o.rev} onChange={(rev) => onChange({ rev })} />
      </label>
    </div>
  );
}

/** An IP address kept as four numbers (a network output's "pins"). */
function IpInput({ id, value, onChange }: { id: string; value: number[]; onChange: (v: number[]) => void }) {
  const [text, setText] = useState(value.join('.'));
  const parts = text.split('.');
  const valid = parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  return (
    <Input
      id={id}
      value={text}
      inputMode="decimal"
      className={cn('font-mono', !valid && 'ring-red-400 dark:ring-red-500')}
      onChange={(e) => {
        const t = e.target.value.replace(/[^\d.]/g, '');
        setText(t);
        const p = t.split('.');
        if (p.length === 4 && p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255)) onChange(p.map(Number));
      }}
    />
  );
}

// ---------- Power-up ----------

function PowerTab({ draft, setDraft, set, presets }: { draft: WledConfig; setDraft: (d: WledConfig) => void; set: SetValue; presets: DevicePreset[] }) {
  const gamma = gammaOf(draft);
  const ps = Number(getPath(draft, 'def.ps')) || 0;
  const dur = Number(getPath(draft, 'light.tr.dur'));
  return (
    <>
      <Group title="At power-up" note="What the device does when it gets power, before this app sends it anything.">
        <Toggle label="Turn on" value={!!getPath(draft, 'def.on')} onChange={(v) => set('def.on', v)} />
        <NumberRow label="Brightness" hint="1 to 255." value={getPath(draft, 'def.bri') ?? null} min={1} max={255} onChange={(n) => set('def.bri', n)} />
        <SelectRow<number>
          label="Preset"
          hint="Presets imported from the device."
          value={ps}
          onChange={(v) => set('def.ps', v)}
          options={[[0, 'None'], ...(presets.some((p) => p.id === ps) || !ps ? [] : ([[ps, `Preset ${ps}`]] as [number, string][])), ...presets.map((p): [number, string] => [p.id, `${p.id}. ${p.name}`])]}
        />
      </Group>
      <Group title="Brightness and color">
        <NumberRow
          label="Brightness factor"
          hint="Scales every brightness the device shows. 100% is as set."
          value={getPath(draft, 'light.scale-bri') ?? null}
          min={1}
          max={255}
          unit="%"
          onChange={(n) => set('light.scale-bri', n)}
        />
        <NumberRow
          label="Transition"
          hint="How long WLED's own changes of color and brightness take."
          value={Number.isFinite(dur) ? dur / 10 : null}
          decimal
          min={0}
          max={65}
          step={0.1}
          unit="s"
          onChange={(s) => set('light.tr.dur', Math.round(s * 10))}
        />
        <Toggle label="Gamma-correct colors" hint="Makes colors look even to the eye." value={gamma.colors} onChange={(colors) => setDraft(setGamma(draft, { ...gamma, colors }))} />
        <Toggle label="Gamma-correct brightness" value={gamma.brightness} onChange={(brightness) => setDraft(setGamma(draft, { ...gamma, brightness }))} />
        <NumberRow
          label="Gamma"
          hint="1 to 3. WLED uses 2.2 (2.8 is FastLED's)."
          value={gamma.value}
          decimal
          min={1}
          max={3}
          step={0.1}
          disabled={!gamma.colors && !gamma.brightness}
          onChange={(value) => setDraft(setGamma(draft, { ...gamma, value }))}
        />
      </Group>
    </>
  );
}

// ---------- Real-time ----------

function RealtimeTab({ draft, set }: { draft: WledConfig; set: SetValue }) {
  const live = (k: string) => getPath(draft, `if.live.${k}`);
  const on = !!live('en');
  const timeout = Number(live('timeout'));
  return (
    <>
      <Group title="Real-time frames" note="This app plays effects, games and sequences on the device by sending it frames over the network (DDP).">
        <Toggle
          label="Take real-time frames"
          hint={on ? 'Frames from this app (and other DDP, E1.31 or Art-Net senders) show on the LEDs.' : <span className="text-red-600 dark:text-red-400">Off: the device ignores this app's effects and games.</span>}
          value={on}
          onChange={(v) => set('if.live.en', v)}
        />
        <NumberRow
          label="Timeout"
          hint="After the last frame, the device goes back to its own effect this long after."
          value={Number.isFinite(timeout) ? timeout / 10 : null}
          decimal
          min={0.1}
          max={65}
          step={0.1}
          unit="s"
          onChange={(s) => set('if.live.timeout', Math.max(1, Math.round(s * 10)))}
        />
        <Toggle label="Full brightness" hint="Show frames at full brightness, not at the device's brightness (this app's brightness then has no effect)." value={!!live('maxbri')} onChange={(v) => set('if.live.maxbri', v)} />
        <Toggle label="Gamma-correct frames" hint="Off: frames show the colors exactly as sent." value={!live('no-gc')} onChange={(v) => set('if.live.no-gc', !v)} />
        <Toggle label="Main segment only" hint="Frames show on the main segment, not the whole strip." value={!!live('mso')} onChange={(v) => set('if.live.mso', v)} />
        <Toggle label="Follow LED maps" hint="Frames go through the device's LED map, if it has one." value={!!live('rlm')} onChange={(v) => set('if.live.rlm', v)} />
        <NumberRow label="LED offset" hint="Moves the frames along the strip by this many LEDs." value={live('offset') ?? 0} decimal min={-8192} max={8192} onChange={(n) => set('if.live.offset', Math.round(n))} />
      </Group>
      <Group title="Sync with other WLEDs" note="WLED's own sync: a change made on one device shows on the others on the network.">
        <Toggle label="Send changes" value={!!getPath(draft, 'if.sync.send.en')} onChange={(v) => set('if.sync.send.en', v)} />
        <Toggle label="Take brightness" value={!!getPath(draft, 'if.sync.recv.bri')} onChange={(v) => set('if.sync.recv.bri', v)} />
        <Toggle label="Take colors" value={!!getPath(draft, 'if.sync.recv.col')} onChange={(v) => set('if.sync.recv.col', v)} />
        <Toggle label="Take effects" value={!!getPath(draft, 'if.sync.recv.fx')} onChange={(v) => set('if.sync.recv.fx', v)} />
      </Group>
    </>
  );
}

// ---------- Device ----------

/** WLED's Wi-Fi transmit powers, in quarter dBm. */
const TX_POWER: [number, string][] = [
  [78, '19.5 dBm (most)'],
  [76, '19 dBm'],
  [74, '18.5 dBm'],
  [68, '17 dBm'],
  [60, '15 dBm'],
  [52, '13 dBm'],
  [44, '11 dBm'],
  [34, '8.5 dBm'],
  [28, '7 dBm'],
  [20, '5 dBm'],
  [8, '2 dBm (least)']
];

function uptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}

function DeviceTab({ draft, set, settings }: { draft: WledConfig; set: SetValue; settings: WledSettings }) {
  const info = settings.info;
  const ssid = getPath(draft, 'nw.ins.0.ssid');
  const mdns = String(getPath(draft, 'id.mdns') ?? '');
  const facts: [string, ReactNode][] = [
    ['Wi-Fi network', ssid || '—'],
    ['Signal', info?.wifi?.signal != null ? `${info.wifi.signal}%${info.wifi.rssi != null ? ` (${info.wifi.rssi} dBm)` : ''}${info.wifi.channel ? `, channel ${info.wifi.channel}` : ''}` : '—'],
    ['Access point', info?.wifi?.bssid ? <span className="font-mono">{info.wifi.bssid}</span> : '—'],
    ['Address', info?.ip ? <span className="font-mono">{info.ip}</span> : '—'],
    ['Firmware', info?.ver ? `WLED ${info.ver}` : '—'],
    ['Running for', info?.uptime != null ? uptime(info.uptime) : '—'],
    ['Real-time now', info?.live ? `${info.lm ?? 'Yes'}${info.lip ? ` from ${info.lip}` : ''}` : 'No'],
    ['Frames shown', info?.leds?.fps != null ? `${info.leds.fps} a second` : '—']
  ];
  return (
    <>
      <Group title="Names">
        <Row label="Name" hint="The name WLED shows. This console's name for the device is set with Edit." wide>
          <Input aria-label="Name" value={String(getPath(draft, 'id.name') ?? '')} maxLength={32} onChange={(e) => set('id.name', e.target.value)} />
        </Row>
        <Row label="Network name" hint={mdns ? <>Reach it at <span className="font-mono">{mdns}.local</span>.</> : 'Its mDNS name on the network.'} wide>
          <Input aria-label="Network name" className="font-mono" value={mdns} maxLength={32} onChange={(e) => set('id.mdns', e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))} />
        </Row>
      </Group>
      <Group title="Wi-Fi radio">
        <Toggle label="Wi-Fi sleep" hint="Off keeps the radio awake, for smoother real-time frames (it uses a little more power)." value={!!getPath(draft, 'wifi.sleep')} onChange={(v) => set('wifi.sleep', v)} />
        <SelectRow<number> label="Transmit power" hint="Lower it only if the device is close to the access point." value={Number(getPath(draft, 'wifi.txpwr') ?? 78)} onChange={(v) => set('wifi.txpwr', v)} options={TX_POWER} />
      </Group>
      <Group title="Now" note="Wi-Fi networks and passwords are changed on WLED's own page, on the same network as the device: a mistake there would cut it off from this app.">
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-1.5 py-3 text-sm">
          {facts.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-stone-500 dark:text-stone-400">{k}</dt>
              <dd className="min-w-0 truncate">{v}</dd>
            </div>
          ))}
        </dl>
      </Group>
    </>
  );
}

// ---------- JSON ----------

function JsonTab({ draft, onDraft, onError }: { draft: WledConfig; onDraft: (d: WledConfig) => void; onError: (e: string | null) => void }) {
  // The text is the form's copy when the tab opens; while it is not valid JSON the copy keeps
  // the last valid text.
  const [text, setText] = useState(() => JSON.stringify(draft, null, 2));
  useEffect(() => () => onError(null), [onError]);
  return (
    <Group title="All settings" note="Everything the device keeps, as WLED's /json/cfg has it. Only what you change is sent. Wi-Fi (nw), the access point (ap) and security (ota) are not changed from here.">
      <textarea
        aria-label="All settings as JSON"
        spellCheck={false}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          try {
            const v = JSON.parse(e.target.value);
            if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('it has to be an object, in { }');
            onDraft(v);
            onError(null);
          } catch (err) {
            onError(err instanceof Error ? err.message : String(err));
          }
        }}
        className="mt-2 h-[50dvh] w-full resize-y rounded-xl bg-stone-50 p-3 font-mono text-xs leading-relaxed ring-1 ring-stone-200 ring-inset focus:ring-2 focus:ring-accent-500 focus:outline-none dark:bg-stone-950 dark:ring-stone-800"
      />
    </Group>
  );
}
