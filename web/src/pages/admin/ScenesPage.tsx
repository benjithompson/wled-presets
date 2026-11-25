import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import { ArrowDown, ArrowUp, ChevronDown, Clapperboard, Download, Layers, Link2, Pencil, Play, Plus, RefreshCw, Sparkles, Star, Trash2, Upload } from 'lucide-react';
import { defaultSettings, deviceKey, effectInfo, effectObjects, effectTarget, keyDevice, paletteColors, YARD, type EffectId, type EffectSettings } from '../../../../shared/effects.ts';
import type { SequenceSummary } from '../../../../shared/sequence.ts';
import type { Layout } from '../../../../shared/layout.ts';
import { toast } from 'sonner';
import type { DeviceWithStatus, Scene } from '../../../../shared/types.ts';
import { Badge, Button, Card, ConfirmDialog, Dialog, Empty, Field, Input, PageHeader, Select, Spinner, StatusDot } from '../../components/ui.tsx';
import { MoreButton } from '../../components/mobile.tsx';
import { api, type Overview, isQueued } from '../../lib/api.ts';
import { copyLink, downloadJson, errorText } from '../../lib/utils.ts';
import { scenePath } from '../../../../shared/links.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';
import { EFFECT_GROUPS, EffectProps, PaletteSwatch } from './effectProps.tsx';

/**
 * The effects of a scene on the yard, devices, objects or segments of the layout, those objects,
 * and the devices they are on. A scene with a sequence lights the objects of the sequence instead.
 * `layoutDevices`: the devices reached by effects from the layout editor (not whole-device ones).
 */
function sceneEffects(scene: Scene, layout: Layout | undefined, devices: { id: string; name: string }[], seq?: SequenceSummary & { objects?: string[] }) {
  const fixtures = layout?.fixtures ?? [];
  const byId = new Map(fixtures.map((f) => [f.id, f]));
  const deviceName = new Map(devices.map((d) => [d.id, d.name]));
  const items = seq
    ? []
    : Object.entries(scene.effects ?? {}).flatMap(([key, effect]) => {
        if (key === YARD) return [{ key, effect, name: 'Whole yard', device: false }];
        const dev = keyDevice(key);
        if (dev != null) return deviceName.has(dev) && fixtures.some((f) => f.deviceId === dev) ? [{ key, effect, name: deviceName.get(dev)!, device: true }] : [];
        const t = effectTarget(key);
        const f = byId.get(t.id);
        return f ? [{ key, effect, name: t.segment == null ? f.name : `${f.name} · segment ${t.segment + 1}`, device: false }] : [];
      });
  const devicesOf = (ids: Set<string>) =>
    new Set(
      fixtures
        .filter((f) => ids.has(f.id))
        .map((f) => f.deviceId)
        .filter((id): id is string => !!id)
    );
  const ids = new Set(
    seq
      ? fixtures.map((f) => f.id)
      : effectObjects(
          { fixtures },
          items.map((i) => i.key)
        )
  );
  const fromLayout = new Set(
    seq
      ? ids
      : effectObjects(
          { fixtures },
          items.filter((i) => !i.device).map((i) => i.key)
        )
  );
  const objects = fixtures.filter((f) => ids.has(f.id));
  return { items, objects, devices: devicesOf(ids), layoutDevices: devicesOf(fromLayout), layoutItems: items.filter((i) => !i.device).length };
}

const SEQUENCES = ['admin', 'sequences'];

export function ScenesPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useOverview();
  const [editing, setEditing] = useState<Scene | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Scene | null>(null);
  const [restoreFile, setRestoreFile] = useState<{ name: string; data: any } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const refresh = () => qc.invalidateQueries({ queryKey: OVERVIEW });
  const { data: layout } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const { data: seqData } = useQuery({ queryKey: SEQUENCES, queryFn: api.sequences });
  const seqById = new Map((seqData?.sequences ?? []).map((q) => [q.id, q]));

  const apply = useMutation({
    mutationFn: (id: string) => api.applyScene(id),
    onSuccess: (r) => (isQueued(r) ? toast.info(r.queued.message) : r.failed.length ? toast.warning(`Applied to ${r.applied.length} device(s). ${r.failed.length} did not respond.`) : toast.success('Scene applied')),
    onError: (e) => toast.error(errorText(e))
  });

  const reorder = useMutation({
    mutationFn: (ids: string[]) => api.reorderScenes(ids),
    onMutate: (ids) => {
      qc.setQueryData<Overview>(OVERVIEW, (o) => o && { ...o, scenes: ids.map((id) => o.scenes.find((s) => s.id === id)!).filter(Boolean) });
    },
    onSettled: refresh
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteScene(id),
    onSuccess: () => {
      toast.success('Scene deleted');
      setDeleting(null);
      refresh();
    },
    onError: (e) => toast.error(errorText(e))
  });

  const restore = useMutation({
    mutationFn: (file: unknown) => api.importScenes(file),
    onSuccess: (r) => {
      toast.success(`Restored ${r.restored} scene(s)`);
      setRestoreFile(null);
      refresh();
    },
    onError: (e) => toast.error(`Restore failed: ${errorText(e)}`)
  });

  async function exportScenes() {
    try {
      downloadJson(await api.exportScenes(), `wled-scenes-${new Date().toISOString().slice(0, 10)}.json`);
    } catch (e) {
      toast.error(errorText(e));
    }
  }

  async function pickFile(file: File | undefined) {
    if (!file) return;
    try {
      const json = JSON.parse(await file.text());
      if (!Array.isArray(json?.publicPresets)) throw new Error('This is not a scenes backup file');
      setRestoreFile({ name: file.name, data: json });
    } catch (e) {
      toast.error(errorText(e));
    }
  }

  const move = (i: number, dir: -1 | 1) => {
    if (!data) return;
    const ids = data.scenes.map((s) => s.id);
    const j = i + dir;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    reorder.mutate(ids);
  };

  const enabledDevices = data?.devices.filter((d) => d.enabled) ?? [];
  const openSequence = (id: string) => navigate(`/admin/sequences?open=${encodeURIComponent(id)}`);
  const openEffects = (id: string) => navigate(`/admin/layout?scene=${encodeURIComponent(id)}`);

  return (
    <>
      <PageHeader
        title="Scenes"
        description="A scene is one button on the public page. Each device plays one of its WLED presets or a built-in effect drawn by the server, all at the same time. For an effect on single objects, use the layout editor."
        more={[
          { label: 'Effects per object', icon: Sparkles, run: () => navigate('/admin/layout') },
          { label: 'Export', icon: Download, run: () => void exportScenes(), disabled: !data?.scenes.length },
          { label: 'Import', icon: Upload, run: () => fileInput.current?.click() }
        ]}
        actions={
          <Button variant="primary" onClick={() => setEditing('new')} disabled={!enabledDevices.length}>
            <Plus /> New scene
          </Button>
        }
      />
      <input ref={fileInput} type="file" accept="application/json,.json" hidden onChange={(e) => (pickFile(e.target.files?.[0]), (e.target.value = ''))} />

      <Card>
        {isLoading ? (
          <div className="grid place-items-center py-16">
            <Spinner />
          </div>
        ) : !data?.scenes.length ? (
          <Empty
            icon={<Layers />}
            title="No scenes yet"
            action={
              enabledDevices.length ? (
                <Button variant="primary" onClick={() => setEditing('new')}>
                  <Plus /> Create the first scene
                </Button>
              ) : (
                <Button variant="primary" onClick={() => navigate('/admin/devices')}>
                  Add a device first
                </Button>
              )
            }
          >
            {enabledDevices.length ? 'Create a scene, then choose which WLED preset each device plays for it.' : 'Scenes control devices. Add a WLED device before you create a scene.'}
          </Empty>
        ) : (
          <ul className="divide-y divide-stone-100 dark:divide-stone-800">
            {data.scenes.map((s, i) => {
              const seq = s.sequenceId ? seqById.get(s.sequenceId) : undefined;
              const fx = sceneEffects(s, layout, data.devices, seq);
              const mapped = enabledDevices.filter((d) => s.devicePresets[d.id] || fx.devices.has(d.id)).length;
              const playable = mapped > 0 || fx.objects.length > 0;
              const isDefault = data.settings.defaultSceneId === s.id;
              const isCurrent = data.state.currentSceneId === s.id;
              return (
                <li key={s.id} className="flex items-center gap-3 py-3 pr-2 pl-4 sm:px-5">
                  <div className="flex flex-col max-md:hidden">
                    <button
                      type="button"
                      aria-label={`Move ${s.name} up`}
                      disabled={i === 0}
                      onClick={() => move(i, -1)}
                      className="rounded p-0.5 text-stone-400 hover:text-stone-900 disabled:opacity-25 dark:hover:text-white"
                    >
                      <ArrowUp className="size-3.5" />
                    </button>
                    <button
                      type="button"
                      aria-label={`Move ${s.name} down`}
                      disabled={i === data.scenes.length - 1}
                      onClick={() => move(i, 1)}
                      className="rounded p-0.5 text-stone-400 hover:text-stone-900 disabled:opacity-25 dark:hover:text-white"
                    >
                      <ArrowDown className="size-3.5" />
                    </button>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate font-medium">{s.name}</span>
                      {isCurrent ? <Badge tone="green">Playing</Badge> : null}
                      {isDefault ? (
                        <Badge tone="amber">
                          <Star className="size-3" /> Default
                        </Badge>
                      ) : null}
                    </div>
                    <p className="mt-0.5 text-sm text-stone-500 dark:text-stone-400">
                      {mapped === enabledDevices.length ? `All ${mapped} device(s)` : `${mapped} of ${enabledDevices.length} device(s)`}
                      {seq ? ` · plays the sequence “${seq.name}”` : fx.objects.length ? ` · effects on ${fx.objects.length} object(s)` : ''}
                      {!playable ? ' — this scene does nothing yet' : ''}
                    </p>
                    {fx.objects.length ? (
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {fx.items.map((it) => (
                          <span
                            key={it.key}
                            className="inline-flex items-center gap-1.5 rounded-full bg-stone-100 py-0.5 pr-2 pl-1 text-xs text-stone-600 dark:bg-stone-800 dark:text-stone-300"
                            title={it.name}
                          >
                            <PaletteSwatch colors={paletteColors(it.effect)} className="block h-3 w-5 rounded-full" />
                            <span className="max-w-40 truncate">{it.name}</span>
                            <span className="text-stone-400">{effectInfo(it.effect.effect).name}</span>
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <Button size="sm" variant="ghost" onClick={() => apply.mutate(s.id)} loading={apply.isPending && apply.variables === s.id} disabled={!playable} className="max-md:h-10">
                      <Play /> Try
                    </Button>
                    {seq ? (
                      <Button size="sm" variant="ghost" onClick={() => openSequence(seq.id)} title="Open the sequence in the sequence editor" className="max-md:hidden">
                        <Clapperboard /> Sequence
                      </Button>
                    ) : fx.layoutItems ? (
                      <Button size="sm" variant="ghost" onClick={() => openEffects(s.id)} title="Change the effects in the layout editor" className="max-md:hidden">
                        <Sparkles /> Effects
                      </Button>
                    ) : null}
                    <Button size="sm" variant="ghost" onClick={() => setEditing(s)} className="max-md:hidden">
                      <Pencil /> Edit
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Copy a link to ${s.name}`}
                      title="Copy a link that plays this scene"
                      onClick={() => void copyLink(scenePath(s, data.scenes), `Link to ${s.name}`)}
                      className="max-md:hidden"
                    >
                      <Link2 />
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(s)} className="hover:text-red-600 max-md:hidden dark:hover:text-red-400">
                      <Trash2 />
                    </Button>
                    <MoreButton
                      className="md:hidden"
                      label={`More for ${s.name}`}
                      title={s.name}
                      items={[
                        { label: 'Edit', icon: Pencil, run: () => setEditing(s) },
                        { label: 'Copy link', icon: Link2, run: () => void copyLink(scenePath(s, data.scenes), `Link to ${s.name}`) },
                        ...(seq
                          ? [{ label: 'Open the sequence', icon: Clapperboard, run: () => openSequence(seq.id) }]
                          : fx.layoutItems
                            ? [{ label: 'Effects in the layout editor', icon: Sparkles, run: () => openEffects(s.id) }]
                            : []),
                        { label: 'Move up', icon: ArrowUp, disabled: i === 0, run: () => move(i, -1) },
                        { label: 'Move down', icon: ArrowDown, disabled: i === data.scenes.length - 1, run: () => move(i, 1) },
                        { label: 'Delete', icon: Trash2, danger: true, run: () => setDeleting(s) }
                      ]}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {data && editing ? (
        <SceneEditor
          key={editing === 'new' ? 'new' : editing.id}
          scene={editing === 'new' ? null : editing}
          data={data}
          layout={layout}
          sequences={seqData?.sequences ?? []}
          onClose={() => setEditing(null)}
        />
      ) : null}

      <ConfirmDialog
        open={!!deleting}
        title={`Delete "${deleting?.name}"?`}
        confirmLabel="Delete scene"
        danger
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        The button goes away from the public page. The presets on the devices stay as they are.
      </ConfirmDialog>

      <ConfirmDialog
        open={!!restoreFile}
        title="Restore scenes from backup?"
        confirmLabel="Replace scenes"
        danger={!!data?.scenes.length}
        loading={restore.isPending}
        onConfirm={() => restoreFile && restore.mutate(restoreFile.data)}
        onClose={() => setRestoreFile(null)}
      >
        {restoreFile
          ? `${restoreFile.name} has ${restoreFile.data.publicPresets.length} scene(s).${data?.scenes.length ? ` They replace your ${data.scenes.length} current scene(s).` : ''} Device links are matched by device id, then by address.`
          : null}
      </ConfirmDialog>
    </>
  );
}

function SceneEditor({ scene, data, layout, sequences, onClose }: { scene: Scene | null; data: Overview; layout: Layout | undefined; sequences: SequenceSummary[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(scene?.name ?? '');
  const [map, setMap] = useState<Record<string, number>>(scene?.devicePresets ?? {});
  /** deviceId -> the built-in effect it plays on all its objects. */
  const [dfx, setDfx] = useState<Record<string, EffectSettings>>(() =>
    Object.fromEntries(Object.entries(scene?.effects ?? {}).flatMap(([k, v]) => (keyDevice(k) != null ? [[keyDevice(k)!, v]] : [])))
  );
  const [sequenceId, setSequenceId] = useState<string>(scene?.sequenceId ?? '');
  const devices = data.devices.filter((d) => d.enabled);
  const seq = sequences.find((q) => q.id === sequenceId);
  const fx = scene || seq ? sceneEffects(scene ?? { id: '', name, sortOrder: 0, devicePresets: {} }, layout, data.devices, seq) : null;
  const hasObjects = new Set((layout?.fixtures ?? []).map((f) => f.deviceId).filter((id): id is string => !!id));
  const missing = devices.filter((d) => !data.devicePresets[d.id]?.length && !fx?.layoutDevices.has(d.id) && !dfx[d.id]);

  const save = useMutation({
    mutationFn: () => {
      // A device plays its effect or its preset, not both.
      const devicePresets = Object.fromEntries(Object.entries(map).filter(([id, v]) => v >= 1 && !dfx[id]));
      const effects = {
        ...Object.fromEntries(Object.entries(scene?.effects ?? {}).filter(([k]) => keyDevice(k) == null)),
        ...Object.fromEntries(Object.entries(dfx).map(([id, v]) => [deviceKey(id), v]))
      };
      const body = { name, devicePresets, effects, sequenceId: sequenceId || null };
      return scene ? api.updateScene(scene.id, body) : api.createScene(body);
    },
    onSuccess: () => {
      toast.success(scene ? 'Scene saved' : 'Scene created');
      qc.invalidateQueries({ queryKey: OVERVIEW });
      onClose();
    },
    onError: (e) => toast.error(errorText(e))
  });

  const sync = useMutation({
    mutationFn: api.syncAllPresets,
    onSuccess: (r) => {
      const bad = r.results.filter((x) => !x.ok).length;
      bad ? toast.warning(`${bad} device(s) did not respond`) : toast.success('Presets imported');
      qc.invalidateQueries({ queryKey: OVERVIEW });
    },
    onError: (e) => toast.error(errorText(e))
  });

  const setAll = (presetName: string) => {
    const next: Record<string, number> = { ...map };
    const nextFx = { ...dfx };
    for (const d of devices) {
      const p = data.devicePresets[d.id]?.find((x) => x.name.toLowerCase() === presetName.toLowerCase());
      if (p) ((next[d.id] = p.id), delete nextFx[d.id]);
    }
    setMap(next);
    setDfx(nextFx);
  };
  /** Every device that can play built-in effects plays this one (the same settings, so 3-D effects line up). */
  const setAllEffect = (id: EffectId) => {
    const settings = defaultSettings(id);
    const next = { ...dfx };
    for (const d of devices) if (hasObjects.has(d.id) && !fx?.layoutDevices.has(d.id)) next[d.id] = settings;
    setDfx(next);
  };
  const choose = (deviceId: string, choice: { preset: number } | { effect: EffectSettings } | null) => {
    setMap((m) => {
      const { [deviceId]: _, ...rest } = m;
      return choice && 'preset' in choice ? { ...rest, [deviceId]: choice.preset } : rest;
    });
    setDfx((m) => {
      const { [deviceId]: _, ...rest } = m;
      return choice && 'effect' in choice ? { ...rest, [deviceId]: choice.effect } : rest;
    });
  };
  const canEffects = devices.some((d) => hasObjects.has(d.id) && !fx?.layoutDevices.has(d.id));
  const sharedNames = [...new Set(devices.flatMap((d) => data.devicePresets[d.id]?.map((p) => p.name) ?? []))].sort();

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={scene ? 'Edit scene' : 'New scene'}
      description="Choose what each device plays for this scene: one of its WLED presets, or a built-in effect that the server draws on all its lights. Leave a device on “Do not change” to skip it."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} disabled={!name.trim()} onClick={() => save.mutate()}>
            {scene ? 'Save scene' : 'Create scene'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-5 pb-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) save.mutate();
        }}
      >
        <Field label="Name" hint="Shown on the public page.">
          {(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="For example: Candy Cane" autoFocus maxLength={100} />}
        </Field>

        {sequences.length ? (
          <Field label="Sequence" hint="Plays a sequence on the lights, over and over, instead of effects. Devices with objects in it play it; the others play their preset below.">
            {(id) => (
              <Select id={id} value={sequenceId} onChange={(e) => setSequenceId(e.target.value)}>
                <option value="">None</option>
                {sequences.map((q) => (
                  <option key={q.id} value={q.id}>
                    {q.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : null}

        {sharedNames.length > 0 || canEffects ? (
          <Field label="Quick fill" hint="Sets every device that has a preset with this name, or every device in the layout to the same built-in effect.">
            {(id) => (
              <Select
                id={id}
                value=""
                onChange={(e) => {
                  const v = e.target.value;
                  if (v.startsWith('e:')) setAllEffect(v.slice(2) as EffectId);
                  else if (v.startsWith('p:')) setAll(v.slice(2));
                }}
              >
                <option value="">Choose a preset or an effect for every device…</option>
                {sharedNames.length ? (
                  <optgroup label="WLED device presets">
                    {sharedNames.map((n) => (
                      <option key={n} value={`p:${n}`}>
                        {n}
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                {canEffects
                  ? EFFECT_GROUPS.map((g) => (
                      <optgroup key={g.label} label={`Built-in effects · ${g.label}`}>
                        {g.options.map(([eid, label]) => (
                          <option key={eid} value={`e:${eid}`}>
                            {label}
                          </option>
                        ))}
                      </optgroup>
                    ))
                  : null}
              </Select>
            )}
          </Field>
        ) : null}

        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium text-stone-700 dark:text-stone-300">Devices</span>
            {missing.length ? (
              <Button size="sm" variant="ghost" onClick={() => sync.mutate()} loading={sync.isPending}>
                <RefreshCw /> Import presets
              </Button>
            ) : null}
          </div>
          <ul className="divide-y divide-stone-100 rounded-xl ring-1 ring-stone-200 dark:divide-stone-800 dark:ring-stone-800">
            {devices.map((d) => (
              <DeviceRow
                key={d.id}
                device={d}
                presets={data.devicePresets[d.id] ?? []}
                value={map[d.id] ?? 0}
                effect={dfx[d.id]}
                inLayout={hasObjects.has(d.id)}
                onChange={(c) => choose(d.id, c)}
                effects={fx?.layoutDevices.has(d.id) ? fx.objects.filter((f) => f.deviceId === d.id).map((f) => f.name) : undefined}
              />
            ))}
          </ul>
        </div>
      </form>
    </Dialog>
  );
}

function DeviceRow({
  device,
  presets,
  value,
  effect,
  inLayout,
  onChange,
  effects
}: {
  device: DeviceWithStatus;
  presets: { id: number; name: string }[];
  value: number;
  /** The built-in effect it plays on all its lights. */
  effect: EffectSettings | undefined;
  /** True when some layout object is on this device: only then can the server draw effects for it. */
  inLayout: boolean;
  onChange: (choice: { preset: number } | { effect: EffectSettings } | null) => void;
  /** Objects on this device that play an effect from the layout editor: then the device plays those, not a preset. */
  effects?: string[];
}) {
  const [typing, setTyping] = useState(false);
  const [adjust, setAdjust] = useState(false);
  const manual = !presets.length && !effect && (typing || value > 0);
  const current = effect ? `e:${effect.effect}` : manual ? 'p:manual' : value ? `p:${value}` : '';
  const pick = (v: string) => {
    setTyping(v === 'p:manual');
    if (!v) return onChange(null);
    if (v === 'p:manual') return onChange(value ? { preset: value } : null);
    if (v.startsWith('p:')) return onChange({ preset: Number(v.slice(2)) });
    const id = v.slice(2) as EffectId;
    // A new effect keeps the brightness and colors you picked for the last one.
    const next = defaultSettings(id);
    onChange({ effect: effect ? { ...next, brightness: effect.brightness } : next });
  };
  return (
    <li className="px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-3">
        <StatusDot online={device.online} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{device.name}</p>
          <p className="truncate text-xs text-stone-500">
            {device.host}
            {device.port !== 80 ? `:${device.port}` : ''}
          </p>
        </div>
        {effects?.length ? (
          <span className="inline-flex w-full items-center gap-1.5 text-sm text-stone-600 sm:w-64 dark:text-stone-300" title={effects.join(', ')}>
            <Sparkles className="size-4 shrink-0 text-sky-600 dark:text-sky-400" />
            <span className="truncate">Effects on {effects.length === 1 ? effects[0] : `${effects.length} objects`}</span>
          </span>
        ) : (
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-64">
            <Select aria-label={`What ${device.name} plays`} className="w-full" value={current} onChange={(e) => pick(e.target.value)}>
              <option value="">Do not change</option>
              <optgroup label="WLED device presets">
                {presets.map((p) => (
                  <option key={p.id} value={`p:${p.id}`}>
                    {p.id}. {p.name}
                  </option>
                ))}
                {value && presets.length && !presets.some((p) => p.id === value) ? <option value={`p:${value}`}>{value}. (not on device)</option> : null}
                {!presets.length ? <option value="p:manual">Type a preset number…</option> : null}
              </optgroup>
              {EFFECT_GROUPS.map((g) => (
                <optgroup key={g.label} label={inLayout ? `Built-in effects · ${g.label}` : `Built-in effects · ${g.label} (put this device in the layout first)`} disabled={!inLayout}>
                  {g.options.map(([eid, label]) => (
                    <option key={eid} value={`e:${eid}`}>
                      {label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </Select>
            {manual ? (
              <Input
                aria-label={`Preset id for ${device.name}`}
                className="w-full"
                inputMode="numeric"
                placeholder="Preset id (1–250)"
                value={value || ''}
                autoFocus={typing && !value}
                onChange={(e) => {
                  const n = Number(e.target.value.replace(/\D/g, '')) || 0;
                  onChange(n ? { preset: n } : null);
                  setTyping(true);
                }}
              />
            ) : null}
          </div>
        )}
      </div>
      {effect && !effects?.length ? (
        <div className="mt-2 ml-5">
          <button
            type="button"
            onClick={() => setAdjust((v) => !v)}
            aria-expanded={adjust}
            className="inline-flex items-center gap-1.5 rounded-md py-0.5 text-xs text-stone-600 hover:text-stone-950 dark:text-stone-400 dark:hover:text-white"
          >
            <PaletteSwatch colors={paletteColors(effect)} className="block h-2.5 w-6 rounded-full ring-1 ring-black/10 dark:ring-white/10" />
            {effectInfo(effect.effect).name} on all its lights
            <ChevronDown className={adjust ? 'size-3.5 rotate-180 transition' : 'size-3.5 transition'} />
            <span className="text-stone-400">{adjust ? 'Done' : 'Colors, speed…'}</span>
          </button>
          {adjust ? (
            <div className="mt-2 space-y-1.5 rounded-lg bg-stone-50 p-3 ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
              <EffectProps effect={effect} onChange={(e) => (e ? onChange({ effect: e }) : (onChange(null), setAdjust(false)))} objectCount={0} noneLabel="Do not change" />
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
