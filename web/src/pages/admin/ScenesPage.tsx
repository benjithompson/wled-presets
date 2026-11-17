import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import { ArrowDown, ArrowUp, Download, Layers, Pencil, Play, Plus, RefreshCw, Star, Trash2, Upload } from 'lucide-react';
import { toast } from 'sonner';
import type { DeviceWithStatus, Scene } from '../../../../shared/types.ts';
import { Badge, Button, Card, ConfirmDialog, Dialog, Empty, Field, Input, PageHeader, Select, Spinner, StatusDot } from '../../components/ui.tsx';
import { api, type Overview } from '../../lib/api.ts';
import { downloadJson, errorText } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';

export function ScenesPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useOverview();
  const [editing, setEditing] = useState<Scene | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Scene | null>(null);
  const [restoreFile, setRestoreFile] = useState<{ name: string; data: any } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const refresh = () => qc.invalidateQueries({ queryKey: OVERVIEW });

  const apply = useMutation({
    mutationFn: (id: string) => api.applyScene(id),
    onSuccess: (r) => (r.failed.length ? toast.warning(`Applied to ${r.applied.length} device(s). ${r.failed.length} did not respond.`) : toast.success('Scene applied')),
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

  return (
    <>
      <PageHeader
        title="Scenes"
        description="A scene is one button on the public page. It sets a WLED preset on each device at the same time."
        actions={
          <>
            <Button onClick={exportScenes} disabled={!data?.scenes.length}>
              <Download /> Export
            </Button>
            <Button onClick={() => fileInput.current?.click()}>
              <Upload /> Import
            </Button>
            <Button variant="primary" onClick={() => setEditing('new')} disabled={!enabledDevices.length}>
              <Plus /> New scene
            </Button>
          </>
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
            {enabledDevices.length
              ? 'Create a scene, then choose which WLED preset each device plays for it.'
              : 'Scenes control devices. Add a WLED device before you create a scene.'}
          </Empty>
        ) : (
          <ul className="divide-y divide-stone-100 dark:divide-stone-800">
            {data.scenes.map((s, i) => {
              const mapped = enabledDevices.filter((d) => s.devicePresets[d.id]).length;
              const isDefault = data.settings.defaultSceneId === s.id;
              const isCurrent = data.state.currentSceneId === s.id;
              return (
                <li key={s.id} className="flex flex-wrap items-center gap-3 px-4 py-3 sm:px-5">
                  <div className="flex flex-col">
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
                      {mapped === 0 ? ' — this scene does nothing yet' : ''}
                    </p>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button size="sm" variant="ghost" onClick={() => apply.mutate(s.id)} loading={apply.isPending && apply.variables === s.id} disabled={!mapped}>
                      <Play /> Try
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(s)}>
                      <Pencil /> Edit
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(s)} className="hover:text-red-600 dark:hover:text-red-400">
                      <Trash2 />
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {data && editing ? <SceneEditor key={editing === 'new' ? 'new' : editing.id} scene={editing === 'new' ? null : editing} data={data} onClose={() => setEditing(null)} /> : null}

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

function SceneEditor({ scene, data, onClose }: { scene: Scene | null; data: Overview; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(scene?.name ?? '');
  const [map, setMap] = useState<Record<string, number>>(scene?.devicePresets ?? {});
  const devices = data.devices.filter((d) => d.enabled);
  const missing = devices.filter((d) => !data.devicePresets[d.id]?.length);

  const save = useMutation({
    mutationFn: () => {
      const devicePresets = Object.fromEntries(Object.entries(map).filter(([, v]) => v >= 1));
      return scene ? api.updateScene(scene.id, { name, devicePresets }) : api.createScene({ name, devicePresets });
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
    for (const d of devices) {
      const p = data.devicePresets[d.id]?.find((x) => x.name.toLowerCase() === presetName.toLowerCase());
      if (p) next[d.id] = p.id;
    }
    setMap(next);
  };
  const sharedNames = [...new Set(devices.flatMap((d) => data.devicePresets[d.id]?.map((p) => p.name) ?? []))].sort();

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={scene ? 'Edit scene' : 'New scene'}
      description="Choose the WLED preset that each device plays for this scene. Leave a device on “Do not change” to skip it."
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

        {sharedNames.length > 0 ? (
          <Field label="Quick fill" hint="Sets every device that has a preset with this name.">
            {(id) => (
              <Select id={id} value="" onChange={(e) => e.target.value && setAll(e.target.value)}>
                <option value="">Choose a preset name…</option>
                {sharedNames.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
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
              <DeviceRow key={d.id} device={d} presets={data.devicePresets[d.id] ?? []} value={map[d.id] ?? 0} onChange={(v) => setMap((m) => ({ ...m, [d.id]: v }))} />
            ))}
          </ul>
        </div>
      </form>
    </Dialog>
  );
}

function DeviceRow({ device, presets, value, onChange }: { device: DeviceWithStatus; presets: { id: number; name: string }[]; value: number; onChange: (v: number) => void }) {
  return (
    <li className="flex flex-wrap items-center gap-3 px-3 py-2.5">
      <StatusDot online={device.online} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{device.name}</p>
        <p className="truncate text-xs text-stone-500">
          {device.host}
          {device.port !== 80 ? `:${device.port}` : ''}
        </p>
      </div>
      {presets.length ? (
        <Select aria-label={`Preset for ${device.name}`} className="w-full sm:w-56" value={value} onChange={(e) => onChange(Number(e.target.value))}>
          <option value={0}>Do not change</option>
          {presets.map((p) => (
            <option key={p.id} value={p.id}>
              {p.id}. {p.name}
            </option>
          ))}
          {value && !presets.some((p) => p.id === value) ? <option value={value}>{value}. (not on device)</option> : null}
        </Select>
      ) : (
        <Input
          aria-label={`Preset id for ${device.name}`}
          className="w-full sm:w-56"
          inputMode="numeric"
          placeholder="Preset id (1–250)"
          value={value || ''}
          onChange={(e) => onChange(Number(e.target.value.replace(/\D/g, '')) || 0)}
        />
      )}
    </li>
  );
}
