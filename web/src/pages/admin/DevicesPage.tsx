import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, Pencil, Play, Plus, Radar, RefreshCw, Router, SlidersHorizontal, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { DeviceWithStatus, DiscoveredDevice } from '../../../../shared/types.ts';
import { Badge, Button, Card, ConfirmDialog, Dialog, Empty, Field, Input, PageHeader, Spinner, StatusDot, Switch } from '../../components/ui.tsx';
import { MoreButton } from '../../components/mobile.tsx';
import { api, type DeviceInput, type PresetImport } from '../../lib/api.ts';
import { cn, errorText, relativeTime } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';
import { LightsCard } from './LightsCard.tsx';
import { WledSettingsDialog } from './WledSettings.tsx';

export function DevicesPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useOverview();
  const [editing, setEditing] = useState<DeviceWithStatus | 'new' | null>(null);
  const [deleting, setDeleting] = useState<DeviceWithStatus | null>(null);
  const [configuring, setConfiguring] = useState<DeviceWithStatus | null>(null);
  const [discovering, setDiscovering] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: OVERVIEW });

  const toggle = useMutation({
    mutationFn: (d: DeviceWithStatus) => api.updateDevice(d.id, { name: d.name, host: d.host, port: d.port, enabled: !d.enabled }),
    onSuccess: refresh,
    onError: (e) => toast.error(errorText(e))
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteDevice(id),
    onSuccess: () => {
      toast.success('Device removed');
      setDeleting(null);
      refresh();
    },
    onError: (e) => toast.error(errorText(e))
  });
  const syncOne = useMutation({
    mutationFn: (id: string) => api.syncPresets(id),
    onSuccess: (r) => {
      toast.success(`Imported ${r.count} preset(s)`);
      refresh();
    },
    onError: (e) => toast.error(errorText(e))
  });
  const syncAll = useMutation({
    mutationFn: api.syncAllPresets,
    onSuccess: (r) => {
      const ok = r.results.filter((x) => x.ok).length;
      ok === r.results.length ? toast.success(`Imported presets from ${ok} device(s)`) : toast.warning(`Imported from ${ok} of ${r.results.length} device(s)`);
      refresh();
    },
    onError: (e) => toast.error(errorText(e))
  });

  const devices = data?.devices ?? [];
  const online = devices.filter((d) => d.online).length;
  const enabled = devices.filter((d) => d.enabled).length;

  return (
    <>
      <PageHeader
        title="Devices"
        description={
          devices.length ? `${online} of ${enabled} enabled device(s) online. Status refreshes every few seconds.` : 'The WLED controllers that this app sends commands to.'
        }
        more={[
          { label: syncAll.isPending ? 'Importing presets…' : 'Import all presets', icon: RefreshCw, run: () => syncAll.mutate(), disabled: !enabled || syncAll.isPending },
          { label: 'Discover', icon: Radar, run: () => setDiscovering(true) }
        ]}
        actions={
          <Button variant="primary" onClick={() => setEditing('new')}>
            <Plus /> Add device
          </Button>
        }
      />

      <LightsCard devices={devices} />

      <Card>
        {isLoading ? (
          <div className="grid place-items-center py-16">
            <Spinner />
          </div>
        ) : !devices.length ? (
          <Empty
            icon={<Router />}
            title="No devices yet"
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Button onClick={() => setDiscovering(true)}>
                  <Radar /> Scan the network
                </Button>
                <Button variant="primary" onClick={() => setEditing('new')}>
                  <Plus /> Add by address
                </Button>
              </div>
            }
          >
            Scan the network to find WLED devices, or add one by its IP address.
          </Empty>
        ) : (
          <ul className="divide-y divide-stone-100 dark:divide-stone-800">
            {devices.map((d) => {
              const presets = data?.devicePresets[d.id] ?? [];
              const open = expanded === d.id;
              return (
                <li key={d.id}>
                  <div className="flex items-center gap-x-3 gap-y-2 py-3.5 pr-2 pl-4 sm:gap-x-4 sm:px-5">
                    <StatusDot online={d.enabled ? d.online : null} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate font-medium">{d.name}</span>
                        {!d.enabled ? <Badge>Disabled</Badge> : d.online === false ? <Badge tone="red">Offline</Badge> : null}
                      </div>
                      <p className="mt-0.5 flex flex-wrap gap-x-3 text-sm text-stone-500 dark:text-stone-400">
                        <span className="font-mono text-[13px]">
                          {d.host}
                          {d.port !== 80 ? `:${d.port}` : ''}
                        </span>
                        {d.info?.ver ? <span>WLED {d.info.ver}</span> : null}
                        {d.info?.leds?.count ? <span>{d.info.leds.count} LEDs</span> : null}
                        {d.online === false && d.lastSeen ? <span>Last seen {relativeTime(d.lastSeen)}</span> : null}
                      </p>
                      <button
                        type="button"
                        onClick={() => setExpanded(open ? null : d.id)}
                        aria-expanded={open}
                        className="-ml-2 inline-flex h-9 items-center gap-1 rounded-lg px-2 text-[13px] font-medium text-stone-600 md:hidden dark:text-stone-400"
                      >
                        {presets.length} preset{presets.length === 1 ? '' : 's'}
                        <ChevronDown className={cn('size-3.5 transition', open && 'rotate-180')} />
                      </button>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        onClick={() => setExpanded(open ? null : d.id)}
                        aria-expanded={open}
                        className="inline-flex h-8 items-center gap-1 rounded-lg px-2.5 text-[13px] font-medium text-stone-600 hover:bg-stone-100 max-md:hidden dark:text-stone-400 dark:hover:bg-stone-800"
                      >
                        {presets.length} preset{presets.length === 1 ? '' : 's'}
                        <ChevronDown className={cn('size-3.5 transition', open && 'rotate-180')} />
                      </button>
                      <Button size="sm" variant="ghost" title="WLED settings" aria-label={`WLED settings of ${d.name}`} onClick={() => setConfiguring(d)} className="max-md:hidden">
                        <SlidersHorizontal />
                      </Button>
                      <Button size="sm" variant="ghost" aria-label={`Edit ${d.name}`} onClick={() => setEditing(d)} className="max-md:hidden">
                        <Pencil />
                      </Button>
                      <Button size="sm" variant="ghost" aria-label={`Remove ${d.name}`} onClick={() => setDeleting(d)} className="hover:text-red-600 max-md:hidden dark:hover:text-red-400">
                        <Trash2 />
                      </Button>
                      <span className="ml-1">
                        <Switch label={`${d.name} enabled`} checked={d.enabled} onChange={() => toggle.mutate(d)} disabled={toggle.isPending} />
                      </span>
                      <MoreButton
                        className="md:hidden"
                        label={`More for ${d.name}`}
                        title={d.name}
                        items={[
                          { label: 'WLED settings', icon: SlidersHorizontal, run: () => setConfiguring(d) },
                          { label: 'Edit', icon: Pencil, run: () => setEditing(d) },
                          { label: 'Import its presets', icon: RefreshCw, disabled: !d.enabled, run: () => syncOne.mutate(d.id) },
                          { label: 'Remove', icon: Trash2, danger: true, run: () => setDeleting(d) }
                        ]}
                      />
                    </div>
                  </div>
                  {open ? (
                    <div className="border-t border-stone-100 bg-stone-50/60 px-4 py-4 sm:px-5 dark:border-stone-800 dark:bg-stone-950/40">
                      <div className="mb-3 flex items-center justify-between gap-2">
                        <p className="text-sm text-stone-500">Presets stored on this device. Play one to test it.</p>
                        <Button size="sm" onClick={() => syncOne.mutate(d.id)} loading={syncOne.isPending && syncOne.variables === d.id} disabled={!d.enabled}>
                          <RefreshCw /> Import
                        </Button>
                      </div>
                      {presets.length ? (
                        <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                          {presets.map((p) => (
                            <PresetChip key={p.id} deviceId={d.id} id={p.id} name={p.name} disabled={!d.enabled || d.online === false} />
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-stone-500">No presets imported yet.</p>
                      )}
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {editing ? <DeviceDialog key={editing === 'new' ? 'new' : editing.id} device={editing === 'new' ? null : editing} onClose={() => setEditing(null)} /> : null}
      {configuring ? <WledSettingsDialog key={configuring.id} device={configuring} presets={data?.devicePresets[configuring.id] ?? []} onClose={() => setConfiguring(null)} /> : null}
      {discovering ? <DiscoverDialog defaultSubnets={data?.settings.discoverySubnets ?? []} onClose={() => setDiscovering(false)} /> : null}

      <ConfirmDialog
        open={!!deleting}
        title={`Remove "${deleting?.name}"?`}
        confirmLabel="Remove device"
        danger
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Scenes stop sending commands to this device, and its links in every scene are deleted. The device itself does not change.
      </ConfirmDialog>
    </>
  );
}

function PresetChip({ deviceId, id, name, disabled }: { deviceId: string; id: number; name: string; disabled: boolean }) {
  const play = useMutation({
    mutationFn: () => api.applyDevicePreset(deviceId, id),
    onError: (e) => toast.error(errorText(e))
  });
  return (
    <div className="flex items-center gap-2 rounded-lg bg-white px-3 py-1.5 text-sm ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
      <span className="w-6 shrink-0 text-xs text-stone-400 tabular-nums">{id}</span>
      <span className="min-w-0 flex-1 truncate">{name}</span>
      <button
        type="button"
        aria-label={`Play ${name}`}
        disabled={disabled || play.isPending}
        onClick={() => play.mutate()}
        className="grid size-6 place-items-center rounded-md text-stone-400 hover:bg-stone-100 hover:text-stone-900 disabled:opacity-30 dark:hover:bg-stone-800 dark:hover:text-white"
      >
        {play.isPending ? <Spinner className="size-3.5" /> : <Play className="size-3.5" />}
      </button>
    </div>
  );
}

/** The port of WLED's built-in web server. */
const WLED_PORT = 80;

function DeviceDialog({ device, onClose }: { device: DeviceWithStatus | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<DeviceInput>({
    name: device?.name ?? '',
    host: device?.host ?? '',
    port: device?.port ?? 80,
    enabled: device?.enabled ?? true
  });
  const [probe, setProbe] = useState<{ ok: boolean; text: string } | null>(null);
  // The port is kept as text while typing, so the field can be cleared.
  // An empty field means the WLED default and is filled back in when the field loses focus.
  const [portText, setPortText] = useState(String(device?.port ?? WLED_PORT));
  const port = portText === '' ? WLED_PORT : Number(portText);
  const portError = portText !== '' && (!Number.isInteger(port) || port < 1 || port > 65535) ? 'Use a port from 1 to 65535.' : null;
  const canSave = !!form.host.trim() && !portError;

  const test = useMutation({
    mutationFn: () => api.probe(form.host, port),
    onSuccess: (r) => {
      if (r.ok) {
        setProbe({ ok: true, text: `Found “${r.info.name ?? 'WLED'}”${r.info.ver ? `, WLED ${r.info.ver}` : ''}` });
        if (!form.name && r.info.name) setForm((f) => ({ ...f, name: r.info.name! }));
      } else setProbe({ ok: false, text: r.error });
    },
    onError: (e) => setProbe({ ok: false, text: errorText(e) })
  });

  const save = useMutation({
    mutationFn: () => (device ? api.updateDevice(device.id, { ...form, port }) : api.addDevice({ ...form, port })),
    onSuccess: (r) => {
      const imported = r && typeof r === 'object' && 'presets' in r ? (r.presets as PresetImport | null) : null;
      if (!device && imported && !imported.ok) toast.warning(`Device added, but its presets could not be read: ${imported.error}. Use Import to try again.`);
      else if (!device && imported?.ok) toast.success(`Device added with ${imported.count} preset(s)`);
      else toast.success(device ? 'Device saved' : 'Device added');
      qc.invalidateQueries({ queryKey: OVERVIEW });
      onClose();
    },
    onError: (e) => toast.error(errorText(e))
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={device ? 'Edit device' : 'Add device'}
      description={device ? undefined : 'Enter the IP address or host name of a WLED controller.'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} disabled={!canSave} onClick={() => save.mutate()}>
            {device ? 'Save' : 'Add device'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-4 pb-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) save.mutate();
        }}
      >
        <div className="grid grid-cols-[1fr_6rem] gap-3">
          <Field label="Address">
            {(id) => (
              <Input
                id={id}
                value={form.host}
                onChange={(e) => (setForm({ ...form, host: e.target.value }), setProbe(null))}
                placeholder="192.168.1.50"
                autoFocus
                className="font-mono"
              />
            )}
          </Field>
          <Field label="Port" error={portError} hint="WLED uses 80.">
            {(id) => (
              <Input
                id={id}
                inputMode="numeric"
                placeholder={String(WLED_PORT)}
                onBlur={() => portText === '' && setPortText(String(WLED_PORT))}
                maxLength={5}
                value={portText}
                onChange={(e) => (setPortText(e.target.value.replace(/\D/g, '')), setProbe(null))}
              />
            )}
          </Field>
        </div>
        <div className="flex items-center gap-3">
          <Button size="sm" onClick={() => test.mutate()} loading={test.isPending} disabled={!canSave}>
            Test connection
          </Button>
          {probe ? <span className={cn('text-sm', probe.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400')}>{probe.text}</span> : null}
        </div>
        <Field label="Name" hint="Leave empty to use the name set on the device.">
          {(id) => <Input id={id} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Roofline" />}
        </Field>
        <label className="flex items-center justify-between gap-4 rounded-xl px-1 py-1">
          <span>
            <span className="block text-sm font-medium">Enabled</span>
            <span className="block text-xs text-stone-500">Disabled devices get no commands and are not checked.</span>
          </span>
          <Switch label="Enabled" checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} />
        </label>
      </form>
    </Dialog>
  );
}

function DiscoverDialog({ defaultSubnets, onClose }: { defaultSubnets: string[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [subnets, setSubnets] = useState(defaultSubnets.join(', '));
  const [found, setFound] = useState<DiscoveredDevice[] | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());

  const scan = useMutation({
    mutationFn: () =>
      api.discover(
        subnets
          .split(/[,\s]+/)
          .map((s) => s.trim())
          .filter(Boolean)
      ),
    onSuccess: (r) => {
      setFound(r.found);
      setPicked(new Set(r.found.filter((f) => !f.alreadyAdded).map((f) => f.host)));
    },
    onError: (e) => toast.error(errorText(e))
  });

  const add = useMutation({
    mutationFn: () => api.addDevices(found!.filter((f) => picked.has(f.host)).map((f) => ({ name: f.name, host: f.host, port: f.port, enabled: true }))),
    onSuccess: (r) => {
      const ok = r.presets.filter((p) => p.ok);
      const count = ok.reduce((n, p) => n + (p.ok ? p.count : 0), 0);
      if (ok.length === r.presets.length) toast.success(`Added ${r.added.length} device(s) with ${count} preset(s)`);
      else toast.warning(`Added ${r.added.length} device(s). Presets could not be read from ${r.presets.length - ok.length} of them. Use Import to try again.`);
      qc.invalidateQueries({ queryKey: OVERVIEW });
      onClose();
    },
    onError: (e) => toast.error(errorText(e))
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title="Discover devices"
      description="Scan the network for WLED controllers. With no subnet, the server scans the networks it is connected to."
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          {found?.length ? (
            <Button variant="primary" onClick={() => add.mutate()} loading={add.isPending} disabled={!picked.size}>
              Add {picked.size || ''} device{picked.size === 1 ? '' : 's'}
            </Button>
          ) : null}
        </>
      }
    >
      <div className="space-y-4 pb-2">
        <form
          className="flex items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            scan.mutate();
          }}
        >
          <div className="flex-1">
            <Field label="Subnets (optional)">
              {(id) => <Input id={id} value={subnets} onChange={(e) => setSubnets(e.target.value)} placeholder="192.168.1.0/24" className="font-mono" />}
            </Field>
          </div>
          <Button type="submit" variant={found ? 'secondary' : 'primary'} loading={scan.isPending}>
            <Radar /> {found ? 'Scan again' : 'Scan'}
          </Button>
        </form>

        {scan.isPending ? (
          <div className="flex items-center gap-3 rounded-xl bg-stone-50 px-4 py-6 text-sm text-stone-500 dark:bg-stone-950/50">
            <Spinner /> Scanning. This can take up to 30 seconds.
          </div>
        ) : found ? (
          found.length ? (
            <ul className="divide-y divide-stone-100 rounded-xl ring-1 ring-stone-200 dark:divide-stone-800 dark:ring-stone-800">
              {found.map((f) => (
                <li key={f.host}>
                  <label className={cn('flex items-center gap-3 px-3 py-2.5', f.alreadyAdded ? 'opacity-60' : 'cursor-pointer')}>
                    <input
                      type="checkbox"
                      className="size-4 accent-stone-900 dark:accent-amber-400"
                      disabled={f.alreadyAdded}
                      checked={picked.has(f.host)}
                      onChange={(e) =>
                        setPicked((s) => {
                          const n = new Set(s);
                          e.target.checked ? n.add(f.host) : n.delete(f.host);
                          return n;
                        })
                      }
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{f.name}</span>
                      <span className="block font-mono text-xs text-stone-500">{f.host}</span>
                    </span>
                    {f.alreadyAdded ? <Badge>Added</Badge> : f.version ? <Badge tone="blue">WLED {f.version}</Badge> : null}
                  </label>
                </li>
              ))}
            </ul>
          ) : (
            <p className="rounded-xl bg-stone-50 px-4 py-6 text-center text-sm text-stone-500 dark:bg-stone-950/50">
              No WLED devices found. In Docker, the container needs host networking to scan your LAN.
            </p>
          )
        ) : null}
      </div>
    </Dialog>
  );
}
