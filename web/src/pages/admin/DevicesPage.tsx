import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { House, Plus, Radar, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import type { DeviceWithStatus, DiscoveredDevice } from '../../../../shared/types.ts';
import { Badge, Button, ConfirmDialog, Dialog, Field, Input, PageHeader, Spinner, Switch } from '../../components/ui.tsx';
import { api, type DeviceInput, type PresetImport } from '../../lib/api.ts';
import { cn, errorText } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';
import { DeviceTable } from './DeviceTable.tsx';
import { AddHaLightsDialog } from './HaLightDialogs.tsx';
import { HomeAssistantCard, useHomeAssistant } from './HomeAssistantCard.tsx';
import { DeviceSettingsCard } from './DeviceSettingsCard.tsx';
import { WledSettingsDialog } from './WledSettings.tsx';

export function DevicesPage() {
  const qc = useQueryClient();
  // Read often: a device's frame rate and Wi-Fi change between status checks.
  const { data, isLoading } = useOverview(10_000);
  const [editing, setEditing] = useState<DeviceWithStatus | 'new' | null>(null);
  const [deleting, setDeleting] = useState<DeviceWithStatus | null>(null);
  const [configuring, setConfiguring] = useState<DeviceWithStatus | null>(null);
  const [discovering, setDiscovering] = useState(false);
  const [addingHa, setAddingHa] = useState(false);
  const { data: ha } = useHomeAssistant();
  const haConnected = !!ha?.url && ha.hasToken;
  const refresh = () => qc.invalidateQueries({ queryKey: OVERVIEW });

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteDevice(id),
    onSuccess: () => {
      toast.success('Device removed');
      setDeleting(null);
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
  const enabled = devices.filter((d) => d.enabled);
  const online = enabled.filter((d) => d.online).length;
  const haLights = haConnected ? ha.lights.length : 0;

  return (
    <>
      <PageHeader
        title="Devices"
        description={
          devices.length || haLights
            ? `${online} of ${enabled.length} enabled WLED device(s) online${haLights ? `, and ${haLights} Home Assistant light(s)` : ''}. Status refreshes every few seconds.`
            : 'The WLED controllers and Home Assistant lights that this app controls.'
        }
        more={[
          { label: syncAll.isPending ? 'Importing presets…' : 'Import all presets', icon: RefreshCw, run: () => syncAll.mutate(), disabled: !enabled.length || syncAll.isPending },
          { label: 'Discover', icon: Radar, run: () => setDiscovering(true) },
          ...(haConnected ? [{ label: 'Add Home Assistant lights', icon: House, run: () => setAddingHa(true) }] : [])
        ]}
        actions={
          <Button variant="primary" onClick={() => setEditing('new')}>
            <Plus /> Add WLED device
          </Button>
        }
      />

      <DeviceTable
        devices={devices}
        presets={data?.devicePresets ?? {}}
        maxFps={data?.settings.maxFps ?? 30}
        debugHa={!!data?.settings.debugHa}
        loading={isLoading}
        onAdd={() => setEditing('new')}
        onDiscover={() => setDiscovering(true)}
        onEdit={setEditing}
        onConfigure={setConfiguring}
        onRemove={setDeleting}
      />
      <HomeAssistantCard devices={enabled} />
      <DeviceSettingsCard />

      {haConnected ? <AddHaLightsDialog open={addingHa} view={ha} onClose={() => setAddingHa(false)} /> : null}
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
