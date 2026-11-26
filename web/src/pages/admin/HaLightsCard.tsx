import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { House, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { haId, type HaEntity, type HaView } from '../../../../shared/homeAssistant.ts';
import { Badge, Button, Card, CardHeader, Dialog, Empty, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { errorText } from '../../lib/utils.ts';
import { OVERVIEW } from './AdminLayout.tsx';
import { EntityIcon, EntityTable, kindOf } from './EntityTable.tsx';
import { HA, useHomeAssistant } from './HomeAssistantCard.tsx';

/** Saves the Home Assistant lights in use, with the caches they touch kept fresh. */
function useSaveLights() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (lights: string[]) => api.saveHaLights(lights),
    onSuccess: (v: HaView) => {
      qc.setQueryData(HA, v);
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      void qc.invalidateQueries({ queryKey: ['admin', 'lights'] });
    },
    onError: (e) => toast.error(errorText(e))
  });
}

/**
 * Home Assistant lights the site controls, as devices: added from Home Assistant's lights and
 * switches, each with where it is and what it does. In the layout, any object can be one of
 * them (its Device), so effects and games reach it too.
 */
export function HaLightsCard({ adding, onAdding }: { adding: boolean; onAdding: (v: boolean) => void }) {
  const { data: ha } = useHomeAssistant();
  const { data: layout } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const save = useSaveLights();
  const connected = !!ha?.url && ha.hasToken;
  if (!ha) return null;

  const byId = new Map(ha.entities.map((e) => [e.id, e]));
  const objectsOf = (id: string) => (layout?.fixtures ?? []).filter((f) => f.deviceId === haId(id)).map((f) => f.name);

  return (
    <Card className="mt-6">
      <CardHeader
        title="Home Assistant lights"
        description="Lights from Home Assistant that the site controls: they switch with all lights and the schedule, take scene and visitor colors, and in the layout any object can be one (its Device)."
        actions={
          connected ? (
            <Button size="sm" onClick={() => onAdding(true)}>
              <Plus /> Add lights
            </Button>
          ) : null
        }
      />
      {!connected ? (
        <Empty icon={<House />} title="Home Assistant is not connected">
          Connect it under <Link to="/admin/settings" className="font-medium text-stone-900 underline underline-offset-2 dark:text-white">Settings → Home Assistant</Link>, then add its lights here.
        </Empty>
      ) : !ha.lights.length ? (
        <Empty
          icon={<House />}
          title="No Home Assistant lights yet"
          action={
            <Button variant="primary" onClick={() => onAdding(true)}>
              <Plus /> Add lights
            </Button>
          }
        >
          Pick lights and switches from Home Assistant to control them with the yard.
        </Empty>
      ) : (
        <ul className="divide-y divide-stone-100 dark:divide-stone-800">
          {ha.lights.map((id) => {
            const e = byId.get(id);
            const objects = objectsOf(id);
            return (
              <li key={id} className="flex items-center gap-3 py-3 pr-2 pl-4 sm:px-5">
                {e ? <EntityIcon e={e} className="size-5" /> : null}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate font-medium">{e?.name ?? id}</span>
                    {!e ? <Badge tone="amber">Not in Home Assistant</Badge> : e.state === 'unavailable' ? <Badge tone="red">Unavailable</Badge> : null}
                  </div>
                  <p className="mt-0.5 flex flex-wrap gap-x-3 text-sm text-stone-500 dark:text-stone-400">
                    <span className="font-mono text-[13px]">{id}</span>
                    {e?.area ? <span>{e.area}</span> : null}
                    {e ? <span>{kindOf(e) === 'light' ? (e.color ? 'Color' : e.dimmable ? 'Dims' : 'On and off') : 'On and off'}</span> : null}
                    <span>{objects.length ? `In the layout: ${objects.join(', ')}` : 'Not in the layout'}</span>
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={`Remove ${e?.name ?? id}`}
                  className="hover:text-red-600 dark:hover:text-red-400"
                  disabled={save.isPending}
                  onClick={() => save.mutate(ha.lights.filter((x) => x !== id), { onSuccess: () => toast.success(`${e?.name ?? id} removed`) })}
                >
                  <Trash2 />
                </Button>
              </li>
            );
          })}
        </ul>
      )}
      {connected ? <AddHaLightsDialog open={adding} view={ha} onClose={() => onAdding(false)} /> : null}
    </Card>
  );
}

/** Home Assistant's lights and switches, to pick the ones the site controls. Each switch saves at once. */
function AddHaLightsDialog({ open, view, onClose }: { open: boolean; view: HaView; onClose: () => void }) {
  const save = useSaveLights();
  const [busy, setBusy] = useState<string | null>(null);
  const plugs = new Set(Object.values(view.plugs));
  const toggle = (e: HaEntity, on: boolean) => {
    setBusy(e.id);
    save.mutate(on ? [...view.lights, e.id] : view.lights.filter((x) => x !== e.id), { onSettled: () => setBusy(null) });
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="xl"
      title="Add Home Assistant lights"
      description="Switch on the ones the site should control. Then, to place one in the yard, pick it as an object's Device in the layout."
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {open ? (
        <div className="pb-2">
          <EntityTable
            entities={view.entities}
            initialKind="light"
            used={(e) => view.lights.includes(e.id)}
            usedLabel={`Added (${view.lights.length})`}
            action={(e) =>
              plugs.has(e.id) ? (
                <span className="text-xs text-stone-500">Power plug</span>
              ) : (
                <Switch label={`Control ${e.name}`} checked={view.lights.includes(e.id)} disabled={save.isPending || busy === e.id} onChange={(on) => toggle(e, on)} />
              )
            }
          />
        </div>
      ) : null}
    </Dialog>
  );
}
