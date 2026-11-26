import { House, RotateCcw } from 'lucide-react';
import type { DeviceWithStatus } from '../../../../shared/types.ts';
import { LevelSlider, PowerButton, useLightControls, useLightMutations } from '../../components/LightControls.tsx';
import { Card, CardHeader, Spinner } from '../../components/ui.tsx';
import { cn, relativeTime } from '../../lib/utils.ts';
import { haId } from '../../../../shared/homeAssistant.ts';
import { useHomeAssistant } from './HomeAssistantCard.tsx';

/** WLED's brightness (1 to 255) in percent, as the switches count it. */
const percent = (bri: number) => Math.max(1, Math.round((bri / 255) * 100));

/**
 * Power and brightness for every light, and for each device. Off holds: scenes, colors, games
 * and the auto-revert leave a switched-off light dark until it is switched on here. Each device
 * shows what it reports itself (the server follows changes made in WLED's own app, too), and
 * one that does not answer shows as offline.
 */
export function LightsCard({ devices }: { devices: DeviceWithStatus[] }) {
  const { data: controls } = useLightControls();
  const { power, brightness } = useLightMutations();
  const { data: ha } = useHomeAssistant();
  const enabled = devices.filter((d) => d.enabled);
  // Home Assistant's lights that switch with these (see HaSettings).
  const haLights = ha?.url && ha.hasToken ? ha.lights.map((id) => ha.entities.find((e) => e.id === id) ?? { id, name: id, state: 'unknown', color: false, dimmable: false }) : [];
  if (!enabled.length && !haLights.length) return null;
  if (!controls) {
    return (
      <Card className="mb-6 grid place-items-center py-10">
        <Spinner />
      </Card>
    );
  }
  const off = new Set(controls.off);
  const isOn = (d: DeviceWithStatus) => (d.power ? d.power.on : !off.has(d.id));
  // A device whose plug is off does not answer, and that is as it should be.
  const unplugged = (d: DeviceWithStatus) => d.online === false && !!d.plug && d.plug.on === false;
  const haOn = (id: string, state: string) => (state === 'on' ? true : state === 'off' ? false : !off.has(haId(id)));
  // Lights that answer say how they are; an offline one cannot.
  const reachable = enabled.filter((d) => d.online !== false || unplugged(d));
  const haReachable = haLights.filter((e) => e.state !== 'unavailable');
  const offline = enabled.length - reachable.length + haLights.length - haReachable.length;
  const lit = reachable.filter((d) => !unplugged(d) && isOn(d)).length + haReachable.filter((e) => haOn(e.id, e.state)).length;
  const total = reachable.length + haReachable.length;
  const allOff = total ? lit === 0 : [...enabled.map((d) => d.id), ...haLights.map((e) => haId(e.id))].every((id) => off.has(id));
  const all = controls.brightness.all;
  const summary = !total ? 'Offline' : allOff ? 'Off' : lit < total ? `${total - lit} of ${total} off` : 'On';

  return (
    <Card className="mb-6">
      <CardHeader
        title="Lights"
        description={
          allOff
            ? 'Every light is off. Visitors cannot change them, games cannot start, and the auto-revert waits, until you switch them on.'
            : 'Switch the lights on or off and set how bright they are. A light switched off stays off through scenes, colors and games.'
        }
      />
      <div className="px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
          <PowerButton on={!allOff} label="All lights" disabled={power.isPending} onToggle={() => power.mutate({ on: allOff })} />
          <div className="min-w-0">
            <p className="font-medium">All lights</p>
            <p className="text-sm text-stone-500 dark:text-stone-400">
              {summary}
              {offline && total ? <span className="text-red-600 dark:text-red-400">{` · ${offline} offline`}</span> : null}
            </p>
          </div>
          <LevelSlider className="min-w-56 flex-1" label="Brightness of all lights" value={all} onCommit={(level) => brightness.mutate({ level })} />
          {all != null ? (
            <button
              type="button"
              onClick={() => brightness.mutate({ level: null })}
              className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-stone-500 hover:bg-stone-100 hover:text-stone-800 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white"
              title="Each scene's presets set the brightness again"
            >
              <RotateCcw className="size-3.5" /> Let scenes decide
            </button>
          ) : null}
        </div>
      </div>
      <ul className="divide-y divide-stone-100 border-t border-stone-100 dark:divide-stone-800 dark:border-stone-800">
        {enabled.map((d) => {
          const asleep = unplugged(d);
          const gone = d.online === false && !asleep;
          const on = !gone && !asleep && isOn(d);
          const own = controls.brightness.devices[d.id];
          return (
            <li key={d.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 sm:px-5">
              <PowerButton
                size="sm"
                on={on}
                label={gone ? `${d.name} (offline)` : d.name}
                // A device with a plug can be switched on or off even when it does not answer.
                disabled={power.isPending || (gone && !d.plug)}
                onToggle={() => power.mutate({ on: gone && d.plug ? off.has(d.id) : !on, deviceId: d.id })}
              />
              <span className={cn('min-w-28 flex-1 truncate text-sm font-medium sm:flex-none sm:basis-40', !on && 'text-stone-400')}>{d.name}</span>
              {asleep ? (
                <span className="min-w-48 flex-1 text-sm text-stone-500 dark:text-stone-400">Power off at {d.plug!.name}</span>
              ) : gone ? (
                <span className="min-w-48 flex-1 text-sm text-red-600 dark:text-red-400">
                  {d.plug && !off.has(d.id) ? 'Starting up, or offline' : 'Offline'}
                  {d.lastSeen ? <span className="text-stone-500 dark:text-stone-400">{` · last seen ${relativeTime(d.lastSeen)}`}</span> : null}
                </span>
              ) : (
                <LevelSlider
                  className="min-w-48 flex-1"
                  label={`Brightness of ${d.name}`}
                  value={d.power ? percent(d.power.bri) : (own ?? all)}
                  disabled={!on}
                  onCommit={(level) => brightness.mutate({ level, deviceId: d.id })}
                />
              )}
              {own != null && !gone ? (
                <button
                  type="button"
                  onClick={() => brightness.mutate({ level: null, deviceId: d.id })}
                  className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-stone-500 hover:bg-stone-100 hover:text-stone-800 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white"
                  title="Follow the brightness of all lights"
                >
                  <RotateCcw className="size-3.5" /> Own level
                </button>
              ) : (
                <span className="w-[5.5rem]" />
              )}
            </li>
          );
        })}
        {haLights.map((e) => {
          const id = haId(e.id);
          const gone = e.state === 'unavailable';
          const on = !gone && haOn(e.id, e.state);
          const own = controls.brightness.devices[id];
          return (
            <li key={id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 sm:px-5">
              <PowerButton size="sm" on={on} label={e.name} disabled={power.isPending || gone} onToggle={() => power.mutate({ on: !on, deviceId: id })} />
              <span className={cn('flex min-w-28 flex-1 items-center gap-1.5 text-sm font-medium sm:flex-none sm:basis-40', !on && 'text-stone-400')} title={`${e.id} in Home Assistant`}>
                <span className="truncate">{e.name}</span>
                <House className="size-3.5 shrink-0 text-stone-400" aria-label="Home Assistant" />
              </span>
              {gone ? (
                <span className="min-w-48 flex-1 text-sm text-red-600 dark:text-red-400">Unavailable in Home Assistant</span>
              ) : e.dimmable ? (
                <LevelSlider className="min-w-48 flex-1" label={`Brightness of ${e.name}`} value={own ?? all} disabled={!on} onCommit={(level) => brightness.mutate({ level, deviceId: id })} />
              ) : (
                <span className="min-w-48 flex-1 text-sm text-stone-500 dark:text-stone-400">On or off · Home Assistant</span>
              )}
              {own != null && !gone && e.dimmable ? (
                <button
                  type="button"
                  onClick={() => brightness.mutate({ level: null, deviceId: id })}
                  className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-stone-500 hover:bg-stone-100 hover:text-stone-800 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-white"
                  title="Follow the brightness of all lights"
                >
                  <RotateCcw className="size-3.5" /> Own level
                </button>
              ) : (
                <span className="w-[5.5rem]" />
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
