import { RotateCcw } from 'lucide-react';
import type { DeviceWithStatus } from '../../../../shared/types.ts';
import { LevelSlider, PowerButton, useLightControls, useLightMutations } from '../../components/LightControls.tsx';
import { Card, CardHeader, Spinner } from '../../components/ui.tsx';
import { cn, relativeTime } from '../../lib/utils.ts';

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
  const enabled = devices.filter((d) => d.enabled);
  if (!enabled.length) return null;
  if (!controls) {
    return (
      <Card className="mb-6 grid place-items-center py-10">
        <Spinner />
      </Card>
    );
  }
  const off = new Set(controls.off);
  const isOn = (d: DeviceWithStatus) => (d.power ? d.power.on : !off.has(d.id));
  // Lights that answer say how they are; an offline one cannot.
  const reachable = enabled.filter((d) => d.online !== false);
  const offline = enabled.length - reachable.length;
  const lit = reachable.filter(isOn).length;
  const allOff = reachable.length ? lit === 0 : enabled.every((d) => off.has(d.id));
  const all = controls.brightness.all;
  const summary = !reachable.length ? 'Offline' : allOff ? 'Off' : lit < reachable.length ? `${reachable.length - lit} of ${reachable.length} off` : 'On';

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
              {offline && reachable.length ? <span className="text-red-600 dark:text-red-400">{` · ${offline} offline`}</span> : null}
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
          const gone = d.online === false;
          const on = !gone && isOn(d);
          const own = controls.brightness.devices[d.id];
          return (
            <li key={d.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 sm:px-5">
              <PowerButton size="sm" on={on} label={gone ? `${d.name} (offline)` : d.name} disabled={power.isPending || gone} onToggle={() => power.mutate({ on: !on, deviceId: d.id })} />
              <span className={cn('min-w-28 flex-1 truncate text-sm font-medium sm:flex-none sm:basis-40', !on && 'text-stone-400')}>{d.name}</span>
              {gone ? (
                <span className="min-w-48 flex-1 text-sm text-red-600 dark:text-red-400">
                  Offline{d.lastSeen ? <span className="text-stone-500 dark:text-stone-400">{` · last seen ${relativeTime(d.lastSeen)}`}</span> : null}
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
      </ul>
    </Card>
  );
}
