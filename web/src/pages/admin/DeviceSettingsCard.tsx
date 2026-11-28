import { useEffect, useState } from 'react';
import { FRAME_RATE } from '../../../../shared/types.ts';
import { Button, Card, CardHeader, Field, Input, Switch } from '../../components/ui.tsx';
import { useSettingsDraft } from './settingsDraft.ts';

const KEYS = ['maxFps', 'discoverySubnets', 'debugHa'] as const;
const subnetList = (text: string) =>
  text
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);

/**
 * Admin → Devices: how the server talks to the devices. The frame rate they get, where
 * Discover looks for WLED controllers, and the Home Assistant lights' command times.
 */
export function DeviceSettingsCard() {
  const s = useSettingsDraft(KEYS, (v) => ({ ...v, maxFps: Math.min(FRAME_RATE.max, Math.max(FRAME_RATE.min, Math.round(v.maxFps) || FRAME_RATE.default)) }));
  // The subnets are kept as typed text until saved.
  const [subnets, setSubnets] = useState<string | null>(null);
  const saved = s.value?.discoverySubnets.join(', ') ?? '';
  useEffect(() => {
    if (!s.dirty) setSubnets(null);
  }, [s.dirty]);
  if (!s.value) return null;
  const v = s.value;

  return (
    <Card className="mt-6">
      <CardHeader
        title="Sending to devices"
        description="How the server talks to the lights."
        actions={
          s.dirty ? (
            <>
              <Button variant="ghost" onClick={s.undo}>
                Undo
              </Button>
              <Button variant="primary" onClick={s.save} loading={s.saving}>
                Save
              </Button>
            </>
          ) : null
        }
      />
      <div className="grid gap-5 p-5 sm:grid-cols-2">
        <Field
          label="Frame rate (frames a second, at most)"
          hint={`What WLED devices get while effects, sequences, games and the editors' previews play: ${FRAME_RATE.min} to ${FRAME_RATE.max}. Fewer leave a device more room; one whose strip is too long for this many, or that falls behind, gets fewer.`}
        >
          {(id) => (
            <Input
              id={id}
              type="number"
              inputMode="numeric"
              min={FRAME_RATE.min}
              max={FRAME_RATE.max}
              step={1}
              value={Number.isFinite(v.maxFps) ? v.maxFps : ''}
              onChange={(e) => s.set('maxFps', e.target.value === '' ? NaN : Math.round(Number(e.target.value)))}
            />
          )}
        </Field>
        <Field label="Subnets to discover" hint="Where Discover looks for WLED devices: CIDR ranges, comma-separated. Empty: the server's own networks. DISCOVERY_SUBNETS in the environment overrides this.">
          {(id) => (
            <Input
              id={id}
              value={subnets ?? saved}
              onChange={(e) => (setSubnets(e.target.value), s.set('discoverySubnets', subnetList(e.target.value)))}
              placeholder="192.168.1.0/24"
              className="font-mono"
            />
          )}
        </Field>
        <label className="flex items-center justify-between gap-4 sm:col-span-2">
          <span>
            <span className="block text-sm font-medium">Show Home Assistant command times</span>
            <span className="block text-xs text-stone-500">
              For finding out why a light is slow: under each Home Assistant light, how long it takes to answer, how many commands are on their way or waiting, and how many came late or failed, counted from when this is switched on.
            </span>
          </span>
          <Switch label="Show Home Assistant command times" checked={v.debugHa} onChange={(x) => s.set('debugHa', x)} />
        </label>
      </div>
    </Card>
  );
}
