import type { HaSpeedResult } from '../../shared/homeAssistant.ts';
import { hsvBytes } from '../../shared/color.ts';
import type { HomeAssistant } from './homeAssistant.ts';

/**
 * Plays a rainbow on one Home Assistant light for a few seconds, asking for `fps` colors a
 * second, as HaFrames does: up to `inflight` commands on their way at once, a fade as long as
 * the gap (or none). It
 * says how many colors the light took and how long each took, so the rate for the layout can
 * be set to what the light (and its Zigbee network) can do. Afterwards, a light that was off
 * goes off again.
 */
export async function haSpeedTest(
  ha: HomeAssistant,
  entity: string,
  { fps, seconds, via, inflight = 1, fade = true }: { fps: number; seconds: number; via: 'ws' | 'rest'; inflight?: number; fade?: boolean }
): Promise<HaSpeedResult> {
  const wasOff = ha.entity(entity)?.state === 'off';
  const every = 1000 / fps;
  const transition = fade ? Math.round(every / 100) / 10 : 0;
  const latencies: number[] = [];
  let sent = 0;
  let waited = 0;
  let errors = 0;
  let error: string | undefined;
  let busy = 0;
  const start = performance.now();
  // One rainbow every three seconds: each color is far from the last, so every one shows.
  const tick = () => {
    if (busy >= inflight) return void waited++;
    busy++;
    const t = (performance.now() - start) / 1000;
    const rgb = hsvBytes((t / 3) % 1, 1);
    const at = performance.now();
    void ha
      .set(entity, true, { rgb: [rgb[0], rgb[1], rgb[2]], bri: sent === 0 ? 255 : null, transition, via })
      .then((r) => {
        latencies.push(performance.now() - at);
        sent++;
        if (!r.ok) {
          errors++;
          error ??= r.error;
        }
      })
      .finally(() => busy--);
  };
  tick();
  await new Promise<void>((resolve) => {
    const timer = setInterval(tick, every);
    setTimeout(() => {
      clearInterval(timer);
      resolve();
    }, seconds * 1000);
  });
  // The last command still on its way.
  for (let i = 0; busy > 0 && i < 100; i++) await new Promise((r) => setTimeout(r, 50));
  if (wasOff) await ha.set(entity, false, { via });
  const sorted = [...latencies].sort((a, b) => a - b);
  const pct = (p: number) => Math.round(sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))] ?? 0);
  return {
    entity,
    via,
    inflight,
    fade,
    fps,
    seconds,
    sent,
    waited,
    errors,
    ...(error ? { error } : {}),
    achieved: Math.round((sent / seconds) * 10) / 10,
    latency: { avg: Math.round(sorted.reduce((a, b) => a + b, 0) / (sorted.length || 1)), p50: pct(0.5), p95: pct(0.95), max: Math.round(sorted.at(-1) ?? 0) }
  };
}
