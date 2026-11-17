import type { ApplyResult, Device, DeviceInfo, DeviceWithStatus, LogLevel, PublicState } from '../../shared/types.ts';
import type { Db } from './db.ts';
import type { Bus } from './events.ts';
import { KEY, readSettings } from './settings.ts';
import { hexToRgb, wled, type FetchResult } from './wled.ts';
import { mergeLooks, type PresetLook } from './presetLook.ts';

export type PresetImport = { deviceId: string; ok: true; count: number } | { deviceId: string; ok: false; error: string };

export interface Actor {
  ip?: string | null;
  userAgent?: string | null;
}

interface Status {
  online: boolean;
  /** Checks in a row that got no answer. One miss is not enough to call a device offline. */
  misses?: number;
  info: DeviceInfo | null;
  lastSeen: string | null;
}

/**
 * Owns everything that talks to the lights: applying scenes and colors, the auto-revert
 * timer, and the device status monitor. One instance per process.
 */
export class Lights {
  private status = new Map<string, Status>();
  private revertTimer: NodeJS.Timeout | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private db: Db;
  private bus: Bus;

  constructor(db: Db, bus: Bus) {
    this.db = db;
    this.bus = bus;
  }

  log(level: LogLevel, action: string, message: string, details?: unknown, actor?: Actor) {
    const line = `[${level.toUpperCase()}] ${action}: ${message}`;
    (level === 'error' ? console.error : console.log)(line);
    try {
      this.db.addLog({ level, action, message, details, clientIp: actor?.ip ?? 'server', userAgent: actor?.userAgent ?? 'system' });
      this.bus.emit('log', null);
    } catch (e) {
      console.error('Could not write log:', (e as Error).message);
    }
  }

  // ---------- Status monitor ----------

  start(intervalMs: number) {
    void this.refreshStatus();
    this.pollTimer = setInterval(() => void this.refreshStatus(), intervalMs);
    this.restoreRevertTimer();
  }

  stop() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.revertTimer) clearTimeout(this.revertTimer);
  }

  async refreshStatus(): Promise<void> {
    const devices = this.db.listDevices().filter((d) => d.enabled);
    // A device busy with real-time frames over Wi-Fi can answer slowly; allow 3 s.
    const results = await Promise.all(devices.map((d) => wled.info(d, 3000)));
    let changed = false;
    const seen = new Set<string>();
    devices.forEach((d, i) => {
      seen.add(d.id);
      const r = results[i];
      const prev = this.status.get(d.id);
      const misses = r.ok ? 0 : (prev?.misses ?? 0) + 1;
      const next: Status = r.ok
        ? { online: true, misses, info: r.data, lastSeen: new Date().toISOString() }
        : // Offline only after two missed checks in a row, so one slow answer does not flash "offline".
          { online: prev?.online === true && misses < 2, misses, info: prev?.info ?? null, lastSeen: prev?.lastSeen ?? null };
      if (!prev || prev.online !== next.online) changed = true;
      this.status.set(d.id, next);
    });
    for (const id of this.status.keys()) {
      if (!seen.has(id)) {
        this.status.delete(id);
        changed = true;
      }
    }
    if (changed) {
      this.bus.emit('state');
      this.bus.emit('devices');
    }
  }

  devicesWithStatus(): DeviceWithStatus[] {
    return this.db.listDevices().map((d) => {
      const s = this.status.get(d.id);
      return { ...d, online: d.enabled ? (s?.online ?? null) : null, info: s?.info ?? null, lastSeen: s?.lastSeen ?? null };
    });
  }

  publicState(): PublicState {
    const settings = readSettings(this.db);
    const enabled = this.db.listDevices().filter((d) => d.enabled);
    const isOnline = (id: string) => this.status.get(id)?.online === true;
    const enabledIds = new Set(enabled.map((d) => d.id));
    const presets = this.db.listDevicePresets();
    const scenes = this.db.listScenes().map((s) => {
      const mapped = Object.keys(s.devicePresets).filter((id) => enabledIds.has(id));
      const looks: PresetLook[] = [];
      for (const deviceId of mapped) {
        const p = presets[deviceId]?.find((x) => x.id === s.devicePresets[deviceId]);
        if (p?.colors?.length) looks.push({ colors: p.colors, energy: p.energy ?? 0.3 });
      }
      const look = mergeLooks(looks);
      return { id: s.id, name: s.name, online: mapped.length === 0 ? false : mapped.some(isOnline), palette: look.colors, energy: look.energy };
    });
    const onlineDevices = enabled.filter((d) => isOnline(d.id)).length;
    return {
      title: settings.siteTitle,
      subtitle: settings.siteSubtitle,
      showColors: settings.showColors,
      scenes,
      currentSceneId: this.db.getSetting(KEY.currentScene) || null,
      currentColor: this.db.getSetting(KEY.currentColor) || null,
      anyOnline: onlineDevices > 0,
      onlineDevices,
      totalDevices: enabled.length,
      revertAt: this.db.getSetting(KEY.revertAt) || null
    };
  }

  // ---------- Commands ----------

  private async fanOut(work: { device: Device; run: () => Promise<FetchResult<unknown>> }[]): Promise<ApplyResult> {
    const results = await Promise.all(work.map((w) => w.run()));
    const out: ApplyResult = { applied: [], skipped: [], failed: [] };
    results.forEach((r, i) => {
      const id = work[i].device.id;
      if (r.ok) out.applied.push(id);
      else out.failed.push({ deviceId: id, error: r.error });
      // A command result is fresh evidence of the device status.
      const prev = this.status.get(id);
      if (prev && prev.online !== r.ok) {
        this.status.set(id, { ...prev, online: r.ok });
      }
    });
    return out;
  }

  async applyScene(sceneId: string, actor?: Actor, reason: 'user' | 'revert' = 'user'): Promise<ApplyResult | null> {
    const scene = this.db.getScene(sceneId);
    if (!scene) return null;
    const devices = this.db.listDevices().filter((d) => d.enabled);
    const work = [];
    const skipped: string[] = [];
    for (const device of devices) {
      const presetId = scene.devicePresets[device.id];
      if (!presetId) skipped.push(device.id);
      else work.push({ device, run: () => wled.applyPreset(device, presetId) });
    }
    const result = await this.fanOut(work);
    result.skipped = skipped;

    if (result.applied.length > 0) {
      this.db.setSetting(KEY.currentScene, scene.id);
      this.db.setSetting(KEY.currentColor, '');
      const { defaultSceneId } = readSettings(this.db);
      if (scene.id === defaultSceneId) this.cancelRevert();
      else this.scheduleRevert();
    }
    this.log(
      result.applied.length ? (result.failed.length ? 'warn' : 'info') : 'error',
      reason === 'revert' ? 'auto_revert' : 'applied',
      `Scene "${scene.name}" applied to ${result.applied.length}/${work.length} device(s)`,
      { sceneId: scene.id, sceneName: scene.name, ...result },
      actor
    );
    this.bus.emit('state');
    return result;
  }

  async applyColor(hex: string, actor?: Actor): Promise<ApplyResult | null> {
    const rgb = hexToRgb(hex);
    if (!rgb) return null;
    const color = `#${hex.replace('#', '').toLowerCase()}`;
    const devices = this.db.listDevices().filter((d) => d.enabled);
    const result = await this.fanOut(devices.map((device) => ({ device, run: () => wled.applyColor(device, rgb) })));
    if (result.applied.length > 0) {
      this.db.setSetting(KEY.currentScene, '');
      this.db.setSetting(KEY.currentColor, color);
      this.scheduleRevert();
    }
    this.log(
      result.applied.length ? (result.failed.length ? 'warn' : 'info') : 'error',
      'applied',
      `Color ${color} applied to ${result.applied.length}/${devices.length} device(s)`,
      { color, ...result },
      actor
    );
    this.bus.emit('state');
    return result;
  }

  // ---------- Device presets ----------

  /** Reads presets.json from a device and stores the list. Never throws. */
  async importPresets(deviceId: string): Promise<PresetImport> {
    const device = this.db.getDevice(deviceId);
    if (!device) return { deviceId, ok: false, error: 'Unknown device' };
    const r = await wled.presets(device);
    if (!r.ok) return { deviceId, ok: false, error: r.error };
    this.db.replaceDevicePresets(device.id, r.data);
    this.bus.emit('devices');
    return { deviceId, ok: true, count: r.data.length };
  }

  /** Imports presets for newly added devices and logs one line with the outcome. */
  async importPresetsForNew(deviceIds: string[], actor?: Actor): Promise<PresetImport[]> {
    if (!deviceIds.length) return [];
    const results = await Promise.all(deviceIds.map((id) => this.importPresets(id)));
    const ok = results.filter((r) => r.ok);
    const total = ok.reduce((n, r) => n + (r.ok ? r.count : 0), 0);
    this.log(
      ok.length === results.length ? 'info' : 'warn',
      'import',
      `Imported ${total} preset(s) from ${ok.length}/${results.length} new device(s)`,
      results,
      actor
    );
    return results;
  }

  // ---------- Auto-revert ----------
  // The revert time is stored, so a restart does not lose a pending revert.

  scheduleRevert() {
    const { revertMinutes, defaultSceneId } = readSettings(this.db);
    if (revertMinutes <= 0 || !defaultSceneId) return this.cancelRevert();
    const at = new Date(Date.now() + revertMinutes * 60_000);
    this.db.setSetting(KEY.revertAt, at.toISOString());
    this.armRevert(at);
    this.log('info', 'auto_revert', `Scheduled in ${revertMinutes} minute(s)`);
  }

  cancelRevert() {
    if (this.revertTimer) clearTimeout(this.revertTimer);
    this.revertTimer = null;
    if (this.db.getSetting(KEY.revertAt)) this.db.setSetting(KEY.revertAt, '');
  }

  /** Call after settings change. A pending revert restarts with the new values. */
  onSettingsChanged() {
    if (this.db.getSetting(KEY.revertAt)) this.scheduleRevert();
    this.bus.emit('state');
  }

  private armRevert(at: Date) {
    if (this.revertTimer) clearTimeout(this.revertTimer);
    const ms = Math.max(0, at.getTime() - Date.now());
    this.revertTimer = setTimeout(() => void this.revertNow(), Math.min(ms, 2 ** 31 - 1));
  }

  private restoreRevertTimer() {
    const at = this.db.getSetting(KEY.revertAt);
    if (at && !Number.isNaN(Date.parse(at))) this.armRevert(new Date(at));
  }

  private async revertNow() {
    this.revertTimer = null;
    this.db.setSetting(KEY.revertAt, '');
    const { defaultSceneId } = readSettings(this.db);
    if (!defaultSceneId || !this.db.getScene(defaultSceneId)) {
      this.log('warn', 'auto_revert', 'Default scene is not set or no longer exists');
      this.bus.emit('state');
      return;
    }
    await this.applyScene(defaultSceneId, undefined, 'revert');
  }
}
