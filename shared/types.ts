// Types shared by the server and the web client. Keep this file free of runtime code
// that depends on Node or the DOM.

import type { EffectSettings } from './effects.ts';

export interface Device {
  id: string;
  name: string;
  host: string;
  port: number;
  enabled: boolean;
}

export interface DeviceWithStatus extends Device {
  online: boolean | null; // null = not checked yet
  info: DeviceInfo | null;
  lastSeen: string | null;
}

/** Subset of WLED /json/info that the UI shows. */
export interface DeviceInfo {
  ver?: string;
  name?: string;
  mac?: string;
  arch?: string;
  leds?: { count?: number };
  /** Port for real-time UDP. */
  udpport?: number;
  /** Not in real WLED (it always uses 4048): the DDP port of a fake device in development. */
  ddpport?: number;
  wifi?: { signal?: number };
}

/** A preset stored on a WLED device (from /presets.json). */
export interface DevicePreset {
  id: number;
  name: string;
  /** Colors the preset shows, as hex. Empty when unknown. */
  colors?: string[];
  /** 0 = still, 1 = fast and intense. */
  energy?: number;
}

/**
 * A button on the public page. It plays a WLED preset on each device, and/or effects that the
 * server draws for layout objects (saved from the layout editor). A device with an object that
 * plays an effect gets the effect, not its preset.
 */
export interface Scene {
  id: string;
  name: string;
  sortOrder: number;
  /** deviceId -> WLED preset id */
  devicePresets: Record<string, number>;
  /** Effect key (see effectKey: "*", an object id, or "<object id>#<segment>") -> the effect it plays. */
  effects?: Record<string, EffectSettings>;
  /** A sequence that plays (and loops) on the lights instead of the effects. */
  sequenceId?: string | null;
}

/** An uploaded audio file, for the sequence editor. */
export interface AudioFile {
  id: string;
  name: string;
  type: string;
  size: number;
  createdAt: string;
}

export interface Settings {
  siteTitle: string;
  siteSubtitle: string;
  defaultSceneId: string | null;
  revertMinutes: number;
  discoverySubnets: string[];
  showColors: boolean;
}

export interface PublicScene {
  id: string;
  name: string;
  online: boolean;
  /** Colors of the presets this scene plays, as hex. Empty when unknown. */
  palette: string[];
  /** 0 = still, 1 = fast and intense. */
  energy: number;
}

export interface PublicState {
  title: string;
  subtitle: string;
  showColors: boolean;
  scenes: PublicScene[];
  currentSceneId: string | null;
  currentColor: string | null;
  anyOnline: boolean;
  onlineDevices: number;
  totalDevices: number;
  revertAt: string | null;
}

export interface ApplyResult {
  /** Devices that took the scene: their preset, or the effects stream. */
  applied: string[];
  /** Layout objects that play an effect now (including objects with no device: simulator only). */
  effects?: number;
  skipped: string[];
  failed: { deviceId: string; error: string }[];
}

export type LogLevel = 'info' | 'warn' | 'error';

export interface LogEntry {
  id: number;
  timestamp: string;
  level: LogLevel;
  action: string;
  message: string;
  clientIp: string | null;
  userAgent: string | null;
  details: unknown;
}

export interface DiscoveredDevice {
  host: string;
  port: number;
  name: string;
  version: string | null;
  alreadyAdded: boolean;
}

export interface SessionInfo {
  user: { id: string; username: string } | null;
  needsBootstrap: boolean;
}

export interface BackupFile {
  version: 1 | 2;
  exportedAt: string;
  publicPresets: { id: string; name: string; sortOrder?: number; devicePresets: Record<string, number>; effects?: Record<string, EffectSettings>; sequenceId?: string | null }[];
}
