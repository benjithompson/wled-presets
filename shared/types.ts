// Types shared by the server and the web client. Keep this file free of runtime code
// that depends on Node or the DOM.

import type { EffectSettings } from './effects.ts';
import type { SceneTransitionChoice } from './transitions.ts';
import type { Playlist } from './playlist.ts';

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
  /**
   * What the device itself reports now: on or off, and its brightness (1 to 255; when off, the
   * level it comes back on at). Null while it is offline, or has not said yet.
   */
  power: { on: boolean; bri: number } | null;
  /** The Home Assistant plug that powers it, and whether it is on (null: unknown). */
  plug?: { entity: string; name: string; on: boolean | null };
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
  /**
   * Not in /json/info: the device's LED outputs, from /json/cfg (LEDs on each and their LED
   * type, as WLED numbers it). They set how fast the device can show frames.
   */
  outputs?: { len: number; type: number }[];
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
  /** Effect key (see effectKey: "*", "@<device id>", an object id, or "<object id>#<segment>") -> the effect it plays. */
  effects?: Record<string, EffectSettings>;
  /** A sequence that plays (and loops) on the lights instead of the effects. */
  sequenceId?: string | null;
  /** A playlist: the scene plays other scenes one after another, and nothing of its own. */
  playlist?: Playlist | null;
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
  /**
   * How the lights go from one scene to the next when someone picks a scene: a transition,
   * "random" (a different one each time), or "none" (at once). Effects and sequences, which the
   * server draws, transition; a device that plays a WLED preset changes as WLED does.
   */
  sceneTransition: SceneTransitionChoice;
  /** How long the transition takes, in seconds. */
  sceneTransitionSeconds: number;
}

export interface PublicScene {
  id: string;
  name: string;
  online: boolean;
  /** Colors of the presets this scene plays, as hex. Empty when unknown. */
  palette: string[];
  /** 0 = still, 1 = fast and intense. */
  energy: number;
  /** A playlist: it plays other scenes in turn. */
  playlist?: boolean;
}

export interface PublicState {
  title: string;
  subtitle: string;
  showColors: boolean;
  scenes: PublicScene[];
  currentSceneId: string | null;
  currentColor: string | null;
  /** When the current scene is a playlist: the scene of it that plays now. */
  playlistSceneId?: string | null;
  anyOnline: boolean;
  onlineDevices: number;
  totalDevices: number;
  revertAt: string | null;
  /** An admin switched every light off: nothing plays until one switches them on again. */
  lightsOff: boolean;
  /** While the lights are off: when the schedule switches them on again (ISO), or null. */
  lightsOnAt: string | null;
  /** Games an admin hid from visitors (by id). */
  hiddenGames: string[];
}

/**
 * The admin's switches for the lights, kept by the server so they hold through scenes, colors,
 * games and the auto-revert.
 */
export interface LightControls {
  /** Devices switched off: they stay dark (no scene, color, effect or game) until switched on. */
  off: string[];
  /**
   * Brightness in percent (1 to 100). `all`: every device; null leaves it to each scene's
   * presets. `devices`: a device's own level, which wins over `all`.
   */
  brightness: { all: number | null; devices: Record<string, number> };
}

/**
 * The roofline as the home page draws it (see RoofView): the roof's LEDs gathered into cells in
 * strip order (the way a chase runs), its left end (as seen from the street) first. The page
 * wraps them around the border of the window.
 */
export interface RoofGeometry {
  /** How many cells: each frame has one RGB triple per cell. */
  cells: number;
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

/** An admin's passkey (see server/src/passkeys.ts). */
export interface Passkey {
  /** The credential id (base64url). */
  id: string;
  name: string;
  /** The site name it belongs to: it signs in only there. */
  rpId: string;
  /** Kept in a synced password manager (iCloud Keychain, Google, 1Password…), not on one device only. */
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface SessionInfo {
  user: { id: string; username: string } | null;
  needsBootstrap: boolean;
}

export interface BackupFile {
  version: 1 | 2;
  exportedAt: string;
  publicPresets: { id: string; name: string; sortOrder?: number; devicePresets: Record<string, number>; effects?: Record<string, EffectSettings>; sequenceId?: string | null; playlist?: Playlist | null }[];
}
