import type { GameArea } from '../../shared/layout.ts';
import type { LightControls, Settings } from '../../shared/types.ts';
import type { Db } from './db.ts';
import { DEFAULT_LINE, type LineSettings } from '../../shared/line.ts';
import { SCENE_TRANSITION_SECONDS, TRANSITION_CHOICES, type SceneTransition, type SceneTransitionChoice } from '../../shared/transitions.ts';

// Keys match v1 where the concept existed.
export const KEY = {
  title: 'siteTitle',
  subtitle: 'siteSubtitle',
  showColors: 'showColors',
  defaultScene: 'defaultPresetId',
  revertMinutes: 'revertTimeout',
  subnets: 'discoverySubnets',
  currentScene: 'currentPresetId',
  currentColor: 'currentColor',
  revertAt: 'revertAt',
  gameArea: 'gameArea',
  line: 'lineSettings',
  lightsOff: 'lightsOff',
  brightness: 'lightsBrightness',
  sceneTransition: 'sceneTransition',
  sceneTransitionSeconds: 'sceneTransitionSeconds'
} as const;

/** What a new install does between scenes: a short crossfade. */
export const DEFAULT_SCENE_TRANSITION: SceneTransitionChoice = 'fade';

const isSceneTransition = (v: unknown): v is SceneTransitionChoice => v === 'none' || TRANSITION_CHOICES.some((t) => t.id === v);

/** How long a scene transition takes: a number in range, else the default. */
export function sceneTransitionSeconds(v: unknown): number {
  const n = typeof v === 'number' ? v : parseFloat(String(v ?? ''));
  if (!Number.isFinite(n)) return SCENE_TRANSITION_SECONDS.default;
  return Math.min(SCENE_TRANSITION_SECONDS.max, Math.max(SCENE_TRANSITION_SECONDS.min, Math.round(n * 10) / 10));
}

/** The transition between scenes someone picks, or null when they change at once. */
export function sceneTransitionOf(s: Pick<Settings, 'sceneTransition' | 'sceneTransitionSeconds'>): SceneTransition | null {
  return s.sceneTransition === 'none' ? null : { type: s.sceneTransition, seconds: s.sceneTransitionSeconds };
}

export const DEFAULT_TITLE = 'Lights';
export const DEFAULT_SUBTITLE = 'Tap a color or a scene.';

export function readSettings(db: Db): Settings {
  let subnets: string[] = [];
  try {
    const parsed = JSON.parse(db.getSetting(KEY.subnets) || '[]');
    if (Array.isArray(parsed)) subnets = parsed.map(String);
  } catch {
    /* ignore */
  }
  return {
    siteTitle: db.getSetting(KEY.title) || DEFAULT_TITLE,
    siteSubtitle: db.getSetting(KEY.subtitle) ?? DEFAULT_SUBTITLE,
    showColors: db.getSetting(KEY.showColors) !== '0',
    defaultSceneId: db.getSetting(KEY.defaultScene) || null,
    revertMinutes: Math.max(0, parseInt(db.getSetting(KEY.revertMinutes) || '0', 10) || 0),
    discoverySubnets: subnets,
    sceneTransition: isSceneTransition(db.getSetting(KEY.sceneTransition)) ? (db.getSetting(KEY.sceneTransition) as SceneTransitionChoice) : DEFAULT_SCENE_TRANSITION,
    sceneTransitionSeconds: sceneTransitionSeconds(db.getSetting(KEY.sceneTransitionSeconds))
  };
}

export function writeSettings(db: Db, s: Settings) {
  db.setSetting(KEY.title, s.siteTitle);
  db.setSetting(KEY.subtitle, s.siteSubtitle);
  db.setSetting(KEY.showColors, s.showColors ? '1' : '0');
  db.setSetting(KEY.defaultScene, s.defaultSceneId ?? '');
  db.setSetting(KEY.revertMinutes, s.revertMinutes);
  db.setSetting(KEY.subnets, JSON.stringify(s.discoverySubnets));
  db.setSetting(KEY.sceneTransition, s.sceneTransition);
  db.setSetting(KEY.sceneTransitionSeconds, sceneTransitionSeconds(s.sceneTransitionSeconds));
}

/** A v1 install had a hard-coded page title. Keep it, so the public page looks the same after upgrade. */
export function migrateV1Settings(db: Db) {
  if (db.getSetting(KEY.title) == null && !db.isEmpty()) {
    db.setSetting(KEY.title, 'Christmas Lights');
    db.setSetting(KEY.subtitle, 'Tap a color or preset.');
  }
}

/** The part of the yard that games use (see GameArea). Null: all of it. */
export function readGameArea(db: Db): GameArea | null {
  try {
    const v = JSON.parse(db.getSetting(KEY.gameArea) || 'null');
    return v && typeof v === 'object' ? (v as GameArea) : null;
  } catch {
    return null;
  }
}

export function writeGameArea(db: Db, area: GameArea | null) {
  db.setSetting(KEY.gameArea, area ? JSON.stringify(area) : '');
}

/** The line for the lights (see shared/line.ts). On by default: the site may be open to anyone. */
export function readLineSettings(db: Db): LineSettings {
  try {
    const v = JSON.parse(db.getSetting(KEY.line) || '{}');
    return { ...DEFAULT_LINE, ...(v && typeof v === 'object' ? v : {}) };
  } catch {
    return { ...DEFAULT_LINE };
  }
}

export function writeLineSettings(db: Db, s: LineSettings) {
  db.setSetting(KEY.line, JSON.stringify(s));
}

/** The admin's power and brightness switches (see LightControls). */
export function readLightControls(db: Db): LightControls {
  const parse = (key: string) => {
    try {
      return JSON.parse(db.getSetting(key) || 'null');
    } catch {
      return null;
    }
  };
  const off = parse(KEY.lightsOff);
  const b = parse(KEY.brightness);
  const level = (v: unknown) => (typeof v === 'number' && v >= 1 && v <= 100 ? Math.round(v) : null);
  const devices: Record<string, number> = {};
  if (b && typeof b.devices === 'object') for (const [id, v] of Object.entries(b.devices ?? {})) if (level(v) != null) devices[id] = level(v)!;
  return { off: Array.isArray(off) ? off.filter((x): x is string => typeof x === 'string') : [], brightness: { all: level(b?.all), devices } };
}

export function writeLightControls(db: Db, c: LightControls) {
  db.setSetting(KEY.lightsOff, JSON.stringify(c.off));
  db.setSetting(KEY.brightness, JSON.stringify(c.brightness));
}
