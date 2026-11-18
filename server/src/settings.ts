import type { GameArea } from '../../shared/layout.ts';
import type { Settings } from '../../shared/types.ts';
import type { Db } from './db.ts';
import { DEFAULT_LINE, type LineSettings } from '../../shared/line.ts';

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
  line: 'lineSettings'
} as const;

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
    discoverySubnets: subnets
  };
}

export function writeSettings(db: Db, s: Settings) {
  db.setSetting(KEY.title, s.siteTitle);
  db.setSetting(KEY.subtitle, s.siteSubtitle);
  db.setSetting(KEY.showColors, s.showColors ? '1' : '0');
  db.setSetting(KEY.defaultScene, s.defaultSceneId ?? '');
  db.setSetting(KEY.revertMinutes, s.revertMinutes);
  db.setSetting(KEY.subnets, JSON.stringify(s.discoverySubnets));
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
