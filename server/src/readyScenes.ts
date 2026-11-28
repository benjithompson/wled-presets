// Scenes that come with the site: one for each effect that is best seen on the whole yard. Each
// is added once, when the server first starts with it, at the end of the scene list. After that
// it is the admin's like any other: renamed, changed or deleted, it stays that way.

import { defaultSettings, YARD, type EffectId, type EffectSettings } from '../../shared/effects.ts';
import type { Scene } from '../../shared/types.ts';
import type { Db } from './db.ts';

const KEY = 'readyScenes';

/** A ready-made scene: its key (never reused), name and whole-yard effect. */
interface ReadyScene {
  key: string;
  name: string;
  effect: EffectSettings;
}

const yard = (effect: EffectId, patch: Partial<EffectSettings> = {}): EffectSettings => ({ ...defaultSettings(effect), brightness: 1, ...patch });

export const READY_SCENES: ReadyScene[] = [
  { key: 'carillon', name: 'Carillon', effect: yard('carillon', { intensity: 0.8 }) },
  { key: 'coaster', name: 'Roller coaster', effect: yard('coaster', { intensity: 0.6 }) },
  { key: 'wheel', name: 'Prize wheel', effect: yard('wheel') },
  { key: 'clockwork', name: 'Clockwork', effect: yard('clockwork', { intensity: 0.7 }) },
  { key: 'talent', name: 'Talent show', effect: yard('talent') }
];

/** The keys of the ready-made scenes this install has had. */
function added(db: Db): Set<string> {
  try {
    const v = JSON.parse(db.getSetting(KEY) || '[]');
    return new Set(Array.isArray(v) ? v.filter((k): k is string => typeof k === 'string') : []);
  } catch {
    return new Set();
  }
}

/**
 * Adds the ready-made scenes this install has not had yet (one with the same name already there
 * counts as had). A new install with no devices and no scenes gets them once it has some: scenes
 * in an empty install would make migrateV1Settings take it for a version 1 install. Returns the
 * names of the scenes it added.
 */
export function addReadyScenes(db: Db): string[] {
  if (db.isEmpty()) return [];
  const had = added(db);
  const names = new Set(db.listScenes().map((s) => s.name.trim().toLowerCase()));
  const out: string[] = [];
  for (const r of READY_SCENES) {
    if (had.has(r.key)) continue;
    had.add(r.key);
    if (names.has(r.name.toLowerCase())) continue;
    const scene: Scene = { id: crypto.randomUUID(), name: r.name, sortOrder: db.nextSortOrder(), devicePresets: {}, effects: { [YARD]: { ...r.effect } } };
    db.saveScene(scene);
    out.push(r.name);
  }
  db.setSetting(KEY, JSON.stringify([...had]));
  return out;
}
