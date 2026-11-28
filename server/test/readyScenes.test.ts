import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.ts';
import { addReadyScenes, READY_SCENES } from '../src/readyScenes.ts';
import { EFFECTS, YARD } from '../../shared/effects.ts';

const withScene = () => {
  const db = openDatabase(':memory:');
  db.saveScene({ id: 'mine', name: 'Clockwork', sortOrder: 0, devicePresets: {} });
  return db;
};

describe('ready-made scenes', () => {
  it('play a real effect on the whole yard', () => {
    for (const r of READY_SCENES) expect(EFFECTS.map((e) => e.id)).toContain(r.effect.effect);
  });

  it('are added once, after the scenes there are, and leave one with the same name alone', () => {
    const db = withScene();
    expect(addReadyScenes(db)).toEqual(['Carillon', 'Roller coaster', 'Prize wheel', 'Talent show']);
    const scenes = db.listScenes();
    expect(scenes.map((s) => s.name)).toEqual(['Clockwork', 'Carillon', 'Roller coaster', 'Prize wheel', 'Talent show']);
    expect(scenes[1].effects?.[YARD]?.effect).toBe('carillon');
    expect(scenes[0].effects).toBeUndefined();
    // Deleted by the admin, a scene stays deleted.
    db.deleteScene(scenes[1].id);
    expect(addReadyScenes(db)).toEqual([]);
    expect(db.listScenes().length).toBe(4);
  });

  it('wait until a new install has devices or scenes', () => {
    const db = openDatabase(':memory:');
    expect(addReadyScenes(db)).toEqual([]);
    expect(db.listScenes()).toEqual([]);
    db.saveScene({ id: 'first', name: 'Warm white', sortOrder: 0, devicePresets: {} });
    expect(addReadyScenes(db).length).toBe(READY_SCENES.length);
  });
});
