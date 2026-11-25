// Playlists: a scene that plays other scenes one after another, each for its time, with a
// transition between them, round and round (see Scene.playlist). Keep this file free of Node and
// DOM APIs: the server plays playlists and the admin console edits them.

import type { Scene } from './types.ts';
import { SCENE_TRANSITION_SECONDS, type SceneTransition, type SceneTransitionChoice } from './transitions.ts';

export interface Playlist {
  /** Every scene, in the order of the scenes page, ones made later too (other playlists not). */
  all: boolean;
  /** The scenes it plays, in order, when not `all`. */
  sceneIds: string[];
  /** How long each scene plays, in seconds. */
  seconds: number;
  /** A scene's own time, in seconds, in place of `seconds`. */
  durations?: Record<string, number>;
  /** How one scene gives way to the next ("none": at once). */
  transition: SceneTransitionChoice;
  /** How long the transition takes, in seconds. */
  transitionSeconds: number;
}

/** How long a scene in a playlist plays, in seconds. */
export const PLAYLIST_SECONDS = { min: 5, max: 3600, default: 60 } as const;

export const newPlaylist = (): Playlist => ({ all: true, sceneIds: [], seconds: PLAYLIST_SECONDS.default, transition: 'fade', transitionSeconds: 2 });

/** True when a scene plays something of its own: presets, effects or a sequence. */
export const playsSomething = (s: Scene) => !s.playlist && (Object.keys(s.devicePresets).length > 0 || Object.keys(s.effects ?? {}).length > 0 || !!s.sequenceId);

/**
 * The scenes a playlist plays, in order, with how long each one plays (seconds). Other playlists
 * and scenes that play nothing are left out, and so are scenes that no longer exist.
 * `scenes`: every scene, in the order of the scenes page.
 */
export function playlistSteps(p: Playlist, scenes: Scene[]): { scene: Scene; seconds: number }[] {
  const byId = new Map(scenes.map((s) => [s.id, s]));
  const picked = p.all ? scenes : p.sceneIds.map((id) => byId.get(id)).filter((s): s is Scene => !!s);
  const seen = new Set<string>();
  return picked
    .filter((s) => playsSomething(s) && !seen.has(s.id) && seen.add(s.id))
    .map((scene) => ({ scene, seconds: clampSeconds(p.durations?.[scene.id] ?? p.seconds) }));
}

export const clampSeconds = (n: number) => Math.min(PLAYLIST_SECONDS.max, Math.max(PLAYLIST_SECONDS.min, Math.round(Number.isFinite(n) ? n : PLAYLIST_SECONDS.default)));

/** The transition between a playlist's scenes, or null when they change at once. */
export function playlistTransition(p: Playlist): SceneTransition | null {
  if (p.transition === 'none') return null;
  const s = Math.min(SCENE_TRANSITION_SECONDS.max, Math.max(SCENE_TRANSITION_SECONDS.min, p.transitionSeconds));
  return { type: p.transition, seconds: s };
}

/**
 * A playlist as it is kept: its own id, scenes that no longer exist and durations for scenes it
 * does not play are left out, and times are in range.
 */
export function cleanPlaylist(p: Playlist, selfId: string, sceneIds: Iterable<string>): Playlist {
  const known = new Set(sceneIds);
  known.delete(selfId);
  const ids = p.all ? [] : [...new Set(p.sceneIds)].filter((id) => known.has(id));
  const plays = p.all ? known : new Set(ids);
  const durations = Object.fromEntries(Object.entries(p.durations ?? {}).flatMap(([id, n]) => (plays.has(id) && clampSeconds(n) !== clampSeconds(p.seconds) ? [[id, clampSeconds(n)]] : [])));
  return {
    all: p.all,
    sceneIds: ids,
    seconds: clampSeconds(p.seconds),
    ...(Object.keys(durations).length ? { durations } : {}),
    transition: p.transition,
    transitionSeconds: Math.min(SCENE_TRANSITION_SECONDS.max, Math.max(SCENE_TRANSITION_SECONDS.min, Math.round(p.transitionSeconds * 10) / 10))
  };
}
