import { describe, expect, it } from 'vitest';
import { cleanPlaylist, newPlaylist, playlistSteps, playlistTransition } from '../../shared/playlist.ts';
import type { Scene } from '../../shared/types.ts';

const scene = (id: string, more: Partial<Scene> = {}): Scene => ({ id, name: id, sortOrder: 0, devicePresets: { d: 1 }, ...more });

describe('playlists', () => {
  const scenes = [scene('a'), scene('b'), scene('empty', { devicePresets: {} }), scene('list', { playlist: newPlaylist() }), scene('c')];

  it('play every scene in the order of the scenes page, but not other playlists or empty scenes', () => {
    expect(playlistSteps({ ...newPlaylist(), seconds: 30 }, scenes).map((s) => [s.scene.id, s.seconds])).toEqual([
      ['a', 30],
      ['b', 30],
      ['c', 30]
    ]);
  });

  it('play the scenes picked, in their order, each for its own time', () => {
    const p = { ...newPlaylist(), all: false, sceneIds: ['c', 'gone', 'a', 'list'], seconds: 20, durations: { a: 90 } };
    expect(playlistSteps(p, scenes).map((s) => [s.scene.id, s.seconds])).toEqual([
      ['c', 20],
      ['a', 90]
    ]);
  });

  it('are kept without themselves, missing scenes or times that change nothing', () => {
    const p = cleanPlaylist({ ...newPlaylist(), all: false, sceneIds: ['a', 'self', 'gone', 'a', 'b'], seconds: 2, durations: { a: 5, b: 99999, gone: 10 }, transitionSeconds: 30 }, 'self', ['a', 'b', 'self']);
    expect(p).toEqual({ all: false, sceneIds: ['a', 'b'], seconds: 5, durations: { b: 3600 }, transition: 'fade', transitionSeconds: 10 });
  });

  it('change at once with no transition', () => {
    expect(playlistTransition({ ...newPlaylist(), transition: 'none' })).toBeNull();
    expect(playlistTransition({ ...newPlaylist(), transition: 'random', transitionSeconds: 3 })).toEqual({ type: 'random', seconds: 3 });
  });
});
