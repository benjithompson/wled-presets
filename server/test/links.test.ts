import { describe, expect, it } from 'vitest';
import { findScene, gamePath, scenePath, slug } from '../../shared/links.ts';

describe('links to a game or a scene', () => {
  it('reads names as they go in a link', () => {
    expect(slug('Candy Cane!')).toBe('candy-cane');
    expect(slug('  Noël — Blue & White ')).toBe('noel-blue-white');
    expect(slug('🎄')).toBe('');
    expect(gamePath('cascade')).toBe('/play/cascade');
  });

  it('links to a scene by its name when no other scene has it, else by its id', () => {
    const scenes = [
      { id: 'a1', name: 'Candy Cane' },
      { id: 'b2', name: 'Warm White' },
      { id: 'c3', name: 'warm white' },
      { id: 'd4', name: '🎄' }
    ];
    expect(scenePath(scenes[0], scenes)).toBe('/scene/candy-cane');
    expect(scenePath(scenes[1], scenes)).toBe('/scene/b2');
    expect(scenePath(scenes[3], scenes)).toBe('/scene/d4');
    expect(findScene('candy-cane', scenes)?.id).toBe('a1');
    expect(findScene('Candy Cane', scenes)?.id).toBe('a1');
    expect(findScene('c3', scenes)?.id).toBe('c3');
    expect(findScene('d4', scenes)?.id).toBe('d4');
    expect(findScene('nope', scenes)).toBeUndefined();
    expect(findScene('', scenes)).toBeUndefined();
  });
});
