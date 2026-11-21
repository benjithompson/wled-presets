import { describe, expect, it } from 'vitest';
import { insertPoint, keepLocked, sampleLayout, type Layout } from '../../shared/layout.ts';
import { layoutSchema } from '../src/layoutStore.ts';

const locked = (): Layout => {
  const l = sampleLayout();
  return { ...l, fixtures: l.fixtures.map((f) => (f.id === 'roof' || f.id === 'bush-1' ? { ...f, locked: true } : f)) };
};
const move = (l: Layout, id: string, dx: number): Layout => ({ ...l, fixtures: l.fixtures.map((f) => (f.id === id ? { ...f, points: f.points.map((p) => ({ ...p, x: p.x + dx })) } : f)) });

describe('locked objects', () => {
  it('stay where they are: a move, a new point or a new size is undone, and named', () => {
    const prev = locked();
    const moved = keepLocked(prev, move(move(prev, 'roof', 50), 'bush-2', 50));
    expect(moved.blocked).toEqual(['Roofline']);
    expect(moved.layout.fixtures[0]).toBe(prev.fixtures[0]);
    // An unlocked object moves.
    expect(moved.layout.fixtures[2].points[0].x).toBe(prev.fixtures[2].points[0].x + 50);

    const roof = prev.fixtures[0];
    const withPoint = { ...prev, fixtures: [{ ...roof, ...insertPoint(roof, 0, { x: 300, y: 470 }) }, ...prev.fixtures.slice(1)] };
    // The point goes, and its LED pin with it: the whole object comes back.
    expect(keepLocked(prev, withPoint).layout.fixtures[0]).toBe(roof);

    const bigger = { ...prev, fixtures: prev.fixtures.map((f) => (f.id === 'bush-1' ? { ...f, radius: 200 } : f)) };
    expect(keepLocked(prev, bigger).blocked).toEqual(['Left bush']);
  });

  it('cannot be deleted: they come back in their place in the list', () => {
    const prev = locked();
    const next = { ...prev, fixtures: prev.fixtures.filter((f) => f.id === 'bush-2') };
    const kept = keepLocked(prev, next);
    expect(kept.blocked).toEqual(['Roofline', 'Left bush']);
    expect(kept.layout.fixtures.map((f) => f.id)).toEqual(['roof', 'bush-1', 'bush-2']);
  });

  it('can still change their LEDs, wiring and name, and can be unlocked and moved in one edit', () => {
    const prev = locked();
    const wired = { ...prev, fixtures: prev.fixtures.map((f) => (f.id === 'roof' ? { ...f, reversed: true, startPixel: 10, name: 'Front roof' } : f)) };
    const kept = keepLocked(prev, wired);
    expect(kept.blocked).toEqual([]);
    expect(kept.layout).toBe(wired);
    const unlocked = move({ ...prev, fixtures: prev.fixtures.map((f) => (f.id === 'roof' ? { ...f, locked: undefined } : f)) }, 'roof', 50);
    expect(keepLocked(prev, unlocked).blocked).toEqual([]);
  });

  it('is saved with the layout', () => {
    const parsed = layoutSchema.parse(locked());
    expect(parsed.fixtures[0].locked).toBe(true);
    expect(parsed.fixtures[2].locked).toBeUndefined();
  });
});
