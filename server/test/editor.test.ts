// The layout editor's logic that needs no screen: line edits, undo, and the 2D views.
import { describe, expect, it } from 'vitest';
import { buildStage, pinPoint, pointOffsets, removePoint, sampleLayout, setSkipped, splitLine, unpinPoint, type Fixture } from '../../shared/layout.ts';
import { EditHistory } from '../../web/src/pages/admin/editHistory.ts';
import { fromView, toView, viewPositions, type ViewSide } from '../../web/src/yard/views.ts';

const fx = (effect: string) => ({ effect }) as unknown as NonNullable<Fixture['effect']>;

/** A line of four points 100 apart, 31 LEDs from device LED 100, the third point pinned to LED 22. */
const line: Fixture = {
  id: 'l',
  name: 'Gutter',
  kind: 'line',
  points: [
    { x: 0, y: 100 },
    { x: 100, y: 100 },
    { x: 200, y: 100 },
    { x: 300, y: 100 }
  ],
  pixels: 31,
  deviceId: 'd',
  startPixel: 100,
  reversed: false,
  pointLeds: [null, null, 22, null],
  skip: [0, 2],
  segmentEffects: { '1': fx('a'), '2': fx('b') }
};

describe('editing a line', () => {
  it('cuts it in two at a corner, each part with its own LEDs, pins and segments', () => {
    expect(pointOffsets(line)).toEqual([0, 11, 22, 30]);
    const [a, b] = splitLine(line, 2, 'l2')!;
    expect(a).toMatchObject({ id: 'l', points: line.points.slice(0, 3), startPixel: 100, pixels: 23, skip: [0], segmentEffects: { '1': fx('a') } });
    expect(a.pointLeds).toBeUndefined();
    expect(b).toMatchObject({ id: 'l2', name: 'Gutter (part 2)', points: line.points.slice(2), startPixel: 123, pixels: 8, skip: [0], segmentEffects: { '0': fx('b') } });
  });

  it('will not cut where a part would have no LED', () => {
    expect(splitLine({ ...line, pixels: 2, pointLeds: undefined }, 1, 'x')).toBeNull();
  });

  it('takes a first or last point away with its segment, and joins the segments of one inside', () => {
    expect(removePoint(line, 0)).toMatchObject({ points: line.points.slice(1), startPixel: 111, pixels: 20, pointLeds: [null, 11, null], skip: [1] });
    const end = removePoint(line, 3)!;
    expect(end).toMatchObject({ points: line.points.slice(0, 3), startPixel: 100, pixels: 23, skip: [0] });
    expect(end.pointLeds).toBeUndefined();
    const inside = removePoint(line, 1)!;
    expect(inside.points).toHaveLength(3);
    expect(inside.pointLeds).toEqual([null, 22, null]);
    expect(inside.pixels).toBeUndefined();
    expect(removePoint({ ...line, points: line.points.slice(0, 2), pointLeds: undefined }, 0)).toBeNull();
  });

  it('pins and unpins a corner, and turns segments off and on', () => {
    expect(unpinPoint(line, 2).pointLeds).toBeUndefined();
    const pinned = { ...line, ...pinPoint(line, 1, 105) };
    expect(pointOffsets(pinned)).toEqual([0, 5, 22, 30]);
    expect(setSkipped(line, 1, true).skip).toEqual([0, 1, 2]);
    expect(setSkipped(line, 0, false).skip).toEqual([2]);
    expect(setSkipped({ ...line, skip: [3] }, 3, false).skip).toBeUndefined();
    expect(setSkipped(line, 2, true).skip).toEqual([0, 2]);
  });
});

describe('undo', () => {
  it('keeps the state before each step, and edits close together are one step', () => {
    const h = new EditHistory<string>(100, 600);
    expect(h.canUndo).toBe(false);
    expect(h.record('a', 1000)).toBe(true);
    expect(h.record('b', 1300)).toBe(false);
    expect(h.record('c', 2000)).toBe(true);
    expect(h.undo('d')).toBe('c');
    expect(h.undo('c')).toBe('a');
    expect(h.undo('a')).toBeNull();
    expect(h.canRedo).toBe(true);
    expect(h.redo('a')).toBe('c');
    expect(h.redo('c')).toBe('d');
    expect(h.redo('d')).toBeNull();
  });

  it('starts a new step on request, forgets what Redo had after an edit, and goes only so far back', () => {
    const h = new EditHistory<number>(3, 600);
    h.record(1, 1000);
    h.newStep();
    expect(h.record(2, 1100)).toBe(true);
    h.undo(3);
    expect(h.canRedo).toBe(true);
    h.record(2, 5000);
    expect(h.canRedo).toBe(false);
    for (let i = 0; i < 5; i++) h.record(10 + i, 10_000 + i * 1000);
    const back: number[] = [];
    for (let s = h.undo(99); s != null; s = h.undo(s)) back.push(s);
    expect(back).toEqual([14, 13, 12]);
  });

  it('rolls back the steps since a mark, and clears', () => {
    const h = new EditHistory<number>();
    h.record(1, 1000);
    const mark = h.mark();
    h.record(2, 5000);
    h.rollback(mark);
    expect(h.undo(3)).toBe(1);
    h.clear();
    expect(h.canUndo || h.canRedo).toBe(false);
  });
});

describe('the 2D views', () => {
  const sides: ViewSide[] = ['front', 'top', 'side'];

  it('turns a position in a view back into the point it shows, keeping what the view does not show', () => {
    const p = { x: 120, y: 340, z: -55 };
    for (const side of sides) expect(fromView(toView(p, side, -480), side, -480, { x: 0, y: 0, z: 0 })).toMatchObject(side === 'front' ? { x: 120, y: 340, z: 0 } : side === 'top' ? { x: 120, y: 0, z: -55 } : { x: 0, y: 340, z: -55 });
  });

  it('places every LED of the stage where toView puts its position', () => {
    const stage = buildStage(sampleLayout());
    const p = stage.positions3;
    for (const side of sides) {
      const uv = viewPositions(p, side, -480);
      for (const i of [0, 7, stage.pixelCount - 1]) {
        const at = toView({ x: p[i * 3], y: p[i * 3 + 1], z: p[i * 3 + 2] }, side, -480);
        expect(uv[i * 2]).toBeCloseTo(at.u, 3);
        expect(uv[i * 2 + 1]).toBeCloseTo(at.v, 3);
      }
    }
  });
});
