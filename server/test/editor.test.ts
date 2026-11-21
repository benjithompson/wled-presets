// The layout editor's logic that needs no screen: line edits, undo, and the 2D views.
import { describe, expect, it } from 'vitest';
import { buildStage, BUSH_TALL, layoutGround, layoutScale, pinPoint, pointOffsets, removePoint, sampleLayout, setSkipped, splitLine, unpinPoint, type Fixture, type Layout } from '../../shared/layout.ts';
import { EditHistory } from '../../web/src/pages/admin/editHistory.ts';
import { draftOutline, draftSize, shapeFrom } from '../../web/src/pages/admin/newShapes.ts';
import { fromView, LayoutInView, toView, viewPositions, type ViewSide } from '../../web/src/yard/views.ts';

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

describe('a layout in one view', () => {
  const layout: Layout = { ...sampleLayout(), fixtures: [line, { ...line, id: 'm', points: [{ x: 300, y: 100 }, { x: 300, y: 400, z: 80 }], pointLeds: undefined, skip: undefined }, { id: 'b', name: 'Bush', kind: 'bush', points: [{ x: 600, y: 500, z: 40 }], radius: 50, pixels: 50, deviceId: null, startPixel: 0, reversed: false }] };
  const front = new LayoutInView(layout, 'front', -480);
  const top = new LayoutInView(layout, 'top', -480);

  it('lists what can be snapped to, leaving out a point being dragged and its segments', () => {
    const t = front.targets();
    expect(t.points).toHaveLength(6);
    expect(t.segments).toHaveLength(4);
    expect(t.centers).toEqual([{ u: 600, v: 500 }]);
    const dragging = front.targets({ id: 'l', index: 1 }, true);
    expect(dragging.points).toHaveLength(5);
    expect(dragging.segments).toHaveLength(2);
    expect(dragging.centers).toEqual([]);
  });

  it('finds the point at a spot, the nearest end of a line, and the point on a segment', () => {
    expect(front.pointAt({ u: 300, v: 100 })).toEqual({ x: 300, y: 100 });
    expect(front.pointAt({ u: 300, v: 100 }, { id: 'l', index: 3 })).toEqual({ x: 300, y: 100 });
    expect(front.pointAt({ u: 310, v: 100 })).toBeUndefined();
    expect(front.lineEndAt({ u: 302, v: 398 }, 10)).toMatchObject({ f: { id: 'm' }, at: 'last' });
    expect(front.lineEndAt({ u: 150, v: 150 }, 10)).toBeNull();
    // Halfway down the second line, seen from above: its depth is the view's, its height halfway.
    expect(top.pointOnLine(layout.fixtures[1], 0, { u: 300, v: 480 + 40 })).toEqual({ x: 300, y: 250, z: 40 });
  });

  it('moves points in the view, keeping the coordinate it does not show', () => {
    expect(top.moved([{ x: 1, y: 2, z: 3 }], 10, 20)).toEqual([{ x: 11, y: 2, z: 23 }]);
    expect(new LayoutInView(layout, 'side', -480).moved([{ x: 1, y: 2 }], 10, 20)).toEqual([{ x: 1, y: 22, z: 10 }]);
  });

  it('boxes an object: a line by its points, a bush by its size', () => {
    expect(front.box(layout.fixtures[0])).toEqual({ x: 0, y: 100, w: 300, h: 0 });
    expect(front.box(layout.fixtures[2])).toEqual({ x: 550, y: 500 - 50 * BUSH_TALL, w: 100, h: 100 * BUSH_TALL });
    expect(top.box(layout.fixtures[2])).toEqual({ x: 550, y: 470, w: 100, h: 100 });
  });
});

describe('drawing a new shape', () => {
  const layout = sampleLayout();
  const s = layoutScale(layout);
  const ground = layoutGround(layout);

  it('sizes it as the pointer is dragged', () => {
    expect(draftSize({ shape: 'bush', side: 'front', at: { u: 0, v: 0 }, size: 0 }, { u: 30, v: 40 * BUSH_TALL })).toBe(50);
    expect(draftSize({ shape: 'tree', side: 'front', at: { u: 0, v: 300 }, size: 0 }, { u: 99, v: 100 })).toBe(200);
    expect(draftSize({ shape: 'tree', side: 'front', at: { u: 0, v: 300 }, size: 0 }, { u: 0, v: 400 })).toBe(0);
    expect(draftSize({ shape: 'semicircle', side: 'top', at: { u: 0, v: 0 }, size: 0 }, { u: 30, v: 40 })).toBe(50);
    expect(draftOutline({ shape: 'tree', side: 'front', at: { u: 100, v: 300 }, size: 150 })).toBe('M 50.5 300 L 100 150 L 149.5 300 Z');
  });

  it('makes a bush against the front wall, or on the ground from above', () => {
    expect(shapeFrom({ shape: 'bush', side: 'front', at: { u: 200, v: 600 }, size: 80 }, layout, -480, 'n')).toMatchObject({ id: 'n', kind: 'bush', points: [{ x: 200, y: 600, z: 80 }], radius: 80, pattern: 'fill', pixels: 60 });
    const small = shapeFrom({ shape: 'bush', side: 'top', at: { u: 200, v: 500 }, size: 0 }, layout, -480, 'n');
    expect(small).toMatchObject({ name: `Bush ${layout.fixtures.filter((f) => f.kind === 'bush').length + 1}`, radius: 70, points: [{ x: 200, y: Math.round(ground - 70 * BUSH_TALL), z: 20 }] });
  });

  it('makes a tree and a semicircle of a usual size from a click', () => {
    const tree = shapeFrom({ shape: 'tree', side: 'front', at: { u: 200, v: 600 }, size: 0 }, layout, -480, 'n');
    const height = Math.max(40, 2.5 * s);
    expect(tree).toMatchObject({ kind: 'tree', height: Math.round(height), radius: Math.round(height * 0.33), pattern: 'spiral', turns: 8, pixels: 200 });
    expect(tree.points[0]).toEqual({ x: 200, y: 600, z: Math.round(Math.round(height * 0.33) + 0.5 * s) });
    const semi = shapeFrom({ shape: 'semicircle', side: 'top', at: { u: 200, v: 500 }, size: 0 }, layout, -480, 'n');
    expect(semi).toMatchObject({ kind: 'semicircle', radius: Math.max(15, Math.round(0.6 * s)), strands: 8, zigzag: 'down', pixels: 100, points: [{ x: 200, y: Math.round(ground), z: 20 }] });
  });
});

describe('the editor picture', () => {
  it('is the same in the editor page and on the lights', async () => {
    const { editorFrame } = await import('../src/layoutPreview.ts');
    const { deviceMaps } = await import('../src/framePipeline.ts');
    const { framePut, paintEditorView } = await import('../../shared/editorView.ts');
    const layout = sampleLayout();
    const stage = buildStage(layout);
    const selected = layout.fixtures[0].id;
    for (const view of [{ selected, corner: 1 }, { selected: null, corner: null }, { selected, corner: null, area: null }, { selected, corner: null, check: { kind: 'slice', axis: 'x', at: 400 } as const }]) {
      for (const pulse of [false, true]) {
        const lights = editorFrame({ layout, ...view }, { stage, maps: deviceMaps(layout, stage) }, pulse, 1000).bytes;
        const page = new Uint8Array(stage.pixelCount * 3);
        paintEditorView(layout, stage, view, 1000, pulse, framePut(stage, page), page);
        expect(page).toEqual(lights);
      }
    }
  });

  it('plays the effects into a frame, and follows a change of stage', async () => {
    const { LayoutEffects } = await import('../../shared/effects.ts');
    const layout: Layout = { ...sampleLayout(), effect: { effect: 'rainbow', palette: 'rainbow', speed: 0.5, intensity: 0.5, size: 0.5, brightness: 0.8 } as never };
    const stage = buildStage(layout);
    const fx = new LayoutEffects(stage, layout);
    expect(fx.frame(0.1).some((v) => v > 0)).toBe(true);
    const smaller = { ...layout, fixtures: layout.fixtures.slice(0, 2) };
    const stage2 = buildStage(smaller);
    fx.sync(stage2, smaller);
    expect(fx.frame(0.1)).toHaveLength(stage2.pixelCount * 3);
  });
});
