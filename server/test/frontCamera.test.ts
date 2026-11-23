import { describe, expect, it } from 'vitest';
import { sampleLayout, type FrontView, type Layout } from '../../shared/layout.ts';
import { frontCamera, project, unproject } from '../../web/src/yard/frontCamera.ts';
import { fromView, LayoutInView, toView, viewPositions } from '../../web/src/yard/views.ts';
import { layoutSchema } from '../src/layoutStore.ts';

const layout = (frontView?: FrontView): Layout => ({ ...sampleLayout(), frontView });

describe('the front view seen from an angle', () => {
  it('is the plain front view when straight on from far away', () => {
    expect(frontCamera(layout())).toBeNull();
    expect(frontCamera(layout({}))).toBeNull();
    expect(frontCamera(layout({ yaw: 0, pitch: 0 }))).toBeNull();
    const p = { x: 300, y: 500, z: 120 };
    expect(toView(p, 'front', 0, frontCamera(layout()))).toEqual({ u: 300, v: 500 });
  });

  it('turns the yard about the middle of the front wall at the ground', () => {
    const l = layout({ yaw: 30 });
    const cam = frontCamera(l)!;
    const ground = l.groundY ?? l.height;
    // The pivot stays; a point on the front wall to its right comes closer (foreshortened).
    expect(project(cam, l.width / 2, ground, 0)).toEqual({ u: l.width / 2, v: ground });
    const right = project(cam, l.width / 2 + 100, ground, 0);
    expect(right.u - l.width / 2).toBeCloseTo(100 * Math.cos(Math.PI / 6), 5);
    // Seen from the right, a tree out toward the street shows to the left of the wall behind it.
    expect(project(cam, l.width / 2, ground, 200).u).toBeLessThan(l.width / 2);
    // Heights stay heights.
    expect(project(cam, l.width / 2, ground - 300, 0).v).toBeCloseTo(ground - 300, 5);
  });

  it('finds the point at a spot back at the depth it had, from an angle, from above and up close', () => {
    for (const v of [{ yaw: 40 }, { yaw: -25, pitch: 20 }, { yaw: 15, pitch: 10, distance: 900 }] satisfies FrontView[]) {
      const cam = frontCamera(layout(v))!;
      for (const p of [
        { x: 200, y: 400, z: 0 },
        { x: 1100, y: 650, z: 250 },
        { x: 900, y: 300, z: -180 }
      ]) {
        const at = project(cam, p.x, p.y, p.z);
        const back = unproject(cam, at.u, at.v, p.z);
        expect(back.x).toBeCloseTo(p.x, 3);
        expect(back.y).toBeCloseTo(p.y, 3);
        expect(back.z).toBe(p.z);
      }
    }
  });

  it('with perspective only, keeps the front wall where the picture has it and makes nearer things bigger', () => {
    const l = layout({ distance: 800 });
    const cam = frontCamera(l)!;
    const wall = project(cam, 300, 200, 0);
    expect(wall.u).toBeCloseTo(300, 5);
    expect(wall.v).toBeCloseTo(200, 5);
    // Out toward the street (the camera), farther from the middle on the screen.
    const near = project(cam, 300, 200, 200);
    expect(Math.abs(near.u - l.width / 2)).toBeGreaterThan(Math.abs(300 - l.width / 2));
  });

  it('moves, places and draws objects through the camera', () => {
    const l = layout({ yaw: 35, pitch: 15 });
    const cam = frontCamera(l);
    const view = new LayoutInView(l, 'front', 0);
    const pts = [
      { x: 400, y: 500, z: 60 },
      { x: 700, y: 520, z: -40 }
    ];
    const moved = view.moved(pts, 25, -10);
    moved.forEach((q, i) => {
      // Each point keeps its depth and moves across the screen as the pointer did.
      expect(q.z).toBe(pts[i].z);
      const a = view.at(pts[i]);
      const b = view.at(q);
      expect(b.u - a.u).toBeCloseTo(25, 1);
      expect(b.v - a.v).toBeCloseTo(-10, 1);
    });
    const placed = fromView({ u: 800, v: 400 }, 'front', 0, { x: 0, y: 0, z: 120 }, cam);
    expect(placed.z).toBe(120);
    const seen = toView(placed, 'front', 0, cam);
    expect(seen.u).toBeCloseTo(800, 1);
    expect(seen.v).toBeCloseTo(400, 1);
    // LED positions go the same way.
    const pos = viewPositions(Float32Array.from([placed.x, placed.y, placed.z]), 'front', 0, cam);
    expect(pos[0]).toBeCloseTo(800, 0);
    expect(pos[1]).toBeCloseTo(400, 0);
    // The top view does not turn.
    expect(toView({ x: 10, y: 20, z: 30 }, 'top', -100, cam)).toEqual({ u: 10, v: 130 });
  });
});

describe('saving the front view angle', () => {
  it('keeps it with the layout, within its limits', () => {
    expect(layoutSchema.safeParse(layout({ yaw: -30, pitch: 12, distance: 900 })).success).toBe(true);
    expect(layoutSchema.safeParse(layout({ yaw: 120 })).success).toBe(false);
    expect(layoutSchema.safeParse(layout({ pitch: -5 })).success).toBe(false);
  });
});
