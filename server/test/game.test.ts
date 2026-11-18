import { describe, expect, it } from 'vitest';
import http from 'node:http';
import { WebSocket } from 'ws';
import {
  activeLeds,
  clampPointLed,
  segmentLeds,
  buildStage,
  cornerPixels,
  deviceLed,
  deviceRuns,
  fixturePixels,
  fromLedRange,
  paintEditor,
  pointOffsets,
  sampleLayout,
  setPointLed,
  skipAfterInsert,
  skipAfterRemove,
  type Fixture
} from '../../shared/layout.ts';
import { layoutSchema } from '../src/layoutStore.ts';
import { catcherGame } from '../src/game/catcher.ts';
import { Frame } from '../src/game/frame.ts';
import { GameHost } from '../src/game/host.ts';
import { defaultSettings } from '../../shared/effects.ts';

describe('layout geometry', () => {
  it('spreads roof LEDs evenly from the first point to the last', () => {
    const roof = sampleLayout().fixtures[0];
    const px = fixturePixels(roof);
    expect(px).toHaveLength(450);
    expect(px[0]).toEqual({ ...roof.points[0], z: 0 });
    expect(px[449].x).toBeCloseTo(roof.points.at(-1)!.x);
  });
  it('finds the corners of the roof', () => {
    const roof = sampleLayout().fixtures[0];
    const corners = cornerPixels(roof);
    expect(corners).toHaveLength(3);
    // The peak is the middle corner of a symmetric gable.
    expect(corners[1]).toBeGreaterThan(200);
    expect(corners[1]).toBeLessThan(250);
  });
  it('spreads LEDs by their real 3D length, so a run back along the side gets its share', () => {
    // From the front the side run (point 1 to 2) has no length; it is 400 units deep.
    const f: Fixture = {
      ...sampleLayout().fixtures[0],
      points: [
        { x: 0, y: 100 },
        { x: 400, y: 100 },
        { x: 400, y: 100, z: -400 }
      ],
      pixels: 101,
      pointLeds: undefined
    };
    expect(pointOffsets(f)).toEqual([0, 50, 100]);
    const px = fixturePixels(f);
    expect(px[75]).toEqual({ x: 400, y: 100, z: -200 });
  });
  it('places bush LEDs on a dome in front of its center, and tree LEDs on a cone', () => {
    const bush: Fixture = { id: 'b', name: 'B', kind: 'bush', points: [{ x: 500, y: 700, z: 100 }], radius: 80, pattern: 'fill', pixels: 60, deviceId: null, startPixel: 0, reversed: false };
    for (const p of fixturePixels(bush)) {
      expect(p.z).toBeGreaterThanOrEqual(100);
      expect(p.z).toBeLessThanOrEqual(100 + 80 * 0.75 + 1e-9);
    }
    const tree: Fixture = {
      id: 't',
      name: 'T',
      kind: 'tree',
      points: [{ x: 800, y: 900, z: 300 }],
      radius: 100,
      height: 400,
      pattern: 'spiral',
      turns: 6,
      pixels: 200,
      deviceId: null,
      startPixel: 0,
      reversed: false
    };
    const tp = fixturePixels(tree);
    expect(tp).toHaveLength(200);
    // LED 0 at the base, at the front; the last LED at the top, on the axis.
    expect(tp[0]).toMatchObject({ y: 900 });
    expect(tp[0].z).toBeCloseTo(400);
    expect(tp[199].y).toBeCloseTo(500);
    expect(Math.hypot(tp[199].x - 800, tp[199].z - 300)).toBeLessThan(5);
    const strands = fixturePixels({ ...tree, pattern: 'strands', strands: 4 });
    // Zigzag: strand 0 goes up (ends at the top), strand 1 comes down (ends at the base).
    expect(strands[49].y).toBeCloseTo(500);
    expect(strands[50].y).toBeCloseTo(500);
    expect(strands[99].y).toBeCloseTo(900);
  });
  it('keeps 3D positions in the stage, and accepts layouts saved before depth existed', () => {
    const old = sampleLayout();
    expect(layoutSchema.safeParse(old).success).toBe(true);
    const withDepth = {
      ...old,
      scale: 50,
      units: 'm' as const,
      groundY: 880,
      fixtures: [
        ...old.fixtures,
        {
          id: 't',
          name: 'Tree',
          kind: 'tree' as const,
          points: [{ x: 1, y: 2, z: -3 }],
          radius: 40,
          height: 200,
          pattern: 'strands' as const,
          strands: 8,
          pixels: 80,
          deviceId: null,
          startPixel: 0,
          reversed: false
        }
      ]
    };
    const parsed = layoutSchema.parse(withDepth);
    expect(parsed.fixtures.at(-1)).toMatchObject({ kind: 'tree', points: [{ z: -3 }], height: 200, strands: 8 });
    expect(parsed).toMatchObject({ scale: 50, units: 'm', groundY: 880 });
    const stage = buildStage(parsed);
    expect(stage.positions3).toHaveLength(stage.pixelCount * 3);
    expect(stage.scale).toBe(50);
  });
  it('builds one frame index range per object', () => {
    const stage = buildStage(sampleLayout());
    expect(stage.pixelCount).toBe(450 + 3 * 60);
    expect(stage.fixtures.map((f) => f.offset)).toEqual([0, 450, 510, 570]);
  });
});

describe('LED numbers', () => {
  const roof = (over: Partial<Fixture>): Fixture => ({ ...sampleLayout().fixtures[0], ...over });

  it('maps first and last LED numbers to start, count and direction', () => {
    expect(fromLedRange(87, 536)).toEqual({ startPixel: 87, pixels: 450, reversed: false });
    expect(fromLedRange(536, 87)).toEqual({ startPixel: 87, pixels: 450, reversed: true });
    const down = roof(fromLedRange(536, 87));
    expect(deviceLed(down, 0)).toBe(536);
    expect(deviceLed(down, 449)).toBe(87);
  });

  it('places a pinned corner at exactly its LED', () => {
    // Peak (point 2) pinned at LED 300 instead of the even-spacing estimate (about 225).
    const f = roof({ pointLeds: [null, null, 300, null, null] });
    const px = fixturePixels(f);
    expect(px).toHaveLength(450);
    expect(px[300]).toEqual({ ...f.points[2], z: 0 });
    expect(pointOffsets(f)[2]).toBe(300);
    expect(px[449]).toEqual({ ...f.points[4], z: 0 });
    // Corners between pins still spread by length.
    expect(pointOffsets(f)[1]).toBeGreaterThan(0);
    expect(pointOffsets(f)[1]).toBeLessThan(300);
  });

  it('ignores a pin that is out of order', () => {
    const f = roof({ pointLeds: [null, 400, 300, null, null] });
    const offs = pointOffsets(f);
    expect(offs[1]).toBe(400);
    expect(offs[2]).toBeGreaterThan(400);
  });

  it('joins roof parts in strip order and skips the gap between them', () => {
    const layout = sampleLayout();
    const [whole] = layout.fixtures;
    const left: Fixture = { ...whole, id: 'a', points: whole.points.slice(0, 3), deviceId: 'd', ...fromLedRange(100, 299) };
    // The right part is drawn first in the list and counts down along its line; a 10-LED gap sits between.
    const right: Fixture = { ...whole, id: 'b', points: whole.points.slice(2), deviceId: 'd', ...fromLedRange(509, 310) };
    layout.fixtures = [right, left];
    const stage = buildStage(layout);
    expect(stage.roofPath).toHaveLength(400);
    const [sr, sl] = stage.fixtures;
    // Strip order: the left part (LED 100 up), then the right part from LED 310, which is its last point.
    expect(stage.roofPath[0]).toBe(sl.offset);
    expect(stage.roofPath[200]).toBe(sr.offset + sr.count - 1);
    expect(stage.roofCorners).toContain(200);
    expect(deviceRuns(layout).get('d')!.overlaps).toHaveLength(0);
  });

  it('sets one segment end and keeps the other segments where they are', () => {
    const f = roof(fromLedRange(100, 549));
    const before = pointOffsets(f).map((o) => deviceLed(f, o));
    // Move the end of segment 1 (point 2, the peak) to LED 340, locking segment 1's start.
    const g = { ...f, ...setPointLed(f, 2, 340, [1, 2]) };
    const after = pointOffsets(g).map((o) => deviceLed(g, o));
    expect(after[0]).toBe(100);
    expect(after[1]).toBe(before[1]);
    expect(after[2]).toBe(340);
    expect(after[4]).toBe(549);
    // Moving the first point changes the object's first LED; pinned corners keep their numbers.
    const h = { ...g, ...setPointLed(g, 0, 90) };
    expect(
      pointOffsets(h)
        .map((o) => deviceLed(h, o))
        .slice(0, 3)
    ).toEqual([90, before[1], 340]);
  });

  it('keeps points in order: a segment start cannot pass the segment before it', () => {
    const f = roof({ ...fromLedRange(0, 449), pointLeds: [null, 50, 150, 300, null] });
    // Segment 3 starts at point 2 (LED 150). Typing 1 stops at 51: segment 2 keeps one LED (50).
    expect(clampPointLed(f, 2, 1)).toBe(51);
    expect(clampPointLed(f, 2, 999)).toBe(299);
    // The first LED cannot pass the first corner, and cannot go below 0.
    expect(clampPointLed(f, 0, 120)).toBe(49);
    // The last LED stays after the last corner.
    expect(clampPointLed(f, 4, 10)).toBe(301);
    // A line that counts down keeps counting down.
    const down = roof({ ...fromLedRange(449, 0), pointLeds: [null, 50, 150, 300, null] });
    expect(clampPointLed(down, 0, 0)).toBe(deviceLed(down, 49));
    expect(clampPointLed(down, 4, 900)).toBe(deviceLed(down, 301));
  });

  it('moves only one point when every point is locked', () => {
    const f = roof(fromLedRange(0, 449));
    const all = f.points.map((_, i) => i);
    const before = pointOffsets(f).map((o) => deviceLed(f, o));
    const g = { ...f, ...setPointLed(f, 2, 260, all) };
    const after = pointOffsets(g).map((o) => deviceLed(g, o));
    expect(after).toEqual([before[0], before[1], 260, before[3], before[4]]);
    // The first LED moves alone too; the corners keep their numbers.
    const h = { ...g, ...setPointLed(g, 0, 20, all) };
    expect(pointOffsets(h).map((o) => deviceLed(h, o))).toEqual([20, before[1], 260, before[3], before[4]]);
  });

  it('skips the LEDs of a segment that is off', () => {
    const layout = sampleLayout();
    const f = { ...layout.fixtures[0], skip: [1] };
    layout.fixtures[0] = f;
    const offs = pointOffsets(f);
    const on = activeLeds(f);
    // Segment 1 runs from the LED at its first corner to the LED just before the next corner.
    expect(on[offs[1] - 1]).toBe(1); // last LED of segment 0
    expect(on[offs[1]]).toBe(0);
    expect(on[offs[2] - 1]).toBe(0);
    expect(on[offs[2]]).toBe(1); // first LED of segment 2
    const stage = buildStage(layout);
    expect(stage.roofPath).toHaveLength(450 - (offs[2] - offs[1]));
    // The game path joins across the gap, and the join counts as a corner.
    expect(stage.roofCorners).toContain(offs[1]);
    // The editor paints the off segment dark.
    const lit: number[] = [];
    paintEditor(layout, null, null, null, true, (fi, i, rgb) => fi === 0 && rgb.some((v) => v > 0) && lit.push(i));
    expect(lit).not.toContain(offs[1]);
  });

  it('gives each LED to exactly one segment: the next segment starts after the last one ends', () => {
    const f = roof({ ...fromLedRange(0, 449), pointLeds: [null, 50, 150, 300, null] });
    expect([0, 1, 2, 3].map((k) => segmentLeds(f, k))).toEqual([
      { lo: 0, hi: 49 },
      { lo: 50, hi: 149 },
      { lo: 150, hi: 299 },
      { lo: 300, hi: 449 }
    ]);
  });

  it('keeps skipped segments in place when corners are added or removed', () => {
    expect(skipAfterInsert([1, 3], 1)).toEqual([1, 2, 4]);
    expect(skipAfterInsert([1, 3], 2)).toEqual([1, 4]);
    expect(skipAfterRemove([1, 2, 4], 2)).toEqual([1, 3]);
    expect(skipAfterRemove([1, 4], 2)).toEqual([3]);
  });

  it('rejects two objects on the same LEDs of one device', () => {
    const layout = sampleLayout();
    layout.fixtures[1] = { ...layout.fixtures[1], deviceId: 'd', ...fromLedRange(0, 59) };
    layout.fixtures[2] = { ...layout.fixtures[2], deviceId: 'd', ...fromLedRange(50, 109) };
    const r = layoutSchema.safeParse(layout);
    expect(r.success).toBe(false);
    expect(r.error!.issues[0].message).toMatch(/Left bush and Middle bush use the same LEDs \(50–59\)/);
  });
});

/** Runs the game until the comet sits in the middle of the gate, then presses. */
function playUntilCatch(game: ReturnType<typeof catcherGame>, frame: Frame, stage: ReturnType<typeof buildStage>) {
  for (let i = 0; i < 2000; i++) {
    game.update(1 / 60, frame);
    // The gate posts are the two brightest green LEDs; the comet is the brightest blue one.
    const roof = stage.fixtures[0];
    let comet = -1;
    let best = 0;
    for (let p = 0; p < roof.count; p++) {
      const b = frame.data[(roof.offset + p) * 3 + 2];
      if (b > best) {
        best = b;
        comet = p;
      }
    }
    const green: number[] = [];
    for (let p = 0; p < roof.count; p++) {
      const g = frame.data[(roof.offset + p) * 3 + 1];
      const b = frame.data[(roof.offset + p) * 3 + 2];
      // Gate posts are strongly green; the comet's tail is blue-white.
      if (g > 0.4 && g > b * 1.6) green.push(p);
    }
    if (green.length && comet >= Math.min(...green) + 1 && comet <= Math.max(...green) - 1) {
      game.input({ playerId: 'p', action: 'press' });
      return true;
    }
  }
  return false;
}

describe('Comet Catcher', () => {
  it('starts on a press, counts a catch, and lights a bush', () => {
    const stage = buildStage(sampleLayout());
    const game = catcherGame(stage);
    const frame = new Frame(stage.pixelCount);
    expect(game.status().phase).toBe('ready');
    game.input({ playerId: 'p', action: 'press' });
    expect(game.status().phase).toBe('running');
    expect(playUntilCatch(game, frame, stage)).toBe(true);
    expect(game.status().score).toBe(1);
    for (let i = 0; i < 120; i++) game.update(1 / 60, frame);
    const bush = stage.fixtures[1];
    const lit = Array.from({ length: bush.count }, (_, i) => frame.data[(bush.offset + i) * 3]).filter((v) => v > 0.3).length;
    expect(lit).toBeGreaterThan(bush.count * 0.5);
  });

  it('loses a life on a press outside the gate', () => {
    const stage = buildStage(sampleLayout());
    const game = catcherGame(stage);
    const frame = new Frame(stage.pixelCount);
    game.input({ playerId: 'p', action: 'press' });
    game.update(1 / 60, frame);
    // The comet starts at the left end; the gate is never right there.
    game.input({ playerId: 'p', action: 'press' });
    expect(game.status()).toMatchObject({ phase: 'miss', lives: 2 });
  });

  it('asks for a roofline when there is none', () => {
    const layout = sampleLayout();
    layout.fixtures = layout.fixtures.filter((f) => f.kind !== 'roof');
    expect(catcherGame(buildStage(layout)).status().phase).toBe('setup');
  });
});

describe('game host', () => {
  it('streams the layout, status and binary frames, and starts a game', async () => {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(sampleLayout(), () => {});
    host.attach(server, '/api/play');

    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    const seen = { layout: false, frames: 0, statuses: [] as any[] };
    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        seen.frames++;
        expect((data as Buffer).length).toBe((450 + 180) * 3);
      } else {
        const m = JSON.parse(String(data));
        if (m.type === 'layout') seen.layout = true;
        if (m.type === 'status') seen.statuses.push(m.status);
      }
    });
    await new Promise((r) => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', game: 'catcher' }));
    await new Promise((r) => setTimeout(r, 300));
    expect(seen.layout).toBe(true);
    expect(seen.frames).toBeGreaterThan(5);
    expect(seen.statuses.at(-1)).toMatchObject({ game: 'catcher', phase: 'ready', players: 1 });
    ws.close();
    host.stop();
    server.close();
  });

  it('streams compressed frames 30 times a second to a browser that asks, and nothing while the yard is still', async () => {
    const zlib = await import('node:zlib');
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(sampleLayout(), () => {});
    host.attach(server, '/api/play');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/play?frames=deflate`);
    const sizes: number[] = [];
    let last: Buffer | null = null;
    ws.on('message', (data, isBinary) => {
      if (!isBinary) return;
      sizes.push((data as Buffer).length);
      last = zlib.inflateRawSync(data as Buffer);
    });
    await new Promise((r) => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', game: 'catcher' }));
    await new Promise((r) => setTimeout(r, 1000));
    expect(sizes.length).toBeGreaterThanOrEqual(25);
    expect(sizes.length).toBeLessThanOrEqual(32);
    expect(last!.length).toBe((450 + 180) * 3);
    // Mostly dark: far smaller than the raw frame.
    expect(Math.max(...sizes)).toBeLessThan(((450 + 180) * 3) / 3);
    // A still yard (a solid color scene) sends one frame, then nothing until it changes.
    ws.send(JSON.stringify({ type: 'stop' }));
    host.playEffects({ '*': { ...defaultSettings('solid'), brightness: 1 } });
    await new Promise((r) => setTimeout(r, 300));
    const before = sizes.length;
    await new Promise((r) => setTimeout(r, 300));
    expect(sizes.length).toBe(before);
    ws.close();
    host.stop();
    server.close();
  });

  it('ends a game at once when the player says goodbye, and drops a browser that stops answering', async () => {
    const server = http.createServer();
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const host = new GameHost(sampleLayout(), () => {}, undefined, 200);
    host.attach(server, '/api/play');
    const players = () => (host as any).clients.size as number;

    const a = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    await new Promise((r) => a.on('open', r));
    a.send(JSON.stringify({ type: 'start', game: 'catcher' }));
    a.send(JSON.stringify({ type: 'leave' }));
    await new Promise((r) => setTimeout(r, 100));
    expect(players()).toBe(0);
    // The last player left, so the game ended: the next visitor starts at the game picker.
    expect((host as any).game.id).toBe('idle');

    // A half-open connection: the browser is gone, but nothing closed the socket.
    const b = new WebSocket(`ws://127.0.0.1:${port}/api/play`);
    await new Promise((r) => b.on('open', r));
    expect(players()).toBe(1);
    (b as any)._socket.pause(); // stops reading, so it never answers a ping
    await new Promise((r) => setTimeout(r, 700));
    expect(players()).toBe(0);
    host.stop();
    server.close();
  });
});

describe('line editing', () => {
  const base: Fixture = {
    id: 'r',
    name: 'R',
    kind: 'roof',
    points: [
      { x: 0, y: 100 },
      { x: 100, y: 100 }
    ],
    pixels: 11,
    deviceId: 'd',
    startPixel: 20,
    reversed: false
  };

  it('continues a line from its last point at the same LED spacing, and keeps the old LED numbers', async () => {
    const { extendLine } = await import('../../shared/layout.ts');
    const { patch, shifted } = extendLine(base, 'last', [
      { x: 100, y: 0 },
      { x: 150, y: 0 }
    ]);
    expect(shifted).toBe(false);
    expect(patch.points).toHaveLength(4);
    // 10 units per LED step: 100 more units → 10 LEDs, then 50 → 5 LEDs.
    expect(patch.pixels).toBe(26);
    expect(patch.startPixel).toBe(20);
    const f = { ...base, ...patch };
    expect(pointOffsets(f)).toEqual([0, 10, 20, 25]);
    expect(deviceLed(f, 10)).toBe(30);
  });

  it('continues a line from its first point; the start moves down so old LEDs keep their numbers', async () => {
    const { extendLine } = await import('../../shared/layout.ts');
    const { patch } = extendLine(base, 'first', [{ x: -50, y: 100 }]);
    const f = { ...base, ...patch };
    expect(f.points[0]).toEqual({ x: -50, y: 100 });
    expect(f.pixels).toBe(16);
    expect(f.startPixel).toBe(15);
    // The old first point still has device LED 20.
    expect(deviceLed(f, pointOffsets(f)[1])).toBe(20);
    // Not enough room below LED 0: the numbers start at 0 instead.
    expect(extendLine({ ...base, startPixel: 2 }, 'first', [{ x: -50, y: 100 }]).shifted).toBe(true);
  });

  it('snaps to points, midpoints and alignments, and keeps 45° steps with Shift', async () => {
    const { snapPoint, constrainAngle } = await import('../../web/src/yard/snap.ts');
    const targets = {
      points: [
        { u: 0, v: 0 },
        { u: 100, v: 0 }
      ],
      segments: [
        [
          { u: 0, v: 0 },
          { u: 100, v: 0 }
        ]
      ] as [{ u: number; v: number }, { u: number; v: number }][],
      centers: []
    };
    expect(snapPoint({ u: 97, v: 4 }, targets, 8, {}).kind).toBe('point');
    expect(snapPoint({ u: 52, v: 3 }, targets, 8, {})).toMatchObject({ kind: 'mid', at: { u: 50, v: 0 } });
    expect(snapPoint({ u: 30, v: 5 }, targets, 8, {})).toMatchObject({ kind: 'on', at: { u: 30, v: 0 } });
    expect(snapPoint({ u: 103, v: 60 }, targets, 8, {})).toMatchObject({ kind: 'align', at: { u: 100, v: 60 } });
    expect(snapPoint({ u: 103, v: 60 }, targets, 8, { snap: false }).kind).toBe('free');
    expect(constrainAngle({ u: 0, v: 0 }, { u: 100, v: 8 })).toEqual({ u: 100, v: 0 });
    const diag = constrainAngle({ u: 0, v: 0 }, { u: 100, v: 90 });
    expect(diag.u).toBeCloseTo(diag.v);
  });

  it('snaps to the grid where nothing else is near, and moves a point straight up exactly', async () => {
    const { snapPoint, onGrid } = await import('../../web/src/yard/snap.ts');
    const none = { points: [], segments: [], centers: [] };
    const grid = { step: 24.38, origin: { u: 0, v: 300 } };
    // The nearest crossing, counted from the origin (the ground in the front view).
    expect(snapPoint({ u: 30, v: 260 }, none, 8, { grid })).toMatchObject({ kind: 'grid', at: { u: 24.38, v: 251.24 } });
    expect(onGrid(-13, grid, 'u')).toBe(-24.38);
    // Points and lines win over the grid; without a grid, nothing changes.
    const roof = { points: [{ u: 100, v: 100 }], segments: [], centers: [] };
    expect(snapPoint({ u: 97, v: 103 }, roof, 8, { grid }).kind).toBe('point');
    expect(snapPoint({ u: 30, v: 260 }, none, 8, {}).kind).toBe('free');
    // Lined up with a point one way, on the grid the other way.
    expect(snapPoint({ u: 103, v: 160 }, roof, 8, { grid })).toMatchObject({ kind: 'align', at: { u: 100, v: 153.72 } });
    // Snapping to objects off: the grid still holds.
    expect(snapPoint({ u: 97, v: 103 }, roof, 8, { grid, snap: false }).kind).toBe('grid');

    // A move locked to 90° from where the point started (Shift-drag): the other coordinate stays exactly the same,
    // even when the point is not on a whole unit.
    const start = { u: 50.37, v: 200.5 };
    const up = snapPoint({ u: 58, v: 120 }, none, 8, { from: start, angle: 90 });
    expect(up).toMatchObject({ kind: 'angle', at: { u: 50.37, v: 120 } });
    expect(snapPoint({ u: 58, v: 120 }, none, 8, { from: start, angle: 90, grid })).toMatchObject({ kind: 'grid', at: { u: 50.37, v: 129.34 } });
    expect(snapPoint({ u: 140, v: 205 }, none, 8, { from: start, angle: 90, grid }).at.v).toBe(200.5);
  });

  it('fits the whole roof in the yard view, even a peak above the picture', async () => {
    const { fitBox } = await import('../../web/src/yard/YardView.tsx');
    const layout = sampleLayout();
    const inside = fitBox(layout, 'front', [-480, 480]);
    expect(inside.x).toBeLessThanOrEqual(0);
    expect(inside.y).toBeLessThanOrEqual(0);
    expect(inside.x + inside.w).toBeGreaterThanOrEqual(layout.width);
    // Raise the middle of the roof above the top of the picture, and past its right edge.
    const roof = layout.fixtures[0];
    const pts = roof.points.map((p) => ({ ...p }));
    pts[1] = { ...pts[1], y: -120 };
    pts[pts.length - 1] = { ...pts[pts.length - 1], x: layout.width + 200 };
    layout.fixtures[0] = { ...roof, points: pts };
    const b = fitBox(layout, 'front', [-480, 480]);
    expect(b.y).toBeLessThan(-120);
    expect(b.x + b.w).toBeGreaterThan(layout.width + 200);
    expect(b.y + b.h).toBeGreaterThanOrEqual(layout.height);
  });
});
