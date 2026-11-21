import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { DIRECTIONS, EFFECTS, PALETTES, type Direction, type EffectId, type PaletteId } from '../../shared/effects.ts';
import { deviceRuns, LAYOUT_WIDTH, MAX_FIXTURE_PIXELS, sampleLayout, type Layout } from '../../shared/layout.ts';
import type { Db } from './db.ts';

const KEY = 'layout';
const BG_TYPE_KEY = 'layoutBackgroundType';

const coord = z.number().finite().min(-20_000).max(20_000);
const unit = z.number().finite().min(0).max(1);

/** One object's effect, in a layout or a scene. */
export const effectSettingsSchema = z.object({
  effect: z.enum(EFFECTS.map((e) => e.id) as [EffectId, ...EffectId[]]),
  palette: z.enum(PALETTES.map((p) => p.id) as [PaletteId, ...PaletteId[]]),
  colors: z
    .array(z.string().regex(/^#[0-9a-fA-F]{6}$/))
    .min(1)
    .max(6)
    .optional(),
  speed: unit,
  intensity: unit,
  size: unit,
  brightness: unit,
  reverse: z.boolean().optional(),
  direction: z.enum(Object.keys(DIRECTIONS) as [Direction, ...Direction[]]).optional()
});

/** Effects by layout object id, or "<object id>#<segment>" for one segment of a line. */
export const effectsSchema = z.record(z.string().min(1).max(72), effectSettingsSchema).refine((r) => Object.keys(r).length <= 512, 'Too many effects');
const point = z.object({ x: coord, y: coord, z: coord.optional() });
const id = z.string().min(1).max(64);

/** A light string type of your own (see shared/lights.ts). */
const lightTypeSchema = z.object({
  id,
  name: z.string().trim().min(1).max(80),
  chip: z.string().trim().min(1).max(40),
  volts: z.number().min(1).max(60),
  style: z.enum(['bullet', 'bulb', 'strip', 'module', 'other']),
  spacing: z.number().min(0.001).max(10),
  perStrand: z.number().int().min(1).max(MAX_FIXTURE_PIXELS).nullable(),
  milliamps: z.number().min(0).max(1000)
});

/** A custom object's strokes, in meters (at most 100 m from its anchor). */
const meters = z.number().finite().min(-100).max(100);
// A scanned stroke has a point for each LED (exact), so up to a whole string's worth.
const strokesSchema = z
  .array(z.object({ points: z.array(z.object({ x: meters, y: meters, z: meters.optional() })).min(1).max(MAX_FIXTURE_PIXELS), closed: z.boolean().optional(), exact: z.boolean().optional() }))
  .max(64)
  .refine((list) => list.reduce((a, s) => a + s.points.length, 0) <= MAX_FIXTURE_PIXELS * 2, 'Too many points');

const designSchema = z.object({
  id,
  name: z.string().trim().min(1).max(60),
  strokes: strokesSchema,
  pixels: z.number().int().min(1).max(MAX_FIXTURE_PIXELS),
  lights: id.optional()
});

/** The shape only. `layoutSchema` adds the checks a saved layout must pass. */
export const layoutShape = z.object({
  width: z.literal(LAYOUT_WIDTH),
  height: z.number().min(200).max(4000),
  background: z.string().max(200).nullable(),
  scale: z.number().min(1).max(10_000).optional(),
  units: z.enum(['ft', 'm']).optional(),
  groundY: coord.optional(),
  /** The whole yard's effect. */
  effect: effectSettingsSchema.optional(),
  lightTypes: z.array(lightTypeSchema).max(100).optional(),
  lights: id.optional(),
  designs: z.array(designSchema).max(200).optional(),
  aerial: z
    .object({
      url: z.string().max(200),
      x: coord,
      z: coord,
      width: z.number().min(10).max(200_000),
      aspect: z.number().min(0.02).max(50),
      rotation: z.number().finite().min(-3600).max(3600),
      opacity: unit.optional()
    })
    .nullable()
    .optional(),
  fixtures: z
    .array(
      z.object({
        id: z.string().min(1).max(64),
        name: z.string().trim().min(1).max(60),
        kind: z.enum(['roof', 'line', 'bush', 'tree', 'semicircle', 'custom']),
        points: z.array(point).min(1).max(64),
        radius: z.number().min(5).max(4000).optional(),
        height: z.number().min(5).max(8000).optional(),
        pattern: z.enum(['fill', 'ring', 'spiral', 'strands']).optional(),
        turns: z.number().min(0.5).max(100).optional(),
        strands: z.number().int().min(1).max(64).optional(),
        shape: z.enum(['cone', 'cylinder', 'sphere']).optional(),
        spin: z.enum(['ccw', 'cw']).optional(),
        start: z.enum(['base', 'top']).optional(),
        zigzag: z.enum(['down', 'up', 'right', 'left']).optional(),
        pixels: z.number().int().min(1).max(MAX_FIXTURE_PIXELS),
        lights: id.optional(),
        design: strokesSchema.optional(),
        designId: id.optional(),
        size: z.number().min(0.01).max(100).optional(),
        rotation: z.number().finite().min(-3600).max(3600).optional(),
        facing: z.number().finite().min(-3600).max(3600).optional(),
        deviceId: z.string().nullable(),
        startPixel: z.number().int().min(0).max(10_000),
        reversed: z.boolean(),
        pointLeds: z.array(z.number().int().min(0).max(MAX_FIXTURE_PIXELS).nullable()).max(64).optional(),
        skip: z.array(z.number().int().min(0).max(64)).max(64).optional(),
        effect: effectSettingsSchema.optional(),
        segmentEffects: z.record(z.string().regex(/^\d{1,2}$/, 'Segment index'), effectSettingsSchema).optional()
      })
    )
    .max(64)
    .refine((fs) => new Set(fs.map((f) => f.id)).size === fs.length, 'Object ids must be unique')
});

export const layoutSchema = layoutShape.superRefine((layout, ctx) => {
    // Two objects cannot drive the same LED of a device.
    for (const { overlaps } of deviceRuns(layout).values()) {
      for (const [a, b] of overlaps) {
        const name = (id: string) => layout.fixtures.find((f) => f.id === id)?.name ?? id;
        ctx.addIssue({ code: 'custom', message: `${name(a.fixtureId)} and ${name(b.fixtureId)} use the same LEDs (${b.lo}–${Math.min(a.hi, b.hi)}) on one device` });
      }
    }
  });

export function readLayout(db: Db): Layout {
  const raw = db.getSetting(KEY);
  if (!raw) return sampleLayout();
  try {
    const parsed = layoutSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : sampleLayout();
  } catch {
    return sampleLayout();
  }
}

export function writeLayout(db: Db, layout: Layout) {
  db.setSetting(KEY, JSON.stringify(layout));
}

// The pictures are files next to the database, not database rows. background: the front of the
// house. aerial: the yard from above.
export type LayoutPicture = 'background' | 'aerial';
const TYPE_KEYS: Record<LayoutPicture, string> = { background: BG_TYPE_KEY, aerial: 'layoutAerialType' };

export function backgroundFile(databasePath: string, kind: LayoutPicture = 'background') {
  return path.join(databasePath === ':memory:' ? process.cwd() : path.dirname(databasePath), `layout-${kind}`);
}

export function saveBackground(db: Db, databasePath: string, bytes: Uint8Array, type: string, kind: LayoutPicture = 'background') {
  const file = backgroundFile(databasePath, kind);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, bytes);
  db.setSetting(TYPE_KEYS[kind], type);
}

export function readBackground(db: Db, databasePath: string, kind: LayoutPicture = 'background'): { bytes: Buffer; type: string } | null {
  try {
    return { bytes: fs.readFileSync(backgroundFile(databasePath, kind)), type: db.getSetting(TYPE_KEYS[kind]) || 'image/jpeg' };
  } catch {
    return null;
  }
}

export function deleteBackground(databasePath: string, kind: LayoutPicture = 'background') {
  fs.rmSync(backgroundFile(databasePath, kind), { force: true });
}
