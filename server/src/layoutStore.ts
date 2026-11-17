import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { deviceRuns, LAYOUT_WIDTH, MAX_FIXTURE_PIXELS, sampleLayout, type Layout } from '../../shared/layout.ts';
import type { Db } from './db.ts';

const KEY = 'layout';
const BG_TYPE_KEY = 'layoutBackgroundType';

const point = z.object({ x: z.number().finite(), y: z.number().finite() });

/** The shape only. `layoutSchema` adds the checks a saved layout must pass. */
export const layoutShape = z.object({
  width: z.literal(LAYOUT_WIDTH),
  height: z.number().min(200).max(4000),
  background: z.string().max(200).nullable(),
  fixtures: z
    .array(
      z.object({
        id: z.string().min(1).max(64),
        name: z.string().trim().min(1).max(60),
        kind: z.enum(['roof', 'bush']),
        points: z.array(point).min(1).max(64),
        radius: z.number().min(5).max(2000).optional(),
        pattern: z.enum(['fill', 'ring', 'spiral']).optional(),
        pixels: z.number().int().min(1).max(MAX_FIXTURE_PIXELS),
        deviceId: z.string().nullable(),
        startPixel: z.number().int().min(0).max(10_000),
        reversed: z.boolean(),
        pointLeds: z.array(z.number().int().min(0).max(MAX_FIXTURE_PIXELS).nullable()).max(64).optional(),
        skip: z.array(z.number().int().min(0).max(64)).max(64).optional()
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

// The background picture is a file next to the database, not a database row.
export function backgroundFile(databasePath: string) {
  return path.join(databasePath === ':memory:' ? process.cwd() : path.dirname(databasePath), 'layout-background');
}

export function saveBackground(db: Db, databasePath: string, bytes: Uint8Array, type: string) {
  fs.writeFileSync(backgroundFile(databasePath), bytes);
  db.setSetting(BG_TYPE_KEY, type);
}

export function readBackground(db: Db, databasePath: string): { bytes: Buffer; type: string } | null {
  try {
    return { bytes: fs.readFileSync(backgroundFile(databasePath)), type: db.getSetting(BG_TYPE_KEY) || 'image/jpeg' };
  } catch {
    return null;
  }
}

export function deleteBackground(databasePath: string) {
  fs.rmSync(backgroundFile(databasePath), { force: true });
}
