import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { MAX_SEQUENCE_SECONDS, TRANSITION_CHOICES, type AudioClip, type AudioTrack, type Marker, type SeqClip, type SeqTrack, type Sequence, type TransitionChoice } from '../../shared/sequence.ts';
import { effectSettingsSchema } from './layoutStore.ts';
import type { SchemaOf } from './schemaOf.ts';

const id = z.string().min(1).max(64);
const seconds = z.number().finite().min(0).max(MAX_SEQUENCE_SECONDS);
const transition = z.enum(TRANSITION_CHOICES.map((t) => t.id) as [TransitionChoice, ...TransitionChoice[]]);

const clipSchema = z.object({
  id,
  start: seconds,
  duration: z.number().finite().min(0.05).max(MAX_SEQUENCE_SECONDS),
  targets: z.array(z.string().min(1).max(72)).min(1).max(128),
  effect: effectSettingsSchema,
  fadeIn: seconds.optional(),
  fadeOut: seconds.optional(),
  transitionIn: transition.optional(),
  transitionOut: transition.optional(),
  eachObject: z.boolean().optional(),
  name: z.string().trim().max(80).optional()
} satisfies SchemaOf<SeqClip>);

const trackSchema = z.object({
  id,
  name: z.string().trim().min(1).max(60),
  clips: z.array(clipSchema).max(1000),
  opacity: z.number().min(0).max(1),
  blend: z.enum(['normal', 'add', 'lighten', 'multiply']),
  hidden: z.boolean().optional(),
  solo: z.boolean().optional(),
  locked: z.boolean().optional()
} satisfies SchemaOf<SeqTrack>);

const audioClipSchema = z.object({ id, fileId: id, name: z.string().max(200), start: seconds, offset: seconds, duration: z.number().finite().min(0.05).max(MAX_SEQUENCE_SECONDS) } satisfies SchemaOf<AudioClip>);

const audioTrackSchema = z.object({
  id,
  name: z.string().trim().min(1).max(60),
  clips: z.array(audioClipSchema).max(200),
  volume: z.number().min(0).max(1),
  muted: z.boolean().optional()
} satisfies SchemaOf<AudioTrack>);

/** A sequence as the editor sends it (the id comes from the URL). */
export const sequenceInput = z.object({
  name: z.string().trim().min(1, 'Name is required').max(100),
  duration: z.number().finite().min(1).max(MAX_SEQUENCE_SECONDS),
  loop: z.boolean().optional(),
  bpm: z.number().min(20).max(400).optional(),
  tracks: z.array(trackSchema).max(64),
  audio: z.array(audioTrackSchema).max(16).default([]),
  markers: z.array(z.object({ id, t: seconds, label: z.string().max(60).optional() } satisfies SchemaOf<Marker>)).max(1000).default([])
} satisfies SchemaOf<Omit<Sequence, 'id' | 'updatedAt'>>);

// Audio files sit next to the database, one file per upload.
export function audioDir(databasePath: string) {
  return path.join(databasePath === ':memory:' ? path.join(os.tmpdir(), `wled-presets-test-${process.pid}`) : path.dirname(databasePath), 'audio');
}

export const audioPath = (databasePath: string, fileId: string) => path.join(audioDir(databasePath), fileId.replace(/[^\w-]/g, ''));

export function writeAudio(databasePath: string, fileId: string, bytes: Uint8Array) {
  fs.mkdirSync(audioDir(databasePath), { recursive: true });
  fs.writeFileSync(audioPath(databasePath, fileId), bytes);
}

export function readAudio(databasePath: string, fileId: string): Buffer | null {
  try {
    return fs.readFileSync(audioPath(databasePath, fileId));
  } catch {
    return null;
  }
}

export function removeAudio(databasePath: string, fileId: string) {
  fs.rmSync(audioPath(databasePath, fileId), { force: true });
}
