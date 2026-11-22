// A sequence saved to a file, to keep it outside the site or open it on another one.
//
// The file is JSON: the sequence and, inside it, the audio its clips play (base64), so it
// opens with its music anywhere. The objects it lights are named by their ids in the layout:
// on another yard, clips for objects it doesn't have light nothing until they are retargeted.
import type { Sequence } from './sequence.ts';

export const SEQUENCE_FILE_FORMAT = 'wled-presets-sequence';
export const SEQUENCE_FILE_VERSION = 1;
export const SEQUENCE_FILE_EXT = '.wledseq';

/** One audio file a sequence plays, inside the file. */
export interface SequenceFileAudio {
  /** Its id where the file was saved: the sequence's audio clips name it. */
  id: string;
  name: string;
  type: string;
  /** The bytes, base64. */
  data: string;
}

export interface SequenceFile {
  format: typeof SEQUENCE_FILE_FORMAT;
  version: number;
  savedAt: string;
  sequence: Omit<Sequence, 'id' | 'updatedAt'>;
  audio: SequenceFileAudio[];
}

/** The audio files a sequence plays, each once. */
export const sequenceAudioIds = (seq: Pick<Sequence, 'audio'>) => [...new Set(seq.audio.flatMap((t) => t.clips.map((c) => c.fileId)))];

/** A file name for the sequence: its name, without what file systems refuse. */
export function sequenceFileName(name: string): string {
  const base = name.replace(/[\\/:*?"<>|\u0000-\u001f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80) || 'Sequence';
  return base + SEQUENCE_FILE_EXT;
}

export function writeSequenceFile(seq: Sequence, audio: SequenceFileAudio[], savedAt = new Date()): string {
  const { id: _id, updatedAt: _u, ...sequence } = seq;
  const file: SequenceFile = { format: SEQUENCE_FILE_FORMAT, version: SEQUENCE_FILE_VERSION, savedAt: savedAt.toISOString(), sequence, audio };
  return JSON.stringify(file);
}

/**
 * Reads a sequence file. The sequence comes back unchecked (the server checks it, as it checks
 * one being saved); the wrapper and its audio are checked here. A plain sequence, as the API
 * gives it, opens too, without audio. Throws an Error that says what is wrong.
 */
export function readSequenceFile(text: string): { sequence: unknown; audio: SequenceFileAudio[] } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('This is not a sequence file (it is not JSON).');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('This is not a sequence file.');
  const o = raw as Record<string, unknown>;
  if (o.format === undefined && Array.isArray(o.tracks)) {
    const { id: _id, updatedAt: _u, ...sequence } = o;
    return { sequence, audio: [] };
  }
  if (o.format !== SEQUENCE_FILE_FORMAT) throw new Error('This is not a sequence file.');
  if (typeof o.version !== 'number' || o.version > SEQUENCE_FILE_VERSION) throw new Error('This sequence file is from a newer version of the site: update it to open the file.');
  if (!o.sequence || typeof o.sequence !== 'object') throw new Error('The sequence file has no sequence in it.');
  const audio = Array.isArray(o.audio) ? o.audio : [];
  for (const a of audio) {
    const ok = a && typeof a === 'object' && typeof a.id === 'string' && typeof a.name === 'string' && typeof a.type === 'string' && /^audio\/[\w.+-]+$/.test(a.type) && typeof a.data === 'string';
    if (!ok) throw new Error('An audio file in the sequence file is damaged.');
  }
  return { sequence: o.sequence, audio: audio as SequenceFileAudio[] };
}

/** The sequence with its audio clips playing other files: `ids` maps an old id to a new one. */
export function remapAudio<S extends Pick<Sequence, 'audio'>>(seq: S, ids: Record<string, string>): S {
  return { ...seq, audio: seq.audio.map((t) => ({ ...t, clips: t.clips.map((c) => (ids[c.fileId] ? { ...c, fileId: ids[c.fileId] } : c)) })) };
}
