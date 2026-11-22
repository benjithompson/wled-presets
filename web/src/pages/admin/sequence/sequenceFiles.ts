// Saving a sequence to a file on this computer, and opening one: the browser's side of
// shared/sequenceFile.ts. The file carries the audio the sequence plays, so it opens with its
// music on any copy of the site.
import { YARD } from '../../../../../shared/effects.ts';
import type { Layout } from '../../../../../shared/layout.ts';
import type { Sequence } from '../../../../../shared/sequence.ts';
import { readSequenceFile, remapAudio, sequenceAudioIds, sequenceFileName, writeSequenceFile, type SequenceFileAudio } from '../../../../../shared/sequenceFile.ts';
import { api } from '../../../lib/api.ts';

/** Downloads the sequence as it is in the editor, saved or not. Returns the audio files it couldn't include. */
export async function saveSequenceFile(seq: Sequence): Promise<{ name: string; missing: string[] }> {
  const ids = sequenceAudioIds(seq);
  const names = new Map(ids.length ? (await api.audioFiles()).files.map((f) => [f.id, f.name]) : []);
  const clipName = (id: string) => seq.audio.flatMap((t) => t.clips).find((c) => c.fileId === id)?.name ?? 'Audio';
  const audio: SequenceFileAudio[] = [];
  const missing: string[] = [];
  for (const id of ids) {
    const res = await fetch(api.audioUrl(id), { credentials: 'same-origin' });
    if (!res.ok) {
      missing.push(names.get(id) ?? clipName(id));
      continue;
    }
    const blob = await res.blob();
    const type = (res.headers.get('content-type') ?? blob.type).split(';')[0].trim() || 'audio/mpeg';
    audio.push({ id, name: names.get(id) ?? clipName(id), type, data: await toBase64(blob) });
  }
  const name = sequenceFileName(seq.name);
  download(new Blob([writeSequenceFile(seq, audio)], { type: 'application/json' }), name);
  return { name, missing };
}

/**
 * Reads a sequence file: the server checks the sequence, then its audio is uploaded (a file
 * already here, the same one, is used again). The sequence comes back unsaved, with the
 * objects it lights that this yard doesn't have.
 */
export async function openSequenceFile(file: File, layout: Layout | undefined): Promise<{ sequence: Sequence; unknownObjects: string[] }> {
  const { sequence, audio } = readSequenceFile(await file.text());
  const checked = await api.checkSequence(sequence);
  const here = audio.length ? (await api.audioFiles()).files : [];
  const ids: Record<string, string> = {};
  for (const a of audio) {
    const bytes = fromBase64(a.data);
    const same = here.find((f) => f.id === a.id && f.size === bytes.length) ?? here.find((f) => f.name === a.name && f.size === bytes.length && f.type === a.type);
    ids[a.id] = same ? same.id : (await api.uploadAudio(new File([bytes], a.name, { type: a.type }))).id;
  }
  const known = new Set(layout?.fixtures.map((f) => f.id) ?? []);
  const targets = checked.tracks.flatMap((t) => t.clips.flatMap((c) => c.targets));
  const unknownObjects = layout ? [...new Set(targets.filter((t) => t !== YARD).map((t) => t.split('#')[0]))].filter((id) => !known.has(id)) : [];
  return { sequence: { ...remapAudio(checked, ids), id: '' }, unknownObjects };
}

function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

function toBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).slice(String(r.result).indexOf(',') + 1));
    r.onerror = () => reject(r.error ?? new Error('Could not read the audio'));
    r.readAsDataURL(blob);
  });
}

function fromBase64(data: string): Uint8Array<ArrayBuffer> {
  let bin: string;
  try {
    bin = atob(data);
  } catch {
    throw new Error('An audio file in the sequence file is damaged.');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
