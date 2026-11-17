// Editing a sequence: small pure functions the timeline, the inspector and the shortcuts share.
import { defaultSettings, effectTarget, YARD, type EffectId, type EffectSettings } from '../../../../../shared/effects.ts';
import { isLine, type Layout } from '../../../../../shared/layout.ts';
import { clipEnd, newId, type AudioClip, type SeqClip, type SeqTrack, type Sequence } from '../../../../../shared/sequence.ts';

/** What is selected in the editor. Clips can be several at once. */
export type Selection =
  | { kind: 'clips'; ids: string[] }
  | { kind: 'audio'; ids: string[] }
  | { kind: 'track'; id: string }
  | { kind: 'audioTrack'; id: string }
  | { kind: 'marker'; id: string }
  | null;

export const MIN_CLIP = 0.1;
/** A new clip from the effects: this long, unless the layer or the sequence ends sooner. */
export const NEW_CLIP_SECONDS = 8;

export function findClip(seq: Sequence, id: string): { track: SeqTrack; clip: SeqClip; ti: number } | null {
  for (let ti = 0; ti < seq.tracks.length; ti++) {
    const clip = seq.tracks[ti].clips.find((c) => c.id === id);
    if (clip) return { track: seq.tracks[ti], clip, ti };
  }
  return null;
}

export function findAudioClip(seq: Sequence, id: string): { clip: AudioClip; ti: number } | null {
  for (let ti = 0; ti < seq.audio.length; ti++) {
    const clip = seq.audio[ti].clips.find((c) => c.id === id);
    if (clip) return { clip, ti };
  }
  return null;
}

export function updateClips(seq: Sequence, ids: Iterable<string>, fn: (c: SeqClip) => SeqClip): Sequence {
  const set = new Set(ids);
  return { ...seq, tracks: seq.tracks.map((t) => (t.clips.some((c) => set.has(c.id)) ? { ...t, clips: t.clips.map((c) => (set.has(c.id) ? fn(c) : c)) } : t)) };
}

export function updateTrack(seq: Sequence, id: string, patch: Partial<SeqTrack>): Sequence {
  return { ...seq, tracks: seq.tracks.map((t) => (t.id === id ? { ...t, ...patch } : t)) };
}

export function removeClips(seq: Sequence, ids: Iterable<string>): Sequence {
  const set = new Set(ids);
  return {
    ...seq,
    tracks: seq.tracks.map((t) => (t.locked ? t : { ...t, clips: t.clips.filter((c) => !set.has(c.id)) })),
    audio: seq.audio.map((t) => ({ ...t, clips: t.clips.filter((c) => !set.has(c.id)) }))
  };
}

/** Cuts the clips in two at `t` (the ones that play then). Returns the sequence and the ids of the right halves. */
export function splitClips(seq: Sequence, ids: string[] | null, t: number): { seq: Sequence; added: string[] } {
  const added: string[] = [];
  const pick = ids ? new Set(ids) : null;
  const tracks = seq.tracks.map((tr) => {
    if (tr.locked) return tr;
    const clips: SeqClip[] = [];
    for (const c of tr.clips) {
      if ((pick && !pick.has(c.id)) || t <= c.start + MIN_CLIP || t >= clipEnd(c) - MIN_CLIP) {
        clips.push(c);
        continue;
      }
      const right: SeqClip = { ...c, id: newId('clip'), start: t, duration: clipEnd(c) - t, fadeIn: 0 };
      clips.push({ ...c, duration: t - c.start, fadeOut: 0 }, right);
      added.push(right.id);
    }
    return { ...tr, clips };
  });
  const audio = seq.audio.map((tr) => {
    const clips: AudioClip[] = [];
    for (const c of tr.clips) {
      if ((pick && !pick.has(c.id)) || t <= c.start + MIN_CLIP || t >= c.start + c.duration - MIN_CLIP) {
        clips.push(c);
        continue;
      }
      const cut = t - c.start;
      const right: AudioClip = { ...c, id: newId('aclip'), start: t, offset: c.offset + cut, duration: c.duration - cut };
      clips.push({ ...c, duration: cut }, right);
      added.push(right.id);
    }
    return { ...tr, clips };
  });
  return { seq: { ...seq, tracks, audio }, added };
}

/** A new clip of an effect on a layer, from `start`. */
export function makeClip(seq: Sequence, track: SeqTrack, effect: EffectId | EffectSettings, start: number, targets: string[]): SeqClip {
  const s = Math.max(0, Math.min(start, seq.duration - MIN_CLIP));
  // Up to the next clip on the layer, or the end.
  const next = track.clips.filter((c) => c.start > s + 0.5).reduce((m, c) => Math.min(m, c.start), Infinity);
  const duration = Math.max(1, Math.min(NEW_CLIP_SECONDS, next - s, seq.duration - s));
  return {
    id: newId('clip'),
    start: round(s),
    duration: round(Math.min(duration, seq.duration - s)),
    targets: targets.length ? targets : [YARD],
    effect: typeof effect === 'string' ? { ...defaultSettings(effect), brightness: 1 } : effect,
    fadeIn: 0.5,
    fadeOut: 0.5
  };
}

export const round = (t: number) => Math.round(t * 1000) / 1000;

/** Names of the things a clip plays on, for its label: "Whole yard", "Roofline", "Roofline · segment 2". */
export function targetName(layout: Layout | undefined, key: string): string {
  if (key === YARD) return 'Whole yard';
  const t = effectTarget(key);
  const f = layout?.fixtures.find((x) => x.id === t.id);
  if (!f) return 'Missing object';
  return t.segment == null ? f.name : `${f.name} · segment ${t.segment + 1}`;
}

export function targetsLabel(layout: Layout | undefined, keys: string[]): string {
  if (!keys.length) return 'Nothing';
  if (keys.includes(YARD)) return 'Whole yard';
  const names = keys.map((k) => targetName(layout, k));
  return names.length <= 2 ? names.join(' + ') : `${names[0]} + ${names.length - 1} more`;
}

/** Every target you can pick: the yard, each object, and each segment of each line. */
export function allTargets(layout: Layout | undefined): { key: string; name: string; depth: number; kind?: string }[] {
  const out: { key: string; name: string; depth: number; kind?: string }[] = [{ key: YARD, name: 'Whole yard', depth: 0 }];
  for (const f of layout?.fixtures ?? []) {
    out.push({ key: f.id, name: f.name, depth: 0, kind: f.kind });
    if (isLine(f) && f.points.length > 2) for (let k = 0; k < f.points.length - 1; k++) out.push({ key: `${f.id}#${k}`, name: `Segment ${k + 1}`, depth: 1 });
  }
  return out;
}

/** Times a dragged edge can stick to: the start, the end, the playhead, every clip edge and marker. */
export function snapPoints(seq: Sequence, playhead: number, skip: Set<string>): number[] {
  const out = [0, seq.duration, playhead];
  for (const t of seq.tracks) for (const c of t.clips) if (!skip.has(c.id)) out.push(c.start, clipEnd(c));
  for (const t of seq.audio) for (const c of t.clips) if (!skip.has(c.id)) out.push(c.start, c.start + c.duration);
  for (const m of seq.markers) out.push(m.t);
  return out;
}

/** Sticks `t` to the nearest point within `px` pixels, or to the beat grid. */
export function snapTime(t: number, points: number[], pps: number, bpm: number | undefined, px = 8): number {
  let best = t;
  let dist = px / pps;
  for (const p of points) {
    const d = Math.abs(p - t);
    if (d < dist) {
      dist = d;
      best = p;
    }
  }
  if (best !== t) return best;
  if (bpm) {
    const beat = 60 / bpm;
    const g = Math.round(t / beat) * beat;
    if (Math.abs(g - t) * pps < px) return g;
  }
  return t;
}

/** 83.25 -> "1:23.25" */
export function fmtTime(t: number, cents = true): string {
  const s = Math.max(0, t);
  const m = Math.floor(s / 60);
  const sec = s - m * 60;
  const whole = Math.floor(sec);
  const frac = Math.floor((sec - whole) * 100);
  return `${m}:${String(whole).padStart(2, '0')}${cents ? `.${String(frac).padStart(2, '0')}` : ''}`;
}

/** "1:23.5", "83.5", "1:23" -> seconds (null when not a time). */
export function parseTime(text: string): number | null {
  const m = /^\s*(?:(\d+):)?(\d+(?:\.\d*)?)\s*$/.exec(text);
  if (!m) return null;
  return (m[1] ? Number(m[1]) * 60 : 0) + Number(m[2]);
}
