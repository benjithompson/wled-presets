// Sequences: an animated light show on a timeline, built like a video in a video editor. Layers
// (tracks) are stacked; each holds clips. A clip plays one effect on some objects (or segments,
// or the whole yard) for a while. Upper layers cover lower ones, mixed by their blend mode and
// opacity. Clips fade in and out, and two clips that overlap on one layer cross over with a
// transition (crossfade, wipe, dissolve...). Audio tracks play along in the editor.
//
// The server plays sequences on the real lights, and the editor draws the same frames in the
// browser. Keep this file free of Node and DOM APIs.

import { clamp01 } from './color.ts';
import { effectObjects, effectTarget, isSpatial, RunSet, YARD, type EffectSettings } from './effects.ts';
import { activeLeds, isLine, segmentLeds, type Layout, type Stage } from './layout.ts';
import { hashUnit, LedPlaces, pickTransition, transitionCoord, transitionWeights, unionBox, type Box, type TransitionChoice, type TransitionId } from './transitions.ts';

export { TRANSITION_CHOICES, TRANSITIONS, transitionInfo, type TransitionChoice, type TransitionId } from './transitions.ts';

export type BlendMode = 'normal' | 'add' | 'lighten' | 'multiply';

export const BLEND_MODES: { id: BlendMode; name: string; description: string }[] = [
  { id: 'normal', name: 'Normal', description: 'Covers the layers below where it lights (dark parts of the effect cover too).' },
  { id: 'add', name: 'Add', description: 'Adds its light to the layers below: sparkles over a wash.' },
  { id: 'lighten', name: 'Lighten', description: 'Shows whichever is brighter, this layer or the layers below.' },
  { id: 'multiply', name: 'Multiply (mask)', description: 'Tints and darkens the layers below with its colors: dark parts hide them.' }
];

export const blendInfo = (id: BlendMode | undefined) => BLEND_MODES.find((b) => b.id === id) ?? BLEND_MODES[0];

export interface SeqClip {
  id: string;
  /** Seconds from the start of the sequence. */
  start: number;
  duration: number;
  /** What it lights: effect keys ("*" the whole yard, an object id, or "<object id>#<segment>"). */
  targets: string[];
  effect: EffectSettings;
  /** Seconds to fade in and out (when no other clip overlaps that end). */
  fadeIn?: number;
  fadeOut?: number;
  /** How it comes in (also over an overlapping clip before it on the layer), and how it goes out. "random": a different one each time round. */
  transitionIn?: TransitionChoice;
  transitionOut?: TransitionChoice;
  /** A label of your own. */
  name?: string;
}

export interface SeqTrack {
  id: string;
  name: string;
  clips: SeqClip[];
  /** 0..1 */
  opacity: number;
  blend: BlendMode;
  /** Hidden layers do not play. */
  hidden?: boolean;
  /** When any layer is solo, only solo layers play. */
  solo?: boolean;
  /** Locked layers cannot be changed in the editor. */
  locked?: boolean;
}

export interface AudioClip {
  id: string;
  /** The uploaded audio file. */
  fileId: string;
  name: string;
  /** Where it starts on the timeline, and where in the file it starts playing (seconds). */
  start: number;
  offset: number;
  duration: number;
}

export interface AudioTrack {
  id: string;
  name: string;
  clips: AudioClip[];
  /** 0..1 */
  volume: number;
  muted?: boolean;
}

export interface Marker {
  id: string;
  t: number;
  label?: string;
}

export interface Sequence {
  id: string;
  name: string;
  /** Seconds. */
  duration: number;
  /** Starts again at the end (in the editor; a scene always loops). */
  loop?: boolean;
  /** Beats per minute: the timeline shows beats and snaps to them. */
  bpm?: number;
  /** The first is the top layer (it covers the others). */
  tracks: SeqTrack[];
  audio: AudioTrack[];
  markers: Marker[];
  updatedAt?: string;
}

/** A sequence in a list: without its tracks. */
export interface SequenceSummary {
  id: string;
  name: string;
  duration: number;
  layers: number;
  clips: number;
  updatedAt?: string;
}

export const MAX_SEQUENCE_SECONDS = 60 * 60;

export function summarize(s: Sequence): SequenceSummary {
  return { id: s.id, name: s.name, duration: s.duration, layers: s.tracks.length, clips: s.tracks.reduce((n, t) => n + t.clips.length, 0), updatedAt: s.updatedAt };
}

export const clipEnd = (c: Pick<SeqClip, 'start' | 'duration'>) => c.start + c.duration;

/** Clips of a layer in time order, each with the clip it overlaps before and after it (they cross over). */
export function neighbours(track: Pick<SeqTrack, 'clips'>): { clip: SeqClip; prev: SeqClip | null; next: SeqClip | null }[] {
  const sorted = [...track.clips].sort((a, b) => a.start - b.start || a.id.localeCompare(b.id));
  return sorted.map((clip, i) => {
    const p = sorted[i - 1];
    const n = sorted[i + 1];
    return { clip, prev: p && clipEnd(p) > clip.start + 1e-6 ? p : null, next: n && n.start < clipEnd(clip) - 1e-6 ? n : null };
  });
}

/** Seconds that clip `b` crosses over clip `a` before it (0: they do not overlap). */
export function overlapOf(a: SeqClip, b: SeqClip): number {
  return Math.max(0, Math.min(clipEnd(a), clipEnd(b)) - b.start, 0);
}

/** The ids of the objects a sequence lights (on layers that play). */
export function sequenceObjects(seq: Pick<Sequence, 'tracks'>, layout: Pick<Layout, 'fixtures'>): string[] {
  return effectObjects(layout, seq.tracks.flatMap((t) => (t.hidden ? [] : t.clips.flatMap((c) => c.targets))));
}

/** Every effect used in a sequence, for its look on the public page. */
export const sequenceEffects = (seq: Pick<Sequence, 'tracks'>) => seq.tracks.flatMap((t) => (t.hidden ? [] : t.clips.map((c) => c.effect)));

/**
 * The stage LEDs that a list of targets reaches, per object (stage indexes, in string order).
 * Segments of an object listed on its own are already in it. LEDs in skipped segments are left out.
 */
export function targetLeds(stage: Stage, layout: Pick<Layout, 'fixtures'>, targets: string[]): { fixture: string; leds: number[] }[] {
  const all = targets.includes(YARD);
  const whole = new Set<string>();
  const segs = new Map<string, Set<number>>();
  for (const key of targets) {
    const t = effectTarget(key);
    if (t.segment == null) whole.add(t.id);
    else segs.set(t.id, (segs.get(t.id) ?? new Set()).add(t.segment));
  }
  const out: { fixture: string; leds: number[] }[] = [];
  layout.fixtures.forEach((f, fi) => {
    const sf = stage.fixtures[fi];
    if (!sf || sf.id !== f.id) return;
    const on = activeLeds(f);
    const pick = new Uint8Array(sf.count);
    if (all || whole.has(f.id)) pick.fill(1);
    else if (segs.has(f.id) && isLine(f)) {
      for (const k of segs.get(f.id)!) {
        if (k >= f.points.length - 1) continue;
        const { lo, hi } = segmentLeds(f, k);
        for (let i = lo; i <= hi && i < sf.count; i++) pick[i] = 1;
      }
    } else return;
    const leds: number[] = [];
    for (let i = 0; i < sf.count; i++) if (pick[i] && (on[i] ?? 1)) leds.push(sf.offset + i);
    if (leds.length) out.push({ fixture: f.id, leds });
  });
  return out;
}

// ---------- Playing ----------

/** The clips that play at time `t`, top layer first, and how far each has come in. */
export function activeAt(seq: Pick<Sequence, 'tracks'>, t: number): ActiveClip[] {
  const out: ActiveClip[] = [];
  const solo = seq.tracks.some((tr) => tr.solo && !tr.hidden);
  for (const track of seq.tracks) {
    if (track.hidden || (solo && !track.solo)) continue;
    for (const { clip, prev } of neighbours(track)) {
      if (t < clip.start || t >= clipEnd(clip)) continue;
      let level = 1;
      let from: ActiveClip['from'];
      if (prev && t < clipEnd(prev)) {
        const ov = overlapOf(prev, clip);
        const p = ov > 0 ? (t - clip.start) / ov : 1;
        level = p;
        from = { clipId: prev.id, p, transition: clip.transitionIn ?? 'fade' };
      } else if (clip.fadeIn && t - clip.start < clip.fadeIn) level = (t - clip.start) / clip.fadeIn;
      if (clip.fadeOut && clipEnd(clip) - t < clip.fadeOut) level = Math.min(level, (clipEnd(clip) - t) / clip.fadeOut);
      out.push({ trackId: track.id, clipId: clip.id, level, from, fixtures: [] });
    }
  }
  return out;
}

interface ClipState {
  sig: string;
  runs: RunSet;
  /** Every stage LED the clip lights, and its colors this frame. */
  leds: Int32Array;
  col: Float32Array;
  /** For each run: where its LEDs are in `leds`. */
  slots: Map<string, Int32Array>;
  box: Box;
  fixtures: string[];
}

/** One clip that plays at a moment, for the editor's "now playing" list. */
export interface ActiveClip {
  trackId: string;
  clipId: string;
  /** 0..1: how far it has come in (1: fully in, below 1 while it fades in or crosses over). */
  level: number;
  /** Set while it crosses over from the clip before it: that clip, and how far (0..1). */
  from?: { clipId: string; p: number; transition: TransitionChoice };
  fixtures: string[];
}

/**
 * Plays a sequence on a stage. `update` moves the time on and draws a frame; `seek` jumps.
 * Effects of the clips that play at the time run on their own clock from the clip's start, so a
 * clip looks the same every time it plays (particles may differ after a jump).
 */
export class SequencePlayer {
  private stage: Stage;
  private layout: Pick<Layout, 'fixtures'>;
  private seq: Sequence;
  private clips = new Map<string, ClipState>();
  /** Clips by layer, with their neighbours, rebuilt when the sequence changes. */
  private order: { track: SeqTrack; items: ReturnType<typeof neighbours> }[] = [];
  /** Where each stage LED is, for transitions. */
  private places: LedPlaces | null = null;
  private trackCol = new Float32Array(0);
  private trackA = new Float32Array(0);
  private w = new Float32Array(5);
  private w2 = new Float32Array(5);
  /** Clips need a fresh start (after a jump): how many seconds of warm-up they get. */
  private warm = 2.5;
  private needsWarm = new Set<string>();
  time = 0;
  /** How many times it has started again at the end: a "random" transition picks again each time round. */
  pass = 0;

  constructor(stage: Stage, layout: Pick<Layout, 'fixtures'>, seq: Sequence) {
    this.stage = stage;
    this.layout = layout;
    this.seq = seq;
    this.setStage(stage, layout);
    this.setSequence(seq);
  }

  get sequence() {
    return this.seq;
  }

  setStage(stage: Stage, layout: Pick<Layout, 'fixtures'>) {
    const changed = stage !== this.stage || layout !== this.layout || this.places?.ux.length !== stage.pixelCount;
    this.stage = stage;
    this.layout = layout;
    if (!changed && this.places) return;
    const n = stage.pixelCount;
    this.places = new LedPlaces(stage);
    this.trackCol = new Float32Array(n * 3);
    this.trackA = new Float32Array(n);
    // Clip runs keep going where their LEDs stay the same.
    for (const id of this.clips.keys()) this.clips.get(id)!.sig = '';
  }

  /** New or changed sequence. Clips whose effect and targets stay the same keep running. */
  setSequence(seq: Sequence) {
    this.seq = seq;
    this.order = seq.tracks.map((track) => ({ track, items: neighbours(track) }));
    const ids = new Set(seq.tracks.flatMap((t) => t.clips.map((c) => c.id)));
    for (const id of [...this.clips.keys()]) if (!ids.has(id)) this.clips.delete(id);
  }

  /** Jumps to a time. `warm`: seconds each playing effect runs to catch up (less is quicker, for scrubbing). */
  seek(t: number, warm = 2.5) {
    this.time = Math.max(0, t);
    this.warm = warm;
    this.clips.clear();
    this.needsWarm.clear();
  }

  /** The ids of the objects the sequence lights. */
  objects(): string[] {
    return sequenceObjects(this.seq, this.layout);
  }

  /**
   * Moves on by `dt` seconds and draws the frame into `out` (3 floats per stage LED). At the end
   * it starts again with `loop`, or stays on the last moment.
   */
  update(dt: number, out: Float32Array, loop = this.seq.loop ?? false) {
    let t = this.time + Math.max(0, dt);
    if (t >= this.seq.duration) {
      if (loop && this.seq.duration > 0) {
        this.pass++;
        this.seek(t % this.seq.duration, 0);
        t = this.time;
        dt = 0;
      } else {
        t = this.seq.duration;
        dt = Math.max(0, t - this.time);
      }
    }
    this.time = t;
    this.draw(dt, out);
  }

  /** The clips that play at time `t` (default: now), top layer first (for the editor). */
  active(t = this.time): ActiveClip[] {
    return activeAt(this.seq, t).map((a) => ({
      ...a,
      ...(a.from ? { from: { ...a.from, transition: this.transitionOf(a.from.transition, a.clipId, 'in') } } : {}),
      fixtures: this.clips.get(a.clipId)?.fixtures ?? a.fixtures
    }));
  }

  /** The transition a clip comes in or goes out with: "random" picks one for the clip, again each time round. */
  transitionOf(choice: TransitionChoice | undefined, clipId: string, side: 'in' | 'out'): TransitionId {
    return pickTransition(choice, choice === 'random' ? hashUnit(`${clipId}|${side}|${this.pass}`) : 0);
  }

  private state(clip: SeqClip): ClipState | null {
    const sig = `${clip.effect.effect}|${isSpatial(clip.effect.effect) ? '' : clip.effect.reverse ? 'r' : ''}|${[...clip.targets].sort().join(',')}`;
    let st = this.clips.get(clip.id);
    if (st && st.sig === sig) return st;
    const groups = targetLeds(this.stage, this.layout, clip.targets);
    if (!groups.length) return null;
    const runs = st?.runs ?? new RunSet();
    const leds: number[] = [];
    const slots = new Map<string, Int32Array>();
    runs.begin();
    const fresh: string[] = [];
    if (isSpatial(clip.effect.effect)) {
      // One picture over everything the clip lights.
      for (const g of groups) for (const i of g.leds) leds.push(i);
      if (runs.add(this.stage, 'all', clip.id, clip.effect, leds, leds, groups.map((g) => g.fixture), `${clip.id}:all`)) fresh.push('all');
      slots.set('all', Int32Array.from(leds.map((_, j) => j)));
    } else {
      // Along each object's own string.
      for (const g of groups) {
        const base = leds.length;
        for (const i of g.leds) leds.push(i);
        if (runs.add(this.stage, g.fixture, clip.id, clip.effect, g.leds, g.leds, [g.fixture], `${clip.id}:${g.fixture}`)) fresh.push(g.fixture);
        const idx = g.leds.map((_, j) => base + j);
        slots.set(g.fixture, Int32Array.from(clip.effect.reverse ? idx.reverse() : idx));
      }
    }
    runs.commit();
    let box: Box = [Infinity, -Infinity, Infinity, -Infinity];
    const { ux, uy } = this.places!;
    for (const i of leds) box = [Math.min(box[0], ux[i]), Math.max(box[1], ux[i]), Math.min(box[2], uy[i]), Math.max(box[3], uy[i])];
    st = { sig, runs, leds: Int32Array.from(leds), col: new Float32Array(leds.length * 3), slots, box, fixtures: groups.map((g) => g.fixture) };
    this.clips.set(clip.id, st);
    for (const k of fresh) this.needsWarm.add(`${clip.id}\n${k}`);
    return st;
  }

  private renderClip(clip: SeqClip, st: ClipState, dt: number) {
    const local = this.time - clip.start;
    for (const key of st.runs.keys()) {
      const run = st.runs.get(key)!;
      const wk = `${clip.id}\n${key}`;
      if (this.needsWarm.has(wk)) {
        this.needsWarm.delete(wk);
        run.runner.warmUp(Math.max(0, local - dt), clip.effect, this.warm);
      }
      const buf = run.runner.render(dt, clip.effect);
      const slot = st.slots.get(key)!;
      for (let j = 0; j < slot.length; j++) {
        const k = slot[j] * 3;
        st.col[k] = buf[j * 3];
        st.col[k + 1] = buf[j * 3 + 1];
        st.col[k + 2] = buf[j * 3 + 2];
      }
    }
  }

  private draw(dt: number, out: Float32Array) {
    out.fill(0);
    const t = this.time;
    const solo = this.seq.tracks.some((tr) => tr.solo && !tr.hidden);
    const playing = new Set<string>();
    const tc = this.trackCol;
    const ta = this.trackA;
    // Bottom layer first; each layer is mixed over what is below it.
    for (let li = this.order.length - 1; li >= 0; li--) {
      const { track, items } = this.order[li];
      if (track.hidden || (solo && !track.solo)) continue;
      let any = false;
      for (const { clip, prev, next } of items) {
        if (t < clip.start || t >= clipEnd(clip)) continue;
        const st = this.state(clip);
        if (!st) continue;
        playing.add(clip.id);
        if (!any) {
          tc.fill(0);
          ta.fill(0);
          any = true;
        }
        this.renderClip(clip, st, dt);
        this.addClip(clip, st, prev, next, t);
      }
      if (any) blend(out, tc, ta, track.opacity, track.blend);
    }
    // Clips that stopped playing start fresh next time.
    for (const id of [...this.clips.keys()]) if (!playing.has(id)) this.clips.delete(id);
    this.warm = 2.5;
  }

  /** Adds a clip's colors to the layer, weighted by its fades and crossovers at each LED. */
  private addClip(clip: SeqClip, st: ClipState, prev: SeqClip | null, next: SeqClip | null, t: number) {
    const tc = this.trackCol;
    const ta = this.trackA;
    // In: crossing over the clip before, or a fade-in from nothing.
    let inType: TransitionId | null = null;
    let inP = 1;
    let inBox = st.box;
    if (prev && t < clipEnd(prev)) {
      const ov = overlapOf(prev, clip);
      inType = this.transitionOf(clip.transitionIn, clip.id, 'in');
      inP = ov > 0 ? (t - clip.start) / ov : 1;
      const ps = this.clips.get(prev.id);
      if (ps) inBox = unionBox(ps.box, st.box);
    } else if (clip.fadeIn && t - clip.start < clip.fadeIn) {
      inType = this.transitionOf(clip.transitionIn, clip.id, 'in');
      inP = (t - clip.start) / clip.fadeIn;
    }
    // Out: the next clip crossing over this one, or a fade-out to nothing.
    let outType: TransitionId | null = null;
    let outP = 0;
    let outBox = st.box;
    let fadeOut = false;
    if (next && t >= next.start) {
      const ov = overlapOf(clip, next);
      outType = this.transitionOf(next.transitionIn, next.id, 'in');
      outP = ov > 0 ? (t - next.start) / ov : 1;
      const ns = this.clips.get(next.id) ?? this.state(next);
      if (ns) outBox = unionBox(ns.box, st.box);
    } else if (clip.fadeOut && clipEnd(clip) - t < clip.fadeOut) {
      outType = this.transitionOf(clip.transitionOut, clip.id, 'out');
      fadeOut = true;
      outP = 1 - (clipEnd(clip) - t) / clip.fadeOut;
    }
    const w = this.w;
    const w2 = this.w2;
    const leds = st.leds;
    const col = st.col;
    const places = this.places!;
    for (let j = 0; j < leds.length; j++) {
      const i = leds[j];
      let c = 1;
      let a = 1;
      // A flash's white: the incoming clip adds it, over a crossover too; the outgoing one only when it fades out to nothing.
      let white = 0;
      if (inType) {
        transitionWeights(inType, clamp01(inP), transitionCoord(inType, places, i, inBox), w);
        c = w[2];
        a = w[3];
        white = w[4];
      }
      if (outType) {
        transitionWeights(outType, clamp01(outP), transitionCoord(outType, places, i, outBox), w2);
        c *= w2[0];
        a *= w2[1];
        if (fadeOut) white += w2[4];
      }
      if (a <= 0 && c <= 0 && white <= 0) continue;
      const k = i * 3;
      tc[k] += col[j * 3] * c + white;
      tc[k + 1] += col[j * 3 + 1] * c + white;
      tc[k + 2] += col[j * 3 + 2] * c + white;
      ta[i] = Math.min(1, ta[i] + a);
    }
  }
}


/** Mixes a layer (colors already weighted by cover, cover 0..1 per LED) over `out`. */
function blend(out: Float32Array, col: Float32Array, cover: Float32Array, opacity: number, mode: BlendMode) {
  const op = clamp01(opacity);
  const n = cover.length;
  for (let i = 0; i < n; i++) {
    const a = cover[i] * op;
    if (a <= 0) continue;
    const k = i * 3;
    for (let j = 0; j < 3; j++) {
      const c = col[k + j] * op;
      const o = out[k + j];
      switch (mode) {
        case 'add':
          out[k + j] = o + c;
          break;
        case 'lighten':
          out[k + j] = Math.max(o, c);
          break;
        case 'multiply':
          out[k + j] = o * (1 - a + Math.min(1, c));
          break;
        default:
          out[k + j] = o * (1 - a) + c;
      }
    }
  }
}

// ---------- Making sequences ----------

export const newId = (prefix: string) => `${prefix}-${Math.random().toString(36).slice(2, 10)}`;

export function emptySequence(name = 'New sequence'): Sequence {
  return {
    id: '',
    name,
    duration: 60,
    loop: true,
    tracks: [
      { id: newId('layer'), name: 'Layer 2', clips: [], opacity: 1, blend: 'add' },
      { id: newId('layer'), name: 'Layer 1', clips: [], opacity: 1, blend: 'normal' }
    ],
    audio: [{ id: newId('audio'), name: 'Audio 1', clips: [], volume: 1 }],
    markers: []
  };
}
