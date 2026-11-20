// The timeline: a ruler with the playhead and markers, layers of clips, and audio tracks, as in
// a video editor. Drag clips to move them (also to another layer; Alt-drag copies), drag their
// edges to trim, drag the knobs at their top corners to fade. Clips that overlap on a layer cross
// over. Drag on empty space to select several; click it to move the playhead there.
// By touch: a tap selects a clip and a drag moves a selected one; one finger scrolls, two pinch
// to zoom, and a drag on the ruler moves the playhead.
import { createContext, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type MutableRefObject, type PointerEvent as RPointerEvent, type ReactNode } from 'react';
import { Eye, EyeOff, GripVertical, Lock, Music, Plus, Unlock, Upload, Volume2, VolumeX } from 'lucide-react';
import { effectInfo, paletteColors, type EffectId } from '../../../../../shared/effects.ts';
import type { Layout } from '../../../../../shared/layout.ts';
import { blendInfo, clipEnd, neighbours, newId, overlapOf, transitionInfo, type AudioClip, type SeqClip, type Sequence, type TransitionId } from '../../../../../shared/sequence.ts';
import { cn } from '../../../lib/utils.ts';
import { PEAKS_PER_SECOND, type AudioEngine, type Clock } from './audio.ts';
import { findAudioClip, findClip, fmtTime, makeClip, MIN_CLIP, round, snapPoints, snapTime, targetsLabel, type Selection } from './model.ts';

export const HEADER_W = 208;
/** On a phone the layer names get a narrow column; their switches are in the inspector. */
const COMPACT_HEADER_W = 112;
const Compact = createContext(false);
const useHeaderW = () => (useContext(Compact) ? COMPACT_HEADER_W : HEADER_W);
const RULER_H = 30;
export const TRACK_H = 56;
const AUDIO_H = 64;
export const MIN_PPS = 4;
export const MAX_PPS = 400;

export const EFFECT_MIME = 'application/x-wled-effect';
export const TRANSITION_MIME = 'application/x-wled-transition';

export interface TimelineApi {
  /** Zooms so the whole sequence fits. */
  fit(): void;
  /** Scrolls so time `t` is in view. */
  reveal(t: number): void;
}

type Drag =
  | { kind: 'move'; x0: number; y0: number; orig: Sequence; ids: string[]; audio: boolean; grab: { start: number; end: number; ti: number }; key: string; moved: boolean; reselect: string | null }
  | { kind: 'trimStart' | 'trimEnd' | 'fadeIn' | 'fadeOut'; x0: number; orig: Sequence; id: string; audio: boolean; key: string }
  | { kind: 'scrub' }
  | { kind: 'marker'; id: string; x0: number; orig: Sequence; key: string }
  | { kind: 'end'; x0: number; orig: Sequence; key: string }
  | { kind: 'marquee'; x0: number; y0: number; x1: number; y1: number; base: string[]; moved: boolean; t: number }
  | { kind: 'order'; id: string; audio: boolean; y0: number; orig: Sequence; key: string };

/** Re-renders the component on clock events, and `fps` times a second while playing. */
export function useClockTick(clock: Clock, fps: number) {
  const [, setTick] = useState(0);
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;
    const sync = () => {
      setTick((n) => n + 1);
      if (clock.playing && !timer) timer = setInterval(() => setTick((n) => n + 1), 1000 / fps);
      if (!clock.playing && timer) {
        clearInterval(timer);
        timer = null;
      }
    };
    const off = clock.on(sync);
    sync();
    return () => {
      off();
      if (timer) clearInterval(timer);
    };
  }, [clock, fps]);
}

/** Ruler steps: labels at least ~70 px apart. */
function rulerStep(pps: number): { major: number; minor: number } {
  const steps = [0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300];
  const major = steps.find((s) => s * pps >= 70) ?? 600;
  const minor = major >= 1 ? major / (major === 15 || major === 30 ? 3 : major === 2 ? 4 : 5) : major / 5;
  return { major, minor };
}

export function Timeline({
  seq,
  layout,
  change,
  sel,
  setSel,
  clock,
  seek,
  pps,
  setPps,
  snap,
  audio,
  newTargets,
  brush,
  onAudioFiles,
  onPickAudio,
  apiRef,
  hoverObject,
  compact = false
}: {
  seq: Sequence;
  layout: Layout | undefined;
  /** A change. Changes with the same key in a row are one step for Undo (one drag). */
  change: (next: Sequence, key?: string) => void;
  sel: Selection;
  setSel: (s: Selection) => void;
  clock: Clock;
  seek: (t: number, scrub?: boolean) => void;
  pps: number;
  setPps: (n: number) => void;
  snap: boolean;
  audio: AudioEngine;
  /** What new clips play on. */
  newTargets: string[];
  /** The effect a double-click adds. */
  brush: EffectId;
  /** Audio files dropped on the timeline (or an audio track), at a time. */
  onAudioFiles: (files: File[], trackId: string | null, at: number) => void;
  /** Opens the file picker for an audio track. */
  onPickAudio: (trackId: string | null) => void;
  apiRef: MutableRefObject<TimelineApi | null>;
  /** An object under the pointer in the preview: clips that light it are marked. */
  hoverObject: string | null;
  /** A phone: narrow layer names, without their switches. */
  compact?: boolean;
}) {
  useClockTick(clock, 12);
  const scroller = useRef<HTMLDivElement>(null);
  const content = useRef<HTMLDivElement>(null);
  const drag = useRef<Drag | null>(null);
  const [marquee, setMarquee] = useState<{ x0: number; y0: number; x1: number; y1: number } | null>(null);
  const [view, setView] = useState({ x: 0, w: 1200 });
  const [ghost, setGhost] = useState<{ track: number; t: number; effect?: boolean } | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [, setAudioTick] = useState(0);
  useEffect(() => audio.on(() => setAudioTick((n) => n + 1)), [audio]);

  const seqRef = useRef(seq);
  seqRef.current = seq;
  const ppsRef = useRef(pps);
  ppsRef.current = pps;
  const selRef = useRef(sel);
  selRef.current = sel;
  const headerW = compact ? COMPACT_HEADER_W : HEADER_W;
  const hwRef = useRef(headerW);
  hwRef.current = headerW;

  const now = clock.time();
  const contentW = Math.max(seq.duration * pps + 160, view.w - headerW);
  const selected = new Set(sel && (sel.kind === 'clips' || sel.kind === 'audio') ? sel.ids : []);
  const { major, minor } = rulerStep(pps);
  const beat = seq.bpm ? 60 / seq.bpm : null;

  // Scrolling and zoom.
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const upd = () => setView({ x: el.scrollLeft, w: el.clientWidth });
    upd();
    el.addEventListener('scroll', upd, { passive: true });
    const ro = new ResizeObserver(upd);
    ro.observe(el);
    // Ctrl/⌘ + wheel (or a pinch) zooms at the pointer; Shift + wheel scrolls sideways.
    const wheel = (e: WheelEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      const x = e.clientX - r.left - hwRef.current + el.scrollLeft;
      const t = x / ppsRef.current;
      const next = Math.min(MAX_PPS, Math.max(MIN_PPS, ppsRef.current * Math.exp(-e.deltaY * 0.004)));
      setPps(next);
      requestAnimationFrame(() => (el.scrollLeft = t * next - (e.clientX - r.left - hwRef.current)));
    };
    el.addEventListener('wheel', wheel, { passive: false });
    // Two fingers pinch to zoom, at the point between them.
    let pinch: { d: number; pps: number; t: number; x: number } | null = null;
    const spread = (e: TouchEvent) => Math.max(30, Math.abs(e.touches[0].clientX - e.touches[1].clientX));
    const between = (e: TouchEvent) => (e.touches[0].clientX + e.touches[1].clientX) / 2 - el.getBoundingClientRect().left - hwRef.current;
    const touchStart = (e: TouchEvent) => {
      if (e.touches.length !== 2) return;
      const x = between(e);
      pinch = { d: spread(e), pps: ppsRef.current, t: (x + el.scrollLeft) / ppsRef.current, x };
    };
    const touchMove = (e: TouchEvent) => {
      if (!pinch || e.touches.length !== 2) return;
      e.preventDefault();
      const p = pinch;
      const next = Math.min(MAX_PPS, Math.max(MIN_PPS, (p.pps * spread(e)) / p.d));
      setPps(next);
      requestAnimationFrame(() => (el.scrollLeft = p.t * next - p.x));
    };
    const touchEnd = (e: TouchEvent) => {
      if (e.touches.length < 2) pinch = null;
    };
    el.addEventListener('touchstart', touchStart, { passive: true });
    el.addEventListener('touchmove', touchMove, { passive: false });
    el.addEventListener('touchend', touchEnd);
    el.addEventListener('touchcancel', touchEnd);
    return () => {
      el.removeEventListener('scroll', upd);
      el.removeEventListener('wheel', wheel);
      el.removeEventListener('touchstart', touchStart);
      el.removeEventListener('touchmove', touchMove);
      el.removeEventListener('touchend', touchEnd);
      el.removeEventListener('touchcancel', touchEnd);
      ro.disconnect();
    };
  }, [setPps]);

  apiRef.current = {
    fit: () => {
      const el = scroller.current;
      if (!el) return;
      setPps(Math.min(MAX_PPS, Math.max(MIN_PPS, (el.clientWidth - hwRef.current - 40) / Math.max(1, seqRef.current.duration))));
      el.scrollLeft = 0;
    },
    reveal: (t: number) => {
      const el = scroller.current;
      if (!el) return;
      const x = t * ppsRef.current;
      const w = el.clientWidth - hwRef.current;
      if (x < el.scrollLeft + 20 || x > el.scrollLeft + w - 40) el.scrollLeft = Math.max(0, x - w * 0.15);
    }
  };

  // ---------- Dragging ----------

  const timeAt = (clientX: number) => {
    const r = content.current!.getBoundingClientRect();
    return (clientX - r.left - hwRef.current) / ppsRef.current;
  };

  useEffect(() => {
    const move = (e: PointerEvent) => {
      const d = drag.current;
      if (!d) return;
      const s = seqRef.current;
      const k = ppsRef.current;
      const sn = (t: number, skip: Set<string>) => (snap && !e.altKey ? snapTime(t, snapPoints(d.kind === 'scrub' || d.kind === 'marquee' ? s : d.orig, clock.time(), skip), k, s.bpm) : t);
      switch (d.kind) {
        case 'scrub': {
          const t = Math.max(0, Math.min(s.duration, timeAt(e.clientX)));
          seek(snap && !e.altKey ? snapTime(t, snapPoints(s, -1, new Set()), k, s.bpm) : t, true);
          return;
        }
        case 'marquee': {
          const r = content.current!.getBoundingClientRect();
          d.x1 = e.clientX - r.left;
          d.y1 = e.clientY - r.top;
          if (Math.abs(d.x1 - d.x0) + Math.abs(d.y1 - d.y0) > 4) d.moved = true;
          if (!d.moved) return;
          setMarquee({ x0: d.x0, y0: d.y0, x1: d.x1, y1: d.y1 });
          // Clips the box touches.
          const t0 = (Math.min(d.x0, d.x1) - hwRef.current) / k;
          const t1 = (Math.max(d.x0, d.x1) - hwRef.current) / k;
          const y0 = Math.min(d.y0, d.y1) - RULER_H;
          const y1 = Math.max(d.y0, d.y1) - RULER_H;
          const ids: string[] = [];
          s.tracks.forEach((tr, i) => {
            if (tr.locked || y1 < i * TRACK_H || y0 > (i + 1) * TRACK_H) return;
            for (const c of tr.clips) if (c.start < t1 && clipEnd(c) > t0) ids.push(c.id);
          });
          setSel(ids.length || d.base.length ? { kind: 'clips', ids: [...new Set([...d.base, ...ids])] } : null);
          return;
        }
        case 'move': {
          const dx = e.clientX - d.x0;
          const dy = e.clientY - d.y0;
          if (!d.moved && Math.abs(dx) + Math.abs(dy) < 3) return;
          d.moved = true;
          const skip = new Set(d.ids);
          const len = d.grab.end - d.grab.start;
          // The clip's start or its end sticks to whatever is nearest.
          const raw = d.grab.start + dx / k;
          const a = sn(raw, skip);
          const b = sn(raw + len, skip) - len;
          const ca = a !== raw ? Math.abs(a - raw) : Infinity;
          const cb = Math.abs(b - raw) > 1e-9 ? Math.abs(b - raw) : Infinity;
          const start = ca === Infinity && cb === Infinity ? raw : ca <= cb ? a : b;
          let delta = start - d.grab.start;
          // Nothing moves before 0.
          const items = d.audio ? d.orig.audio.flatMap((t) => t.clips.filter((c) => skip.has(c.id))) : d.orig.tracks.flatMap((t) => t.clips.filter((c) => skip.has(c.id)));
          const first = Math.min(...items.map((c) => c.start));
          delta = Math.max(delta, -first);
          const rows = d.audio ? d.orig.audio.length : d.orig.tracks.length;
          let dt = Math.round(dy / (d.audio ? AUDIO_H : TRACK_H));
          const from = (d.audio ? d.orig.audio : d.orig.tracks).map((t, i) => (t.clips.some((c) => skip.has(c.id)) ? i : -1)).filter((i) => i >= 0);
          dt = Math.max(-Math.min(...from), Math.min(rows - 1 - Math.max(...from), dt));
          if (!d.audio && from.some((i) => d.orig.tracks[i + dt]?.locked)) dt = 0;
          change(moveClips(d.orig, skip, round(delta), dt, d.audio), d.key);
          return;
        }
        case 'trimStart':
        case 'trimEnd':
        case 'fadeIn':
        case 'fadeOut': {
          const dt = (e.clientX - d.x0) / k;
          change(trim(d.orig, d.id, d.kind, dt, d.audio, (t) => sn(t, new Set([d.id])), audio), d.key);
          return;
        }
        case 'marker': {
          const m = d.orig.markers.find((x) => x.id === d.id);
          if (!m) return;
          const t = Math.max(0, Math.min(d.orig.duration, sn(m.t + (e.clientX - d.x0) / k, new Set())));
          change({ ...d.orig, markers: d.orig.markers.map((x) => (x.id === d.id ? { ...x, t: round(t) } : x)) }, d.key);
          return;
        }
        case 'end': {
          const t = Math.max(1, sn(d.orig.duration + (e.clientX - d.x0) / k, new Set()));
          change({ ...d.orig, duration: round(Math.min(3600, t)) }, d.key);
          return;
        }
        case 'order': {
          const rows = d.audio ? d.orig.audio : d.orig.tracks;
          const from = rows.findIndex((t) => t.id === d.id);
          const to = Math.max(0, Math.min(rows.length - 1, from + Math.round((e.clientY - d.y0) / (d.audio ? AUDIO_H : TRACK_H))));
          if (to === from) return change(d.orig, d.key);
          const next = [...rows];
          const [it] = next.splice(from, 1);
          next.splice(to, 0, it as never);
          change(d.audio ? { ...d.orig, audio: next as Sequence['audio'] } : { ...d.orig, tracks: next as Sequence['tracks'] }, d.key);
          return;
        }
      }
    };
    const up = (e: PointerEvent) => {
      const d = drag.current;
      drag.current = null;
      if (!d) return;
      if (d.kind === 'scrub') {
        clock.scrubbing = false;
        seek(clock.time());
      }
      if (d.kind === 'marquee') {
        setMarquee(null);
        // A click (no box): move the playhead there. Not when a finger scrolled the timeline (cancel).
        if (!d.moved && e.type !== 'pointercancel') seek(Math.max(0, Math.min(seqRef.current.duration, d.t)));
      }
      if (d.kind === 'move' && !d.moved && d.reselect) setSel({ kind: d.audio ? 'audio' : 'clips', ids: [d.reselect] });
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
    return () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
    };
  }, [snap, change, seek, setSel, clock, audio]);

  const key = () => `drag-${Math.random()}`;

  function pressClip(e: RPointerEvent, c: { id: string; start: number; duration: number }, ti: number, isAudio: boolean, locked: boolean) {
    if (e.button !== 0) return;
    e.stopPropagation();
    const kind = isAudio ? 'audio' : 'clips';
    const cur = sel && sel.kind === kind ? sel.ids : [];
    let ids: string[];
    let reselect: string | null = null;
    if (e.ctrlKey || e.metaKey || e.shiftKey) {
      ids = cur.includes(c.id) ? cur.filter((x) => x !== c.id) : [...cur, c.id];
      setSel(ids.length ? { kind, ids } : null);
      if (!ids.includes(c.id)) return;
    } else if (cur.includes(c.id)) {
      ids = cur;
      // A click (no drag) on one of several selected clips selects just that one.
      if (cur.length > 1) reselect = c.id;
    } else {
      ids = [c.id];
      setSel({ kind, ids });
      // A finger selects a clip first, and drags it once it is selected: a finger on any other clip scrolls the timeline.
      if (e.pointerType === 'touch') return;
    }
    if (locked) return;
    let orig = seq;
    // Alt-drag: drag copies, the originals stay.
    if (e.altKey && !isAudio) {
      const copies = new Map<string, string>();
      orig = {
        ...seq,
        tracks: seq.tracks.map((tr) => ({
          ...tr,
          clips: tr.clips.flatMap((x) => {
            if (!ids.includes(x.id)) return [x];
            const id = newId('clip');
            copies.set(x.id, id);
            return [x, { ...x, id }];
          })
        }))
      };
      ids = ids.map((x) => copies.get(x) ?? x);
      setSel({ kind: 'clips', ids });
    }
    drag.current = { kind: 'move', x0: e.clientX, y0: e.clientY, orig, ids, audio: isAudio, grab: { start: c.start, end: c.start + c.duration, ti }, key: key(), moved: false, reselect };
  }

  function pressEdge(e: RPointerEvent, id: string, kind: 'trimStart' | 'trimEnd' | 'fadeIn' | 'fadeOut', isAudio: boolean) {
    if (e.button !== 0) return;
    e.stopPropagation();
    if (!selected.has(id)) setSel({ kind: isAudio ? 'audio' : 'clips', ids: [id] });
    drag.current = { kind, x0: e.clientX, orig: seq, id, audio: isAudio, key: key() };
  }

  function pressLane(e: RPointerEvent) {
    if (e.button !== 0) return;
    const r = content.current!.getBoundingClientRect();
    const add = e.ctrlKey || e.metaKey || e.shiftKey;
    const base = add && sel?.kind === 'clips' ? sel.ids : [];
    if (!add) setSel(null);
    drag.current = { kind: 'marquee', x0: e.clientX - r.left, y0: e.clientY - r.top, x1: e.clientX - r.left, y1: e.clientY - r.top, base, moved: false, t: timeAt(e.clientX) };
  }

  function pressRuler(e: RPointerEvent) {
    if (e.button !== 0) return;
    clock.scrubbing = true;
    drag.current = { kind: 'scrub' };
    seek(Math.max(0, Math.min(seq.duration, timeAt(e.clientX))), true);
  }

  // ---------- Dropping effects, transitions and audio ----------

  const dropKind = (e: React.DragEvent) => (e.dataTransfer.types.includes(EFFECT_MIME) ? 'effect' : e.dataTransfer.types.includes(TRANSITION_MIME) ? 'transition' : e.dataTransfer.types.includes('Files') ? 'files' : null);

  function laneDragOver(e: React.DragEvent, ti: number) {
    const k = dropKind(e);
    if (k !== 'effect' && k !== 'files') return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    let t = Math.max(0, timeAt(e.clientX));
    if (snap) t = snapTime(t, snapPoints(seq, clock.time(), new Set()), pps, seq.bpm);
    setGhost({ track: ti, t, effect: k === 'effect' });
  }

  function laneDrop(e: React.DragEvent, ti: number) {
    const k = dropKind(e);
    setGhost(null);
    if (!k) return;
    e.preventDefault();
    let t = Math.max(0, timeAt(e.clientX));
    if (snap) t = snapTime(t, snapPoints(seq, clock.time(), new Set()), pps, seq.bpm);
    if (k === 'files') return onAudioFiles([...e.dataTransfer.files], null, t);
    if (k !== 'effect') return;
    const id = e.dataTransfer.getData(EFFECT_MIME) as EffectId;
    if (!effectInfo(id) || id !== effectInfo(id).id) return;
    let next = seq;
    let track = seq.tracks[ti];
    if (!track || track.locked) {
      // Dropped below the layers: a new layer on top.
      track = { id: newId('layer'), name: `Layer ${seq.tracks.length + 1}`, clips: [], opacity: 1, blend: seq.tracks.length ? 'normal' : 'normal' };
      next = { ...seq, tracks: [track, ...seq.tracks] };
    }
    const clip = makeClip(next, track, id, t, newTargets);
    change({ ...next, tracks: next.tracks.map((tr) => (tr.id === track.id ? { ...tr, clips: [...tr.clips, clip] } : tr)) });
    setSel({ kind: 'clips', ids: [clip.id] });
  }

  function clipDrop(e: React.DragEvent, c: SeqClip) {
    if (dropKind(e) !== 'transition') return;
    e.preventDefault();
    e.stopPropagation();
    const id = e.dataTransfer.getData(TRANSITION_MIME) as TransitionId;
    // Over the clip before it, if they overlap; else a fade in of 1 s.
    change(
      {
        ...seq,
        tracks: seq.tracks.map((tr) => ({ ...tr, clips: tr.clips.map((x) => (x.id === c.id ? { ...x, transitionIn: id, fadeIn: x.fadeIn && x.fadeIn > 0.05 ? x.fadeIn : Math.min(1, x.duration / 2) } : x)) }))
      }
    );
    setSel({ kind: 'clips', ids: [c.id] });
  }

  // ---------- Drawing ----------

  const ticks = useMemo(() => {
    const t0 = Math.max(0, Math.floor((view.x - 40) / pps / minor) * minor);
    const t1 = (view.x + view.w) / pps;
    const out: { t: number; major: boolean }[] = [];
    for (let t = t0; t <= t1 && out.length < 2000; t += minor) {
      const r = Math.round(t * 1000) / 1000;
      out.push({ t: r, major: Math.abs(r / major - Math.round(r / major)) < 1e-6 });
    }
    return out;
  }, [view.x, view.w, pps, major, minor]);

  const gridBg = useMemo(() => {
    const layers: string[] = [];
    const sizes: string[] = [];
    if (beat && beat * pps >= 8) {
      layers.push('linear-gradient(to right, rgba(56,189,248,0.10) 1px, transparent 1px)');
      sizes.push(`${beat * pps}px 100%`);
    }
    layers.push('linear-gradient(to right, rgba(128,128,128,0.16) 1px, transparent 1px)');
    sizes.push(`${major * pps}px 100%`);
    return { backgroundImage: layers.join(', '), backgroundSize: sizes.join(', ') };
  }, [beat, pps, major]);

  const hoverClips = useMemo(() => {
    if (!hoverObject) return new Set<string>();
    return new Set(seq.tracks.flatMap((t) => t.clips.filter((c) => c.targets.some((k) => k === '*' || k === hoverObject || k.startsWith(`${hoverObject}#`))).map((c) => c.id)));
  }, [hoverObject, seq]);

  const endX = seq.duration * pps;

  return (
    <Compact.Provider value={compact}>
    {/* Touch: one finger scrolls (or drags a selected clip), two fingers pinch to zoom; the page itself does not zoom. */}
    <div ref={scroller} className="relative h-full touch-pan-x touch-pan-y overflow-auto overscroll-contain bg-stone-50 select-none dark:bg-stone-950" data-timeline>
      <div ref={content} className="relative" style={{ width: headerW + contentW, minHeight: '100%' }}>
        {/* Ruler */}
        <div className="sticky top-0 z-30 flex border-b border-stone-200 bg-white/95 backdrop-blur dark:border-stone-800 dark:bg-stone-900/95" style={{ height: RULER_H }}>
          <div className="sticky left-0 z-40 flex shrink-0 items-center gap-1 border-r border-stone-200 bg-white px-2 dark:border-stone-800 dark:bg-stone-900" style={{ width: headerW }}>
            <span className="flex-1 text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Layers</span>
            <button
              type="button"
              title="Add a layer on top"
              onClick={() => change({ ...seq, tracks: [{ id: newId('layer'), name: `Layer ${seq.tracks.length + 1}`, clips: [], opacity: 1, blend: 'normal' }, ...seq.tracks] })}
              className="grid size-6 place-items-center rounded text-stone-500 hover:bg-stone-100 hover:text-stone-900 dark:hover:bg-stone-800 dark:hover:text-white"
            >
              <Plus className="size-3.5" />
            </button>
          </div>
          <div className="relative cursor-text touch-none" style={{ width: contentW }} onPointerDown={pressRuler} onDoubleClick={(e) => addMarkerAt(timeAt(e.clientX))}>
            {ticks.map(({ t, major: big }) => (
              <div key={t} className="pointer-events-none absolute bottom-0" style={{ left: t * pps }}>
                <div className={cn('w-px', big ? 'h-3 bg-stone-400 dark:bg-stone-500' : 'h-1.5 bg-stone-300 dark:bg-stone-700')} />
                {big ? <span className="absolute bottom-3 left-1 text-[10px] whitespace-nowrap text-stone-500 tabular-nums">{fmtTime(t, major < 1)}</span> : null}
              </div>
            ))}
            {/* Past the end */}
            <div className="pointer-events-none absolute inset-y-0 right-0 bg-stone-200/60 dark:bg-stone-800/60" style={{ left: endX }} />
            <div
              title="Drag to change how long the sequence is"
              onPointerDown={(e) => {
                e.stopPropagation();
                drag.current = { kind: 'end', x0: e.clientX, orig: seq, key: key() };
              }}
              className="absolute inset-y-0 z-10 w-2 -translate-x-1 cursor-ew-resize border-x-2 border-stone-400 hover:border-sky-500"
              style={{ left: endX }}
            />
            {seq.markers.map((m) => (
              <button
                key={m.id}
                type="button"
                title={`${m.label || 'Marker'} at ${fmtTime(m.t)} · drag to move · Delete to remove`}
                onPointerDown={(e) => {
                  e.stopPropagation();
                  setSel({ kind: 'marker', id: m.id });
                  seek(m.t);
                  drag.current = { kind: 'marker', id: m.id, x0: e.clientX, orig: seq, key: key() };
                }}
                className={cn('absolute top-0 z-10 flex h-4 -translate-x-1/2 items-center rounded-b px-1 text-[9px] font-semibold text-stone-950', sel?.kind === 'marker' && sel.id === m.id ? 'bg-amber-300 ring-2 ring-sky-500' : 'bg-amber-400')}
                style={{ left: m.t * pps }}
              >
                {m.label || '◆'}
              </button>
            ))}
          </div>
        </div>

        {/* Layers */}
        {seq.tracks.map((tr, ti) => {
          const items = neighbours(tr);
          const isSel = sel?.kind === 'track' && sel.id === tr.id;
          return (
            <div key={tr.id} className="flex border-b border-stone-200 dark:border-stone-800" style={{ height: TRACK_H }}>
              <TrackHeader
                selected={isSel}
                onSelect={() => setSel({ kind: 'track', id: tr.id })}
                onGrip={(e) => (drag.current = { kind: 'order', id: tr.id, audio: false, y0: e.clientY, orig: seq, key: key() })}
                name={tr.name}
                renaming={renaming === tr.id}
                onRename={(name) => {
                  setRenaming(null);
                  if (name) change({ ...seq, tracks: seq.tracks.map((x) => (x.id === tr.id ? { ...x, name } : x)) });
                }}
                onStartRename={() => setRenaming(tr.id)}
                sub={`${blendInfo(tr.blend).name}${tr.opacity < 1 ? ` · ${Math.round(tr.opacity * 100)}%` : ''}`}
              >
                <IconToggle on={!tr.hidden} title={tr.hidden ? 'Show this layer' : 'Hide this layer'} onClick={() => change({ ...seq, tracks: seq.tracks.map((x) => (x.id === tr.id ? { ...x, hidden: !x.hidden || undefined } : x)) })}>
                  {tr.hidden ? <EyeOff /> : <Eye />}
                </IconToggle>
                <IconToggle on={!!tr.solo} title={tr.solo ? 'Solo off' : 'Solo: play only this layer (and other solo layers)'} onClick={() => change({ ...seq, tracks: seq.tracks.map((x) => (x.id === tr.id ? { ...x, solo: !x.solo || undefined } : x)) })} accent>
                  <span className="text-[10px] font-bold">S</span>
                </IconToggle>
                <IconToggle on={!!tr.locked} title={tr.locked ? 'Unlock' : 'Lock: clips cannot be changed'} onClick={() => change({ ...seq, tracks: seq.tracks.map((x) => (x.id === tr.id ? { ...x, locked: !x.locked || undefined } : x)) })} accent>
                  {tr.locked ? <Lock /> : <Unlock />}
                </IconToggle>
              </TrackHeader>
              <div
                className={cn('relative', tr.hidden && 'opacity-40', tr.locked && 'bg-[repeating-linear-gradient(135deg,transparent,transparent_6px,rgba(128,128,128,0.07)_6px,rgba(128,128,128,0.07)_12px)]')}
                style={{ width: contentW, ...gridBg }}
                onPointerDown={pressLane}
                onDoubleClick={(e) => {
                  if (tr.locked) return;
                  const clip = makeClip(seq, tr, brush, timeAt(e.clientX), newTargets);
                  change({ ...seq, tracks: seq.tracks.map((x) => (x.id === tr.id ? { ...x, clips: [...x.clips, clip] } : x)) });
                  setSel({ kind: 'clips', ids: [clip.id] });
                }}
                onDragOver={(e) => laneDragOver(e, ti)}
                onDragLeave={() => setGhost(null)}
                onDrop={(e) => laneDrop(e, ti)}
              >
                <div className="pointer-events-none absolute inset-y-0 right-0 bg-stone-200/50 dark:bg-stone-900/70" style={{ left: endX }} />
                {items.map(({ clip, prev }) => (
                  <ClipBlock
                    key={clip.id}
                    clip={clip}
                    prev={prev}
                    pps={pps}
                    layout={layout}
                    selected={selected.has(clip.id)}
                    active={now >= clip.start && now < clipEnd(clip) && !tr.hidden}
                    hovered={hoverClips.has(clip.id)}
                    locked={!!tr.locked}
                    onPress={(e) => pressClip(e, clip, ti, false, !!tr.locked)}
                    onEdge={(e, k) => !tr.locked && pressEdge(e, clip.id, k, false)}
                    onDrop={(e) => clipDrop(e, clip)}
                  />
                ))}
                {ghost && ghost.track === ti && ghost.effect ? (
                  <div className="pointer-events-none absolute inset-y-1 rounded-md border-2 border-dashed border-sky-500 bg-sky-500/10" style={{ left: ghost.t * pps, width: Math.min(8, seq.duration - ghost.t) * pps }} />
                ) : null}
              </div>
            </div>
          );
        })}

        {/* Drop row: a new layer */}
        <div className="flex border-b border-stone-200 dark:border-stone-800" style={{ height: 30 }}>
          <div className="sticky left-0 z-20 flex shrink-0 items-center border-r border-stone-200 bg-stone-50 px-2 text-[11px] text-stone-400 dark:border-stone-800 dark:bg-stone-950" style={{ width: headerW }}>
            {compact ? 'New layer' : 'Drop an effect below for a new layer'}
          </div>
          <div
            className={cn('relative text-[11px] text-stone-400', ghost && ghost.track === seq.tracks.length && 'bg-sky-500/10')}
            style={{ width: contentW }}
            onPointerDown={pressLane}
            onDragOver={(e) => laneDragOver(e, seq.tracks.length)}
            onDragLeave={() => setGhost(null)}
            onDrop={(e) => laneDrop(e, seq.tracks.length)}
          />
        </div>

        {/* Audio */}
        {seq.audio.map((at, ai) => {
          const isSel = sel?.kind === 'audioTrack' && sel.id === at.id;
          return (
            <div key={at.id} className="flex border-b border-stone-200 dark:border-stone-800" style={{ height: AUDIO_H }}>
              <TrackHeader
                selected={isSel}
                onSelect={() => setSel({ kind: 'audioTrack', id: at.id })}
                onGrip={(e) => (drag.current = { kind: 'order', id: at.id, audio: true, y0: e.clientY, orig: seq, key: key() })}
                name={at.name}
                icon={<Music className="size-3.5 text-violet-500" />}
                renaming={renaming === at.id}
                onRename={(name) => {
                  setRenaming(null);
                  if (name) change({ ...seq, audio: seq.audio.map((x) => (x.id === at.id ? { ...x, name } : x)) });
                }}
                onStartRename={() => setRenaming(at.id)}
                sub={at.muted ? 'Muted' : `Volume ${Math.round(at.volume * 100)}%`}
              >
                <IconToggle on={!at.muted} title={at.muted ? 'Unmute' : 'Mute'} onClick={() => change({ ...seq, audio: seq.audio.map((x) => (x.id === at.id ? { ...x, muted: !x.muted || undefined } : x)) })}>
                  {at.muted ? <VolumeX /> : <Volume2 />}
                </IconToggle>
                <IconToggle on={false} title="Add an audio file to this track" onClick={() => onPickAudio(at.id)}>
                  <Upload />
                </IconToggle>
              </TrackHeader>
              <div
                className="relative"
                style={{ width: contentW, ...gridBg }}
                onPointerDown={pressLane}
                onDragOver={(e) => {
                  if (dropKind(e) !== 'files') return;
                  e.preventDefault();
                }}
                onDrop={(e) => {
                  if (dropKind(e) !== 'files') return;
                  e.preventDefault();
                  onAudioFiles([...e.dataTransfer.files], at.id, Math.max(0, timeAt(e.clientX)));
                }}
              >
                <div className="pointer-events-none absolute inset-y-0 right-0 bg-stone-200/50 dark:bg-stone-900/70" style={{ left: endX }} />
                {at.clips.length === 0 ? (
                  <button type="button" onPointerDown={(e) => e.stopPropagation()} onClick={() => onPickAudio(at.id)} className="absolute inset-y-2 left-2 flex items-center gap-2 rounded-md border border-dashed border-stone-300 px-3 text-xs text-stone-500 hover:border-violet-400 hover:text-violet-600 dark:border-stone-700">
                    <Music className="size-3.5" /> {compact ? 'Add music' : 'Add music: click, or drop an audio file here'}
                  </button>
                ) : null}
                {at.clips.map((c) => (
                  <AudioBlock
                    key={c.id}
                    clip={c}
                    pps={pps}
                    view={view}
                    engine={audio}
                    selected={selected.has(c.id)}
                    muted={!!at.muted}
                    onPress={(e) => pressClip(e, c, ai, true, false)}
                    onEdge={(e, k) => pressEdge(e, c.id, k, true)}
                  />
                ))}
              </div>
            </div>
          );
        })}
        <div className="flex" style={{ height: 34 }}>
          <div className="sticky left-0 z-20 flex shrink-0 items-center gap-1 border-r border-stone-200 bg-stone-50 px-2 dark:border-stone-800 dark:bg-stone-950" style={{ width: headerW }}>
            <button
              type="button"
              onClick={() => change({ ...seq, audio: [...seq.audio, { id: newId('audio'), name: `Audio ${seq.audio.length + 1}`, clips: [], volume: 1 }] })}
              className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[11px] text-stone-500 hover:bg-stone-100 hover:text-stone-900 dark:hover:bg-stone-800 dark:hover:text-white"
            >
              <Plus className="size-3" /> Audio track
            </button>
          </div>
          <div style={{ width: contentW }} onPointerDown={pressLane} />
        </div>

        {/* Playhead */}
        <Playhead clock={clock} pps={pps} apiRef={apiRef} />
        {marquee ? (
          <div
            className="pointer-events-none absolute z-30 border border-sky-500 bg-sky-500/10"
            style={{ left: Math.min(marquee.x0, marquee.x1), top: Math.min(marquee.y0, marquee.y1), width: Math.abs(marquee.x1 - marquee.x0), height: Math.abs(marquee.y1 - marquee.y0) }}
          />
        ) : null}
      </div>
    </div>
    </Compact.Provider>
  );

  function addMarkerAt(t: number) {
    const m = { id: newId('marker'), t: round(Math.max(0, Math.min(seq.duration, t))) };
    change({ ...seq, markers: [...seq.markers, m] });
    setSel({ kind: 'marker', id: m.id });
  }
}

/** Moves clips by `dt` seconds and `dTrack` rows (layers or audio tracks). */
function moveClips(seq: Sequence, ids: Set<string>, dt: number, dTrack: number, isAudio: boolean): Sequence {
  if (isAudio) {
    const moved: AudioClip[][] = seq.audio.map(() => []);
    const audio = seq.audio.map((t, i) => {
      const keep: AudioClip[] = [];
      for (const c of t.clips) (ids.has(c.id) ? moved[i + dTrack] : keep).push(ids.has(c.id) ? { ...c, start: round(c.start + dt) } : c);
      return { ...t, clips: keep };
    });
    return { ...seq, audio: audio.map((t, i) => ({ ...t, clips: [...t.clips, ...moved[i]] })) };
  }
  const moved: SeqClip[][] = seq.tracks.map(() => []);
  const tracks = seq.tracks.map((t, i) => {
    const keep: SeqClip[] = [];
    for (const c of t.clips) {
      if (ids.has(c.id)) moved[i + dTrack].push({ ...c, start: round(c.start + dt) });
      else keep.push(c);
    }
    return { ...t, clips: keep };
  });
  return { ...seq, tracks: tracks.map((t, i) => ({ ...t, clips: [...t.clips, ...moved[i]] })) };
}

/** Drags an edge or a fade knob of one clip by `dt` seconds. */
function trim(seq: Sequence, id: string, kind: 'trimStart' | 'trimEnd' | 'fadeIn' | 'fadeOut', dt: number, isAudio: boolean, sn: (t: number) => number, engine: AudioEngine): Sequence {
  if (isAudio) {
    const f = findAudioClip(seq, id);
    if (!f) return seq;
    const c = f.clip;
    const fileLen = engine.buffer(c.fileId)?.duration ?? Infinity;
    let next = c;
    if (kind === 'trimStart') {
      const end = c.start + c.duration;
      const s = Math.max(c.start - c.offset, 0, Math.min(end - MIN_CLIP, sn(c.start + dt)));
      next = { ...c, start: round(s), offset: round(c.offset + (s - c.start)), duration: round(end - s) };
    } else if (kind === 'trimEnd') {
      const e = Math.max(c.start + MIN_CLIP, Math.min(c.start + fileLen - c.offset, sn(c.start + c.duration + dt)));
      next = { ...c, duration: round(e - c.start) };
    }
    return { ...seq, audio: seq.audio.map((t) => ({ ...t, clips: t.clips.map((x) => (x.id === id ? next : x)) })) };
  }
  const f = findClip(seq, id);
  if (!f) return seq;
  const c = f.clip;
  const end = clipEnd(c);
  let next: SeqClip = c;
  if (kind === 'trimStart') {
    const s = Math.max(0, Math.min(end - MIN_CLIP, sn(c.start + dt)));
    const duration = end - s;
    next = { ...c, start: round(s), duration: round(duration), fadeIn: Math.min(c.fadeIn ?? 0, Math.max(0, duration - (c.fadeOut ?? 0))) };
  } else if (kind === 'trimEnd') {
    const e = Math.max(c.start + MIN_CLIP, Math.min(seq.duration, sn(end + dt)));
    const duration = e - c.start;
    next = { ...c, duration: round(duration), fadeOut: Math.min(c.fadeOut ?? 0, Math.max(0, duration - (c.fadeIn ?? 0))) };
  } else if (kind === 'fadeIn') {
    next = { ...c, fadeIn: round(Math.max(0, Math.min(c.duration - (c.fadeOut ?? 0), (c.fadeIn ?? 0) + dt))) };
  } else {
    next = { ...c, fadeOut: round(Math.max(0, Math.min(c.duration - (c.fadeIn ?? 0), (c.fadeOut ?? 0) - dt))) };
  }
  return { ...seq, tracks: seq.tracks.map((t, i) => (i === f.ti ? { ...t, clips: t.clips.map((x) => (x.id === id ? next : x)) } : t)) };
}

function Playhead({ clock, pps, apiRef }: { clock: Clock; pps: number; apiRef: MutableRefObject<TimelineApi | null> }) {
  const el = useRef<HTMLDivElement>(null);
  const ppsRef = useRef(pps);
  ppsRef.current = pps;
  const hw = useRef(0);
  hw.current = useHeaderW();
  useLayoutEffect(() => {
    let raf = 0;
    let last = -1;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      const t = clock.time();
      if (t === last && !clock.playing) return;
      last = t;
      if (el.current) el.current.style.transform = `translateX(${hw.current + t * ppsRef.current}px)`;
      // Follow the playhead while playing.
      if (clock.playing && !clock.scrubbing) apiRef.current?.reveal(t);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [clock, apiRef]);
  return (
    <div ref={el} className="pointer-events-none absolute inset-y-0 left-0 z-[25] w-px bg-red-500">
      <div className="sticky top-0 -ml-[5px] h-0 w-0 border-x-[5.5px] border-t-[8px] border-x-transparent border-t-red-500" />
    </div>
  );
}

function TrackHeader({
  name,
  sub,
  selected,
  onSelect,
  onGrip,
  renaming,
  onRename,
  onStartRename,
  icon,
  children
}: {
  name: string;
  sub: string;
  selected: boolean;
  onSelect: () => void;
  onGrip: (e: RPointerEvent) => void;
  renaming: boolean;
  onRename: (name: string | null) => void;
  onStartRename: () => void;
  icon?: ReactNode;
  children: ReactNode;
}) {
  const compact = useContext(Compact);
  return (
    <div
      className={cn(
        'sticky left-0 z-20 flex shrink-0 items-center gap-1 border-r border-stone-200 pr-1.5 dark:border-stone-800',
        compact && 'pl-2',
        selected ? 'bg-sky-50 dark:bg-sky-950/60' : 'bg-white dark:bg-stone-900'
      )}
      style={{ width: useHeaderW() }}
      onPointerDown={onSelect}
    >
      {compact ? null : (
        <span
          title="Drag up or down to reorder"
          onPointerDown={(e) => {
            e.preventDefault();
            onGrip(e);
          }}
          className="flex h-full w-4 shrink-0 cursor-grab items-center justify-center text-stone-300 hover:text-stone-600 active:cursor-grabbing dark:text-stone-600"
        >
          <GripVertical className="size-3.5" />
        </span>
      )}
      <div className="min-w-0 flex-1" onDoubleClick={onStartRename}>
        {renaming ? (
          <input
            autoFocus
            defaultValue={name}
            maxLength={60}
            onBlur={(e) => onRename(e.target.value.trim() || null)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
              if (e.key === 'Escape') onRename(null);
            }}
            className="h-6 w-full rounded bg-white px-1 text-xs ring-1 ring-sky-500 outline-none dark:bg-stone-950"
          />
        ) : (
          <p className="flex items-center gap-1 truncate text-xs font-medium" title="Double-click to rename">
            {icon}
            {name}
          </p>
        )}
        <p className="truncate text-[10px] text-stone-500">{sub}</p>
      </div>
      {compact ? null : (
        <div className="flex shrink-0 items-center" onPointerDown={(e) => e.stopPropagation()}>
          {children}
        </div>
      )}
    </div>
  );
}

function IconToggle({ on, title, onClick, children, accent }: { on: boolean; title: string; onClick: () => void; children: ReactNode; accent?: boolean }) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      aria-pressed={on}
      onClick={onClick}
      className={cn(
        'grid size-6 place-items-center rounded transition [&_svg]:size-3.5',
        accent && on ? 'bg-amber-400 text-stone-950' : on ? 'text-stone-600 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800' : 'text-stone-400 hover:bg-stone-100 dark:hover:bg-stone-800'
      )}
    >
      {children}
    </button>
  );
}

function ClipBlock({
  clip,
  prev,
  pps,
  layout,
  selected,
  active,
  hovered,
  locked,
  onPress,
  onEdge,
  onDrop
}: {
  clip: SeqClip;
  prev: SeqClip | null;
  pps: number;
  layout: Layout | undefined;
  selected: boolean;
  active: boolean;
  hovered: boolean;
  locked: boolean;
  onPress: (e: RPointerEvent) => void;
  onEdge: (e: RPointerEvent, kind: 'trimStart' | 'trimEnd' | 'fadeIn' | 'fadeOut') => void;
  onDrop: (e: React.DragEvent) => void;
}) {
  const [over, setOver] = useState(false);
  const w = Math.max(2, clip.duration * pps);
  const colors = paletteColors(clip.effect);
  const info = effectInfo(clip.effect.effect);
  const ov = prev ? overlapOf(prev, clip) : 0;
  const fin = ov ? 0 : (clip.fadeIn ?? 0) * pps;
  const fout = (clip.fadeOut ?? 0) * pps;
  const H = TRACK_H - 8;
  const tIn = transitionInfo(clip.transitionIn);
  return (
    <div
      className={cn(
        'group absolute top-1 overflow-hidden rounded-md text-white shadow-sm transition-[box-shadow]',
        selected ? 'z-10 touch-none ring-2 ring-sky-400 ring-offset-1 ring-offset-white dark:ring-offset-stone-950' : 'ring-1 ring-black/20',
        active && 'shadow-[0_0_14px_rgba(255,255,255,0.35)]',
        hovered && !selected && 'ring-2 ring-amber-400',
        over && 'ring-2 ring-violet-500',
        locked ? 'cursor-not-allowed' : 'cursor-grab active:cursor-grabbing'
      )}
      style={{ left: clip.start * pps, width: w, height: H }}
      onPointerDown={onPress}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes(TRANSITION_MIME) || locked) return;
        e.preventDefault();
        e.stopPropagation();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        setOver(false);
        onDrop(e);
      }}
      title={`${info.name} on ${targetsLabel(layout, clip.targets)}\n${fmtTime(clip.start)} – ${fmtTime(clipEnd(clip))}${ov ? `\nCrosses over the clip before (${tIn.name}, ${ov.toFixed(1)} s)` : ''}`}
    >
      <div className="absolute inset-0" style={{ background: `linear-gradient(90deg, ${(colors.length > 1 ? colors : [colors[0], colors[0]]).join(', ')})`, opacity: active ? 0.95 : 0.7 }} />
      <div className="absolute inset-0 bg-gradient-to-b from-black/50 via-black/25 to-black/45" />
      {/* Fades and crossovers */}
      <svg className="pointer-events-none absolute inset-0 h-full w-full" preserveAspectRatio="none">
        {fin > 0 ? <polygon points={`0,0 ${fin},0 0,${H}`} fill="rgba(0,0,0,0.45)" /> : null}
        {fin > 0 ? <line x1={0} y1={H} x2={fin} y2={0} stroke="rgba(255,255,255,0.8)" strokeWidth={1} /> : null}
        {fout > 0 ? <polygon points={`${w - fout},0 ${w},0 ${w},${H}`} fill="rgba(0,0,0,0.45)" /> : null}
        {fout > 0 ? <line x1={w - fout} y1={0} x2={w} y2={H} stroke="rgba(255,255,255,0.8)" strokeWidth={1} /> : null}
        {ov > 0 ? (
          <>
            <rect x={0} y={0} width={ov * pps} height={H} fill="rgba(139,92,246,0.35)" />
            <line x1={0} y1={H} x2={ov * pps} y2={0} stroke="white" strokeWidth={1.5} />
            <line x1={0} y1={0} x2={ov * pps} y2={H} stroke="rgba(255,255,255,0.5)" strokeWidth={1} />
          </>
        ) : null}
      </svg>
      <div className="pointer-events-none relative flex h-full flex-col justify-center px-2 leading-tight" style={{ paddingLeft: Math.max(8, Math.min(ov * pps, w / 2) + 4) }}>
        <p className="truncate text-[11px] font-semibold drop-shadow">
          {clip.name || info.name}
          {info.space === '3d' ? <span className="ml-1 rounded bg-white/25 px-1 text-[9px] font-bold">3D</span> : null}
        </p>
        <p className="truncate text-[10px] text-white/85 drop-shadow">{targetsLabel(layout, clip.targets)}</p>
        {ov > 0 && ov * pps > 50 ? <p className="truncate text-[9px] text-violet-100">{tIn.name}</p> : null}
      </div>
      {!locked ? (
        <>
          <div className={cn('absolute inset-y-0 left-0 w-1.5 cursor-ew-resize hover:bg-white/50', w >= 64 && 'pointer-coarse:w-4')} onPointerDown={(e) => onEdge(e, 'trimStart')} title="Drag to trim the start" />
          <div className={cn('absolute inset-y-0 right-0 w-1.5 cursor-ew-resize hover:bg-white/50', w >= 64 && 'pointer-coarse:w-4')} onPointerDown={(e) => onEdge(e, 'trimEnd')} title="Drag to trim the end" />
          {!ov ? (
            <div
              className={cn('absolute top-0.5 size-2.5 -translate-x-1/2 cursor-ew-resize rounded-full bg-white opacity-0 shadow ring-1 ring-black/30 group-hover:opacity-100 pointer-coarse:size-3.5', selected && w >= 48 && 'pointer-coarse:opacity-100')}
              style={{ left: Math.max(5, fin) }}
              onPointerDown={(e) => onEdge(e, 'fadeIn')}
              title="Drag to fade in"
            />
          ) : null}
          <div
            className={cn('absolute top-0.5 size-2.5 translate-x-1/2 cursor-ew-resize rounded-full bg-white opacity-0 shadow ring-1 ring-black/30 group-hover:opacity-100 pointer-coarse:size-3.5', selected && w >= 48 && 'pointer-coarse:opacity-100')}
            style={{ right: Math.max(5, fout) }}
            onPointerDown={(e) => onEdge(e, 'fadeOut')}
            title="Drag to fade out"
          />
        </>
      ) : null}
    </div>
  );
}

function AudioBlock({
  clip,
  pps,
  view,
  engine,
  selected,
  muted,
  onPress,
  onEdge
}: {
  clip: AudioClip;
  pps: number;
  view: { x: number; w: number };
  engine: AudioEngine;
  selected: boolean;
  muted: boolean;
  onPress: (e: RPointerEvent) => void;
  onEdge: (e: RPointerEvent, kind: 'trimStart' | 'trimEnd') => void;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const state = engine.state(clip.fileId);
  const peaks = engine.peaks(clip.fileId);
  const w = Math.max(2, clip.duration * pps);
  const H = AUDIO_H - 8;
  // Only the part on the screen is drawn (a long song at a close zoom is very wide).
  const left = clip.start * pps;
  const vis0 = Math.max(0, view.x - useHeaderW() - left);
  const vis1 = Math.min(w, view.x + view.w - left);
  useEffect(() => {
    if (state === 'none') void engine.load(clip.fileId);
  }, [state, engine, clip.fileId]);
  useEffect(() => {
    const cv = canvas.current;
    if (!cv) return;
    const width = Math.max(1, Math.ceil(vis1 - vis0));
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    cv.width = Math.min(8192, width * dpr);
    cv.height = H * dpr;
    const g = cv.getContext('2d');
    if (!g || !peaks) return;
    g.clearRect(0, 0, cv.width, cv.height);
    g.fillStyle = muted ? 'rgba(255,255,255,0.35)' : 'rgba(255,255,255,0.85)';
    const sx = cv.width / width;
    for (let x = 0; x < cv.width; x++) {
      const t0 = clip.offset + (vis0 + x / sx) / pps;
      const t1 = clip.offset + (vis0 + (x + 1) / sx) / pps;
      let m = 0;
      for (let k = Math.floor(t0 * PEAKS_PER_SECOND); k <= Math.floor(t1 * PEAKS_PER_SECOND) && k < peaks.length; k++) m = Math.max(m, peaks[k] ?? 0);
      const h = Math.max(1, m * cv.height * 0.9);
      g.fillRect(x, (cv.height - h) / 2, 1, h);
    }
  }, [peaks, pps, clip.offset, vis0, vis1, H, muted]);
  return (
    <div
      className={cn(
        'absolute top-1 cursor-grab overflow-hidden rounded-md bg-gradient-to-b from-violet-600 to-violet-800 text-white shadow-sm active:cursor-grabbing',
        selected ? 'z-10 touch-none ring-2 ring-sky-400 ring-offset-1 ring-offset-white dark:ring-offset-stone-950' : 'ring-1 ring-black/20',
        muted && 'opacity-60'
      )}
      style={{ left, width: w, height: H }}
      onPointerDown={onPress}
      title={`${clip.name}\n${fmtTime(clip.start)} – ${fmtTime(clip.start + clip.duration)}`}
    >
      {vis1 > vis0 ? <canvas ref={canvas} className="pointer-events-none absolute top-0" style={{ left: vis0, width: vis1 - vis0, height: H }} /> : null}
      <p className="pointer-events-none relative truncate px-2 pt-0.5 text-[10px] font-semibold drop-shadow">
        {clip.name}
        {state === 'loading' ? ' · loading…' : state === 'error' ? ' · could not load' : ''}
      </p>
      <div className={cn('absolute inset-y-0 left-0 w-1.5 cursor-ew-resize hover:bg-white/50', w >= 64 && 'pointer-coarse:w-4')} onPointerDown={(e) => onEdge(e, 'trimStart')} />
      <div className={cn('absolute inset-y-0 right-0 w-1.5 cursor-ew-resize hover:bg-white/50', w >= 64 && 'pointer-coarse:w-4')} onPointerDown={(e) => onEdge(e, 'trimEnd')} />
    </div>
  );
}
