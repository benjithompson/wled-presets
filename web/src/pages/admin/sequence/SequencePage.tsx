// The sequence editor: build an animated light show on a timeline, as in a video editor.
//
//   ┌ toolbar: sequence, save, undo, transport, snapping, zoom, lights ┐
//   │ browser (effects,     │ preview of the yard     │ inspector     │
//   │ transitions, objects) │ (front or 3-D, live)    │ (properties)  │
//   ├───────────────────────┴─────────────────────────┴───────────────┤
//   │ timeline: ruler, layers of clips, audio tracks                   │
//   └──────────────────────────────────────────────────────────────────┘
//
// On a phone (or a narrow window) it is one column, like a mobile app: the preview, the
// transport and the timeline, with the browser and the inspector in a bottom sheet.
//
// The preview draws the same frames the server sends to the lights (shared/sequence.ts).
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router';
import {
  ChevronDown,
  Clapperboard,
  Copy,
  FilePlus2,
  Flag,
  Lightbulb,
  LightbulbOff,
  Magnet,
  Maximize2,
  Pause,
  Play,
  Redo2,
  Repeat,
  Save,
  SkipBack,
  SkipForward,
  SlidersHorizontal,
  Sparkles,
  Trash2,
  Undo2,
  ZoomIn,
  ZoomOut
} from 'lucide-react';
import { toast } from 'sonner';
import { effectInfo, paletteColors, toBytes, YARD, type EffectId } from '../../../../../shared/effects.ts';
import { buildStage, type Layout, type Stage } from '../../../../../shared/layout.ts';
import { activeAt, clipEnd, emptySequence, newId, SequencePlayer, transitionInfo, type SeqClip, type Sequence } from '../../../../../shared/sequence.ts';
import { Button, ConfirmDialog, Spinner } from '../../../components/ui.tsx';
import { BottomSheet, MoreButton, type SheetSize } from '../../../components/mobile.tsx';
import { useMedia } from '../../../lib/useMedia.ts';
import { api } from '../../../lib/api.ts';
import { cn, errorText } from '../../../lib/utils.ts';
import { useInFront } from '../../../lib/useInFront.ts';
import { useStopOnLeave } from '../../../lib/useLightsPreview.ts';
import { PREVIEW_KEEPALIVE_MS } from '../../../../../shared/editorView.ts';
import { YardView } from '../../../yard/YardView.tsx';
import { OVERVIEW } from '../AdminLayout.tsx';
import { PaletteSwatch } from '../effectProps.tsx';
import { AudioEngine, Clock } from './audio.ts';
import { findClip, fmtTime, makeClip, removeClips, round, splitClips, targetsLabel, type Selection } from './model.ts';
import { Browser, Inspector } from './panels.tsx';
import { MAX_PPS, MIN_PPS, Timeline, useClockTick, type TimelineApi } from './Timeline.tsx';

const Scene3D = lazy(() => import('../../../yard/Scene3D.tsx').then((m) => ({ default: m.Scene3D })));

const SEQUENCES = ['admin', 'sequences'];
const LAST_KEY = 'seq.last';
const LIGHTS_KEY = 'seq.lights';
const HEIGHT_KEY = 'seq.timelineHeight';
const UNDO_STEPS = 150;
/** Changes with the same key closer together than this are one step for Undo. */
const UNDO_GROUP_MS = 1500;

const readLocal = (k: string, d: string) => {
  try {
    return localStorage.getItem(k) ?? d;
  } catch {
    return d;
  }
};
const writeLocal = (k: string, v: string) => {
  try {
    localStorage.setItem(k, v);
  } catch {}
};

/** The sequence without what the server adds. */
const content = (s: Sequence) => {
  const { updatedAt: _u, ...rest } = s;
  return JSON.stringify(rest);
};

export function SequencePage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { data: layout } = useQuery({ queryKey: ['layout'], queryFn: api.layout });
  const { data: list } = useQuery({ queryKey: SEQUENCES, queryFn: api.sequences });
  const [params, setParams] = useSearchParams();

  const [seq, setSeqState] = useState<Sequence | null>(null);
  const [saved, setSaved] = useState('');
  const seqRef = useRef<Sequence | null>(null);
  seqRef.current = seq;
  const past = useRef<Sequence[]>([]);
  const future = useRef<Sequence[]>([]);
  const lastChange = useRef<{ key?: string; at: number }>({ at: 0 });
  const [, setHistoryTick] = useState(0);

  const [sel, setSel] = useState<Selection>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [brush, setBrush] = useState<EffectId>('wash');
  const [pps, setPpsState] = useState(() => Number(readLocal('seq.pps', '30')) || 30);
  const setPps = useCallback((n: number) => {
    const v = Math.min(MAX_PPS, Math.max(MIN_PPS, n));
    setPpsState(v);
    writeLocal('seq.pps', String(v));
  }, []);
  const [snap, setSnap] = useState(() => readLocal('seq.snap', 'on') === 'on');
  const [lightsOn, setLightsOn] = useState(() => readLocal(LIGHTS_KEY, 'off') === 'on');
  const [lightDevices, setLightDevices] = useState<string[]>([]);
  const [view, setView] = useState<'front' | '3d'>(() => (readLocal('seq.view', 'front') === '3d' ? '3d' : 'front'));
  const [hover, setHover] = useState<{ id: string | null; x: number; y: number }>({ id: null, x: 0, y: 0 });
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<{ title: string; body: ReactNode; label: string; danger?: boolean; run: () => void } | null>(null);
  const [menu, setMenu] = useState(false);
  const [timelineH, setTimelineH] = useState(() => Number(readLocal(HEIGHT_KEY, '320')) || 320);
  // Wide screens get the editor's panels side by side; a phone (or a narrow window) gets one
  // column, with the library and the inspector in a bottom sheet.
  const wide = useMedia('(min-width: 1024px)');
  /** Touch: taps instead of drags and double-clicks. */
  const coarse = useMedia('(pointer: coarse)');
  const [sheet, setSheet] = useState<SheetSize>('peek');
  const [sheetTab, setSheetTab] = useState<'library' | 'details'>('library');
  // Something new selected (a tap on a clip): the sheet shows its properties.
  useEffect(() => {
    if (sel) setSheetTab('details');
  }, [sel]);

  const clock = useMemo(() => new Clock(), []);
  const audio = useMemo(() => new AudioEngine(), []);
  const timelineApi = useRef<TimelineApi | null>(null);
  const audioInput = useRef<HTMLInputElement>(null);
  const audioTarget = useRef<string | null>(null);
  const clipboard = useRef<{ clips: (SeqClip & { track: string })[]; t0: number } | null>(null);

  const dirty = !!seq && content(seq) !== saved;

  // ---------- History ----------

  const change = useCallback((next: Sequence, key?: string) => {
    const cur = seqRef.current;
    if (!cur || next === cur) return;
    const now = Date.now();
    const group = key && lastChange.current.key === key && now - lastChange.current.at < UNDO_GROUP_MS;
    if (!group) {
      past.current.push(cur);
      if (past.current.length > UNDO_STEPS) past.current.shift();
      future.current = [];
    }
    lastChange.current = { key, at: now };
    seqRef.current = next;
    setSeqState(next);
    setHistoryTick((n) => n + 1);
  }, []);

  const undo = () => {
    const cur = seqRef.current;
    const prev = past.current.pop();
    if (!cur || !prev) return;
    future.current.push(cur);
    lastChange.current = { at: 0 };
    setSeqState(prev);
    setHistoryTick((n) => n + 1);
  };
  const redo = () => {
    const cur = seqRef.current;
    const next = future.current.pop();
    if (!cur || !next) return;
    past.current.push(cur);
    lastChange.current = { at: 0 };
    setSeqState(next);
    setHistoryTick((n) => n + 1);
  };

  // ---------- Opening and saving ----------

  const stopPlayback = () => {
    clock.pause();
    audio.stop();
  };

  function open(next: Sequence, isSaved: boolean) {
    stopPlayback();
    clock.seek(0);
    past.current = [];
    future.current = [];
    lastChange.current = { at: 0 };
    setSeqState(next);
    setSaved(isSaved ? content(next) : '');
    setSel(null);
    if (next.id) writeLocal(LAST_KEY, next.id);
    for (const t of next.audio) for (const c of t.clips) void audio.load(c.fileId);
    requestAnimationFrame(() => timelineApi.current?.fit());
  }

  const loadById = async (id: string) => {
    try {
      open(await api.sequence(id), true);
    } catch (e) {
      toast.error(errorText(e));
    }
  };

  /** Asks first when there are unsaved changes. */
  const guard = (run: () => void) => {
    if (!dirty) return run();
    setConfirm({ title: 'Discard unsaved changes?', body: `“${seq?.name}” has changes that are not saved.`, label: 'Discard changes', danger: true, run });
  };

  // The first sequence to show: ?open=<id>, the last one opened, the first one, or a new one.
  const started = useRef(false);
  useEffect(() => {
    if (started.current || !list) return;
    started.current = true;
    const want = params.get('open') ?? readLocal(LAST_KEY, '');
    if (params.get('open')) setParams({}, { replace: true });
    const id = list.sequences.some((s) => s.id === want) ? want : list.sequences[0]?.id;
    if (id) void loadById(id);
    else open(emptySequence('My first show'), false);
  }, [list]);

  async function save(): Promise<Sequence | null> {
    const cur = seqRef.current;
    if (!cur) return null;
    setBusy(true);
    try {
      const out = cur.id ? await api.saveSequence(cur) : await api.createSequence(cur);
      // Keep what was edited while saving; take the id.
      const latest = seqRef.current ?? cur;
      const merged = { ...latest, id: out.id, updatedAt: out.updatedAt };
      seqRef.current = merged;
      setSeqState(merged);
      setSaved(content({ ...cur, id: out.id }));
      writeLocal(LAST_KEY, out.id);
      void qc.invalidateQueries({ queryKey: SEQUENCES });
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      toast.success(`“${out.name}” saved`);
      return merged;
    } catch (e) {
      toast.error(errorText(e));
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function makeScene() {
    const s = dirty || !seq?.id ? await save() : seq;
    if (!s?.id) return;
    try {
      await api.createScene({ name: s.name, devicePresets: {}, sequenceId: s.id });
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      toast.success(`Scene “${s.name}” created: it plays this sequence on the lights, over and over.`, { action: { label: 'Open Scenes', onClick: () => navigate('/admin/scenes') } });
    } catch (e) {
      toast.error(errorText(e));
    }
  }

  async function remove() {
    if (!seq) return;
    if (!seq.id) return open(emptySequence(), false);
    try {
      await api.deleteSequence(seq.id);
      toast.success(`“${seq.name}” deleted`);
      const rest = (await qc.fetchQuery({ queryKey: SEQUENCES, queryFn: api.sequences })).sequences;
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      if (rest[0]) void loadById(rest[0].id);
      else open(emptySequence(), false);
    } catch (e) {
      toast.error(errorText(e));
    }
  }

  // Leaving with unsaved changes.
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  // ---------- Playback ----------

  const play = useCallback(() => {
    const s = seqRef.current;
    if (!s) return;
    if (clock.time() >= s.duration - 0.02) clock.seek(0);
    const ctx = audio.context();
    const from = clock.time();
    const when = clock.play(ctx);
    audio.start(s, from, when);
  }, [clock, audio]);

  const pause = useCallback(() => {
    clock.pause();
    audio.stop();
  }, [clock, audio]);

  const resumeAfterScrub = useRef(false);
  const seek = useCallback(
    (t: number, scrub = false) => {
      const s = seqRef.current;
      const tt = Math.max(0, Math.min(s?.duration ?? t, t));
      if (clock.playing) {
        pause();
        if (scrub) resumeAfterScrub.current = true;
        clock.seek(tt);
        if (!scrub) play();
        return;
      }
      clock.seek(tt);
      if (!scrub && resumeAfterScrub.current) {
        resumeAfterScrub.current = false;
        play();
      }
    },
    [clock, play, pause]
  );

  const toggle = () => (clock.playing ? pause() : play());

  // The end: loop, or stop there.
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      const s = seqRef.current;
      if (!s || !clock.playing) return;
      if (clock.time() >= s.duration) {
        if (s.loop) {
          pause();
          clock.seek(0);
          play();
        } else {
          pause();
          clock.seek(s.duration);
        }
      }
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [clock, play, pause]);

  // Audio changed while playing (volume, mute, a moved clip): play it again from here.
  const audioKey = seq ? JSON.stringify(seq.audio) : '';
  useEffect(() => {
    if (!clock.playing) return;
    pause();
    play();
  }, [audioKey]);

  useEffect(() => () => stopPlayback(), []);

  // ---------- The preview ----------

  const stage = useMemo(() => (layout ? buildStage(layout) : null), [layout]);
  const fx = useRef<{ player: SequencePlayer; stage: Stage; data: Float32Array; bytes: Uint8Array; drawn: number; swatches: Map<string, string>; frames: number } | null>(null);
  useEffect(() => {
    if (!stage || !layout || !seq) return;
    const cur = fx.current;
    if (!cur || cur.stage !== stage) {
      const player = new SequencePlayer(stage, layout, seq);
      player.seek(clock.time());
      fx.current = { player, stage, data: new Float32Array(stage.pixelCount * 3), bytes: new Uint8Array(stage.pixelCount * 3), drawn: 0, swatches: new Map(), frames: 0 };
    } else cur.player.setSequence(seq);
  }, [stage, layout, seq]);

  const getFrame = () => {
    const f = fx.current;
    if (!f || !stage) return null;
    const now = performance.now();
    // Every view asks on each animation frame: draw once per frame.
    if (now - f.drawn > 4) {
      f.drawn = now;
      const t = clock.time();
      const p = f.player;
      if (t < p.time - 1e-6 || t - p.time > 0.25) p.seek(t, clock.scrubbing ? 0.4 : 2.5);
      p.update(Math.max(0, t - p.time), f.data, false);
      toBytes(f.data, f.bytes);
      // The color of each object, for the object list.
      if (f.frames++ % 8 === 0) {
        for (const sf of f.stage.fixtures) {
          let r = 0;
          let g = 0;
          let b = 0;
          let n = 0;
          for (let i = sf.offset; i < sf.offset + sf.count; i++) {
            const m = f.bytes[i * 3] + f.bytes[i * 3 + 1] + f.bytes[i * 3 + 2];
            if (m < 15) continue;
            r += f.bytes[i * 3];
            g += f.bytes[i * 3 + 1];
            b += f.bytes[i * 3 + 2];
            n++;
          }
          f.swatches.set(sf.id, n ? `rgb(${Math.round(r / n)},${Math.round(g / n)},${Math.round(b / n)})` : 'transparent');
        }
      }
    }
    return f.bytes;
  };

  // ---------- The lights ----------

  const mapped = !!layout?.fixtures.some((f) => f.deviceId);
  // Only while this window is in front: a sequence editor left in a background tab still sends
  // now and then (timers there run about once a minute), and each time it took every light for
  // 8 seconds, showing the paused moment of the sequence (often dark).
  const inFront = useInFront();
  const previewing = lightsOn && mapped && !!seq && inFront;
  const sendLights = useRef<() => void>(() => {});
  sendLights.current = () => {
    const s = seqRef.current;
    if (!previewing || !s) return;
    const { updatedAt: _u, ...sequence } = s;
    void api
      .previewSequence({ sequence, time: clock.time(), playing: clock.playing })
      .then((r) => setLightDevices(r.devices))
      .catch(() => setLightDevices([]));
  };
  useEffect(() => {
    if (!previewing) return;
    const t = setTimeout(() => sendLights.current(), 120);
    return () => clearTimeout(t);
  }, [previewing, seq]);
  useEffect(() => {
    if (!previewing) return;
    let pending: ReturnType<typeof setTimeout> | null = null;
    const off = clock.on(() => {
      if (pending) return;
      pending = setTimeout(() => {
        pending = null;
        sendLights.current();
      }, 60);
    });
    const keep = setInterval(() => sendLights.current(), PREVIEW_KEEPALIVE_MS);
    return () => {
      off();
      if (pending) clearTimeout(pending);
      clearInterval(keep);
      setLightDevices([]);
    };
  }, [previewing, clock]);
  useStopOnLeave(previewing, api.stopSequencePreview);

  // ---------- Editing commands ----------

  const selectedClipIds = sel?.kind === 'clips' ? sel.ids : sel?.kind === 'audio' ? sel.ids : [];

  function addAtPlayhead(id: EffectId) {
    if (!seq) return;
    let s = seq;
    let track = sel?.kind === 'track' ? s.tracks.find((t) => t.id === sel.id) : sel?.kind === 'clips' && sel.ids[0] ? findClip(s, sel.ids[0])?.track : undefined;
    track = track && !track.locked ? track : s.tracks.find((t) => !t.locked);
    if (!track) {
      track = { id: newId('layer'), name: `Layer ${s.tracks.length + 1}`, clips: [], opacity: 1, blend: 'normal' };
      s = { ...s, tracks: [track, ...s.tracks] };
    }
    const clip = makeClip(s, track, id, clock.time(), picked);
    change({ ...s, tracks: s.tracks.map((t) => (t.id === track!.id ? { ...t, clips: [...t.clips, clip] } : t)) });
    setSel({ kind: 'clips', ids: [clip.id] });
  }

  function deleteSelection() {
    if (!seq || !sel) return;
    if (sel.kind === 'clips' || sel.kind === 'audio') change(removeClips(seq, sel.ids));
    else if (sel.kind === 'marker') change({ ...seq, markers: seq.markers.filter((m) => m.id !== sel.id) });
    else if (sel.kind === 'track') change({ ...seq, tracks: seq.tracks.filter((t) => t.id !== sel.id) });
    else if (sel.kind === 'audioTrack') change({ ...seq, audio: seq.audio.filter((t) => t.id !== sel.id) });
    setSel(null);
  }

  function split() {
    if (!seq) return;
    const ids = selectedClipIds.length ? selectedClipIds : null;
    const r = splitClips(seq, ids, clock.time());
    if (!r.added.length) return void toast.info(ids ? 'The playhead is not inside the selected clips.' : 'No clip plays at the playhead.');
    change(r.seq);
  }

  function copy(cut = false) {
    if (!seq || sel?.kind !== 'clips' || !sel.ids.length) return;
    const clips = sel.ids.map((id) => findClip(seq, id)).filter((f): f is NonNullable<typeof f> => !!f);
    clipboard.current = { clips: clips.map((f) => ({ ...f.clip, track: f.track.id })), t0: Math.min(...clips.map((f) => f.clip.start)) };
    if (cut) {
      change(removeClips(seq, sel.ids));
      setSel(null);
    }
    toast.success(`${clips.length} clip(s) ${cut ? 'cut' : 'copied'}`);
  }

  function paste(at: number) {
    const cb = clipboard.current;
    if (!seq || !cb) return;
    const firstOpen = seq.tracks.find((t) => !t.locked);
    const ids: string[] = [];
    const tracks = seq.tracks.map((t) => {
      const add = cb.clips
        .filter((c) => (seq.tracks.some((x) => x.id === c.track && !x.locked) ? c.track === t.id : t.id === firstOpen?.id))
        .map(({ track: _t, ...c }) => {
          const id = newId('clip');
          ids.push(id);
          return { ...c, id, start: round(Math.max(0, Math.min(seq.duration - 0.1, at + c.start - cb.t0))) };
        });
      return add.length ? { ...t, clips: [...t.clips, ...add] } : t;
    });
    if (!ids.length) return;
    change({ ...seq, tracks });
    setSel({ kind: 'clips', ids });
  }

  function duplicate() {
    if (!seq || sel?.kind !== 'clips' || !sel.ids.length) return;
    const clips = sel.ids.map((id) => findClip(seq, id)?.clip).filter((c): c is SeqClip => !!c);
    const span = Math.max(...clips.map(clipEnd)) - Math.min(...clips.map((c) => c.start));
    const ids: string[] = [];
    const tracks = seq.tracks.map((t) => {
      if (t.locked) return t;
      const add = t.clips
        .filter((c) => sel.ids.includes(c.id))
        .map((c) => {
          const id = newId('clip');
          ids.push(id);
          return { ...c, id, start: round(c.start + span) };
        });
      return add.length ? { ...t, clips: [...t.clips, ...add] } : t;
    });
    change({ ...seq, tracks, duration: Math.max(seq.duration, round(Math.max(...clips.map(clipEnd)) + span)) });
    setSel({ kind: 'clips', ids });
  }

  function addMarker() {
    if (!seq) return;
    const m = { id: newId('marker'), t: round(clock.time()) };
    change({ ...seq, markers: [...seq.markers, m] });
  }

  async function addAudioFiles(files: File[], trackId: string | null, at: number) {
    const s0 = seqRef.current;
    if (!s0) return;
    const audioFiles = files.filter((f) => f.type.startsWith('audio/') || /\.(mp3|wav|ogg|oga|m4a|aac|flac)$/i.test(f.name));
    if (!audioFiles.length) return void toast.error('Drop an audio file (MP3, WAV, OGG, M4A or FLAC).');
    for (const file of audioFiles) {
      const id = toast.loading(`Uploading ${file.name}…`);
      try {
        const up = await api.uploadAudio(file);
        const buf = await audio.load(up.id);
        toast.success(`${file.name} added`, { id });
        const s = seqRef.current!;
        const length = buf?.duration ?? 30;
        let track = s.audio.find((t) => t.id === trackId) ?? s.audio[0];
        let next = s;
        if (!track) {
          track = { id: newId('audio'), name: 'Audio 1', clips: [], volume: 1 };
          next = { ...s, audio: [track] };
        }
        const clip = { id: newId('aclip'), fileId: up.id, name: file.name.replace(/\.[^.]+$/, ''), start: round(at), offset: 0, duration: round(length) };
        next = { ...next, audio: next.audio.map((t) => (t.id === track!.id ? { ...t, clips: [...t.clips, clip] } : t)) };
        // A song longer than the sequence: the sequence grows to fit it.
        if (at + length > next.duration) next = { ...next, duration: Math.ceil(at + length) };
        change(next);
        setSel({ kind: 'audio', ids: [clip.id] });
        requestAnimationFrame(() => timelineApi.current?.fit());
      } catch (e) {
        toast.error(errorText(e), { id });
      }
    }
  }

  // ---------- Keyboard ----------

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))) return;
      if (document.querySelector('dialog[open]')) return;
      const mod = e.ctrlKey || e.metaKey;
      const k = e.key.toLowerCase();
      const s = seqRef.current;
      if (!s) return;
      const handled = () => e.preventDefault();
      if (mod && k === 's') return (handled(), void save());
      if (mod && k === 'z') return (handled(), e.shiftKey ? redo() : undo());
      if (mod && k === 'y') return (handled(), redo());
      if (mod && k === 'c') return (handled(), copy());
      if (mod && k === 'x') return (handled(), copy(true));
      if (mod && k === 'v') return (handled(), paste(clock.time()));
      if (mod && k === 'd') return (handled(), duplicate());
      if (mod && k === 'k') return (handled(), split());
      if (mod && k === 'a') return (handled(), setSel({ kind: 'clips', ids: s.tracks.filter((t) => !t.locked).flatMap((t) => t.clips.map((c) => c.id)) }));
      if (mod) return;
      if (e.key === ' ') return (handled(), toggle());
      if (e.key === 'Home') return (handled(), seek(0));
      if (e.key === 'End') return (handled(), seek(s.duration));
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') return (handled(), seek(clock.time() + (e.key === 'ArrowLeft' ? -1 : 1) * (e.shiftKey ? 1 : 0.1)));
      if (e.key === 'Delete' || e.key === 'Backspace') return (handled(), deleteSelection());
      if (e.key === 'Escape') return setSel(null);
      if (k === 's') return (handled(), split());
      if (k === 'm') return (handled(), addMarker());
      if (k === 'n') return (handled(), setSnap((v) => (writeLocal('seq.snap', v ? 'off' : 'on'), !v)));
      if (e.key === '+' || e.key === '=') return (handled(), setPps(pps * 1.4));
      if (e.key === '-' || e.key === '_') return (handled(), setPps(pps / 1.4));
      if (e.key === '\\') return (handled(), timelineApi.current?.fit());
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  // ---------- Timeline height ----------

  const startResize = (e: React.PointerEvent) => {
    e.preventDefault();
    const y0 = e.clientY;
    const h0 = timelineH;
    const move = (ev: PointerEvent) => setTimelineH(Math.max(160, Math.min(window.innerHeight - 260, h0 - (ev.clientY - y0))));
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      setTimelineH((h) => (writeLocal(HEIGHT_KEY, String(h)), h));
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };

  if (!seq || !list) {
    return (
      <div className="grid h-full min-h-[50dvh] place-items-center">
        <Spinner />
      </div>
    );
  }

  // What the preview outlines: the selected clips' objects, or the picked ones.
  const selClips = sel?.kind === 'clips' ? sel.ids.map((id) => findClip(seq, id)?.clip).filter((c): c is SeqClip => !!c) : [];
  const outlineKeys = selClips.length ? selClips.flatMap((c) => c.targets) : picked;
  // The whole yard is not outlined: that would be everything.
  const outline = outlineKeys.includes(YARD) ? [] : [...new Set(outlineKeys.map((k) => k.split('#')[0]))];

  const toggleLights = () => setLightsOn((v) => (writeLocal(LIGHTS_KEY, v ? 'off' : 'on'), !v));
  const toggleSnap = () => setSnap((v) => (writeLocal('seq.snap', v ? 'off' : 'on'), !v));
  const toggleLoop = () => change({ ...seq, loop: !seq.loop || undefined });
  const lightsTitle = mapped ? (lightsOn ? `On the real lights${lightDevices.length ? `: ${lightDevices.join(', ')}` : ''}` : 'Show it on the real lights as you edit') : 'No object has a device yet (set one in Layout)';
  const canScene = !busy && seq.tracks.some((t) => t.clips.length);

  const seqMenu = (
    <div className="relative min-w-0">
      <button
        type="button"
        onClick={() => setMenu((v) => !v)}
        className="flex h-8 max-w-64 min-w-0 items-center gap-1.5 rounded-lg px-2 text-sm font-semibold hover:bg-stone-100 max-lg:h-10 dark:hover:bg-stone-800"
        aria-haspopup="menu"
        aria-expanded={menu}
      >
        <Clapperboard className="size-4 shrink-0 text-sky-600" />
        <span className="truncate">{seq.name}</span>
        {dirty ? <span className="size-2 shrink-0 rounded-full bg-amber-500" title="Not saved" /> : null}
        <ChevronDown className="size-3.5 shrink-0 text-stone-400" />
      </button>
      {menu ? (
        <SequenceMenu
          current={seq.id}
          list={list.sequences}
          onClose={() => setMenu(false)}
          onOpen={(id) => guard(() => void loadById(id))}
          onNew={() => guard(() => open(emptySequence(`Sequence ${list.sequences.length + 1}`), false))}
          onDuplicate={() => open({ ...seq, id: '', name: `${seq.name} copy` }, false)}
          onDelete={() =>
            setConfirm({ title: `Delete “${seq.name}”?`, body: 'Scenes that play it stop playing it. Audio files stay uploaded.', label: 'Delete sequence', danger: true, run: () => void remove() })
          }
        />
      ) : null}
    </div>
  );

  const preview = (
    <>
      {layout ? (
        view === 'front' ? (
          <YardView
            layout={layout}
            getFrame={getFrame}
            fill
            highlight={outline}
            onPick={(id, add) => {
              if (!id) return setPicked([]);
              // A finger picks one object after another; a click picks one (Shift or Ctrl/⌘ adds).
              setPicked(add || coarse ? (picked.includes(id) ? picked.filter((k) => k !== id) : [...picked.filter((k) => k !== YARD), id]) : picked.length === 1 && picked[0] === id ? [] : [id]);
            }}
            onHover={(id, at) => setHover({ id, ...at })}
          />
        ) : (
          <Suspense fallback={<div className="absolute inset-0 grid place-items-center text-sm text-white/50">Loading 3D view…</div>}>
            <Scene3D layout={layout} getFrame={getFrame} selected={outline} fill onSelect={(id, add) => (id ? setPicked(add ? [...new Set([...picked, id])] : [id]) : setPicked([]))} />
          </Suspense>
        )
      ) : null}
      <div className="absolute top-2 left-2 flex gap-1">
        {(['front', '3d'] as const).map((v) => (
          <button
            key={v}
            type="button"
            onClick={() => (setView(v), writeLocal('seq.view', v))}
            className={cn(
              'rounded-lg px-2.5 py-1 text-xs font-medium ring-1 ring-white/10 backdrop-blur max-lg:px-3 max-lg:py-1.5',
              view === v ? 'bg-white/85 text-stone-900' : 'bg-black/50 text-white/80 hover:bg-black/70'
            )}
          >
            {v === 'front' ? 'Front' : '3D'}
          </button>
        ))}
      </div>
      {layout && wide ? <NowPlaying clock={clock} seq={seq} layout={layout} onSelect={(id) => setSel({ kind: 'clips', ids: [id] })} /> : null}
      {hover.id && view === 'front' && !coarse ? <HoverCard clock={clock} seq={seq} id={hover.id} name={layout?.fixtures.find((f) => f.id === hover.id)?.name ?? ''} at={hover} /> : null}
      {lightsOn && lightDevices.length ? (
        <span className="pointer-events-none absolute top-2 right-2 max-w-[50%] truncate rounded-lg bg-amber-400/90 px-2 py-1 text-[11px] font-semibold text-stone-950">
          ● On the lights{wide ? `: ${lightDevices.join(', ')}` : ''}
        </span>
      ) : null}
    </>
  );

  const browser = (
    <Browser
      layout={layout}
      seq={seq}
      picked={picked}
      setPicked={setPicked}
      brush={brush}
      setBrush={setBrush}
      onAdd={(id) => {
        addAtPlayhead(id);
        // On a phone: close the panel, to show the new clip on the timeline.
        if (!wide) setSheet('peek');
      }}
      onTransition={(id) => {
        if (sel?.kind !== 'clips' || !sel.ids.length) return void toast.info(coarse ? 'Tap a clip first.' : 'Select a clip first, or drag the transition onto a clip.');
        change({ ...seq, tracks: seq.tracks.map((t) => ({ ...t, clips: t.clips.map((c) => (sel.ids.includes(c.id) ? { ...c, transitionIn: id, fadeIn: c.fadeIn && c.fadeIn > 0.05 ? c.fadeIn : Math.min(1, c.duration / 2) } : c)) })) });
      }}
      swatch={(id) => fx.current?.swatches.get(id) ?? null}
      hover={hover.id}
      setHover={(id) => setHover((h) => ({ ...h, id }))}
      touch={coarse}
    />
  );

  const inspector = (
    <Inspector
      seq={seq}
      layout={layout}
      sel={sel}
      setSel={setSel}
      change={change}
      playhead={clock.time()}
      picked={picked}
      onSplit={split}
      onDuplicate={duplicate}
      onDelete={deleteSelection}
      audioLength={(id) => audio.buffer(id)?.duration ?? null}
      touch={coarse}
    />
  );

  const timeline = (
    <Timeline
      seq={seq}
      layout={layout}
      change={change}
      sel={sel}
      setSel={setSel}
      clock={clock}
      seek={seek}
      pps={pps}
      setPps={setPps}
      snap={snap}
      audio={audio}
      newTargets={picked}
      brush={brush}
      onAudioFiles={(files, trackId, at) => void addAudioFiles(files, trackId, at)}
      onPickAudio={(trackId) => {
        audioTarget.current = trackId;
        audioInput.current?.click();
      }}
      apiRef={timelineApi}
      hoverObject={hover.id}
      compact={!wide}
    />
  );

  const extras = (
    <>
      <input
        ref={audioInput}
        type="file"
        accept="audio/*,.mp3,.wav,.ogg,.m4a,.flac"
        hidden
        onChange={(e) => {
          const files = [...(e.target.files ?? [])];
          e.target.value = '';
          if (files.length) void addAudioFiles(files, audioTarget.current, clock.time());
        }}
      />

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title ?? ''}
        confirmLabel={confirm?.label}
        danger={confirm?.danger}
        onConfirm={() => {
          const c = confirm;
          setConfirm(null);
          c?.run();
        }}
        onClose={() => setConfirm(null)}
      >
        {confirm?.body}
      </ConfirmDialog>
    </>
  );

  // A phone (or a narrow window) is laid out like a mobile app: the preview, the transport and
  // the timeline fill the screen, and the library and the inspector are in a bottom sheet.
  if (!wide) {
    const selCount = sel?.kind === 'clips' || sel?.kind === 'audio' ? sel.ids.length : 0;
    const detailsLabel =
      sel?.kind === 'clips' && selCount === 1
        ? ((c) => (c ? c.name || effectInfo(c.effect.effect).name : 'Clip'))(findClip(seq, sel.ids[0])?.clip)
        : selCount > 1
          ? `${selCount} clips`
          : sel?.kind === 'track'
            ? (seq.tracks.find((t) => t.id === sel.id)?.name ?? 'Layer')
            : sel?.kind === 'audioTrack'
              ? (seq.audio.find((t) => t.id === sel.id)?.name ?? 'Audio')
              : sel?.kind === 'audio'
                ? 'Audio clip'
                : sel?.kind === 'marker'
                  ? 'Marker'
                  : 'Sequence';
    const full = sheet === 'full';
    return (
      <div className="flex h-full flex-col bg-stone-100 dark:bg-stone-950">
        {/* The command bar: one row, the rest under ⋯. */}
        <div className="flex shrink-0 items-center gap-0.5 border-b border-stone-200 bg-stone-50 px-1.5 py-1 dark:border-stone-800 dark:bg-stone-900">
          <div className="mr-1 min-w-0 flex-1">{seqMenu}</div>
          <button type="button" onClick={undo} disabled={!past.current.length} aria-label="Undo" className={phoneIcon}>
            <Undo2 />
          </button>
          <button type="button" onClick={redo} disabled={!future.current.length} aria-label="Redo" className={phoneIcon}>
            <Redo2 />
          </button>
          <button type="button" onClick={toggleLights} disabled={!mapped} aria-pressed={lightsOn} aria-label={lightsTitle} title={lightsTitle} className={cn(phoneIcon, lightsOn && 'text-amber-500 dark:text-amber-400')}>
            {lightsOn ? <Lightbulb /> : <LightbulbOff />}
          </button>
          <MoreButton
            title={seq.name}
            label="More: loop, snapping, scenes"
            className="rounded-lg"
            items={[
              { label: seq.loop ? 'Loop: on' : 'Loop: off', icon: Repeat, run: toggleLoop },
              { label: snap ? 'Snapping: on' : 'Snapping: off', icon: Magnet, run: toggleSnap },
              { label: 'Zoom to fit', icon: Maximize2, run: () => timelineApi.current?.fit() },
              { label: 'Add a marker at the playhead', icon: Flag, run: addMarker },
              { label: 'Use in a scene', icon: Copy, disabled: !canScene, run: () => void makeScene() }
            ]}
          />
          <Button size="sm" variant="primary" onClick={() => void save()} disabled={busy || (!dirty && !!seq.id)} loading={busy} className="h-10">
            <Save /> Save
          </Button>
        </div>
        {full ? null : (
          <>
            <section className="relative h-[26dvh] min-h-36 shrink-0 bg-[#05070f]">{preview}</section>
            {/* Transport */}
            <div className="flex shrink-0 items-center gap-1 border-b border-stone-200 bg-stone-50 px-1.5 py-1 dark:border-stone-800 dark:bg-stone-900">
              <Transport clock={clock} duration={seq.duration} onToggle={toggle} onStart={() => seek(0)} onEnd={() => seek(seq.duration)} big />
              <span className="ml-auto" />
              <button type="button" onClick={() => setPps(pps / 1.4)} aria-label="Zoom out" className={phoneIcon}>
                <ZoomOut />
              </button>
              <button type="button" onClick={() => setPps(pps * 1.4)} aria-label="Zoom in" className={phoneIcon}>
                <ZoomIn />
              </button>
            </div>
            <div className="min-h-0 flex-1">{timeline}</div>
          </>
        )}
        <BottomSheet
          label="Library and properties"
          size={sheet}
          onSize={setSheet}
          tab={sheetTab}
          onTab={setSheetTab}
          tabs={[
            {
              id: 'library',
              content: (
                <>
                  <Sparkles /> Library
                </>
              )
            },
            {
              id: 'details',
              content: (
                <>
                  <SlidersHorizontal /> <span className="truncate">{detailsLabel}</span>
                </>
              )
            }
          ]}
        >
          {sheetTab === 'library' ? <div className="h-full">{browser}</div> : inspector}
        </BottomSheet>
        {extras}
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Toolbar */}
      <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-stone-200 bg-white px-2 py-1.5 dark:border-stone-800 dark:bg-stone-900">
        {seqMenu}
        <ToolButton onClick={() => void save()} disabled={busy || (!dirty && !!seq.id)} title="Save (Ctrl/⌘+S)" primary={dirty || !seq.id}>
          <Save /> Save
        </ToolButton>
        <Divider />
        <ToolButton onClick={undo} disabled={!past.current.length} title="Undo (Ctrl/⌘+Z)">
          <Undo2 />
        </ToolButton>
        <ToolButton onClick={redo} disabled={!future.current.length} title="Redo (Ctrl/⌘+Shift+Z)">
          <Redo2 />
        </ToolButton>
        <Divider />
        <Transport clock={clock} duration={seq.duration} onToggle={toggle} onStart={() => seek(0)} onEnd={() => seek(seq.duration)} />
        <ToolButton onClick={toggleLoop} active={!!seq.loop} title="Loop: start again at the end">
          <Repeat />
        </ToolButton>
        <Divider />
        <ToolButton onClick={toggleSnap} active={snap} title="Snap to clips, markers, the playhead and beats (N)">
          <Magnet />
        </ToolButton>
        <ToolButton onClick={() => setPps(pps / 1.4)} title="Zoom out (−)">
          <ZoomOut />
        </ToolButton>
        <ToolButton onClick={() => setPps(pps * 1.4)} title="Zoom in (+)">
          <ZoomIn />
        </ToolButton>
        <ToolButton onClick={() => timelineApi.current?.fit()} title="Zoom to fit (\)">
          <Maximize2 />
        </ToolButton>
        <div className="ml-auto flex items-center gap-1">
          <ToolButton onClick={toggleLights} active={lightsOn} disabled={!mapped} title={lightsTitle}>
            {lightsOn ? <Lightbulb /> : <LightbulbOff />} Lights
          </ToolButton>
          <ToolButton onClick={() => void makeScene()} disabled={!canScene} title="Make a scene that plays this sequence: a button on the public page">
            <Copy /> Use in a scene
          </ToolButton>
        </div>
      </div>

      {/* Upper area: browser, preview, inspector */}
      <div className="flex min-h-0 flex-1 flex-row">
        <aside className="w-64 shrink-0 border-r border-stone-200 bg-white dark:border-stone-800 dark:bg-stone-900">{browser}</aside>
        <section className="relative min-h-0 min-w-0 flex-1 bg-[#05070f]">{preview}</section>
        <aside className="w-80 shrink-0 overflow-y-auto border-l border-stone-200 bg-white dark:border-stone-800 dark:bg-stone-900">{inspector}</aside>
      </div>

      {/* Timeline */}
      <div onPointerDown={startResize} className="h-1.5 shrink-0 cursor-ns-resize border-y border-stone-200 bg-stone-100 hover:bg-sky-200 dark:border-stone-800 dark:bg-stone-900 dark:hover:bg-sky-900" title="Drag to resize" />
      <div className="shrink-0" style={{ height: timelineH }}>
        {timeline}
      </div>
      {extras}
    </div>
  );
}

const phoneIcon =
  'grid size-10 shrink-0 place-items-center rounded-lg text-stone-600 transition hover:bg-stone-200/70 active:bg-stone-200 disabled:opacity-35 dark:text-stone-300 dark:hover:bg-stone-800 dark:active:bg-stone-700 [&_svg]:size-[18px]';

function Divider() {
  return <span className="mx-0.5 h-5 w-px bg-stone-200 dark:bg-stone-700" />;
}

function ToolButton({ children, onClick, disabled, title, active, primary }: { children: ReactNode; onClick: () => void; disabled?: boolean; title?: string; active?: boolean; primary?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-label={title}
      aria-pressed={active}
      className={cn(
        'inline-flex h-8 items-center gap-1.5 rounded-lg px-2 text-xs font-medium transition disabled:pointer-events-none disabled:opacity-40 [&_svg]:size-4',
        primary
          ? 'bg-stone-900 text-white hover:bg-stone-800 dark:bg-accent-400 dark:text-stone-950'
          : active
            ? 'bg-sky-100 text-sky-800 dark:bg-sky-900/60 dark:text-sky-100'
            : 'text-stone-600 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-300 dark:hover:bg-stone-800 dark:hover:text-white'
      )}
    >
      {children}
    </button>
  );
}

function Transport({ clock, duration, onToggle, onStart, onEnd, big }: { clock: Clock; duration: number; onToggle: () => void; onStart: () => void; onEnd: () => void; big?: boolean }) {
  useClockTick(clock, 4);
  const time = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      if (time.current) time.current.textContent = fmtTime(clock.time());
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [clock]);
  return (
    <div className="flex items-center gap-0.5">
      {big ? (
        <button type="button" onClick={onStart} aria-label="To the start" className={phoneIcon}>
          <SkipBack />
        </button>
      ) : (
        <ToolButton onClick={onStart} title="To the start (Home)">
          <SkipBack />
        </ToolButton>
      )}
      <button
        type="button"
        onClick={onToggle}
        title={clock.playing ? 'Pause (Space)' : 'Play (Space)'}
        aria-label={clock.playing ? 'Pause' : 'Play'}
        className={cn('grid place-items-center rounded-full bg-sky-600 text-white shadow-sm transition hover:bg-sky-500', big ? 'size-10 [&_svg]:size-5' : 'size-8 [&_svg]:size-4')}
      >
        {clock.playing ? <Pause /> : <Play className="translate-x-px" />}
      </button>
      {big ? (
        <button type="button" onClick={onEnd} aria-label="To the end" className={phoneIcon}>
          <SkipForward />
        </button>
      ) : (
        <ToolButton onClick={onEnd} title="To the end (End)">
          <SkipForward />
        </ToolButton>
      )}
      <span className="ml-1 rounded-md bg-stone-100 px-2 py-1 font-mono text-xs tabular-nums dark:bg-stone-800">
        <span ref={time}>{fmtTime(clock.time())}</span>
        <span className="text-stone-400"> / {fmtTime(duration, false)}</span>
      </span>
    </div>
  );
}

function SequenceMenu({
  current,
  list,
  onClose,
  onOpen,
  onNew,
  onDuplicate,
  onDelete
}: {
  current: string;
  list: { id: string; name: string; duration: number; clips: number }[];
  onClose: () => void;
  onOpen: (id: string) => void;
  onNew: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) onClose();
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, [onClose]);
  const item = 'flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-sm hover:bg-stone-100 dark:hover:bg-stone-800 [&_svg]:size-4';
  return (
    <div ref={ref} role="menu" className="absolute top-full left-0 z-50 mt-1 w-72 rounded-xl bg-white p-1.5 shadow-xl ring-1 ring-stone-200 dark:bg-stone-900 dark:ring-stone-800">
      {list.length ? <p className="px-2.5 pt-1 pb-1 text-[11px] font-semibold tracking-wide text-stone-500 uppercase">Sequences</p> : null}
      <div className="max-h-72 overflow-y-auto">
        {list.map((s) => (
          <button key={s.id} type="button" role="menuitem" className={cn(item, s.id === current && 'bg-sky-50 dark:bg-sky-950/50')} onClick={() => (onClose(), onOpen(s.id))}>
            <span className="min-w-0 flex-1 truncate">{s.name}</span>
            <span className="text-xs text-stone-400">
              {fmtTime(s.duration, false)} · {s.clips} clip{s.clips === 1 ? '' : 's'}
            </span>
          </button>
        ))}
      </div>
      <div className="my-1 h-px bg-stone-100 dark:bg-stone-800" />
      <button type="button" role="menuitem" className={item} onClick={() => (onClose(), onNew())}>
        <FilePlus2 /> New sequence
      </button>
      <button type="button" role="menuitem" className={item} onClick={() => (onClose(), onDuplicate())}>
        <Copy /> Duplicate this one
      </button>
      <button type="button" role="menuitem" className={cn(item, 'text-red-600 dark:text-red-400')} onClick={() => (onClose(), onDelete())}>
        <Trash2 /> Delete this one
      </button>
    </div>
  );
}

/** What plays right now, layer by layer, over the preview. */
function NowPlaying({ clock, seq, layout, onSelect }: { clock: Clock; seq: Sequence; layout: Layout | undefined; onSelect: (id: string) => void }) {
  useClockTick(clock, 8);
  const [open, setOpen] = useState(true);
  // Read what plays at the clock's time (the player draws on the next frame).
  const now = clock.time();
  const active = activeAt(seq, now);
  return (
    <div className="absolute bottom-2 left-2 max-w-[min(26rem,calc(100%-1rem))] rounded-xl bg-black/60 p-2 text-white ring-1 ring-white/10 backdrop-blur">
      <button type="button" onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-2 text-left text-[11px] font-semibold tracking-wide text-white/70 uppercase">
        Now playing <span className="font-mono normal-case">{fmtTime(now)}</span>
        <ChevronDown className={cn('ml-auto size-3.5 transition', !open && '-rotate-90')} />
      </button>
      {open ? (
        active.length ? (
          <ul className="mt-1 space-y-1">
            {active.map((a) => {
              const tr = seq.tracks.find((t) => t.id === a.trackId);
              const clip = tr?.clips.find((c) => c.id === a.clipId);
              if (!tr || !clip) return null;
              return (
                <li key={a.clipId}>
                  <button type="button" onClick={() => onSelect(clip.id)} className="flex w-full items-center gap-2 rounded-md px-1 py-0.5 text-left text-xs hover:bg-white/10">
                    <PaletteSwatch colors={paletteColors(clip.effect)} className="block h-3 w-6 shrink-0 rounded-sm" />
                    <span className="w-16 shrink-0 truncate text-white/60">{tr.name}</span>
                    <span className="min-w-0 flex-1 truncate">
                      <b>{clip.name || effectInfo(clip.effect.effect).name}</b> <span className="text-white/70">on {targetsLabel(layout, clip.targets)}</span>
                    </span>
                    {a.level < 0.999 ? (
                      <span className="flex shrink-0 items-center gap-1 text-[10px] text-violet-200" title={a.from ? `${transitionInfo(a.from.transition).name} from the clip before` : 'Fading'}>
                        {a.from ? transitionInfo(a.from.transition).name : 'fade'}
                        <span className="h-1 w-8 overflow-hidden rounded bg-white/20">
                          <span className="block h-full bg-violet-300" style={{ width: `${Math.round(a.level * 100)}%` }} />
                        </span>
                      </span>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="mt-1 text-xs text-white/60">Nothing plays here. Drag an effect onto a layer below.</p>
        )
      ) : null}
    </div>
  );
}

/** Under the pointer in the preview: an object, and the clips that light it now. */
function HoverCard({ clock, seq, id, name, at }: { clock: Clock; seq: Sequence; id: string; name: string; at: { x: number; y: number } }) {
  useClockTick(clock, 8);
  const t = clock.time();
  const active = activeAt(seq, t).filter((a) => {
    const clip = seq.tracks.find((tr) => tr.id === a.trackId)?.clips.find((c) => c.id === a.clipId);
    return !!clip?.targets.some((k) => k === YARD || k === id || k.startsWith(`${id}#`));
  });
  return (
    <div className="pointer-events-none absolute z-10 max-w-64 rounded-lg bg-white/95 px-2.5 py-1.5 text-xs text-stone-900 shadow-lg ring-1 ring-black/10" style={{ left: at.x + 14, top: at.y + 14 }}>
      <p className="font-semibold">{name}</p>
      {active.length ? (
        active.map((a) => {
          const tr = seq.tracks.find((t) => t.id === a.trackId);
          const clip = tr?.clips.find((c) => c.id === a.clipId);
          return clip ? (
            <p key={a.clipId} className="truncate text-stone-600">
              {tr!.name}: {clip.name || effectInfo(clip.effect.effect).name}
              {a.level < 0.999 ? ` (${Math.round(a.level * 100)}%)` : ''}
            </p>
          ) : null;
        })
      ) : (
        <p className="text-stone-500">Dark now · click to pick it for new clips</p>
      )}
    </div>
  );
}
