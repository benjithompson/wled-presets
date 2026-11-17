// The sequence editor's side panels: the browser (effects, transitions and objects, on the
// left) and the inspector (properties of what is selected, on the right).
import { useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, Box, Circle, Copy, Crosshair, House, Scissors, Shapes, Spline, Trash2, TreePine } from 'lucide-react';
import { EFFECTS, effectInfo, paletteColors, YARD, type EffectId, type EffectInfo, type EffectSettings } from '../../../../../shared/effects.ts';
import type { FixtureKind, Layout } from '../../../../../shared/layout.ts';
import { BLEND_MODES, clipEnd, neighbours, overlapOf, TRANSITIONS, transitionInfo, type BlendMode, type SeqClip, type Sequence, type TransitionId } from '../../../../../shared/sequence.ts';
import { cn } from '../../../lib/utils.ts';
import { EffectProps, PaletteSwatch } from '../effectProps.tsx';
import { PropButton, PropNote, PropNumber, PropRow, PropSection, PropSelect, PropSlider, PropText } from '../props.tsx';
import { EFFECT_MIME, TRANSITION_MIME } from './Timeline.tsx';
import { allTargets, findAudioClip, findClip, fmtTime, MIN_CLIP, round, targetName, targetsLabel, updateClips, updateTrack, type Selection } from './model.ts';

const KIND_ICONS: Record<FixtureKind, typeof House> = { roof: House, line: Spline, bush: Circle, tree: TreePine, custom: Shapes };

type BrowserTab = 'effects' | 'transitions' | 'objects';

/** The effects tab: the basics first, then the effects in space, then along a string. */
const BROWSER_GROUPS: { label: string; has: (e: EffectInfo) => boolean }[] = [
  { label: 'Basics', has: (e) => !!e.basic },
  { label: 'In space (3-D)', has: (e) => e.space === '3d' },
  { label: 'Along the string (1-D)', has: (e) => e.space === '1d' && !e.basic }
];

export function Browser({
  layout,
  seq,
  picked,
  setPicked,
  brush,
  setBrush,
  onAdd,
  onTransition,
  swatch,
  hover,
  setHover
}: {
  layout: Layout | undefined;
  seq: Sequence;
  picked: string[];
  setPicked: (keys: string[]) => void;
  brush: EffectId;
  setBrush: (id: EffectId) => void;
  /** Adds a clip of this effect at the playhead. */
  onAdd: (id: EffectId) => void;
  /** Gives the selected clips this transition. */
  onTransition: (id: TransitionId) => void;
  /** The color an object shows now (CSS), from the preview. */
  swatch: (id: string) => string | null;
  hover: string | null;
  setHover: (id: string | null) => void;
}) {
  const [tab, setTab] = useState<BrowserTab>(() => {
    try {
      return (localStorage.getItem('seq.browser') as BrowserTab) || 'effects';
    } catch {
      return 'effects';
    }
  });
  const choose = (t: BrowserTab) => {
    setTab(t);
    try {
      localStorage.setItem('seq.browser', t);
    } catch {}
  };
  const uses = (key: string) => seq.tracks.reduce((n, t) => n + t.clips.filter((c) => c.targets.includes(key)).length, 0);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 gap-0.5 border-b border-stone-200 p-1 dark:border-stone-800">
        {(['effects', 'transitions', 'objects'] as BrowserTab[]).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => choose(t)}
            className={cn(
              'flex-1 rounded-md px-2 py-1 text-xs font-medium capitalize transition',
              tab === t ? 'bg-stone-900 text-white dark:bg-white dark:text-stone-900' : 'text-stone-600 hover:bg-stone-100 dark:text-stone-400 dark:hover:bg-stone-800'
            )}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {tab === 'effects' ? (
          <>
            <p className="px-1 pb-2 text-[11px] leading-snug text-stone-500">
              Drag an effect onto a layer, or double-click a layer. It plays on <b className="text-stone-700 dark:text-stone-300">{targetsLabel(layout, picked.length ? picked : [YARD])}</b> (pick objects in the Objects tab or the preview).
            </p>
            {BROWSER_GROUPS.map((group) => (
              <div key={group.label} className="mb-3">
                <p className="px-1 pb-1 text-[10px] font-semibold tracking-wide text-stone-500 uppercase">{group.label}</p>
                <div className="grid grid-cols-2 gap-1.5">
                  {EFFECTS.filter(group.has).map((e) => (
                    <button
                      key={e.id}
                      type="button"
                      draggable
                      onDragStart={(ev) => {
                        ev.dataTransfer.setData(EFFECT_MIME, e.id);
                        ev.dataTransfer.effectAllowed = 'copy';
                        setBrush(e.id);
                      }}
                      onClick={() => setBrush(e.id)}
                      onDoubleClick={() => onAdd(e.id)}
                      title={`${e.description}\nDrag onto a layer · double-click to add at the playhead`}
                      className={cn(
                        'group flex cursor-grab flex-col gap-1 rounded-lg p-1.5 text-left ring-1 transition active:cursor-grabbing',
                        brush === e.id ? 'bg-sky-50 ring-sky-400 dark:bg-sky-950/50' : 'bg-white ring-stone-200 hover:ring-stone-300 dark:bg-stone-900 dark:ring-stone-800 dark:hover:ring-stone-700'
                      )}
                    >
                      <PaletteSwatch colors={paletteColors({ palette: e.palette, colors: e.colors })} className="block h-5 w-full rounded" />
                      <span className="truncate text-[11px] font-medium">{e.name}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </>
        ) : tab === 'transitions' ? (
          <>
            <p className="px-1 pb-2 text-[11px] leading-snug text-stone-500">
              Drag a transition onto a clip: it is how the clip comes in. Overlap two clips on one layer to cross over from one to the other (also from one object to another). Click one to give it to the selected clips.
            </p>
            <div className="space-y-1">
              {TRANSITIONS.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  draggable
                  onDragStart={(ev) => {
                    ev.dataTransfer.setData(TRANSITION_MIME, t.id);
                    ev.dataTransfer.effectAllowed = 'copy';
                  }}
                  onClick={() => onTransition(t.id)}
                  className="flex w-full cursor-grab items-center gap-2 rounded-lg bg-white p-2 text-left ring-1 ring-stone-200 hover:ring-violet-400 active:cursor-grabbing dark:bg-stone-900 dark:ring-stone-800"
                >
                  <TransitionIcon id={t.id} />
                  <span className="min-w-0">
                    <span className="block text-xs font-medium">{t.name}</span>
                    <span className="block text-[10px] leading-snug text-stone-500">{t.description}</span>
                  </span>
                </button>
              ))}
            </div>
          </>
        ) : (
          <>
            <p className="px-1 pb-2 text-[11px] leading-snug text-stone-500">New clips play on the picked objects. Click to pick one, Ctrl/⌘-click to pick several. The dot shows each object’s color right now.</p>
            <ul className="space-y-0.5">
              {allTargets(layout).map((t) => {
                const on = picked.includes(t.key);
                const Icon = t.key === YARD ? Box : t.kind ? KIND_ICONS[t.kind as FixtureKind] : null;
                const color = t.key === YARD ? null : swatch(t.key);
                const n = uses(t.key);
                return (
                  <li key={t.key}>
                    <button
                      type="button"
                      onMouseEnter={() => t.depth === 0 && t.key !== YARD && setHover(t.key)}
                      onMouseLeave={() => setHover(null)}
                      onClick={(e) => {
                        if (e.ctrlKey || e.metaKey || e.shiftKey) setPicked(on ? picked.filter((k) => k !== t.key) : [...picked.filter((k) => k !== YARD), t.key].filter((k) => t.key !== YARD || k === YARD));
                        else setPicked(on && picked.length === 1 ? [] : [t.key]);
                      }}
                      className={cn(
                        'flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-xs',
                        t.depth && 'pl-7',
                        on ? 'bg-sky-100 text-sky-900 dark:bg-sky-900/60 dark:text-sky-100' : hover === t.key ? 'bg-amber-50 dark:bg-amber-950/40' : 'hover:bg-stone-100 dark:hover:bg-stone-800'
                      )}
                    >
                      {Icon ? <Icon className="size-3.5 shrink-0 text-stone-400" /> : <span className="w-3.5" />}
                      <span className={cn('min-w-0 flex-1 truncate', t.depth === 0 && 'font-medium')}>{t.name}</span>
                      {n ? <span className="text-[10px] text-stone-400">{n} clip{n === 1 ? '' : 's'}</span> : null}
                      {t.depth === 0 && t.key !== YARD ? <span className="size-3 shrink-0 rounded-full ring-1 ring-black/10 dark:ring-white/15" style={{ background: color ?? 'transparent' }} /> : null}
                    </button>
                  </li>
                );
              })}
            </ul>
            {picked.length ? (
              <div className="pt-2">
                <PropButton onClick={() => setPicked([])}>Pick nothing (whole yard)</PropButton>
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}

/** A small picture of a transition. */
export function TransitionIcon({ id }: { id: TransitionId }) {
  const common = 'size-8 shrink-0 rounded-md overflow-hidden ring-1 ring-black/10';
  const a = '#7c3aed';
  const b = '#f59e0b';
  const bg: Record<TransitionId, string> = {
    fade: `linear-gradient(90deg, ${a}, ${b})`,
    dip: `linear-gradient(90deg, ${a}, #000 50%, ${b})`,
    wipeRight: `linear-gradient(90deg, ${b} 45%, ${a} 55%)`,
    wipeLeft: `linear-gradient(90deg, ${a} 45%, ${b} 55%)`,
    wipeUp: `linear-gradient(0deg, ${b} 45%, ${a} 55%)`,
    wipeDown: `linear-gradient(180deg, ${b} 45%, ${a} 55%)`,
    iris: `radial-gradient(circle, ${b} 35%, ${a} 45%)`,
    dissolve: `repeating-conic-gradient(${a} 0 25%, ${b} 0 50%) 0 0 / 8px 8px`
  };
  return <span className={common} style={{ background: bg[id] }} />;
}

// ---------- Inspector ----------

export function Inspector({
  seq,
  layout,
  sel,
  setSel,
  change,
  playhead,
  picked,
  onSplit,
  onDuplicate,
  onDelete,
  audioLength
}: {
  seq: Sequence;
  layout: Layout | undefined;
  sel: Selection;
  setSel: (s: Selection) => void;
  change: (next: Sequence, key?: string) => void;
  playhead: number;
  picked: string[];
  onSplit: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
  /** Length of an audio file, when it is loaded. */
  audioLength: (fileId: string) => number | null;
}) {
  if (sel?.kind === 'clips' && sel.ids.length === 1) {
    const f = findClip(seq, sel.ids[0]);
    if (f) return <ClipInspector key={f.clip.id} seq={seq} layout={layout} clip={f.clip} locked={!!f.track.locked} trackName={f.track.name} change={change} playhead={playhead} picked={picked} onSplit={onSplit} onDuplicate={onDuplicate} onDelete={onDelete} />;
  }
  if (sel?.kind === 'clips' && sel.ids.length > 1) return <MultiInspector seq={seq} layout={layout} ids={sel.ids} change={change} picked={picked} onDuplicate={onDuplicate} onDelete={onDelete} onSplit={onSplit} />;
  if (sel?.kind === 'track') {
    const ti = seq.tracks.findIndex((t) => t.id === sel.id);
    const tr = seq.tracks[ti];
    if (tr)
      return (
        <>
          <Header title={tr.name} sub={`Layer ${seq.tracks.length - ti} of ${seq.tracks.length} · ${tr.clips.length} clip(s)`} />
          <PropSection id="seq-layer" title="Layer">
            <PropText label="Name" value={tr.name} maxLength={60} onChange={(name) => change(updateTrack(seq, tr.id, { name }), `name-${tr.id}`)} />
            <PropSelect<BlendMode> label="Blend" value={tr.blend} options={BLEND_MODES.map((b): [BlendMode, string] => [b.id, b.name])} onChange={(blend) => change(updateTrack(seq, tr.id, { blend }))} />
            <PropNote>{BLEND_MODES.find((b) => b.id === tr.blend)?.description}</PropNote>
            <PropSlider label="Opacity" value={tr.opacity} onChange={(opacity) => change(updateTrack(seq, tr.id, { opacity }), `opacity-${tr.id}`)} />
            <PropRow label="">
              <div className="flex flex-wrap gap-3 text-xs">
                <Check label="Hidden" checked={!!tr.hidden} onChange={(v) => change(updateTrack(seq, tr.id, { hidden: v || undefined }))} />
                <Check label="Solo" checked={!!tr.solo} onChange={(v) => change(updateTrack(seq, tr.id, { solo: v || undefined }))} />
                <Check label="Locked" checked={!!tr.locked} onChange={(v) => change(updateTrack(seq, tr.id, { locked: v || undefined }))} />
              </div>
            </PropRow>
            <div className="flex flex-wrap gap-1.5 pt-1">
              <PropButton onClick={() => change({ ...seq, tracks: swap(seq.tracks, ti, ti - 1) })} disabled={ti === 0} title="Move up: covers more layers">
                <ArrowUp /> Up
              </PropButton>
              <PropButton onClick={() => change({ ...seq, tracks: swap(seq.tracks, ti, ti + 1) })} disabled={ti === seq.tracks.length - 1}>
                <ArrowDown /> Down
              </PropButton>
              <PropButton
                danger
                onClick={() => {
                  change({ ...seq, tracks: seq.tracks.filter((t) => t.id !== tr.id) });
                  setSel(null);
                }}
              >
                <Trash2 /> Delete layer
              </PropButton>
            </div>
            <PropNote>Layers higher in the list cover the ones below, mixed by their blend and opacity.</PropNote>
          </PropSection>
        </>
      );
  }
  if (sel?.kind === 'audioTrack') {
    const tr = seq.audio.find((t) => t.id === sel.id);
    if (tr)
      return (
        <>
          <Header title={tr.name} sub={`Audio track · ${tr.clips.length} clip(s)`} />
          <PropSection id="seq-audio" title="Audio track">
            <PropText label="Name" value={tr.name} maxLength={60} onChange={(name) => change({ ...seq, audio: seq.audio.map((t) => (t.id === tr.id ? { ...t, name } : t)) }, `aname-${tr.id}`)} />
            <PropSlider label="Volume" value={tr.volume} onChange={(volume) => change({ ...seq, audio: seq.audio.map((t) => (t.id === tr.id ? { ...t, volume } : t)) }, `vol-${tr.id}`)} />
            <PropRow label="">
              <Check label="Muted" checked={!!tr.muted} onChange={(v) => change({ ...seq, audio: seq.audio.map((t) => (t.id === tr.id ? { ...t, muted: v || undefined } : t)) })} />
            </PropRow>
            <PropButton
              danger
              onClick={() => {
                change({ ...seq, audio: seq.audio.filter((t) => t.id !== tr.id) });
                setSel(null);
              }}
            >
              <Trash2 /> Delete track
            </PropButton>
            <PropNote>Audio plays in this browser while you edit, so you can time the lights to the music. The lights do not play sound.</PropNote>
          </PropSection>
        </>
      );
  }
  if (sel?.kind === 'audio' && sel.ids.length) {
    const f = findAudioClip(seq, sel.ids[0]);
    if (f) {
      const c = f.clip;
      const len = audioLength(c.fileId);
      const set = (patch: Partial<typeof c>, key?: string) => change({ ...seq, audio: seq.audio.map((t) => ({ ...t, clips: t.clips.map((x) => (x.id === c.id ? { ...x, ...patch } : x)) })) }, key);
      return (
        <>
          <Header title={c.name} sub={`Audio · ${fmtTime(c.start)} – ${fmtTime(c.start + c.duration)}`} />
          <PropSection id="seq-aclip" title="Audio clip">
            <PropNumber label="Start" unit="s" decimal step={0.1} min={0} max={seq.duration} value={round(c.start)} onChange={(start) => set({ start })} />
            <PropNumber label="Length" unit="s" decimal step={0.1} min={MIN_CLIP} max={len ? len - c.offset : 3600} value={round(c.duration)} onChange={(duration) => set({ duration })} />
            <PropNumber label="Skip in file" unit="s" decimal step={0.1} min={0} max={len ?? 3600} value={round(c.offset)} onChange={(offset) => set({ offset })} hint="Where in the file it starts playing" />
            {len ? <PropNote>The file is {fmtTime(len)} long.</PropNote> : null}
            <div className="flex flex-wrap gap-1.5 pt-1">
              <PropButton onClick={onSplit} disabled={playhead <= c.start || playhead >= c.start + c.duration}>
                <Scissors /> Split at playhead
              </PropButton>
              <PropButton danger onClick={onDelete}>
                <Trash2 /> Remove
              </PropButton>
            </div>
          </PropSection>
        </>
      );
    }
  }
  if (sel?.kind === 'marker') {
    const m = seq.markers.find((x) => x.id === sel.id);
    if (m)
      return (
        <>
          <Header title={m.label || 'Marker'} sub={`at ${fmtTime(m.t)}`} />
          <PropSection id="seq-marker" title="Marker">
            <PropText label="Label" value={m.label ?? ''} maxLength={60} onChange={(label) => change({ ...seq, markers: seq.markers.map((x) => (x.id === m.id ? { ...x, label: label || undefined } : x)) }, `mlabel-${m.id}`)} />
            <PropNumber label="Time" unit="s" decimal step={0.1} min={0} max={seq.duration} value={round(m.t)} onChange={(t) => change({ ...seq, markers: seq.markers.map((x) => (x.id === m.id ? { ...x, t } : x)) })} />
            <PropButton
              danger
              onClick={() => {
                change({ ...seq, markers: seq.markers.filter((x) => x.id !== m.id) });
                setSel(null);
              }}
            >
              <Trash2 /> Remove marker
            </PropButton>
            <PropNote>Clips and the playhead snap to markers. Press M while the music plays to tap markers on the beats.</PropNote>
          </PropSection>
        </>
      );
  }
  // Nothing selected: the sequence.
  const clips = seq.tracks.reduce((n, t) => n + t.clips.length, 0);
  return (
    <>
      <Header title={seq.name} sub={`${fmtTime(seq.duration, false)} · ${seq.tracks.length} layer(s) · ${clips} clip(s)`} />
      <PropSection id="seq-props" title="Sequence">
        <PropText label="Name" value={seq.name} maxLength={100} onChange={(name) => change({ ...seq, name }, 'seq-name')} />
        <PropNumber label="Length" unit="s" decimal step={1} min={1} max={3600} value={round(seq.duration)} onChange={(duration) => change({ ...seq, duration })} hint="Or drag the end mark on the ruler" />
        <PropNumber label="Tempo" unit="BPM" decimal step={1} min={0} max={400} value={seq.bpm ?? null} placeholder="none" onChange={(bpm) => change({ ...seq, bpm: bpm >= 20 ? bpm : undefined })} hint="Shows beats on the timeline; clips snap to them" />
        <PropRow label="">
          <Check label="Loop (start again at the end)" checked={!!seq.loop} onChange={(loop) => change({ ...seq, loop: loop || undefined })} />
        </PropRow>
      </PropSection>
      <PropSection id="seq-help" title="How it works">
        <ul className="list-disc space-y-1 pl-4 text-[11px] leading-snug text-stone-600 dark:text-stone-400">
          <li>Pick objects (Objects tab, or click them in the preview), then drag an effect onto a layer. With nothing picked, it plays on the whole yard.</li>
          <li>Upper layers cover lower ones. Set a layer to Add to put sparkles over a wash.</li>
          <li>Drag a clip over the end of another on the same layer to cross over: from one effect, or one object, to the next. Drop a transition on it to choose how.</li>
          <li>Drag the knobs at a clip’s top corners to fade it in and out.</li>
          <li>Turn on Lights to see it on the real lights as you edit. Use a sequence in a scene to put it on the public page.</li>
        </ul>
      </PropSection>
      <PropSection id="seq-keys" title="Keyboard and mouse" defaultOpen={false}>
        <Shortcuts />
      </PropSection>
    </>
  );
}

function ClipInspector({
  seq,
  layout,
  clip,
  locked,
  trackName,
  change,
  playhead,
  picked,
  onSplit,
  onDuplicate,
  onDelete
}: {
  seq: Sequence;
  layout: Layout | undefined;
  clip: SeqClip;
  locked: boolean;
  trackName: string;
  change: (next: Sequence, key?: string) => void;
  playhead: number;
  picked: string[];
  onSplit: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
}) {
  const set = (patch: Partial<SeqClip>, key?: string) => !locked && change(updateClips(seq, [clip.id], (c) => ({ ...c, ...patch })), key);
  const track = seq.tracks.find((t) => t.clips.some((c) => c.id === clip.id))!;
  const n = neighbours(track).find((x) => x.clip.id === clip.id);
  const ov = n?.prev ? overlapOf(n.prev, clip) : 0;
  const next = n?.next;
  const info = effectInfo(clip.effect.effect);
  return (
    <>
      <Header title={clip.name || info.name} sub={`${trackName} · ${fmtTime(clip.start)} – ${fmtTime(clipEnd(clip))}${locked ? ' · locked' : ''}`} />
      <PropSection id="seq-target" title="Plays on">
        <TargetPicker layout={layout} value={clip.targets} onChange={(targets) => set({ targets })} />
        <div className="flex flex-wrap gap-1.5 pt-1">
          <PropButton onClick={() => set({ targets: picked.length ? picked : [YARD] })} disabled={locked} title="Plays on the objects picked in the Objects tab or the preview">
            <Crosshair /> Use picked ({targetsLabel(layout, picked.length ? picked : [YARD])})
          </PropButton>
        </div>
      </PropSection>
      <PropSection id="seq-effect" title="Effect">
        <EffectProps effect={clip.effect} objectCount={0} noneLabel="(choose an effect)" onChange={(effect) => effect && set({ effect }, `fx-${clip.id}`)} />
      </PropSection>
      <PropSection id="seq-timing" title="Timing">
        <PropText label="Label" value={clip.name ?? ''} maxLength={80} onChange={(name) => set({ name: name || undefined }, `cname-${clip.id}`)} />
        <PropNumber label="Start" unit="s" decimal step={0.1} min={0} max={seq.duration - MIN_CLIP} value={round(clip.start)} onChange={(start) => set({ start })} />
        <PropNumber label="Length" unit="s" decimal step={0.1} min={MIN_CLIP} max={seq.duration} value={round(clip.duration)} onChange={(duration) => set({ duration })} />
        <PropNumber label="End" unit="s" decimal step={0.1} min={clip.start + MIN_CLIP} max={seq.duration} value={round(clipEnd(clip))} onChange={(end) => set({ duration: round(end - clip.start) })} />
      </PropSection>
      <PropSection id="seq-trans" title="Transitions">
        <PropSelect<TransitionId> label={ov ? 'Cross over' : 'In'} value={clip.transitionIn ?? 'fade'} options={TRANSITIONS.map((t): [TransitionId, string] => [t.id, t.name])} onChange={(transitionIn) => set({ transitionIn })} />
        {ov ? (
          <PropNote>
            Crosses over from the clip before it over {ov.toFixed(2)} s (where they overlap). {transitionInfo(clip.transitionIn).description}
          </PropNote>
        ) : (
          <PropNumber label="Fade in" unit="s" decimal step={0.1} min={0} max={clip.duration} value={round(clip.fadeIn ?? 0)} onChange={(fadeIn) => set({ fadeIn })} />
        )}
        <PropSelect<TransitionId> label="Out" value={clip.transitionOut ?? 'fade'} options={TRANSITIONS.map((t): [TransitionId, string] => [t.id, t.name])} onChange={(transitionOut) => set({ transitionOut })} />
        {next ? (
          <PropNote>The next clip on this layer crosses over this one (its own transition decides how).</PropNote>
        ) : (
          <PropNumber label="Fade out" unit="s" decimal step={0.1} min={0} max={clip.duration} value={round(clip.fadeOut ?? 0)} onChange={(fadeOut) => set({ fadeOut })} />
        )}
      </PropSection>
      <PropSection id="seq-clip-actions" title="Clip">
        <div className="flex flex-wrap gap-1.5">
          <PropButton onClick={onSplit} disabled={locked || playhead <= clip.start || playhead >= clipEnd(clip)} title="S">
            <Scissors /> Split at playhead
          </PropButton>
          <PropButton onClick={onDuplicate} disabled={locked} title="Ctrl+D">
            <Copy /> Duplicate
          </PropButton>
          <PropButton danger onClick={onDelete} disabled={locked}>
            <Trash2 /> Delete
          </PropButton>
        </div>
      </PropSection>
    </>
  );
}

/** Several clips: what they play on and their effect settings, changed together. */
function MultiInspector({
  seq,
  layout,
  ids,
  change,
  picked,
  onDuplicate,
  onDelete,
  onSplit
}: {
  seq: Sequence;
  layout: Layout | undefined;
  ids: string[];
  change: (next: Sequence, key?: string) => void;
  picked: string[];
  onDuplicate: () => void;
  onDelete: () => void;
  onSplit: () => void;
}) {
  const clips = ids.map((id) => findClip(seq, id)?.clip).filter((c): c is SeqClip => !!c);
  const first = clips[0];
  const same = clips.every((c) => c.effect.effect === first?.effect.effect);
  return (
    <>
      <Header title={`${clips.length} clips selected`} sub="Changes go to every selected clip" />
      <PropSection id="seq-multi-target" title="Plays on">
        <PropButton onClick={() => change(updateClips(seq, ids, (c) => ({ ...c, targets: picked.length ? picked : [YARD] })))}>
          <Crosshair /> Use picked ({targetsLabel(layout, picked.length ? picked : [YARD])})
        </PropButton>
      </PropSection>
      {first ? (
        <PropSection id="seq-multi-effect" title="Effect">
          {!same ? <PropNote>The clips play different effects. A setting you change here goes to all of them; picking an effect replaces theirs.</PropNote> : null}
          <EffectProps
            effect={first.effect}
            objectCount={0}
            onChange={(next) => {
              if (!next) return;
              const prev = first.effect;
              // Only what changed goes to each clip; the rest of its settings stay.
              const patch = Object.fromEntries(Object.entries(next).filter(([k, v]) => JSON.stringify(v) !== JSON.stringify(prev[k as keyof EffectSettings]))) as Partial<EffectSettings>;
              change(updateClips(seq, ids, (c) => ({ ...c, effect: patch.effect ? next : { ...c.effect, ...patch } })), 'multi-fx');
            }}
          />
        </PropSection>
      ) : null}
      <PropSection id="seq-multi-actions" title="Clips">
        <PropSelect<TransitionId | ''>
          label="Transition in"
          value=""
          options={[['', 'Set for all…'], ...TRANSITIONS.map((t): [TransitionId, string] => [t.id, t.name])]}
          onChange={(t) => t && change(updateClips(seq, ids, (c) => ({ ...c, transitionIn: t })))}
        />
        <div className="flex flex-wrap gap-1.5 pt-1">
          <PropButton onClick={onSplit}>
            <Scissors /> Split at playhead
          </PropButton>
          <PropButton onClick={onDuplicate}>
            <Copy /> Duplicate
          </PropButton>
          <PropButton danger onClick={onDelete}>
            <Trash2 /> Delete
          </PropButton>
        </div>
      </PropSection>
    </>
  );
}

function TargetPicker({ layout, value, onChange }: { layout: Layout | undefined; value: string[]; onChange: (keys: string[]) => void }) {
  const [open, setOpen] = useState(false);
  const toggle = (key: string) => {
    if (key === YARD) return onChange([YARD]);
    const rest = value.filter((k) => k !== YARD);
    const next = rest.includes(key) ? rest.filter((k) => k !== key) : [...rest, key];
    onChange(next.length ? next : [YARD]);
  };
  return (
    <div>
      <div className="flex flex-wrap gap-1">
        {value.map((k) => (
          <span key={k} className="inline-flex items-center gap-1 rounded-full bg-sky-100 px-2 py-0.5 text-[11px] text-sky-900 dark:bg-sky-900/50 dark:text-sky-100">
            {targetName(layout, k)}
            {value.length > 1 ? (
              <button type="button" aria-label={`Remove ${targetName(layout, k)}`} onClick={() => toggle(k)} className="text-sky-700 hover:text-sky-950 dark:text-sky-300">
                ×
              </button>
            ) : null}
          </span>
        ))}
        <button type="button" onClick={() => setOpen((v) => !v)} className="rounded-full px-2 py-0.5 text-[11px] text-stone-500 ring-1 ring-stone-200 hover:text-stone-900 dark:ring-stone-700 dark:hover:text-white">
          {open ? 'Done' : 'Change…'}
        </button>
      </div>
      {open ? (
        <ul className="mt-1.5 max-h-56 space-y-0.5 overflow-y-auto rounded-md p-1 ring-1 ring-stone-200 dark:ring-stone-800">
          {allTargets(layout).map((t) => (
            <li key={t.key}>
              <label className={cn('flex cursor-pointer items-center gap-2 rounded px-1.5 py-0.5 text-xs hover:bg-stone-100 dark:hover:bg-stone-800', t.depth && 'pl-6')}>
                <input type="checkbox" checked={value.includes(t.key)} onChange={() => toggle(t.key)} className="accent-sky-600" />
                <span className={cn('truncate', t.depth === 0 && 'font-medium')}>{t.name}</span>
              </label>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function Header({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="sticky top-0 z-10 border-b border-stone-200 bg-white px-3 py-2 dark:border-stone-800 dark:bg-stone-900">
      <p className="truncate text-[13px] font-semibold">{title}</p>
      <p className="truncate text-[11px] text-stone-500">{sub}</p>
    </div>
  );
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center gap-1.5 text-xs text-stone-700 dark:text-stone-300">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="accent-sky-600" />
      {label}
    </label>
  );
}

function swap<T>(arr: T[], i: number, j: number): T[] {
  if (j < 0 || j >= arr.length) return arr;
  const out = [...arr];
  [out[i], out[j]] = [out[j], out[i]];
  return out;
}

const SHORTCUTS: [string, ReactNode][] = [
  ['Space', 'Play or pause'],
  ['Home / End', 'Go to the start / the end'],
  ['← / →', 'Step 0.1 s (Shift: 1 s)'],
  ['Click the ruler', 'Move the playhead (drag to scrub)'],
  ['Click empty space', 'Move the playhead there'],
  ['Drag on empty space', 'Select clips in a box'],
  ['Ctrl/⌘-click', 'Add a clip to the selection'],
  ['Alt-drag a clip', 'Drag a copy'],
  ['Alt while dragging', 'No snapping'],
  ['S or Ctrl/⌘+K', 'Split at the playhead'],
  ['Ctrl/⌘+D', 'Duplicate'],
  ['Ctrl/⌘+C / X / V', 'Copy, cut, paste at the playhead'],
  ['Delete', 'Delete the selection'],
  ['M', 'Add a marker (also while playing)'],
  ['Double-click the ruler', 'Add a marker there'],
  ['N', 'Snapping on or off'],
  ['+ / − / \\', 'Zoom in, out, to fit (or Ctrl/⌘ + wheel)'],
  ['Ctrl/⌘+Z / Shift+Z', 'Undo / redo'],
  ['Ctrl/⌘+S', 'Save'],
  ['Esc', 'Select nothing']
];

function Shortcuts() {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
      {SHORTCUTS.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-medium whitespace-nowrap text-stone-700 dark:text-stone-300">{k}</dt>
          <dd className="text-stone-500">{v}</dd>
        </div>
      ))}
    </dl>
  );
}
