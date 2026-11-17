// The sequence editor's audio and clock. Audio files are decoded once with Web Audio and played
// sample-accurately from any point; the same audio clock times the light preview, so the lights
// and the music stay together.
import { api } from '../../../lib/api.ts';
import type { Sequence } from '../../../../../shared/sequence.ts';

/** Loudness peaks per second kept for the waveform. */
export const PEAKS_PER_SECOND = 100;

type Listener = () => void;

export class AudioEngine {
  private ctx: AudioContext | null = null;
  private buffers = new Map<string, AudioBuffer | 'loading' | 'error'>();
  private peakCache = new Map<string, Float32Array>();
  private sources: AudioScheduledSourceNode[] = [];
  private listeners = new Set<Listener>();

  /** The audio context, made on first use (browsers allow sound only after a click or key). */
  context(): AudioContext | null {
    if (!this.ctx) {
      try {
        this.ctx = new AudioContext({ latencyHint: 'interactive' });
      } catch {
        return null;
      }
    }
    if (this.ctx.state === 'suspended') void this.ctx.resume();
    return this.ctx;
  }

  on(fn: Listener) {
    this.listeners.add(fn);
    return () => void this.listeners.delete(fn);
  }

  private emit() {
    for (const fn of this.listeners) fn();
  }

  state(fileId: string): 'ready' | 'loading' | 'error' | 'none' {
    const b = this.buffers.get(fileId);
    return !b ? 'none' : b === 'loading' ? 'loading' : b === 'error' ? 'error' : 'ready';
  }

  buffer(fileId: string): AudioBuffer | null {
    const b = this.buffers.get(fileId);
    return b && typeof b !== 'string' ? b : null;
  }

  /** Loads and decodes a file (once). */
  async load(fileId: string): Promise<AudioBuffer | null> {
    const have = this.buffers.get(fileId);
    if (have && typeof have !== 'string') return have;
    if (have) return null;
    this.buffers.set(fileId, 'loading');
    this.emit();
    try {
      const res = await fetch(api.audioUrl(fileId), { credentials: 'same-origin' });
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.arrayBuffer();
      // Decoding needs a context but no sound: an offline one works before any click.
      const dec = this.ctx ?? new OfflineAudioContext(1, 1, 44100);
      const buf = await dec.decodeAudioData(data);
      this.buffers.set(fileId, buf);
      this.peakCache.set(fileId, computePeaks(buf));
      this.emit();
      return buf;
    } catch {
      this.buffers.set(fileId, 'error');
      this.emit();
      return null;
    }
  }

  /** Loudness 0..1, PEAKS_PER_SECOND values per second of the file. */
  peaks(fileId: string): Float32Array | null {
    return this.peakCache.get(fileId) ?? null;
  }

  /**
   * Plays the sequence's audio from `from` seconds, starting at context time `when`. Muted
   * tracks (and solo, when any track is solo) are left out.
   */
  start(seq: Sequence, from: number, when: number) {
    this.stop();
    const ctx = this.ctx;
    if (!ctx) return;
    for (const tr of seq.audio) {
      if (tr.muted || tr.volume <= 0) continue;
      const gain = ctx.createGain();
      gain.gain.value = tr.volume;
      gain.connect(ctx.destination);
      for (const c of tr.clips) {
        const end = c.start + c.duration;
        const buf = this.buffer(c.fileId);
        if (!buf || end <= from) continue;
        const skip = Math.max(0, from - c.start);
        const offset = c.offset + skip;
        const dur = Math.min(c.duration - skip, buf.duration - offset);
        if (dur <= 0) continue;
        const src = ctx.createBufferSource();
        src.buffer = buf;
        src.connect(gain);
        src.start(when + Math.max(0, c.start - from), offset, dur);
        this.sources.push(src);
      }
    }
  }

  stop() {
    for (const s of this.sources) {
      try {
        s.stop();
      } catch {}
      s.disconnect();
    }
    this.sources = [];
  }
}

function computePeaks(buf: AudioBuffer): Float32Array {
  const per = Math.max(1, Math.floor(buf.sampleRate / PEAKS_PER_SECOND));
  const n = Math.ceil(buf.length / per);
  const out = new Float32Array(n);
  const chans = Array.from({ length: Math.min(2, buf.numberOfChannels) }, (_, i) => buf.getChannelData(i));
  for (let k = 0; k < n; k++) {
    let m = 0;
    const end = Math.min(buf.length, (k + 1) * per);
    for (const ch of chans) for (let i = k * per; i < end; i += 4) m = Math.max(m, Math.abs(ch[i]));
    out[k] = m;
  }
  // Scale so the loudest part fills the height.
  let max = 0;
  for (const v of out) max = Math.max(max, v);
  if (max > 0) for (let i = 0; i < n; i++) out[i] /= max;
  return out;
}

/**
 * The playhead. While playing it follows the audio clock (or the page clock when there is no
 * audio), so the lights stay in step with the music.
 */
export class Clock {
  playing = false;
  private base = 0;
  private startedAt = 0;
  private ctx: AudioContext | null = null;
  private listeners = new Set<Listener>();
  /** Set while the playhead is dragged: frames are drawn quicker, with less catching up. */
  scrubbing = false;

  private now() {
    return this.ctx ? this.ctx.currentTime : performance.now() / 1000;
  }

  time(): number {
    return this.playing ? this.base + Math.max(0, this.now() - this.startedAt) : this.base;
  }

  /** Starts from the current time. Returns the context time at which it starts (for the audio). */
  play(ctx: AudioContext | null): number {
    this.ctx = ctx;
    this.startedAt = this.now() + (ctx ? 0.06 : 0);
    this.playing = true;
    this.emit();
    return this.startedAt;
  }

  pause() {
    if (!this.playing) return;
    this.base = this.time();
    this.playing = false;
    this.emit();
  }

  /** Moves the playhead; while playing it goes on from there. */
  seek(t: number) {
    this.base = Math.max(0, t);
    this.startedAt = this.now();
    this.emit();
  }

  on(fn: Listener) {
    this.listeners.add(fn);
    return () => void this.listeners.delete(fn);
  }

  emit() {
    for (const fn of this.listeners) fn();
  }
}
