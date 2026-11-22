// The showcase's music, synthesized in the browser from its score (shared/showcase.ts): drums,
// bass, pads, a lead and an arpeggio, rendered offline with Web Audio into a WAV file that the
// editor uploads as the sequence's audio track. Each note is panned to where its light is.

import { SHOWCASE_BPM, type ScoreNote } from '../../../../../shared/showcase.ts';

const BEAT = 60 / SHOWCASE_BPM;
const hz = (m: number) => 440 * 2 ** ((m - 69) / 12);

/** Notes are made a second at a time, and taken out once they have died away: Web Audio keeps working on every node in the graph. */
const WINDOW = 1;

/** Renders the score to a stereo WAV file. */
export async function renderShowcaseAudio(score: ScoreNote[], seconds: number, sampleRate = 24000): Promise<Blob> {
  const ctx = new OfflineAudioContext(2, Math.ceil(seconds * sampleRate), sampleRate);
  const s = new Synth(ctx);
  const notes = [...score].sort((a, b) => a.t - b.t);
  let k = 0;
  const upTo = (t: number) => {
    while (k < notes.length && notes[k].t < t) s.play(notes[k++]);
  };
  upTo(WINDOW + 0.05);
  for (let w = WINDOW; w < seconds; w += WINDOW) {
    void ctx.suspend(w).then(() => {
      s.release(w);
      upTo(w + WINDOW + 0.05);
      void ctx.resume();
    });
  }
  return wav(await ctx.startRendering());
}

class Synth {
  private ctx: OfflineAudioContext;
  private noise: AudioBuffer;
  /** Everything but the drums: it ducks on each kick in the drops (a sidechain pump). */
  private music: GainNode;
  private drums: GainNode;
  private reverb: GainNode;
  private echo: GainNode;
  /** The nodes of the notes playing, and when each note has died away. */
  private live: { end: number; nodes: AudioNode[] }[] = [];
  private cur: AudioNode[] = [];

  constructor(ctx: OfflineAudioContext) {
    this.ctx = ctx;
    const master = ctx.createDynamicsCompressor();
    master.threshold.value = -16;
    master.knee.value = 8;
    master.ratio.value = 4;
    master.attack.value = 0.004;
    master.release.value = 0.2;
    const out = ctx.createGain();
    out.gain.value = 0.9;
    master.connect(out).connect(ctx.destination);

    this.noise = ctx.createBuffer(1, ctx.sampleRate * 2, ctx.sampleRate);
    const d = this.noise.getChannelData(0);
    let seed = 12345;
    for (let i = 0; i < d.length; i++) {
      seed = (seed * 1103515245 + 12345) >>> 0;
      d[i] = (seed / 2 ** 32) * 2 - 1;
    }

    this.music = ctx.createGain();
    this.music.connect(master);
    this.drums = ctx.createGain();
    this.drums.connect(master);

    // A hall: decaying noise as the impulse.
    const conv = ctx.createConvolver();
    const len = Math.floor(ctx.sampleRate * 2.4);
    const ir = ctx.createBuffer(2, len, ctx.sampleRate);
    for (let c = 0; c < 2; c++) {
      const ch = ir.getChannelData(c);
      for (let i = 0; i < len; i++) {
        seed = (seed * 1103515245 + 12345) >>> 0;
        ch[i] = ((seed / 2 ** 32) * 2 - 1) * (1 - i / len) ** 3;
      }
    }
    conv.buffer = ir;
    this.reverb = ctx.createGain();
    this.reverb.gain.value = 0.22;
    this.reverb.connect(conv).connect(this.music);

    // A dotted-eighth echo.
    const delay = ctx.createDelay(2);
    delay.delayTime.value = BEAT * 0.75;
    const fb = ctx.createGain();
    fb.gain.value = 0.38;
    const tone = ctx.createBiquadFilter();
    tone.type = 'lowpass';
    tone.frequency.value = 2600;
    this.echo = ctx.createGain();
    this.echo.gain.value = 0.3;
    this.echo.connect(delay);
    delay.connect(tone).connect(fb).connect(delay);
    tone.connect(this.music);
  }

  play(n: ScoreNote) {
    this.cur = [];
    this.note(n);
    this.live.push({ end: n.t + n.dur + 2.5, nodes: this.cur });
  }

  /** Disconnects the notes that have died away by time `t`. */
  release(t: number) {
    this.live = this.live.filter((v) => {
      if (v.end > t) return true;
      for (const node of v.nodes) node.disconnect();
      return false;
    });
  }

  private note(n: ScoreNote) {
    switch (n.inst) {
      case 'kick':
        return this.kick(n);
      case 'clap':
        return this.clap(n);
      case 'snare':
        return this.snare(n);
      case 'hat':
        return this.hat(n);
      case 'bass':
        return this.bass(n);
      case 'lead':
        return this.lead(n);
      case 'arp':
        return this.arp(n);
      case 'pad':
        return this.pad(n);
      case 'stab':
        return this.stab(n);
      case 'impact':
        return this.impact(n);
      case 'riser':
        return this.riser(n);
    }
  }

  // ---------- Building blocks ----------

  /** A voice's output: gain (with an envelope set by the caller), panned, into `bus`, with sends. */
  private voice(n: ScoreNote, bus: AudioNode, sends: { reverb?: number; echo?: number } = {}) {
    const g = this.ctx.createGain();
    g.gain.value = 0;
    const pan = this.ctx.createStereoPanner();
    pan.pan.value = n.pan;
    this.cur.push(g, pan);
    g.connect(pan).connect(bus);
    if (sends.reverb) this.send(pan, this.reverb, sends.reverb);
    if (sends.echo) this.send(pan, this.echo, sends.echo);
    return g;
  }

  private send(from: AudioNode, to: AudioNode, amount: number) {
    const g = this.ctx.createGain();
    g.gain.value = amount;
    from.connect(g).connect(to);
    this.cur.push(g);
  }

  /** Attack, hold at `level`, then release to silence. */
  private env(p: AudioParam, t: number, level: number, attack: number, hold: number, release: number) {
    p.setValueAtTime(0, t);
    p.linearRampToValueAtTime(level, t + attack);
    p.setValueAtTime(level, t + attack + hold);
    p.exponentialRampToValueAtTime(0.0001, t + attack + hold + release);
  }

  private osc(type: OscillatorType, freq: number, t: number, end: number, to: AudioNode, detune = 0) {
    const o = this.ctx.createOscillator();
    o.type = type;
    o.frequency.value = freq;
    o.detune.value = detune;
    o.connect(to);
    this.cur.push(o);
    o.start(t);
    o.stop(end);
    return o;
  }

  private noiseAt(t: number, dur: number, to: AudioNode) {
    const src = this.ctx.createBufferSource();
    src.buffer = this.noise;
    src.loop = true;
    src.connect(to);
    this.cur.push(src);
    src.start(t, (t * 0.37) % 1.5);
    src.stop(t + dur);
    return src;
  }

  private filter(type: BiquadFilterType, freq: number, q = 0.7) {
    const f = this.ctx.createBiquadFilter();
    f.type = type;
    f.frequency.value = freq;
    f.Q.value = q;
    this.cur.push(f);
    return f;
  }

  // ---------- Drums ----------

  private kick(n: ScoreNote) {
    const { t } = n;
    const g = this.voice(n, this.drums);
    this.env(g.gain, t, 0.95 * n.vel, 0.002, 0.03, 0.4);
    const o = this.osc('sine', 150, t, t + 0.5, g);
    o.frequency.setValueAtTime(155, t);
    o.frequency.exponentialRampToValueAtTime(44, t + 0.13);
    // The click on top.
    const c = this.voice(n, this.drums);
    this.env(c.gain, t, 0.25 * n.vel, 0.001, 0, 0.02);
    const hp = this.filter('highpass', 2500);
    hp.connect(c);
    this.noiseAt(t, 0.04, hp);
    // The pump: the rest of the music makes room for it.
    const deep = n.vel >= 1 ? 0.35 : 0.7;
    this.music.gain.setValueAtTime(deep, t);
    this.music.gain.linearRampToValueAtTime(1, t + BEAT * 0.75);
  }

  private clap(n: ScoreNote) {
    const { t } = n;
    const bp = this.filter('bandpass', 1400, 0.9);
    const g = this.voice(n, this.drums, { reverb: 0.5 });
    bp.connect(g);
    g.gain.setValueAtTime(0, t);
    for (let k = 0; k < 3; k++) {
      g.gain.setValueAtTime(0.7 * n.vel, t + k * 0.011);
      g.gain.exponentialRampToValueAtTime(0.08, t + k * 0.011 + 0.009);
    }
    g.gain.setValueAtTime(0.6 * n.vel, t + 0.034);
    g.gain.exponentialRampToValueAtTime(0.0001, t + 0.26);
    this.noiseAt(t, 0.3, bp);
  }

  private snare(n: ScoreNote) {
    const { t } = n;
    const g = this.voice(n, this.drums, { reverb: 0.3 });
    this.env(g.gain, t, 0.5 * n.vel, 0.001, 0.005, 0.14);
    const hp = this.filter('highpass', 1200);
    hp.connect(g);
    this.noiseAt(t, 0.2, hp);
    const body = this.voice(n, this.drums);
    this.env(body.gain, t, 0.35 * n.vel, 0.001, 0, 0.08);
    const o = this.osc('triangle', 220, t, t + 0.12, body);
    o.frequency.exponentialRampToValueAtTime(160, t + 0.08);
  }

  private hat(n: ScoreNote) {
    const { t } = n;
    const g = this.voice(n, this.drums);
    this.env(g.gain, t, 0.28 * n.vel, 0.001, 0, n.vel > 0.4 ? 0.07 : 0.035);
    const hp = this.filter('highpass', 7500);
    hp.connect(g);
    this.noiseAt(t, 0.1, hp);
  }

  private impact(n: ScoreNote) {
    const { t, dur } = n;
    const boom = this.voice(n, this.drums, { reverb: 0.6 });
    this.env(boom.gain, t, 0.9, 0.003, 0.05, 1.6);
    const o = this.osc('sine', 70, t, t + dur, boom);
    o.frequency.exponentialRampToValueAtTime(28, t + 1.4);
    // A crash cymbal.
    const crash = this.voice(n, this.drums, { reverb: 0.5 });
    this.env(crash.gain, t, 0.3, 0.002, 0.02, dur);
    const hp = this.filter('highpass', 4500);
    hp.connect(crash);
    this.noiseAt(t, dur, hp);
  }

  private riser(n: ScoreNote) {
    const { t, dur } = n;
    const g = this.voice(n, this.music, { reverb: 0.5 });
    g.gain.setValueAtTime(0.001, t);
    g.gain.exponentialRampToValueAtTime(0.4 * n.vel, t + dur);
    g.gain.linearRampToValueAtTime(0, t + dur + 0.05);
    const bp = this.filter('bandpass', 300, 3);
    bp.frequency.setValueAtTime(300, t);
    bp.frequency.exponentialRampToValueAtTime(7000, t + dur);
    bp.connect(g);
    this.noiseAt(t, dur + 0.06, bp);
  }

  // ---------- Tones ----------

  private bass(n: ScoreNote) {
    const { t, dur } = n;
    const f = this.filter('lowpass', 900, 7);
    f.frequency.setValueAtTime(1400, t);
    f.frequency.exponentialRampToValueAtTime(180, t + dur);
    const g = this.voice(n, this.music);
    f.connect(g);
    this.env(g.gain, t, 0.42 * n.vel, 0.004, dur * 0.5, dur * 0.5);
    const end = t + dur + 0.05;
    this.osc('sawtooth', hz(n.notes[0]), t, end, f);
    this.osc('square', hz(n.notes[0] - 12), t, end, f);
  }

  private lead(n: ScoreNote) {
    const { t, dur } = n;
    const f = this.filter('lowpass', 3400, 2);
    f.frequency.setValueAtTime(5200, t);
    f.frequency.exponentialRampToValueAtTime(2200, t + Math.min(dur, 0.3));
    const g = this.voice(n, this.music, { reverb: 0.35, echo: 0.5 });
    f.connect(g);
    this.env(g.gain, t, 0.13 * n.vel, 0.008, Math.max(0, dur - 0.05), 0.12);
    const end = t + dur + 0.2;
    for (const d of [-9, 9]) this.osc('sawtooth', hz(n.notes[0]), t, end, f, d);
    this.osc('square', hz(n.notes[0] - 12), t, end, f);
  }

  private arp(n: ScoreNote) {
    const { t, dur } = n;
    const f = this.filter('lowpass', 4000, 4);
    f.frequency.setValueAtTime(5000, t);
    f.frequency.exponentialRampToValueAtTime(700, t + 0.18);
    const g = this.voice(n, this.music, { reverb: 0.3, echo: 0.6 });
    f.connect(g);
    this.env(g.gain, t, 0.16 * n.vel, 0.002, 0, Math.max(0.08, dur * 1.3));
    this.osc('square', hz(n.notes[0]), t, t + dur * 1.4 + 0.05, f);
    this.osc('triangle', hz(n.notes[0] + 12), t, t + dur * 1.4 + 0.05, f);
  }

  private pad(n: ScoreNote) {
    const { t, dur } = n;
    const f = this.filter('lowpass', 1100, 0.8);
    const g = this.voice(n, this.music, { reverb: 0.8 });
    f.connect(g);
    this.env(g.gain, t, 0.05 * n.vel, 0.35, Math.max(0, dur - 0.5), 0.6);
    for (const m of n.notes) for (const d of [-12, 0, 12]) this.osc('sawtooth', hz(m), t, t + dur + 0.7, f, d);
  }

  private stab(n: ScoreNote) {
    const { t, dur } = n;
    const f = this.filter('lowpass', 1800, 3);
    f.frequency.setValueAtTime(6000, t);
    f.frequency.exponentialRampToValueAtTime(1200, t + Math.min(0.4, dur));
    const g = this.voice(n, this.music, { reverb: 0.6, echo: 0.3 });
    f.connect(g);
    this.env(g.gain, t, 0.07 * n.vel, 0.003, dur * 0.3, dur * 0.7);
    for (const m of n.notes) for (const d of [-8, 8]) this.osc('sawtooth', hz(m), t, t + dur + 0.1, f, d);
  }
}

/** 16-bit PCM WAV, scaled so the loudest sample is just under full. */
function wav(buf: AudioBuffer): Blob {
  const chans = buf.numberOfChannels;
  const len = buf.length;
  const data = Array.from({ length: chans }, (_, c) => buf.getChannelData(c));
  let peak = 0;
  for (const ch of data) for (let i = 0; i < len; i++) peak = Math.max(peak, Math.abs(ch[i]));
  const k = peak > 0 ? 0.92 / peak : 1;
  const bytes = 44 + len * chans * 2;
  const view = new DataView(new ArrayBuffer(bytes));
  const str = (o: number, s: string) => [...s].forEach((ch, i) => view.setUint8(o + i, ch.charCodeAt(0)));
  str(0, 'RIFF');
  view.setUint32(4, bytes - 8, true);
  str(8, 'WAVE');
  str(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, chans, true);
  view.setUint32(24, buf.sampleRate, true);
  view.setUint32(28, buf.sampleRate * chans * 2, true);
  view.setUint16(32, chans * 2, true);
  view.setUint16(34, 16, true);
  str(36, 'data');
  view.setUint32(40, len * chans * 2, true);
  let o = 44;
  for (let i = 0; i < len; i++) {
    for (let c = 0; c < chans; c++) {
      const v = Math.max(-1, Math.min(1, data[c][i] * k));
      view.setInt16(o, v < 0 ? v * 0x8000 : v * 0x7fff, true);
      o += 2;
    }
  }
  return new Blob([view.buffer], { type: 'audio/wav' });
}
