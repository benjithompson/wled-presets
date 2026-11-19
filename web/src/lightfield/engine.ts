import * as S from './shaders.ts';
import { borderPoint } from '../lib/border.ts';

type Rgb = [number, number, number];

export interface Look {
  /** Hex colors. Empty uses the default palette. */
  colors: string[];
  /** 0 = still, 1 = fast. */
  energy: number;
}

interface Target {
  tex: WebGLTexture;
  fb: WebGLFramebuffer;
  w: number;
  h: number;
}
interface PingPong {
  read: Target;
  write: Target;
  swap(): void;
}

class Program {
  prog: WebGLProgram;
  u: Record<string, WebGLUniformLocation> = {};
  private gl: WebGL2RenderingContext;

  constructor(gl: WebGL2RenderingContext, vs: string, fs: string) {
    this.gl = gl;
    const compile = (type: number, src: string) => {
      const sh = gl.createShader(type)!;
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh) ?? 'shader');
      return sh;
    };
    const p = gl.createProgram()!;
    gl.attachShader(p, compile(gl.VERTEX_SHADER, vs));
    gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fs));
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) ?? 'link');
    this.prog = p;
    const n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS) as number;
    for (let i = 0; i < n; i++) {
      const name = gl.getActiveUniform(p, i)!.name;
      this.u[name] = gl.getUniformLocation(p, name)!;
    }
  }
  use() {
    this.gl.useProgram(this.prog);
    return this;
  }
  /** Binds textures to units in order and sets the other uniforms. */
  set(values: Record<string, number | number[] | WebGLTexture>) {
    const gl = this.gl;
    let unit = 0;
    for (const [k, v] of Object.entries(values)) {
      const loc = this.u[k];
      if (loc === undefined) continue;
      if (v instanceof WebGLTexture) {
        gl.activeTexture(gl.TEXTURE0 + unit);
        gl.bindTexture(gl.TEXTURE_2D, v);
        gl.uniform1i(loc, unit++);
      } else if (typeof v === 'number') gl.uniform1f(loc, v);
      else if (v.length === 2) gl.uniform2f(loc, v[0], v[1]);
      else if (v.length === 3) gl.uniform3f(loc, v[0], v[1], v[2]);
    }
    return this;
  }
}

const hexToRgb = (h: string): Rgb => {
  const n = parseInt(h.replace('#', ''), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
};

/**
 * Default for how fast simulation time runs, as a fraction of real time. Lower is calmer.
 * Motion slows; the amount of light and how fast it fades stay tied to real time,
 * so brightness looks the same at any speed.
 */
export const DEFAULT_SPEED = 0.125;
export const MIN_SPEED = 0.025;
export const MAX_SPEED = 1;

/** In light mode, color fades back to paper this many times faster than it fades in dark mode. */
const LIGHT_FADE = 2.4;

/** Colors of the page when nothing is playing: warm candlelight with dusk accents. */
export const DEFAULT_LOOK: Look = { colors: ['#ff9f43', '#7c3aed', '#f43f5e', '#0ea5e9'], energy: 0.3 };

/** A light that drifts through the fluid. Spring physics toward a wandering target. */
interface Emitter {
  x: number;
  y: number;
  vx: number;
  vy: number;
  phase: number;
  color: Rgb;
  target: Rgb;
}

export interface EngineOptions {
  dark: boolean;
  reducedQuality?: boolean;
}

export class LightFieldEngine {
  private gl: WebGL2RenderingContext;
  private canvas: HTMLCanvasElement;
  private progs!: Record<string, Program>;
  private velocity!: PingPong;
  private dye!: PingPong;
  private pressure!: PingPong;
  private divergence!: Target;
  private curl!: Target;
  private particles: PingPong | null = null;
  private particleWidth = 0;
  private vao: WebGLVertexArrayObject;
  private canFloat32: boolean;
  private raf = 0;
  private last = 0;
  private time = 0;
  private emitters: Emitter[] = [];
  private look: Look = DEFAULT_LOOK;
  private preview: Look | null = null;
  private energy = DEFAULT_LOOK.energy;
  private dark: boolean;
  private speed = DEFAULT_SPEED;
  private quality: number;
  private slowFrames = 0;
  private pointer = { x: 0, y: 0, px: 0, py: 0, down: false, moved: false, active: false, type: 'mouse' };
  private queue: { x: number; y: number; dx: number; dy: number; color: Rgb; radius: number }[] = [];
  /** The roofline around the window's border (see setRoof): its light spills in from the edges. */
  private roof: { cells: number; zones: { t: number; color: Rgb; lum: number; seen: number; flash: number }[] } | null = null;
  private roofTurn = 0;
  private cleanup: (() => void)[] = [];

  /** Returns null when WebGL 2 with renderable float textures is not available. */
  static create(canvas: HTMLCanvasElement, opts: EngineOptions): LightFieldEngine | null {
    const gl = canvas.getContext('webgl2', { alpha: false, antialias: false, depth: false, stencil: false, powerPreference: 'high-performance', preserveDrawingBuffer: false });
    if (!gl) return null;
    const f32 = !!gl.getExtension('EXT_color_buffer_float');
    const f16 = f32 || !!gl.getExtension('EXT_color_buffer_half_float');
    if (!f16) return null;
    try {
      return new LightFieldEngine(canvas, gl, f32, opts);
    } catch (e) {
      console.warn('Light field disabled:', e);
      return null;
    }
  }

  private constructor(canvas: HTMLCanvasElement, gl: WebGL2RenderingContext, f32: boolean, opts: EngineOptions) {
    this.canvas = canvas;
    this.gl = gl;
    this.canFloat32 = f32;
    this.dark = opts.dark;
    this.quality = opts.reducedQuality ? 0 : 1;
    this.vao = gl.createVertexArray()!;
    gl.bindVertexArray(this.vao);
    gl.disable(gl.DEPTH_TEST);

    const P = (fs: string, vs = S.fullscreenVS) => new Program(gl, vs, fs);
    this.progs = {
      splat: P(S.splatFS),
      advect: P(S.advectFS),
      divergence: P(S.divergenceFS),
      curl: P(S.curlFS),
      vorticity: P(S.vorticityFS),
      pressure: P(S.pressureFS),
      gradient: P(S.gradientSubtractFS),
      scale: P(S.scaleFS),
      display: P(S.displayFS),
      particleUpdate: P(S.particleUpdateFS),
      particleDraw: P(S.particleFS, S.particleVS)
    };
    this.resize();
    this.setLook(DEFAULT_LOOK, true);
    this.bindInput();
    // Seed the canvas with a few blooms so the first frame is not empty.
    for (let i = 0; i < 6; i++) this.randomSplat(1.2);
  }

  // ---------- Resources ----------

  private makeTarget(w: number, h: number, internal: number, format: number, type: number, filter: number): Target {
    const gl = this.gl;
    const tex = gl.createTexture()!;
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, filter);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, filter);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texImage2D(gl.TEXTURE_2D, 0, internal, w, h, 0, format, type, null);
    const fb = gl.createFramebuffer()!;
    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
    if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) throw new Error('Framebuffer not complete');
    gl.viewport(0, 0, w, h);
    gl.clearColor(0, 0, 0, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    return { tex, fb, w, h };
  }

  private pingPong(w: number, h: number, internal: number, format: number, type: number, filter: number): PingPong {
    const pp = {
      read: this.makeTarget(w, h, internal, format, type, filter),
      write: this.makeTarget(w, h, internal, format, type, filter),
      swap() {
        [pp.read, pp.write] = [pp.write, pp.read];
      }
    };
    return pp;
  }

  private gridSize(base: number) {
    const aspect = this.canvas.width / this.canvas.height;
    return aspect >= 1 ? { w: Math.round(base * aspect), h: base } : { w: base, h: Math.round(base / aspect) };
  }

  resize() {
    const gl = this.gl;
    const dpr = Math.min(window.devicePixelRatio || 1, this.quality ? 2 : 1);
    const w = Math.max(1, Math.round(this.canvas.clientWidth * dpr));
    const h = Math.max(1, Math.round(this.canvas.clientHeight * dpr));
    if (this.velocity && w === this.canvas.width && h === this.canvas.height) return;
    this.canvas.width = w;
    this.canvas.height = h;
    this.release();

    const H = gl.HALF_FLOAT;
    const sim = this.gridSize(this.quality ? 128 : 96);
    const dye = this.gridSize(this.quality ? 720 : 360);
    this.velocity = this.pingPong(sim.w, sim.h, gl.RG16F, gl.RG, H, gl.LINEAR);
    this.pressure = this.pingPong(sim.w, sim.h, gl.R16F, gl.RED, H, gl.NEAREST);
    this.divergence = this.makeTarget(sim.w, sim.h, gl.R16F, gl.RED, H, gl.NEAREST);
    this.curl = this.makeTarget(sim.w, sim.h, gl.R16F, gl.RED, H, gl.NEAREST);
    this.dye = this.pingPong(dye.w, dye.h, gl.RGBA16F, gl.RGBA, H, gl.LINEAR);

    if (this.canFloat32) {
      // Spark state needs full float precision; half floats make slow sparks stutter.
      this.particleWidth = this.quality ? 96 : 48;
      const n = this.particleWidth * this.particleWidth;
      const data = new Float32Array(n * 4);
      for (let i = 0; i < n; i++) data.set([Math.random(), Math.random(), Math.random(), Math.random()], i * 4);
      this.particles = this.pingPong(this.particleWidth, this.particleWidth, gl.RGBA32F, gl.RGBA, gl.FLOAT, gl.NEAREST);
      gl.bindTexture(gl.TEXTURE_2D, this.particles.read.tex);
      gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, this.particleWidth, this.particleWidth, gl.RGBA, gl.FLOAT, data);
    }
  }

  private release() {
    const gl = this.gl;
    const free = (t?: Target) => {
      if (!t) return;
      gl.deleteTexture(t.tex);
      gl.deleteFramebuffer(t.fb);
    };
    for (const pp of [this.velocity, this.pressure, this.dye, this.particles]) {
      if (pp) {
        free(pp.read);
        free(pp.write);
      }
    }
    free(this.divergence);
    free(this.curl);
  }

  // ---------- Public API ----------

  setTheme(dark: boolean) {
    this.dark = dark;
  }

  /** Fraction of real time the simulation runs at. */
  setSpeed(speed: number) {
    this.speed = Math.min(MAX_SPEED, Math.max(MIN_SPEED, speed || DEFAULT_SPEED));
  }

  /** Changes the palette. Emitters fade to the new colors over about a second. */
  setLook(look: Look, instant = false) {
    this.look = look.colors.length ? look : { ...DEFAULT_LOOK, energy: look.energy };
    this.retarget(instant);
  }

  /** Shows another palette while the pointer rests on a scene. Null ends the preview. */
  setPreview(look: Look | null) {
    this.preview = look && look.colors.length ? look : null;
    this.retarget(false);
  }

  /**
   * The roofline's colors now: one RGB triple per cell, in strip order, wrapped around the
   * window's border (see border.ts). Null: no roofline. The border is gathered into zones; each
   * one spills its light in from the edge, and a sudden change (a flash, a chase arriving) pushes
   * harder, so the field answers what the lights do.
   */
  setRoof(rgb: Uint8Array | null) {
    const cells = rgb ? Math.floor(rgb.length / 3) : 0;
    if (!rgb || !cells) {
      this.roof = null;
      return;
    }
    const ZONES = 20;
    if (!this.roof || this.roof.cells !== cells) {
      this.roof = { cells, zones: Array.from({ length: ZONES }, (_, z) => ({ t: (z + 0.5) / ZONES, color: [0, 0, 0] as Rgb, lum: 0, seen: 0, flash: 0 })) };
    }
    const sums = Array.from({ length: ZONES }, () => ({ r: 0, g: 0, b: 0, n: 0, peak: 0 }));
    for (let i = 0; i < cells; i++) {
      const s = sums[Math.min(ZONES - 1, Math.floor(((i + 0.5) / cells) * ZONES))];
      const r = rgb[i * 3] / 255;
      const g = rgb[i * 3 + 1] / 255;
      const b = rgb[i * 3 + 2] / 255;
      s.r += r;
      s.g += g;
      s.b += b;
      s.n++;
      s.peak = Math.max(s.peak, r, g, b);
    }
    this.roof.zones.forEach((z, k) => {
      const s = sums[k];
      if (!s.n) {
        z.color = [0, 0, 0];
        z.lum = 0;
        return;
      }
      // The zone's hue at its brightest: a few lit bulbs among dark ones still show their color.
      const m = Math.max(s.r, s.g, s.b) || 1;
      z.color = [(s.r / m) * s.peak, (s.g / m) * s.peak, (s.b / m) * s.peak];
      const lum = (s.r + s.g + s.b) / (3 * s.n);
      z.flash = Math.max(z.flash, lum - z.seen);
      z.seen += (lum - z.seen) * 0.35;
      z.lum = lum;
    });
  }

  /** A radial burst of the given colors at a screen point, for example a tapped button. */
  burst(clientX: number, clientY: number, colors?: string[], strength = 1) {
    const { x, y } = this.toUv(clientX, clientY);
    const palette = (colors?.length ? colors : this.activeLook().colors).map(hexToRgb);
    const n = 10;
    for (let i = 0; i < n; i++) {
      const a = (i / n) * Math.PI * 2 + Math.random() * 0.4;
      const f = (900 + Math.random() * 700) * strength;
      const c = palette[i % palette.length];
      this.queue.push({ x, y, dx: Math.cos(a) * f, dy: Math.sin(a) * f, color: c.map((v) => v * 0.9 * strength) as Rgb, radius: 0.0012 });
    }
    // Pull nearby emitters toward the burst, so the lights answer the tap.
    for (const e of this.emitters) {
      const dx = x - e.x;
      const dy = y - e.y;
      const d = Math.hypot(dx, dy) + 0.05;
      e.vx += (dx / d) * 0.25 * strength;
      e.vy += (dy / d) * 0.25 * strength;
    }
  }

  start() {
    const frame = (now: number) => {
      this.raf = requestAnimationFrame(frame);
      const dt = Math.min((now - (this.last || now)) / 1000, 1 / 30);
      this.last = now;
      if (dt <= 0) return;
      this.watchPerformance(dt);
      this.step(dt * this.speed, dt);
      this.render();
    };
    this.raf = requestAnimationFrame(frame);
  }

  dispose() {
    cancelAnimationFrame(this.raf);
    for (const c of this.cleanup) c();
    // Free GPU memory but keep the context: the same canvas can get a new engine
    // (React mounts effects twice in development), and a lost context cannot be reused.
    this.release();
    for (const p of Object.values(this.progs)) this.gl.deleteProgram(p.prog);
    this.gl.deleteVertexArray(this.vao);
  }

  // ---------- Simulation ----------

  private activeLook() {
    return this.preview ?? this.look;
  }

  private retarget(instant: boolean) {
    const look = this.activeLook();
    const colors = look.colors.map(hexToRgb);
    const count = Math.max(4, Math.min(7, colors.length + 2));
    while (this.emitters.length < count) {
      const i = this.emitters.length;
      this.emitters.push({ x: 0.2 + Math.random() * 0.6, y: 0.2 + Math.random() * 0.6, vx: 0, vy: 0, phase: i * 2.39996 + Math.random(), color: [0, 0, 0], target: [0, 0, 0] });
    }
    this.emitters.length = count;
    this.emitters.forEach((e, i) => {
      e.target = colors[i % colors.length];
      if (instant) e.color = [...e.target];
    });
  }

  private watchPerformance(dt: number) {
    // Drop to the lighter quality level after about two seconds of slow frames.
    if (this.quality === 0) return;
    this.slowFrames = dt > 1 / 40 ? this.slowFrames + 1 : Math.max(0, this.slowFrames - 1);
    if (this.slowFrames > 120) {
      this.quality = 0;
      this.canvas.width = 0;
      this.resize();
    }
  }

  private toUv(clientX: number, clientY: number) {
    const r = this.canvas.getBoundingClientRect();
    return { x: (clientX - r.left) / r.width, y: 1 - (clientY - r.top) / r.height };
  }

  private randomSplat(strength: number) {
    const colors = this.activeLook().colors.map(hexToRgb);
    const c = colors[Math.floor(Math.random() * colors.length)];
    const a = Math.random() * Math.PI * 2;
    this.queue.push({
      x: 0.15 + Math.random() * 0.7,
      y: 0.15 + Math.random() * 0.7,
      dx: Math.cos(a) * 600 * strength,
      dy: Math.sin(a) * 600 * strength,
      color: c.map((v) => v * 0.32 * strength) as Rgb,
      radius: 0.0018
    });
  }

  /** dt: simulation seconds (moves things). realDt: wall-clock seconds (adds and fades light). */
  private step(dt: number, realDt: number) {
    this.time += dt;
    const look = this.activeLook();
    this.energy += (look.energy - this.energy) * Math.min(1, realDt * 1.5);
    const e = this.energy;
    const aspect = this.canvas.width / this.canvas.height;

    // Emitters: damped springs toward slowly wandering Lissajous targets.
    const pace = 0.05 + 0.22 * e;
    for (const em of this.emitters) {
      const t = this.time * pace + em.phase;
      const tx = 0.5 + 0.38 * Math.sin(t * 1.3 + Math.sin(t * 0.37) * 1.7);
      const ty = 0.5 + 0.36 * Math.sin(t * 0.9 + em.phase * 0.5 + Math.cos(t * 0.53));
      const k = 1.4 + 2.5 * e;
      const damping = 1.6;
      em.vx += ((tx - em.x) * k - em.vx * damping) * dt;
      em.vy += ((ty - em.y) * k - em.vy * damping) * dt;
      // Lights are curious: a resting or moving pointer draws them in a little.
      if (this.pointer.active) {
        const dx = this.pointer.x - em.x;
        const dy = this.pointer.y - em.y;
        const d2 = dx * dx * aspect * aspect + dy * dy + 0.02;
        const pull = (this.pointer.down ? 0.9 : 0.25) / d2;
        em.vx += dx * Math.min(pull, 12) * dt * 0.2;
        em.vy += dy * Math.min(pull, 12) * dt * 0.2;
      }
      em.x += em.vx * dt;
      em.y += em.vy * dt;
      for (let i = 0; i < 3; i++) em.color[i] += (em.target[i] - em.color[i]) * Math.min(1, realDt * 1.2);

      const speed = Math.hypot(em.vx, em.vy);
      const force = 2600 + 3200 * e;
      // Light added per second, so the look does not depend on the frame rate.
      const glow = (0.9 + 1.2 * e) * (0.55 + Math.min(speed * 5, 1.5)) * realDt;
      this.splat(em.x, em.y, em.vx * force * dt * 60, em.vy * force * dt * 60, em.color.map((v) => v * glow) as Rgb, 0.0009 + 0.0006 * e);
    }

    // Pointer: stir the fluid along the path of the mouse or finger.
    const p = this.pointer;
    if (p.moved) {
      p.moved = false;
      const dx = p.x - p.px;
      const dy = p.y - p.py;
      p.px = p.x;
      p.py = p.y;
      const strength = p.down || p.type !== 'mouse' ? 1 : 0.45;
      const colors = look.colors.map(hexToRgb);
      const c = colors[Math.floor(this.time * 0.8) % colors.length];
      const amount = Math.min(Math.hypot(dx * aspect, dy) * 18, 1) * 0.22 * strength;
      this.splat(p.x, p.y, dx * 5200 * strength, dy * 5200 * strength, c.map((v) => v * amount) as Rgb, 0.0007);
    }

    // The roofline: half the zones each frame, light pouring in from the border.
    if (this.roof) {
      const zones = this.roof.zones;
      this.roofTurn ^= 1;
      for (let k = this.roofTurn; k < zones.length; k += 2) {
        const z = zones[k];
        if (z.lum <= 0.01 && z.flash <= 0.01) continue;
        const kick = Math.min(1, z.flash * 3);
        z.flash *= 0.5;
        const amount = (0.3 + 0.9 * Math.sqrt(z.lum) + 1.6 * kick) * realDt * 2;
        const push = (700 + 2600 * kick + 600 * z.lum) * dt * 60;
        // Window fractions (y down) to the field's (y up); a little in from the edge.
        const b = borderPoint(z.t + (Math.random() - 0.5) * 0.02, this.canvas.width, this.canvas.height);
        const x = b.x + b.nx * 0.008;
        const y = 1 - (b.y + b.ny * 0.008);
        const along = (Math.random() - 0.5) * 300;
        this.splat(x, y, b.nx * push + b.ny * along, -b.ny * push + b.nx * along, z.color.map((v) => v * amount) as Rgb, 0.0008 + 0.0009 * kick);
      }
    }

    // Occasional slow blooms keep the field alive when nobody touches it.
    if (Math.random() < realDt * (0.12 + 0.35 * e)) this.randomSplat(0.35 + 0.4 * e);

    for (const s of this.queue.splice(0)) this.splat(s.x, s.y, s.dx, s.dy, s.color, s.radius);

    this.solve(dt, e, realDt);
  }

  private blit(target: Target | null) {
    const gl = this.gl;
    if (target) {
      gl.bindFramebuffer(gl.FRAMEBUFFER, target.fb);
      gl.viewport(0, 0, target.w, target.h);
    } else {
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    }
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  private splat(x: number, y: number, dx: number, dy: number, color: Rgb, radius: number) {
    const aspect = this.canvas.width / this.canvas.height;
    const r = aspect > 1 ? radius * aspect : radius;
    const sp = this.progs.splat.use();
    sp.set({ uTarget: this.velocity.read.tex, uAspect: aspect, uPoint: [x, y], uColor: [dx, dy, 0], uRadius: r });
    this.blit(this.velocity.write);
    this.velocity.swap();
    sp.set({ uTarget: this.dye.read.tex, uColor: color });
    this.blit(this.dye.write);
    this.dye.swap();
  }

  private solve(dt: number, energy: number, realDt: number) {
    const v = this.velocity;
    const texel = [1 / v.read.w, 1 / v.read.h];

    this.progs.curl.use().set({ uVelocity: v.read.tex, uTexel: texel });
    this.blit(this.curl);
    this.progs.vorticity.use().set({ uVelocity: v.read.tex, uCurl: this.curl.tex, uTexel: texel, uStrength: 18 + 22 * energy, uDt: dt });
    this.blit(v.write);
    v.swap();

    this.progs.divergence.use().set({ uVelocity: v.read.tex, uTexel: texel });
    this.blit(this.divergence);

    this.progs.scale.use().set({ uTexture: this.pressure.read.tex, uValue: 0.8 });
    this.blit(this.pressure.write);
    this.pressure.swap();
    const pressure = this.progs.pressure.use();
    for (let i = 0; i < (this.quality ? 22 : 12); i++) {
      pressure.set({ uPressure: this.pressure.read.tex, uDivergence: this.divergence.tex, uTexel: texel });
      this.blit(this.pressure.write);
      this.pressure.swap();
    }

    this.progs.gradient.use().set({ uPressure: this.pressure.read.tex, uVelocity: v.read.tex, uTexel: texel });
    this.blit(v.write);
    v.swap();

    const advect = this.progs.advect.use();
    advect.set({ uVelocity: v.read.tex, uSource: v.read.tex, uVelTexel: texel, uDt: dt, uDissipation: 0.25 });
    this.blit(v.write);
    v.swap();
    advect.set({ uVelocity: v.read.tex, uSource: this.dye.read.tex, uVelTexel: texel, uDt: dt, uDissipation: ((0.85 + 0.55 * energy) * (this.dark ? 1 : LIGHT_FADE) * realDt) / dt });
    this.blit(this.dye.write);
    this.dye.swap();

    if (this.particles) {
      this.progs.particleUpdate.use().set({ uState: this.particles.read.tex, uVelocity: v.read.tex, uVelTexel: texel, uDt: dt, uTime: this.time % 1000 });
      this.blit(this.particles.write);
      this.particles.swap();
    }
  }

  private render() {
    const gl = this.gl;
    const bg = this.dark ? [0.047, 0.039, 0.035] : [0.98, 0.98, 0.976];
    this.progs.display.use().set({
      uDye: this.dye.read.tex,
      uDyeTexel: [1 / this.dye.read.w, 1 / this.dye.read.h],
      uBackground: bg,
      uDark: this.dark ? 1 : 0,
      uTime: this.time,
      uAspect: this.canvas.width / this.canvas.height
    });
    this.blit(null);

    if (this.particles) {
      gl.enable(gl.BLEND);
      if (this.dark) gl.blendFunc(gl.ONE, gl.ONE);
      else gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
      const dpr = this.canvas.width / Math.max(1, this.canvas.clientWidth);
      const prog = this.progs.particleDraw.use();
      prog.set({ uState: this.particles.read.tex, uDye: this.dye.read.tex, uPointSize: 3.2 * dpr, uDark: this.dark ? 1 : 0 });
      gl.uniform1i(prog.u.uWidth, this.particleWidth);
      gl.drawArrays(gl.POINTS, 0, this.particleWidth * this.particleWidth);
      gl.disable(gl.BLEND);
    }
  }

  // ---------- Input ----------

  private bindInput() {
    const p = this.pointer;
    const move = (e: PointerEvent) => {
      const { x, y } = this.toUv(e.clientX, e.clientY);
      if (!p.active) {
        p.px = x;
        p.py = y;
      }
      p.x = x;
      p.y = y;
      p.moved = true;
      p.active = true;
      p.type = e.pointerType;
    };
    const down = (e: PointerEvent) => {
      move(e);
      p.down = true;
      p.px = p.x;
      p.py = p.y;
      // A tap on the open background makes a small burst. Buttons make their own.
      const el = e.target instanceof Element ? e.target : null;
      if (!el?.closest('button, a, input, select, [role="slider"], [data-no-burst]')) this.burst(e.clientX, e.clientY, undefined, 0.55);
    };
    const up = (e: PointerEvent) => {
      p.down = false;
      if (e.pointerType !== 'mouse') p.active = false;
    };
    const leave = () => {
      p.active = false;
      p.down = false;
    };
    const resize = () => this.resize();
    window.addEventListener('pointermove', move, { passive: true });
    window.addEventListener('pointerdown', down, { passive: true });
    window.addEventListener('pointerup', up, { passive: true });
    window.addEventListener('pointercancel', up, { passive: true });
    document.documentElement.addEventListener('pointerleave', leave);
    const ro = new ResizeObserver(resize);
    ro.observe(this.canvas);
    this.cleanup.push(() => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerdown', down);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
      document.documentElement.removeEventListener('pointerleave', leave);
      ro.disconnect();
    });
  }
}
