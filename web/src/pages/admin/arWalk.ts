// The phone's camera in AR (WebXR, on Android with ARCore): every picture with where the phone
// was and which way it faced, from its own tracking (camera and motion sensors together). The
// page shows nothing of its own over the camera but the overlay (a DOM overlay: the status and
// the buttons).
//
// The pictures come from the camera-access feature: each frame's camera image, as a texture.
// Reading a whole camera picture back from the GPU is slow on a phone, and the page waits for
// it, so the camera view stutters. Instead the GPU makes it smaller first (each pixel the mean
// of a square of them, rows turned top down) and, with WebGL 2, the small picture is read back
// without waiting: it is picked up a frame or two later, once the GPU has it ready.

import type { PosedCam } from '../../../../shared/scan3d.ts';

// The parts of WebXR this uses (camera access is not in the usual types yet).
interface XRCameraLike {
  width: number;
  height: number;
}
interface XRViewLike {
  camera?: XRCameraLike | null;
  projectionMatrix: Float32Array;
  transform: { inverse: { matrix: Float32Array } };
}
interface XRPoseLike {
  views: readonly XRViewLike[];
  emulatedPosition: boolean;
}
interface XRFrameLike {
  getViewerPose(space: unknown): XRPoseLike | null | undefined;
}
interface XRSessionLike {
  requestReferenceSpace(type: string): Promise<unknown>;
  updateRenderState(state: { baseLayer: unknown }): void;
  requestAnimationFrame(cb: (time: number, frame: XRFrameLike) => void): number;
  end(): Promise<void>;
  addEventListener(type: 'end', cb: () => void): void;
  renderState: { baseLayer?: { framebuffer: WebGLFramebuffer | null } };
}
interface XRSystemLike {
  isSessionSupported(mode: string): Promise<boolean>;
  requestSession(mode: string, init: Record<string, unknown>): Promise<XRSessionLike>;
}
type GL = WebGLRenderingContext | WebGL2RenderingContext;
interface XRGlobals {
  XRWebGLLayer: new (session: XRSessionLike, gl: GL, init?: Record<string, unknown>) => { framebuffer: WebGLFramebuffer | null };
  XRWebGLBinding?: new (session: XRSessionLike, gl: GL) => { getCameraImage(camera: XRCameraLike): WebGLTexture | null };
}

const xr = () => (typeof navigator !== 'undefined' ? (navigator as unknown as { xr?: XRSystemLike }).xr : undefined);

/** True when this browser can walk round in AR with the camera's pictures (Chrome on Android, with ARCore). */
export async function arAvailable(): Promise<boolean> {
  const sys = xr();
  const g = globalThis as unknown as Partial<XRGlobals>;
  if (!sys || !g.XRWebGLBinding || !window.isSecureContext) return false;
  try {
    return await sys.isSessionSupported('immersive-ar');
  } catch {
    return false;
  }
}

/** One picture, made smaller, rows top down; and the camera, for those pixels. */
export interface ArFrame {
  width: number;
  height: number;
  data: Uint8Array;
  cam: PosedCam;
}

export interface ArHandlers {
  /** True when a picture is wanted now (the worker is ready for one). */
  wants: () => boolean;
  /** A buffer to read the picture into (its size: width × height × 4), or null for a new one. */
  buffer: (bytes: number) => Uint8Array | null;
  frame: (f: ArFrame) => void;
  /** Whether the phone knows where it is (false: it lost its place, too dark or too fast). */
  tracking: (ok: boolean) => void;
  ended: () => void;
}

/**
 * Starts AR, with `overlay` shown over the camera. Must be called straight from a tap (the
 * browser asks for the camera then). Throws when the browser says no.
 */
export async function startAr(overlay: HTMLElement, on: ArHandlers, maxSide = 960): Promise<{ end: () => void }> {
  const sys = xr();
  const g = globalThis as unknown as XRGlobals;
  if (!sys || !g.XRWebGLBinding) throw new Error('No AR');
  const session = await sys.requestSession('immersive-ar', { requiredFeatures: ['camera-access', 'dom-overlay'], domOverlay: { root: overlay } });
  let over = false;
  session.addEventListener('end', () => {
    over = true;
    on.ended();
  });
  try {
    const canvas = document.createElement('canvas');
    const opts = { xrCompatible: true, alpha: true, antialias: false, depth: false, stencil: false, preserveDrawingBuffer: false };
    const gl = (canvas.getContext('webgl2', opts) ?? canvas.getContext('webgl', opts)) as GL | null;
    if (!gl) throw new Error('No WebGL');
    // The page draws nothing over the camera: the smallest layer the browser allows, plain.
    const layer = new g.XRWebGLLayer(session, gl, { antialias: false, depth: false, stencil: false, alpha: true, framebufferScaleFactor: 0.2 });
    session.updateRenderState({ baseLayer: layer });
    const binding = new g.XRWebGLBinding(session, gl);
    const space = await session.requestReferenceSpace('local');
    const shrink = shrinker(gl);
    let wasTracking: boolean | null = null;
    /** A small picture on its way back from the GPU, and what goes with it. */
    let pending: { sync: WebGLSync; width: number; height: number; cam: PosedCam } | null = null;

    const deliver = (width: number, height: number, cam: PosedCam, read: (into: Uint8Array) => void) => {
      const bytes = width * height * 4;
      const data = on.buffer(bytes) ?? new Uint8Array(bytes);
      read(data);
      on.frame({ width, height, data, cam });
    };

    const onFrame = (_time: number, frame: XRFrameLike) => {
      if (over) return;
      session.requestAnimationFrame(onFrame);
      // Nothing of ours over the camera.
      gl.bindFramebuffer(gl.FRAMEBUFFER, session.renderState.baseLayer?.framebuffer ?? null);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      // The last picture, once the GPU has it ready (it never waits for it).
      if (pending && shrink.gl2) {
        const gl2 = gl as WebGL2RenderingContext;
        if (gl2.getSyncParameter(pending.sync, gl2.SYNC_STATUS) === gl2.SIGNALED) {
          const p = pending;
          pending = null;
          gl2.deleteSync(p.sync);
          deliver(p.width, p.height, p.cam, (into) => shrink.take(into));
        }
      }
      const pose = frame.getViewerPose(space);
      const ok = !!pose && !pose.emulatedPosition;
      if (ok !== wasTracking) on.tracking((wasTracking = ok));
      if (pending || !pose || !ok || !on.wants()) return;
      const view = pose.views[0];
      const camera = view?.camera;
      if (!camera) return;
      const tex = binding.getCameraImage(camera);
      if (!tex) return;
      const s = Math.min(MAX_STEP, Math.max(1, Math.ceil(Math.max(camera.width, camera.height) / maxSide)));
      const width = Math.floor(camera.width / s);
      const height = Math.floor(camera.height / s);
      const cam = scaled(cameraOf(view, camera.width, camera.height), s);
      shrink.draw(tex, camera.width, camera.height, s, width, height);
      if (shrink.gl2) {
        const gl2 = gl as WebGL2RenderingContext;
        shrink.start(width, height);
        const sync = gl2.fenceSync(gl2.SYNC_GPU_COMMANDS_COMPLETE, 0);
        gl2.flush();
        if (sync) pending = { sync, width, height, cam };
      } else {
        deliver(width, height, cam, (into) => gl.readPixels(0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, into));
      }
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    };
    session.requestAnimationFrame(onFrame);
  } catch (e) {
    void session.end().catch(() => {});
    throw e;
  }
  return { end: () => void (over ? null : session.end().catch(() => {})) };
}

/** The most pixels of the camera's picture that one pixel of the small picture is the mean of, across. */
const MAX_STEP = 8;

/** The camera for the picture made `s` times smaller (pixel centers at whole numbers). */
export function scaled(c: PosedCam, s: number): PosedCam {
  return { R: c.R, t: c.t, f: c.f / s, fy: (c.fy ?? c.f) / s, cu: (c.cu + 0.5) / s - 0.5, cv: (c.cv + 0.5) / s - 0.5 };
}

/**
 * Makes the camera's picture smaller on the GPU: each pixel the mean of an s × s square, the
 * rows turned top down (the camera texture has them from the bottom up), into a small
 * framebuffer, left bound. With WebGL 2, start() reads it into a pixel buffer without waiting,
 * and take() copies it out once the GPU is done.
 */
function shrinker(gl: GL) {
  const gl2 = typeof WebGL2RenderingContext !== 'undefined' && gl instanceof WebGL2RenderingContext;
  const vs = gl2 ? '#version 300 es\nin vec2 p;\nvoid main() { gl_Position = vec4(p, 0.0, 1.0); }' : 'attribute vec2 p;\nvoid main() { gl_Position = vec4(p, 0.0, 1.0); }';
  const fs = gl2
    ? `#version 300 es
precision highp float;
precision highp int;
uniform sampler2D img;
uniform int s;
uniform int h;
out vec4 o;
void main() {
  ivec2 q = ivec2(gl_FragCoord.xy);
  vec3 c = vec3(0.0);
  for (int dy = 0; dy < ${MAX_STEP}; dy++) {
    if (dy >= s) break;
    for (int dx = 0; dx < ${MAX_STEP}; dx++) {
      if (dx >= s) break;
      c += texelFetch(img, ivec2(q.x * s + dx, h - 1 - (q.y * s + dy)), 0).rgb;
    }
  }
  o = vec4(c / float(s * s), 1.0);
}`
    : `precision highp float;
uniform sampler2D img;
uniform float s;
uniform vec2 size;
void main() {
  vec2 q = floor(gl_FragCoord.xy);
  vec3 c = vec3(0.0);
  for (int dy = 0; dy < ${MAX_STEP}; dy++) {
    if (float(dy) >= s) break;
    for (int dx = 0; dx < ${MAX_STEP}; dx++) {
      if (float(dx) >= s) break;
      // At a texel's center: its own color, however the texture is filtered.
      vec2 t = vec2(q.x * s + float(dx), size.y - 1.0 - (q.y * s + float(dy))) + 0.5;
      c += texture2D(img, t / size).rgb;
    }
  }
  gl_FragColor = vec4(c / (s * s), 1.0);
}`;
  const compile = (type: number, src: string) => {
    const sh = gl.createShader(type)!;
    gl.shaderSource(sh, src);
    gl.compileShader(sh);
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh) ?? 'Shader');
    return sh;
  };
  const prog = gl.createProgram()!;
  gl.attachShader(prog, compile(gl.VERTEX_SHADER, vs));
  gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, fs));
  gl.bindAttribLocation(prog, 0, 'p');
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog) ?? 'Program');
  const u = (name: string) => gl.getUniformLocation(prog, name);
  const at = { img: u('img'), s: u('s'), h: u('h'), size: u('size') };
  // One triangle over the whole framebuffer.
  const quad = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, quad);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const fbo = gl.createFramebuffer();
  const target = gl.createTexture();
  const pbo = gl2 ? (gl as WebGL2RenderingContext).createBuffer() : null;
  let w = 0;
  let h = 0;
  let pboBytes = 0;
  return {
    gl2,
    draw(tex: WebGLTexture, srcW: number, srcH: number, s: number, width: number, height: number) {
      if (width !== w || height !== h) {
        w = width;
        h = height;
        gl.bindTexture(gl.TEXTURE_2D, target);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, w, h, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, target, 0);
      }
      gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
      gl.viewport(0, 0, w, h);
      gl.disable(gl.BLEND);
      gl.useProgram(prog);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.uniform1i(at.img, 0);
      if (gl2) {
        gl.uniform1i(at.s, s);
        gl.uniform1i(at.h, srcH);
      } else {
        gl.uniform1f(at.s, s);
        gl.uniform2f(at.size, srcW, srcH);
      }
      gl.bindBuffer(gl.ARRAY_BUFFER, quad);
      gl.enableVertexAttribArray(0);
      gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.bindTexture(gl.TEXTURE_2D, null);
    },
    /** WebGL 2: reads the small picture into the pixel buffer; the GPU does it in its own time. */
    start(width: number, height: number) {
      const g2 = gl as WebGL2RenderingContext;
      g2.bindBuffer(g2.PIXEL_PACK_BUFFER, pbo);
      const bytes = width * height * 4;
      if (bytes !== pboBytes) {
        g2.bufferData(g2.PIXEL_PACK_BUFFER, bytes, g2.STREAM_READ);
        pboBytes = bytes;
      }
      g2.readPixels(0, 0, width, height, g2.RGBA, g2.UNSIGNED_BYTE, 0);
      g2.bindBuffer(g2.PIXEL_PACK_BUFFER, null);
    },
    /** WebGL 2: the picture start() read, once the GPU is done with it. */
    take(into: Uint8Array) {
      const g2 = gl as WebGL2RenderingContext;
      g2.bindBuffer(g2.PIXEL_PACK_BUFFER, pbo);
      g2.getBufferSubData(g2.PIXEL_PACK_BUFFER, 0, into, 0, into.length);
      g2.bindBuffer(g2.PIXEL_PACK_BUFFER, null);
    }
  };
}

/**
 * The camera of a view, for its picture (width × height) with the rows top down: the view's
 * place and turn (world to camera), and its lens from its projection (the camera image lines up
 * with the view). Pixel centers at whole numbers.
 */
export function cameraOf(view: XRViewLike, width: number, height: number): PosedCam {
  const m = view.transform.inverse.matrix;
  const p = view.projectionMatrix;
  // Column by column: row i of the rotation is m[i], m[4 + i], m[8 + i].
  const R = [m[0], m[4], m[8], m[1], m[5], m[9], m[2], m[6], m[10]];
  return {
    R,
    t: [m[12], m[13], m[14]],
    f: (p[0] * width) / 2,
    fy: (p[5] * height) / 2,
    cu: ((1 - p[8]) * width) / 2 - 0.5,
    cv: ((1 + p[9]) * height) / 2 - 0.5
  };
}
