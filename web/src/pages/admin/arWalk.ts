// The phone's camera in AR (WebXR, on Android with ARCore): every picture with where the phone
// was and which way it faced, from its own tracking (camera and motion sensors together). The
// page shows nothing of its own over the camera but the overlay (a DOM overlay: the status and
// the buttons).
//
// The pictures come from the camera-access feature: each frame's camera image, as a texture,
// read back here. They are read at full size; the worker (walkWorker.ts) makes them smaller.

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
  XRWebGLLayer: new (session: XRSessionLike, gl: GL) => { framebuffer: WebGLFramebuffer | null };
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

/** One picture, at full size: rows from the bottom up (as WebGL reads them), and the camera, for those pixels. */
export interface ArFrame {
  width: number;
  height: number;
  data: Uint8Array;
  /** The camera for the picture with its rows turned top down (see walkWorker). */
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
export async function startAr(overlay: HTMLElement, on: ArHandlers): Promise<{ end: () => void }> {
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
    const gl = (canvas.getContext('webgl2', { xrCompatible: true, alpha: true }) ?? canvas.getContext('webgl', { xrCompatible: true, alpha: true })) as GL | null;
    if (!gl) throw new Error('No WebGL');
    const layer = new g.XRWebGLLayer(session, gl);
    session.updateRenderState({ baseLayer: layer });
    const binding = new g.XRWebGLBinding(session, gl);
    const space = await session.requestReferenceSpace('local');
    const fbo = gl.createFramebuffer();
    let wasTracking: boolean | null = null;

    const onFrame = (_time: number, frame: XRFrameLike) => {
      if (over) return;
      session.requestAnimationFrame(onFrame);
      // Nothing of ours over the camera.
      gl.bindFramebuffer(gl.FRAMEBUFFER, session.renderState.baseLayer?.framebuffer ?? null);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      const pose = frame.getViewerPose(space);
      const ok = !!pose && !pose.emulatedPosition;
      if (ok !== wasTracking) on.tracking((wasTracking = ok));
      if (!pose || !ok || !on.wants()) return;
      const view = pose.views[0];
      const camera = view?.camera;
      if (!camera) return;
      const tex = binding.getCameraImage(camera);
      if (!tex) return;
      const { width, height } = camera;
      gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
      if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) {
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);
        return;
      }
      const bytes = width * height * 4;
      const data = on.buffer(bytes) ?? new Uint8Array(bytes);
      gl.readPixels(0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, data);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, null, 0);
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      on.frame({ width, height, data, cam: cameraOf(view, width, height) });
    };
    session.requestAnimationFrame(onFrame);
  } catch (e) {
    void session.end().catch(() => {});
    throw e;
  }
  return { end: () => void (over ? null : session.end().catch(() => {})) };
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
