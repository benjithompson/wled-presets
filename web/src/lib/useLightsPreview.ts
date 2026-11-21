import { useEffect, useRef } from 'react';
import { PREVIEW_KEEPALIVE_MS, type PreviewRequest } from '../../../shared/editorView.ts';
import { api } from './api.ts';

/** Stops an editor's preview on the lights when `active` goes false, and when the page closes. */
export function useStopOnLeave(active: boolean, stop: () => Promise<unknown>) {
  const stopRef = useRef(stop);
  stopRef.current = stop;
  useEffect(() => {
    if (!active) return;
    const leave = () => void stopRef.current().catch(() => {});
    window.addEventListener('pagehide', leave);
    return () => {
      window.removeEventListener('pagehide', leave);
      leave();
    };
  }, [active]);
}

/**
 * Shows an editor's picture on the real lights while `req` is set: sends it after `delayMs`,
 * again at once whenever it changes, and every few seconds so the server keeps showing it (see
 * PREVIEW_EXPIRE_MS). Stops it when `active` (default: `req` is set) goes false, or the page
 * closes. `onDevices`: the names of the devices it lights, after each send.
 */
export function useLightsPreview(
  req: PreviewRequest | null,
  opts: { active?: boolean; delayMs?: number; onDevices?: (names: string[]) => void; onError?: (e: unknown) => void } = {}
) {
  const body = req ? JSON.stringify(req) : null;
  const latest = useRef({ req, opts });
  latest.current = { req, opts };
  useEffect(() => {
    if (!body) return;
    let alive = true;
    const send = () => {
      const { req, opts } = latest.current;
      if (!req) return;
      api
        .previewLayout(req)
        .then((r) => alive && opts.onDevices?.(r.devices))
        .catch((e: unknown) => alive && opts.onError?.(e));
    };
    const t = setTimeout(send, latest.current.opts.delayMs ?? 40);
    const keep = setInterval(send, PREVIEW_KEEPALIVE_MS);
    return () => {
      alive = false;
      clearTimeout(t);
      clearInterval(keep);
    };
  }, [body]);
  useStopOnLeave(opts.active ?? body != null, api.stopLayoutPreview);
}
