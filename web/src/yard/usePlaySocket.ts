import { useCallback, useEffect, useRef, useState } from 'react';
import type { GameInfo, GameStatus, Layout } from '../../../shared/layout.ts';

export type PlayMessage = { type: 'start'; game: string } | { type: 'stop' } | { type: 'input'; action: 'press' | 'release'; button?: string } | { type: 'setting'; id: string; value: string } | { type: 'initials'; id: number; initials: string };

/** Whether this browser can unpack compressed frames (all current ones can). */
const DEFLATE = typeof DecompressionStream !== 'undefined';

/** Unpacks one compressed frame (raw deflate). */
async function inflate(data: ArrayBuffer): Promise<Uint8Array> {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Connects to the game host. Keeps the latest frame in a ref (it changes up to 30 times a
 * second, too often for React state) and the layout, games and status in state. Frames come
 * compressed where the browser can unpack them.
 */
export function usePlaySocket() {
  const [layout, setLayout] = useState<Layout | null>(null);
  const [games, setGames] = useState<GameInfo[]>([]);
  const [status, setStatus] = useState<GameStatus | null>(null);
  const [connected, setConnected] = useState(false);
  const frame = useRef<Uint8Array | null>(null);
  const socket = useRef<WebSocket | null>(null);

  useEffect(() => {
    let closed = false;
    let retry: ReturnType<typeof setTimeout> | null = null;
    const open = () => {
      const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/play${DEFLATE ? '?frames=deflate' : ''}`);
      ws.binaryType = 'arraybuffer';
      socket.current = ws;
      ws.onopen = () => setConnected(true);
      // Compressed frames are unpacked one after another, so a later frame never shows first.
      let unpacking = Promise.resolve();
      ws.onmessage = (e) => {
        if (e.data instanceof ArrayBuffer) {
          const data = e.data;
          if (!DEFLATE) frame.current = new Uint8Array(data);
          else unpacking = unpacking.then(() => inflate(data).then((f) => void (frame.current = f), () => {}));
          return;
        }
        const m = JSON.parse(e.data);
        if (m.type === 'layout') setLayout(m.layout);
        else if (m.type === 'games') setGames(m.games);
        else if (m.type === 'status') setStatus(m.status);
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(open, 1500);
      };
    };
    // Say goodbye before closing, so the server ends this player's hold on the lights at once,
    // even when the close itself gets lost on the way (for example through a proxy).
    const leave = () => {
      const ws = socket.current;
      if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'leave' }));
      ws?.close();
    };
    window.addEventListener('pagehide', leave);
    open();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      window.removeEventListener('pagehide', leave);
      leave();
    };
  }, []);

  const send = useCallback((m: PlayMessage) => {
    if (socket.current?.readyState === WebSocket.OPEN) socket.current.send(JSON.stringify(m));
  }, []);

  return { layout, games, status, connected, frame, send };
}
