import WebSocket from 'ws';

/** How long to wait before connecting again after Home Assistant closed the connection. */
const RETRY_MS = 5000;

type Answer = { ok: true; result: unknown } | { ok: false; error: string };
type Pending = { resolve: (r: Answer) => void; timer: NodeJS.Timeout };
/** A subscription (subscribe_events, say): made again on each new connection. */
type Sub = { msg: Record<string, unknown>; onEvent: (event: unknown) => void };

/**
 * One WebSocket to Home Assistant (its /api/websocket), for switching lights fast: a command is
 * a small message on a connection that stays open, where a REST call is an HTTP request each
 * time. Home Assistant answers each one when it has done it, which for a Zigbee light is when
 * the light said it took it: that answer's time is how fast the light can go.
 */
export class HaSocket {
  private ws: WebSocket | null = null;
  private ready: Promise<boolean> | null = null;
  private next = 1;
  private pending = new Map<number, Pending>();
  private retryAt = 0;
  private closed = false;
  private subs: Sub[] = [];
  /** The live subscriptions on this connection, by message id. */
  private subIds = new Map<number, Sub>();
  private reconnect: NodeJS.Timeout | null = null;
  private pinger: NodeJS.Timeout | null = null;
  /** How often the connection is pinged: no pong by the next ping, and it is dropped (and made again). */
  pingMs = 30_000;
  private url: string;
  private token: string;
  timeoutMs = 5000;

  constructor(url: string, token: string) {
    this.url = url.replace(/^http/, 'ws') + '/api/websocket';
    this.token = token;
  }

  get open() {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /** Connects and signs in, once; true when it can take commands. */
  private connect(): Promise<boolean> {
    if (this.ready) return this.ready;
    if (this.closed || Date.now() < this.retryAt) return Promise.resolve(false);
    this.ready = new Promise<boolean>((resolve) => {
      const ws = new WebSocket(this.url, { handshakeTimeout: this.timeoutMs });
      this.ws = ws;
      let done = false;
      const finish = (ok: boolean) => {
        if (done) return;
        done = true;
        resolve(ok);
        if (!ok) this.drop(ws);
      };
      const timer = setTimeout(() => finish(false), this.timeoutMs);
      ws.on('message', (raw) => {
        let m: { type?: string; id?: number; success?: boolean; result?: unknown; error?: { message?: string } };
        try {
          m = JSON.parse(String(raw));
        } catch {
          return;
        }
        if (m.type === 'auth_required') ws.send(JSON.stringify({ type: 'auth', access_token: this.token }));
        else if (m.type === 'auth_ok') {
          clearTimeout(timer);
          finish(true);
          let alive = true;
          ws.on('pong', () => (alive = true));
          if (this.pinger) clearInterval(this.pinger);
          this.pinger = setInterval(() => {
            if (!alive) return void this.drop(ws);
            alive = false;
            ws.ping();
          }, this.pingMs);
          this.pinger.unref?.();
          for (const sub of this.subs) this.sendSub(ws, sub);
        } else if (m.type === 'event' && typeof m.id === 'number') {
          this.subIds.get(m.id)?.onEvent((m as { event?: unknown }).event);
        } else if (m.type === 'auth_invalid') {
          clearTimeout(timer);
          finish(false);
        } else if (m.type === 'result' && typeof m.id === 'number') {
          const p = this.pending.get(m.id);
          if (!p) return;
          this.pending.delete(m.id);
          clearTimeout(p.timer);
          p.resolve(m.success ? { ok: true, result: m.result } : { ok: false, error: m.error?.message || 'Home Assistant refused it' });
        }
      });
      ws.on('error', () => finish(false));
      ws.on('close', () => {
        clearTimeout(timer);
        finish(false);
        this.drop(ws);
      });
    });
    return this.ready;
  }

  /** The connection is gone: what waits on it fails, and the next command connects again (after a pause). */
  private drop(ws: WebSocket) {
    if (this.ws !== ws) return;
    if (this.pinger) clearInterval(this.pinger);
    this.pinger = null;
    this.ws = null;
    this.ready = null;
    this.retryAt = Date.now() + RETRY_MS;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.resolve({ ok: false, error: 'The connection to Home Assistant closed' });
    }
    this.pending.clear();
    this.subIds.clear();
    ws.terminate();
    // Subscribed: connect again by itself, so no event is missed for long.
    if (this.subs.length && !this.closed && !this.reconnect) {
      this.reconnect = setTimeout(() => {
        this.reconnect = null;
        void this.connect();
      }, RETRY_MS + 100);
      this.reconnect.unref?.();
    }
  }

  private sendSub(ws: WebSocket, sub: Sub) {
    const id = this.next++;
    this.subIds.set(id, sub);
    ws.send(JSON.stringify({ ...sub.msg, id }));
  }

  /**
   * Subscribes (a message such as { type: 'subscribe_events', event_type: 'state_changed' }):
   * each event goes to onEvent, now and on every connection after this one. Connects at once,
   * and keeps the connection up.
   */
  subscribe(msg: Record<string, unknown>, onEvent: (event: unknown) => void) {
    const sub = { msg, onEvent };
    this.subs.push(sub);
    if (this.open && this.ws) this.sendSub(this.ws, sub);
    else void this.connect();
  }

  /**
   * Sends one command (a message with a type) and resolves with Home Assistant's answer; null
   * when there is no connection.
   */
  async send(msg: Record<string, unknown>): Promise<Answer | null> {
    if (!(await this.connect()) || !this.ws) return null;
    const ws = this.ws;
    const id = this.next++;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ ok: false, error: 'Home Assistant did not answer in time' });
      }, this.timeoutMs);
      this.pending.set(id, { resolve, timer });
      ws.send(JSON.stringify({ ...msg, id }));
    });
  }

  /**
   * Calls a service (light.turn_on, say), on one entity or none. Resolves when Home Assistant has
   * done it; null when there is no connection (use REST instead).
   */
  call(domain: string, service: string, entityId: string | null, data: Record<string, unknown>): Promise<Answer | null> {
    return this.send({ type: 'call_service', domain, service, service_data: data, ...(entityId ? { target: { entity_id: entityId } } : {}) });
  }

  close() {
    this.closed = true;
    if (this.reconnect) clearTimeout(this.reconnect);
    this.reconnect = null;
    if (this.ws) this.drop(this.ws);
  }
}
