// A pretend Home Assistant for development and tests: its REST API's config, states and the
// turn_on and turn_off services of lights and switches, behind a token.
//
//   MOCK_HA_MS=90 node scripts/mock-ha.ts [port] [token]
import http from 'node:http';
import { WebSocketServer } from 'ws';

export interface MockEntity {
  state: string;
  attributes: { friendly_name: string; supported_color_modes?: string[]; brightness?: number; rgb_color?: number[]; device_class?: string };
  /** Not in a state: where it is (the site reads it with a template). */
  place?: { area: string; device: string; integration: string };
}

export function startMockHa(port = 0, token = 'mock-home-assistant-token-0123456789') {
  const states = new Map<string, MockEntity>([
    ['switch.roof_psu', { state: 'on', attributes: { friendly_name: 'Roof PSU', device_class: 'outlet' }, place: { area: 'Garage', device: 'Roof plug', integration: 'tplink' } }],
    ['switch.tree_psu', { state: 'on', attributes: { friendly_name: 'Tree PSU', device_class: 'outlet' }, place: { area: 'Front yard', device: 'Tree plug', integration: 'tplink' } }],
    ['light.porch', { state: 'off', attributes: { friendly_name: 'Porch', supported_color_modes: ['xy', 'color_temp'] }, place: { area: 'Front yard', device: 'Porch bulb', integration: 'zha' } }],
    ['light.garage', { state: 'off', attributes: { friendly_name: 'Garage', supported_color_modes: ['brightness'] }, place: { area: 'Garage', device: 'Garage dimmer', integration: 'zwave_js' } }],
    ['switch.fan', { state: 'off', attributes: { friendly_name: 'Fan' } }],
    ['sensor.outside', { state: '3.5', attributes: { friendly_name: 'Outside' } }]
  ]);
  const calls: { service: string; body: Record<string, unknown>; via: 'rest' | 'ws' }[] = [];
  /** ZHA's devices (zha/devices): the porch bulb, its color cluster on endpoint 11 (as on Hue bulbs). */
  const zhaDevices = [
    { ieee: '00:17:88:01:0b:2a:3c:4d', name: 'Porch bulb', entities: [{ entity_id: 'light.porch', name: 'Porch' }], signature: { endpoints: { '11': { profile_id: 260, input_clusters: ['0x0000', '0x0006', '0x0008', '0x0300'], output_clusters: ['0x0019'] }, '242': { input_clusters: [], output_clusters: ['0x0021'] } } } }
  ];
  /** How long a service takes, in ms: a Zigbee light answers when it took the command. */
  const timing = { serviceMs: 0 };

  /** Does a service, as both APIs do. Null: no such entity. */
  const service = (domain: string, name: string, body: Record<string, unknown>, via: 'rest' | 'ws'): MockEntity | null => {
    calls.push({ service: `${domain}.${name}`, body, via });
    const e = states.get(String(body.entity_id));
    // Reads the entity again from the device: nothing changes here.
    if (domain === 'homeassistant' && name === 'update_entity') return e ?? null;
    if (!e || !String(body.entity_id).startsWith(`${domain}.`)) return null;
    const on = name === 'turn_on';
    const was = e.state;
    e.state = on ? 'on' : 'off';
    if (was !== e.state) emit(String(body.entity_id));
    if (on && typeof body.brightness === 'number') e.attributes.brightness = body.brightness;
    if (on && Array.isArray(body.rgb_color)) e.attributes.rgb_color = body.rgb_color;
    hooks.onSwitch?.(String(body.entity_id), on);
    return e;
  };
  /** Called after a service switched an entity: a plug powering a controller, say. */
  const hooks: { onSwitch?: (entity: string, on: boolean) => void } = {};
  /** The WebSocket subscriptions to state_changed: each connection and its message id. */
  const watchers = new Set<{ ws: { send: (s: string) => void }; id: number }>();
  /** Tells the subscribers an entity's state, as Home Assistant's state_changed event does. */
  const emit = (entityId: string) => {
    const e = states.get(entityId);
    for (const w of watchers) w.ws.send(JSON.stringify({ id: w.id, type: 'event', event: { event_type: 'state_changed', data: { entity_id: entityId, new_state: e ? { entity_id: entityId, state: e.state, attributes: e.attributes } : null } } }));
  };

  const server = http.createServer((req, res) => {
    const json = (status: number, v: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(v));
    };
    if (req.headers.authorization !== `Bearer ${token}`) return json(401, { message: '401: Unauthorized' });
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      if (req.method === 'GET' && req.url === '/api/config') return json(200, { version: '2026.11.3', location_name: 'Home' });
      if (req.method === 'GET' && req.url === '/api/states') return json(200, [...states].map(([entity_id, s]) => ({ entity_id, state: s.state, attributes: s.attributes })));
      // The site's one template (PLACES_TEMPLATE), answered as Home Assistant would render it.
      if (req.method === 'POST' && req.url === '/api/template') {
        const rows = [...states].filter(([id]) => /^(light|switch)\./.test(id)).map(([id, s]) => [id, s.place?.area ?? '', s.place?.device ?? '', s.place?.integration ?? '']);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end(JSON.stringify(rows));
      }
      const m = /^\/api\/services\/(\w+)\/(turn_on|turn_off)$/.exec(req.url ?? '');
      if (req.method === 'POST' && m) {
        const body = raw ? JSON.parse(raw) : {};
        setTimeout(() => {
          const e = service(m[1], m[2], body, 'rest');
          if (!e) return json(400, { message: 'Unknown entity' });
          json(200, [{ entity_id: body.entity_id, state: e.state, attributes: e.attributes }]);
        }, timing.serviceMs);
        return;
      }
      json(404, { message: 'Not found' });
    });
  });

  // The WebSocket API (/api/websocket): sign in with the token, then call_service.
  const wss = new WebSocketServer({ server, path: '/api/websocket' });
  wss.on('connection', (ws) => {
    let authed = false;
    ws.send(JSON.stringify({ type: 'auth_required', ha_version: '2026.11.3' }));
    ws.on('message', (raw) => {
      const m = JSON.parse(String(raw));
      if (m.type === 'auth') {
        authed = m.access_token === token;
        ws.send(JSON.stringify({ type: authed ? 'auth_ok' : 'auth_invalid' }));
        if (!authed) ws.close();
        return;
      }
      if (!authed) return;
      if (m.type === 'subscribe_events' && m.event_type === 'state_changed') {
        const w = { ws, id: m.id };
        watchers.add(w);
        ws.on('close', () => watchers.delete(w));
        return void ws.send(JSON.stringify({ id: m.id, type: 'result', success: true, result: null }));
      }
      if (m.type === 'zha/devices') return void ws.send(JSON.stringify({ id: m.id, type: 'result', success: true, result: zhaDevices }));
      // A Zigbee command straight to a ZHA light: the light takes it, Home Assistant's state is left as it was.
      if (m.type === 'call_service' && m.domain === 'zha' && m.service === 'issue_zigbee_cluster_command') {
        setTimeout(() => {
          calls.push({ service: 'zha.issue_zigbee_cluster_command', body: m.service_data, via: 'ws' });
          const known = zhaDevices.some((d) => d.ieee === m.service_data?.ieee);
          ws.send(JSON.stringify(known ? { id: m.id, type: 'result', success: true, result: null } : { id: m.id, type: 'result', success: false, error: { message: 'Unknown device' } }));
        }, timing.serviceMs);
        return;
      }
      if (m.type === 'call_service') {
        setTimeout(() => {
          const e = service(m.domain, m.service, { ...m.service_data, entity_id: m.target?.entity_id }, 'ws');
          ws.send(JSON.stringify(e ? { id: m.id, type: 'result', success: true, result: { context: {} } } : { id: m.id, type: 'result', success: false, error: { code: 'not_found', message: 'Unknown entity' } }));
        }, timing.serviceMs);
      }
    });
  });

  return new Promise<{ port: number; url: string; token: string; states: typeof states; calls: typeof calls; hooks: typeof hooks; timing: typeof timing; emit: typeof emit; watching: () => number; close: () => Promise<void> }>((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const actual = (server.address() as { port: number }).port;
      resolve({
        port: actual,
        url: `http://127.0.0.1:${actual}`,
        token,
        states,
        calls,
        hooks,
        emit,
        watching: () => watchers.size,
        timing,
        close: () => new Promise((r) => (wss.clients.forEach((c) => c.terminate()), wss.close(), server.close(() => r()), server.closeAllConnections()))
      });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const ha = await startMockHa(Number(process.argv[2] ?? 8123), process.argv[3]);
  // MOCK_HA_MS: how long each command takes, as a Zigbee light's answer does (about 60 to 150 ms).
  ha.timing.serviceMs = Number(process.env.MOCK_HA_MS ?? 0);
  console.log(`Mock Home Assistant on ${ha.url}, token ${ha.token}`);
}
