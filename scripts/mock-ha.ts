// A pretend Home Assistant for development and tests: its REST API's config, states and the
// turn_on and turn_off services of lights and switches, behind a token.
//
//   node scripts/mock-ha.ts [port] [token]
import http from 'node:http';

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
    ['light.porch', { state: 'off', attributes: { friendly_name: 'Porch', supported_color_modes: ['hs', 'color_temp'] }, place: { area: 'Front yard', device: 'Porch bulb', integration: 'hue' } }],
    ['light.garage', { state: 'off', attributes: { friendly_name: 'Garage', supported_color_modes: ['brightness'] }, place: { area: 'Garage', device: 'Garage dimmer', integration: 'zwave_js' } }],
    ['switch.fan', { state: 'off', attributes: { friendly_name: 'Fan' } }],
    ['sensor.outside', { state: '3.5', attributes: { friendly_name: 'Outside' } }]
  ]);
  const calls: { service: string; body: Record<string, unknown> }[] = [];
  /** Called after a service switched an entity: a plug powering a controller, say. */
  const hooks: { onSwitch?: (entity: string, on: boolean) => void } = {};

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
        calls.push({ service: `${m[1]}.${m[2]}`, body });
        const e = states.get(body.entity_id);
        if (!e || !body.entity_id.startsWith(`${m[1]}.`)) return json(400, { message: 'Unknown entity' });
        const on = m[2] === 'turn_on';
        e.state = on ? 'on' : 'off';
        if (on && typeof body.brightness === 'number') e.attributes.brightness = body.brightness;
        if (on && Array.isArray(body.rgb_color)) e.attributes.rgb_color = body.rgb_color;
        hooks.onSwitch?.(body.entity_id, on);
        return json(200, [{ entity_id: body.entity_id, state: e.state, attributes: e.attributes }]);
      }
      json(404, { message: 'Not found' });
    });
  });

  return new Promise<{ port: number; url: string; token: string; states: typeof states; calls: typeof calls; hooks: typeof hooks; close: () => Promise<void> }>((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const actual = (server.address() as { port: number }).port;
      resolve({ port: actual, url: `http://127.0.0.1:${actual}`, token, states, calls, hooks, close: () => new Promise((r) => (server.close(() => r()), server.closeAllConnections())) });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const ha = await startMockHa(Number(process.argv[2] ?? 8123), process.argv[3]);
  console.log(`Mock Home Assistant on ${ha.url}, token ${ha.token}`);
}
