// Fake WLED devices for local development and tests.
// Usage: node scripts/mock-wled.ts [count=3] [basePort=9101]
import dgram from 'node:dgram';
import http from 'node:http';

const NAMES = ['Roofline', 'Porch', 'Tree', 'Garage', 'Fence', 'Window'];
// Shaped like real WLED presets.json entries, so colors and effects can be read from them.
const PRESETS: { n: string; seg: Record<string, unknown>[] }[] = [
  { n: 'Warm White', seg: [{ col: [[255, 160, 70], [0, 0, 0], [0, 0, 0]], fx: 0 }] },
  { n: 'Candy Cane', seg: [{ col: [[255, 0, 0], [255, 255, 255], [0, 0, 0]], fx: 15, sx: 120, ix: 128, pal: 3 }] },
  { n: 'Rainbow', seg: [{ col: [[255, 0, 0], [0, 0, 0], [0, 0, 0]], fx: 9, sx: 160, ix: 200, pal: 0 }] },
  { n: 'Twinkle', seg: [{ col: [[255, 200, 90], [40, 40, 160], [0, 0, 0]], fx: 74, sx: 70, ix: 160, pal: 3 }] },
  { n: 'Fire', seg: [{ col: [[255, 80, 0], [0, 0, 0], [0, 0, 0]], fx: 66, sx: 200, ix: 220, pal: 35 }] },
  { n: 'Snowfall', seg: [{ col: [[200, 230, 255], [30, 60, 200], [0, 0, 0]], fx: 47, sx: 60, ix: 90, pal: 3 }] },
  { n: 'Ocean', seg: [{ col: [[0, 120, 255], [0, 0, 0], [0, 0, 0]], fx: 101, sx: 90, ix: 128, pal: 9 }] }
];

/** `dropUdp`: ignore real-time UDP, like a device behind a router that drops UDP. */
export function startMockWled(port: number, name: string, ledCount = 150, { dropUdp = false } = {}) {
  const presets: Record<string, unknown> = { '0': {} };
  PRESETS.forEach((p, i) => (presets[String(i + 1)] = { on: true, bri: 160, ...p }));
  const state = { on: true, bri: 128, ps: -1, seg: [{ id: 0, col: [[255, 160, 80]], fx: 0 }] };
  const requests: { method: string; url: string; body: unknown }[] = [];
  // Real-time UDP (DNRGB), on the same number as the HTTP port so several mocks can run.
  const realtime = { packets: 0, httpFrames: 0, ddpPackets: 0, ddpFrames: 0, leds: new Uint8Array(ledCount * 3), at: 0 };
  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg) => {
    if (dropUdp || msg[0] !== 4 || msg.length < 4) return;
    const start = (msg[2] << 8) | msg[3];
    for (let i = 0; (i + 1) * 3 <= msg.length - 4 && start + i < ledCount; i++) realtime.leds.set(msg.subarray(4 + i * 3, 7 + i * 3), (start + i) * 3);
    realtime.packets++;
    realtime.at = Date.now();
  });
  udp.on('error', () => {});
  // DDP, as the app sends it. Real WLED listens on port 4048; each fake device uses its own
  // port and reports it as "ddpport" in /json/info. Data shows only on a packet with "push".
  const ddp = dgram.createSocket('udp4');
  const pending = new Uint8Array(ledCount * 3);
  ddp.on('message', (msg) => {
    if (dropUdp || msg.length < 10 || (msg[0] & 0xc0) !== 0x40) return;
    const offset = msg.readUInt32BE(4);
    const len = Math.min(msg.readUInt16BE(8), msg.length - 10);
    pending.set(msg.subarray(10, 10 + Math.max(0, Math.min(len, pending.length - offset))), offset);
    realtime.ddpPackets++;
    if (msg[0] & 0x01) {
      realtime.leds.set(pending);
      realtime.ddpFrames++;
      realtime.at = Date.now();
    }
  });
  ddp.on('error', () => {});
  let ddpPort = 0;
  let actualPort = port;

  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const body = raw ? JSON.parse(raw) : null;
      requests.push({ method: req.method!, url: req.url!, body });
      const json = (data: unknown) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      };
      if (req.url === '/json/info') return json({ ver: '0.15.0', name, mac: `aabbcc${port}`, arch: 'esp32', leds: { count: ledCount }, wifi: { signal: 80 }, udpport: actualPort, ddpport: ddpPort, live: realtime.at > 0 && Date.now() - realtime.at < 2500 });
      if (req.url === '/json/cfg') return json({ hw: { led: { ins: [{ start: 0, len: ledCount, type: 22, pin: [2] }] } } });
      if (req.url === '/presets.json') return json(presets);
      if (req.url === '/json/state' && req.method === 'POST') {
        // Individual LEDs ("i": hex colors from LED 0), as the HTTP fallback sends them.
        const hex = body?.seg && !Array.isArray(body.seg) ? body.seg.i : undefined;
        if (Array.isArray(hex)) {
          hex.forEach((h: string, i: number) => i < ledCount && realtime.leds.set([parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)], i * 3));
          realtime.httpFrames++;
          return json({ success: true });
        }
        Object.assign(state, body);
        return json({ success: true });
      }
      if (req.url === '/json/state') return json(state);
      // Not in real WLED: what the real-time packets lit, for checks during development.
      if (req.url?.startsWith('/mock/led/')) {
        const i = Number(req.url.slice(10));
        return json(Array.from(realtime.leds.subarray(i * 3, i * 3 + 3)));
      }
      if (req.url === '/mock/realtime') {
        const lit: number[] = [];
        for (let i = 0; i < ledCount; i++) if (realtime.leds[i * 3] + realtime.leds[i * 3 + 1] + realtime.leds[i * 3 + 2] > 0) lit.push(i);
        const color = (i: number) => Array.from(realtime.leds.subarray(i * 3, i * 3 + 3));
        return json({ packets: realtime.packets, ddpPackets: realtime.ddpPackets, ddpFrames: realtime.ddpFrames, httpFrames: realtime.httpFrames, ageMs: realtime.at ? Date.now() - realtime.at : null, lit: lit.length, firstLit: lit[0] ?? null, lastLit: lit.at(-1) ?? null, colors: Object.fromEntries(lit.filter((i, k) => k === 0 || k === lit.length - 1 || i % 50 === 0).map((i) => [i, color(i)])) });
      }
      res.writeHead(404).end();
    });
  });
  return new Promise<{ port: number; ddpPort: () => number; state: typeof state; requests: typeof requests; realtime: typeof realtime; close: () => Promise<void> }>((resolve) => {
    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use. Another copy of the mock is probably running. Stop it, or pass another base port: node scripts/mock-wled.ts 4 9201`);
        process.exit(1);
      }
      throw err;
    });
    server.listen(port, '127.0.0.1', () => {
      const actual = (server.address() as { port: number }).port;
      actualPort = actual;
      udp.bind(actual, '127.0.0.1');
      ddp.bind(0, '127.0.0.1', () => (ddpPort = ddp.address().port));
      resolve({ port: actual, ddpPort: () => ddpPort, state, requests, realtime, close: () => new Promise((r) => (udp.close(), ddp.close(), server.close(() => r()))) });
    });
  });
}

if (import.meta.main) {
  const count = Number(process.argv[2]) || 3;
  const base = Number(process.argv[3]) || 9101;
  for (let i = 0; i < count; i++) {
    // The first mock stands in for the roofline, with room for a hidden side and gaps.
    const m = await startMockWled(base + i, NAMES[i % NAMES.length], i === 0 ? 600 : 150);
    console.log(`Mock WLED "${NAMES[i % NAMES.length]}" on 127.0.0.1:${m.port}`);
  }
}
