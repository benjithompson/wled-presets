import { describe, expect, it } from 'vitest';
import { buildRows, filterRows, groupRows, NO_FILTER, sortRows, type RowSources } from '../../web/src/pages/admin/deviceRows.ts';
import type { DeviceWithStatus } from '../../shared/types.ts';
import type { HaEntity, HaView } from '../../shared/homeAssistant.ts';

const device = (id: string, over: Partial<DeviceWithStatus> = {}): DeviceWithStatus => ({
  id,
  name: id,
  host: `10.0.0.${id.length}`,
  port: 80,
  enabled: true,
  online: true,
  info: { ver: '0.15.0', leds: { count: 100, fps: 42 } },
  lastSeen: null,
  power: { on: true, bri: 255 },
  ...over
});
const entity = (id: string, over: Partial<HaEntity> = {}): HaEntity => ({ id, name: id, state: 'on', color: true, dimmable: true, outlet: false, area: '', device: '', integration: 'zha', ...over });
const view = (entities: HaEntity[], lights: string[], disabled: string[] = []): HaView => ({
  url: 'http://ha',
  hasToken: true,
  plugs: {},
  lights,
  disabled,
  status: null,
  entities,
  fps: 10,
  inflight: 1,
  fade: true,
  direct: false
});
const sources = (over: Partial<RowSources>): RowSources => ({ devices: [], ha: undefined, off: new Set(), fixtures: [], ...over });

describe('device rows', () => {
  it('says how each WLED device stands', () => {
    const rows = buildRows(
      sources({
        devices: [
          device('lit'),
          device('dark', { power: { on: false, bri: 100 } }),
          device('gone', { online: false, power: null }),
          device('plugoff', { online: false, power: null, plug: { entity: 'switch.p', name: 'Roof plug', on: false } }),
          device('booting', { online: false, power: null, plug: { entity: 'switch.q', name: 'Tree plug', on: true } }),
          device('off', { enabled: false, online: null })
        ]
      })
    );
    expect(rows.map((r) => [r.key, r.status, r.statusText])).toEqual([
      ['lit', 'on', 'On'],
      ['dark', 'off', 'Off'],
      ['gone', 'offline', 'Offline'],
      ['plugoff', 'off', 'Plug off'],
      ['booting', 'offline', 'Starting up'],
      ['off', 'disabled', 'Disabled']
    ]);
    // Frame rate only from a device that answers now.
    expect(rows.map((r) => r.fps)).toEqual([42, 42, null, null, null, null]);
  });

  it('adds the Home Assistant lights, held off here winning over what Home Assistant says', () => {
    const ha = view([entity('light.porch', { area: 'Porch' }), entity('light.held'), entity('light.out', { state: 'unavailable' }), entity('light.idle')], ['light.porch', 'light.held', 'light.out', 'light.gone', 'light.idle'], ['light.idle']);
    const rows = buildRows(sources({ ha, off: new Set(['ha:light.held']), fixtures: [{ name: 'Lamp', deviceId: 'ha:light.porch' }] }));
    expect(rows.map((r) => [r.key, r.status, r.statusText])).toEqual([
      ['ha:light.porch', 'on', 'On'],
      ['ha:light.held', 'off', 'Off'],
      ['ha:light.out', 'offline', 'Unavailable'],
      ['ha:light.gone', 'offline', 'Missing'],
      ['ha:light.idle', 'disabled', 'Disabled']
    ]);
    expect(rows[0]).toMatchObject({ area: 'Porch', integration: 'zha', objects: ['Lamp'] });
  });

  it('leaves Home Assistant out while it is not connected', () => {
    const ha = { ...view([entity('light.porch')], ['light.porch']), hasToken: false };
    expect(buildRows(sources({ ha }))).toEqual([]);
  });

  it('filters, sorts and groups', () => {
    const ha = view([entity('light.porch', { area: 'Porch' })], ['light.porch']);
    const rows = buildRows(
      sources({
        devices: [device('roof', { info: { leds: { count: 300, fps: 20 } } }), device('tree', { info: { leds: { count: 50, fps: 60 } } }), device('bush', { enabled: false })],
        ha,
        fixtures: [{ name: 'Roof', deviceId: 'roof' }]
      })
    );
    expect(filterRows(rows, { ...NO_FILTER, query: 'porch' }).map((r) => r.key)).toEqual(['ha:light.porch']);
    expect(filterRows(rows, { ...NO_FILTER, source: 'wled', status: 'on' }).map((r) => r.key)).toEqual(['roof', 'tree']);
    expect(filterRows(rows, { ...NO_FILTER, layout: 'in' }).map((r) => r.key)).toEqual(['roof']);
    expect(filterRows(rows, { ...NO_FILTER, area: '-' }).map((r) => r.key)).toEqual(['roof', 'tree', 'bush']);
    // Rows with no frame rate go last, whichever way.
    expect(sortRows(rows, { key: 'fps', dir: 'desc' }).map((r) => r.key)).toEqual(['tree', 'roof', 'bush', 'ha:light.porch']);
    expect(sortRows(rows, { key: 'fps', dir: 'asc' }).map((r) => r.key)).toEqual(['roof', 'tree', 'bush', 'ha:light.porch']);
    expect(groupRows(sortRows(rows, { key: 'name', dir: 'asc' }), 'status').map(([g, list]) => [g, list.map((r) => r.key)])).toEqual([
      ['On', ['ha:light.porch', 'roof', 'tree']],
      ['Disabled', ['bush']]
    ]);
    expect(groupRows(rows, 'area').map(([g]) => g)).toEqual(['Porch', 'No area']);
    expect(groupRows(rows, 'source').map(([g]) => g)).toEqual(['WLED', 'Home Assistant']);
  });
});
