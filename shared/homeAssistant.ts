// Home Assistant: smart plugs that power the WLED controllers, and other lights it switches.

/** A light or switch in Home Assistant, as the console shows it. */
export interface HaEntity {
  /** Its entity id, such as light.porch or switch.roof_psu. */
  id: string;
  name: string;
  /** on, off, unavailable or unknown. */
  state: string;
  /** It takes a color (rgb_color). */
  color: boolean;
  /** It takes a brightness. */
  dimmable: boolean;
  /** A switch that says it is a plug (device class outlet). */
  outlet: boolean;
  /** A ZHA light: a color can go straight to it as a Zigbee command (see HomeAssistant.set). */
  zigbee?: boolean;
  /** Its area in Home Assistant, its device, and the integration it comes from ('' when none). */
  area: string;
  device: string;
  integration: string;
}

/**
 * What the site does with Home Assistant. `plugs`: WLED device id -> the plug (a switch or a
 * light) that powers it, controller and all: switched on before the device, off after it.
 * `lights`: other lights, switched with the lights' power (all and each), the schedule, and
 * scenes and colors, unless they are in `disabled`.
 */
export interface HaSettings {
  /** Its address, such as http://192.168.29.29:8123. Empty: not connected. */
  url: string;
  plugs: Record<string, string>;
  lights: string[];
  /** Lights added but disabled: kept, with their place in the layout, but the site leaves them alone. */
  disabled: string[];
}

/** For the console: the settings, whether a token is kept (never the token), and what HA has. */
export interface HaView extends HaSettings {
  hasToken: boolean;
  /** The last answer from Home Assistant: its version, or what went wrong. Null: not asked yet. */
  status: { ok: true; version: string; location: string } | { ok: false; error: string } | null;
  /** Its lights and switches. */
  entities: HaEntity[];
  /** How many colors a second a light in the layout may take (see HaFrames). */
  fps: number;
  /** Commands on their way to one light at once. */
  inflight: number;
  /** Each color fades in over the gap to the next (else it changes at once). */
  fade: boolean;
  /** Colors go to ZHA lights as Zigbee commands (else light.turn_on). */
  direct: boolean;
}

/** How one light takes the site's commands (see HomeAssistant.set), since the server started or the debug view was switched on. */
export interface HaCommandStats {
  /** Commands Home Assistant answered (or that waited LATE_MS for an answer and gave up). */
  answered: number;
  /** Of those, the ones answered after the site stopped waiting (its timeout, 5 s). */
  late: number;
  /** Of those, the ones that failed (Home Assistant refused it, or never answered). */
  failed: number;
  /** How long the last answer took, and the running mean, in ms. */
  lastMs: number;
  avgMs: number;
  /** The longest an answer took, in ms. */
  maxMs: number;
  /** On their way now, and waiting behind them (at most one: the newest). */
  going: number;
  waiting: number;
  /** How long the oldest command on its way has gone without an answer, in ms (0: none on its way). */
  goingMs: number;
}

/** A light that has had no command yet. */
export const NO_COMMANDS: HaCommandStats = { answered: 0, late: 0, failed: 0, lastMs: 0, avgMs: 0, maxMs: 0, going: 0, waiting: 0, goingMs: 0 };

/** What a speed test of one light found (see HomeAssistant speed test). */
export interface HaSpeedResult {
  entity: string;
  via: 'ws' | 'rest';
  inflight: number;
  fade: boolean;
  /** Sent as Zigbee commands (a ZHA light), else light.turn_on. */
  direct: boolean;
  /** Colors a second asked for, and how many it took. */
  fps: number;
  achieved: number;
  seconds: number;
  sent: number;
  /** Ticks with a command still on its way: the light was not ready for the next. */
  waited: number;
  errors: number;
  error?: string;
  /** How long Home Assistant took to do each command, in ms. */
  latency: { avg: number; p50: number; p95: number; max: number };
}

/** In the lights' switches (LightControls) a Home Assistant light is "ha:" and its entity id. */
export const HA_PREFIX = 'ha:';
export const haId = (entityId: string) => HA_PREFIX + entityId;
export const isHaId = (id: string) => id.startsWith(HA_PREFIX);
export const entityOf = (id: string) => id.slice(HA_PREFIX.length);

/** An entity id Home Assistant could have, of the kinds the site switches. */
export const isSwitchable = (id: string) => /^(light|switch)\.[a-z0-9_]+$/.test(id);
