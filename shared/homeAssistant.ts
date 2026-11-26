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
}

/**
 * What the site does with Home Assistant. `plugs`: WLED device id -> the plug (a switch or a
 * light) that powers it, controller and all: switched on before the device, off after it.
 * `lights`: other lights, switched with the lights' power (all and each), the schedule, and
 * scenes and colors.
 */
export interface HaSettings {
  /** Its address, such as http://192.168.29.29:8123. Empty: not connected. */
  url: string;
  plugs: Record<string, string>;
  lights: string[];
}

/** For the console: the settings, whether a token is kept (never the token), and what HA has. */
export interface HaView extends HaSettings {
  hasToken: boolean;
  /** The last answer from Home Assistant: its version, or what went wrong. Null: not asked yet. */
  status: { ok: true; version: string; location: string } | { ok: false; error: string } | null;
  /** Its lights and switches. */
  entities: HaEntity[];
}

/** In the lights' switches (LightControls) a Home Assistant light is "ha:" and its entity id. */
export const HA_PREFIX = 'ha:';
export const haId = (entityId: string) => HA_PREFIX + entityId;
export const isHaId = (id: string) => id.startsWith(HA_PREFIX);
export const entityOf = (id: string) => id.slice(HA_PREFIX.length);

/** An entity id Home Assistant could have, of the kinds the site switches. */
export const isSwitchable = (id: string) => /^(light|switch)\.[a-z0-9_]+$/.test(id);
