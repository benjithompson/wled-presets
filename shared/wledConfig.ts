/**
 * A WLED device's own settings (its /json/cfg), as the device settings in the console edit
 * them: the LED outputs, the brightness limiter, what it does at power-up, how it takes
 * real-time frames, its name. The editor changes a copy, and only what changed goes back to
 * the device (`configPatch`): WLED takes a partial config on POST /json/cfg and leaves the rest.
 */

// WLED's config is loose JSON with many versions behind it.
export type WledConfig = Record<string, any>;

/** One LED output (a "bus") in WLED's settings: hw.led.ins[]. */
export interface WledOutput {
  start: number;
  len: number;
  /** GPIO pins; a network output keeps its IP address here, one number a part. */
  pin: number[];
  /** Color order in the low 4 bits (0 GRB, 1 RGB, 2 BRG, 3 RBG, 4 BGR, 5 GBR), white swap above. */
  order: number;
  rev: boolean;
  skip: number;
  type: number;
  /** mA per LED at full white; 255 means a WS2815 (12 mA). */
  ledma?: number;
  /** The most current this output may draw, in mA (0: no limit of its own). */
  maxpwr?: number;
  /** Auto white for a strip with a white channel (0 none, 1 brighter, 2 accurate, 3 dual, 4 max). */
  rgbwm?: number;
  [key: string]: unknown;
}

/** An LED type a device can drive, as its LED settings page lists them. */
export interface LedType {
  id: number;
  name: string;
  /** What it is wired with: data pin(s), PWM channels, or the network. */
  kind: 'digital' | 'spi' | 'pwm' | 'onoff' | 'network';
  /** GPIO pins it takes (network: 4, the parts of an IP address). */
  pins: number;
  /** It has a white channel. */
  white: boolean;
}

/** GPIO pins the device cannot drive LEDs on. */
export interface Gpio {
  /** Taken by the flash, PSRAM or a usermod. */
  reserved: number[];
  /** Input only. */
  readOnly: number[];
  /** The highest GPIO number. */
  max: number | null;
}

/** What the console's device settings load. */
export interface WledSettings {
  config: WledConfig;
  ledTypes: LedType[];
  gpio: Gpio | null;
  /** From /json/info: firmware, Wi-Fi signal, LEDs. Null when the device did not say. */
  info: WledStatus | null;
}

export interface WledStatus {
  ver?: string;
  arch?: string;
  ip?: string;
  mac?: string;
  uptime?: number;
  freeheap?: number;
  wifi?: { signal?: number; rssi?: number; channel?: number; bssid?: string };
  leds?: { count?: number; fps?: number; pwr?: number };
  live?: boolean;
  lm?: string;
  lip?: string;
}

export function pickStatus(d: any): WledStatus {
  const num = (v: unknown) => (typeof v === 'number' ? v : undefined);
  const str = (v: unknown) => (typeof v === 'string' ? v : undefined);
  return {
    ver: str(d?.ver),
    arch: str(d?.arch),
    ip: str(d?.ip),
    mac: str(d?.mac),
    uptime: num(d?.uptime),
    freeheap: num(d?.freeheap),
    wifi: d?.wifi ? { signal: num(d.wifi.signal), rssi: num(d.wifi.rssi), channel: num(d.wifi.channel), bssid: str(d.wifi.bssid) } : undefined,
    leds: d?.leds ? { count: num(d.leds.count), fps: num(d.leds.fps), pwr: num(d.leds.pwr) } : undefined,
    live: typeof d?.live === 'boolean' ? d.live : undefined,
    lm: str(d?.lm),
    lip: str(d?.lip)
  };
}

/**
 * Settings this app does not change: Wi-Fi, the device's own access point and its update lock.
 * A mistake there loses the device, and from the console (open to the internet) there would be
 * no way back to it. WLED's own page, on the LAN, still changes them.
 */
export const PROTECTED_SECTIONS: Record<string, string> = { nw: 'Wi-Fi', ap: 'the access point', ota: 'security and updates' };

/** The protected section a patch would change, by name, or null. */
export function protectedSection(patch: WledConfig): string | null {
  for (const key of Object.keys(patch)) if (key in PROTECTED_SECTIONS) return PROTECTED_SECTIONS[key];
  return null;
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * What changed from `before` to `after`, as a partial config, or undefined when nothing did.
 * Objects are compared key by key; an array that changed goes whole (WLED replaces arrays, so
 * a list of LED outputs is sent in full). A key gone from `after` is not sent: WLED keeps it.
 */
export function configPatch(before: unknown, after: unknown): any {
  if (isObject(before) && isObject(after)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(after)) {
      const p = configPatch(before[k], after[k]);
      if (p !== undefined) out[k] = p;
    }
    return Object.keys(out).length ? out : undefined;
  }
  return JSON.stringify(before) === JSON.stringify(after) ? undefined : after;
}

/**
 * Where the device's settings, read back after a save, are not what was sent: what it did not
 * take (an output on a pin it cannot use, more outputs than it has, a value it limits). Dotted
 * paths, as "hw.led.ins.1.pin".
 */
export function unappliedPaths(patch: unknown, config: unknown, at = ''): string[] {
  if (isObject(patch)) {
    if (!isObject(config)) return [at];
    return Object.keys(patch).flatMap((k) => unappliedPaths(patch[k], config[k], at ? `${at}.${k}` : k));
  }
  if (Array.isArray(patch)) {
    if (!Array.isArray(config) || config.length !== patch.length) return [at];
    return patch.flatMap((v, i) => unappliedPaths(v, config[i], `${at}.${i}`));
  }
  // WLED keeps some numbers as floats (gamma): 2.2 can come back as 2.2000000476837.
  if (typeof patch === 'number' && typeof config === 'number') return Math.abs(patch - config) < 1e-3 ? [] : [at];
  return patch === config ? [] : [at];
}

/** The value at a dotted path ("if.live.en"), or undefined. */
export function getPath(config: unknown, path: string): any {
  let v: any = config;
  for (const k of path.split('.')) {
    if (v == null || typeof v !== 'object') return undefined;
    v = v[k];
  }
  return v;
}

/** A copy of the config with the value at a dotted path set (objects on the way made as needed). */
export function setPath<T extends WledConfig>(config: T, path: string, value: unknown): T {
  const [k, ...rest] = path.split('.');
  const copy: any = Array.isArray(config) ? [...config] : { ...config };
  copy[k] = rest.length ? setPath(isObject(copy[k]) || Array.isArray(copy[k]) ? copy[k] : {}, rest.join('.'), value) : value;
  return copy;
}

// ---------- LED outputs ----------

export function outputsOf(config: WledConfig): WledOutput[] {
  const ins = getPath(config, 'hw.led.ins');
  return Array.isArray(ins) ? ins : [];
}

export function withOutputs(config: WledConfig, outputs: WledOutput[]): WledConfig {
  return setPath(config, 'hw.led.ins', outputs);
}

/** LEDs on the device: up to the end of the last output. */
export function totalLeds(outputs: WledOutput[]): number {
  return outputs.reduce((n, o) => Math.max(n, (o.start ?? 0) + (o.len ?? 0)), 0);
}

/**
 * An output with a new number of LEDs. The outputs after it that followed on from it (each
 * starting where the one before ended) move with its end, so the LED numbers stay one run.
 */
export function setOutputLength(outputs: WledOutput[], index: number, len: number): WledOutput[] {
  const out = outputs.map((o) => ({ ...o }));
  let end = out[index].start + out[index].len;
  out[index].len = len;
  let newEnd = out[index].start + len;
  for (let i = index + 1; i < out.length && out[i].start === end; i++) {
    end = out[i].start + out[i].len;
    out[i].start = newEnd;
    newEnd = out[i].start + out[i].len;
  }
  return out;
}

/** An output with a new LED type, with as many pins as that type takes. */
export function setOutputType(output: WledOutput, type: LedType): WledOutput {
  const pins = Array.from({ length: type.pins }, (_, i) => output.pin?.[i] ?? (type.kind === 'network' ? 0 : -1));
  return { ...output, type: type.id, pin: pins };
}

/** A new output after the last one, like the last one, on no pin yet (-1). */
export function newOutput(outputs: WledOutput[], types: LedType[]): WledOutput {
  const last = outputs.at(-1);
  const type = types.find((t) => t.id === last?.type) ?? types.find((t) => t.id === 22) ?? types[0];
  const base: WledOutput = { start: totalLeds(outputs), len: last?.len ?? 30, pin: [], order: last?.order ?? 0, rev: false, skip: 0, type: type?.id ?? 22, ledma: last?.ledma ?? 55, maxpwr: last?.maxpwr ?? 0 };
  return type ? setOutputType(base, type) : { ...base, pin: [-1] };
}

/** What is wrong with the outputs, to fix before they go to the device. */
export function outputProblems(outputs: WledOutput[], types: LedType[], gpio: Gpio | null): string[] {
  const problems: string[] = [];
  const used = new Map<number, number>();
  outputs.forEach((o, i) => {
    const name = `Output ${i + 1}`;
    const type = types.find((t) => t.id === o.type);
    if (!(o.len >= 1)) problems.push(`${name} needs at least one LED.`);
    if (type?.kind === 'network') return;
    for (const p of o.pin ?? []) {
      if (!Number.isInteger(p) || p < 0) {
        problems.push(`${name} needs a GPIO pin.`);
        continue;
      }
      if (gpio?.max != null && p > gpio.max) problems.push(`${name}: this board has no GPIO ${p}.`);
      else if (gpio?.reserved.includes(p)) problems.push(`${name}: GPIO ${p} is taken on this board.`);
      else if (gpio?.readOnly.includes(p)) problems.push(`${name}: GPIO ${p} is input only.`);
      if (used.has(p)) problems.push(`${name} uses GPIO ${p}, as output ${used.get(p)! + 1} does.`);
      else used.set(p, i);
    }
  });
  return [...new Set(problems)];
}

// ---------- Brightness limiter ----------

/**
 * WLED's automatic brightness limiter: off, one limit for the whole device (hw.led.maxpwr, the
 * power supply), or a limit on each output (the device limit 0, each output's maxpwr).
 */
export type LimiterMode = 'off' | 'device' | 'output';

export function limiterOf(config: WledConfig): { mode: LimiterMode; ma: number } {
  const ma = Number(getPath(config, 'hw.led.maxpwr')) || 0;
  if (ma > 0) return { mode: 'device', ma };
  const outputs = outputsOf(config);
  const sum = outputs.reduce((n, o) => n + (Number(o.maxpwr) || 0), 0);
  return sum > 0 ? { mode: 'output', ma: sum } : { mode: 'off', ma: 0 };
}

/** The lowest limit WLED's page allows for a limited device or output. */
export const MIN_LIMIT_MA = 250;

/**
 * The config with the limiter set. With one limit for the device, each output gets its share
 * by LEDs (as WLED's page does). Turned to per-output, each output keeps its limit, or gets its
 * share of the device's.
 */
export function setLimiter(config: WledConfig, mode: LimiterMode, ma?: number): WledConfig {
  const outputs = outputsOf(config);
  const total = Math.max(1, outputs.reduce((n, o) => n + (o.len || 0), 0));
  const before = limiterOf(config);
  if (mode === 'off') return withOutputs(setPath(config, 'hw.led.maxpwr', 0), outputs.map((o) => ({ ...o, maxpwr: 0 })));
  if (mode === 'device') {
    const limit = Math.max(MIN_LIMIT_MA, Math.round(ma ?? (before.ma || 5000)));
    return withOutputs(
      setPath(config, 'hw.led.maxpwr', limit),
      outputs.map((o) => ({ ...o, maxpwr: Math.round((limit * (o.len || 0)) / total) }))
    );
  }
  const pool = before.ma || 5000;
  return withOutputs(
    setPath(config, 'hw.led.maxpwr', 0),
    outputs.map((o) => ({ ...o, maxpwr: before.mode === 'output' && o.maxpwr ? o.maxpwr : Math.max(MIN_LIMIT_MA, Math.round((pool * (o.len || 0)) / total)) }))
  );
}

// ---------- Gamma ----------

/**
 * Gamma correction: WLED keeps one value (light.gc.val) and has it on for colors and/or for
 * brightness when that one is above 1.
 */
export function gammaOf(config: WledConfig): { colors: boolean; brightness: boolean; value: number } {
  const gc = getPath(config, 'light.gc') ?? {};
  const on = Math.max(Number(gc.col) || 0, Number(gc.bri) || 0);
  const value = Number(gc.val) > 1 ? Number(gc.val) : on > 1 ? on : 2.2;
  return { colors: Number(gc.col) > 1, brightness: Number(gc.bri) > 1, value };
}

export function setGamma(config: WledConfig, g: { colors: boolean; brightness: boolean; value: number }): WledConfig {
  const value = Math.min(3, Math.max(1, g.value));
  return setPath(config, 'light.gc', { ...getPath(config, 'light.gc'), col: g.colors ? value : 1, bri: g.brightness ? value : 1, val: value });
}

// ---------- What the device reports about itself ----------

/**
 * The LED types and GPIO limits in a device's LED settings script (/settings/s.js?p=2), which
 * WLED's settings page runs: `d.ledTypes=[{i:22,c:1,t:"D",n:"WS281x RGB"},…]`, `d.rsvd=[…]`,
 * `d.ro_gpio=[…]`, `d.max_gpio=40`. Older WLED has no list: then `ledTypes` is null.
 */
export function parseSettingsScript(js: string): { ledTypes: LedType[] | null; gpio: Gpio | null } {
  const list = (name: string) => {
    const m = new RegExp(`d\\.${name}=\\[([-\\d,\\s]*)\\]`).exec(js);
    return m ? m[1].split(',').map(Number).filter((n) => Number.isInteger(n) && n >= 0) : null;
  };
  const max = /d\.max_gpio=(\d+)/.exec(js);
  const reserved = list('rsvd');
  const readOnly = list('ro_gpio');
  const usermods = list('um_p');
  const gpio = reserved || readOnly || max ? { reserved: [...new Set([...(reserved ?? []), ...(usermods ?? [])])].sort((a, b) => a - b), readOnly: readOnly ?? [], max: max ? Number(max[1]) : null } : null;

  let ledTypes: LedType[] | null = null;
  const m = /d\.ledTypes=(\[.*?\]);/.exec(js);
  if (m) {
    try {
      const raw = JSON.parse(m[1].replace(/([{,])\s*([A-Za-z_]\w*)\s*:/g, '$1"$2":')) as { i: number; c: number; t: string; n: string }[];
      ledTypes = raw.filter((t) => Number.isInteger(t?.i) && typeof t.n === 'string').map((t) => ledType(t.i, t.n, String(t.t ?? ''), Number(t.c) || 0));
      if (!ledTypes.length) ledTypes = null;
    } catch {
      ledTypes = null;
    }
  }
  return { ledTypes, gpio };
}

/** A type from WLED's list: `t` says its wires ("D" a data pin, "2P" data and clock, an "A" a PWM pin, "N" the network). */
function ledType(id: number, name: string, t: string, caps: number): LedType {
  const kind: LedType['kind'] = t === 'N' ? 'network' : t === 'D' ? 'digital' : t === '2P' ? 'spi' : t.startsWith('A') ? 'pwm' : 'onoff';
  const pins = kind === 'network' ? 4 : kind === 'spi' ? 2 : kind === 'pwm' ? t.length : 1;
  return { id, name, kind, pins, white: (caps & 2) !== 0 };
}

/** The types of WLED 0.15 and later on an ESP32, for a device that does not list its own. */
export const DEFAULT_LED_TYPES: LedType[] = [
  ledType(22, 'WS281x RGB', 'D', 1),
  ledType(24, '400kHz RGB', 'D', 1),
  ledType(25, 'TM1829 RGB', 'D', 1),
  ledType(26, 'UCS8903 RGB', 'D', 17),
  ledType(27, 'APA106/PL9823 RGB', 'D', 1),
  ledType(33, 'TM1914 RGB', 'D', 1),
  ledType(30, 'SK6812/WS2814 RGBW', 'D', 3),
  ledType(29, 'UCS8904 RGBW', 'D', 19),
  ledType(31, 'TM1814 RGBW', 'D', 35),
  ledType(28, 'FW1906/WS2811 RGBCCT', 'D', 7),
  ledType(32, 'WS2805 RGBCCT', 'D', 7),
  ledType(34, 'SM16825 RGBCCT', 'D', 23),
  ledType(19, 'WS2811 White', 'D', 2),
  ledType(21, 'WS281x WWA', 'D', 6),
  ledType(50, 'WS2801 RGB', '2P', 1),
  ledType(51, 'APA102 RGB', '2P', 1),
  ledType(52, 'LPD8806 RGB', '2P', 1),
  ledType(54, 'LPD6803 RGB', '2P', 1),
  ledType(53, 'P9813 RGB', '2P', 1),
  ledType(40, 'On/Off', '', 0),
  ledType(41, 'PWM White', 'A', 2),
  ledType(42, 'PWM CCT', 'AA', 6),
  ledType(43, 'PWM RGB', 'AAA', 1),
  ledType(44, 'PWM RGBW', 'AAAA', 3),
  ledType(45, 'PWM RGBCCT', 'AAAAA', 7),
  ledType(80, 'DDP RGB (network)', 'N', 1),
  ledType(82, 'Art-Net RGB (network)', 'N', 1),
  ledType(88, 'DDP RGBW (network)', 'N', 3),
  ledType(89, 'Art-Net RGBW (network)', 'N', 3)
];

/** WLED's color orders (the low 4 bits of an output's `order`). */
export const COLOR_ORDERS = ['GRB', 'RGB', 'BRG', 'RBG', 'BGR', 'GBR'] as const;
