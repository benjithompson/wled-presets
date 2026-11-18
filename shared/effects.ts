// Light effects that the server draws for each LED, 60 times a second, and sends to the real
// lights (and the browser draws for the editor's preview). A 1-D effect runs along one object's
// LEDs as a single string, from its first point to its last. A 3-D effect is a field in space:
// it lights each LED by where it is, so it fills a bush, spirals around a tree, or sweeps over
// the whole yard as one picture.
//
// Unlike the effects built into WLED, these run on a full computer: float color, physics,
// noise fields and hundreds of particles. Keep this file free of Node and DOM APIs.

import { activeLeds, isLine, segmentLeds, type Fixture, type Layout, type Stage } from './layout.ts';

export type EffectId =
  // Basics
  | 'solid'
  | 'gradient'
  | 'blocks'
  | 'rainbow'
  | 'colorloop'
  | 'breathe'
  | 'blink'
  | 'strobe'
  | 'chase'
  | 'wipe'
  | 'twinkle'
  | 'sparkle'
  | 'bounce'
  // 1-D
  | 'aurora'
  | 'fireworks'
  | 'inferno'
  | 'meteors'
  | 'ocean'
  | 'plasma'
  | 'starlight'
  | 'storm'
  | 'raindrops'
  | 'candy'
  // 3-D
  | 'wash'
  | 'scanner'
  | 'bonfire'
  | 'vortex'
  | 'shockwave'
  | 'nebula'
  | 'snowfall'
  | 'fireflies'
  | 'starburst'
  | 'equalizer';
export type PaletteId =
  | 'rainbow'
  | 'aurora'
  | 'fire'
  | 'ocean'
  | 'ice'
  | 'candy'
  | 'christmas'
  | 'party'
  | 'sunset'
  | 'warm'
  | 'storm'
  | 'halloween'
  | 'neon'
  | 'galaxy'
  | 'snow'
  | 'spectrum'
  | 'custom';
/** Which way a 3-D effect moves through space. Right, up and toward the street are positive. */
export type Direction = 'right' | 'left' | 'up' | 'down' | 'toward' | 'away' | 'out' | 'in';

export const DIRECTIONS: Record<Direction, string> = {
  right: 'Left to right',
  left: 'Right to left',
  up: 'Upward',
  down: 'Downward',
  toward: 'Toward the street',
  away: 'Toward the house',
  out: 'From the middle out',
  in: 'From the edges in'
};

/** The effect one object plays, and how. Every number is 0..1. */
export interface EffectSettings {
  effect: EffectId;
  palette: PaletteId;
  /** Palette "custom": 2 to 6 hex colors. */
  colors?: string[];
  /** 0.5 is the effect's normal pace; 0 is 4 times slower, 1 is 4 times faster. */
  speed: number;
  /** What it means depends on the effect (see EffectInfo.intensity), for example how many rockets. */
  intensity: number;
  /** The size of the effect's features along the string (see EffectInfo.size). */
  size: number;
  brightness: number;
  /** 1-D: run from the last point to the first. 3-D: run the other way (see EffectInfo.reverse). */
  reverse?: boolean;
  /** 3-D effects with a direction (see EffectInfo.directions). Default: the first one. */
  direction?: Direction;
}

export interface EffectInfo {
  id: EffectId;
  name: string;
  description: string;
  palette: PaletteId;
  /** What the intensity and size controls do in this effect. Left out: the effect has no such control. */
  intensity?: string;
  size?: string;
  /** False: it stands still, so there is no speed control. */
  speed?: false;
  /** Basics: the simple, standard effects (a color, a gradient, a chase...), listed first. */
  basic?: true;
  /** 1-D effects that light every LED the same: running backwards changes nothing. */
  uniform?: true;
  /** With the palette "custom": the colors it starts with. */
  colors?: string[];
  /** How lively it looks, 0..1, for the public page's background. */
  energy: number;
  /** 1-D: along the string. 3-D: by where each LED is in space. */
  space: '1d' | '3d';
  /** 3-D: the directions it can move in; the first is the default. */
  directions?: Direction[];
  /** 3-D without directions: what "reverse" does. Left out: no reverse. */
  reverse?: string;
}

export const EFFECTS: EffectInfo[] = [
  { id: 'solid', name: 'Solid color', description: 'One steady color. With several colors, the string is split into equal parts, one per color.', palette: 'custom', colors: ['#ffb46e'], speed: false, energy: 0, space: '1d', basic: true },
  { id: 'gradient', name: 'Gradient', description: 'The colors blend smoothly from one end of the string to the other, standing still.', palette: 'sunset', size: 'Length', speed: false, energy: 0.05, space: '1d', basic: true },
  { id: 'blocks', name: 'Color blocks', description: 'Blocks of each color side by side, standing still: red, green, red, green…', palette: 'christmas', size: 'Block size', speed: false, energy: 0.05, space: '1d', basic: true },
  { id: 'rainbow', name: 'Rainbow', description: 'The colors roll smoothly along the string.', palette: 'rainbow', size: 'Length', energy: 0.4, space: '1d', basic: true },
  { id: 'colorloop', name: 'Color fade', description: 'All the lights fade together from one color to the next.', palette: 'rainbow', energy: 0.25, space: '1d', basic: true, uniform: true },
  { id: 'breathe', name: 'Breathe', description: 'The lights slowly brighten and dim, like breathing. With several colors, each breath takes the next one.', palette: 'custom', colors: ['#2a6cff'], intensity: 'Depth', energy: 0.15, space: '1d', basic: true, uniform: true },
  { id: 'blink', name: 'Blink', description: 'On and off. With several colors, each blink takes the next one.', palette: 'christmas', intensity: 'Time on', energy: 0.5, space: '1d', basic: true, uniform: true },
  { id: 'strobe', name: 'Strobe', description: 'Short, bright flashes, like a strobe light.', palette: 'snow', intensity: 'Flash length', energy: 1, space: '1d', basic: true, uniform: true },
  { id: 'chase', name: 'Theater chase', description: 'Dots of light march along the string, with dark gaps between them, like the lights around a theater sign.', palette: 'christmas', intensity: 'Dot length', size: 'Spacing', energy: 0.55, space: '1d', basic: true },
  { id: 'wipe', name: 'Color wipe', description: 'Each color in turn fills the string from one end to the other. With one color, it fills and then empties.', palette: 'christmas', intensity: 'Pause when full', size: 'Soft edge', energy: 0.45, space: '1d', basic: true },
  { id: 'twinkle', name: 'Twinkle', description: 'Lights glow up at random, each in one of the colors, and fade away again.', palette: 'christmas', intensity: 'Twinkles', size: 'Twinkle length', energy: 0.3, space: '1d', basic: true },
  { id: 'sparkle', name: 'Sparkle', description: 'Steady colors with bright white sparkles that flash on and off.', palette: 'ice', intensity: 'Sparkles', size: 'Sparkle length', energy: 0.35, space: '1d', basic: true },
  { id: 'bounce', name: 'Bouncing dot', description: 'A dot of light runs from end to end and back, with a fading tail. With several colors, every run takes the next one.', palette: 'custom', colors: ['#ff1800'], intensity: 'Tail', size: 'Dot size', energy: 0.55, space: '1d', basic: true },
  { id: 'aurora', name: 'Aurora', description: 'Curtains of light that fold, drift and shimmer, like the northern lights.', palette: 'aurora', intensity: 'Shimmer', size: 'Curtain width', energy: 0.3, space: '1d' },
  { id: 'fireworks', name: 'Fireworks', description: 'Rockets climb and burst into sparks that slow down, cool and crackle.', palette: 'party', intensity: 'Rockets', size: 'Burst size', energy: 0.85, space: '1d' },
  { id: 'inferno', name: 'Inferno', description: 'Flames that lick and flicker, with sparks that drift away.', palette: 'fire', intensity: 'Heat', size: 'Flame size', energy: 0.6, space: '1d' },
  { id: 'meteors', name: 'Meteor shower', description: 'Meteors streak both ways and leave trails that crumble into glowing dust.', palette: 'ice', intensity: 'Meteors', size: 'Trail length', energy: 0.7, space: '1d' },
  { id: 'ocean', name: 'Ocean', description: 'Waves of different lengths roll and cross; white foam breaks on the crests.', palette: 'ocean', intensity: 'Swell', size: 'Wavelength', energy: 0.4, space: '1d' },
  { id: 'plasma', name: 'Plasma', description: 'Liquid color that swirls and folds into itself.', palette: 'rainbow', intensity: 'Contrast', size: 'Blob size', energy: 0.45, space: '1d' },
  { id: 'starlight', name: 'Starlight', description: 'Every LED is a star that twinkles at its own pace. Now and then, a shooting star.', palette: 'warm', intensity: 'Stars', size: 'Twinkle length', energy: 0.2, space: '1d' },
  { id: 'storm', name: 'Lightning storm', description: 'Dark clouds roll; lightning strikes in flickering forks and lights up the sky.', palette: 'storm', intensity: 'Strikes', size: 'Bolt size', energy: 0.75, space: '1d' },
  { id: 'raindrops', name: 'Raindrops', description: 'Drops land and send out ripples that spread, cross and fade.', palette: 'ice', intensity: 'Rain', size: 'Ripple size', energy: 0.45, space: '1d' },
  { id: 'candy', name: 'Candy cane', description: 'Crisp stripes that roll along, with a glint of light sweeping over them.', palette: 'candy', intensity: 'Shine', size: 'Stripe width', energy: 0.35, space: '1d' },
  {
    id: 'wash',
    name: 'Color wash',
    description: 'Broad bands of color roll through space: across the yard, up a tree, or out from the middle.',
    palette: 'rainbow',
    intensity: 'Crisp bands',
    size: 'Band width',
    energy: 0.35,
    space: '3d',
    directions: ['right', 'left', 'up', 'down', 'toward', 'away', 'out', 'in']
  },
  {
    id: 'scanner',
    name: 'Laser scan',
    description: 'A thin plane of light sweeps back and forth through everything, with a glowing trail. A new color on every pass.',
    palette: 'neon',
    intensity: 'Trail',
    size: 'Beam width',
    energy: 0.6,
    space: '3d',
    directions: ['right', 'up', 'toward', 'out']
  },
  { id: 'bonfire', name: 'Bonfire', description: 'Fire that climbs from the ground: bushes burn, flames lick up the walls, sparks rise into the night.', palette: 'fire', intensity: 'Flame height', size: 'Flame size', energy: 0.6, space: '3d', reverse: 'Flames hang from the top' },
  { id: 'vortex', name: 'Vortex', description: 'Spiral arms spin: around the trunk of a tree, or like a pinwheel on a flat object or the house.', palette: 'christmas', intensity: 'Arms', size: 'Twist', energy: 0.5, space: '3d', reverse: 'Spin the other way' },
  {
    id: 'shockwave',
    name: 'Shockwaves',
    description: 'Rings of light burst from random spots and roll over every light they reach.',
    palette: 'party',
    intensity: 'How often',
    size: 'Ring width',
    energy: 0.65,
    space: '3d',
    directions: ['out', 'in']
  },
  {
    id: 'nebula',
    name: 'Nebula',
    description: 'A glowing cloud of color drifts through space; every object shows its own slice of it, with a few stars.',
    palette: 'galaxy',
    intensity: 'Contrast',
    size: 'Cloud size',
    energy: 0.25,
    space: '3d',
    directions: ['right', 'left', 'up', 'down', 'toward', 'away']
  },
  { id: 'snowfall', name: 'Snowfall', description: 'Flakes drift down past the lights; where they touch, the lights sparkle and keep a soft glow that melts away.', palette: 'snow', intensity: 'Snow', size: 'Flake size', energy: 0.25, space: '3d', reverse: 'Rise like bubbles' },
  { id: 'fireflies', name: 'Fireflies', description: 'Glowing orbs wander lazily through the yard, from bush to roof, and blink on and off.', palette: 'aurora', intensity: 'Fireflies', size: 'Glow size', energy: 0.3, space: '3d' },
  { id: 'starburst', name: 'Starburst', description: 'Fireworks in 3-D: shells rise and burst into spheres of sparks that grow, fall, crackle and fade over the house.', palette: 'party', intensity: 'Shells', size: 'Burst size', energy: 0.9, space: '3d' },
  { id: 'equalizer', name: 'Equalizer', description: 'Bars of light bounce to a beat across the yard, like a music visualizer, with peaks that fall slowly.', palette: 'spectrum', intensity: 'Energy', size: 'Bar width', energy: 0.8, space: '3d', reverse: 'Bars hang from the top' }
];

/** True for effects that light each LED by where it is in space (3-D). */
export const isSpatial = (id: EffectId) => effectInfo(id).space === '3d';

export const effectInfo = (id: EffectId) => EFFECTS.find((e) => e.id === id) ?? EFFECTS[0];

export interface PaletteInfo {
  id: PaletteId;
  name: string;
  colors: string[];
  /** The last color runs back into the first (a color wheel). */
  cyclic?: boolean;
}

export const PALETTES: PaletteInfo[] = [
  { id: 'rainbow', name: 'Rainbow', colors: ['#ff0000', '#ff8000', '#ffe000', '#00ff40', '#00c0ff', '#2040ff', '#c000ff'], cyclic: true },
  { id: 'aurora', name: 'Aurora', colors: ['#00ff6a', '#00ffb4', '#00b4ff', '#4a3cff', '#c03cff'] },
  { id: 'fire', name: 'Fire', colors: ['#000000', '#6a0000', '#e01000', '#ff6000', '#ffb020', '#fff0b0'] },
  { id: 'ocean', name: 'Ocean', colors: ['#000a30', '#00307a', '#0068c0', '#00b8d8', '#90f4ff'] },
  { id: 'ice', name: 'Ice', colors: ['#0a1aff', '#3a8cff', '#7fd4ff', '#e0f6ff'] },
  { id: 'candy', name: 'Candy cane', colors: ['#ff0012', '#ffffff'], cyclic: true },
  { id: 'christmas', name: 'Christmas', colors: ['#ff0a14', '#00d040', '#ffb428', '#ffffff'], cyclic: true },
  { id: 'party', name: 'Party', colors: ['#ff1070', '#ff8000', '#ffe800', '#20ff60', '#00b0ff', '#8a2cff'], cyclic: true },
  { id: 'sunset', name: 'Sunset', colors: ['#3a0070', '#b0106a', '#ff3a20', '#ff9400', '#ffd870'] },
  { id: 'warm', name: 'Warm white', colors: ['#ff9a40', '#ffc078', '#ffe0b0', '#fff4e0'] },
  { id: 'storm', name: 'Storm', colors: ['#0a0830', '#26307a', '#6a70ff', '#c8d0ff', '#ffffff'] },
  { id: 'halloween', name: 'Halloween', colors: ['#ff5a00', '#9a00ff', '#40ff00', '#ff9a00'], cyclic: true },
  { id: 'neon', name: 'Neon', colors: ['#ff00aa', '#00e5ff', '#8a2cff', '#00ff88'], cyclic: true },
  { id: 'galaxy', name: 'Galaxy', colors: ['#0a0038', '#3a10b0', '#9020d0', '#ff3fa0', '#ffd0ec'] },
  { id: 'snow', name: 'Snow', colors: ['#ffffff', '#d8ecff', '#a8d4ff'] },
  { id: 'spectrum', name: 'Level meter', colors: ['#00ff40', '#a0ff00', '#ffe000', '#ff8000', '#ff0020'] },
  { id: 'custom', name: 'My colors', colors: ['#ff0000', '#00ff00', '#0000ff'], cyclic: true }
];

export const paletteInfo = (id: PaletteId) => PALETTES.find((p) => p.id === id) ?? PALETTES[0];

/** The hex colors an effect shows: its palette's, or your own for "custom". */
export function paletteColors(s: Pick<EffectSettings, 'palette' | 'colors'>): string[] {
  return s.palette === 'custom' && s.colors?.length ? s.colors : paletteInfo(s.palette).colors;
}

export function defaultSettings(effect: EffectId): EffectSettings {
  const info = effectInfo(effect);
  return { effect, palette: info.palette, ...(info.colors ? { colors: [...info.colors] } : {}), speed: 0.5, intensity: 0.5, size: 0.5, brightness: 0.8 };
}

/** The direction a 3-D effect moves in now (its setting, or its default). */
export function effectDirection(s: Pick<EffectSettings, 'effect' | 'direction'>): Direction {
  const dirs = effectInfo(s.effect).directions;
  return dirs ? (s.direction && dirs.includes(s.direction) ? s.direction : dirs[0]) : 'right';
}

/**
 * Where an effect plays: the whole yard ("*"), every object of one WLED device ("@<device id>"),
 * a whole object ("roof"), or one segment of a line ("roof#2": segment 2, from point 2 to
 * point 3). Scenes store their effects under these keys. A segment's effect wins over its
 * object's, an object's over its device's, and a device's over the yard's.
 */
export const YARD = '*';

/** The key of an effect that plays on every object of a WLED device. */
export const deviceKey = (deviceId: string) => `@${deviceId}`;

/** The device a device key names, or null for any other key. */
export const keyDevice = (key: string): string | null => (key.startsWith('@') ? key.slice(1) : null);

export const effectKey = (fixtureId: string, segment?: number | null) => (segment == null ? fixtureId : `${fixtureId}#${segment}`);

export function effectTarget(key: string): { id: string; segment: number | null } {
  const m = /^(.*)#(\d+)$/.exec(key);
  return m ? { id: m[1], segment: Number(m[2]) } : { id: key, segment: null };
}

/** The ids of the layout objects that a list of effect keys reaches ("*" reaches every object). */
export function effectObjects(layout: Pick<Layout, 'fixtures'>, keys: Iterable<string>): string[] {
  const ids = new Set(layout.fixtures.map((f) => f.id));
  const out = new Set<string>();
  for (const key of keys) {
    if (key === YARD) return [...ids];
    const device = keyDevice(key);
    if (device) {
      for (const f of layout.fixtures) if (f.deviceId === device) out.add(f.id);
      continue;
    }
    const id = effectTarget(key).id;
    if (ids.has(id)) out.add(id);
  }
  return [...out];
}

/** The effects of a scene that play on whole devices (picked in the scene dialog, not the layout editor). */
export function deviceEffects(effects: Record<string, EffectSettings> | undefined): Record<string, EffectSettings> {
  return Object.fromEntries(Object.entries(effects ?? {}).filter(([k]) => keyDevice(k)));
}

/** The effects of the yard, a layout's objects and segments, by effect key (the editor's working copy). */
export function layoutEffects(layout: Pick<Layout, 'fixtures' | 'effect'>): Record<string, EffectSettings> {
  const out: Record<string, EffectSettings> = {};
  if (layout.effect) out[YARD] = layout.effect;
  for (const f of layout.fixtures) {
    if (f.effect) out[f.id] = f.effect;
    if (isLine(f)) for (const [k, s] of Object.entries(f.segmentEffects ?? {})) if (Number(k) < f.points.length - 1) out[effectKey(f.id, Number(k))] = s;
  }
  return out;
}

/** A scene's effects as the editor keeps them: on each object and its segments. */
export function withEffects<F extends Layout['fixtures'][number]>(f: F, effects: Record<string, EffectSettings> | undefined): F {
  const { effect: _e, segmentEffects: _s, ...rest } = f;
  const segs: Record<string, EffectSettings> = {};
  for (const [key, s] of Object.entries(effects ?? {})) {
    const t = effectTarget(key);
    if (t.id === f.id && t.segment != null && isLine(f) && t.segment < f.points.length - 1) segs[t.segment] = s;
  }
  return { ...rest, ...(effects?.[f.id] ? { effect: effects[f.id] } : {}), ...(Object.keys(segs).length ? { segmentEffects: segs } : {}) } as F;
}

/** Colors and liveliness of a set of effects, for a scene's button and the public page. */
export function effectsLook(effects: EffectSettings[]): { colors: string[]; energy: number }[] {
  return effects.map((s) => {
    const all = paletteColors(s);
    const bright = all.filter((c) => luma(hexToRgb(c)) > 0.2);
    // A dark color of its own (a deep blue) still shows, when it is all there is.
    const colors = bright.length ? bright : all;
    return { colors: colors.slice(0, 4), energy: Math.min(1, effectInfo(s.effect).energy * (0.6 + 0.8 * s.speed)) };
  });
}

// ---------- Small math ----------

type Rgb = [number, number, number];

const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);
const smooth = (a: number, b: number, x: number) => {
  const t = clamp01((x - a) / (b - a));
  return t * t * (3 - 2 * t);
};
const fract = (x: number) => x - Math.floor(x);
const luma = ([r, g, b]: Rgb) => 0.3 * r + 0.55 * g + 0.15 * b;
const WHITE: Rgb = [1, 1, 1];

export function hexToRgb(hex: string): Rgb {
  const n = parseInt(hex.replace('#', '').slice(0, 6), 16) || 0;
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/** A small, fast random number generator, so every run of an effect can start the same way. */
export function seededRandom(seed: number): () => number {
  let a = seed >>> 0 || 1;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

/** Smooth 2-D gradient noise (Perlin), about -1..1. Space along the string is x, time is y. */
class Noise {
  private p = new Uint8Array(512);
  constructor(rand: () => number) {
    const a = Array.from({ length: 256 }, (_, i) => i);
    for (let i = 255; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    for (let i = 0; i < 512; i++) this.p[i] = a[i & 255];
  }
  n2(x: number, y: number): number {
    const p = this.p;
    const xi = Math.floor(x);
    const yi = Math.floor(y);
    const xf = x - xi;
    const yf = y - yi;
    const X = xi & 255;
    const Y = yi & 255;
    const u = xf * xf * xf * (xf * (xf * 6 - 15) + 10);
    const v = yf * yf * yf * (yf * (yf * 6 - 15) + 10);
    const g = (h: number, dx: number, dy: number) => ((h & 1 ? -dx : dx) + (h & 2 ? -dy : dy)) * (h & 4 ? 0.7 : 1);
    const aa = p[p[X] + Y];
    const ab = p[p[X] + Y + 1];
    const ba = p[p[X + 1] + Y];
    const bb = p[p[X + 1] + Y + 1];
    const x1 = g(aa, xf, yf) + (g(ba, xf - 1, yf) - g(aa, xf, yf)) * u;
    const x2 = g(ab, xf, yf - 1) + (g(bb, xf - 1, yf - 1) - g(ab, xf, yf - 1)) * u;
    return x1 + (x2 - x1) * v;
  }
  /** Smooth 3-D gradient noise (Perlin), about -1..1. */
  n3(x: number, y: number, z: number): number {
    const p = this.p;
    const fx = Math.floor(x);
    const fy = Math.floor(y);
    const fz = Math.floor(z);
    const X = fx & 255;
    const Y = fy & 255;
    const Z = fz & 255;
    x -= fx;
    y -= fy;
    z -= fz;
    const u = x * x * x * (x * (x * 6 - 15) + 10);
    const v = y * y * y * (y * (y * 6 - 15) + 10);
    const w = z * z * z * (z * (z * 6 - 15) + 10);
    const A = p[X] + Y;
    const AA = p[A] + Z;
    const AB = p[A + 1] + Z;
    const B = p[X + 1] + Y;
    const BA = p[B] + Z;
    const BB = p[B + 1] + Z;
    const g = (h: number, a: number, b: number, c: number) => {
      h &= 15;
      const s = h < 8 ? a : b;
      const t = h < 4 ? b : h === 12 || h === 14 ? a : c;
      return (h & 1 ? -s : s) + (h & 2 ? -t : t);
    };
    const l = (t: number, a: number, b: number) => a + t * (b - a);
    return (
      l(w, l(v, l(u, g(p[AA], x, y, z), g(p[BA], x - 1, y, z)), l(u, g(p[AB], x, y - 1, z), g(p[BB], x - 1, y - 1, z))), l(v, l(u, g(p[AA + 1], x, y, z - 1), g(p[BA + 1], x - 1, y, z - 1)), l(u, g(p[AB + 1], x, y - 1, z - 1), g(p[BB + 1], x - 1, y - 1, z - 1)))) *
      0.8
    );
  }
  fbm3(x: number, y: number, z: number, octaves = 3): number {
    let sum = 0;
    let amp = 1;
    let norm = 0;
    for (let o = 0; o < octaves; o++) {
      sum += this.n3(x, y, z + o * 13.1) * amp;
      norm += amp;
      amp *= 0.5;
      x *= 2.03;
      y *= 1.97;
      z *= 2.01;
    }
    return sum / norm;
  }
  /** Several octaves of noise: big shapes with finer detail on top. */
  fbm(x: number, y: number, octaves = 3): number {
    let sum = 0;
    let amp = 1;
    let norm = 0;
    for (let o = 0; o < octaves; o++) {
      sum += this.n2(x, y + o * 17.17) * amp;
      norm += amp;
      amp *= 0.5;
      x *= 2.03;
      y *= 1.97;
    }
    return sum / norm;
  }
}

/** Colors along a palette. Not cyclic palettes run there and back again, so there is no seam. */
class Pal {
  readonly stops: Rgb[];
  readonly cyclic: boolean;
  constructor(colors: string[], cyclic: boolean) {
    this.stops = (colors.length ? colors : ['#ffffff']).map(hexToRgb);
    this.cyclic = cyclic;
  }
  /** Adds the color at t (0..1 across the palette) times `k` to out[i]. */
  add(out: Float32Array, i: number, t: number, k: number) {
    const s = this.stops;
    const n = s.length;
    if (n === 1 || k === 0) {
      const c = s[0];
      out[i] += c[0] * k;
      out[i + 1] += c[1] * k;
      out[i + 2] += c[2] * k;
      return;
    }
    let x: number;
    if (this.cyclic) x = fract(t) * n;
    else {
      // Clamp to the ends: callers that want a seamless loop use wave().
      x = clamp01(t) * (n - 1);
    }
    const a = Math.floor(x);
    const f = x - a;
    const ca = s[a % n];
    const cb = s[(a + 1) % n];
    const w = f * f * (3 - 2 * f);
    out[i] += (ca[0] + (cb[0] - ca[0]) * w) * k;
    out[i + 1] += (ca[1] + (cb[1] - ca[1]) * w) * k;
    out[i + 2] += (ca[2] + (cb[2] - ca[2]) * w) * k;
  }
  /** For a value that grows without end (a hue that keeps turning): loops without a seam. */
  wave(t: number) {
    return this.cyclic ? t : 1 - Math.abs(fract(t * 0.5) * 2 - 1);
  }
  /** A random color of the palette. */
  pick(rand: () => number): Rgb {
    return this.stops[Math.floor(rand() * this.stops.length) % this.stops.length];
  }
}

function addRgb(out: Float32Array, i: number, c: Rgb, k: number) {
  out[i] += c[0] * k;
  out[i + 1] += c[1] * k;
  out[i + 2] += c[2] * k;
}

/** A soft dot at a fractional position: it lights its neighbours too, so it glides between LEDs. */
function splat(out: Float32Array, n: number, pos: number, c: Rgb, k: number, width = 0.9) {
  const lo = Math.max(0, Math.floor(pos - width * 2.2));
  const hi = Math.min(n - 1, Math.ceil(pos + width * 2.2));
  for (let p = lo; p <= hi; p++) {
    const d = (p - pos) / width;
    addRgb(out, p * 3, c, Math.exp(-d * d) * k);
  }
}

/** A streak from a to b (one frame of a moving dot), so fast things leave no gaps. */
function streak(out: Float32Array, n: number, a: number, b: number, c: Rgb, k: number, width = 0.8) {
  const len = Math.abs(b - a);
  const steps = Math.max(1, Math.ceil(len / 0.5));
  for (let s = 0; s < steps; s++) splat(out, n, a + ((b - a) * (s + 0.5)) / steps, c, k / steps, width);
}

// ---------- Effects ----------

/**
 * Where the LEDs of an effect sit in space: x to the right, y up, z toward the street. The box
 * around the LEDs is centered on 0, and scaled so its longest side is 1: an effect fills a bush
 * the same way it fills the whole yard.
 */
export interface Space {
  x: Float32Array;
  y: Float32Array;
  z: Float32Array;
  /** The size of the box along each axis (the longest is 1, unless every LED is at one spot). */
  ex: number;
  ey: number;
  ez: number;
  /** About the distance between neighbouring LEDs, in the same units. */
  pitch: number;
}

/** A straight string along x: where a 3-D effect plays when it gets no positions. */
export function lineSpace(n: number): Space {
  const x = new Float32Array(n);
  for (let i = 0; i < n; i++) x[i] = n > 1 ? i / (n - 1) - 0.5 : 0;
  return { x, y: new Float32Array(n), z: new Float32Array(n), ex: n > 1 ? 1 : 0, ey: 0, ez: 0, pitch: n > 1 ? 1 / (n - 1) : 1 };
}

/** The space of some stage LEDs, in a box around `box` (default: the same LEDs). */
export function stageSpace(stage: Pick<Stage, 'positions3'>, leds: ArrayLike<number>, box: ArrayLike<number> = leds): Space {
  const P = stage.positions3;
  let x0 = Infinity;
  let y0 = Infinity;
  let z0 = Infinity;
  let x1 = -Infinity;
  let y1 = -Infinity;
  let z1 = -Infinity;
  for (let j = 0; j < box.length; j++) {
    const k = box[j] * 3;
    const x = P[k];
    const y = -P[k + 1];
    const z = P[k + 2];
    if (x < x0) x0 = x;
    if (x > x1) x1 = x;
    if (y < y0) y0 = y;
    if (y > y1) y1 = y;
    if (z < z0) z0 = z;
    if (z > z1) z1 = z;
  }
  if (!box.length) x0 = x1 = y0 = y1 = z0 = z1 = 0;
  const m = Math.max(x1 - x0, y1 - y0, z1 - z0) || 1;
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  const cz = (z0 + z1) / 2;
  const n = leds.length;
  const sp: Space = { x: new Float32Array(n), y: new Float32Array(n), z: new Float32Array(n), ex: (x1 - x0) / m, ey: (y1 - y0) / m, ez: (z1 - z0) / m, pitch: 0 };
  for (let i = 0; i < n; i++) {
    const k = leds[i] * 3;
    sp.x[i] = (P[k] - cx) / m;
    sp.y[i] = (-P[k + 1] - cy) / m;
    sp.z[i] = (P[k + 2] - cz) / m;
  }
  sp.pitch = estimatePitch(sp);
  return sp;
}

/** The median distance from an LED to its nearest neighbour, from a sample of LEDs. */
function estimatePitch(sp: Space): number {
  const n = sp.x.length;
  if (n < 2) return 1;
  const samples = Math.min(n, 40);
  const d: number[] = [];
  for (let s = 0; s < samples; s++) {
    const i = Math.floor((s * n) / samples);
    let best = Infinity;
    for (let j = 0; j < n; j++) {
      if (j === i) continue;
      const dd = (sp.x[i] - sp.x[j]) ** 2 + (sp.y[i] - sp.y[j]) ** 2 + (sp.z[i] - sp.z[j]) ** 2;
      if (dd > 1e-12 && dd < best) best = dd;
    }
    if (best < Infinity) d.push(Math.sqrt(best));
  }
  d.sort((a, b) => a - b);
  return d.length ? Math.max(1e-4, d[Math.floor(d.length / 2)]) : 1;
}

/** 0..1 across the box along one axis (0.5 when the box is flat that way). */
const unitX = (sp: Space, i: number) => (sp.ex > 1e-6 ? sp.x[i] / sp.ex + 0.5 : 0.5);
const unitY = (sp: Space, i: number) => (sp.ey > 1e-6 ? sp.y[i] / sp.ey + 0.5 : 0.5);
const unitZ = (sp: Space, i: number) => (sp.ez > 1e-6 ? sp.z[i] / sp.ez + 0.5 : 0.5);

/** For each LED: 0..1, how far along a direction it is (where a wave that moves that way reaches it first: 0). */
export function directionCoord(sp: Space, dir: Direction): Float32Array {
  const n = sp.x.length;
  const out = new Float32Array(n);
  const R = 0.5 * Math.hypot(sp.ex, sp.ey, sp.ez) || 0.5;
  for (let i = 0; i < n; i++) {
    let v: number;
    switch (dir) {
      case 'left':
        v = 1 - unitX(sp, i);
        break;
      case 'up':
        v = unitY(sp, i);
        break;
      case 'down':
        v = 1 - unitY(sp, i);
        break;
      case 'toward':
        v = unitZ(sp, i);
        break;
      case 'away':
        v = 1 - unitZ(sp, i);
        break;
      case 'out':
        v = Math.hypot(sp.x[i], sp.y[i], sp.z[i]) / R;
        break;
      case 'in':
        v = 1 - Math.hypot(sp.x[i], sp.y[i], sp.z[i]) / R;
        break;
      default:
        v = unitX(sp, i);
    }
    out[i] = clamp01(v);
  }
  return out;
}

const DIR_VECTORS: Record<Direction, [number, number, number]> = { right: [1, 0, 0], left: [-1, 0, 0], up: [0, 1, 0], down: [0, -1, 0], toward: [0, 0, 1], away: [0, 0, -1], out: [1, 0, 0], in: [-1, 0, 0] };

/** What an effect gets each frame. */
interface Params {
  /** Seconds of effect time since the start (it runs faster or slower with the speed). */
  t: number;
  /** Effect time since the last frame. */
  dt: number;
  intensity: number;
  /** Size of features, as a factor: 1 is normal, about 0.35 to 2.8. */
  size: number;
  pal: Pal;
  /** 3-D: where each LED is. */
  space: Space;
  /** 3-D: the direction setting, and 0..1 along it for each LED (see directionCoord). */
  dir: Direction;
  along: Float32Array;
  /** 3-D: the reverse setting. */
  reverse: boolean;
}

/** Draws one frame: adds linear RGB (0..1, may go above) for n LEDs to `out` (cleared before). */
type Draw = (out: Float32Array, p: Params) => void;
type Factory = (n: number, rand: () => number, noise: Noise) => Draw;

/** A stable pseudo-random number 0..1 for an LED (and a step), without state. */
const hash01 = (i: number, k = 0) => fract(Math.sin(i * 12.9898 + k * 78.233) * 43758.5453);

/** Adds a soft round glow around a point in space to every LED near it. `flat`: by front-view distance (x and y only). */
function glow3(out: Float32Array, sp: Space, px: number, py: number, pz: number, r: number, c: Rgb, k: number, flat = false) {
  if (k <= 0) return;
  const inv = 1 / (r * r);
  const cut = 9 * r * r;
  const n = sp.x.length;
  for (let i = 0; i < n; i++) {
    const dx = sp.x[i] - px;
    if (dx > 3 * r || dx < -3 * r) continue;
    const dy = sp.y[i] - py;
    let d2 = dx * dx + dy * dy;
    if (!flat) {
      const dz = sp.z[i] - pz;
      d2 += dz * dz;
    }
    if (d2 > cut) continue;
    addRgb(out, i * 3, c, Math.exp(-d2 * inv) * k);
  }
}

/** Things happen at a rate per 100 LEDs, so a long roofline is as busy as a short window. */
const perLength = (n: number) => Math.max(0.6, n / 100);

const aurora: Factory = (n, _rand, noise) => (out, { t, intensity, size, pal }) => {
  const scale = 1 / (30 * size);
  for (let i = 0; i < n; i++) {
    const x = i * scale;
    // Big folds that drift; the curtains bunch up and spread out as they go.
    const warp = noise.fbm(x * 0.35 + 3.3, t * 0.06, 2) * 2.2;
    const a = noise.n2(x + warp + t * 0.11, t * 0.16);
    const fold = (1 - Math.abs(a)) ** 3.5;
    // Fine rays that shimmer along the folds.
    const b = noise.n2(x * 3.1 - t * 0.35, 7.3 + t * 0.4);
    const rays = (1 - Math.abs(b)) ** 12;
    const glow = 0.5 + 0.5 * noise.fbm(x * 0.45 - t * 0.04, 3.1, 2);
    const v = 1.3 * glow ** 1.5 * (0.18 + 1.15 * fold * fold + (0.35 + 1.1 * intensity) * rays * (0.3 + glow));
    // The color drifts slowly: mostly the palette's first colors, with the far end now and then.
    const hue = 0.2 + 0.5 * noise.n2(x * 0.22 + t * 0.025, 11.1) + 0.2 * fold;
    pal.add(out, i * 3, pal.wave(hue), v);
    // White-hot edges where a fold is brightest.
    if (fold > 0.75) addRgb(out, i * 3, WHITE, (fold - 0.75) * 0.8 * glow);
  }
};

interface Spark {
  x: number;
  v: number;
  life: number;
  max: number;
  color: Rgb;
  drag: number;
  crackle: boolean;
}
interface Rocket {
  x0: number;
  dir: number;
  dist: number;
  age: number;
  dur: number;
  last: number;
}

const fireworks: Factory = (n, rand) => {
  const trail = new Float32Array(n * 3);
  const sparks: Spark[] = [];
  const rockets: Rocket[] = [];
  const flashes: { x: number; age: number; color: Rgb; r: number }[] = [];
  let due = 0.2;
  const EMBER: Rgb = [1, 0.45, 0.12];
  return (out, { dt, intensity, size, pal }) => {
    // Trails: what was drawn before fades away fast.
    const keep = Math.exp(-dt * 7);
    for (let i = 0; i < trail.length; i++) trail[i] *= keep;
    const fill = 1 - keep;

    due -= dt * (0.3 + 1.8 * intensity) * perLength(n) * 0.8;
    while (due <= 0 && rockets.length < 24) {
      due += 0.4 + rand() * 1.2;
      const dist = (10 + rand() * 22) * Math.min(1.6, size);
      const dir = rand() < 0.5 ? -1 : 1;
      // Launch from a point that leaves room for the climb.
      const x0 = n < 2 * dist ? n / 2 - (dir * dist) / 2 : dist * 0.5 + rand() * (n - dist * 2) + (dir < 0 ? dist : 0);
      rockets.push({ x0, dir, dist, age: 0, dur: 0.55 + rand() * 0.5, last: x0 });
    }
    for (let r = rockets.length - 1; r >= 0; r--) {
      const k = rockets[r];
      k.age += dt;
      const u = Math.min(1, k.age / k.dur);
      // The climb slows down at the top, as a rocket does.
      const x = k.x0 + k.dir * k.dist * (1 - (1 - u) * (1 - u));
      streak(trail, n, k.last, x, [1, 0.7, 0.35], (0.5 + rand() * 0.9) * 6 * fill * (1 - u * 0.5), 0.6);
      k.last = x;
      if (u < 1) continue;
      rockets.splice(r, 1);
      // The burst: one or two colors, a white flash, and sparks that fly out both ways.
      const c1 = pal.pick(rand);
      const c2 = rand() < 0.35 ? pal.pick(rand) : c1;
      const count = Math.round(28 + rand() * 30);
      const power = (20 + rand() * 25) * size;
      flashes.push({ x, age: 0, color: c1, r: 3 + power * 0.12 });
      for (let s = 0; s < count; s++) {
        // Most sparks fly near the full speed, so the burst has a bright edge.
        const sp = power * (0.35 + 0.65 * Math.sqrt(rand()));
        const max = 0.9 + rand() * 1.4;
        sparks.push({ x, v: (rand() < 0.5 ? -1 : 1) * sp, life: max, max, color: rand() < 0.5 ? c1 : c2, drag: 2.2 + rand() * 1.2, crackle: rand() < 0.3 });
      }
    }
    for (let s = sparks.length - 1; s >= 0; s--) {
      const p = sparks[s];
      p.life -= dt;
      if (p.life <= 0 || p.x < -5 || p.x > n + 5) {
        sparks.splice(s, 1);
        continue;
      }
      const prev = p.x;
      p.v *= Math.exp(-p.drag * dt);
      p.x += p.v * dt;
      const age = 1 - p.life / p.max;
      // White-hot at first, then the shell's color, then a dim ember.
      const hot = 1 - smooth(0, 0.12, age);
      const cool = smooth(0.55, 1, age);
      const c: Rgb = [0, 1, 2].map((j) => (p.color[j] + (EMBER[j] - p.color[j]) * cool) * (1 - hot) + hot) as Rgb;
      let b = (1 - age) ** 1.5 * 1.4;
      if (p.crackle && age > 0.55) b *= rand() < 0.45 ? 2.5 : 0.05;
      streak(trail, n, prev, p.x, c, b * fill * 4, 0.7);
    }
    out.set(trail);
    for (let f = flashes.length - 1; f >= 0; f--) {
      const fl = flashes[f];
      fl.age += dt;
      const b = Math.exp(-fl.age * 22) * 1.6;
      if (b < 0.01) {
        flashes.splice(f, 1);
        continue;
      }
      splat(out, n, fl.x, [1, 1, 1], b, fl.r * 0.5);
      splat(out, n, fl.x, fl.color, b * 0.6, fl.r * 1.3);
    }
  };
};

const inferno: Factory = (n, rand, noise) => {
  const embers: { x: number; v: number; life: number; max: number }[] = [];
  let due = 0;
  return (out, { t, dt, intensity, size, pal }) => {
    const scale = 1 / (9 * size);
    const heat = 0.55 + 0.55 * intensity;
    for (let i = 0; i < n; i++) {
      const x = i * scale;
      // Tongues of flame: shapes that grow, split and die quickly, drifting a little.
      const body = 0.5 + 0.5 * noise.fbm(x * 0.5 + t * 0.15, t * 0.9, 3);
      const tongue = 0.5 + 0.5 * noise.n2(x * 1.7 - t * 0.6, t * 2.3 + 5);
      const flick = 0.5 + 0.5 * noise.n2(x * 4.1, t * 9 + 11);
      let h = body ** 1.3 * (0.6 + 0.6 * tongue) * (0.8 + 0.35 * flick) * heat * 1.6;
      h = clamp01(h);
      // The palette runs from cold (dark) to hot (bright); a cool spot is also dimmer.
      pal.add(out, i * 3, h, smooth(0.04, 0.5, h) * 1.15);
    }
    // Sparks that pop off the flames, drift and burn out.
    due -= dt * (2 + 10 * intensity) * perLength(n);
    while (due <= 0) {
      due += 0.5 + rand();
      if (embers.length < 200) {
        const max = 0.25 + rand() * 0.7;
        embers.push({ x: rand() * n, v: (rand() - 0.5) * 10 * size, life: max, max });
      }
    }
    for (let e = embers.length - 1; e >= 0; e--) {
      const m = embers[e];
      m.life -= dt;
      if (m.life <= 0) {
        embers.splice(e, 1);
        continue;
      }
      m.x += m.v * dt;
      const a = m.life / m.max;
      const b = a * a * (0.6 + 0.8 * rand());
      splat(out, n, m.x, [1, 0.75 * a + 0.2, 0.25 * a], b, 0.6);
    }
  };
};

const meteors: Factory = (n, rand) => {
  const trail = new Float32Array(n * 3);
  const list: { x: number; v: number; color: Rgb; b: number }[] = [];
  const dust: { x: number; life: number; max: number; color: Rgb }[] = [];
  let due = 0;
  return (out, { dt, intensity, size, pal }) => {
    // The trail crumbles: every LED fades at its own random rate, each frame anew.
    const rate = 2.6 / size;
    for (let i = 0; i < n; i++) {
      const keep = Math.exp(-dt * rate * (0.35 + 1.3 * rand()));
      trail[i * 3] *= keep;
      trail[i * 3 + 1] *= keep;
      trail[i * 3 + 2] *= keep;
    }
    due -= dt * (0.25 + 1.8 * intensity) * perLength(n) * 0.5;
    while (due <= 0) {
      due += 0.3 + rand() * 1.4;
      const dir = rand() < 0.5 ? -1 : 1;
      if (list.length < 40) list.push({ x: dir > 0 ? -3 : n + 2, v: dir * (45 + rand() * 90), color: pal.pick(rand), b: 0.8 + rand() * 0.6 });
    }
    for (let m = list.length - 1; m >= 0; m--) {
      const me = list[m];
      const prev = me.x;
      me.x += me.v * dt;
      if (me.x < -10 || me.x > n + 10) {
        list.splice(m, 1);
        continue;
      }
      streak(trail, n, prev, me.x, me.color, me.b * 1.4, 0.7);
      // Now and then a speck breaks off and glows on for a while.
      if (rand() < dt * 18) {
        const max = 0.6 + rand() * 1.6;
        dust.push({ x: me.x + (rand() - 0.5) * 2, life: max, max, color: me.color });
      }
    }
    out.set(trail);
    // The head itself: a white-hot core in front of the trail.
    for (const me of list) splat(out, n, me.x, WHITE, me.b * 0.9, 0.7);
    for (let d = dust.length - 1; d >= 0; d--) {
      const s = dust[d];
      s.life -= dt;
      if (s.life <= 0) {
        dust.splice(d, 1);
        continue;
      }
      const a = s.life / s.max;
      splat(out, n, s.x, s.color, a * (0.3 + 0.5 * rand()), 0.5);
    }
  };
};

const ocean: Factory = (n, rand) => {
  // Waves of several lengths; their speed follows their length (longer waves are faster),
  // so they slide over each other and the crests build and break.
  const waves = [61, 37, 23, 14.5, 97, 9.3].map((len, k) => ({
    len,
    amp: len ** 0.7,
    dir: k === 3 || k === 4 ? -1 : 1,
    phase: rand() * Math.PI * 2
  }));
  const norm = waves.reduce((s, w) => s + w.amp, 0);
  const foam = new Float32Array(n);
  return (out, { t, dt, intensity, size, pal }) => {
    const swell = 0.7 + 0.6 * intensity;
    const fade = Math.exp(-dt * 1.6);
    for (let i = 0; i < n; i++) {
      let h = 0;
      for (const w of waves) {
        const k = (Math.PI * 2) / (w.len * size);
        const speed = Math.sqrt(w.len * size) * 1.7;
        h += Math.sin(k * (i - w.dir * speed * t) + w.phase) * w.amp;
      }
      h = (h / norm) * 1.9 * swell;
      // Foam builds where a crest rises high, then slowly breaks up.
      foam[i] = Math.max(foam[i] * fade, smooth(0.62, 1.05, h));
      const lift = clamp01(0.5 + 0.5 * h);
      pal.add(out, i * 3, 0.12 + 0.78 * lift, 0.18 + 0.85 * lift ** 1.4);
      const f = foam[i] * (0.65 + 0.35 * Math.sin(i * 1.7 + t * 3.1) * Math.sin(i * 0.61 - t * 1.3));
      addRgb(out, i * 3, WHITE, f * 0.75);
    }
  };
};

const plasma: Factory = (n, _rand, noise) => (out, { t, intensity, size, pal }) => {
  const scale = 1 / (40 * size);
  for (let i = 0; i < n; i++) {
    const x = i * scale;
    // Noise folded through noise (domain warping): the shapes swirl into each other.
    const q = noise.fbm(x + t * 0.05, t * 0.07, 2);
    const r = noise.fbm(x + 3.1 * q + 1.7, t * 0.11 + 4.2, 2);
    const v = noise.fbm(x + 2.6 * r - t * 0.03, 8.3 + t * 0.05, 3);
    const hue = 0.5 + v * 1.1 + t * 0.035;
    const band = 0.5 + 0.5 * Math.sin((v + q) * 9 + t * 0.6);
    const b = 1 - intensity * 0.95 * (1 - band * band);
    pal.add(out, i * 3, pal.wave(hue), b * 1.05);
  }
};

const starlight: Factory = (n, rand) => {
  // Each LED twinkles on its own clock; when one twinkle ends, the next gets a new color.
  const phase = new Float32Array(n).map(() => rand());
  const period = new Float32Array(n).map(() => 2 + rand() * 5);
  const cycle = new Int32Array(n).fill(-1);
  const peak = new Float32Array(n);
  const lit = new Uint8Array(n);
  const color: Rgb[] = new Array(n);
  let shoot: { x: number; v: number } | null = null;
  let nextShoot = 3 + rand() * 6;
  const trail = new Float32Array(n * 3);
  return (out, { t, dt, intensity, size, pal }) => {
    const duty = 0.12 + 0.25 * size;
    const density = 0.15 + 0.85 * intensity;
    for (let i = 0; i < n; i++) {
      const u = phase[i] + t / period[i];
      const c = Math.floor(u);
      if (c !== cycle[i]) {
        cycle[i] = c;
        lit[i] = rand() < density ? 1 : 0;
        peak[i] = 0.35 + rand() * rand() * 1.1;
        color[i] = pal.pick(rand);
      }
      if (!lit[i]) continue;
      const w = fract(u) / duty;
      if (w >= 1) continue;
      // A quick rise and a long, soft fade, as a real star scintillates.
      const env = w < 0.2 ? smooth(0, 0.2, w) : Math.exp(-(w - 0.2) * 4.5) * (1 - smooth(0.85, 1, w));
      addRgb(out, i * 3, color[i], env * peak[i]);
      // A white glint right at the top of the brightest twinkles.
      if (peak[i] > 0.9 && w < 0.35) addRgb(out, i * 3, WHITE, env * (peak[i] - 0.9) * 2);
    }
    // Now and then a shooting star.
    const keep = Math.exp(-dt * 9);
    for (let i = 0; i < trail.length; i++) trail[i] *= keep;
    nextShoot -= dt * perLength(n) * 0.5;
    if (!shoot && nextShoot <= 0 && n > 12) {
      const dir = rand() < 0.5 ? -1 : 1;
      shoot = { x: dir > 0 ? rand() * n * 0.5 : n - rand() * n * 0.5, v: dir * (90 + rand() * 70) };
      nextShoot = 4 + rand() * 10;
    }
    if (shoot) {
      const prev = shoot.x;
      shoot.x += shoot.v * dt;
      streak(trail, n, prev, shoot.x, [0.85, 0.92, 1], 1.4, 0.6);
      if (shoot.x < -4 || shoot.x > n + 4 || rand() < dt * 0.7) shoot = null;
    }
    for (let i = 0; i < out.length; i++) out[i] += trail[i];
  };
};

interface Strike {
  c: number;
  w: number;
  age: number;
  flashes: { at: number; len: number; amp: number }[];
  branches: { c: number; w: number }[];
  seed: number;
  end: number;
  sheet: boolean;
}

const storm: Factory = (n, rand, noise) => {
  const strikes: Strike[] = [];
  let due = 1 + rand() * 2;
  return (out, { t, dt, intensity, size, pal }) => {
    // Low clouds roll by, dimly lit from inside.
    for (let i = 0; i < n; i++) {
      const cl = 0.5 + 0.5 * noise.fbm(i * 0.025 - t * 0.12, t * 0.05, 3);
      pal.add(out, i * 3, 0.12 + 0.3 * cl, 0.1 + 0.55 * cl * cl * cl);
    }
    due -= dt * (0.3 + 1.6 * intensity) * perLength(n) * 0.6;
    if (due <= 0) {
      due = 0.3 + rand() * 2;
      // One in three is lightning inside the clouds: a wide glow and no bolt.
      const sheet = rand() < 0.35;
      const w = (sheet ? 0 : 3 + rand() * 7) * size;
      const flashes = [];
      let at = 0;
      // A strike flickers: two to five flashes in about half a second.
      for (let f = 0, count = 2 + Math.floor(rand() * 4); f < count; f++) {
        const len = 0.03 + rand() * 0.07;
        flashes.push({ at, len, amp: f === 0 ? 1 : 0.4 + rand() * 0.8 });
        at += len + 0.03 + rand() * 0.12;
      }
      const branches = Array.from({ length: Math.floor(rand() * 3) }, () => ({ c: (rand() - 0.5) * w * 5, w: w * (0.3 + rand() * 0.5) }));
      if (sheet) for (const f of flashes) f.amp *= 0.45;
      strikes.push({ c: rand() * n, w: Math.max(w, sheet ? 6 * size : 0), age: 0, flashes, branches: sheet ? [] : branches, seed: rand() * 100, end: at + 0.5, sheet });
    }
    for (let s = strikes.length - 1; s >= 0; s--) {
      const k = strikes[s];
      k.age += dt;
      if (k.age > k.end) {
        strikes.splice(s, 1);
        continue;
      }
      // Brightness now: on during a flash, then a quick afterglow.
      let L = 0;
      for (const f of k.flashes) {
        if (k.age < f.at) continue;
        L = Math.max(L, k.age < f.at + f.len ? f.amp : f.amp * Math.exp(-(k.age - f.at - f.len) * 14));
      }
      if (L < 0.005) continue;
      const reach = k.w * 9;
      const lo = Math.max(0, Math.floor(k.c - reach));
      const hi = Math.min(n - 1, Math.ceil(k.c + reach));
      for (let i = lo; i <= hi; i++) {
        const d = i - k.c;
        // The sky lights up around the strike...
        const sky = Math.exp(-Math.abs(d) / (k.w * 2.5)) * 0.55;
        // ...and the bolt is a jagged, white-hot core with forks off to the side.
        let bolt = !k.sheet && Math.abs(d) < k.w ? 0.55 + 0.45 * noise.n2(i * 0.8, k.seed) : 0;
        for (const b of k.branches) if (Math.abs(d - b.c) < b.w) bolt = Math.max(bolt, 0.4 + 0.4 * noise.n2(i * 1.3, k.seed + 9));
        pal.add(out, i * 3, 0.7, sky * L);
        addRgb(out, i * 3, WHITE, bolt * L * 1.5);
      }
    }
  };
};

const raindrops: Factory = (n, rand) => {
  // Each drop sends a ring of ripples out both ways. Rings cross and add up, and they spread
  // and fade as they travel.
  const drops: { x: number; age: number; amp: number }[] = [];
  let due = 0;
  return (out, { dt, intensity, size, pal }) => {
    due -= dt * (0.4 + 3 * intensity) * perLength(n) * 0.5;
    while (due <= 0) {
      due += 0.3 + rand() * 0.9;
      if (drops.length < 60) drops.push({ x: rand() * n, age: 0, amp: 0.7 + rand() * 0.6 });
    }
    const speed = 16 * size;
    const wl = 4.2 * size;
    for (let d = drops.length - 1; d >= 0; d--) {
      drops[d].age += dt;
      if (drops[d].age > 4) drops.splice(d, 1);
    }
    for (let i = 0; i < n; i++) {
      let h = 0;
      let splash = 0;
      for (const d of drops) {
        const r = Math.abs(i - d.x);
        const front = speed * d.age;
        const width = wl * (0.9 + d.age * 0.9);
        const off = r - front;
        if (off > width * 2.5 || off < -width * 4) continue;
        // A wave train behind the front, damped as it travels.
        const env = Math.exp(-(off * off) / (2 * width * width)) * Math.exp(-d.age * 0.9) * d.amp;
        h += Math.cos((off / wl) * Math.PI * 2) * env;
        splash += Math.exp(-r * r * 0.5) * Math.exp(-d.age * 14) * d.amp;
      }
      const e = Math.tanh(h * 1.4);
      const lift = clamp01(Math.abs(e));
      pal.add(out, i * 3, 0.5 + 0.45 * e, 0.04 + lift ** 1.2 * 1.4);
      if (e > 0.55) addRgb(out, i * 3, WHITE, (e - 0.55) * 1.4);
      if (splash > 0.01) addRgb(out, i * 3, WHITE, splash * 1.6);
    }
  };
};

const candy: Factory = (n, rand) => {
  const glintAt = rand() * 40;
  const glints = new Float32Array(n);
  return (out, { t, dt, intensity, size, pal }) => {
    const colors = pal.stops;
    const m = colors.length;
    const width = 6 * size;
    const pos = t * 5;
    // Glints sweep along every few seconds, spaced so a long roofline has several at once.
    const spacing = Math.max(n, 90);
    const g = (t * 40 + glintAt) % (spacing * 1.3);
    for (let i = 0; i < n; i++) {
      // Stripe coordinate; the LED covers one unit of it, so edges blend over one LED.
      const s = (i - pos) / width;
      const band = Math.floor(s);
      const f = s - band;
      const edge = 1 / width;
      const a = colors[((band % m) + m) % m];
      const b = colors[(((band + 1) % m) + m) % m];
      const mix = clamp01((f - (1 - edge)) / edge);
      const c: Rgb = [a[0] + (b[0] - a[0]) * mix, a[1] + (b[1] - a[1]) * mix, a[2] + (b[2] - a[2]) * mix];
      // A soft sheen passes over the stripes.
      let shine = 0;
      for (let k = -1; k <= Math.ceil(n / spacing); k++) {
        const d = (i - (g - spacing * 0.3) - k * spacing) / (5 * size + 3);
        shine += Math.exp(-d * d);
      }
      shine *= intensity;
      addRgb(out, i * 3, c, 0.7 + 0.3 * shine);
      addRgb(out, i * 3, WHITE, shine * 0.9);
      // Sugar sparkle: a few LEDs glint for a moment.
      if (rand() < dt * 0.6 * intensity) glints[i] = 1;
      glints[i] *= Math.exp(-dt * 10);
      if (glints[i] > 0.02) addRgb(out, i * 3, WHITE, glints[i] * 0.8);
    }
  };
};

// ---------- Basics ----------
// The simple, standard effects: a steady color, a gradient, a chase... They take the palette's
// colors as they are, one by one, so with "My colors" you get exactly the colors you picked.

/** The k-th color of the palette, round and round. */
const stopAt = (pal: Pal, k: number): Rgb => pal.stops[((k % pal.stops.length) + pal.stops.length) % pal.stops.length];

function mixRgb(a: Rgb, b: Rgb, f: number): Rgb {
  return [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f];
}

function fillRgb(out: Float32Array, c: Rgb, k: number) {
  for (let i = 0; i < out.length; i += 3) addRgb(out, i, c, k);
}

/** Where LED i is in the palette when it spreads over `span` LEDs: from its first color to its last. */
function spread(pal: Pal, i: number, span: number): number {
  const x = i / span;
  return pal.cyclic ? (x * (pal.stops.length - 1)) / pal.stops.length : pal.wave(x);
}

const BLACK: Rgb = [0, 0, 0];

const solid: Factory = (n) => (out, { pal }) => {
  const m = pal.stops.length;
  for (let i = 0; i < n; i++) addRgb(out, i * 3, pal.stops[Math.min(m - 1, Math.floor((i * m) / n))], 1);
};

const gradient: Factory = (n) => (out, { size, pal }) => {
  // Size 50: the colors spread once over the string. Smaller: they repeat; bigger: they stretch.
  const span = Math.max(1, n - 1) * size;
  for (let i = 0; i < n; i++) pal.add(out, i * 3, spread(pal, i, span), 1);
};

const blocks: Factory = (n) => (out, { size, pal }) => {
  const w = Math.max(1, Math.round(3 * size));
  for (let i = 0; i < n; i++) addRgb(out, i * 3, stopAt(pal, Math.floor(i / w)), 1);
};

const rainbow: Factory = (n) => (out, { t, size, pal }) => {
  const len = 45 * size;
  for (let i = 0; i < n; i++) pal.add(out, i * 3, pal.wave(i / len - t * 0.22), 1);
};

const colorloop: Factory = () => (out, { t, pal }) => {
  // The palette's smooth blend lingers on each color a moment before it moves on.
  const hue = pal.cyclic ? t * 0.07 : pal.wave(t * 0.14);
  for (let i = 0; i < out.length; i += 3) pal.add(out, i, hue, 1);
};

const breathe: Factory = () => (out, { t, intensity, pal }) => {
  const ph = t / 4;
  const k = Math.floor(ph);
  const f = ph - k;
  const b = (1 - Math.cos(f * Math.PI * 2)) / 2;
  // Depth 100: down to dark. 0: only a little dimmer.
  const low = 0.6 - 0.6 * intensity;
  // The next color comes in while the lights are low.
  const c = mixRgb(stopAt(pal, k - 1), stopAt(pal, k), smooth(0, 0.2, f));
  fillRgb(out, c, low + (1 - low) * b * b);
};

const blink: Factory = () => (out, { t, intensity, pal }) => {
  const k = Math.floor(t);
  if (t - k < 0.1 + 0.8 * intensity) fillRgb(out, stopAt(pal, k), 1);
};

const strobe: Factory = () => {
  let last = -1;
  return (out, { t, intensity, pal }) => {
    const ph = t * 5;
    const k = Math.floor(ph);
    // Every flash shows for at least one frame, however fast it goes.
    const on = ph - k < 0.06 + 0.34 * intensity || k !== last;
    last = k;
    if (on) fillRgb(out, stopAt(pal, k), 1.3);
  };
};

const chase: Factory = (n) => (out, { t, intensity, size, pal }) => {
  const period = Math.max(2, Math.round(4 * size));
  const len = Math.max(0.6, period * (0.15 + 0.6 * intensity));
  const pos = t * 7;
  for (let i = 0; i < n; i++) {
    const p = i - pos;
    const k = Math.floor(p / period);
    const f = p - k * period;
    // How much of the LED (f to f + 1) a dot (0 to len, and period to period + len) covers.
    const cover = clamp01(Math.min(f + 1, len) - f) + Math.min(len, clamp01(f + 1 - period));
    if (cover > 0) addRgb(out, i * 3, stopAt(pal, f + 1 > period ? k + 1 : k), Math.min(1, cover));
  }
};

const wipe: Factory = (n) => (out, { t, intensity, size, pal }) => {
  const one = pal.stops.length === 1;
  const fill = 1 + n / 40;
  const hold = intensity * 2.5;
  const cycle = fill + hold;
  const k = Math.floor(t / cycle);
  const edge = 0.5 + 6 * (size - 0.35);
  // The soft edge runs off the end too, so the string is all the new color before the next one.
  const head = Math.min(1, (t - k * cycle) / fill) * (n - 1 + edge);
  const color = (j: number) => (one ? (((j % 2) + 2) % 2 === 0 ? pal.stops[0] : BLACK) : stopAt(pal, j));
  const from = color(k - 1);
  const to = color(k);
  for (let i = 0; i < n; i++) addRgb(out, i * 3, mixRgb(from, to, clamp01((head - i) / edge)), 1);
};

const twinkle: Factory = (n, rand) => {
  const v = new Float32Array(n);
  const rising = new Uint8Array(n);
  const col = new Uint8Array(n);
  return (out, { dt, intensity, size, pal }) => {
    const rate = (0.04 + 0.6 * intensity) / size;
    const up = dt / (0.25 * size);
    const down = dt / (0.8 * size);
    for (let i = 0; i < n; i++) {
      if (rising[i]) {
        v[i] += up;
        if (v[i] >= 1) {
          v[i] = 1;
          rising[i] = 0;
        }
      } else if (v[i] > 0) v[i] = Math.max(0, v[i] - down);
      else if (rand() < rate * dt) {
        rising[i] = 1;
        col[i] = Math.floor(rand() * pal.stops.length);
      }
      if (v[i] > 0) addRgb(out, i * 3, stopAt(pal, col[i]), v[i] * v[i]);
    }
  };
};

const sparkle: Factory = (n, rand) => {
  const g = new Float32Array(n);
  return (out, { dt, intensity, size, pal }) => {
    const rate = 0.03 + 0.9 * intensity;
    const keep = Math.exp(-dt * (14 / size));
    const span = Math.max(1, n - 1);
    for (let i = 0; i < n; i++) {
      pal.add(out, i * 3, pal.stops.length > 1 ? spread(pal, i, span) : 0, 0.75);
      g[i] *= keep;
      if (rand() < rate * dt) g[i] = 1;
      if (g[i] > 0.01) addRgb(out, i * 3, WHITE, g[i] * 1.2);
    }
  };
};

const bounce: Factory = (n) => {
  const trail = new Float32Array(n * 3);
  let last: number | null = null;
  return (out, { t, dt, intensity, size, pal }) => {
    const run = Math.max(0.6, (n - 1) / 45);
    const ph = t / run;
    const k = Math.floor(ph);
    const f = ph - k;
    const pos = (k % 2 === 0 ? f : 1 - f) * (n - 1);
    const c = stopAt(pal, k);
    const keep = Math.exp(-dt * (16 - 14 * intensity));
    const w = 0.5 + 1.2 * size;
    // The dot lights every LED it passed since the last frame, so a fast dot leaves no gaps.
    const a = last == null || Math.abs(pos - last) > n / 2 ? pos : Math.min(pos, last);
    const b = last == null || Math.abs(pos - last) > n / 2 ? pos : Math.max(pos, last);
    last = pos;
    for (let i = 0; i < n; i++) {
      const j = i * 3;
      trail[j] *= keep;
      trail[j + 1] *= keep;
      trail[j + 2] *= keep;
      const d = (i < a ? a - i : i > b ? i - b : 0) / w;
      if (d > 3) continue;
      const core = Math.exp(-d * d);
      trail[j] = Math.max(trail[j], c[0] * core);
      trail[j + 1] = Math.max(trail[j + 1], c[1] * core);
      trail[j + 2] = Math.max(trail[j + 2], c[2] * core);
    }
    out.set(trail);
  };
};

// ---------- 3-D effects ----------
// They light each LED by where it is (Params.space), so the same effect fills a bush, climbs a
// tree, or plays over the whole yard as one picture.

const wash: Factory = () => (out, { t, intensity, size, pal, along }) => {
  const n = along.length;
  const freq = 1.1 / size;
  const m = Math.max(2, pal.stops.length);
  for (let i = 0; i < n; i++) {
    const phase = along[i] * freq - t * 0.22;
    // Intensity 0: a soft gradient. 1: crisp bands of each color, with dark seams between.
    const k = phase * m;
    const band = Math.floor(k);
    const f = k - band;
    const stepped = (band + 0.5) / m;
    const hue = phase + (stepped - phase) * intensity * 0.9;
    const edge = Math.abs(f - 0.5) * 2;
    const v = 1 - intensity * 0.85 * smooth(0.55, 1, edge);
    pal.add(out, i * 3, pal.wave(hue), v);
  }
};

const scanner: Factory = (n) => {
  const trail = new Float32Array(n * 3);
  return (out, { t, dt, intensity, size, pal, along }) => {
    const cyc = t * 0.32;
    const pass = Math.floor(cyc * 2);
    const f = fract(cyc);
    const pos = f < 0.5 ? f * 2 : 2 - f * 2;
    const head = -0.06 + pos * 1.12;
    const color = pal.stops[((pass % pal.stops.length) + pal.stops.length) % pal.stops.length];
    const keep = Math.exp(-dt * (16 - 13 * intensity));
    const w = 0.012 + 0.03 * size;
    for (let i = 0; i < n; i++) {
      const j = i * 3;
      trail[j] *= keep;
      trail[j + 1] *= keep;
      trail[j + 2] *= keep;
      const d = (along[i] - head) / w;
      const core = Math.exp(-d * d);
      if (core < 0.002) continue;
      trail[j] = Math.max(trail[j], color[0] * core * 1.3);
      trail[j + 1] = Math.max(trail[j + 1], color[1] * core * 1.3);
      trail[j + 2] = Math.max(trail[j + 2], color[2] * core * 1.3);
    }
    out.set(trail);
    // The beam itself is white-hot.
    for (let i = 0; i < n; i++) {
      const d = (along[i] - head) / (w * 0.6);
      if (d > 3 || d < -3) continue;
      addRgb(out, i * 3, WHITE, Math.exp(-d * d) * 0.7);
    }
  };
};

const bonfire: Factory = (n, rand, noise) => {
  const sparks: { x: number; y: number; z: number; v: number; life: number; max: number; ph: number }[] = [];
  let due = 0;
  return (out, { t, dt, intensity, size, pal, space, reverse }) => {
    const f = 3.2 / size;
    const flip = reverse ? -1 : 1;
    const reach = 1.3 - 0.75 * intensity;
    for (let i = 0; i < n; i++) {
      const h = reverse ? 1 - unitY(space, i) : unitY(space, i);
      const x = space.x[i] * f;
      const y = space.y[i] * f * flip;
      const z = space.z[i] * f;
      // Tongues of flame that rise: the noise moves up through space.
      const body = noise.fbm3(x, y - t * 1.5, z + t * 0.25, 3);
      const lick = noise.n3(x * 2.3 + 5, y * 2.3 - t * 3.2, z * 2.3);
      const heat = clamp01((0.95 + 0.95 * body + 0.35 * lick - h * reach) * 0.85);
      pal.add(out, i * 3, heat, smooth(0.08, 0.55, heat) * 1.2);
    }
    // Sparks rise from the flames and burn out.
    due -= dt * (3 + 10 * intensity);
    while (due <= 0) {
      due += 0.5 + rand();
      if (sparks.length < 60) {
        const max = 0.8 + rand() * 1.4;
        sparks.push({ x: (rand() - 0.5) * space.ex, y: (-space.ey / 2) * flip + (rand() - 0.2) * space.ey * 0.4 * flip, z: (rand() - 0.5) * space.ez, v: (0.15 + rand() * 0.25) * flip, life: max, max, ph: rand() * 6 });
      }
    }
    const r = Math.max(space.pitch * 1.3, 0.008);
    for (let s = sparks.length - 1; s >= 0; s--) {
      const p = sparks[s];
      p.life -= dt;
      if (p.life <= 0) {
        sparks.splice(s, 1);
        continue;
      }
      p.y += p.v * dt;
      p.x += Math.sin(t * 3 + p.ph) * 0.03 * dt;
      const a = p.life / p.max;
      glow3(out, space, p.x, p.y, p.z, r, [1, 0.55 + 0.35 * a, 0.15 * a], a * 1.4);
    }
  };
};

const vortex: Factory = () => (out, { t, intensity, size, pal, space, reverse }) => {
  const n = space.x.length;
  // Tall things (a tree) spin around the vertical axis; flat things like a pinwheel facing the street.
  const tall = space.ey >= 0.8 * Math.max(space.ex, space.ez);
  const arms = 1 + Math.round(intensity * 5);
  const twist = 1.4 * size;
  const spin = (reverse ? -1 : 1) * t * 0.16;
  for (let i = 0; i < n; i++) {
    let a: number;
    let along: number;
    if (tall) {
      a = Math.atan2(space.z[i], space.x[i]);
      along = unitY(space, i);
    } else {
      a = Math.atan2(space.y[i], space.x[i]);
      along = Math.hypot(space.x[i], space.y[i]) * 2;
    }
    const ph = arms * (a / (Math.PI * 2) - spin) + along * twist * 1.5;
    const c = 0.5 + 0.5 * Math.cos(ph * Math.PI * 2);
    pal.add(out, i * 3, pal.wave(ph / arms), 0.08 + 1.0 * c * c);
    if (c > 0.93) addRgb(out, i * 3, WHITE, (c - 0.93) * 4);
  }
};

const shockwave: Factory = (_n, rand) => {
  const rings: { x: number; y: number; z: number; age: number; color: Rgb; amp: number }[] = [];
  let due = 0.1;
  return (out, { dt, intensity, size, pal, space, dir }) => {
    const n = space.x.length;
    const R = 0.5 * Math.hypot(space.ex, space.ey, space.ez) || 0.5;
    const speed = 0.5;
    const inward = dir === 'in';
    due -= dt * (0.35 + 1.6 * intensity);
    while (due <= 0) {
      due += 0.5 + rand();
      if (rings.length < 14)
        rings.push(
          inward
            ? { x: 0, y: 0, z: 0, age: 0, color: pal.pick(rand), amp: 0.8 + rand() * 0.5 }
            : { x: (rand() - 0.5) * space.ex, y: (rand() - 0.5) * space.ey, z: (rand() - 0.5) * space.ez, age: 0, color: pal.pick(rand), amp: 0.8 + rand() * 0.5 }
        );
    }
    const w = Math.max(space.pitch * 1.5, 0.02 + 0.05 * size);
    const life = (2.2 * R) / speed;
    for (let r = rings.length - 1; r >= 0; r--) {
      const g = rings[r];
      g.age += dt;
      const rad = inward ? R * 1.1 - speed * g.age : speed * g.age;
      if (g.age > life || rad < -w) {
        rings.splice(r, 1);
        continue;
      }
      const amp = g.amp * (inward ? smooth(0, 0.3, g.age) * (0.4 + 0.6 * smooth(R * 1.1, 0, rad)) : Math.exp(-g.age * 0.55));
      for (let i = 0; i < n; i++) {
        const d = Math.hypot(space.x[i] - g.x, space.y[i] - g.y, space.z[i] - g.z);
        const off = (d - rad) / w;
        if (off > 3 || off < -3) continue;
        const v = Math.exp(-off * off) * amp;
        addRgb(out, i * 3, g.color, v * 1.2);
        addRgb(out, i * 3, WHITE, v * v * v * 0.5);
      }
      // A flash where it starts.
      if (!inward && g.age < 0.3) glow3(out, space, g.x, g.y, g.z, w * 1.5, WHITE, (1 - g.age / 0.3) * 1.2);
    }
  };
};

const nebula: Factory = (_n, _rand, noise) => (out, { t, intensity, size, pal, space, dir }) => {
  const n = space.x.length;
  const f = 2.2 / size;
  const [vx, vy, vz] = DIR_VECTORS[dir];
  const ox = -vx * t * 0.12 * f;
  const oy = -vy * t * 0.12 * f;
  const oz = -vz * t * 0.12 * f;
  for (let i = 0; i < n; i++) {
    const x = space.x[i] * f + ox;
    const y = space.y[i] * f + oy;
    const z = space.z[i] * f + oz;
    // Noise folded through noise: the cloud swirls as it drifts.
    const q = noise.fbm3(x + t * 0.03, y, z - t * 0.02, 2);
    const v = noise.fbm3(x + 1.8 * q + 3.1, y - 1.2 * q + t * 0.04, z + 1.5 * q, 3);
    const dens = clamp01(0.5 + v * 1.6);
    pal.add(out, i * 3, pal.wave(0.5 + v * 1.3 + t * 0.02), 0.1 + 1.0 * dens ** (1 + intensity * 2.5));
    // A few stars twinkle in the cloud.
    const h = hash01(i, 3);
    if (h > 0.985) addRgb(out, i * 3, WHITE, 0.25 + 0.45 * (0.5 + 0.5 * Math.sin(t * 2.5 + h * 300)));
  }
};

const snowfall: Factory = (n, rand) => {
  const flakes: { x: number; y: number; v: number; ph: number; c: number }[] = [];
  const settle = new Float32Array(n);
  let started = false;
  return (out, { t, dt, intensity, size, pal, space, reverse }) => {
    const count = Math.round(25 + 140 * intensity);
    const top = space.ey / 2 + 0.06;
    const W = Math.max(space.ex, 0.2) + 0.1;
    const dirY = reverse ? 1 : -1;
    const spawn = (anywhere: boolean) => ({
      x: (rand() - 0.5) * W,
      y: anywhere ? (rand() - 0.5) * 2 * top : -dirY * top,
      v: 0.05 + rand() * 0.06,
      ph: rand() * 6.28,
      c: Math.floor(rand() * 16)
    });
    if (!started) {
      started = true;
      while (flakes.length < count) flakes.push(spawn(true));
    }
    while (flakes.length < count) flakes.push(spawn(false));
    if (flakes.length > count) flakes.length = count;
    const keep = Math.exp(-dt * 0.35);
    for (let i = 0; i < n; i++) settle[i] *= keep;
    const r = Math.max(space.pitch * 1.6, 0.012) * size;
    const inv = 1 / (r * r);
    const cut = 9 * r * r;
    const m = pal.stops.length;
    for (let k = 0; k < flakes.length; k++) {
      const fl = flakes[k];
      fl.y += dirY * fl.v * dt;
      fl.x += Math.sin(t * 1.3 + fl.ph) * 0.02 * dt;
      if (fl.y * -dirY < -top) flakes[k] = spawn(false);
      const c = pal.stops[fl.c % m];
      // Seen from the street: by front-view distance, so flakes pass in front of every object.
      for (let i = 0; i < n; i++) {
        const dx = space.x[i] - fl.x;
        if (dx > 3 * r || dx < -3 * r) continue;
        const dy = space.y[i] - fl.y;
        const d2 = dx * dx + dy * dy;
        if (d2 > cut) continue;
        const p = Math.exp(-d2 * inv);
        addRgb(out, i * 3, c, p * 1.1);
        if (p * 0.8 > settle[i]) settle[i] = p * 0.8;
      }
    }
    const glowC = pal.stops[0];
    for (let i = 0; i < n; i++) if (settle[i] > 0.01) addRgb(out, i * 3, glowC, settle[i] * 0.35);
  };
};

const fireflies: Factory = (_n, rand, noise) => {
  const flies = Array.from({ length: 18 }, () => ({ seed: rand() * 200, ph: rand() * 10, rate: 0.12 + rand() * 0.25 }));
  return (out, { t, intensity, size, pal, space }) => {
    const count = 3 + Math.round(intensity * 15);
    const r = Math.max(space.pitch * 2.5, 0.06 * size);
    const m = pal.stops.length;
    // A shallow target (a house front with bushes before it): fireflies light what they pass in front of.
    const flat = space.ez < 0.5 * Math.max(space.ex, space.ey);
    for (let k = 0; k < count; k++) {
      const f = flies[k];
      // Lazy paths through the box: smooth noise for each axis.
      const x = clamp(noise.n2(f.seed, t * 0.07) * 1.4, -0.5, 0.5) * (space.ex + 0.05);
      const y = clamp(noise.n2(f.seed + 31.7, t * 0.06) * 1.4, -0.5, 0.5) * (space.ey + 0.05);
      const z = clamp(noise.n2(f.seed + 63.1, t * 0.05) * 1.4, -0.5, 0.5) * (space.ez + 0.05);
      const blink = smooth(0.05, 0.5, 0.5 + 0.5 * Math.sin(t * f.rate * Math.PI * 2 + f.ph));
      glow3(out, space, x, y, z, r, pal.stops[k % m], 1.6 * blink, flat);
      glow3(out, space, x, y, z, r * 0.45, WHITE, 0.6 * blink, flat);
    }
  };
};

const clamp = (x: number, a: number, b: number) => (x < a ? a : x > b ? b : x);

const starburst: Factory = (_n, rand) => {
  const EMBER: Rgb = [1, 0.4, 0.1];
  const shells: { x: number; y: number; z: number; age: number; rise: number; life: number; R: number; c1: Rgb; c2: Rgb; seed: number }[] = [];
  let due = 0.2;
  return (out, { dt, intensity, size, pal, space }) => {
    const n = space.x.length;
    due -= dt * (0.3 + 1.4 * intensity);
    while (due <= 0) {
      due += 0.4 + rand() * 1.1;
      if (shells.length < 10) {
        const c1 = pal.pick(rand);
        shells.push({
          x: (rand() - 0.5) * space.ex * 0.9,
          y: space.ey * (rand() * 0.45 - 0.05),
          z: (rand() - 0.5) * space.ez,
          age: 0,
          rise: 0.45 + rand() * 0.3,
          life: 1.6 + rand() * 1.2,
          R: (0.18 + 0.17 * rand()) * size,
          c1,
          c2: rand() < 0.4 ? pal.pick(rand) : c1,
          seed: Math.floor(rand() * 1000)
        });
      }
    }
    const bottom = -space.ey / 2 - 0.05;
    for (let s = shells.length - 1; s >= 0; s--) {
      const sh = shells[s];
      sh.age += dt;
      if (sh.age < sh.rise) {
        // The rocket climbs to where it bursts.
        const u = sh.age / sh.rise;
        const y = bottom + (sh.y - bottom) * (1 - (1 - u) * (1 - u));
        glow3(out, space, sh.x, y, sh.z, Math.max(space.pitch * 1.5, 0.012), [1, 0.75, 0.4], 1.2);
        continue;
      }
      const a = sh.age - sh.rise;
      const u = a / sh.life;
      if (u >= 1) {
        shells.splice(s, 1);
        continue;
      }
      const rad = sh.R * (1 - Math.exp(-a * 4));
      const cy = sh.y - 0.1 * a * a;
      const w = Math.max(space.pitch * 2, 0.03 + 0.04 * size) * (1 + u);
      const bright = (1 - u) ** 1.4 * 2.2;
      const hot = 1 - smooth(0, 0.15, u);
      const cool = smooth(0.5, 1, u);
      const step = Math.floor(a * 20);
      for (let i = 0; i < n; i++) {
        const d = Math.hypot(space.x[i] - sh.x, space.y[i] - cy, space.z[i] - sh.z);
        const off = (d - rad) / w;
        if (off > 3 || off < -3) continue;
        let v = Math.exp(-off * off) * bright;
        // Late in the burst the sparks crackle.
        if (u > 0.5) v *= hash01(i + sh.seed, step) > 0.5 ? 1.8 : 0.15;
        const base = hash01(i, sh.seed) < 0.5 ? sh.c1 : sh.c2;
        const c: Rgb = [0, 1, 2].map((j) => (base[j] + (EMBER[j] - base[j]) * cool) * (1 - hot) + hot) as Rgb;
        addRgb(out, i * 3, c, v);
      }
      if (a < 0.15) glow3(out, space, sh.x, sh.y, sh.z, sh.R * 0.5 + 0.02, WHITE, (1 - a / 0.15) * 1.4);
    }
  };
};

const equalizer: Factory = (_n, _rand, noise) => {
  const peaks = new Float32Array(64);
  const levels = new Float32Array(64);
  return (out, { t, dt, intensity, size, pal, space, reverse }) => {
    const n = space.x.length;
    const K = Math.max(3, Math.min(48, Math.round(14 / size)));
    // A beat at 120 per minute (at normal speed); the low bars (left) follow it most.
    const beat = Math.exp(-fract(t * 2) * 5);
    for (let b = 0; b < K; b++) {
      const base = clamp01(0.5 + 0.8 * noise.n2(b * 0.61 + 3, t * 1.3));
      const bass = b < K / 3 ? beat : beat * 0.4;
      levels[b] = clamp01(0.02 + base * base * (0.55 + 0.45 * intensity) + bass * 0.45 * (0.4 + intensity));
      peaks[b] = Math.max(levels[b], peaks[b] - dt * 0.45);
    }
    // A flat object (one level, like a straight roofline) shows the bars as brightness.
    const flat = space.ey < 0.05;
    for (let i = 0; i < n; i++) {
      const X = unitX(space, i) * K;
      const b = Math.min(K - 1, Math.floor(X));
      const edge = X - b;
      const gap = K <= 24 && (edge < 0.07 || edge > 0.93) ? 0.25 : 1;
      if (flat) {
        const v = levels[b];
        pal.add(out, i * 3, v, v * v * 1.3 * gap);
        continue;
      }
      const h = reverse ? 1 - unitY(space, i) : unitY(space, i);
      const lit = smooth(levels[b] + 0.03, levels[b] - 0.03, h);
      if (lit > 0) pal.add(out, i * 3, h, 1.1 * lit * gap);
      const pk = Math.abs(h - peaks[b]);
      if (pk < 0.04) addRgb(out, i * 3, WHITE, (1 - pk / 0.04) * 0.9 * gap);
    }
  };
};

const FACTORIES: Record<EffectId, Factory> = {
  solid,
  gradient,
  blocks,
  rainbow,
  colorloop,
  breathe,
  blink,
  strobe,
  chase,
  wipe,
  twinkle,
  sparkle,
  bounce,
  aurora,
  fireworks,
  inferno,
  meteors,
  ocean,
  plasma,
  starlight,
  storm,
  raindrops,
  candy,
  wash,
  scanner,
  bonfire,
  vortex,
  shockwave,
  nebula,
  snowfall,
  fireflies,
  starburst,
  equalizer
};

/** One running effect on `n` LEDs: along a string (1-D), or at the places in `space` (3-D). */
export class EffectRunner {
  readonly n: number;
  readonly effect: EffectId;
  private draw: Draw;
  private t = 0;
  private pal: Pal | null = null;
  private palKey = '';
  private buf: Float32Array;
  private space: Space;
  private along: Float32Array | null = null;
  private alongDir: Direction | null = null;

  constructor(effect: EffectId, n: number, seed = 1, space?: Space) {
    this.n = n;
    this.effect = effect;
    const rand = seededRandom(seed);
    this.draw = (FACTORIES[effect] ?? FACTORIES.aurora)(n, rand, new Noise(rand));
    this.buf = new Float32Array(n * 3);
    this.space = space && space.x.length === n ? space : lineSpace(n);
  }

  /** New positions for the same LEDs (an object was moved): the effect goes on without a restart. */
  setSpace(space: Space) {
    if (space.x.length !== this.n || space === this.space) return;
    this.space = space;
    this.along = null;
  }

  /**
   * Moves the effect on by `dt` seconds of real time and returns its colors (linear RGB, one
   * triple per LED, brightness applied). The settings can change between frames: a new speed
   * changes the pace from now on, without a jump.
   */
  render(dt: number, s: EffectSettings): Float32Array {
    const key = `${s.palette}:${s.colors?.join(',') ?? ''}`;
    if (!this.pal || key !== this.palKey) {
      const info = paletteInfo(s.palette);
      this.pal = new Pal(paletteColors(s), info.cyclic ?? false);
      this.palKey = key;
    }
    const dir = effectDirection(s);
    if (!this.along || this.alongDir !== dir) {
      this.along = directionCoord(this.space, dir);
      this.alongDir = dir;
    }
    const pace = paceOf(s);
    const step = Math.min(0.1, Math.max(0, dt)) * pace;
    this.t += step;
    this.buf.fill(0);
    this.draw(this.buf, {
      t: this.t,
      dt: step,
      intensity: clamp01(s.intensity),
      size: 2 ** ((clamp01(s.size) - 0.5) * 3),
      pal: this.pal,
      space: this.space,
      dir,
      along: this.along,
      reverse: !!s.reverse
    });
    const k = clamp01(s.brightness);
    if (k !== 1) for (let i = 0; i < this.buf.length; i++) this.buf[i] *= k;
    return this.buf;
  }

  /**
   * Starts a new effect as if it had been running for `seconds` already (to show a moment in
   * the middle of a sequence): it jumps ahead, then runs the last `warm` seconds, so particles
   * and trails are where they would be. Effects that follow the clock alone are exact.
   */
  warmUp(seconds: number, s: EffectSettings, warm = 2.5) {
    const w = Math.max(0, Math.min(seconds, warm));
    this.t = Math.max(0, seconds - w) * paceOf(s);
    const steps = Math.round(w * 30);
    for (let k = 0; k < steps; k++) this.render(w / steps, s);
  }
}

const paceOf = (s: Pick<EffectSettings, 'speed'>) => 2 ** ((clamp01(s.speed) - 0.5) * 4);

const sameInts = (a: Int32Array, b: ArrayLike<number>) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

interface Run {
  /** The settings it plays: an effect key of the scene, or a clip of a sequence. */
  src: string;
  runner: EffectRunner;
  /** Stage LEDs, in the order the effect runs over them. */
  leds: Int32Array;
  /** 3-D: the LEDs whose box makes the space, and the stage the space is for. */
  box: Int32Array | null;
  stage: Stage | null;
  /** Ids of the objects it lights. */
  fixtures: string[];
}

/**
 * The running effects of a scene or of a sequence's clips, by run key. Rebuilt with begin/add/
 * commit whenever the layout or the settings change: a run whose effect and LEDs stay the same
 * keeps its runner, so it goes on smoothly.
 */
export class RunSet {
  private runs = new Map<string, Run>();
  private next: Map<string, Run> | null = null;

  begin() {
    this.next = new Map();
  }

  /**
   * Plays `s` on `leds` (stage indexes). 1-D: along them in this order (reversed with the reverse
   * setting). 3-D: at their places, in the box of `box`. Returns true when the runner is new.
   */
  add(stage: Stage, key: string, src: string, s: EffectSettings, leds: number[], box: number[], fixtures: string[], seed = key): boolean {
    if (!leds.length || !this.next) return false;
    const spatial = isSpatial(s.effect);
    if (!spatial && s.reverse) leds = [...leds].reverse();
    const old = this.runs.get(key);
    const same = !!old && old.runner.effect === s.effect && sameInts(old.leds, leds);
    let runner = same ? old!.runner : null;
    let boxArr: Int32Array | null = null;
    if (spatial) {
      // Keep the space when nothing about it changed (sliders call this on every move).
      const reuse = same && old!.box && old!.stage === stage && sameInts(old!.box, box);
      boxArr = reuse ? old!.box : Int32Array.from(box);
      const space = reuse ? null : stageSpace(stage, leds, box);
      if (!runner) runner = new EffectRunner(s.effect, leds.length, hashString(seed), space ?? undefined);
      else if (space) runner.setSpace(space);
    }
    runner ??= new EffectRunner(s.effect, leds.length, hashString(seed));
    this.next.set(key, { src, runner, leds: same ? old!.leds : Int32Array.from(leds), box: boxArr, stage, fixtures });
    return !same;
  }

  commit() {
    if (this.next) this.runs = this.next;
    this.next = null;
  }

  get(key: string) {
    return this.runs.get(key);
  }

  keys() {
    return this.runs.keys();
  }

  values() {
    return this.runs.values();
  }

  get size() {
    return this.runs.size;
  }
}

/** For each object of the layout: the offsets (within it) of its LEDs that are in use, in order. */
function activeOffsets(f: Fixture, count: number): number[] {
  const on = activeLeds(f);
  const out: number[] = [];
  for (let i = 0; i < count; i++) if (on[i] ?? 1) out.push(i);
  return out;
}

/**
 * Plays effects on the yard, its devices, objects and their segments, into one frame for every
 * LED of the stage. A segment's effect wins over its object's, an object's over its device's
 * ("@<id>"), and a device's over the yard's ("*").
 * LEDs with no effect stay dark, and so do LEDs in skipped segments: a 1-D effect runs over the
 * lit LEDs only, so it flows across a skipped stretch without a gap. A 1-D effect on the yard
 * or a device plays on each of its objects, along its own string; a 3-D one is one picture.
 */
export class EffectScene {
  private stage: Stage | null = null;
  private layout: Pick<Layout, 'fixtures'> | null = null;
  private effects: Record<string, EffectSettings> = {};
  private runs = new RunSet();

  constructor(stage: Stage, layout: Pick<Layout, 'fixtures'>, effects: Record<string, EffectSettings>) {
    this.setStage(stage, layout);
    this.setEffects(effects);
  }

  /** A new or changed layout. Effects on objects that keep their LEDs keep running. */
  setStage(stage: Stage, layout: Pick<Layout, 'fixtures'>) {
    this.stage = stage;
    this.layout = layout;
    this.sync();
  }

  /** New settings. An object whose effect stays the same keeps running smoothly. */
  setEffects(effects: Record<string, EffectSettings>) {
    this.effects = effects;
    this.sync();
  }

  /** The effect keys (the yard, objects and segments) that play now. */
  playing(): string[] {
    return [...new Set([...this.runs.values()].map((r) => r.src))];
  }

  /** The ids of the objects that play an effect now: their own, a segment's, or the yard's. */
  objects(): string[] {
    return [...new Set([...this.runs.values()].flatMap((r) => r.fixtures))];
  }

  private sync() {
    const stage = this.stage;
    const layout = this.layout;
    if (!stage || !layout) return;
    const yard = this.effects[YARD];
    const spatial = new Map<string, { leds: number[]; fixtures: string[] }>();
    const allActive: number[] = [];
    this.runs.begin();
    layout.fixtures.forEach((f, fi) => {
      const sf = stage.fixtures[fi];
      if (!sf || sf.id !== f.id) return;
      const on = activeOffsets(f, sf.count).map((i) => sf.offset + i);
      for (const i of on) allActive.push(i);
      // Segments with their own effect first; the object's effect fills the rest of the line.
      const taken = new Uint8Array(sf.count);
      if (isLine(f)) {
        for (let k = 0; k < f.points.length - 1; k++) {
          const key = effectKey(f.id, k);
          const s = this.effects[key];
          if (!s) continue;
          const { lo, hi } = segmentLeds(f, k);
          const leds: number[] = [];
          for (let i = lo; i <= hi && i < sf.count; i++) {
            if (!taken[i] && stage.active[sf.offset + i]) leds.push(sf.offset + i);
            taken[i] = 1;
          }
          this.runs.add(stage, key, key, s, leds, leds, [f.id]);
        }
      }
      const rest = on.filter((i) => !taken[i - sf.offset]);
      const s = this.effects[f.id];
      if (s) {
        this.runs.add(stage, f.id, f.id, s, rest, on, [f.id]);
        return;
      }
      if (!rest.length) return;
      // The device's effect, else the yard's: a 1-D one along this object's string, a 3-D one in
      // one picture over all the objects it reaches.
      const dk = f.deviceId ? deviceKey(f.deviceId) : null;
      const src = dk && this.effects[dk] ? dk : yard ? YARD : null;
      if (!src) return;
      const fs = this.effects[src];
      if (isSpatial(fs.effect)) {
        const g = spatial.get(src) ?? { leds: [], fixtures: [] };
        for (const i of rest) g.leds.push(i);
        g.fixtures.push(f.id);
        spatial.set(src, g);
      } else this.runs.add(stage, `${src}:${f.id}`, src, fs, rest, on, [f.id], `${src}:${f.id}`);
    });
    // A 3-D effect is placed in the box of the whole yard, so devices with the same one line up.
    for (const [src, g] of spatial) this.runs.add(stage, src, src, this.effects[src], g.leds, allActive, g.fixtures);
    this.runs.commit();
  }

  /** Draws the next frame into `out` (3 floats per stage LED). */
  update(dt: number, out: Float32Array) {
    out.fill(0);
    for (const { src, runner, leds } of this.runs.values()) {
      const s = this.effects[src];
      if (!s || !leds.length) continue;
      const buf = runner.render(dt, s);
      for (let j = 0; j < leds.length; j++) {
        const k = leds[j] * 3;
        if (k + 2 >= out.length) continue;
        out[k] = buf[j * 3];
        out[k + 1] = buf[j * 3 + 1];
        out[k + 2] = buf[j * 3 + 2];
      }
    }
  }
}

/**
 * Linear color (0..1, may go above) to bytes, with a soft shoulder so bright, added-up colors
 * roll off instead of clipping flat. The games use the same curve.
 */
export function toBytes<T extends Uint8Array>(data: Float32Array, out: T): T {
  for (let i = 0; i < data.length; i++) {
    const v = data[i];
    out[i] = Math.round(255 * (v <= 0 ? 0 : v >= 1.5 ? 1 : v < 0.8 ? v : 0.8 + (v - 0.8) * 0.2857));
  }
  return out;
}
