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
  | 'equalizer'
  | 'hyperspace'
  | 'digitalrain'
  | 'tesla'
  | 'blackhole'
  | 'lavalamp'
  | 'helix'
  | 'hologram'
  | 'orbits'
  | 'supernova'
  | 'kaleidoscope';
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
  | 'matrix'
  | 'plasma'
  | 'lava'
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
  { id: 'equalizer', name: 'Equalizer', description: 'Bars of light bounce to a beat across the yard, like a music visualizer, with peaks that fall slowly.', palette: 'spectrum', intensity: 'Energy', size: 'Bar width', energy: 0.8, space: '3d', reverse: 'Bars hang from the top' },
  {
    id: 'hyperspace',
    name: 'Hyperspace',
    description: 'Stars stream out of the middle of the yard as if you fly through them. Every few seconds they stretch into streaks, and the jump ends in a white flash.',
    palette: 'ice',
    intensity: 'Stars',
    size: 'Streak length',
    energy: 0.85,
    space: '3d',
    directions: ['out', 'in']
  },
  { id: 'digitalrain', name: 'Digital rain', description: 'Columns of glowing code pour down the house, each drop with a white-hot head and a flickering trail.', palette: 'matrix', intensity: 'Rain', size: 'Column width', energy: 0.55, space: '3d', reverse: 'Rain upward' },
  { id: 'tesla', name: 'Plasma globe', description: 'Crackling tendrils of electricity reach from a glowing core out to every corner, wander, fork and flicker.', palette: 'plasma', intensity: 'Tendrils', size: 'Bolt width', energy: 0.7, space: '3d' },
  { id: 'blackhole', name: 'Black hole', description: 'A dark hole with a burning ring of light; a tilted disk of fire swirls around it, faster near the middle, and now and then jets shoot up and down.', palette: 'fire', intensity: 'Jets', size: 'Hole size', energy: 0.45, space: '3d', reverse: 'Spin the other way' },
  { id: 'lavalamp', name: 'Lava lamp', description: 'Big glowing blobs rise, sink, stretch and melt into each other, all through the yard.', palette: 'lava', intensity: 'Blobs', size: 'Blob size', energy: 0.25, space: '3d' },
  { id: 'helix', name: 'Double helix', description: 'Two strands of light twist around each other across the yard or up a tree, joined by colored rungs, with a pulse running along them.', palette: 'neon', intensity: 'Rungs', size: 'Twist length', energy: 0.45, space: '3d', reverse: 'Twist the other way' },
  { id: 'hologram', name: 'Hologram', description: 'A wireframe cube, a diamond and a four-dimensional tesseract turn in the air over the yard, with scan lines and glitches.', palette: 'ice', intensity: 'Glitch', size: 'Line width', energy: 0.55, space: '3d' },
  { id: 'orbits', name: 'Orbits', description: 'Comets with long tails race around a glowing nucleus on tilted orbits, like an atom, in front of and behind each other.', palette: 'party', intensity: 'Comets', size: 'Comet size', energy: 0.55, space: '3d' },
  { id: 'supernova', name: 'Supernova', description: 'A star shudders and collapses, explodes in a flash, and a ragged shock wave rolls over the yard; it leaves a glowing cloud and a spinning pulsar.', palette: 'sunset', intensity: 'Afterglow', size: 'Blast size', energy: 0.9, space: '3d' },
  { id: 'kaleidoscope', name: 'Kaleidoscope', description: 'Colors fold into mirrored wedges around the middle of the yard and keep turning, with glints along the mirrors.', palette: 'rainbow', intensity: 'Mirrors', size: 'Pattern size', energy: 0.5, space: '3d', reverse: 'Turn the other way' }
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
  { id: 'matrix', name: 'Code green', colors: ['#002a08', '#00a028', '#30ff60', '#c8ffd0'] },
  { id: 'plasma', name: 'Plasma', colors: ['#7a2cff', '#ff40ff', '#40b0ff', '#c070ff'], cyclic: true },
  { id: 'lava', name: 'Lava', colors: ['#ff1a00', '#ff7a00', '#ff0060', '#ffc400'], cyclic: true },
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
  /** The color at t (as in add), as RGB. */
  at(t: number): Rgb {
    const o = new Float32Array(3);
    this.add(o, 0, t, 1);
    return [o[0], o[1], o[2]];
  }
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

// ---------- 3-D shows ----------
// Big pictures for the whole yard: most are drawn as the street sees them (by x and y), so the
// house front becomes one screen; the ones with depth (orbits, the plasma globe) also thread
// through a tree.

/** Where on the last segment segD2 measured the nearest point is, 0..1. */
let segT = 0;

/** Squared distance from p to the segment a..b (sets segT). */
function segD2(px: number, py: number, pz: number, ax: number, ay: number, az: number, bx: number, by: number, bz: number): number {
  const dx = bx - ax;
  const dy = by - ay;
  const dz = bz - az;
  const L = dx * dx + dy * dy + dz * dz;
  let u = L > 1e-12 ? ((px - ax) * dx + (py - ay) * dy + (pz - az) * dz) / L : 0;
  u = u < 0 ? 0 : u > 1 ? 1 : u;
  segT = u;
  const ex = ax + dx * u - px;
  const ey = ay + dy * u - py;
  const ez = az + dz * u - pz;
  return ex * ex + ey * ey + ez * ez;
}

/**
 * Adds a glowing line from a to b, `w` wide: color ca at a with brightness ka, fading to cb and
 * kb at b. `flat`: by front-view distance, as seen from the street.
 */
function line3(out: Float32Array, sp: Space, ax: number, ay: number, az: number, bx: number, by: number, bz: number, w: number, ca: Rgb, ka: number, cb: Rgb, kb: number, flat = false) {
  if (ka <= 0 && kb <= 0) return;
  const m = 3 * w;
  const x0 = Math.min(ax, bx) - m;
  const x1 = Math.max(ax, bx) + m;
  const y0 = Math.min(ay, by) - m;
  const y1 = Math.max(ay, by) + m;
  const inv = 1 / (w * w);
  const cut = 9 * w * w;
  const n = sp.x.length;
  for (let i = 0; i < n; i++) {
    const x = sp.x[i];
    if (x < x0 || x > x1) continue;
    const y = sp.y[i];
    if (y < y0 || y > y1) continue;
    const d2 = flat ? segD2(x, y, 0, ax, ay, 0, bx, by, 0) : segD2(x, y, sp.z[i], ax, ay, az, bx, by, bz);
    if (d2 > cut) continue;
    const u = segT;
    const g = Math.exp(-d2 * inv) * (ka + (kb - ka) * u);
    const j = i * 3;
    out[j] += (ca[0] + (cb[0] - ca[0]) * u) * g;
    out[j + 1] += (ca[1] + (cb[1] - ca[1]) * u) * g;
    out[j + 2] += (ca[2] + (cb[2] - ca[2]) * u) * g;
  }
}

/** Adds a glowing path through `count` points (x, y, z each), without bright knots where its pieces meet. */
function path3(out: Float32Array, sp: Space, pts: Float32Array, count: number, w: number, c: Rgb, k: number, flat = false) {
  if (k <= 0 || count < 2) return;
  let x0 = Infinity;
  let x1 = -Infinity;
  let y0 = Infinity;
  let y1 = -Infinity;
  for (let s = 0; s < count; s++) {
    x0 = Math.min(x0, pts[s * 3]);
    x1 = Math.max(x1, pts[s * 3]);
    y0 = Math.min(y0, pts[s * 3 + 1]);
    y1 = Math.max(y1, pts[s * 3 + 1]);
  }
  const m = 3 * w;
  const inv = 1 / (w * w);
  const cut = 9 * w * w;
  const n = sp.x.length;
  for (let i = 0; i < n; i++) {
    const x = sp.x[i];
    if (x < x0 - m || x > x1 + m) continue;
    const y = sp.y[i];
    if (y < y0 - m || y > y1 + m) continue;
    const z = flat ? 0 : sp.z[i];
    let best = cut;
    for (let s = 0; s < count - 1; s++) {
      const a = s * 3;
      const d2 = flat ? segD2(x, y, 0, pts[a], pts[a + 1], 0, pts[a + 3], pts[a + 4], 0) : segD2(x, y, z, pts[a], pts[a + 1], pts[a + 2], pts[a + 3], pts[a + 4], pts[a + 5]);
      if (d2 < best) best = d2;
    }
    if (best < cut) addRgb(out, i * 3, c, Math.exp(-best * inv) * k);
  }
}

const hyperspace: Factory = (_n, rand) => {
  const stars: { a: number; p: number; v: number; c: number }[] = [];
  let lastU = 0;
  const reset = (s: { a: number; p: number; v: number; c: number }, p: number) => {
    s.a = rand() * Math.PI * 2;
    s.p = p;
    s.v = 0.14 + rand() * 0.22;
    s.c = Math.floor(rand() * 16);
  };
  return (out, { t, dt, intensity, size, pal, space, dir }) => {
    const count = Math.round(24 + 96 * intensity);
    while (stars.length < count) {
      const s = { a: 0, p: 0, v: 0, c: 0 };
      reset(s, rand());
      stars.push(s);
    }
    if (stars.length > count) stars.length = count;
    // The jump, every 12 seconds: the stars stretch into streaks, then a white flash.
    const T = 12;
    const u = fract(t / T) * T;
    const surge = smooth(6, 9, u) * (1 - smooth(9, 9.2, u));
    const flash = u >= 9 ? Math.exp(-(u - 9) * 5) : 0;
    if (lastU < 9 && u >= 9) for (const s of stars) reset(s, rand() * 0.7);
    lastU = u;
    const R = 0.55 * Math.hypot(space.ex, space.ey) || 0.5;
    const inward = dir === 'in';
    const w = Math.max(space.pitch * 1.2, 0.006) * (1 + surge * 0.6);
    const len = (0.03 + 0.07 * size) * (1 + 7 * surge);
    const speed = 1 + 4 * surge;
    const m = pal.stops.length;
    // Where they come from glows, and blazes up before the jump.
    glow3(out, space, 0, 0, 0, 0.05 + 0.12 * surge, pal.stops[0], 0.35 + 1.4 * surge, true);
    const rr = (q: number) => R * clamp01(inward ? 1 - q : q) ** 1.8;
    for (const s of stars) {
      s.p += s.v * speed * dt;
      if (s.p > 1 + len) reset(s, rand() * 0.08);
      const head = Math.min(1, s.p);
      const tail = Math.max(0, s.p - len);
      const rh = rr(head);
      const rt = rr(tail);
      const ca = Math.cos(s.a);
      const sa = Math.sin(s.a);
      // Nearer stars (further out) are brighter.
      const k = 0.2 + 1.3 * (Math.max(rh, rt) / R);
      const c = mixRgb(pal.stops[s.c % m], WHITE, 0.45);
      line3(out, space, rt * ca, rt * sa, 0, rh * ca, rh * sa, 0, w, c, k * 0.12, c, k, true);
    }
    if (flash > 0.002) fillRgb(out, WHITE, flash * 1.4);
  };
};

const digitalrain: Factory = () => (out, { t, intensity, size, pal, space, reverse }) => {
  const n = space.x.length;
  const K = Math.max(3, Math.min(90, Math.round((10 + 30 * Math.max(space.ex, 0.1)) / size)));
  const drops = 1 + Math.round(intensity * 2);
  const tail = 0.35 + 0.25 * intensity;
  for (let i = 0; i < n; i++) {
    const col = Math.min(K - 1, Math.floor(unitX(space, i) * K));
    const h = reverse ? 1 - unitY(space, i) : unitY(space, i);
    let best = 0;
    let head = 0;
    for (let d = 0; d < drops; d++) {
      const v = 0.16 + 0.3 * hash01(col, d * 7 + 1);
      const lane = t * v + hash01(col, d * 7 + 2) + d / drops;
      const cyc = Math.floor(lane);
      // The head falls from above the top (a new height each time) to below the bottom.
      const y = 1.25 + 0.6 * hash01(col * 31 + d, cyc) - fract(lane) * (2.1 + tail);
      const dist = h - y;
      if (dist < -0.03 || dist > tail) continue;
      if (dist < 0.03) head = Math.max(head, 1 - Math.abs(dist) / 0.03);
      const f = 1 - Math.max(0, dist) / tail;
      if (f > best) best = f;
    }
    // The glyphs flicker as they change.
    const glyph = 0.55 + 0.45 * hash01(i, Math.floor(t * 9 + hash01(i, 5) * 9));
    pal.add(out, i * 3, 0, 0.03);
    if (best > 0) pal.add(out, i * 3, 0.15 + 0.85 * best, best ** 1.6 * glyph * 1.15);
    if (head > 0) addRgb(out, i * 3, WHITE, head * 1.2);
  }
};

const tesla: Factory = (_n, rand, noise) => {
  const S = 16;
  const pts = new Float32Array((S + 1) * 3);
  const fork = new Float32Array(6 * 3);
  const seeds = Array.from({ length: 10 }, () => rand() * 100);
  return (out, { t, intensity, size, pal, space }) => {
    const K = 3 + Math.round(intensity * 7);
    const hx = Math.max(space.ex, 0.04) / 2;
    const hy = Math.max(space.ey, 0.04) / 2;
    const hz = Math.max(space.ez, 0.04) / 2;
    const w = Math.max(space.pitch * 1.4, 0.009 * size);
    const m = pal.stops.length;
    const jit = t * 5;
    // A shallow target (the house front): the bolts light what they pass in front of.
    const flat = space.ez < 0.5 * Math.max(space.ex, space.ey);
    // The core.
    const pulse = 0.85 + 0.15 * noise.n2(3.3, t * 8);
    glow3(out, space, 0, 0, 0, 0.07 + 0.03 * size, pal.stops[0], 0.5 * pulse, flat);
    glow3(out, space, 0, 0, 0, 0.03 + 0.02 * size, WHITE, 1.5 * pulse, flat);
    for (let k = 0; k < K; k++) {
      const sd = seeds[k];
      // Where it touches the glass wanders slowly over the sphere.
      const th = sd + noise.n2(sd, t * 0.16) * 5;
      const ph = Math.acos(clamp(noise.n2(sd + 40, t * 0.14) * 1.5, -1, 1));
      const ex = Math.sin(ph) * Math.cos(th) * hx;
      const ey = Math.cos(ph) * hy;
      const ez = Math.sin(ph) * Math.sin(th) * hz;
      const amp = 0.16 * Math.hypot(ex, ey, ez) + 0.01;
      for (let s = 0; s <= S; s++) {
        const u = s / S;
        const env = Math.sin(Math.PI * u) * amp;
        pts[s * 3] = ex * u + noise.n2(sd * 3 + u * 4, jit) * env;
        pts[s * 3 + 1] = ey * u + noise.n2(sd * 3 + u * 4 + 50, jit) * env;
        pts[s * 3 + 2] = ez * u + noise.n2(sd * 3 + u * 4 + 90, jit) * env;
      }
      const flick = 0.7 + 0.3 * noise.n2(sd + 9, t * 22);
      const c = mixRgb(pal.stops[k % m], WHITE, 0.3);
      path3(out, space, pts, S + 1, w, c, 1.4 * flick, flat);
      // A branch now and then, from the middle of the bolt.
      const fb = noise.n2(sd + 17, t * 1.5);
      if (fb > 0.15) {
        const s0 = Math.floor(S * (0.4 + 0.2 * hash01(k, Math.floor(t * 2))));
        for (let f = 0; f < 6; f++) {
          const u = f / 5;
          const a = s0 * 3;
          fork[f * 3] = pts[a] + (ex - pts[a]) * u * 0.5 + noise.n2(sd + 70 + u * 3, jit) * amp * u;
          fork[f * 3 + 1] = pts[a + 1] + (ey - pts[a + 1]) * u * 0.2 + noise.n2(sd + 80 + u * 3, jit) * amp * u;
          fork[f * 3 + 2] = pts[a + 2] + noise.n2(sd + 85 + u * 3, jit) * amp * u;
        }
        path3(out, space, fork, 6, w * 0.8, c, smooth(0.15, 0.4, fb) * 0.9 * flick, flat);
      }
      // Where it touches, the glass glows.
      glow3(out, space, ex, ey, ez, 0.03 + 0.03 * size, c, 0.9 * flick, flat);
    }
  };
};

const blackhole: Factory = (_n, _rand, noise) => (out, { t, intensity, size, pal, space, reverse }) => {
  const n = space.x.length;
  const Rd = 0.5 * Math.max(space.ex, 0.25);
  const rh = Rd * (0.07 + 0.07 * size);
  // The disk, seen almost edge-on.
  const tilt = 0.3;
  const spin = reverse ? -1 : 1;
  // Jets: how often they fire (none at 0).
  const T = 10 - 6 * intensity;
  const ju = fract(t / T) * T;
  const jet = intensity > 0.02 ? smooth(0, 0.25, ju) * (1 - smooth(1.5, 3.2, ju)) : 0;
  const front = rh + ju * 0.9;
  const JET: Rgb = [0.55, 0.75, 1];
  for (let i = 0; i < n; i++) {
    const x = space.x[i];
    const y = space.y[i];
    const r = Math.hypot(x, y);
    const j = i * 3;
    // The disk: in its own plane the radius is hypot(x, y / tilt).
    const yd = y / tilt;
    const dr = Math.hypot(x, yd);
    let heat = 0;
    if (dr > rh * 1.3 && dr < Rd * 1.1) {
      const a = Math.atan2(yd, x);
      const q = dr / Rd;
      // Inner rings turn faster, so the swirls shear into streaks.
      const ap = a - spin * t * (0.35 / (q ** 1.5 + 0.12));
      const turb = 0.5 + 0.5 * noise.fbm3(Math.cos(ap) * 1.7, Math.sin(ap) * 1.7, Math.log(q + 0.02) * 2.6, 3);
      const band = smooth(rh * 1.3, rh * 2.3, dr) * (1 - smooth(Rd * 0.55, Rd * 1.1, dr));
      // The side that turns toward you is brighter.
      const dopp = 1 - 0.55 * spin * Math.cos(a);
      heat = band * (0.3 + 0.7 * turb) * (1.25 - 0.6 * q) * dopp;
    }
    if (r < rh) {
      // The shadow: only the near side of the disk crosses in front of it.
      if (y < 0 && heat > 0) pal.add(out, j, clamp01(heat * 0.85), heat * 1.1);
      continue;
    }
    if (heat > 0) pal.add(out, j, clamp01(heat * 0.85), heat * 1.1);
    // The photon ring, right at the edge of the shadow.
    const pr = (r - rh * 1.1) / (rh * 0.14 + space.pitch);
    if (pr < 3) addRgb(out, j, [1, 0.85, 0.6], Math.exp(-pr * pr) * 1.6);
    // The far side of the disk, bent by gravity into a halo over and under the hole.
    const lr = (r - rh * 1.65) / (rh * 0.55);
    if (lr > -3 && lr < 3) {
      const a = Math.atan2(y, x) - spin * t * 0.6;
      const tw = 0.6 + 0.4 * noise.n2(Math.cos(a) * 2 + 7, Math.sin(a) * 2);
      pal.add(out, j, 0.75, Math.exp(-lr * lr) * 0.65 * tw);
    }
    if (jet > 0) {
      const ay = Math.abs(y);
      const wj = rh * 0.35 + ay * 0.1 + space.pitch;
      const ax = Math.abs(x) / wj;
      if (ax < 3 && ay > rh * 0.8) {
        const knots = 0.65 + 0.35 * Math.sin(ay * 45 - ju * 25);
        const k = Math.exp(-ax * ax) * smooth(front + 0.04, front - 0.04, ay) * jet * knots * 1.5;
        addRgb(out, j, JET, k);
        addRgb(out, j, WHITE, k * k * 0.4);
      }
    }
    // A few stars behind it all.
    const h = hash01(i, 7);
    if (h > 0.985) addRgb(out, j, WHITE, 0.15 + 0.25 * (0.5 + 0.5 * Math.sin(t * 2 + h * 400)));
  }
};

const lavalamp: Factory = (_n, rand, noise) => {
  const blobs = Array.from({ length: 9 }, () => ({ seed: rand() * 100, ph: rand(), rate: 0.035 + rand() * 0.045, r: 0.7 + rand() * 0.6 }));
  const bx = new Float32Array(9);
  const by = new Float32Array(9);
  const bz = new Float32Array(9);
  const bi = new Float32Array(9);
  return (out, { t, intensity, size, pal, space }) => {
    const n = space.x.length;
    const B = 3 + Math.round(intensity * 6);
    const hx = space.ex / 2;
    const hy = space.ey / 2;
    const hz = space.ez / 2;
    const m = pal.stops.length;
    for (let b = 0; b < B; b++) {
      const f = blobs[b];
      // Heated at the bottom they rise, cool at the top and sink again.
      by[b] = Math.sin((t * f.rate + f.ph) * Math.PI * 2) * hy * 0.85;
      bx[b] = clamp(noise.n2(f.seed, t * 0.04) * 1.3, -1, 1) * hx;
      bz[b] = clamp(noise.n2(f.seed + 50, t * 0.04) * 1.3, -1, 1) * hz;
      // They swell and shrink a little as they go. Kernel reach: twice the radius.
      const rad = Math.max(space.pitch * 3, 0.085 * size * f.r) * (1 + 0.22 * Math.sin(t * 0.6 + f.seed));
      bi[b] = 1 / (4 * rad * rad);
    }
    const c: Rgb = [0, 0, 0];
    for (let i = 0; i < n; i++) {
      const x = space.x[i];
      const y = space.y[i];
      const z = space.z[i];
      let F = 0;
      c[0] = c[1] = c[2] = 0;
      for (let b = 0; b < B; b++) {
        const q = ((x - bx[b]) ** 2 + (y - by[b]) ** 2 + (z - bz[b]) ** 2) * bi[b];
        if (q >= 1) continue;
        const k = (1 - q) * (1 - q);
        F += k;
        const s = pal.stops[b % m];
        c[0] += s[0] * k;
        c[1] += s[1] * k;
        c[2] += s[2] * k;
      }
      const j = i * 3;
      pal.add(out, j, 0, 0.04);
      if (F <= 0) continue;
      c[0] /= F;
      c[1] /= F;
      c[2] /= F;
      // The surface is where the field reaches 0.56 (a lone blob's radius).
      const v = F / 0.5625;
      const inside = smooth(0.8, 1.05, v);
      const rim = Math.exp(-(((v - 1) / 0.13) ** 2));
      const heat = 1.15 - 0.3 * unitY(space, i);
      addRgb(out, j, c, (inside * 1.05 + clamp01(v) * 0.22) * heat);
      addRgb(out, j, WHITE, rim * 0.3);
    }
  };
};

const helix: Factory = () => (out, { t, intensity, size, pal, space, reverse }) => {
  const n = space.x.length;
  // Along the longest side: across the yard, or up a tree.
  const upright = space.ey >= Math.max(space.ex, space.ez);
  const rb = ((upright ? space.ex : space.ey) / 2) * 0.8;
  const rc = (space.ez / 2) * 0.8;
  const useB = rb > 1e-4;
  // A shallow target (the house front): as the street sees it, two waves that cross.
  const useC = rc > 1e-4 && space.ez >= 0.5 * Math.max(space.ex, space.ey);
  const turns = 2.4 / size;
  const spin = (reverse ? -1 : 1) * t * 0.22;
  const rungs = 2 + Math.round(intensity * 8);
  const W = 0.3;
  const pulse = fract(t * 0.07);
  const c1 = pal.stops[0];
  const c2 = pal.stops[1 % pal.stops.length];
  const r1 = pal.stops[2 % pal.stops.length];
  const r2 = pal.stops[3 % pal.stops.length];
  for (let i = 0; i < n; i++) {
    const a = upright ? unitY(space, i) : unitX(space, i);
    const nb = useB ? (upright ? space.x[i] : space.y[i]) / rb : 0;
    const nc = useC ? space.z[i] / rc : 0;
    const th = Math.PI * 2 * (a * turns - spin);
    const sb = useB ? Math.cos(th) : 0;
    const sc = useC ? Math.sin(th) : 0;
    const d1 = Math.hypot(nb - sb, nc - sc) / W;
    const d2 = Math.hypot(nb + sb, nc + sc) / W;
    // The strand nearer the street is brighter.
    const zs = Math.sin(th);
    const k1 = Math.exp(-d1 * d1) * (0.55 + 0.45 * zs);
    const k2 = Math.exp(-d2 * d2) * (0.55 - 0.45 * zs);
    const j = i * 3;
    // A pulse runs along the strands.
    const pd = (a - pulse) / 0.035;
    const glint = pd > -3 && pd < 3 ? Math.exp(-pd * pd) : 0;
    addRgb(out, j, c1, k1 * 1.2);
    addRgb(out, j, c2, k2 * 1.2);
    if (glint > 0) addRgb(out, j, WHITE, (k1 + k2) * glint);
    // Rungs: pairs between the strands, each half its own color.
    const rp = a * turns * rungs;
    const ri = Math.round(rp);
    const da = (rp - ri) / 0.13;
    if (da > -3 && da < 3) {
      const dd = segD2(nb, nc, 0, sb, sc, 0, -sb, -sc, 0) / (0.2 * 0.2);
      if (dd < 9) {
        const k = Math.exp(-da * da - dd) * 0.75;
        const swap = hash01(ri, 11) < 0.5;
        addRgb(out, j, segT < 0.5 === swap ? r1 : r2, k);
      }
    }
  }
};

const S3 = 1 / Math.sqrt(3);
const CUBE_V = [-1, 1].flatMap((x) => [-1, 1].flatMap((y) => [-1, 1].map((z) => [x * S3, y * S3, z * S3, 0])));
const OCTA_V = [[1, 0, 0, 0], [-1, 0, 0, 0], [0, 1, 0, 0], [0, -1, 0, 0], [0, 0, 1, 0], [0, 0, -1, 0]];
const TESS_V = Array.from({ length: 16 }, (_, k) => [k & 1 ? 0.5 : -0.5, k & 2 ? 0.5 : -0.5, k & 4 ? 0.5 : -0.5, k & 8 ? 0.5 : -0.5]);
/** Pairs of vertices `apart` from each other: the edges of a shape. */
const edgesOf = (v: number[][], apart: number) => {
  const e: [number, number][] = [];
  for (let a = 0; a < v.length; a++) for (let b = a + 1; b < v.length; b++) if (Math.abs(Math.hypot(...v[a].map((x, k) => x - v[b][k])) - apart) < 1e-6) e.push([a, b]);
  return e;
};
const SHAPES = [
  { v: CUBE_V, e: edgesOf(CUBE_V, 2 * S3), four: false },
  { v: OCTA_V, e: edgesOf(OCTA_V, Math.SQRT2), four: false },
  { v: TESS_V, e: edgesOf(TESS_V, 1), four: true }
];

const hologram: Factory = () => {
  const P = new Float32Array(16 * 3);
  return (out, { t, intensity, size, pal, space }) => {
    const n = space.x.length;
    const T = 11;
    const cyc = Math.floor(t / T);
    const u = t - cyc * T;
    const shape = SHAPES[cyc % SHAPES.length];
    // Each shape pops out of the projector and folds away again.
    const grow = smooth(0, 0.7, u) * (1 + 0.12 * Math.sin(Math.min(u, 1.4) * 4.5) * (1 - smooth(0.7, 1.4, u))) * (1 - smooth(T - 0.5, T, u));
    const glitch = Math.max(u < 0.5 ? 1 - u / 0.5 : 0, T - u < 0.5 ? 1 - (T - u) / 0.5 : 0);
    const sx = Math.max(space.ex, 0.04) * 0.4 * grow;
    const sy = Math.max(space.ey, 0.04) * 0.48 * grow;
    const ay = t * 0.45;
    const ax = 0.45 + 0.35 * Math.sin(t * 0.21);
    const xw = t * 0.38;
    const zw = t * 0.23;
    for (let k = 0; k < shape.v.length; k++) {
      let [x, y, z, w] = shape.v[k];
      if (shape.four) {
        // Turn in four dimensions, then look at it from the fourth.
        [x, w] = [x * Math.cos(xw) - w * Math.sin(xw), x * Math.sin(xw) + w * Math.cos(xw)];
        [z, w] = [z * Math.cos(zw) - w * Math.sin(zw), z * Math.sin(zw) + w * Math.cos(zw)];
        const f = 1.5 / (2 - w);
        x *= f;
        y *= f;
        z *= f;
      }
      [x, z] = [x * Math.cos(ay) + z * Math.sin(ay), -x * Math.sin(ay) + z * Math.cos(ay)];
      [y, z] = [y * Math.cos(ax) - z * Math.sin(ax), y * Math.sin(ax) + z * Math.cos(ax)];
      const f = 3 / (3.4 - z);
      P[k * 3] = x * f * sx;
      P[k * 3 + 1] = y * f * sy;
      P[k * 3 + 2] = z;
    }
    const lw = Math.max(space.pitch * 1.3, 0.006 * size);
    const depth = (z: number) => clamp01(0.5 + z * 0.45);
    for (const [a, b] of shape.e) {
      const za = P[a * 3 + 2];
      const zb = P[b * 3 + 2];
      line3(out, space, P[a * 3], P[a * 3 + 1], 0, P[b * 3], P[b * 3 + 1], 0, lw, pal.at(depth(za)), 0.35 + 0.85 * depth(za), pal.at(depth(zb)), 0.35 + 0.85 * depth(zb), true);
    }
    for (let k = 0; k < shape.v.length; k++) glow3(out, space, P[k * 3], P[k * 3 + 1], 0, lw * 1.8, WHITE, 0.4 + 0.6 * depth(P[k * 3 + 2]), true);
    // The projector glows at the bottom.
    glow3(out, space, 0, -space.ey / 2, 0, 0.06 + 0.04 * size, pal.stops[pal.stops.length - 1], 0.35 + 0.4 * grow, true);
    // Scan lines roll up; it flickers, and glitches as the shapes change.
    const flicker = hash01(Math.floor(t * 24), 3) > 1 - 0.12 * intensity ? 0.45 : 1;
    const speckle = (0.03 + 0.25 * intensity) * glitch;
    const step = Math.floor(t * 30);
    for (let i = 0; i < n; i++) {
      const j = i * 3;
      const scan = (0.72 + 0.28 * Math.sin(Math.PI * 2 * (unitY(space, i) * 9 - t * 1.4))) * flicker;
      out[j] *= scan;
      out[j + 1] *= scan;
      out[j + 2] *= scan;
      if (speckle > 0 && hash01(i, step) < speckle) pal.add(out, j, hash01(i, step + 1), 0.9);
    }
  };
};

const orbits: Factory = (_n, rand) => {
  const orbs = Array.from({ length: 7 }, (_, k) => ({ tilt: 0.4 + rand() * 2.3, yaw: (k / 7) * Math.PI + rand() * 0.4, rate: (0.3 + rand() * 0.25) * (rand() < 0.5 ? -1 : 1), ph: rand() * 6.28, ecc: 0.7 + rand() * 0.3 }));
  return (out, { t, intensity, size, pal, space }) => {
    const K = 2 + Math.round(intensity * 5);
    // A shallow target (the house front): comets light what they pass in front of.
    const flat = space.ez < 0.5 * Math.max(space.ex, space.ey);
    const hx = (Math.max(space.ex, 0.05) / 2) * 0.92;
    const hy = (Math.max(space.ey, 0.05) / 2) * 0.92;
    const hz = (Math.max(space.ez, 0.05) / 2) * 0.92;
    const r = Math.max(space.pitch * 1.6, 0.022 * size);
    const m = pal.stops.length;
    const beat = 0.8 + 0.2 * Math.sin(t * 3.2);
    glow3(out, space, 0, 0, 0, 0.07 + 0.04 * size, pal.stops[0], 1.0 * beat, flat);
    glow3(out, space, 0, 0, 0, 0.025 + 0.015 * size, WHITE, 1.2 * beat, flat);
    const TAIL = 18;
    for (let k = 0; k < K; k++) {
      const o = orbs[k];
      const c = pal.stops[(k + 1) % m];
      const head = o.ph + o.rate * t * Math.PI;
      const back = Math.sign(o.rate) * 0.055;
      for (let s = TAIL; s >= 0; s--) {
        const a = head - s * back;
        // A circle, tilted and turned in space.
        const x0 = Math.cos(a);
        const y0 = Math.sin(a) * o.ecc;
        const y1 = y0 * Math.cos(o.tilt);
        const z1 = y0 * Math.sin(o.tilt);
        const x = x0 * Math.cos(o.yaw) + z1 * Math.sin(o.yaw);
        const z = -x0 * Math.sin(o.yaw) + z1 * Math.cos(o.yaw);
        const fade = (1 - s / (TAIL + 1)) ** 1.6;
        // In front of the nucleus brighter, behind it dimmer.
        const near = 0.6 + 0.4 * z;
        glow3(out, space, x * hx, y1 * hy, z * hz, r * (1 - 0.45 * (s / TAIL)), c, 1.25 * fade * near, flat);
        if (s === 0) glow3(out, space, x * hx, y1 * hy, z * hz, r * 0.5, WHITE, 0.9 * near, flat);
      }
    }
  };
};

const supernova: Factory = (_n, _rand, noise) => (out, { t, intensity, size, pal, space }) => {
  const n = space.x.length;
  const T = 10;
  const cyc = Math.floor(t / T);
  const u = t - cyc * T;
  // Each star goes off somewhere else.
  const cx = (hash01(cyc, 1) - 0.5) * space.ex * 0.5;
  const cy = (hash01(cyc, 2) - 0.5) * space.ey * 0.4;
  const cz = (hash01(cyc, 3) - 0.5) * space.ez * 0.5;
  const R = (0.5 * Math.hypot(space.ex, space.ey, space.ez) || 0.5) * (0.75 + 0.45 * size);
  const BANG = 2.4;
  const fadeOut = 1 - smooth(T - 1.2, T, u);
  const top = pal.stops[pal.stops.length - 1];
  const core = mixRgb(top, WHITE, 0.5);
  if (u < BANG) {
    // The star shudders, faster and faster, as its shell falls in.
    const q = u / BANG;
    const shell = R * (1 - q * q) * 0.9;
    const w = Math.max(space.pitch * 1.5, 0.03);
    const rs = (0.035 + 0.03 * size) * (1 + 0.25 * Math.sin(u * (5 + q * q * 40))) * (1 - 0.6 * q * q * q);
    for (let i = 0; i < n; i++) {
      const d = Math.hypot(space.x[i] - cx, space.y[i] - cy, space.z[i] - cz);
      const off = (d - shell) / w;
      if (off > -3 && off < 3) pal.add(out, i * 3, 0.3, Math.exp(-off * off) * 0.7 * q);
      const g = d / rs;
      if (g < 3) addRgb(out, i * 3, core, Math.exp(-g * g) * (0.7 + 1.4 * q));
    }
    return;
  }
  const a = u - BANG;
  const flash = Math.exp(-a * 6) * 1.8;
  const rad = R * (1 - Math.exp(-a * 1.1)) * 1.15;
  const w = Math.max(space.pitch * 2, 0.035 + 0.04 * a);
  const shockK = Math.exp(-a * 0.4) * 1.6 * fadeOut;
  const remnant = (0.2 + 0.7 * intensity) * smooth(0.2, 1.2, a) * fadeOut;
  // The pulsar's two beams sweep round, as the street sees them.
  const beam = Math.PI * 2 * a * 0.45;
  const pulsar = smooth(1.5, 3, a) * fadeOut;
  for (let i = 0; i < n; i++) {
    const dx = space.x[i] - cx;
    const dy = space.y[i] - cy;
    const dz = space.z[i] - cz;
    const d = Math.hypot(dx, dy, dz) + 1e-6;
    const j = i * 3;
    // A ragged front: it races ahead in some directions.
    const rag = 1 + 0.22 * noise.n3((dx / d) * 2.2, (dy / d) * 2.2, (dz / d) * 2.2 + cyc * 7.3);
    const off = (d - rad * rag) / w;
    if (off > -6 && off < 3) {
      const s = off > 0 ? Math.exp(-off * off) : Math.exp(-off * off * 0.15);
      // White-hot at the front, the palette's colors behind it.
      pal.add(out, j, clamp01(1 + off * 0.16), s * shockK);
      if (off > -1.5) addRgb(out, j, WHITE, Math.exp(-off * off) * shockK * 0.45);
    }
    if (remnant > 0 && d < rad * rag) {
      const fil = noise.fbm3(dx * 5.5, dy * 5.5, dz * 5.5 + cyc * 3.7 + a * 0.12, 3);
      const v = smooth(-0.05, 0.45, fil) * smooth(0, 0.35 * rad, d);
      if (v > 0) pal.add(out, j, 0.25 + 0.6 * clamp01(d / (rad * rag)), v * remnant);
    }
    if (pulsar > 0) {
      const ang = Math.atan2(dy, dx) - beam;
      const db = Math.abs(Math.atan2(Math.sin(ang), Math.cos(ang)));
      const off2 = Math.min(db, Math.PI - db) / 0.13;
      if (off2 < 3) addRgb(out, j, [0.7, 0.85, 1], Math.exp(-off2 * off2) * Math.exp(-(d / R) * 2) * pulsar * 0.9);
      const g = d / 0.025;
      if (g < 3) addRgb(out, j, WHITE, Math.exp(-g * g) * pulsar * (0.6 + 0.6 * (Math.sin(t * 25) > 0 ? 1 : 0)));
    }
    if (flash > 0.002) addRgb(out, j, core, flash * (0.4 + 0.6 * Math.exp(-d / R)));
  }
};

const kaleidoscope: Factory = (_n, _rand, noise) => (out, { t, intensity, size, pal, space, reverse }) => {
  const n = space.x.length;
  const N = 3 + Math.round(intensity * 7);
  const wedge = Math.PI / N;
  const rot = (reverse ? -1 : 1) * t * 0.12;
  const f = 3.2 / size;
  const seam = Math.max(space.pitch * 1.2, 0.006);
  for (let i = 0; i < n; i++) {
    const x = space.x[i];
    const y = space.y[i];
    const r = Math.hypot(x, y);
    // Fold every direction into one wedge, mirrored.
    let a = Math.atan2(y, x) + rot;
    a = ((a % (2 * wedge)) + 2 * wedge) % (2 * wedge);
    if (a > wedge) a = 2 * wedge - a;
    const px = r * Math.cos(a) * f;
    const py = r * Math.sin(a) * f;
    const v = noise.fbm3(px + t * 0.11, py - t * 0.07, t * 0.09 + space.z[i] * 1.5, 3);
    const rings = 0.5 + 0.5 * Math.cos(Math.PI * 2 * (r * f * 0.9 - t * 0.3));
    const bright = clamp01(0.5 + v * 1.9) ** 1.4;
    const j = i * 3;
    pal.add(out, j, pal.wave(v * 1.5 + r * 0.9 - t * 0.05), (0.12 + 1.05 * bright) * (0.6 + 0.4 * rings));
    // Glints along the mirrors.
    const edge = (Math.min(a, wedge - a) * r) / seam;
    if (edge < 3) addRgb(out, j, WHITE, Math.exp(-edge * edge) * 0.35 * bright);
  }
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
  equalizer,
  hyperspace,
  digitalrain,
  tesla,
  blackhole,
  lavalamp,
  helix,
  hologram,
  orbits,
  supernova,
  kaleidoscope
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
