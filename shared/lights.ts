// What the lights are made of: the LED string or strip of each object. It knows how far apart
// the LEDs are, so the editor can tell how many LEDs fit a line you drew, where one strand
// ends and the next begins, and about how much current the lights draw.

import type { Layout } from './layout.ts';

/** How the LEDs look, for the editor's labels. */
export type LightStyle = 'bullet' | 'bulb' | 'strip' | 'module' | 'other';

export const LIGHT_STYLES: Record<LightStyle, string> = {
  bullet: 'Bullet pixels',
  bulb: 'Bulbs (C7, C9…)',
  strip: 'LED strip',
  module: 'Square modules',
  other: 'Other'
};

/** The chips WLED drives most often, for the menu. Any name is allowed. */
export const LED_CHIPS = ['WS2811', 'WS2812B', 'WS2813', 'WS2815', 'SK6812', 'SK6812 RGBW', 'TM1814', 'UCS1903', 'APA102', 'Other'];

export interface LightType {
  id: string;
  name: string;
  chip: string;
  volts: number;
  style: LightStyle;
  /** From one LED to the next, in meters. */
  spacing: number;
  /** LEDs in one strand (a string or a reel), or null for a strip that is cut to length. */
  perStrand: number | null;
  /** The most current one LED draws (full white, full brightness), in milliamps. */
  milliamps: number;
}

const INCH = 0.0254;

/** Common light strings. Your own are kept in the layout (Layout.lightTypes). */
export const BUILT_IN_LIGHTS: LightType[] = [
  { id: 'novabright-bullet-12v-4in', name: 'NovaBright 12 V bullet pixels, 4 in', chip: 'WS2811', volts: 12, style: 'bullet', spacing: 4 * INCH, perStrand: 50, milliamps: 25 },
  { id: 'bullet-12v-3in', name: '12 V bullet pixels, 3 in', chip: 'WS2811', volts: 12, style: 'bullet', spacing: 3 * INCH, perStrand: 50, milliamps: 25 },
  { id: 'bullet-12v-6in', name: '12 V bullet pixels, 6 in', chip: 'WS2811', volts: 12, style: 'bullet', spacing: 6 * INCH, perStrand: 50, milliamps: 25 },
  { id: 'bullet-5v-3in', name: '5 V bullet pixels, 3 in', chip: 'WS2811', volts: 5, style: 'bullet', spacing: 3 * INCH, perStrand: 50, milliamps: 50 },
  { id: 'c9-12v-12in', name: '12 V C9 pixel bulbs, 12 in', chip: 'WS2811', volts: 12, style: 'bulb', spacing: 12 * INCH, perStrand: 50, milliamps: 40 },
  { id: 'strip-ws2812b-30', name: 'WS2812B strip, 30 LEDs/m', chip: 'WS2812B', volts: 5, style: 'strip', spacing: 1 / 30, perStrand: null, milliamps: 60 },
  { id: 'strip-ws2812b-60', name: 'WS2812B strip, 60 LEDs/m', chip: 'WS2812B', volts: 5, style: 'strip', spacing: 1 / 60, perStrand: null, milliamps: 60 },
  { id: 'strip-ws2812b-144', name: 'WS2812B strip, 144 LEDs/m', chip: 'WS2812B', volts: 5, style: 'strip', spacing: 1 / 144, perStrand: null, milliamps: 60 },
  { id: 'strip-ws2815-60', name: 'WS2815 strip, 60 LEDs/m', chip: 'WS2815', volts: 12, style: 'strip', spacing: 1 / 60, perStrand: null, milliamps: 25 }
];

/** Your own light types first, then the built-in ones. */
export function allLights(layout: Pick<Layout, 'lightTypes'> | undefined): LightType[] {
  return [...(layout?.lightTypes ?? []), ...BUILT_IN_LIGHTS];
}

export function lightsOf(layout: Pick<Layout, 'lightTypes'> | undefined, id: string | undefined | null): LightType | null {
  if (!id) return null;
  return allLights(layout).find((l) => l.id === id) ?? null;
}

export const isBuiltInLight = (id: string) => BUILT_IN_LIGHTS.some((l) => l.id === id);

/**
 * How many LEDs a stretch of `meters` holds at this spacing. `ends`: count both ends (a whole
 * line: 0 m holds 1 LED). Without: the LEDs of one segment, which ends where the next one starts.
 */
export function ledsForLength(meters: number, spacing: number, ends = true): number {
  if (!(spacing > 0)) return 1;
  return Math.max(1, Math.round(meters / spacing + 1e-9) + (ends ? 1 : 0));
}

/** The length of string from the first LED to the last, in meters. */
export const stringLength = (leds: number, spacing: number) => Math.max(0, leds - 1) * spacing;

/** "3 strands of 50", "2 strands of 50 + 13 LEDs", or null for a strip. */
export function strandText(leds: number, perStrand: number | null): string | null {
  if (!perStrand || perStrand < 1) return null;
  const full = Math.floor(leds / perStrand);
  const rest = leds - full * perStrand;
  if (!full) return `${rest} of a strand of ${perStrand}`;
  const head = `${full} strand${full === 1 ? '' : 's'} of ${perStrand}`;
  return rest ? `${head} + ${rest} LED${rest === 1 ? '' : 's'}` : head;
}

/**
 * The LEDs of the fewest whole strands (strings) that hold `leds`: an object is made of whole
 * strings. A strip that is cut to length (no strands): `leds` as it is.
 */
export function wholeStrands(leds: number, perStrand: number | null): number {
  if (!perStrand || perStrand < 1) return leds;
  return Math.max(1, Math.ceil(leds / perStrand - 1e-9)) * perStrand;
}

/** The LEDs (counted from the object's first LED) where a new strand begins: 50, 100… */
export function strandStarts(leds: number, perStrand: number | null): number[] {
  if (!perStrand || perStrand < 1) return [];
  const out: number[] = [];
  for (let i = perStrand; i < leds; i += perStrand) out.push(i);
  return out;
}

// ---------- The strings an object is made of ----------
// An object's LEDs are one or more strings (strands) one after the other along the data wire, in
// the order of the device's LED numbers. Each string has perStrand LEDs unless its start and end
// are set (Fixture.stringBreaks: a string that was cut, or that hides a few LEDs). Positions here
// count from the object's lowest device LED number (its first LED on the wire).

/** Where each string after the first starts. `breaks`: as set (the valid ones, in order); none: every perStrand LEDs. */
export function stringStarts(leds: number, perStrand: number | null, breaks?: number[]): number[] {
  if (!breaks?.length) return strandStarts(leds, perStrand);
  const out: number[] = [];
  let prev = 0;
  for (const b of [...breaks].sort((a, c) => a - c)) {
    if (Number.isInteger(b) && b > prev && b < leds) {
      out.push(b);
      prev = b;
    }
  }
  return out;
}

/** Each string's first and last LED (inclusive). One string for lights that do not come in strings. */
export function stringRanges(leds: number, perStrand: number | null, breaks?: number[]): { lo: number; hi: number }[] {
  if (leds < 1) return [];
  const starts = [0, ...stringStarts(leds, perStrand, breaks)];
  return starts.map((lo, i) => ({ lo, hi: (starts[i + 1] ?? leds) - 1 }));
}

/** Breaks as they are stored: none when they are where the strings start anyway. */
function tidyBreaks(leds: number, perStrand: number | null, starts: number[]): number[] | undefined {
  const plain = strandStarts(leds, perStrand);
  return plain.length === starts.length && plain.every((b, i) => b === starts[i]) ? undefined : starts;
}

/**
 * An object made of `n` strings: whole strings of perStrand LEDs. Strings whose start and end
 * are set keep them; strings added after them are whole, and strings taken away go from the end.
 */
export function setStringCount(leds: number, perStrand: number, breaks: number[] | undefined, n: number): { pixels: number; stringBreaks: number[] | undefined } {
  const count = Math.max(1, Math.round(n));
  if (!breaks?.length) return { pixels: count * perStrand, stringBreaks: undefined };
  const starts = stringStarts(leds, perStrand, breaks);
  const now = starts.length + 1;
  if (count >= now) {
    const added = Array.from({ length: count - now }, (_, i) => leds + i * perStrand);
    const pixels = leds + (count - now) * perStrand;
    return { pixels, stringBreaks: tidyBreaks(pixels, perStrand, [...starts, ...added]) };
  }
  const pixels = starts[count - 1];
  return { pixels, stringBreaks: tidyBreaks(pixels, perStrand, starts.slice(0, count - 1)) };
}

/**
 * Moves the last LED of string k (0 the first) to `end`: the next string starts just after it,
 * and keeps at least one LED. The last string's end is the object's last LED, so the object
 * gets longer or shorter.
 */
export function setStringEnd(leds: number, perStrand: number | null, breaks: number[] | undefined, k: number, end: number): { pixels: number; stringBreaks: number[] | undefined } {
  const ranges = stringRanges(leds, perStrand, breaks);
  const r = ranges[k];
  if (!r) return { pixels: leds, stringBreaks: breaks };
  const starts = ranges.slice(1).map((x) => x.lo);
  const at = Math.max(r.lo, Math.round(end));
  if (k === ranges.length - 1) {
    const pixels = at + 1;
    return { pixels, stringBreaks: tidyBreaks(pixels, perStrand, starts) };
  }
  starts[k] = Math.min(at, ranges[k + 1].hi - 1) + 1;
  return { pixels: leds, stringBreaks: tidyBreaks(leds, perStrand, starts) };
}

/** Moves the first LED of string k (1 or later) to `start`: the string before ends just before it. */
export const setStringStart = (leds: number, perStrand: number | null, breaks: number[] | undefined, k: number, start: number) => setStringEnd(leds, perStrand, breaks, k - 1, start - 1);

/** The most current the LEDs draw, in amps (all white, full brightness). */
export const maxAmps = (leds: number, l: Pick<LightType, 'milliamps'>) => (leds * l.milliamps) / 1000;

/** The spacing as you would say it: "4 in" or "10.2 cm". */
export function spacingText(meters: number, units: 'ft' | 'm' = 'ft'): string {
  if (units === 'm') return `${Math.round(meters * 1000) / 10} cm`;
  return `${Math.round((meters / INCH) * 100) / 100} in`;
}

/** One line about a light type: "WS2811 · 12 V · 4 in · 50 per strand". */
export function lightSummary(l: LightType, units: 'ft' | 'm' = 'ft'): string {
  return [l.chip, `${l.volts} V`, `${spacingText(l.spacing, units)} apart`, l.perStrand ? `${l.perStrand} per strand` : 'cut to length'].join(' · ');
}
