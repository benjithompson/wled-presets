// Reads the "look" of a WLED preset (its colors and how lively it is) from presets.json.
// The public page uses it to tint and animate its background.

export interface PresetLook {
  /** Up to 6 hex colors, most characteristic first. Empty when the preset sets no color. */
  colors: string[];
  /** 0 = still (solid color), 1 = fast and intense effect. */
  energy: number;
}

type Rgb = [number, number, number];

// Approximate colors of WLED's built-in palettes, by palette id. They only tint the page,
// so exact values do not matter.
const PALETTES: Record<number, string[]> = {
  1: ['#ff0000', '#ffd000', '#00ff40', '#0080ff', '#c000ff'], // Random Cycle
  6: ['#5500ab', '#b5004b', '#e81700', '#ab7700'], // Party
  7: ['#1e3cff', '#00008b', '#87ceeb', '#ffffff'], // Cloud
  8: ['#800000', '#ff1a00', '#ff8c00', '#ffd27a'], // Lava
  9: ['#191970', '#0047ab', '#008080', '#7fffd4'], // Ocean
  10: ['#006400', '#556b2f', '#228b22', '#9acd32'], // Forest
  11: ['#ff0000', '#ffab00', '#abff00', '#00ff55', '#0055ff', '#ab00ff'], // Rainbow
  12: ['#ff0000', '#ffab00', '#abff00', '#00ff55', '#0055ff', '#ab00ff'], // Rainbow Bands
  13: ['#780000', '#ff6800', '#a71661', '#640067'], // Sunset
  35: ['#ff0000', '#ff6000', '#ffc000', '#fff2c0'], // Fire
  36: ['#002b80', '#00a0ff', '#ffffff', '#ff8a00', '#c80000'], // Icefire
  50: ['#00ff50', '#00c8a0', '#7200a6', '#1a0060'] // Aurora
};
// Effects that cycle through the rainbow when no palette is chosen.
const RAINBOW_FX = new Set([8, 9]);

function toRgb(c: unknown): Rgb | null {
  if (Array.isArray(c) && c.length >= 3 && c.slice(0, 3).every((n) => typeof n === 'number')) {
    const [r, g, b, w = 0] = c as number[];
    // RGBW strips: blend the white channel in, so warm-white presets are not black.
    return [Math.min(255, r + w * 0.9), Math.min(255, g + w * 0.8), Math.min(255, b + w * 0.6)];
  }
  if (typeof c === 'string' && /^#?[0-9a-f]{6}([0-9a-f]{2})?$/i.test(c)) {
    const n = parseInt(c.replace('#', '').slice(0, 6), 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  return null;
}

const hex = ([r, g, b]: Rgb) => `#${[r, g, b].map((v) => Math.round(v).toString(16).padStart(2, '0')).join('')}`;
const fromHex = (h: string): Rgb => toRgb(h)!;

/** Removes near-black and near-duplicate colors, and keeps at most `max`. */
export function distinctColors(colors: string[], max = 6): string[] {
  const out: Rgb[] = [];
  for (const h of colors) {
    const c = fromHex(h);
    if (Math.max(...c) < 24) continue;
    if (out.some((o) => Math.hypot(o[0] - c[0], o[1] - c[1], o[2] - c[2]) < 48)) continue;
    out.push(c);
    if (out.length >= max) break;
  }
  return out.map(hex);
}

function segmentLook(seg: any): PresetLook | null {
  if (!seg || typeof seg !== 'object' || seg.on === false) return null;
  const fx = Number(seg.fx ?? 0);
  const pal = Number(seg.pal ?? 0);
  const own = (Array.isArray(seg.col) ? seg.col : []).map(toRgb).filter((c: Rgb | null): c is Rgb => c !== null).map(hex);
  let colors: string[] = [];
  if (PALETTES[pal]) colors = [...PALETTES[pal], ...own];
  else if (RAINBOW_FX.has(fx) && pal <= 1) colors = [...PALETTES[11], ...own];
  else colors = own;
  const sx = Number(seg.sx ?? 128) / 255;
  const ix = Number(seg.ix ?? 128) / 255;
  const energy = fx === 0 ? 0.12 : 0.25 + 0.55 * sx + 0.2 * ix;
  return { colors, energy };
}

export function presetLook(id: number, all: Record<string, any>, depth = 0): PresetLook {
  const p = all[String(id)];
  if (!p || typeof p !== 'object' || p.on === false) return { colors: [], energy: 0.05 };
  // A playlist looks like its first preset.
  const first = p.playlist?.ps?.[0];
  if (first != null && depth < 3) {
    const look = presetLook(Number(first), all, depth + 1);
    return { ...look, energy: Math.min(1, look.energy + 0.15) };
  }
  const segs = Array.isArray(p.seg) ? p.seg : p.seg ? [p.seg] : [];
  const looks = segs.map(segmentLook).filter((l: PresetLook | null): l is PresetLook => l !== null);
  if (!looks.length) return { colors: [], energy: 0.2 };
  const colors = distinctColors(looks.flatMap((l: PresetLook) => l.colors));
  const energy = Math.min(1, looks.reduce((n: number, l: PresetLook) => n + l.energy, 0) / looks.length);
  return { colors, energy: Math.round(energy * 100) / 100 };
}

/** Merges the looks of several presets (one per device) into one look for a scene. */
export function mergeLooks(looks: PresetLook[]): PresetLook {
  if (!looks.length) return { colors: [], energy: 0.3 };
  // Interleave so each device contributes its main color first.
  const interleaved: string[] = [];
  for (let i = 0; i < 6; i++) for (const l of looks) if (l.colors[i]) interleaved.push(l.colors[i]);
  const energy = looks.reduce((n, l) => n + l.energy, 0) / looks.length;
  return { colors: distinctColors(interleaved), energy: Math.round(energy * 100) / 100 };
}
