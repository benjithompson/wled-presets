import { fromHex } from '../../../shared/color.ts';
import { SWATCHES } from '../components/ColorPicker.tsx';

/** Hue names, each up to the hue (degrees) where the next begins. */
const HUES: [number, string][] = [
  [10, 'Red'],
  [22, 'Red-orange'],
  [38, 'Orange'],
  [48, 'Amber'],
  [64, 'Yellow'],
  [80, 'Chartreuse'],
  [100, 'Lime'],
  [158, 'Green'],
  [178, 'Teal'],
  [195, 'Cyan'],
  [215, 'Sky blue'],
  [245, 'Blue'],
  [262, 'Indigo'],
  [285, 'Purple'],
  [305, 'Magenta'],
  [330, 'Pink'],
  [348, 'Rose'],
  [360, 'Red']
];

/**
 * A color's name as people say it ("Warm white", "Teal", "Deep blue"), never its hex: the
 * swatch's own name when it is one of them, otherwise worked out from its hue and shade.
 */
export function colorName(value: string): string {
  const swatch = SWATCHES.find((s) => s.hex.toLowerCase() === value.toLowerCase());
  if (swatch) return swatch.name;
  const [r, g, b] = fromHex(value);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  if (max < 0.08) return 'Off';
  const sat = d / max;
  if (sat < 0.15) return max > 0.85 ? 'White' : max > 0.35 ? 'Gray' : 'Dim white';
  const h = ((max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4) * 60 + 360) % 360;
  // Light, orangey colors are what people call warm white on lights.
  if (sat < 0.7 && max > 0.85 && h >= 18 && h < 50) return 'Warm white';
  const name = HUES.find(([to]) => h < to)?.[1] ?? 'Red';
  if (sat < 0.45) return `Pale ${name.toLowerCase()}`;
  if (max < 0.55) return `Deep ${name.toLowerCase()}`;
  return name;
}
