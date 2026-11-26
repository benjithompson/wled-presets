import { Circle, House, Lightbulb, Rainbow, Shapes, Spline, TreePine, type LucideIcon } from 'lucide-react';
import type { FixtureKind } from '../../../shared/layout.ts';

/** Each kind of layout object's icon and name, wherever objects are listed. */
export const KIND_ICONS: Record<FixtureKind, LucideIcon> = { roof: House, line: Spline, bush: Circle, tree: TreePine, semicircle: Rainbow, custom: Shapes, bulb: Lightbulb };
export const KIND_LABELS: Record<FixtureKind, string> = { roof: 'Roofline', line: 'Line of lights', bush: 'Bush', tree: 'Tree', semicircle: 'Semicircle', custom: 'Custom object', bulb: 'Bulb' };
