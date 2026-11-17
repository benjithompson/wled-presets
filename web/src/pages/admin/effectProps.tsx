// The Effect section of the layout editor's inspector: which effect the selected object plays,
// and how. The effects themselves are in shared/effects.ts.
import type { ReactNode } from 'react';
import { Copy, Plus, X } from 'lucide-react';
import { defaultSettings, DIRECTIONS, effectDirection, EFFECTS, effectInfo, paletteColors, PALETTES, type Direction, type EffectId, type EffectSettings, type PaletteId } from '../../../../shared/effects.ts';
import { PropButton, PropNote, PropRow, PropSelect, PropSlider } from './props.tsx';

/** The effect menu: the basics, effects along a string, and effects in space. */
export const EFFECT_GROUPS: { label: string; options: [EffectId, string][] }[] = [
  { label: 'Basics', options: EFFECTS.filter((e) => e.basic).map((e) => [e.id, e.name]) },
  { label: 'Along the string (1-D)', options: EFFECTS.filter((e) => e.space === '1d' && !e.basic).map((e) => [e.id, e.name]) },
  { label: 'In space (3-D)', options: EFFECTS.filter((e) => e.space === '3d').map((e) => [e.id, e.name]) }
];

/** True when the effect plays colors you picked, not the ones it starts with. */
function ownColors(s: EffectSettings): boolean {
  if (s.palette !== 'custom') return false;
  const start = effectInfo(s.effect).colors;
  return !start || start.join() !== (s.colors ?? []).join();
}

/** A strip that shows a palette's colors as they blend. */
export function PaletteSwatch({ colors, className }: { colors: string[]; className?: string }) {
  const stops = colors.length > 1 ? colors : [colors[0] ?? '#ffffff', colors[0] ?? '#ffffff'];
  return <span aria-hidden className={className} style={{ background: `linear-gradient(90deg, ${stops.join(', ')})` }} />;
}

export function EffectProps({
  effect,
  onChange,
  onCopyToAll,
  objectCount,
  noneLabel = 'None (dark)',
  copyLabel = 'Use on every object',
  copyTitle = 'Every object plays this effect, with these settings',
  emptyNote
}: {
  effect: EffectSettings | undefined;
  onChange: (effect: EffectSettings | undefined) => void;
  /** Gives every object (or every segment) this effect. Left out: no such button. */
  onCopyToAll?: () => void;
  /** How many objects (or segments) "copy" would reach; the button is off below 2. */
  objectCount: number;
  noneLabel?: string;
  copyLabel?: string;
  copyTitle?: string;
  /** Shown when there is no effect. */
  emptyNote?: ReactNode;
}) {
  const set = (patch: Partial<EffectSettings>) => effect && onChange({ ...effect, ...patch });
  const info = effect ? effectInfo(effect.effect) : null;
  const colors = effect ? paletteColors(effect) : [];

  return (
    <>
      <PropSelect<EffectId | ''>
        label="Effect"
        hint="Drawn by the server, 60 times a second, and sent to the lights."
        value={effect?.effect ?? ''}
        options={[['', noneLabel]]}
        groups={EFFECT_GROUPS}
        onChange={(id) => {
          if (!id) return onChange(undefined);
          // A new effect starts with its own colors, unless you picked yours.
          const next = defaultSettings(id);
          onChange(effect ? { ...next, ...(ownColors(effect) ? { palette: 'custom', colors: effect.colors } : {}), brightness: effect.brightness } : next);
        }}
      />
      {effect && info ? (
        <>
          <PropNote>{info.description}</PropNote>
          <PropSelect<PaletteId>
            label="Colors"
            value={effect.palette}
            options={PALETTES.map((p): [PaletteId, string] => [p.id, p.id === info.palette ? `${p.name} (default)` : p.name])}
            onChange={(palette) => set({ palette, colors: palette === 'custom' ? (effect.colors ?? paletteColors(effect).slice(0, 3)) : effect.colors })}
          />
          <PropRow label="">
            <PaletteSwatch colors={colors} className="block h-2.5 w-full rounded-full ring-1 ring-black/10 dark:ring-white/10" />
          </PropRow>
          {effect.palette === 'custom' ? <CustomColors colors={colors} onChange={(c) => set({ colors: c })} /> : null}
          {info.speed !== false ? <PropSlider label="Speed" value={effect.speed} onChange={(speed) => set({ speed })} hint="50 is the effect's normal pace" /> : null}
          {info.intensity ? <PropSlider label={info.intensity} value={effect.intensity} onChange={(intensity) => set({ intensity })} /> : null}
          {info.size ? <PropSlider label={info.size} value={effect.size} onChange={(size) => set({ size })} /> : null}
          <PropSlider label="Brightness" value={effect.brightness} onChange={(brightness) => set({ brightness })} />
          {info.directions ? (
            <PropSelect<Direction>
              label="Direction"
              hint="Which way it moves through space"
              value={effectDirection(effect)}
              options={info.directions.map((d): [Direction, string] => [d, DIRECTIONS[d]])}
              onChange={(direction) => set({ direction })}
            />
          ) : (info.space === '1d' && !info.uniform) || info.reverse ? (
            <PropRow label="Direction" hint={info.space === '1d' ? 'The effect runs from the first point to the last, or back' : undefined}>
              <label className="flex h-7 cursor-pointer items-center gap-2 text-xs text-stone-700 dark:text-stone-300">
                <input type="checkbox" checked={!!effect.reverse} onChange={(e) => set({ reverse: e.target.checked || undefined })} className="accent-sky-600" />
                {info.space === '1d' ? 'Last point to first' : info.reverse}
              </label>
            </PropRow>
          ) : null}
          <div className="flex flex-wrap gap-1.5 pt-1">
            {onCopyToAll ? (
              <PropButton onClick={onCopyToAll} disabled={objectCount < 2} title={copyTitle}>
                <Copy /> {copyLabel}
              </PropButton>
            ) : null}
            <PropButton onClick={() => onChange(undefined)} danger>
              <X /> Remove
            </PropButton>
          </div>
        </>
      ) : emptyNote ? (
        <PropNote>{emptyNote}</PropNote>
      ) : (
        <PropNote>Pick an effect for this object. Effects play in the views; turn on Lights to see them on the real lights too. Save them as a scene to put them on the public page.</PropNote>
      )}
    </>
  );
}

function CustomColors({ colors, onChange }: { colors: string[]; onChange: (c: string[]) => void }) {
  return (
    <PropRow label="My colors">
      <div className="flex flex-wrap items-center gap-1">
        {colors.map((c, i) => (
          <span key={i} className="group relative">
            <input
              type="color"
              value={c}
              aria-label={`Color ${i + 1}`}
              onChange={(e) => onChange(colors.map((x, j) => (j === i ? e.target.value : x)))}
              className="block size-7 cursor-pointer rounded-md border-0 bg-transparent p-0 [&::-moz-color-swatch]:rounded-md [&::-webkit-color-swatch]:rounded-md [&::-webkit-color-swatch]:border-0 [&::-webkit-color-swatch-wrapper]:p-0.5"
            />
            {colors.length > 1 ? (
              <button
                type="button"
                aria-label={`Remove color ${i + 1}`}
                onClick={() => onChange(colors.filter((_, j) => j !== i))}
                className="absolute -top-1 -right-1 hidden size-3.5 place-items-center rounded-full bg-stone-900 text-white group-hover:grid dark:bg-white dark:text-stone-900 [&_svg]:size-2.5"
              >
                <X />
              </button>
            ) : null}
          </span>
        ))}
        {colors.length < 6 ? (
          <button
            type="button"
            aria-label="Add a color"
            title="Add a color"
            onClick={() => onChange([...colors, colors.at(-1) ?? '#ffffff'])}
            className="grid size-7 place-items-center rounded-md bg-stone-100 text-stone-600 hover:bg-stone-200 dark:bg-stone-800 dark:text-stone-300 dark:hover:bg-stone-700 [&_svg]:size-3.5"
          >
            <Plus />
          </button>
        ) : null}
      </div>
    </PropRow>
  );
}
