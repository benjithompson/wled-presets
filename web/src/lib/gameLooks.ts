import { Bomb, Droplets, Rocket, Swords, type LucideIcon } from 'lucide-react';

/** Each game's icon and colors: the gradient of its icon tile, and the colors of its strip. */
export const GAME_LOOKS: Record<string, { icon: LucideIcon; className: string; colors: string[] }> = {
  catcher: { icon: Rocket, className: 'from-amber-300 to-orange-500 shadow-orange-500/30', colors: ['#fcd34d', '#f97316'] },
  cascade: { icon: Bomb, className: 'from-fuchsia-500 via-violet-500 to-cyan-400 shadow-fuchsia-500/30', colors: ['#d946ef', '#8b5cf6', '#22d3ee'] },
  overflow: { icon: Droplets, className: 'from-sky-400 via-emerald-400 to-amber-300 shadow-sky-500/30', colors: ['#38bdf8', '#34d399', '#fcd34d'] },
  duel: { icon: Swords, className: 'from-orange-500 to-sky-500 shadow-orange-500/30', colors: ['#f97316', '#0ea5e9'] }
};

export const gameLook = (id: string) => GAME_LOOKS[id] ?? GAME_LOOKS.catcher;
