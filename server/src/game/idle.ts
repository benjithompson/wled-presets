import type { Stage } from '../../../shared/layout.ts';
import { hsv, type Frame } from './frame.ts';
import type { Game } from './types.ts';

/** Calm animation shown when nobody is playing: slow color waves on the roof; everything else breathes. */
export function idleGame(stage: Stage): Game {
  let t = 0;
  return {
    id: 'idle',
    update(dt, frame) {
      t += dt;
      frame.clear();
      // The roof as one strip, so the waves flow across every roof object.
      const path = stage.roofPath;
      for (let i = 0; i < path.length; i++) {
        const x = i / Math.max(1, path.length - 1);
        const wave = 0.5 + 0.5 * Math.sin(x * 9 - t * 0.6) * Math.sin(x * 3.1 + t * 0.23);
        frame.set(path[i], hsv(0.08 + 0.06 * Math.sin(x * 4 + t * 0.1), 0.75, 0.12 + 0.35 * wave));
      }
      stage.fixtures.forEach((f, fi) => {
        for (let i = 0; i < f.count; i++) {
          // Everything that is not the roof (bushes, trees, other lines) breathes and twinkles.
          if (f.kind !== 'roof') {
            const breathe = 0.5 + 0.5 * Math.sin(t * 0.8 + fi * 1.7);
            const twinkle = Math.max(0, Math.sin(t * 3 + i * 12.9898) - 0.85) * 3;
            frame.set(f.offset + i, hsv(0.36 + 0.05 * fi, 0.7, 0.08 + 0.18 * breathe + 0.4 * twinkle));
          }
        }
      });
    },
    input() {},
    status: () => ({ phase: 'idle', message: 'Pick a game to play!', score: 0, lives: null, goal: null })
  };
}
