import { roofTrack, type Stage } from '../../../shared/layout.ts';
import { hsv, type Frame } from './frame.ts';
import type { Game } from './types.ts';

/** Calm animation shown when nobody is playing: slow color waves on the roof; everything else breathes. */
export function idleGame(stage: Stage): Game {
  let t = 0;
  // The roof as one track, as it looks from the street, so the waves flow evenly across the house.
  const track = roofTrack(stage);
  const span = Math.max(1, track.n - 1);
  // Everything that is not the roof (bushes, trees, other lines) breathes and twinkles.
  const others = stage.fixtures.map((f, fi) => ({ f, fi })).filter(({ f }) => f.kind !== 'roof');
  return {
    id: 'idle',
    update(dt, frame) {
      t += dt;
      frame.clear();
      for (let k = 0; k < track.leds.length; k++) {
        const x = track.at[k] / span;
        const wave = 0.5 + 0.5 * Math.sin(x * 9 - t * 0.6) * Math.sin(x * 3.1 + t * 0.23);
        frame.set(track.leds[k], hsv(0.08 + 0.06 * Math.sin(x * 4 + t * 0.1), 0.75, 0.12 + 0.35 * wave));
      }
      for (const { f, fi } of others) {
        const breathe = 0.5 + 0.5 * Math.sin(t * 0.8 + fi * 1.7);
        for (let i = 0; i < f.count; i++) {
          const twinkle = Math.max(0, Math.sin(t * 3 + i * 12.9898) - 0.85) * 3;
          frame.set(f.offset + i, hsv(0.36 + 0.05 * fi, 0.7, 0.08 + 0.18 * breathe + 0.4 * twinkle));
        }
      }
    },
    input() {},
    status: () => ({ phase: 'idle', message: 'Pick a game to play!', score: 0, lives: null, goal: null })
  };
}
