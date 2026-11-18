// The games on the play page: what the server runs and what the public page and play page show.
import type { GameInfo } from './layout.ts';

export const GAME_CATALOG: (GameInfo & { tagline: string })[] = [
  {
    id: 'catcher',
    name: 'Comet Catcher',
    tagline: 'Stop the comet in the gate',
    description: 'Stop the comet inside the green gate. Every catch lights up a bush.',
    players: '1 player'
  },
  {
    id: 'cascade',
    name: 'Cascade',
    tagline: 'One tap, one chain reaction',
    description: 'Glowing orbs roll along the roof. One tap sets off a blast: catch them in a chain reaction.',
    players: '1 player'
  },
  {
    id: 'overflow',
    name: 'Overflow',
    tagline: 'Pour light, stop at the ring',
    description: 'Hold to pour light into each bush and tree. Let go so it settles inside the ring, not over it.',
    players: '1 player'
  },
  {
    id: 'duel',
    name: 'Roof Duel',
    tagline: 'Fire against Ice on the roof',
    description: 'Fire against Ice: hit the ball back when it reaches your end of the roof. The later the hit, the faster it flies.',
    players: '2 players, or play the house'
  }
];
