// The games on the play page: what the server runs and what the public page and play page show.
import type { GameInfo } from './layout.ts';
import type { PaintStroke } from './paint.ts';

export const GAME_CATALOG = [
  {
    id: 'catcher',
    name: 'Comet Catcher',
    tagline: 'Stop the comet in the gate',
    description: 'Stop the comet inside the green gate before it closes in. Every catch lights up a bush.',
    players: '1 player'
  },
  {
    id: 'cascade',
    name: 'Cascade',
    tagline: 'One tap, one chain reaction',
    description: 'Orbs in four colors roll along the roof. Tap to set off the white bomb before its fuse burns down: same colors set each other off for double.',
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
    description: 'Fire against Ice: hit the ball back when it reaches your end of the roof. The later the hit, the faster it flies. Tap as the ball crosses the flashing power orb for power shots.',
    players: '2 players, or play the house'
  },
  {
    id: 'slice',
    name: 'Slice',
    tagline: 'Stack it, edge to edge',
    description: 'Drop the sliding light on the band below: whatever hangs over breaks off. Line up the edges for a perfect; five in a row and the band grows back.',
    players: '1 player'
  },
  {
    id: 'colorgate',
    name: 'Color Gate',
    tagline: 'Match every wall that comes',
    description: 'Walls of color stream down the roof toward your light. Tap to change your color so each one passes: walls in a row multiply the points.',
    players: '1 player'
  },
  {
    id: 'ricochet',
    name: 'Ricochet',
    tagline: 'Catch it, it turns around',
    description: 'Tap while the white comet is in the green gate: it turns around and the next gate is already waiting. One miss ends the run.',
    players: '1 player'
  },
  {
    id: 'beads',
    name: 'Bead Rush',
    tagline: 'Match the chain before it lands',
    description: 'A chain of colored beads creeps along the roof toward you. Turn the color wheel with ◀ ▶ and fire the matching bead into its front: three of a color pop and push the chain back. Every minute brings a new color.',
    players: '1 player'
  },
  {
    id: 'beat',
    name: 'Beat Drop',
    tagline: 'Hit the colors on the beat',
    description: 'Notes in four colors slide along the roof to the lit zone: press the button in each note\'s color as it passes through, hold the long ones to their end. Pick 1, 2 or 4 colors and Easy, Normal or Hard; the beat never stops, keeps getting faster, and every 8 bars the whole roofline changes its look.',
    players: '1 player'
  },
  {
    id: 'whack',
    name: 'Whack-a-Mole',
    tagline: 'Whack them before they hide',
    description: 'Moles pop up in the bushes and trees: tap the glowing hole on your phone to whack each one before it ducks back down. Whacks in a row multiply the points, golden moles are worth five times as much, and the clock on the roof runs out in 45 seconds.',
    players: '1 player'
  },
  {
    id: 'paint',
    name: 'Light Painter',
    tagline: 'Paint the house with your finger',
    description: 'For little artists: pick a color and a sparkle, then paint the lights with your finger. Fill a whole bush in one touch, or tap Surprise!',
    players: '1 player'
  }
] as const satisfies readonly (GameInfo & { tagline: string })[];

/** A game's id: one of the catalog's. */
export type GameId = (typeof GAME_CATALOG)[number]['id'];

/** What a phone sends the game host. */
export type PlayMessage =
  | { type: 'start'; game: string }
  | { type: 'accept' }
  | { type: 'leaveLine' }
  | { type: 'stop' }
  | { type: 'leave' }
  | { type: 'input'; action: 'press' | 'release'; button?: string }
  | { type: 'setting'; id: string; value: string }
  | { type: 'initials'; id: number; initials: string }
  | ({ type: 'paint' } & PaintStroke);
