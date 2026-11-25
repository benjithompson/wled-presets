import type { Stage } from '../../../shared/layout.ts';
import { hex, hsv, mix, WHITE, type Rgb } from '../../../shared/color.ts';
import { type Frame } from './frame.ts';
import { COLORS, Flare, heat, Recent, Sparks, TONES, Trail, Yard } from './kit.ts';
import { Fx, MIN_ROOF, Round } from './round.ts';
import type { Mood } from './show.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Roof Duel: Fire (the left end of the roof) against Ice (the right end). A ball of light flies
// along the roofline; tap when it is in your end zone to send it back. The later you hit it (the
// nearer the end), the faster it flies back: a hit at the very tip is a SMASH. The ball rolls
// over the real roof: it slows climbing to a peak and speeds up coming down. Every hit makes the
// rally faster. Let the ball past your end and the other side scores; first to five wins.
//
// The yard keeps the score: the roof is split between Fire and Ice, and the line between them
// moves toward whoever is losing. Each point flies as a light from the roof into the scorer's
// bushes (the bushes on their side of the house), which fill up with their color. The trees
// heat up with a long rally. The windows and doors on each side glow in their team's color and
// flash with every hit. One phone plays the house: tap twice.
//
// The ends are the ends of the roof the street can see: where the roof line runs on out of sight
// (back along the side of the house), that stretch belongs to neither end, and each end zone is
// as long as the other in what can be seen.
//
// Now and then a power orb shows up somewhere along the middle of the roof: one or two LEDs,
// flashing. The first to tap while the ball is right over it takes it (a tap that misses is a
// swing at nothing). The orb's winner gets power: their side of the yard throbs with it, and
// their next few shots (a serve too) fly much faster, as a white-hot ball crackling with sparks.

type Phase = 'lobby' | 'countdown' | 'serve' | 'rally' | 'point' | 'won';

interface Slot {
  id: string | null;
  house: boolean;
}

const WIN = 5;
const TEAMS = [
  { name: 'Fire', color: COLORS.fire },
  { name: 'Ice', color: COLORS.ice }
];
/** A press this late (the ball already past the end) still counts: Wi-Fi is not always quick. */
const GRACE = 0.12;
/** The ball as the player saw it: this long ago. */
const LAG = 0.07;
/** The power orb: its color (none of the teams', nor the ball's white). */
const ORB = TONES.magenta;
/** How close (in roof steps) the ball must be to the orb, as the player saw it, for a tap to take it. */
const ORB_REACH = 1.5;
/** Seconds of rally an orb waits for someone to take it. */
const ORB_LIFE = 9;
/** Powered shots the orb gives, and how much faster they fly. */
const POWER_SHOTS = 3;
const POWER_BOOST = 1.55;
/** A random number from lo to hi. */
const between = (lo: number, hi: number) => lo + Math.random() * (hi - lo);

export function duelGame(stage: Stage): Game {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= MIN_ROOF;
  const sparks = new Sparks(roof, n * 0.12, 1.6);
  const fx = new Fx(yard, { sparks });
  const { motes, waves, show } = fx;
  const flare = [new Flare(4), new Flare(4)];
  // What the street can see of the roof: from the first step that shows to the last. Distances
  // from an end count only steps that show, so a stretch out of sight (the roof running back
  // along the side of the house) does not eat into an end zone.
  let first = 0;
  let last = n - 1;
  const anySeen = roof.hidden.some((h) => !h);
  if (anySeen) {
    while (first < n - 1 && roof.hidden[first]) first++;
    while (last > first && roof.hidden[last]) last--;
  }
  /** Per step: how many steps that show from position 0 up to it. */
  const seenAt = new Float32Array(n);
  for (let i = 1; i < n; i++) seenAt[i] = seenAt[i - 1] + (anySeen && roof.hidden[i] ? 0 : 1);
  const span = Math.max(1, seenAt[last] - seenAt[first]);
  const zone = Math.max(8, Math.round(span * 0.16));
  const baseSpeed = n / 2.6;
  const topSpeed = n / 0.75;
  const gravity = n * 0.25;
  /** The ball's trail, tagged with the side that hit it last (for its color). */
  const trail = new Trail(n);
  // The whole yard plays along: its backdrop is Fire's on the left and Ice's on the right, the leader's taking more,
  // heats up with a long rally, and every point sweeps the yard in the scorer's color.
  for (const t of yard.trees) show.dim(t, 0.45);
  // The ball is the only white on the roof: the show stays faint there.
  show.roofShare = 0.25;
  // Fireworks burst below the eaves (where there is something there), so they stay off the roof.
  show.belowRoof();
  show.roofLevel = 0.5;
  /** Rally lengths that set off a sweep through the yard. */
  let rallyMark = 0;

  // Each bush LED belongs to the side of the house it is on; they fill bottom up.
  const sideLeds: number[][] = [[], []];
  for (const b of yard.bushes) {
    for (const i of b.bottomUp) {
      const x = stage.positions[(b.offset + i) * 2];
      sideLeds[x < yard.middle ? 0 : 1].push(b.offset + i);
    }
  }
  for (const list of sideLeds) list.sort((a, b) => stage.positions[b * 2 + 1] - stage.positions[a * 2 + 1]);

  const slots: Slot[] = [
    { id: null, house: false },
    { id: null, house: false }
  ];
  const round = new Round<Phase>('duel', 'lobby');
  const score = [0, 0];
  /** Points that have landed in the bushes (they fly there first). */
  const shown = [0, 0];
  let server = Math.random() < 0.5 ? 0 : 1;
  let pos = 0;
  let vel = 0;
  let owner = 0;
  let rally = 0;
  let rallySpeed = baseSpeed;
  let lastHit = '';
  let lastScorer = 0;
  const lockout = [0, 0];
  /** Where the ball was lately: a swing is judged by what the player saw. */
  const seen = new Recent<{ pos: number; vel: number }>(0.4);
  /** The house's plan for the ball coming at it: how deep to hit, or to miss. */
  let housePlan: { depth: number; miss: boolean } | null = null;
  /** The power orb on the roof, and the rally seconds it has been there. */
  let orb: { pos: number; age: number } | null = null;
  /** Seconds of rally (in this match) so far, and when the next orb shows up. */
  let rallyClock = 0;
  let orbAt = 0;
  /** Powered shots each side has left. */
  const power = [0, 0];
  /** The ball in play was hit with power. */
  let powered = false;
  /** Who took the orb last, and when: the yard sparkles for a while after. */
  let orbTaken: { side: number; at: number } | null = null;
  /** A word for the phones for a moment (the orb taken, a power shot), and until when. */
  let news = { text: '', until: 0 };

  // ---------- The two ends ----------

  /** Position of a side's end of the roof. Fire is the left end, as seen from the street. */
  const endOf = (side: number) => ((side === 0) === roof.startsLeft ? first : last);
  /** Steps that show from position 0 to a fractional position. */
  function seen0(p: number) {
    const q = Math.max(0, Math.min(n - 1, p));
    const i = Math.floor(q);
    const j = Math.min(n - 1, i + 1);
    return seenAt[i] + (seenAt[j] - seenAt[i]) * (q - i);
  }
  /** How far a position is from a side's end, in steps that show (0 at the end and past it). */
  const fromEnd = (side: number, p: number) => Math.abs(seen0(Math.max(first, Math.min(last, p))) - seenAt[endOf(side)]);
  /** The direction of travel toward a side's end. */
  const toward = (side: number) => ((side === 0) === roof.startsLeft ? -1 : 1);
  /** The position `d` steps that show in from a side's end. */
  function inward(side: number, d: number) {
    const e = endOf(side);
    const dir = -toward(side);
    for (let i = e; i >= 0 && i < n; i += dir) if (fromEnd(side, i) >= d) return i;
    return e + dir * d;
  }
  /** The steps of each end zone, from the end in, with how deep in the zone each is (1 at the end). */
  const zoneSteps = [0, 1].map((side) => {
    const steps: { i: number; depth: number }[] = [];
    for (let i = endOf(side); i >= 0 && i < n && fromEnd(side, i) < zone; i -= toward(side)) steps.push({ i, depth: 1 - fromEnd(side, i) / zone });
    return steps;
  });
  const heading = () => (Math.sign(vel) === toward(0) ? 0 : 1);
  const human = (side: number) => !!slots[side].id;
  const sideOf = (id: string) => slots.findIndex((s) => s.id === id);

  function startMatch() {
    score[0] = score[1] = 0;
    shown[0] = shown[1] = 0;
    fx.clear();
    rallyMark = 0;
    orb = null;
    orbTaken = null;
    power[0] = power[1] = 0;
    powered = false;
    rallyClock = 0;
    orbAt = between(8, 20);
    // Both colors run in from their own ends and meet in the middle.
    show.sweep(TEAMS[0].color, { dir: 'right', amount: 0.6, duration: 1 });
    show.sweep(TEAMS[1].color, { dir: 'left', amount: 0.6, duration: 1 });
    round.to('countdown');
  }

  function serve() {
    pos = inward(server, zone * 0.4);
    vel = 0;
    owner = server;
    powered = false;
    rally = 0;
    rallySpeed = baseSpeed;
    trail.clear();
    seen.clear();
    housePlan = null;
    round.to('serve');
  }

  function launch() {
    const boost = usePower(server);
    vel = -toward(server) * rallySpeed * (boost ? POWER_BOOST * 1.1 : 1);
    const p = roof.point(pos);
    sparks.burst(pos, [TEAMS[server].color, WHITE], 20, n * 0.2, 0.7);
    flare[server].add(TEAMS[server].color, 0.6);
    waves.add(p.x, p.y, TEAMS[server].color, { amount: 0.35 });
    show.pulse(TEAMS[server].color, 0.08);
    round.to('rally');
  }

  /**
   * A shot by a side with power: it uses one up, and goes off like a bomb. True when it did. The
   * ball flies faster and looks it (see drawBall).
   */
  function usePower(side: number) {
    powered = power[side] > 0;
    if (!powered) return false;
    power[side]--;
    const c = TEAMS[side].color;
    const p = roof.point(pos);
    sparks.burst(pos, [WHITE, c, COLORS.gold, ORB], 70, n * 0.45, 1.3);
    show.explode(p.x, p.y, mix(c, WHITE, 0.3), { size: 1.3 });
    waves.add(p.x, p.y, mix(c, ORB, 0.3), { amount: 0.9 });
    flare[side].add(WHITE, 1.4);
    rocket(side, [c, ORB, COLORS.gold], 1, 'crackle');
    news = { text: power[side] ? `⚡ POWER SHOT! (${power[side]} left)` : '⚡ POWER SHOT! (the last one)', until: round.clock + 1.6 };
    return true;
  }

  function hit(side: number, depth: number) {
    const d = Math.max(0, Math.min(1, depth));
    rally++;
    rallySpeed = Math.min(topSpeed, rallySpeed * 1.05);
    const boost = usePower(side);
    const speed = boost ? Math.min(topSpeed * 1.6, rallySpeed * (0.8 + 0.9 * d * d) * POWER_BOOST) : Math.min(topSpeed, rallySpeed * (0.8 + 0.9 * d * d));
    vel = -toward(side) * speed;
    // A press late enough that the ball had gone past the end: bring it back on the roof.
    pos = Math.max(first, Math.min(last, pos));
    owner = side;
    housePlan = null;
    const smash = d > 0.8;
    lastHit = smash ? 'SMASH!' : d > 0.5 ? 'Great hit!' : 'Hit!';
    const c = TEAMS[side].color;
    sparks.burst(pos, smash ? [WHITE, c, mix(c, WHITE, 0.5)] : [c, mix(c, WHITE, 0.4)], smash ? 50 : 24, n * (smash ? 0.4 : 0.25), smash ? 1.2 : 0.8);
    flare[side].add(smash ? WHITE : c, smash ? 1.2 : 0.6);
    show.pulse(c, smash ? 0.16 : 0.06);
    if (smash) {
      const p = roof.point(pos);
      waves.add(p.x, p.y, mix(c, WHITE, 0.3), { amount: 0.8 });
      rocket(side, [c, mix(c, COLORS.gold, 0.5)], 1, 'crackle');
    } else if (d > 0.5) rocket(side, [c], 0.6);
    // Every five in a rally, the rally's heat sweeps out through the yard.
    if (rally >= rallyMark + 5) {
      rallyMark = rally;
      show.sweep(heat(Math.min(1, rally / 15) * 0.8 + 0.2), { dir: 'out', amount: 0.55, duration: 0.7 });
    }
  }

  /** The middle of a side of the yard, as seen from the street: Fire left, Ice right. */
  function sideX(side: number, spread = 0.3) {
    const box = show.box;
    return box.x + box.w * (side === 0 ? 0.08 + Math.random() * spread : 0.92 - Math.random() * spread);
  }

  /** A firework on one team's side of the yard (no more than a few in the air). */
  function rocket(side: number, colors: Rgb[], size: number, kind?: 'peony' | 'ring' | 'willow' | 'crackle') {
    if (show.rocketsUp >= 3) return;
    show.firework({ x: sideX(side), colors, size, kind });
  }

  function whiff(side: number) {
    lockout[side] = round.clock + 0.4;
    sparks.burst(inward(side, zone * 0.3), [[0.3, 0.3, 0.35]], 6, n * 0.05, 0.4);
    // A swing at nothing: a dull red shudder on that side of the house.
    const p = roof.point(endOf(side));
    show.ripple(p.x, p.y, COLORS.bad, { amount: 0.25, speed: stage.scale * 10 });
  }

  function pointTo(scorer: number) {
    const loser = 1 - scorer;
    score[scorer]++;
    lastScorer = scorer;
    const end = endOf(loser);
    const p = roof.point(end);
    const c = TEAMS[scorer].color;
    sparks.burst(end, [c, WHITE, COLORS.bad], powered ? 110 : 60, n * (powered ? 0.6 : 0.4), 1.3);
    waves.add(p.x, p.y, c, { amount: 0.9 });
    flare[loser].add(COLORS.bad, 0.8);
    // The loser's end blows up (a power shot blows it up more); the scorer's color sweeps over
    // the yard from their end, and fireworks go up on their side.
    show.explode(p.x, p.y, mix(c, COLORS.bad, 0.4), { size: powered ? 2.2 : 1.4 });
    powered = false;
    show.sweep(c, { dir: scorer === 0 ? 'right' : 'left', amount: 0.8, duration: 0.9 });
    const won = score[scorer] >= WIN;
    if (!won) for (let k = 0; k < 2; k++) show.firework({ x: sideX(scorer), colors: [c, mix(c, COLORS.gold, 0.5)], delay: k * 0.25 });
    else {
      // The match: a flash over everything, and the winner's finale.
      show.explode(p.x, p.y, c, { size: 2.5, over: true });
      show.finale(7, { colors: [[c, COLORS.gold], [c], [mix(c, WHITE, 0.3), c]] });
    }
    // The point flies from the roof into the scorer's bushes.
    const leds = sideLeds[scorer];
    const target = leds.length ? leds.reduce((a, i) => ({ x: a.x + stage.positions[i * 2] / leds.length, y: a.y + stage.positions[i * 2 + 1] / leds.length }), { x: 0, y: 0 }) : roof.point(endOf(scorer));
    motes.fly(p, target, c, 1.1, {
      arc: stage.scale * 3,
      size: 40,
      arrive: () => {
        shown[scorer]++;
        waves.add(target.x, target.y, c, { amount: 0.6, reach: stage.scale * 6 });
      }
    });
    trail.clear();
    server = loser;
    round.to('point');
  }

  // ---------- Input ----------

  function inZone(side: number, h: { pos: number; vel: number }) {
    return Math.sign(h.vel) === toward(side) && fromEnd(side, h.pos) <= zone;
  }

  function swing(side: number) {
    if (round.clock < lockout[side]) return;
    if (round.phase === 'serve' && side === server && round.time > 0.3) return launch();
    if (round.phase !== 'rally') return;
    // Where the ball was when the player saw it; past the end counts as the deepest hit.
    const then = seen.since(round.clock - LAG)[0] ?? seen.latest;
    const recent = seen.since(round.clock - GRACE).filter((h) => inZone(side, h));
    const h = then && inZone(side, then) ? then : recent.at(-1);
    if (h) return hit(side, 1 - fromEnd(side, h.pos) / zone);
    if (orb && overOrb()) return takeOrb(side);
    whiff(side);
  }

  // ---------- The power orb ----------

  /** A new orb, at a random spot of the roof that shows, well away from both end zones. */
  function spawnOrb() {
    const spots: number[] = [];
    for (let i = first; i <= last; i++) {
      if (fromEnd(0, i) < zone + span * 0.08 || fromEnd(1, i) < zone + span * 0.08) continue;
      if (roof.hiddenAt(i - 1) || roof.hiddenAt(i) || roof.hiddenAt(i + 1)) continue;
      spots.push(i);
    }
    if (!spots.length) return;
    orb = { pos: spots[Math.floor(Math.random() * spots.length)], age: 0 };
    // It arrives with a little crackle, so the players notice it.
    const p = roof.point(orb.pos);
    sparks.burst(orb.pos, [ORB, WHITE], 18, n * 0.1, 0.6);
    waves.add(p.x, p.y, ORB, { amount: 0.4, reach: stage.scale * 4 });
    news = { text: '⚡ A power orb! Tap just as the ball crosses it.', until: round.clock + 2.5 };
  }

  /** Whether the ball, as the player saw it lately, went right over the orb. */
  function overOrb() {
    if (!orb) return false;
    const path = seen.since(round.clock - GRACE);
    for (let k = 0; k < path.length; k++) {
      const a = path[k].pos;
      const b = path[Math.max(0, k - 1)].pos;
      if (orb.pos >= Math.min(a, b) - ORB_REACH && orb.pos <= Math.max(a, b) + ORB_REACH) return true;
    }
    return false;
  }

  /** A side takes the orb: a sparkling explosion, and power for their next few shots. */
  function takeOrb(side: number) {
    if (!orb) return;
    const c = TEAMS[side].color;
    const p = roof.point(orb.pos);
    power[side] = POWER_SHOTS;
    orbTaken = { side, at: round.clock };
    sparks.burst(orb.pos, [WHITE, ORB, COLORS.gold, c], 120, n * 0.6, 1.8);
    show.explode(p.x, p.y, mix(ORB, WHITE, 0.35), { size: 2.2, debris: 60 });
    show.flash(p.x, p.y, WHITE, { size: 3, duration: 0.3 });
    waves.add(p.x, p.y, ORB, { amount: 1 });
    waves.add(p.x, p.y, c, { amount: 0.8, speed: stage.scale * 9 });
    // Their color runs from the orb to their end of the yard, and fireworks go up on their side.
    show.sweep(c, { dir: side === 0 ? 'left' : 'right', amount: 0.8, duration: 0.7 });
    for (let k = 0; k < 3; k++) show.firework({ x: sideX(side), colors: [c, ORB, COLORS.gold], kind: k === 1 ? 'crackle' : 'peony', delay: k * 0.2 });
    flare[side].add(WHITE, 1.6);
    news = { text: `⚡ ${TEAMS[side].name} takes the power orb! The next ${POWER_SHOTS} shots fly.`, until: round.clock + 2.5 };
    orb = null;
    orbAt = Infinity;
  }

  /** The orb's clock, which runs only in a rally: it shows up, waits, and fizzles out. */
  function stepOrb(dt: number, from: number) {
    if (round.phase !== 'rally') return;
    rallyClock += dt;
    // Once a side's power is used up, the next orb is some time off.
    if (orbAt === Infinity && !power[0] && !power[1]) orbAt = rallyClock + between(12, 30);
    if (!orb && rallyClock >= orbAt) spawnOrb();
    if (!orb) return;
    orb.age += dt;
    if (orb.age > ORB_LIFE) {
      sparks.burst(orb.pos, [[0.3, 0.1, 0.3]], 8, n * 0.05, 0.5);
      orb = null;
      orbAt = rallyClock + between(10, 25);
      return;
    }
    // The house goes for the orb now and then, as the ball goes over it.
    const crossed = Math.min(from, pos) - ORB_REACH <= orb.pos && orb.pos <= Math.max(from, pos) + ORB_REACH;
    const houses = [0, 1].filter((s) => !human(s) && slots[s].house);
    if (crossed && houses.length && Math.random() < 0.1) takeOrb(houses[Math.floor(Math.random() * houses.length)]);
  }

  function input(e: GameInput) {
    if (e.action !== 'press' || !playable) return;
    const side = sideOf(e.playerId);
    if (round.phase === 'lobby') {
      if (side >= 0) {
        // A second tap with nobody else here: play the house.
        const other = 1 - side;
        if (!slots[other].id) {
          slots[other] = { id: null, house: true };
          startMatch();
        }
        return;
      }
      const free = slots.findIndex((s) => !s.id);
      if (free < 0) return;
      slots[free] = { id: e.playerId, house: false };
      const p = roof.point(endOf(free));
      waves.add(p.x, p.y, TEAMS[free].color, { amount: 0.7 });
      sparks.burst(endOf(free), [TEAMS[free].color, WHITE], 30, n * 0.25);
      show.sweep(TEAMS[free].color, { dir: free === 0 ? 'right' : 'left', amount: 0.7 });
      show.firework({ x: sideX(free), colors: [TEAMS[free].color] });
      if (slots.every((s) => s.id)) startMatch();
      return;
    }
    if (side < 0) return;
    if (round.phase === 'won' && round.time > 2.5) return startMatch();
    swing(side);
  }

  function leave(id: string) {
    const side = sideOf(id);
    if (side < 0) return;
    // In a match the house takes over; in the lobby the place is free again.
    slots[side] = round.phase === 'lobby' ? { id: null, house: false } : { id: null, house: true };
    if (!slots[0].id && !slots[1].id) {
      slots[0] = { id: null, house: false };
      slots[1] = { id: null, house: false };
      round.to('lobby');
    }
  }

  // ---------- Physics ----------

  function stepBall(dt: number) {
    if (round.phase !== 'rally') return;
    const dir = Math.sign(vel) || 1;
    // Gravity along the roof; the ball never stalls on a climb.
    vel -= gravity * roof.slopeAt(pos) * dt;
    // A power shot keeps its pace: it hardly slows on a climb.
    const minSpeed = n * (powered ? 0.4 : 0.16);
    const cap = topSpeed * (powered ? 1.8 : 1.2);
    if (Math.sign(vel) !== dir || Math.abs(vel) < minSpeed) vel = dir * minSpeed;
    vel = Math.max(-cap, Math.min(cap, vel));
    const from = pos;
    pos += vel * dt;
    seen.push(round.clock, { pos, vel });
    stepOrb(dt, from);

    const target = heading();
    // The house plays its side.
    if (!human(target) && slots[target].house) {
      if (fromEnd(target, pos) <= zone && !housePlan) {
        const behind = score[target] - score[1 - target];
        const pace = Math.abs(vel) / topSpeed;
        housePlan = { depth: 0.2 + Math.random() * (0.55 + Math.max(0, -behind) * 0.05), miss: Math.random() < Math.min(0.45, 0.05 + rally * 0.012 + pace * 0.25) };
      }
      if (housePlan && !housePlan.miss && 1 - fromEnd(target, pos) / zone >= housePlan.depth) hit(target, 1 - fromEnd(target, pos) / zone);
    }
    // Past the end, with a little grace for a late press.
    const over = (pos - endOf(target)) * toward(target);
    if (over > Math.abs(vel) * GRACE) pointTo(1 - target);
  }

  // ---------- Drawing ----------

  /** How strongly a side's power throbs now (0: no power). Quicker as its last shots go. */
  function throbOf(side: number) {
    if (!power[side]) return 0;
    const rate = 5 + (POWER_SHOTS - power[side]) * 2;
    return 0.5 + 0.5 * Math.sin(round.clock * rate);
  }

  function drawRoof(dt: number) {
    // The roof is split between the teams; the line moves toward whoever is losing. A side with
    // power throbs with it.
    const front = 0.5 + (0.4 * (score[0] - score[1])) / WIN;
    const throb = [throbOf(0), throbOf(1)];
    for (let i = 0; i < n; i++) {
      const q = fromEnd(0, i) / span;
      const side = q < front ? 0 : 1;
      const edge = Math.abs(q - front) * span < 1.5;
      yard.roofAt(i, TEAMS[side].color, 0.05 + 0.015 * Math.sin(round.clock * 2 + i * 0.2) + (power[side] ? 0.06 + 0.14 * throb[side] : 0));
      if (edge) yard.roofAt(i, WHITE, 0.25 + 0.2 * Math.sin(round.clock * 9));
    }
    // End zones: brighter as the ball comes at them, with a white-hot tip for a smash.
    for (let side = 0; side < 2; side++) {
      const c = TEAMS[side].color;
      const coming = round.phase === 'rally' && heading() === side ? Math.max(0, 1 - Math.max(0, fromEnd(side, pos) - zone) / (span * 0.5)) : 0;
      const locked = round.clock < lockout[side];
      for (const { i, depth } of zoneSteps[side]) {
        const tip = depth > 0.8 ? 0.15 + 0.1 * Math.sin(round.clock * 10) : 0;
        yard.roofAt(i, locked ? [0.3, 0.3, 0.3] : c, 0.1 + coming * 0.3 + depth * 0.06);
        if (tip && !locked) yard.roofAt(i, WHITE, tip * (0.5 + coming));
      }
    }
    drawOrb();
    // The ball and its trail, in the color of whoever hit it last (a power shot's trail burns gold).
    trail.fade(dt, (4 + (Math.abs(vel) / n) * 4) * (powered ? 0.45 : 1));
    if (round.phase === 'rally' || round.phase === 'serve') drawBall();
    trail.draw(yard, (_, tag) => (tag >= 2 ? mix(TEAMS[tag - 2].color, COLORS.gold, 0.35) : TEAMS[tag].color), 0.8, 0.02);
    if (round.phase === 'countdown') {
      // Three beats run out from the middle of the roof to both ends.
      const beat = round.time % 1;
      const mid = (first + last) / 2;
      const half = Math.max(1, (last - first) / 2);
      for (let i = 0; i < n; i++) {
        const d = Math.abs(i - mid) / half;
        yard.roofAt(i, WHITE, Math.exp(-(((d - beat) * 12) ** 2)) * 0.8);
      }
    }
    sparks.draw(yard);
  }

  function drawBall() {
    const p = Math.max(0, Math.min(n - 1, pos));
    trail.mark(p, owner + (powered ? 2 : 0));
    const hot = Math.min(1, Math.abs(vel) / topSpeed);
    const team = TEAMS[owner].color;
    const pulse = round.phase === 'serve' ? 0.6 + 0.4 * Math.sin(round.clock * 8) : 1;
    // A serve with power already crackles as it waits.
    if (!powered && !(round.phase === 'serve' && power[server])) {
      yard.roofSplat(p, mix(team, WHITE, 0.25 + hot * 0.6), 1.4, pulse);
      if (hot > 0.6 && Math.random() < hot * 0.5) sparks.burst(p, [team], 1, n * 0.08, 0.4);
      return;
    }
    // A power shot: a white-hot core in a wide, flickering corona of its team's color, lightning
    // crackling round it, a spray of sparks behind it, and the yard near it lit as it passes.
    const flicker = 0.75 + 0.25 * Math.random();
    yard.roofSplat(p, team, 3.4, 0.85 * flicker);
    yard.roofSplat(p, WHITE, 1.1, 1);
    for (let k = 0; k < 2; k++) if (Math.random() < 0.6) yard.roofSplat(p + (Math.random() - 0.5) * 9, Math.random() < 0.5 ? COLORS.gold : WHITE, 0.6, 0.4 + Math.random() * 0.6);
    sparks.burst(p, [team, COLORS.gold, WHITE], 3, n * 0.14, 0.55);
    const at = roof.point(p);
    yard.glow(at.x, at.y, stage.scale * 1.6, team, 0.5 * flicker);
  }

  /** The orb: a needle of light, flashing magenta and white, quicker as it is about to go. */
  function drawOrb() {
    if (!orb || round.phase === 'won') return;
    const late = orb.age > ORB_LIFE - 2;
    const rate = late ? 22 : 11;
    const on = Math.sin(round.clock * rate * Math.PI) > -0.2;
    const c = Math.floor(round.clock * rate) % 3 === 0 ? WHITE : ORB;
    const born = Math.min(1, orb.age * 3);
    if (on) yard.roofSplat(orb.pos, c, 0.55, born);
    // A faint halo, so it can be found between flashes.
    yard.roofSplat(orb.pos, ORB, 2.5, 0.08 + 0.06 * Math.sin(round.clock * 4));
    if (Math.random() < 0.08) sparks.burst(orb.pos, [ORB, WHITE], 1, n * 0.05, 0.3);
  }

  /** For a while after the orb is taken, the whole yard glitters; the taker's side most. */
  function drawGlitter() {
    if (!orbTaken) return;
    const t = round.clock - orbTaken.at;
    if (t > 1.6) return;
    const c = TEAMS[orbTaken.side].color;
    const colors = [WHITE, ORB, COLORS.gold, c, c];
    const count = Math.round(yard.lit.length * 0.04 * (1 - t / 1.6));
    for (let k = 0; k < count; k++) {
      const i = yard.lit[Math.floor(Math.random() * yard.lit.length)];
      const side = stage.positions[i * 2] < yard.middle ? 0 : 1;
      if (side !== orbTaken.side && Math.random() < 0.5) continue;
      yard.add(i, colors[Math.floor(Math.random() * colors.length)], 0.6 + Math.random() * 0.4);
    }
  }

  function drawBushes() {
    for (let side = 0; side < 2; side++) {
      const leds = sideLeds[side];
      const c = TEAMS[side].color;
      const lit = Math.round((Math.min(WIN, shown[side]) / WIN) * leds.length);
      const winning = round.phase === 'won' && score[side] >= WIN;
      const throb = throbOf(side);
      leds.forEach((at, k) => {
        if (k < lit || winning) yard.add(at, winning ? mix(c, WHITE, Math.max(0, Math.sin(round.clock * 10 + k * 1.3)) * 0.5) : c, 0.55 + 0.1 * Math.sin(round.clock * 3 + k) + (power[side] ? 0.3 * throb : 0));
        else yard.add(at, c, 0.035 + (power[side] ? 0.1 + 0.25 * throb : 0));
      });
    }
  }

  function drawTreesAndDecor() {
    // Trees: the rally's heat, from the base up. A tree on a side with power throbs in its color.
    const t = Math.min(1, rally / 12);
    for (const tree of yard.trees) {
      const side = tree.x < yard.middle ? 0 : 1;
      const throb = power[side] ? 0.1 + 0.3 * throbOf(side) : 0;
      for (let i = 0; i < tree.count; i++) {
        const u = tree.up[i];
        if (rally && u <= t) yard.add(tree.offset + i, t >= 1 ? hsv((round.clock * 0.5 + u) % 1) : heat(u), 0.55);
        else if (throb) yard.add(tree.offset + i, TEAMS[side].color, throb);
      }
    }
    // Windows and doors: each side of the house glows in its team's color and flashes with its
    // hits, and throbs while that side has power.
    const matchPoint = round.phase !== 'won' && (score[0] === WIN - 1 || score[1] === WIN - 1);
    for (const d of yard.decor) {
      for (let i = 0; i < d.count; i++) {
        const at = d.offset + i;
        const side = stage.positions[at * 2] < yard.middle ? 0 : 1;
        // A faint tint of its side's team over the show's backdrop, and the flash of every hit.
        yard.add(at, TEAMS[side].color, 0.03 + (power[side] ? 0.1 + 0.4 * throbOf(side) : 0));
        yard.add(at, flare[side].color, 0.7);
        if (matchPoint) yard.add(at, Math.sin(round.clock * 5) > 0 ? COLORS.bad : WHITE, 0.12);
      }
    }
  }

  function drawWin() {
    const w = score[0] >= WIN ? 0 : 1;
    const c = TEAMS[w].color;
    // The winner's color takes the whole yard, in waves from their end of the roof.
    yard.wash(c, 0.12 + 0.06 * Math.sin(round.clock * 4));
    if (Math.random() < 0.04) {
      const p = roof.point(endOf(w));
      waves.add(p.x, p.y, mix(c, WHITE, 0.3), { amount: 0.7 });
    }
    if (Math.random() < 0.15) sparks.burst(Math.random() * n, [c, WHITE, mix(c, hsv(Math.random()), 0.3)], 24, n * 0.3);
    // Fireworks in the winner's colors keep going up.
    if (round.time > 1.5 && show.rocketsUp < 2 && Math.random() < 0.03) show.firework({ colors: [c, Math.random() < 0.5 ? COLORS.gold : mix(c, WHITE, 0.3)] });
  }

  /**
   * The yard's mood: Fire and Ice drifting across the house, the leader's color taking more of
   * it; brighter and quicker as a rally goes on; throbbing at match point; the winner's color
   * once the match is won. The lobby cycles gently between the two.
   */
  function moodNow(): Mood {
    const [fire, ice] = [TEAMS[0].color, TEAMS[1].color];
    if (round.phase === 'won') {
      const c = TEAMS[score[0] >= WIN ? 0 : 1].color;
      return { a: c, b: mix(c, COLORS.gold, 0.35), level: 1.2, drift: 1.6 };
    }
    // Fire's half of the yard on the left (side 0), Ice's on the right; the leader's color takes more of it.
    if (round.phase === 'lobby') return { a: fire, b: ice, level: 0.9, drift: 0.7, split: 0.5 };
    const lead = (score[0] - score[1]) / WIN;
    const heatK = Math.min(1, rally / 12);
    const matchPoint = score[0] === WIN - 1 || score[1] === WIN - 1;
    return {
      a: mix(fire, heat(0.5), heatK * 0.35),
      b: mix(ice, heat(0.5), heatK * 0.35),
      level: 0.85 + heatK * 0.5,
      drift: 1 + heatK * 1.5,
      throb: matchPoint && round.phase === 'rally' ? 1.5 : 0,
      split: 0.5 + lead * 0.35
    };
  }

  return {
    id: 'duel',

    input,
    leave,

    update(dt: number, frame: Frame) {
      round.tick(dt);
      yard.begin(frame);
      if (!playable) return;

      if (round.phase === 'countdown' && round.time >= 3) serve();
      if (round.phase === 'serve' && !human(server) && round.time > 1.2) launch();
      if (round.phase === 'serve' && human(server) && round.time > 5) launch();
      if (round.phase === 'point' && round.time > 2.2) {
        if (score[lastScorer] >= WIN) round.to('won');
        else serve();
      }
      if (round.phase === 'won' && round.time > 30) {
        // Nobody asked for a rematch: open the lobby again.
        slots[0] = { id: null, house: false };
        slots[1] = { id: null, house: false };
        round.to('lobby');
      }
      stepBall(dt);
      sparks.update(dt);
      motes.update(dt);
      waves.update(dt);
      for (const f of flare) f.update(dt);
      show.update(dt);
      show.followMood(moodNow(), 2, dt);
      // The countdown: the yard pumps once a second in both colors.
      if (round.phase === 'countdown' && Math.floor(round.time) !== Math.floor(round.time - dt)) {
        show.pulse(TEAMS[0].color, 0.08);
        show.pulse(TEAMS[1].color, 0.08);
      }
      // The lobby: now and then a firework on a side that waits for a player.
      if (round.phase === 'lobby' && show.rocketsUp === 0 && Math.random() < dt / 3) {
        const side = Math.random() < 0.5 ? 0 : 1;
        show.firework({ x: sideX(side), colors: [TEAMS[side].color], size: 0.7 });
      }

      drawRoof(dt);
      drawBushes();
      drawTreesAndDecor();
      drawGlitter();
      // A side with power sends a throb of its color out over its half of the yard.
      for (let side = 0; side < 2; side++) {
        if (!power[side] || round.phase === 'won' || Math.floor(round.clock * 1.4) === Math.floor((round.clock - dt) * 1.4)) continue;
        const p = roof.point(inward(side, zone * 0.5));
        waves.add(p.x, p.y, mix(TEAMS[side].color, ORB, 0.15), { amount: 0.45, reach: show.box.w * 0.55 });
      }
      if (round.phase === 'won') drawWin();
      if (round.phase === 'lobby') {
        // Each free end calls for a player.
        for (let side = 0; side < 2; side++) {
          if (slots[side].id) continue;
          yard.roofSplat(inward(side, zone * 0.5), TEAMS[side].color, zone * 0.3, 0.25 + 0.2 * Math.sin(round.clock * 3 + side * Math.PI));
        }
      }
      fx.draw(frame);
    },

    status(): GameStatusFields {
      if (!playable) return round.setup();
      const scores = TEAMS.map((t, i) => ({ name: slots[i].house ? `${t.name} (house)` : t.name, color: hex(t.color), value: score[i] }));
      const stats: { label: string; value: string | number }[] = rally > 1 && round.phase === 'rally' ? [{ label: 'Rally', value: rally }] : [];
      for (let side = 0; side < 2; side++) if (power[side] && round.phase !== 'won') stats.push({ label: `⚡ ${TEAMS[side].name} power`, value: power[side] });
      const base = { score: 0, lives: null, goal: null, scores, stats };
      const w = score[0] >= WIN ? 0 : 1;
      const messages: Record<Phase, string> = {
        lobby: 'Tap to join! Fire plays the left end, Ice the right.',
        countdown: 'Get ready…',
        serve: `${TEAMS[server].name} serves.`,
        rally: rally > 2 ? `${lastHit} Rally of ${rally}!` : rally ? lastHit : 'Hit it back when it reaches your end!',
        point: `${TEAMS[lastScorer].name} scores! ${score[0]}–${score[1]}`,
        won: `${TEAMS[w].name} wins ${score[w]}–${score[1 - w]}!`
      };
      const playing = round.phase === 'rally' || round.phase === 'serve';
      const message = playing && round.clock < news.until ? news.text : messages[round.phase];
      return { ...base, phase: round.phase, message, button: round.phase === 'lobby' ? 'JOIN' : '…', tone: round.phase === 'lobby' ? 'go' : 'wait' };
    },

    playerStatus(id: string): Partial<GameStatusFields> {
      const side = sideOf(id);
      if (side < 0) {
        const full = slots.every((s) => s.id);
        if (round.phase === 'lobby' && !full) return { you: null };
        return { you: null, button: '👀', tone: 'wait', message: round.phase === 'lobby' ? 'Two players are on. Watch the roof!' : `Watching: ${TEAMS[0].name} ${score[0]}–${score[1]} ${TEAMS[1].name}` };
      }
      const team = TEAMS[side];
      const you = { name: team.name, color: hex(team.color) };
      const end = side === 0 ? 'left' : 'right';
      if (round.phase === 'lobby') {
        return { you, button: 'VS HOUSE', tone: 'go', message: `You're ${team.name}: the ${end} end of the roof. Waiting for a friend to tap on their phone… or tap again to play the house.` };
      }
      if (round.phase === 'countdown') return { you, button: '…', tone: 'wait', message: `You're ${team.name} (${end} end). Get ready…` };
      if (round.phase === 'serve') return side === server ? { you, button: 'SERVE', tone: 'go', message: power[side] ? '⚡ Your serve, with power! Tap to launch.' : 'Your serve! Tap to launch.' } : { you, button: 'HIT!', tone: 'go' };
      if (round.phase === 'rally') return { you, button: 'HIT!', tone: 'go' };
      if (round.phase === 'won') return { you, button: round.time > 2.5 ? 'REMATCH' : '…', tone: score[side] >= WIN ? 'good' : 'bad', message: score[side] >= WIN ? `You win ${score[side]}–${score[1 - side]}!` : `${TEAMS[1 - side].name} wins this time. Rematch?` };
      return { you, button: '…', tone: 'wait' };
    }
  };
}
