import type { Stage } from '../../../shared/layout.ts';
import { hsv, mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { COLORS, css, Flare, heat, Recent, Sparks, Trail, Yard } from './kit.ts';
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

export function duelGame(stage: Stage): Game {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= MIN_ROOF;
  const sparks = new Sparks(roof, n * 0.12, 1.6);
  const fx = new Fx(yard, { sparks });
  const { motes, waves, show } = fx;
  const flare = [new Flare(4), new Flare(4)];
  const zone = Math.max(8, Math.round(n * 0.16));
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

  // ---------- The two ends ----------

  /** Position of a side's end of the roof. Fire is the left end, as seen from the street. */
  const endOf = (side: number) => ((side === 0) === roof.startsLeft ? 0 : n - 1);
  /** How far a position is from a side's end. */
  const fromEnd = (side: number, p: number) => Math.abs(p - endOf(side));
  /** The direction of travel toward a side's end. */
  const toward = (side: number) => (endOf(side) === 0 ? -1 : 1);
  const heading = () => (Math.sign(vel) === toward(0) ? 0 : 1);
  const human = (side: number) => !!slots[side].id;
  const sideOf = (id: string) => slots.findIndex((s) => s.id === id);

  function startMatch() {
    score[0] = score[1] = 0;
    shown[0] = shown[1] = 0;
    fx.clear();
    rallyMark = 0;
    // Both colors run in from their own ends and meet in the middle.
    show.sweep(TEAMS[0].color, { dir: 'right', amount: 0.6, duration: 1 });
    show.sweep(TEAMS[1].color, { dir: 'left', amount: 0.6, duration: 1 });
    round.to('countdown');
  }

  function serve() {
    pos = endOf(server) - toward(server) * zone * 0.4;
    vel = 0;
    owner = server;
    rally = 0;
    rallySpeed = baseSpeed;
    trail.clear();
    seen.clear();
    housePlan = null;
    round.to('serve');
  }

  function launch() {
    vel = -toward(server) * rallySpeed;
    const p = roof.point(pos);
    sparks.burst(pos, [TEAMS[server].color, WHITE], 20, n * 0.2, 0.7);
    flare[server].add(TEAMS[server].color, 0.6);
    waves.add(p.x, p.y, TEAMS[server].color, { amount: 0.35 });
    show.pulse(TEAMS[server].color, 0.08);
    round.to('rally');
  }

  function hit(side: number, depth: number) {
    const d = Math.max(0, Math.min(1, depth));
    rally++;
    rallySpeed = Math.min(topSpeed, rallySpeed * 1.05);
    const speed = Math.min(topSpeed, rallySpeed * (0.8 + 0.9 * d * d));
    vel = -toward(side) * speed;
    // A press late enough that the ball had gone past the end: bring it back on the roof.
    pos = Math.max(0, Math.min(n - 1, pos));
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
    sparks.burst(endOf(side) - toward(side) * zone * 0.3, [[0.3, 0.3, 0.35]], 6, n * 0.05, 0.4);
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
    sparks.burst(end, [c, WHITE, COLORS.bad], 60, n * 0.4, 1.3);
    waves.add(p.x, p.y, c, { amount: 0.9 });
    flare[loser].add(COLORS.bad, 0.8);
    // The loser's end blows up; the scorer's color sweeps over the yard from their end, and
    // fireworks go up on their side.
    show.explode(p.x, p.y, mix(c, COLORS.bad, 0.4), { size: 1.4 });
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
    if (!h) return whiff(side);
    hit(side, 1 - fromEnd(side, Math.max(0, Math.min(n - 1, h.pos))) / zone);
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
    const minSpeed = n * 0.16;
    if (Math.sign(vel) !== dir || Math.abs(vel) < minSpeed) vel = dir * minSpeed;
    vel = Math.max(-topSpeed * 1.2, Math.min(topSpeed * 1.2, vel));
    pos += vel * dt;
    seen.push(round.clock, { pos, vel });

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

  function drawRoof(dt: number) {
    // The roof is split between the teams; the line moves toward whoever is losing.
    const front = 0.5 + (0.4 * (score[0] - score[1])) / WIN;
    for (let i = 0; i < n; i++) {
      const q = fromEnd(0, i) / Math.max(1, n - 1);
      const side = q < front ? 0 : 1;
      const edge = Math.abs(q - front) * n < 1.5;
      yard.roofAt(i, TEAMS[side].color, 0.05 + 0.015 * Math.sin(round.clock * 2 + i * 0.2));
      if (edge) yard.roofAt(i, WHITE, 0.25 + 0.2 * Math.sin(round.clock * 9));
    }
    // End zones: brighter as the ball comes at them, with a white-hot tip for a smash.
    for (let side = 0; side < 2; side++) {
      const c = TEAMS[side].color;
      const coming = round.phase === 'rally' && heading() === side ? Math.max(0, 1 - Math.max(0, fromEnd(side, pos) - zone) / (n * 0.5)) : 0;
      const locked = round.clock < lockout[side];
      for (let k = 0; k < zone; k++) {
        const i = endOf(side) - toward(side) * k;
        const depth = 1 - k / zone;
        const tip = depth > 0.8 ? 0.15 + 0.1 * Math.sin(round.clock * 10) : 0;
        yard.roofAt(i, locked ? [0.3, 0.3, 0.3] : c, 0.1 + coming * 0.3 + depth * 0.06);
        if (tip && !locked) yard.roofAt(i, WHITE, tip * (0.5 + coming));
      }
    }
    // The ball and its trail, in the color of whoever hit it last.
    trail.fade(dt, 4 + (Math.abs(vel) / n) * 4);
    if (round.phase === 'rally' || round.phase === 'serve') {
      const p = Math.max(0, Math.min(n - 1, pos));
      trail.mark(p, owner);
      const hot = Math.min(1, Math.abs(vel) / topSpeed);
      const c = mix(TEAMS[owner].color, WHITE, 0.25 + hot * 0.6);
      const pulse = round.phase === 'serve' ? 0.6 + 0.4 * Math.sin(round.clock * 8) : 1;
      yard.roofSplat(p, c, 1.4, pulse);
      if (hot > 0.6 && Math.random() < hot * 0.5) sparks.burst(p, [TEAMS[owner].color], 1, n * 0.08, 0.4);
    }
    trail.draw(yard, (_, side) => TEAMS[side].color, 0.8, 0.02);
    if (round.phase === 'countdown') {
      // Three beats run out from the middle of the roof to both ends.
      const beat = round.time % 1;
      const mid = (n - 1) / 2;
      for (let i = 0; i < n; i++) {
        const d = Math.abs(i - mid) / mid;
        yard.roofAt(i, WHITE, Math.exp(-(((d - beat) * 12) ** 2)) * 0.8);
      }
    }
    sparks.draw(yard);
  }

  function drawBushes() {
    for (let side = 0; side < 2; side++) {
      const leds = sideLeds[side];
      const c = TEAMS[side].color;
      const lit = Math.round((Math.min(WIN, shown[side]) / WIN) * leds.length);
      const winning = round.phase === 'won' && score[side] >= WIN;
      leds.forEach((at, k) => {
        if (k < lit || winning) yard.add(at, winning ? mix(c, WHITE, Math.max(0, Math.sin(round.clock * 10 + k * 1.3)) * 0.5) : c, 0.55 + 0.1 * Math.sin(round.clock * 3 + k));
        else yard.add(at, c, 0.035);
      });
    }
  }

  function drawTreesAndDecor() {
    // Trees: the rally's heat, from the base up.
    const t = Math.min(1, rally / 12);
    for (const tree of yard.trees) {
      for (let i = 0; i < tree.count; i++) {
        const u = tree.up[i];
        if (rally && u <= t) yard.add(tree.offset + i, t >= 1 ? hsv((round.clock * 0.5 + u) % 1) : heat(u), 0.55);
      }
    }
    // Windows and doors: each side of the house glows in its team's color and flashes with its hits.
    const matchPoint = round.phase !== 'won' && (score[0] === WIN - 1 || score[1] === WIN - 1);
    for (const d of yard.decor) {
      for (let i = 0; i < d.count; i++) {
        const at = d.offset + i;
        const side = stage.positions[at * 2] < yard.middle ? 0 : 1;
        // A faint tint of its side's team over the show's backdrop, and the flash of every hit.
        yard.add(at, TEAMS[side].color, 0.03);
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
      if (round.phase === 'won') drawWin();
      if (round.phase === 'lobby') {
        // Each free end calls for a player.
        for (let side = 0; side < 2; side++) {
          if (slots[side].id) continue;
          yard.roofSplat(endOf(side) - toward(side) * zone * 0.5, TEAMS[side].color, zone * 0.3, 0.25 + 0.2 * Math.sin(round.clock * 3 + side * Math.PI));
        }
      }
      fx.draw(frame);
    },

    status(): GameStatusFields {
      if (!playable) return round.setup();
      const scores = TEAMS.map((t, i) => ({ name: slots[i].house ? `${t.name} (house)` : t.name, color: css(t.color), value: score[i] }));
      const base = { score: 0, lives: null, goal: null, scores, stats: rally > 1 && round.phase === 'rally' ? [{ label: 'Rally', value: rally }] : [] };
      const w = score[0] >= WIN ? 0 : 1;
      const messages: Record<Phase, string> = {
        lobby: 'Tap to join! Fire plays the left end, Ice the right.',
        countdown: 'Get ready…',
        serve: `${TEAMS[server].name} serves.`,
        rally: rally > 2 ? `${lastHit} Rally of ${rally}!` : rally ? lastHit : 'Hit it back when it reaches your end!',
        point: `${TEAMS[lastScorer].name} scores! ${score[0]}–${score[1]}`,
        won: `${TEAMS[w].name} wins ${score[w]}–${score[1 - w]}!`
      };
      return { ...base, phase: round.phase, message: messages[round.phase], button: round.phase === 'lobby' ? 'JOIN' : '…', tone: round.phase === 'lobby' ? 'go' : 'wait' };
    },

    playerStatus(id: string): Partial<GameStatusFields> {
      const side = sideOf(id);
      if (side < 0) {
        const full = slots.every((s) => s.id);
        if (round.phase === 'lobby' && !full) return { you: null };
        return { you: null, button: '👀', tone: 'wait', message: round.phase === 'lobby' ? 'Two players are on. Watch the roof!' : `Watching: ${TEAMS[0].name} ${score[0]}–${score[1]} ${TEAMS[1].name}` };
      }
      const team = TEAMS[side];
      const you = { name: team.name, color: css(team.color) };
      const end = side === 0 ? 'left' : 'right';
      if (round.phase === 'lobby') {
        return { you, button: 'VS HOUSE', tone: 'go', message: `You're ${team.name}: the ${end} end of the roof. Waiting for a friend to tap on their phone… or tap again to play the house.` };
      }
      if (round.phase === 'countdown') return { you, button: '…', tone: 'wait', message: `You're ${team.name} (${end} end). Get ready…` };
      if (round.phase === 'serve') return side === server ? { you, button: 'SERVE', tone: 'go', message: 'Your serve! Tap to launch.' } : { you, button: 'HIT!', tone: 'go' };
      if (round.phase === 'rally') return { you, button: 'HIT!', tone: 'go' };
      if (round.phase === 'won') return { you, button: round.time > 2.5 ? 'REMATCH' : '…', tone: score[side] >= WIN ? 'good' : 'bad', message: score[side] >= WIN ? `You win ${score[side]}–${score[1 - side]}!` : `${TEAMS[1 - side].name} wins this time. Rematch?` };
      return { you, button: '…', tone: 'wait' };
    }
  };
}
