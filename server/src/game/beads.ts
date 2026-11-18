import type { Stage } from '../../../shared/layout.ts';
import { mix, WHITE, type Frame, type Rgb } from './frame.ts';
import { bestScore, COLORS, css, Flare, heat, Motes, record, scale, Sparks, Waves, Yard, type Part } from './kit.ts';
import type { Game, GameInput, GameStatusFields } from './types.ts';

// Bead Rush: a chain of colored beads creeps along the roofline toward the launcher at the start
// of the roof. Pick the launcher's color with the left and right buttons (or the arrow keys): the
// colors sit on a wheel in rainbow order, and each press turns it one step, wrapping round. The
// middle button (the space bar) fires the loaded bead into the front of the chain at once; three or
// more of one color at the front pop, and the chain recoils. Shots that pop in a row build a combo
// that multiplies the points and kicks the chain back harder; a shot that does not pop just
// lengthens the chain, toward you. Later on, gold beads come down the chain: hit one at the front
// and it blows up the beads behind it. If the chain reaches the launcher, its front bursts red, it
// is shoved back and a life is lost.
//
// Stages bring more colors, so the wheel takes more turning: three colors (green, blue, magenta)
// at first, cyan after STAGE_EVERY seconds of play, orange after twice that. New beads in the feed
// use the new color at once; the selected color stays selected. The chain speeds up over the first
// three minutes, then holds a pace that a player who turns the short way round and makes a move
// every 0.4 s (two and a half a second) can keep up with for ever; slower than every 0.5 s, it
// catches up in the end.
//
// Colors mean one thing each: the beads are green, cyan, blue, magenta and orange; white is only
// the shot in flight (and the small mark where it leaves); gold is points (gold beads, a combo);
// red is danger and a lost life.
//
// The yard: the bushes mirror the phone's three buttons. With three or more, the middle one glows
// the loaded color, the one left of it the color the left button would pick, the one right of it
// the color the right button would pick (dimmer); other bushes sparkle gold with the combo. With one
// or two, they all glow the loaded color. The trees are a danger meter: they fill from the base up
// as the chain nears the launcher and blink red when it is close. Windows and doors flash the color
// of every pop. On a roof alone, the loaded bead sits at the launcher.

type Phase = 'ready' | 'play' | 'breach' | 'over';

interface Bead {
  /** Which of BEAD_COLORS; gold beads: -1. */
  tone: number;
  /** Seconds since it joined the chain, for the arrival flash. */
  age: number;
}

const LIVES = 3;
/** Roof steps between neighbouring beads. */
const SPACING = 2.2;
/** Where a shot leaves from, and the chain front that costs a life. */
const LAUNCH = 5;
const LOSE = 8;
/**
 * Every bead color, in wheel order (by hue: the left and right buttons step through them). Far
 * apart on real LEDs and none of the colors that mean something else: the orange sits between red
 * (danger) and gold (points), with about half of gold's green, so it reads as its own color.
 */
export const BEAD_COLORS: { name: string; color: Rgb }[] = [
  { name: 'orange', color: [1, 0.3, 0] },
  { name: 'green', color: [0.05, 1, 0.12] },
  { name: 'cyan', color: [0, 0.72, 1] },
  { name: 'blue', color: [0.14, 0.08, 1] },
  { name: 'magenta', color: [1, 0, 0.7] }
];
/** The colors of each stage (BEAD_COLORS indexes), and the seconds of play between stages. */
const STAGES: number[][] = [
  [1, 3, 4],
  [1, 2, 3, 4],
  [0, 1, 2, 3, 4]
];
export const STAGE_EVERY = 60;
/** How long the phone says which color is new. */
const NEWS = 3;
/** Where a new chain's front starts, and the furthest a recoil can push it (fractions of the roof). */
const START = 0.55;
const FURTHEST = 0.8;
/** The creep, in roofs per second: at the start, at full pace, and the seconds between. */
const CREEP_START = 1 / 90;
const CREEP_FULL = 1 / 32;
const CREEP_RAMP = 180;
/** How fast a recoil dies away, per second. */
const RECOIL_DECAY = 6;
/** Gold beads come after this many seconds, one bead in this many. */
const GOLD_AFTER = 45;
const GOLD_CHANCE = 0.04;
/** A gold bead takes this many beads with it (itself too). */
const BOMB = 6;
const NIGHT: Rgb = [0.02, 0.012, 0.04];
const DARK: Rgb = [0.02, 0.02, 0.035];

const beadColor = (tone: number): Rgb => (tone >= 0 ? BEAD_COLORS[tone].color : COLORS.gold);

/**
 * The state, for tests: the chain's front, its colors (front first, BEAD_COLORS indexes; gold:
 * -1), the loaded color, the colors of this stage in wheel order, a shot in flight, the stage (1..).
 */
export interface BeadsPeek {
  front: number;
  tones: number[];
  loaded: number;
  palette: number[];
  flying: boolean;
  stage: number;
}

export function beadsGame(stage: Stage): Game & { peek(): BeadsPeek } {
  const yard = new Yard(stage);
  const roof = yard.roof;
  const n = roof.n;
  const playable = n >= 30;
  const sparks = new Sparks(roof, n * 0.1, 1.8);
  const motes = new Motes(yard);
  const waves = new Waves(yard);
  const decorFlare = new Flare(3);
  /** The bushes, left to right; the middle one shows the loaded bead (see drawBushes). */
  const bushes = yard.bushes;
  const middle = bushes.length >= 3 ? Math.floor(bushes.length / 2) : -1;

  let phase: Phase = 'ready';
  let phaseTime = 0;
  let clock = 0;
  /** Seconds of play in this game: the creep's pace comes from it. */
  let elapsed = 0;
  let lives = LIVES;
  let score = 0;
  let combo = 0;
  let bestCombo = 0;
  let newBest = false;
  /** The chain, front first: bead i is at front + i * SPACING. */
  let chain: Bead[] = [];
  let front = 0;
  /** The recoil's speed (toward the far end), in steps per second. */
  let recoil = 0;
  let shot: { pos: number; tone: number } | null = null;
  /** A tap while a shot is in flight fires as soon as it lands. */
  let queued = false;
  /** The loaded color (a BEAD_COLORS index), and the stage (0-based index into STAGES). */
  let loaded = STAGES[0][0];
  let stageIndex = 0;
  /** When the last stage began (clock), for the phone's news of the new color. */
  let stageAt = -99;
  /** A flash at the launcher when the color changes. */
  let turned = 9;
  /** The feed: the color of the last bead added at the back, and how many in a row. */
  let lastTone = -2;
  let runLen = 0;
  /** The tree meter, smoothed. */
  let meter = 0;

  const creep = () => n * Math.min(CREEP_FULL, CREEP_START + (elapsed * (CREEP_FULL - CREEP_START)) / CREEP_RAMP);
  /** How far a pop pushes the chain back, per bead popped. */
  const knockPer = n * 0.008;
  const shotSpeed = n * 2.2;

  const palette = () => STAGES[stageIndex];
  /** The color one step left (-1) or right (+1) of the loaded one on the wheel. */
  function neighbour(step: number) {
    const p = palette();
    const at = Math.max(0, p.indexOf(loaded));
    return p[(at + step + p.length) % p.length];
  }

  function setPhase(p: Phase) {
    phase = p;
    phaseTime = 0;
  }

  /** A new bead for the back of the chain: runs of one or two, never three, of a color. */
  function newBead(): Bead {
    if (phase === 'play' && elapsed > GOLD_AFTER && lastTone !== -1 && Math.random() < GOLD_CHANCE) {
      lastTone = -1;
      runLen = 1;
      return { tone: -1, age: 1 };
    }
    let tone: number;
    if (lastTone >= 0 && runLen === 1 && Math.random() < 0.45) tone = lastTone;
    else {
      const others = palette().filter((i) => i !== lastTone);
      tone = others[Math.floor(Math.random() * others.length)];
    }
    runLen = tone === lastTone ? runLen + 1 : 1;
    lastTone = tone;
    return { tone, age: 1 };
  }

  /** Keeps the chain going past the far end of the roof: new beads come in from there. */
  function feed() {
    while (chain.length === 0 || front + (chain.length - 1) * SPACING < n - 1 + SPACING * 2) chain.push(newBead());
  }

  function spawnChain() {
    chain = [];
    front = n * START;
    recoil = 0;
    lastTone = -2;
    runLen = 0;
    feed();
  }

  function newGame() {
    lives = LIVES;
    score = 0;
    combo = 0;
    bestCombo = 0;
    elapsed = 0;
    newBest = false;
    shot = null;
    queued = false;
    stageIndex = 0;
    stageAt = -99;
    sparks.clear();
    motes.clear();
    waves.clear();
    setPhase('play');
    spawnChain();
    loaded = chain[0]?.tone >= 0 ? chain[0].tone : palette()[0];
  }

  /** The run of one color at the front of the chain. */
  function frontRun() {
    const tone = chain[0]?.tone ?? -2;
    let len = 0;
    while (len < chain.length && chain[len].tone === tone) len++;
    return { tone, len };
  }

  function fire() {
    if (phase !== 'play') return;
    if (shot) {
      queued = true;
      return;
    }
    shot = { pos: LAUNCH, tone: loaded };
  }

  /** The left or right button: the next color on the wheel. */
  function turn(step: number) {
    if (phase !== 'play' && phase !== 'breach') return;
    loaded = neighbour(step);
    turned = 0;
  }

  /** Another color joins the feed. */
  function nextStage() {
    stageIndex++;
    stageAt = clock;
    const added = palette().find((t) => !STAGES[stageIndex - 1].includes(t))!;
    const color = beadColor(added);
    const p = roof.point(n / 2);
    waves.add(p.x, p.y, color, { amount: 0.9 });
    decorFlare.add(color, 1);
    sparks.burst(LAUNCH, [color], 20, n * 0.15, 0.8);
  }

  function kick(beads: number) {
    recoil += beads * knockPer * (1 + 0.15 * Math.max(0, combo - 1)) * RECOIL_DECAY;
  }

  function pop(len: number, tone: number) {
    combo++;
    bestCombo = Math.max(bestCombo, combo);
    score += len * combo;
    const at = front + ((len - 1) * SPACING) / 2;
    const color = beadColor(tone);
    chain.splice(0, len);
    front += len * SPACING;
    kick(len);
    const colors = combo >= 2 ? [color, mix(color, WHITE, 0.4), COLORS.gold] : [color, mix(color, WHITE, 0.4)];
    sparks.burst(at, colors, 18 + len * 6 + combo * 4, n * (0.2 + Math.min(0.2, combo * 0.03)), 1 + Math.min(0.6, combo * 0.1));
    decorFlare.add(color, 0.5 + Math.min(0.8, combo * 0.15));
    if (combo >= 3) {
      const p = roof.point(at);
      waves.add(p.x, p.y, color, { amount: Math.min(1, 0.5 + combo * 0.08) });
    }
  }

  /** A shot that hits a gold bead at the front: it blows up the beads behind it. */
  function bomb() {
    const k = Math.min(BOMB, chain.length);
    const at = front + ((k - 1) * SPACING) / 2;
    combo++;
    bestCombo = Math.max(bestCombo, combo);
    score += 10 * combo + k;
    chain.splice(0, k);
    front += k * SPACING;
    kick(k);
    sparks.burst(at, [COLORS.gold, mix(COLORS.gold, WHITE, 0.5), WHITE], 60, n * 0.45, 1.5);
    decorFlare.add(COLORS.gold, 1.2);
    const p = roof.point(at);
    waves.add(p.x, p.y, COLORS.gold, { amount: 1 });
  }

  function land() {
    const s = shot!;
    shot = null;
    if (chain[0]?.tone === -1) bomb();
    else {
      chain.unshift({ tone: s.tone, age: 0 });
      front -= SPACING;
      const run = frontRun();
      if (run.tone >= 0 && run.len >= 3) pop(run.len, run.tone);
      else combo = 0;
    }
    if (queued) {
      queued = false;
      fire();
    }
  }

  /** The chain reached the launcher: its front bursts red and it is shoved back. */
  function breach() {
    lives--;
    combo = 0;
    shot = null;
    queued = false;
    const k = Math.min(4, chain.length);
    for (let i = 0; i < k; i++) sparks.burst(front + i * SPACING, [COLORS.bad, [1, 0.3, 0]], 10, n * 0.15);
    chain.splice(0, k);
    front += k * SPACING;
    recoil = n * 0.2 * RECOIL_DECAY;
    if (lives > 0) return setPhase('breach');
    newBest = record('beads', score).isNew;
    // What is left falls off the gutter.
    for (let i = 0; i < chain.length; i++) {
      const pos = front + i * SPACING;
      if (pos > n - 1) break;
      const p = roof.point(pos);
      motes.drop(p.x, p.y, mix(beadColor(chain[i].tone), COLORS.bad, 0.6), { vx: (Math.random() - 0.5) * 60, size: 18 });
    }
    chain = [];
    setPhase('over');
  }

  function input(e: GameInput) {
    if (!playable || e.action !== 'press') return;
    if (e.button === 'left') return turn(-1);
    if (e.button === 'right') return turn(1);
    if (e.button) return;
    if (phase === 'ready' || (phase === 'over' && phaseTime > 1.5)) return newGame();
    fire();
  }

  const danger = () => Math.max(0, Math.min(1, 1 - (front - LOSE) / (n * START - LOSE)));

  // ---------- Drawing ----------

  function drawRoof() {
    for (let i = 0; i < n; i++) yard.roofAt(i, NIGHT, 1 + 0.3 * Math.sin(clock * 0.8 + i * 0.07));
    const playing = phase === 'play' || phase === 'breach';
    // Danger: the roof between the launcher and the chain pulses red when it is close.
    const d = playing ? danger() : 0;
    if (d > 0.7) {
      const pulse = (0.5 + 0.5 * Math.sin(clock * (8 + d * 8))) * (d - 0.7) * 0.6;
      for (let i = 0; i < front; i++) yard.roofAt(i, COLORS.bad, pulse);
    }
    const run = frontRun().len;
    for (let i = 0; i < chain.length; i++) {
      const pos = front + i * SPACING;
      if (pos > n) break;
      const b = chain[i];
      const color = beadColor(b.tone);
      const arrive = b.age < 0.2 ? 1 - b.age / 0.2 : 0;
      if (b.tone === -1) {
        yard.roofSplat(pos, COLORS.gold, 0.9, 0.9 + 0.4 * Math.max(0, Math.sin(clock * 10 + i)));
        if (Math.random() < 0.3) yard.roofAt(pos + (Math.random() - 0.5) * 3, mix(COLORS.gold, WHITE, 0.3), 0.5);
        continue;
      }
      // The front run, the one to match, glows brighter, with a halo.
      const isFront = playing && i < run;
      yard.roofSplat(pos, color, 0.85, (isFront ? 1.1 + 0.2 * Math.sin(clock * 9) : 0.7) + arrive);
      if (isFront) yard.roofSplat(pos, color, 2.6, 0.12);
    }
    if (playing) {
      // The launcher: the loaded bead (it flares as the color changes), and a small white mark.
      const flare = turned < 0.25 ? 1 - turned / 0.25 : 0;
      yard.roofSplat(2.5, beadColor(loaded), 1 + flare * 0.6, 1 + flare * 0.3);
      yard.roofSplat(LAUNCH, WHITE, 0.5, 0.25 + 0.1 * Math.sin(clock * 6));
    }
    if (shot) {
      const color = beadColor(shot.tone);
      for (let k = 1; k <= 4; k++) yard.roofSplat(shot.pos - k * 1.6, color, 0.8, 0.6 * (1 - k / 5));
      yard.roofSplat(shot.pos, color, 1.3, 0.9);
      yard.roofSplat(shot.pos, WHITE, 0.8, 0.9);
    }
    sparks.draw(yard);
  }

  function drawBushes() {
    const flare = turned < 0.25 ? 1 - turned / 0.25 : 0;
    bushes.forEach((b, bi) => {
      // Which color this bush shows: the loaded one (the middle bush, or every bush when there are
      // fewer than three), the left button's, the right button's, or none (the combo's gold).
      const role = middle < 0 || bi === middle ? 0 : bi === middle - 1 ? -1 : bi === middle + 1 ? 1 : null;
      for (let i = 0; i < b.count; i++) {
        const at = b.offset + i;
        if (phase === 'ready') {
          const tone = BEAD_COLORS[Math.floor(clock * 0.5 + bi) % BEAD_COLORS.length].color;
          yard.add(at, tone, 0.35 + 0.1 * Math.sin(clock * 3 + i));
        } else if (phase === 'over') yard.add(at, COLORS.bad, 0.06 + 0.05 * Math.sin(phaseTime * 3));
        else if (role === 0) yard.add(at, beadColor(loaded), 0.65 + 0.1 * Math.sin(clock * 4 + i * 0.7) + flare * 0.3);
        else if (role !== null) yard.add(at, beadColor(neighbour(role)), 0.22);
        else {
          const glow = Math.min(1, combo / 6);
          if (glow > 0) yard.add(at, mix(COLORS.gold, WHITE, Math.max(0, Math.sin(clock * 9 + i * 2.3)) * 0.3), glow * (0.4 + 0.3 * Math.sin(clock * 7 + i * 1.9)));
          else yard.add(at, DARK);
        }
      }
    });
  }

  function drawTree(part: Part) {
    const urgent = meter > 0.8;
    for (let i = 0; i < part.count; i++) {
      const u = part.up[i];
      if (phase !== 'ready' && u <= meter) {
        const c = urgent && Math.sin(clock * 14) > 0 ? COLORS.bad : heat(u * 0.9);
        yard.add(part.offset + i, c, 0.6);
      } else yard.add(part.offset + i, DARK);
    }
  }

  function drawDecor(part: Part) {
    for (let i = 0; i < part.count; i++) {
      yard.add(part.offset + i, NIGHT, 1.2);
      yard.add(part.offset + i, decorFlare.color, 1.1);
    }
  }

  spawnChain();

  return {
    id: 'beads',

    peek: () => ({ front, tones: chain.map((b) => b.tone), loaded, palette: [...palette()], flying: !!shot, stage: stageIndex + 1 }),

    input,

    update(dt: number, frame: Frame) {
      clock += dt;
      phaseTime += dt;
      yard.begin(frame);
      if (!playable) return;

      turned += dt;
      if (phase === 'play') {
        elapsed += dt;
        front -= creep() * dt;
        if (stageIndex + 1 < STAGES.length && elapsed >= (stageIndex + 1) * STAGE_EVERY) nextStage();
      }
      if (phase === 'ready') {
        front -= (n / 80) * dt;
        if (front < n * 0.3) spawnChain();
      }
      front += recoil * dt;
      recoil *= Math.exp(-dt * RECOIL_DECAY);
      if (front > n * FURTHEST && recoil > 0) {
        front = n * FURTHEST;
        recoil = 0;
      }
      if (phase !== 'over') feed();
      if (shot) {
        shot.pos += shotSpeed * dt;
        if (shot.pos >= front - SPACING) land();
      }
      if (phase === 'play' && front <= LOSE) breach();
      if (phase === 'breach' && phaseTime > 1.4) setPhase('play');
      if (phase === 'over' && phaseTime > 10) {
        spawnChain();
        setPhase('ready');
      }
      for (const b of chain) b.age += dt;
      sparks.update(dt);
      motes.update(dt);
      waves.update(dt);
      decorFlare.update(dt);
      const target = phase === 'play' || phase === 'breach' ? danger() : 0;
      meter += (target - meter) * Math.min(1, dt * 6);

      drawRoof();
      drawBushes();
      for (const t of yard.trees) drawTree(t);
      for (const d of yard.decor) drawDecor(d);
      if (phase === 'breach' && phaseTime < 0.6) yard.wash(COLORS.bad, 0.2 * (1 - phaseTime / 0.6));
      if (phase === 'over') yard.wash(scale(COLORS.bad, 0.5 + 0.5 * Math.sin(phaseTime * 3)), 0.05);
      motes.draw();
      waves.draw();
    },

    status(): GameStatusFields {
      const best = bestScore('beads');
      if (!playable) return { phase: 'setup', message: 'Draw a roofline in Layout first.', score: 0, lives: null, goal: null };
      const stats = [
        { label: 'Score', value: score },
        { label: 'Best', value: Math.max(best, score) },
        { label: 'Combo', value: `×${combo}` },
        { label: 'Colors', value: palette().length }
      ];
      const common = { score, lives, goal: null, stats };
      // The three buttons, each in the color it stands for: pick left, fire the loaded one, pick right.
      const controls = {
        controls: [
          { id: 'left', label: '◀', color: css(beadColor(neighbour(-1))), keys: ['ArrowLeft', 'KeyA'] },
          { id: 'main', label: 'FIRE', color: css(beadColor(loaded)), keys: ['Space', 'Enter', 'ArrowUp', 'KeyW'], big: true },
          { id: 'right', label: '▶', color: css(beadColor(neighbour(1))), keys: ['ArrowRight', 'KeyD'] }
        ],
        keysHint: '← → change color, space fires'
      };
      const news = stageIndex > 0 && clock - stageAt < NEWS ? `New color: ${BEAD_COLORS[palette().find((t) => !STAGES[stageIndex - 1].includes(t))!].name}!` : null;
      switch (phase) {
        case 'ready':
          return { ...common, phase, lives: null, message: 'Tap to start! Match the front of the chain: ◀ ▶ pick a color, FIRE shoots it.', button: 'GO!', tone: 'go', stats: [{ label: 'Best', value: best }] };
        case 'play': {
          const message = news ?? (combo >= 2 ? `Combo ×${combo}!` : danger() > 0.75 ? 'Too close! Fire fast!' : 'Match the front of the chain! ◀ ▶ pick a color, FIRE shoots it.');
          return { ...common, ...controls, phase, message, button: 'FIRE', tone: 'go' };
        }
        case 'breach':
          return { ...common, ...controls, phase, message: lives === 1 ? 'The chain reached you! Last life!' : 'The chain reached you! Push it back!', button: 'FIRE', tone: 'bad' };
        case 'over':
          return { ...common, phase, message: newBest ? `New best: ${score}!` : `Game over: ${score} points. Best combo ×${bestCombo}.`, button: 'GO!', tone: 'go' };
      }
    }
  };
}
