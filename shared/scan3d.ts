// A custom object in 3D, from camera scans taken from several sides.
//
// Each scan (see readScan in photoTrace.ts) tells where every LED it read is in that picture, by
// the LED's own number. So the scans need no matching: LED 17 in one picture is LED 17 in the
// next. From two or more pictures taken from different sides, each LED is where the lines of
// sight from those cameras meet; and where each camera stood follows from the same LEDs. This is
// how motion capture and the LED-mapping of Christmas trees work.
//
// The cameras: a phone held upright, moved round the object (or the object turned in front of
// it) a step at a time. Each picture is a pinhole camera: turned by some angle about the upright
// axis, tilted the same for all (looking down at a table, say) give or take a little, at some
// distance. The angles are found from the LEDs; how far the user was asked to step only starts
// the search and steadies it when the pictures cannot tell (two pictures alone hardly can).
//
// The world: x to the right and z toward the camera as seen from the first scan (the front of
// the object), y up. Distances come out in arbitrary units; the string's LED spacing (or a width
// typed in) turns them into meters, as for a photo.

import { seededRandom } from './color.ts';
import type { DesignStroke } from './layout.ts';
import { tautStep } from './photoTrace.ts';

export interface Pt3 {
  x: number;
  y: number;
  z: number;
}

/** One scan: the LEDs it read, by number, where they are in its picture (pixels). */
export interface ScanView {
  leds: { num: number; x: number; y: number }[];
  width: number;
  height: number;
}

/** How far round the object to step between scans (degrees), as the user is asked to. */
export const SCAN_STEP = 45;

/** The camera's focal length as a share of the picture's long side: a phone's main camera, about 70° across. */
export const FOCAL = 0.8;

export interface Solved3D {
  /** By LED number: where it is (null: not seen from two sides, or not well). */
  points: (Pt3 | null)[];
  /** Where each scan's camera was, in the same units, and the way it turned round (degrees). */
  cameras: (Pt3 & { angle: number })[];
  /** How far the LEDs land from where the pictures show them, in picture pixels (root mean square). */
  rms: number;
  /** How many LEDs it placed. */
  placed: number;
}

// ---------- Small linear algebra ----------

type M3 = number[];
const mul3 = (a: M3, b: M3): M3 => {
  const o = new Array(9).fill(0);
  for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) for (let k = 0; k < 3; k++) o[i * 3 + j] += a[i * 3 + k] * b[k * 3 + j];
  return o;
};

/** Solves A x = b (A n×n, row-major) by Gaussian elimination; null when A is singular. */
function solve(A: number[], b: number[], n: number): number[] | null {
  const m = A.slice();
  const x = b.slice();
  for (let c = 0; c < n; c++) {
    let p = c;
    for (let r = c + 1; r < n; r++) if (Math.abs(m[r * n + c]) > Math.abs(m[p * n + c])) p = r;
    if (Math.abs(m[p * n + c]) < 1e-12) return null;
    if (p !== c) {
      for (let k = 0; k < n; k++) [m[c * n + k], m[p * n + k]] = [m[p * n + k], m[c * n + k]];
      [x[c], x[p]] = [x[p], x[c]];
    }
    for (let r = c + 1; r < n; r++) {
      const f = m[r * n + c] / m[c * n + c];
      if (!f) continue;
      for (let k = c; k < n; k++) m[r * n + k] -= f * m[c * n + k];
      x[r] -= f * x[c];
    }
  }
  for (let c = n - 1; c >= 0; c--) {
    let s = x[c];
    for (let k = c + 1; k < n; k++) s -= m[c * n + k] * x[k];
    x[c] = s / m[c * n + c];
  }
  return x.every(Number.isFinite) ? x : null;
}

/**
 * Levenberg–Marquardt: the parameters that make the residuals smallest (in the least-squares
 * sense), from a start nearby. Derivatives by small steps.
 */
function leastSquares(p0: number[], residuals: (p: number[]) => number[], iterations: number): number[] {
  let p = p0.slice();
  let r = residuals(p);
  let cost = r.reduce((a, v) => a + v * v, 0);
  let lambda = 1e-3;
  const n = p.length;
  for (let it = 0; it < iterations; it++) {
    const J: number[][] = [];
    for (let j = 0; j < n; j++) {
      const h = 1e-6 * Math.max(1, Math.abs(p[j]));
      const q = p.slice();
      q[j] += h;
      const rq = residuals(q);
      J.push(rq.map((v, i) => (v - r[i]) / h));
    }
    const A = new Array(n * n).fill(0);
    const g = new Array(n).fill(0);
    for (let a = 0; a < n; a++) {
      const ja = J[a];
      for (let i = 0; i < r.length; i++) g[a] += ja[i] * r[i];
      for (let b = a; b < n; b++) {
        const jb = J[b];
        let s = 0;
        for (let i = 0; i < r.length; i++) s += ja[i] * jb[i];
        A[a * n + b] = A[b * n + a] = s;
      }
    }
    let better = false;
    for (let tries = 0; tries < 8 && !better; tries++) {
      const D = A.slice();
      for (let a = 0; a < n; a++) D[a * n + a] += lambda * (A[a * n + a] + 1e-9);
      const step = solve(
        D,
        g.map((v) => -v),
        n
      );
      if (!step) {
        lambda *= 10;
        continue;
      }
      const q = p.map((v, i) => v + step[i]);
      const rq = residuals(q);
      const c = rq.reduce((a, v) => a + v * v, 0);
      if (c < cost) {
        better = true;
        p = q;
        r = rq;
        const done = cost - c < cost * 1e-7;
        cost = c;
        lambda = Math.max(1e-7, lambda / 3);
        if (done) return p;
      } else lambda *= 5;
    }
    if (!better) break;
  }
  return p;
}

function inverse3(m: number[]): number[] | null {
  const [a, b, c, d, e, f, g, h, i] = m;
  const A = e * i - f * h;
  const B = -(d * i - f * g);
  const C = d * h - e * g;
  const det = a * A + b * B + c * C;
  if (!(Math.abs(det) > 1e-18)) return null;
  return [A / det, -(b * i - c * h) / det, (b * f - c * e) / det, B / det, (a * i - c * g) / det, -(a * f - c * d) / det, C / det, -(a * h - b * g) / det, (a * e - b * d) / det];
}

// ---------- The cameras ----------

/** One scan's camera: turned `a` (radians) round the upright axis, tilted by the shared tilt plus `dp`, rolled `roll`, and moved by `t`. */
interface Pose {
  a: number;
  dp: number;
  roll: number;
  t: [number, number, number];
}

interface Cam {
  R: M3;
  t: [number, number, number];
  f: number;
  /** Up and down, when the pixels are not square (else f). */
  fy?: number;
  cu: number;
  cv: number;
}

function rotation(tilt: number, p: Pose): M3 {
  const ca = Math.cos(p.a);
  const sa = Math.sin(p.a);
  const cx = Math.cos(tilt + p.dp);
  const sx = Math.sin(tilt + p.dp);
  const cz = Math.cos(p.roll);
  const sz = Math.sin(p.roll);
  // Round the upright axis: at a = 90° the camera stands on the object's right, looking left.
  const turn = [ca, 0, -sa, 0, 1, 0, sa, 0, ca];
  const tiltM = [1, 0, 0, 0, cx, -sx, 0, sx, cx];
  const rollM = [cz, -sz, 0, sz, cz, 0, 0, 0, 1];
  return mul3(rollM, mul3(tiltM, turn));
}

const camOf = (tilt: number, p: Pose, v: ScanView, f: number): Cam => ({ R: rotation(tilt, p), t: p.t, f, cu: v.width / 2, cv: v.height / 2 });

/** Where a point shows in a camera's picture, and how far in front of it it is. */
function project(c: Cam, X: number[]): [number, number, number] {
  const R = c.R;
  const px = R[0] * X[0] + R[1] * X[1] + R[2] * X[2] + c.t[0];
  const py = R[3] * X[0] + R[4] * X[1] + R[5] * X[2] + c.t[1];
  const pz = R[6] * X[0] + R[7] * X[1] + R[8] * X[2] + c.t[2];
  const d = -pz;
  return [c.cu + (c.f * px) / d, c.cv - ((c.fy ?? c.f) * py) / d, d];
}

/** Where a camera is. */
function center(c: Cam): Pt3 {
  const R = c.R;
  const [tx, ty, tz] = c.t;
  return { x: -(R[0] * tx + R[3] * ty + R[6] * tz), y: -(R[1] * tx + R[4] * ty + R[7] * tz), z: -(R[2] * tx + R[5] * ty + R[8] * tz) };
}

// ---------- The points ----------

interface Obs {
  k: number;
  u: number;
  v: number;
  /** Weight: down for a reading that lands far off (a misread number). */
  w: number;
  /** False once dropped as a misreading. */
  ok: boolean;
}

/** A point from its sightings, by straight-line least squares (a start for refine). */
function triangulate(cams: Cam[], obs: Obs[]): number[] | null {
  const A = new Array(9).fill(0);
  const b = [0, 0, 0];
  for (const o of obs) {
    if (!o.ok) continue;
    const c = cams[o.k];
    const R = c.R;
    // Rows of M [R | t], with M taking the camera's view to pixels times depth.
    const row = (i: number) => [R[i * 3], R[i * 3 + 1], R[i * 3 + 2], c.t[i]];
    const r0 = row(0);
    const r1 = row(1);
    const r2 = row(2);
    const P1 = r0.map((x, i) => c.f * x - c.cu * r2[i]);
    const P2 = r1.map((x, i) => -(c.fy ?? c.f) * x - c.cv * r2[i]);
    const P3 = r2.map((x) => -x);
    for (const [P, m] of [
      [P1, o.u],
      [P2, o.v]
    ] as const) {
      const e = [m * P3[0] - P[0], m * P3[1] - P[1], m * P3[2] - P[2]];
      const rhs = -(m * P3[3] - P[3]);
      for (let i = 0; i < 3; i++) {
        b[i] += e[i] * rhs;
        for (let j = 0; j < 3; j++) A[i * 3 + j] += e[i] * e[j];
      }
    }
  }
  return solve(A, b, 3);
}

/** Moves a point to where its sightings agree best (Gauss–Newton). */
function refinePoint(cams: Cam[], obs: Obs[], X: number[], iterations = 4): number[] {
  let x = X.slice();
  for (let it = 0; it < iterations; it++) {
    const A = new Array(9).fill(0);
    const g = [0, 0, 0];
    for (const o of obs) {
      if (!o.ok) continue;
      const c = cams[o.k];
      const R = c.R;
      const px = R[0] * x[0] + R[1] * x[1] + R[2] * x[2] + c.t[0];
      const py = R[3] * x[0] + R[4] * x[1] + R[5] * x[2] + c.t[1];
      const pz = R[6] * x[0] + R[7] * x[1] + R[8] * x[2] + c.t[2];
      const d = -pz;
      if (d <= 1e-6) return x;
      const ru = c.cu + (c.f * px) / d - o.u;
      const fy = c.fy ?? c.f;
      const rv = c.cv - (fy * py) / d - o.v;
      const ju = [0, 1, 2].map((i) => c.f * (R[i] / d + (px * R[6 + i]) / (d * d)));
      const jv = [0, 1, 2].map((i) => -fy * (R[3 + i] / d + (py * R[6 + i]) / (d * d)));
      for (let i = 0; i < 3; i++) {
        g[i] += o.w * (ju[i] * ru + jv[i] * rv);
        for (let j = 0; j < 3; j++) A[i * 3 + j] += o.w * (ju[i] * ju[j] + jv[i] * jv[j]);
      }
    }
    for (let i = 0; i < 3; i++) A[i * 4] *= 1 + 1e-6;
    const s = solve(
      A,
      g.map((v) => -v),
      3
    );
    if (!s) return x;
    x = x.map((v, i) => v + s[i]);
    if (Math.hypot(...s) < 1e-6 * (1 + Math.hypot(...x))) break;
  }
  return x;
}

/** The widest angle (radians) between two of a point's lines of sight: near 0, its depth is a guess. */
function spread(cams: Cam[], obs: Obs[], X: number[]): number {
  const dirs = obs
    .filter((o) => o.ok)
    .map((o) => {
      const c = center(cams[o.k]);
      const d = [X[0] - c.x, X[1] - c.y, X[2] - c.z];
      const l = Math.hypot(...d) || 1;
      return d.map((v) => v / l);
    });
  let best = 0;
  for (let i = 0; i < dirs.length; i++)
    for (let j = i + 1; j < dirs.length; j++) {
      const dot = dirs[i][0] * dirs[j][0] + dirs[i][1] * dirs[j][1] + dirs[i][2] * dirs[j][2];
      best = Math.max(best, Math.acos(Math.max(-1, Math.min(1, dot))));
    }
  return best;
}

// ---------- Solving ----------

const DEG = Math.PI / 180;
/** In pixels: what one standard deviation of each guess about the cameras weighs against the pictures. */
const PRIOR_PX = 2;
/** How sure the guesses are: the step round (degrees), the tilt and roll of each picture. */
const STEP_SD = 25 * DEG;
const TILT_SD = 8 * DEG;
const SHARED_TILT_SD = 45 * DEG;
/** Readings farther off than this (pixels) count less, as likely misread. */
const HUBER = 3;

interface Model {
  tilt: number;
  poses: Pose[];
  f: number;
}

/**
 * Solves once: from a focal length and the way round the user went (1: as asked, -1: the other
 * way). Returns the cameras, the points and how well they agree.
 */
function solveOnce(views: ScanView[], n: number, f: number, dir: number) {
  const K = views.length;
  const step = dir * SCAN_STEP * DEG;
  // World units: a pixel at the first camera's distance, which is f away.
  const D = f;
  const model: Model = { tilt: 0, f, poses: views.map((_, k) => ({ a: k * step, dp: 0, roll: 0, t: [0, 0, -D] as [number, number, number] })) };
  const obs: Obs[][] = Array.from({ length: n }, () => []);
  views.forEach((v, k) => {
    const seen = new Set<number>();
    for (const l of v.leds) {
      if (l.num < 0 || l.num >= n || seen.has(l.num) || !Number.isFinite(l.x) || !Number.isFinite(l.y)) continue;
      seen.add(l.num);
      obs[l.num].push({ k, u: l.x, v: l.y, w: 1, ok: true });
    }
  });
  const X: (number[] | null)[] = Array.from({ length: n }, () => null);
  const cams = () => model.poses.map((p, k) => camOf(model.tilt, p, views[k], f));
  // A start: the first picture's LEDs flat, at its distance.
  for (let i = 0; i < n; i++) {
    const o = obs[i].find((o) => o.k === 0);
    if (o) X[i] = [((o.u - views[0].width / 2) * D) / f, (-(o.v - views[0].height / 2) * D) / f, 0];
  }

  // The cameras' numbers as one list: the shared tilt, the first camera's roll, then for each
  // other camera its angle, tilt, roll and place. The first camera stays put: it sets where the
  // world is, which way is front and how big it is.
  const pack = (m: Model, active: number) => [m.tilt, m.poses[0].roll, ...m.poses.slice(1, active).flatMap((p) => [p.a, p.dp, p.roll, ...p.t])];
  const unpack = (q: number[], active: number): Model => ({
    f,
    tilt: q[0],
    poses: model.poses.map((p, k) => (k === 0 ? { ...p, roll: q[1] } : k < active ? { a: q[2 + (k - 1) * 6], dp: q[3 + (k - 1) * 6], roll: q[4 + (k - 1) * 6], t: [q[5 + (k - 1) * 6], q[6 + (k - 1) * 6], q[7 + (k - 1) * 6]] } : p))
  });

  const placePoints = (active: number) => {
    const cs = cams();
    for (let i = 0; i < n; i++) {
      const list = obs[i].filter((o) => o.ok && o.k < active);
      if (list.length < 2) continue;
      const start = X[i] && obs[i].some((o) => o.k > 0 && o.k < active - 1) ? X[i] : triangulate(cs, list);
      if (!start) continue;
      X[i] = refinePoint(cs, list, start);
    }
  };
  const reweigh = (active: number) => {
    const cs = cams();
    for (let i = 0; i < n; i++) {
      const x = X[i];
      if (!x) continue;
      for (const o of obs[i]) {
        if (o.k >= active) continue;
        const [u, v] = project(cs[o.k], x);
        const r = Math.hypot(u - o.u, v - o.v);
        o.w = r <= HUBER ? 1 : HUBER / r;
      }
    }
  };
  const priors = (m: Model, active: number) => {
    const out = [(PRIOR_PX * m.tilt) / SHARED_TILT_SD];
    for (let k = 0; k < active; k++) {
      const p = m.poses[k];
      if (k > 0) out.push((PRIOR_PX * (p.a - m.poses[k - 1].a - step)) / STEP_SD, (PRIOR_PX * p.dp) / TILT_SD);
      out.push((PRIOR_PX * p.roll) / TILT_SD);
    }
    return out;
  };

  /**
   * Moves the cameras and the LEDs together (bundle adjustment), so they settle where the
   * pictures agree: Levenberg–Marquardt, with each LED's three numbers solved out first (the
   * Schur complement), as only the cameras tie the LEDs to each other.
   */
  const bundle = (active: number, rounds: number) => {
    placePoints(active);
    let lambda = 1e-3;
    const P = 2 + 6 * (active - 1);
    /** The views a camera number moves: the shared tilt moves them all. */
    const viewOf = (j: number) => (j === 0 ? -1 : j === 1 ? 0 : 1 + Math.floor((j - 2) / 6));
    for (let round = 0; round < rounds; round++) {
      reweigh(active);
      const pts = X.map((x, i) => ({ i, x, list: obs[i].filter((o) => o.ok && o.k < active) })).filter((p): p is { i: number; x: number[]; list: Obs[] } => !!p.x && p.list.length >= 2);
      const q0 = pack(model, active);
      const cs = cams();
      const cost = (m: Model, at: (k: number) => number[]) => {
        const c2 = m.poses.slice(0, active).map((p, k) => camOf(m.tilt, p, views[k], f));
        let c = 0;
        pts.forEach((p, k) => {
          const x = at(k);
          for (const o of p.list) {
            const [u, v, d] = project(c2[o.k], x);
            c += d <= 1e-6 * D ? 1e12 : o.w * ((u - o.u) ** 2 + (v - o.v) ** 2);
          }
        });
        return c + priors(m, active).reduce((a, v) => a + v * v, 0);
      };
      // The residuals and how they change: with each LED (exactly) and each camera number (by a small step).
      type Row = { o: Obs; r: [number, number]; jx: number[]; jc: number[] };
      const rows: Row[][] = pts.map((p) =>
        p.list.map((o) => {
          const c = cs[o.k];
          const R = c.R;
          const x = p.x;
          const px = R[0] * x[0] + R[1] * x[1] + R[2] * x[2] + c.t[0];
          const py = R[3] * x[0] + R[4] * x[1] + R[5] * x[2] + c.t[1];
          const d = -(R[6] * x[0] + R[7] * x[1] + R[8] * x[2] + c.t[2]);
          const sw = Math.sqrt(o.w);
          const ju = [0, 1, 2].map((i) => sw * c.f * (R[i] / d + (px * R[6 + i]) / (d * d)));
          const jv = [0, 1, 2].map((i) => -sw * c.f * (R[3 + i] / d + (py * R[6 + i]) / (d * d)));
          return { o, r: [sw * (c.cu + (c.f * px) / d - o.u), sw * (c.cv - (c.f * py) / d - o.v)], jx: [...ju, ...jv], jc: new Array(2 * P).fill(0) };
        })
      );
      for (let j = 0; j < P; j++) {
        const h = 1e-6 * Math.max(1, Math.abs(q0[j]));
        const q = q0.slice();
        q[j] += h;
        const m = unpack(q, active);
        const view = viewOf(j);
        const c2 = m.poses.slice(0, active).map((p, k) => (view < 0 || k === view ? camOf(m.tilt, p, views[k], f) : null));
        pts.forEach((p, k) => {
          rows[k].forEach((row) => {
            const c = c2[row.o.k];
            if (!c) return;
            const [u, v] = project(c, p.x);
            const sw = Math.sqrt(row.o.w);
            row.jc[j] = (sw * (u - row.o.u) - row.r[0]) / h;
            row.jc[P + j] = (sw * (v - row.o.v) - row.r[1]) / h;
          });
        });
      }
      const pr0 = priors(model, active);
      const jp = Array.from({ length: P }, (_, j) => {
        const h = 1e-6 * Math.max(1, Math.abs(q0[j]));
        const q = q0.slice();
        q[j] += h;
        return priors(unpack(q, active), active).map((v, i) => (v - pr0[i]) / h);
      });
      // The normal equations: U for the cameras, V for each LED, W between them.
      const U = new Array(P * P).fill(0);
      const gc = new Array(P).fill(0);
      for (let a = 0; a < P; a++) {
        for (let i = 0; i < pr0.length; i++) gc[a] += jp[a][i] * pr0[i];
        for (let b = a; b < P; b++) {
          let v = 0;
          for (let i = 0; i < pr0.length; i++) v += jp[a][i] * jp[b][i];
          U[a * P + b] += v;
        }
      }
      const V: number[][] = [];
      const Wm: number[][] = [];
      const gx: number[][] = [];
      rows.forEach((list, k) => {
        const v = new Array(9).fill(0);
        const w = new Array(P * 3).fill(0);
        const g = [0, 0, 0];
        for (const row of list) {
          for (let e = 0; e < 2; e++) {
            const jx = row.jx.slice(e * 3, e * 3 + 3);
            const jc = row.jc.slice(e * P, e * P + P);
            const r = row.r[e];
            for (let a = 0; a < 3; a++) {
              g[a] += jx[a] * r;
              for (let b = 0; b < 3; b++) v[a * 3 + b] += jx[a] * jx[b];
            }
            for (let a = 0; a < P; a++) {
              if (!jc[a]) continue;
              gc[a] += jc[a] * r;
              for (let b = 0; b < 3; b++) w[a * 3 + b] += jc[a] * jx[b];
              for (let b = a; b < P; b++) U[a * P + b] += jc[a] * jc[b];
            }
          }
        }
        V[k] = v;
        Wm[k] = w;
        gx[k] = g;
      });
      for (let a = 0; a < P; a++) for (let b = 0; b < a; b++) U[a * P + b] = U[b * P + a];
      const before = cost(model, (k) => pts[k].x);
      let better = false;
      for (let tries = 0; tries < 8 && !better; tries++) {
        // With the LEDs solved out: S δc = rhs, then each LED's own step.
        const S = U.map((v, i) => (i % (P + 1) === 0 ? v * (1 + lambda) + 1e-9 : v));
        const rhs = gc.map((v) => -v);
        const inv: (number[] | null)[] = V.map((v) => inverse3(v.map((x, i) => (i % 4 === 0 ? x * (1 + lambda) + 1e-12 : x))));
        rows.forEach((_, k) => {
          const vi = inv[k];
          if (!vi) return;
          const w = Wm[k];
          // W V⁻¹ (P×3)
          const wv = new Array(P * 3).fill(0);
          for (let a = 0; a < P; a++) for (let b = 0; b < 3; b++) wv[a * 3 + b] = w[a * 3] * vi[b] + w[a * 3 + 1] * vi[3 + b] + w[a * 3 + 2] * vi[6 + b];
          for (let a = 0; a < P; a++) {
            if (!wv[a * 3] && !wv[a * 3 + 1] && !wv[a * 3 + 2]) continue;
            rhs[a] += wv[a * 3] * gx[k][0] + wv[a * 3 + 1] * gx[k][1] + wv[a * 3 + 2] * gx[k][2];
            for (let b = 0; b < P; b++) S[a * P + b] -= wv[a * 3] * w[b * 3] + wv[a * 3 + 1] * w[b * 3 + 1] + wv[a * 3 + 2] * w[b * 3 + 2];
          }
        });
        const dc = solve(S, rhs, P);
        if (!dc) {
          lambda *= 10;
          continue;
        }
        const next = pts.map((p, k) => {
          const vi = inv[k];
          if (!vi) return p.x;
          const w = Wm[k];
          const b = [0, 1, 2].map((e) => -gx[k][e] - dc.reduce((s, v, a) => s + w[a * 3 + e] * v, 0));
          return [0, 1, 2].map((e) => p.x[e] + vi[e * 3] * b[0] + vi[e * 3 + 1] * b[1] + vi[e * 3 + 2] * b[2]);
        });
        const m = unpack(
          q0.map((v, i) => v + dc[i]),
          active
        );
        const after = cost(m, (k) => next[k]);
        if (after < before) {
          better = true;
          Object.assign(model, m);
          pts.forEach((p, k) => (X[p.i] = next[k]));
          lambda = Math.max(1e-9, lambda / 4);
          if (before - after < before * 1e-9) return;
        } else lambda *= 6;
      }
      if (!better) break;
    }
  };

  /** Puts camera k where the LEDs it shares with the earlier ones land about right, turned `a`. */
  const startCamera = (k: number, a: number) => {
    const p: Pose = { a, dp: 0, roll: 0, t: [0, 0, -D] };
    const shared = obs.map((list, i) => ({ x: X[i], o: list.find((o) => o.k === k) })).filter((s): s is { x: number[]; o: Obs } => !!s.x && !!s.o);
    if (!shared.length) return p;
    const c = [0, 1, 2].map((j) => shared.reduce((s, q) => s + q.x[j], 0) / shared.length);
    const mu = shared.reduce((s, q) => s + q.o.u, 0) / shared.length;
    const mv = shared.reduce((s, q) => s + q.o.v, 0) / shared.length;
    // How big they look here, against how big they would look from the first camera's distance.
    const cam = camOf(model.tilt, p, views[k], f);
    const proj = shared.map((q) => project(cam, q.x));
    const pu = proj.reduce((s, q) => s + q[0], 0) / proj.length;
    const pv = proj.reduce((s, q) => s + q[1], 0) / proj.length;
    const seenR = Math.sqrt(shared.reduce((s, q) => s + (q.o.u - mu) ** 2 + (q.o.v - mv) ** 2, 0) / shared.length);
    const projR = Math.sqrt(proj.reduce((s, q) => s + (q[0] - pu) ** 2 + (q[1] - pv) ** 2, 0) / proj.length);
    const depth = D * (seenR > 1e-6 && projR > 1e-6 ? Math.min(4, Math.max(0.25, projR / seenR)) : 1);
    const R = cam.R;
    const rc = [R[0] * c[0] + R[1] * c[1] + R[2] * c[2], R[3] * c[0] + R[4] * c[1] + R[5] * c[2], R[6] * c[0] + R[7] * c[1] + R[8] * c[2]];
    const want = [((mu - views[k].width / 2) * depth) / f, (-(mv - views[k].height / 2) * depth) / f, -depth];
    p.t = [want[0] - rc[0], want[1] - rc[1], want[2] - rc[2]];
    return p;
  };

  const save = () => ({ X: X.map((x) => x && x.slice()), tilt: model.tilt, poses: model.poses.map((p) => ({ ...p, t: [...p.t] as Pose['t'] })), w: obs.map((l) => l.map((o) => o.w)) });
  const restore = (s: ReturnType<typeof save>) => {
    s.X.forEach((x, i) => (X[i] = x && x.slice()));
    model.tilt = s.tilt;
    model.poses = s.poses.map((p) => ({ ...p, t: [...p.t] as Pose['t'] }));
    obs.forEach((l, i) => l.forEach((o, j) => (o.w = s.w[i][j])));
  };

  for (let k = 1; k < K; k++) {
    const prev = model.poses[k - 1].a;
    if (k === 1) {
      // The second camera: every angle round, each with the LEDs placed from the two pictures;
      // the one where they agree best (with how far the user was asked to go, for when the
      // pictures can hardly tell).
      const start = save();
      let best: { s: ReturnType<typeof save>; cost: number } | null = null;
      for (let d = 15; d <= 150; d += 15) {
        restore(start);
        model.poses[1] = startCamera(1, prev + dir * d * DEG);
        bundle(2, 8);
        const cost = costOf(2);
        if (!best || cost < best.cost) best = { s: save(), cost };
      }
      restore(best!.s);
      continue;
    }
    // Later ones: the angle that fits the LEDs placed so far best, searched round from the one before.
    let best: { p: Pose; cost: number } | null = null;
    for (let d = 10; d <= 150; d += 10) {
      model.poses[k] = startCamera(k, prev + dir * d * DEG);
      // Only this camera moves: a quick fit of it alone.
      const q = leastSquares([model.poses[k].a, model.poses[k].dp, model.poses[k].roll, ...model.poses[k].t], (q) => cameraFit(k, q), 6);
      const cost = cameraFit(k, q).reduce((s, v) => s + v * v, 0);
      if (!best || cost < best.cost) best = { p: { a: q[0], dp: q[1], roll: q[2], t: [q[3], q[4], q[5]] }, cost };
    }
    model.poses[k] = best!.p;
    bundle(k + 1, k === K - 1 ? 15 : 6);
  }

  /** How well the first `active` cameras and the LEDs agree: the pictures (misreadings counting less) and the guesses. */
  function costOf(active: number) {
    const cs = cams();
    let data = 0;
    for (let i = 0; i < n; i++) {
      const x = X[i];
      const list = obs[i].filter((o) => o.ok && o.k < active);
      if (!x || list.length < 2) continue;
      for (const o of list) {
        const [u, v] = project(cs[o.k], x);
        const r = Math.hypot(u - o.u, v - o.v);
        data += r <= HUBER ? r * r : HUBER * (2 * r - HUBER);
      }
    }
    const prior = priors(model, active).reduce((s, v) => s + v * v, 0);
    return data + prior;
  }

  /** Camera k against the LEDs placed so far: its residuals and its guesses. */
  function cameraFit(k: number, q: number[]) {
    const p: Pose = { a: q[0], dp: q[1], roll: q[2], t: [q[3], q[4], q[5]] };
    const cam = camOf(model.tilt, p, views[k], f);
    const out: number[] = [];
    for (let i = 0; i < n; i++) {
      const x = X[i];
      const o = obs[i].find((o) => o.k === k);
      if (!x || !o || !obs[i].some((q) => q.k > 0 && q.k < k)) continue;
      const [u, v, d] = project(cam, x);
      if (d <= 1e-6 * D) out.push(1e3, 1e3);
      else {
        // Robust: a misread LED should not pull the camera.
        const r = Math.hypot(u - o.u, v - o.v);
        const w = r <= HUBER * 3 ? 1 : Math.sqrt((HUBER * 3) / r);
        out.push(w * (u - o.u), w * (v - o.v));
      }
    }
    out.push((PRIOR_PX * (p.a - model.poses[k - 1].a - step)) / STEP_SD, (PRIOR_PX * p.dp) / TILT_SD, (PRIOR_PX * p.roll) / TILT_SD);
    return out;
  }

  // Readings that still land far off are misread numbers (or a reflection): leave them out.
  const errors = () => {
    const cs = cams();
    const list: { o: Obs; r: number }[] = [];
    for (let i = 0; i < n; i++) {
      const x = X[i];
      if (!x || obs[i].filter((o) => o.ok).length < 2) continue;
      for (const o of obs[i])
        if (o.ok) {
          const [u, v] = project(cs[o.k], x);
          list.push({ o, r: Math.hypot(u - o.u, v - o.v) });
        }
    }
    return list;
  };
  if (K >= 2) {
    const e = errors();
    const med = e.map((x) => x.r).sort((a, b) => a - b)[Math.floor(e.length / 2)] ?? 0;
    const limit = Math.max(6, med * 5);
    let dropped = 0;
    for (const x of e)
      if (x.r > limit) {
        x.o.ok = false;
        dropped++;
      }
    if (dropped) {
      for (let i = 0; i < n; i++) if (obs[i].filter((o) => o.ok).length < 2) X[i] = obs[i].some((o) => o.ok && o.k === 0) ? X[i] : null;
      bundle(K, 10);
    }
  }
  const e = errors();
  const cost = costOf(K);
  const cs = cams();
  const points: (Pt3 | null)[] = X.map((x, i) => {
    if (!x || obs[i].filter((o) => o.ok).length < 2) return null;
    // Seen from nearly the same way (or straight opposite ways): its depth cannot be told.
    const s = spread(cs, obs[i], x);
    if (s < 8 * DEG || s > 172 * DEG) return null;
    return { x: x[0], y: x[1], z: x[2] };
  });
  const W = upright(cs);
  const turn = (p: Pt3): Pt3 => ({ x: W[0] * p.x + W[1] * p.y + W[2] * p.z, y: W[3] * p.x + W[4] * p.y + W[5] * p.z, z: W[6] * p.x + W[7] * p.y + W[8] * p.z });
  return {
    points: points.map((p) => p && turn(p)),
    cameras: cs.map((c) => {
      const back = turn({ x: c.R[6], y: c.R[7], z: c.R[8] });
      return { ...turn(center(c)), angle: Math.atan2(back.x, back.z) / DEG };
    }),
    rms: e.length ? Math.sqrt(e.reduce((s, x) => s + x.r * x.r, 0) / e.length) : 0,
    cost,
    placed: points.filter(Boolean).length
  };
}

/**
 * The turn that stands the world up: the phone was held level, so each camera's side to side
 * is level, and up is square to all of them (the pictures alone cannot tell a world tipped a
 * little, with every camera tipped to match). Front: toward the first camera.
 */
function upright(cs: Cam[]): M3 {
  const M = new Array(9).fill(0);
  for (const c of cs) for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) M[i * 3 + j] += c.R[i] * c.R[j];
  // The smallest eigenvector of M: the biggest of (trace − M), by repeated multiplying.
  const tr = M[0] + M[4] + M[8];
  const B = M.map((v, i) => (i % 4 === 0 ? tr - v : -v));
  let up = [cs[0].R[3], cs[0].R[4], cs[0].R[5]];
  for (let it = 0; it < 60; it++) {
    const next = [0, 1, 2].map((i) => B[i * 3] * up[0] + B[i * 3 + 1] * up[1] + B[i * 3 + 2] * up[2]);
    const l = Math.hypot(...next);
    if (!(l > 1e-12)) break;
    up = next.map((v) => v / l);
  }
  // Up as the first camera has it, not down.
  if (up[0] * cs[0].R[3] + up[1] * cs[0].R[4] + up[2] * cs[0].R[5] < 0) up = up.map((v) => -v);
  const back = [cs[0].R[6], cs[0].R[7], cs[0].R[8]];
  const along = back[0] * up[0] + back[1] * up[1] + back[2] * up[2];
  let z = back.map((v, i) => v - along * up[i]);
  const lz = Math.hypot(...z);
  if (!(lz > 1e-9)) return [1, 0, 0, 0, 1, 0, 0, 0, 1];
  z = z.map((v) => v / lz);
  const x = [up[1] * z[2] - up[2] * z[1], up[2] * z[0] - up[0] * z[2], up[0] * z[1] - up[1] * z[0]];
  return [...x, ...up, ...z];
}

/**
 * The LEDs in 3D from two or more scans of the same LEDs taken from different sides, a step
 * round each time (see SCAN_STEP). The first scan is the front.
 */
export function solveViews(views: ScanView[], n: number, opts: { focal?: number } = {}): Solved3D {
  const live = views.filter((v) => v.leds.length >= 4);
  if (live.length < 2) return { points: Array.from({ length: n }, () => null), cameras: [], rms: 0, placed: 0 };
  const long = Math.max(live[0].width, live[0].height);
  // Both ways round: where the pictures can tell (from how near parts look bigger), the other
  // way wins only when it clearly fits better; else the user went the way they were asked.
  const focal = opts.focal ?? FOCAL;
  const tries = [1, -1].map((dir) => ({ dir, ...solveOnce(live, n, focal * long, dir) }));
  const [asked, other] = tries;
  const best = other.cost < asked.cost * 0.8 && other.placed >= asked.placed * 0.9 ? other : asked;
  return { points: best.points, cameras: best.cameras, rms: best.rms, placed: best.placed };
}

// ---------- Cameras whose places are known ----------
//
// Walking round with the phone in AR (see scanWalk.ts), the phone's own tracking (its camera and
// motion sensors together, as AR apps do) says where it was and which way it faced for every
// picture, in meters. Then each LED is simply where its lines of sight meet.

/** A camera whose place and turn are known: world to camera (looking down −z, y up), and its lens in pixels. */
export interface PosedCam {
  R: number[];
  t: [number, number, number];
  f: number;
  fy?: number;
  cu: number;
  cv: number;
}

/** An LED seen in a picture: which camera, and where (pixels). */
export interface Sighting {
  cam: number;
  u: number;
  v: number;
}

/** How far a sighting may land from where the point shows and still count (pixels). */
const KNOWN_TOL = 4;
/** The widest angle between two lines of sight needed for a depth (radians). */
const KNOWN_SPREAD = 3 * DEG;

/** A small steady random sequence (the same answer every time), spread out from small seeds. */
const rand = (seed: number) => seededRandom(Math.imul(seed, 2654435761));

/**
 * Where each LED is, from cameras whose places are known. A few sightings may be of the wrong
 * LED (one followed into its neighbor, a misread number), so a point is first guessed from pairs
 * of sightings, keeping the one most others agree with (RANSAC), then made exact on those.
 * Returns, by LED, the point (null: not seen from far enough apart) and how many sightings agree.
 */
export function placeSeen(cams: PosedCam[], seen: Sighting[][]): { points: (Pt3 | null)[]; agree: number[]; rms: number; placed: number } {
  const cs: Cam[] = cams.map((c) => ({ R: c.R, t: c.t, f: c.f, fy: c.fy, cu: c.cu, cv: c.cv }));
  const centers = cs.map(center);
  const ray = (o: Sighting) => {
    const c = cs[o.cam];
    const R = c.R;
    const d = [(o.u - c.cu) / c.f, -(o.v - c.cv) / (c.fy ?? c.f), -1];
    const w = [R[0] * d[0] + R[3] * d[1] + R[6] * d[2], R[1] * d[0] + R[4] * d[1] + R[7] * d[2], R[2] * d[0] + R[5] * d[1] + R[8] * d[2]];
    const l = Math.hypot(...w);
    return w.map((x) => x / l);
  };
  const points: (Pt3 | null)[] = [];
  const agree: number[] = [];
  let se = 0;
  let count = 0;
  seen.forEach((list, i) => {
    // One sighting per picture.
    const byCam = new Map<number, Sighting>();
    for (const o of list) if (o.cam >= 0 && o.cam < cs.length && Number.isFinite(o.u) && Number.isFinite(o.v)) byCam.set(o.cam, o);
    const S = [...byCam.values()];
    points.push(null);
    agree.push(0);
    if (S.length < 2) return;
    const rays = S.map(ray);
    const obs: Obs[] = S.map((o) => ({ k: o.cam, u: o.u, v: o.v, w: 1, ok: true }));
    const err = (X: number[], o: Obs) => {
      const [u, v, d] = project(cs[o.k], X);
      return d > 1e-3 ? Math.hypot(u - o.u, v - o.v) : Infinity;
    };
    // Where two lines of sight pass closest.
    const meet = (a: number, b: number): number[] | null => {
      const p = centers[S[a].cam];
      const q = centers[S[b].cam];
      const u = rays[a];
      const v = rays[b];
      const uv = u[0] * v[0] + u[1] * v[1] + u[2] * v[2];
      if (Math.acos(Math.min(1, Math.abs(uv))) < KNOWN_SPREAD) return null;
      const w = [p.x - q.x, p.y - q.y, p.z - q.z];
      const uw = u[0] * w[0] + u[1] * w[1] + u[2] * w[2];
      const vw = v[0] * w[0] + v[1] * w[1] + v[2] * w[2];
      const den = 1 - uv * uv;
      const s = (uv * vw - uw) / den;
      const t = (vw - uv * uw) / den;
      if (s <= 0 || t <= 0) return null;
      return [0, 1, 2].map((k) => ([p.x, p.y, p.z][k] + s * u[k] + [q.x, q.y, q.z][k] + t * v[k]) / 2);
    };
    const pairs: [number, number][] = [];
    if (S.length <= 9) for (let a = 0; a < S.length; a++) for (let b = a + 1; b < S.length; b++) pairs.push([a, b]);
    else {
      const r = rand(i + 1);
      for (let k = 0; k < 48; k++) {
        const a = Math.floor(r() * S.length);
        const b = Math.floor(r() * S.length);
        if (a !== b) pairs.push([a, b]);
      }
    }
    let best: { X: number[]; n: number; sum: number } | null = null;
    for (const [a, b] of pairs) {
      const X = meet(a, b);
      if (!X) continue;
      let n = 0;
      let sum = 0;
      for (const o of obs) {
        const e = err(X, o);
        if (e <= KNOWN_TOL * 2) (n++, (sum += e));
      }
      if (!best || n > best.n || (n === best.n && sum < best.sum)) best = { X, n, sum };
    }
    if (!best) return;
    let X = best.X;
    for (let round = 0; round < 3; round++) {
      const tol = round === 0 ? KNOWN_TOL * 2 : KNOWN_TOL;
      for (const o of obs) o.ok = err(X, o) <= tol;
      if (obs.filter((o) => o.ok).length < 2) return;
      X = refinePoint(cs, obs, X, 5);
    }
    for (const o of obs) o.ok = err(X, o) <= KNOWN_TOL;
    const good = obs.filter((o) => o.ok);
    // Most of its sightings agree, from far enough apart for a depth.
    if (good.length < 2 || good.length < S.length * 0.3 || spread(cs, good, X) < KNOWN_SPREAD) return;
    for (const o of good) {
      se += err(X, o) ** 2;
      count++;
    }
    points[i] = { x: X[0], y: X[1], z: X[2] };
    agree[i] = good.length;
  });
  return { points, agree, rms: count ? Math.sqrt(se / count) : 0, placed: points.filter(Boolean).length };
}

// ---------- From the points to a design ----------

const dist3 = (a: Pt3, b: Pt3) => Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z);

/** The string's spacing in the points' units: between LEDs whose numbers follow on (see tautStep). */
export function step3d(points: (Pt3 | null)[]): number {
  const steps: number[] = [];
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    if (a && b) steps.push(dist3(a, b));
  }
  return tautStep(steps, 0.85);
}

/** How wide the LEDs are, side to side as seen from the front, in the points' units. */
export function width3d(points: (Pt3 | null)[]): number {
  const xs = points.filter((p): p is Pt3 => !!p).map((p) => p.x);
  return xs.length ? Math.max(...xs) - Math.min(...xs) : 0;
}

/**
 * The LEDs as runs of points, one for every LED in number order: an LED not placed sits on the
 * straight line between the ones placed before and after it (or, before the first or after the
 * last, on it). A new run where the wire jumps farther than its LEDs could reach.
 */
export function wire3d(points: (Pt3 | null)[]): Pt3[][] {
  const n = points.length;
  const known = points.map((p, i) => ({ p, i })).filter((x): x is { p: Pt3; i: number } => !!x.p);
  if (!known.length) return [];
  const step = step3d(points);
  const runs: Pt3[][] = [[]];
  for (let i = 0; i < known[0].i; i++) runs[0].push({ ...known[0].p });
  for (let j = 0; j < known.length; j++) {
    const b = known[j];
    const a = known[j - 1];
    if (a) {
      const gap = b.i - a.i;
      const far = step > 0 && dist3(a.p, b.p) > step * gap * 1.5 + step * 0.5;
      for (let m = 1; m < gap; m++) {
        const t = m / gap;
        runs.at(-1)!.push({ x: a.p.x + (b.p.x - a.p.x) * t, y: a.p.y + (b.p.y - a.p.y) * t, z: a.p.z + (b.p.z - a.p.z) * t });
      }
      if (far) runs.push([]);
    }
    runs.at(-1)!.push({ ...b.p });
  }
  const last = known.at(-1)!;
  for (let i = last.i + 1; i < n; i++) runs.at(-1)!.push({ ...last.p });
  return runs.filter((r) => r.length);
}

/**
 * The points as a design in meters: one exact stroke per run (an LED at each point), the anchor
 * in the middle of the object. `mirror` turns front and back round (when the scans went the
 * other way round than they were taken).
 */
export function design3d(points: (Pt3 | null)[], metersPerUnit: number, mirror = false): DesignStroke[] {
  const runs = wire3d(points);
  const all = runs.flat();
  if (!all.length || !(metersPerUnit > 0)) return [];
  const mid = (k: 'x' | 'y' | 'z') => (Math.min(...all.map((p) => p[k])) + Math.max(...all.map((p) => p[k]))) / 2;
  const c = { x: mid('x'), y: mid('y'), z: mid('z') };
  const r3 = (v: number) => Math.round(v * 1000) / 1000 + 0;
  return runs.map((run) => ({
    points: run.map((p) => ({ x: r3((p.x - c.x) * metersPerUnit), y: r3((p.y - c.y) * metersPerUnit), z: r3((mirror ? c.z - p.z : p.z - c.z) * metersPerUnit) })),
    exact: true
  }));
}
