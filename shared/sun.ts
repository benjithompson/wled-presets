// Sunrise and sunset for a place on Earth, to within a minute or two: the sunrise equation as
// the US Naval Observatory and NOAA give it (the sun's upper edge on the horizon, with the air's
// refraction). Nothing here knows about time zones: times are instants (ms since 1970, UTC).

const RAD = Math.PI / 180;
const DAY_MS = 86_400_000;
const J1970 = 2440588;
const J2000 = 2451545;
const J0 = 0.0009;
/** The sun's center this far below the horizon is sunrise or sunset (refraction and its radius). */
const HORIZON = -0.833 * RAD;
/** The tilt of the Earth's axis. */
const OBLIQUITY = 23.4397 * RAD;

const toDays = (ms: number) => ms / DAY_MS - 0.5 + J1970 - J2000;
const fromJulian = (j: number) => (j + 0.5 - J1970) * DAY_MS;

export interface SunTimes {
  /** Null where the sun does not rise that day, or does not set (near the poles). */
  sunrise: number | null;
  sunset: number | null;
}

/**
 * The sunrise and sunset of the solar day nearest `near` (an instant: local noon picks that
 * local date's), at latitude and longitude in degrees (east and north positive).
 */
export function sunTimes(near: number, latitude: number, longitude: number): SunTimes {
  const lw = -longitude * RAD;
  const phi = latitude * RAD;
  const d = toDays(near);
  const n = Math.round(d - J0 - lw / (2 * Math.PI));
  const ds = J0 + lw / (2 * Math.PI) + n;
  const M = (357.5291 + 0.98560028 * ds) * RAD;
  const C = (1.9148 * Math.sin(M) + 0.02 * Math.sin(2 * M) + 0.0003 * Math.sin(3 * M)) * RAD;
  const L = M + C + 102.9372 * RAD + Math.PI;
  const dec = Math.asin(Math.sin(OBLIQUITY) * Math.sin(L));
  const transit = (a: number) => J2000 + a + 0.0053 * Math.sin(M) - 0.0069 * Math.sin(2 * L);
  const noon = transit(ds);
  const cosW = (Math.sin(HORIZON) - Math.sin(phi) * Math.sin(dec)) / (Math.cos(phi) * Math.cos(dec));
  // Above 1: the sun stays down all day; below -1: it stays up.
  if (!(cosW >= -1 && cosW <= 1)) return { sunrise: null, sunset: null };
  const w = Math.acos(cosW);
  const set = transit(J0 + (w + lw) / (2 * Math.PI) + n);
  return { sunrise: fromJulian(noon - (set - noon)), sunset: fromJulian(set) };
}
