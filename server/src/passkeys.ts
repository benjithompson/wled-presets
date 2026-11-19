import crypto from 'node:crypto';
import net from 'node:net';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON
} from '@simplewebauthn/server';
import type { Passkey } from '../../shared/types.ts';
import type { Db } from './db.ts';

// Passkeys for the admin sign-in (WebAuthn). A passkey is a key pair kept by the phone, computer
// or security key: the site stores only the public half, and a sign-in is a fresh signature that
// the device makes after the owner unlocks it (fingerprint, face, PIN). Nothing to guess, and a
// passkey made here does not work on any other site, so it cannot be phished.
//
// A passkey belongs to the site's name (its "RP ID", like lights.example.com), and browsers only
// make them for pages over HTTPS (or on localhost), never for an IP address.

/** How long a sign-in or a new passkey may take, from asking to answering. */
const CHALLENGE_MS = 5 * 60_000;
/** At most this many open challenges (a flood of requests for one cannot fill memory). */
const MAX_CHALLENGES = 1000;
/** At most this many passkeys per admin. */
export const MAX_PASSKEYS = 20;

/** Where the request came from, as the browser sees it: the page's origin and the site's name. */
export interface Site {
  origin: string;
  rpId: string;
}

/**
 * The site of a request: from its Origin header (which sameOrigin() has matched to Host). Null
 * with the reason when passkeys cannot work there: plain HTTP, or an address instead of a name.
 */
export function siteOf(origin: string | undefined, host: string | undefined, https: boolean): Site | { error: string } {
  let url: URL;
  try {
    url = new URL(origin || `${https ? 'https' : 'http'}://${host ?? ''}`);
  } catch {
    return { error: 'Passkeys need to know the address of this page.' };
  }
  const name = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const local = name === 'localhost' || name.endsWith('.localhost');
  if (net.isIP(name)) return { error: 'Passkeys need the site’s name, not an IP address. Open the admin console by its name over HTTPS.' };
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    return { error: 'Passkeys work only over HTTPS. Open the admin console at its https:// address.' };
  }
  return { origin: url.origin, rpId: name };
}

interface Challenge {
  /** A sign-in (anyone), or a new passkey for this admin. */
  userId: string | null;
  rpId: string;
  expires: number;
}

export function createPasskeys(db: Db, opts: { rpName?: string; now?: () => number } = {}) {
  const rpName = opts.rpName ?? 'WLED Presets';
  const now = opts.now ?? Date.now;
  const challenges = new Map<string, Challenge>();

  function remember(challenge: string, c: Omit<Challenge, 'expires'>) {
    const t = now();
    if (challenges.size >= MAX_CHALLENGES) {
      for (const [k, v] of challenges) if (v.expires < t) challenges.delete(k);
      // Still full: forget the oldest (the map keeps the order they were made in).
      for (const k of challenges.keys()) {
        if (challenges.size < MAX_CHALLENGES) break;
        challenges.delete(k);
      }
    }
    challenges.set(challenge, { ...c, expires: t + CHALLENGE_MS });
  }

  /** Takes a challenge: each works once, before it expires, for the site and admin it was made for. */
  function take(challenge: string, site: Site, userId: string | null) {
    const c = challenges.get(challenge);
    if (!c) return false;
    challenges.delete(challenge);
    return c.expires >= now() && c.rpId === site.rpId && c.userId === userId;
  }

  return {
    list: (userId: string): Passkey[] => db.listPasskeys(userId),

    /** What the browser needs to make a new passkey for this admin on this site. */
    async registrationOptions(user: { id: string; username: string }, site: Site): Promise<PublicKeyCredentialCreationOptionsJSON> {
      const existing = db.passkeyCredentials(user.id).filter((p) => p.rpId === site.rpId);
      if (existing.length >= MAX_PASSKEYS) throw new PasskeyError(`An admin can have at most ${MAX_PASSKEYS} passkeys. Remove one first.`);
      const options = await generateRegistrationOptions({
        rpName,
        rpID: site.rpId,
        userName: user.username,
        userDisplayName: user.username,
        userID: userHandle(user.id),
        timeout: CHALLENGE_MS,
        attestationType: 'none',
        // The same device twice is no use: the browser says so instead.
        excludeCredentials: existing.map((p) => ({ id: p.id, transports: p.transports })),
        // A passkey the device can find by itself (no username to type), unlocked by its owner.
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
      });
      remember(options.challenge, { userId: user.id, rpId: site.rpId });
      return options;
    },

    /** Checks the browser's answer and keeps the new passkey. */
    async register(user: { id: string }, response: RegistrationResponseJSON, site: Site, name: string): Promise<Passkey> {
      let info;
      try {
        const v = await verifyRegistrationResponse({
          response,
          expectedChallenge: (ch) => take(ch, site, user.id),
          expectedOrigin: site.origin,
          expectedRPID: site.rpId,
          requireUserVerification: true
        });
        info = v.verified ? v.registrationInfo : null;
      } catch (e) {
        throw new PasskeyError(`That passkey could not be checked: ${(e as Error).message}`);
      }
      if (!info) throw new PasskeyError('That passkey could not be checked.');
      if (db.getPasskey(info.credential.id)) throw new PasskeyError('That passkey is already saved.');
      db.addPasskey({
        id: info.credential.id,
        userId: user.id,
        name: name.trim() || 'Passkey',
        publicKey: Buffer.from(info.credential.publicKey),
        counter: info.credential.counter,
        transports: response.response.transports ?? [],
        rpId: site.rpId,
        backedUp: info.credentialBackedUp
      });
      return db.listPasskeys(user.id).find((p) => p.id === info.credential.id)!;
    },

    /** What the browser needs to sign in with any passkey of this site. */
    async authenticationOptions(site: Site): Promise<PublicKeyCredentialRequestOptionsJSON> {
      const options = await generateAuthenticationOptions({ rpID: site.rpId, timeout: CHALLENGE_MS, userVerification: 'required' });
      remember(options.challenge, { userId: null, rpId: site.rpId });
      return options;
    },

    /** The admin whose passkey signed this answer, or null. */
    async authenticate(response: AuthenticationResponseJSON, site: Site): Promise<{ user: { id: string; username: string }; passkey: string } | null> {
      // A failed answer still uses up its challenge, so it cannot be tried again.
      const refuse = () => {
        const ch = clientChallenge(response);
        if (ch) challenges.delete(ch);
        return null;
      };
      const key = typeof response?.id === 'string' ? db.getPasskey(response.id) : null;
      // A passkey made on another of the site's names (say the LAN name) only works there.
      if (!key || key.rpId !== site.rpId) return refuse();
      // The device says whose passkey it is: it has to be the admin it was saved for.
      const handle = response.response?.userHandle;
      if (handle && handle !== Buffer.from(userHandle(key.userId)).toString('base64url')) return refuse();
      try {
        const v = await verifyAuthenticationResponse({
          response,
          expectedChallenge: (ch) => take(ch, site, null),
          expectedOrigin: site.origin,
          expectedRPID: site.rpId,
          credential: { id: key.id, publicKey: new Uint8Array(key.publicKey), counter: key.counter, transports: key.transports },
          requireUserVerification: true
        });
        if (!v.verified) return refuse();
        db.usePasskey(key.id, v.authenticationInfo.newCounter, v.authenticationInfo.credentialBackedUp);
      } catch {
        return refuse();
      }
      const user = db.getUserById(key.userId);
      return user ? { user, passkey: key.name } : null;
    },

    rename(userId: string, id: string, name: string) {
      return db.renamePasskey(userId, id, name.trim() || 'Passkey');
    },

    remove(userId: string, id: string) {
      return db.deletePasskey(userId, id);
    }
  };
}

export type Passkeys = ReturnType<typeof createPasskeys>;

/** A passkey that could not be made: the message says why. */
export class PasskeyError extends Error {}

/** The id the device keeps with the passkey for its admin: the admin's id, hashed (no username in it). */
function userHandle(userId: string) {
  return new Uint8Array(crypto.createHash('sha256').update(`wled-presets:${userId}`).digest());
}

function clientChallenge(response: AuthenticationResponseJSON): string | null {
  try {
    const data = JSON.parse(Buffer.from(String(response?.response?.clientDataJSON), 'base64url').toString('utf8'));
    return typeof data?.challenge === 'string' ? data.challenge : null;
  } catch {
    return null;
  }
}
