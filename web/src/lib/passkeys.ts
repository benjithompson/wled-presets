import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, startAuthentication, startRegistration, WebAuthnAbortService, WebAuthnError } from '@simplewebauthn/browser';
import type { Passkey } from '../../../shared/types.ts';
import { api } from './api.ts';

// Passkeys in the browser: the server makes a challenge, the device signs it after its owner
// unlocks it, and the server checks the signature (server/src/passkeys.ts).

/**
 * Why passkeys cannot work on this page, or null when they can. Browsers make passkeys only for
 * pages over HTTPS (or on localhost), and only for a name, not an IP address.
 */
export function passkeysUnavailable(): string | null {
  const host = location.hostname.replace(/^\[|\]$/g, '');
  if (/^[\d.]+$/.test(host) || host.includes(':')) return 'Passkeys need the site’s name, not an IP address. Open the admin console by its name over HTTPS.';
  if (!window.isSecureContext) return 'Passkeys work only over HTTPS. Open the admin console at its https:// address.';
  if (!browserSupportsWebAuthn()) return 'This browser does not support passkeys.';
  return null;
}

/** The person closed the passkey prompt, or another one replaced it: nothing to report. */
export function passkeyCancelled(e: unknown) {
  if (e instanceof WebAuthnError && e.code === 'ERROR_CEREMONY_ABORTED') return true;
  const name = (e as Error)?.name;
  return name === 'NotAllowedError' || name === 'AbortError';
}

/** Words for a failed passkey step. */
export function passkeyErrorText(e: unknown): string {
  if (e instanceof WebAuthnError && e.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED') return 'This device already has a passkey for this site.';
  return (e as Error)?.message || 'The passkey did not work.';
}

/**
 * Signs in with a passkey. `autofill`: offers the passkeys in the username field's suggestions
 * instead of a prompt; it waits until one is picked (or another sign-in starts).
 */
export async function signInWithPasskey(autofill = false) {
  const { options } = await api.passkeyOptions();
  const response = await startAuthentication({ optionsJSON: options, useBrowserAutofill: autofill });
  return api.passkeyLogin(response);
}

/** Whether the username field can offer passkeys as suggestions. */
export const passkeyAutofill = () => (passkeysUnavailable() ? Promise.resolve(false) : browserSupportsWebAuthnAutofill());

/** Stops a waiting autofill sign-in (leaving the page). */
export const stopPasskeyPrompt = () => WebAuthnAbortService.cancelCeremony();

/** Makes a passkey on this device for the signed-in admin; the password confirms it is them. */
export async function addPasskey(password: string, name: string): Promise<Passkey> {
  const { options } = await api.passkeyRegistration(password);
  const response = await startRegistration({ optionsJSON: options });
  return api.addPasskey(name, response);
}

/** A first name for a new passkey: the kind of device it is made on. */
export function guessDeviceName(): string {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/Android/.test(ua)) return 'Android phone';
  if (/Macintosh/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows PC';
  if (/CrOS/.test(ua)) return 'Chromebook';
  if (/Linux/.test(ua)) return 'Linux computer';
  return 'Passkey';
}
