// Signing a slip with a passkey, in a browser. This is the only file that
// touches the page: it calls the browser's Web Authentication interface.
//
// Format description, section 4.2.

import { toBase64url, fromBase64url } from './encoding.js';
import { assembleApproval, prepareApproval } from './approval.js';
import { assembleSlip, prepareSlip } from './slip.js';
import { assembleCancellation, prepareCancellation } from './standing.js';

/** A plain reason a passkey step could not be done, with a code a page can act on. */
export class PasskeyError extends Error {
  /** @param {'unavailable'|'cancelled'|'unsupported-key'} code @param {string} message */
  constructor(code, message) {
    super(message);
    this.name = 'PasskeyError';
    this.code = code;
  }
}

function credentials() {
  if (!globalThis.isSecureContext || !globalThis.navigator || !navigator.credentials || !globalThis.PublicKeyCredential) {
    throw new PasskeyError('unavailable', 'This browser cannot use passkeys on this page.');
  }
  return navigator.credentials;
}

// The signing methods asked for, in order of preference, by their numbers
// in the COSE registry: ES256 (-7), Ed25519 (-8), RS256 (-257).
const METHODS = [
  { type: 'public-key', alg: -7 },
  { type: 'public-key', alg: -8 },
  { type: 'public-key', alg: -257 },
];

async function publicKeyToJwk(spki, coseAlg) {
  const subtle = crypto.subtle;
  if (coseAlg === -7) {
    const key = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const jwk = await subtle.exportKey('jwk', key);
    return { alg: 'ES256', crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y };
  }
  if (coseAlg === -257) {
    const key = await subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
    const jwk = await subtle.exportKey('jwk', key);
    return { alg: 'RS256', e: jwk.e, kty: 'RSA', n: jwk.n };
  }
  if (coseAlg === -8) {
    const key = await subtle.importKey('spki', spki, { name: 'Ed25519' }, true, ['verify']);
    const jwk = await subtle.exportKey('jwk', key);
    return { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: jwk.x };
  }
  throw new PasskeyError('unsupported-key', 'The passkey uses a signing method this format does not accept.');
}

/**
 * Make a new passkey on this device for this website.
 *
 * @param {object} who
 * @param {string} who.name the person's name, shown by the device when it asks
 * @param {string} who.site a name for this website, shown by the device
 * @returns {Promise<{credentialId: string, key: object, rpId: string, origin: string}>}
 *   what must be kept to sign slips later: the passkey's identifier, its public key, and the website
 */
export async function createPasskey({ name, site }) {
  const container = credentials();
  let credential;
  try {
    credential = await container.create({
      publicKey: {
        rp: { id: location.hostname, name: site },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: METHODS,
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        attestation: 'none',
      },
    });
  } catch (e) {
    throw new PasskeyError('cancelled', 'The passkey was not made. The request was cancelled or the device refused it.');
  }
  const response = credential.response;
  const spki = response.getPublicKey();
  if (!spki) throw new PasskeyError('unsupported-key', 'The device did not give the passkey\'s public key.');
  const key = await publicKeyToJwk(spki, response.getPublicKeyAlgorithm());
  return { credentialId: toBase64url(new Uint8Array(credential.rawId)), key, rpId: location.hostname, origin: location.origin };
}

// Ask the passkey to sign a challenge: the device asks the person first.
// Only where the caller asks for it ("choose"), and names no identifier (a
// passkey this browser has forgotten), the device offers every passkey it
// holds for the website and the person chooses; the answer then says which
// was chosen, and the caller must check it against the key it expects
// before it relies on it. Everywhere else a passkey with no identifier is
// refused, so that no caller is offered a choice it did not ask for.
async function signedBy(passkey, challenge, refused, { choose = false } = {}) {
  const container = credentials();
  if (!choose && (!passkey || typeof passkey.credentialId !== 'string' || !passkey.credentialId)) {
    throw new PasskeyError('cancelled', 'No passkey was named, so nothing was signed.');
  }
  let assertion;
  try {
    assertion = await container.get({
      publicKey: {
        challenge,
        rpId: passkey.rpId,
        ...(!choose ? { allowCredentials: [{ type: 'public-key', id: fromBase64url(passkey.credentialId) }] } : {}),
        userVerification: 'required',
      },
    });
  } catch (e) {
    throw new PasskeyError('cancelled', refused);
  }
  const r = assertion.response;
  return {
    authenticatorData: new Uint8Array(r.authenticatorData),
    clientDataJSON: new Uint8Array(r.clientDataJSON),
    signature: new Uint8Array(r.signature),
    credentialId: toBase64url(new Uint8Array(assertion.rawId)),
  };
}

/**
 * Sign a slip with a passkey made by createPasskey.
 *
 * @param {object} fields the slip's members except "type", "id" and "issuer"
 * @param {object} passkey what createPasskey returned
 * @param {string} issuerName the label to write as the issuer's name
 * @returns {Promise<object>} the signed slip record
 */
export async function signSlipWithPasskey(fields, passkey, issuerName) {
  credentials();
  const prepared = await prepareSlip({
    ...fields,
    issuer: { name: issuerName, key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
  });
  return assembleSlip(prepared, await signedBy(passkey, prepared.challenge, 'The slip was not signed. The request was cancelled or the device refused it.'));
}

/**
 * Approve one action with a passkey made by createPasskey: the person's own
 * yes, signed with the same passkey as the slip.
 *
 * @param {object} request what prepareApproval takes: the slip's fingerprint, the action, and where present the amount, the service, the documents and the time
 * @param {object} passkey what createPasskey returned
 * @returns {Promise<object>} the signed approval record
 */
export async function approveWithPasskey(request, passkey) {
  credentials();
  const prepared = await prepareApproval(request);
  return assembleApproval(prepared, await signedBy(passkey, prepared.challenge, 'The action was not approved. The request was cancelled or the device refused it.'));
}

/**
 * Cancel a slip with the passkey that signed it, made by createPasskey.
 * Keep a copy of what this returns, with its time-stamps: it counts even
 * where whoever keeps the book leaves it out.
 *
 * @param {object} request what prepareCancellation takes: the slip's fingerprint, and where present the time
 * @param {object} passkey what createPasskey returned
 * @returns {Promise<object>} the signed cancellation record
 */
export async function cancelWithPasskey(request, passkey) {
  credentials();
  const prepared = await prepareCancellation(request);
  return assembleCancellation(prepared, await signedBy(passkey, prepared.challenge, 'The slip was not cancelled. The request was cancelled or the device refused it.'));
}

/**
 * Sign the challenge of anything prepared for a passkey (prepareSlip with
 * covered fields, for one) with a passkey made by createPasskey. Hand what
 * this returns to the matching assemble function.
 *
 * @param {Uint8Array} challenge the "challenge" of what was prepared
 * @param {object} passkey what createPasskey returned
 * @returns {Promise<{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array}>}
 */
export async function signChallengeWithPasskey(challenge, passkey) {
  credentials();
  return signedBy(passkey, challenge, 'Nothing was signed. The request was cancelled or the device refused it.');
}

/**
 * Sign a challenge with a passkey the person chooses, where this browser
 * has forgotten which passkey it should ask (a passkey made on another
 * device, or this browser's storage cleared). The device offers every
 * passkey it holds for the website, and the person chooses one; nothing
 * new is made. What comes back names the passkey chosen by its identifier,
 * but not its public key: the caller must put the answer into the record
 * and check it with the library's checker against the key it expects, and
 * only then remember the identifier beside that key.
 *
 * @param {Uint8Array} challenge the "challenge" of what was prepared
 * @param {string} rpId the website the passkey belongs to (this page's hostname)
 * @returns {Promise<{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array, credentialId: string}>}
 */
export async function signChallengeWithChosenPasskey(challenge, rpId) {
  credentials();
  return signedBy({ rpId }, challenge, 'Nothing was signed. The request was cancelled, or this device holds no passkey for this website.', { choose: true });
}
