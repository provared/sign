// Checking a passkey signature (a Web Authentication assertion), later and
// offline. The steps are those of W3C Web Authentication Level 3, section
// 7.2 ("Verifying an Authentication Assertion"), as far as they apply
// without a server session: format description, section 4.4.

import { Refusal, concatBytes, equalBytes, fromUtf8, sha256, toBase64url, utf8 } from './encoding.js';
import { verifySignature } from './signatures.js';

// The flags byte of the authenticator data (Web Authentication, section 6.1).
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_DATA = 0x40;
const FLAG_EXTENSION_DATA = 0x80;

function badData(why) {
  return new Refusal('passkey-bad-data', why);
}

/**
 * A passkey returns an ES256 signature in ASN.1 DER form (Web
 * Authentication, section 6.5.5). Web Crypto checks the two numbers side by
 * side, 32 bytes each. This converts one into the other and refuses any DER
 * that is not strictly encoded.
 * @param {Uint8Array} der
 * @returns {Uint8Array} 64 bytes
 */
export function ecdsaDerToRaw(der) {
  // SEQUENCE, short-form length (two 33-byte INTEGERs at most: 70 bytes).
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) {
    throw badData('The passkey signature is not a well-formed ECDSA signature.');
  }
  const out = new Uint8Array(64);
  let at = 2;
  for (let part = 0; part < 2; part++) {
    if (at + 2 > der.length || der[at] !== 0x02) throw badData('The passkey signature is not a well-formed ECDSA signature.');
    const length = der[at + 1];
    const start = at + 2;
    const end = start + length;
    if (length < 1 || length > 33 || end > der.length) throw badData('The passkey signature is not a well-formed ECDSA signature.');
    // A positive whole number in its shortest form.
    if (der[start] & 0x80) throw badData('The passkey signature holds a negative number.');
    if (length > 1 && der[start] === 0x00 && !(der[start + 1] & 0x80)) {
      throw badData('The passkey signature is not in its shortest form.');
    }
    const digits = der[start] === 0x00 ? der.subarray(start + 1, end) : der.subarray(start, end);
    if (digits.length > 32) throw badData('The passkey signature holds a number that is too large.');
    out.set(digits, part * 32 + (32 - digits.length));
    at = end;
  }
  if (at !== der.length) throw badData('The passkey signature has bytes left over.');
  return out;
}

/**
 * Check a passkey signature over some bytes.
 *
 * @param {object} a
 * @param {any} a.key the passkey's public key, already passed by checkKey
 * @param {string} a.rpId the website the passkey belongs to
 * @param {string} a.origin the address of the page it was used on
 * @param {Uint8Array} a.signedBytes the bytes the signature must cover; the challenge is their SHA-256 hash
 * @param {Uint8Array} a.authenticatorData as the passkey returned it
 * @param {Uint8Array} a.clientDataJSON as the passkey returned it
 * @param {Uint8Array} a.signature as the passkey returned it
 * @param {string[]} [without] see verifySignature
 * @returns {Promise<'valid'|'unavailable'>} "unavailable" when this device cannot check the passkey's signing method
 * @throws {Refusal} with a code that says which check failed
 */
export async function checkAssertion({ key, rpId, origin, signedBytes, authenticatorData, clientDataJSON, signature }, without = []) {
  let client;
  try {
    client = JSON.parse(fromUtf8(clientDataJSON, 'passkey-bad-data'));
  } catch {
    throw badData('The passkey\'s client data is not JSON.');
  }
  if (client === null || typeof client !== 'object' || Array.isArray(client)) throw badData('The passkey\'s client data is not an object.');

  // This must be an answer to "sign", not to "create a passkey".
  if (client.type !== 'webauthn.get') {
    throw new Refusal('passkey-wrong-type', 'The passkey answer was not made for signing.');
  }
  // The challenge is the hash of the bytes that had to be signed.
  const challenge = toBase64url(await sha256(signedBytes));
  if (client.challenge !== challenge) {
    throw new Refusal('passkey-challenge-mismatch', 'The passkey signed something other than this slip.');
  }
  // The page it was used on.
  if (client.origin !== origin || client.crossOrigin === true) {
    throw new Refusal('passkey-origin-mismatch', 'The passkey was used on a page other than the one the slip names.');
  }

  // The authenticator data: which website, and the two flags.
  if (authenticatorData.length < 37) throw badData('The passkey\'s authenticator data is cut short.');
  const rpIdHash = await sha256(utf8(rpId));
  if (!equalBytes(authenticatorData.subarray(0, 32), rpIdHash)) {
    throw new Refusal('passkey-rpid-mismatch', 'The passkey belongs to a website other than the one the slip names.');
  }
  const flags = authenticatorData[32];
  if (!(flags & FLAG_USER_PRESENT)) {
    throw new Refusal('passkey-user-not-present', 'The passkey did not record that a person was present.');
  }
  if (!(flags & FLAG_USER_VERIFIED)) {
    throw new Refusal('passkey-user-not-verified', 'The device did not confirm the person by fingerprint, face or PIN.');
  }
  // An answer to "sign" never carries a new passkey's data, and carries
  // further bytes only when it says so.
  if (flags & FLAG_ATTESTED_DATA) throw badData('The passkey\'s authenticator data holds data that belongs to creating a passkey.');
  if (!(flags & FLAG_EXTENSION_DATA) && authenticatorData.length !== 37) {
    throw badData('The passkey\'s authenticator data has bytes left over.');
  }

  // The signature covers the authenticator data followed by
  // the hash of the client data.
  const signed = concatBytes(authenticatorData, await sha256(clientDataJSON));
  const raw = key.alg === 'ES256' ? ecdsaDerToRaw(signature) : signature;
  const state = await verifySignature(key, raw, signed, without);
  if (state === 'invalid') throw new Refusal('signature-invalid', 'The passkey signature does not fit the key the slip names.');
  return state;
}
