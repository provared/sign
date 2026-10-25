// A development stand-in for a passkey, and a stub writer opened under a
// slip it signed: for trying the library in an evening, and for tests.
//
// It is NOT a passkey. Its private key is an ordinary key made in this
// process's memory, and no person confirmed anything. It returns the same
// three values a passkey returns (the authenticator data, the client data,
// the signature), in the forms the W3C Web Authentication standard sets
// out, so that every record it signs passes the checker exactly as a real
// one would. To keep such a record from being mistaken for a person's, the
// name of the issuer in every slip it signs ends with " (development)",
// and the checker prints that name beside the slip.
//
// A real slip is signed by the person, in a browser, with a real passkey:
// see passkey-browser.js and the checking page. Nothing in this file is
// part of the library's checker, and nothing here reaches the network.

import { concatBytes, fingerprint, formatTime, fromBase64url, sha256, toBase64url, utf8 } from './encoding.js';
import { thumbprint } from './keys.js';
import { openRecorder } from './recorder.js';
import { generateKeySet } from './signatures.js';
import { assembleSlip, prepareSlip } from './slip.js';
import { writeBook } from './book.js';

const subtle = globalThis.crypto.subtle;

/** The words every development slip carries in its issuer's name. */
export const DEVELOPMENT_MARK = '(development)';

// Two numbers of 32 bytes each, side by side, to the ASN.1 DER form a
// passkey returns for an ECDSA signature.
function ecdsaRawToDer(raw) {
  const part = (bytes) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let digits = bytes.subarray(start);
    if (digits[0] & 0x80) digits = concatBytes(new Uint8Array([0]), digits);
    return concatBytes(new Uint8Array([0x02, digits.length]), digits);
  };
  const body = concatBytes(part(raw.subarray(0, 32)), part(raw.subarray(32)));
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

/**
 * A development stand-in for a passkey (ES256, the method most passkeys
 * use). It signs on this computer, for the page address http://localhost,
 * which the format allows for development only.
 *
 * @returns {Promise<{key: object, rpId: string, origin: string, sign: (challenge: Uint8Array) => Promise<{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array}>}>}
 */
export async function developmentPasskey() {
  const rpId = 'localhost';
  const origin = 'http://localhost';
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const j = await subtle.exportKey('jwk', pair.publicKey);
  const key = { alg: 'ES256', crv: 'P-256', kty: 'EC', x: j.x, y: j.y };
  return {
    key,
    rpId,
    origin,
    async sign(challenge) {
      const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.get', challenge: toBase64url(challenge), origin, crossOrigin: false }));
      // Flags 0x05: "user present" and "user verified". Nobody was: this is a stand-in.
      const authenticatorData = concatBytes(await sha256(utf8(rpId)), new Uint8Array([0x05, 0, 0, 0, 1]));
      const signed = concatBytes(authenticatorData, await sha256(clientDataJSON));
      const signature = ecdsaRawToDer(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed)));
      return { authenticatorData, clientDataJSON, signature };
    },
  };
}

// The issuer's name always ends with the development mark, whatever name is given.
function markedName(name) {
  const given = typeof name === 'string' && name.trim() ? name.trim() : 'Development passkey';
  return given.endsWith(DEVELOPMENT_MARK) ? given : `${given} ${DEVELOPMENT_MARK}`;
}

/**
 * A slip signed with a development stand-in for a passkey, and new keys for
 * the agent. Give the slip's actions, limits, conditions and the rest as for
 * prepareSlip; "issuer" and "agent.keys" are filled in, and the issuer's
 * name is made to end with " (development)". By default the slip runs from
 * a minute ago for one day, and its purpose says that it is for development.
 *
 * @param {object} fields the members of the slip; "actions" is required
 * @returns {Promise<{slip: object, slipFingerprint: string, book: string, issuerKeys: string[], agent: {keys: object[], privateKeys: CryptoKey[]}, passkey: object}>}
 */
export async function developmentSlip(fields = {}) {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new TypeError('developmentSlip: give the members of the slip as an object, with at least "actions".');
  const passkey = await developmentPasskey();
  const agent = await generateKeySet();
  const now = Date.now();
  const issuer = fields.issuer && typeof fields.issuer === 'object' ? fields.issuer : {};
  const agentGiven = fields.agent && typeof fields.agent === 'object' ? fields.agent : {};
  const prepared = await prepareSlip({
    validFrom: formatTime(now - 60 * 1000),
    validUntil: formatTime(now + 24 * 3600 * 1000),
    purpose: 'For development: a record made with a stand-in for a passkey, which no person signed.',
    limits: [],
    with: [],
    ...fields,
    issuer: { name: markedName(issuer.name), key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: typeof agentGiven.name === 'string' ? agentGiven.name : 'Development agent', ...agentGiven, keys: agent.keys },
  });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
  const slipFingerprint = await fingerprint(fromBase64url(slip.payload));
  return { slip, slipFingerprint, book: writeBook([{ slip }]), issuerKeys: [await thumbprint(passkey.key)], agent, passkey };
}

/**
 * The stub writer, opened under a development slip, in one call: the
 * shortest way to a first record. The same as developmentSlip followed by
 * openRecorder; "more" is passed to openRecorder (options, now,
 * countersignWithin, signWithin, denials, denialsPerHour).
 *
 * @param {object} fields the members of the slip; "actions" is required
 * @param {object} [more]
 * @returns {Promise<{recorder: object, slip: object, slipFingerprint: string, issuerKeys: string[], agent: {keys: object[], privateKeys: CryptoKey[]}, passkey: object}>}
 */
export async function developmentRecorder(fields = {}, more = {}) {
  const made = await developmentSlip(fields);
  const recorder = await openRecorder({ book: made.book, slip: made.slipFingerprint, privateKeys: made.agent.privateKeys, issuerKeys: made.issuerKeys, ...more });
  return { recorder, slip: made.slip, slipFingerprint: made.slipFingerprint, issuerKeys: made.issuerKeys, agent: made.agent, passkey: made.passkey };
}
