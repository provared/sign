// Records that begin or end someone's standing:
//   - a cancellation: the person ends a slip early, with their passkey;
//   - an acknowledgement: the agent's side states that it was handed a
//     cancellation;
//   - a vouching record: an organisation states whose key a key is;
//   - a withdrawal: the organisation ends a vouching record.
// Format description, sections 22, 23 and 26.

import { fingerprint, formatTime, randomId } from './encoding.js';
import * as f from './fields.js';
import { KINDS } from './jws.js';
import { PASSKEY_METHODS, checkKey, checkKeySet, checkSealKeySet } from './keys.js';
import { assembleSlip, preparePasskeyRecord } from './slip.js';
import { signWithKeySet } from './stub.js';

/** What a vouching record can vouch for, and the keys each kind has. */
export const VOUCHED_KINDS = {
  person: 'A person, known by the public key of their passkey.',
  agent: 'An agent, known by its two keys.',
  service: 'A service, known by its two keys.',
  recorder: 'A recorder, known by its three keys.',
};

/**
 * Confirm every member of a cancellation's content.
 * @param {any} c
 */
export function validateCancellationContent(c) {
  f.members(c, ['id', 'slip', 'type', 'when'], [], 'cancellation');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  f.time(c.when, 'when');
}

/**
 * Confirm every member of an acknowledgement's content.
 * @param {any} c
 */
export function validateAcknowledgementContent(c) {
  f.members(c, ['cancellation', 'id', 'slip', 'type', 'when'], ['pass'], 'acknowledgement');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  f.fingerprintText(c.cancellation, 'cancellation');
  if (Object.hasOwn(c, 'pass')) f.fingerprintText(c.pass, 'pass');
  f.time(c.when, 'when');
}

/**
 * Confirm every member of a vouching record's content.
 * @param {any} c
 */
export function validateVouchingContent(c) {
  f.members(c, ['by', 'for', 'id', 'type', 'validFrom', 'validUntil', 'when'], [], 'vouching');
  f.id(c.id, 'id');
  f.members(c.by, ['keys', 'name'], [], 'by');
  f.label(c.by.name, 'by.name');
  checkKeySet(c.by.keys, 'by.keys');
  const who = c.for;
  if (who === null || typeof who !== 'object' || typeof who.kind !== 'string' || !Object.hasOwn(VOUCHED_KINDS, who.kind)) {
    throw f.fail('for.kind', 'must be "person", "agent", "service" or "recorder".');
  }
  if (who.kind === 'person') {
    f.members(who, ['key', 'kind', 'name'], [], 'for');
    checkKey(who.key, PASSKEY_METHODS, 'for.key');
  } else {
    f.members(who, ['keys', 'kind', 'name'], [], 'for');
    if (who.kind === 'recorder') checkSealKeySet(who.keys, 'for.keys');
    else checkKeySet(who.keys, 'for.keys');
  }
  f.label(who.name, 'for.name');
  const from = f.time(c.validFrom, 'validFrom');
  const until = f.time(c.validUntil, 'validUntil');
  if (!(from < until)) throw f.fail('validUntil', 'must be later than validFrom.');
  f.time(c.when, 'when');
}

/**
 * Confirm every member of a withdrawal's content.
 * @param {any} c
 */
export function validateWithdrawalContent(c) {
  f.members(c, ['id', 'type', 'vouching', 'when'], [], 'withdrawal');
  f.id(c.id, 'id');
  f.fingerprintText(c.vouching, 'vouching');
  f.time(c.when, 'when');
}

/**
 * Build the content of a cancellation and the challenge the person's
 * passkey must sign.
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip to cancel
 * @param {number|Date} [fields.when] defaults to now
 * @returns {Promise<{payloadB64: string, protectedB64: string, challenge: Uint8Array, fingerprint: string}>}
 */
export async function prepareCancellation(fields) {
  const content = { type: KINDS.cancellation.type, id: fields.id ?? randomId(), slip: fields.slip, when: formatTime(fields.when ?? Date.now()) };
  validateCancellationContent(content);
  const prepared = await preparePasskeyRecord('cancellation', content);
  return { ...prepared, fingerprint: await fingerprint(prepared.contentBytes) };
}

/**
 * Put the passkey's three values with the prepared content: the signed
 * cancellation.
 * @param {{payloadB64: string, protectedB64: string}} prepared from prepareCancellation
 * @param {{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array}} assertion
 * @returns {object} the cancellation record
 */
export function assembleCancellation(prepared, assertion) {
  return assembleSlip(prepared, assertion);
}

/**
 * Write and sign an acknowledgement: the statement of the agent's side
 * that it was handed the person's cancellation of a slip, and when. It is
 * signed with the keys of the agent the slip names or, where the signer is
 * a helper agent, with the keys the pass names.
 *
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip that was cancelled
 * @param {string} fields.cancellation the fingerprint of the cancellation
 * @param {string} [fields.pass] for a helper agent: the fingerprint of the pass it acts under
 * @param {number|Date} [fields.when] when the cancellation was handed over; defaults to now
 * @param {any[]} privateKeys the agent's private keys, or signers: Ed25519, then ML-DSA-87
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeAcknowledgement(fields, privateKeys) {
  const content = {
    type: KINDS.acknowledgement.type,
    id: fields.id ?? randomId(),
    slip: fields.slip,
    cancellation: fields.cancellation,
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.pass) content.pass = fields.pass;
  validateAcknowledgementContent(content);
  return signWithKeySet('acknowledgement', content, privateKeys);
}

/**
 * Write and sign a vouching record: an organisation's statement that a key
 * belongs to a name.
 *
 * @param {object} fields
 * @param {{keys: object[], name: string}} fields.by the organisation's public key set and its name (a label)
 * @param {{kind: string, name: string, key?: object, keys?: object[]}} fields.for whom it vouches for
 * @param {string} fields.validFrom
 * @param {string} fields.validUntil
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the organisation's private keys, or signers: Ed25519, then ML-DSA-87. A signer must hold the keys "by" names
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeVouching(fields, privateKeys) {
  const content = {
    type: KINDS.vouching.type,
    id: fields.id ?? randomId(),
    by: fields.by,
    for: fields.for,
    validFrom: fields.validFrom,
    validUntil: fields.validUntil,
    when: formatTime(fields.when ?? Date.now()),
  };
  validateVouchingContent(content);
  return signWithKeySet('vouching', content, privateKeys, content.by.keys);
}

/**
 * Write and sign a withdrawal: the organisation ends a vouching record.
 *
 * @param {object} fields
 * @param {string} fields.vouching the fingerprint of the vouching record
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the private keys of the organisation that made the vouching record, or signers
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeWithdrawal(fields, privateKeys) {
  const content = { type: KINDS.withdrawal.type, id: fields.id ?? randomId(), vouching: fields.vouching, when: formatTime(fields.when ?? Date.now()) };
  validateWithdrawalContent(content);
  return signWithKeySet('withdrawal', content, privateKeys);
}
