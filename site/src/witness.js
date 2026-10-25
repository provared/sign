// The witness statement: a party with a key set of its own (a witness)
// states that it saw a seal, that the seal extends every earlier seal of
// the same book it signed for, and that it will sign for no seal of that
// book that does not extend this one. It is signed with the witness's two
// keys. A statement sits beside its seal in the seal's book entry, as
// time-stamps do, or is handed to a checker beside a seal held elsewhere.
// Format description, section 29.

import { formatTime, randomId } from './encoding.js';
import * as f from './fields.js';
import { KINDS } from './jws.js';
import { checkKeySet } from './keys.js';
import { signWithKeySet } from './stub.js';

/** The most witness statements one seal entry may hold, or that may be handed over with one seal. */
export const MAX_WITNESSES = 4;

/**
 * Confirm every member of a witness statement's content.
 * @param {any} c
 */
export function validateWitnessContent(c) {
  f.members(c, ['by', 'id', 'root', 'seal', 'size', 'type', 'when'], [], 'witness');
  f.id(c.id, 'id');
  f.fingerprintText(c.seal, 'seal');
  f.wholeNumber(c.size, 'size');
  if (c.size < 1) throw f.fail('size', 'must be 1 or more.');
  f.fingerprintText(c.root, 'root');
  f.members(c.by, ['keys', 'name'], [], 'by');
  f.label(c.by.name, 'by.name');
  checkKeySet(c.by.keys, 'by.keys');
  f.time(c.when, 'when');
}

/**
 * Write and sign a witness statement for a seal. This function only writes
 * the statement: it does not check the seal. A witness should sign only as
 * the format description, section 29.3, sets out; openWitness
 * (witnessing.js) does.
 *
 * @param {object} fields
 * @param {string} fields.seal the seal's fingerprint
 * @param {number} fields.size the seal's "size", repeated
 * @param {string} fields.root the seal's "root", repeated
 * @param {{keys: object[], name: string}} fields.by the witness's public key set and its name (a label)
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the witness's private keys, or signers (signatures.js): Ed25519, then ML-DSA-87. A
 *   signer must hold the key "by" names in its place
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeWitness(fields, privateKeys) {
  const content = {
    type: KINDS.witness.type,
    id: fields.id ?? randomId(),
    seal: fields.seal,
    size: fields.size,
    root: fields.root,
    by: fields.by,
    when: formatTime(fields.when ?? Date.now()),
  };
  validateWitnessContent(content);
  return signWithKeySet('witness', content, privateKeys, content.by.keys);
}
