// Passing a slip on: an agent hands part of its permission to a helper
// agent. Format description, section 25.

import { formatTime, randomId } from './encoding.js';
import * as f from './fields.js';
import { KINDS } from './jws.js';
import { checkKeySet } from './keys.js';
import { validateLimits } from './slip.js';
import { signWithKeySet } from './stub.js';

/** The most times a slip may let its permission be passed on. */
export const MAX_PASSES = 10;

/**
 * Confirm every member of a pass's content.
 * @param {any} c
 */
export function validatePassContent(c) {
  f.members(c, ['actions', 'id', 'limits', 'slip', 'to', 'type', 'validFrom', 'validUntil', 'when'], ['from'], 'pass');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  if (Object.hasOwn(c, 'from')) f.fingerprintText(c.from, 'from');
  f.members(c.to, ['keys', 'name'], [], 'to');
  f.label(c.to.name, 'to.name');
  checkKeySet(c.to.keys, 'to.keys');
  f.list(c.actions, 1, 64, 'actions');
  c.actions.forEach((a, i) => f.actionName(a, `actions[${i}]`));
  if (new Set(c.actions).size !== c.actions.length) throw f.fail('actions', 'an action name is repeated.');
  validateLimits(c.actions, c.limits);
  const from = f.time(c.validFrom, 'validFrom');
  const until = f.time(c.validUntil, 'validUntil');
  if (!(from < until)) throw f.fail('validUntil', 'must be later than validFrom.');
  f.time(c.when, 'when');
}

/**
 * Write and sign a pass: the agent that holds a permission hands part of it
 * to a helper agent.
 *
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip
 * @param {string} [fields.from] the fingerprint of the pass the signer itself acts under; absent when the signer is the slip's own agent
 * @param {{keys: object[], name: string}} fields.to the helper agent's public key set and its name (a label)
 * @param {string[]} fields.actions what the helper may do: no more than the signer may
 * @param {object[]} [fields.limits] limits for the helper, in the form a slip uses
 * @param {string} fields.validFrom
 * @param {string} fields.validUntil
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the private keys of the agent that passes on, or signers: Ed25519, then ML-DSA-87
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writePass(fields, privateKeys) {
  const content = {
    type: KINDS.pass.type,
    id: fields.id ?? randomId(),
    slip: fields.slip,
    to: fields.to,
    actions: fields.actions,
    limits: fields.limits ?? [],
    validFrom: fields.validFrom,
    validUntil: fields.validUntil,
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.from) content.from = fields.from;
  validatePassContent(content);
  return signWithKeySet('pass', content, privateKeys);
}
