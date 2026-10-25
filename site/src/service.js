// The other side's voice: two records a service writes and signs itself.
// A refusal says "this agent asked for something, and we refused". Terms
// say which actions the service accepts from agents.
// Format description, sections 18 and 19.

import { actionKind, isNeverName } from './actions.js';
import { formatTime, randomId } from './encoding.js';
import * as f from './fields.js';
import { KINDS } from './jws.js';
import { checkKeySet } from './keys.js';
import { signWithKeySet, validateRequest } from './stub.js';

/** Why a service refused. A refusal gives exactly one of these. */
export const REFUSAL_REASONS = {
  'not-in-slip': 'The slip does not cover the action, or does not name this service.',
  'over-limit': 'The action would pass a limit of the slip.',
  'outside-valid-time': 'The slip was not in force at that time.',
  'slip-not-sound': 'The slip did not pass its check.',
  'needs-approval': 'The slip asks for the person\'s approval, and none was shown.',
  'against-terms': 'The service\'s terms for agents do not accept the action.',
  other: 'Another reason.',
};

function validateBy(by) {
  f.members(by, ['keys', 'name'], [], 'by');
  f.label(by.name, 'by.name');
  checkKeySet(by.keys, 'by.keys');
}

/**
 * Confirm every member of a refusal's content.
 * @param {any} c
 */
export function validateRefusalContent(c) {
  f.members(c, ['action', 'by', 'id', 'reason', 'slip', 'type', 'when'], ['amount'], 'refusal');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  validateBy(c.by);
  // What was asked for is written down as it was asked, even a reserved
  // name that is not on the shared list: that may be why it was refused.
  f.shortName(c.action, 'action');
  if (Object.hasOwn(c, 'amount')) validateRequest({ action: 'x', amount: c.amount });
  if (typeof c.reason !== 'string' || !Object.hasOwn(REFUSAL_REASONS, c.reason)) throw f.fail('reason', 'must be one of the listed reasons.');
  f.time(c.when, 'when');
}

/**
 * Confirm every member of a service's terms for agents.
 * @param {any} c
 */
export function validateTermsContent(c) {
  f.members(c, ['accepts', 'by', 'id', 'never', 'type', 'validFrom', 'validUntil'], [], 'terms');
  f.id(c.id, 'id');
  validateBy(c.by);
  f.list(c.accepts, 1, 64, 'accepts');
  c.accepts.forEach((a, i) => f.actionName(a, `accepts[${i}]`));
  if (new Set(c.accepts).size !== c.accepts.length) throw f.fail('accepts', 'an action name is repeated.');
  f.list(c.never, 0, 16, 'never');
  c.never.forEach((n, i) => {
    if (!isNeverName(n)) throw f.fail(`never[${i}]`, 'must be a listed kind of action or a listed rule of conduct.');
  });
  if (new Set(c.never).size !== c.never.length) throw f.fail('never', 'a name is repeated.');
  for (const a of c.accepts) {
    if (c.never.includes(actionKind(a))) throw f.fail('never', 'forbids a kind of action that the terms also accept.');
  }
  const from = f.time(c.validFrom, 'validFrom');
  const until = f.time(c.validUntil, 'validUntil');
  if (!(from < until)) throw f.fail('validUntil', 'must be later than validFrom.');
}

/**
 * Write and sign a refusal: the service's statement that an agent asked for
 * something under a slip, and was refused.
 *
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip the agent showed
 * @param {{keys: object[], name: string}} fields.by the service's public key set and its name (a label)
 * @param {string} fields.action what the agent asked for
 * @param {{unit: string, value: number}} [fields.amount]
 * @param {string} fields.reason one of REFUSAL_REASONS
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the service's private keys, or signers: Ed25519, then ML-DSA-87. A signer must hold the keys "by" names
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeRefusal(fields, privateKeys) {
  const content = {
    type: KINDS.refusal.type,
    id: fields.id ?? randomId(),
    slip: fields.slip,
    by: fields.by,
    action: fields.action,
    reason: fields.reason,
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.amount) content.amount = fields.amount;
  validateRefusalContent(content);
  return signWithKeySet('refusal', content, privateKeys, content.by.keys);
}

/**
 * Write and sign a service's terms for agents.
 *
 * @param {object} fields
 * @param {{keys: object[], name: string}} fields.by the service's public key set and its name (a label)
 * @param {string[]} fields.accepts the actions the service accepts from agents
 * @param {string[]} [fields.never] kinds of action and rules of conduct the service asks agents to keep
 * @param {string} fields.validFrom
 * @param {string} fields.validUntil
 * @param {any[]} privateKeys the service's private keys, or signers: Ed25519, then ML-DSA-87. A signer must hold the keys "by" names
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeTerms(fields, privateKeys) {
  const content = {
    type: KINDS.terms.type,
    id: fields.id ?? randomId(),
    by: fields.by,
    accepts: fields.accepts,
    never: fields.never ?? [],
    validFrom: fields.validFrom,
    validUntil: fields.validUntil,
  };
  validateTermsContent(content);
  return signWithKeySet('terms', content, privateKeys, content.by.keys);
}
