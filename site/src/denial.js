// The denial: the agent's own side states that it did not take an action
// that was asked for, and why. It is signed with the agent's two keys, or
// with the helper agent's under its pass. It is the agent's side's own
// word, and an agent can simply not write one.
// Format description, section 28.

import { formatTime, randomId } from './encoding.js';
import * as f from './fields.js';
import { KINDS } from './jws.js';
import { signWithKeySet, validateRequest } from './stub.js';

/** Who said no. */
export const DENIAL_SOURCES = {
  check: 'The check before acting (section 20) did not allow the action.',
  person: 'The person refused, or gave no approval when asked.',
  rule: 'A rule of the software around the agent, outside the slip.',
};

/**
 * The format's own list of finding codes: every code a checker or the check
 * before acting gives (format description, section 28; the same list is in
 * the list of threats, section 8). A denial whose source is "check" names
 * its reasons from this list.
 */
export const FINDING_CODES = Object.freeze([
  'not-json', 'bad-envelope', 'bad-base64url', 'too-large', 'unknown-type', 'bad-signatures-layout', 'payload-not-canonical',
  'payload-type-mismatch', 'bad-field', 'bad-key', 'signature-invalid', 'passkey-wrong-type', 'passkey-challenge-mismatch',
  'passkey-origin-mismatch', 'passkey-rpid-mismatch', 'passkey-user-not-present', 'passkey-user-not-verified', 'passkey-bad-data',
  'issuer-not-expected', 'slip-missing', 'slip-unusable', 'chain-broken', 'time-went-backwards', 'duplicate-id', 'duplicate-slip',
  'countersignature-invalid', 'countersignature-wrong-stub', 'countersignature-not-possible', 'line-not-canonical', 'unknown-entry',
  'approval-mismatch', 'approval-reused', 'approval-invalid', 'approval-not-found', 'approval-dated-after-stub', 'terms-not-found',
  'terms-unusable', 'terms-mismatch', 'pass-missing', 'pass-mismatch', 'pass-too-deep', 'cover-invalid', 'cancellation-invalid',
  'cancellation-not-found', 'acknowledgement-mismatch', 'vouching-missing', 'seal-mismatch', 'seal-chain-broken', 'sealer-not-expected', 'book-cut-short', 'seal-not-in-book', 'witness-invalid',
  'dated-after-stamp', 'stamp-bad-data', 'stamp-wrong-data', 'stamp-invalid', 'headers-invalid', 'record-not-sound', 'proof-invalid',
  'root-mismatch', 'check-failed', 'action-not-allowed', 'party-not-allowed', 'outside-valid-time', 'amount-missing', 'over-limit',
  'over-each-limit', 'over-count-limit', 'over-period-limit', 'countersignature-missing', 'approval-missing', 'prohibited',
  'pass-not-allowed', 'pass-wider', 'after-cancellation', 'outside-terms',
]);

/** The most finding codes one denial may name. */
export const MAX_DENIAL_CODES = 16;

/**
 * The reasons of a refusal by the check before acting, as a denial names
 * them: the codes of its problems, then of its findings, each once, in that
 * order, from the format's own list, at most 16. Where none is on the list,
 * "check-failed".
 * @param {{problems: {code: string}[], breaches: {code: string}[]}} answer the answer of the check before acting
 * @returns {string[]}
 */
export function denialCodes(answer) {
  const codes = [];
  for (const p of [...answer.problems, ...answer.breaches]) {
    if (p && typeof p.code === 'string' && FINDING_CODES.includes(p.code) && !codes.includes(p.code)) codes.push(p.code);
  }
  return codes.length ? codes.slice(0, MAX_DENIAL_CODES) : ['check-failed'];
}

/**
 * Confirm every member of a denial's content.
 * @param {any} c
 */
export function validateDenialContent(c) {
  f.members(c, ['action', 'id', 'slip', 'source', 'type', 'when'], ['amount', 'codes', 'details', 'pass', 'with'], 'denial');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  if (Object.hasOwn(c, 'pass')) f.fingerprintText(c.pass, 'pass');
  // What was asked for is written down as it was asked, as in a refusal: a
  // reserved name that is not on the shared list may be why it was refused.
  f.shortName(c.action, 'action');
  // The amount, the service and the documents as in a stub; the service
  // need not be one the slip names.
  validateRequest({ ...c, action: 'x' });
  if (typeof c.source !== 'string' || !Object.hasOwn(DENIAL_SOURCES, c.source)) throw f.fail('source', 'must be "check", "person" or "rule".');
  if (c.source === 'check') {
    if (!Object.hasOwn(c, 'codes')) throw f.fail('codes', 'is missing: a denial by the check before acting names its reasons.');
    f.list(c.codes, 1, MAX_DENIAL_CODES, 'codes');
    c.codes.forEach((code, i) => {
      if (typeof code !== 'string' || !FINDING_CODES.includes(code)) throw f.fail(`codes[${i}]`, 'must be a code from the format\'s own list of finding codes.');
    });
    if (new Set(c.codes).size !== c.codes.length) throw f.fail('codes', 'a code is repeated.');
  } else if (Object.hasOwn(c, 'codes')) {
    throw f.fail('codes', 'only a denial by the check before acting names codes.');
  }
  f.time(c.when, 'when');
}

/**
 * Write and sign a denial: the agent's side states that it did not take an
 * action that was asked for, and why. It is signed with the keys of the
 * agent the slip names or, where the signer is a helper agent, with the
 * keys the pass names.
 *
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip the agent acts under
 * @param {string} [fields.pass] for a helper agent: the fingerprint of the pass it acts under
 * @param {string} fields.action what was asked for
 * @param {{unit: string, value: number}} [fields.amount]
 * @param {string} [fields.with] the service asked for, as asked; it need not be one the slip names
 * @param {{name: string, sha256: string}[]} [fields.details] fingerprints of documents, never the documents
 * @param {'check'|'person'|'rule'} fields.source who said no
 * @param {string[]} [fields.codes] where the source is "check": 1 to 16 finding codes, from FINDING_CODES
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the agent's private keys, or signers: Ed25519, then ML-DSA-87
 * @returns {Promise<{record: object, fingerprint: string}>}
 */
export async function writeDenial(fields, privateKeys) {
  const content = {
    type: KINDS.denial.type,
    id: fields.id ?? randomId(),
    slip: fields.slip,
    action: fields.action,
    source: fields.source,
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.pass) content.pass = fields.pass;
  if (fields.amount) content.amount = fields.amount;
  if (fields.with) content.with = fields.with;
  if (fields.details && fields.details.length) content.details = fields.details;
  if (fields.codes !== undefined && fields.codes !== null) content.codes = fields.codes;
  validateDenialContent(content);
  return signWithKeySet('denial', content, privateKeys);
}
