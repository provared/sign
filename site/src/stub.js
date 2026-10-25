// The Stub (the receipt for one action) and the countersignature.
// Format description, sections 5 and 6.

import { DOCUMENT_NAMES, REPEATABLE_DOCUMENT_NAMES, isUnknownReservedDocument } from './documents.js';
import { fingerprint, formatTime, randomId, toBase64url } from './encoding.js';
import * as f from './fields.js';
import { encodeContent, parseRecord, protectedHeaders, signingInput, withinSize, KINDS } from './jws.js';
import { KEY_SET_METHODS } from './keys.js';
import { signingKeys } from './signatures.js';

/**
 * Confirm every member of a stub's content (format description, section 5.1).
 * @param {any} c
 */
export function validateStubContent(c) {
  f.members(c, ['action', 'id', 'seq', 'slip', 'type', 'when'], ['amount', 'approval', 'details', 'pass', 'previous', 'terms', 'with'], 'stub');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  f.wholeNumber(c.seq, 'seq');
  if (c.seq === 0) {
    if (Object.hasOwn(c, 'previous')) throw f.fail('previous', 'the first stub under a slip names no stub before it.');
  } else {
    if (!Object.hasOwn(c, 'previous')) throw f.fail('previous', 'is missing.');
    f.fingerprintText(c.previous, 'previous');
  }
  validateRequest(c);
  if (Object.hasOwn(c, 'approval')) f.fingerprintText(c.approval, 'approval');
  if (Object.hasOwn(c, 'pass')) f.fingerprintText(c.pass, 'pass');
  if (Object.hasOwn(c, 'terms')) {
    f.fingerprintText(c.terms, 'terms');
    if (!Object.hasOwn(c, 'with')) throw f.fail('terms', 'a stub that relies on the terms of a service must name the service.');
  }
  f.time(c.when, 'when');
}

/**
 * Confirm the members that say what was done, or what is asked for: the
 * action, and where present the amount, the service and the documents. A
 * stub, an approval and a refusal share them.
 * @param {any} c
 */
export function validateRequest(c) {
  f.actionName(c.action, 'action');
  if (Object.hasOwn(c, 'amount')) {
    f.members(c.amount, ['unit', 'value'], [], 'amount');
    f.unit(c.amount.unit, 'amount.unit');
    f.wholeNumber(c.amount.value, 'amount.value');
  }
  if (Object.hasOwn(c, 'with')) f.shortName(c.with, 'with');
  if (Object.hasOwn(c, 'details')) {
    f.list(c.details, 1, 32, 'details');
    const once = new Set();
    c.details.forEach((d, i) => {
      f.members(d, ['name', 'sha256'], [], `details[${i}]`);
      f.label(d.name, `details[${i}].name`);
      if (isUnknownReservedDocument(d.name)) throw f.fail(`details[${i}].name`, 'names that begin "provared." are reserved, and this one is not on the list of document names.');
      if (Object.hasOwn(DOCUMENT_NAMES, d.name) && !REPEATABLE_DOCUMENT_NAMES.includes(d.name)) {
        if (once.has(d.name)) {
          throw f.fail(`details[${i}].name`, 'this reserved name is named twice. Only provared.trace-id, provared.request-id and provared.event-id may be named more than once.');
        }
        once.add(d.name);
      }
      f.fingerprintText(d.sha256, `details[${i}].sha256`);
    });
  }
}

/**
 * Confirm every member of a countersignature's content (format description,
 * section 6).
 * @param {any} c
 */
export function validateCountersignatureContent(c) {
  f.members(c, ['stub', 'type', 'when'], [], 'countersignature');
  f.fingerprintText(c.stub, 'stub');
  f.time(c.when, 'when');
}

// --- writing ---

// Sign content with a key set: two signatures side by side, Ed25519 then
// ML-DSA-87, each over its own signing input (format description, 3.9).
// Each item of "privateKeys" is a key or a signer (signatures.js);
// "expected" is the key set the record must be signed with, where the
// writer knows it, and a signer that holds another key is refused.
export async function signWithKeySet(kind, content, privateKeys, expected) {
  const { contentBytes, payloadB64 } = encodeContent(content);
  const headers = protectedHeaders(kind);
  const signers = await signingKeys(privateKeys, KEY_SET_METHODS, expected);
  const signatures = [];
  for (let i = 0; i < KEY_SET_METHODS.length; i++) {
    const signature = await signers[i](signingInput(headers[i], payloadB64));
    signatures.push({ protected: headers[i], signature: toBase64url(signature) });
  }
  return { record: withinSize({ payload: payloadB64, signatures }), fingerprint: await fingerprint(contentBytes) };
}

/**
 * Write and sign a stub.
 *
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip relied on
 * @param {{seq: number, fingerprint: string}|null} fields.after the stub before this one under the same slip, or null for the first
 * @param {string} fields.action
 * @param {{unit: string, value: number}} [fields.amount]
 * @param {string} [fields.with] the id of the service, as the slip names it
 * @param {{name: string, sha256: string}[]} [fields.details] fingerprints of documents, never the documents
 * @param {string} [fields.approval] the fingerprint of the person's approval of this one action
 * @param {string} [fields.terms] the fingerprint of the service's terms for agents that the agent relied on
 * @param {string} [fields.pass] for a helper agent: the fingerprint of the pass it acts under; "after" is then the stub before it under that pass
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the agent's private keys, or signers (signatures.js): Ed25519, then ML-DSA-87
 * @returns {Promise<{record: object, fingerprint: string, seq: number}>}
 */
export async function writeStub(fields, privateKeys) {
  const seq = fields.after ? fields.after.seq + 1 : 0;
  const content = {
    type: KINDS.stub.type,
    id: fields.id ?? randomId(),
    slip: fields.slip,
    seq,
    action: fields.action,
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.after) content.previous = fields.after.fingerprint;
  if (fields.amount) content.amount = fields.amount;
  if (fields.with) content.with = fields.with;
  if (fields.details && fields.details.length) content.details = fields.details;
  if (fields.approval) content.approval = fields.approval;
  if (fields.terms) content.terms = fields.terms;
  if (fields.pass) content.pass = fields.pass;
  validateStubContent(content);
  const signed = await signWithKeySet('stub', content, privateKeys);
  return { ...signed, seq };
}

/**
 * Countersign a stub: the service's statement "this happened with me".
 *
 * The service should check the stub before it signs. This function only
 * reads the stub's fingerprint; it does not judge the stub.
 *
 * @param {object} stubRecord the stub as the agent sent it
 * @param {any[]} privateKeys the service's private keys, or signers: Ed25519, then ML-DSA-87
 * @param {number|Date} [when] defaults to now
 * @returns {Promise<object>} the countersignature record
 */
export async function countersign(stubRecord, privateKeys, when) {
  const stub = await parseRecord(stubRecord, 'stub');
  const content = { type: KINDS.countersignature.type, stub: stub.fingerprint, when: formatTime(when ?? Date.now()) };
  validateCountersignatureContent(content);
  return (await signWithKeySet('countersignature', content, privateKeys)).record;
}
