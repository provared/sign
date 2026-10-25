// The approval: the person's own yes to one action, signed with the same
// passkey as the slip. Format description, section 17.

import { canonicalJson, fingerprint, formatTime, randomId } from './encoding.js';
import * as f from './fields.js';
import { KINDS } from './jws.js';
import { assembleSlip, preparePasskeyRecord } from './slip.js';
import { validateRequest } from './stub.js';

/**
 * Confirm every member of an approval's content.
 * @param {any} c
 */
export function validateApprovalContent(c) {
  f.members(c, ['action', 'id', 'slip', 'type', 'when'], ['amount', 'details', 'with'], 'approval');
  f.id(c.id, 'id');
  f.fingerprintText(c.slip, 'slip');
  validateRequest(c);
  f.time(c.when, 'when');
}

/**
 * What an approval and a stub must agree on: the action, and the amount, the
 * service and the documents, each present in both or in neither.
 * @param {any} c the content of an approval or of a stub
 * @returns {string}
 */
export function requestOf(c) {
  const request = { action: c.action };
  for (const name of ['amount', 'details', 'with']) if (Object.hasOwn(c, name)) request[name] = c[name];
  return canonicalJson(request);
}

/**
 * Build the content of an approval and the challenge the person's passkey
 * must sign.
 *
 * @param {object} fields
 * @param {string} fields.slip the fingerprint of the slip
 * @param {string} fields.action
 * @param {{unit: string, value: number}} [fields.amount]
 * @param {string} [fields.with]
 * @param {{name: string, sha256: string}[]} [fields.details]
 * @param {number|Date} [fields.when] defaults to now
 * @returns {Promise<{payloadB64: string, protectedB64: string, challenge: Uint8Array, fingerprint: string}>}
 *   "fingerprint" is what the agent's stub must name as its approval
 */
export async function prepareApproval(fields) {
  const content = {
    type: KINDS.approval.type,
    id: fields.id ?? randomId(),
    slip: fields.slip,
    action: fields.action,
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.amount) content.amount = fields.amount;
  if (fields.with) content.with = fields.with;
  if (fields.details && fields.details.length) content.details = fields.details;
  validateApprovalContent(content);
  const prepared = await preparePasskeyRecord('approval', content);
  return { ...prepared, fingerprint: await fingerprint(prepared.contentBytes) };
}

/**
 * Put the passkey's three values with the prepared content: the signed
 * approval. The values are stored exactly as the passkey returned them.
 * @param {{payloadB64: string, protectedB64: string}} prepared from prepareApproval
 * @param {{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array}} assertion
 * @returns {object} the approval record
 */
export function assembleApproval(prepared, assertion) {
  return assembleSlip(prepared, assertion);
}
