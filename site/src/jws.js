// The signed envelope: JSON Web Signature (RFC 7515) in the general JSON
// serialisation (section 7.2.1), as the format description, sections 3.1 to
// 3.5, narrows it.
//
// Each layout is built in one place, here, and used by both the writers and
// the checker.

import { Refusal, canonicalJson, fingerprint, fromBase64url, fromUtf8, parseCanonical, toBase64url, utf8 } from './encoding.js';

/** The largest record, in bytes. */
export const MAX_RECORD_BYTES = 65536;

/**
 * The kinds of record. For each: the "type" of its content, and the exact
 * protected header of each signature, in order. A checker compares protected
 * headers byte for byte with these texts and interprets nothing else.
 */
export const KINDS = {
  slip: {
    type: 'provared.slip.v0',
    passkey: true,
    protected: ['{"typ":"vnd.provared.slip.v0+json","alg":"prova.red/webauthn/v0"}'],
  },
  stub: {
    type: 'provared.stub.v0',
    protected: ['{"typ":"vnd.provared.stub.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.stub.v0+json","alg":"ML-DSA-87"}'],
  },
  countersignature: {
    type: 'provared.countersignature.v0',
    protected: [
      '{"typ":"vnd.provared.countersignature.v0+json","alg":"Ed25519"}',
      '{"typ":"vnd.provared.countersignature.v0+json","alg":"ML-DSA-87"}',
    ],
  },
  approval: {
    type: 'provared.approval.v0',
    passkey: true,
    protected: ['{"typ":"vnd.provared.approval.v0+json","alg":"prova.red/webauthn/v0"}'],
  },
  refusal: {
    type: 'provared.refusal.v0',
    protected: ['{"typ":"vnd.provared.refusal.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.refusal.v0+json","alg":"ML-DSA-87"}'],
  },
  terms: {
    type: 'provared.terms.v0',
    protected: ['{"typ":"vnd.provared.terms.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.terms.v0+json","alg":"ML-DSA-87"}'],
  },
  cancellation: {
    type: 'provared.cancellation.v0',
    passkey: true,
    protected: ['{"typ":"vnd.provared.cancellation.v0+json","alg":"prova.red/webauthn/v0"}'],
  },
  acknowledgement: {
    type: 'provared.acknowledgement.v0',
    protected: ['{"typ":"vnd.provared.acknowledgement.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.acknowledgement.v0+json","alg":"ML-DSA-87"}'],
  },
  vouching: {
    type: 'provared.vouching.v0',
    protected: ['{"typ":"vnd.provared.vouching.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.vouching.v0+json","alg":"ML-DSA-87"}'],
  },
  withdrawal: {
    type: 'provared.withdrawal.v0',
    protected: ['{"typ":"vnd.provared.withdrawal.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.withdrawal.v0+json","alg":"ML-DSA-87"}'],
  },
  pass: {
    type: 'provared.pass.v0',
    protected: ['{"typ":"vnd.provared.pass.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.pass.v0+json","alg":"ML-DSA-87"}'],
  },
  denial: {
    type: 'provared.denial.v0',
    protected: ['{"typ":"vnd.provared.denial.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.denial.v0+json","alg":"ML-DSA-87"}'],
  },
  witness: {
    type: 'provared.witness.v0',
    protected: ['{"typ":"vnd.provared.witness.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.witness.v0+json","alg":"ML-DSA-87"}'],
  },
  seal: {
    type: 'provared.seal.v0',
    protected: [
      '{"typ":"vnd.provared.seal.v0+json","alg":"Ed25519"}',
      '{"typ":"vnd.provared.seal.v0+json","alg":"ML-DSA-87"}',
      '{"typ":"vnd.provared.seal.v0+json","alg":"SLH-DSA-SHA2-256s"}',
    ],
  },
};

const ALL_PROTECTED = new Map();
for (const [kind, k] of Object.entries(KINDS)) {
  for (const text of k.protected) ALL_PROTECTED.set(text, kind);
}

/**
 * The protected headers of a kind, in base64url, in signature order.
 * @param {'slip'|'stub'|'countersignature'} kind
 * @returns {string[]}
 */
export function protectedHeaders(kind) {
  return KINDS[kind].protected.map((text) => toBase64url(utf8(text)));
}

/**
 * The bytes a signature covers (RFC 7515 section 5.1): the protected header
 * in base64url, a full stop, the content in base64url.
 * @param {string} protectedB64
 * @param {string} payloadB64
 * @returns {Uint8Array}
 */
export function signingInput(protectedB64, payloadB64) {
  return utf8(protectedB64 + '.' + payloadB64);
}

/**
 * The size of a record, as the format description, section 3.1, measures it:
 * the lengths of its "payload" and of every text value in its signature
 * entries, added up. It does not depend on how the JSON around them is
 * written.
 * @param {any} record
 * @returns {number}
 */
export function recordSize(record) {
  let size = typeof record.payload === 'string' ? record.payload.length : 0;
  if (!Array.isArray(record.signatures)) return size;
  for (const s of record.signatures) {
    if (s === null || typeof s !== 'object') continue;
    for (const v of Object.values(s)) size += typeof v === 'string' ? v.length : 0;
    if (s.header !== null && typeof s.header === 'object') {
      for (const v of Object.values(s.header)) size += typeof v === 'string' ? v.length : 0;
    }
  }
  return size;
}

/**
 * A writer's check that what it has made is small enough to be accepted.
 * @param {any} record
 * @returns {any} the record
 */
export function withinSize(record) {
  if (recordSize(record) > MAX_RECORD_BYTES) throw new Refusal('too-large', 'The record would be larger than 65,536 bytes.');
  return record;
}

function exactMembers(object, names, what) {
  if (object === null || typeof object !== 'object' || Array.isArray(object)) {
    throw new Refusal('bad-envelope', `${what} must be an object.`);
  }
  const have = Object.keys(object).sort();
  const want = [...names].sort();
  if (have.length !== want.length || have.some((n, i) => n !== want[i])) {
    throw new Refusal('bad-envelope', `${what} must hold exactly: ${want.join(', ')}.`);
  }
}

/**
 * @typedef {object} ParsedRecord
 * @property {string} kind
 * @property {string} payloadB64 the content exactly as carried
 * @property {Uint8Array} contentBytes the content bytes, exactly as signed
 * @property {any} content the content, read from those bytes
 * @property {string} fingerprint the fingerprint of the record
 * @property {{protectedB64: string, signature: Uint8Array, header?: any}[]} signatures
 */

/**
 * Read a record and confirm its envelope, its labels and the canonical form
 * of its content. This checks no signature and no field of the content
 * other than "type".
 *
 * @param {any} record the record as a JavaScript object
 * @param {string} kind the kind of record expected in this place: one of the names of KINDS
 * @returns {Promise<ParsedRecord>}
 */
export async function parseRecord(record, kind) {
  const expected = KINDS[kind];
  exactMembers(record, ['payload', 'signatures'], 'A record');
  if (typeof record.payload !== 'string') throw new Refusal('bad-envelope', '"payload" must be text.');
  if (!Array.isArray(record.signatures)) throw new Refusal('bad-envelope', '"signatures" must be a list.');

  // The size is measured before anything is decoded.
  if (recordSize(record) > MAX_RECORD_BYTES) throw new Refusal('too-large', 'The record is larger than 65,536 bytes.');

  // Labels first: what kind of record does each signature say this is?
  const signatures = [];
  const seen = [];
  for (const s of record.signatures) {
    exactMembers(s, expected.passkey ? ['header', 'protected', 'signature'] : ['protected', 'signature'], 'A signature entry');
    if (typeof s.protected !== 'string' || typeof s.signature !== 'string') {
      throw new Refusal('bad-envelope', '"protected" and "signature" must be text.');
    }
    const text = fromUtf8(fromBase64url(s.protected), 'unknown-type');
    if (!ALL_PROTECTED.has(text)) {
      throw new Refusal('unknown-type', 'A signature carries a label that is not one of the known labels.');
    }
    if (ALL_PROTECTED.get(text) !== kind) {
      throw new Refusal('payload-type-mismatch', `A signature is labelled as a ${ALL_PROTECTED.get(text)}, but a ${kind} is expected here.`);
    }
    seen.push(text);
    const entry = { protectedB64: s.protected, signature: fromBase64url(s.signature) };
    if (expected.passkey) {
      exactMembers(s.header, ['authenticatorData', 'clientDataJSON'], 'The "header" of a passkey signature');
      entry.header = s.header;
    }
    signatures.push(entry);
  }
  if (seen.length !== expected.protected.length || seen.some((text, i) => text !== expected.protected[i])) {
    throw new Refusal(
      'bad-signatures-layout',
      expected.passkey
        ? `A ${kind} carries exactly one signature.`
        : kind === 'seal'
          ? 'A seal carries exactly three signatures: Ed25519, ML-DSA-87, then SLH-DSA-SHA2-256s.'
          : `A ${kind} carries exactly two signatures: Ed25519, then ML-DSA-87.`,
    );
  }

  const contentBytes = fromBase64url(record.payload);
  const content = parseCanonical(fromUtf8(contentBytes, 'payload-not-canonical'));
  if (content === null || typeof content !== 'object' || Array.isArray(content)) {
    throw new Refusal('bad-field', 'The content must be an object.');
  }
  if (content.type !== expected.type) {
    // Nothing from the content goes into the message: it is untrusted, and need not even be text.
    throw new Refusal('payload-type-mismatch', `The content does not say it is a ${kind}, which is what is expected here.`);
  }
  return {
    kind,
    payloadB64: record.payload,
    contentBytes,
    content,
    fingerprint: await fingerprint(contentBytes),
    signatures,
  };
}

/**
 * Write content in the canonical form and return what a signer needs.
 * @param {any} content
 * @returns {{contentBytes: Uint8Array, payloadB64: string}}
 */
export function encodeContent(content) {
  const contentBytes = utf8(canonicalJson(content));
  return { contentBytes, payloadB64: toBase64url(contentBytes) };
}
