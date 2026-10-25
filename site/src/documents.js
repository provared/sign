// The reserved names of the documents a stub names (format description,
// section 27), and the fingerprints they stand for.
//
// A stub's "details" names documents by their fingerprints. Most names are
// labels that whoever wrote the stub chose. Names that begin "provared."
// are reserved: each one on the list below says exactly which text its
// fingerprint is made from, so that an investigator who holds that text
// (the call's arguments, the HTTP request, the identifier a platform's own
// log shows for the call) can work the fingerprint out again and match
// the stub to it, without either side's help.

import { Refusal, fingerprint, sha256, toBase64url, utf8 } from './encoding.js';

/** Every document name that begins with this is reserved for the list below. */
export const RESERVED_DOCUMENT_PREFIX = 'provared.';

/** The reserved document names, and the exact text whose SHA-256 each one gives. */
export const DOCUMENT_NAMES = Object.freeze({
  'provared.arguments': "The call's arguments, written in the one form of RFC 8785.",
  'provared.http-request': 'The request, written as the signature base of RFC 9421, section 2.5, over "@method", "@target-uri" and, where there is a body, "content-digest" (RFC 9530, with SHA-256). No header is covered.',
  'provared.http-response': 'The answer, written as the signature base of RFC 9421, section 2.5, over "@status" and, where there is a body, "content-digest" (RFC 9530, with SHA-256). No header is covered.',
  'provared.trace-id': 'The trace-id of the W3C Trace Context "traceparent" header that the agent\'s side sent, which that standard writes as 32 lower-case hexadecimal characters. Its form is not checked.',
  'provared.request-id': "An identifier that the agent's side chose and sent with the call, exactly as sent.",
  'provared.event-id': 'An identifier that the platform gave for the call, exactly as it gave it.',
  'provared.error': "The error text that the agent's software was given, exactly as given.",
});

/**
 * The reserved names that may appear more than once in one record: an
 * identifier from each of several systems. Every other reserved name may
 * appear once at most.
 */
export const REPEATABLE_DOCUMENT_NAMES = Object.freeze(['provared.trace-id', 'provared.request-id', 'provared.event-id']);

/**
 * Whether a document name is reserved and not on the list: such a name is refused.
 * @param {string} name
 */
export function isUnknownReservedDocument(name) {
  return typeof name === 'string' && name.startsWith(RESERVED_DOCUMENT_PREFIX) && !Object.hasOwn(DOCUMENT_NAMES, name);
}

// A method is a token of RFC 9110, section 5.6.2: one or more of these.
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// An address is taken exactly as it was sent, never rewritten: so it must
// already be in the form a request carries, an absolute http or https
// address of visible ASCII characters, with no fragment (which is never
// sent).
const ADDRESS = /^https?:\/\/[\x21-\x22\x24-\x7e]+$/;

function body(value, path) {
  // Nothing given, or null: the message has no body.
  if (value === undefined || value === null) return undefined;
  if (!(value instanceof Uint8Array)) throw new Refusal('bad-field', `${path}: must be the bytes of the body, as sent.`);
  return value;
}

// Base64 with padding (RFC 4648, section 4), as a byte sequence of RFC 8941 is written.
function base64(bytes) {
  const text = toBase64url(bytes).replace(/-/g, '+').replace(/_/g, '/');
  return text + '='.repeat((4 - (text.length % 4)) % 4);
}

// The Content-Digest field value of RFC 9530, with SHA-256 only.
async function contentDigest(bytes) {
  return `sha-256=:${base64(await sha256(bytes))}:`;
}

// The signature base of RFC 9421, section 2.5: a line for each component,
// "<identifier>: <value>" and a line feed, then the line
// "@signature-params" with the list of the components and no parameters,
// and no line feed after it. Nothing is signed with it: it is only an exact
// way to write a request or an answer as text.
function signatureBase(components) {
  const lines = components.map(([id, value]) => `"${id}": ${value}\n`);
  return lines.join('') + `"@signature-params": (${components.map(([id]) => `"${id}"`).join(' ')})`;
}

/**
 * The text that the reserved name "provared.http-request" is made from.
 * @param {{method: string, url: string, body?: Uint8Array}} r
 * @returns {Promise<string>}
 */
export async function httpRequestBase(r) {
  if (r === null || typeof r !== 'object') throw new Refusal('bad-field', 'The request must be an object.');
  const { method, url } = r;
  const given = body(r.body, 'body');
  if (typeof method !== 'string' || !TOKEN.test(method)) throw new Refusal('bad-field', 'method: must be the method of the request as sent, a token such as GET or POST.');
  if (typeof url !== 'string' || !ADDRESS.test(url)) {
    throw new Refusal('bad-field', 'url: must be the address of the request as sent: an absolute http or https address of visible ASCII characters, with no fragment.');
  }
  const components = [
    ['@method', method],
    ['@target-uri', url],
  ];
  if (given !== undefined) components.push(['content-digest', await contentDigest(given)]);
  return signatureBase(components);
}

/**
 * The text that the reserved name "provared.http-response" is made from.
 * @param {{status: number, body?: Uint8Array}} r
 * @returns {Promise<string>}
 */
export async function httpResponseBase(r) {
  if (r === null || typeof r !== 'object') throw new Refusal('bad-field', 'The answer must be an object.');
  const { status } = r;
  const given = body(r.body, 'body');
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new Refusal('bad-field', 'status: must be the status code of the answer, a whole number from 100 to 599.');
  const components = [['@status', String(status)]];
  if (given !== undefined) components.push(['content-digest', await contentDigest(given)]);
  return signatureBase(components);
}

/**
 * The fingerprint of an HTTP request, for the document "provared.http-request".
 * @param {{method: string, url: string, body?: Uint8Array}} r the method and the address exactly as sent, and the body's bytes where there is a body
 * @returns {Promise<string>}
 * @throws {Refusal} "bad-field" if the request is not as set out
 */
export async function httpRequestFingerprint(r) {
  return fingerprint(utf8(await httpRequestBase(r)));
}

/**
 * The fingerprint of an HTTP answer, for the document "provared.http-response".
 * @param {{status: number, body?: Uint8Array}} r the status code, and the body's bytes where there is a body
 * @returns {Promise<string>}
 * @throws {Refusal} "bad-field" if the answer is not as set out
 */
export async function httpResponseFingerprint(r) {
  return fingerprint(utf8(await httpResponseBase(r)));
}

/**
 * The fingerprint of an identifier or of an error text, exactly as given:
 * SHA-256 of its UTF-8 bytes. For "provared.trace-id", "provared.request-id",
 * "provared.event-id" and "provared.error".
 * @param {string} id
 * @returns {Promise<string>}
 * @throws {Refusal} "bad-field" if it is not text, is empty, or is not well-formed Unicode
 */
export async function identifierFingerprint(id) {
  if (typeof id !== 'string' || id.length === 0) throw new Refusal('bad-field', 'The identifier must be text of one character or more.');
  if (typeof id.isWellFormed === 'function' ? !id.isWellFormed() : /[\ud800-\udfff]/.test(id.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ''))) {
    throw new Refusal('bad-field', 'The identifier holds text that is not well-formed Unicode.');
  }
  return fingerprint(utf8(id));
}
