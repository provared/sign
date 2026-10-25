// Bytes, base64url, the canonical form of JSON, fingerprints and times.
//
// Runs unchanged in a browser and in Node.js: it uses only Web Crypto and
// the standard text encoders. Nothing here is specific to a kind of record.

/**
 * A refusal: a named reason why a record does not check. A failed check is
 * a normal answer, not a crash, so callers catch this and report its code.
 */
export class Refusal extends Error {
  /**
   * @param {string} code one of the codes in docs/threat-model.md, section 8
   * @param {string} message a plain sentence for a person
   */
  constructor(code, message) {
    super(message);
    this.name = 'Refusal';
    this.code = code;
  }
}

/**
 * Turn anything thrown while checking into a problem to report. A Refusal
 * keeps its code. Anything else means the checker itself met something it
 * did not expect: that is reported as "check-failed" and is never a pass.
 * @param {unknown} e
 * @returns {{code: string, message: string}}
 */
export function problemFrom(e) {
  if (e instanceof Refusal) return { code: e.code, message: e.message };
  return { code: 'check-failed', message: 'The checker met something it did not expect here. This is treated as not intact.' };
}

/** The largest whole number the format allows (2^53 - 1). */
export const MAX_NUMBER = Number.MAX_SAFE_INTEGER;

/** How deep the content of a record or a line of a book may nest. */
export const MAX_DEPTH = 8;

function subtle() {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) {
    throw new Error('Web Crypto is not available here. In a browser, open the page over https or on localhost.');
  }
  return s;
}

const encoder = new TextEncoder();
// fatal: malformed UTF-8 is refused. ignoreBOM: a byte order mark is kept in
// the text, where the JSON parser then refuses it.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** @param {string} text @returns {Uint8Array} */
export function utf8(text) {
  return encoder.encode(text);
}

/**
 * Strict UTF-8 decoding.
 * @param {Uint8Array} bytes
 * @param {string} code the refusal code to use if the bytes are not UTF-8
 * @returns {string}
 */
export function fromUtf8(bytes, code = 'not-json') {
  try {
    return decoder.decode(bytes);
  } catch {
    throw new Refusal(code, 'The bytes are not valid UTF-8 text.');
  }
}

/** @param {...Uint8Array} parts @returns {Uint8Array} */
export function concatBytes(...parts) {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** @param {Uint8Array} a @param {Uint8Array} b @returns {boolean} */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** SHA-256 (FIPS 180-4). @param {Uint8Array} bytes @returns {Promise<Uint8Array>} */
export async function sha256(bytes) {
  return new Uint8Array(await subtle().digest('SHA-256', bytes));
}

// --- base64url (RFC 4648 section 5, no padding; RFC 7515 section 2) ---

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

/** @param {Uint8Array} bytes @returns {string} */
export function toBase64url(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i] << 16;
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63];
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63];
  }
  return out;
}

/**
 * Strict decoding: refuses any character outside the alphabet, padding, an
 * impossible length, and stray bits in the last character. So one value has
 * exactly one text form.
 * @param {unknown} text
 * @returns {Uint8Array}
 */
export function fromBase64url(text) {
  if (typeof text !== 'string') throw new Refusal('bad-base64url', 'A base64url value must be text.');
  if (text.length % 4 === 1) throw new Refusal('bad-base64url', 'A base64url value has an impossible length.');
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let at = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    const v = c < 128 ? LOOKUP[c] : -1;
    if (v < 0) throw new Refusal('bad-base64url', 'A base64url value holds a character that is not allowed.');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) throw new Refusal('bad-base64url', 'A base64url value has stray bits in its last character.');
  return out;
}

// --- the canonical form (RFC 8785, narrowed as the format description says) ---

function wellFormed(text) {
  if (typeof text.isWellFormed === 'function') return text.isWellFormed();
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Write a value in the canonical form: RFC 8785, narrowed to objects, lists,
 * strings and whole numbers from 0 to 2^53 - 1. For those types RFC 8785 is
 * exactly: members sorted by name (by UTF-16 code unit, which is how
 * JavaScript sorts strings), strings as JSON.stringify writes them, no
 * spaces.
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {string}
 */
export function canonicalJson(value, depth = 0) {
  if (typeof value === 'string') {
    if (!wellFormed(value)) throw new Refusal('payload-not-canonical', 'A string is not well-formed Unicode.');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    // Object.is refuses -0, which JSON.parse gives for the text "-0".
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
      throw new Refusal('payload-not-canonical', 'A number must be a whole number from 0 to 9,007,199,254,740,991.');
    }
    return String(value);
  }
  if (value === null || typeof value !== 'object') {
    throw new Refusal('payload-not-canonical', 'Only objects, lists, strings and whole numbers are allowed.');
  }
  if (depth >= MAX_DEPTH) throw new Refusal('payload-not-canonical', 'The content nests too deeply.');
  if (Array.isArray(value)) {
    // A list with a gap in it is not JSON: "map" would skip the gap and write nothing in its place.
    const items = [];
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) throw new Refusal('payload-not-canonical', 'A list has a gap in it.');
      items.push(canonicalJson(value[i], depth + 1));
    }
    return '[' + items.join(',') + ']';
  }
  const names = Object.keys(value).sort();
  return '{' + names.map((n) => canonicalJson(n, depth + 1) + ':' + canonicalJson(value[n], depth + 1)).join(',') + '}';
}

/**
 * Read JSON text that must already be in the canonical form. The text is
 * parsed, written again canonically, and refused if the two differ. This
 * refuses a repeated member name, stray spaces and unusual number forms.
 * @param {string} text
 * @param {string} code the refusal code for text that is not canonical
 * @returns {any}
 */
export function parseCanonical(text, code = 'payload-not-canonical') {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Refusal(code === 'payload-not-canonical' ? code : 'not-json', 'The text is not JSON.');
  }
  let again;
  try {
    again = canonicalJson(value);
  } catch (e) {
    if (e instanceof Refusal) throw new Refusal(code, e.message);
    // Nesting so deep that the engine itself gives up.
    throw new Refusal(code, 'The content nests too deeply.');
  }
  if (again !== text) {
    throw new Refusal(code, 'The JSON is not in the canonical form (a repeated name, stray spaces, or members out of order).');
  }
  return value;
}

/**
 * How many characters a text holds, counted as Unicode code points, so that
 * every implementation counts the same way.
 * @param {string} text
 * @returns {number}
 */
export function countCharacters(text) {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    // The second half of a pair does not count again.
    if (!(c >= 0xdc00 && c <= 0xdfff)) count++;
  }
  return count;
}

/**
 * The fingerprint of a record: SHA-256 of its content bytes, in base64url.
 * @param {Uint8Array} contentBytes
 * @returns {Promise<string>}
 */
export async function fingerprint(contentBytes) {
  return toBase64url(await sha256(contentBytes));
}

// --- times (RFC 3339, UTC, to the second) ---

const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * @param {unknown} text
 * @returns {number} milliseconds since 1970, or NaN if the text is not a time in the one accepted form
 */
export function parseTime(text) {
  if (typeof text !== 'string' || !TIME.test(text)) return NaN;
  const ms = Date.parse(text);
  if (Number.isNaN(ms)) return NaN;
  // Refuses dates that do not exist, such as 30 February.
  return formatTime(ms) === text ? ms : NaN;
}

/**
 * A time, written in the one accepted form. Only a number of milliseconds
 * or a Date is read: text, true or a list would be read by rules that
 * differ from one device to another (text with no time zone is taken as
 * local time), so they are refused.
 * @param {number|Date} when
 * @returns {string}
 */
export function formatTime(when) {
  if (typeof when !== 'number' && !(when instanceof Date)) throw new RangeError('Invalid time value');
  return new Date(when).toISOString().slice(0, 19) + 'Z';
}

/** 16 random bytes in base64url: the unique number of a record. @returns {string} */
export function randomId() {
  return toBase64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}
