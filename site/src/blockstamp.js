// A block time-stamp: proof that a fingerprint was written into a block of
// a public blockchain. The chain is used purely as a clock. No coin, no
// wallet, no account and no payment is involved, in making a proof or in
// checking one.
//
// The proof is a file of the open format "OpenTimestamps", version 1, as
// that format's reference reader accepts it, read strictly here. It is a
// list of steps that lead from the fingerprint to the Merkle root in the
// header of a block of the Bitcoin blockchain: join bytes before, join
// bytes after, take SHA-256. The block's own 80-byte header comes with the
// proof.
//
// Nothing here rests on a signature. It rests on SHA-256 (FIPS 180-4), and
// on the person checking having named the block as one they trust to be
// part of the chain.
//
// Format description, section 21.4. Runs unchanged in a browser.

import { Refusal, concatBytes, equalBytes, formatTime, sha256, toBase64url, utf8 } from './encoding.js';

/** The largest proof accepted, in bytes: the same as for a time-stamp from a service. */
export const MAX_PROOF_BYTES = 12288;
/** The length of a block header, in bytes. */
export const BLOCK_HEADER_BYTES = 80;
/**
 * How far the time a block states may be from the true time: two hours.
 * A block's time is set by whoever made the block, within about that much.
 */
export const BLOCK_TIME_ALLOWANCE_MS = 7200 * 1000;

// The limits of the format's own reference reader.
const MAX_VALUE_BYTES = 4096;
const MAX_ATTESTATION_BYTES = 8192;
const MAX_DEPTH = 255;

// How a proof file begins, and the mark of "this value is the Merkle root
// of a block of the Bitcoin blockchain".
const MAGIC = concatBytes(new Uint8Array([0x00]), utf8('OpenTimestamps'), new Uint8Array([0x00, 0x00]), utf8('Proof'), new Uint8Array([0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]));
const BLOCK_MARK = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);

const STEP = { SHA256: 0x08, JOIN_AFTER: 0xf0, JOIN_BEFORE: 0xf1, ATTESTATION: 0x00, FORK: 0xff };

function bad(why) {
  return new Refusal('stamp-bad-data', `A block time-stamp is not laid out as its format sets out: ${why}`);
}

function reader(bytes) {
  let at = 0;
  return {
    byte() {
      if (at >= bytes.length) throw bad('it is cut short.');
      return bytes[at++];
    },
    take(length) {
      if (at + length > bytes.length) throw bad('it is cut short.');
      at += length;
      return bytes.subarray(at - length, at);
    },
    done() {
      return at === bytes.length;
    },
  };
}

// A whole number as the format writes it: seven bits to a byte, lowest
// first, the top bit saying that another byte follows. Only the shortest
// form is accepted, so that one number has one form.
function number(r, most) {
  let value = 0;
  for (let i = 0; i < 5; i++) {
    const b = r.byte();
    value += (b & 0x7f) * 2 ** (7 * i);
    if (!(b & 0x80)) {
      if (i > 0 && b === 0) throw bad('a number is not written in its shortest form.');
      if (value > most) throw bad('a number is larger than the format allows.');
      return value;
    }
  }
  throw bad('a number is longer than the format allows.');
}

// One thing that follows from a value: a statement about it, or a step
// that makes a new value, with everything that follows from that.
async function readItem(r, tag, value, depth, found) {
  if (tag === STEP.ATTESTATION) {
    const mark = r.take(8);
    const payload = r.take(number(r, MAX_ATTESTATION_BYTES));
    // Statements of other kinds (a proof not yet complete, another chain) say nothing here.
    if (!equalBytes(mark, BLOCK_MARK)) return;
    const p = reader(payload);
    const height = number(p, 2 ** 35 - 1);
    if (!p.done()) throw bad('the statement about a block holds more than the block\'s number.');
    if (value.length === 32) found.push({ root: value, height });
    return;
  }
  let next;
  if (tag === STEP.SHA256) {
    next = await sha256(value);
  } else if (tag === STEP.JOIN_AFTER || tag === STEP.JOIN_BEFORE) {
    const joined = r.take(number(r, MAX_VALUE_BYTES));
    if (joined.length === 0) throw bad('a step joins nothing.');
    if (value.length + joined.length > MAX_VALUE_BYTES) throw bad('a step makes a value longer than 4,096 bytes.');
    next = tag === STEP.JOIN_AFTER ? concatBytes(value, joined) : concatBytes(joined, value);
  } else {
    throw bad('it uses a step other than "join before", "join after" and SHA-256.');
  }
  await readFrom(r, next, depth + 1, found);
}

// Everything that follows from a value. Each thing but the last is marked
// as one of several.
async function readFrom(r, value, depth, found) {
  if (depth > MAX_DEPTH) throw bad('its steps go deeper than the format allows.');
  let tag = r.byte();
  while (tag === STEP.FORK) {
    await readItem(r, r.byte(), value, depth, found);
    tag = r.byte();
  }
  await readItem(r, tag, value, depth, found);
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * The fingerprint of a block, as it is written everywhere: SHA-256 taken
 * twice over the header, the bytes in reverse order, in hex.
 * @param {Uint8Array} header the 80-byte block header
 * @returns {Promise<string>} 64 hex characters
 */
export async function blockFingerprint(header) {
  return hex((await sha256(await sha256(header))).reverse());
}

/**
 * Put a proof and the header of its block in the form they have beside a
 * seal or a cancellation, in the list "stamps".
 * @param {Uint8Array} proof the proof file, complete: it must lead to a block
 * @param {Uint8Array} header the 80-byte header of that block
 * @returns {{block: string, proof: string}}
 */
export function blockStampItem(proof, header) {
  if (!(proof instanceof Uint8Array) || proof.length === 0 || proof.length > MAX_PROOF_BYTES) throw bad('it must be at most 12,288 bytes.');
  if (!(header instanceof Uint8Array) || header.length !== BLOCK_HEADER_BYTES) throw bad('the block header that comes with it must be 80 bytes.');
  return { block: toBase64url(header), proof: toBase64url(proof) };
}

/**
 * Check one block time-stamp.
 *
 * @param {Uint8Array} proof the proof file; it is not changed
 * @param {Uint8Array} header the 80-byte header of the block the proof leads to
 * @param {Uint8Array} fingerprintBytes the 32 bytes that must have been stamped
 * @param {string[]} [trusted] the fingerprints (64 hex characters) of the blocks the checker trusts to be part of the chain
 * @returns {Promise<{kind: 'block', state: 'valid'|'untrusted', when: string, time: number, earliest: number, authority: string, height: number}>}
 *   "valid": the proof leads to a block the checker named. "untrusted": it
 *   leads to the block that comes with it, which the checker did not name;
 *   never treat this as a time. "when" is the time the block states. A
 *   block's time is only right to within about two hours, so there are two
 *   times in milliseconds. "time" is when the record existed by: the
 *   stated time and two hours. "earliest" is the earliest the proof could
 *   have been made: the stated time less two hours. Which of the two is
 *   the safe one depends on what is asked (see book.js). "authority" is
 *   the block's fingerprint. "height" is the block's number as the proof
 *   states it; nothing checks it.
 * @throws {Refusal} "stamp-bad-data", "stamp-wrong-data" or "stamp-invalid"
 */
export async function checkBlockStamp(proof, header, fingerprintBytes, trusted) {
  if (!(proof instanceof Uint8Array) || proof.length > MAX_PROOF_BYTES) throw bad('it must be at most 12,288 bytes.');
  if (!(header instanceof Uint8Array) || header.length !== BLOCK_HEADER_BYTES) throw bad('the block header that comes with it must be 80 bytes.');
  const r = reader(proof);
  if (!equalBytes(r.take(MAGIC.length), MAGIC)) throw bad('it does not begin as a proof file does.');
  if (r.byte() !== 1) throw bad('it is not version 1 of the format.');
  if (r.byte() !== STEP.SHA256) throw bad('its first fingerprint is not SHA-256.');
  const stamped = r.take(32);
  const found = [];
  await readFrom(r, stamped, 0, found);
  if (!r.done()) throw bad('there are bytes after its end.');

  if (!(fingerprintBytes instanceof Uint8Array) || !equalBytes(stamped, fingerprintBytes)) {
    throw new Refusal('stamp-wrong-data', 'A block time-stamp was made for something other than this record.');
  }
  // The Merkle root is bytes 36 to 67 of a block header, and the time bytes 68 to 71, lowest first.
  const root = header.subarray(36, 68);
  const match = found.find((f) => equalBytes(f.root, root));
  if (!match) throw new Refusal('stamp-invalid', 'A block time-stamp does not lead to the block that comes with it.');
  const stated = (header[68] + header[69] * 2 ** 8 + header[70] * 2 ** 16 + header[71] * 2 ** 24) * 1000;
  const fingerprint = await blockFingerprint(header);
  const named = Array.isArray(trusted) && trusted.some((t) => typeof t === 'string' && t.toLowerCase() === fingerprint);
  return {
    kind: 'block',
    state: named ? 'valid' : 'untrusted',
    when: formatTime(stated),
    time: stated + BLOCK_TIME_ALLOWANCE_MS,
    earliest: stated - BLOCK_TIME_ALLOWANCE_MS,
    authority: fingerprint,
    height: match.height,
  };
}
