// A chain of block headers, checked on this device: the means to know,
// without asking anyone, that a block which a block time-stamp leads to is
// part of the Bitcoin blockchain.
//
// Nothing here makes a request. The headers come from a file the person
// has; the command provared-headers fetches them from Bitcoin nodes the
// person names (net/headers.js), and nothing else in this library does.
//
// Each header is checked against the one before it, by the rules every
// Bitcoin node applies to headers: it names the block before it; its
// double SHA-256 meets the target written in it; that target follows the
// difficulty rule (unchanged within a run of 2,016 blocks, recomputed at
// the start of each run from the time the run before it took); its time is
// later than the middle of the eleven before it, and not more than two
// hours ahead of this device's clock. The first header must be the
// chain's own first block, and the chain must hold the blocks listed
// below at their places. Those known blocks are what stops a chain that
// branches off early and keeps its difficulty low: such a chain would have
// to hold each of them, which no one can make without the real chain's
// work.

import { Refusal, formatTime } from './encoding.js';

/** The bytes of one block header. */
export const HEADER_BYTES = 80;

/** A block counts as part of the chain only with at least this many blocks after it. */
export const MIN_BLOCKS_AFTER = 6;

/** The most headers a chain file may hold: room for the chain to about the year 2045. */
export const MAX_HEADERS = 2_000_000;

// Node.js's own SHA-256 is far faster than Web Crypto for a million short
// inputs; it is reached without an import, so this file still loads in a
// browser, where Web Crypto is used.
const nodeCrypto = globalThis.process && typeof globalThis.process.getBuiltinModule === 'function' ? globalThis.process.getBuiltinModule('node:crypto') : null;

async function doubleSha256(bytes, webCrypto = false) {
  if (nodeCrypto && !webCrypto) {
    const once = nodeCrypto.createHash('sha256').update(bytes).digest();
    return new Uint8Array(nodeCrypto.createHash('sha256').update(once).digest());
  }
  const once = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', once));
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text) => new Uint8Array(text.match(/../g).map((pair) => parseInt(pair, 16)));
/** A block's fingerprint as it is written everywhere: the hash's bytes in reverse order, in hex. */
const written = (hash) => hex(Uint8Array.from(hash).reverse());

/**
 * The rules of the Bitcoin chain that headers are checked by. The known
 * blocks were read on 5 October 2026 from the whole chain of headers, which
 * was checked by these rules from the first block on this computer, and
 * which a second node on another network agreed with.
 */
export const BITCOIN = Object.freeze({
  first: '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c',
  // The easiest target a block may have.
  limit: (1n << 224n) - 1n,
  // The difficulty is recomputed every 2,016 blocks, aiming at two weeks for each run.
  interval: 2016,
  timespan: 14 * 24 * 60 * 60,
  retarget: true,
  // From these blocks on, a header's version must be at least this (the
  // upgrades of 2013 and 2015 that every node enforces).
  versions: Object.freeze([
    [227931, 2],
    [363725, 3],
    [388381, 4],
  ]),
  // After the last known block, no target may be more than four times
  // easier than that block's. Every change of difficulty in the real chain
  // so far eased it by less than one and a half times; a branch made after
  // the last known block, with dates pushed forward to ease it at every
  // change, is held to work no less than a quarter of the real chain's then.
  ease: 4n,
  known: Object.freeze([
    [100000, '000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506'],
    [200000, '000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf'],
    [300000, '000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254'],
    [400000, '000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f'],
    [500000, '00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04'],
    [600000, '00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91'],
    [700000, '0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959'],
    [800000, '00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054'],
    [900000, '000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a'],
    [969696, '000000000000000000001e39df127cbab82a824ac43cfcdbf62e59f6a08b9f0b'],
  ]),
});

const invalid = (message) => new Refusal('headers-invalid', message);

/** The target that a compact "bits" value stands for. */
function targetOf(bits) {
  if (bits & 0x00800000) return -1n; // a negative target: no hash meets it
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x007fffff);
  return exponent <= 3 ? mantissa >> BigInt(8 * (3 - exponent)) : mantissa << BigInt(8 * (exponent - 3));
}

/** The compact "bits" value of a target, as Bitcoin writes it. */
function compactOf(target) {
  let size = Math.ceil(target.toString(16).length / 2);
  let c = size <= 3 ? Number(target << BigInt(8 * (3 - size))) : Number(target >> BigInt(8 * (size - 3)));
  if (c & 0x00800000) {
    c >>>= 8;
    size++;
  }
  return (c | (size << 24)) >>> 0;
}

/**
 * The "bits" at the start of a run: the target of the last block, scaled by
 * how long the run took against how long it should, by at most four times
 * either way, and never easier than the limit. Not part of the public
 * interface.
 * @param {number} bits the last block's bits
 * @param {number} firstTime the time of the run's first block, in seconds
 * @param {number} lastTime the time of the run's last block, in seconds
 * @param {object} [rules]
 */
export function nextBits(bits, firstTime, lastTime, rules = BITCOIN) {
  const span = Math.min(Math.max(lastTime - firstTime, rules.timespan / 4), rules.timespan * 4);
  let target = (targetOf(bits) * BigInt(Math.floor(span))) / BigInt(rules.timespan);
  if (target > rules.limit) target = rules.limit;
  return compactOf(target);
}

/**
 * A chain of headers being read, one header at a time. Not part of the
 * public interface: checkHeaderChain reads a whole file with it, and the
 * command provared-headers adds what it fetches.
 * @param {object} [rules]
 */
export function startHeaderChain(rules = BITCOIN, { webCrypto = false } = {}) {
  let room = 1024;
  let headers = new Uint8Array(room * HEADER_BYTES);
  let hashes = new Uint8Array(room * 32);
  let count = 0;
  const known = new Map(rules.known.map(([height, fingerprint]) => [height, fingerprint]));
  let view = new DataView(headers.buffer);
  const timeAt = (h) => view.getUint32(h * HEADER_BYTES + 68, true);
  const bitsAt = (h) => view.getUint32(h * HEADER_BYTES + 72, true);
  const hashAt = (h) => hashes.subarray(h * 32, h * 32 + 32);
  // The target of the bits last seen, as 32 bytes, most significant first,
  // so that a hash is compared with it byte by byte.
  let targetBits = -1;
  let targetBytes = null;
  const meets = (hash, bits) => {
    if (bits !== targetBits) {
      const target = targetOf(bits);
      targetBits = bits;
      targetBytes = target <= 0n || target > rules.limit ? null : fromHex(target.toString(16).padStart(64, '0'));
    }
    if (targetBytes === null) return false;
    // The hash is a number written least significant byte first.
    for (let i = 0; i < 32; i++) {
      const a = hash[31 - i];
      const b = targetBytes[i];
      if (a !== b) return a < b;
    }
    return true;
  };
  // The last known block, and its target once the chain has reached it.
  const lastKnown = rules.known.length ? rules.known.at(-1)[0] : -1;
  let floor = null;
  const versions = rules.versions ?? [];
  const grow = () => {
    room *= 2;
    const moreHeaders = new Uint8Array(room * HEADER_BYTES);
    moreHeaders.set(headers.subarray(0, count * HEADER_BYTES));
    const moreHashes = new Uint8Array(room * 32);
    moreHashes.set(hashes.subarray(0, count * 32));
    headers = moreHeaders;
    hashes = moreHashes;
    view = new DataView(headers.buffer);
  };
  const chain = {
    rules,
    /** The number of the latest block held; -1 before the first. */
    get height() {
      return count - 1;
    },
    /**
     * Check one header as the next of the chain, and add it.
     * @param {Uint8Array} header 80 bytes
     * @param {number} now this device's clock, in milliseconds
     */
    async add(header, now) {
      const h = count;
      if (!(header instanceof Uint8Array) || header.length !== HEADER_BYTES) throw invalid(`Block ${h}: a header must be 80 bytes.`);
      if (h >= MAX_HEADERS) throw invalid(`The chain holds more than ${MAX_HEADERS} headers.`);
      const hash = await doubleSha256(header, webCrypto);
      const fields = new DataView(header.buffer, header.byteOffset, HEADER_BYTES);
      if (h === 0) {
        if (hex(header) !== rules.first) throw invalid('Block 0: this is not the chain\'s first block.');
      } else {
        const previous = hashAt(h - 1);
        for (let i = 0; i < 32; i++) if (header[4 + i] !== previous[i]) throw invalid(`Block ${h}: it does not name the block before it.`);
        const bits = fields.getUint32(72, true);
        const expected = rules.retarget && h % rules.interval === 0 ? nextBits(bitsAt(h - 1), timeAt(h - rules.interval), timeAt(h - 1), rules) : bitsAt(h - 1);
        if (bits !== expected) throw invalid(`Block ${h}: its difficulty does not follow the rule.`);
        if (!meets(hash, bits)) throw invalid(`Block ${h}: its hash does not meet its target, so it does not carry the work it claims.`);
        if (floor !== null && h > lastKnown && targetOf(bits) > floor * (rules.ease ?? 4n)) {
          throw invalid(`Block ${h}: its target is more than four times easier than that of block ${lastKnown}, the last block known to be part of the chain.`);
        }
        const version = fields.getInt32(0, true);
        for (const [from, least] of versions) if (h >= from && version < least) throw invalid(`Block ${h}: its version is lower than every block from ${from} on must have.`);
        const time = fields.getUint32(68, true);
        const before = [];
        for (let k = Math.max(0, h - 11); k < h; k++) before.push(timeAt(k));
        before.sort((a, b) => a - b);
        if (time <= before[before.length >> 1]) throw invalid(`Block ${h}: its time is not later than the middle of the eleven blocks before it.`);
        if (time * 1000 > now + 7200 * 1000) throw invalid(`Block ${h}: its time is more than two hours ahead of this device's clock.`);
      }
      if (known.has(h) && written(hash) !== known.get(h)) throw invalid(`Block ${h}: it is not the block known to be at that place in the chain.`);
      if (h === lastKnown) floor = targetOf(fields.getUint32(72, true));
      if (h >= room) grow();
      headers.set(header, h * HEADER_BYTES);
      hashes.set(hash, h * 32);
      count++;
    },
    /** Keep the blocks up to and including this one, where another chain parts from this one near its end. */
    keepTo(height) {
      if (height < 0 || height >= count) throw new RangeError('no such block');
      count = height + 1;
      if (height < lastKnown) floor = null;
    },
    /** A copy that shares nothing with this chain, to try another node's headers on. */
    copy() {
      const other = startHeaderChain(rules, { webCrypto });
      other[INSIDE].set({ headers: headers.slice(0, Math.max(count, 1) * HEADER_BYTES), hashes: hashes.slice(0, Math.max(count, 1) * 32), count, floor });
      return other;
    },
    /** Take on what another chain holds: a branch that carries more work. */
    adopt(other) {
      const state = other[INSIDE].get();
      headers = state.headers.slice();
      hashes = state.hashes.slice();
      room = headers.length / HEADER_BYTES;
      view = new DataView(headers.buffer);
      count = state.count;
      floor = state.floor;
      targetBits = -1;
    },
    /** The work of the blocks after this one, to the latest: the number of hashes their targets ask for, together. */
    workAfter(height) {
      let work = 0n;
      for (let h = height + 1; h < count; h++) {
        const target = targetOf(bitsAt(h));
        if (target > 0n) work += (1n << 256n) / (target + 1n);
      }
      return work;
    },
    /** The fingerprint of a block, 64 hex characters. */
    fingerprintAt(h) {
      return written(hashAt(h));
    },
    /** The hash of a block, as it is named inside the next header and in a request for headers. */
    hashAt(h) {
      return Uint8Array.from(hashAt(h));
    },
    /** The time a block states, in milliseconds. */
    timeAt(h) {
      return timeAt(h) * 1000;
    },
    /** The number of the block with this fingerprint, or -1 where the chain does not hold it. */
    heightOf(fingerprint) {
      if (typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(fingerprint)) return -1;
      const wanted = fromHex(fingerprint).reverse();
      outer: for (let h = count - 1; h >= 0; h--) {
        const at = h * 32;
        for (let i = 31; i >= 0; i--) if (hashes[at + i] !== wanted[i]) continue outer;
        return h;
      }
      return -1;
    },
    /** Every header held, one after another, as a chain file holds them. */
    bytes() {
      return headers.slice(0, count * HEADER_BYTES);
    },
    [INSIDE]: {
      get: () => ({ headers: headers.subarray(0, count * HEADER_BYTES), hashes: hashes.subarray(0, count * 32), count, floor }),
      set: (state) => {
        headers = state.headers;
        hashes = state.hashes;
        room = Math.max(1, headers.length / HEADER_BYTES);
        view = new DataView(headers.buffer);
        count = state.count;
        floor = state.floor;
        targetBits = -1;
      },
    },
  };
  return chain;
}

// What one chain hands another, and nothing else can reach.
const INSIDE = Symbol('inside');

/**
 * Read a whole chain file into a chain being read. Not part of the public
 * interface. Throws a Refusal "headers-invalid" at the first header that
 * breaks a rule. A chain that ends before the last known block is refused,
 * unless "partial": the command that fetches headers carries such a chain
 * on; nothing may count a block in it.
 * @param {Uint8Array} bytes
 * @param {{now?: number, rules?: object, partial?: boolean}} [o]
 */
export async function readHeaderChain(bytes, { now = Date.now(), rules = BITCOIN, partial = false, webCrypto = false } = {}) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length % HEADER_BYTES !== 0) {
    throw invalid('A chain file holds whole headers of 80 bytes each, one after another, from the first block.');
  }
  if (bytes.length / HEADER_BYTES > MAX_HEADERS) throw invalid(`The chain holds more than ${MAX_HEADERS} headers.`);
  const chain = startHeaderChain(rules, { webCrypto });
  for (let at = 0; at < bytes.length; at += HEADER_BYTES) await chain.add(bytes.subarray(at, at + HEADER_BYTES), now);
  const last = rules.known.at(-1);
  if (!partial && last && chain.height < last[0]) throw invalid(`The chain ends at block ${chain.height}, before block ${last[0]}, which is known to be part of it. Fetch more headers.`);
  return chain;
}

/**
 * Check a chain of Bitcoin block headers held in a file: every header, from
 * the chain's first block, by the rules above. Nothing is asked of anyone.
 *
 * @param {Uint8Array} bytes the headers, 80 bytes each, one after another, from the first block
 * @param {{now?: number}} [o] this device's clock, in milliseconds; by default the device's own
 * @returns {Promise<{height: number, tip: string, tipWhen: string, find: (fingerprint: string) => {height: number, after: number} | null}>}
 *   the number and fingerprint of the latest block, the time it states, and a way to find a block:
 *   its number, and how many blocks come after it in this chain
 * @throws {Refusal} "headers-invalid", at the first header that breaks a rule
 */
export async function checkHeaderChain(bytes, { now = Date.now() } = {}) {
  return answerFor(await readHeaderChain(bytes, { now }));
}

/**
 * What checkHeaderChain gives, for a chain that has been read. Not part of
 * the public interface.
 * @param {ReturnType<typeof startHeaderChain>} chain
 */
export function answerFor(chain) {
  const height = chain.height;
  return {
    height,
    tip: chain.fingerprintAt(height),
    tipWhen: formatTime(chain.timeAt(height)),
    find(fingerprint) {
      const at = chain.heightOf(fingerprint);
      return at < 0 ? null : { height: at, after: height - at };
    },
  };
}

/**
 * The blocks a check's block time-stamps lead to that a chain of headers
 * holds with at least MIN_BLOCKS_AFTER blocks after them: the blocks a
 * person who checked that chain can name as trusted. Each block
 * time-stamp the result shows is looked for, with what was found.
 *
 * @param {object} result what checkBook or checkShow returned
 * @param {{find: Function}} chain what checkHeaderChain returned
 * @returns {{blocks: string[], found: {block: string, stated: number, height: number|null, after: number|null, counted: boolean}[]}}
 */
export function blocksInChain(result, chain) {
  const stamps = [];
  for (const e of result.entries ?? []) stamps.push(...(e.stamps ?? []));
  for (const h of result.held ?? []) stamps.push(...(h.stamps ?? []));
  const found = [];
  const seen = new Set();
  for (const s of stamps) {
    if (s.kind !== 'block' || typeof s.authority !== 'string' || seen.has(s.authority)) continue;
    seen.add(s.authority);
    const at = chain.find(s.authority);
    found.push({ block: s.authority, stated: s.height, height: at ? at.height : null, after: at ? at.after : null, counted: at !== null && at.after >= MIN_BLOCKS_AFTER });
  }
  return { blocks: found.filter((f) => f.counted).map((f) => f.block), found };
}
