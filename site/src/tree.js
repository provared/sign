// The tree of fingerprints: a Merkle tree built exactly as RFC 6962
// (Certificate Transparency), section 2.1, sets out, with SHA-256.
//
//   leaf  = SHA-256(0x00 || data)
//   node  = SHA-256(0x01 || left || right)
//   a tree of n leaves splits at the largest power of two smaller than n
//
// The proof that one leaf is in the tree is the audit path of section
// 2.1.1. It is checked with the steps of RFC 9162, section 2.1.3.2.
//
// The proof that a tree of m leaves is the first part of a tree of n leaves
// (a consistency proof) is made as RFC 9162, section 2.1.4.1, sets out, and
// checked with the steps of section 2.1.4.2. RFC 9162 builds the same tree
// as RFC 6962.

import { Refusal, concatBytes, equalBytes, sha256 } from './encoding.js';

const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

/** @param {Uint8Array} data @returns {Promise<Uint8Array>} */
export function leafHash(data) {
  return sha256(concatBytes(LEAF, data));
}

function nodeHash(left, right) {
  return sha256(concatBytes(NODE, left, right));
}

// Every level of the tree, from the leaf hashes up to the root. Pairing
// neighbours and carrying a last odd node up unchanged gives the same tree
// as the recursive definition in RFC 6962: the test vectors prove it.
async function levels(leafHashes) {
  const all = [leafHashes];
  let level = leafHashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(await nodeHash(level[i], level[i + 1]));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    all.push(next);
    level = next;
  }
  return all;
}

/**
 * The root of the tree over the given leaves: the top fingerprint.
 * @param {Uint8Array[]} leaves the data of each leaf
 * @returns {Promise<Uint8Array>} 32 bytes; for no leaves, the hash of nothing, as RFC 6962 defines
 */
export async function treeRoot(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  const hashes = [];
  for (const leaf of leaves) hashes.push(await leafHash(leaf));
  const all = await levels(hashes);
  return all[all.length - 1][0];
}

/**
 * Work out the root as the leaves arrive, one at a time, so that the root of
 * the first n leaves is at hand after each. It keeps one fingerprint for
 * each complete part of the tree and folds them together from the right.
 * This is the same tree as treeRoot gives: the tests compare the two at
 * every size.
 */
export function treeBuilder(from = []) {
  /** @type {{hash: Uint8Array, size: number}[]} */
  const parts = from.slice();
  const addLeafHash = async (hash) => {
    if (!(hash instanceof Uint8Array) || hash.length !== 32) throw new Refusal('bad-field', 'leaf: must be a leaf fingerprint: 32 bytes.');
    let node = { hash: hash.slice(), size: 1 };
    while (parts.length && parts[parts.length - 1].size === node.size) {
      const left = parts.pop();
      node = { hash: await nodeHash(left.hash, node.hash), size: left.size * 2 };
    }
    parts.push(node);
  };
  return {
    /** A builder that carries on from here by itself: what is added to one is not added to the other. */
    fork() {
      return treeBuilder(parts);
    },
    /** @param {Uint8Array} leaf the data of the next leaf */
    async add(leaf) {
      await addLeafHash(await leafHash(leaf));
    },
    /**
     * Add the next leaf by its fingerprint alone (leafHash of its data), as a
     * sealer that never sees the lines does.
     * @param {Uint8Array} hash 32 bytes
     */
    addLeafHash,
    /** One fingerprint for each complete part of the tree, the largest first: what a sealer saves. */
    parts() {
      return parts.map((p) => ({ hash: p.hash.slice(), size: p.size }));
    },
    /** @returns {Promise<Uint8Array>} the root of the leaves added so far */
    async root() {
      if (parts.length === 0) return sha256(new Uint8Array(0));
      let hash = parts[parts.length - 1].hash;
      for (let i = parts.length - 2; i >= 0; i--) hash = await nodeHash(parts[i].hash, hash);
      return hash;
    },
  };
}

/**
 * The audit path for one leaf: the fingerprints needed to work out the root
 * from that leaf alone.
 * @param {Uint8Array[]} leaves
 * @param {number} index which leaf, counting from 0
 * @returns {Promise<Uint8Array[]>}
 */
export async function inclusionPath(leaves, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new RangeError('no such leaf');
  const hashes = [];
  for (const leaf of leaves) hashes.push(await leafHash(leaf));
  const all = await levels(hashes);
  const path = [];
  let at = index;
  for (let depth = 0; depth < all.length - 1; depth++) {
    const level = all[depth];
    if (at % 2 === 1) path.push(level[at - 1]);
    else if (at + 1 < level.length) path.push(level[at + 1]);
    // else: a last odd node, carried up with no neighbour at this level.
    at = Math.floor(at / 2);
  }
  return path;
}

/**
 * Check an audit path (RFC 9162, section 2.1.3.2).
 * @param {number} index which leaf, counting from 0
 * @param {number} size how many leaves the tree has
 * @param {Uint8Array} leaf the data of the leaf
 * @param {Uint8Array[]} path
 * @param {Uint8Array} root
 * @returns {Promise<boolean>}
 */
export async function verifyInclusion(index, size, leaf, path, root) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = await leafHash(leaf);
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(r, root);
}

// The largest power of two smaller than n, for n of 2 or more (RFC 9162,
// section 2.1.1: "k be the largest power of two smaller than n").
function splitAt(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// The root of the tree over the leaves whose hashes are hashes[lo] to
// hashes[hi - 1], for hi > lo: MTH of RFC 9162, section 2.1.1.
async function rangeRoot(hashes, lo, hi) {
  if (hi - lo === 1) return hashes[lo];
  const k = splitAt(hi - lo);
  return nodeHash(await rangeRoot(hashes, lo, lo + k), await rangeRoot(hashes, lo + k, hi));
}

// SUBPROOF(m, D[lo:hi], b) of RFC 9162, section 2.1.4.1, for 0 < m <= hi - lo.
async function subproof(hashes, m, lo, hi, b) {
  const n = hi - lo;
  if (m === n) return b ? [] : [await rangeRoot(hashes, lo, hi)];
  const k = splitAt(n);
  if (m <= k) return [...(await subproof(hashes, m, lo, lo + k, b)), await rangeRoot(hashes, lo + k, hi)];
  return [...(await subproof(hashes, m - k, lo + k, hi, false)), await rangeRoot(hashes, lo, lo + k)];
}

/**
 * The proof that the first m leaves form a tree that the whole tree extends:
 * the consistency proof of RFC 9162, section 2.1.4.1, from the tree of the
 * first m leaves to the tree of all of them. For m equal to the number of
 * leaves, and for m of 0, the proof is empty (RFC 9162 defines a proof only
 * for 0 < m; every tree extends the empty one).
 * @param {Uint8Array[]} leaves the data of each leaf
 * @param {number} m how many leaves the earlier tree has, from 0 to the number of leaves
 * @returns {Promise<Uint8Array[]>}
 */
export async function consistencyProof(leaves, m) {
  if (!Array.isArray(leaves)) throw new TypeError('the leaves must be a list');
  if (!Number.isSafeInteger(m) || m < 0 || m > leaves.length) throw new RangeError('no such earlier tree');
  if (m === 0 || m === leaves.length) return [];
  const hashes = [];
  for (const leaf of leaves) hashes.push(await leafHash(leaf));
  return subproof(hashes, m, 0, hashes.length, true);
}

const isHash = (value) => value instanceof Uint8Array && value.length === 32;

/**
 * Check a consistency proof (RFC 9162, section 2.1.4.2): that the tree of m
 * leaves whose root is rootM is the first part of the tree of n leaves whose
 * root is rootN. Where m equals n the proof must be empty and the two roots
 * the same; where m is 0 the proof must be empty and rootM the root of the
 * empty tree (the SHA-256 hash of nothing). Anything that is not a proof of
 * these sizes gives false: the function never throws for a bad proof.
 * @param {number} m
 * @param {number} n
 * @param {Uint8Array} rootM 32 bytes
 * @param {Uint8Array} rootN 32 bytes
 * @param {Uint8Array[]} proof each 32 bytes
 * @returns {Promise<boolean>}
 */
export async function verifyConsistency(m, n, rootM, rootN, proof) {
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || m < 0 || m > n) return false;
  if (!isHash(rootM) || !isHash(rootN) || !Array.isArray(proof)) return false;
  // Read place by place, a gap included: a gap is not a fingerprint.
  const path = [];
  for (let i = 0; i < proof.length; i++) {
    if (!isHash(proof[i])) return false;
    path.push(proof[i]);
  }
  if (m === n) return path.length === 0 && equalBytes(rootM, rootN);
  if (m === 0) return path.length === 0 && equalBytes(rootM, await sha256(new Uint8Array(0)));
  // The steps of RFC 9162, section 2.1.4.2, in their order.
  // 1. An empty proof fails.
  if (path.length === 0) return false;
  // 2. Where m is an exact power of two, the root of the earlier tree is the first value.
  // (Worked out by doubling, not with the bit operators, which hold only 32 bits.)
  let power = 1;
  while (power < m) power *= 2;
  if (power === m) path.unshift(rootM);
  // 3.
  let fn = m - 1;
  let sn = n - 1;
  // 4. Sizes are below 2 to the power 53, so halving with Math.floor is exact.
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  // 5.
  let fr = path[0];
  let sr = path[0];
  // 6.
  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  // 7.
  return equalBytes(fr, rootM) && equalBytes(sr, rootN) && sn === 0;
}
