// Public keys: the exact shapes the format accepts (format description,
// section 3.8), their thumbprints (RFC 7638) and how each is loaded for
// checking a signature.

import { Refusal, fromBase64url, sha256, toBase64url, utf8 } from './encoding.js';

/** The signing methods of an agent's or a service's key set, in order. */
export const KEY_SET_METHODS = ['Ed25519', 'ML-DSA-87'];

/**
 * The signing methods of a recorder's key set, which signs seals, in order.
 * The third rests only on fingerprint functions (FIPS 205).
 */
export const SEAL_METHODS = ['Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s'];

/** The signing methods a passkey may use. */
export const PASSKEY_METHODS = ['ES256', 'RS256', 'Ed25519'];

// For each method: the exact members of its JSON Web Key, in sorted order.
const SHAPES = {
  Ed25519: ['alg', 'crv', 'kty', 'x'],
  'ML-DSA-87': ['alg', 'kty', 'pub'],
  'SLH-DSA-SHA2-256s': ['alg', 'kty', 'pub'],
  ES256: ['alg', 'crv', 'kty', 'x', 'y'],
  RS256: ['alg', 'e', 'kty', 'n'],
};

// The Ed25519 public keys under which anyone can make a signature that
// checks: the eight points of small order. RFC 8032 does not say to refuse
// them, and libraries differ, so a checker refuses them itself, with any
// key whose number y is not below p (written in more than one way), so
// that two checkers cannot disagree.
const P = 2n ** 255n - 19n;
const ORDER_8_Y = 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n;
const SMALL_ORDER_Y = new Set([0n, 1n, P - 1n, ORDER_8_Y, P - ORDER_8_Y]);

/**
 * Whether 32 bytes are an Ed25519 public key under which anyone can sign,
 * or one written in more than one way.
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function weakEd25519(bytes) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  return y >= P || SMALL_ORDER_Y.has(y);
}

// The order L of the Ed25519 base point (RFC 8032, section 5.1). The number
// S of a signature must be below it (RFC 8032, section 5.1.7); libraries
// differ in whether they check, so a checker checks itself.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/**
 * Whether bytes are an Ed25519 signature that can never be valid, whatever
 * the key: not 64 bytes; or its first half (the point R) is one under which
 * anyone can sign or is written in more than one way; or its second half
 * (the number S, little-endian) is not below L.
 * @param {Uint8Array} signature
 * @returns {boolean}
 */
export function badEd25519Signature(signature) {
  if (signature.length !== 64) return true;
  if (weakEd25519(signature.subarray(0, 32))) return true;
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]);
  return s >= L;
}

// The curve P-256 (FIPS 186-5, section D.1.2.3): y^2 = x^3 - 3x + b over
// the whole numbers modulo p. A key whose two halves are not a point on it
// can check no signature, and libraries report it in different ways, so a
// checker refuses it itself.
const P256_P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/**
 * Whether two halves of 32 bytes each (x and y, big-endian) are a point on
 * the curve P-256, each below p.
 * @param {Uint8Array} x
 * @param {Uint8Array} y
 * @returns {boolean}
 */
export function onP256(x, y) {
  let X = 0n;
  let Y = 0n;
  for (const b of x) X = (X << 8n) | BigInt(b);
  for (const b of y) Y = (Y << 8n) | BigInt(b);
  if (X >= P256_P || Y >= P256_P) return false;
  return (Y * Y) % P256_P === (((X * X * X - 3n * X + P256_B) % P256_P) + P256_P) % P256_P;
}

function bad(where, why) {
  return new Refusal('bad-key', `${where}: ${why}`);
}

function bytesOf(jwk, member, where) {
  try {
    return fromBase64url(jwk[member]);
  } catch {
    throw bad(where, `"${member}" is not base64url.`);
  }
}

/**
 * Confirm that a key is exactly one of the accepted shapes.
 * @param {any} jwk
 * @param {string[]} allowed the methods allowed in this place
 * @param {string} where which key, for the message
 * @returns {string} the key's method
 */
export function checkKey(jwk, allowed, where) {
  if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) throw bad(where, 'a key must be an object.');
  const alg = jwk.alg;
  if (typeof alg !== 'string' || !allowed.includes(alg) || !Object.hasOwn(SHAPES, alg)) {
    throw bad(where, `the signing method must be one of ${allowed.join(', ')}.`);
  }
  const names = Object.keys(jwk).sort();
  const expected = SHAPES[alg];
  if (names.length !== expected.length || names.some((n, i) => n !== expected[i])) {
    throw bad(where, `a ${alg} key must hold exactly ${expected.join(', ')}.`);
  }
  for (const n of names) {
    if (typeof jwk[n] !== 'string') throw bad(where, `"${n}" must be text.`);
  }
  if (alg === 'Ed25519') {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') throw bad(where, 'an Ed25519 key has kty OKP and crv Ed25519.');
    const x = bytesOf(jwk, 'x', where);
    if (x.length !== 32) throw bad(where, 'an Ed25519 public key is 32 bytes.');
    if (weakEd25519(x)) throw bad(where, 'this Ed25519 public key is one under which anyone can sign, and is not accepted.');
  } else if (alg === 'ML-DSA-87') {
    if (jwk.kty !== 'AKP') throw bad(where, 'an ML-DSA-87 key has kty AKP.');
    // FIPS 204, table 2: an ML-DSA-87 public key is 2,592 bytes.
    if (bytesOf(jwk, 'pub', where).length !== 2592) throw bad(where, 'an ML-DSA-87 public key is 2,592 bytes.');
  } else if (alg === 'SLH-DSA-SHA2-256s') {
    if (jwk.kty !== 'AKP') throw bad(where, 'an SLH-DSA key has kty AKP.');
    // FIPS 205, table 2: an SLH-DSA-SHA2-256s public key is 64 bytes.
    if (bytesOf(jwk, 'pub', where).length !== 64) throw bad(where, 'an SLH-DSA-SHA2-256s public key is 64 bytes.');
  } else if (alg === 'ES256') {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw bad(where, 'an ES256 key has kty EC and crv P-256.');
    const x = bytesOf(jwk, 'x', where);
    const y = bytesOf(jwk, 'y', where);
    if (x.length !== 32 || y.length !== 32) {
      throw bad(where, 'the two halves of a P-256 public key are 32 bytes each.');
    }
    if (!onP256(x, y)) throw bad(where, 'a P-256 public key must be a point on the curve, each half below the prime of the curve.');
  } else {
    if (jwk.kty !== 'RSA' || jwk.e !== 'AQAB') throw bad(where, 'an RS256 key has kty RSA and e AQAB.');
    const n = bytesOf(jwk, 'n', where);
    // The size in bits: whole bytes after the first, and the bits of the first.
    const bits = n.length === 0 || n[0] === 0 ? 0 : (n.length - 1) * 8 + (32 - Math.clz32(n[0]));
    if (bits < 2048 || bits > 8192) throw bad(where, 'an RS256 key is 2,048 to 8,192 bits.');
  }
  return alg;
}

/**
 * Confirm that a value is a key set: exactly an Ed25519 key, then an
 * ML-DSA-87 key (format description, section 3.9).
 * @param {any} keys
 * @param {string} where
 */
export function checkKeySet(keys, where) {
  if (!Array.isArray(keys) || keys.length !== KEY_SET_METHODS.length) {
    throw bad(where, 'a key set is exactly two keys: Ed25519, then ML-DSA-87.');
  }
  KEY_SET_METHODS.forEach((alg, i) => checkKey(keys[i], [alg], `${where}[${i}]`));
}

/**
 * Confirm that a value is a recorder's key set: exactly an Ed25519 key, an
 * ML-DSA-87 key and an SLH-DSA-SHA2-256s key, in that order.
 * @param {any} keys
 * @param {string} where
 */
export function checkSealKeySet(keys, where) {
  if (!Array.isArray(keys) || keys.length !== SEAL_METHODS.length) {
    throw bad(where, 'a recorder\'s key set is exactly three keys: Ed25519, ML-DSA-87, then SLH-DSA-SHA2-256s.');
  }
  SEAL_METHODS.forEach((alg, i) => checkKey(keys[i], [alg], `${where}[${i}]`));
}

/**
 * The thumbprint of a key: RFC 7638 with SHA-256. The members used are those
 * RFC 7638 section 3.2 names, and for ML-DSA those RFC 9964 section 6 names.
 * The key must already have passed checkKey, so its members are exactly the
 * required ones, already known to be plain base64url text.
 * @param {any} jwk
 * @returns {Promise<string>}
 */
export async function thumbprint(jwk) {
  const required = { ...jwk };
  // "alg" is part of the thumbprint only for the AKP key type.
  if (jwk.kty !== 'AKP') delete required.alg;
  const names = Object.keys(required).sort();
  const text = '{' + names.map((n) => JSON.stringify(n) + ':' + JSON.stringify(required[n])).join(',') + '}';
  return toBase64url(await sha256(utf8(text)));
}

/**
 * Load a public key for checking signatures.
 * @param {any} jwk a key that has passed checkKey
 * @returns {Promise<CryptoKey>}
 */
export function importPublicKey(jwk) {
  const subtle = globalThis.crypto.subtle;
  switch (jwk.alg) {
    case 'Ed25519':
      return subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify']);
    case 'ML-DSA-87':
      return subtle.importKey('jwk', { kty: 'AKP', alg: 'ML-DSA-87', pub: jwk.pub }, { name: 'ML-DSA-87' }, false, ['verify']);
    case 'ES256':
      return subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    case 'RS256':
      return subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    default:
      return Promise.reject(new Error('unknown signing method'));
  }
}
