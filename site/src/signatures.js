// Checking and making signatures with the cryptography built into the
// browser or Node.js (Web Crypto). No outside code.
//
// Methods:
//   Ed25519    RFC 8032
//   ML-DSA-87  FIPS 204, plain method, empty context (RFC 9964 section 5)
//   ES256      ECDSA with P-256 and SHA-256 (FIPS 186-5), passkeys only
//   RS256      RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), passkeys only
//   SLH-DSA-SHA2-256s  FIPS 205, plain method, empty context; seals only
//
// SLH-DSA is not yet in Web Crypto anywhere. Node.js has it in its own
// cryptography module, which is asked for here without an import, so that
// this file still loads in a browser. In a browser the method is reported as
// not built in, which is never a pass.

import { Refusal } from './encoding.js';
import { badEd25519Signature, checkKey, importPublicKey, thumbprint } from './keys.js';

const SLH = 'SLH-DSA-SHA2-256s';

// The length of a signature, in bytes, by method (RFC 8032, FIPS 204,
// FIPS 205).
const SIGNATURE_BYTES = { Ed25519: 64, 'ML-DSA-87': 4627, [SLH]: 29792 };
const nodeCrypto = globalThis.process && typeof globalThis.process.getBuiltinModule === 'function' ? globalThis.process.getBuiltinModule('node:crypto') : null;

function slhKey(pub) {
  return nodeCrypto.createPublicKey({ key: { kty: 'AKP', alg: SLH, pub }, format: 'jwk' });
}

/** @typedef {'valid'|'invalid'|'unavailable'} SignatureState */

const VERIFY_PARAMS = {
  Ed25519: { name: 'Ed25519' },
  'ML-DSA-87': { name: 'ML-DSA-87' },
  ES256: { name: 'ECDSA', hash: 'SHA-256' },
  RS256: { name: 'RSASSA-PKCS1-v1_5' },
};

// Whether this device has a method built in. Ed25519 and ML-DSA are newer
// additions to Web Crypto, so they are probed once by making a key. ES256 and
// RS256 have been in Web Crypto from the start.
const available = new Map();

/**
 * @param {string} alg
 * @returns {Promise<boolean>} whether this device can check signatures made with this method
 */
export function methodAvailable(alg) {
  if (alg === 'ES256' || alg === 'RS256') return Promise.resolve(true);
  if (alg === SLH && !available.has(alg)) {
    let has = false;
    try {
      // An all-zero key is a key of the right shape: loading it shows whether the method is there.
      slhKey('A'.repeat(86));
      has = true;
    } catch {
      has = false;
    }
    available.set(alg, Promise.resolve(has));
  }
  if (!available.has(alg)) {
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    const probe = subtle
      ? Promise.resolve()
          .then(() => subtle.generateKey({ name: alg }, false, ['sign', 'verify']))
          .then(() => true, () => false)
      : Promise.resolve(false);
    available.set(alg, probe);
  }
  return available.get(alg);
}

/**
 * Check one signature.
 *
 * "unavailable" means this device has no built-in support for the method. It
 * is never treated as a pass. On a device that has the method, any failure,
 * including a key the device refuses to load, is "invalid".
 *
 * @param {any} jwk a public key that has passed checkKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} data the bytes that were signed
 * @param {string[]} [without] methods to treat as not built in, to see how a
 *   check behaves on a device without them; it can only withhold a pass
 * @returns {Promise<SignatureState>}
 */
export async function verifySignature(jwk, signature, data, without = []) {
  // A signature of another length than its method's can never check, so it
  // is refused on every device, whether or not this one has the method.
  if (Object.hasOwn(SIGNATURE_BYTES, jwk.alg) && signature.length !== SIGNATURE_BYTES[jwk.alg]) return 'invalid';
  if (jwk.alg === SLH) {
    if (without.includes(SLH) || !(await methodAvailable(SLH))) return 'unavailable';
    try {
      return nodeCrypto.verify(null, data, slhKey(jwk.pub), signature) ? 'valid' : 'invalid';
    } catch {
      return 'invalid';
    }
  }
  if (!Object.hasOwn(VERIFY_PARAMS, jwk.alg)) return 'invalid';
  const params = VERIFY_PARAMS[jwk.alg];
  if (without.includes(jwk.alg) || !(await methodAvailable(jwk.alg))) return 'unavailable';
  // An Ed25519 signature whose first half is a point of small order, or
  // whose second half, the number S, is not below the order L, is refused
  // here, whatever the device's own library would say: libraries differ on
  // both (format description, section 3.8).
  if (jwk.alg === 'Ed25519' && badEd25519Signature(signature)) return 'invalid';
  try {
    const key = await importPublicKey(jwk);
    return (await globalThis.crypto.subtle.verify(params, key, signature, data)) ? 'valid' : 'invalid';
  } catch {
    return 'invalid';
  }
}

/**
 * Sign with one private key of a key set.
 * @param {string} alg 'Ed25519', 'ML-DSA-87' or, for a seal, 'SLH-DSA-SHA2-256s'
 * @param {any} privateKey
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function sign(alg, privateKey, data) {
  if (alg === SLH) return new Uint8Array(nodeCrypto.sign(null, data, privateKey));
  return new Uint8Array(await globalThis.crypto.subtle.sign({ name: alg }, privateKey, data));
}

// --- signers ---
//
// Wherever a writer takes "privateKeys", each item may be a private key of
// the platform (a Web Crypto CryptoKey, or a Node.js KeyObject), used as it
// always was, or a signer: an object with "key", the public key as a JSON
// Web Key in one of the shapes of the format description, section 3.8, and
// "sign(data)", which gives the signature over exactly those bytes. A
// signer lets a key live elsewhere: in a key service, or a hardware module.
// It changes where a signature is made, not how: the record is the same.
//
// A signer is not taken on trust. Its two members are read once. Its key
// must be of the method of its place in the list, a method this device can
// check, and, where the writer knows the key the record must be signed
// with, that key. All of this is settled before any signer is asked to
// sign. Every signature it gives is checked against its key before it is
// used. A signer that fails in any way leaves no record, and the error
// names the method and the key. Signers earlier in the list may have
// signed by then: a key service's own log may hold signatures that match
// no record.

/**
 * Whether an item of "privateKeys" is a private key of the platform for the
 * method of its place: a private Web Crypto CryptoKey of that method that
 * may sign, or for SLH-DSA a private Node.js KeyObject of that kind. What
 * only looks like one (an object made from CryptoKey's own prototype, a
 * public key, a key of another method) is not one.
 * @param {any} item
 * @param {string} alg
 * @returns {boolean}
 */
function platformKey(item, alg) {
  try {
    if (alg === SLH) return Boolean(nodeCrypto) && item instanceof nodeCrypto.KeyObject && item.type === 'private' && item.asymmetricKeyType === 'slh-dsa-sha2-256s';
    return typeof globalThis.CryptoKey === 'function' && item instanceof globalThis.CryptoKey && item.type === 'private' && item.algorithm.name === alg && item.usages.includes('sign');
  } catch {
    return false; // a value that cannot even be looked into (a revoked Proxy), or one that only looks like a key
  }
}

// What a place in "privateKeys" must hold.
const signerShape = (alg) =>
  `must be a private key for ${alg} (${alg === SLH ? 'a Node.js KeyObject, or what Node.js reads as one: PEM text, DER bytes with their format, or a JSON Web Key with its format' : 'a Web Crypto CryptoKey'}), or a signer: an object with "key", the public key, and "sign", a function that gives the signature bytes.`;

/**
 * In the SLH-DSA place, the seal writer has always handed the key to
 * Node.js's own signing call, which also reads a key written out: PEM text,
 * DER bytes with their format, or a JSON Web Key with its format. Such a
 * key is still taken: it is read exactly as that call read it (with
 * crypto.createPrivateKey, which the call itself uses), and then it must be
 * a private SLH-DSA-SHA2-256s key, as a KeyObject must.
 * @param {any} item
 * @param {string} where
 * @returns {any} the key, as a KeyObject
 */
function writtenSlhKey(item, where) {
  let made;
  try {
    made = nodeCrypto.createPrivateKey(item);
  } catch {
    made = null; // not a private key Node.js can read, or no Node.js here
  }
  if (!platformKey(made, SLH)) throw new Refusal('bad-field', `${where}: ${signerShape(SLH)}`);
  return made;
}

// A signer that gave no answer in the time the stub writer gives it.
class NoAnswer extends Error {
  constructor(ms) {
    super(`no answer within ${ms} milliseconds`);
    this.ms = ms;
  }
}

// Two public keys that have passed checkKey: the same key, member for member.
function sameKey(a, b) {
  const names = Object.keys(b);
  return Object.keys(a).length === names.length && names.every((n) => a[n] === b[n]);
}

// The signature bytes a signer gave, copied, or null where it gave anything
// else. Bytes are a Uint8Array (a Node.js Buffer is one) or an ArrayBuffer,
// which is what Web Crypto's own "sign" gives.
function bytesOf(given) {
  try {
    if (given instanceof Uint8Array) return new Uint8Array(given);
    if (given instanceof ArrayBuffer) return new Uint8Array(given.slice(0));
  } catch {
    // fall through: not bytes that can be read
  }
  return null;
}

/**
 * Read one item of "privateKeys" for the method of its place.
 * @param {any} item
 * @param {string} alg
 * @param {string} where its place, for messages
 * @param {object} [expected] the public key the record must be signed with, where the writer knows it
 * @returns {Promise<{platform: boolean, item: any, key?: object, call?: (data: Uint8Array) => any, sign: (data: Uint8Array) => Promise<Uint8Array>}>}
 */
async function takeItem(item, alg, where, expected) {
  const platform = (privateKey) => ({ platform: true, item: privateKey, sign: (data) => sign(alg, privateKey, data) });
  if (platformKey(item, alg)) return platform(item);
  let key;
  let fn;
  if (item !== null && (typeof item === 'object' || typeof item === 'function')) {
    try {
      key = item.key;
      fn = item.sign;
    } catch {
      throw new Refusal('bad-field', `${where}: could not be read.`);
    }
  }
  if (typeof fn !== 'function') {
    // Not a signer: in the SLH-DSA place, perhaps a key written out.
    if (alg === SLH && item !== null && item !== undefined) return platform(writtenSlhKey(item, where));
    throw new Refusal('bad-field', `${where}: ${signerShape(alg)}`);
  }
  if (key === undefined || key === null) throw new Refusal('bad-field', `${where}: ${signerShape(alg)}`);
  let copy;
  try {
    copy = structuredClone(key);
  } catch {
    throw new Refusal('bad-key', `${where}.key: must be a public key, as plain data.`);
  }
  checkKey(copy, [alg], `${where}.key`);
  Object.freeze(copy);
  const label = `the ${alg} key ${await thumbprint(copy)}`;
  if (expected && !sameKey(copy, expected)) {
    throw new Refusal('bad-key', `${where}: the signer holds ${label}, which is not the key this record must be signed with (${await thumbprint(expected)}).`);
  }
  // Nothing is signed that this device cannot check: so a signer for a
  // method it does not have built in is refused before any signer is asked.
  if (!(await methodAvailable(alg))) {
    throw new Refusal('bad-key', `${where}: this device does not have ${alg} built in, so it cannot check a signature from the signer for ${label}. No record was made.`);
  }
  const call = (data) => fn.call(item, data);
  return { platform: false, item, key: copy, call, sign: (data) => signerSignature(call, copy, alg, label, where, data) };
}

// One signature from a signer, checked before it is used.
async function signerSignature(call, key, alg, label, where, data) {
  const failed = (why, cause) => {
    const e = new Refusal('signature-invalid', `${where}: the signer for ${label} ${why} No record was made.`);
    if (cause !== undefined) e.cause = cause;
    return e;
  };
  let given;
  try {
    // The signer is handed a copy: nothing it does to it changes what is checked.
    given = await call(data.slice());
  } catch (e) {
    if (e instanceof NoAnswer) throw failed(`gave no answer within ${e.ms} milliseconds.`);
    throw failed('failed with an error.', e);
  }
  const signature = bytesOf(given);
  if (signature === null) throw failed('gave something other than bytes.');
  if (Object.hasOwn(SIGNATURE_BYTES, alg) && signature.length !== SIGNATURE_BYTES[alg]) {
    throw failed(`gave a signature of ${signature.length} bytes, where an ${alg} signature is ${SIGNATURE_BYTES[alg]}.`);
  }
  // Whether the method is built in was settled before any signer was asked;
  // a signature that cannot be checked even so is not used.
  const state = await verifySignature(key, signature, data);
  if (state !== 'valid') throw failed('gave a signature that does not check against its key: it holds another key, or signed other bytes.');
  return signature;
}

/**
 * Read every item of "privateKeys", one for each method, before anything is
 * signed.
 * @param {any} privateKeys
 * @param {string[]} methods
 * @param {object[]} [expected] the public keys the record must be signed with, where the writer knows them
 * @returns {Promise<Awaited<ReturnType<typeof takeItem>>[]>}
 */
async function takeItems(privateKeys, methods, expected) {
  let list;
  try {
    list = Array.isArray(privateKeys);
  } catch {
    list = false; // a revoked Proxy
  }
  if (!list) throw new Refusal('bad-field', `privateKeys: must be a list, one private key or signer for each of ${methods.join(', ')}.`);
  const taken = [];
  for (let i = 0; i < methods.length; i++) {
    let item;
    try {
      item = privateKeys[i];
    } catch {
      throw new Refusal('bad-field', `privateKeys[${i}]: could not be read.`);
    }
    taken.push(await takeItem(item, methods[i], `privateKeys[${i}]`, expected ? expected[i] : undefined));
  }
  return taken;
}

/**
 * The functions that sign, one for each method, for a writer that signs
 * now. Keys of the platform sign as they always did; each signer is read
 * and checked as set out above.
 * @param {any} privateKeys
 * @param {string[]} methods
 * @param {object[]} [expected]
 * @returns {Promise<((data: Uint8Array) => Promise<Uint8Array>)[]>}
 */
export async function signingKeys(privateKeys, methods, expected) {
  return (await takeItems(privateKeys, methods, expected)).map((t) => t.sign);
}

/**
 * For a writer that holds its keys, such as the stub writer: the list to
 * use in place of "privateKeys". Keys of the platform are kept as they
 * are. Each signer is read once, here, and checked against the key the
 * records must be signed with where that is known; in its place stands a
 * signer that waits "ms" milliseconds at most for each signature, through
 * "run". A late answer is not used.
 * @param {any} privateKeys
 * @param {string[]} methods
 * @param {object[]|undefined} expected
 * @param {number} ms
 * @param {(work: () => Promise<any>) => Promise<any>} [run]
 * @returns {Promise<any[]>}
 */
export async function holdSigningKeys(privateKeys, methods, expected, ms, run = (work) => work()) {
  return (await takeItems(privateKeys, methods, expected)).map((t) => {
    if (t.platform) return t.item;
    const waited = (data) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new NoAnswer(ms)), ms);
        let answer;
        try {
          answer = Promise.resolve(t.call(data));
        } catch (e) {
          clearTimeout(timer);
          reject(e);
          return;
        }
        answer.then(
          (value) => {
            clearTimeout(timer);
            resolve(value);
          },
          (e) => {
            clearTimeout(timer);
            reject(e);
          },
        );
      });
    return Object.freeze({ key: t.key, sign: (data) => run(() => waited(data)) });
  });
}

/**
 * Wrap a private key held in memory as a signer, so that a key in memory
 * and a key held elsewhere take one path.
 * @param {string} alg 'Ed25519', 'ML-DSA-87' or 'SLH-DSA-SHA2-256s'
 * @param {any} privateKey a Web Crypto CryptoKey, or for SLH-DSA a Node.js KeyObject
 * @param {object} publicJwk its public key, in one of the shapes of the format description, section 3.8
 * @returns {{key: object, sign: (data: Uint8Array) => Promise<Uint8Array>}}
 */
export function signerFromKey(alg, privateKey, publicJwk) {
  if (alg !== 'Ed25519' && alg !== 'ML-DSA-87' && alg !== SLH) throw new Refusal('bad-field', `alg: must be Ed25519, ML-DSA-87 or ${SLH}.`);
  // Web Crypto holds the first two methods; Node.js's own module the third.
  if (!platformKey(privateKey, alg)) throw new Refusal('bad-field', `privateKey: must be a private key for ${alg}: ${alg === SLH ? 'a Node.js KeyObject' : 'a Web Crypto CryptoKey'}.`);
  let key;
  try {
    key = structuredClone(publicJwk);
  } catch {
    throw new Refusal('bad-key', 'key: must be a public key, as plain data.');
  }
  checkKey(key, [alg], 'key');
  return Object.freeze({ key: Object.freeze(key), sign: (data) => sign(alg, privateKey, data) });
}

/**
 * Make a new key set for a recorder, which signs seals: an Ed25519 key, an
 * ML-DSA-87 key and an SLH-DSA-SHA2-256s key. It needs Node.js: no browser
 * has the third method.
 * @returns {Promise<{keys: object[], privateKeys: any[]}>}
 */
export async function generateSealKeySet() {
  if (!(await methodAvailable(SLH))) throw new Error('SLH-DSA is not built into this device.');
  const two = await generateKeySet();
  const slh = nodeCrypto.generateKeyPairSync('slh-dsa-sha2-256s');
  const { pub } = slh.publicKey.export({ format: 'jwk' });
  return { keys: [...two.keys, { alg: SLH, kty: 'AKP', pub }], privateKeys: [...two.privateKeys, slh.privateKey] };
}

/**
 * Make a new key set for an agent or a service: an Ed25519 key and an
 * ML-DSA-87 key. The private halves cannot be exported from the returned
 * objects; they stay in the memory of this process.
 * @returns {Promise<{keys: object[], privateKeys: CryptoKey[]}>} the public key set, and the private keys in the same order
 */
export async function generateKeySet() {
  const subtle = globalThis.crypto.subtle;
  const ed = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const ml = await subtle.generateKey({ name: 'ML-DSA-87' }, false, ['sign', 'verify']);
  const edJwk = await subtle.exportKey('jwk', ed.publicKey);
  const mlJwk = await subtle.exportKey('jwk', ml.publicKey);
  return {
    keys: [
      { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: edJwk.x },
      { alg: 'ML-DSA-87', kty: 'AKP', pub: mlJwk.pub },
    ],
    privateKeys: [ed.privateKey, ml.privateKey],
  };
}
