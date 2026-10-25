// Checking an outside time-stamp: a signed statement by a time-stamp
// service that some fingerprint existed at some time.
//
// The standard is RFC 3161 (the time-stamp), carried in the signed-data
// layout of RFC 5652, signed with a key named by an X.509 certificate
// (RFC 5280). Format description, section 21.
//
// The checker is told which services it trusts, by the fingerprint of each
// service's certificate. It follows no chain of certificates and asks no
// outside party: the person checking decides whom to trust.

import { TAG, badStamp, children, contentOf, ecdsaToRaw, expect, hexOf, readElement, setInOrder, timeOf, validateDer, wholeOf } from './der.js';
import { Refusal, equalBytes, formatTime, sha256, toBase64url } from './encoding.js';
import { badEd25519Signature, weakEd25519 } from './keys.js';

/** The largest time-stamp, in bytes. */
export const MAX_STAMP_BYTES = 12288;

/** The loosest a time-stamp may state its own time and still count, in seconds. */
export const MAX_ACCURACY_SECONDS = 300;

// Object identifiers, as the hexadecimal of their DER content.
const OID = {
  signedData: '2a864886f70d010702',
  tstInfo: '2a864886f70d0109100104',
  contentType: '2a864886f70d010903',
  messageDigest: '2a864886f70d010904',
  signingCertificate: '2a864886f70d010910020c',
  signingCertificateV2: '2a864886f70d010910022f',
  sha1: '2b0e03021a',
  sha256: '608648016503040201',
  sha384: '608648016503040202',
  sha512: '608648016503040203',
  rsaEncryption: '2a864886f70d010101',
  sha256WithRsa: '2a864886f70d01010b',
  sha384WithRsa: '2a864886f70d01010c',
  sha512WithRsa: '2a864886f70d01010d',
  ecdsaWithSha256: '2a8648ce3d040302',
  ecdsaWithSha384: '2a8648ce3d040303',
  ecdsaWithSha512: '2a8648ce3d040304',
  ecPublicKey: '2a8648ce3d0201',
  p256: '2a8648ce3d030107',
  p384: '2b81040022',
  ed25519: '2b6570',
};

const HASHES = { [OID.sha256]: 'SHA-256', [OID.sha384]: 'SHA-384', [OID.sha512]: 'SHA-512' };
const RSA_WITH = { [OID.sha256WithRsa]: 'SHA-256', [OID.sha384WithRsa]: 'SHA-384', [OID.sha512WithRsa]: 'SHA-512' };
const ECDSA_WITH = { [OID.ecdsaWithSha256]: 'SHA-256', [OID.ecdsaWithSha384]: 'SHA-384', [OID.ecdsaWithSha512]: 'SHA-512' };

const invalid = (why) => new Refusal('stamp-invalid', why);

// An "AlgorithmIdentifier": a sequence that begins with an object identifier.
function algorithmOf(bytes, element, what) {
  expect(element, TAG.SEQUENCE, what);
  const parts = children(bytes, element, 2);
  return { oid: hexOf(bytes, expect(parts[0], TAG.OID, what)), parameters: parts[1] };
}

async function digest(name, bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest(name, bytes));
}

// The statement the service signed (RFC 3161 section 2.4.2, "TSTInfo").
function readStatement(bytes) {
  const outer = expect(readElement(bytes, 0), TAG.SEQUENCE, 'the statement');
  if (outer.end !== bytes.length) throw badStamp('the statement has bytes left over.');
  validateDer(bytes, outer);
  const parts = children(bytes, outer, 10);
  const version = expect(parts[0], TAG.INTEGER, 'the version of the statement');
  if (hexOf(bytes, version) !== '01') throw badStamp('the statement is of a version other than 1.');
  expect(parts[1], TAG.OID, 'the policy');
  const imprint = children(bytes, expect(parts[2], TAG.SEQUENCE, 'the fingerprint that was stamped'), 2);
  const hash = algorithmOf(bytes, imprint[0], 'the fingerprint method').oid;
  const stamped = contentOf(bytes, expect(imprint[1], TAG.OCTET_STRING, 'the fingerprint that was stamped'));
  expect(parts[3], TAG.INTEGER, 'the serial number');
  const time = timeOf(bytes, expect(parts[4], TAG.GENERALIZED_TIME, 'the time'));

  // What may follow, each at most once and in this order: how exact the
  // time is, whether stamps are strictly ordered, a number used once, the
  // service's name, and extensions.
  let i = 5;
  let accuracySeconds = 0;
  if (parts[i] && parts[i].tag === TAG.SEQUENCE) {
    for (const a of children(bytes, parts[i], 3)) {
      if (a.tag === TAG.INTEGER) {
        const digits = contentOf(bytes, a);
        if (digits.length > 4 || digits[0] & 0x80) throw badStamp('the statement says how exact its time is in a way that cannot be read.');
        accuracySeconds = digits.reduce((n, b) => n * 256 + b, 0);
      } else if (a.tag !== 0x80 && a.tag !== 0x81) {
        throw badStamp('the statement says how exact its time is in a way that cannot be read.');
      }
    }
    i++;
  }
  if (parts[i] && parts[i].tag === TAG.BOOLEAN) i++;
  if (parts[i] && parts[i].tag === TAG.INTEGER) i++;
  if (parts[i] && parts[i].tag === TAG.CONTEXT_0) i++;
  let critical = false;
  if (parts[i] && parts[i].tag === TAG.CONTEXT_1) {
    for (const extension of children(bytes, parts[i], 16)) {
      const fields = children(bytes, expect(extension, TAG.SEQUENCE, 'an extension'), 3);
      if (fields.some((x) => x.tag === TAG.BOOLEAN && bytes[x.start] === 0xff)) critical = true;
    }
    i++;
  }
  if (i !== parts.length) throw badStamp('the statement holds parts that are not in the order its standard sets out.');
  return { hash, stamped, time, accuracySeconds, critical };
}

// The public key of a certificate, written exactly as its standard sets
// out, so that two checkers cannot disagree about whether it can be read:
// RSA as RFC 3279 section 2.3.1 sets out (the method's parameters empty,
// the key two positive whole numbers in strict DER, nothing after them);
// ECDSA as RFC 5480 section 2.2 (an uncompressed point of the named
// curve); Ed25519 as RFC 8410 section 4 (no parameters, 32 bytes). In each,
// the string of bits has no unused bits.
//
// An RSA key is 2,048 to 8,192 bits, with an odd public number from 3 to
// 2^32 - 1: a small number, so that checking a signature cannot be made
// slow, and never 1, under which anyone can make a signature that checks.
function checkKeyEncoding(bytes, certificate, method, size) {
  const why = 'the public key of a certificate is not written as its standard sets out.';
  const bits = certificate.keyBits;
  if (bits.end - bits.start < 1 || bytes[bits.start] !== 0) throw badStamp(why);
  const inner = bytes.subarray(bits.start + 1, bits.end);
  const parameters = certificate.keyParameters;
  if (method === 'ECDSA') {
    if (inner.length !== 1 + 2 * size || inner[0] !== 0x04) throw badStamp(why);
    return;
  }
  if (method === 'Ed25519') {
    if (parameters !== null || inner.length !== 32) throw badStamp(why);
    if (weakEd25519(inner)) throw invalid('A time-stamp was signed with an Ed25519 key under which anyone can sign, which is not accepted.');
    return;
  }
  if (parameters === null || parameters.tag !== TAG.NULL) throw badStamp(why);
  let n;
  let e;
  try {
    const key = readElement(inner, 0);
    if (key.tag !== TAG.SEQUENCE || key.end !== inner.length) throw new Error();
    validateDer(inner, key);
    const parts = children(inner, key, 3);
    [n, e] = parts;
    if (parts.length !== 2 || n.tag !== TAG.INTEGER || e.tag !== TAG.INTEGER || inner[n.start] & 0x80 || inner[e.start] & 0x80) throw new Error();
  } catch {
    throw badStamp(why);
  }
  let modulus = contentOf(inner, n);
  if (modulus[0] === 0) modulus = modulus.subarray(1);
  const length = modulus.length === 0 ? 0 : (modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0]));
  let exponent = contentOf(inner, e);
  if (exponent[0] === 0) exponent = exponent.subarray(1);
  const odd = exponent.length > 0 && (exponent[exponent.length - 1] & 1) === 1;
  if (length < 2048 || length > 8192 || exponent.length === 0 || exponent.length > 4 || !odd || (exponent.length === 1 && exponent[0] < 3)) {
    throw invalid('A time-stamp was signed with an RSA key whose size or public number is not accepted.');
  }
}

// What is needed from a certificate (RFC 5280 section 4.1): when it is in
// force, and its public key.
function readCertificate(bytes, element) {
  const whole = wholeOf(bytes, expect(element, TAG.SEQUENCE, 'a certificate'));
  // A certificate is DER (RFC 5280 section 4.1), so the order of every set inside it is held here.
  validateDer(bytes, element);
  const tbs = expect(children(bytes, element, 3)[0], TAG.SEQUENCE, 'the body of a certificate');
  const parts = children(bytes, tbs, 12);
  // The version, in [0], is absent only in the oldest kind of certificate.
  let i = parts[0] && parts[0].tag === TAG.CONTEXT_0 ? 1 : 0;
  expect(parts[i++], TAG.INTEGER, 'the serial number of a certificate');
  expect(parts[i++], TAG.SEQUENCE, 'the signing method of a certificate');
  expect(parts[i++], TAG.SEQUENCE, 'the issuer of a certificate');
  const validity = children(bytes, expect(parts[i++], TAG.SEQUENCE, 'the dates of a certificate'), 2);
  if (validity.length !== 2) throw badStamp('a certificate does not hold two dates.');
  expect(parts[i++], TAG.SEQUENCE, 'the subject of a certificate');
  const keyInfo = expect(parts[i], TAG.SEQUENCE, 'the public key of a certificate');
  const keyParts = children(bytes, keyInfo, 2);
  const keyAlgorithm = algorithmOf(bytes, keyParts[0], 'the kind of public key');
  return {
    whole,
    notBefore: timeOf(bytes, validity[0]),
    notAfter: timeOf(bytes, validity[1]),
    spki: wholeOf(bytes, keyInfo),
    keyOid: keyAlgorithm.oid,
    keyParameters: keyAlgorithm.parameters ?? null,
    keyBits: expect(keyParts[1], TAG.BIT_STRING, 'the public key of a certificate'),
    curveOid: keyAlgorithm.parameters && keyAlgorithm.parameters.tag === TAG.OID ? hexOf(bytes, keyAlgorithm.parameters) : null,
  };
}

// The signed attribute that says which certificate signed (RFC 3161 section
// 2.4.2; RFC 2634 and RFC 5035): the fingerprint method and the fingerprint
// of the certificate.
function signingCertificateOf(bytes, value, v2) {
  const certs = children(bytes, expect(children(bytes, expect(value, TAG.SEQUENCE, 'the signing certificate attribute'), 2)[0], TAG.SEQUENCE, 'the signing certificate attribute'), 8);
  const first = children(bytes, expect(certs[0], TAG.SEQUENCE, 'the signing certificate attribute'), 3);
  let at = 0;
  let hash = v2 ? 'SHA-256' : 'SHA-1';
  if (v2 && first[0] && first[0].tag === TAG.SEQUENCE) {
    hash = HASHES[algorithmOf(bytes, first[0], 'the signing certificate attribute').oid];
    if (!hash) throw invalid('A time-stamp names its certificate with a fingerprint method that is not accepted.');
    at = 1;
  }
  return { hash, value: contentOf(bytes, expect(first[at], TAG.OCTET_STRING, 'the signing certificate attribute')) };
}

const KIND_NOT_ACCEPTED = 'A time-stamp was signed with a kind of key that is not accepted: RSA, ECDSA on the curves P-256 and P-384, and Ed25519 are.';
const ED25519_DIGEST = 'A time-stamp signed with Ed25519 names a fingerprint method other than SHA-512, or gives the method parameters, which RFC 8419 does not allow.';
const ED25519_PARAMETERS = 'A time-stamp signed with Ed25519 gives its signing method parameters, which RFC 8419 does not allow.';

// Check the service's signature with the public key of its certificate.
// Returns "valid", "invalid", or "unavailable" where this device has no
// built-in support for the method. The fingerprint method is the one the
// signer names (RFC 5652 section 5.4); a signing method that names another
// is refused; a key of a kind that is not accepted is refused in words that
// say so. "parameters" holds the parameters, if any, of the signing method
// and of the signer's fingerprint method.
async function verifyWith(certificate, bytes, signatureOid, digestName, signature, signed, without, parameters) {
  const subtle = globalThis.crypto.subtle;
  let importParams;
  let verifyParams;
  let method;
  let raw = signature;
  if (certificate.keyOid === OID.rsaEncryption) {
    if (signatureOid !== OID.rsaEncryption && RSA_WITH[signatureOid] !== digestName) return 'invalid';
    checkKeyEncoding(bytes, certificate, 'RSA');
    method = 'RSA';
    importParams = { name: 'RSASSA-PKCS1-v1_5', hash: digestName };
    verifyParams = { name: 'RSASSA-PKCS1-v1_5' };
  } else if (certificate.keyOid === OID.ecPublicKey) {
    const curve = certificate.curveOid === OID.p256 ? ['P-256', 32] : certificate.curveOid === OID.p384 ? ['P-384', 48] : null;
    if (!curve) throw invalid(KIND_NOT_ACCEPTED);
    if (ECDSA_WITH[signatureOid] !== digestName) return 'invalid';
    checkKeyEncoding(bytes, certificate, 'ECDSA', curve[1]);
    method = 'ECDSA';
    importParams = { name: 'ECDSA', namedCurve: curve[0] };
    verifyParams = { name: 'ECDSA', hash: digestName };
    try {
      raw = ecdsaToRaw(signature, curve[1]);
    } catch {
      return 'invalid';
    }
  } else if (certificate.keyOid === OID.ed25519) {
    // With Ed25519 the signer's fingerprint method is SHA-512 with no
    // parameters, and the signing method carries none (RFC 8419, section 3.1).
    if (signatureOid !== OID.ed25519) return 'invalid';
    if (digestName !== 'SHA-512' || parameters.digest !== undefined) throw invalid(ED25519_DIGEST);
    if (parameters.signature !== undefined) throw invalid(ED25519_PARAMETERS);
    checkKeyEncoding(bytes, certificate, 'Ed25519');
    method = 'Ed25519';
    importParams = { name: 'Ed25519' };
    verifyParams = { name: 'Ed25519' };
  } else {
    throw invalid(KIND_NOT_ACCEPTED);
  }
  if (without.includes(method)) return 'unavailable';
  let key;
  try {
    key = await subtle.importKey('spki', certificate.spki, importParams, false, ['verify']);
  } catch (e) {
    // A device with no Ed25519 says so when the key is loaded.
    return method === 'Ed25519' && e && e.name === 'NotSupportedError' ? 'unavailable' : 'invalid';
  }
  // An Ed25519 signature whose first half is a point of small order, or whose number S is not below L, is refused, as everywhere (format description, section 3.8).
  if (method === 'Ed25519' && badEd25519Signature(raw)) return 'invalid';
  try {
    return (await subtle.verify(verifyParams, key, raw, signed)) ? 'valid' : 'invalid';
  } catch {
    return 'invalid';
  }
}

/**
 * Check one time-stamp.
 *
 * @param {Uint8Array} token the time-stamp, as the service returned it (the "TimeStampToken"); it is not changed
 * @param {Uint8Array} fingerprintBytes the 32 bytes that must have been stamped
 * @param {object} [options]
 * @param {string[]} [options.trusted] the certificate fingerprints (SHA-256, base64url) of the services the checker trusts
 * @param {string[]} [options.without] methods ("RSA", "ECDSA", "Ed25519") to treat as not built into this device
 * @returns {Promise<{state: 'valid'|'untrusted'|'unavailable', when: string|null, time: number, authority: string|null}>}
 *   "valid": signed by a service the checker trusts. "untrusted": signed
 *   soundly, by a service the checker did not name. "unavailable": this
 *   device cannot check the service's signing method; no time is given.
 *   "authority" is the fingerprint of the certificate that signed. "when"
 *   is the stated time, to the second, rounded down; "time" is it in
 *   milliseconds, a fraction of a second kept to the millisecond.
 * @throws {Refusal} "stamp-bad-data", "stamp-wrong-data" or "stamp-invalid"
 */
export async function checkStamp(token, fingerprintBytes, options) {
  if (options === null || typeof options !== 'object') options = {};
  const without = Array.isArray(options.without) ? options.without : [];
  if (!(token instanceof Uint8Array) || token.length === 0 || token.length > MAX_STAMP_BYTES) {
    throw badStamp('it is empty, or larger than 12,288 bytes.');
  }
  if (!(fingerprintBytes instanceof Uint8Array)) throw badStamp('there is no fingerprint to compare it with.');

  // The outer wrapper, and the signed data inside it (RFC 5652 sections 3
  // and 5.1). Every part the reader can tell apart is read, and must be
  // strict DER, except that the order of a set is held only where a standard
  // requires DER: the signed attributes (RFC 5652 section 5.3), the statement
  // (RFC 3161 section 2.4.2) and each certificate (RFC 5280 section 4.1),
  // each walked again below with the order held. The signed data's own sets
  // (the fingerprint methods, the certificates, the withdrawn certificates,
  // the signers) and the rest of the signer may be in any order: CMS does not
  // require DER of them, and real services list their certificates in chain
  // order, the signing certificate before its issuer.
  const wrapper = expect(readElement(token, 0), TAG.SEQUENCE, 'the wrapper');
  if (wrapper.end !== token.length) throw badStamp('it has bytes left over.');
  validateDer(token, wrapper, false);
  const outer = children(token, wrapper, 2);
  if (outer.length !== 2 || hexOf(token, expect(outer[0], TAG.OID, 'the kind of content')) !== OID.signedData) throw badStamp('it is not signed data.');
  const inner = children(token, expect(outer[1], TAG.CONTEXT_0, 'the signed data'), 1);
  const parts = children(token, expect(inner[0], TAG.SEQUENCE, 'the signed data'), 6);
  if (hexOf(token, expect(parts[0], TAG.INTEGER, 'the version')) !== '03') throw badStamp('the signed data is of a version other than 3.');
  for (const method of children(token, expect(parts[1], TAG.SET, 'the list of fingerprint methods'), 8)) algorithmOf(token, method, 'a fingerprint method');
  const enclosed = children(token, expect(parts[2], TAG.SEQUENCE, 'the enclosed content'), 2);
  if (enclosed.length !== 2 || hexOf(token, expect(enclosed[0], TAG.OID, 'the kind of enclosed content')) !== OID.tstInfo) {
    throw badStamp('what it encloses is not a time-stamp statement.');
  }
  const statementHolder = children(token, expect(enclosed[1], TAG.CONTEXT_0, 'the statement'), 1);
  const statementBytes = contentOf(token, expect(statementHolder[0], TAG.OCTET_STRING, 'the statement'));
  const statement = readStatement(statementBytes);

  // The certificates, a list of withdrawn certificates (not used), and the one signer. Nothing else.
  let next = 3;
  const certificates = [];
  if (parts[next] && parts[next].tag === TAG.CONTEXT_0) {
    // A set of the signed data's own (RFC 5652 section 10.2.3), which CMS does
    // not require to be in DER order; each certificate inside it is DER (RFC
    // 5280 section 4.1), and is held to it when it is read.
    const items = children(token, parts[next], 8);
    for (const c of items) {
      // Other kinds of certificate may sit here; only the ordinary kind is read.
      if (c.tag === TAG.SEQUENCE) certificates.push(readCertificate(token, c));
    }
    next++;
  }
  if (parts[next] && parts[next].tag === TAG.CONTEXT_1) next++;
  if (next !== parts.length - 1) throw badStamp('the signed data holds parts that are not in the order its standard sets out.');
  const signers = children(token, expect(parts[next], TAG.SET, 'the signer'), 1);
  const signer = children(token, expect(signers[0], TAG.SEQUENCE, 'the signer'), 7);
  // Version 1 names the certificate by its issuer and number; version 3 by its key.
  const signerVersion = hexOf(token, expect(signer[0], TAG.INTEGER, 'the version of the signer'));
  if (!signer[1] || !((signerVersion === '01' && signer[1].tag === TAG.SEQUENCE) || (signerVersion === '03' && signer[1].tag === 0x80))) {
    throw badStamp('the signer is not named as its standard sets out.');
  }
  const digesting = algorithmOf(token, signer[2], 'the signer\'s fingerprint method');
  const digestName = HASHES[digesting.oid];
  const attributes = expect(signer[3], TAG.CONTEXT_0, 'the signed attributes');
  // A set under a tag of its own, in DER (RFC 5652 section 5.3), so its order,
  // and the order of every set inside it, is held to DER here.
  const attributeList = children(token, attributes, 16);
  if (!setInOrder(token, attributeList)) throw badStamp('the signed attributes are not in the order DER requires.');
  for (const a of attributeList) validateDer(token, a);
  const signing = algorithmOf(token, signer[4], 'the signing method');
  const signatureOid = signing.oid;
  const signature = contentOf(token, expect(signer[5], TAG.OCTET_STRING, 'the signature'));
  if (signer.length > 7 || (signer.length === 7 && signer[6].tag !== TAG.CONTEXT_1)) throw badStamp('the signer holds parts that are not in the order its standard sets out.');

  // What was stamped must be the fingerprint the checker holds.
  if (statement.hash !== OID.sha256 || !equalBytes(statement.stamped, fingerprintBytes)) {
    throw new Refusal('stamp-wrong-data', 'A time-stamp was made for something else.');
  }
  if (statement.critical) throw invalid('A time-stamp carries an extension that it says must be understood, and this checker does not understand it.');
  if (statement.accuracySeconds > MAX_ACCURACY_SECONDS) throw invalid('A time-stamp states its time too loosely: to no better than more than 300 seconds.');

  // The signed attributes must name the statement (its kind and its
  // fingerprint, RFC 5652 section 5.4) and the certificate that signed
  // (RFC 3161 section 2.4.2).
  if (!digestName) throw invalid('A time-stamp uses a fingerprint method that is not accepted.');
  let kindNamed = false;
  let digestNamed = false;
  let named = null;
  let newerNamed = false;
  let olderNamed = false;
  for (const attribute of attributeList) {
    const pair = children(token, expect(attribute, TAG.SEQUENCE, 'an attribute'), 2);
    const name = hexOf(token, expect(pair[0], TAG.OID, 'the name of an attribute'));
    const values = children(token, expect(pair[1], TAG.SET, 'the value of an attribute'), 4);
    if (name === OID.contentType) {
      if (kindNamed || values.length !== 1 || values[0].tag !== TAG.OID || hexOf(token, values[0]) !== OID.tstInfo) {
        throw invalid('A time-stamp\'s signature does not cover a time-stamp statement.');
      }
      kindNamed = true;
    } else if (name === OID.messageDigest) {
      if (digestNamed || values.length !== 1 || values[0].tag !== TAG.OCTET_STRING || !equalBytes(contentOf(token, values[0]), await digest(digestName, statementBytes))) {
        throw invalid('A time-stamp\'s signature does not cover its statement.');
      }
      digestNamed = true;
    } else if (name === OID.signingCertificateV2 || name === OID.signingCertificate) {
      if (values.length !== 1) throw invalid('A time-stamp does not say, in one way, which certificate signed it.');
      // Each form at most once: RFC 5035 section 3 for the newer form, and
      // for the older section 5.4.2 of RFC 2634 as RFC 5035 section 5 writes
      // it. Where both forms are present, the newer one is used: this
      // format's choice, where RFC 5035 section 7 lets a reader refuse a
      // time-stamp whose two forms disagree.
      const newer = name === OID.signingCertificateV2;
      if (newer ? newerNamed : olderNamed) throw invalid('A time-stamp names the certificate that signed it more than once in the same form, which its standard does not allow.');
      if (newer) newerNamed = true;
      else olderNamed = true;
      if (named === null || newer) named = signingCertificateOf(token, values[0], newer);
    }
  }
  if (!kindNamed || !digestNamed) throw invalid('A time-stamp\'s signature does not cover its statement.');
  if (named === null) throw invalid('A time-stamp does not say which certificate signed it.');

  // The one certificate the signed attributes name. A copy with the same
  // key and other contents has another fingerprint, and is not it.
  let certificate = null;
  for (const c of certificates) {
    if (equalBytes(await digest(named.hash, c.whole), named.value)) {
      certificate = c;
      break;
    }
  }
  if (!certificate) throw invalid(certificates.length ? 'A time-stamp does not carry the certificate it says signed it.' : 'A time-stamp carries no certificate to check it with.');

  // The signature covers the attributes, written as a set (RFC 5652 section
  // 5.4). The bytes are copied, so that the caller's time-stamp is not changed.
  const signed = new Uint8Array(wholeOf(token, attributes));
  signed[0] = TAG.SET;
  const state = await verifyWith(certificate, token, signatureOid, digestName, signature, signed, without, { signature: signing.parameters, digest: digesting.parameters });
  if (state === 'unavailable') return { state: 'unavailable', when: null, time: NaN, authority: null };
  if (state !== 'valid') throw invalid('A time-stamp\'s signature does not fit the certificate it names.');
  if (statement.time < certificate.notBefore || statement.time > certificate.notAfter) {
    throw invalid('A time-stamp is dated outside the time its service\'s certificate was in force.');
  }
  const authority = toBase64url(await sha256(certificate.whole));
  const trusted = Array.isArray(options.trusted) && options.trusted.includes(authority);
  return { state: trusted ? 'valid' : 'untrusted', when: formatTime(statement.time), time: statement.time, authority };
}
