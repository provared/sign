// Covered fields: a record can be shown with some fields hidden, while its
// signatures still check. The method is the standard "Selective Disclosure
// for JSON Web Tokens" (RFC 9901), as it stands:
//
//   - a field to be covered is taken out of the signed content, and the
//     fingerprint of a "disclosure" is put in its place, in a list named
//     "_sd" (section 4.2.4.1);
//   - a disclosure is a salt (a random value), the field's name and its
//     value, written as a JSON list and then in base64url (section 4.2.1);
//   - the fingerprint is taken over the base64url text itself (section 4.2.3);
//   - to reveal the field, hand over the disclosure; to hide it, do not.
//
// Format description, section 24.

import { Refusal, canonicalJson, fromBase64url, fromUtf8, parseCanonical, randomId, sha256, toBase64url, utf8 } from './encoding.js';

/** The most disclosures one record may come with. */
export const MAX_DISCLOSURES = 64;

const MAX_DEPTH = 12;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function bad(why) {
  return new Refusal('cover-invalid', `A covered field is not as its standard sets out: ${why}`);
}

/**
 * The fingerprint of a disclosure: SHA-256 over the characters of its
 * base64url text, written in base64url (RFC 9901, section 4.2.3).
 * @param {string} disclosure
 * @returns {Promise<string>}
 */
export async function disclosureDigest(disclosure) {
  return toBase64url(await sha256(utf8(disclosure)));
}

/**
 * Make the disclosure for one member of an object (RFC 9901, section 4.2.1).
 * @param {string} name the member's name
 * @param {any} value the member's value
 * @param {string} [salt] 128 random bits in base64url; made if absent
 * @returns {Promise<{disclosure: string, digest: string}>}
 */
export async function makeDisclosure(name, value, salt = randomId()) {
  const disclosure = toBase64url(utf8(canonicalJson([salt, name, value])));
  return { disclosure, digest: await disclosureDigest(disclosure) };
}

/**
 * Take the named members out of an object and leave the fingerprints of
 * their disclosures in its "_sd" list, sorted, so that their order says
 * nothing (RFC 9901, section 4.2.4.1).
 * @param {object} object the object; it is not changed
 * @param {string[]} names the members to cover; one that is absent is skipped
 * @returns {Promise<{object: object, disclosures: string[]}>}
 */
export async function coverMembers(object, names) {
  const out = { ...object };
  const digests = Array.isArray(out._sd) ? [...out._sd] : [];
  const disclosures = [];
  for (const name of names) {
    if (!Object.hasOwn(out, name)) continue;
    const made = await makeDisclosure(name, out[name]);
    delete out[name];
    digests.push(made.digest);
    disclosures.push(made.disclosure);
  }
  if (digests.length) out._sd = digests.sort();
  return { object: out, disclosures };
}

/**
 * Put back what the disclosures reveal, by the steps of RFC 9901, section
 * 7.1, step 3 to step 5.
 *
 * @param {any} payload the signed content, read from JSON
 * @param {string[]} [disclosures] the disclosures handed over with it
 * @param {object} [rules] what a kind of record narrows. A Provared slip sets both.
 * @param {boolean} [rules.listItems] false to refuse a covered item of a list, which the standard allows
 * @param {boolean} [rules.canonical] true to refuse a disclosure that is not JSON in the canonical form,
 *   so that two checkers cannot read one disclosure in two ways
 * @returns {Promise<{content: any, places: Map<string, {covered: number, revealed: string[]}>, named: boolean}>}
 *   "content" is the content with every revealed field back in place and
 *   every "_sd" list, covered list item and "_sd_alg" removed. "places"
 *   says, for each object that held an "_sd" list, by its path ("" for the
 *   top, "issuer", "with[0]"), how many fields are still covered there and
 *   which were revealed. "named" says whether the content named its
 *   fingerprint method ("_sd_alg").
 * @throws {Refusal} "cover-invalid"
 */
export async function uncover(payload, disclosures = [], rules = {}) {
  const listItems = rules.listItems !== false;
  const canonical = rules.canonical === true;
  if (!Array.isArray(disclosures) || disclosures.length > MAX_DISCLOSURES) throw bad('the disclosures must be a list of at most 64.');
  // Each disclosure, by its fingerprint.
  const given = new Map();
  // Read place by place, never through the list's own way of walking through itself.
  for (let i = 0; i < disclosures.length; i++) {
    const d = disclosures[i];
    if (typeof d !== 'string' || d.length === 0 || d.length > 87384) throw bad('a disclosure must be text in base64url.');
    let parts;
    try {
      const text = fromUtf8(fromBase64url(d), 'cover-invalid');
      parts = canonical ? parseCanonical(text, 'cover-invalid') : JSON.parse(text);
    } catch {
      throw bad(canonical ? 'a disclosure is not JSON in the canonical form, written in base64url.' : 'a disclosure is not JSON written in base64url.');
    }
    if (!Array.isArray(parts) || (parts.length !== 2 && parts.length !== 3) || typeof parts[0] !== 'string') {
      throw bad('a disclosure must be a list of a salt and a value, or of a salt, a name and a value.');
    }
    const digest = await disclosureDigest(d);
    if (given.has(digest)) throw bad('a disclosure is handed over twice.');
    given.set(digest, { parts, used: false });
  }

  const seen = new Set();
  const places = new Map();
  const once = (digest) => {
    // A fingerprint is SHA-256 in base64url: 43 characters, and nothing else.
    let bytes = null;
    try {
      bytes = typeof digest === 'string' && digest.length === 43 ? fromBase64url(digest) : null;
    } catch {
      bytes = null;
    }
    if (bytes === null || bytes.length !== 32) throw bad('a fingerprint in the content is not a SHA-256 fingerprint in base64url.');
    // Step 4: a fingerprint may appear only once in the whole content.
    if (seen.has(digest)) throw bad('the same fingerprint appears twice in the content.');
    seen.add(digest);
    return given.get(digest);
  };

  // A member is always put in place as a member of its own, whatever its
  // name. Plain assignment would let a member named "__proto__" replace the
  // object's prototype: the member would then be hidden from every check of
  // which members an object holds, and what it held would be inherited.
  const put = (object, name, member) => Object.defineProperty(object, name, { value: member, enumerable: true, writable: true, configurable: true });

  let named = false;
  const walk = (value, path, depth) => {
    if (depth > MAX_DEPTH) throw bad('the content is nested too deeply.');
    if (Array.isArray(value)) {
      const out = [];
      value.forEach((item, i) => {
        const keys = isObject(item) ? Object.keys(item) : [];
        if (keys.length === 1 && keys[0] === '...') {
          if (!listItems) throw bad('an item of a list may not be covered in this kind of record.');
          const found = once(item['...']);
          // A covered list item with no disclosure is left out (step 3d).
          if (!found) return;
          if (found.parts.length !== 2) throw bad('the disclosure of a list item must hold a salt and a value.');
          found.used = true;
          out.push(walk(found.parts[1], `${path}[${i}]`, depth + 1));
        } else {
          out.push(walk(item, `${path}[${i}]`, depth + 1));
        }
      });
      return out;
    }
    if (!isObject(value)) return value;
    const out = {};
    for (const [name, member] of Object.entries(value)) {
      if (name === '_sd') continue;
      if (name === '_sd_alg') {
        // The fingerprint method is named at the top only, and is SHA-256.
        if (path !== '' || member !== 'sha-256') throw bad('"_sd_alg" may stand only at the top, and must be "sha-256".');
        named = true;
        continue;
      }
      put(out, name, walk(member, path === '' ? name : `${path}.${name}`, depth + 1));
    }
    if (Object.hasOwn(value, '_sd')) {
      if (!Array.isArray(value._sd)) throw bad('"_sd" must be a list of fingerprints.');
      const place = { covered: 0, revealed: [] };
      for (const digest of value._sd) {
        const found = once(digest);
        if (!found) {
          place.covered++;
          continue;
        }
        if (found.parts.length !== 3) throw bad('the disclosure of a named field must hold a salt, a name and a value.');
        const name = found.parts[1];
        if (typeof name !== 'string' || name === '_sd' || name === '...' || name === '_sd_alg') throw bad('a disclosure names a field that may not be covered.');
        if (Object.hasOwn(out, name)) throw bad('a disclosure names a field that is already there.');
        found.used = true;
        put(out, name, walk(found.parts[2], path === '' ? name : `${path}.${name}`, depth + 1));
        place.revealed.push(name);
      }
      places.set(path, place);
    }
    return out;
  };

  const content = walk(payload, '', 0);
  // Step 5: every disclosure handed over must belong to this content.
  for (const d of given.values()) if (!d.used) throw bad('a disclosure does not belong to this record.');
  return { content, places, named };
}
