// The Slip: the permission a person signs with a passkey.
// Format description, section 4.

import { actionKind, isNeverName } from './actions.js';
import { coverMembers, uncover } from './cover.js';
import { Refusal, fromBase64url, problemFrom, randomId, toBase64url } from './encoding.js';
import * as f from './fields.js';
import { encodeContent, parseRecord, protectedHeaders, signingInput, withinSize, KINDS } from './jws.js';
import { PASSKEY_METHODS, checkKey, checkKeySet, thumbprint } from './keys.js';
import { checkAssertion } from './webauthn.js';

const SLIP_MEMBERS = ['actions', 'agent', 'id', 'issuer', 'limits', 'never', 'purpose', 'requires', 'type', 'validFrom', 'validUntil', 'with'];
const LIMIT_KINDS = ['count', 'each', 'max'];
/** The longest period a limit may name: 366 days. */
const MAX_PERIOD_SECONDS = 366 * 86400;

// The address of the page a slip was signed on, by an exact rule that any
// checker can follow without a reader of web addresses or tables of
// Unicode: "https://" (or "http://" for localhost), a host, a port only if
// it is not the scheme's own, and nothing more. A host is labels of
// lower-case letters, digits and hyphens, separated by full stops; no label
// begins or ends with a hyphen, and the last is not all digits. A browser
// writes a page's address in exactly this form, with a name in another
// script written in its "xn--" form, which the rule takes as it is.
const ORIGIN = /^(https|http):\/\/([a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?$/;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

function checkOrigin(origin, rpId) {
  f.text(origin, 1, 300, 'issuer.origin');
  if (typeof rpId !== 'string' || !/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(rpId)) {
    throw f.fail('issuer.rpId', 'must be a website name in lower case, such as example.org.');
  }
  const m = ORIGIN.exec(origin);
  const labels = m ? m[2].split('.') : [];
  const port = m && m[3] !== undefined ? Number(m[3]) : null;
  if (!m || !labels.every((l) => LABEL.test(l)) || /^[0-9]+$/.test(labels[labels.length - 1]) || (port !== null && (port > 65535 || port === (m[1] === 'https' ? 443 : 80)))) {
    throw f.fail('issuer.origin', 'must be the address of a page: https://, a website name in lower case, a port only if it is needed, and nothing more, such as https://sign.example.org.');
  }
  const [, scheme, host] = m;
  if (!(scheme === 'https' || (scheme === 'http' && host === 'localhost'))) {
    throw f.fail('issuer.origin', 'must begin https://, or http://localhost.');
  }
  if (!(host === rpId || host.endsWith('.' + rpId))) {
    throw f.fail('issuer.origin', 'must be on the website that issuer.rpId names.');
  }
}

/** Not part of the public interface: for the shared test files. */
export const checkOriginForTests = checkOrigin;

/**
 * Confirm a list of limits against the actions it may name (format
 * description, section 4.1). A slip and a pass share it.
 * @param {string[]} actions
 * @param {any} limits
 * @returns {(action: string, unit: any, path: string) => void} a check that every amount for one action is in one unit, to use on what follows
 */
export function validateLimits(actions, limits) {
  // Every amount named for one action, in a limit or a condition, is in one
  // unit: a stub gives one amount.
  const units = new Map();
  const oneUnit = (action, unit, path) => {
    f.unit(unit, path);
    if (units.has(action) && units.get(action) !== unit) throw f.fail(path, 'every amount for one action must be in the same unit.');
    units.set(action, unit);
  };

  f.list(limits, 0, 64, 'limits');
  const limitsSeen = new Set();
  limits.forEach((limit, i) => {
    const p = `limits[${i}]`;
    f.members(limit, ['action'], ['count', 'each', 'max', 'per', 'unit'], p);
    if (!actions.includes(limit.action)) throw f.fail(`${p}.action`, 'must be one of the slip\'s actions.');
    const kinds = LIMIT_KINDS.filter((k) => Object.hasOwn(limit, k));
    if (kinds.length !== 1) throw f.fail(p, 'must hold exactly one of "max", "each" and "count".');
    const kind = kinds[0];
    f.wholeNumber(limit[kind], `${p}.${kind}`);
    if (kind === 'count') {
      if (Object.hasOwn(limit, 'unit')) throw f.fail(`${p}.unit`, 'a count of actions has no unit.');
      if (limit.count < 1) throw f.fail(`${p}.count`, 'must be 1 or more.');
    } else {
      if (!Object.hasOwn(limit, 'unit')) throw f.fail(p, '"unit" is missing.');
      oneUnit(limit.action, limit.unit, `${p}.unit`);
    }
    if (Object.hasOwn(limit, 'per')) {
      if (kind === 'each') throw f.fail(`${p}.per`, 'a limit on each action has no period.');
      f.wholeNumber(limit.per, `${p}.per`);
      if (limit.per < 1 || limit.per > MAX_PERIOD_SECONDS) throw f.fail(`${p}.per`, 'must be from 1 second to 366 days, in seconds.');
    }
    const key = `${limit.action} ${kind} ${limit.per ?? ''}`;
    if (limitsSeen.has(key)) throw f.fail(p, 'the same kind of limit is given twice for one action.');
    limitsSeen.add(key);
  });
  return oneUnit;
}

/** What a slip may cover: the names in it, and its purpose (format description, section 24). */
export const COVERABLE = ['issuer.name', 'agent.name', 'purpose', 'with.name'];

/**
 * Confirm every member of a slip's content (format description, section
 * 4.1).
 * @param {any} c the content, with every revealed field back in place
 * @param {Map<string, {covered: number, revealed: string[]}>} [places] where the signed content held covered fields (see uncover)
 * @param {boolean} [named] whether the signed content named its fingerprint method (see uncover)
 * @returns {string[]} the fields that are covered and were not revealed, for example "issuer.name"
 * @throws {Refusal} "bad-field" or "bad-key"
 */
export function validateSlipContent(c, places = new Map(), named = false) {
  // Only a name or the purpose may be covered, each in its own object. A
  // list of covered fields there holds exactly one fingerprint: that of the
  // one field. So a field is absent only where its fingerprint stands in
  // its place, and nothing can be shown as covered that is not.
  const coveredNow = [];
  const mayLack = (object, path, name) => {
    const place = places.get(path);
    if (!place || place.covered !== 1) return [];
    if (object !== null && typeof object === 'object' && Object.hasOwn(object, name)) {
      throw f.fail(path || 'slip', 'holds a field and, as well, a fingerprint that stands in for it.');
    }
    coveredNow.push(path === '' ? name : `${path}.${name}`);
    return [name];
  };
  for (const [path, place] of places) {
    const name = path === '' ? 'purpose' : path === 'issuer' || path === 'agent' || /^with\[\d+\]$/.test(path) ? 'name' : null;
    if (name === null || place.revealed.some((r) => r !== name)) {
      throw f.fail(path || 'slip', 'only a name or the purpose of a slip may be covered.');
    }
    if (place.covered + place.revealed.length !== 1) {
      throw f.fail(path || 'slip', 'a list of covered fields in a slip holds exactly one fingerprint.');
    }
  }
  if ((places.size > 0) !== named) throw f.fail('slip', '"_sd_alg" is given where a field is covered, and only there.');
  const lacksPurpose = mayLack(c, '', 'purpose');
  f.members(c, SLIP_MEMBERS.filter((m) => !lacksPurpose.includes(m)), ['passes'], 'slip');
  f.id(c.id, 'id');
  // How many times the permission may be passed on to a helper agent. Absent: not at all.
  if (Object.hasOwn(c, 'passes')) {
    f.wholeNumber(c.passes, 'passes');
    if (c.passes < 1 || c.passes > 10) throw f.fail('passes', 'must be from 1 to 10; leave it out if the permission may not be passed on.');
  }

  const lacksIssuerName = mayLack(c.issuer, 'issuer', 'name');
  f.members(c.issuer, ['key', 'name', 'origin', 'rpId'].filter((m) => !lacksIssuerName.includes(m)), [], 'issuer');
  if (!lacksIssuerName.length) f.label(c.issuer.name, 'issuer.name');
  checkKey(c.issuer.key, PASSKEY_METHODS, 'issuer.key');
  checkOrigin(c.issuer.origin, c.issuer.rpId);

  const lacksAgentName = mayLack(c.agent, 'agent', 'name');
  f.members(c.agent, ['keys', 'name'].filter((m) => !lacksAgentName.includes(m)), ['software'], 'agent');
  if (!lacksAgentName.length) f.label(c.agent.name, 'agent.name');
  checkKeySet(c.agent.keys, 'agent.keys');
  if (Object.hasOwn(c.agent, 'software')) {
    f.list(c.agent.software, 1, 16, 'agent.software');
    c.agent.software.forEach((s, i) => {
      f.members(s, ['name', 'sha256'], [], `agent.software[${i}]`);
      f.label(s.name, `agent.software[${i}].name`);
      f.fingerprintText(s.sha256, `agent.software[${i}].sha256`);
    });
  }

  f.list(c.actions, 1, 64, 'actions');
  c.actions.forEach((a, i) => f.actionName(a, `actions[${i}]`));
  if (new Set(c.actions).size !== c.actions.length) throw f.fail('actions', 'an action name is repeated.');

  const oneUnit = validateLimits(c.actions, c.limits);

  f.list(c.requires, 0, 64, 'requires');
  const requiresSeen = new Set();
  c.requires.forEach((r, i) => {
    const p = `requires[${i}]`;
    f.members(r, ['need'], ['above', 'action', 'unit'], p);
    if (r.need !== 'approval' && r.need !== 'countersignature') throw f.fail(`${p}.need`, 'must be "approval" or "countersignature".');
    if (Object.hasOwn(r, 'action') && !c.actions.includes(r.action)) throw f.fail(`${p}.action`, 'must be one of the slip\'s actions.');
    if (Object.hasOwn(r, 'above') !== Object.hasOwn(r, 'unit')) throw f.fail(p, '"above" and "unit" come together.');
    if (Object.hasOwn(r, 'above')) {
      if (!Object.hasOwn(r, 'action')) throw f.fail(p, '"above" needs an "action".');
      f.wholeNumber(r.above, `${p}.above`);
      oneUnit(r.action, r.unit, `${p}.unit`);
    }
    const key = `${r.need} ${r.action ?? ''}`;
    if (requiresSeen.has(key)) throw f.fail(p, 'the same condition is given twice.');
    requiresSeen.add(key);
  });

  f.list(c.never, 0, 16, 'never');
  c.never.forEach((n, i) => {
    if (!isNeverName(n)) throw f.fail(`never[${i}]`, 'must be a listed kind of action or a listed rule of conduct.');
  });
  if (new Set(c.never).size !== c.never.length) throw f.fail('never', 'a name is repeated.');
  for (const a of c.actions) {
    if (c.never.includes(actionKind(a))) throw f.fail('never', 'forbids a kind of action that the slip also allows.');
  }

  f.list(c.with, 0, 64, 'with');
  const ids = new Set();
  c.with.forEach((service, i) => {
    const lacksName = mayLack(service, `with[${i}]`, 'name');
    f.members(service, ['id', 'name'].filter((m) => !lacksName.includes(m)), ['keys'], `with[${i}]`);
    f.shortName(service.id, `with[${i}].id`);
    if (ids.has(service.id)) throw f.fail(`with[${i}].id`, 'a service id is repeated.');
    ids.add(service.id);
    if (!lacksName.length) f.label(service.name, `with[${i}].name`);
    if (Object.hasOwn(service, 'keys')) checkKeySet(service.keys, `with[${i}].keys`);
  });

  const from = f.time(c.validFrom, 'validFrom');
  const until = f.time(c.validUntil, 'validUntil');
  if (!(from < until)) throw f.fail('validUntil', 'must be later than validFrom.');
  if (!lacksPurpose.length) f.text(c.purpose, 1, 1000, 'purpose');
  return coveredNow;
}

/**
 * Check the passkey signature on a record (a slip or an approval) against
 * the issuer a slip names (format description, section 4.4).
 * @param {any} parsed what parseRecord returned
 * @param {{key: any, rpId: string, origin: string}} issuer
 * @param {string[]} [without] see verifySignature
 * @returns {Promise<'valid'|'unavailable'>}
 * @throws {Refusal}
 */
export async function checkPasskeySignature(parsed, issuer, without) {
  const only = parsed.signatures[0];
  let authenticatorData;
  let clientDataJSON;
  try {
    authenticatorData = fromBase64url(only.header.authenticatorData);
    clientDataJSON = fromBase64url(only.header.clientDataJSON);
  } catch {
    throw new Refusal('passkey-bad-data', 'The passkey values stored with the record are not base64url.');
  }
  return checkAssertion(
    {
      key: issuer.key,
      rpId: issuer.rpId,
      origin: issuer.origin,
      signedBytes: signingInput(only.protectedB64, parsed.payloadB64),
      authenticatorData,
      clientDataJSON,
      signature: only.signature,
    },
    without,
  );
}

/**
 * Build the challenge a passkey must sign for a record's content, and put
 * the passkey's answer with it. Used for slips and for approvals.
 * @param {'slip'|'approval'} kind
 * @param {any} content
 */
export async function preparePasskeyRecord(kind, content) {
  const { contentBytes, payloadB64 } = encodeContent(content);
  // Leave room for what the passkey returns, so the signed record still fits.
  withinSize({ payload: payloadB64, signatures: [{ signature: 'A'.repeat(2048) }] });
  const [protectedB64] = protectedHeaders(kind);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', signingInput(protectedB64, payloadB64));
  return { contentBytes, payloadB64, protectedB64, challenge: new Uint8Array(digest) };
}

/**
 * @typedef {object} SlipCheck
 * @property {'slip'} kind
 * @property {string|null} fingerprint
 * @property {{code: string, message: string}[]} problems reasons the slip cannot be relied on; empty if none
 * @property {string[]} notes things a person should know that are not faults
 * @property {{method: string, alg: string|null, state: 'valid'|'invalid'|'unavailable'|'unchecked'}} signature
 * @property {string|null} issuerKey the thumbprint of the passkey's public key
 * @property {any} content the slip's content, with revealed fields in place, or null if it could not be read
 * @property {string[]} covered the fields that are covered and were not revealed, for example "issuer.name"
 * @property {{code: string, message: string}[]} disclosureProblems why the disclosures handed over were not used, if they
 *   were not. The slip is then checked with those fields covered: what a slip is does not depend on what is handed over with it
 */

/**
 * Check one slip (format description, section 4.4).
 *
 * @param {any} record the slip as a JavaScript object
 * @param {object} [options]
 * @param {string[]} [options.issuerKeys] thumbprints of the issuer keys the checker expects
 * @param {string[]} [options.withoutMethods] see verifySignature
 * @param {Record<string, string[]>} [options.disclosures] for covered fields: the disclosures handed over, by the fingerprint of the record they belong to
 * @param {string[]} [disclosures] the disclosures for this slip, where they come with it (a page of a Show)
 * @returns {Promise<SlipCheck>}
 */
export async function checkSlip(record, options = {}, disclosures) {
  /** @type {SlipCheck} */
  const result = {
    kind: 'slip',
    fingerprint: null,
    problems: [],
    notes: [],
    signature: { method: 'passkey', alg: null, state: 'unchecked' },
    issuerKey: null,
    content: null,
    covered: [],
    disclosureProblems: [],
  };
  try {
    if (options === null || typeof options !== 'object') options = {};
    const parsed = await parseRecord(record, 'slip');
    result.fingerprint = parsed.fingerprint;
    // Covered fields: put back what was revealed, by the standard's own steps.
    const handed = options.disclosures;
    const beside = handed !== null && typeof handed === 'object' && Object.hasOwn(handed, parsed.fingerprint) ? handed[parsed.fingerprint] : [];
    // Those that come with the slip (a page of a Show) and those handed
    // over beside it are used together; one given both ways counts once.
    let forThis = disclosures ?? beside;
    if (disclosures !== undefined && Array.isArray(disclosures) && (!Array.isArray(beside) || beside.length > 0)) {
      forThis = Array.isArray(beside) ? [...disclosures, ...beside.filter((d) => !disclosures.includes(d))] : beside;
    }
    // A slip narrows the standard: no covered item of a list, and every
    // disclosure in the canonical form.
    const reveal = async (given) => {
      const { content, places, named } = await uncover(parsed.content, given, { listItems: false, canonical: true });
      return { content, covered: validateSlipContent(content, places, named) };
    };
    let read;
    try {
      read = await reveal(forThis);
    } catch (e) {
      // What a slip is must not depend on what is handed over with it. If
      // the slip is sound with its fields covered, the fault lies in the
      // disclosures: they are not used, and that is reported apart.
      if (Array.isArray(forThis) && forThis.length === 0) throw e;
      read = await reveal([]);
      result.disclosureProblems.push(problemFrom(e));
    }
    result.covered = read.covered;
    const content = read.content;
    result.content = content;
    const { issuer } = content;
    result.signature.method = `passkey (${issuer.key.alg})`;
    result.signature.alg = issuer.key.alg;
    result.issuerKey = await thumbprint(issuer.key);

    result.signature.state = 'invalid';
    // As everywhere else, only a list counts as a list of methods to treat as not built in.
    result.signature.state = await checkPasskeySignature(parsed, issuer, Array.isArray(options.withoutMethods) ? options.withoutMethods : []);
    if (result.signature.state === 'unavailable') {
      result.notes.push(`This device cannot check the passkey's signing method (${issuer.key.alg}).`);
    }

    if (Array.isArray(options.issuerKeys)) {
      if (!options.issuerKeys.includes(result.issuerKey)) {
        throw new Refusal('issuer-not-expected', 'The slip was signed by a passkey other than the ones expected.');
      }
    } else {
      result.notes.push('The issuer\'s key was not compared with a key you already trust. The name on the slip is only a label.');
    }
  } catch (e) {
    result.problems.push(problemFrom(e));
  }
  return result;
}

// --- writing a slip ---

/**
 * Build the content of a new slip and the challenge a passkey must sign
 * (format description, section 4.2, steps 1 and 2).
 *
 * @param {object} fields every member of the slip except "type"; "id" is made if absent
 * @param {object} [options]
 * @param {string[]} [options.cover] the fields to cover, from COVERABLE: "issuer.name", "agent.name", "purpose", and "with.name" for the name of every service
 * @returns {Promise<{contentBytes: Uint8Array, payloadB64: string, protectedB64: string, challenge: Uint8Array, disclosures: string[]}>}
 *   "disclosures" reveal the covered fields. Keep them beside the slip, and hand over only the ones a reader needs.
 */
export async function prepareSlip(fields, options = {}) {
  // A slip with no conditions and no prohibitions says so with empty lists.
  let content = { requires: [], never: [], ...fields, type: KINDS.slip.type, id: fields.id ?? randomId() };
  validateSlipContent(content);
  const cover = Array.isArray(options.cover) ? options.cover : [];
  if (cover.some((name) => !COVERABLE.includes(name))) throw f.fail('cover', 'only a name or the purpose of a slip may be covered.');
  const disclosures = [];
  const hide = async (object, names) => {
    const covered = await coverMembers(object, names);
    disclosures.push(...covered.disclosures);
    return covered.object;
  };
  if (cover.includes('issuer.name')) content.issuer = await hide(content.issuer, ['name']);
  if (cover.includes('agent.name')) content.agent = await hide(content.agent, ['name']);
  if (cover.includes('with.name')) content.with = await Promise.all(content.with.map((service) => hide(service, ['name'])));
  if (cover.includes('purpose')) content = await hide(content, ['purpose']);
  // The fingerprint method is named, as the standard allows, wherever anything is covered.
  if (disclosures.length) content._sd_alg = 'sha-256';
  return { ...(await preparePasskeyRecord('slip', content)), disclosures };
}

/**
 * Put the passkey's three values with the prepared content: the signed slip
 * (format description, sections 4.2 step 4 and 4.3). The values are stored
 * exactly as the passkey returned them.
 *
 * @param {{payloadB64: string, protectedB64: string}} prepared from prepareSlip
 * @param {{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array}} assertion
 * @returns {object} the slip record
 */
export function assembleSlip(prepared, assertion) {
  return withinSize({
    payload: prepared.payloadB64,
    signatures: [
      {
        protected: prepared.protectedB64,
        header: {
          authenticatorData: toBase64url(assertion.authenticatorData),
          clientDataJSON: toBase64url(assertion.clientDataJSON),
        },
        signature: toBase64url(assertion.signature),
      },
    ],
  });
}
