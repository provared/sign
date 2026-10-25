// A witness: a party, with a key set of its own, that keeps, for each
// person, agent and recorder, the latest seal it has signed for, and signs
// a statement for a new seal only if the new seal extends that one: in the
// same book, or as the first seal of the next book.
// Format description, section 29.3.
//
// This is the part of a witness that decides and signs. Keeping its state
// on a disk, and taking seals over a network, are the business of whoever
// runs it. Its state is handed back with every statement, and MUST be saved
// before the statement is given out: a witness that loses its state can be
// made to sign a fork.
//
// A witness checks a seal's three signatures, so it needs SLH-DSA. Where
// the device does not have it built in, it signs nothing.

import { checkSealAlone } from './book.js';
import { Refusal, canonicalJson, fingerprint, fromBase64url, fromUtf8, parseCanonical, parseTime, problemFrom, utf8 } from './encoding.js';
import * as f from './fields.js';
import { encodeContent, parseRecord, signingInput } from './jws.js';
import { PASSKEY_METHODS, checkKey, checkKeySet, checkSealKeySet, thumbprint } from './keys.js';
import { CLOCK_ALLOWANCE_MS, keySetFingerprint } from './seal.js';
import { verifySignature } from './signatures.js';
import { consistencyProof, inclusionPath, verifyConsistency, verifyInclusion } from './tree.js';
import { MAX_WITNESSES, validateWitnessContent, writeWitness } from './witness.js';

/** The "type" of a witness's saved state. */
export const WITNESS_STATE_TYPE = 'provared.witness-state.v0';

/**
 * How a witness knows which books are one sequence: by the fingerprint of
 * the recorder's key set, with the passkey and the agent that the
 * permission (the slip) on the book's first line names: the thumbprint of
 * its passkey key (RFC 7638) and the fingerprint of the agent's key set.
 * So every permission one person gives one agent, under one recorder, is
 * one sequence, renewals included, and a book that starts with a later
 * permission must follow on from the seal the witness holds, as any new
 * book (section 21.6). This is not written into any record.
 * @param {object[]} keys the recorder's key set, as a seal gives it
 * @param {Uint8Array} firstLine the bytes of the book's first line, without its line feed: a permission
 * @returns {Promise<string>} a fingerprint, in base64url
 */
export async function bookIdentity(keys, firstLine) {
  checkSealKeySet(keys, 'keys');
  return identityOf(await keySetFingerprint(keys), await sequenceOf(firstLine));
}

// The fingerprint of {"agent": the agent's key set fingerprint, "passkey": the passkey's thumbprint, "recorder": the
// recorder's key set fingerprint}, written in the canonical form.
const identityOf = async (recorder, { agent, passkey }) => fingerprint(encodeContent({ agent, passkey, recorder }).contentBytes);

// The passkey and the agent that the permission on a book's first line names. The passkey's signature is not
// checked here: a witness knows a sequence by them, and a reader counts a statement only where the permission
// passed and its passkey is one they named. A central sealer reads a book's first line the same way (sealer.js).
export async function sequenceOf(firstLine) {
  if (!(firstLine instanceof Uint8Array) || firstLine.length === 0) throw f.fail('firstLine', 'must be the bytes of the book\'s first line.');
  if (firstLine[firstLine.length - 1] === 0x0a || firstLine[firstLine.length - 1] === 0x0d) {
    throw f.fail('firstLine', 'must be the book\'s first line without its line feed.');
  }
  let value;
  try {
    value = parseCanonical(fromUtf8(firstLine, 'line-not-canonical'), 'line-not-canonical');
  } catch {
    throw new Refusal('slip-missing', 'The book\'s first line is not a line of a book in its one written form, so it is not a permission. A book starts with its permission.');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 1 || !Object.hasOwn(value, 'slip')) {
    throw new Refusal('slip-missing', 'The book\'s first line is not a permission, an entry that holds only a slip. A book starts with its permission.');
  }
  const c = (await parseRecord(value.slip, 'slip')).content;
  try {
    checkKey(c.issuer.key, PASSKEY_METHODS, 'issuer.key');
    checkKeySet(c.agent.keys, 'agent.keys');
  } catch {
    throw new Refusal('slip-unusable', 'The permission on the book\'s first line does not name a passkey key and an agent\'s key set in the forms a slip gives them.');
  }
  return { passkey: await thumbprint(c.issuer.key), agent: await keySetFingerprint(c.agent.keys) };
}

// A seal's book number (section 21.6): absent is the first book.
const numberOf = (content) => (Object.hasOwn(content, 'book') ? content.book : 1);

/**
 * What a witness needs to be sent with a seal: where it holds an earlier
 * seal of the same book, the consistency proof from that seal's number of
 * entries to the new seal's (RFC 9162, section 2.1.4.1); where it holds
 * none, or the new seal is the first of the next book, the audit path of
 * the book's first line in the new seal's tree (section 2.1.3), which ties
 * the first line to the seal.
 * @param {string} book the book, as text
 * @param {number} size the new seal's number of entries
 * @param {number|null} [from] the number of entries of the seal the witness holds of this book, or null for none
 *   (and for the first seal of the next book)
 * @returns {Promise<Uint8Array[]>}
 */
export async function witnessProof(book, size, from = null) {
  const lines = book.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  if (!Number.isSafeInteger(size) || size < 1 || size > lines.length) throw new RangeError('the book has no such number of entries');
  const leaves = lines.slice(0, size).map(utf8);
  if (from === null || from === undefined) return inclusionPath(leaves, 0);
  return consistencyProof(leaves, from);
}

const refused = (code, message) => ({ refused: { code, message } });

/**
 * Open a witness.
 *
 * @param {object} o
 * @param {{keys: object[], name: string}} o.by the witness's public key set (Ed25519, then ML-DSA-87) and its name (a label)
 * @param {any[]} o.signers the witness's private keys, or signers (signatures.js), in the order of the key set
 * @param {object} [o.state] the state a witness handed back before, as saved. A witness opened with a state signs
 *   nothing until it has been brought up to date (update) and told so (ready)
 * @param {() => number} [o.clock] the time now, in milliseconds since 1970; Date.now by default
 * @param {string[]} [o.withoutMethods] signing methods to treat as not built into this device
 * @returns {Promise<object>} the witness: witness, update, ready, latest, state
 */
export async function openWitness({ by, signers, state, clock = Date.now, withoutMethods = [] } = {}) {
  f.members(by, ['keys', 'name'], [], 'by');
  f.label(by.name, 'by.name');
  checkKeySet(by.keys, 'by.keys');
  if (!Array.isArray(signers) || signers.length !== 2) throw f.fail('signers', 'must be the witness\'s two private keys, or signers: Ed25519, then ML-DSA-87.');
  if (typeof clock !== 'function') throw f.fail('clock', 'must be a function that gives the time now.');
  if (!Array.isArray(withoutMethods)) throw f.fail('withoutMethods', 'must be a list of signing methods.');
  // Copied once, so that nothing done to them afterwards changes the witness.
  const me = JSON.parse(canonicalJson({ keys: by.keys, name: by.name }));
  const mine = canonicalJson(me.keys);
  const meFingerprint = await keySetFingerprint(me.keys);
  const keys = signers.slice();
  const without = withoutMethods.slice();

  /** @type {Map<string, {sequence: {passkey: string, agent: string}, seal: object, statement: object, fingerprint: string, content: any}>} */
  const books = new Map();
  let ready = true;
  if (state !== undefined) {
    await restore(state);
    ready = false;
  }

  // The calls wait for one another, so that two seals of one book are never weighed at the same time.
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const run = turn.then(work);
    turn = run.catch(() => {});
    return run;
  };

  function snapshot() {
    return {
      type: WITNESS_STATE_TYPE,
      by: meFingerprint,
      books: [...books.values()].map((b) => ({ passkey: b.sequence.passkey, agent: b.sequence.agent, seal: structuredClone(b.seal), statement: structuredClone(b.statement) })),
    };
  }

  // A statement by this witness, for this seal, that checks: or why not.
  async function ownStatement(record, seal) {
    const parsed = await parseRecord(record, 'witness');
    validateWitnessContent(parsed.content);
    const c = parsed.content;
    if (canonicalJson(c.by.keys) !== mine) throw new Refusal('witness-invalid', 'The statement is not signed with this witness\'s keys.');
    if (c.seal !== seal.fingerprint || c.size !== seal.content.size || c.root !== seal.content.root) {
      throw new Refusal('witness-invalid', 'The statement speaks of another seal.');
    }
    for (let i = 0; i < parsed.signatures.length; i++) {
      const s = parsed.signatures[i];
      const checked = await verifySignature(c.by.keys[i], s.signature, signingInput(s.protectedB64, parsed.payloadB64), without);
      if (checked !== 'valid') throw new Refusal('witness-invalid', 'A signature on the statement does not check on this device.');
    }
    return parsed;
  }

  async function restore(saved) {
    if (saved === null || typeof saved !== 'object' || Array.isArray(saved)) throw f.fail('state', 'must be a state a witness handed back.');
    f.members(saved, ['books', 'by', 'type'], [], 'state');
    if (saved.type !== WITNESS_STATE_TYPE) throw f.fail('state.type', `must be ${WITNESS_STATE_TYPE}.`);
    if (saved.by !== meFingerprint) throw f.fail('state.by', 'is the state of another witness: its key set is not this witness\'s.');
    if (!Array.isArray(saved.books)) throw f.fail('state.books', 'must be a list.');
    for (let i = 0; i < saved.books.length; i++) {
      const b = saved.books[i];
      f.members(b, ['agent', 'passkey', 'seal', 'statement'], [], `state.books[${i}]`);
      f.fingerprintText(b.passkey, `state.books[${i}].passkey`);
      f.fingerprintText(b.agent, `state.books[${i}].agent`);
      const sequence = { passkey: b.passkey, agent: b.agent };
      const seal = await checkSealAlone(b.seal, without);
      if (seal.problems.length > 0) throw new Refusal(seal.problems[0].code, `The seal of book ${i + 1} in the state does not pass its check. ${seal.problems[0].message}`);
      await ownStatement(b.statement, seal);
      const identity = await identityOf(await keySetFingerprint(seal.content.by.keys), sequence);
      if (books.has(identity)) throw f.fail(`state.books[${i}]`, 'the same person, agent and recorder are given twice.');
      books.set(identity, { sequence, seal: structuredClone(b.seal), statement: structuredClone(b.statement), fingerprint: seal.fingerprint, content: seal.content });
    }
  }

  // Everything that must hold before this witness takes a seal of a book,
  // whether it is to sign for it (witness) or has signed for it before
  // (update). Returns what it found, or a refusal.
  async function weigh(entry, proof, firstLine, signing) {
    try {
      f.members(entry, ['seal'], ['stamps', 'witnesses'], 'entry');
    } catch (e) {
      return { refused: problemFrom(e) };
    }
    if (!(firstLine instanceof Uint8Array) || firstLine.length === 0) return refused('bad-field', 'The book\'s first line must be given as its bytes, without its line feed.');
    if (!Array.isArray(proof)) return refused('proof-invalid', 'The proof must be a list of fingerprints, each 32 bytes.');
    const path = [];
    for (let i = 0; i < proof.length; i++) {
      if (!(proof[i] instanceof Uint8Array) || proof[i].length !== 32) return refused('proof-invalid', 'The proof must be a list of fingerprints, each 32 bytes.');
      path.push(proof[i]);
    }
    const seal = await checkSealAlone(entry.seal, without);
    if (seal.problems.length > 0) return refused(seal.problems[0].code, `The seal did not pass its check. ${seal.problems[0].message}`);
    if (seal.signatures.some((s) => s.state !== 'valid')) {
      return refused('check-failed', 'A witness signs only for a seal whose three signatures it checked, and this device could not check them all.');
    }
    const c = seal.content;
    let sequence;
    try {
      sequence = await sequenceOf(firstLine);
    } catch (e) {
      return { refused: problemFrom(e) };
    }
    const identity = await identityOf(await keySetFingerprint(c.by.keys), sequence);
    const held = books.get(identity) ?? null;
    if (held && held.fingerprint === seal.fingerprint) return { seal, identity, sequence, held, same: true };
    const root = fromBase64url(c.root);
    const firstLineTied = () => verifyInclusion(0, c.size, firstLine, path, root);
    const number = numberOf(c);
    if (held) {
      const heldNumber = numberOf(held.content);
      if (number < heldNumber) {
        return refused('seal-mismatch', `The seal is of book ${number}, and this witness holds a seal of book ${heldNumber} of this person, agent and recorder. It signs for no seal of an earlier book again.`);
      }
      if (number > heldNumber + 1) {
        return refused('seal-chain-broken', `The seal is of book ${number}, and the latest seal this witness holds of this person, agent and recorder is of book ${heldNumber}: the books between were not shown to it. Hand it their seals first, in their order.`);
      }
      if (number === heldNumber) {
        if (c.size <= held.content.size) {
          return refused('seal-mismatch', `This witness holds a seal of this book with ${held.content.size} entries. It signs for no other seal of this book that does not extend that one.`);
        }
        if (signing && (Object.hasOwn(c, 'previous') ? c.previous : null) !== held.fingerprint) {
          return refused('seal-chain-broken', 'The seal does not name, as the seal before it, the latest seal of this book this witness signed for. Hand it the seals in between first, in their order.');
        }
        if (!(await verifyConsistency(held.content.size, c.size, fromBase64url(held.content.root), root, path))) {
          return refused('proof-invalid', 'The consistency proof does not show that the seal extends the latest seal of this book this witness signed for.');
        }
      } else {
        // The first seal of the next book: it starts from the latest seal the witness holds of the book before.
        if (c.previous !== held.fingerprint) {
          return refused('seal-chain-broken', `The first seal of book ${number} must name, as the seal before it, the latest seal this witness holds of book ${heldNumber}. Hand it the seals in between first, in their order.`);
        }
        if (!(await firstLineTied())) {
          return refused('proof-invalid', 'The proof does not show that the line given as the book\'s first is the first entry of the book the seal covers.');
        }
      }
      if (signing && parseTime(c.when) < parseTime(held.content.when)) return refused('time-went-backwards', 'The seal is dated before the latest seal of this person, agent and recorder this witness signed for.');
    } else if (!(await firstLineTied())) {
      return refused('proof-invalid', 'The proof does not show that the line given as the book\'s first is the first entry of the book the seal covers.');
    }
    return { seal, identity, sequence, held, same: false };
  }

  return {
    /**
     * Sign a statement for a seal, if it extends the latest seal of its book
     * that this witness holds; or say why not. The state handed back already
     * holds the new seal: save it before the statement is given out.
     * @param {{seal: object, stamps?: any[], witnesses?: any[]}} entry the seal's entry; only "seal" is read
     * @param {Uint8Array[]} proof see witnessProof
     * @param {Uint8Array} firstLine the bytes of the book's first line
     * @returns {Promise<{statement: object, state: object} | {refused: {code: string, message: string}}>}
     */
    witness(entry, proof, firstLine) {
      return inTurn(async () => {
        if (!ready) {
          return refused('witness-not-ready', 'This witness was opened from a saved state, and has not been brought up to date and told so. It signs nothing until then.');
        }
        const found = await weigh(entry, proof, firstLine, true);
        if (found.refused) return found;
        const { seal, identity, sequence, same } = found;
        // The same seal again: the same statement, with no second signature.
        if (same) return { statement: structuredClone(found.held.statement), state: snapshot() };
        let now;
        try {
          now = clock();
        } catch {
          now = NaN;
        }
        if (typeof now !== 'number' || !Number.isFinite(now)) return refused('check-failed', 'The witness\'s clock did not give a time.');
        if (parseTime(seal.content.when) > now + CLOCK_ALLOWANCE_MS) return refused('time-went-backwards', 'The seal is dated more than 300 seconds after this witness\'s clock.');
        let statement;
        try {
          ({ record: statement } = await writeWitness({ seal: seal.fingerprint, size: seal.content.size, root: seal.content.root, by: me, when: now }, keys));
          // Every signature is checked before the statement is given out or kept.
          await ownStatement(statement, seal);
        } catch (e) {
          const p = problemFrom(e);
          return refused('check-failed', `The witness could not sign a statement that checks, so it signed none. ${p.message}`);
        }
        books.set(identity, { sequence, seal: structuredClone(entry.seal), statement, fingerprint: seal.fingerprint, content: seal.content });
        return { statement: structuredClone(statement), state: snapshot() };
      });
    },

    /**
     * Bring the witness up to date: hand it a seal's entry that holds a
     * statement this witness signed for that seal, from wherever what it
     * gave out was kept (the book, or a copy kept apart from its state). It
     * takes that seal as the latest of its book, where the seal extends the
     * one it holds. It signs nothing.
     * @param {{seal: object, witnesses: any[], stamps?: any[]}} entry
     * @param {Uint8Array[]} proof see witnessProof
     * @param {Uint8Array} firstLine
     * @returns {Promise<{state: object} | {refused: {code: string, message: string}}>}
     */
    update(entry, proof, firstLine) {
      return inTurn(async () => {
        const found = await weigh(entry, proof, firstLine, false);
        if (found.refused) return found;
        const { seal, identity, sequence, same } = found;
        const list = entry.witnesses;
        if (!Array.isArray(list) || list.length < 1 || list.length > MAX_WITNESSES) return refused('witness-invalid', 'The entry holds no statement by this witness for the seal.');
        let statement = null;
        for (let i = 0; i < list.length && statement === null; i++) {
          try {
            await ownStatement(list[i], seal);
            statement = JSON.parse(canonicalJson(list[i]));
          } catch {
            // Another witness's statement, or one that does not check: not this witness's.
          }
        }
        if (statement === null) return refused('witness-invalid', 'The entry holds no statement by this witness for the seal.');
        // The seal it holds already: nothing changes.
        if (same) return { state: snapshot() };
        books.set(identity, { sequence, seal: structuredClone(entry.seal), statement, fingerprint: seal.fingerprint, content: seal.content });
        return { state: snapshot() };
      });
    },

    /**
     * Say that the witness, opened from a saved state, has been brought up
     * to date. The witness cannot tell whether a state is the latest it
     * handed back: this is the word of whoever runs it.
     */
    ready() {
      ready = true;
    },

    /**
     * The latest seal of a book that this witness holds, with its statement.
     * @param {string} book the book's fingerprint, as bookIdentity gives it
     * @returns {{seal: object, statement: object} | null}
     */
    latest(book) {
      const held = typeof book === 'string' ? books.get(book) : undefined;
      return held ? { seal: structuredClone(held.seal), statement: structuredClone(held.statement) } : null;
    },

    /** The witness's state as it stands, to be saved. */
    state() {
      return snapshot();
    },
  };
}
