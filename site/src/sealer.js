// The central sealer: a party, run apart from whoever runs the agent, that
// holds a recorder's three keys and seals books it never sees. It is sent
// the leaf fingerprint of each new line (RFC 6962, section 2.1: the SHA-256
// of the byte 0x00 and the line), never the line. It keeps for each book
// the same running tree the checker's tree builder keeps (one fingerprint
// for each complete part of the tree), extended only by what it was sent,
// and on request signs a seal over its own tree: its own number of entries
// and its own top fingerprint, naming its own latest seal of that book.
// Format description, section 21.7.
//
// It cannot be made to sign a number of entries and a top fingerprint
// handed to it, nor a history that changes a line it has sealed (choice
// 388). Every book that starts with the same first line is one chain: a
// book with a first line it already holds may start only as the next book
// after the latest book with that first line. A seal it signs is added to
// the book through the stub writer's "add", which checks it against the
// whole book: a sealer that was sent a wrong fingerprint signs a seal the
// book refuses (seal-mismatch).
//
// One sealer may serve several recorders (forRecorder): each book, and
// every book that follows it, belongs to the recorder that started it, and
// no other recorder can send lines for it, seal it, bring it up to date,
// start a book after it or start a book with its first line. A recorder may
// be given rules: the agents whose permissions it may start books with (by
// the fingerprint of the agent's key set), and the most books it may hold.
// Where any recorder has a list of agents, every book is started with its
// first line itself, which must be a permission; one whose agent a
// recorder's list names is started only by that recorder. So no recorder
// can start a book whose first line is a permission for another recorder's
// agent.
//
// What it cannot see: the lines after the first. So it cannot tell that a
// book which starts from another first line repeats the lines of a book it
// has sealed. Nor, so, that a recorder started a book from a permission for
// its own agent and copied into it another recorder's agent's permissions
// and stubs, some left out: it seals such a book, which reads as intact
// and within its slips where one person's passkey signed the permissions
// for both agents. A seal of the other recorder's own book, held elsewhere
// and handed to the checker with it, shows a problem (book-cut-short or
// seal-not-in-book; or, where the two books' numbers differ, it cannot be
// compared, and gives no pass); a witness statement on such a seal is not counted
// (section 29). Readers of books from a shared sealer hold the recorder's
// own seals elsewhere, or use a sealer for each recorder.
//
// This is the part that keeps the trees and signs. Keeping its state on a
// disk, and taking requests over a network, are the business of whoever
// runs it (the program in sealer/ does both). Its state is handed back with
// every change that must last (a book started, a seal, a book brought up
// to date), and MUST be saved before the answer is given out: a sealer that
// loses its state can be made to sign a second history. Lines that no seal
// covers are not kept in the state: a sealer opened again stands at each
// book's latest seal (or, for a book with no seal, at its first line) and
// asks for the lines since.
//
// It checks every seal it signs, so it needs SLH-DSA: it opens only where
// the device has all three methods built in (Node.js).

import { MAX_ENTRIES, MAX_LINE_BYTES, checkSealAlone, entryLine } from './book.js';
import { Refusal, canonicalJson, formatTime, fromBase64url, parseTime, problemFrom, toBase64url, utf8 } from './encoding.js';
import * as f from './fields.js';
import { SEAL_METHODS, checkSealKeySet } from './keys.js';
import { CLOCK_ALLOWANCE_MS, decodeStamps, keySetFingerprint, sealOver } from './seal.js';
import { holdSigningKeys, methodAvailable } from './signatures.js';
import { leafHash, treeBuilder } from './tree.js';
import { sequenceOf } from './witnessing.js';

/** The "type" of a sealer's saved state. */
export const SEALER_STATE_TYPE = 'provared.sealer-state.v0';

/** The most books one sealer keeps: its whole state is written at each change that must last. */
export const MAX_SEALER_BOOKS = 1000;

/** The most agents one recorder's rules may name. */
export const MAX_RECORDER_AGENTS = 64;

/** How long a signer, and the time-stamp hook, may take, in milliseconds, unless the sealer is told otherwise. */
export const SEALER_WAIT_MS = 30 * 1000;

const MAX_WAIT_MS = 2 ** 31 - 1;

/**
 * The leaf fingerprint of one line of a book: the SHA-256 of the byte 0x00
 * and the line's bytes, without its line feed (RFC 6962, section 2.1;
 * format description, section 10). This is what a recorder sends a central
 * sealer in place of the line.
 * @param {string} line one line of a book, without its line feed
 * @returns {Promise<Uint8Array>} 32 bytes
 */
export async function leafFingerprint(line) {
  if (typeof line !== 'string') throw f.fail('line', 'must be text: one line of a book, without its line feed.');
  if (line.length === 0) throw f.fail('line', 'must not be empty: no line of a book is.');
  if (line.includes('\n')) throw f.fail('line', 'must be one line of a book, without its line feed.');
  if (!line.isWellFormed()) throw f.fail('line', 'must be well-formed Unicode text: a line of a book is written in UTF-8.');
  if (line.length > MAX_LINE_BYTES || utf8(line).length > MAX_LINE_BYTES) throw f.fail('line', 'must be at most 131,072 bytes, as a line of a book is.');
  return leafHash(utf8(line));
}

const refused = (code, message, more = {}) => ({ refused: { code, message }, ...more });

const OTHER_RECORDER = 'This book is another recorder\'s: a book, and every book that follows it, is sealed only for the recorder that started it.';
const BEFORE_CLOSED = (n) => `Book ${n}, which this book was started after, is closed: another book follows it. Nothing was signed for this book, so it can be released (releaseUnsealed, or the program's command release-unsealed).`;

// A seal's book number (section 21.6): absent is the first book.
const numberOf = (content) => (Object.hasOwn(content, 'book') ? content.book : 1);

/**
 * Which book a call is about: the leaf fingerprint of its first line, in
 * base64url, for a first book; or {first, number} for any book. A recorder
 * that starts a new book with the same permission as its first line starts
 * a book with the same first line, so the number keeps the two apart.
 * @returns {{first: string, number: number}}
 */
function bookRef(book) {
  if (typeof book === 'string') {
    f.fingerprintText(book, 'book');
    return { first: book, number: 1 };
  }
  f.members(book, ['first'], ['number'], 'book');
  f.fingerprintText(book.first, 'book.first');
  const number = Object.hasOwn(book, 'number') ? book.number : 1;
  if (!Number.isSafeInteger(number) || number < 1) throw f.fail('book.number', 'must be a whole number, 1 or more.');
  return { first: book.first, number };
}

const keyOf = (ref) => `${ref.number} ${ref.first}`;

// Leaf fingerprints, each 32 bytes, copied.
function readLeaves(leaves) {
  if (!Array.isArray(leaves) || leaves.length > MAX_ENTRIES) throw f.fail('leaves', 'must be a list of leaf fingerprints, at most 100,000.');
  const out = [];
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i];
    if (!(leaf instanceof Uint8Array) || leaf.length !== 32) throw f.fail(`leaves[${i}]`, 'must be a leaf fingerprint: 32 bytes.');
    out.push(leaf.slice());
  }
  return out;
}

// The sizes of the complete parts of a tree of n leaves, the largest first: the powers of two that add up to n.
function partSizes(n) {
  const sizes = [];
  for (let bit = 2 ** 30; bit >= 1; bit /= 2) if (Math.floor(n / bit) % 2 === 1) sizes.push(bit);
  return sizes;
}

// Parts as saved (fingerprints in base64url) for a tree of n leaves, read strictly.
function readParts(hashes, n, where) {
  const sizes = partSizes(n);
  if (!Array.isArray(hashes) || hashes.length !== sizes.length) throw f.fail(where, `must be the ${sizes.length} fingerprints of a tree of ${n} leaves.`);
  return hashes.map((h, i) => {
    f.fingerprintText(h, `${where}[${i}]`);
    return { hash: fromBase64url(h), size: sizes[i] };
  });
}

const writeParts = (parts) => parts.map((p) => toBase64url(p.hash));

// A recorder's rules, read strictly: "agents", the fingerprints of the agents' key sets whose permissions it may
// start books with (1 to 64, none twice), and "books", the most books it may hold (1 to 1,000). Either may be left out.
function readRules(given) {
  f.members(given, [], ['agents', 'books'], 'rules');
  let agents = null;
  if (Object.hasOwn(given, 'agents')) {
    if (!Array.isArray(given.agents) || given.agents.length < 1 || given.agents.length > MAX_RECORDER_AGENTS) {
      throw f.fail('rules.agents', 'must be a list of 1 to 64 fingerprints of agents\' key sets.');
    }
    agents = new Set();
    for (let i = 0; i < given.agents.length; i++) {
      f.fingerprintText(given.agents[i], `rules.agents[${i}]`);
      if (agents.has(given.agents[i])) throw f.fail(`rules.agents[${i}]`, 'is named twice.');
      agents.add(given.agents[i]);
    }
  }
  let books = null;
  if (Object.hasOwn(given, 'books')) {
    if (!Number.isSafeInteger(given.books) || given.books < 1 || given.books > MAX_SEALER_BOOKS) throw f.fail('rules.books', 'must be a whole number from 1 to 1,000.');
    books = given.books;
  }
  return { agents, books, text: JSON.stringify([agents ? [...agents].sort() : null, books]) };
}

// Wait for a promise at most "ms" milliseconds.
function within(promise, ms, what) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Refusal('check-failed', `${what} gave no answer within ${ms} milliseconds.`)), ms);
    Promise.resolve(promise).then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/**
 * Open a central sealer.
 *
 * @param {object} o
 * @param {{keys: object[], name: string}} o.by the recorder's public key set (Ed25519, ML-DSA-87, SLH-DSA-SHA2-256s) and its name (a label)
 * @param {any[]} o.signers its three private keys, or signers (signatures.js), in the order of the key set, as writeSeal takes them
 * @param {(fingerprintBytes: Uint8Array) => any} [o.stamp] asks a time-stamp service for a stamp over a seal's fingerprint:
 *   gives an item of "stamps" (format description, section 21.2), or null for none. No service is named here
 * @param {object} [o.state] the state a sealer handed back before, as saved
 * @param {() => number} [o.clock] the time now, in milliseconds since 1970; Date.now by default
 * @param {number} [o.signWithin] how long each signature, and the time-stamp hook, may take, in milliseconds (30 seconds)
 * @returns {Promise<object>} the sealer: extend, seal, update, latest, held, state, and forRecorder
 */
export async function openSealer({ by, signers, stamp, state, clock = Date.now, signWithin = SEALER_WAIT_MS } = {}) {
  f.members(by, ['keys', 'name'], [], 'by');
  f.label(by.name, 'by.name');
  checkSealKeySet(by.keys, 'by.keys');
  for (const alg of SEAL_METHODS) {
    if (!(await methodAvailable(alg))) throw new Refusal('bad-key', `A sealer checks every seal it signs, and this device does not have ${alg} built in.`);
  }
  if (!Array.isArray(signers) || signers.length !== 3) throw f.fail('signers', 'must be the recorder\'s three private keys, or signers: Ed25519, ML-DSA-87, then SLH-DSA-SHA2-256s.');
  if (stamp !== undefined && typeof stamp !== 'function') throw f.fail('stamp', 'must be a function that asks a time-stamp service for a stamp, or be left out.');
  if (typeof clock !== 'function') throw f.fail('clock', 'must be a function that gives the time now.');
  if (!(Number.isSafeInteger(signWithin) && signWithin >= 1 && signWithin <= MAX_WAIT_MS)) throw f.fail('signWithin', 'must be a number of milliseconds from 1 to 2,147,483,647.');
  // Copied once, so that nothing done to them afterwards changes the sealer.
  const me = JSON.parse(canonicalJson({ keys: by.keys, name: by.name }));
  const mine = canonicalJson(me.keys);
  const meFingerprint = await keySetFingerprint(me.keys);
  // Each signer is read once, here, and checked against the key it must hold; each signature waits "signWithin" at most.
  const keys = await holdSigningKeys(signers, SEAL_METHODS, me.keys, signWithin);

  /**
   * @typedef {{entry: object, fingerprint: string, content: any, parts: {hash: Uint8Array, size: number}[]}} Latest
   * @typedef {{first: string, number: number, follows: string|null, size: number, builder: ReturnType<typeof treeBuilder>, closed: boolean, latest: Latest|null, recorder: string|null}} Book
   * @type {Map<string, Book>}
   */
  const books = new Map();
  // Every book held with this first line, whatever its number.
  const withFirst = (first) => [...books.values()].filter((b) => b.first === first);
  // Each recorder's rules (forRecorder), fixed by the first call that gives them; and the recorder each agent belongs to.
  /** @type {Map<string, {agents: Set<string>|null, books: number|null, text: string}>} */
  const rules = new Map();
  /** @type {Map<string, string>} */
  const agentOwner = new Map();
  if (state !== undefined) await restore(state);

  // The calls wait for one another, so that two calls about one book never cross.
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const run = turn.then(work);
    turn = run.catch(() => {});
    return run;
  };

  function snapshot() {
    return {
      type: SEALER_STATE_TYPE,
      by: meFingerprint,
      books: [...books.values()].map((b) => {
        const saved = { first: b.first, number: b.number, closed: b.closed };
        if (b.recorder !== null) saved.recorder = b.recorder;
        if (b.follows !== null) saved.follows = b.follows;
        // A book is kept at its latest seal, or with none at its first line: the lines since are asked for again after a start.
        if (b.latest) saved.latest = { entry: structuredClone(b.latest.entry), parts: writeParts(b.latest.parts) };
        return saved;
      }),
    };
  }

  // A seal entry signed with this sealer's keys, that passes its check with all three signatures checked here; and
  // what of it is kept (choices K67, K79): the seal, which it checks, and its time-stamps, which it reads for their form
  // only, by the rules a book reads their form by (at most four, each at most 12,288 bytes, in base64url, none twice): it
  // checks no time-stamp's signature and trusts no service. Never the witness statements, which it does not check either.
  // An entry as a book holds it is one
  // line, so one longer than a line of a book may be is refused before anything in it is checked. "optional" is the
  // members it may hold besides the seal: a book's entry may hold witness statements, a saved state's may not.
  async function ownSeal(entry, where, optional) {
    f.members(entry, ['seal'], optional, where);
    // The entry is read once, into its one written form, and only that copy is used from here on (choice K76): what is
    // measured, what is checked and what is kept are one value, even where a member gives another value at each
    // reading (a getter, a Proxy).
    let line;
    try {
      line = entryLine(entry);
    } catch (e) {
      const problem = problemFrom(e);
      throw new Refusal(problem.code, `${where}: is not an entry a line of a book can hold. ${problem.message}`);
    }
    if (line.length > MAX_LINE_BYTES || utf8(line).length > MAX_LINE_BYTES) throw new Refusal('too-large', `${where}: is longer than a line of a book may be (131,072 bytes).`);
    const plain = JSON.parse(line);
    // Its members are looked at again in the copy: an object whose members change between readings may have written others.
    f.members(plain, ['seal'], optional, where);
    const kept = { seal: plain.seal };
    if (Object.hasOwn(plain, 'stamps')) {
      decodeStamps(plain.stamps);
      kept.stamps = plain.stamps;
    }
    const checked = await checkSealAlone(plain.seal);
    // On a device that opens a sealer all three methods are built in, so every signature is checked, and one that
    // was not would be a problem too; the two are one test.
    if (checked.problems.length > 0 || checked.signatures.some((s) => s.state !== 'valid')) {
      const problem = checked.problems[0] ?? { code: 'check-failed', message: 'This device could not check all three signatures of the seal.' };
      throw new Refusal(problem.code, `The seal ${where === 'entry' ? 'handed over' : `in ${where}`} does not pass its check. ${problem.message}`);
    }
    if (canonicalJson(checked.content.by.keys) !== mine) throw new Refusal('sealer-not-expected', 'The seal is not signed with this sealer\'s keys.');
    // Copied again through its one written form, so that what is kept shares nothing with what was checked or handed over.
    return { checked, kept: JSON.parse(canonicalJson(kept)) };
  }

  async function restore(saved) {
    if (saved === null || typeof saved !== 'object' || Array.isArray(saved)) throw f.fail('state', 'must be a state a sealer handed back.');
    f.members(saved, ['books', 'by', 'type'], [], 'state');
    if (saved.type !== SEALER_STATE_TYPE) throw f.fail('state.type', `must be ${SEALER_STATE_TYPE}.`);
    if (saved.by !== meFingerprint) throw f.fail('state.by', 'is the state of another sealer: its key set is not this sealer\'s.');
    if (!Array.isArray(saved.books) || saved.books.length > MAX_SEALER_BOOKS) throw f.fail('state.books', 'must be a list of at most 1,000 books.');
    for (let i = 0; i < saved.books.length; i++) {
      const where = `state.books[${i}]`;
      const b = saved.books[i];
      f.members(b, ['closed', 'first', 'number'], ['follows', 'latest', 'recorder'], where);
      const ref = bookRef({ first: b.first, number: b.number });
      if (typeof b.closed !== 'boolean') throw f.fail(`${where}.closed`, 'must be true or false.');
      let recorder = null;
      if (Object.hasOwn(b, 'recorder')) {
        f.label(b.recorder, `${where}.recorder`);
        recorder = b.recorder;
      }
      let follows = null;
      if (Object.hasOwn(b, 'follows')) {
        if (ref.number === 1) throw f.fail(`${where}.follows`, 'is given for a first book, which follows none.');
        f.fingerprintText(b.follows, `${where}.follows`);
        follows = b.follows;
      }
      let latest = null;
      let size;
      let parts;
      if (Object.hasOwn(b, 'latest')) {
        // A sealed book stands at its latest seal: the lines since are not kept, so none can rewrite a sealed line.
        f.members(b.latest, ['entry', 'parts'], [], `${where}.latest`);
        // A saved entry holds the seal and its time-stamps only (choice K67).
        const { checked, kept } = await ownSeal(b.latest.entry, `${where}.latest.entry`, ['stamps']);
        const c = checked.content;
        if (numberOf(c) !== ref.number) throw f.fail(`${where}.latest`, 'is a seal of another book number.');
        const latestParts = readParts(b.latest.parts, c.size, `${where}.latest.parts`);
        if (toBase64url(await treeBuilder(latestParts).root()) !== c.root) throw f.fail(`${where}.latest.parts`, 'do not give the seal\'s top fingerprint.');
        latest = { entry: kept, fingerprint: checked.fingerprint, content: c, parts: latestParts };
        size = c.size;
        parts = latestParts;
      } else {
        // A book with no seal stands at its first line, the line it is known by.
        parts = [{ hash: fromBase64url(ref.first), size: 1 }];
        size = 1;
        if (ref.number > 1 && follows === null) throw f.fail(where, 'is a later book with no seal, so it must name the book it follows ("follows").');
      }
      if (books.has(keyOf(ref))) throw f.fail(where, 'the same book is given twice.');
      books.set(keyOf(ref), { first: ref.first, number: ref.number, follows, size, builder: treeBuilder(parts), closed: b.closed, latest, recorder });
    }
    // Every book that follows another names one this state holds, with a seal, of the same recorder; no two follow the same one.
    const followed = new Set();
    for (const b of books.values()) {
      if (b.follows === null) continue;
      const key = keyOf({ first: b.follows, number: b.number - 1 });
      const before = books.get(key);
      if (!before && !b.latest) throw f.fail('state.books', 'a later book follows a book that this state does not hold.');
      if (before && !before.latest) throw f.fail('state.books', 'a later book follows a book that has no seal.');
      if (before && before.recorder !== b.recorder) throw f.fail('state.books', 'a later book follows a book of another recorder.');
      if (followed.has(key)) throw f.fail('state.books', 'two books follow the same book.');
      followed.add(key);
    }
    // The books of one first line belong to one recorder.
    for (const b of books.values()) {
      if (withFirst(b.first).some((other) => other.recorder !== b.recorder)) throw f.fail('state.books', 'books with one first line belong to more than one recorder.');
    }
  }

  // The book a later book follows, if this sealer holds it.
  const followedBy = (b) => (b.follows === null ? null : (books.get(keyOf({ first: b.follows, number: b.number - 1 })) ?? null));

  // The seal the next seal of a book must name: its own latest, or for the first seal of a later book the latest of the book before.
  const beforeOf = (b) => b.latest ?? followedBy(b)?.latest ?? null;

  // The first line handed over with a call ("line"), read: it must be the line the book is known by. Gives its text,
  // undefined where none was handed over, or throws.
  async function readLine(more, ref) {
    if (!Object.hasOwn(more, 'line')) return undefined;
    const leaf = await leafFingerprint(more.line);
    if (toBase64url(leaf) !== ref.first) throw f.fail('line', 'is not the line the book is known by: its leaf fingerprint is not the book\'s first.');
    return more.line;
  }

  // Whether "who" may start a book (a book this sealer does not hold, by extend or by update) with this first line:
  // within its book limit; and, where any recorder has a list of agents, only with the first line itself, a permission
  // whose agent belongs to no other recorder and, where "who" has a list, is on it. Gives a refusal, or null.
  async function mayStart(who, line) {
    const own = who === null ? undefined : rules.get(who);
    if (own?.books != null && [...books.values()].filter((b) => b.recorder === who).length >= own.books) {
      return refused('too-large', `This recorder holds ${own.books} books, the most its rules allow. A book with no seal can be released (releaseUnsealed, or the program's command release-unsealed): nothing was signed for it.`);
    }
    if (agentOwner.size === 0) return null;
    if (line === undefined) return refused('bad-field', 'line: a book is started with its first line itself, the permission it starts with, so that the sealer can tell whose agent it is for.');
    let agent;
    try {
      ({ agent } = await sequenceOf(utf8(line)));
    } catch (e) {
      const problem = problemFrom(e);
      return refused(problem.code, `line: ${problem.message}`);
    }
    const owner = agentOwner.get(agent);
    if (owner !== undefined && owner !== who) return refused('other-recorder', 'The permission on this first line is for an agent that another recorder\'s rules name: only that recorder starts books with it.');
    if (own?.agents && !own.agents.has(agent)) return refused('agent-not-allowed', 'The permission on this first line is for an agent this recorder\'s rules do not name: it starts books only with permissions for its own agents.');
    return null;
  }

  function extend(who, book, at, leaves, more = {}) {
    return inTurn(async () => {
      let ref;
      let list;
      let follows;
      let line;
      try {
        ref = bookRef(book);
        if (!Number.isSafeInteger(at) || at < 0) throw f.fail('at', 'must be a whole number: the place of the first of these lines in the book, counting from 0.');
        list = readLeaves(leaves);
        f.members(more, [], ['follows', 'line'], 'more');
        if (Object.hasOwn(more, 'follows')) {
          f.fingerprintText(more.follows, 'follows');
          follows = more.follows;
        }
        line = await readLine(more, ref);
      } catch (e) {
        return { refused: problemFrom(e) };
      }
      let b = books.get(keyOf(ref));
      const fresh = !b;
      if (fresh) {
        if (at !== 0) return refused('out-of-step', 'This sealer holds no line of this book, so the first lines it is sent must start at place 0.', { size: 0 });
        if (list.length === 0) return refused('bad-field', 'leaves: must hold at least the book\'s first line, to start a book.');
        if (toBase64url(list[0]) !== ref.first) return refused('bad-field', 'leaves[0]: is not the leaf fingerprint the book is known by: a book is known by its first line.');
        if (books.size >= MAX_SEALER_BOOKS) return refused('too-large', 'This sealer holds 1,000 books, the most it keeps.');
        const barred = await mayStart(who, line);
        if (barred) return barred;
        let before = null;
        if (ref.number === 1) {
          if (follows !== undefined) return refused('bad-field', 'follows: only a book after the first follows another.');
        } else {
          if (follows === undefined) return refused('bad-field', `follows: book ${ref.number} must name the book it follows: the leaf fingerprint of the first line of book ${ref.number - 1}.`);
          before = books.get(keyOf({ first: follows, number: ref.number - 1 })) ?? null;
          if (!before) return refused('unknown-book', `This sealer holds no book ${ref.number - 1} whose first line has that leaf fingerprint.`);
        }
        // Every book with one first line is one chain, of one recorder (choices K33, K34).
        const kin = withFirst(ref.first);
        if (kin.some((k) => k.recorder !== who)) return refused('other-recorder', OTHER_RECORDER);
        if (kin.length > 0) {
          const top = kin.reduce((a, k) => (k.number > a.number ? k : a));
          if (ref.number !== top.number + 1 || follows !== ref.first) {
            return refused('not-next-book', `This sealer holds book ${top.number} with this first line already: a book with this first line may start only as book ${top.number + 1}, following it ("follows": that same first line).`);
          }
        }
        if (before) {
          if (before.recorder !== who) return refused('other-recorder', OTHER_RECORDER);
          if (!before.latest) return refused('not-sealed', `Book ${ref.number - 1} has no seal from this sealer yet. The first seal of book ${ref.number} names its last seal: seal it first.`);
          if (before.closed) return refused('book-closed', `Book ${ref.number - 1} is closed: another book already follows it.`);
          for (const other of books.values()) {
            if (other.number === ref.number && other.follows === follows) return refused('book-closed', `Book ${ref.number - 1} is closed: another book already follows it.`);
          }
        }
        b = { first: ref.first, number: ref.number, follows: follows ?? null, size: 0, builder: treeBuilder(), closed: false, latest: null, recorder: who };
      } else {
        if (b.recorder !== who) return refused('other-recorder', OTHER_RECORDER);
        if (b.closed) return refused('book-closed', 'This book is closed: a later book follows it, so this sealer seals no more of it.');
        if (follows !== undefined && follows !== b.follows) return refused('bad-field', 'follows: is not the book this book was started after.');
        if (at !== b.size) return refused('out-of-step', `This sealer holds ${b.size} lines of this book: send the lines from place ${b.size}.`, { size: b.size });
      }
      if (b.size + list.length > MAX_ENTRIES) return refused('too-large', 'A book holds at most 100,000 entries.');
      // Taken in whole or not at all.
      const next = b.builder.fork();
      for (const leaf of list) await next.addLeafHash(leaf);
      b.builder = next;
      b.size += list.length;
      if (!fresh) return { size: b.size };
      // A book started binds its first line, its recorder and the book it follows: that must last, so the state is handed back.
      books.set(keyOf(ref), b);
      return { size: b.size, state: snapshot() };
    });
  }

  function seal(who, book, more) {
    return inTurn(async () => {
      let ref;
      let previous;
      try {
        ref = bookRef(book);
        f.members(more, ['previous'], ['id', 'when'], 'more');
        previous = more.previous;
        if (previous !== null) f.fingerprintText(previous, 'previous');
        if (Object.hasOwn(more, 'id')) f.id(more.id, 'id');
      } catch (e) {
        return { refused: problemFrom(e) };
      }
      const b = books.get(keyOf(ref));
      if (!b) return refused('unknown-book', 'This sealer holds no line of this book.');
      if (b.recorder !== who) return refused('other-recorder', OTHER_RECORDER);
      if (b.closed) return refused('book-closed', 'This book is closed: a later book follows it, so this sealer seals no more of it.');
      // The first seal of a later book only where the book it was started after is still open: once another book
      // follows that one, this book waits for nothing (a state put back can leave one waiting).
      if (!b.latest && followedBy(b)?.closed) return refused('book-closed', BEFORE_CLOSED(b.number - 1));
      const before = beforeOf(b);
      const own = before ? before.fingerprint : null;
      if (previous !== own) {
        return refused(
          'not-up-to-date',
          own === null
            ? 'The book names a seal before this one, and this sealer holds none of it: its state is behind the book. Bring it up to date first (update), with the latest seal of the book and the lines since.'
            : 'The seal before this one, as the book shows it, is not the latest this sealer holds. If the book is behind, add the sealer\'s latest seal to it (latest); if the sealer is behind, bring it up to date first (update).',
        );
      }
      if (b.latest && b.size <= b.latest.content.size) {
        return refused('nothing-new', `This sealer has taken in no line of this book since its latest seal, at ${b.latest.content.size} entries: send the line of that seal, and any after it, first.`);
      }
      let now;
      try {
        now = clock();
      } catch {
        now = NaN;
      }
      // A time a seal can be dated with: within the years a date can be written in (section 3.6).
      const writable = (t) => typeof t === 'number' && Number.isFinite(t) && t >= 0 && t < 253402300800000;
      if (!writable(now)) return refused('check-failed', 'The sealer\'s clock did not give a time.');
      let when = now;
      if (Object.hasOwn(more, 'when')) {
        when = more.when instanceof Date ? more.when.getTime() : more.when;
        if (!writable(when)) return refused('bad-field', 'when: must be a time: milliseconds since 1970, or a Date.');
        if (Math.abs(when - now) > CLOCK_ALLOWANCE_MS) return refused('bad-field', 'when: must be within 300 seconds of this sealer\'s clock: a sealer dates its own seals.');
      }
      if (before && parseTime(formatTime(when)) < parseTime(before.content.when)) {
        return refused('time-went-backwards', 'The seal would be dated before the seal it names.');
      }
      let made;
      let checked;
      try {
        const fields = { by: me, book: b.number, when };
        if (own !== null) fields.previous = own;
        if (Object.hasOwn(more, 'id')) fields.id = more.id;
        made = await sealOver(b.size, await b.builder.root(), fields, keys);
        checked = await checkSealAlone(made.record);
      } catch (e) {
        return refused('check-failed', `The sealer could not sign a seal, so it gave none. ${problemFrom(e).message}`);
      }
      // Every seal is checked before it is kept or given out.
      if (checked.problems.length > 0 || checked.signatures.length !== 3 || checked.signatures.some((s) => s.state !== 'valid')) {
        return refused('check-failed', 'The seal the sealer signed does not pass its own check, so it gave none.');
      }
      const entry = { seal: made.record };
      let stampProblem = null;
      if (stamp) {
        try {
          const item = await within(stamp(made.fingerprintBytes.slice()), signWithin, 'The time-stamp hook');
          if (item !== null && item !== undefined) {
            const copy = JSON.parse(canonicalJson(item));
            decodeStamps([copy]);
            entry.stamps = [copy];
          }
        } catch (e) {
          stampProblem = problemFrom(e);
        }
      }
      // Signed and checked: kept, whatever the time-stamp did.
      const followed = b.latest ? null : followedBy(b);
      b.latest = { entry, fingerprint: made.fingerprint, content: checked.content, parts: b.builder.parts() };
      if (followed) followed.closed = true;
      const answer = { entry: structuredClone(entry), line: entryLine(entry), fingerprint: made.fingerprint, fingerprintBytes: made.fingerprintBytes, state: snapshot() };
      if (stampProblem) answer.stampProblem = stampProblem;
      return answer;
    });
  }

  function update(who, book, entry, leaves, more = {}) {
    return inTurn(async () => {
      let ref;
      let list;
      let checked;
      let kept;
      let line;
      try {
        ref = bookRef(book);
        list = readLeaves(leaves);
        f.members(more, [], ['line'], 'more');
        line = await readLine(more, ref);
        // The entry as the book holds it: its witness statements are allowed and set aside (choice K67).
        ({ checked, kept } = await ownSeal(entry, 'entry', ['stamps', 'witnesses']));
      } catch (e) {
        return { refused: problemFrom(e) };
      }
      const c = checked.content;
      if (numberOf(c) !== ref.number) return refused('seal-mismatch', `The seal is of book ${numberOf(c)}, not of book ${ref.number}.`);
      const held = books.get(keyOf(ref)) ?? null;
      if (held && held.recorder !== who) return refused('other-recorder', OTHER_RECORDER);
      if (held && held.closed) return refused('book-closed', 'This book is closed: a later book follows it, so this sealer seals no more of it.');
      const base = held?.latest ?? null;
      if (base && base.fingerprint === checked.fingerprint) {
        if (list.length > 0) return refused('bad-field', 'leaves: this sealer holds this seal already as the latest of the book, so no lines are taken.');
        return { size: held.size, state: snapshot() };
      }
      const baseSize = base ? base.content.size : 0;
      if (c.size <= baseSize) {
        return refused(
          'seal-mismatch',
          c.size === baseSize
            ? 'This sealer holds another seal of this book at the same number of entries. It takes no second seal at one size.'
            : `The seal is earlier than the latest seal this sealer holds of this book, at ${baseSize} entries. A sealer is never moved back: add its latest seal to the book (latest).`,
        );
      }
      if (list.length !== c.size - baseSize) return refused('bad-field', `leaves: must be the ${c.size - baseSize} leaf fingerprints from place ${baseSize} to the seal, at ${c.size} entries.`);
      if (baseSize === 0 && toBase64url(list[0]) !== ref.first) return refused('bad-field', 'leaves[0]: is not the leaf fingerprint the book is known by: a book is known by its first line.');
      // A book this sealer does not hold, brought in from a seal it signed: where it stands among the books it holds (choice K35).
      let follows = held ? held.follows : null;
      let followed = held && !held.latest ? followedBy(held) : null;
      // A book waiting to follow a book that another book already follows takes no seal (choice K48).
      if (followed?.closed) return refused('book-closed', BEFORE_CLOSED(followed.number));
      // The first seal of a book started after another names that book's latest seal: where this sealer holds another as
      // its latest, that book is behind, and is brought up to date first.
      if (followed && c.previous !== followed.latest.fingerprint) {
        return refused('not-up-to-date', `The seal names, as the seal before it, a seal that is not the latest this sealer holds of book ${followed.number}, the book this book was started after. Bring that book up to date first (update).`);
      }
      let earlier = [];
      if (!held) {
        if (books.size >= MAX_SEALER_BOOKS) return refused('too-large', 'This sealer holds 1,000 books, the most it keeps.');
        // A book brought in is started here as much as one sent line by line: the same rules (choices K45, K47).
        const barred = await mayStart(who, line);
        if (barred) return barred;
        const kin = withFirst(ref.first);
        if (kin.some((k) => k.recorder !== who)) return refused('other-recorder', OTHER_RECORDER);
        if (kin.some((k) => k.number > ref.number)) return refused('book-closed', `This sealer holds a later book with this first line: book ${ref.number} is closed.`);
        // Every earlier book with this first line is over: a later one has a seal.
        earlier = kin;
        if (ref.number > 1 && Object.hasOwn(c, 'previous')) {
          // The first seal of book n names the last seal of book n - 1: where this sealer holds that seal as the latest of
          // a book, this is it, and that book is book n - 1 (a sealer names no other as the seal before a first seal).
          const named = [...books.values()].find((x) => x.latest && x.latest.fingerprint === c.previous) ?? null;
          if (named) {
            if (named.recorder !== who) return refused('other-recorder', OTHER_RECORDER);
            if (kin.length > 0 && named.first !== ref.first) return refused('not-next-book', 'This sealer holds a book with this first line already: a book with this first line follows only the latest book with that first line.');
            const taken = [...books.values()].some((x) => x.number === ref.number && x.follows === named.first);
            if (named.closed || taken) return refused('book-closed', `Book ${named.number} is closed: another book already follows it.`);
            follows = named.first;
            followed = named;
          }
        }
      }
      const builder = treeBuilder(base ? base.parts : []);
      for (const leaf of list) await builder.addLeafHash(leaf);
      if (toBase64url(await builder.root()) !== c.root) {
        return refused('seal-mismatch', 'The lines handed over do not give the seal\'s top fingerprint from the latest seal this sealer holds of this book.');
      }
      const b = held ?? { first: ref.first, number: ref.number, follows, size: 0, builder: null, closed: false, latest: null, recorder: who };
      b.builder = builder;
      b.size = c.size;
      b.latest = { entry: kept, fingerprint: checked.fingerprint, content: c, parts: builder.parts() };
      if (!held) books.set(keyOf(ref), b);
      // A seal of a later book shows that its first seal was signed: the book before is closed, and so is every earlier book with its first line.
      if (followed) followed.closed = true;
      for (const k of earlier) k.closed = true;
      return { size: b.size, state: snapshot() };
    });
  }

  function latest(who, book) {
    let ref;
    try {
      ref = bookRef(book);
    } catch {
      return null;
    }
    const b = books.get(keyOf(ref));
    if (!b || b.recorder !== who || !b.latest) return null;
    return { entry: structuredClone(b.latest.entry), line: entryLine(b.latest.entry), fingerprint: b.latest.fingerprint };
  }

  function held(who, book) {
    let ref;
    try {
      ref = bookRef(book);
    } catch {
      return null;
    }
    const b = books.get(keyOf(ref));
    if (!b || b.recorder !== who) return null;
    return { first: b.first, number: b.number, follows: b.follows, size: b.size, closed: b.closed, latest: b.latest ? b.latest.fingerprint : null, sealed: b.latest ? b.latest.content.size : 0 };
  }

  // The calls, as one recorder (or, for the sealer's own methods, as no named recorder).
  const view = (who) =>
    Object.freeze({
      /**
       * Take in the leaf fingerprints of new lines of one book, in order.
       * "at" is the place of the first of them in the book, counting from 0:
       * it must be the number of lines this sealer already holds of the book,
       * so that lines sent twice are never taken in twice. A book this sealer
       * does not hold starts at place 0, with its first line, whose leaf
       * fingerprint is the one the book is known by. A later book (number 2 or
       * more) names, in "follows", the book before it (the leaf fingerprint of
       * that book's first line), which must have a seal from this sealer. A
       * book whose first line this sealer holds already may start only as the
       * next book after the latest book with that first line. "line" is the
       * book's first line itself: where any recorder has a list of agents, a
       * book is started only with it, and it must be a permission for an
       * agent of the caller's own (forRecorder). Where the call started a
       * book, the answer holds the state: save it first.
       * @param {string|{first: string, number?: number}} book
       * @param {number} at
       * @param {Uint8Array[]} leaves
       * @param {{follows?: string, line?: string}} [more]
       */
      extend: (book, at, leaves, more) => extend(who, book, at, leaves, more),
      /**
       * Sign a seal over the tree this sealer holds of a book: its number of
       * lines and their top fingerprint. "previous" is the seal the new seal
       * must name, as the caller's book shows it: its latest seal, or, for the
       * first seal of a later book, the last seal of the book before; null for
       * the first seal of a first book. It must be the one this sealer holds,
       * or nothing is signed. The state handed back already holds the new
       * seal: save it before the seal is given out.
       * @param {string|{first: string, number?: number}} book
       * @param {{previous: string|null, when?: number|Date, id?: string}} more
       */
      seal: (book, more) => seal(who, book, more),
      /**
       * Bring the sealer up to date for one book, from a seal it signed that
       * the book holds and its own state does not: the seal's entry, and the
       * leaf fingerprints of the lines from the latest seal this sealer holds
       * of the book (or from the start) up to the seal. They must give the
       * seal's top fingerprint. It is never moved back. Where the seal is the
       * first seal of a book after the first, and names the latest seal of a
       * book it holds, that book is closed; where the sealer holds the book
       * this book was started after at an earlier seal than the one named,
       * nothing is taken until that book is brought up to date. A book it
       * does not hold is started here, under the same rules as with extend,
       * "line" included. It signs nothing. Of the entry it keeps the seal
       * and its time-stamps (at most four), not the witness statements; an
       * entry longer than a line of a book may be is refused (too-large).
       * @param {string|{first: string, number?: number}} book
       * @param {{seal: object, stamps?: any[], witnesses?: any[]}} entry the seal's entry, as the book holds it
       * @param {Uint8Array[]} leaves
       * @param {{line?: string}} [more]
       */
      update: (book, entry, leaves, more) => update(who, book, entry, leaves, more),
      /** The latest seal this sealer holds of a book: its entry (the seal and its time-stamps), its line and its fingerprint; or null. */
      latest: (book) => latest(who, book),
      /** What this sealer holds of a book: how many lines, its number, the book it follows, whether it is closed, and its latest seal; or null. */
      held: (book) => held(who, book),
    });

  return {
    ...view(null),
    /** The sealer's state as it stands, to be saved. */
    state() {
      return snapshot();
    },
    /**
     * The same calls, made for one named recorder: a book it starts, and
     * every book that follows it, is its own, and no other recorder (nor the
     * sealer's own calls) can extend, seal or bring it up to date, start a
     * book after it, or start a book with its first line. Asked about
     * another's book, it is answered as a book the sealer does not hold.
     * "rules", where given: "agents", the fingerprints of the key sets of
     * the agents whose permissions it may start books with (1 to 64), and
     * "books", the most books it may hold (1 to 1,000). A recorder's rules
     * are fixed by the first call that gives them; an agent belongs to one
     * recorder only.
     * @param {string} recorder a label, 1 to 200 characters
     * @param {{agents?: string[], books?: number}} [given]
     */
    forRecorder(recorder, given) {
      f.label(recorder, 'recorder');
      if (given !== undefined) {
        const r = readRules(given);
        const held = rules.get(recorder);
        if (held) {
          if (held.text !== r.text) throw f.fail('rules', 'are not the rules this recorder was given before: a recorder\'s rules are fixed by the first call that gives them.');
        } else {
          for (const agent of r.agents ?? []) {
            if (agentOwner.has(agent)) throw f.fail('rules.agents', 'names an agent that another recorder\'s rules name: an agent belongs to one recorder.');
          }
          rules.set(recorder, r);
          for (const agent of r.agents ?? []) agentOwner.set(agent, recorder);
        }
      }
      return view(recorder);
    },
    /**
     * Release the books that hold no seal from this sealer: nothing was
     * signed for them, so taking them off frees their places (in the limit
     * of books, as the next book after another, and their first lines).
     * "recorder": only that recorder's books (null for the sealer's own
     * calls); left out, every recorder's. The state handed back is to be
     * saved.
     * @param {{recorder?: string|null}} [o]
     * @returns {Promise<{released: {first: string, number: number, recorder: string|null}[], state: object}>}
     */
    releaseUnsealed(o = {}) {
      return inTurn(async () => {
        f.members(o, [], ['recorder'], 'options');
        const all = !Object.hasOwn(o, 'recorder');
        if (!all && o.recorder !== null) f.label(o.recorder, 'recorder');
        const released = [];
        for (const [key, b] of [...books]) {
          if (b.latest || (!all && b.recorder !== o.recorder)) continue;
          books.delete(key);
          released.push({ first: b.first, number: b.number, recorder: b.recorder });
        }
        return { released, state: snapshot() };
      });
    },
  };
}
