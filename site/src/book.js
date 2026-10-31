// The book (a list of entries, one to a line), the chain, what a stub shows
// about the agent, the top fingerprint and the Show.
// Format description, sections 7 to 11 and 17 to 19.
//
// The checker keeps three questions apart:
//   - was a problem found in the record?          (problems)
//   - was every signature checked on this device? (fullyChecked)
//   - did the agent stay in its slip?             (breaches)
// A breach is not a fault in the record. It is what a sound record shows.
// "Intact" is said only when no problem was found and every signature was
// checked.

import { Refusal, canonicalJson, formatTime, fromBase64url, parseCanonical, parseTime, problemFrom, toBase64url, utf8 } from './encoding.js';
import * as f from './fields.js';
import { checkBlockStamp } from './blockstamp.js';
import { parseRecord, signingInput } from './jws.js';
import { MAX_PASSES, validatePassContent } from './pass.js';
import { CLOCK_ALLOWANCE_MS, decodeStamps, keySetFingerprint, validateSealContent } from './seal.js';
import { verifySignature } from './signatures.js';
import { validateAcknowledgementContent, validateCancellationContent, validateVouchingContent, validateWithdrawalContent } from './standing.js';
import { validateDenialContent } from './denial.js';
import { MAX_WITNESSES, validateWitnessContent } from './witness.js';
import { requestOf, validateApprovalContent } from './approval.js';
import { compareWithSlip, newTally, settlePeriods } from './compare.js';
import { validateRefusalContent, validateTermsContent } from './service.js';
import { checkOriginsOption, checkPasskeySignature, checkSlip } from './slip.js';
import { validateCountersignatureContent, validateStubContent } from './stub.js';
import { checkStamp } from './timestamp.js';
import { inclusionPath, treeBuilder, treeRoot, verifyInclusion } from './tree.js';

/** The most entries a book may hold. */
export const MAX_ENTRIES = 100000;
/** The longest line of a book, in bytes. */
export const MAX_LINE_BYTES = 131072;
/** The most pages a Show may hold. */
export const MAX_PAGES = 64;
/** The most cancellations that may be handed over beside a book. */
export const MAX_HELD = 16;
/** The most acknowledgements that may be handed over with one cancellation. */
export const MAX_ACKNOWLEDGEMENTS = 4;
/** The most seals held elsewhere that may be handed over beside a book. */
export const MAX_HELD_SEALS = 64;

// What can be said about time, with and without an outside time-stamp.
const NOT_STAMPED =
  'Nothing here is time-stamped by an outside service that you named as trusted. So it does not show when the record was made, and the latest stubs under a slip or a pass, or a slip or a pass with all its stubs, could have been removed.';
const blockWords = (sealed) =>
  `A block of a public blockchain, which you trust to be part of the chain, covers the first ${sealed.entries} entries: they existed by ${sealed.when}, taking the time the block states as right to within two hours. What came after is not time-stamped, and a later seal with everything after it could have been removed: compare the top fingerprint and the number of entries with a copy you trust. A block time-stamp rests on SHA-256 and on the block being part of the chain, not on a signature.`;
const stampedWords = (sealed) =>
  sealed.by === 'block'
    ? blockWords(sealed)
    : `An outside time-stamp covers the first ${sealed.entries} entries: they existed by ${sealed.when}, as the time-stamp service states. What came after is not time-stamped, and a later seal with everything after it could have been removed: compare the top fingerprint and the number of entries with a copy you trust. Time-stamp services sign with methods of today's kind, which are not quantum-safe.`;

// What a witness the reader trusts shows, and what it does not (format description, section 29.4).
const witnessedWords = (w) =>
  `A witness you named as trusted signed for the seal at entry ${w.seal}, which covers the first ${w.entries} entries. This book starts from a permission signed by a passkey you named, every permission before the seal is from that passkey for the same agent, and the book is sealed by a recorder you named. For that recorder, that passkey and the agent the permission names, the witness states that it saw this seal, and that it will sign for no seal that does not extend it, in this book or a later one, whichever permission from that passkey to that agent the book starts from. So a second history of those entries, sealed by the same recorder and starting from a permission that passkey gave that agent, shown to someone else, would need that witness to sign for it too. It does not cover a history sealed with other keys, even keys you also named, nor one that starts from a permission for another agent. It does not show when the seal was made, that nothing was cut off after a later seal, nor anything never shown to the witness: to see whether the end of the book is missing, ask the witness for the latest seal it holds for this recorder, passkey and agent, and hand that seal over beside the book it is of.`;

/** What no check of a draft version 0 record can show. Stated with every result. */
export const LIMITS = [
  'It shows what was recorded, not what was left out. An agent that acts and writes no stub leaves no trace here.',
  'A one-sided stub shows what the agent\'s side said, not what the other side did.',
  'A refusal shows what the service\'s side said, not what the agent did.',
  'It does not show that an action was wise, lawful or wanted.',
  'A rule of conduct in a slip, such as "never claim to be a human being", is the person\'s signed instruction. No check can show that the agent kept it.',
  'It does not show who was holding the device when the passkey signed.',
  'A name in a record is a label. Only keys are checked.',
  NOT_STAMPED,
];

/**
 * Write one entry of a book as its line (without the line feed).
 * @param {object} entry one of: {slip}, {stub, countersignature?, approval?}, {refusal}, {terms}, {seal, stamps?, witnesses?},
 *   {cancellation, stamps?}, {acknowledgement}, {vouching}, {withdrawal}, {pass}, {denial}
 * @returns {string}
 */
export function entryLine(entry) {
  return canonicalJson(entry);
}

/**
 * Write a book from its entries.
 * @param {object[]} entries
 * @returns {string}
 */
export function writeBook(entries) {
  return entries.map((e) => entryLine(e) + '\n').join('');
}

// Split a book into its lines, stopping as soon as there are too many, so
// that a flood of line feeds costs nothing. A missing line feed after the
// last line is allowed.
function splitLines(text) {
  const lines = [];
  let at = 0;
  while (at < text.length) {
    if (lines.length >= MAX_ENTRIES) throw new Refusal('too-large', 'The book holds more than 100,000 entries.');
    const feed = text.indexOf('\n', at);
    const end = feed === -1 ? text.length : feed;
    lines.push(text.slice(at, end));
    at = end + 1;
  }
  return lines;
}

// Check the two signatures of a stub or a countersignature against a key set.
async function checkKeySetSignatures(parsed, keys, without) {
  const states = [];
  for (let i = 0; i < parsed.signatures.length; i++) {
    const s = parsed.signatures[i];
    const state = await verifySignature(keys[i], s.signature, signingInput(s.protectedB64, parsed.payloadB64), without);
    states.push({ method: keys[i].alg, state });
  }
  return states;
}

function overall(states) {
  if (states.some((s) => s.state === 'invalid')) return 'invalid';
  if (states.some((s) => s.state === 'unavailable')) return 'unavailable';
  return 'valid';
}

// How much of an entry's own signing was confirmed on this device: "all",
// "some" (one of two signatures; the other method is not built in) or "none".
function verifiedBy(states) {
  if (states.length === 0 || states.some((s) => s.state === 'invalid')) return 'none';
  const valid = states.filter((s) => s.state === 'valid').length;
  return valid === states.length ? 'all' : valid > 0 ? 'some' : 'none';
}

/**
 * What a reader keeps while it reads the entries of a book, one line at a
 * time. Everything worked out from the lines so far is here, so that one
 * more line can be read without reading the others again.
 *
 * In "whole" mode the lines are a whole book: the chain and the running
 * totals are checked. Otherwise they are single pages out of a book, and
 * only what one page can show is checked.
 */
function newReader(options, whole) {
  const ids = new Set();
  // The ids of the approvals used so far: one approval is one action.
  ids.approvals = new Set();
  // The vouching records so far, by fingerprint; and by whom they vouch
  // for, so that looking one up does not mean reading them all.
  /** @type {Map<string, any>} */
  const vouchings = new Map();
  vouchings.index = new Map();
  return {
    options,
    whole,
    // Whether this reader was split off another one to try one more stub, and reads nothing else (forkReader).
    forked: false,
    entries: [],
    /** @type {Map<string, any>} */
    slips: new Map(),
    /** @type {Map<string, any>} */
    terms: new Map(),
    ids,
    // The passes so far, by fingerprint: permissions handed on to helper agents.
    /** @type {Map<string, any>} */
    passes: new Map(),
    vouchings,
    // The seals so far: the last one, how far an outside time-stamp reaches,
    // and the tree as it grows, so that each seal can be compared with the
    // entries before it.
    seals: { count: 0, last: null, lastWhen: -Infinity, lastStampTime: -Infinity, latest: -Infinity, next: 0, sealed: null, book: null, firstPrevious: null },
    tree: whole ? treeBuilder() : null,
    // Problems with what was handed over beside the record (disclosures), which are not faults of an entry.
    handedProblems: [],
  };
}

/**
 * Read one more line: check it against everything read before it, and
 * keep what later lines will need.
 * @param {ReturnType<typeof newReader>} reader
 * @param {{index: number, line: string, disclosures?: string[]}} item the line, its place in the book, and for a
 *   page of a Show the disclosures handed over with it
 */
async function readLine(reader, item) {
  const { options, whole, entries, slips, terms, ids, passes, vouchings, seals, tree, handedProblems } = reader;
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  {
    const { index, line } = item;
    const entry = { index, kind: 'unreadable', fingerprint: null, verified: 'none', problems: [], breaches: [], notes: [] };
    entries.push(entry);
    try {
      // A character is at least one byte, so the first test needs no encoding.
      if (line.length > MAX_LINE_BYTES || utf8(line).length > MAX_LINE_BYTES) {
        throw new Refusal('too-large', 'The line is longer than 131,072 bytes.');
      }
      // Three common slips get words of their own; the codes are those any
      // other such line gets.
      if (line === '') throw new Refusal('not-json', 'The line is empty. A book holds no empty lines, and ends with a single line feed.');
      if (line.startsWith('﻿')) throw new Refusal('not-json', 'The line starts with a byte-order mark, which a book may not hold. Save the file as UTF-8 without one.');
      if (line.endsWith('\r')) {
        throw new Refusal('line-not-canonical', 'The line ends with a carriage return. A line of a book ends with a line feed alone, with no carriage return before it.');
      }
      const value = parseCanonical(line, 'line-not-canonical');
      const names = value !== null && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value).sort().join(',') : '';
      // A reader split off to try one more stub reads nothing else: a stub
      // is the one kind of entry that changes nothing read before it.
      // A denial changes nothing read before it either.
      if (reader.forked && !STUB_ENTRIES.includes(names) && names !== 'denial') throw new Error('only a stub or a denial may be tried');
      if (names === 'slip') {
        entry.kind = 'slip';
        const check = await checkSlip(value.slip, options, item.disclosures);
        // (Disclosures on a page of a Show and disclosures handed over beside it are used together: see checkSlip.)
        for (const p of check.disclosureProblems) {
          handedProblems.push({
            code: p.code,
            message: `The disclosures handed over for the slip at entry ${index} did not pass their check, so they were not used: the slip was checked with those fields covered. ${p.message}`,
          });
        }
        Object.assign(entry, {
          covered: check.covered,
          fingerprint: check.fingerprint,
          problems: check.problems,
          notes: check.notes,
          signature: check.signature,
          issuerKey: check.issuerKey,
          content: check.content,
        });
        if (check.content) {
          if (ids.has(check.content.id)) entry.problems.push({ code: 'duplicate-id', message: 'Another record has the same unique number.' });
          ids.add(check.content.id);
        }
        if (check.fingerprint) {
          if (slips.has(check.fingerprint)) {
            entry.problems.push({ code: 'duplicate-slip', message: 'This slip is already in the book.' });
          } else {
            slips.set(check.fingerprint, {
              content: check.content,
              usable: entry.problems.length === 0,
              verified: entry.problems.length === 0 && check.signature.state === 'valid',
              next: 0,
              last: null,
              lastWhen: -Infinity,
              tally: newTally(),
              // The stubs compared so far, and the cancellation, if there is one.
              stubs: [],
              cancelled: null,
            });
          }
        }
        entry.verified = check.signature.state === 'valid' ? 'all' : 'none';
        // Who vouches for the names in the slip, if anyone does.
        if (check.content) {
          const s = check.content;
          // A vouching record must be in force for the whole of the slip's time.
          const span = { from: parseTime(s.validFrom), until: parseTime(s.validUntil) };
          entry.vouched = {
            issuer: vouchFor(vouchings, 'person', s.issuer.key, s.issuer.name, span),
            agent: vouchFor(vouchings, 'agent', s.agent.keys, s.agent.name, span),
            // Every service has a place here, so that looking one up by its id finds only what was put there.
            services: Object.fromEntries(s.with.map((w) => [w.id, keysOf(w) ? vouchFor(vouchings, 'service', w.keys, w.name, span) : null])),
          };
          // A name that an organisation the checker trusts vouches for is no longer only a label.
          if (entry.vouched.issuer && entry.vouched.issuer.counted) {
            entry.notes = entry.notes.filter((n) => !n.startsWith('The issuer\'s key was not compared'));
          }
        }
      } else if (STUB_ENTRIES.includes(names)) {
        entry.kind = 'stub';
        await checkStubEntry(entry, value, slips, terms, passes, ids, without, whole);
      } else if (names === 'refusal') {
        entry.kind = 'refusal';
        await checkRefusalEntry(entry, value, slips, ids, without, whole);
      } else if (names === 'terms') {
        entry.kind = 'terms';
        await checkTermsEntry(entry, value, terms, ids, without);
      } else if (SEAL_ENTRIES.includes(names)) {
        entry.kind = 'seal';
        // The line itself is kept, out of sight, so that a seal held elsewhere can be compared with it (checkHeldSeals).
        sealLines.set(entry, line);
        // The top fingerprint of the entries before it is worked out only once the seal has been read.
        const before = whole ? async () => ({ size: index, root: toBase64url(await tree.root()) }) : null;
        await checkSealEntry(entry, value, seals, ids, options, before, entries, !whole);
        if (entry.content) {
          // In force at the time the seal states and, where a counted time-stamp says when the seal existed, then too.
          const times = [parseTime(entry.content.when)];
          if (entry.stampedAt) times.push(parseTime(entry.stampedAt));
          entry.vouched = vouchFor(vouchings, 'recorder', entry.content.by.keys, entry.content.by.name, { from: Math.min(...times), until: Math.max(...times) + 1 });
          if (entry.vouched && entry.vouched.counted) entry.notes = entry.notes.filter((n) => !n.startsWith('The keys that signed this seal were not compared'));
        }
      } else if (names === 'cancellation' || names === 'cancellation,stamps') {
        entry.kind = 'cancellation';
        await checkCancellationEntry(entry, value, slips, ids, options, whole);
      } else if (names === 'acknowledgement') {
        entry.kind = 'acknowledgement';
        await checkAcknowledgementEntry(entry, value, slips, passes, ids, entries, without, whole);
      } else if (names === 'denial') {
        entry.kind = 'denial';
        await checkDenialEntry(entry, value, slips, passes, ids, without, whole);
      } else if (names === 'pass') {
        entry.kind = 'pass';
        await checkPassEntry(entry, value, slips, passes, ids, without, whole);
        if (entry.content) {
          const span = { from: parseTime(entry.content.validFrom), until: parseTime(entry.content.validUntil) };
          entry.vouched = vouchFor(vouchings, 'agent', entry.content.to.keys, entry.content.to.name, span);
        }
      } else if (names === 'vouching') {
        entry.kind = 'vouching';
        await checkVouchingEntry(entry, value, vouchings, ids, options);
      } else if (names === 'withdrawal') {
        entry.kind = 'withdrawal';
        await checkWithdrawalEntry(entry, value, vouchings, ids, options, whole);
      } else {
        throw new Refusal('unknown-entry', 'The line is not one of the known kinds of entry.');
      }
      // Only a slip may hold covered fields: disclosures handed over with any other page belong to nothing.
      if (item.disclosures !== undefined && entry.kind !== 'slip') {
        entry.problems.push({ code: 'cover-invalid', message: 'Disclosures were handed over with a page that is not a slip. Only a slip may hold covered fields.' });
      }
    } catch (e) {
      entry.problems.push(problemFrom(e));
    }
    if (entry.problems.length) entry.verified = 'none';
    // The latest time that a sound entry so far states: a seal cannot be dated before it.
    else if (entry.verified !== 'none' && whenOf(entry) > seals.latest) seals.latest = whenOf(entry);
    if (tree) await tree.add(utf8(line));
  }
}

/**
 * The findings that can be made only once every stub so far has been read:
 * the limits "in any period" (a stub further on in the book, in another
 * chain, may be dated earlier), and what a cancellation handed over beside
 * the book shows (checkHeld). They are worked out afresh for each answer
 * and kept apart from the entries, each list under its entry's own list of
 * findings, so that a book can be carried on after an answer was given.
 * @returns {Map<object[], {code: string, message: string}[]>}
 */
function settleLate(reader) {
  const late = new Map();
  // The slips first, then the passes from the last in the book to the
  // first, which is from the pass nearest a stub upwards: a finding
  // already given for a stub is not given again (compare.js).
  for (const slip of reader.slips.values()) if (slip.content) settlePeriods(slip.content, slip.tally, late);
  for (const pass of [...reader.passes.values()].reverse()) settlePeriods(passAsSlip(pass.content), pass.tally, late);
  return late;
}

// An entry as an answer gives it: with the findings that were worked out
// last, and with no time of its own if it did not pass its check. The
// entry the reader keeps is left as it is.
function answered(entry, late, entries, why = () => null) {
  const more = late.get(entry.breaches);
  const copy = more && more.length > 0 ? { ...entry, breaches: [...entry.breaches, ...more] } : { ...entry };
  // A cancellation that passed when its acknowledgement was read may have
  // failed since: a later seal's time-stamp can show that it is not dated
  // as it says. The acknowledgement then names a cancellation that did not
  // pass its check.
  if (entry.kind === 'acknowledgement' && entry.cancellation !== undefined && entries[entry.cancellation].problems.length > 0) failAcknowledgement(copy);
  if (copy.problems.length > 0) delete copy.stampedAt;
  // Whether each witness statement counts is settled now that the seal's own check is complete.
  if (copy.kind === 'seal' && Array.isArray(copy.witnesses)) Object.assign(copy, witnessesCounted(copy, why(copy)));
  return copy;
}

function failAcknowledgement(entry) {
  entry.problems = [...entry.problems, { code: 'cancellation-not-found', message: 'The cancellation this acknowledgement names did not pass its own check.' }];
  entry.verified = 'none';
  delete entry.cancellation;
}

/**
 * A reader that carries on by itself from where this one stands, to try
 * one more line. The reader it was split from is left exactly as it was,
 * whatever becomes of this one.
 *
 * To try a stub, what a stub changes is copied (its chain, the running
 * totals, the unique numbers, the tree); the entries read so far, the
 * terms and the vouching records are shared, because a stub changes none
 * of them, and such a reader refuses any other kind of line.
 *
 * To try a line of any kind ("whole"), the entries are copied as well,
 * with the lists inside them that a later line may add to (a seal's
 * time-stamp marks the entries before it; a cancellation marks stubs),
 * and so are the terms and the vouching records. Whatever points at an
 * entry, or at its list of findings, is pointed at the copy.
 *
 * @param {ReturnType<typeof newReader>} reader
 * @param {boolean} [whole] true to read any kind of line
 */
function forkReader(reader, whole = false) {
  const twinEntry = new Map();
  const twinList = new Map();
  const entries = whole
    ? reader.entries.map((e) => {
        const copy = { ...e, problems: e.problems.slice(), breaches: e.breaches.slice(), notes: e.notes.slice() };
        twinEntry.set(e, copy);
        twinList.set(e.breaches, copy.breaches);
        if (stampedTimes.has(e)) stampedTimes.set(copy, stampedTimes.get(e));
        if (sealLines.has(e)) sealLines.set(copy, sealLines.get(e));
        return copy;
      })
    : reader.entries.slice();
  const copyTally = (t) => ({
    sums: new Map(t.sums),
    counts: new Map(t.counts),
    periods: new Map([...t.periods].map(([i, items]) => [i, whole ? items.map((item) => ({ ...item, late: twinList.get(item.late) ?? item.late })) : items.slice()])),
  });
  const slips = new Map();
  for (const [fingerprint, s] of reader.slips) {
    slips.set(fingerprint, {
      ...s,
      tally: copyTally(s.tally),
      stubs: whole ? s.stubs.map((e) => twinEntry.get(e) ?? e) : s.stubs.slice(),
      cancelled: s.cancelled === null ? null : { ...s.cancelled },
    });
  }
  // The vouching records can be withdrawn by a later line: they are copied, and found again by the copies.
  let { terms, vouchings } = reader;
  if (whole) {
    terms = new Map(reader.terms);
    const twinVouching = new Map();
    vouchings = new Map();
    for (const [fingerprint, v] of reader.vouchings) {
      const copy = { ...v };
      twinVouching.set(v, copy);
      vouchings.set(fingerprint, copy);
    }
    vouchings.index = new Map();
    for (const [key, found] of reader.vouchings.index) {
      vouchings.index.set(key, { counted: found.counted.map((v) => twinVouching.get(v) ?? v), other: found.other.map((v) => twinVouching.get(v) ?? v) });
    }
  }
  // A pass points to the pass it was handed on from, which is earlier in the book: the copies point to the copies.
  const passes = new Map();
  const twins = new Map();
  for (const [fingerprint, p] of reader.passes) {
    const copy = { ...p, parent: p.parent ? twins.get(p.parent) : null, tally: copyTally(p.tally) };
    twins.set(p, copy);
    passes.set(fingerprint, copy);
  }
  const ids = new Set(reader.ids);
  ids.approvals = new Set(reader.ids.approvals);
  return {
    ...reader,
    forked: !whole,
    entries,
    slips,
    terms,
    passes,
    ids,
    vouchings,
    seals: { ...reader.seals },
    tree: reader.tree.fork(),
    handedProblems: reader.handedProblems.slice(),
  };
}

// The options a checker reads. Each is read once, as a whole check reads
// it: by its name, whether the member is the object's own, inherited, or
// worked out when it is asked for.
// The fixed copies made so far. Nothing changes one once it is made.
const FIXED = new WeakSet();
const OPTION_NAMES = ['issuerKeys', 'issuerOrigins', 'sealKeys', 'stampServices', 'blocks', 'vouchers', 'witnesses', 'disclosures', 'cancellations', 'seals', 'expectedRoot', 'expectedSize', 'withoutMethods'];

/**
 * The options of a check, fixed: read once and copied, so that nothing done
 * afterwards to what was handed over changes a check that is carried on.
 * Lists and plain objects are copied, through and through. Anything else
 * (an object of a class, a function, or a value that cannot be looked
 * into, such as a revoked Proxy, or a list whose length is not a whole
 * number) is kept as it was handed over: a check refuses or ignores it
 * exactly as a whole check does. A value met twice is copied once, so that
 * the copy holds the same sharing, and the same loops, as what was handed
 * over, and costs no more to make than that has values. A value more than
 * 16 levels down cannot be read: no option nests so deep, and nothing past
 * that depth is kept as it was handed over. A fixed copy handed in again is
 * used as it is. Not part of the public interface.
 * @param {any} options
 * @returns {object}
 */
export function fixedOptions(options) {
  if (FIXED.has(options)) return options;
  const fixed = {};
  FIXED.add(fixed);
  if (options === null || typeof options !== 'object') return fixed;
  const copies = new Map();
  const copy = (value, depth) => {
    if (value === null || typeof value !== 'object') return value;
    if (depth > 16) throw new RangeError('The options nest more than 16 levels deep.');
    if (copies.has(value)) return copies.get(value);
    // What the value is, and which members it has, is found out first. A
    // value that cannot be looked into is kept as it was handed over.
    let list;
    let made;
    let names;
    try {
      list = Array.isArray(value);
      if (list) {
        // A gap stays a gap, so that the copy is read as a whole check reads
        // the list. Only the places that hold an item are visited, so a long
        // list with few items in it costs little.
        const length = value.length;
        if (!(Number.isInteger(length) && length >= 0 && length <= 2 ** 32 - 1)) return value;
        names = Object.getOwnPropertyNames(value)
          .filter((name) => /^(0|[1-9][0-9]*)$/.test(name) && Number(name) < length)
          .map((name) => [name, true]);
        made = new Array(length);
      } else {
        const proto = Object.getPrototypeOf(value);
        if (proto !== Object.prototype && proto !== null) return value;
        // A member with a special name, such as "__proto__", stays a member like any other.
        // A member that is not enumerable stays so: a whole check sees it where it reads a
        // member by its name, and not where it lists the members, and so does the copy.
        names = Object.getOwnPropertyNames(value).map((name) => [name, Object.getOwnPropertyDescriptor(value, name)?.enumerable === true]);
        made = proto === null ? Object.create(null) : {};
      }
    } catch {
      return value;
    }
    copies.set(value, made);
    for (const [name, enumerable] of names) take(made, value, name, depth, enumerable);
    return made;
  };
  // One member or place, read once. One that cannot be read fails, with the
  // same error, wherever a whole check reads it, and nowhere else.
  const take = (made, value, name, depth, enumerable) => {
    try {
      Object.defineProperty(made, name, { value: copy(value[name], depth + 1), enumerable, writable: true, configurable: true });
    } catch (e) {
      Object.defineProperty(made, name, { get: () => { throw e; }, enumerable, configurable: true });
    }
  };
  for (const name of OPTION_NAMES) {
    let value;
    try {
      value = options[name];
    } catch (e) {
      Object.defineProperty(fixed, name, { get: () => { throw e; }, enumerable: true, configurable: true });
      continue;
    }
    if (value !== undefined) fixed[name] = copy(value, 0);
  }
  return fixed;
}

/** The most vouching records from organisations the checker did not name that are kept for one name and key. */
const MAX_UNCOUNTED = 8;

// The keys a slip gives for a service, if it gives any.
export const keysOf = (service) => (service !== null && typeof service === 'object' && Object.hasOwn(service, 'keys') ? service.keys : null);

// What a vouching record is found by: the kind, the key or keys, and the name, exactly.
const vouchedKey = (kind, key, name) => canonicalJson([kind, key, name]);

/**
 * Who vouches for a name: the vouching record earlier in the book, still
 * standing, that names exactly this key (or these keys) and exactly this
 * name, and was in force for the whole of the time given. One from an
 * organisation the checker named as trusted is preferred, and only that
 * one counts.
 * @param {any} vouchings the vouching records so far, with their index
 * @param {string} kind
 * @param {any} key the key, or the keys
 * @param {any} name the name; a covered name is not text, and nobody vouches for it
 * @param {{from: number, until: number}} span the time: from, and until (not included)
 * @returns {{counted: boolean, by: string, keys: string}|null}
 */
function vouchFor(vouchings, kind, key, name, span) {
  if (typeof name !== 'string') return null;
  const found = vouchings.index.get(vouchedKey(kind, key, name));
  if (!found) return null;
  const standing = (v) => !v.withdrawn && span.from >= parseTime(v.content.validFrom) && span.until <= parseTime(v.content.validUntil);
  const v = found.counted.find(standing) ?? found.other.find(standing);
  return v ? { counted: v.counted, by: v.content.by.name, keys: v.signer } : null;
}

// The pass a stub or a further pass relies on.
function findPass(passes, fingerprint, slipFingerprint, whole) {
  const pass = passes.get(fingerprint);
  if (!pass || !pass.usable) {
    throw new Refusal('pass-missing', whole ? 'The pass this entry relies on is not earlier in the book, or did not pass its own check.' : 'The pass this entry relies on is not among the pages, or did not pass its own check.');
  }
  if (pass.content.slip !== slipFingerprint) throw new Refusal('pass-mismatch', 'The pass this entry relies on was given under another slip.');
  return pass;
}

// A pass seen as a slip, so that the same comparison can be made with it.
export function passAsSlip(p) {
  return { actions: p.actions, limits: p.limits, requires: [], never: [], validFrom: p.validFrom, validUntil: p.validUntil };
}

// A pass: an agent hands part of its permission to a helper agent.
async function checkPassEntry(entry, value, slips, passes, ids, without, whole) {
  entry.signatures = [];
  // Whether this pass was compared with what its writer holds. It is not,
  // if the pass or the slip could not be confirmed.
  entry.compared = false;
  const parsed = await parseRecord(value.pass, 'pass');
  entry.fingerprint = parsed.fingerprint;
  validatePassContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  entry.slip = c.slip;
  noteId(entry, ids, c.id);
  const slip = findSlip(slips, c.slip, whole);
  // Who may pass on: the slip's own agent, or the helper named in the pass before.
  const parent = Object.hasOwn(c, 'from') ? findPass(passes, c.from, c.slip, whole) : null;
  entry.signatures = await checkKeySetSignatures(parsed, parent ? parent.content.to.keys : slip.content.agent.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({ code: 'signature-invalid', message: 'A signature on the pass does not fit the keys of the agent that passes on.' });
  }
  entry.verified = verifiedBy(entry.signatures);
  underConfirmedSlip(entry, slip);
  const level = parent ? parent.level + 1 : 1;
  // No slip can allow a permission to be passed on more than ten times in
  // a row. A pass further down is refused, so that every stub can be
  // compared with every pass above its own.
  if (level > MAX_PASSES) {
    entry.problems.push({ code: 'pass-too-deep', message: 'A permission may be passed on at most ten times in a row, and this pass is one more.' });
  }
  const allowed = Object.hasOwn(slip.content, 'passes') ? slip.content.passes : 0;
  let notAllowed = parent ? parent.notAllowed : false;

  // What the pass shows about the agent that passed on.
  if (entry.problems.length === 0 && entry.verified !== 'none' && slip.verified) {
    entry.compared = true;
    const held = parent ? parent.content : slip.content;
    if (level > allowed) {
      notAllowed = true;
      entry.breaches.push({
        code: 'pass-not-allowed',
        message: allowed === 0 ? 'The slip does not allow its permission to be passed on.' : `The slip allows its permission to be passed on ${allowed === 1 ? 'once' : `${allowed} times`}, and this is one more.`,
      });
    }
    if (c.actions.some((action) => !held.actions.includes(action)) || parseTime(c.validFrom) < parseTime(held.validFrom) || parseTime(c.validUntil) > parseTime(held.validUntil)) {
      entry.breaches.push({ code: 'pass-wider', message: 'The pass hands on more than the agent that wrote it holds: an action, or a time, outside its own permission.' });
    }
    const when = parseTime(c.when);
    if (when < parseTime(held.validFrom) || when >= parseTime(held.validUntil)) {
      entry.breaches.push({ code: 'outside-valid-time', message: 'The pass is dated outside the time its writer\'s own permission allows.' });
    }
    if (slip.cancelled !== null) entry.breaches.push({ code: 'after-cancellation', message: 'The person cancelled the slip before this pass.' });
  }
  if (passes.has(parsed.fingerprint)) entry.problems.push({ code: 'duplicate-id', message: 'This pass is already in the book.' });
  else {
    passes.set(parsed.fingerprint, {
      content: c,
      usable: entry.problems.length === 0,
      // The pass this one was handed on from, if any.
      parent,
      level,
      notAllowed,
      // The helper's own chain of stubs, and its running totals under the pass.
      next: 0,
      last: null,
      lastWhen: -Infinity,
      tally: newTally(),
    });
  }
}

// A vouching record: an organisation states that a key belongs to a name.
async function checkVouchingEntry(entry, value, vouchings, ids, options) {
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  entry.signatures = [];
  const parsed = await parseRecord(value.vouching, 'vouching');
  entry.fingerprint = parsed.fingerprint;
  validateVouchingContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  noteId(entry, ids, c.id);
  entry.signatures = await checkKeySetSignatures(parsed, c.by.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({ code: 'signature-invalid', message: 'A signature on the vouching record does not fit the keys it gives.' });
  }
  entry.verified = verifiedBy(entry.signatures);
  entry.signer = await keySetFingerprint(c.by.keys);
  // It counts only if the checker named this organisation as one it trusts.
  entry.counted = Array.isArray(options.vouchers) && options.vouchers.includes(entry.signer);
  if (!entry.counted) {
    entry.notes.push(`This vouching record is from an organisation you did not name as trusted, so it is not counted. The fingerprint of its key set is ${entry.signer}.`);
  }
  if (vouchings.has(parsed.fingerprint)) entry.problems.push({ code: 'duplicate-id', message: 'This vouching record is already in the book.' });
  else {
    const usable = entry.problems.length === 0 && entry.verified !== 'none';
    const vouching = { content: c, signer: entry.signer, usable, counted: entry.counted && usable, withdrawn: false };
    vouchings.set(parsed.fingerprint, vouching);
    if (usable) {
      const key = vouchedKey(c.for.kind, c.for.kind === 'person' ? c.for.key : c.for.keys, c.for.name);
      const found = vouchings.index.get(key) ?? { counted: [], other: [] };
      vouchings.index.set(key, found);
      // Only an organisation the checker named can add to the first list.
      // Anyone can add to the second, so it is kept short.
      if (vouching.counted) found.counted.push(vouching);
      else if (found.other.length < MAX_UNCOUNTED) found.other.push(vouching);
    }
  }
}

// A withdrawal: the organisation ends one of its vouching records. From
// this place in the book onwards that record vouches for nothing.
async function checkWithdrawalEntry(entry, value, vouchings, ids, options, whole) {
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  entry.signatures = [];
  const parsed = await parseRecord(value.withdrawal, 'withdrawal');
  entry.fingerprint = parsed.fingerprint;
  validateWithdrawalContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  noteId(entry, ids, c.id);
  const vouching = vouchings.get(c.vouching);
  if (!vouching) {
    throw new Refusal('vouching-missing', whole ? 'The vouching record this withdrawal ends is not earlier in the book.' : 'The vouching record this withdrawal ends is not among the pages.');
  }
  // Only the organisation that vouched can withdraw.
  entry.signatures = await checkKeySetSignatures(parsed, vouching.content.by.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({ code: 'signature-invalid', message: 'A signature on the withdrawal does not fit the keys of the organisation that vouched.' });
  }
  entry.verified = verifiedBy(entry.signatures);
  entry.signer = vouching.signer;
  if (entry.problems.length === 0 && entry.verified !== 'none') vouching.withdrawn = true;
}

// A cancellation: the person ends a slip early, with the passkey that signed it.
async function checkCancellationEntry(entry, value, slips, ids, options, whole) {
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  entry.stamps = [];
  const parsed = await parseRecord(value.cancellation, 'cancellation');
  entry.fingerprint = parsed.fingerprint;
  validateCancellationContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  entry.slip = c.slip;
  noteId(entry, ids, c.id);
  const slip = findSlip(slips, c.slip, whole);
  const alg = slip.content.issuer.key.alg;
  entry.signature = { method: `passkey (${alg})`, alg, state: 'invalid' };
  try {
    entry.signature.state = await checkPasskeySignature(parsed, slip.content.issuer, without);
  } catch {
    throw new Refusal('cancellation-invalid', 'The cancellation was not signed with the passkey the slip names, or its passkey values do not check.');
  }
  entry.verified = entry.signature.state === 'valid' ? 'all' : 'none';
  // A time-stamp is held against the cancellation's own date only where this device could confirm the cancellation.
  const confirmed = entry.verified === 'all' && slip.verified;
  const time = Object.hasOwn(value, 'stamps') ? await checkStamps(entry, value.stamps, parsed.fingerprint, parseTime(c.when), options, confirmed) : null;
  if (time !== null && entry.problems.length === 0 && !confirmed) {
    entry.notes.push('The time-stamp beside this cancellation was not counted: this device could not check the cancellation\'s signature, or the slip\'s.');
  }
  if (entry.problems.length > 0 || entry.verified === 'none' || !slip.verified) return;
  // Every sound cancellation counts. The slip is cancelled from the place
  // of the first one in the book, and the earliest time that a counted
  // time-stamp gives any of them is the time used for the stubs before it.
  // So whoever keeps the book gains nothing by the order they stand in.
  const first = slip.cancelled === null;
  if (first) slip.cancelled = { index: entry.index, time: null };
  else entry.notes.push('The slip had already been cancelled, earlier in the book. Every cancellation counts: the earliest time that a time-stamp you trust gives any of them is the one used.');
  if (time === null) {
    if (first) entry.notes.push('This cancellation has no time-stamp from a service you named as trusted. Only its place in the book says when it took effect.');
    return;
  }
  // The time of a cancellation is the earliest its time-stamps allow.
  const made = cancelledAt(entry, parseTime(c.when));
  entry.stampedAt = formatTime(made);
  noteLateStamp(entry, made, c.when);
  noteBlockSetAside(entry, parseTime(c.when), CANCELLATION_BLOCK_SET_ASIDE);
  if (!whole) {
    entry.notes.push('This cancellation is time-stamped. Single pages cannot show which stubs existed before that time: that needs the seals of the whole book. Here only the place of each page in the book is used.');
    return;
  }
  if (slip.cancelled.time !== null && slip.cancelled.time <= made) return;
  slip.cancelled.time = made;
  markNotShownEarlier(slip, made, 'This stub is not shown to have existed before the person cancelled the slip: no outside time-stamp from before the cancellation covers it.');
}

// An acknowledgement: the agent's side states that it was handed the
// person's cancellation of a slip, and when. It is signed with the keys of
// the agent the slip names or, where it names a pass, of the helper agent
// that pass names. In a book it comes after the cancellation it names.
async function checkAcknowledgementEntry(entry, value, slips, passes, ids, entries, without, whole) {
  entry.signatures = [];
  const parsed = await parseRecord(value.acknowledgement, 'acknowledgement');
  entry.fingerprint = parsed.fingerprint;
  validateAcknowledgementContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  entry.slip = c.slip;
  noteId(entry, ids, c.id);
  const slip = findSlip(slips, c.slip, whole);
  const pass = Object.hasOwn(c, 'pass') ? findPass(passes, c.pass, c.slip, whole) : null;
  if (pass) entry.pass = c.pass;
  entry.signatures = await checkKeySetSignatures(parsed, pass ? pass.content.to.keys : slip.content.agent.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({
      code: 'signature-invalid',
      message: pass ? 'A signature on the acknowledgement does not fit the keys of the helper agent the pass names.' : 'A signature on the acknowledgement does not fit the agent\'s keys.',
    });
  }
  entry.verified = verifiedBy(entry.signatures);
  underConfirmedSlip(entry, slip);
  // The cancellation it names: of the same slip, and sound.
  const named = entries.find((e) => e !== entry && e.kind === 'cancellation' && e.fingerprint === c.cancellation);
  if (!named) {
    entry.problems.push({
      code: 'cancellation-not-found',
      message: whole ? 'The cancellation this acknowledgement names is not earlier in the book.' : 'The cancellation this acknowledgement names is not among the pages.',
    });
  } else if (named.problems.length > 0 || named.slip !== c.slip) {
    entry.problems.push({ code: 'cancellation-not-found', message: 'The cancellation this acknowledgement names did not pass its own check, or cancels another slip.' });
  } else {
    entry.cancellation = named.index;
  }
}

// A denial: the agent's side states that it did not take an action that was
// asked for, and why. It is signed as an acknowledgement is, with the keys of
// the agent the slip names or of the helper agent its pass names. It is in
// no chain and is compared with nothing: a checker does not judge whether
// the refusal was right, and never counts it against the agent.
const DENIED = 'The agent\'s side states that it did not take this action, and why. That is its own word: it is not counted against the agent, and it does not show that the action was not taken in some other way.';
async function checkDenialEntry(entry, value, slips, passes, ids, without, whole) {
  entry.signatures = [];
  const parsed = await parseRecord(value.denial, 'denial');
  entry.fingerprint = parsed.fingerprint;
  validateDenialContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  entry.slip = c.slip;
  noteId(entry, ids, c.id);
  const slip = findSlip(slips, c.slip, whole);
  const pass = Object.hasOwn(c, 'pass') ? findPass(passes, c.pass, c.slip, whole) : null;
  if (pass) entry.pass = c.pass;
  entry.signatures = await checkKeySetSignatures(parsed, pass ? pass.content.to.keys : slip.content.agent.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({
      code: 'signature-invalid',
      message: pass ? 'A signature on the denial does not fit the keys of the helper agent the pass names.' : 'A signature on the denial does not fit the agent\'s keys.',
    });
  }
  entry.verified = verifiedBy(entry.signatures);
  underConfirmedSlip(entry, slip);
  if (entry.problems.length === 0 && entry.verified !== 'none') entry.notes.push(DENIED);
}

// The acknowledgements handed over with the person's own copy of a
// cancellation. Each must be for exactly that cancellation, and signed with
// the keys of the slip's agent, or of a helper agent under a pass that the
// book holds. One that does not check is a problem of its own: it is not
// used, the reader is told, and the cancellation itself still counts. (The
// agent's side cannot spoil the person's copy by handing them an
// acknowledgement that does not check.)
// "confirmed": whether this device confirmed the slip and the copy, and so
// whose keys an acknowledgement is to be held against.
// Returns the problems found.
async function checkHeldAcknowledgements(held, list, fingerprintText, slipFingerprint, slip, passes, entries, without, confirmed) {
  const problems = [];
  try {
    f.list(list, 1, MAX_ACKNOWLEDGEMENTS, 'acknowledgements');
  } catch (e) {
    return [problemFrom(e)];
  }
  const seen = new Set();
  // Read place by place, never through the list's own way of walking through itself.
  for (let i = 0; i < list.length; i++) {
    const record = list[i];
    try {
      const parsed = await parseRecord(record, 'acknowledgement');
      validateAcknowledgementContent(parsed.content);
      const a = parsed.content;
      if (a.cancellation !== fingerprintText || a.slip !== slipFingerprint) {
        throw new Refusal('acknowledgement-mismatch', 'An acknowledgement handed over with it was given for another cancellation, or under another slip.');
      }
      if (seen.has(parsed.fingerprint)) throw f.fail('acknowledgements', 'the same acknowledgement is handed over twice.');
      seen.add(parsed.fingerprint);
      let pass = null;
      if (Object.hasOwn(a, 'pass')) {
        pass = passes.get(a.pass);
        if (!pass || !pass.usable || pass.content.slip !== slipFingerprint) {
          throw new Refusal('pass-missing', 'The pass an acknowledgement names is not in the book, was given under another slip, or did not pass its own check.');
        }
      }
      const signatures = await checkKeySetSignatures(parsed, pass ? pass.content.to.keys : slip.content.agent.keys, without);
      let state = overall(signatures);
      if (state === 'invalid') throw new Refusal('signature-invalid', 'A signature on an acknowledgement handed over with it does not fit the keys of the agent it is said to be from.');
      // The keys it was held against came from the slip: where this device could not confirm the slip or the copy, it confirmed nothing here either.
      if (!confirmed) state = 'unavailable';
      const inBook = entries.find((e) => e.kind === 'acknowledgement' && e.fingerprint === parsed.fingerprint);
      held.acknowledgements.push({
        fingerprint: parsed.fingerprint,
        by: pass ? 'helper' : 'agent',
        pass: pass ? a.pass : null,
        state,
        signatures,
        // What it says is given only where this device confirmed who signed it.
        when: state === 'valid' ? a.when : null,
        inBook: inBook ? inBook.index : null,
      });
    } catch (e) {
      problems.push(problemFrom(e));
    }
  }
  return problems;
}

// What an acknowledgement shows, where the person hands it over with their
// own copy of the cancellation: the agent's side says it was told at that
// time. A stub of that agent's own chain that is dated later was, by the
// agent's own dates, made after it was told. So was a pass that the agent
// handed on later, every pass handed on from such a pass, and every stub
// under any of them: an agent that was told cannot go on through a helper.
// Both dates are the agent's own word; the finding says so.
//
// It is applied after the time-stamp rule (markNotShownEarlier), whichever
// order the copies were handed over in. A stub that the time-stamp rule
// already reports keeps that finding, which rests on an outside
// time-stamp, and the finding is added to.
const ACKNOWLEDGED = 'the agent\'s side acknowledged that it was handed the person\'s cancellation of the slip. Both dates are the agent\'s own word. The acknowledgement was handed over beside the book, with the person\'s own copy of the cancellation.';
function markAfterAcknowledged(slip, slipFingerprint, passes, entries, acknowledgement, late, strict, added, underPasses) {
  const marked = (b) => b.code === 'after-cancellation';
  const told = parseTime(acknowledgement.when);
  // Whether a pass was handed on by the acknowledging agent after it was told, or comes from such a pass.
  const handedOnLate = (pass) => {
    for (let p = pass; p; p = p.parent) {
      const writer = Object.hasOwn(p.content, 'from') ? p.content.from : null;
      if (writer === acknowledgement.pass && parseTime(p.content.when) > told) return true;
    }
    return false;
  };
  const mark = (entry, message) => {
    const more = late.get(entry.breaches);
    if (entry.breaches.some(marked)) return;
    const already = more ? more.find(marked) : undefined;
    if (already) {
      // Reported by the time-stamp rule: said as well, once.
      if (strict.has(already) && !added.has(already)) {
        already.message += ' It is also dated after the agent\'s side acknowledged the cancellation, by the agent\'s own dates.';
        added.add(already);
      }
      return;
    }
    const finding = { code: 'after-cancellation', message };
    if (more) more.push(finding);
    else late.set(entry.breaches, [finding]);
  };
  for (const stub of slip.stubs) {
    const pass = stub.pass === undefined ? null : passes.get(stub.pass);
    if ((stub.pass ?? null) === acknowledgement.pass && parseTime(stub.content.when) > told) {
      if (!underPasses) mark(stub, `This stub is dated after ${ACKNOWLEDGED}`);
    } else if (underPasses && pass && handedOnLate(pass)) mark(stub, `This stub was written under a pass that was handed on after ${ACKNOWLEDGED}`);
  }
  if (!underPasses) return;
  for (const entry of entries) {
    if (entry.kind !== 'pass' || entry.slip !== slipFingerprint || entry.compared !== true) continue;
    const pass = passes.get(entry.fingerprint);
    if (pass && handedOnLate(pass)) mark(entry, `This pass was handed on, or comes from a pass that was handed on, after ${ACKNOWLEDGED}`);
  }
}

// The time-stamps stand beside a cancellation, and whoever keeps it could
// put a later one in the place of an earlier one. No check can show that. A
// gap between the person's own date and the time-stamp is what it would
// leave, so the gap is pointed out.
function noteLateStamp(entry, time, when) {
  if (time > parseTime(when) + CLOCK_ALLOWANCE_MS) {
    entry.notes.push(
      'The time-stamp on this cancellation states a time more than 300 seconds after the date the person\'s device gave. Whoever keeps the book could have put a later time-stamp in the place of an earlier one. If the person holds an earlier time-stamp of this cancellation, that is the one to go by.',
    );
  }
}

// With a time-stamp, a cancellation has a proven time. A stub counts as
// made before it only if an outside time-stamp shows that it existed by
// then. An agent cannot escape a cancellation by writing an earlier time.
//
// For a cancellation in the book the finding goes into the stub's own
// list. For one handed over beside the book it is gathered in "late", as
// the other findings are that are worked out afresh for each answer
// (settleLate).
function markNotShownEarlier(slip, time, message, late = null, strict = null) {
  const marked = (b) => b.code === 'after-cancellation';
  for (const stub of slip.stubs) {
    const more = late ? late.get(stub.breaches) : undefined;
    if (stub.breaches.some(marked) || (more && more.some(marked))) continue;
    if (!((stampedTimes.get(stub) ?? Infinity) > time + CLOCK_ALLOWANCE_MS)) continue;
    const finding = { code: 'after-cancellation', message };
    // The findings made here for a copy handed over beside the book are noted, for markAfterAcknowledged.
    if (strict) strict.add(finding);
    if (!late) stub.breaches.push(finding);
    else if (more) more.push(finding);
    else late.set(stub.breaches, [finding]);
  }
}

// The time of the first counted time-stamp that covers an entry, as a number.
const stampedTimes = new WeakMap();
// The line of each seal in the book, exactly as it stands there.
const sealLines = new WeakMap();

// The outside time-stamps beside a record. Each states that the record
// existed at a time. Returns the earliest time stated by a service the
// checker trusts, or null.
async function checkStamps(entry, stamps, fingerprintText, when, options, counted = true, floor = -Infinity) {
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  const stamped = fromBase64url(fingerprintText);
  const methods = { without: without.filter((m) => m === 'RSA' || m === 'ECDSA' || m === 'Ed25519'), trusted: options.stampServices };
  for (const item of decodeStamps(stamps)) {
    try {
      const stamp = item.kind === 'block' ? await checkBlockStamp(item.proof, item.header, stamped, options.blocks) : { kind: 'service', ...(await checkStamp(item.token, stamped, methods)) };
      // A service states one time. A block's time is loose, and has two (blockstamp.js).
      stamp.earliest ??= stamp.time;
      entry.stamps.push(stamp);
    } catch (e) {
      entry.stamps.push({ kind: item.kind, state: 'invalid', when: null, time: NaN, authority: null });
      entry.problems.push(problemFrom(e));
    }
  }
  for (const s of entry.stamps) {
    if (s.state !== 'untrusted') continue;
    entry.notes.push(
      s.kind === 'block'
        ? `A block time-stamp on this record leads to a block you did not name as trusted. The block's fingerprint is ${s.authority}.`
        : `A time-stamp on this record is from a service you did not name as trusted. Its certificate's fingerprint is ${s.authority}.`,
    );
  }
  const giving = givingStamps(entry, when, floor);
  const time = giving.length ? Math.min(...giving.map((s) => s.time)) : null;
  // A record dated later than the time-stamp that covers it is not as it
  // says. Said only where the time-stamp can be counted at all.
  if (counted && time !== null && time < when - CLOCK_ALLOWANCE_MS) {
    entry.problems.push({ code: 'dated-after-stamp', message: 'This record is dated later than a time-stamp that covers it.' });
  }
  return time;
}

// The time-stamps that give a seal its time: every counted one, and the
// earliest time any of them states is the time by which the seal existed.
// (A block states its time and two hours.) Two cases are set apart, both
// of a block that states a time far behind the true time, which a service
// settles. The reader is told of each (noteBlockSetAside, noteBlockBehind).
//  - Beside a time-stamp from a service, a block that states a time more
//    than 300 seconds before the seal's own date, even with its two hours,
//    is set aside. With no service's time-stamp beside it, nothing settles
//    it, and the record reads as dated after its time-stamp.
//  - A block that states a time, even with its two hours, more than 300
//    seconds before the latest time a service gave a seal before this one
//    ("floor") is set aside. This seal covers that seal's line, time-stamp
//    included, so it cannot have existed by then.
// (For a cancellation, the time it counts from is worked out by cancelledAt.)
function givingStamps(entry, when, floor = -Infinity) {
  const valid = entry.stamps.filter((s) => s.state === 'valid' && !behindEarlierSeal(s, floor));
  if (!valid.some((s) => s.kind === 'service')) return valid;
  return valid.filter((s) => s.kind === 'service' || !(s.time < when - CLOCK_ALLOWANCE_MS));
}
const behindEarlierSeal = (s, floor) => s.kind === 'block' && s.time < floor - CLOCK_ALLOWANCE_MS;

// The time of a cancellation: the earliest that any counted time-stamp
// beside it gives. A later time would excuse stubs made after the person
// cancelled, so every counted time-stamp is taken, of either kind: a later
// one put beside an earlier one changes nothing. A service's time is
// exact. A block's time is loose and is taken at its earliest, two hours
// before the time the block states; but never as earlier than the date the
// person signed in the cancellation itself, because by the person's own
// word it was not made before then. So nobody can move a cancellation back
// in time by having it put into a block before the date it gives.
function cancelledAt(entry, when) {
  const times = entry.stamps.filter((s) => s.state === 'valid').map((s) => (s.kind === 'block' ? Math.max(s.earliest, when) : s.time));
  return times.length ? Math.min(...times) : null;
}

// Two witnesses that do not agree: beside a time-stamp from a service, a
// block time-stamp that states a time long before the record's own date,
// even with its two hours. The block is set aside (givingStamps,
// cancelledAt), and the reader is told.
function noteBlockSetAside(entry, when, words) {
  const valid = entry.stamps.filter((s) => s.state === 'valid');
  if (valid.some((s) => s.kind === 'service') && valid.some((s) => s.kind === 'block' && s.time < when - CLOCK_ALLOWANCE_MS)) entry.notes.push(words);
}
const CANCELLATION_BLOCK_SET_ASIDE =
  'A block time-stamp beside this cancellation states a time more than two hours before the cancellation\'s own date. The cancellation is not taken to have been made before the date the person signed in it. Either the block states a time far behind the true time, which the chain\'s rules allow in rare cases, or the cancellation was signed with a date later than the time it was made.';
const SEAL_BLOCK_SET_ASIDE =
  'A block time-stamp beside this seal states a time more than two hours before the seal\'s own date. It was set aside, and the time-stamp from a service was used. Either the block states a time far behind the true time, which the chain\'s rules allow in rare cases, or the seal existed before the date it gives.';

// A block time-stamp that states a time before a service's time-stamp on a
// seal earlier in the book. It is set aside (givingStamps), and the reader
// is told.
function noteBlockBehind(entry, floor) {
  if (entry.stamps.some((s) => s.state === 'valid' && behindEarlierSeal(s, floor))) entry.notes.push(SEAL_BLOCK_BEHIND);
}
const SEAL_BLOCK_BEHIND =
  'A block time-stamp beside this seal states a time that is, even with its two hours, before the time a time-stamp service gave a seal that comes before this one. This seal covers that seal and its time-stamp, so it cannot have existed by then. The block time-stamp was set aside: the block states a time far behind the true time, which the chain\'s rules allow in rare cases.';

// The earliest time that a counted time-stamp from a service gives a seal,
// or null where none does.
function serviceTime(entry) {
  const times = entry.stamps.filter((s) => s.state === 'valid' && s.kind === 'service').map((s) => s.time);
  return times.length ? Math.min(...times) : null;
}

// In a Show, a seal among the pages cannot be compared with the entries
// before it, and its time-stamp is credited to no page. But the seal and
// the pages that come before it are each shown to be in the book, at their
// places. So their dates can be held against one another as in a whole
// book: where they do not fit, the whole book would fail its check, one
// way or another. Which of the two is at fault, single pages cannot show:
// the seal may not belong to the book at that place. So the finding is
// given for the seal, which is the page that could not be compared, and
// never for the page before it.
function comparePageSeals(pages) {
  for (const seal of pages) {
    if (seal.kind !== 'seal' || !seal.content || seal.problems.length > 0 || seal.verified === 'none') continue;
    const when = parseTime(seal.content.when);
    const time = seal.stampedAt ? parseTime(seal.stampedAt) : null;
    let after = null;
    let before = null;
    for (const page of pages) {
      if (!(page.index < seal.index) || page.problems.length > 0 || page.verified === 'none') continue;
      const stated = whenOf(page);
      if (time !== null && stated > time + CLOCK_ALLOWANCE_MS) after ??= page.index;
      else if (stated > when + CLOCK_ALLOWANCE_MS) before ??= page.index;
    }
    if (after !== null) {
      seal.problems.push({
        code: 'dated-after-stamp',
        message: `Page ${after}, which comes before this seal in the book, is dated later than this seal's outside time-stamp. Either that page's date is not as it says, or this seal does not fit the entries before it. Single pages cannot show which.`,
      });
    }
    if (before !== null) {
      seal.problems.push({
        code: 'time-went-backwards',
        message: `This seal is dated before page ${before}, which comes before it in the book. Either one of the two dates is not as it says, or this seal does not fit the entries before it.`,
      });
    }
    laterThanSeals(seal, pages);
    if (seal.problems.length > 0) seal.verified = 'none';
  }
}

// In a Show: a seal against the seals among the pages that come before it
// in the book. Its date may not be earlier than theirs, nor the time a
// service gave it more than 300 seconds earlier than a service gave them.
// And the seals form a chain: a seal names the seal just before it.
function laterThanSeals(seal, pages) {
  const when = parseTime(seal.content.when);
  const service = seal.verified === 'all' ? serviceTime(seal) : null;
  let dated = false;
  let stamped = false;
  for (const p of pages) {
    if (p === seal || p.kind !== 'seal' || !p.content || !(p.index < seal.index) || p.problems.length > 0 || p.verified === 'none') continue;
    if (when < parseTime(p.content.when)) dated = true;
    const earlier = p.verified === 'all' ? serviceTime(p) : null;
    if (service !== null && earlier !== null && service < earlier - CLOCK_ALLOWANCE_MS) stamped = true;
  }
  if (dated) seal.problems.push({ code: 'time-went-backwards', message: 'This seal is dated before a seal, among the pages, that comes before it in the book. One of the two is not as it says.' });
  if (stamped) {
    seal.problems.push({ code: 'time-went-backwards', message: 'This seal\'s time-stamp is earlier than the time-stamp of a seal, among the pages, that comes before it in the book. One of the two is not as it says.' });
  }
  // The chain of seals, as far as the pages show it. Every seal that could be read has its place in it.
  const others = pages.filter((p) => p !== seal && p.kind === 'seal' && p.content && p.fingerprint);
  const earlier = others.filter((p) => p.index < seal.index);
  let broken;
  if (!Object.hasOwn(seal.content, 'previous')) {
    // It says it is the first seal of the book, and a seal comes before it.
    broken = earlier.length > 0;
  } else {
    // If the seal it names is among the pages, that seal comes before it, with no other seal between the two.
    const named = others.find((p) => p.fingerprint === seal.content.previous);
    broken = named !== undefined && (!(named.index < seal.index) || earlier.some((p) => p.index > named.index));
  }
  // The seals of one book all give the same book number (section 21.6).
  const number = (s) => (Object.hasOwn(s.content, 'book') ? s.content.book : 1);
  if (earlier.some((p) => number(p) !== number(seal))) broken = true;
  if (broken) {
    seal.problems.push({ code: 'seal-chain-broken', message: 'The seal does not name the seal before it among the pages: a seal is missing, moved or changed.' });
  }
}

// The kind of the counted time-stamp that gives a seal its time: the one
// that states the earliest. A service's, where the two state the same.
function countedBy(entry, floor) {
  const giving = givingStamps(entry, parseTime(entry.content.when), floor);
  if (!giving.length) return 'service';
  const earliest = Math.min(...giving.map((s) => s.time));
  return giving.some((s) => s.kind === 'service' && s.time === earliest) ? 'service' : 'block';
}

// Whether a seal is dated before an entry it covers, where no counted
// time-stamp settles which of the two dates is wrong. An entry that failed
// its own check says nothing. One dated after the counted time-stamp is
// marked itself (creditStamp), and is not counted here.
function datedBeforeCovered(when, covered, count, creditedTime) {
  for (let i = 0; i < count; i++) {
    const e = covered[i];
    if (e.problems.length > 0 || e.verified === 'none') continue;
    const stated = whenOf(e);
    if (!(stated > when + CLOCK_ALLOWANCE_MS)) continue;
    if (creditedTime !== null && stated > creditedTime + CLOCK_ALLOWANCE_MS) continue;
    return true;
  }
  return false;
}

/**
 * The latest time a checked entry states, in milliseconds; NaN if it states none.
 * @param {any} entry an entry of a result
 * @returns {number}
 */
export function latestWhen(entry) {
  return whenOf(entry);
}

// The latest time an entry states: its own, and that of a countersignature
// or an approval on the same line. NaN if it states none.
function whenOf(entry) {
  const times = [entry.content && entry.content.when, entry.countersignature && entry.countersignature.when, entry.approval && entry.approval.when]
    .filter((t) => typeof t === 'string')
    .map(parseTime)
    .filter((t) => !Number.isNaN(t));
  return times.length ? Math.max(...times) : NaN;
}

// An entry that a trusted time-stamp covers existed by the stated time. One
// that is dated later is not as it says. An entry keeps the earliest time
// that any seal after it shows, as "existedBy". Returns false if the entry
// was already shown to have existed by then.
function creditStamp(earlier, stampedAt, time) {
  const before = stampedTimes.get(earlier);
  if (before !== undefined && before <= time) return false;
  stampedTimes.set(earlier, time);
  // The time that a seal's or a cancellation's own time-stamps give it is
  // another matter, and is kept apart, as "stampedAt": a cancellation does
  // not count from the time of a seal after it.
  earlier.existedBy = stampedAt;
  if (whenOf(earlier) > time + CLOCK_ALLOWANCE_MS && !earlier.problems.some((p) => p.code === 'dated-after-stamp')) {
    earlier.problems.push({ code: 'dated-after-stamp', message: 'This entry is dated later than the outside time-stamp that covers it.' });
    earlier.verified = 'none';
  }
  return true;
}

/**
 * A seal: the recorder's signed statement of the top fingerprint and the
 * number of entries before it, with outside time-stamps beside it.
 *
 * @param {any} entry the entry being filled in
 * @param {any} value the line, read
 * @param {any} seals the state of the seals so far, or a fresh state for a seal that stands alone
 * @param {Set<string>} ids
 * @param {any} options the checker's options
 * @param {(() => Promise<{size: number, root: string}>)|null} before works out the entries before the seal, where they are at hand
 * @param {any[]} entries the entries so far, so that the ones a time-stamp covers can be marked
 * @param {boolean} [asPage] whether the seal is a single page of a Show, with nothing to compare it with
 * @param {boolean} [held] whether the seal is one held elsewhere and handed over beside the book, with no place of its own
 */
async function checkSealEntry(entry, value, seals, ids, options, before, entries, asPage = false, held = false) {
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  entry.signatures = [];
  entry.stamps = [];
  entry.witnesses = [];
  const parsed = await parseRecord(value.seal, 'seal');
  entry.fingerprint = parsed.fingerprint;
  validateSealContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  noteId(entry, ids, c.id);
  seals.count++;

  // The recorder's three signatures: all must check.
  entry.signatures = await checkKeySetSignatures(parsed, c.by.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({ code: 'signature-invalid', message: 'A signature on the seal does not fit the keys the seal gives.' });
  }
  entry.verified = verifiedBy(entry.signatures);
  entry.sealer = await keySetFingerprint(c.by.keys);
  if (Array.isArray(options.sealKeys)) {
    if (!options.sealKeys.includes(entry.sealer)) {
      entry.problems.push({ code: 'sealer-not-expected', message: 'The seal was signed with keys other than the ones expected.' });
    }
  } else {
    entry.notes.push('The keys that signed this seal were not compared with keys you already trust. The name on the seal is only a label.');
  }

  // The seal against the entries before it, and against the seal before it.
  const when = parseTime(c.when);
  const at = before ? await before() : null;
  // A seal sits after exactly as many entries as it covers.
  if (!at && !held && c.size !== entry.index) {
    entry.problems.push({ code: 'seal-mismatch', message: 'A seal sits after exactly as many entries as it covers, and this one does not.' });
  }
  if (asPage) {
    entry.notes.push(
      'This seal is shown as a single page. It could not be compared with the entries before it, so its time-stamp is not taken to show when any other page existed. Its dates are still held against the pages that come before it in the book.',
    );
  }
  if (at) {
    if (c.size !== at.size || c.root !== at.root) {
      entry.problems.push({ code: 'seal-mismatch', message: 'The seal does not fit the entries before it: an entry was changed, added or removed after the seal was made.' });
    }
    // The book's number (section 21.6): absent is the first book. The first seal of a book after the first names,
    // as the seal before it, the last seal of the book before, which is not in this book: it is not compared here,
    // and is kept, so that a copy of that seal handed over beside the book can be (checkHeldSeals).
    const number = Object.hasOwn(c, 'book') ? c.book : 1;
    if (seals.last === null && number > 1) {
      seals.firstPrevious = c.previous;
      entry.notes.push(`This is the first seal of book ${number} in this book. It names, as the seal before it, the last seal of book ${number - 1}, which is not in this book and was not compared. To compare the two, check book ${number - 1} with that seal handed over beside it.`);
    } else if ((Object.hasOwn(c, 'previous') ? c.previous : null) !== seals.last) {
      entry.problems.push({ code: 'seal-chain-broken', message: 'The seal does not name the seal before it: a seal is missing, moved or changed.' });
    }
    if (seals.last !== null && number !== seals.book) {
      entry.problems.push({ code: 'seal-chain-broken', message: 'The seal gives another book number than the seals before it in this book.' });
    }
    if (seals.last === null) seals.book = number;
    if (when < seals.lastWhen) {
      entry.problems.push({ code: 'time-went-backwards', message: 'This seal is dated before the seal ahead of it.' });
    }
    seals.last = parsed.fingerprint;
    seals.lastWhen = when;
  }

  // The outside time-stamps. Each states that this seal existed at a time.
  // They are read only for a seal whose own signatures did not fail. The
  // latest time a service gave a seal before this one is the "floor": a
  // block time-stamp that states a time before it is set aside (givingStamps).
  const floor = seals.lastStampTime ?? -Infinity;
  // The same floor holds for the seal's own date. A seal covers the lines of
  // the seals before it, time-stamps included, so it cannot have been made
  // before the latest time a service gave one of them.
  if (when < floor - CLOCK_ALLOWANCE_MS) {
    entry.problems.push({
      code: 'time-went-backwards',
      message: 'This seal is dated before the time that a time-stamp service gave a seal that comes before it. It covers that seal and its time-stamp, so it cannot have been made by then.',
    });
  }
  const stampedTime =
    Object.hasOwn(value, 'stamps') && overall(entry.signatures) !== 'invalid'
      ? await checkStamps(entry, value.stamps, parsed.fingerprint, when, options, entry.verified === 'all', floor)
      : null;
  if (Object.hasOwn(value, 'stamps') && overall(entry.signatures) === 'invalid') decodeStamps(value.stamps);

  // The witness statements on the seal's own line. (Those handed over beside
  // a seal held elsewhere are checked apart: see ownChecks.)
  if (!held && Object.hasOwn(value, 'witnesses')) {
    const { items, problems } = await checkWitnesses(value.witnesses, parsed, options, without, ids);
    entry.witnesses = items;
    entry.problems.push(...problems);
    noteWitnesses(entry);
  }

  // A seal counts as signed only if all three of its signatures were
  // checked. Only then is a time-stamp on it credited.
  const credited = entry.problems.length === 0 && entry.verified === 'all' && stampedTime !== null;
  if (stampedTime !== null && entry.problems.length === 0 && entry.verified !== 'all') {
    entry.notes.push('The time-stamp beside this seal was not counted: this device could not check all three of the seal\'s signatures.');
  }
  if (entry.problems.length === 0 && entry.verified === 'all') noteBlockBehind(entry, floor);

  // A seal dated before an entry it covers: one of the two dates is not as
  // it says. Where a counted time-stamp settles which (the entry is dated
  // after the time-stamp too), the entry is marked instead (below). Where
  // none does, the seal is where the two meet.
  if (at && seals.latest > when + CLOCK_ALLOWANCE_MS && datedBeforeCovered(when, entries, entries.length - 1, credited ? stampedTime : null)) {
    entry.problems.push({ code: 'time-went-backwards', message: 'This seal is dated before an entry it covers. One of the two dates is not as it says.' });
  }
  if (!credited || entry.problems.length > 0) return;
  const time = stampedTime;
  entry.stampedAt = formatTime(time);
  noteBlockSetAside(entry, when, SEAL_BLOCK_SET_ASIDE);
  const service = serviceTime(entry);
  if (!at) {
    // Among the pages of a Show, the services' times are held against one
    // another later (laterThanSeals). The floor for a block time-stamp on
    // a seal further on is kept here, as in a whole book.
    if (service !== null && service > (seals.lastStampTime ?? -Infinity)) seals.lastStampTime = service;
    return;
  }
  // A later seal cannot have been time-stamped by a service before an
  // earlier one: not before the latest time a service gave any seal so
  // far. A block time-stamp is not reported in this way: it is made hours
  // after the seal, and its time is only right to within two hours. One
  // that states a time before that floor is set aside (givingStamps).
  if (service !== null) {
    if (service < seals.lastStampTime - CLOCK_ALLOWANCE_MS) {
      entry.problems.push({ code: 'time-went-backwards', message: 'This seal\'s time-stamp is earlier than the time-stamp of a seal before it.' });
      return;
    }
    if (service > seals.lastStampTime) seals.lastStampTime = service;
  }
  const by = countedBy(entry, floor);
  // What a trusted time-stamp covers: every entry before the seal existed
  // by then. An entry dated later than that is not as it says. The
  // earliest time that any seal after an entry shows is the one that
  // counts for it. Going back from the seal, the entries already shown to
  // have existed earlier are left as they are, with everything before them.
  for (let i = entries.length - 2; i >= 0; i--) if (!creditStamp(entries[i], entry.stampedAt, time)) break;
  seals.next = entries.length - 1;
  seals.sealed = { entries: c.size, when: entry.stampedAt, seal: entry.index, by };
}

/**
 * The witness statements beside a seal (format description, section 29.2):
 * on the seal's line, or handed over with a seal held elsewhere. Each is
 * checked by itself: its envelope and content, its two signatures against
 * the keys it gives, and that it speaks of this seal. One that does not
 * pass is a problem. One from a witness the reader did not name is shown,
 * and not counted. Whether a statement counts is settled with the answer
 * (witnessesCounted), once it is known whether its seal passed.
 *
 * @param {any} list the statements, as handed over
 * @param {any} seal the seal they speak of, as parseRecord read it
 * @param {any} options the checker's options
 * @param {string[]} without signing methods to treat as not built in
 * @param {Set<string>|null} ids the unique numbers of the book so far, for statements on a line of the book
 * @returns {Promise<{items: object[], problems: {code: string, message: string}[]}>}
 */
async function checkWitnesses(list, seal, options, without, ids) {
  const items = [];
  const problems = [];
  try {
    f.list(list, 1, MAX_WITNESSES, 'witnesses');
  } catch (e) {
    return { items, problems: [problemFrom(e)] };
  }
  const seen = new Set();
  // Every place is read by its number, a gap included: a gap is not a statement.
  for (let i = 0; i < list.length; i++) {
    const item = { fingerprint: null, witness: null, name: null, when: null, state: 'invalid', trusted: false, counted: false, signatures: [] };
    items.push(item);
    try {
      const parsed = await parseRecord(list[i], 'witness');
      item.fingerprint = parsed.fingerprint;
      validateWitnessContent(parsed.content);
      const c = parsed.content;
      item.witness = await keySetFingerprint(c.by.keys);
      item.name = c.by.name;
      item.when = c.when;
      if (ids) {
        if (ids.has(c.id)) throw new Refusal('duplicate-id', 'Another record has the same unique number.');
        ids.add(c.id);
      }
      item.signatures = await checkKeySetSignatures(parsed, c.by.keys, without);
      if (overall(item.signatures) === 'invalid') throw new Refusal('witness-invalid', 'A signature on the witness statement does not fit the keys it gives.');
      if (c.seal !== seal.fingerprint || c.size !== seal.content.size || c.root !== seal.content.root) {
        throw new Refusal('witness-invalid', 'The witness statement speaks of another seal: its seal, its number of entries or its top fingerprint is not this seal\'s.');
      }
      if (parseTime(c.when) < parseTime(seal.content.when) - CLOCK_ALLOWANCE_MS) {
        throw new Refusal('witness-invalid', 'The witness statement is dated more than 300 seconds before the seal it speaks of.');
      }
      if (seen.has(item.witness)) throw f.fail('witnesses', 'the same witness signs twice.');
      seen.add(item.witness);
      item.state = overall(item.signatures) === 'valid' ? 'valid' : 'unavailable';
      item.trusted = Array.isArray(options.witnesses) && options.witnesses.includes(item.witness);
    } catch (e) {
      item.state = 'invalid';
      const p = problemFrom(e);
      problems.push({ code: p.code, message: `Witness statement ${i + 1} beside the seal did not pass its check. ${p.message}` });
    }
  }
  return { items, problems };
}

// What a reader is told of the statements beside a seal that passed their check.
function noteWitnesses(entry) {
  entry.witnesses.forEach((w, i) => {
    if (w.state === 'unavailable') entry.notes.push(`This device could not check witness statement ${i + 1} beside this seal, so it was not counted.`);
    else if (w.state === 'valid' && !w.trusted) {
      entry.notes.push(`Witness statement ${i + 1} beside this seal is from a witness you did not name as trusted, so it was not counted. The fingerprint of its key set is ${w.witness}.`);
    }
  });
}

// Whether a seal's first two signatures (Ed25519 and ML-DSA-87) were both
// checked on this device. A statement counts on those two, as a seal held
// elsewhere does: its third (SLH-DSA) may be one this device cannot check.
function firstTwoChecked(signatures) {
  const state = (method) => signatures.find((s) => s.method === method)?.state;
  return state('Ed25519') === 'valid' && state('ML-DSA-87') === 'valid';
}

/**
 * Why a witness's statement cannot count for this book, or null where it
 * can (format description, section 29.2). A witness knows a book by the
 * permission on its first line and the keys of its recorder, and the
 * recorder chooses both. So a statement counts only where the reader fixed
 * both: the book's first line is a permission that passed its check, signed
 * by a passkey the reader named, and the reader named the recorders they
 * expect (so that a seal by any other recorder is a problem).
 * @param {any[]} entries the entries of the book, or the pages of a Show
 * @param {any} options the options the lines were read with
 * @returns {string|null}
 */
function unfixedStart(entries, options) {
  // An option that cannot be read names nothing here; a check that reads it elsewhere reports it.
  const isList = (name) => {
    try {
      return Array.isArray(options[name]);
    } catch {
      return false;
    }
  };
  if (!isList('issuerKeys')) return 'you named no passkey you trust, so the permission this book starts from is not fixed';
  if (!isList('sealKeys')) return 'you named no recorder you expect, so anyone could have sealed it';
  const first = entries[0];
  if (first === undefined || first.index !== 0 || first.kind !== 'slip' || first.problems.length > 0 || !first.signature || first.signature.state !== 'valid') {
    return 'this book does not start with a permission that passed its check here, signed by a passkey you named';
  }
  return null;
}
/**
 * For each seal: why a witness's statement cannot count for it, or null
 * where it can (format description, section 29.2). Beyond a start the
 * reader fixed (unfixedStart), every permission among the entries the seal
 * covers must name the passkey and the agent's key set of the permission
 * the book starts from. A witness knows a sequence by those two and the
 * recorder's keys, so a book that starts with one person's permission for
 * one agent, and holds another's further on, could be the first book of a
 * sequence the witness never saw, and so a fork of another. Among the pages
 * of a Show, the pages must hold every entry the seal covers: single pages
 * cannot show that no other permission stands between them.
 * @param {any[]} entries the entries of the book, or the pages of a Show
 * @param {any} options the options the lines were read with
 * @param {Set<number>|null} [pages] for a Show: the places of its pages
 * @returns {(seal: any) => string|null}
 */
function whyFor(entries, options, pages = null) {
  const start = unfixedStart(entries, options);
  if (start !== null) return () => start;
  const first = entries[0];
  const agent = canonicalJson(first.content.agent.keys);
  const others = entries.filter((e) => e.kind === 'slip' && (!e.content || e.issuerKey !== first.issuerKey || canonicalJson(e.content.agent.keys) !== agent));
  return (seal) => {
    const size = seal.content ? seal.content.size : 0;
    if (pages !== null) {
      for (let i = 0; i < size; i++) {
        if (!pages.has(i)) return 'the pages do not hold every entry this seal covers, and single pages cannot show that every permission among them is from the passkey and for the agent of the permission the book starts from';
      }
    }
    if (others.some((e) => e.index < size)) {
      return 'the entries this seal covers hold a permission from another passkey, or for another agent, than the permission the book starts from, and a witness keeps the books of each person and agent apart';
    }
    return null;
  };
}
const unfixedWords = (why) =>
  `The statements beside this seal from witnesses you trust were not counted: ${why}. A witness knows a book only by the passkey and the agent of the permission it starts from and the keys of its recorder, which the recorder chooses, so a statement counts only for a book that starts with a permission signed by a passkey you named, sealed by a recorder you named.`;

/**
 * The statements beside a seal, each with whether it counts: it passed its
 * check, its witness is one the reader named, the book's start is one the
 * reader fixed (unfixedStart), and the seal passed its own check with its
 * first two signatures checked on this device. A new list: the one the
 * reader keeps is left as it is. Where a statement from a witness the
 * reader trusts is not counted because the start is not fixed, the reader
 * is told why, in "notes", a new list too.
 * @param {any} seal an entry of kind "seal", or a seal held elsewhere
 * @param {string|null} why what whyFor gives for the seal
 * @param {boolean} [sound] whether the seal counts as sound here
 * @returns {{witnesses: object[], notes: string[]}}
 */
function witnessesCounted(seal, why, sound = seal.problems.length === 0) {
  const ok = sound && why === null && firstTwoChecked(seal.signatures ?? []);
  const witnesses = (seal.witnesses ?? []).map((w) => ({ ...w, counted: ok && w.state === 'valid' && w.trusted }));
  const notes = why !== null && sound && witnesses.some((w) => w.state === 'valid' && w.trusted) ? [...seal.notes, unfixedWords(why)] : seal.notes;
  return { witnesses, notes };
}

// A stub may have with it, on the same line, the service's countersignature
// and the person's approval.
const STUB_ENTRIES = ['stub', 'countersignature,stub', 'approval,stub', 'approval,countersignature,stub'];
// A seal may have beside it, on the same line, time-stamps and witness statements.
const SEAL_ENTRIES = ['seal', 'seal,stamps', 'seal,witnesses', 'seal,stamps,witnesses'];

function findSlip(slips, fingerprint, whole) {
  const slip = slips.get(fingerprint);
  if (!slip) {
    throw new Refusal('slip-missing', whole ? 'The slip this entry relies on is not earlier in the book.' : 'The slip this entry relies on is not among the pages.');
  }
  if (!slip.usable) throw new Refusal('slip-unusable', 'The slip this entry relies on did not pass its own check.');
  return slip;
}

// What sits under a slip this device could not confirm is not evidence
// either, whatever its own signatures say: the keys it was checked against
// came from that slip.
function underConfirmedSlip(entry, slip) {
  if (slip.verified || entry.verified === 'none') return;
  entry.verified = 'none';
  entry.notes.push('The slip this entry relies on could not be confirmed on this device, so this entry is not shown.');
}

/**
 * Check the person's approval of one action against that action: it must be
 * for exactly this request, under this slip, not used before, and signed
 * with the passkey the slip names. Used by the checker and by the check
 * before acting.
 * @returns {Promise<{state: 'valid'|'unavailable', when: string, alg: string}>}
 * @throws {Refusal}
 */
export async function checkApprovalRecord(record, request, slipFingerprint, slip, ids, without) {
  const approval = await parseRecord(record, 'approval');
  validateApprovalContent(approval.content);
  const a = approval.content;
  if (a.slip !== slipFingerprint || requestOf(a) !== requestOf(request)) {
    throw new Refusal('approval-mismatch', 'The approval was given for something else.');
  }
  if (Object.hasOwn(request, 'approval') && request.approval !== approval.fingerprint) {
    throw new Refusal('approval-mismatch', 'The approval with this stub is not the one the stub names.');
  }
  if (ids.approvals.has(a.id)) throw new Refusal('approval-reused', 'This approval has already been used for another stub.');
  if (ids.has(a.id)) throw new Refusal('duplicate-id', 'Another record has the same unique number.');
  ids.add(a.id);
  ids.approvals.add(a.id);
  let state;
  try {
    state = await checkPasskeySignature(approval, slip.content.issuer, without);
  } catch {
    throw new Refusal('approval-invalid', 'The approval was not signed with the passkey the slip names, or its passkey values do not check.');
  }
  return { state, when: a.when, alg: slip.content.issuer.key.alg, fingerprint: approval.fingerprint };
}

/**
 * Check a countersignature against the stub it was made for and the keys
 * the slip gives for the service. Used by the checker, and by the stub
 * writer before it puts a countersignature into its book.
 * @param {any} record the countersignature
 * @param {string} stubFingerprint
 * @param {any} service the service the stub names, as the slip gives it, if it gives it
 * @param {string[]} without
 * @param {{state: string, signatures: object[], when?: string}} [into] filled in as the check goes
 * @returns {Promise<{state: 'valid'|'unavailable', signatures: object[], when: string}>}
 * @throws {Refusal}
 */
export async function checkCountersignature(record, stubFingerprint, service, without, into = { state: 'invalid', signatures: [] }) {
  const counter = await parseRecord(record, 'countersignature');
  validateCountersignatureContent(counter.content);
  if (counter.content.stub !== stubFingerprint) {
    throw new Refusal('countersignature-wrong-stub', 'The countersignature was made for a different stub.');
  }
  if (!keysOf(service)) {
    throw new Refusal('countersignature-not-possible', 'The slip names no keys for a service that could have countersigned this stub.');
  }
  into.when = counter.content.when;
  into.signatures = await checkKeySetSignatures(counter, service.keys, without);
  into.state = overall(into.signatures);
  if (into.state === 'invalid') {
    throw new Refusal('countersignature-invalid', 'A signature on the countersignature does not fit the service\'s keys.');
  }
  return into;
}

function noteId(entry, ids, id) {
  if (ids.has(id)) entry.problems.push({ code: 'duplicate-id', message: 'Another record has the same unique number.' });
  ids.add(id);
}

// A refusal: what a service says it refused. It is the service's own
// statement, signed with the keys the refusal itself gives.
async function checkRefusalEntry(entry, value, slips, ids, without, whole) {
  entry.signatures = [];
  const parsed = await parseRecord(value.refusal, 'refusal');
  entry.fingerprint = parsed.fingerprint;
  validateRefusalContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  entry.slip = c.slip;
  noteId(entry, ids, c.id);
  const slip = findSlip(slips, c.slip, whole);
  entry.signatures = await checkKeySetSignatures(parsed, c.by.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({ code: 'signature-invalid', message: 'A signature on the refusal does not fit the keys the refusal gives.' });
  }
  entry.verified = verifiedBy(entry.signatures);
  entry.signer = await keySetFingerprint(c.by.keys);
  underConfirmedSlip(entry, slip);
  // Is this a service the slip names? Only its keys can say.
  const keys = canonicalJson(c.by.keys);
  const named = slip.content.with.find((s) => keysOf(s) && canonicalJson(s.keys) === keys);
  entry.service = named ? named.id : null;
}

// A service's terms for agents, signed with the keys the terms themselves give.
async function checkTermsEntry(entry, value, terms, ids, without) {
  entry.signatures = [];
  const parsed = await parseRecord(value.terms, 'terms');
  entry.fingerprint = parsed.fingerprint;
  try {
    validateTermsContent(parsed.content);
    const c = parsed.content;
    entry.content = c;
    noteId(entry, ids, c.id);
    entry.signatures = await checkKeySetSignatures(parsed, c.by.keys, without);
    if (overall(entry.signatures) === 'invalid') {
      entry.problems.push({ code: 'signature-invalid', message: 'A signature on the terms does not fit the keys the terms give.' });
    }
    entry.verified = verifiedBy(entry.signatures);
    // 5. Whose keys signed these terms: a name is only a label.
    entry.signer = await keySetFingerprint(c.by.keys);
  } catch (e) {
    entry.problems.push(problemFrom(e));
  }
  if (terms.has(parsed.fingerprint)) entry.problems.push({ code: 'duplicate-id', message: 'These terms are already in the book.' });
  else terms.set(parsed.fingerprint, { content: entry.content, usable: entry.problems.length === 0, verified: entry.problems.length === 0 && entry.verified !== 'none' });
}

async function checkStubEntry(entry, value, slips, terms, passes, ids, without, whole) {
  entry.signatures = [];
  // A countersignature the line holds is "unchecked" until it is checked,
  // so that a stub whose slip fails is not counted as one-sided.
  entry.countersignature = { state: Object.hasOwn(value, 'countersignature') ? 'unchecked' : 'absent', signatures: [] };
  entry.approval = { state: 'absent' };
  // Whether this stub was compared with its slip. It is not, if the stub or
  // the slip could not be confirmed.
  entry.compared = false;

  const parsed = await parseRecord(value.stub, 'stub');
  entry.fingerprint = parsed.fingerprint;
  validateStubContent(parsed.content);
  const c = parsed.content;
  entry.content = c;
  entry.slip = c.slip;

  noteId(entry, ids, c.id);
  const slip = findSlip(slips, c.slip, whole);

  // A helper agent's stub names the pass it acts under: it is signed with
  // the helper's keys, and sits in the helper's own chain.
  const pass = Object.hasOwn(c, 'pass') ? findPass(passes, c.pass, c.slip, whole) : null;
  const chain = pass ?? slip;
  if (pass) entry.pass = c.pass;

  // The agent's two signatures: both must check.
  entry.signatures = await checkKeySetSignatures(parsed, pass ? pass.content.to.keys : slip.content.agent.keys, without);
  if (overall(entry.signatures) === 'invalid') {
    entry.problems.push({ code: 'signature-invalid', message: pass ? 'A signature on the stub does not fit the keys of the helper agent the pass names.' : 'A signature on the stub does not fit the agent\'s keys.' });
  }
  entry.verified = verifiedBy(entry.signatures);
  underConfirmedSlip(entry, slip);

  // Its place in the chain.
  const when = parseTime(c.when);
  if (whole) {
    if (c.seq !== chain.next || (c.seq > 0 && c.previous !== chain.last)) {
      entry.problems.push({ code: 'chain-broken', message: 'The chain is broken here: a stub is missing, moved, repeated or changed.' });
    }
    if (when < chain.lastWhen) {
      entry.problems.push({ code: 'time-went-backwards', message: 'This stub is dated before the stub ahead of it.' });
    }
    // Carry on from this stub, so that one break is reported once.
    chain.next = c.seq + 1;
    chain.last = parsed.fingerprint;
    chain.lastWhen = when;
  }

  // The countersignature, if there is one.
  const service = Object.hasOwn(c, 'with') ? slip.content.with.find((s) => s.id === c.with) : undefined;
  if (Object.hasOwn(value, 'countersignature')) {
    entry.countersignature.state = 'invalid';
    try {
      await checkCountersignature(value.countersignature, parsed.fingerprint, service, without, entry.countersignature);
    } catch (e) {
      entry.problems.push(problemFrom(e));
    }
  }

  // The person's approval of this one action, if there is one. It is signed
  // with the passkey the slip names, and must be for exactly this action.
  if (Object.hasOwn(value, 'approval')) {
    entry.approval.state = 'invalid';
    try {
      // A stub must name the approval that is with it.
      if (!Object.hasOwn(c, 'approval')) throw new Refusal('approval-mismatch', 'The stub does not name the approval that is with it.');
      const checked = await checkApprovalRecord(value.approval, c, c.slip, slip, ids, without);
      entry.approval = { state: checked.state, when: checked.when, alg: checked.alg };
      // The stub names the approval, so it was signed after the approval
      // was written. A stub dated before its approval is not as it says.
      if (parseTime(checked.when) > when + CLOCK_ALLOWANCE_MS) {
        throw new Refusal('approval-dated-after-stub', 'The approval is dated later than the stub that carries it.');
      }
    } catch (e) {
      entry.problems.push(problemFrom(e));
    }
  } else if (Object.hasOwn(c, 'approval')) {
    entry.problems.push({ code: 'approval-not-found', message: 'The stub names an approval that is not with it.' });
  }

  // The service's terms for agents, if the stub relies on them.
  let termsContent;
  let termsConfirmed = true;
  if (Object.hasOwn(c, 'terms')) {
    const t = terms.get(c.terms);
    if (!t) {
      entry.problems.push({ code: 'terms-not-found', message: whole ? 'The terms this stub relies on are not earlier in the book.' : 'The terms this stub relies on are not among the pages.' });
    } else if (!t.usable) {
      entry.problems.push({ code: 'terms-unusable', message: 'The terms this stub relies on did not pass their own check.' });
    } else if (!keysOf(service) || canonicalJson(service.keys) !== canonicalJson(t.content.by.keys)) {
      entry.problems.push({ code: 'terms-mismatch', message: 'The terms this stub relies on were not signed with the keys the slip gives for the service it names.' });
    } else {
      termsContent = t.content;
      termsConfirmed = t.verified;
    }
  }

  // What the stub shows about the agent. Only a stub that is itself sound,
  // that this device could confirm at least in part, under a slip this
  // device confirmed, is evidence of anything.
  if (entry.problems.length > 0 || entry.verified === 'none' || !slip.verified || !termsConfirmed) return;
  entry.compared = true;
  const shown = compareWithSlip(slip.content, whole ? slip.tally : null, c, { service, terms: termsContent, cancelled: slip.cancelled !== null, late: entry.breaches });
  slip.stubs.push(entry);
  // A helper's stub is compared with the slip, as every stub is, and also
  // with the pass it acts under and with every pass above that one: what a
  // helper holds, it holds under each of them, and their totals take in
  // what is done further down. A finding already given is not repeated.
  // (There are at most ten: a pass further down is refused.)
  if (pass) {
    const given = [...shown.breaches];
    for (let p = pass; p; p = p.parent) {
      const under = compareWithSlip(passAsSlip(p.content), whole ? p.tally : null, c, { service, what: p === pass ? 'pass' : 'earlier-pass', late: entry.breaches });
      for (const b of under.breaches) {
        if (given.some((x) => x.code === b.code)) continue;
        given.push(b);
        entry.breaches.push(b);
      }
    }
    if (pass.notAllowed) entry.breaches.push({ code: 'pass-not-allowed', message: 'This stub was written under a pass that the slip does not allow.' });
  }
  entry.breaches.push(...shown.breaches);
  if (shown.running) entry.running = shown.running;
  entry.needs = shown.needs;
  if (shown.needs.includes('countersignature') && entry.countersignature.state === 'absent') {
    entry.breaches.push({ code: 'countersignature-missing', message: 'The slip asks for the other side to countersign this action, and there is no countersignature.' });
  }
  if (shown.needs.includes('approval') && entry.approval.state === 'absent') {
    entry.breaches.push({ code: 'approval-missing', message: 'The slip asks for the person\'s own approval of this action, and there is none.' });
  }
}
// How far a witness the reader trusts reaches: the seals that passed their
// own check, with their first two signatures checked on this device, for
// which at least one statement counts (on the seal's line, or handed over
// beside the book with a copy of the seal). Null where there is none.
function witnessedReach(entries, heldWitnessed) {
  const seals = [];
  let last = null;
  for (const e of entries) {
    if (e.kind !== 'seal' || !e.content || e.problems.length > 0 || !firstTwoChecked(e.signatures ?? [])) continue;
    const by = new Set([...(e.witnesses ?? []).filter((w) => w.counted).map((w) => w.witness), ...(heldWitnessed.get(e.index) ?? [])]);
    if (by.size === 0) continue;
    seals.push(e.index);
    last = { seal: e.index, entries: e.content.size, by: [...by].sort() };
  }
  return last && { ...last, seals };
}

// Beside a Show's witnessed answer: the limit of a Show (format description, section 11).
const SHOW_WITNESSED_WORDS = 'These are single pages of a book: they cannot show that a limit over the whole book was kept (section 11), so being witnessed says nothing here about totals.';

function summarise(entries, bookProblems, sealed = null, held = [], heldWitnessed = new Map(), isShow = false) {
  // Methods this device lacked, and whether any signature was never reached
  // because its entry, or the whole record, could not be read or used.
  const missing = new Set();
  let skipped = bookProblems.length > 0 || entries.length === 0;
  let slipCount = 0;
  let stubCount = 0;
  let countersigned = 0;
  let oneSided = 0;
  let approved = 0;
  let refusals = 0;
  let termsCount = 0;
  let sealCount = 0;
  let cancellations = 0;
  let vouchingCount = 0;
  let passCount = 0;
  let acknowledgementCount = 0;
  let denialCount = 0;
  const note = (signatures) => {
    if (signatures.length === 0) skipped = true;
    for (const s of signatures) if (s.state === 'unavailable') missing.add(s.method);
  };
  for (const e of entries) {
    if (e.kind === 'slip') {
      slipCount++;
      if (e.signature.state === 'unavailable') missing.add(e.signature.alg);
      else if (e.signature.state === 'unchecked') skipped = true;
    } else if (e.kind === 'stub') {
      stubCount++;
      note(e.signatures ?? []);
      const counter = e.countersignature ?? { state: 'absent', signatures: [] };
      if (counter.state === 'absent') oneSided++;
      else {
        note(counter.signatures);
        // Counted only when both of its signatures were confirmed here.
        if (counter.state === 'valid') countersigned++;
      }
      const approval = e.approval ?? { state: 'absent' };
      if (approval.state === 'unavailable') missing.add(approval.alg);
      else if (approval.state === 'valid') approved++;
    } else if (e.kind === 'refusal' || e.kind === 'terms') {
      if (e.kind === 'refusal') refusals++;
      else termsCount++;
      note(e.signatures ?? []);
    } else if (e.kind === 'seal') {
      sealCount++;
      note(e.signatures ?? []);
      for (const w of e.witnesses ?? []) note(w.signatures);
      for (const s of e.stamps ?? []) if (s.state === 'unavailable') missing.add('the time-stamp service\'s method');
    } else if (e.kind === 'cancellation') {
      cancellations++;
      if (!e.signature) skipped = true;
      else if (e.signature.state === 'unavailable') missing.add(e.signature.alg);
      for (const s of e.stamps ?? []) if (s.state === 'unavailable') missing.add('the time-stamp service\'s method');
    } else if (e.kind === 'vouching' || e.kind === 'withdrawal' || e.kind === 'pass' || e.kind === 'acknowledgement' || e.kind === 'denial') {
      if (e.kind === 'vouching') vouchingCount++;
      if (e.kind === 'denial') denialCount++;
      if (e.kind === 'pass') passCount++;
      if (e.kind === 'acknowledgement') acknowledgementCount++;
      note(e.signatures ?? []);
    } else {
      skipped = true;
    }
  }
  for (const h of held) {
    for (const s of h.stamps) if (s.state === 'unavailable') missing.add('the time-stamp service\'s method');
    for (const a of h.acknowledgements ?? []) note(a.signatures);
    // A seal held elsewhere: each of its signatures that this device could not check, and those of the witness statements handed over with it.
    for (const s of h.kind === 'seal' ? h.signatures : []) if (s.state === 'unavailable') missing.add(s.method);
    for (const w of h.kind === 'seal' ? h.witnesses : []) note(w.signatures);
  }
  const problemFound = bookProblems.length > 0 || entries.some((e) => e.problems.length > 0);
  const fullyChecked = !skipped && missing.size === 0;
  const witnessed = problemFound ? null : witnessedReach(entries, heldWitnessed);
  const firstBreach = entries.find((e) => e.breaches.length > 0);
  // "Within its slip" is said only if every stub, and every pass, was
  // compared with what it rests on, and none was found outside it.
  const allCompared = entries.every((e) => (e.kind === 'stub' || e.kind === 'pass' ? e.compared === true : e.kind !== 'unreadable'));
  return {
    intact: !problemFound && fullyChecked,
    problemFound,
    fullyChecked,
    methodsMissing: [...missing].sort(),
    withinSlips: !firstBreach && allCompared && !problemFound,
    firstBreach: firstBreach ? firstBreach.index : null,
    counts: {
      slips: slipCount,
      stubs: stubCount,
      countersigned,
      oneSided,
      approved,
      refusals,
      terms: termsCount,
      seals: sealCount,
      cancellations,
      acknowledgements: acknowledgementCount,
      denials: denialCount,
      vouchings: vouchingCount,
      passes: passCount,
    },
    // How far an outside time-stamp from a trusted service reaches, if any does.
    sealed: problemFound ? null : sealed,
    // How far a witness the reader trusts reaches, if any does.
    witnessed,
    limits: [...(sealed && !problemFound ? [...LIMITS.slice(0, -1), stampedWords(sealed)] : LIMITS), ...(witnessed ? [isShow ? `${witnessedWords(witnessed)} ${SHOW_WITNESSED_WORDS}` : witnessedWords(witnessed)] : [])],
  };
}

// Disclosures are handed over as {fingerprint of a slip: [disclosures]}.
// Anything else is refused, never set aside: the person handed it over to
// have fields revealed. Where no such slip is among the entries, the
// disclosures were not used, and the person is told.
function unusedDisclosures(result, options) {
  const handed = options.disclosures;
  if (handed === undefined) return;
  const proto = handed === null || typeof handed !== 'object' ? undefined : Object.getPrototypeOf(handed);
  if (Array.isArray(handed) || (proto !== Object.prototype && proto !== null)) {
    throw f.fail('disclosures', 'must be laid out as {the fingerprint of a slip: [its disclosures]}.');
  }
  const slips = new Set(result.entries.filter((e) => e.kind === 'slip').map((e) => e.fingerprint));
  if (Object.keys(handed).some((fingerprint) => !slips.has(fingerprint))) {
    result.notes.push('Disclosures were handed over for a slip that is not here. They were not used.');
  }
}

/**
 * Cancellations that the person kept, handed over beside the book.
 *
 * Whoever keeps a book can leave a cancellation out of it, or put a later
 * time-stamp in the place of the person's own. The person's own copy, with
 * its time-stamp, settles both: it is checked against the slip's passkey
 * as a cancellation in the book is, and the earliest time a counted
 * time-stamp gives it is used. A stub then counts as made before the
 * cancellation only if an outside time-stamp shows that it existed by then.
 *
 * A copy that does not pass its check is a problem, never dropped: the
 * person handed it over to have it counted.
 *
 * Nothing the reader keeps is changed: what the copies show about the
 * stubs is gathered in "late", and the slips they cancel in "beside".
 */
async function checkHeld(result, reader, options, late, beside) {
  const { slips, passes } = reader;
  const handed = options.cancellations;
  if (handed === undefined) return;
  const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
  // Up to sixteen, none included: an empty list is what a stub writer that holds none hands back.
  f.list(handed, 0, MAX_HELD, 'cancellations');
  const seen = new Set();
  // What the acknowledgements show is applied once every copy has been through the time-stamp rule.
  const acknowledgedCopies = [];
  const strict = new Set();
  // The problems with acknowledgements, by the place of their copy: reported, without setting the copy aside.
  const acknowledgementProblems = [];
  for (let i = 0; i < handed.length; i++) {
    const value = handed[i];
    const held = { kind: 'cancellation', fingerprint: null, slip: null, inBook: null, used: false, problems: [], notes: [], stamps: [], acknowledgements: [] };
    result.held.push(held);
    try {
      f.members(value, ['cancellation'], ['acknowledgements', 'stamps'], `cancellations[${i}]`);
      const parsed = await parseRecord(value.cancellation, 'cancellation');
      held.fingerprint = parsed.fingerprint;
      validateCancellationContent(parsed.content);
      const c = parsed.content;
      held.content = c;
      held.slip = c.slip;
      if (seen.has(parsed.fingerprint)) throw f.fail(`cancellations[${i}]`, 'the same cancellation is handed over twice.');
      seen.add(parsed.fingerprint);
      const slip = slips.get(c.slip);
      if (!slip || !slip.usable) throw new Refusal('slip-missing', 'The slip it names is not in the book, or did not pass its own check.');
      const alg = slip.content.issuer.key.alg;
      held.signature = { method: `passkey (${alg})`, alg, state: 'invalid' };
      try {
        held.signature.state = await checkPasskeySignature(parsed, slip.content.issuer, without);
      } catch {
        throw new Refusal('cancellation-invalid', 'It was not signed with the passkey the slip names, or its passkey values do not check.');
      }
      const confirmed = held.signature.state === 'valid' && slip.verified;
      const time = Object.hasOwn(value, 'stamps') ? await checkStamps(held, value.stamps, parsed.fingerprint, parseTime(c.when), options, confirmed) : null;
      if (Object.hasOwn(value, 'acknowledgements')) {
        const found = await checkHeldAcknowledgements(held, value.acknowledgements, parsed.fingerprint, c.slip, slip, passes, result.entries, without, confirmed);
        for (const p of found) acknowledgementProblems.push([i, p]);
        if (found.length > 0) held.notes.push('An acknowledgement handed over with it did not pass its check, so that acknowledgement was not used. See the problems at the top.');
      }
      if (held.problems.length > 0) continue;
      if (held.signature.state !== 'valid' || !slip.verified) {
        held.notes.push('This device could not confirm it, or the slip it names, so it was not used.');
        continue;
      }
      held.used = true;
      // The check before acting allows nothing under a slip the person has cancelled.
      beside.add(c.slip);
      const inBook = result.entries.find((e) => e.kind === 'cancellation' && e.fingerprint === parsed.fingerprint);
      held.inBook = inBook ? inBook.index : null;
      // What the agent's side acknowledged, where this device confirmed who signed.
      const told = held.acknowledgements.filter((a) => a.state === 'valid');
      if (held.acknowledgements.length > told.length) held.notes.push('This device could not check an acknowledgement handed over with it, so that acknowledgement was not used.');
      if (!inBook && told.length > 0) {
        const first = told.map((a) => a.when).sort()[0];
        held.notes.push(
          `The book does not hold this cancellation, though the agent's side acknowledged at ${first} (its own word for the time) that it was handed it. So it was left out of the book, or was still to be written into it when this copy of the book was made.`,
        );
      } else if (!inBook) held.notes.push('The book does not hold this cancellation: whoever keeps the book left it out, or was never given it.');
      else if (inBook.problems.length) held.notes.push(`The book holds this cancellation at entry ${inBook.index}, but that entry did not pass its check.`);
      for (const a of told) acknowledgedCopies.push([slip, c.slip, a]);
      if (time === null) {
        held.notes.push(
          told.length > 0
            ? 'It has no time-stamp from a service you named as trusted, so it cannot be placed in time. A stub is reported because of it only where the stub is dated after the agent\'s side acknowledged it.'
            : 'It has no time-stamp from a service you named as trusted, so it cannot be placed in time, and no stub is marked because of it.',
        );
        continue;
      }
      const made = cancelledAt(held, parseTime(c.when));
      held.stampedAt = formatTime(made);
      noteLateStamp(held, made, c.when);
      noteBlockSetAside(held, parseTime(c.when), CANCELLATION_BLOCK_SET_ASIDE);
      markNotShownEarlier(
        slip,
        made,
        'This stub is not shown to have existed before the person cancelled the slip: no outside time-stamp from before the cancellation covers it. The person\'s own copy of the cancellation was handed over beside the book.',
        late,
        strict,
      );
    } catch (e) {
      held.problems.push(problemFrom(e));
    }
  }
  const added = new Set();
  // First what each acknowledging agent did itself after it was told, for every acknowledgement; then what was
  // done under a pass handed on late. So the words a stub is given do not depend on the order of the acknowledgements.
  for (const underPasses of [false, true]) {
    for (const [slip, slipFingerprint, a] of acknowledgedCopies) markAfterAcknowledged(slip, slipFingerprint, passes, result.entries, a, late, strict, added, underPasses);
  }
  for (const [i, held] of result.held.entries()) {
    for (const p of held.problems) result.problems.push({ code: p.code, message: `Cancellation ${i + 1} of those handed over beside the book did not pass its check, so it was not used. ${p.message}` });
  }
  for (const [i, p] of acknowledgementProblems) {
    result.problems.push({
      code: p.code,
      message: `An acknowledgement handed over with cancellation ${i + 1} of those beside the book did not pass its check, so it was not used. The cancellation itself was not set aside because of it. ${p.message}`,
    });
  }
}

/**
 * Seals held elsewhere, handed over beside the book: by the person, an
 * auditor, or any copy kept out of the recorder's reach.
 *
 * Whoever keeps a book can cut off its end, the last seal with it, and what
 * is left still checks. A seal that someone else holds shows it: a seal at
 * entry n covers the n entries before it, so the book must hold that very
 * seal at entry n. A book that ends before it was cut short; a book that
 * holds another line there was changed, or is not the book the seal is of.
 *
 * Each seal handed over is checked as any seal is: its three signatures and
 * its time-stamps. It counts only where its recorder is one the person
 * named, and where this device checked its Ed25519 and ML-DSA-87
 * signatures; its third (SLH-DSA) may be one this device cannot check, as
 * in the check before acting (guard.js). The book holds it where the seal
 * at its place has the same content (the same fingerprint); other
 * signatures over the same content are said, and are not a fault of the
 * book. A seal handed over says nothing
 * for the book, only against it, so this widens nothing. One that does not
 * pass its own check is a problem with the whole check, never set aside:
 * the person handed it over to have it counted.
 *
 * Its time-stamps are checked and shown, but are not used for the entries
 * of the book. Nothing the reader keeps is changed.
 *
 * Witness statements handed over with it (format description, section
 * 29.2) are checked as statements on a seal's line are. One that does not
 * pass is a problem with the whole check, and is not used; the seal is used
 * all the same. A statement that counts, for a seal the book holds at its
 * place, counts for the book's seal there.
 *
 * @returns {Promise<Map<number, string[]>>} for each entry of the book that is a seal, the key set fingerprints
 *   of the witnesses whose statements, handed over beside the book, count for it
 */
async function checkHeldSeals(result, carried, options) {
  const witnessed = new Map();
  const handed = options.seals;
  if (handed === undefined) return witnessed;
  // Up to sixty-four, none included: an empty list is none.
  f.list(handed, 0, MAX_HELD_SEALS, 'seals');
  const own = await ownChecks(carried, handed, options);
  const entries = carried.reader.entries;
  // Whether a statement handed over can count for the book's seals (whyFor).
  const why = whyFor(entries, carried.options);
  // This book's number (section 21.6), from its first seal; null where it holds no seal.
  const bookNumber = carried.reader.seals.book;
  const firstSeal = entries.find((e) => e.kind === 'seal' && e.content);
  // The problems, in the order of the seals handed over.
  const found = [];
  for (let i = 0; i < own.length; i++) {
    const n = i + 1;
    const { sealText, stampsText, witnessProblems } = own[i];
    const held = structuredClone(own[i].held);
    result.held.push(held);
    for (const p of witnessProblems) {
      found.push({ code: p.code, message: `A witness statement handed over with seal ${n} of those beside the book did not pass its check, so it was not used. The seal itself was not set aside because of it. ${p.message}` });
    }
    // Whether each statement handed over with it counts is settled once it is known whether the seal is used.
    const settle = () => {
      Object.assign(held, witnessesCounted(held, why(held), held.used));
      // A statement that counts, for a seal the book holds at its place, counts for the book's seal there.
      if (held.inBook !== null) {
        const by = held.witnesses.filter((w) => w.counted).map((w) => w.witness);
        if (by.length > 0) witnessed.set(held.inBook, [...(witnessed.get(held.inBook) ?? []), ...by]);
      }
    };
    try {
      if (held.problems.length > 0) {
        for (const p of held.problems) found.push({ code: p.code, message: `Seal ${n} of those handed over beside the book did not pass its check, so it was not used. ${p.message}` });
        continue;
      }
      // It counts only where the person named its recorder.
      if (!Array.isArray(options.sealKeys)) {
        held.notes.push('It was not used: a seal handed over beside the book counts only where you named its recorder as one you expect.');
        continue;
      }
      const state = (method) => held.signatures.find((s) => s.method === method)?.state;
      if (state('Ed25519') !== 'valid' || state('ML-DSA-87') !== 'valid') {
        held.notes.push('It was not used: a seal handed over beside the book counts only where this device checked its Ed25519 and ML-DSA-87 signatures, and this device could not check both.');
        continue;
      }
      if (state(SEAL_THIRD) !== 'valid') {
        held.notes.push(`This device could not check its third signature (${SEAL_THIRD}). It was used on the strength of its Ed25519 and ML-DSA-87 signatures, which were checked here.`);
      }
      held.used = true;
      // A seal of another book of the same permission is not compared by its place (section 21.6), so it is not
      // used: it never counts as compared with the book, whatever it shows about the books around this one. The
      // number is the recorder's own word, and a book cut short could be sealed again under another number.
      const heldNumber = Object.hasOwn(held.content, 'book') ? held.content.book : 1;
      if (bookNumber !== null && heldNumber !== bookNumber) {
        held.used = false;
        const notCompared = `It was not compared with this book, so it gives no pass: a book is compared only with seals that give its own book number.`;
        if (heldNumber === bookNumber - 1 && held.fingerprint === carried.reader.seals.firstPrevious) {
          // The last seal of the book before, which the first seal of this book names.
          if (held.sealer !== firstSeal.sealer) {
            found.push({ code: 'seal-chain-broken', message: `Seal ${n} of those handed over beside the book is the seal the first seal of this book names as the last seal of the book before, but it was signed with other keys than this book's first seal.` });
          } else if (parseTime(held.content.when) > parseTime(firstSeal.content.when)) {
            found.push({ code: 'time-went-backwards', message: `Seal ${n} of those handed over beside the book is the last seal of the book before, which the first seal of this book names, but it is dated after that first seal.` });
          } else {
            held.notes.push(`It is the last seal of book ${heldNumber}, which the first seal of this book (book ${bookNumber}) names as the seal before it: this book follows on from it. It does not show whether book ${heldNumber} was cut short after it: check book ${heldNumber} with it. ${notCompared}`);
          }
        } else if (heldNumber === bookNumber - 1) {
          held.notes.push(`It is a seal of book ${heldNumber}, but the first seal of this book (book ${bookNumber}) names another seal as the last seal of book ${heldNumber}. So this book does not show whether book ${heldNumber} was cut short, nor that this book follows on from that book: check book ${heldNumber} with this seal. ${notCompared}`);
        } else if (heldNumber === bookNumber + 1 && entries.some((e) => e.kind === 'seal' && e.fingerprint === held.content.previous)) {
          const named = entries.find((e) => e.kind === 'seal' && e.fingerprint === held.content.previous);
          held.notes.push(`It is a seal of book ${heldNumber}, the next book, and names the seal at entry ${named.index} of this book as the seal before it: the next book follows on from this one there. It does not show whether this book was cut short. ${notCompared}`);
        } else if (heldNumber > bookNumber) {
          held.notes.push(`It is a seal of book ${heldNumber}, a later book than this one (book ${bookNumber}). This book does not show whether the books after it were cut short. Hand over seals of the book being checked. ${notCompared}`);
        } else {
          held.notes.push(`It is a seal of book ${heldNumber}, an earlier book than this one (book ${bookNumber}). This book does not show whether that book was cut short. Hand over seals of the book being checked. ${notCompared}`);
        }
        continue;
      }
      const at = held.place;
      if (at >= entries.length) {
        found.push({
          code: 'book-cut-short',
          message: `Seal ${n} of those handed over beside the book stands at entry ${at}, but the book ends at entry ${entries.length - 1}. The end of the book was cut off after that seal was made.`,
        });
        continue;
      }
      // The book holds this seal at its place where the seal there has the
      // same content: its fingerprint fixes the number of entries and their
      // top fingerprint, and so the entries before it.
      const there = entries[at];
      if (there.kind !== 'seal' || there.fingerprint !== held.fingerprint) {
        found.push({
          code: 'seal-not-in-book',
          message: `Seal ${n} of those handed over beside the book stands at entry ${at}, but the book holds another line there. The book was changed after that seal was made, or the seal is of another book.`,
        });
        continue;
      }
      held.inBook = at;
      if (there.problems.length > 0) held.notes.push(`The book holds this seal at entry ${at}, but that entry did not pass its check.`);
      // The same content with other signatures, or with other time-stamps
      // beside it, is not a fault of the book: it is said.
      const line = JSON.parse(sealLines.get(there));
      if (canonicalJson(line.seal) !== sealText) {
        held.notes.push(
          `The book holds this seal at entry ${at} with the same content, but with other signatures than this copy. The same content fixes the same entries, so this is not a fault of the book. Only someone who holds the recorder's keys can sign a seal again.`,
        );
      }
      if ((Object.hasOwn(line, 'stamps') ? canonicalJson(line.stamps) : null) !== stampsText) {
        held.notes.push(
          `The book holds this seal at entry ${at}, with other time-stamps beside it than this copy. Time-stamps stand outside a seal's signatures, so either side may have added one. This copy's own are shown here, and are not used for the entries of the book.`,
        );
      }
    } finally {
      settle();
    }
  }
  result.problems.push(...found);
  return witnessed;
}

/**
 * The check of each seal handed over that rests on the seal alone: its
 * signatures, its recorder and its time-stamps. It does not depend on the
 * book, so a checker that is carried on, and the stub writer, make it once
 * and keep it for as long as they are given the same seals with the same
 * options; each answer starts from a copy of it.
 */
async function ownChecks(carried, handed, options) {
  const key = [handed, options.sealKeys, options.stampServices, options.blocks, options.witnesses, options.withoutMethods];
  const kept = carried.heldSeals;
  if (kept && kept.key.every((value, i) => value === key[i])) return kept.items;
  const seen = new Set();
  const items = [];
  for (let i = 0; i < handed.length; i++) {
    const value = handed[i];
    const held = { kind: 'seal', fingerprint: null, sealer: null, place: null, inBook: null, used: false, verified: 'none', problems: [], notes: [], signatures: [], stamps: [], witnesses: [] };
    let sealText = null;
    let stampsText = null;
    // The problems with the witness statements handed over with it: reported, without setting the seal aside.
    let witnessProblems = [];
    try {
      f.members(value, ['seal'], ['stamps', 'witnesses'], `seals[${i}]`);
      const parsed = await parseRecord(value.seal, 'seal');
      held.fingerprint = parsed.fingerprint;
      if (seen.has(parsed.fingerprint)) throw f.fail(`seals[${i}]`, 'the same seal is handed over twice.');
      seen.add(parsed.fingerprint);
      // Checked as a seal that stands alone: its own unique number is the
      // book's seal's own, and its place is the one it states.
      const fresh = { count: 0, last: null, lastWhen: -Infinity, lastStampTime: -Infinity, latest: -Infinity, next: 0, sealed: null };
      await checkSealEntry(held, value, fresh, new Set(), options, null, [], false, true);
      sealText = canonicalJson(value.seal);
      stampsText = Object.hasOwn(value, 'stamps') ? canonicalJson(value.stamps) : null;
      // Witness statements that arrived after the seal was written into the book, handed over with it.
      // They are not entries of the book, so their unique numbers are not held against its own.
      if (held.problems.length === 0 && Object.hasOwn(value, 'witnesses')) {
        const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
        const { items: statements, problems } = await checkWitnesses(value.witnesses, parsed, options, without, null);
        held.witnesses = statements;
        witnessProblems = problems;
        noteWitnesses(held);
        if (problems.length > 0) held.notes.push('A witness statement handed over with it did not pass its check, so that statement was not used. See the problems at the top.');
      }
    } catch (e) {
      held.problems.push(problemFrom(e));
    }
    if (held.content) held.place = held.content.size;
    items.push({ held, sealText, stampsText, witnessProblems });
  }
  carried.heldSeals = { key, items };
  return items;
}

/**
 * Check a seal record by itself, as a seal held elsewhere is checked: its
 * envelope, its content and its three signatures against the keys it
 * gives. Nothing is said about where it stands in a book. For a witness
 * (witnessing.js). Not part of the public interface.
 * @param {any} record the seal record
 * @param {string[]} [withoutMethods] signing methods to treat as not built in
 * @returns {Promise<{fingerprint: string|null, content?: any, signatures: object[], problems: object[]}>}
 */
export async function checkSealAlone(record, withoutMethods = []) {
  const entry = { kind: 'seal', index: null, fingerprint: null, verified: 'none', problems: [], breaches: [], notes: [], signatures: [], stamps: [], witnesses: [] };
  try {
    const fresh = { count: 0, last: null, lastWhen: -Infinity, lastStampTime: -Infinity, latest: -Infinity, next: 0, sealed: null };
    await checkSealEntry(entry, { seal: record }, fresh, new Set(), { withoutMethods }, null, [], false, true);
  } catch (e) {
    entry.problems.push(problemFrom(e));
  }
  return entry;
}

// The third signing method of a seal, which some devices (the Python
// version, and every browser when tested) do not have.
const SEAL_THIRD = 'SLH-DSA-SHA2-256s';

// The blocks a person trusts are named by their fingerprints: 64 hex
// characters each. Anything else is refused, never set aside.
function checkBlocksOption(options) {
  const { blocks } = options;
  if (blocks === undefined) return;
  // At most as many as a book holds entries. Every place in the list is
  // read by its number, a gap included: "every" would skip a gap, and a
  // list's own way of walking through itself is not used.
  let sound = Array.isArray(blocks) && blocks.length <= MAX_ENTRIES;
  for (let i = 0; sound && i < blocks.length; i++) sound = typeof blocks[i] === 'string' && /^[0-9a-fA-F]{64}$/.test(blocks[i]);
  if (!sound) throw f.fail('blocks', 'must be a list of block fingerprints, each 64 hex characters, at most 100,000.');
}

// Compare the top fingerprint and the number of entries with what the
// checker already trusts, if it was given either.
function compareTrusted(result, options) {
  if (options.expectedRoot !== undefined && options.expectedRoot !== result.root) {
    throw new Refusal('root-mismatch', 'The top fingerprint is not the one expected.');
  }
  if (options.expectedSize !== undefined && options.expectedSize !== result.size) {
    throw new Refusal('root-mismatch', 'The number of entries is not the one expected.');
  }
}

/**
 * Check a whole book.
 *
 * The answer always has the same shape, whatever the book holds. It never
 * throws for a bad record: a failed check is a normal answer.
 *
 * @param {string} text the book
 * @param {object} [options]
 * @param {string[]} [options.issuerKeys] thumbprints of the issuer keys the checker expects
 * @param {string[]} [options.issuerOrigins] the addresses of the pages at which the checker expects every slip to have been signed,
 *   each in the form of section 4.1 (https://, a website name in lower case, a port only if needed). At most 64
 * @param {string} [options.expectedRoot] the top fingerprint the checker already trusts
 * @param {number} [options.expectedSize] the number of entries the checker already trusts
 * @param {string[]} [options.stampServices] the certificate fingerprints of the time-stamp services the checker trusts
 * @param {string[]} [options.blocks] the fingerprints (64 hex characters) of the blocks of a public blockchain that the checker trusts
 * @param {string[]} [options.sealKeys] the key set fingerprints of the recorders the checker expects
 * @param {string[]} [options.vouchers] the key set fingerprints of the organisations whose vouching the checker trusts
 * @param {Record<string, string[]>} [options.disclosures] for covered fields: the disclosures handed over, by the fingerprint of the slip they belong to
 * @param {object[]} [options.cancellations] the person's own copies of cancellations, each as the entry it would be in a book:
 *   {cancellation, stamps?}. At most 16. They count even where the book leaves them out
 * @param {object[]} [options.seals] seals held elsewhere (by the person, an auditor, a copy kept apart), each as the
 *   entry it is in a book: {seal, stamps?, witnesses?}. At most 64. The book must hold each at the place it states
 * @param {string[]} [options.witnesses] the key set fingerprints of the witnesses the checker trusts (section 29)
 * @param {string[]} [options.withoutMethods] signing methods to treat as not built into this device
 * @returns {Promise<object>} see the README, "What the checker returns".
 *   The content of an entry that has problems, or whose "verified" is
 *   "none", is given as it was read, for whoever must find out what went
 *   wrong. It is unverified: never show it as fact.
 */
export async function checkBook(text, options = {}) {
  return (await checkBookKeepingState(text, options)).result;
}

/**
 * Check a whole book, and also hand back the running state of every slip,
 * for the check before acting (guard.js). Not part of the public interface.
 */
export async function checkBookKeepingState(text, options = {}) {
  // The options are read through the same fixed copy as a checker that is
  // carried on reads them, so that the two cannot read them differently.
  const carried = startCarried(fixedOptions(options));
  await carryOn(carried, text);
  return answerOf(carried);
}

// --- a book that is read once and then carried on ---
//
// A whole check is: start, read every line, give the answer. The three
// steps are kept apart here, so that more lines can be read after an
// answer was given, without reading the earlier ones again. checkBook does
// the three in one go; openChecker and the stub writer (recorder.js) carry
// a book on. There is one way of reading a line (readLine), so a book that
// is carried on gets the answer that a whole check gives.

/**
 * Start reading a book. Not part of the public interface.
 * @param {object} [options] the checker's options, fixed from here on
 */
export function startCarried(options = {}) {
  if (options === null || typeof options !== 'object') options = {};
  const carried = {
    options,
    reader: newReader(options, true),
    // Whether any text was handed over at all, and whether it ended with a line feed.
    any: false,
    closed: true,
    // A problem with the book as a whole, which no later line can mend: an option that cannot be used, or too many entries.
    failure: null,
    // The check of the seals handed over that rests on the seals alone, made once (ownChecks).
    heldSeals: null,
  };
  try {
    lookIntoOptions(options);
    checkBlocksOption(options);
    checkOriginsOption(options);
    // Every line is read with this option, so one that cannot be read is a
    // problem with the whole check, found before any line is read.
    Array.isArray(options.withoutMethods);
  } catch (e) {
    carried.failure = problemFrom(e);
  }
  return carried;
}

// An option that cannot even be looked into (a revoked Proxy, for one),
// which the fixed copy keeps as it was handed over, is a problem with the
// whole check, wherever it would have been read. One that cannot be read
// at all still fails only where a check reads it.
function lookIntoOptions(options) {
  for (const name of OPTION_NAMES) {
    let value;
    try {
      value = options[name];
    } catch {
      continue;
    }
    Array.isArray(value);
  }
}

/**
 * Read more of a book: whole lines, each ending with a line feed. (The
 * last line of all may lack its line feed, as in a whole check; nothing
 * can then be added after it.) Not part of the public interface.
 * @param {ReturnType<typeof startCarried>} carried
 * @param {string} text
 */
export async function carryOn(carried, text) {
  if (typeof text !== 'string' || text.length === 0) return;
  if (carried.any && !carried.closed) throw new RangeError('The book so far does not end with a line feed, so nothing can be added to it.');
  carried.any = true;
  carried.closed = text.endsWith('\n');
  if (carried.failure) return;
  const { reader } = carried;
  let lines;
  try {
    lines = splitLines(text);
    if (reader.entries.length + lines.length > MAX_ENTRIES) throw new Refusal('too-large', 'The book holds more than 100,000 entries.');
  } catch (e) {
    carried.failure = problemFrom(e);
    return;
  }
  for (const line of lines) await readLine(reader, { index: reader.entries.length, line });
}

/**
 * The answer for a book as it stands. It changes nothing that the reader
 * keeps, so more lines can be read afterwards, and the answer asked for
 * again. Not part of the public interface.
 *
 * @param {ReturnType<typeof startCarried>} carried
 * @param {object} [options] the options for what is handed over beside the book (cancellations, disclosures)
 *   and for what is expected of it (expectedRoot, expectedSize); the options the lines were read with by default
 * @returns {Promise<{result: object, state: object, beside: Set<string>}>} the answer; the running state of every
 *   slip, for the check before acting; and the slips that a cancellation handed over beside the book cancels
 */
export async function answerOf(carried, options = carried.options) {
  const result = { format: 'provared-book-draft-v0', size: 0, root: null, problems: [], notes: [], entries: [], held: [], summary: null };
  let state = { slips: new Map(), terms: new Map(), passes: new Map(), ids: new Set() };
  let sealed = null;
  let late = new Map();
  const beside = new Set();
  // For each seal of the book, the witnesses whose statements, handed over beside it, count for it.
  let heldWitnessed = new Map();
  if (options === null || typeof options !== 'object') options = {};
  try {
    if (!carried.any) throw new Refusal('not-json', 'There is no record to check.');
    if (carried.failure) throw new Refusal(carried.failure.code, carried.failure.message);
    const { reader } = carried;
    result.size = reader.entries.length;
    // Until the answer is put together, the entries are looked at as the reader keeps them.
    result.entries = reader.entries;
    late = settleLate(reader);
    state = { slips: reader.slips, terms: reader.terms, passes: reader.passes, ids: reader.ids };
    sealed = reader.seals.sealed;
    result.root = toBase64url(await reader.tree.root());
    result.problems.push(...reader.handedProblems);
    unusedDisclosures(result, options);
    await checkHeld(result, reader, options, late, beside);
    heldWitnessed = await checkHeldSeals(result, carried, options);
    compareTrusted(result, options);
  } catch (e) {
    result.problems.push(problemFrom(e));
  }
  const read = result.entries;
  // Whether a witness's statement can count for each seal (whyFor).
  const why = whyFor(read, carried.options);
  result.entries = read.map((e) => answered(e, late, read, why));
  result.summary = summarise(result.entries, result.problems, sealed, result.held, heldWitnessed);
  return { result, state, beside };
}

/**
 * A book that carries on by itself from where this one stands, to try one
 * more line: a stub or, with "whole", a line of any kind (forkReader). The
 * book it was split from is left exactly as it was. Not part of the public
 * interface.
 */
export function forkCarried(carried, whole = false) {
  return { ...carried, reader: forkReader(carried.reader, whole) };
}

/**
 * A book that was split off to try a line takes the place of the one it
 * was split from, which is not used again. From here on it reads any kind
 * of entry. Not part of the public interface.
 */
export function promoteCarried(carried) {
  carried.reader.forked = false;
  return carried;
}

/**
 * A checker that can be carried on. It reads a book once, keeps what it
 * has worked out, and then takes more lines as the book grows, without
 * reading the earlier lines again. Its answer for the book so far is the
 * answer that checkBook gives for the same text.
 *
 * @param {string} [text] the book so far; it may be empty
 * @param {object} [options] as for checkBook. They are read once, when the checker is opened, as checkBook
 *   reads them, and fixed: lists and plain objects are copied, so that nothing done to them afterwards
 *   changes the checker
 * @returns {Promise<{add: (text: string) => Promise<void>, result: () => Promise<object>}>}
 *   "add" takes more whole lines, each ending with a line feed. "result"
 *   gives the answer for the book so far: a copy of its own each time, so
 *   that nothing done to an answer changes the checker. The calls wait
 *   for one another.
 */
export async function openChecker(text = '', options = {}) {
  const carried = startCarried(fixedOptions(options));
  await carryOn(carried, text);
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const run = turn.then(work);
    turn = run.catch(() => {});
    return run;
  };
  return {
    add(more) {
      return inTurn(() => carryOn(carried, more));
    },
    result() {
      return inTurn(async () => structuredClone((await answerOf(carried)).result));
    },
  };
}

/**
 * Make a Show: some entries of a book, each with the proof that it is in the
 * book (format description, section 11).
 * @param {string} text the book
 * @param {number[]} indexes which entries, counting from 0; at most 64
 * @param {object} [options]
 * @param {number} [options.seal] the entry that is a seal to show the pages under: the Show is then of
 *   the book as it stood when that seal was made, and carries the seal and its time-stamps
 * @param {Record<number, string[]>} [options.disclosures] for covered fields: the disclosures to hand over
 *   with a page, by the page's index
 * @returns {Promise<object>}
 */
export async function makeShow(text, indexes, options = {}) {
  let lines = splitLines(text);
  let seal;
  if (options.seal !== undefined) {
    if (!Number.isInteger(options.seal) || options.seal < 1 || options.seal >= lines.length) throw new RangeError('there is no such entry');
    seal = JSON.parse(lines[options.seal]);
    if (seal === null || typeof seal !== 'object' || !Object.hasOwn(seal, 'seal')) throw new RangeError('that entry is not a seal');
    lines = lines.slice(0, options.seal);
  }
  const leaves = lines.map(utf8);
  const wanted = [...new Set(indexes)].sort((a, b) => a - b);
  if (wanted.length < 1 || wanted.length > MAX_PAGES) throw new RangeError('a Show holds 1 to 64 pages');
  const pages = [];
  for (const index of wanted) {
    const path = await inclusionPath(leaves, index);
    const page = { index, entry: lines[index], path: path.map(toBase64url) };
    const reveal = options.disclosures && Object.hasOwn(options.disclosures, index) ? options.disclosures[index] : null;
    if (reveal) page.disclosures = reveal;
    pages.push(page);
  }
  const show = { type: 'provared.show.v0', size: lines.length, root: toBase64url(await treeRoot(leaves)), pages };
  if (seal) show.seal = seal;
  return show;
}

/**
 * Check a Show.
 *
 * A Show can show a stub outside its slip (a wrong action, a wrong party, a
 * wrong time, or a single stub over the limit). It cannot show that the
 * agent stayed within a limit: that needs every stub under the slip.
 *
 * @param {any} show the Show, as a JavaScript object or as JSON text
 * @param {object} [options]
 * @param {string} [options.expectedRoot] the top fingerprint the checker already trusts
 * @param {number} [options.expectedSize] the number of entries the checker already trusts
 * @param {string[]} [options.issuerKeys]
 * @param {string[]} [options.stampServices]
 * @param {string[]} [options.sealKeys]
 * @param {string[]} [options.witnesses]
 * @param {string[]} [options.withoutMethods]
 * @returns {Promise<object>} the same shape as checkBook returns. A seal that comes with the Show is the last entry.
 */
export async function checkShow(show, options = {}) {
  const result = { format: 'provared-show-draft-v0', size: 0, root: null, problems: [], notes: [], entries: [], held: [], summary: null };
  let sealed = null;
  try {
    // Read through the same fixed copy as a whole check reads them.
    options = fixedOptions(options);
    if (typeof show === 'string') {
      try {
        show = JSON.parse(show);
      } catch {
        throw new Refusal('not-json', 'The Show is not JSON.');
      }
    }
    lookIntoOptions(options);
    checkBlocksOption(options);
    checkOriginsOption(options);
    f.members(show, ['pages', 'root', 'size', 'type'], ['seal'], 'show');
    if (show.type !== 'provared.show.v0') throw f.fail('show.type', 'must be provared.show.v0.');
    f.wholeNumber(show.size, 'show.size');
    if (show.size < 1 || show.size > MAX_ENTRIES) throw f.fail('show.size', 'must be from 1 to 100,000.');
    f.fingerprintText(show.root, 'show.root');
    f.list(show.pages, 1, MAX_PAGES, 'show.pages');
    result.size = show.size;
    result.root = show.root;
    const root = fromBase64url(show.root);

    compareTrusted(result, options);

    const lines = [];
    const seen = new Set();
    for (let i = 0; i < show.pages.length; i++) {
      const page = show.pages[i];
      f.members(page, ['entry', 'index', 'path'], ['disclosures'], `pages[${i}]`);
      if (Object.hasOwn(page, 'disclosures')) f.list(page.disclosures, 1, 64, `pages[${i}].disclosures`);
      f.wholeNumber(page.index, `pages[${i}].index`);
      if (typeof page.entry !== 'string' || page.entry.length < 1 || page.entry.length > MAX_LINE_BYTES) {
        throw f.fail(`pages[${i}].entry`, 'must be one line of a book.');
      }
      f.list(page.path, 0, 64, `pages[${i}].path`);
      if (seen.has(page.index)) throw f.fail(`pages[${i}].index`, 'a page is repeated.');
      seen.add(page.index);
      const path = page.path.map((p, j) => {
        f.fingerprintText(p, `pages[${i}].path[${j}]`);
        return fromBase64url(p);
      });
      if (!(await verifyInclusion(page.index, show.size, utf8(page.entry), path, root))) {
        throw new Refusal('proof-invalid', `The proof for page ${page.index} does not lead to the top fingerprint.`);
      }
      lines.push({ index: page.index, line: page.entry, disclosures: page.disclosures });
    }
    lines.sort((a, b) => a.index - b.index);
    const reader = newReader(options, false);
    for (const item of lines) await readLine(reader, item);
    const checked = { ids: reader.ids, stampFloor: reader.seals.lastStampTime };
    result.entries = reader.entries;
    result.problems.push(...reader.handedProblems);
    unusedDisclosures(result, options);
    comparePageSeals(result.entries);

    // A seal that comes with the Show: the recorder's signature on exactly
    // this top fingerprint and this number of entries, and the outside
    // time-stamps on that seal.
    if (Object.hasOwn(show, 'seal')) {
      const entry = { index: show.size, kind: 'seal', fingerprint: null, verified: 'none', problems: [], breaches: [], notes: [] };
      result.entries.push(entry);
      try {
        f.members(show.seal, ['seal'], ['stamps', 'witnesses'], 'show.seal');
        // It is held to the pages as a seal in a whole book is held to the
        // entries before it: no unique number twice, and no block
        // time-stamp counted that states a time before a service's
        // time-stamp on a seal among the pages.
        await checkSealEntry(entry, show.seal, { count: 0, last: null, lastWhen: -Infinity, lastStampTime: checked.stampFloor, next: 0, sealed: null }, checked.ids, options, null, []);
        entry.vouched = null;
        if (entry.content.size !== show.size || entry.content.root !== show.root) {
          entry.problems.push({ code: 'seal-mismatch', message: 'The seal that comes with the Show is for another book, or for this book at another length.' });
        }
        // Against the seals among the pages, which all come before it in the book.
        laterThanSeals(entry, result.entries);
        // The seal's own date against the pages it covers, as in a whole book.
        if (datedBeforeCovered(parseTime(entry.content.when), result.entries, result.entries.length - 1, entry.stampedAt ? parseTime(entry.stampedAt) : null)) {
          entry.problems.push({ code: 'time-went-backwards', message: 'This seal is dated before a page it covers. One of the two dates is not as it says.' });
        }
      } catch (e) {
        entry.problems.push(problemFrom(e));
      }
      if (entry.problems.length) entry.verified = 'none';
      else if (entry.stampedAt) {
        const time = parseTime(entry.stampedAt);
        for (const page of result.entries) if (page !== entry) creditStamp(page, entry.stampedAt, time);
        sealed = { entries: show.size, when: entry.stampedAt, seal: show.size, by: countedBy(entry, checked.stampFloor) };
      }
    }
    if (options.expectedRoot === undefined && !sealed) {
      result.notes.push('The top fingerprint was not compared with a copy you already trust, and no seal with a time-stamp from a service you trust comes with it.');
    } else if (options.expectedSize === undefined && !sealed) {
      result.notes.push('The number of entries was not compared with a number you already trust. The top fingerprint alone does not fix it.');
    }
    result.notes.push('Single pages cannot show whether the chain is whole, whether a limit was kept, or whether an approval was used only once. Those need every stub under the slip.');
    result.notes.push('Single pages cannot show that a slip was not cancelled, or that a vouching record was not withdrawn, on a page that is not shown.');
    // An empty list is none, as for a whole book.
    if (options.cancellations !== undefined && !(Array.isArray(options.cancellations) && options.cancellations.length === 0)) {
      result.notes.push('Cancellations were handed over beside this Show. They were not used: single pages cannot show which stubs existed before a cancellation. Check the whole book with them.');
    }
    if (options.seals !== undefined && !(Array.isArray(options.seals) && options.seals.length === 0)) {
      result.notes.push('Seals held elsewhere were handed over beside this Show. They were not used: single pages cannot show what the book holds at the place each seal states, nor that the book goes on to it. Check the whole book with them.');
    }
  } catch (e) {
    result.problems.push(problemFrom(e));
  }
  // An acknowledgement whose cancellation, among the pages, failed after the acknowledgement was read.
  for (const e of result.entries) {
    if (e.kind !== 'acknowledgement' || e.cancellation === undefined) continue;
    const named = result.entries.find((p) => p.index === e.cancellation);
    if (named && named.problems.length > 0) failAcknowledgement(e);
  }
  // A seal or a cancellation that did not pass its check shows no time of its own.
  for (const e of result.entries) if (e.problems.length > 0) delete e.stampedAt;
  // Whether each witness statement counts, now that each seal's own check is complete.
  const why = whyFor(result.entries, options, new Set(result.entries.map((e) => e.index)));
  for (const e of result.entries) if (e.kind === 'seal' && Array.isArray(e.witnesses)) Object.assign(e, witnessesCounted(e, why(e)));
  result.summary = summarise(result.entries, result.problems, sealed, [], new Map(), true);
  return result;
}
