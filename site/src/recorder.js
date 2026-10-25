// The stub writer beside an agent. It keeps the agent's place in its chain,
// asks the check before acting (guard.js) before each action, and writes a
// stub for each action that is taken. It holds the book as text; where the
// text is kept is the caller's business.
//
// It makes the two things an agent's software must do into one call, so
// that they are not forgotten: ask first, and write the receipt after.
//
// One writer serves one chain: an agent under its slip, or a helper under
// its pass. Its calls wait for one another, so two actions asked for at the
// same moment are taken one after the other, each against the book as the
// one before left it. Two writers on copies of one book know nothing of
// each other: keeping them apart is the caller's business.
//
// The writer never puts into its book a line that would make the book fail
// its check. Before an action is taken, its stub is written and checked
// with the whole book; what the other side hands back is checked before it
// joins the stub, and left out if it does not check.
//
// The book is read once, when the writer is opened, and is then carried on
// (book.js): each new line is read by itself, against what was worked out
// from the lines before it. So no signature is checked twice, and what an
// action costs grows only slowly with the length of the book. Every line
// is tried on a reader split off the book's own, which takes the book's
// place only if the line is written, and is thrown away otherwise. So the
// book's own reader always stands for exactly the text of the book,
// whatever fails on the way.
//
// What is handed to the writer is copied when it is handed over: the
// request, the approval, what the other side hands back. The copy is what
// is checked and what is written, so a later change to the caller's own
// objects changes nothing.

import { MAX_LINE_BYTES, answerOf, carryOn, checkCountersignature, entryLine, fixedOptions, forkCarried, latestWhen, promoteCarried, startCarried } from './book.js';
import { Refusal, canonicalJson, fingerprint, formatTime, fromBase64url, parseTime, problemFrom, utf8 } from './encoding.js';
import { checkBeforeRead, lineBound } from './guard.js';
import { KEY_SET_METHODS } from './keys.js';
import { CLOCK_ALLOWANCE_MS, MAX_STAMPS } from './seal.js';
import { holdSigningKeys } from './signatures.js';
import { writeAcknowledgement } from './standing.js';
import { denialCodes, writeDenial } from './denial.js';
import { validateRequest, writeStub } from './stub.js';

/** How long the other side is given to hand back its countersignature, unless the caller says otherwise: 30 seconds. */
export const COUNTERSIGN_WITHIN_MS = 30000;
/** How long a signer is given for each signature, unless the caller says otherwise: 30 seconds. */
export const SIGN_WITHIN_MS = 30000;
/** The most denials a writer writes in any hour, unless the caller says otherwise: 600. */
export const DENIALS_PER_HOUR = 600;
// The most a caller may set it to: as many as a book may hold entries.
const MAX_DENIALS_PER_HOUR = 100000;
const HOUR_MS = 3600000;
// The longest wait a timer can hold.
const MAX_WAIT_MS = 2 ** 31 - 1;
// "detailsAfter" in "act": the most documents it may add, and the most the
// request may name beside them, so that a stub never names more than 32.
const MAX_DETAILS_AFTER = 4;
const MAX_DETAILS_BEFORE = 32 - MAX_DETAILS_AFTER;
// The room kept for them: the largest documents a stub may name, a name of
// 200 characters that are each written as six (a control character, which
// the one form of RFC 8785 writes as "\u00XX"), with a fingerprint.
const ROOM_DOCUMENT = Object.freeze({ name: '\u0001'.repeat(200), sha256: 'A'.repeat(43) });
// The stub with the further documents could not be made or signed.
class NotAdded extends Error {}
// The most cancellations a check may be handed beside a book (book.js).
const MAX_HANDED = 16;

// Where the platform can tell (Node.js), a call to the writer made by an
// action that the writer is taking is refused at once. It would otherwise
// wait for the action to end, while the action waits for it.
const hooks = globalThis.process && typeof globalThis.process.getBuiltinModule === 'function' ? globalThis.process.getBuiltinModule('node:async_hooks') : null;

function within(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no answer in time')), ms);
    promise.then(
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
}

const notWritten = (why) => new Refusal('record-not-sound', why);

// A time handed in: a number of milliseconds, or a Date. Text, true or a
// list would be read by rules that differ from one device to another (text
// with no time zone is taken as local time), so they are refused. A Date
// that cannot be read (one wrapped in a Proxy) gives no time, as a Date
// that is not a time gives none, and the check before acting refuses it.
function timeOf(when) {
  if (typeof when === 'number') return new Date(when).getTime();
  if (when instanceof Date) {
    try {
      return when.getTime();
    } catch {
      return NaN;
    }
  }
  throw new Refusal('bad-field', 'when: must be a number of milliseconds, or a Date.');
}

// A copy that nothing else holds, as structuredClone makes one, refused if
// it nests more than MAX_COPY_DEPTH levels deep: far more than a record
// holds. structuredClone's own limit depends on how much of the stack is in
// use, so without this two runs could give two answers. The depth is
// measured on the copy, so the caller's value is read once.
function clone(value) {
  const copy = structuredClone(value);
  const seen = new Set();
  const stack = [[copy, 0]];
  while (stack.length) {
    const [v, depth] = stack.pop();
    if (v === null || typeof v !== 'object' || seen.has(v)) continue;
    seen.add(v);
    if (depth > MAX_COPY_DEPTH) throw new TypeError('the value nests too deeply');
    for (const item of Object.values(v)) stack.push([item, depth + 1]);
  }
  return copy;
}

// A copy that nothing else holds.
function plain(value, what) {
  try {
    return clone(value);
  } catch {
    throw new Refusal('bad-field', `${what} must be plain data: text, numbers, lists and objects.`);
  }
}

// The deepest a copied value may nest: far more than a line of a book can hold.
const MAX_COPY_DEPTH = 64;

// A copy that nothing else holds, made in one pass: each member and each
// place is read once, and copied as it is read. So a member whose value
// changes from one reading to the next is read only once. An object of any
// kind, a Proxy among them, is copied as its own listed members; a list as
// its length and the places that hold an item, so that a gap stays a gap
// (and a check refuses it), and a faulty item beside a sound one leaves the
// sound one as it is. A value met twice is copied once. Throws where it
// cannot be done: a function, a list whose length is not a whole number, a
// value that holds itself (which nests without end), or a value that,
// written out, would be longer than a line of a book may be.
//
// The copies one copier makes share one count, so that several values,
// each short enough for a line, cannot together cost more than a line.
function copier() {
  const copies = new Map();
  let total = 0;
  // The copy, and the fewest characters it takes written out: a text its
  // characters and two quotation marks; any other single value one; a list
  // or an object its brackets and commas, and each member's name with its
  // quotation marks and colon. A value met again is counted again, as it is
  // written out again.
  const walk = (v, depth) => {
    if (typeof v === 'function' || typeof v === 'symbol' || typeof v === 'bigint') throw new TypeError('not plain data');
    if (typeof v === 'string') return [v, v.length + 2];
    if (v === null || typeof v !== 'object') return [v, 1];
    if (copies.has(v)) return copies.get(v);
    if (depth > MAX_COPY_DEPTH) throw new TypeError('the value nests too deeply, or holds itself');
    const list = Array.isArray(v);
    let made = {};
    if (list) {
      const length = v.length;
      if (!(Number.isInteger(length) && length >= 0 && length <= MAX_LIST_LENGTH)) throw new TypeError('not plain data');
      made = new Array(length);
    }
    let size = 2;
    let members = 0;
    for (const name of Object.keys(v)) {
      const [item, count] = walk(v[name], depth + 1);
      size += count + (members++ > 0 ? 1 : 0) + (list ? 0 : name.length + 3);
      if (size > MAX_LINE_BYTES) throw new TypeError('more than a line can hold');
      Object.defineProperty(made, name, { value: item, enumerable: true, writable: true, configurable: true });
    }
    copies.set(v, [made, size]);
    return [made, size];
  };
  return (value) => {
    const [made, size] = walk(value, 0);
    total += size;
    if (total > MAX_LINE_BYTES) throw new TypeError('more than a line can hold');
    return made;
  };
}

const copyOf = (value) => copier()(value);

// The longest a list can be.
const MAX_LIST_LENGTH = 2 ** 32 - 1;

// A copy of a cancellation given when the writer is opened, as plain data:
// its three members as a check reads them (by name, whether or not they are
// enumerable), and any other member as a check lists it. So what
// "cancellations" hands back is what was checked, and the writer never
// changes the caller's own object. An object of a class is copied in the
// same way: a check reads only its own members. One that cannot be copied
// so is refused when the writer is opened. Each of the three may be as long
// as a line; the other members share one line's length.
function plainHeld(copy) {
  if (copy === null || typeof copy !== 'object' || Array.isArray(copy)) return copy;
  try {
    const made = {};
    const rest = copier();
    for (const name of Object.getOwnPropertyNames(copy)) {
      const known = name === 'cancellation' || name === 'stamps' || name === 'acknowledgements';
      if (!known && Object.getOwnPropertyDescriptor(copy, name)?.enumerable !== true) continue;
      Object.defineProperty(made, name, { value: known ? copyOf(copy[name]) : rest(copy[name]), enumerable: true, writable: true, configurable: true });
    }
    return made;
  } catch {
    throw new Refusal('bad-field', 'options.cancellations: a copy of a cancellation could not be read as plain data.');
  }
}

/**
 * Open the stub writer for one agent under one slip.
 *
 * @param {object} o
 * @param {string} o.book the book so far: at least the slip
 * @param {string} o.slip the fingerprint of the slip
 * @param {any[]} o.privateKeys the agent's private keys, or signers (signatures.js): Ed25519, then ML-DSA-87
 * @param {string[]} o.issuerKeys the thumbprints of the passkeys this agent's software trusts; a slip from any other key allows nothing
 * @param {string} [o.pass] for a helper agent: the fingerprint of the pass it acts under
 * @param {object} [o.options] further options for the checker (sealKeys, stampServices, blocks, vouchers, cancellations).
 *   They are read once, as a whole check reads them, and fixed
 * @param {() => number} [o.now] the clock, in milliseconds; defaults to the device's. "act" takes an action at the clock's time, and nothing is written that is dated more than 300 seconds ahead of it
 * @param {number} [o.countersignWithin] how long the other side is given to countersign, in milliseconds; defaults to 30,000
 * @param {number} [o.signWithin] how long a signer is given for each signature, in milliseconds; defaults to 30,000.
 *   After that the action is not taken and nothing is written; a late answer is not used
 * @param {boolean} [o.denials] true to write a denial (format description, section 28) whenever "act" does not take an
 *   action, and to let "deny" write one; defaults to false, and then no denial is written
 * @param {number} [o.denialsPerHour] the most denials written in any hour, by the clock; defaults to 600. Each
 *   denial this writer writes, or is handed through "add", counts at the clock's time when it joins the book, whatever
 *   date it states; those the book held when the writer was opened count at the dates they state. Past the limit, a
 *   denial is not written, and the answers count those not written
 * @returns {Promise<object>} the writer: before, record, act, deny, book, check, cancellations, add
 * @throws {Refusal} "record-not-sound" if the book so far has a problem; "bad-field" or "bad-key" if an item of
 *   privateKeys is neither a key nor a signer, or is a signer that holds another key than the slip, or the pass, names
 */
export async function openRecorder({
  book,
  slip,
  privateKeys,
  issuerKeys,
  pass,
  options = {},
  now = Date.now,
  countersignWithin = COUNTERSIGN_WITHIN_MS,
  signWithin = SIGN_WITHIN_MS,
  denials = false,
  denialsPerHour = DENIALS_PER_HOUR,
}) {
  if (typeof now !== 'function') throw new Refusal('bad-field', 'now: must be a function that gives the time in milliseconds.');
  // A clock that gives anything but a time is a clock that failed: no comparison with it would hold.
  const device = now;
  now = () => {
    const time = device();
    if (!Number.isFinite(time)) throw new Refusal('bad-field', 'now: the clock did not give a time in milliseconds.');
    return time;
  };
  if (!(Number.isFinite(countersignWithin) && countersignWithin >= 1 && countersignWithin <= MAX_WAIT_MS)) {
    throw new Refusal('bad-field', 'countersignWithin: must be a number of milliseconds from 1 to 2,147,483,647.');
  }
  if (!(Number.isFinite(signWithin) && signWithin >= 1 && signWithin <= MAX_WAIT_MS)) {
    throw new Refusal('bad-field', 'signWithin: must be a number of milliseconds from 1 to 2,147,483,647.');
  }
  if (typeof denials !== 'boolean') throw new Refusal('bad-field', 'denials: must be true or false.');
  if (!(Number.isInteger(denialsPerHour) && denialsPerHour >= 1 && denialsPerHour <= MAX_DENIALS_PER_HOUR)) {
    throw new Refusal('bad-field', 'denialsPerHour: must be a whole number from 1 to 100,000.');
  }
  // Whom the writer trusts is fixed when it is opened: read once, as a whole
  // check reads it, and copied. The passkeys it trusts are its own
  // "issuerKeys", whatever the options say, read through the same fixed
  // copy. An option that cannot be read is refused here.
  const fixed = fixedOptions(options);
  const own = fixedOptions({ issuerKeys });
  let base;
  try {
    base = {};
    for (const name of Object.keys(fixed)) if (name !== 'issuerKeys') base[name] = fixed[name];
    Object.assign(base, own);
    // A value that cannot even be looked into (a revoked Proxy) is refused here.
    for (const value of Object.values(base)) Array.isArray(value);
    // A list longer than a check accepts is refused by the check; it is not walked through here.
    if (Array.isArray(base.cancellations) && base.cancellations.length <= MAX_HANDED) base.cancellations = base.cancellations.map(plainHeld);
  } catch (e) {
    if (e instanceof Refusal) throw e;
    throw new Refusal('bad-field', 'options: a member could not be read.');
  }
  // The person's cancellations that the writer holds beside its book: those
  // given when it was opened, and those of its own slip that were handed
  // to it since and could not yet be written into the book ("kept"). A
  // cancellation of another slip that cannot be added is nothing to this
  // writer and is not kept, so no number of them can crowd out one that
  // matters. Each is written into the book as soon as it can be
  // (writeWaiting). Until then it lives only in this writer:
  // "cancellations" hands it back, so that the caller can keep it with the
  // book. A check may be handed 16 at most: see "beside".
  const given = Array.isArray(base.cancellations) ? base.cancellations : [];
  /** @type {{entry: any, when: number, fingerprint: string, tried: boolean}[]} */
  const kept = [];
  // Those given at opening that the book does not hold: written into it as the kept ones are.
  /** @type {{entry: any, slip: string, when: number, fingerprint: string, tried: boolean}[]} */
  const unwritten = [];
  // The copies given at opening that already hold an acknowledgement of
  // this writer's own agent: the writer puts no second one with them.
  const ownAcked = new Set();
  // Whether the person's cancellation of this writer's slip was handed to
  // it. From then on it takes no action, whatever becomes of the
  // cancellation itself.
  let stopped = false;
  // The acknowledgements that this writer's own agent has signed, by the
  // fingerprint of the cancellation each is for: those the book holds
  // ("written"), and those signed since the writer was opened. One
  // cancellation is acknowledged once.
  const acknowledged = new Map();
  const written = new Set();
  // Those that could not yet follow their cancellation into the book, by
  // the fingerprint of the cancellation, with the cancellation itself.
  const waiting = new Map();
  // An acknowledgement that waits to follow its cancellation into the book
  // is handed back too, with the cancellation, unless a copy given at
  // opening already carries it. So a writer opened again from what this
  // one hands back writes the same acknowledgement, not a second one.
  // What the writer holds beside its book, the most needed first: the
  // person's cancellations of its own slip that the book does not hold
  // (those kept, then those given at opening), which stop the writer; then
  // the acknowledgements that wait, in the order in which they began to
  // wait (each carried by a copy given at opening, or handed back by
  // itself); then every other copy given at opening. A check may be handed
  // sixteen at most: where there are more, the last give way, so that
  // copies of other slips, or of cancellations the book holds, can never
  // crowd out one that matters.
  const ownUnwritten = () => unwritten.filter((u) => u.slip === slip).map((u) => u.entry);
  const waitingPart = (own = ownUnwritten()) => {
    const part = [];
    for (const [cancellation, record] of waiting) {
      const carriers = given.filter((g) => g && g.cancellation && g.cancellation.payload === record.payload);
      if (carriers.length === 0) part.push({ cancellation: record, acknowledgements: [acknowledged.get(cancellation)] });
      for (const g of carriers) if (!own.includes(g) && !part.includes(g)) part.push(g);
    }
    return part;
  };
  const room = () => {
    const own = ownUnwritten();
    return MAX_HANDED - kept.length - own.length - waitingPart(own).length;
  };
  const beside = () => {
    if (!kept.length && !waiting.size) return given;
    const own = ownUnwritten();
    const waits = waitingPart(own);
    const rest = given.filter((g) => !own.includes(g) && !waits.includes(g));
    return [...kept.map((k) => k.entry), ...own, ...waits, ...rest].slice(0, MAX_HANDED);
  };
  const checking = () => (kept.length || waiting.size ? { ...base, cancellations: beside() } : base);
  const STOPPED = { code: 'after-cancellation', message: 'The person cancelled the slip: the cancellation was handed to this stub writer.' };
  const whileStopped = (answer) => {
    if (stopped && answer.allowed) {
      answer.allowed = false;
      answer.breaches.push({ ...STOPPED });
    }
    return answer;
  };
  const without = Array.isArray(base.withoutMethods) ? base.withoutMethods : [];
  let text = typeof book === 'string' && book !== '' && !book.endsWith('\n') ? book + '\n' : book;

  // Where the agent's own chain stands: the last stub under this slip, and
  // under this pass if it acts under one.
  const lastStub = (entries) => {
    let last = null;
    for (const e of entries) {
      if (e.kind === 'stub' && e.slip === slip && (e.pass ?? null) === (pass ?? null)) last = { seq: e.content.seq, fingerprint: e.fingerprint };
    }
    return last;
  };
  // The book is read once, here. "carried" always stands for exactly the
  // text of the book: every line that joins the text is read into it.
  let carried = startCarried(base);
  await carryOn(carried, text);
  // The answer for the book as it stands, or for a reader split off it, with the cancellations held beside the book.
  const standing = (of = carried) => answerOf(of, checking());
  const { result } = await standing();
  if (result.summary.problemFound) throw notWritten('A problem was found in the record so far. It must be looked at before the agent acts again.');
  let after = lastStub(result.entries);
  // The times of the denials of this writer's own chain, which the hourly
  // limit counts: those the book held when the writer was opened, at the
  // dates they state; and each one that joins the book since, at the
  // clock's time when it joined, whatever date it states (a denial may be
  // dated up to 300 seconds back, and counting it there would let more
  // than the limit be written in an hour of the clock).
  const ownDenial = (e) => e.kind === 'denial' && e.problems.length === 0 && e.slip === slip && (e.pass ?? null) === (pass ?? null);
  const denialTimes = result.entries.filter(ownDenial).map((e) => parseTime(e.content.when));
  // How many denials were not written because of the hourly limit, since the writer was opened.
  let notWrittenDenials = 0;
  // What was given at opening: the first sound acknowledgement of this
  // writer's own agent that came with a cancellation is the one it goes on
  // handing back; a cancellation that the book does not hold waits to be
  // written.
  // (Seals held elsewhere, handed over with the options, come after the cancellations, and are not these.)
  result.held.forEach((h, i) => {
    if (h.kind !== 'cancellation' || !h.used) return;
    // The person's cancellation of this writer's own slip, given when it was opened, stops it from the start.
    if (h.slip === slip) stopped = true;
    h.acknowledgements.forEach((a, j) => {
      if (a.state !== 'valid' || h.slip !== slip || a.pass !== (pass ?? null)) return;
      ownAcked.add(given[i]);
      if (!acknowledged.has(h.fingerprint)) acknowledged.set(h.fingerprint, given[i].acknowledgements[j]);
    });
    if (h.inBook === null) unwritten.push({ entry: given[i], slip: h.slip, when: parseTime(h.content.when), fingerprint: h.fingerprint, tried: false });
  });
  {
    // The first acknowledgement of this writer's own agent that the book
    // holds for a cancellation is the one it goes on handing back.
    const lines = typeof text === 'string' ? text.split('\n') : [];
    for (const e of result.entries) {
      if (e.kind !== 'acknowledgement' || e.problems.length > 0 || e.slip !== slip || (e.pass ?? null) !== (pass ?? null)) continue;
      if (written.has(e.content.cancellation)) continue;
      acknowledged.set(e.content.cancellation, JSON.parse(lines[e.index]).acknowledgement);
      written.add(e.content.cancellation);
    }
  }
  // An acknowledgement given at opening, for a cancellation that the book
  // holds without it, follows the cancellation into the book: it was still
  // waiting when the writer that signed it handed it back.
  result.held.forEach((h, i) => {
    if (h.kind === 'cancellation' && h.used && h.slip === slip && h.inBook !== null && acknowledged.has(h.fingerprint) && !written.has(h.fingerprint)) waiting.set(h.fingerprint, given[i].cancellation);
  });
  // The services the slip names, to check a countersignature before it goes into the book.
  const slipEntry = result.entries.find((e) => e.kind === 'slip' && e.fingerprint === slip);
  const services = slipEntry && slipEntry.content ? slipEntry.content.with : [];

  // One call at a time. The answer to "would this be outside the slip?"
  // holds only until the next stub is written.
  const inside = hooks ? new hooks.AsyncLocalStorage() : null;
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const mark = inside ? inside.getStore() : undefined;
    if (mark && mark.writer === inTurn && mark.running) {
      return Promise.reject(new Error('The stub writer was called from inside an action it is taking. Call it once the action has ended.'));
    }
    const run = turn.then(work);
    turn = run.catch(() => {});
    return run;
  };
  // What the caller hands in to be run (the action, the request for a
  // countersignature) is run under a mark, so that the call above is
  // caught. The mark holds only while the writer is waiting for that work:
  // until it ends or, for a countersignature, until its time runs out.
  const runInside = async (work) => {
    if (!inside) return work();
    const mark = { writer: inTurn, running: true };
    try {
      return await inside.run(mark, work);
    } finally {
      mark.running = false;
    }
  };

  // The agent's keys, or signers (signatures.js). A signer is read once,
  // here, and must hold the keys that the slip, or the pass this writer
  // acts under, names for its agent. Each of its signatures is waited for
  // "signWithin" at most, under the same mark as an action, so that a
  // signer that calls the writer is refused at once; after that nothing is
  // written, and a late answer is not used. Keys of the platform are used
  // as they always were.
  const passEntry = pass ? result.entries.find((e) => e.kind === 'pass' && e.fingerprint === pass) : undefined;
  const ownKeys = pass ? passEntry?.content?.to?.keys : slipEntry?.content?.agent?.keys;
  const signing = await holdSigningKeys(privateKeys, KEY_SET_METHODS, ownKeys, signWithin, runInside);

  // What a call hands in, copied at the moment of the call.
  const asked = (request, more) => {
    if (request === null || typeof request !== 'object') throw new Refusal('bad-field', 'The request must be an object.');
    if (more === null || typeof more !== 'object') more = {};
    const call = {
      request: plain(request, 'The request'),
      when: more.when === undefined || more.when === null ? undefined : timeOf(more.when),
      terms: more.terms,
      countersign: more.countersign,
      detailsAfter: more.detailsAfter,
      hasApproval: more.approval !== undefined && more.approval !== null,
      approval: undefined,
      // For "act": false writes no denial for this call. For "deny": who said no, and why.
      denial: more.denial,
      source: more.source,
      codes: more.codes === undefined ? undefined : plain(more.codes, 'codes'),
    };
    if (call.hasApproval) {
      try {
        call.approval = clone(more.approval.record);
      } catch {
        call.approval = undefined; // not a record: refused when the stub is written
      }
    }
    return call;
  };
  const calling = (request, more, work) => {
    let call;
    try {
      call = asked(request, more);
    } catch (e) {
      return Promise.reject(e);
    }
    return inTurn(() => work(call));
  };

  const proposalFrom = (call, when) => {
    const { request } = call;
    const proposal = { slip, action: request.action };
    for (const name of ['amount', 'with', 'details']) {
      // An empty list of documents is the same as none, as the stub itself is written.
      if (name === 'details' && Array.isArray(request.details) && request.details.length === 0) continue;
      if (request[name] !== undefined) proposal[name] = request[name];
    }
    if (pass) proposal.pass = pass;
    proposal.when = when;
    if (call.terms !== undefined) proposal.terms = call.terms;
    if (call.hasApproval) proposal.approval = call.approval;
    return proposal;
  };
  // Whether the stub for this request, with the countersignature the check
  // before acting keeps room for, would still fit a line with the largest
  // further documents that "detailsAfter" may add: the same bound as the
  // check before acting uses, over the request with those documents.
  const roomForMore = (request, when) => {
    try {
      const c = { action: request.action, when: formatTime(when) };
      for (const name of ['amount', 'with']) if (request[name] !== undefined) c[name] = request[name];
      c.details = [...(Array.isArray(request.details) ? request.details : []), ...Array(MAX_DETAILS_AFTER).fill(ROOM_DOCUMENT)];
      return lineBound(c, undefined) <= MAX_LINE_BYTES;
    } catch {
      return false;
    }
  };
  const aheadOfClock = (when) => when > now() + CLOCK_ALLOWANCE_MS;
  const behindClock = (when) => when < now() - CLOCK_ALLOWANCE_MS;

  // The stub for an action, checked with the whole book before anything is
  // done with it. Nothing on its line may be dated ahead of the clock: the
  // stub's own date is looked at before this, and the approval's here. It
  // is read by a reader split off the book's own, which is handed back: if
  // the stub is not written after all, that reader is simply not used.
  const fitsBook = async (made, otherwise) => {
    const tried = forkCarried(carried);
    await carryOn(tried, made.line + '\n');
    const checked = (await standing(tried)).result;
    if (checked.summary.problemFound) throw notWritten(otherwise);
    if (latestWhen(checked.entries.at(-1)) > now() + CLOCK_ALLOWANCE_MS) throw notWritten('The approval that goes with this action is dated ahead of the clock, so nothing was written.');
    return tried;
  };

  // The fingerprint of an approval is worked out here, from the record
  // itself. One handed over with it is not relied on.
  const approvalFingerprint = async (record) => {
    try {
      return await fingerprint(fromBase64url(record.payload));
    } catch {
      throw new Refusal('approval-invalid', 'The approval handed over is not a signed record.');
    }
  };

  // The stub for an action, with the approval that goes with it, as a line.
  const composeStub = async (call, when) => {
    const { request } = call;
    const stub = await writeStub(
      {
        slip,
        after,
        action: request.action,
        amount: request.amount,
        with: request.with,
        details: request.details,
        approval: call.hasApproval ? await approvalFingerprint(call.approval) : undefined,
        terms: call.terms,
        pass,
        when,
      },
      signing,
    );
    const entry = { stub: stub.record };
    if (call.hasApproval) entry.approval = call.approval;
    const line = entryLine(entry);
    if (utf8(line).length > MAX_LINE_BYTES) throw new Refusal('too-large', 'The record of this action is longer than a line of a book may be.');
    return { stub, entry, line, countersignature: { accepted: false, problem: null } };
  };

  // Ask the other side for its countersignature, and put it with the stub
  // if it checks: the right keys, the right stub, not dated ahead of the
  // clock, and a line that still fits. One that does not check is left
  // out, and the stub stands one-sided, which is what happened.
  const countersigned = async (made, call) => {
    if (typeof call.countersign !== 'function') return made;
    const countersignature = { accepted: false, problem: null };
    let line = made.line;
    try {
      // The other side is handed a copy: nothing it does to it changes the stub.
      const given = await runInside(() => within(Promise.resolve(call.countersign(structuredClone(made.stub.record))), countersignWithin));
      if (given) {
        // What it hands back is copied at once. The copy is what is checked, and what joins the stub.
        let kept;
        try {
          kept = clone(given);
        } catch {
          throw new Refusal('countersignature-invalid', 'What the other side handed back is not a signed record.');
        }
        const service = typeof call.request.with === 'string' ? services.find((s) => s.id === call.request.with) : undefined;
        const checked = await checkCountersignature(kept, made.stub.fingerprint, service, without);
        if (checked.state !== 'valid') throw new Refusal('countersignature-invalid', 'This device could not check the countersignature.');
        if (parseTime(checked.when) > now() + CLOCK_ALLOWANCE_MS) {
          throw new Refusal('countersignature-invalid', 'The countersignature is dated ahead of the clock.');
        }
        const withIt = entryLine({ ...made.entry, countersignature: kept });
        if (utf8(withIt).length > MAX_LINE_BYTES) throw new Refusal('too-large', 'With the countersignature, the line would be longer than a line of a book may be.');
        line = withIt;
        countersignature.accepted = true;
      }
    } catch (e) {
      countersignature.problem = e instanceof Refusal ? problemFrom(e) : { code: 'countersignature-missing', message: 'Asking the other side for its countersignature failed, or took too long.' };
    }
    return { ...made, line, countersignature };
  };

  // The line joins the book. The reader that takes the book's place is
  // the one the stub was tried on, if the line is still the one tried.
  // With a countersignature the line is another: it is read from where
  // the book stood, and the reader that tried the stub alone is not used.
  const commit = async ({ stub, line, countersignature }, made, tried) => {
    let next = tried;
    if (line !== made.line) {
      next = forkCarried(carried);
      await carryOn(next, line + '\n');
    }
    carried = promoteCarried(next);
    text += line + '\n';
    after = { seq: stub.seq, fingerprint: stub.fingerprint };
    return { ...stub, line, countersignature };
  };

  // A line that someone else made is tried on a reader split off the
  // book's own, which may read a line of any kind. If the book passes its
  // check with the line, and the line is not dated ahead of the clock, that
  // reader takes the book's place and the line joins the text. Otherwise it
  // is thrown away, and the book's own reader is as it was. "at" is the
  // clock, read once by the caller.
  const takeLine = async (line, at, options = checking()) => {
    const tried = forkCarried(carried, true);
    await carryOn(tried, line + '\n');
    const checked = (await answerOf(tried, options)).result;
    if (checked.summary.problemFound) return { fits: false, ahead: false, why: 'with it, the book would not pass its check.' };
    if (latestWhen(checked.entries.at(-1)) > at + CLOCK_ALLOWANCE_MS) return { fits: false, ahead: true, why: 'it is dated ahead of the clock.' };
    carried = promoteCarried(tried);
    text += line + '\n';
    return { fits: true, checked };
  };

  // A denial: the agent's side states that it did not take an action, and
  // why. It is written into the book only if the book still passes its check
  // with it and it is not dated ahead of the clock; it is tried on a reader
  // split off the book's own, as a stub is, because a denial changes nothing
  // read before it. At most "denialsPerHour" are written in any hour, by
  // the clock: past it, none is written and the writer counts it. Whatever
  // happens, the answer says what was done; nothing is thrown, so a denial
  // never stands in the way of what the writer does next. The request is the
  // copy made when the call was made, and only its action, amount, service
  // and documents are written: the documents are fingerprints, never the
  // documents themselves.
  const denialAnswer = (problem) => ({ written: false, problem, notWritten: notWrittenDenials });
  const writeDenialLine = async (request, source, codes, when) => {
    try {
      const at = now();
      const t = when ?? at;
      if (!Number.isFinite(t)) return denialAnswer({ code: 'bad-field', message: 'when: does not give a time.' });
      if (aheadOfClock(t) || behindClock(t)) {
        return denialAnswer({ code: 'record-not-sound', message: 'The denial was not written: a denial is written when the action is refused, so its date must be within 300 seconds of the stub writer\'s clock.' });
      }
      const inHour = denialTimes.filter((d) => d > at - HOUR_MS).length;
      if (inHour >= denialsPerHour) {
        notWrittenDenials++;
        return denialAnswer({
          code: 'denials-over-limit',
          message: `The denial was not written: this stub writer has written ${denialsPerHour} denials in the last hour, the most it may. Since it was opened, ${notWrittenDenials} were not written for that reason.`,
        });
      }
      const fields = { slip, action: request.action, source, when: t };
      for (const name of ['amount', 'with', 'details']) if (request[name] !== undefined) fields[name] = request[name];
      if (pass) fields.pass = pass;
      if (codes) fields.codes = codes;
      const made = await writeDenial(fields, signing);
      const line = entryLine({ denial: made.record });
      if (utf8(line).length > MAX_LINE_BYTES) return denialAnswer({ code: 'too-large', message: 'The denial is longer than a line of a book may be.' });
      const tried = forkCarried(carried);
      await carryOn(tried, line + '\n');
      const checked = (await standing(tried)).result;
      if (checked.summary.problemFound) return denialAnswer({ code: 'record-not-sound', message: 'The denial was not written: with it, the book would not pass its check.' });
      carried = promoteCarried(tried);
      text += line + '\n';
      denialTimes.push(at);
      return { written: true, fingerprint: made.fingerprint, line, notWritten: notWrittenDenials };
    } catch (e) {
      return denialAnswer(problemFrom(e));
    }
  };

  // A cancellation held beside the book is written into the book as soon as
  // it can be: once the date it gives is no longer ahead of the clock. It
  // goes in as the entry it is, without the acknowledgements that came with
  // it. If the book would not pass its check with it even then, it is not
  // tried again, and the writer goes on holding it.
  const writeWaiting = async (at) => {
    for (const list of [kept, unwritten]) {
      for (const item of [...list]) {
        if (item.tried || item.when > at + CLOCK_ALLOWANCE_MS) continue;
        const entry = { cancellation: item.entry.cancellation };
        if (Object.hasOwn(item.entry, 'stamps')) entry.stamps = item.entry.stamps;
        const taken = await takeLine(entryLine(entry), at);
        if (!taken.fits) {
          item.tried = true;
          continue;
        }
        // In the book, it is no longer one that waits.
        list.splice(list.indexOf(item), 1);
        // The acknowledgement that was signed when it was handed over follows it into the book.
        if (acknowledged.has(item.fingerprint)) await acknowledge(item.fingerprint, item.entry.cancellation, true, at);
      }
    }
    // An acknowledgement that could not follow its cancellation into the
    // book, because it was dated ahead of the clock, is tried again.
    for (const [cancellation] of [...waiting]) {
      const taken = await takeLine(entryLine({ acknowledgement: acknowledged.get(cancellation) }), at);
      if (taken.fits) written.add(cancellation);
      if (taken.fits || !taken.ahead) waiting.delete(cancellation);
    }
  };
  // The acknowledgement goes with the cancellation that the writer holds
  // beside its book, so that "cancellations" hands the two back together.
  // A copy holds four at most. The writer's own is always kept: where the
  // copy already holds four, the last of the others gives way to it.
  // Another agent's is put with the copy only where there is room.
  const putWith = (entry, record, own = true) => {
    if (!record) return;
    let list = Array.isArray(entry.acknowledgements) ? entry.acknowledgements : [];
    if (list.some((a) => a && a.payload === record.payload)) return;
    // A copy given at opening that already holds one of the agent's own takes no second one.
    if (own && ownAcked.has(entry)) return;
    if (list.length >= 4) {
      if (!own) return;
      list = list.slice(0, 3);
    }
    entry.acknowledgements = [...list, structuredClone(record)];
  };

  // The agent's side says that it was handed the person's cancellation of
  // its slip, and when: signed with this writer's own keys, once for each
  // cancellation, and dated by the writer's clock. Where the book holds
  // the cancellation, the acknowledgement follows it into the book. It is
  // handed back to the caller, to be given to the person. If it cannot be
  // signed, or does not check (the writer was opened with keys that are
  // not the agent's), there is none; the cancellation stops the writer all
  // the same.
  //
  // It is not dated before the writer's own last stub, nor before a pass
  // that its agent handed on. Either may be dated up to 300 seconds ahead
  // of the clock, and the agent was not told before it made them: an
  // acknowledgement dated by the clock alone would have them read as made
  // after the agent was told.
  const acknowledge = async (cancellation, cancellationRecord, inBook, at) => {
    let record = acknowledged.get(cancellation);
    if (!record) {
      let when = at;
      for (const e of (await standing()).result.entries) {
        if (e.slip !== slip || !e.content) continue;
        const own =
          (e.kind === 'stub' && (e.pass ?? null) === (pass ?? null)) ||
          (e.kind === 'pass' && (Object.hasOwn(e.content, 'from') ? e.content.from : null) === (pass ?? null));
        if (own && parseTime(e.content.when) > when) when = parseTime(e.content.when);
      }
      let made;
      try {
        made = (await writeAcknowledgement({ slip, cancellation, pass, when }, signing)).record;
      } catch {
        return undefined;
      }
      // Checked as a reader will check it, beside the person's own copy of the cancellation.
      const [beside] = (await answerOf(carried, { ...base, cancellations: [{ cancellation: cancellationRecord, acknowledgements: [made] }] })).result.held;
      if (!beside || beside.acknowledgements.length !== 1 || beside.acknowledgements[0].state !== 'valid') return undefined;
      record = made;
      acknowledged.set(cancellation, record);
    }
    if (inBook && !written.has(cancellation)) {
      const taken = await takeLine(entryLine({ acknowledgement: record }), at);
      if (taken.fits) written.add(cancellation);
      else if (taken.ahead) waiting.set(cancellation, cancellationRecord);
    }
    // It goes with the cancellation wherever the writer holds that beside its book.
    const held = kept.find((k) => k.fingerprint === cancellation);
    if (held) putWith(held.entry, record);
    const opened = given.find((h) => h && h.cancellation && h.cancellation.payload === cancellationRecord.payload);
    if (opened) putWith(opened, record);
    return structuredClone(record);
  };
  const refused = (message, acknowledgement) => {
    const e = notWritten(message);
    if (acknowledgement) e.acknowledgement = acknowledgement;
    return e;
  };

  // The acknowledgements handed over with the person's cancellation of this
  // writer's slip. Each is checked by itself, so that one which does not
  // check is never taken for one which does. The first sound one of this
  // writer's own agent is the one the writer goes on handing back, unless
  // it already has one; any further one of its own agent is let go, so that
  // a copy never holds two. The sound ones of other agents are handed back,
  // to stay with the copy. At most sixteen are looked at.
  const sortHanded = async (cancellation, cancellationRecord, handed) => {
    const others = [];
    if (!Array.isArray(handed)) return others;
    for (const record of handed.slice(0, MAX_HANDED)) {
      const [beside] = (await answerOf(carried, { ...base, cancellations: [{ cancellation: cancellationRecord, acknowledgements: [record] }] })).result.held;
      if (!beside || !beside.used || beside.acknowledgements.length !== 1 || beside.acknowledgements[0].state !== 'valid') continue;
      if (beside.acknowledgements[0].pass !== (pass ?? null)) others.push(record);
      else if (!acknowledged.has(cancellation)) acknowledged.set(cancellation, record);
    }
    return others;
  };
  // The writer's own acknowledgement, and the sound ones of other agents, go with a copy the writer holds.
  const putHanded = (entry, cancellation, others) => {
    putWith(entry, acknowledged.get(cancellation));
    for (const other of others) putWith(entry, other, false);
  };

  // The time-stamps that a cancellation should go with: those a copy of it
  // already holds, and those handed over now, none twice. Each is judged by
  // itself, beside the book: one with which the cancellation does not pass
  // its check is left out. Those that this writer counts come first, then
  // the others, four at most, so that a time-stamp the writer counts is
  // never crowded out by one it does not. Only a set with which the book
  // still passes its check is taken. Null where nothing changes.
  const mergedStamps = async (cancellationRecord, holds, offered) => {
    const keyOf = (s) => {
      try {
        return canonicalJson(s);
      } catch {
        return null;
      }
    };
    const held = new Set(holds.map(keyOf));
    const all = [...holds];
    for (const s of offered) {
      const key = keyOf(s);
      if (key === null || held.has(key)) continue;
      held.add(key);
      all.push(s);
    }
    if (all.length === holds.length) return null;
    const counted = [];
    const uncounted = [];
    for (const s of all) {
      const [one] = (await answerOf(carried, { ...base, cancellations: [{ cancellation: cancellationRecord, stamps: [s] }] })).result.held;
      if (!one || !one.used || one.problems.length > 0) continue;
      if (one.stampedAt) counted.push({ s, at: parseTime(one.stampedAt) });
      else uncounted.push(s);
    }
    // Of those it counts, the earliest come first: they place the cancellation earliest in time.
    counted.sort((a, b) => a.at - b.at);
    const stamps = [...counted.map((c) => c.s), ...uncounted].slice(0, MAX_STAMPS);
    if (stamps.length === 0 || keyOf(stamps) === keyOf(holds)) return null;
    let form;
    try {
      form = entryLine({ cancellation: cancellationRecord, stamps });
    } catch {
      return null;
    }
    const tried = forkCarried(carried, true);
    await carryOn(tried, form + '\n');
    if ((await answerOf(tried, checking())).result.summary.problemFound) return null;
    return stamps;
  };

  const writer = {
    /**
     * Ask whether an action would be outside the slip. Nothing is written.
     * The answer holds only until the next stub is written: use "act" to
     * ask and act in one step.
     * @param {{action: string, amount?: object, with?: string, details?: object[]}} request
     * @param {{when?: number|Date, terms?: string, approval?: {record: object}}} [more]
     * @returns {Promise<{allowed: boolean, problems: object[], breaches: object[], needs: string[]}>}
     */
    before(request, more = {}) {
      return calling(request, more, async (call) => whileStopped(await checkBeforeRead(() => standing(), proposalFrom(call, call.when ?? now()), checking())));
    },

    /**
     * Write the stub for an action that was taken, and add it to the book.
     * It does not ask first: use "act" for that. An action that was taken
     * is recorded whether or not it was inside the slip, because the record
     * is of what happened. But a stub is written only if the book still
     * passes its check with it: one dated ahead of the clock, or before
     * the stub ahead of it, or with an approval that does not fit, is
     * refused, and nothing is written. The other side is asked to
     * countersign only once the stub has passed that check, so a stub
     * that is refused has gone nowhere.
     *
     * @param {{action: string, amount?: object, with?: string, details?: object[]}} request
     * @param {object} [more]
     * @param {number|Date} [more.when] when the action was taken; defaults to the clock
     * @param {string} [more.terms] the fingerprint of the service's terms relied on
     * @param {{record: object}} [more.approval] the person's signed approval of this action
     * @param {(stub: object) => Promise<object|null>} [more.countersign] asks the other side for its countersignature; null if it gives none
     * @returns {Promise<{record: object, fingerprint: string, seq: number, line: string, countersignature: {accepted: boolean, problem: object|null}}>}
     *   "countersignature.accepted" says whether a countersignature was given, checked and put with the stub.
     *   Where one was given and did not check, or asking for it failed, "problem" says why, and the stub is one-sided.
     * @throws {Refusal} "record-not-sound" if the book would not pass its check with the stub; nothing is written
     */
    record(request, more = {}) {
      return calling(request, more, async (call) => {
        await writeWaiting(now());
        const when = call.when ?? now();
        // In the words of the check before acting, which "act" and "before" give.
        if (!Number.isFinite(when)) throw new Refusal('bad-field', 'when: does not give a time.');
        if (aheadOfClock(when)) throw notWritten('The stub was not written: it is dated ahead of the clock.');
        const made = await composeStub(call, when);
        const tried = await fitsBook(made, 'The stub was not written: with it, the book would not pass its check.');
        return commit(await countersigned(made, call), made, tried);
      });
    },

    /**
     * Ask first; if the action is allowed, take it and write its stub.
     *
     * If the action is not allowed it is not taken and nothing is written.
     * The action is taken now: a date handed in ("when") must be within 300
     * seconds of the writer's clock, or the action is not taken. Before the
     * action is taken, its stub is written and checked with the whole
     * book, so that the receipt is known to fit before there is anything
     * to give a receipt for. Where the slip asks for a countersignature,
     * the action is taken only if a way to ask for one ("countersign") is
     * given. If taking the action fails with an error, the error is passed
     * on and no stub is written: there is then no receipt for whatever
     * part of the action did happen, and the caller must deal with that.
     * If taking the action never ends, the writer waits: it cannot know
     * what happened.
     *
     * Where an identifier or a document comes only with what the action
     * gives back (the identifier a platform gave the call, say), "detailsAfter"
     * names it: a function of what the action gave, that gives up to four
     * further documents ({name, sha256} each). The stub is then signed again
     * after the action, with them, still in this call's turn, so that no
     * other call comes between; it keeps the time the action began. The
     * request may then name at most 28 documents, and no approval may be
     * given (an approval covers exactly the documents the person saw).
     * "detailsAfter" is given as long as the other side is given to
     * countersign. If it fails, gives no answer in time, gives something
     * that is not a list of at most four documents, or gives documents with
     * which the stub would not pass the check of the book, the stub made
     * before the action is written, without them: an action that was taken
     * always gets its stub. "detailsAfter" in the answer says what was added
     * and, where nothing was, why.
     *
     * @param {{action: string, amount?: object, with?: string, details?: object[]}} request
     * @param {() => Promise<any>} perform takes the action; it must not call this writer
     * @param {object} [more] as for "record"; "when" defaults to the clock and must be within 300 seconds of it
     * @param {(result: any) => object[]|Promise<object[]>} [more.detailsAfter] further documents, from what the action gave; it must not call this writer
     * @returns {Promise<{done: boolean, answer: object, result?: any, stub?: object, detailsAfter?: {added: number, problem: object|null}}>}
     *   "detailsAfter" is there only where it was given and the action was taken
     */
    act(request, perform, more = {}) {
      return calling(request, more, async (call) => {
        await writeWaiting(now());
        const when = call.when ?? now();
        const answer = whileStopped(await checkBeforeRead(() => standing(), proposalFrom(call, when), checking()));
        const stop = (problem) => {
          answer.allowed = false;
          answer.problems.push(problem);
        };
        if (answer.allowed && aheadOfClock(when)) stop({ code: 'record-not-sound', message: 'The action is dated ahead of the clock.' });
        if (answer.allowed && behindClock(when)) {
          stop({
            code: 'record-not-sound',
            message: 'The action is dated behind the clock. An action is taken now, so its date may not be more than 300 seconds before the stub writer\'s clock. An action that was taken earlier is written with "record".',
          });
        }
        // Said whether or not something else stands in the way too, so that whoever reads the answer sees all of it.
        if (answer.needs.includes('countersignature') && typeof call.countersign !== 'function' && !answer.breaches.some((b) => b.code === 'countersignature-missing')) {
          answer.allowed = false;
          answer.breaches.push({
            code: 'countersignature-missing',
            message: 'The slip asks for the other side to countersign this action, and the stub writer was given no way to ask for a countersignature.',
          });
        }
        const later = call.detailsAfter;
        const hasLater = later !== undefined && later !== null;
        if (hasLater) {
          const named = Array.isArray(call.request.details) ? call.request.details.length : 0;
          if (typeof later !== 'function') stop({ code: 'bad-field', message: 'detailsAfter: must be a function of what the action gives.' });
          else if (call.hasApproval) {
            stop({ code: 'bad-field', message: 'detailsAfter: cannot be used with an approval. An approval covers exactly the documents the person saw, so no document may be added to the stub after the action.' });
          } else if (named > MAX_DETAILS_BEFORE) {
            stop({ code: 'bad-field', message: `detailsAfter: the request may then name at most ${MAX_DETAILS_BEFORE} documents, so that there is room for ${MAX_DETAILS_AFTER} more.` });
          } else if (answer.allowed && !roomForMore(call.request, when)) {
            stop({ code: 'too-large', message: 'With room for the documents that "detailsAfter" may add, the record of this action would be longer than a line of a book may be.' });
          }
        }
        let made;
        let tried;
        if (answer.allowed) {
          try {
            made = await composeStub(call, when);
            tried = await fitsBook(made, 'The stub for this action would not pass the check of the book, so the action was not taken.');
          } catch (e) {
            stop(problemFrom(e));
          }
        }
        if (!answer.allowed) {
          if (!denials || call.denial === false) return { done: false, answer };
          return { done: false, answer, denial: await writeDenialLine(call.request, 'check', denialCodes(answer), undefined) };
        }
        const outcome = await runInside(perform);
        if (!hasLater) {
          const stub = await commit(await countersigned(made, call), made, tried);
          return { done: true, answer, result: outcome, stub };
        }
        // The further documents, from what the action gave back. The stub
        // with them is signed now, still in this turn, and keeps the time
        // the action began. If anything about them fails, the stub made
        // before the action, which is known to fit, is the one written: an
        // action that was taken always gets its stub.
        const further = { added: 0, problem: null };
        let chosen = made;
        let chosenTried = tried;
        try {
          const given = await runInside(() => within(Promise.resolve(later(outcome)), countersignWithin));
          let documents;
          try {
            documents = given === undefined || given === null ? [] : clone(given);
          } catch {
            throw new Refusal('bad-field', 'detailsAfter: must give a list of documents, as plain data.');
          }
          if (!Array.isArray(documents)) throw new Refusal('bad-field', 'detailsAfter: must give a list of documents.');
          if (documents.length > MAX_DETAILS_AFTER) throw new Refusal('bad-field', `detailsAfter: gave ${documents.length} documents; it may give ${MAX_DETAILS_AFTER} at most.`);
          if (documents.length > 0) {
            const base = Array.isArray(call.request.details) ? call.request.details : [];
            const all = [...base, ...documents];
            // The documents are checked first, so that a refusal of them says why in its own words.
            validateRequest({ action: call.request.action, details: all });
            const withThem = { ...call, request: { ...call.request, details: all } };
            let next;
            try {
              next = await composeStub(withThem, when);
            } catch {
              // The stub made before the action is the one written: say so, whatever failed.
              throw new NotAdded('The stub with the further documents could not be made or signed, so the stub made before the action was written, without them.');
            }
            chosenTried = await fitsBook(next, 'With the documents that "detailsAfter" gave, the stub would not pass the check of the book.');
            chosen = next;
            further.added = documents.length;
          }
        } catch (e) {
          chosen = made;
          chosenTried = tried;
          further.problem =
            e instanceof NotAdded
              ? { code: 'details-not-added', message: e.message }
              : e instanceof Refusal
                ? problemFrom(e)
                : { code: 'details-not-added', message: 'detailsAfter failed, or gave no answer in time, so the stub was written without further documents.' };
        }
        const stub = await commit(await countersigned(chosen, call), chosen, chosenTried);
        return { done: true, answer, result: outcome, stub, detailsAfter: further };
      });
    },

    /**
     * Write a denial for an action that was not taken, where "act" did not
     * write one: the person refused, or gave no approval when asked
     * ("person"); a rule of the software around the agent, outside the slip,
     * said no ("rule"); or the check before acting said no, and the caller
     * asked "act" to write no denial for that call ("check", with the codes
     * of that answer: denialCodes gives them). Nothing is taken and no stub
     * is written. A writer opened without "denials: true" writes none.
     * @param {{action: string, amount?: object, with?: string, details?: object[]}} request what was asked for
     * @param {{source: 'check'|'person'|'rule', codes?: string[], when?: number|Date}} more "codes" only for "check";
     *   "when" defaults to the clock, and must be within 300 seconds of it
     * @returns {Promise<{written: boolean, fingerprint?: string, line?: string, problem?: object, notWritten: number}>}
     *   "notWritten": how many denials were not written because of the hourly limit since the writer was opened
     */
    deny(request, more = {}) {
      return calling(request, more, async (call) => {
        if (!denials) return denialAnswer({ code: 'bad-field', message: 'This stub writer was opened without "denials: true", so it writes no denial.' });
        if (call.source !== 'check' && call.source !== 'person' && call.source !== 'rule') return denialAnswer({ code: 'bad-field', message: 'source: must be "check", "person" or "rule".' });
        let at;
        try {
          at = now();
        } catch (e) {
          return denialAnswer(problemFrom(e));
        }
        await writeWaiting(at);
        return writeDenialLine(call.request, call.source, call.codes, call.when);
      });
    },

    /** The book as it now stands. */
    book() {
      return text;
    },

    /**
     * What the record shows as it stands: the answer that a whole check of
     * the book gives, with the cancellations the writer holds beside it.
     * Nothing is read again.
     * @returns {Promise<object>} as checkBook returns; a copy of its own each time
     */
    check() {
      return inTurn(async () => structuredClone((await standing()).result));
    },

    /**
     * The person's cancellations that the writer holds beside its book:
     * those it was given when it was opened, and those of its own slip
     * that it could not yet write into the book, each with the
     * acknowledgement the writer signed for it; and a cancellation whose
     * acknowledgement still waits to follow it into the book, with that
     * acknowledgement. They live only in this
     * writer. Keep them with the book, and hand them in again
     * ("options.cancellations") when a writer is opened again from the
     * book: a writer opened without them knows nothing of them.
     * @returns {object[]} copies, each as it is handed to a check: {cancellation, stamps?, acknowledgements?}
     */
    cancellations() {
      return structuredClone(beside());
    },

    /**
     * Add an entry that someone else made (a seal, a cancellation, a
     * refusal) to the book. It is added only if the book still passes its
     * check with it, and it is not dated ahead of the clock.
     *
     * A cancellation is a special case: whatever is wrong with what stands
     * beside it, a cancellation that the person signed is not lost.
     *  - If the entry cannot be added as it was handed over (a faulty
     *    time-stamp beside it, a member that cannot be written as a line),
     *    the cancellation is added with the time-stamps that pass their
     *    check, or by itself, without what else stood beside it, if the
     *    book passes its check with that.
     *  - If it cannot be added even so (a date ahead of the clock), but is
     *    signed with the passkey the slip names, the writer keeps it as the
     *    person's own copy and allows nothing more under the slip. It
     *    writes it into the book, at its next call, once the clock has
     *    reached its date.
     * In both cases the call still fails, and the error says what was done.
     *
     * Whenever the person's cancellation of this writer's own slip is
     * handed to "add", the writer signs an acknowledgement: its agent's
     * statement that it was handed the cancellation, and when. It is
     * handed back, to be given to the person, and it follows the
     * cancellation into the book. One cancellation is acknowledged once:
     * the same acknowledgement is handed back each time, also by a writer
     * opened again and given what "cancellations" handed back.
     *
     * @param {object} entry
     * @returns {Promise<{acknowledgement?: object}>} for the person's cancellation of this writer's slip: the acknowledgement
     * @throws {Refusal} "record-not-sound" if the entry cannot be added as it was handed over.
     *   Nothing is added, except a cancellation by itself as set out above. Where the person's
     *   cancellation of this writer's slip was handed over, the error holds the "acknowledgement"
     */
    add(entry) {
      // What is handed over is read once, member by member, when it is
      // handed over: the members a line of a book lists, and the three of a
      // cancellation by their names. Each is copied as it is read, so a
      // member whose value changes from one reading to the next cannot make
      // the forms below differ. A member that cannot be read or copied makes
      // the entry one that cannot be written as a line. The three members of
      // a cancellation are read first, each with room for a line of its own,
      // so that nothing handed over beside them can keep them from being
      // read. The other members share one line's room: once one of them
      // cannot be read or copied, the entry cannot be a line, and the rest
      // are not read. Anything but an object (a list, or a value that cannot
      // even be looked into) cannot be a line, and is not written out.
      const read = new Map();
      let listed = null;
      let object = false;
      try {
        object = entry !== null && typeof entry === 'object' && !Array.isArray(entry);
      } catch {
        object = false;
      }
      if (object) {
        try {
          listed = Object.keys(entry);
          const known = ['cancellation', 'stamps', 'acknowledgements'].filter((name) => Object.hasOwn(entry, name));
          const rest = copier();
          let whole = true;
          for (const name of [...known, ...listed.filter((name) => !known.includes(name))]) {
            const own = known.includes(name);
            if (!own && !whole) {
              read.set(name, null);
              continue;
            }
            try {
              read.set(name, { value: own ? copyOf(entry[name]) : rest(entry[name]) });
            } catch {
              read.set(name, null);
              if (!own) whole = false;
            }
          }
        } catch {
          listed = [];
          read.clear();
        }
      }
      const member = (name) => read.get(name) ?? null;
      // The entry is written out once, as text. The text is what is checked, and what is added.
      let line = null;
      try {
        if (listed !== null && listed.length > 0 && listed.every((name) => member(name) !== null)) line = entryLine(Object.fromEntries(listed.map((name) => [name, member(name).value])));
      } catch {
        line = null; // it cannot be a line of a book
      }
      // A cancellation is also written out by itself, without what stands beside it.
      let alone = null;
      try {
        if (member('cancellation') !== null) alone = entryLine({ cancellation: member('cancellation').value });
      } catch {
        alone = null; // not a record at all
      }
      // And with its time-stamps alone, where more than those stands beside
      // it; and the time-stamps themselves, each as a line would hold it:
      // every one that can be written, from the first sixteen places of the
      // list, so that a gap or a faulty item beside a sound time-stamp does
      // not lose it.
      let stamped = null;
      const offered = [];
      const stamps = alone !== null ? member('stamps') : null;
      if (stamps !== null) {
        try {
          if (listed.length > 2) stamped = entryLine({ cancellation: member('cancellation').value, stamps: stamps.value });
        } catch {
          stamped = null;
        }
        if (Array.isArray(stamps.value)) {
          for (let i = 0; i < Math.min(stamps.value.length, MAX_HANDED); i++) {
            if (!Object.hasOwn(stamps.value, i)) continue;
            try {
              offered.push(JSON.parse(canonicalJson(stamps.value[i])));
            } catch {
              // not a time-stamp
            }
          }
        }
      }
      // The acknowledgements handed over with it, as "cancellations" hands them back.
      let handed = null;
      const acknowledgements = alone !== null ? member('acknowledgements') : null;
      try {
        if (acknowledgements !== null && Array.isArray(acknowledgements.value)) handed = JSON.parse(JSON.stringify(acknowledgements.value));
      } catch {
        handed = null;
      }
      return inTurn(async () => {
        // The person's cancellation of this writer's own slip stops the
        // writer before anything else is done, the reading of the clock
        // included: whatever fails after this, no action is taken. The
        // acknowledgements handed over with it are sorted at once too, so
        // that a clock that fails loses none of them.
        let early = null;
        if (alone !== null) {
          const candidate = JSON.parse(alone);
          const one = (await answerOf(carried, { ...base, cancellations: [candidate] })).result.held[0];
          if (one && one.used && one.slip === slip) {
            stopped = true;
            early = { candidate, one, others: await sortHanded(one.fingerprint, candidate.cancellation, handed) };
          }
        }
        // Where the writer holds a copy of this cancellation beside its book,
        // the copy takes the acknowledgements handed over now and, where the
        // book does not hold the cancellation, its sound time-stamps: before
        // anything is written into the book. A line of a book is not changed.
        // "keep": where the writer holds no copy, and the book does not hold
        // the cancellation, the writer keeps one, with the sound time-stamps.
        // True where the writer holds a copy afterwards.
        const takeHanded = async (keep, inBook = early !== null && early.one.inBook !== null) => {
          if (!early) return false;
          const { candidate, one, others } = early;
          const holds = kept.find((k) => k.fingerprint === one.fingerprint);
          const atOpening = holds ? undefined : given.find((h) => h && h.cancellation && h.cancellation.payload === candidate.cancellation.payload);
          const copy = holds ? holds.entry : atOpening;
          if (!copy && (inBook || !keep || room() <= 0)) return false;
          const stamps = inBook ? null : await mergedStamps(candidate.cancellation, copy && Object.hasOwn(copy, 'stamps') && Array.isArray(copy.stamps) ? copy.stamps : [], offered);
          if (holds) {
            if (stamps) {
              holds.entry = { ...holds.entry, stamps };
              holds.tried = false;
            }
            putHanded(holds.entry, one.fingerprint, others);
          } else if (atOpening) {
            if (stamps) {
              atOpening.stamps = stamps;
              const item = unwritten.find((u) => u.entry === atOpening);
              if (item) item.tried = false;
            }
            putHanded(atOpening, one.fingerprint, others);
          } else {
            const copied = { cancellation: candidate.cancellation };
            if (stamps) copied.stamps = stamps;
            putHanded(copied, one.fingerprint, others);
            kept.push({ entry: copied, when: parseTime(one.content.when), fingerprint: one.fingerprint, tried: false });
          }
          return true;
        };
        // The clock is read once for the whole call.
        let at;
        try {
          at = now();
        } catch (e) {
          // The cancellation is kept, with its sound time-stamps and the
          // acknowledgements handed over with it, so that none is lost with
          // the call.
          const holding = await takeHanded(true);
          // An acknowledgement of the agent's own, taken for a cancellation
          // the book holds, waits to follow it into the book, and is handed
          // back meanwhile, as one that could not be written at once does.
          const fingerprint = early ? early.one.fingerprint : null;
          if (early && early.one.inBook !== null && acknowledged.has(fingerprint) && !written.has(fingerprint)) waiting.set(fingerprint, early.candidate.cancellation);
          if (early && early.one.inBook === null && !holding) {
            const full = refused(
              'The clock failed, so nothing was written into the book. The cancellation is signed with the passkey the slip names, so the stub writer allows nothing more under that slip. It already holds as many cancellations beside its book as it can, so this one is not kept: hand it over again later.',
            );
            full.cause = e;
            throw full;
          }
          throw e;
        }
        await takeHanded(false);
        await writeWaiting(at);
        let why = 'it cannot be written as a line of a book.';
        if (line !== null) {
          const whole = await takeLine(line, at);
          if (whole.fits) {
            // An added stub of this writer's own chain moves its place in the chain on.
            after = lastStub(whole.checked.entries);
            const last = whole.checked.entries.at(-1);
            if (ownDenial(last)) denialTimes.push(at);
            if (last.kind === 'cancellation' && last.slip === slip && last.verified === 'all') {
              stopped = true;
              return { acknowledgement: await acknowledge(last.fingerprint, JSON.parse(line).cancellation, true, at) };
            }
            return {};
          }
          why = whole.why;
        }
        if (alone === null) throw notWritten(`The entry was not added: ${why}`);
        // The cancellation with its time-stamps, then with those of them that
        // pass their check, then by itself, where it was handed over with more.
        const cancellationRecord = JSON.parse(alone).cancellation;
        const sound = await mergedStamps(cancellationRecord, [], offered);
        const withSound = sound ? entryLine({ cancellation: cancellationRecord, stamps: sound }) : null;
        let added = null;
        const tried = new Set([line]);
        for (const form of [stamped, withSound, alone]) {
          if (form === null || tried.has(form) || added !== null) continue;
          tried.add(form);
          if ((await takeLine(form, at)).fits) added = form;
        }
        // Whether the person signed it, for this writer's own slip, and
        // whether the book now holds it: checked without any other cancellation.
        const candidate = JSON.parse(added ?? alone);
        const one = (await answerOf(carried, { ...base, cancellations: [candidate] })).result.held[0];
        const own = Boolean(one && one.used && one.slip === slip);
        const stops = own ? ' It is signed with the passkey the slip names, so the stub writer allows nothing more under that slip.' : '';
        if (own) stopped = true;
        if (added !== null) {
          const acknowledgement = own ? await acknowledge(one.fingerprint, candidate.cancellation, true, at) : undefined;
          const how =
            added === stamped
              ? 'The cancellation was added to the book with its time-stamps, without what else stood beside it.'
              : added === withSound
                ? 'The cancellation was added to the book with those of its time-stamps that pass their check, without what else stood beside it.'
                : 'The cancellation by itself was added to the book, without what stood beside it.';
          throw refused(`The cancellation was not added as it was handed over: ${why} ${how}${stops}`, acknowledgement);
        }
        if (own) {
          const inBook = one.inBook !== null;
          const acknowledgement = await acknowledge(one.fingerprint, candidate.cancellation, inBook, at);
          const holding = await takeHanded(true, inBook);
          if (inBook) {
            const how = early && early.one.inBook === null ? ' It was written into the book in this call, from the copy the stub writer held beside it, with the time-stamps that copy holds.' : '';
            throw refused(`The book already holds this cancellation, so it was not added again.${how}${stops}`, acknowledgement);
          }
          if (!holding) {
            throw refused(`The cancellation was not added: ${why}${stops} The stub writer already holds as many cancellations beside its book as it can, so this one is not kept: hand it over again later.`, acknowledgement);
          }
          throw refused(`The cancellation was not added: ${why}${stops}`, acknowledgement);
        }
        throw notWritten(`The entry was not added: ${why}`);
      });
    },
  };
  // Whether this writer writes denials, as it was opened. It cannot be changed.
  Object.defineProperty(writer, 'denials', { value: denials, enumerable: true });
  return writer;
}
