// Writes the result of a check into the page.
//
// Every value that comes from a record is untrusted. It is written with
// textContent, as text, and never as markup. Control characters, the
// characters that change the direction of text, and long runs of marks
// drawn on top of a letter are replaced by a visible mark, and each value
// is kept inside its own box, so that a record cannot hide, reorder or
// draw over the words around it.

import { DENIAL_SOURCES, REFUSAL_REASONS, conditionWords, limitWords, neverWords } from '../src/check.js';

// The same holds for characters that cannot be seen (zero-width characters,
// soft hyphens, line separators, fillers), with which two different labels
// could be made to look the same. A tab and a line feed are left as they are.
// \p{DI} is every character that Unicode says is to be left out when text
// is drawn (variation selectors among them); U+2800 is the blank Braille
// pattern, which looks like a space and is not one.
const UNSAFE = /(?![\t\n])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{DI}\u2800]/gu;

// A name or a purpose from a record is shown inside quotation marks, and
// any quotation mark inside it as an apostrophe, so that a reader can see
// where the record's words end and the checker's begin.
const QUOTES = /["\p{Pi}\p{Pf}\uff02\u2033\u2036\u02ba\u02dd\u02ee\u301d\u301e\u301f\u275d\u275e\u2e42]/gu;

/**
 * @param {unknown} text a name or a purpose from a record
 * @returns {string} the text in quotation marks
 */
export function label(text) {
  return `"${String(text).replace(QUOTES, "'")}"`;
}

/**
 * Read a box of fingerprints, one to a line. A line that is not a
 * fingerprint is never dropped silently: dropping it would switch off the
 * very check the person asked for.
 * @param {string} text
 * @returns {{values: string[], bad: string[]}}
 */
export function readFingerprints(text) {
  const lines = String(text).split(/\s+/).filter((line) => line !== '');
  return { values: lines.filter((line) => /^[A-Za-z0-9_-]{43}$/.test(line)), bad: lines.filter((line) => !/^[A-Za-z0-9_-]{43}$/.test(line)) };
}

/**
 * Read the box of blocks, one fingerprint of a block to a line: 64 hex
 * characters each. As with the other boxes, a line that is not one is
 * never dropped silently.
 * @param {string} text
 * @returns {{values: string[], bad: string[]}}
 */
export function readBlocks(text) {
  const lines = String(text).split(/\s+/).filter((line) => line !== '');
  return { values: lines.filter((line) => /^[0-9a-fA-F]{64}$/.test(line)), bad: lines.filter((line) => !/^[0-9a-fA-F]{64}$/.test(line)) };
}

/**
 * @param {unknown} text
 * @returns {string} the text, safe to place among other words
 */
export function shown(text) {
  // Every run of spaces becomes one space, so that a label padded with
  // spaces cannot push words onto a line of their own. Marks drawn on top
  // of the character before them (accents, for one) are kept to three in a
  // row, and the rest of such a run is shown as one mark: a long run is
  // drawn over the lines above and below.
  return String(text).replace(UNSAFE, '\ufffd').replace(/(?<=\p{M}{3})\p{M}+/gu, '\ufffd').replace(/\p{Zs}+/gu, ' ');
}

/**
 * @param {string} tag
 * @param {string} [className]
 * @param {string} [text]
 * @returns {HTMLElement}
 */
export function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = shown(text);
  return e;
}

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

/**
 * A time from a record, in words. The checker has already confirmed its
 * form; anything else is shown as it is.
 * @param {string} time such as 2026-10-05T09:00:00Z
 * @returns {string} such as 5 October 2026, 09:00:00 UTC
 */
export function showTime(time) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})Z$/.exec(time);
  if (!m || !MONTHS[Number(m[2]) - 1]) return String(time);
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}, ${m[4]} UTC`;
}

const STATE_WORDS = { valid: 'valid', invalid: 'INVALID', unavailable: 'not checked on this device', unchecked: 'not checked' };

function row(list, name, value, mono) {
  list.append(el('dt', '', name), el('dd', mono ? 'mono' : '', value));
}

function flag(card, kind, text) {
  card.append(el('p', `flag ${kind}`, text));
}

function answer(list, kind, title, detail) {
  const item = el('li', kind);
  item.append(el('strong', '', title), el('span', '', detail));
  list.append(item);
}

function signatureWords(signatures) {
  return signatures.map((s) => `${s.method}: ${STATE_WORDS[s.state]}`).join('; ');
}

// What an entry says is shown only if the entry passed its check and this
// device could confirm at least one of its signatures. Otherwise it is not
// evidence, and its claims are not put on the page.
function hidden(e) {
  if (e.problems.length) return 'What this entry says is not shown, because the entry did not pass its check.';
  if (e.verified === 'none') return 'What this entry says is not shown, because this device could not check its signature.';
  return null;
}

// What stands behind a name: an organisation the reader trusts, an
// organisation the reader did not name, or nothing.
const COVERED = '(covered: not shown to you)';
// A name or a purpose is read only where the record itself holds it.
const has = (object, name) => Object.hasOwn(object, name);
// Who vouches for a service: only what the checker put there for that id.
const vouchedService = (e, id) => (Object.hasOwn(e.vouched.services, id) ? e.vouched.services[id] : null);

function standing(v) {
  if (v && v.counted) return `vouched for by ${label(v.by)}, key set ${v.keys}`;
  if (v) return `a label; it is not checked. ${label(v.by)} vouches for it, which you did not name as trusted`;
  return 'a label; it is not checked';
}

function stampRows(list, stamps) {
  for (const s of stamps) {
    if (s.kind === 'block') {
      const words = `in block ${s.authority} (number ${s.height}, as the proof states). The block states the time ${showTime(s.when)}; that is taken as right to within two hours`;
      if (s.state === 'valid') row(list, 'Block time-stamp', `${words}. You named this block as trusted`);
      else if (s.state === 'untrusted') row(list, 'Block time-stamp, not counted', `${words}. You did not name this block as trusted`);
    } else if (s.state === 'valid') row(list, 'Outside time-stamp', `${showTime(s.when)}, from a service you named as trusted (certificate ${s.authority})`);
    else if (s.state === 'untrusted') row(list, 'Time-stamp, not counted', `${showTime(s.when)}, from a service you did not name as trusted (certificate ${s.authority})`);
    else if (s.state === 'unavailable') row(list, 'Time-stamp, not checked', 'this browser cannot check the service\'s signing method');
  }
}

// The witness statements beside a seal. What a statement says is shown only where it passed its check.
function witnessRows(list, witnesses) {
  for (const w of witnesses ?? []) {
    if (w.state === 'invalid') row(list, 'Witness statement, not used', 'it did not pass its check (see the problems)');
    else if (w.state === 'unavailable') row(list, 'Witness statement, not checked', 'this browser cannot check both of its signatures');
    else if (w.counted) row(list, 'Witnessed', `by ${label(w.name)} (a label), a witness you named as trusted (key set ${w.witness}), at ${showTime(w.when)} (the witness's own word)`);
    else if (w.trusted) row(list, 'Witness statement, not counted', `from a witness you named as trusted (key set ${w.witness}), but it was not counted (see the notes on this card)`);
    else row(list, 'Witness statement, not counted', `from a witness you did not name as trusted (key set ${w.witness})`);
  }
}

function cancellationCard(e) {
  const card = el('div', `card slip${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Cancellation (the person ends a slip)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const list = el('dl');
  row(list, 'Cancels the slip', e.content.slip, true);
  row(list, 'Dated', `${showTime(e.content.when)} (the person's device's own word)`);
  stampRows(list, e.stamps);
  if (e.stampedAt) row(list, 'Counts as cancelled at', `${showTime(e.stampedAt)} (the earliest its time-stamps allow)`);
  row(list, 'Signature', `${e.signature.method}: ${STATE_WORDS[e.signature.state]}`);
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  return card;
}

// An acknowledgement: the agent's side says it was handed a cancellation.
function acknowledgementCard(e) {
  const card = el('div', `card stub${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Acknowledgement (the agent's side says it was handed a cancellation)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'From', c.pass ? `the helper agent of pass ${c.pass}` : 'the slip\'s own agent');
  row(list, 'Of the slip', c.slip, true);
  row(list, 'The cancellation', e.cancellation === undefined ? c.cancellation : `${c.cancellation}, at entry ${e.cancellation}`, true);
  row(list, 'Handed over at', `${showTime(c.when)} (the agent's side's own word)`);
  row(list, 'Agent\'s signatures', signatureWords(e.signatures));
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  card.append(el('p', 'quiet', 'This shows what the agent\'s side said, not when the person cancelled.'));
  return card;
}

// A seal held elsewhere, handed over beside the book.
function heldSealCard(h, n) {
  const card = el('div', `card seal${h.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Handed over beside the book, ${n}: a seal of the book held elsewhere`));
  if (h.problems.length) {
    card.append(el('p', 'quiet', 'It did not pass its check, so it was not used. See the problems above.'));
    return card;
  }
  if (h.verified === 'none') {
    card.append(el('p', 'quiet', 'What this seal says is not shown, because this device could not check its signatures.'));
  } else {
    const c = h.content;
    const list = el('dl');
    row(list, 'Covers', `the first ${c.size} entries`);
    row(list, 'Stands at', `entry ${h.place}`);
    row(list, 'Top fingerprint', c.root, true);
    row(list, 'Sealed at', `${showTime(c.when)} (the recorder's own word)`);
    row(list, 'Recorder', `${label(c.by.name)} (a label; it is not checked)`);
    row(list, 'Recorder\'s key set', h.sealer, true);
    row(list, 'Recorder\'s signatures', signatureWords(h.signatures));
    stampRows(list, h.stamps);
    witnessRows(list, h.witnesses);
    row(list, 'In the book at that place', h.used ? (h.inBook === null ? 'no' : `yes, at entry ${h.inBook}`) : 'not compared, because it was not used');
    row(list, 'Fingerprint', h.fingerprint, true);
    card.append(list);
  }
  for (const note of h.notes) flag(card, 'note', note);
  return card;
}

// A cancellation the person kept, handed over beside the book.
function heldCard(h, n) {
  if (h.kind === 'seal') return heldSealCard(h, n);
  const card = el('div', `card slip${h.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Handed over beside the book, ${n}: the person's own copy of a cancellation`));
  if (h.problems.length) {
    card.append(el('p', 'quiet', 'It did not pass its check, so it was not used. See the problems above.'));
    return card;
  }
  if (h.signature.state === 'valid') {
    const list = el('dl');
    row(list, 'Cancels the slip', h.slip, true);
    row(list, 'Dated', `${showTime(h.content.when)} (the person's device's own word)`);
    stampRows(list, h.stamps);
    if (h.stampedAt) row(list, 'Counts as cancelled at', `${showTime(h.stampedAt)} (the earliest its time-stamps allow)`);
    row(list, 'In the book', h.inBook === null ? 'no' : `yes, at entry ${h.inBook}`);
    for (const a of h.acknowledgements) {
      const who = a.by === 'helper' ? `the helper agent of pass ${a.pass}` : 'the slip\'s own agent';
      if (a.state === 'valid') row(list, 'Acknowledged', `by ${who}, at ${showTime(a.when)} (the agent's side's own word)${a.inBook === null ? '' : `. The book holds the acknowledgement at entry ${a.inBook}`}`);
      else row(list, 'Acknowledgement, not checked', `from ${who}: ${signatureWords(a.signatures)}`);
    }
    row(list, 'Signature', `${h.signature.method}: ${STATE_WORDS[h.signature.state]}`);
    row(list, 'Fingerprint', h.fingerprint, true);
    card.append(list);
  } else {
    card.append(el('p', 'quiet', 'What this copy says is not shown, because this device could not check its signature.'));
  }
  for (const n of h.notes) flag(card, 'note', n);
  return card;
}

function passCard(e) {
  const card = el('div', `card slip${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Pass (a permission handed on to a helper agent)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'Under the slip', c.slip, true);
  row(list, 'Handed on by', c.from ? `the helper agent of pass ${c.from}` : 'the slip\'s own agent');
  row(list, 'To the helper agent', `${label(c.to.name)} (${standing(e.vouched)})`);
  row(list, 'May do', c.actions.join(', '));
  for (const l of c.limits) row(list, 'Limit', limitWords(l));
  row(list, 'From', showTime(c.validFrom));
  row(list, 'Until', showTime(c.validUntil));
  row(list, 'Signatures', signatureWords(e.signatures));
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  return card;
}

function vouchingCard(e) {
  const card = el('div', `card show${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Vouching record (an organisation stands behind a name)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'Organisation', `${label(c.by.name)} (a label; it is not checked)`);
  row(list, 'Its key set', e.signer, true);
  row(list, 'Vouches for', `the ${c.for.kind} named ${label(c.for.name)}, as the holder of the key or keys in this record`);
  row(list, 'In force from', showTime(c.validFrom));
  row(list, 'In force until', showTime(c.validUntil));
  row(list, 'Counted', e.counted ? 'yes: you named this organisation as trusted' : 'no: you did not name this organisation as trusted');
  row(list, 'Organisation\'s signatures', signatureWords(e.signatures));
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  return card;
}

function withdrawalCard(e) {
  const card = el('div', `card show${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Withdrawal (an organisation ends a vouching record)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const list = el('dl');
  row(list, 'Withdraws', `the vouching record ${e.content.vouching}`, true);
  row(list, 'By the key set', e.signer, true);
  row(list, 'Dated', `${showTime(e.content.when)} (the organisation's own word)`);
  row(list, 'Organisation\'s signatures', signatureWords(e.signatures));
  card.append(list);
  return card;
}

function slipCard(e) {
  const card = el('div', `card slip${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Slip (the permission)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'Issuer', has(c.issuer, 'name') ? `${label(c.issuer.name)} (${standing(e.vouched.issuer)})` : COVERED);
  row(list, 'Issuer\'s key', `${e.issuerKey}. Compare this thumbprint with the one the issuer gave you.`, true);
  row(list, 'Signed on', c.issuer.origin);
  row(list, 'Agent', has(c.agent, 'name') ? `${label(c.agent.name)} (${standing(e.vouched.agent)})` : COVERED);
  for (const s of has(c.agent, 'software') ? c.agent.software : []) row(list, 'Agent\'s software, as stated', `${label(s.name)} (fingerprint ${s.sha256}). A statement, not proof of what ran.`);
  row(list, 'May do', c.actions.join(', '));
  for (const l of c.limits) row(list, 'Limit', limitWords(l));
  for (const r of c.requires) row(list, 'Condition', conditionWords(r));
  for (const n of c.never) row(list, 'Stated rule', neverWords(n));
  if (c.with.length === 0) row(list, 'With', 'Nobody is named');
  for (const s of c.with) row(list, 'With', has(s, 'name') ? `${label(s.name)} [${s.id}] (${standing(vouchedService(e, s.id))})` : `${COVERED} [${s.id}]`);
  if (has(c, 'passes')) row(list, 'May be passed on', c.passes === 1 ? 'once, to a helper agent' : `${c.passes} times in a row, to helper agents`);
  row(list, 'From', showTime(c.validFrom));
  row(list, 'Until', showTime(c.validUntil));
  row(list, 'Purpose', has(c, 'purpose') ? label(c.purpose) : COVERED);
  if (e.covered.length) row(list, 'Covered fields', `${e.covered.length}. They are part of what was signed, and are not shown to you.`);
  row(list, 'Signature', `${e.signature.method}: ${STATE_WORDS[e.signature.state]}`);
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  return card;
}

function stubCard(e) {
  const card = el('div', `card stub${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Stub (a receipt)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'Number', c.pass ? `${c.seq} under a pass, by a helper agent` : `${c.seq} under its slip`);
  if (c.pass) row(list, 'Under the pass', c.pass, true);
  row(list, 'When', showTime(c.when));
  row(list, 'Action', c.action);
  if (c.amount) row(list, 'Amount', `${c.amount.value} ${c.amount.unit}`);
  if (c.with) row(list, 'With', `[${c.with}]`);
  for (const d of c.details ?? []) row(list, 'Document', `${label(d.name)} (fingerprint ${d.sha256})`);
  if (c.terms) row(list, 'Relies on', `the service's terms for agents, fingerprint ${c.terms}`, true);
  row(list, 'Agent\'s signatures', signatureWords(e.signatures));
  if (e.countersignature.state !== 'absent') row(list, 'Countersignature', signatureWords(e.countersignature.signatures));
  if (e.approval.state !== 'absent') row(list, 'Approved by the person', `with the passkey the slip names: ${STATE_WORDS[e.approval.state]}. Dated ${showTime(e.approval.when)}, the person's device's own word.`);
  if (e.running) row(list, 'Running total', `${e.running.total} of ${e.running.max} ${e.running.unit}`);
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  if (e.countersignature.state === 'absent') {
    flag(
      card,
      'onesided',
      c.with
        ? 'One-sided: there is no countersignature. This shows what the agent\'s side said, not what the other side did.'
        : 'No other party is named. This shows what the agent\'s side said.',
    );
  }
  return card;
}

function refusalCard(e) {
  const card = el('div', `card refusal${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Refusal (what a service says it refused)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'When', showTime(c.when));
  row(list, 'Refused', c.action + (c.amount ? `, ${c.amount.value} ${c.amount.unit}` : ''));
  row(list, 'Reason given', REFUSAL_REASONS[c.reason]);
  row(list, 'Signed by', e.service ? `the service the slip names as [${e.service}]` : 'a party the slip does not name');
  row(list, 'Calls itself', `${label(c.by.name)} (a label; it is not checked)`);
  row(list, 'Signed with the key set', e.signer, true);
  row(list, 'Service\'s signatures', signatureWords(e.signatures));
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  flag(card, 'onesided', 'This shows what the service\'s side said, not what the agent did.');
  return card;
}

// A denial: the agent's own side says it did not take an action, and why.
function denialCard(e) {
  const card = el('div', `card refusal${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Denial (the agent's side says it did not take an action)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'From', c.pass ? `the helper agent of pass ${c.pass}` : 'the slip\'s own agent');
  row(list, 'When', `${showTime(c.when)} (the agent's side's own word)`);
  row(list, 'Not taken', c.action + (c.amount ? `, ${c.amount.value} ${c.amount.unit}` : '') + (c.with ? `, with [${c.with}]` : ''));
  if (c.details) row(list, 'Documents named', `${c.details.length}, by their fingerprints only`);
  row(list, 'Who said no', DENIAL_SOURCES[c.source]);
  if (c.codes) row(list, 'Reasons given', c.codes.join(', '));
  row(list, 'Agent\'s signatures', signatureWords(e.signatures));
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  flag(card, 'onesided', 'This shows what the agent\'s side said. It is not counted against the agent, and it does not show that the action was not taken in some other way.');
  return card;
}

function sealCard(e) {
  const card = el('div', `card seal${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: Seal (the book, signed by whoever keeps it)`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'Covers', `the first ${c.size} entries`);
  row(list, 'Top fingerprint', c.root, true);
  row(list, 'Sealed at', `${showTime(c.when)} (the recorder's own word)`);
  row(list, 'Recorder', `${label(c.by.name)} (${standing(e.vouched)})`);
  row(list, 'Recorder\'s key set', `${e.sealer}. Compare this fingerprint with the one the recorder gave you.`, true);
  row(list, 'Recorder\'s signatures', signatureWords(e.signatures));
  stampRows(list, e.stamps);
  witnessRows(list, e.witnesses);
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  if (e.stamps.length === 0) flag(card, 'onesided', 'There is no outside time-stamp: the time is only the recorder\'s own word.');
  return card;
}

function termsCard(e) {
  const card = el('div', `card terms${e.problems.length ? ' broken' : ''}`);
  card.append(el('h3', 'kind', `Entry ${e.index}: A service's terms for agents`));
  if (hidden(e)) {
    card.append(el('p', 'quiet', hidden(e)));
    return card;
  }
  const c = e.content;
  const list = el('dl');
  row(list, 'From', `${label(c.by.name)} (a label; it is not checked)`);
  row(list, 'Signed with the key set', `${e.signer}. These terms count for a stub only if its slip gives these keys for the service.`, true);
  row(list, 'Accepts from agents', c.accepts.join(', '));
  for (const n of c.never) row(list, 'Asks of agents', neverWords(n));
  row(list, 'In force from', showTime(c.validFrom));
  row(list, 'In force until', showTime(c.validUntil));
  row(list, 'Service\'s signatures', signatureWords(e.signatures));
  row(list, 'Fingerprint', e.fingerprint, true);
  card.append(list);
  return card;
}

/**
 * @param {HTMLElement} target where to write
 * @param {object} result what checkBook or checkShow returned
 * @param {object} [o]
 * @param {boolean} [o.isShow]
 * @param {string} [o.checkedBy] a sentence saying which program made the check
 * @param {object} [o.options] what the check was told to trust: the green answer needs the passkey the
 *   person trusts and, where the record has a seal, the recorder they expect
 */
// A copy of a cancellation, a seal, or a file of disclosures, is small.
const MAX_HANDED_BYTES = 1000000;
const MAX_COPIES = 16;
const MAX_SEALS = 64;

async function jsonFrom(file, what) {
  if (file.size > MAX_HANDED_BYTES) throw new Error(`The file of ${what}, ${shown(file.name)}, is too large. Nothing was checked.`);
  try {
    return JSON.parse(await file.text());
  } catch {
    throw new Error(`The file of ${what}, ${shown(file.name)}, is not JSON. Nothing was checked. Choose another file, or clear these files.`);
  }
}

/**
 * What the person was handed with the record: their own copies of
 * cancellations (up to 16), seals held elsewhere (up to 64), and one file of
 * disclosures for covered fields. A file that cannot be read stops the
 * check: it is never set aside silently.
 * @param {{cancellations?: File[], seals?: File[], disclosures?: File|null}} files the files chosen, as the
 *   browser gives them (anything with "name", "size" and "text()")
 * @returns {Promise<{options: object, said: string[]}>} the options to check with, and what to say was handed over
 */
export async function readHanded({ cancellations = [], seals = [], disclosures = null } = {}) {
  const options = {};
  const said = [];
  if (cancellations.length > MAX_COPIES) throw new Error('At most 16 copies of cancellations can be handed over at once. Nothing was checked.');
  if (cancellations.length) {
    options.cancellations = [];
    for (const file of cancellations) options.cancellations.push(await jsonFrom(file, 'a cancellation'));
    said.push(cancellations.length === 1 ? 'one copy of a cancellation' : `${cancellations.length} copies of cancellations`);
  }
  if (seals.length > MAX_SEALS) throw new Error('At most 64 seals held elsewhere can be handed over at once. Nothing was checked.');
  if (seals.length) {
    options.seals = [];
    for (const file of seals) options.seals.push(await jsonFrom(file, 'a seal'));
    said.push(seals.length === 1 ? 'one seal held elsewhere' : `${seals.length} seals held elsewhere`);
  }
  if (disclosures) {
    options.disclosures = await jsonFrom(disclosures, 'disclosures');
    said.push('disclosures for covered fields');
  }
  return { options, said };
}

/**
 * What the check rests on: whether the person named the passkey they trust
 * and, where the record has a seal or seals held elsewhere were handed
 * over, the recorder they expect; and whether those seals went unused
 * because no recorder was named. Without the keys the person named, a
 * record agrees only with the keys inside it, and anyone could have made
 * those.
 * @param {object} result what checkBook or checkShow returned
 * @param {object} [options] what the check was told
 */
export function trustOf(result, options = {}) {
  const s = result.summary;
  const issuerNamed = Array.isArray(options.issuerKeys) && options.issuerKeys.length > 0;
  const sealerNamed = Array.isArray(options.sealKeys) && options.sealKeys.length > 0;
  const sealsHanded = Array.isArray(options.seals) && options.seals.length > 0;
  const named = issuerNamed && ((s.counts.seals === 0 && !sealsHanded) || sealerNamed);
  // A seal handed over that was not compared with the book (it gives another book number, or could not be used) gives no pass.
  // (Where no recorder was named, the seals handed over were not compared at all, and heldUnused says so.)
  const heldCompared = !sealsHanded || !sealerNamed || (result.held ?? []).filter((h) => h.kind === 'seal').every((h) => h.used);
  return { issuerNamed, named, sure: s.intact && named && heldCompared, heldUnused: sealsHanded && !sealerNamed };
}

export function renderResult(target, result, { isShow = false, checkedBy = 'Checked in this browser.', options = {} } = {}) {
  target.replaceChildren();
  const s = result.summary;
  const missing = s.methodsMissing.join(' or ');
  const { issuerNamed, named, sure, heldUnused } = trustOf(result, options);
  const heldCompared = heldUnused || (result.held ?? []).filter((h) => h.kind === 'seal').every((h) => h.used);

  target.append(el('h2', '', 'The answer'));
  const answers = el('ul', 'answers');
  if (s.problemFound) {
    answer(answers, 'no', 'The record is NOT intact.', 'See the problems marked below. A record that is not intact is not evidence.');
  } else if (sure) {
    answer(answers, 'yes', 'The record is intact.', `Every signature fits its key, every label is right and nothing has been changed. ${checkedBy}`);
  } else if (s.intact && named && !heldCompared) {
    answer(
      answers,
      'partly',
      'Not every seal you handed over was compared with this book.',
      'A seal held elsewhere that you handed over gives another book number than this book, or could not be used, so it was not compared with the book. See the note beside it. This is not a pass.',
    );
  } else if (s.intact) {
    answer(
      answers,
      'partly',
      'Intact only as far as its own keys show.',
      !issuerNamed
        ? 'You named no passkey you trust, so anyone could have made a record like this. Put the thumbprint of the passkey you trust in its box. This is not a pass.'
        : s.counts.seals === 0
          ? 'You were handed seals held elsewhere, and you named no recorder you expect, so those seals were not compared with the book. Put the fingerprint of the recorder you expect in its box. This is not a pass.'
          : 'The record has a seal, and you named no recorder you expect, so anyone could have sealed it. Put the fingerprint of the recorder you expect in its box. This is not a pass.',
    );
  } else {
    answer(
      answers,
      'partly',
      'No problem was found, but the check is not complete.',
      `This browser has no built-in ${missing}. Signatures made that way were not checked, so this is not a pass. To check everything, use the command-line checker with Node.js.`,
    );
  }
  if (!s.problemFound) {
    const rests = !s.intact ? ' This rests only on the signatures that could be checked here.' : !named ? ' This rests on keys you did not name.' : '';
    if (s.firstBreach !== null) {
      answer(answers, 'no', 'The record shows the agent outside its slip.', `First at entry ${s.firstBreach}. See the entries marked below.${rests}`);
    } else if (!s.withinSlips) {
      answer(answers, 'partly', 'Whether the agent stayed within its slip could not be checked here.', 'An entry that this browser cannot confirm cannot be compared with its slip.');
    } else if (isShow) {
      answer(answers, sure ? 'yes' : 'partly', 'These pages show nothing outside the slip.', `Single pages cannot show whether a limit was kept. That needs every stub under the slip.${rests}`);
    } else {
      answer(answers, sure ? 'yes' : 'partly', 'The agent stayed within its slip.', `As far as this record shows.${rests}`);
    }
  }
  target.append(answers);

  for (const p of result.problems) {
    const card = el('div', 'card broken');
    flag(card, 'problem', `Problem: ${p.message} (${p.code})`);
    target.append(card);
  }
  for (const n of result.notes ?? []) {
    const card = el('div', 'card show');
    flag(card, 'note', n);
    target.append(card);
  }

  const held = result.held ?? [];
  if (held.length) target.append(el('h2', '', 'Handed over beside the book'));
  if (heldUnused) {
    const card = el('div', 'card show');
    flag(card, 'note', 'The seals held elsewhere that you handed over were not compared with the book, because you named no recorder you expect. Put the fingerprint of the recorder you expect in its box.');
    target.append(card);
  }
  held.forEach((h, i) => target.append(heldCard(h, i + 1)));

  if (result.root) {
    const seal = el('div', 'card seal');
    seal.append(el('h3', 'kind', 'The top fingerprint (the Seal)'));
    const list = el('dl');
    row(list, 'Top fingerprint', result.root, true);
    row(list, 'Entries in the book', String(result.size));
    seal.append(list);
    seal.append(
      el(
        'p',
        'quiet',
        s.sealed
          ? s.sealed.by === 'block'
            ? `It stands for the whole book. A block of a public blockchain that you named covers the first ${s.sealed.entries} entries: they existed by ${showTime(s.sealed.when)}.`
            : `It stands for the whole book. An outside time-stamp from a service you trust covers the first ${s.sealed.entries} entries: they existed by ${showTime(s.sealed.when)}.`
          : 'It stands for the whole book. No outside time-stamp from a service you trust covers it: compare it, and the number of entries, with a copy you already trust.',
      ),
    );
    if (s.witnessed) {
      seal.append(el('p', 'quiet', `A witness you named as trusted signed for the seal at entry ${s.witnessed.seal}, which covers the first ${s.witnessed.entries} entries (${s.witnessed.seals.length} of ${s.counts.seals} seals witnessed). Being witnessed excuses nothing.${isShow ? ' These are single pages: they cannot show that a limit over the whole book was kept, so being witnessed says nothing here about totals.' : ''}`));
    }
    target.append(seal);
  }

  if (result.entries.length) target.append(el('h2', '', isShow ? 'The pages shown' : 'The entries'));
  for (const e of result.entries) {
    let card;
    if (e.kind === 'slip') card = slipCard(e);
    else if (e.kind === 'stub') card = stubCard(e);
    else if (e.kind === 'refusal') card = refusalCard(e);
    else if (e.kind === 'terms') card = termsCard(e);
    else if (e.kind === 'seal') card = sealCard(e);
    else if (e.kind === 'cancellation') card = cancellationCard(e);
    else if (e.kind === 'acknowledgement') card = acknowledgementCard(e);
    else if (e.kind === 'denial') card = denialCard(e);
    else if (e.kind === 'pass') card = passCard(e);
    else if (e.kind === 'vouching') card = vouchingCard(e);
    else if (e.kind === 'withdrawal') card = withdrawalCard(e);
    else {
      card = el('div', 'card unreadable');
      card.append(el('h3', 'kind', `Entry ${e.index}: could not be read`));
    }
    for (const p of e.problems) flag(card, 'problem', `Problem: ${p.message} (${p.code})`);
    for (const b of e.breaches) flag(card, 'breach', `Outside the slip: ${b.message} (${b.code})`);
    for (const n of e.notes ?? []) flag(card, 'note', n);
    target.append(card);
  }

  target.append(el('h2', '', 'What this check does not show'));
  const limits = el('ul');
  for (const l of s.limits) limits.append(el('li', '', l));
  target.append(limits);
}
