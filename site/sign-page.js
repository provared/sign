// The signing page: a person writes a permission, this device's passkey
// signs it, and the signed record goes back to the page that asked for it
// (the Provared application, which opens this page in a small window), or
// is kept as a file. Everything happens in this browser. The page loads only
// its own files and sends nothing anywhere; the passkey is kept by the
// device, and this page remembers only its public key and identifier (in
// this browser's storage) so that the same passkey can sign again later.
//
// Two ways the page is opened:
//   - "#permission=…": a starting permission to edit and sign, as the
//     recorder beside an agent prints it; the signed permission is saved as
//     a file.
//   - "#request=…": a request from another page (the application) for a
//     new permission, a renewal or a cancellation, with the fields to fill,
//     the earlier signed permission where there is one, the public key of
//     the passkey expected to sign, and the address to hand the result back
//     to. The result goes back to that page by postMessage, to its exact
//     address, and the window closes once that page answers that it kept
//     it; where this page was not opened as a window, by a link back to
//     that address with the result after "#"; last, as a file.
//
// What signs is exactly what was read and shown: the permission and the
// name as they stood when "Read the permission" was pressed. Any change
// after that (in the box, in the name, or a new link opened in the same
// tab) takes the page back to its first step, even while the passkey is
// being asked.
//
// The earlier permission a request carries is trusted only once its
// passkey signature has been checked here with the library's checker; the
// expected passkey is found from its public key, by asking the device to
// offer the passkeys it holds and checking the answer, never by making a
// new one silently. Before a new passkey is made, and before an agent's
// key set is signed for the first time on this device, the page warns and
// asks again; a passkey is made only where the warning that one will be
// made was among those the person confirmed, and a passkey prompt that
// fails, or a passkey forgotten, takes the confirmation back. A
// cancellation never makes a passkey: it is signed by the passkey that
// signed the permission, or not at all.
//
// The parts that need no page are plain functions, so that they can be
// tested on their own: readStartingPermission, readRequest, returnAddress,
// whatChanged, agentKeySet, serviceWords, shownByItself, signedMessage,
// receivedReply, replyFrom. The rest runs only in a browser. A page shown
// inside another page offers nothing to sign or cancel.

import { checkBook, checkSlip, conditionWords, keySetFingerprint, limitWords, neverWords } from '../src/check.js';
import { cancelWithPasskey, createPasskey, signChallengeWithChosenPasskey, signChallengeWithPasskey } from '../src/passkey-browser.js';
import { fromBase64url, toBase64url, utf8 } from '../src/encoding.js';
import { checkKeySet, thumbprint } from '../src/keys.js';
import { assembleCancellation, prepareCancellation } from '../src/standing.js';
import { assembleSlip, prepareSlip } from '../src/slip.js';
import { entryLine } from '../src/book.js';
import { el, shown } from './render.js';

const STORE = 'provared-signing-passkey';
const STORE_LIST = 'provared-signing-passkeys';
const STORE_AGENTS = 'provared-signed-agents';
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
/**
 * The exact addresses of the Provared application, where a signed record is
 * expected to go back to: each a website name with its port where it has
 * one, always over https. Any other address, the same name on another port
 * included, is warned of. (Written without "https://", as this page names
 * no address it could load from.)
 */
export const KNOWN_RETURN_ADDRESSES = ['app.prova.red:8443', 'app.prova.red'];
/** The kinds of request another page may make. */
export const REQUEST_KINDS = ['permission', 'renewal', 'cancellation'];
const SLIP_MEMBERS = ['agent', 'actions', 'limits', 'requires', 'never', 'with', 'validFrom', 'validUntil', 'purpose'];
const MAX_STATE = 256;

// A starting point: a coding agent on this computer, under limits.
const soon = (days) => new Date(Date.now() + days * 86400 * 1000).toISOString().slice(0, 19) + 'Z';
export const EXAMPLE = {
  agent: {
    name: 'The agent, as you call it',
    keys: ['paste the agent\'s two public keys here, as its software printed them'],
  },
  actions: ['provared.code.read', 'provared.code.change', 'provared.code.run', 'provared.web.read', 'provared.agent.instruct'],
  limits: [
    { action: 'provared.code.run', count: 500, per: 3600 },
    { action: 'provared.code.change', count: 500, per: 3600 },
  ],
  requires: [],
  never: ['destroys', 'conceal', 'deceive', 'bypass', 'escalate', 'continue-after-stop'],
  with: [],
  validFrom: new Date(Date.now() - 60 * 1000).toISOString().slice(0, 19) + 'Z',
  validUntil: soon(7),
  purpose: 'What the agent is for, in a sentence.',
};

// The JSON object written in base64url after a name in the fragment, or
// why it could not be read.
function readFragmentObject(hash, name) {
  const given = new URLSearchParams(String(hash).replace(/^#/, '')).get(name);
  if (given === null) return { value: null, why: null, absent: true };
  let bytes;
  try {
    bytes = fromBase64url(given);
  } catch {
    return { value: null, why: 'it is not written in base64url' };
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { value: null, why: 'it is not text' };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { value: null, why: `it is not JSON: ${e.message}` };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { value: null, why: 'it is not one JSON object' };
  return { value: parsed, why: null };
}

/**
 * A starting permission from the page's address: after "#permission=", as
 * base64url of its JSON (the recorder beside a coding agent prints such a
 * link, with the agent's public keys in it). The part of an address after
 * "#" (its fragment) stays in the browser: it is never sent to any server,
 * this website's own included. Its members are laid over the starting
 * point, so that what it leaves out (the times) is set when the page
 * opens. A fragment that cannot be read leaves the starting point as it
 * is, and the message says why.
 * @param {string} hash the address's fragment, with or without its "#"
 * @param {object} [example] the starting point
 * @returns {{permission: object, message: string|null}}
 */
export function readStartingPermission(hash, example = EXAMPLE) {
  const { value, why, absent } = readFragmentObject(hash, 'permission');
  if (absent) return { permission: example, message: null };
  if (why) return { permission: example, message: `The permission in this page's address could not be read: ${why}. The page's own starting point is shown instead.` };
  return { permission: { ...example, ...value }, message: 'The permission below came with the link you opened. Read it, change it if you wish, write your name, and press "Read the permission".' };
}

/**
 * The address a signed record is to go back to, read strictly: https://
 * (or http://localhost, for a page tried on this computer), a website
 * name, a port where one is needed, and a path; no sign-in details, no
 * query and nothing after "#". The result says whether the address is one
 * of the application's known addresses, exactly (KNOWN_RETURN_ADDRESSES,
 * over https), so that the page can warn where it is not; http://localhost
 * is taken, and always warned of.
 * @param {any} text
 * @returns {{origin: string, address: string, host: string, known: boolean}|null} null where the text is not such an address
 */
export function returnAddress(text) {
  if (typeof text !== 'string' || text.length > 2048) return null;
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  const local = url.protocol === 'http:' && url.hostname === 'localhost';
  if (!(url.protocol === 'https:' || local)) return null;
  if (url.username || url.password || url.search || url.hash || text.endsWith('#') || text.endsWith('?')) return null;
  if (!/^[a-z0-9.-]+$/.test(url.hostname)) return null;
  return { origin: url.origin, address: url.origin + url.pathname, host: url.hostname, known: url.protocol === 'https:' && KNOWN_RETURN_ADDRESSES.includes(url.host) };
}

/**
 * A request from another page, after "#request=" in the address, as
 * base64url of its JSON: what kind of record is wanted (a permission, a
 * renewal or a cancellation), the fields to fill for a permission or a
 * renewal, the earlier signed permission for a renewal or a cancellation,
 * the public key of the passkey expected to sign (where the request does
 * not carry an earlier permission that names it), where to hand the result
 * back to, and a short text the asking page gets back unchanged, so that
 * it can match the answer to its question. Only the shape is checked here;
 * the earlier permission's signature, and the keys, are checked when the
 * page reads them.
 * @param {string} hash the address's fragment, with or without its "#"
 * @returns {{request: object|null, message: string|null}} the request, or why it was refused
 */
export function readRequest(hash) {
  const { value, why, absent } = readFragmentObject(hash, 'request');
  if (absent) return { request: null, message: null };
  const refused = (reason) => ({ request: null, message: `The request in this page's address could not be used: ${reason}. Nothing is offered to sign. Close this window and try again from the page that opened it.` });
  if (why) return refused(why);
  const known = ['kind', 'fields', 'name', 'earlier', 'issuerKey', 'returnTo', 'state'];
  for (const member of Object.keys(value)) if (!known.includes(member)) return refused(`it holds a member this page does not know, "${member}"`);
  if (!REQUEST_KINDS.includes(value.kind)) return refused('its "kind" must be "permission", "renewal" or "cancellation"');
  const request = { kind: value.kind };
  const isObject = (x) => x && typeof x === 'object' && !Array.isArray(x);
  if (value.kind === 'cancellation') {
    if (Object.hasOwn(value, 'fields')) return refused('a cancellation takes no "fields"');
  } else {
    if (!isObject(value.fields)) return refused('its "fields" must be one JSON object, the permission\'s members except the issuer');
    if (Object.hasOwn(value.fields, 'issuer')) return refused('its "fields" must not hold an "issuer": your passkey and name are the issuer');
    for (const member of SLIP_MEMBERS) {
      if (!Object.hasOwn(value.fields, member)) return refused(`its "fields" has no "${member}" member; every member is needed, and an empty list is written as []`);
    }
    request.fields = value.fields;
  }
  if (Object.hasOwn(value, 'name')) {
    if (typeof value.name !== 'string') return refused('its "name" must be text');
    request.name = value.name;
  }
  if (value.kind === 'permission') {
    if (Object.hasOwn(value, 'earlier')) return refused('a new permission takes no "earlier" permission; ask for a renewal instead');
  } else {
    if (!isObject(value.earlier)) return refused(`a ${value.kind} needs the earlier signed permission, as "earlier"`);
    request.earlier = value.earlier;
  }
  if (Object.hasOwn(value, 'issuerKey')) {
    if (!isObject(value.issuerKey)) return refused('its "issuerKey" must be the passkey\'s public key, as a JSON Web Key');
    request.issuerKey = value.issuerKey;
  }
  if (Object.hasOwn(value, 'returnTo')) {
    const to = returnAddress(value.returnTo);
    if (!to) return refused('its "returnTo" must be a page address that begins https:// (or http://localhost), with no query and nothing after "#"');
    request.returnTo = to;
  }
  if (Object.hasOwn(value, 'state')) {
    if (typeof value.state !== 'string' || value.state.length > MAX_STATE) return refused(`its "state" must be text of at most ${MAX_STATE} characters`);
    request.state = value.state;
  }
  return { request, message: null };
}

/**
 * The message handed back to the page that asked, and written after
 * "#signed=" where the page goes back by a link: what was signed, the
 * signed record, and the request's "state" unchanged.
 * @param {'permission'|'renewal'|'cancellation'} kind
 * @param {object} record the signed record
 * @param {string} [state]
 */
export function signedMessage(kind, record, state) {
  const message = { provared: 'signed', kind, record };
  if (typeof state === 'string') message.state = state;
  return message;
}

/** How long the window waits for the page that opened it to say it kept the record, in milliseconds. */
export const RECEIPT_WAIT = 10000;

/**
 * The answer of the page that opened the window, once it has the signed
 * record: { provared: 'received', kind, state?, kept }, where "kept" says
 * whether its checker passed the record and it kept it. Gives 'kept' or
 * 'not-kept' for an answer to this record's request, and null for anything
 * else (which the window sets aside). The caller has already confirmed
 * that the message came from the window that opened this one, at the
 * return address.
 * @param {any} data the message's data
 * @param {string} kind what was signed
 * @param {string} [state] the request's "state"
 * @returns {'kept'|'not-kept'|null}
 */
export function receivedReply(data, kind, state) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.provared !== 'received') return null;
  if (data.kind !== kind) return null;
  if ((typeof state === 'string' ? state : undefined) !== (typeof data.state === 'string' ? data.state : undefined)) return null;
  if (typeof data.kept !== 'boolean') return null;
  return data.kept ? 'kept' : 'not-kept';
}

/**
 * The answer to this window, read from a message event: taken only where it
 * comes from the window that opened this one and from the return address
 * exactly, and only where it answers this record's request (receivedReply).
 * @param {{source: any, origin: string, data: any}} event
 * @param {{opener: any, origin: string, kind: string, state?: string}} expected
 * @returns {'kept'|'not-kept'|null}
 */
export function replyFrom(event, expected) {
  if (!event || !expected.opener || event.source !== expected.opener) return null;
  if (event.origin !== expected.origin) return null;
  return receivedReply(event.data, expected.kind, expected.state);
}

/** The link that carries a signed message back: the return address with the message after "#signed=". */
export function signedLink(address, message) {
  return `${address}#signed=${toBase64url(utf8(JSON.stringify(message)))}`;
}

/**
 * What the page shows for the agent's keys before the passkey is asked:
 * the fingerprint of the agent's key set, worked out by the library's own
 * function (keySetFingerprint), which is how the format names a key set.
 * The agent's software is to print the same fingerprint, worked out the
 * same way, when it makes its keys. A link, or a permission pasted from
 * elsewhere, could carry someone else's keys under a familiar name: the
 * person compares the two before signing.
 * @param {any} keys the permission's agent.keys
 * @returns {Promise<{fingerprint: string, words: string}>}
 * @throws {Refusal} if they are not a key set (format description, section 3.9)
 */
export async function agentKeySet(keys) {
  checkKeySet(keys, 'agent.keys');
  const fp = await keySetFingerprint(keys);
  return {
    fingerprint: fp,
    words: `${fp}. Compare this fingerprint with the one the agent's software printed when it made its keys. If they differ, these are not your agent's keys: do not sign.`,
  };
}

/**
 * Whether the page is shown by itself, not inside another page (a frame).
 * Another site could show this page in a frame of its own, filled from a
 * link it chose, and lead the person to sign there. The page's own policy
 * cannot forbid framing (only a header can, and the site that serves the
 * page sets none of its own), so a framed page offers nothing to sign or
 * cancel. A page opened as a window by another page is by itself: it is
 * the top of its own window.
 * @param {any} win the window
 */
export function shownByItself(win) {
  try {
    return win.top === win;
  } catch {
    return false;
  }
}

/**
 * The words for the services a permission names, before the passkey is
 * asked: each by its name and id, and, where it may countersign, its keys
 * by the fingerprint of their key set (keySetFingerprint), as a checker
 * names them. A link could name a service with keys of its maker's choosing.
 * @param {any[]} services the permission's "with"
 * @returns {Promise<string>}
 * @throws {Refusal} if a service's keys are not a key set
 */
export async function serviceWords(services) {
  if (!services.length) return 'no other party';
  const words = [];
  for (const [i, s] of services.entries()) {
    let keys = 'no keys of its own, so it cannot countersign';
    if (s && Object.hasOwn(s, 'keys')) {
      checkKeySet(s.keys, `with[${i}].keys`);
      keys = `countersigning with the key set ${await keySetFingerprint(s.keys)}`;
    }
    words.push(`${shown(String(s?.name))} (${shown(String(s?.id))}), ${keys}`);
  }
  return words.join('; ');
}

// Each part of a permission in words, for the comparison; anything that
// cannot be put into words is shown as it is written.
const words = (fn) => (x) => {
  try {
    return fn(x);
  } catch {
    return JSON.stringify(x);
  }
};
const PARTS = [
  ['Agent', (f) => shown(String(f.agent?.name))],
  ['Agent\'s key set', async (f) => (Array.isArray(f.agent?.keys) && f.agent.keys.length === 2 && f.agent.keys.every((k) => k && typeof k === 'object') ? keySetFingerprint(f.agent.keys) : JSON.stringify(f.agent?.keys))],
  ['Agent\'s software', (f) => (Array.isArray(f.agent?.software) ? f.agent.software.map((s) => `${shown(String(s?.name))} ${shown(String(s?.sha256))}`).join('; ') : 'not stated')],
  ['May do', (f) => (Array.isArray(f.actions) ? f.actions.map((a) => shown(String(a))).join(', ') : JSON.stringify(f.actions))],
  ['Limits', (f) => (Array.isArray(f.limits) ? (f.limits.length ? f.limits.map(words(limitWords)).join('; ') : 'none') : JSON.stringify(f.limits))],
  ['Conditions', (f) => (Array.isArray(f.requires) ? (f.requires.length ? f.requires.map(words(conditionWords)).join('; ') : 'none') : JSON.stringify(f.requires))],
  ['Never', (f) => (Array.isArray(f.never) ? (f.never.length ? f.never.map(words(neverWords)).join(' ') : 'nothing stated') : JSON.stringify(f.never))],
  ['With', (f) => (Array.isArray(f.with) ? serviceWords(f.with).catch(() => JSON.stringify(f.with)) : JSON.stringify(f.with))],
  ['From', (f) => String(f.validFrom)],
  ['Until', (f) => String(f.validUntil)],
  ['Purpose', (f) => shown(String(f.purpose))],
  ['May pass on', (f) => (f.passes ? `${f.passes} time(s) in a row` : 'not at all')],
];

/**
 * What a new permission changes against an earlier one, part by part, in
 * the words the page shows: the name of the agent, its key set (by
 * fingerprint), its software, what it may do, the limits, the conditions,
 * the stated rules, the services, the times, the purpose and passing on.
 * The caller trusts the earlier permission only after checking its
 * passkey signature.
 * @param {object} earlier the earlier permission's content
 * @param {object} fields the new permission's members
 * @returns {Promise<{term: string, was: string, now: string, changed: boolean}[]>}
 */
export async function whatChanged(earlier, fields) {
  const out = [];
  for (const [term, fn] of PARTS) {
    const was = String(await fn(earlier));
    const now = String(await fn(fields));
    out.push({ term, was, now, changed: was !== now });
  }
  return out;
}

function page() {
  const $ = (id) => document.getElementById(id);
  const say = (id, text) => {
    $(id).textContent = text;
  };
  const byItself = shownByItself(window);
  const FRAMED = 'This page is shown inside another page, so it offers nothing to sign or cancel. Open sign.prova.red in a tab or a window of its own.';

  // What was read, and is what signs: the permission and the name.
  let fields = null;
  let readName = null;
  let slip = null;
  let cancellation = null;
  // The request another page made, where there is one, with what was
  // settled when the page read it: the earlier permission's content once
  // its signature checked, and the passkey expected to sign.
  let request = null;
  let earlier = null;
  let expected = null;
  // Said beside the request's own words where the earlier passkey belongs to another website.
  let elsewhereNote = '';
  // The warnings shown before signing are confirmed by pressing the button
  // a second time: the texts the person was shown. A press signs only where
  // every warning that stands then was among them; a failed passkey prompt,
  // or a passkey forgotten, empties it, so the warnings are worked out and
  // shown again.
  let confirmed = new Set();
  let cancelConfirmed = new Set();
  // Counts every going back to the first step, so that a signature that
  // arrives after one is not kept.
  let generation = 0;

  // --- what this browser remembers: passkeys, and agents signed for ---

  function readList(name) {
    try {
      const list = JSON.parse(localStorage.getItem(name));
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }
  function writeList(name, list) {
    try {
      localStorage.setItem(name, JSON.stringify(list.slice(-16)));
    } catch {
      // Storage refused: asked again next time.
    }
  }
  const soundPasskey = (p) => p && typeof p.credentialId === 'string' && p.key && typeof p.key === 'object' && p.rpId === location.hostname && p.origin === location.origin;
  // Every passkey this browser remembers for this website, the one kept
  // under the older single name included.
  function rememberedPasskeys() {
    const list = readList(STORE_LIST).filter(soundPasskey);
    try {
      const old = JSON.parse(localStorage.getItem(STORE));
      if (soundPasskey(old) && !list.some((p) => p.credentialId === old.credentialId)) list.push(old);
    } catch {
      // Nothing under the older name.
    }
    return list;
  }
  function rememberPasskey(passkey) {
    writeList(STORE_LIST, [...rememberedPasskeys().filter((p) => p.credentialId !== passkey.credentialId), passkey]);
  }
  function forgetPasskey(passkey) {
    writeList(STORE_LIST, rememberedPasskeys().filter((p) => p.credentialId !== passkey.credentialId));
    try {
      const old = JSON.parse(localStorage.getItem(STORE));
      if (old && old.credentialId === passkey.credentialId) localStorage.removeItem(STORE);
    } catch {
      // Nothing under the older name.
    }
  }
  async function rememberedFor(thumb) {
    for (const p of rememberedPasskeys()) if ((await thumbprint(p.key).catch(() => null)) === thumb) return p;
    return null;
  }
  const agentKnown = (fp) => readList(STORE_AGENTS).includes(fp);
  const rememberAgent = (fp) => {
    if (!agentKnown(fp)) writeList(STORE_AGENTS, [...readList(STORE_AGENTS), fp]);
  };

  // --- the words shown ---

  // The permission in words, so that the person sees what they sign: who
  // signs it, and the agent's keys by the fingerprint of their key set, too.
  function showWords(dl, f, name, agentKeys, passkey, services) {
    dl.replaceChildren();
    const row = (term, text) => dl.append(el('dt', '', term), el('dd', '', text));
    if (name !== null) row('Signed by', `"${shown(name)}" (a label), with ${passkey}`);
    row('Agent', shown(String(f.agent.name)));
    row('Agent\'s key set', agentKeys);
    if (Array.isArray(f.agent.software)) {
      row('Agent\'s software (your statement of what you approve, not proof of what runs)', f.agent.software.map((s) => `${shown(String(s?.name))} ${shown(String(s?.sha256))}`).join('; '));
    }
    row('May do', f.actions.map(shown).join(', '));
    row('Limits', f.limits.length ? f.limits.map(limitWords).join('; ') : 'none');
    row('Conditions', f.requires.length ? f.requires.map(conditionWords).join('; ') : 'none');
    row('Never', f.never.length ? f.never.map(neverWords).join(' ') : 'nothing stated');
    row('With', services);
    row('From', f.validFrom);
    row('Until', f.validUntil);
    row('Purpose', shown(String(f.purpose)));
    if (f.passes) row('May pass on', `${f.passes} time(s) in a row`);
    dl.hidden = false;
  }

  // What changed against the earlier permission, part by part.
  async function showChanged(f) {
    const dl = $('changed');
    dl.replaceChildren();
    const parts = await whatChanged(earlier.content, f);
    const changed = parts.filter((p) => p.changed);
    say('changed-heading', changed.length ? `What changes against the permission being renewed (${changed.length} of ${parts.length} parts)` : 'Nothing changes against the permission being renewed: every part below is the same');
    for (const p of parts) {
      dl.append(el('dt', p.changed ? 'changed' : '', `${p.term}: ${p.changed ? 'changed' : 'the same'}`));
      dl.append(el('dd', '', p.changed ? `Was: ${p.was}` : p.now));
      if (p.changed) dl.append(el('dd', '', `Now: ${p.now}`));
    }
    $('changed-box').hidden = false;
  }

  // Where the signed record goes back to, shown before the passkey is asked.
  function showReturn(lineId, addressId, warningId) {
    const to = request && request.returnTo;
    $(lineId).hidden = !to;
    if (!to) return;
    $(addressId).textContent = to.address;
    say(warningId, to.known ? '' : `This is not a known address of the Provared application (${KNOWN_RETURN_ADDRESSES.join(' or ')}, over https). Go on only if you opened this window from that address yourself; otherwise close it and sign nothing.`);
  }

  // How the passkey that signs is described, before it is asked.
  async function passkeyWords() {
    if (expected) {
      const known = await rememberedFor(expected.thumbprint);
      return `the passkey ${expected.thumbprint}, which signed the earlier permission${known ? ' (this browser remembers it)' : ' (this browser does not remember it: your device will offer the passkeys it holds for this website, and the page checks that the one you choose is that one)'}`;
    }
    const list = rememberedPasskeys();
    if (list.length) return `the passkey this browser remembers, ${await thumbprint(list[list.length - 1].key)}`;
    return 'a new passkey, made for this website when you sign';
  }

  // --- going back to the first step ---

  // The warnings confirmed are taken back: they are worked out and shown
  // again at the next press.
  function unconfirm() {
    confirmed = new Set();
    $('sign').textContent = 'Sign this permission with a passkey';
  }
  function unconfirmCancel() {
    cancelConfirmed = new Set();
    $('cancel').textContent = 'Sign the cancellation with the passkey';
  }

  function unread() {
    generation++;
    fields = null;
    readName = null;
    slip = null;
    unconfirm();
    $('step2').classList.add('waiting');
    $('step3').classList.add('waiting');
    $('sign').disabled = true;
    $('save-line').hidden = true;
    $('back-line').hidden = true;
    $('fingerprint-line').hidden = true;
    $('slip-words').hidden = true;
    $('changed-box').hidden = true;
    $('warnings').hidden = true;
    $('warnings').replaceChildren();
    say('sign-status', '');
  }

  // --- filling the page from its address ---

  async function fill() {
    unread();
    request = null;
    earlier = null;
    expected = null;
    elsewhereNote = '';
    $('steps').hidden = false;
    $('cancel-details').open = false;
    $('cancel-of').value = '';
    $('cancel-of').readOnly = false;
    $('cancel-words').hidden = true;
    $('cancel-return-line').hidden = true;
    $('cancel-warnings').hidden = true;
    $('cancel-warnings').replaceChildren();
    unconfirmCancel();
    say('cancel-status', '');
    $('cancel').disabled = false;
    if (!byItself) {
      say('read-status', FRAMED);
      $('fields').value = JSON.stringify(EXAMPLE, null, 2);
      return;
    }
    const asked = readRequest(location.hash);
    if (asked.message) {
      say('read-status', asked.message);
      $('fields').value = '';
      $('read').disabled = true;
      return;
    }
    $('read').disabled = false;
    if (!asked.request) {
      const { permission, message } = readStartingPermission(location.hash);
      say('read-status', message ?? '');
      $('fields').value = JSON.stringify(permission, null, 2);
      return;
    }
    request = asked.request;
    const at = generation;
    try {
      await settleRequest();
    } catch (e) {
      if (at !== generation) return;
      // Nothing of a request that could not be used stays to sign with.
      request = null;
      earlier = null;
      expected = null;
      const words = `${e && e.message ? e.message : 'The request could not be used.'} Nothing is offered to sign. Close this window and try again from the page that opened it.`;
      say('read-status', words);
      if (asked.request.kind === 'cancellation') say('cancel-status', words);
      $('fields').value = '';
      $('read').disabled = true;
      $('cancel').disabled = true;
      return;
    }
    if (at !== generation) return;
    if (request.kind === 'cancellation') {
      $('steps').hidden = true;
      $('cancel-details').open = true;
      $('cancel-of').value = earlier.fingerprint;
      $('cancel-of').readOnly = true;
      say('cancel-status', `The page that opened this window asks you to cancel the permission below, signed by ${expected.name}. Read it, then sign the cancellation with the passkey ${expected.thumbprint}, the one that signed it.`);
      showWords($('cancel-words'), earlier.content, null, await agentKeySet(earlier.content.agent.keys).then((k) => k.fingerprint), '', await serviceWords(earlier.content.with));
      showReturn('cancel-return-line', 'cancel-return-address', 'cancel-return-warning');
      $('cancel').focus();
      return;
    }
    $('fields').value = JSON.stringify(request.fields, null, 2);
    $('issuer-name').value = request.name ?? (earlier ? String(earlier.content.issuer.name) : '');
    say('read-status', (request.kind === 'renewal'
      ? 'The page that opened this window asks you to renew a permission: the new permission below starts as that page filled it in. Read it, change it if you wish, and press "Read the permission" to see it in words and what it changes.'
      : 'The page that opened this window asks you to sign a new permission, filled in below. Read it, change it if you wish, write your name, and press "Read the permission".') + elsewhereNote);
  }

  // What a request settles before anything is shown: the earlier
  // permission, trusted only once its passkey signature checks here, and
  // the passkey expected to sign, by its public key.
  async function settleRequest() {
    let key = request.issuerKey ?? null;
    if (request.earlier) {
      const result = await checkSlip(request.earlier, {});
      if (result.problems.length) throw new Error(`The earlier permission handed to this page does not pass its check (${result.problems[0].message}), so it is not trusted.`);
      if (result.signature.state !== 'valid') throw new Error('This browser cannot check the passkey signature of the earlier permission handed to this page, so it is not trusted.');
      earlier = { content: result.content, fingerprint: result.fingerprint, record: request.earlier };
      if (key && (await thumbprint(key)) !== result.issuerKey) throw new Error('The request names a passkey other than the one that signed the earlier permission.');
      key = result.content.issuer.key;
    }
    if (key) {
      const thumb = await thumbprint(key);
      const rpId = earlier ? earlier.content.issuer.rpId : location.hostname;
      const origin = earlier ? earlier.content.issuer.origin : location.origin;
      expected = { key, thumbprint: thumb, rpId, origin, name: earlier ? `"${shown(String(earlier.content.issuer.name))}" (a label)` : 'the passkey the request names' };
      if (request.kind === 'cancellation' && rpId !== location.hostname) {
        // A cancellation is signed by the passkey that signed the
        // permission, here, or not at all: a passkey for another website
        // name is not asked, and none is made in its place.
        throw new Error(`This permission was signed with a passkey for the website name ${rpId}, not ${location.hostname}, so it cannot be cancelled on this page.`);
      }
      if (request.kind === 'cancellation' && origin !== location.origin) {
        throw new Error(`This permission was signed at ${origin}, and a checker holds a cancellation to that same address, so it cannot be cancelled here, at ${location.origin}.`);
      }
      if (rpId !== location.hostname) {
        // The passkey belongs to another website: a browser will not let it sign here.
        expected = null;
        elsewhereNote = ` The passkey that signed the earlier permission (${thumb}) belongs to the website ${rpId}, and a browser lets it sign only there, not at ${location.hostname}. The new permission is signed with a passkey for this website instead; the agent's software takes a permission from a passkey it does not yet trust only when it is told to.`;
      }
    }
    if (request.kind === 'cancellation' && !expected) throw new Error('The request names no permission to cancel.');
  }

  fill();
  // A link opened in a tab that shows this page already changes only the
  // fragment, and the browser does not load the page again: the page fills
  // itself in again, and what was read before can no longer be signed.
  window.addEventListener('hashchange', fill);

  // Any change goes back to the first step, also while the page is still
  // reading or the passkey is being asked; where something had been read,
  // the page says so.
  const changed = () => {
    const wasRead = fields !== null || slip !== null || !$('step2').classList.contains('waiting');
    unread();
    if (wasRead) say('read-status', 'Changed since it was read: read it again before signing.');
  };
  $('fields').addEventListener('input', changed);
  $('issuer-name').addEventListener('input', changed);

  $('read').addEventListener('click', async () => {
    unread();
    if (!byItself) {
      say('read-status', FRAMED);
      return;
    }
    const at = generation;
    let parsed;
    try {
      parsed = JSON.parse($('fields').value);
    } catch (e) {
      say('read-status', `This is not JSON: ${e.message}`);
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.hasOwn(parsed, 'issuer')) {
      say('read-status', 'The permission must be one JSON object, without an "issuer" member: your passkey and name are the issuer.');
      return;
    }
    const name = $('issuer-name').value.trim();
    if (!name) {
      say('read-status', 'Write your name: it is the label the permission carries for the person who signed it.');
      return;
    }
    for (const member of SLIP_MEMBERS) {
      if (!Object.hasOwn(parsed, member)) {
        say('read-status', `The permission has no "${member}" member. Every member is needed; an empty list is written as [].`);
        return;
      }
    }
    if (!Array.isArray(parsed.agent?.keys) || parsed.agent.keys.length !== 2 || parsed.agent.keys.some((k) => !k || typeof k !== 'object')) {
      say('read-status', 'agent.keys must hold the agent\'s two public keys, as its software printed them (Ed25519 first, ML-DSA-87 second).');
      return;
    }
    try {
      const agentKeys = (await agentKeySet(parsed.agent.keys)).words;
      const services = await serviceWords(Array.isArray(parsed.with) ? parsed.with : []);
      const passkey = await passkeyWords();
      if (at !== generation) return; // changed while the fingerprints were worked out
      showWords($('slip-words'), parsed, name, agentKeys, passkey, services);
      if (earlier) await showChanged(parsed);
      if (at !== generation) return;
    } catch (e) {
      say('read-status', `The permission could not be read: ${e.message}`);
      return;
    }
    fields = parsed;
    readName = name;
    showReturn('return-line', 'return-address', 'return-warning');
    say('read-status', 'Read. Check the words below, then sign. Anything the format refuses is reported when you sign.');
    $('step2').classList.remove('waiting');
    $('sign').disabled = false;
    $('sign').focus();
  });

  // The warnings before the passkey is asked: a new passkey, an agent's key
  // set signed for the first time on this device, a passkey other than the
  // one that signed the earlier permission, a return address that is not
  // known. They are shown on the first press, and the second press signs.
  // Each warning has a code (what it is about) and its words.
  async function warningsBefore(f) {
    const list = [];
    const add = (code, text) => list.push({ code, text });
    const agentFp = await keySetFingerprint(f.agent.keys);
    // The earlier permission vouches for the agent's keys only where its
    // passkey is the person's own here (expected is set).
    const sameAsEarlier = Boolean(expected) && earlier && (await keySetFingerprint(earlier.content.agent.keys).catch(() => null)) === agentFp;
    if (!agentKnown(agentFp) && !sameAsEarlier) {
      add('new-agent', `You have not signed a permission for this agent's key set on this device before: ${agentFp}. Compare it with the fingerprint the agent's software printed when it made its keys. A permission for someone else's keys lets their agent act in your name.`);
    }
    if (expected) {
      if (!(await rememberedFor(expected.thumbprint))) add('not-remembered', `This browser does not remember the passkey that ${earlier ? 'signed the earlier permission' : 'the request names'}. Your device will offer the passkeys it holds for this website; choose the one you signed with before. The page checks that the passkey you chose is the one expected (${expected.thumbprint}), and signs with no other.`);
    } else {
      if (earlier) add('other-passkey', `The new permission is signed with a passkey other than the one that signed the earlier permission (${await thumbprint(earlier.content.issuer.key)}). The agent's software takes a permission from a passkey it does not yet trust only when it is told to.`);
      if (!rememberedPasskeys().length) add('new-passkey', 'A new passkey will be made for this website, on this device. Make one only if you have not signed here before on this device, or your earlier passkey is gone. The agent\'s software takes a permission from a passkey it does not yet trust only when it is told to.');
    }
    if (request && request.returnTo && !request.returnTo.known) add('unknown-return', `The signed permission will be handed to ${request.returnTo.address}, which is not a known address of the Provared application. Go on only if you opened this window from that address yourself.`);
    return list;
  }

  // The warnings before a cancellation is signed: a return address that is
  // not known.
  function cancelWarningsBefore() {
    const list = [];
    if (request && request.returnTo && !request.returnTo.known) list.push({ code: 'unknown-return', text: `The signed cancellation will be handed to ${request.returnTo.address}, which is not a known address of the Provared application. Go on only if you opened this window from that address yourself.` });
    return list;
  }

  function showWarnings(id, list) {
    const ul = $(id);
    ul.replaceChildren();
    for (const w of list) ul.append(el('li', '', w.text));
    ul.hidden = false;
  }

  // Whether every warning in the list was among those the person confirmed.
  const allConfirmed = (list, set) => list.every((w) => set.has(w.text));

  // The passkey that signs, found as the request and this browser allow:
  // the expected passkey where this browser remembers it; otherwise the
  // person's choice among the passkeys the device holds, which is checked
  // against the expected key once it has signed; otherwise the passkey this
  // browser remembers; otherwise a new one, only where the person confirmed
  // the warning that one will be made (mayMake). "chosen" means the key is
  // the expected one and the identifier is not yet known.
  async function findPasskey(name, { mayMake = false } = {}) {
    if (expected) {
      const known = await rememberedFor(expected.thumbprint);
      if (known) return { passkey: known, chosen: false };
      return { passkey: { key: expected.key, rpId: location.hostname, origin: location.origin }, chosen: true };
    }
    const list = rememberedPasskeys();
    if (list.length) return { passkey: list[list.length - 1], chosen: false };
    if (!mayMake) throw new Error('This browser remembers no passkey for this website, and a new one is made only after you have read the warning that says so.');
    say('sign-status', 'Your device is asking you to make a passkey for this website.');
    const made = await createPasskey({ name, site: 'Provared' });
    rememberPasskey(made);
    return { passkey: made, chosen: false };
  }

  // Ask the passkey found to sign; a chosen passkey is asked for by the
  // website alone, and its identifier is learnt from the answer.
  async function askToSign(statusId, challenge, found) {
    if (found.chosen) {
      say(statusId, 'Your device is offering the passkeys it holds for this website: choose the one you signed with before.');
      const assertion = await signChallengeWithChosenPasskey(challenge, location.hostname);
      found.passkey = { ...found.passkey, credentialId: assertion.credentialId };
      return assertion;
    }
    say(statusId, 'Your device is asking you to confirm it is you, to sign.');
    try {
      return await signChallengeWithPasskey(challenge, found.passkey);
    } catch (e) {
      // Not on this device any more, or the person said no: asked afresh next time.
      if (e && e.name === 'PasskeyError' && e.code === 'cancelled') forgetPasskey(found.passkey);
      throw e;
    }
  }

  // What the checker's refusal of a record just signed means for the person.
  // A refusal that means the signature does not fit the passkey expected.
  const PASSKEY_REFUSALS = ['signature-invalid', 'issuer-not-expected', 'passkey-rpid-mismatch', 'cancellation-invalid'];
  function refusedWords(found, problem, thumb) {
    const byPasskey = problem && PASSKEY_REFUSALS.includes(problem.code);
    if (found.chosen && byPasskey) {
      const whose = earlier ? 'the one that signed the earlier permission' : 'the one the request names';
      return `The passkey you chose is not ${whose} (${thumb}), so nothing is offered. Press the button again and choose that one.`;
    }
    // A passkey this browser remembers whose signature does not fit: asked afresh next time.
    if (!found.chosen && byPasskey) forgetPasskey(found.passkey);
    return `The checker refused what was signed: ${problem ? problem.message : 'the signature could not be checked on this device'}`;
  }

  $('sign').addEventListener('click', async () => {
    if (fields === null || !byItself) return;
    const at = generation;
    const [what, name] = [fields, readName];
    $('sign').disabled = true;
    try {
      // The warnings are worked out at every press: a press signs only
      // where every warning that stands now was shown and confirmed.
      const list = await warningsBefore(what);
      if (at !== generation) return;
      if (!allConfirmed(list, confirmed)) {
        showWarnings('warnings', list);
        confirmed = new Set(list.map((w) => w.text));
        $('sign').textContent = 'I have read the warnings: sign this permission';
        say('sign-status', 'Read the warnings above, then press the button again to sign.');
        $('sign').disabled = false;
        return;
      }
      const found = await findPasskey(name, { mayMake: list.some((w) => w.code === 'new-passkey') });
      const prepared = await prepareSlip({ ...what, issuer: { name, key: found.passkey.key, rpId: location.hostname, origin: location.origin } });
      const signed = assembleSlip(prepared, await askToSign('sign-status', prepared.challenge, found));
      const thumb = await thumbprint(found.passkey.key);
      // The checker confirms what was signed before it is offered: the
      // signature fits the key the permission names (for a chosen passkey,
      // the expected one), at this page's address.
      const result = await checkSlip(signed, { issuerKeys: [thumb], issuerOrigins: [location.origin] });
      if (result.problems.length || result.signature.state !== 'valid') throw new Error(refusedWords(found, result.problems[0], thumb));
      if (found.chosen) rememberPasskey(found.passkey);
      if (at !== generation) {
        // The page went back to its first step while the passkey was asked: what was signed is not offered.
        say('sign-status', 'The permission was changed while your passkey was being asked, so what was signed is not kept. Read the permission again and sign it.');
        return;
      }
      slip = signed;
      rememberAgent(await keySetFingerprint(what.agent.keys));
      $('thumbprint').textContent = thumb;
      $('passkey-line').hidden = false;
      $('fingerprint').textContent = result.fingerprint;
      $('fingerprint-line').hidden = false;
      $('step3').classList.remove('waiting');
      handBack(request ? request.kind : 'permission', slip, 'sign-status', 'save-status', 'save-line', 'back-line', 'back', 'save');
    } catch (e) {
      // A prompt that failed, or a passkey forgotten, takes the warnings
      // confirmed back: they are worked out and shown again at the next press.
      if (at === generation) unconfirm();
      say('sign-status', `${e && e.message ? e.message : 'The permission was not signed.'} You can try again.`);
      if (at === generation) $('sign').disabled = false;
    }
  });

  // The signed record goes back to the page that asked, where there is
  // one: by postMessage to the window that opened this one, to its exact
  // address; where this page was not opened as a window, by a link back
  // with the record after "#"; last, as a file, which stays offered.
  function handBack(kind, record, statusId, saveStatusId, saveLineId, backLineId, backId, saveId) {
    const to = request && request.returnTo;
    const message = request ? signedMessage(kind, record, request.state) : null;
    $(saveLineId).hidden = false;
    if (!to) {
      say(statusId, 'Signed.');
      say(saveStatusId, kind === 'cancellation' ? 'Signed. Save it, and hand it to the agent\'s software.' : 'The permission is signed. Save it, and keep the thumbprint above with it.');
      $(saveId).focus();
      return;
    }
    const opener = window.opener;
    let handed = false;
    if (opener && !opener.closed) {
      try {
        opener.postMessage(message, to.origin);
        handed = true;
      } catch {
        handed = false;
      }
    }
    const what = kind === 'cancellation' ? 'cancellation' : 'permission';
    if (handed) {
      // Sent, not yet handed over: a browser delivers it only where the
      // page that opened this window is at the return address, and says
      // nothing where it is not. It counts as handed over once that page
      // answers. The window closes once that page says it kept the record;
      // until then, and if it never says so, the file stays offered.
      say(statusId, `Signed, and sent to the page that opened this window, for ${to.address}. Waiting for it to confirm that it kept the signed ${what}.`);
      say(saveStatusId, '');
      let timer = null;
      const reply = (event) => {
        const answer = replyFrom(event, { opener, origin: to.origin, kind, state: request.state });
        if (!answer) return;
        window.removeEventListener('message', reply);
        clearTimeout(timer);
        if (answer === 'kept') {
          say(statusId, `Signed, handed to ${to.address}, and kept there. This window closes itself; if it stays open, close it.`);
          setTimeout(() => window.close(), 1000);
        } else {
          say(statusId, `Signed and handed to ${to.address}, but it did not keep it: it says why on its own page. Nothing more is sent from this window.`);
          say(saveStatusId, 'You can still save it as a file.');
        }
      };
      window.addEventListener('message', reply);
      timer = setTimeout(() => {
        window.removeEventListener('message', reply);
        say(statusId, `Signed and sent, but ${to.address} has not confirmed that it kept the signed ${what}. The page that opened this window may be at another address, or it may have been closed or moved on.`);
        say(saveStatusId, 'Save it as a file instead, so that it is not lost.');
        $(saveId).focus();
      }, RECEIPT_WAIT);
      return;
    }
    // Going back by a link can lose the record (a page that does not load,
    // a tab closed on the way): the file is offered first.
    say(statusId, `Signed. This page was not opened as a window by ${to.address}, so the signed ${what} is not handed back by itself. Save it first as a file, then go back there with it.`);
    say(saveStatusId, 'Save it first: the file is your copy if going back does not work.');
    $(backLineId).hidden = false;
    $(backId).textContent = `Then go back to ${to.address} with the signed ${what}`;
    $(backId).onclick = () => location.assign(signedLink(to.address, message));
    $(saveId).focus();
  }

  function download(name, text) {
    const link = el('a');
    link.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
  }

  $('save').addEventListener('click', () => {
    if (slip) download('slip.json', JSON.stringify(slip));
  });

  $('cancel').addEventListener('click', async () => {
    if (!byItself) {
      say('cancel-status', FRAMED);
      return;
    }
    const of = $('cancel-of').value.trim();
    if (!FINGERPRINT.test(of)) {
      say('cancel-status', 'A fingerprint is 43 letters, digits, hyphens or underscores.');
      return;
    }
    const at = generation;
    $('cancel').disabled = true;
    $('cancel-save-line').hidden = true;
    $('cancel-back-line').hidden = true;
    try {
      if (request && request.kind === 'cancellation') {
        // Only ever the passkey that signed the permission (settleRequest
        // refuses any other request): never a new one.
        if (!expected || !earlier) throw new Error('There is no permission to cancel here.');
        const list = cancelWarningsBefore();
        if (!allConfirmed(list, cancelConfirmed)) {
          showWarnings('cancel-warnings', list);
          cancelConfirmed = new Set(list.map((w) => w.text));
          $('cancel').textContent = 'I have read the warning: sign the cancellation';
          say('cancel-status', 'Read the warning above, then press the button again to sign the cancellation.');
          $('cancel').disabled = false;
          return;
        }
        // The passkey that signed the permission, found by its key; the
        // checker holds the cancellation against the permission before it
        // is offered, as a checker given both would.
        const prepared = await prepareCancellation({ slip: of });
        const found = await findPasskey(null, { mayMake: false });
        const record = assembleCancellation(prepared, await askToSign('cancel-status', prepared.challenge, found));
        const result = await checkBook(`${entryLine({ slip: earlier.record })}\n`, { issuerKeys: [expected.thumbprint], cancellations: [{ cancellation: record }] });
        const held = result.held[0];
        const problems = [...result.problems, ...(held ? held.problems : [])];
        if (problems.length || !held || !held.signature || held.signature.state !== 'valid') throw new Error(refusedWords(found, problems[0], expected.thumbprint));
        if (found.chosen) rememberPasskey(found.passkey);
        if (at !== generation) return;
        cancellation = record;
        say('cancel-status', `Signed, dated ${held.content.when}.`);
        handBack('cancellation', record, 'cancel-status', 'cancel-save-status', 'cancel-save-line', 'cancel-back-line', 'cancel-back', 'cancel-save');
        // Handed back, or offered to take back: the button stays off, so that
        // a second press does not sign a second cancellation without a new
        // warning, while the page that asked waits or after it says it did
        // not keep it. The file stays offered; a new request starts the page
        // afresh (fill).
        return;
      } else {
        const list = rememberedPasskeys();
        if (!list.length) throw new Error('No passkey is remembered in this browser. Sign a permission here first with the passkey that signed the one to cancel.');
        const passkey = list[list.length - 1];
        say('cancel-status', 'Your device is asking you to confirm it is you, to sign the cancellation.');
        cancellation = await cancelWithPasskey({ slip: of }, passkey);
        if (at !== generation) return;
        say('cancel-status', `Signed, dated ${new Date().toISOString().slice(0, 19)}Z. Save it, and hand it to the agent's software.`);
        $('cancel-save-line').hidden = false;
      }
    } catch (e) {
      if (at === generation) unconfirmCancel();
      say('cancel-status', `${e && e.message ? e.message : 'The cancellation was not signed.'} You can try again.`);
    }
    $('cancel').disabled = false;
  });

  $('cancel-save').addEventListener('click', () => {
    if (cancellation) download('cancellation.json', JSON.stringify({ cancellation }));
  });
}

if (typeof document !== 'undefined') page();
