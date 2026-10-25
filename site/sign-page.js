// The signing page: a person writes a permission, this device's passkey
// signs it, and the person keeps the signed file. Everything happens in
// this browser. The page loads only its own files and sends nothing
// anywhere; the passkey is kept by the device, and this page remembers
// only its public key and identifier (in this browser's storage) so that
// the same passkey can sign again later.
//
// What signs is exactly what was read and shown: the permission and the
// name as they stood when "Read the permission" was pressed. Any change
// after that (in the box, in the name, or a new link opened in the same
// tab) takes the page back to its first step, even while the passkey is
// being asked.
//
// Reading a starting permission from the page's address, the words shown
// for the agent's keys and the services' keys, and whether the page is
// shown by itself, do not need a page, so that they can be tested on their
// own (readStartingPermission, agentKeySet, serviceWords, shownByItself);
// the rest runs only in a browser. A page shown inside another page offers
// nothing to sign or cancel.

import { conditionWords, keySetFingerprint, limitWords, neverWords } from '../src/check.js';
import { cancelWithPasskey, createPasskey, signSlipWithPasskey } from '../src/passkey-browser.js';
import { fingerprint, fromBase64url } from '../src/encoding.js';
import { checkKeySet, thumbprint } from '../src/keys.js';
import { el, shown } from './render.js';

const STORE = 'provared-signing-passkey';
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;

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
  const given = new URLSearchParams(String(hash).replace(/^#/, '')).get('permission');
  if (given === null) return { permission: example, message: null };
  const instead = 'The page\'s own starting point is shown instead.';
  let bytes;
  try {
    bytes = fromBase64url(given);
  } catch {
    return { permission: example, message: `The permission in this page's address could not be read: it is not written in base64url. ${instead}` };
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { permission: example, message: `The permission in this page's address could not be read: it is not text. ${instead}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { permission: example, message: `The permission in this page's address is not JSON: ${e.message}. ${instead}` };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { permission: example, message: `The permission in this page's address is not one JSON object. ${instead}` };
  }
  return { permission: { ...example, ...parsed }, message: 'The permission below came with the link you opened. Read it, change it if you wish, write your name, and press "Read the permission".' };
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
 * cancel.
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

function page() {
  const $ = (id) => document.getElementById(id);
  const say = (id, text) => {
    $(id).textContent = text;
  };
  const byItself = shownByItself(window);
  const FRAMED = 'This page is shown inside another page, so it offers nothing to sign or cancel. Open prova.red/sign/ in a tab of its own.';

  // What was read, and is what signs: the permission and the name.
  let fields = null;
  let readName = null;
  let slip = null;
  let cancellation = null;
  // Counts every going back to the first step, so that a signature that
  // arrives after one is not kept.
  let generation = 0;

  function remembered() {
    try {
      const p = JSON.parse(localStorage.getItem(STORE));
      if (p && typeof p.credentialId === 'string' && p.key && p.rpId === location.hostname && p.origin === location.origin) return p;
    } catch {
      // Nothing remembered, or not readable: a new passkey is made.
    }
    return null;
  }

  // The permission in words, so that the person sees what they sign: who
  // signs it, and the agent's keys by the fingerprint of their key set, too.
  function showWords(f, name, agentKeys, passkey, services) {
    const dl = $('slip-words');
    dl.replaceChildren();
    const row = (term, text) => dl.append(el('dt', '', term), el('dd', '', text));
    row('Signed by', `"${shown(name)}" (a label), with ${passkey ? `the passkey this browser remembers, ${passkey}` : 'a passkey made for this website when you sign'}`);
    row('Agent', shown(f.agent.name));
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
    row('Purpose', shown(f.purpose));
    if (f.passes) row('May pass on', `${f.passes} time(s) in a row`);
    dl.hidden = false;
  }

  // Back to the first step: nothing read, so nothing can be signed.
  function unread() {
    generation++;
    fields = null;
    readName = null;
    slip = null;
    $('step2').classList.add('waiting');
    $('step3').classList.add('waiting');
    $('sign').disabled = true;
    $('save-line').hidden = true;
    $('fingerprint-line').hidden = true;
    $('slip-words').hidden = true;
  }

  function fill() {
    unread();
    // Shown inside another page, the page does not take a permission from its address: that page chose the link.
    const { permission, message } = readStartingPermission(byItself ? location.hash : '');
    say('read-status', byItself ? message ?? '' : FRAMED);
    $('fields').value = JSON.stringify(permission, null, 2);
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
    for (const member of ['agent', 'actions', 'limits', 'requires', 'never', 'with', 'validFrom', 'validUntil', 'purpose']) {
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
      const passkey = remembered();
      const known = passkey ? await thumbprint(passkey.key) : null;
      if (at !== generation) return; // changed while the fingerprints were worked out
      showWords(parsed, name, agentKeys, known, services);
    } catch (e) {
      say('read-status', `The permission could not be read: ${e.message}`);
      return;
    }
    fields = parsed;
    readName = name;
    say('read-status', 'Read. Check the words below, then sign. Anything the format refuses is reported when you sign.');
    $('step2').classList.remove('waiting');
    $('sign').disabled = false;
    $('sign').focus();
  });

  $('sign').addEventListener('click', async () => {
    if (fields === null || !byItself) return;
    $('sign').disabled = true;
    const at = generation;
    const [what, name] = [fields, readName];
    try {
      let passkey = remembered();
      if (!passkey) {
        say('sign-status', 'Your device is asking you to make a passkey for this website.');
        passkey = await createPasskey({ name, site: 'Provared' });
        localStorage.setItem(STORE, JSON.stringify(passkey));
      }
      say('sign-status', 'Your device is asking you to confirm it is you, to sign the permission.');
      const signed = await signSlipWithPasskey(what, passkey, name);
      if (at !== generation) {
        // The page went back to its first step while the passkey was asked: what was signed is not offered.
        say('sign-status', 'The permission was changed while your passkey was being asked, so what was signed is not kept. Read the permission again and sign it.');
        return;
      }
      slip = signed;
      const fp = await fingerprint(fromBase64url(slip.payload));
      $('thumbprint').textContent = await thumbprint(passkey.key);
      $('passkey-line').hidden = false;
      $('fingerprint').textContent = fp;
      $('fingerprint-line').hidden = false;
      say('sign-status', 'Signed.');
      say('save-status', 'The permission is signed. Save it, and keep the thumbprint above with it.');
      $('step3').classList.remove('waiting');
      $('save-line').hidden = false;
      $('save').focus();
    } catch (e) {
      if (e && e.name === 'PasskeyError' && e.code === 'cancelled') localStorage.removeItem(STORE);
      say('sign-status', `${e && e.message ? e.message : 'The permission was not signed.'} You can try again.`);
      if (at === generation) $('sign').disabled = false;
    }
  });

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
    $('cancel').disabled = true;
    $('cancel-save-line').hidden = true;
    try {
      const passkey = remembered();
      if (!passkey) throw new Error('No passkey is remembered in this browser. Sign a permission here first with the passkey that signed the one to cancel.');
      say('cancel-status', 'Your device is asking you to confirm it is you, to sign the cancellation.');
      cancellation = await cancelWithPasskey({ slip: of }, passkey);
      say('cancel-status', `Signed, dated ${new Date().toISOString().slice(0, 19)}Z. Save it, and hand it to the agent's software.`);
      $('cancel-save-line').hidden = false;
    } catch (e) {
      say('cancel-status', `${e && e.message ? e.message : 'The cancellation was not signed.'} You can try again.`);
    }
    $('cancel').disabled = false;
  });

  $('cancel-save').addEventListener('click', () => {
    if (cancellation) download('cancellation.json', JSON.stringify({ cancellation }));
  });
}

if (typeof document !== 'undefined') page();
