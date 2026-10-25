// Small checks on the fields of a record's content. Each throws a Refusal
// with the code "bad-field" and says which field and why.

import { isUnknownReserved } from './actions.js';
import { MAX_NUMBER, Refusal, countCharacters, fromBase64url, parseTime } from './encoding.js';

export function fail(path, why) {
  return new Refusal('bad-field', `${path}: ${why}`);
}

/**
 * An object must hold every required member, and no member that is neither
 * required nor optional. An unknown member is refused.
 */
export function members(value, required, optional, path) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw fail(path, 'must be an object.');
  for (const name of required) {
    if (!Object.hasOwn(value, name)) throw fail(path, `"${name}" is missing.`);
  }
  for (const name of Object.keys(value)) {
    if (!required.includes(name) && !optional.includes(name)) throw fail(path, 'holds a member that is not known.');
  }
}

export function text(value, min, max, path) {
  // The quick test on the raw length keeps a huge text from being counted.
  if (typeof value !== 'string' || value.length > max * 2 || countCharacters(value) < min || countCharacters(value) > max) {
    throw fail(path, `must be text of ${min} to ${max} characters.`);
  }
}

export function wholeNumber(value, path) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_NUMBER) throw fail(path, 'must be a whole number, 0 or more.');
}

export function list(value, min, max, path) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    throw fail(path, `must be a list of ${min} to ${max} items.`);
  }
}

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const UNIT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/;

/** An action name, or the id of a service. */
export function shortName(value, path) {
  if (typeof value !== 'string' || !NAME.test(value)) {
    throw fail(path, 'must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.');
  }
}

/** An action name. Names that begin "provared." must be on the shared list. */
export function actionName(value, path) {
  shortName(value, path);
  if (isUnknownReserved(value)) throw fail(path, 'names that begin "provared." are reserved, and this one is not on the shared list.');
}

export function unit(value, path) {
  if (typeof value !== 'string' || !UNIT.test(value)) {
    throw fail(path, 'must be 1 to 16 letters, digits, full stops, hyphens or underscores, with no spaces.');
  }
}

/** A label chosen by whoever wrote the record. Never checked against anything. */
export function label(value, path) {
  text(value, 1, 200, path);
}

function base64urlOfLength(value, bytes, path, what) {
  let decoded;
  try {
    decoded = fromBase64url(value);
  } catch {
    throw fail(path, `must be ${what}.`);
  }
  if (decoded.length !== bytes) throw fail(path, `must be ${what}.`);
}

/** A unique number: 16 bytes in base64url. */
export function id(value, path) {
  base64urlOfLength(value, 16, path, 'a unique number of 16 bytes in base64url');
}

/** A fingerprint: SHA-256 in base64url. */
export function fingerprintText(value, path) {
  base64urlOfLength(value, 32, path, 'a SHA-256 fingerprint in base64url');
}

/** @returns {number} the time in milliseconds */
export function time(value, path) {
  const ms = parseTime(value);
  if (Number.isNaN(ms)) throw fail(path, 'must be a time written as YYYY-MM-DDTHH:MM:SSZ.');
  return ms;
}
