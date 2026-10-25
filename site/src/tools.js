// A connector between an agent's tools and the stub writer.
//
// An agent acts by calling tools: functions that its software offers it.
// recordTools puts each tool behind the stub writer (recorder.js), so that
// every call asks first, is run only if the slip allows it, and leaves a
// stub. The agent's software then calls the tools as before.
//
// By default the stub of a call names one document, "provared.arguments"
// (a reserved name, format description section 27): the fingerprint of the
// call's arguments. So the record fixes exactly what was asked for, without
// holding it: whoever kept the arguments can show them later, and anyone
// can work out the fingerprint again. Before version 0.6.0 the document was
// named "arguments"; a checker reads both.
//
// It names no agent software and depends on none: a tool is any function.

import { denialCodes } from './denial.js';
import { Refusal, fingerprint, utf8 } from './encoding.js';
import * as f from './fields.js';

/** How deep the arguments of a call may nest. */
const MAX_ARGUMENT_DEPTH = 64;

// Calling a generator function does not run its body, so its stub would be
// written for an action not yet taken.
const GENERATORS = new Set(['[object GeneratorFunction]', '[object AsyncGeneratorFunction]']);
const NOT_A_GENERATOR = 'must not be a generator function: calling one does not run its body, so its stub would be written for an action not yet taken.';

/**
 * A call through a recorded tool that was not run: the check before acting
 * did not allow it, or the record so far has a problem. "answer" is what
 * the check before acting said (allowed, problems, breaches, needs).
 * "denial", where the stub writer was opened with "denials: true", is what
 * it said of the denial it wrote, or did not write, for the call.
 */
export class NotTaken extends Error {
  /**
   * @param {string} tool the name of the tool
   * @param {{allowed: boolean, problems: object[], breaches: object[], needs: string[]}} answer
   * @param {object} [denial]
   */
  constructor(tool, answer, denial) {
    const first = [...answer.problems, ...answer.breaches][0];
    super(`The tool "${tool}" was not run. ${first ? first.message : 'The check before acting did not allow it.'}`);
    this.name = 'NotTaken';
    this.tool = tool;
    this.answer = answer;
    if (denial !== undefined) this.denial = denial;
  }
}

// The arguments written in one form, as RFC 8785 sets out: members sorted
// by name, no spaces, text and numbers as JSON writes them. So the same
// arguments always give the same fingerprint, whatever order their members
// were written in.
function oneForm(value, depth = 0) {
  if (depth > MAX_ARGUMENT_DEPTH) throw new Refusal('bad-field', 'The arguments nest too deeply.');
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') {
    if (typeof value.isWellFormed === 'function' && !value.isWellFormed()) throw new Refusal('bad-field', 'The arguments hold text that is not well-formed Unicode.');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Refusal('bad-field', 'The arguments hold a number that JSON cannot write.');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    // A list is its items, first to last, and nothing else: a gap, or a member with a name, is not JSON.
    if (Object.keys(value).length !== value.length) throw new Refusal('bad-field', 'The arguments hold a list with a gap in it, or with a named member. That is not JSON.');
    const items = [];
    for (let i = 0; i < value.length; i++) items.push(oneForm(value[i], depth + 1));
    return '[' + items.join(',') + ']';
  }
  const proto = typeof value === 'object' ? Object.getPrototypeOf(value) : undefined;
  if (proto !== Object.prototype && proto !== null) {
    throw new Refusal('bad-field', 'The arguments must be JSON: objects, lists, text, numbers, true, false and null.');
  }
  return '{' + Object.keys(value).sort().map((name) => oneForm(name, depth + 1) + ':' + oneForm(value[name], depth + 1)).join(',') + '}';
}

/**
 * The fingerprint of the arguments of a call: SHA-256, in base64url, of the
 * arguments written in the one form of RFC 8785. It is what a recorded
 * tool puts into its stub, as the document "provared.arguments".
 * @param {unknown} args JSON: objects, lists, text, numbers, true, false and null
 * @returns {Promise<string>}
 * @throws {Refusal} "bad-field" if the arguments are not JSON
 */
export async function argumentsFingerprint(args) {
  return fingerprint(utf8(oneForm(args)));
}

// A copy that nothing else holds.
function copied(value, what) {
  try {
    return structuredClone(value);
  } catch {
    throw new Refusal('bad-field', `${what} must be plain data.`);
  }
}

// A member of a tool's description that is either a value or a function of
// the arguments. A function is handed a copy of the arguments of its own:
// nothing it does to them changes what is recorded, or what the tool is run
// with. It is called by itself, not as a member of the description: it is
// not handed the description, and cannot change it.
const from = (spec, member, args) => {
  const value = spec[member];
  return typeof value === 'function' ? value(structuredClone(args)) : value;
};

// The slip asks for the person's approval, none was handed over, and nothing else stands in the way.
const needsOnlyApproval = (answer) => answer.problems.length === 0 && answer.breaches.length > 0 && answer.breaches.every((b) => b.code === 'approval-missing');

/**
 * Put an agent's tools behind the stub writer. Each tool is then called as
 * before, with one argument; the call asks first, runs the tool only if the
 * slip allows the action, and writes the stub.
 *
 * @param {object} recorder the stub writer (openRecorder)
 * @param {Record<string, object>} tools by name. For each tool:
 *   - "action": the action name the slip uses for what this tool does;
 *   - "run": the tool itself, a function of the arguments, not a generator function. It must not call the stub writer;
 *   Each function is called by itself, without "this". "amount" and "with" must give their value at once, not a promise.
 *   - "with" (optional): the id of the service the tool deals with, as the slip names it, or a function of the arguments that gives it;
 *   - "amount" (optional): {unit, value}, or a function of the arguments that gives it;
 *   - "details" (optional): a function of the arguments that gives the documents to name in the stub
 *     ({name, sha256} each), or false for none. By default: one document, "provared.arguments", the
 *     fingerprint of the arguments (argumentsFingerprint);
 *   - "countersign" (optional): asks the other side to countersign the stub; a function of the stub and the arguments;
 *   - "approve" (optional): asks the person for their approval where the slip asks for one; a function of the
 *     request ({action, amount?, with?, details?}) and the arguments, that gives {record} or nothing.
 * @param {object} [options]
 * @param {(stub: object, tool: string) => any} [options.onStub] called after each stub is written, for example to keep the book
 * @returns {Record<string, (args?: any) => Promise<any>>} the tools. A call gives what the tool gives.
 *   A call that is not allowed throws NotTaken, and the tool is not run. If the tool itself fails,
 *   its error is passed on and no stub is written (see "act" of the stub writer). If "onStub" fails,
 *   its error is passed on too: the tool has run by then, and its stub is in the book.
 * @throws {Refusal} "bad-field" if a tool is not described as set out above
 */
export function recordTools(recorder, tools, options = {}) {
  if (recorder === null || typeof recorder !== 'object' || typeof recorder.act !== 'function') {
    throw new Refusal('bad-field', 'recorder: must be a stub writer.');
  }
  if (tools === null || typeof tools !== 'object' || Array.isArray(tools)) throw new Refusal('bad-field', 'tools: must be an object that holds the tools by name.');
  if (options === null || typeof options !== 'object') options = {};
  // What the tools are put behind is fixed here too.
  const act = recorder.act.bind(recorder);
  // Whether the writer writes denials, read once: only then are denials asked for.
  const deny = recorder.denials === true && typeof recorder.deny === 'function' ? recorder.deny.bind(recorder) : null;
  const onStub = typeof options.onStub === 'function' ? options.onStub : null;
  const recorded = {};
  for (const name of Object.keys(tools)) {
    const spec = tools[name];
    if (spec === null || typeof spec !== 'object') throw f.fail(`tools.${name}`, 'must be an object.');
    // What a tool is, is fixed here, through and through: a later change to the caller's own objects changes nothing.
    // Each member is read once: what is checked is what is fixed.
    const fixed = { action: spec.action, run: spec.run, details: spec.details, countersign: spec.countersign, approve: spec.approve, amount: spec.amount, with: spec.with };
    if (typeof fixed.run !== 'function') throw f.fail(`tools.${name}.run`, 'must be a function.');
    if (GENERATORS.has(Object.prototype.toString.call(fixed.run))) throw f.fail(`tools.${name}.run`, NOT_A_GENERATOR);
    f.actionName(fixed.action, `tools.${name}.action`);
    for (const member of ['countersign', 'approve']) {
      if (fixed[member] !== undefined && typeof fixed[member] !== 'function') throw f.fail(`tools.${name}.${member}`, 'must be a function.');
    }
    if (fixed.details !== undefined && fixed.details !== false && typeof fixed.details !== 'function') throw f.fail(`tools.${name}.details`, 'must be a function, or false.');
    for (const member of ['amount', 'with']) if (typeof fixed[member] !== 'function') fixed[member] = copied(fixed[member], `tools.${name}.${member}`);
    for (const member of ['amount', 'with']) if (fixed[member] !== null && typeof fixed[member] === 'object') Object.freeze(fixed[member]);
    Object.freeze(fixed);
    Object.defineProperty(recorded, name, { enumerable: true, value: (args) => call(act, deny, onStub, name, fixed, args) });
  }
  return recorded;
}

async function call(act, deny, onStub, name, spec, args) {
  // The arguments are copied when the call is made. The fingerprint is made
  // from that copy, and the tool is run with a copy of it. Each of the
  // tool's other functions is handed a copy of its own.
  const given = copied(args, `The arguments of the tool "${name}"`);
  const request = { action: spec.action };
  // What the tool's own functions give is copied too: a function that kept
  // what it gave cannot change it afterwards.
  const amount = copied(from(spec, 'amount', given), `tools.${name}.amount`);
  if (amount !== undefined && amount !== null) request.amount = amount;
  const withWhom = copied(from(spec, 'with', given), `tools.${name}.with`);
  if (withWhom !== undefined && withWhom !== null) request.with = withWhom;
  let details;
  if (spec.details === false) details = [];
  else if (typeof spec.details === 'function') details = (await (0, spec.details)(structuredClone(given))) ?? [];
  else details = given === undefined ? [] : [{ name: 'provared.arguments', sha256: await argumentsFingerprint(given) }];
  if (!Array.isArray(details)) throw f.fail(`tools.${name}.details`, 'must give a list of documents.');
  details = copied(details, `tools.${name}.details`);
  if (details.length > 0) request.details = details;

  const more = {};
  if (typeof spec.countersign === 'function') more.countersign = (stub) => (0, spec.countersign)(stub, structuredClone(given));
  const perform = () => (0, spec.run)(structuredClone(given));
  // Where the person may be asked for their approval, the first call
  // writes no denial: the action may yet be taken. A denial is written once
  // it is known that it will not be, so that one call never leaves both a
  // stub and a denial.
  const asking = typeof spec.approve === 'function' && deny !== null;
  let outcome = await act(request, perform, asking ? { ...more, denial: false } : more);
  // Where the slip asks for the person's own approval of this action, and
  // that is the one thing missing, the person is asked, once.
  if (!outcome.done && typeof spec.approve === 'function' && needsOnlyApproval(outcome.answer)) {
    const approval = await (0, spec.approve)(structuredClone(request), structuredClone(given));
    if (approval) outcome = await act(request, perform, { ...more, approval });
    else if (asking) outcome = { ...outcome, denial: await deny(request, { source: 'person' }) };
  } else if (!outcome.done && asking) {
    outcome = { ...outcome, denial: await deny(request, { source: 'check', codes: denialCodes(outcome.answer) }) };
  }
  if (!outcome.done) throw new NotTaken(name, outcome.answer, outcome.denial);
  if (onStub) await onStub(outcome.stub, name);
  return outcome.result;
}
