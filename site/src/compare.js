// What a stub shows about the agent, compared with its slip.
// Format description, section 8.
//
// The checker and the "check before acting" function both use this one
// comparison, so that nothing is allowed beforehand that would be reported
// afterwards. In one case the check before acting refuses more: see
// periodWith.

import { ACTION_KINDS, CONDUCT_RULES, actionKind } from './actions.js';
import { parseTime } from './encoding.js';

/** The running state kept for one slip while its stubs are read in order. */
export function newTally() {
  return { sums: new Map(), counts: new Map(), periods: new Map() };
}

// The total inside the period that ends at each stub. A period is counted
// back from a stub by the times the stubs state, whichever chain a stub is
// in and wherever it stands in the book: an agent and its helpers each have
// a chain, and their stubs need not stand in the book in order of time. So
// the stubs are first put in order of time (those with the same time stay
// in the order of the book), and the period of each takes in the stubs up
// to it that are later than its time minus the period.
function periodTotals(items, periodMs) {
  const sorted = items.map((item, place) => ({ item, place })).sort((a, b) => a.item.when - b.item.when || a.place - b.place);
  const totals = [];
  let head = 0;
  let sum = 0n;
  for (const { item } of sorted) {
    sum += item.value;
    while (sorted[head].item.when <= item.when - periodMs) {
      sum -= sorted[head].item.value;
      head++;
    }
    totals.push({ item, total: sum });
  }
  return totals;
}

// For a check before acting: the largest total of any period that the
// proposed action would fall in. That is its own period, and the period of
// every stub dated after it and less than one period later.
//
// Where a stub dated after the proposed action is already over the limit,
// the action is refused: it would add to a period that holds too much. A
// checker, with the stub written, reports nothing new, because the finding
// stands with the later stub, which it already marks. This is the one case
// where the check before acting refuses more than a checker would report.
function periodWith(items, when, periodMs, value) {
  const proposed = { when, value };
  let worst = 0n;
  for (const { item, total } of periodTotals([...items, proposed], periodMs)) {
    if ((item === proposed || (item.when > when && item.when < when + periodMs)) && total > worst) worst = total;
  }
  return worst;
}

function periodWords(seconds) {
  if (seconds % 86400 === 0) return seconds === 86400 ? 'any 24 hours' : `any ${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? 'any hour' : `any ${seconds / 3600} hours`;
  return `any ${seconds} seconds`;
}

const allowedIn = (limit) => BigInt(Object.hasOwn(limit, 'count') ? limit.count : limit.max);

// "proposed": an action that is only proposed (a check before acting), of
// which no stub exists yet.
function overPeriod(limit, total, W, proposed = false) {
  const [With, are, is] = proposed ? ['With this action', 'there would be', 'would be'] : ['With this stub', 'there are', 'is'];
  const message = Object.hasOwn(limit, 'count')
    ? `${With} ${are} ${total} such actions in ${periodWords(limit.per)}. ${W} allows ${limit.count}.`
    : `${With} the total in ${periodWords(limit.per)} ${is} ${total} ${limit.unit}. ${W}'s limit is ${limit.max} ${limit.unit}.`;
  return { code: 'over-period-limit', message };
}

// The words for what a stub is compared with: a slip, the pass a helper
// acts under, or a pass further up, from which that pass was handed on.
function wordsFor(what) {
  if (what === 'pass') return ['The pass', 'the pass'];
  if (what === 'earlier-pass') return ['The earlier pass', 'the earlier pass'];
  return ['The slip', 'the slip'];
}

/**
 * Once every stub under a slip, or under a pass, has been read: settle its
 * limits "in any period". Each stub whose period holds more than the limit
 * allows is given the finding. It can be done only at the end, because a
 * stub further on in the book may be dated earlier (see periodTotals).
 *
 * The findings are not put into the stubs' own lists, which stay as they
 * are: they are gathered in "late", each list under the stub's own list.
 * So the same stubs can be settled again after more have been read.
 *
 * @param {any} s the slip's content, or a pass written in the same form
 * @param {ReturnType<typeof newTally>} tally
 * @param {Map<object[], {code: string, message: string}[]>} late where the findings are gathered
 */
export function settlePeriods(s, tally, late) {
  const over = (b) => b.code === 'over-period-limit';
  for (const [i, items] of tally.periods) {
    const limit = s.limits[i];
    const allowed = allowedIn(limit);
    for (const { item, total } of periodTotals(items, limit.per * 1000)) {
      if (!(total > allowed)) continue;
      let found = late.get(item.late);
      if (!found) late.set(item.late, (found = []));
      // A pass does not repeat a finding that the slip, or a pass before it, gave for the stub.
      if (item.what !== 'slip' && (item.late.some(over) || found.some(over))) continue;
      found.push(overPeriod(limit, total, item.W));
    }
  }
}

/**
 * Describe a limit in words, for people.
 * @param {any} limit a limit that has passed the slip's check
 * @returns {string}
 */
export function limitWords(limit) {
  const period = Object.hasOwn(limit, 'per') ? ` in ${periodWords(limit.per)}` : ' in total';
  if (Object.hasOwn(limit, 'each')) return `${limit.action}: no single action above ${limit.each} ${limit.unit}`;
  if (Object.hasOwn(limit, 'count')) return `${limit.action}: no more than ${limit.count} ${limit.count === 1 ? 'action' : 'actions'}${period}`;
  return `${limit.action}: no more than ${limit.max} ${limit.unit}${period}`;
}

/**
 * Describe a condition ("requires") in words, for people.
 * @param {any} r a condition that has passed the slip's check
 * @returns {string}
 */
export function conditionWords(r) {
  const what = r.need === 'approval' ? 'needs the person\'s own approval' : 'needs the other side\'s countersignature';
  const above = Object.hasOwn(r, 'above') ? ` above ${r.above} ${r.unit}` : '';
  return `${Object.hasOwn(r, 'action') ? r.action : 'every action'}: ${what}${above}`;
}

/**
 * Describe one name of a "never" list in words, for people.
 * @param {string} name a name that has passed the slip's check
 * @returns {string}
 */
export function neverWords(name) {
  if (Object.hasOwn(CONDUCT_RULES, name)) return CONDUCT_RULES[name];
  return `Never do an action of the kind "${name}": ${ACTION_KINDS[name].charAt(0).toLowerCase()}${ACTION_KINDS[name].slice(1)}`;
}

/**
 * Compare one stub, or one action that is only proposed, with its slip.
 *
 * @param {any} s the slip's content
 * @param {ReturnType<typeof newTally>|null} tally the slip's running state, or null when only single pages are at hand
 * @param {any} c the stub's content: "action", "when", and where present "amount" and "with"
 * @param {object} facts
 * @param {any} [facts.service] the service in the slip that the stub names, if it names one the slip knows
 * @param {any} [facts.terms] the content of the service's terms the stub relies on, if any
 * @param {boolean} [facts.cancelled] whether the slip was cancelled earlier in the book
 * @param {'slip'|'pass'|'earlier-pass'} [facts.what] what "s" is: a slip, or a pass written in the same form
 * @param {{code: string, message: string}[]} [facts.late] where a finding that can be made only once every stub
 *   has been read is to be put (see settlePeriods). Without it, such a finding joins the list this call returns.
 * @param {boolean} [commit] false to leave the running state as it was (a check before acting)
 * @returns {{breaches: {code: string, message: string}[], needs: string[], running: object|undefined}}
 *   "needs" lists what the slip asks to go with this action: "countersignature", "approval"
 */
export function compareWithSlip(s, tally, c, facts, commit = true) {
  // The same comparison is made with a pass: the messages then say so.
  const [W, w] = wordsFor(facts.what);
  const breaches = [];
  const when = parseTime(c.when);

  // A limit "in any period". While a book is read, the stub is only noted,
  // and the limit is settled once every stub has been read (settlePeriods).
  // A check before acting works it out at once, for the proposed action.
  const inPeriod = (i, limit, value) => {
    const items = tally.periods.get(i) ?? [];
    if (commit) {
      tally.periods.set(i, items);
      items.push({ when, value, W, what: facts.what ?? 'slip', late: facts.late ?? breaches });
      return;
    }
    const worst = periodWith(items, when, limit.per * 1000, value);
    if (worst > allowedIn(limit)) breaches.push(overPeriod(limit, worst, W, true));
  };

  if (!s.actions.includes(c.action)) {
    breaches.push({ code: 'action-not-allowed', message: `${W} does not allow the action "${c.action}".` });
  }
  const kind = actionKind(c.action);
  if (facts.cancelled) {
    breaches.push({ code: 'after-cancellation', message: 'The person cancelled the slip before this action.' });
  }
  if (kind && s.never.includes(kind)) {
    breaches.push({ code: 'prohibited', message: `${W} says the agent must never do an action of the kind "${kind}", and "${c.action}" is of that kind.` });
  }
  if (Object.hasOwn(c, 'with') && !facts.service) {
    breaches.push({ code: 'party-not-allowed', message: `${W} does not name "${c.with}" as someone the agent may deal with.` });
  }
  if (when < parseTime(s.validFrom) || when >= parseTime(s.validUntil)) {
    breaches.push({ code: 'outside-valid-time', message: `The action is dated outside the time ${w} allows.` });
  }
  if (facts.terms) {
    const t = facts.terms;
    if (!t.accepts.includes(c.action)) {
      breaches.push({ code: 'outside-terms', message: `The service's terms for agents do not accept the action "${c.action}".` });
    } else if (when < parseTime(t.validFrom) || when >= parseTime(t.validUntil)) {
      breaches.push({ code: 'outside-terms', message: 'The action is dated outside the time the service\'s terms for agents were in force.' });
    }
  }

  // Amounts. Every amount limit for one action is in one unit (the slip's
  // check makes sure of it), so a stub is asked for its amount once.
  let missing = false;
  const amountIn = (unit) => {
    if (c.amount && c.amount.unit === unit) return true;
    if (!missing) {
      breaches.push({ code: 'amount-missing', message: `${W} sets a limit or a condition in "${unit}" for this action, and the ${commit ? 'stub' : 'action'} gives no amount in that unit.` });
      missing = true;
    }
    return false;
  };

  let running;
  s.limits.forEach((limit, i) => {
    if (limit.action !== c.action) return;
    const periodMs = Object.hasOwn(limit, 'per') ? limit.per * 1000 : null;
    if (Object.hasOwn(limit, 'count')) {
      if (!tally) return; // a single page cannot show a count
      if (periodMs === null) {
        const n = (tally.counts.get(i) ?? 0) + 1;
        if (commit) tally.counts.set(i, n);
        if (n > limit.count) {
          breaches.push({ code: 'over-count-limit', message: `${commit ? 'This is' : 'This would be'} action number ${n} of this kind under ${w}. ${W} allows ${limit.count}.` });
        }
      } else {
        inPeriod(i, limit, 1n);
      }
      return;
    }
    if (!amountIn(limit.unit)) return;
    const value = BigInt(c.amount.value);
    if (Object.hasOwn(limit, 'each')) {
      if (value > BigInt(limit.each)) {
        breaches.push({ code: 'over-each-limit', message: `This action is ${value} ${limit.unit}. ${W} allows no single action above ${limit.each} ${limit.unit}.` });
      }
    } else if (periodMs === null) {
      if (tally) {
        const total = (tally.sums.get(i) ?? 0n) + value;
        if (commit) tally.sums.set(i, total);
        running = { action: c.action, unit: limit.unit, total: total.toString(), max: limit.max };
        if (total > BigInt(limit.max)) {
          breaches.push({
            code: 'over-limit',
            message: `${commit ? 'With this stub the total is' : 'With this action the total would be'} ${total} ${limit.unit}. ${W}'s limit is ${limit.max} ${limit.unit}: over by ${total - BigInt(limit.max)}.`,
          });
        }
      } else if (value > BigInt(limit.max)) {
        // A single page cannot show a running total, but it can show a stub
        // that passes the limit all by itself.
        breaches.push({ code: 'over-limit', message: `This stub alone is ${value} ${limit.unit}. ${W}'s limit is ${limit.max} ${limit.unit} in total.` });
      }
    } else if (tally) {
      inPeriod(i, limit, value);
    } else if (value > BigInt(limit.max)) {
      breaches.push({ code: 'over-period-limit', message: `This stub alone is ${value} ${limit.unit}. ${W}'s limit is ${limit.max} ${limit.unit} in ${periodWords(limit.per)}.` });
    }
  });

  // What the slip asks to go with this action.
  const needs = [];
  for (const r of s.requires) {
    if (Object.hasOwn(r, 'action') && r.action !== c.action) continue;
    if (Object.hasOwn(r, 'above')) {
      if (!amountIn(r.unit)) continue;
      if (!(c.amount.value > r.above)) continue;
    }
    if (!needs.includes(r.need)) needs.push(r.need);
  }

  return { breaches, needs, running };
}
