// The shared list of action names, the kinds of action, and the rules of
// conduct a slip can state. Format description, section 16.
//
// This is a first draft, written before real agents have used it. Anyone may
// go on using action names of their own; names that begin "provared." are
// reserved for this list.

/** Every action name that begins with this is reserved for the shared list. */
export const RESERVED_PREFIX = 'provared.';

/** The kinds of action. Each shared action belongs to exactly one. */
export const ACTION_KINDS = {
  reads: 'Looks at data without changing it.',
  changes: 'Creates or changes data in a way that can be put back.',
  destroys: 'Removes data or a resource in a way that may not be put back.',
  sends: 'Sends a message or data to a person, to the public or to another system.',
  commits: 'Binds the person to something: an order, a booking, an agreement, an account.',
  grants: 'Gives someone or something access or permission.',
  runs: 'Runs a program or a command.',
  enters: 'Signs in to a system or an account.',
};

/** The shared actions: name, kind, and what the name means. */
export const SHARED_ACTIONS = {
  'provared.data.read': ['reads', 'Read stored data or a file.'],
  'provared.data.search': ['reads', 'Search stored data.'],
  'provared.data.create': ['changes', 'Create a new item of data or a new file.'],
  'provared.data.change': ['changes', 'Change an item of data or a file that exists.'],
  'provared.data.delete': ['destroys', 'Delete data or a file.'],
  'provared.data.export': ['sends', 'Copy data out of the system that keeps it.'],
  'provared.message.read': ['reads', 'Read messages.'],
  'provared.message.draft': ['changes', 'Write a message without sending it.'],
  'provared.message.send': ['sends', 'Send a message to a person.'],
  'provared.post.publish': ['sends', 'Publish something where the public can see it.'],
  'provared.calendar.read': ['reads', 'Read a calendar.'],
  'provared.calendar.change': ['changes', 'Add, move or remove an entry in a calendar.'],
  'provared.booking.make': ['commits', 'Book a place, a time or a service.'],
  'provared.booking.cancel': ['commits', 'Cancel a booking.'],
  'provared.order.place': ['commits', 'Place an order for goods or services.'],
  'provared.order.cancel': ['commits', 'Cancel an order.'],
  'provared.terms.accept': ['commits', 'Accept terms, or sign an agreement.'],
  'provared.form.submit': ['commits', 'Submit a form or an application.'],
  'provared.account.create': ['commits', 'Open an account.'],
  'provared.account.sign-in': ['enters', 'Sign in to an account or a system.'],
  'provared.access.grant': ['grants', 'Give a person or a program access.'],
  'provared.access.remove': ['changes', 'Take access away from a person or a program.'],
  'provared.key.create': ['grants', 'Make a key or a password that gives access.'],
  'provared.code.read': ['reads', 'Read the source of a program.'],
  'provared.code.change': ['changes', 'Change the source of a program.'],
  'provared.code.run': ['runs', 'Run a program or a command.'],
  'provared.code.release': ['runs', 'Put a program into live use.'],
  'provared.system.configure': ['changes', 'Change the settings of a system.'],
  'provared.web.read': ['reads', 'Read a public web page.'],
  'provared.agent.instruct': ['sends', 'Hand a task to another agent.'],
};

/**
 * The rules of conduct a slip can state. They are the person's signed
 * instruction. No check of a record can show that an agent kept them.
 */
export const CONDUCT_RULES = {
  impersonate: 'Never claim to be a human being, or to be anyone other than the agent of the person who signed the slip.',
  bypass: 'Never go around an access control, a block or a refusal.',
  escalate: 'Never obtain or use access that it was not given.',
  conceal: 'Never hide, alter or leave out its own records.',
  deceive: 'Never state what it has reason to believe is false, and never make up a record or a result.',
  harass: 'Never threaten, pressure or attack a person.',
  disclose: 'Never pass information that is not public to anyone the slip does not name.',
  'continue-after-stop': 'Never carry on after being told to stop.',
};

/**
 * The kind of a shared action, or null for a name that is not on the shared
 * list (a name of the writer's own).
 * @param {string} name
 * @returns {string|null}
 */
export function actionKind(name) {
  return typeof name === 'string' && Object.hasOwn(SHARED_ACTIONS, name) ? SHARED_ACTIONS[name][0] : null;
}

/** Whether a name may stand in a "never" list: a kind of action, or a rule of conduct. */
export function isNeverName(name) {
  return typeof name === 'string' && (Object.hasOwn(ACTION_KINDS, name) || Object.hasOwn(CONDUCT_RULES, name));
}

/** Whether an action name is reserved and not on the shared list. */
export function isUnknownReserved(name) {
  return typeof name === 'string' && name.startsWith(RESERVED_PREFIX) && !Object.hasOwn(SHARED_ACTIONS, name);
}
