// Provared, draft version 0: proof of what an AI agent was allowed to do,
// and what it then did. Evidence, not a verdict.
//
// Checking:  checkBook, checkShow, checkSlip
//            openChecker (a checker that is carried on as the book grows)
//            checkBefore (would this action be outside the slip?)
// Beside an agent: openRecorder (ask first, act, write the stub),
//            recordTools (the agent's tools, each behind the stub writer)
// Writing:   prepareSlip + assembleSlip (the person, with a passkey),
//            prepareApproval + assembleApproval (the person's yes to one action),
//            writeStub (the agent), countersign, writeRefusal, writeTerms
//            (the service), writeSeal (whoever keeps the book), blockStampItem
//            (a proof from a public blockchain, to put beside a seal),
//            writeWitness (a witness signs for a seal), openWitness (a witness
//            that signs only for a seal that extends the last one it holds),
//            openSealer (a central sealer, which seals books it is sent only
//            the leaf fingerprints of: leafFingerprint),
//            prepareCancellation + assembleCancellation (the person ends a slip),
//            writeAcknowledgement (the agent's side says it was handed a cancellation),
//            writeDenial (the agent's side says it did not take an action, and why),
//            writeVouching, writeWithdrawal (an organisation vouches for a name),
//            writePass (an agent hands part of its permission to a helper agent),
//            writeBook, makeShow
// Keys:      generateKeySet, generateSealKeySet, thumbprint, keySetFingerprint,
//            signerFromKey (a key in memory as a signer: wherever "privateKeys"
//            is taken, each item may be a key or a signer, an object with
//            "key" and "sign", for a key held elsewhere)
// Names:     the shared list of actions, the kinds of action, the rules of conduct;
//            the reserved document names, and the fingerprints they stand for

export * from './check.js';
export { checkBefore } from './guard.js';
export { openRecorder } from './recorder.js';
export { recordTools, argumentsFingerprint, NotTaken } from './tools.js';
export { prepareSlip, assembleSlip, COVERABLE } from './slip.js';
export { prepareApproval, assembleApproval } from './approval.js';
export { writeStub, countersign } from './stub.js';
export { writeRefusal, writeTerms } from './service.js';
export { writePass } from './pass.js';
export { writeSeal } from './seal.js';
export { writeWitness, MAX_WITNESSES } from './witness.js';
export { openWitness, bookIdentity, witnessProof } from './witnessing.js';
export { openSealer, leafFingerprint } from './sealer.js';
export { consistencyProof, inclusionPath } from './tree.js';
export { blockStampItem } from './blockstamp.js';
export { prepareCancellation, assembleCancellation, writeAcknowledgement, writeVouching, writeWithdrawal, VOUCHED_KINDS } from './standing.js';
export { writeDenial, denialCodes, FINDING_CODES } from './denial.js';
export { entryLine, writeBook, makeShow } from './book.js';
export { generateKeySet, generateSealKeySet, signerFromKey } from './signatures.js';
export { ACTION_KINDS, SHARED_ACTIONS, CONDUCT_RULES, RESERVED_PREFIX, actionKind } from './actions.js';
export { DOCUMENT_NAMES, RESERVED_DOCUMENT_PREFIX, httpRequestFingerprint, httpResponseFingerprint, identifierFingerprint } from './documents.js';
export { fingerprint, formatTime, randomId, toBase64url, fromBase64url, utf8, sha256 } from './encoding.js';
