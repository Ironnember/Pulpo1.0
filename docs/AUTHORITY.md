# External approval authority

## Implemented contract

`ApprovalEnvelope` defines the exact material an external human-approval service
must sign:

- schema and authority identifier;
- approval and session identifiers;
- principal;
- exact intent hash;
- exact canonical policy hash;
- nonce and expiration.

`GovernanceKernel` receives an `ApprovalVerifier` when the trusted kernel is
constructed. The governed caller cannot supply a verifier to
`evaluate_with_approval()`. The caller-controlled approval boolean has been
removed from `evaluate()` for every kernel, including kernels with no verifier.
Approval-gated actions therefore have no alternate permit-issuance path.

The session is part of the canonical `Intent`, and the kernel checks envelope
expiry using its bootstrapped clock. The approval call accepts neither a session
override nor a timestamp override. Domain-purchase intents derive their session
from the bounded request identifier.

Approval IDs and nonces are consumed atomically when a permit is issued. With
`SQLiteKernelState`, those replay guards, the permit, and the canonical audit
records survive restart together. Signature failure, binding mismatch, expiry,
replay, missing verifier, and verifier exceptions all fail closed and append
approval evidence to the same audit chain.

## What this proves

The tests prove envelope binding, configured-verifier routing, replay rejection,
permit issuance after successful verification, removal of the boolean bypass,
trusted-clock expiry, and malformed-envelope denial. The SQLite proof reopens
the same state and proves consumed approval IDs, nonces, and permits remain
unusable, while persisted audit tampering blocks kernel bootstrap. The commerce
proof uses this path but its budget state remains in memory.

## Boundary still open

This repository deliberately contains no production signer or private authority
material. Test verifiers are test doubles, not human authentication.

Independent authority requires deployment evidence that:

1. the signer/private credential exists outside the governed workspace and is
   unreadable by the worker principal;
2. the agent cannot replace or reconfigure the verifier on the trusted running
   kernel;
3. the authority authenticates the human, preferably with a passkey and required
   user verification;
4. trusted bootstrap prevents the worker from replacing the kernel clock,
   intent session, verifier, nonce policy, or expiry policy;
5. the SQLite state file is protected from the governed worker and operated with
   deployment-grade backup and recovery evidence;
6. verifier public material and configuration are pinned and auditable;
7. signer failure remains fail closed.

Until that deployment exists, claim **externally-verifiable approval-envelope
semantics**, not independently human-authenticated authority.
