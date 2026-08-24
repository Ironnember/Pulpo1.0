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
`evaluate_with_approval()`. A configured verifier also disables the legacy
caller boolean for approval-gated actions, closing that alternate issuance path
within the configured kernel instance.

Approval IDs and nonces are consumed when a permit is issued. Signature failure,
binding mismatch, expiry, replay, missing verifier, and verifier exceptions all
fail closed and append approval evidence to the canonical audit chain.

## What this proves

The tests prove envelope binding, configured-verifier routing, replay rejection,
permit issuance after successful verification, and fail-closed behavior in one
running process. The commerce proof uses this path rather than `approved=True`.

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
4. the approval service supplies its own trusted clock, session binding, nonce,
   and expiry;
5. consumed approvals and permits survive restart transactionally;
6. verifier public material and configuration are pinned and auditable;
7. signer failure remains fail closed.

Until that deployment exists, claim **externally-verifiable approval-envelope
semantics**, not independently human-authenticated authority.
