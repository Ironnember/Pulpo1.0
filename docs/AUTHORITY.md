# Pinned external approval authority

## Implemented contract

`AuthorityTrust` defines public trust fixed in policy before governed work
begins: authority, verifier, key identifier, algorithm, public-key fingerprint,
deployment identifier, and maximum approval lifetime. The complete descriptor
is hash-bound into canonical policy.

Approval envelope v2 defines the exact material an external human-approval
service must sign:

- schema, authority, verifier, key, deployment, and trust hash;
- approval and session identifiers;
- principal;
- exact intent hash;
- exact canonical policy hash;
- nonce, issue time, and expiration.

`GovernanceKernel` receives an `ApprovalVerifier` when the trusted kernel is
constructed. Its metadata must match policy trust at bootstrap and evaluation.
The governed caller cannot supply a verifier to `evaluate_with_approval()`.
The caller-controlled approval boolean has been removed from `evaluate()` for
every kernel, including kernels with no verifier. Approval-gated actions
therefore have no alternate permit-issuance path.

The session is part of canonical `Intent`. The kernel checks issue time,
maximum lifetime, expiry, and rollback using its bootstrapped clock before and
after verification. The approval call accepts neither a session override nor a
timestamp override. Domain-purchase intents derive their session from the
bounded request identifier.

The optional verification-only `Ed25519ApprovalVerifier` accepts one raw public
key and exposes no signer or private-key API. It uses the reviewed
`cryptography` package through the optional `pulpo[authority]` extra; the base
kernel remains dependency-free.

Approval IDs and nonces are consumed atomically when a permit is issued. With
`SQLiteKernelState`, those replay guards, the permit, and the canonical audit
records survive restart together. Signature failure, trust/key/deployment
mismatch, issue-time or lifetime failure, expiry, replay, missing or untrusted
verifier, non-boolean verification, clock rollback, and verifier exceptions all
fail closed and append public approval evidence to the same audit chain.

## What this proves

The tests prove trust and public-key pinning, envelope binding, configured-
verifier routing, Ed25519 verification, key substitution denial, replay
rejection, permit issuance after successful verification, removal of the
boolean bypass, bounded trusted-clock semantics, and malformed-envelope denial.
The SQLite proof reopens the same state and proves consumed approval IDs,
nonces, and permits remain unusable, while persisted audit tampering blocks
kernel bootstrap. Concurrent presentation of one approval allows exactly once.
The commerce proof uses this path but its budget state remains in memory.

## Boundary still open

This repository deliberately contains no production signer or private authority
material. Test signers are test fixtures, not human authentication or signer-
separation evidence. Python object checks do not protect bootstrap from a
hostile worker that can rebuild or mutate the running kernel.

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
   deployment-grade rollback, backup, and recovery evidence;
6. verifier public material and configuration are deployed from a protected,
   auditable bootstrap rather than merely represented by the policy contract;
7. signer failure remains fail closed.

Until that deployment exists, claim **externally-verifiable approval-envelope
semantics with pinned asymmetric trust**, not independently human-authenticated
authority.

See [the independent authority proof gate](INDEPENDENT_AUTHORITY_PROOF.md) for
the mandatory external acceptance tests and owner-authorized choices.
