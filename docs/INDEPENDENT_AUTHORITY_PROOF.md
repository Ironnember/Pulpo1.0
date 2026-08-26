# Independent Authority Proof Gate

Status date: 2026-08-26

## Current result

This repository now implements a **pinned asymmetric authority trust contract**.
It does not yet prove independently human-authenticated authority.

### Verified in code and tests

- `AuthorityTrust` binds authority, verifier, key identifier, algorithm, public
  key fingerprint, deployment, and maximum approval lifetime into policy.
- Approval envelope v2 binds that trust hash plus exact policy, intent,
  principal, session, nonce, issue time, and expiry.
- A configured verifier must match pinned trust at kernel bootstrap and again at
  evaluation. Key, algorithm, verifier, deployment, or trust substitution fails
  closed.
- The optional `Ed25519ApprovalVerifier` contains public verification material
  only and uses the reviewed `cryptography` package. Pulpo exposes no signing or
  private-key API.
- Verifier exceptions, non-boolean truthy results, invalid signatures, future
  issue time, excessive lifetime, expiry, clock failure, clock rollback, and
  expiry during verification deny.
- Successful authority evidence records public trust metadata and signed-payload
  hashes without storing the signature or private material in the audit chain.
- Approval ID, nonce, permit, and evidence remain atomic; concurrent use of one
  envelope produces exactly one allow result.

These are repository-level protocol and verification semantics. Ephemeral
private keys used inside asymmetric tests are test fixtures only and are not
deployment credentials or evidence of signer separation.

### Recorded

- The legacy `Iron-Ember/pulpo` independent-signer review already recorded that
  a signer or enrollment secret reachable by governed Python is not independent
  authority.
- The current package contains a verifier implementation but no signer,
  credential enrollment path, or human-authentication service.

### Blocked pending a legitimate external boundary

The following claim remains blocked until deployment evidence exists:

> A separately authenticated human principal authorized the exact action, and
> the governed worker could neither obtain nor exercise that authority itself.

## Mandatory deployment acceptance proof

The first real authority deployment must run these adversarial tests from the
governed worker identity:

1. **Private material denial:** the worker cannot read, export, derive, or infer
   signer private material.
2. **Signer invocation denial:** the worker cannot invoke a raw signing API or
   produce an approval without authenticated human presence and verification.
3. **Enrollment denial:** the worker cannot enroll, replace, rotate, or trust an
   attacker-controlled key.
4. **Authority denial:** without a legitimate human assertion, `push`,
   `policy.apply`, credential management, deployment, and consequential
   commerce remain denied.
5. **One exact success:** a legitimate external assertion authorizes one exact
   intent once; substitution, replay, expiry, restart, and verifier outage deny.

The evidence bundle must identify the exact canonical commit, deployment,
worker identity, verifier identity, public key fingerprint, policy hash, intent
hash, envelope hash, test environment, and denial/success results. It must not
contain private credentials.

## Choices requiring legitimate owner authorization

Repository work stops before making these choices on Austin Irvan's behalf:

- one founder passkey versus quorum and recovery principals;
- a passkey/WebAuthn authority service versus another hardware or managed
  signing trust domain;
- trusted time and rollback anchoring outside the governed worker;
- privacy-minimized audit hashes versus separately retained full signature
  bundles for third-party offline verification;
- actual credential enrollment, recovery, rotation, and revocation policy.

These are authority and legitimacy decisions, not routine implementation
details. Learning may recommend them; it may not authorize them.

## Prohibited shortcuts

- same-workspace HMAC or private key;
- a callable signing helper inside Pulpo;
- a second authority gateway, transaction coordinator, or replay ledger;
- home-grown cryptographic primitives;
- caller-asserted human identity or approval booleans;
- UI, narrative, screenshots, or self-supplied evidence treated as proof;
- stronger public claims before the mandatory deployment acceptance proof.
