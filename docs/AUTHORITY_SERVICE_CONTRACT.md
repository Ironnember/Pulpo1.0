# External Authority Service Contract

This is the allowed interface between a governed Pulpo worker and the
independent WebAuthn authority service. It is a boundary contract, not a signer
implementation inside Pulpo.

## Worker-visible operations

### Request approval

The worker may submit the complete unsigned `pulpo.approval.v2` payload. The
service returns an opaque request identifier and a human-facing approval URL.
The request is immutable, short-lived, deployment-bound, and single-use.
The URL identifies the request but carries no bearer authority; opening it never
approves an intent or creates a reusable authenticated session.

Submitting a request creates no authority. It records only that approval was
requested.

### Poll approval

The worker may retrieve one of:

- `pending`;
- `denied` with a non-sensitive reason class;
- `expired`;
- `approved` with the exact signed `pulpo.approval.v2` envelope.

The service never returns WebAuthn private material, recovery material, raw
signing capability, credential-management tokens, or reusable human sessions.

## Human ceremony

The human-facing origin must:

1. display the exact principal, action, resource, cost, deployment, policy hash,
   intent hash, and expiration;
2. derive a domain-separated WebAuthn challenge bound to the immutable request
   ID, Pulpo signing-payload hash, expiration, and a fresh service nonce;
3. obtain a fresh WebAuthn assertion over that challenge with user verification
   required;
4. verify exact challenge, origin, RP ID hash, credential status, user presence,
   user verification, and the approved hardware policy;
5. atomically consume the challenge and advance service-owned monotonic state;
6. sign the already displayed Pulpo envelope with the non-exportable service
   key;
7. retain the full assertion and signature bundle outside Pulpo's worker;
8. expose only the completed envelope through the poll operation.

Authentication success alone does not authorize a different or later intent.
The human ceremony and service signature must remain bound to the exact payload
that Pulpo verifies.

## Prohibited worker-visible operations

- raw sign or decrypt;
- register, enroll, import, export, or enumerate credentials;
- rotate, revoke, recover, or replace credentials;
- change RP ID, origin, approved authenticators, service key, time source,
  replay state, or trust configuration;
- approve by bearer token, API key, remembered browser session, email link,
  caller-supplied boolean, OTP, or narrative assertion;
- obtain a signature without fresh verified human participation.

Administrative and recovery ceremonies require a separately authenticated
human route that is unreachable from the governed worker identity.

## Failure semantics

Unknown request, challenge mismatch, origin mismatch, RP mismatch, missing user
verification, unapproved credential, backup-policy mismatch, revoked
credential, replay, rollback, time failure, evidence-write failure, signer
failure, or service outage returns no approval envelope. Pulpo consequently
denies the action through its existing canonical kernel path.
