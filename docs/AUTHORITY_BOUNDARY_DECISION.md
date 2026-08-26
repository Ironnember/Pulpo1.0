# Authority Boundary Decision

Status date: 2026-08-26

Decision status: **Recorded — owner authorized, not deployed**

Austin Irvan authorized the recommended independent-authority architecture for
Pulpo. The machine-readable decision is
[`docs/governance/authority-boundary-v1.json`](governance/authority-boundary-v1.json).
This authorization selects the architecture; it is not credential enrollment,
deployment evidence, or proof that the boundary is operating.

## Selected boundary

### Primary authority

- One founder-controlled, single-device hardware WebAuthn credential.
- User presence and user verification are required for every approval.
- The primary credential is not backup-eligible or cloud-synced.
- Hardware attestation is required; approved models are selected before
  enrollment.

The separate recovery credential makes cloud synchronization unnecessary for
the primary credential. A future multi-operator deployment must replace the
single-founder rule with an independently authorized quorum policy.

### Recovery authority

- One separate hardware WebAuthn credential stored offline.
- It cannot approve ordinary Pulpo intents.
- It may enter only the credential-recovery ceremony.
- Successful recovery revokes the superseded credential set and requires a new
  offline recovery credential before normal authority resumes.

### External authority service

The WebAuthn relying party and approval signer run in a trust domain outside the
governed worker. The worker may submit an exact approval request and poll for a
completed approval envelope. It may not access raw signing, enrollment,
rotation, recovery, revocation, trust configuration, or private key material.

The service verifies exact origin, RP ID, challenge, credential, user presence,
user verification, allowed hardware class, and current credential status before
it signs `pulpo.approval.v2`. The service signing key is non-exportable and is
not a WebAuthn credential: WebAuthn authenticates the human; the service key
signs the exact Pulpo envelope after that authentication succeeds.

### Time, replay, and evidence

- Approval issue time and a monotonic approval sequence are service-owned.
- Authority replay and revocation state are protected outside the worker.
- Pulpo retains privacy-minimized public hashes in its canonical audit chain.
- Complete WebAuthn assertions and authority signatures are retained in a
  separate append-only evidence store for offline verification.
- Neither evidence store contains private credential material.

## Standards basis

WebAuthn credentials are scoped to a relying party and an origin, and the
authenticator mediates operations with user consent. Pulpo therefore requires
an exact HTTPS origin, exact RP ID validation, a fresh service challenge, and
the WebAuthn user-verification flag for each authority event.

WebAuthn backup eligibility and backup state are recorded credential
properties. Pulpo's primary authority profile rejects backup-eligible
credentials; recovery is provided by a separately controlled hardware
credential instead. Signature counters are treated as a risk signal rather
than proof because conforming authenticators may keep the counter at zero.

The deployment should target phishing-resistant public-key authentication with
non-exportable keys. Recovery must not weaken normal approval authority or
become a worker-accessible bypass.

## Still unresolved by design

These values depend on the real environment and remain **Blocked** until chosen
and independently verified:

- exact RP ID and HTTPS origin;
- authority-service hosting account and isolation boundary;
- approved primary and recovery hardware authenticator models;
- external trusted-time, monotonic-state, and append-only evidence providers;
- the physical enrollment and recovery ceremony.

No placeholder may be treated as deployed configuration. Pulpo's independent
human-authority claim remains **Blocked** until the mandatory acceptance proof
passes against the exact deployed environment.
