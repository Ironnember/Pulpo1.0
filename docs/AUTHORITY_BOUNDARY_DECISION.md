# Authority Boundary Decision

Status date: 2026-08-27

Decision status: **Recorded — owner authorized, not deployed**

Austin Irvan authorized the recommended independent-authority architecture for
Pulpo. The machine-readable decision is
[`docs/governance/authority-boundary-v1.json`](governance/authority-boundary-v1.json).
This authorization selects the architecture; it is not credential enrollment,
deployment evidence, or proof that the boundary is operating.

On 2026-08-27, Austin Irvan separately selected the permanent WebAuthn
deployment identity and hosting class:

- exact HTTPS origin: `https://authority.pulpo.ai`;
- narrow RP ID: `authority.pulpo.ai`;
- hosting boundary: isolated managed cloud, external to `governator.local` and
  the governed worker.

This selection binds deployment identity. It does not select a cloud provider,
create DNS, provision an account, create a signer, enroll credentials, or make
the service reachable.

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

The exact origin, RP ID, and hosting class are now selected. These remaining
values depend on the real environment and remain **Blocked** until chosen and
independently verified:

- exact managed-cloud provider, account, project, region, and service identity;
- DNS control and certificate issuance for `authority.pulpo.ai`;
- approved primary and recovery hardware authenticator models;
- external trusted-time, monotonic-state, and append-only evidence providers;
- the physical enrollment and recovery ceremony.

No placeholder may be treated as deployed configuration. Pulpo's independent
human-authority claim remains **Blocked** until the mandatory acceptance proof
passes against the exact deployed environment.

## Host bound and Pulpo bound
Pulpo is only as secure as the host it is running on. The kernel, permit store, and evidence journal assume that host is still the host that was installed and that it is still enforcing process, file, and boot policy. Pulpo does not own the boot chain, firmware, NVRAM, unused or hidden partitions, storage-controller firmware, the management controller, service-account privileges, or the decision to keep operating a machine that can no longer be measured. An OS reimage, snapshot, or rollback does not restore those layers. A compromised host can skip the process, replace local state, or omit a record. That is an operator incident, not a Pulpo control failure.
Pulpo is accountable for the contract it states, on a host that is still enforcing it: unknown, incomplete, and over-budget intents fail closed; a permit is bound to one exact intent and cannot be replayed; loss of contact does not widen a grant; uncertain execution remains unknown and does not become retry authority; a visible broken audit chain fails closed. A defect in that contract is a Pulpo failure. Survival of host compromise, rollback-proof storage, trusted verifier bootstrap, network isolation, and hostile-code sandboxing are not part of that contract.
