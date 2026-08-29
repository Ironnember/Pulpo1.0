# Hostile Worker Consequence Proof V0 — Frozen Contract

Status: PROPOSED / FROZEN BEFORE IMPLEMENTATION

Source design issue: #82 — `Design freeze: Hostile Worker Consequence Proof V0`

Admitted canonical base: `1209b7a3666e928e6a0bcfcb34be0334666a6718`

PR #80 admission evidence:
- exact reviewed head: `6b8836ae89b5211d5d1aff07771765c6a04123b0`;
- independent collaborator approval on that exact head;
- CI run #214 passed;
- merge commit above is the base for this experiment.

## Purpose

Prove one real bounded external domain consequence while the worker is treated as malicious.

The governing question is:

> Where does authoritative governance truth live when the worker can lie, fork, race, crash, replay, and roll back its local state?

## Constitutional architecture

`multiple bounded governance components -> one authoritative transition protocol -> one monotonically advancing governance truth`

`ONE_TRUTH != ONE_GOD_OBJECT`

`LOCAL_STATE != AUTHORITY`

`PERSISTENCE != PROTECTED_CUSTODY`

`PERMIT != EXACTLY_ONCE_REALITY`

`EXECUTOR_REPORT != ACCEPTED_CONSEQUENCE`

`CUSTODY_LOSS -> FAIL_CLOSED_OR_EXPLICIT_UNCERTAINTY`

`HOSTILE_WORKER_PROOF != HOSTILE_CUSTODIAN_PROOF`

A worker may cache references and observations. Cached state cannot authorize a consequence.

## V0 threat model

Treat as malicious or arbitrarily incorrect:
- model/intelligence process;
- worker/coordinator process;
- worker filesystem/database/cache;
- worker-reported time;
- worker-reported execution result;
- worker-retained permit/approval/directive copies;
- duplicate/forked worker instances;
- worker network behavior, including duplicate submission and lost responses.

Assume trustworthy for V0:
- governance custody runtime and protected persistence;
- custody signing/key material;
- existing independent approval authority/verifier trust;
- bounded executor credential boundary;
- independent reconciliation/observation path.

V0 does not claim security against compromise or rollback of the governance custodian itself.

## Execution claim

The strongest allowed execution claim is:

> One permit -> at most one authorized execution attempt.

Not:

> One permit -> exactly one external consequence.

A transmitted provider request with insufficient independent evidence must enter `RECONCILIATION_REQUIRED` or `UNRESOLVED`. It must not be automatically retried or silently classified as success/failure.

## Frozen acceptance conditions

The implementation fails V0 if any required condition fails.

### A — Fork / replay

Fork the worker before permit/attempt consumption. Two copies using the same target and cached capability material must not produce two authoritative attempt authorizations or two legitimate provider transmissions.

### B — Worker rollback

Restore an old worker filesystem/cache after authority has advanced. Old budget, permit, approval, directive, or audit projections must not regain authority.

### C — Time lie

Worker-supplied stale/future/fabricated time must not affect authority validity. A worker clock rollback must not extend approval, directive, permit, quote, or order validity.

### D — Two-worker race

Concurrent requests for the same exact target/reservation must serialize at custody. At most one legitimate execution attempt may be created.

### E — Directive revocation race

If the exact directive is revoked after permit issuance but before attempt authorization/consumption, live custody revalidation must deny the stale worker.

### F — Crash before provider transmission

No success may be fabricated. Recovery must not manufacture an extra capability or provider effect.

### G — Crash or lost response after provider transmission

No automatic second attempt. Authoritative state must record that the consequence may have occurred and require reconciliation.

### H — Fabricated local success

A worker-supplied fake receipt/success may be retained only as untrusted evidence input. It cannot mark the consequence accepted.

### I — Local evidence corruption

Deleting, corrupting, or rolling back worker-local audit/evidence must not move canonical custody state backward or replace the current governance head.

### J — Custody unavailable

A disconnected worker possessing cached permits, approvals, directives, balances, or targets must not fall back to local authority or start a new consequential attempt.

## Minimum V0 custody properties

- worker has no write access to authoritative custody persistence;
- worker has no custody signing secret;
- authority-relevant transitions use compare-and-swap against one monotonic governance head;
- governance epoch strictly increases;
- stale epoch/root is rejected rather than merged;
- custody-side time is the only authority time input;
- custody clock rollback fails closed;
- copied permit/reference material is insufficient without live custody transition;
- one executor claim per attempt;
- provider credentials are unavailable to the hostile worker;
- worker/executor success is never accepted without independent reconciliation.

## PR #83 admission invariants

These are **Proposed** until their executable denial/restart proofs pass.

### AUTHORIZED_OBJECT_ORIGIN

> A consequential object may enter authority evaluation only by reference to an unexpired trusted `ProposalCommitment`. Reconstructing identical bytes outside that commitment does not confer provenance.

The trusted Name.com sandbox proposal path is:

`domain -> trusted provider observation -> exact ProposalCommitment -> independent approval -> attempt`

A minimal `ProposalCommitment` binds:
- commitment identity and digest;
- exact order hash;
- trusted provider availability/observation hash;
- custody creation time;
- expiry;
- custody provenance needed to validate the commitment.

The hostile-worker API must not accept a caller-originated full consequential order. The worker may choose the normalized domain and carry an opaque proposal reference, approval envelope, and opaque attempt handle. Full-order methods may exist only behind the trusted internal boundary.

Required negative proof:

> Construct a byte-identical `DomainPurchaseOrder` outside custody with no valid proposal commitment. Authorization must fail before permit issuance or budget reservation.

### ACCOUNTABLE_TRANSITION

> Every consequential custody mutation atomically creates a durable canonical-evidence obligation. Authority cannot advance past an unresolved obligation. Projection is restart-safe and idempotent by custody transition hash.

The required transaction is:

`custody mutation + EvidenceObligation(transition_hash, receipt_material) -> COMMIT`

The obligation is not a second evidence ledger. It records that the existing canonical Pulpo evidence chain has not yet caught up with an already committed custody transition.

Projection requirements:
- projection target is the existing canonical Pulpo audit/evidence path;
- projection identity is the custody `transition_hash`;
- duplicate projection yields exactly one canonical custody-transition event;
- a pending obligation blocks any later consequential custody transition;
- a malformed, tampered, or transition-hash-mismatched obligation fails closed and remains pending;
- clearing the obligation is allowed only after canonical projection succeeds.

Required crash/restart proofs:

1. crash before custody commit -> neither custody mutation nor evidence obligation exists;
2. crash after custody/outbox commit but before canonical projection -> restart detects the obligation and blocks subsequent consequential advancement until projection;
3. crash during projection -> restart retries safely;
4. duplicate projection -> exactly one canonical custody-transition event;
5. tampered or mismatched receipt/transition hash -> projection denied and custody remains unable to advance.

## Admission ceremony path

Only the strongest path may count as PR #83 admission evidence:

`domain only`
`-> custody trusted discovery/quote`
`-> ProposalCommitment`
`-> custody-generated authority request`
`-> independently signed approval envelope`
`-> authorization by proposal reference`
`-> one custody-authorized provider transmission`
`-> independent provider observation`
`-> reconciliation`
`-> restart/replay denial`

Any harness that constructs its own request/quote/order, bypasses the independent approval requirement, or calls a weaker direct-order path is stale proof infrastructure and **must not count** toward admission.

## PR #83 scope freeze

Do not add:
- a learning system;
- another policy engine;
- another custody authority abstraction;
- another evidence ledger;
- broader provider support;
- unrelated model, voice, public-lab, retention, sector, or orchestration features.

Only the following work is in scope before the external ceremony:

1. `ProposalCommitment` provenance and worker-surface removal of arbitrary full orders;
2. transactional evidence obligation plus restart-safe idempotent canonical projection;
3. replacement/retirement of the stale sandbox ceremony harness;
4. required admission checks for `hostile-worker-custody` and `hostile-worker-container-isolation`;
5. exact-head freeze, independent review, sandbox ceremony, restart/replay, and final evidence bundle.

## Proof discipline

Do not weaken this contract after observing results.

Do not introduce:
- a second policy engine;
- a second approval authority;
- a second evidence ledger;
- a general-purpose execution gateway;
- distributed consensus merely for V0;
- a broad scheduler or agent-swarm subsystem;
- unrelated model, voice, public-lab, retention, or market features.

The final V0 proof is incomplete until these frozen conditions are exercised against one real low-risk bounded domain consequence with external observation and reconciliation.
