# SQLite operational connection cleanup candidate

Status: local candidate, not published, admitted, deployed or independently
approved. Base: PR #306 at `d11d713d62f412559dc028b2cbb48a9793c4221c`.
Canonical main observed separately: `dc563a089dbd9e67d6d81518d21c36916a62ec7b`.

## Problem and behavior

SQLite connection contexts commit or roll back; they do not close connections.
The evidence projection store and proposal commitment store used that context
alone for short-lived operations. Both now close after the existing transaction
context exits, and close on failed connection configuration. Existing SQL,
transaction boundaries, authority decisions, hashes, schemas and signatures are
unchanged. Eight adjacent fixture connections and two migration-test
connections also close explicitly.

## Required change record

1. Invariant: operation-owned connections close on return and failure without
   weakening denial, commit, rollback, provenance or replay behavior.
2. Authority gained: none. No new route, signer, enrollment, provider access or
   authority source. Existing custodians retain their existing trust boundary.
3. Canonical mutations: none introduced or exposed. Existing proposal claims,
   custody transitions and canonical evidence projections retain the same
   governed owners and SQL. Connection lifetime is narrowed.
4. Evidence: an external connection tracker found 38 open connections after
   118 qualification executions on the base (32 operational and six fixture
   connections). Five additional open connections in the new-head proposal
   migration path and two adjacent evidence-test fixture connections were
   separately reproduced. After repair, the 124 combined qualification and
   adjacent executions leave zero tracked open connections. Five new regression
   methods produce six assertion failures, zero setup errors, against untouched
   exact-base runtime and pass against the candidate. Full-suite and tournament
   results are recorded outside source and bound to their executed revision.
5. Boundaries: no live registrar execution, physical power-loss test, protected
   deployment, whole-chat containment or independent-person review is claimed.
   Passing tests do not make the worker an authorizer.
6. Claims: local executed results are Verified within the recorded environment;
   GitHub checks/reviews are Recorded platform evidence. Admission is pending;
   production custody and independent reproduction remain Unknown.
7. Legacy: the standard-library closing pattern already used by the canonical
   budget store is reused; no parallel control mechanism is introduced.
8. Temporal: the exact pre-repair PR head is a relevant checkpoint. The same
   candidate-authored regression tests reject its leaked connections and accept
   the candidate. This establishes that bounded repair delta, not general
   transfer, model learning or retrospective authorization.

## Eight analytical passes

| Pass | Finding and disposition |
| --- | --- |
| Flip | A hostile caller can repeat failing operations; close occurs on success and exceptions, independent of caller cooperation. |
| Reverse | Transaction exit must finish before close; contexts exit in that order. |
| Invert | A passing decision with leaked resources remains a cleanup defect; baseline failures are retained. |
| Inside-Out | The tracker and regressions are caller-run evidence, not independent authority or attestation. |
| Darken | Repeated leaked handles may exhaust descriptors or retain locks; this is a plausible threat, not an observed production incident. |
| Lighten | Finalizer warnings can result from fixture leaks; those are distinguished from runtime ownership defects. |
| Amplify | Repeated calls and replay denial must still close; proposal claim/replay and evidence-query failures are exercised. |
| Negate | Explicit close uses the existing stores; no new governor, service, credential or evidence ledger is needed. |

## Review and real consequence handoff

Cold reproduction must use a clean checkout of the exact candidate commit,
Python 3.11+, full Git history plus the temporal harness's exact historical
objects, declared optional authority dependencies for the full suite, and
external output directories. Run the new cleanup regressions, the canonical
core suite, and the unchanged repository-native tournament. Inspect every log,
skip, failure and source hash. An artifact hash is integrity metadata, not an
independent signature.

The observed main ruleset requires one approving review, latest-push approval,
stale-review dismissal, resolved review threads, and strict `test`, `authority`,
and `authority-service` checks. Other admission controls may apply; the legacy
branch-protection read returned 403. Older PR approvals are not approvals of
this local repair. No protection adjustment is proposed to satisfy a check.

The existing external path is
`scripts/run_hostile_worker_namecom_ceremony.py`, a sandbox-only custody client.
The older sandbox script is retired and intentionally exits without executing.
Do not replace independent approval with test HMAC fixtures or direct orders.
Do not treat a sandbox result as a paid production purchase.

Before provider entry, independently verify a deployed authority service with
protected durable replay/revocation state, append-only evidence, non-exportable
signer and enrolled approved authenticator; a separately protected custody
runtime; distinct executor and observer credentials that stay outside worker
custody; pinned service identities and origins; and a legitimate exact object,
price limits, destination, identity, session, expiry and permit. These deployed
prerequisites are not established by this candidate. No credential should be
provided to the model to fill the gap.

Acceptance sequence: no approval, revoked approval and substituted object each
produce zero transmissions; one valid exact approval produces one permitted
sandbox action; replay and restart/replay produce zero additional actions;
direct-worker provider access and credentials are unavailable; independent
observation binds receipt/object/version and reconciles through the existing
canonical chain. Retain unknown outcomes without automatic retry. Capture
sanitized action identity, requested/observed prices and renewal state,
transmission count, permit and receipt hashes, independent observation,
reconciliation classification, and unresolved limits.

This handoff is a bounded plan and review package, not a deployment permit.
