# Protected ceremony evidence, replay counter, and worker custody — review candidate

**Status:** Proposed integration, not admitted or deployed. This document is not an approval or a permission to operate external systems.

## Exact source lineage

- Canonical main baseline: `6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`
- Human-ceremony and counter-replay branch / PR #288: `a23c7e07b21d1b9f8663822bcca6518482bd9040`
- Protected evidence reader candidate: `b5f460088f18598cbdbdb7c9f19038e0ea70cc9e`
- Hostile-agent task-injection / PR #333: `08012bf7dbeb0b7dc11ca537e90cb09d7937c4e1`

The candidate combines those reviewed *sources*, not their review decisions. No prior approval transfers authority to this new tree. Its exact final commit must be recorded in the PR.

## Invariant under test

An untrusted worker may request approval, but must receive no raw human authenticator assertion from the public approval poll. The worker sees only the envelope and `ceremony_evidence_ref` (request ID + digest). The existing trusted kernel resolves the record through a separately provisioned reader, checks hash, exact request, envelope, credential, challenge and verifier result, and requires a monotonically advancing authenticated credential counter before issuing an exact permit.

A worker's text, raw assertion, nonexistent record, substituted object, or old counter cannot create new permission.

## Source changes

- `authority-service/src/pulpo_authority_service/core.py`: only approved polls with stored evidence hash return an opaque reference; missing required evidence blocks release.
- `pulpo/ceremony.py`: canonical evidence format, digest binding and credential/challenge checks.
- `pulpo/authority_client.py` and `pulpo/orchestrator.py`: reference-only worker transport. Raw `ceremony_proof` wire fields are rejected rather than forwarded.
- `pulpo/targets.py` and `pulpo/kernel.py`: reuse exact-target resolution and canonical permit issuance; protected evidence reader refuses missing, malformed, tampered, mismatched, raw-substitution and unavailable-reader cases.
- `pulpo/state.py`: reuse the PR #288 atomic authenticator-counter/audit/approval/permit protection, including across restart; no second ledger or authority service.
- `proofs/agent-task-injection/`: retain PR #333's isolated macOS denial proof unchanged.

The old *direct kernel test interface* still supports raw synthetic proof when no protected reader is configured. That is **not** protected-worker mode. The worker-visible `AuthorityClient` no longer accepts raw assertions. A production claim requires proof that all untrusted workers have only the protected path; this source alone does not establish that.

## Current read-only / local evidence

- Focused ceremony and reader before strict transport change: 33 tests passed.
- Updated reference-only ceremony handoff plus protected reference and counter tests: 34 passed.
- Cross-candidate reference+counter conjunction focused run: 30 passed.
- Full combined Python 3.11 tests: **462 run, 459 passed, 3 skipped, zero failures**. Log `/tmp/pulpo-ref-counter-injection-full-20261026.log` SHA-256 `c5bcbf10ceccb9045a730d1df4a9ebc5d824c9aee8380ce41929a083adf75ae4`.
- The three optional Ed25519 tests passed separately with cryptography available in the existing virtual environment.
- The authority-service core passed 9 tests; service restart adapters passed 7 more. These use synthetic signers/verifiers, not a live WebAuthn human.
- The earlier PR #333 hosted macOS proof passed on its own exact revision. Hosted reproduction of the **new combined revision** must be verified separately.

## Required independent review before admission

1. Review the raw-to-reference protocol change for backward compatibility and strict failure, especially alternative callers to `GovernanceKernel.evaluate_with_approval`.
2. Inspect authenticator sign-count provenance and atomic commit under concurrency, failure, restart and persistent state corruption.
3. Verify a real protected evidence reader's identity, IAM isolation, retention and authenticated human-ceremony verification. A test reader is not capability custody.
4. Validate the human-visible approval text, trust roots, exact RP/origin, recovery/backup credential behavior and independent signer.
5. Reproduce the full combined source on an independent host, including a hostile worker with no direct provider route; do not infer this from the earlier separate PR's CI.
6. Execute one approved low-risk real external consequence with independent provider-state observation and no automatic retry on UNKNOWN.

## Evidence labels

**Verified local:** Source-pinned synthetic policy, reference, counter, restart and bounded fake-provider checks.
**Recorded:** Prior hosted PR #333 CI and earlier separate candidate tests.
**Proposed:** Admission and protected-reader deployment, independent physical WebAuthn test and one provider effect.
**Unknown:** Real human ceremony, HSM-backed signer, deployment containment, external-provider result, commercial readiness.

**No cloud, billing, credential, IAM, GitHub mainline merge or real provider effect is authorized or performed by this note.**

## Additional source-to-kernel wire integration evidence

- The `AuthorityService` fixture uses a test Ed25519 signer and synthetic
  WebAuthn verifier to approve exact intent, preserve an evidence bundle,
  and return only `ceremony_evidence_ref`.
- The **actual** `AuthorityClient.poll_approval` parses the service's response
  and rejects raw or unknown fields. A fixture reader retrieves the matching
  canonical bytes for `GovernanceKernel`; the pinned synthetic verifier,
  exact policy and permit rules are checked before one-use consumption.
- Four end-to-end *service-to-kernel* tests cover the positive case, missing
  reader, wrong evidence reference and incomplete approved service state.
  Other tests preserve the durable authenticator-counter replay denial.
- These are cross-module software tests, **not** a real WebAuthn human ceremony:
  the origin, credential and signed envelope are test fixtures. The fixture
  reader is not independent production IAM or protected retention.
- Local reruns and hosted test results must be tied to the **final PR head SHA**,
  not assumed from pre-merge parent commits.
