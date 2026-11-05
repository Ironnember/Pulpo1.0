# Pulpo Current State

Status date: 2026-11-03

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is:

`6d543980a3087f2ff9097fd483c7058e2a135e7d`

This commit canonically admits PR #338, kernel-checked human-ceremony
evidence for opted-in actions (see the ceremony section below), on top of
PR #337 (the 2026-11-03 refresh of this document, `c2bf2b8`) and
PR #336, the dual-signed reciprocal external review record with
SHAETHON AI (documentation/evidence only), on top of the prior kernel
head `6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`. The full test suite at
the current main head was run in a clean detached worktree on
2026-11-03: 451 tests OK, 1 skipped (the run environment had the
`cryptography` package installed; ceremony key-derivation tests skip
without it).

The 2026-09-08 reconciliation this document previously carried pinned
`b44dcd40a1ad2bd5413756bd413807f54f9283da` (PR #200). Sections below are
unchanged where the behavior they describe is unchanged, and are marked
with their update date where this reconciliation revised them.

The SHA is an inspection point, not a permanently pinned source-of-truth designation.

Historical repositories, held branches, Draft pull requests, closed-unmerged proof objects, screenshots, summaries, and experimental distribution artifacts remain evidence or reference material only unless a legitimate governance transition admits their behavior into canonical Pulpo.

Evidence precedence remains:

1. executable behavior and tests;
2. current canonical reviewed code;
3. durable runtime/provider evidence;
4. current state artifacts and explicit decisions;
5. design documents;
6. summaries, screenshots, prototypes, and marketing.

## Constitutional boundary

Pulpo remains the governance and evidence plane between intelligence and consequential execution.

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

Core invariants include:

- `NO_PERMIT != NO_GOVERNED_EFFECT`
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`
- `NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`
- `CORRECTNESS != AUTHORITY`
- `MEMORY != AUTHORITY`

Intelligence may reason, propose, simulate, and learn.

Pulpo governs identity, authority, policy, budget, approval, canonical state transitions, permits, evidence, reconciliation, and governed outcome memory.

Execution surfaces perform only the exact permitted consequence and return evidence. Executor success cannot self-certify reconciliation.

## Claim classes

- **Verified** — reproduced or directly supported by current executable/current canonical evidence.
- **Recorded** — durably captured evidence not independently reproduced in this reconciliation.
- **Inferred** — a conclusion from evidence, explicitly identified as inference.
- **Proposed** — intended next design or action, not yet proved.
- **Unknown** — insufficient or conflicting evidence.

Do not promote `Recorded`, `Inferred`, or `Proposed` claims through repetition.

## Verified canonical software boundary

### Governance kernel and directives

Canonical Pulpo retains the established fail-closed governance kernel, exact intent/policy binding, one-use permits, replay protection, durable state semantics, directive narrowing/revocation behavior, and the separation between intelligence, governance, and execution.

Successful prior execution, model output, retrieval, conversational memory, or governed outcome memory does not independently expand authority.

### Independent approval contract

Canonical approval code pins public trust before governed work begins to the exact authority, verifier, key, algorithm, key fingerprint, deployment, and maximum approval TTL.

Each approval envelope binds approval identity, authority, verifier, key, deployment, trust hash, session, principal, exact intent hash, exact policy hash, nonce, issued time, expiry, and signature.

This is verified canonical software behavior for the approval contract. It does not prove that the complete independent `authority.pulpo.ai` service is deployed or acceptance-proven.

**Ceremony evidence (gap named 2026-11-03; kernel-checking closed by
PR #338, merged 2026-11-03).** The approval contract binds and verifies
a signature; as named earlier on 2026-11-03 it did not, by itself,
require evidence that a human authority ceremony occurred
(`VALID_AUTHORITY_SIGNATURE != PROOF_OF_HUMAN_AUTHORITY_CEREMONY` was
the gap; PR #280 preserved its proof, and a repair candidate, PR #288,
was closed unmerged). PR #338 closes the kernel-checking half of that
gap for actions a policy explicitly opts in via
`Policy.ceremony_actions`: admission inside `evaluate_with_approval`
now additionally requires a ceremony attestation signed under a
ceremony trust pinned separately from the approval authority trust,
bound to the approval id, envelope hash, intent, policy, principal,
session, and nonce, verified with expiry and clock-rollback re-checked
when verification completes, and consumed single-use: in the
persistent SQLite backend the check-and-record transition runs inside
the same `BEGIN IMMEDIATE` transaction that issues the permit, and in
the in-memory backend the same transition is serialized under the
state store's lock, with a scheduler-forced concurrency regression
(two callers, different approval ids, the same ceremony evidence:
exactly one issuance, the rest denied as replays). The single-use
guarantee under concurrent callers is therefore established for both
shipped backends; before this change the in-memory backend recorded
evidence ids without serializing the transition and did not carry the
guarantee — that qualification stood in this document until the
regression and fix landed. Shipped ceremony verifiers derive their key fingerprint
from the pinned public key (the same derivation as the approval
adapters), and policy construction rejects a ceremony fingerprint
equal to the approval fingerprint, so the envelope signer cannot
self-attest. Policies that do not opt in are unchanged, including
byte-identical policy hashes.

Scoped limits, stated plainly: this is a technology-neutral contract
(the kernel parses no WebAuthn or authenticator payloads) and does
**not** establish a production hardware-backed human ceremony — that
acceptance test remains outstanding. Authenticator counter
monotonicity is not verified by the kernel. The authority-client /
directives path does not yet transport ceremony evidence, so
ceremony-required actions there fail closed. A custom ceremony
verifier whose advertised fingerprint misrepresents its effective key
is trusted control-plane code misrepresenting itself; proved key
separation holds for the key-derived verifiers the kernel ships.

### Capability-stripped MCP boundary

PR #134 is canonical.

The MCP-side projection no longer retains the kernel, orchestrator, canonical state backend, authority client, executor, live policy object, trusted clock, or ledger reference.

Proposal construction is ephemeral and non-mutating. Frozen primitive snapshots do not become canonical writers merely because no write route is exposed.

This establishes the tested software/object-capability boundary. It does not establish hostile same-process memory isolation, production remote-MCP authentication, or live-current evidence freshness.

PR #200 canonically adds the trusted-side frozen-snapshot export primitive. It
requires a canonical `PulpoOrchestrator`, copies only six primitive evidence
fields, writes atomically with owner-only permissions, rejects path and symlink
substitution, and remains absent from the MCP tool surface.

An operator-host reconciliation recorded in `docs/MCP_BOUNDARY.md` against
canonical main `b44dcd40a1ad2bd5413756bd413807f54f9283da` independently
reproduced the configured 2,589-record frozen snapshot byte-for-byte from a
disposable copy of the durable SQLite state. The database audit chain was
valid and the resulting snapshot SHA-256 was
`21b8a36425e63b921145dbbb15d07147fb6fbdc4fcb913cdf06045a54f26b397`.
That historical evidence remains pinned to `b44dcd`; it was not rerun at
`f9dd6bd`. This verifies that exact frozen object's compatibility and
provenance at the observation point. No Pulpo process was running, so current
freshness and an admitted same-process runtime handoff remain **Unknown**.

### Consequence reconciliation and governed outcome memory

Issue #153 is completed and its implementation is canonical through PR #161.

Canonical Pulpo now explicitly proves the local software/custody/observer invariant:

`VALID_AUTHORITY + VALID_PERMIT + EXECUTION_SUCCESS != VERIFIED_CONSEQUENCE`

The canonical path distinguishes:

- independently verified success;
- observed mismatch despite executor/provider success;
- independently observed provider failure;
- unresolved or insufficient evidence.

Mismatch and unknown state survive restart without becoming success or retry authority.

Replay, substitution, expiry, revocation, and authority-widening paths remain fail-closed under the tested boundary.

Governed outcome memory is admitted only after exact reconciliation evidence has converged into canonical custody evidence.

The same exact reconciliation transition cannot create multiple canonical outcome-memory records under simultaneous identical callers.

Successful outcome memory remains non-authoritative and cannot mint a permit, alter policy, or authorize an otherwise denied intent.

This is a software/custody/observer proof. It is not a claim of real external-provider containment.

## Reciprocal external evidence (2026-11-03)

PR #336 admitted `docs/RECIPROCAL_EXTERNAL_REVIEW_SHAETHON_2026-11-03.md`,
a dual-signed reciprocal external review between Iron & Ember and
SHAETHON AI, direct competitors in permit-gated execution. Both parties
signed the record as written.

- **Direction 1 (Recorded).** SHAETHON AI independently tested the
  **Pulpo-Preview source release, commit `ec52708` (2026-10-31)** — not
  canonical `main`. Of the release's published 1,030 tests, 1,024 ran:
  936 passed, 60 skipped, 4 failed, 24 errored, with no failure in the
  permit, governance, or verifier suites; the failures are
  environment-sensitive. A 31-probe adversarial boundary battery held in
  full (31 held, 0 broke). Later on 2026-11-03, SHAETHON delivered a
  sanitized harness package whose enclosed counts and probe outcomes were
  re-derived from its raw files in Iron & Ember custody: a same-day
  reproduction run against the identical hash-verified Preview asset ran
  1,024 tests with 940 passed, 56 skipped, the same 4 failures and 24
  errors in the same environmental clusters, and all 31 probes held. The
  package is expressly a reproduction, not the original run's raw
  artifacts: the original October 31 sandbox and logs were not retained,
  and the harness was re-implemented from the original write-up. The
  tester has since been commissioned to run the independent
  reproduction protocol against canonical `main` at
  `6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`; that pass is **Proposed**
  until its results land.
- **Direction 2 (Verified from this side).** Iron & Ember tested the
  live Tether pilot gate under its owner's written rules: ~45 cases, no
  reproduced breaks, governance edges behaving as documented. One
  concurrency anomaly was recorded as an open item on both sides; the
  gate owner's ledger reconciliation (2026-11-03) resolved it as a
  harness-side counting and write-up error on the testing side — the
  gate executed the permit exactly once — and that reconciliation was
  verified against the testing side's retained files. It is closed,
  not a break; the amendment addendum is recorded in PR #339, with the
  gate owner's written sign-off recorded in it on 2026-11-03. Two of the gate owner's three self-disclosed flags were
  independently confirmed from this side; the publishing side's dissent
  on one flag's classification is preserved in the record. The gate
  owner later reported deploying all three fixes and re-running his own
  battery cleanly (39 held, 0 flags; **Recorded** from his report).
  Iron & Ember then independently verified the patched gate in a
  targeted scope — the normal issue/execute/replay control, the
  non-finite-confidence case returning a clean 400, lowercase,
  mixed-case, padded, and exact-case life-safety values all denied, and
  the ledger valid and anchored — 9 of 9 checks held. The full battery
  rerun and joint supervised concurrency soak remain outstanding.

This record establishes reciprocal black-box behavior of the exact
objects tested. It does not establish production readiness, canonical
reproduction, or deployed authority for either system, and it is not a
partnership or endorsement.

## Governance and repository admission

Protected `main` visibly requires:

- `test`
- `authority`
- `authority-service`
- `admission-hold`

Active ruleset `22241311` separately requires strict status checks for `test`, `authority`, and `authority-service`, one approving review, stale-review dismissal after push, last-push approval, review-thread resolution, and reports no bypass actors with `current_user_can_bypass="never"`.

Issue #115 is completed.

Repository admission has executable evidence demonstrating that passing code and an approval do not themselves create admission authority.

A held candidate can be denied while the same code object can later become eligible only after the separately authorized admission-state transition.

During PR #161 admission, previously configured classic branch-protection requirements for successful Preview and Production deployments and a locked read-only `main` were verified as independent blockers. Those requirements were removed through an explicitly authorized settings transition before the protected merge succeeded.

The full classic branch-protection metadata is not completely readable through the connected integration, so unobserved administration metadata should not be overclaimed.

## Bounded commerce

Canonical Pulpo proves the bounded digital-commerce foundation: exact purchase-object binding, budget ceilings, reservation/reconciliation semantics, one-use authority, and separation of provider execution claims from independent consequence evidence.

The earlier auto-renew omission has been corrected in canonical code. PR #312
(commit `dc563a089dbd9e67d6d81518d21c36916a62ec7b`, an ancestor of the
current pin) bound provider-side auto-renew enablement into the exact
request/order identity:

- the request and order carry a strict boolean `auto_renew_enabled` value,
  and that value is carried from the assessed request into the order and
  bound by their hashes;
- the Name.com V0 path supports only the disabled state and rejects an
  enabled order before provider entry;
- delivery acceptance requires an exact independent auto-renew observation;
  a missing observation or a mismatch fails acceptance.

The invariant remains:

`CANONICAL_ACTION_OMISSION != AUTHORIZED_PROVIDER_DEFAULT`

PR #143 is historical corrective work that preceded the admitted correction;
it is not the current-main admission object.

No real registrar purchase or independently observed registrar consequence is established.

## Independent authority

Issue #90 remains open.

### Recorded external signer evidence

Issue #90 durably records acceptance evidence for the exact Google Cloud HSM key version:

`projects/dulcet-opus-499511-a5/locations/us-west1/keyRings/pulpo-authority/cryptoKeys/approval-signer/cryptoKeyVersions/1`

Recorded metadata includes:

- state: `ENABLED`;
- algorithm: `EC_SIGN_P256_SHA256`;
- protection level: `HSM`;
- curve: NIST P-256 / prime256v1;
- Pulpo canonical trust fingerprint, SHA-256 over the exact 65-byte uncompressed SEC1 public point: `b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127`;
- a live KMS signature over `pulpo-independent-authority-proof-v1` that verified locally against the fetched public key.

These facts are classified **Recorded** in this reconciliation because the external Google Cloud operation was not independently re-executed here.

`HSM_SIGNER != DEPLOYED_INDEPENDENT_AUTHORITY`

The complete `authority.pulpo.ai` boundary has not yet been acceptance-proven as an independently deployed human-authority system.

Production-facing authority claims therefore remain bounded below a completed independent authority deployment.

## Noncanonical and historical proof objects

PR #159 is stale documentation reconciliation against pre-#161 canonical state and must not be admitted as-is.

PR #160 remains a preserved Draft negative/composition proof showing the Issue #153 gap before the canonical #161 implementation. It is evidence history, not a production object to merge.

PR #143 remains historical precursor evidence for the auto-renew correction admitted through PR #312, not the current-main admission object.

PR #131 remains a Draft distribution candidate. Its capability-stripping concepts may inform future distribution work, but it is not canonical distribution or production deployment.

PR #128 is closed unmerged structural Stage-C evidence. It does not establish an external unauthorized-effect rate or real external containment.

`Ironnember/The-keel` remains an execution-plane experiment unless and until its exact execution contract is legitimately admitted without becoming a second authority or ledger.

## Proof boundary

### Verified

Canonical Pulpo currently has:

- a governed kernel and one-use authority path;
- an exact-object independent approval contract in canonical software;
- replay/restart and directive freshness controls under the tested boundary;
- hostile-worker software/container controls;
- capability-stripped MCP behavior;
- independent evidence/reconciliation before verified consequence;
- canonical evidence before governed outcome memory;
- concurrent exactly-once outcome-memory admission;
- memory non-authority;
- protected repository admission controls with executable denial/allow evidence.
- one dual-signed reciprocal external review record admitted to canonical `main` (PR #336, 2026-11-03), with both parties' results, limits, and open items stated in the record itself.

### Recorded

Recorded evidence includes the exact Issue #90 HSM signer acceptance record, Keel experiments, historical Stage-C structural work, and held/stale corrective branches. As of 2026-11-03 it also includes SHAETHON AI's Pulpo-Preview test results (Direction 1 of the reciprocal review; the sanitized harness package is now in Iron & Ember custody and its enclosed reproduction-run counts and probe outcomes were re-derived from the raw files) and the ceremony-custody candidate rerun of 2026-10-24 (33 targeted tests passing at a pinned non-canonical revision, artifacts retained off-repository).

These are not automatically canonical or production proof.

### Inferred

Pulpo's strongest current differentiation is the continuity of independently governed authority and evidence from intent through consequence and memory, rather than generic agent orchestration.

A compact framing remains:

**Models can change overnight. Authority should not.**

### Proposed

The next technical sequence is:

1. complete independent authority/provider qualification necessary for a genuine external consequence ceremony;
2. freeze the exact external execution/evidence object;
3. execute one bounded, safe external consequence through the canonical authority -> permit -> execution -> evidence -> reconciliation -> memory path;
4. preserve the evidence bundle and obtain cold reproduction outside the build loop.

### Unknown

Pulpo does not yet establish:

- a production hardware-backed human authority ceremony (kernel-checked ceremony evidence for opted-in actions is established by PR #338 — see the ceremony section — but no hardware authenticator ceremony has been acceptance-proven, and the directives path does not yet transport ceremony evidence);
- independent third-party reproduction of canonical `main` (the reciprocal tester's pass under the reproduction protocol is commissioned and outstanding at this date);
- real external-provider containment;
- a real external unauthorized-effect rate;
- fully accepted independent production authority;
- hostile-host or hostile-custodian containment;
- cold third-party reproduction of the complete consequential chain;
- arbitrary-provider correctness;
- production throughput, reliability, cost, false-denial rate, human-review burden, or customer ROI.

## Explicit nonclaims

Do not convert passing CI, a cloud primitive, repository approval, executor success report, experimental distribution artifact, financing term, social post, or market interest into:

- production readiness;
- external containment;
- independently deployed authority;
- compliance or certification;
- third-party reproducibility;
- valuation proof.

### Inferred positioning

Pulpo currently has canonical software-boundary governance, exact-object approval binding, consequence reconciliation, governed outcome memory, and mechanically exercised repository-admission controls.

External consequence verification and independent production authority remain the next major proof boundary.

## Doctrine

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
