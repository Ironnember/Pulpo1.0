# Pulpo Current State

Status date: 2026-09-20

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` remains the sole source of truth for admitted Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is:

`8e1aab5daaba55228189c994ddad5b86b5aed8ae`

This commit canonically admits PR #229, `Proof: attest GitHub execution context from provider metadata`.

The SHA is an inspection point, not a permanent pin. Drafts, held experiments, green feature branches, provider receipts, comments, screenshots, and summaries remain evidence or proposals until a legitimate admission transition makes them canonical.

Evidence precedence remains:

1. executable behavior and exact-head tests;
2. current canonical reviewed code;
3. durable runtime/provider evidence;
4. current state artifacts and explicit decisions;
5. design documents;
6. summaries, screenshots, prototypes, and marketing.

## Constitutional boundary

Pulpo remains the governance and evidence plane between intelligence and consequential execution.

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

Core invariants include:

- `INTELLIGENCE != AUTHORITY`
- `AVAILABLE_CAPABILITY != AUTHORIZED_CAPABILITY`
- `AUTHENTICATED_CONTEXT != AUTHORIZED_EFFECT`
- `EXECUTOR_SUCCESS != VERIFIED_CONSEQUENCE`
- `MEMORY != AUTHORITY`
- `UNKNOWN != RETRY_AUTHORITY`
- `PAST_SUCCESS != FUTURE_AUTHORITY`

Intelligence may reason, research, propose, simulate, and learn. Pulpo governs identity, authority, policy, budget, approvals, capability activation, one-use permits, evidence, reconciliation, and governed outcome memory. Execution surfaces may perform only the exact permitted consequence and return evidence.

## Claim classes

- **Verified** — reproduced or directly supported by current executable/current canonical evidence.
- **Recorded** — durably captured evidence not independently reproduced in this reconciliation.
- **Inferred** — a conclusion from evidence, explicitly identified as inference.
- **Proposed** — intended next design or action, not yet admitted/proved.
- **Unknown** — insufficient, stale, or conflicting evidence.

Do not promote `Recorded`, `Inferred`, or `Proposed` claims through repetition.

## Verified canonical software boundary

### Governance kernel and exact authority

Canonical Pulpo retains fail-closed intent/policy evaluation, exact-object binding, approval verification, one-use permits, replay denial, durable SQLite state, restart-safe replay semantics, directive narrowing/revocation, audit integrity checks, bounded commerce primitives, and separation between intelligence, governance, and execution.

Successful prior execution, model output, conversational context, retrieval relevance, governed outcome memory, installed tools, or available capabilities do not independently expand authority.

### Independent approval contract

Canonical approval code pins trust to the exact authority/verifier/key/deployment contract and binds approval identity, principal, session, exact intent hash, exact policy hash, nonce, issue time, expiry, and signature.

This is verified canonical software behavior. It does not by itself prove a fully accepted deployment of `authority.pulpo.ai`.

### Consequence reconciliation and governed outcome memory

Canonical Pulpo distinguishes executor/provider claims from verified consequence. Independently observed success, mismatch, failure, and unresolved/unknown outcomes remain distinct across restart.

Governed outcome memory is admitted only after the required reconciliation/custody evidence. Outcome memory remains non-authoritative and cannot mint a permit, widen policy, or authorize an otherwise denied effect.

### Capability activation governance — PR #215

Canonical Pulpo proves:

`AVAILABLE_CAPABILITY != AUTHORIZED_CAPABILITY`

Read-only or ordinary permission does not silently authorize activation of a broader capability. Activation may require its own exact independently verified approval and one-use permit. Substitution, retargeting, and replay fail closed under the tested boundary.

### Telegram authority/custody preparation — PR #217

Canonical software composes a distinct capability-activation permit with a distinct exact Telegram message permit before the custody-only provider callback can be reached.

No live Telegram consequence is established by the merge itself.

### Projection/directive non-elevation — PR #220

Derived, summarized, retrieved, stale, or high-relevance projections cannot broaden directive scope/budget, activate an inactive directive, or restore revoked authority.

`PROJECTION_CANNOT_ELEVATE_SOURCE_AUTHORITY`

### Capability-stripped Agent Plugin — PR #222

The packaged plugin receives only the frozen noncanonical MCP snapshot/projection. It does not receive the kernel, executor, authority client, live policy object, canonical state backend, or evidence ledger reference.

### Secure MCP Tunnel binding — PR #223

Canonical software contains a fail-closed binding for:

`ChatGPT -> Secure MCP Tunnel -> tunnel-client -> capability-stripped Pulpo projection`

The tunnel, ChatGPT, and projection receive no canonical Pulpo authority merely by being connected. Live production ChatGPT tunnel operation remains a separate runtime claim.

### Cloud SQL IAM authority-state seam — PR #224

Canonical software pins the authority-state connection path to the exact Cloud SQL instance/database/IAM DB identity using private IP and automatic IAM authentication, with no password/host/port fallback in the tested path.

This proves the software seam, not full production deployment or accepted live authority-state operation.

### Read-only Google Cloud discovery — PR #226

Canonical Pulpo contains a frozen read-only discovery helper that gates exact operator/project context and rejects mutating substitutions such as service enablement, resource creation, Cloud Run execution, or IAM changes.

`DISCOVERY_COMMAND != CLOUD_MUTATION_AUTHORITY`

### Execution-context binding — PR #227

Canonical Pulpo can bind independently observed execution context into the exact intent and require:

`AUTHORIZED_TARGET == OBSERVED_EXECUTION_CONTEXT`

Mismatch or missing context fails before governed target access/permit consumption under the tested gate.

### GitHub execution-context attestation — PR #229

Canonical Pulpo has a concrete provider-specific attestor that derives execution context from GitHub-returned repository and authenticated-user metadata. Repository/owner substitution, missing identity, and provider failure fail closed. A successful context observation still does not create mutation authority.

## Recorded external/runtime evidence

### Stage-C V1 Supabase real-provider experiment — held PR #165

PR #165 remains Draft/held and is not canonical. It records a successful real-provider Stage-C V1 ceremony on exact authorized runner head:

`9d20b2b1825aef10430bc4b31888059b917138fd`

Recorded evidence includes:

- three distinct executor/observer/cleanup database principals;
- complete 10/10 frozen adversarial-family coverage;
- exactly one expected provider transmission in F07;
- zero unauthorized provider effects under the frozen matrix;
- successful matched consequence reconciliation;
- successful governed cleanup reconciliation;
- independent post-run row count of zero;
- credential-clean evidence hashes;
- post-proof revocation with the three temporary principals left `LOGIN=false`, password absent, and no active sessions.

This is strong bounded external-provider evidence. It does **not** establish general external containment, independent human authority, hostile-host containment, production readiness, or cold reproduction.

### Independent authority / Cloud SQL runtime — Issue #90

Issue #90 remains open.

Recorded evidence includes the accepted HSM signing primitive and a live Cloud Run probe that reached and queried the intended private Cloud SQL session. The run accepted the exact database identity, IAM database identity, search path, and PostgreSQL 16 before failing closed on an invalid `pg_stat_ssl` transport assertion.

That failed run is evidence that the intended path was reached; it is not an accepted connectivity receipt.

Draft PR #225 contains the corrected connector-transport interpretation and has been restaged on current `main`. Its current restaged head still requires fresh exact-head artifact/CI evidence before another live attempt is eligible for evaluation.

No second live execution is authorized by this document.

## Exact-head-green noncanonical engineering frontier

The following current PR heads have both CI and Constitutional Survival Proof reported successful in this reconciliation, but remain **noncanonical until review/admission**:

- #236 — dependency auditing hardening;
- #237 — outbound AI/governance transport trust;
- #238 — zero-unnecessary-inbound-listener evidence;
- #241 — prompt-injection containment by capability removal;
- #242 — bounded untrusted input/resource growth;
- #243 — policy-bound stale-permit expiry;
- #244 — narrower custody-container package surface;
- #245 — HTTP probing admission hardening;
- #246 — audit/delta/index/performance optimization;
- #247 — Windows MCP snapshot loading hardening;
- #248 — audit-integrity fast path for unchanged SQLite state.

These branches are evidence of a strong operational-hardening wave. Green branch evidence is not merge authority and not canonical functionality.

## Reconciliation gates before further expansion

### Semantic provenance

PR #239 and PR #240 currently represent overlapping approaches to binding transformed/semantic provenance into exact authority. They must be reconciled into one constitutional primitive before admission.

`TWO_PROVENANCE_PRIMITIVES != STRONGER_AUTHORITY`

Do not admit both merely because both are green.

### Audit/performance path

PR #246 and PR #248 overlap around reducing repeated audit cost while preserving fail-closed historical integrity. They must be reconciled so Pulpo has one canonical optimization path and one statement of what remains authoritative.

Performance evidence may not weaken restart/tamper detection or create a second evidence truth.

### Portability

PR #219 and PR #247 overlap partially around Windows/POSIX portability. Prefer the smallest current-main-derived fix that preserves the existing filesystem trust boundary; do not accumulate compatibility paths without explicit disposition.

## Current phase

Pulpo is entering **Phase II — Operational Hardening and External Reproduction**.

The objective is no longer to create more proof families. The objective is to convert the existing proof-rich system into a smaller, admitted, independently reproducible consequence-authority chain.

See [Next Phase](NEXT_PHASE.md).

## Proof boundary

### Verified

Canonical Pulpo currently has:

- exact intent/policy authority evaluation;
- independently verifiable approval contracts;
- one-use permits and replay denial;
- durable restart/replay state;
- directive narrowing/revocation;
- capability activation as a separately governed transition;
- projection/memory non-elevation;
- capability-stripped plugin/MCP exposure;
- Secure MCP Tunnel software binding;
- independent consequence reconciliation;
- governed outcome memory;
- execution-context binding;
- provider-derived GitHub context attestation;
- bounded Cloud SQL IAM connection/discovery software seams;
- hostile-worker/container custody controls in the tested topology;
- protected repository-admission controls and constitutional test surfaces.

### Recorded

Recorded evidence includes:

- real-provider Stage-C V1 Supabase execution under the frozen held experiment;
- post-proof credential revocation;
- HSM signer/runtime authority evidence from Issue #90;
- a live Cloud Run -> private Cloud SQL path reach/query before fail-closed receipt rejection.

### Inferred

Pulpo's strongest differentiation is the continuity of legitimate authority from exact proposed consequence through capability activation, execution context, custody, execution, independent observation, reconciliation, and non-authoritative memory.

A compact framing is:

**Infrastructure for legitimate machine consequence.**

### Proposed next sequence

1. admit/reject/reconcile the current hardening wave without widening the constitution;
2. complete independent authority acceptance under Issue #90;
3. reproduce Stage-C on current canonical software with independent authority in the chain;
4. execute one bounded, legible external consequence through that accepted path;
5. obtain cold third-party reproduction and preserve the evidence package;
6. only then widen distribution/product surfaces.

### Unknown / not yet established

Pulpo does not yet establish:

- complete accepted `authority.pulpo.ai` production deployment;
- general external-provider containment;
- hostile-host or hostile-custodian containment;
- cold third-party reproduction of the complete consequential chain;
- arbitrary-provider correctness;
- production throughput/reliability/false-denial burden;
- customer ROI or production-scale economics.

## Explicit nonclaims

Do not convert passing CI, a green PR, a provider response, a cloud primitive, a held experiment, a successful execution report, or a social/market signal into:

- production readiness;
- universal containment;
- independently deployed authority;
- compliance/certification;
- cold reproducibility;
- valuation proof.

## Doctrine

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
