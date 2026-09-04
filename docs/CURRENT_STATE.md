# Pulpo Current State

Status date: 2026-09-01

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is `ca3636680ca50356406519a5722444c0742afb39`, the merge of PR #134, **Proof: governed-effect canonical mutation boundary v0**. The exact capability-stripped MCP head was admitted after fresh independent collaborator approval, CI #461, Constitutional Survival #123, and Admission Hold #65. `authority_effect=none`.

The SHA above is an inspection point, not a permanently pinned source-of-truth designation.

`Iron-Ember/pulpo`, `Ironnember/The-keel`, historical tags/releases, and other earlier or adjacent repositories remain historical or experimental evidence unless a legitimate governance transition explicitly admits behavior into canonical Pulpo.

Evidence precedence remains:

1. executable behavior and tests;
2. current canonical reviewed code;
3. durable runtime/cloud/provider evidence;
4. current state artifacts and explicit decisions;
5. design documents;
6. summaries, screenshots, prototypes, and marketing.

## Claim classes

- **Verified** — reproduced or directly supported by executable/current evidence.
- **Recorded** — durably captured evidence not independently reproduced in this document update.
- **Inferred** — conclusion from evidence, explicitly identified as inference.
- **Proposed** — intended next design/action, not yet proved.
- **Unknown** — insufficient or conflicting evidence.

## Constitutional boundary

Pulpo governs more than external tool execution. A governed effect includes an external consequence **or** a canonical state transition or retained capability that can alter the future consequence surface.

Canonical invariants include:

- `NO_PERMIT != NO_GOVERNED_EFFECT`;
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`;
- `NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`;
- `CORRECTNESS != AUTHORITY`;
- `authority_effect=none` does not imply `governed_effect=none`.

A component does not become non-authoritative merely because it cannot mint a permit. Possession of a canonical writer is itself a governed capability.

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

## Verified in canonical code and CI

### Governance kernel

The canonical kernel and tests prove fail-closed intent/policy evaluation, exact intent hashing, policy hashing, one-use permits, permit substitution denial, durable SQLite replay protection across restart, audit-chain tamper detection, and bootstrap failure on invalid persisted audit state.

Static `AgentGrant` policy constrains configured principals by action, resource prefix, and cost. Unknown principals fail closed and an agent grant cannot broaden the global policy. This is least-authority policy enforcement; it is not yet a general delegated organizational-authority system.

### Independent approval contract

The approval path uses policy-pinned asymmetric public trust. Approval envelopes bind authority, verifier, key, deployment, approval identity, principal/session, exact intent, exact policy, nonce, issue time, and expiry. Invalid signatures, replay, expiry, clock rollback, trust substitution, or verifier failure deny.

The repository also contains the separately packaged authority service, WebAuthn ceremony logic, worker request/poll surface, Google Cloud KMS P-256 signer adapter, protected-evidence adapter contract, and PostgreSQL authority-state adapter. Passing tests prove those code-side contracts only; they do not prove the production authority deployment exists.

### Governed directive projection

Canonical directive code extends the existing authority/policy/state seam rather than creating a second memory governor or policy engine.

Executable tests prove ordinary chat/retrieval cannot activate an authoritative directive; activation/revocation requires the existing pinned external approval path; approval binds the exact directive digest; untrusted issuers deny; active directives can only narrow principal/action/resource/cost; retrieval relevance or model summary cannot raise authority; broadened substitution denies; revocation survives restart; directive-bound permits are one-use; and parent-child same-principal derivation cannot broaden authority and is revalidated at projection/consumption time.

Cross-principal delegation and independent delegated-operator authority minting remain unproved.

### Hostile-worker consequence boundary

The custody/worker proof establishes a tested software/container boundary with exact target/order/policy/permit binding, live directive revalidation, monotonic custody state, compare-and-swap admission, one authoritative attempt under replay/fork/two-worker races, durable budget reservation/attempt/reconciliation state, no blind retry after unknown provider outcome, and separation of executor claims from independent observation.

The hostile-worker container is denied custody persistence, Docker socket, governance secrets, and provider executor/observer tokens. Custody transitions project into the existing Pulpo audit rather than a second ledger.

This does **not** prove hostile-host, hostile-custodian, HSM/TEE containment, arbitrary-provider correctness, or real external-provider containment.

### Intent persistence and governed learning

Canonical intent-persistence proof requires completion evidence for the exact durable target version. Chat, memory, or retrieval claims cannot manufacture completion. File-artifact proof binds target hash, intent hash, absolute artifact path, content SHA-256, byte size, trusted observation time, and audit evidence; unresolved/completed state survives restart.

Governed temporal replay allows historical evidence to improve present competence without reactivating historical credentials, approvals, permits, budgets, directives, policy expansions, or authority.

### MCP boundary — canonical capability stripping

PR #124 originally admitted MCP as capability/transport rather than authority, but hostile review found two deeper failures:

1. the MCP proposal path called canonical target locking, so it could append durable canonical state without a permit; and
2. after removing that direct route, the projection still retained the full orchestrator, meaning `NO_WRITE_ROUTE` still did not equal `NO_WRITE_CAPABILITY`.

PR #134 is canonical and closes both failures at the tested V0 object boundary.

Canonical MCP behavior now:

- trusted Pulpo may freeze primitive evidence metadata into exact-type `MCPReadSnapshot`;
- the MCP projection/server accepts only that capability-free immutable snapshot;
- it retains no kernel, orchestrator, state backend, authority client, executor, policy object, trusted clock, or ledger reference;
- proposals are ephemeral and return no permit and no canonical target hash;
- proposal hashing uses the kernel's deterministic static hash function without retaining a kernel instance;
- evidence/proposal output explicitly reports frozen freshness and no canonical mutation/governed effect/authority effect;
- later canonical writes cannot appear through an already-frozen MCP evidence object;
- injection of write-capable Pulpo objects is denied by exact-type boundaries and tests.

This is **Verified canonical behavior** at current `main`.

It does not prove hostile same-process memory isolation, live read-only IPC, authenticated remote MCP hosting, production deployment, live evidence freshness, or a complete authenticated ingress contract for every canonical-state writer.

### Bounded commerce — verified scope and discovered auto-renew gap

Canonical tests and current code bind the exact domain, registrar, owner reference, privacy requirement, prohibited upsells, purchase price ceiling, renewal **price** ceiling, request/quote/order hashes, reservation/reconciliation semantics, provider idempotency, and the USD 30 pilot purchase ceiling.

A later red proof in closed-unmerged PR #138 established a material omission in current canonical bounded commerce: `DomainPurchaseRequest`, `DomainPurchaseOrder`, verification evidence, and independent observation on current `main` do **not** bind the provider-side `auto_renew_enabled` state. Existing tests can therefore remain green while a provider default could create a future renewal capability/charge outside the exact authorized object.

PR #138 produced a corrective branch that bound `auto_renew_enabled` into request/order hashing, permit resource identity, provider transmission, and independent observation, and that branch passed its fresh hosted test suite. The PR was closed unmerged under the hold, so **none of that corrective behavior is canonical**.

Current classification: the auto-renew omission is a **Verified canonical governed-effect defect**; the corrective implementation is **Recorded branch-local evidence**, not authority and not admitted behavior.

No real registrar registration, external observer separation, or completed external purchase is established. A registrar Stage-C ceremony must not proceed through the current commerce object until this governed-effect omission is legitimately corrected and admitted.

## Recorded external infrastructure evidence

Issue #90 remains the durable deployment record for the independent authority boundary.

Recorded cloud authority evidence includes project `dulcet-opus-499511-a5`, project number `286256558392`, region `us-west1`, and the authority key ring. The exact non-exportable Google Cloud KMS P-256 signing key version is recorded as enabled with HSM protection, and a live KMS signature over the deterministic proof message was independently verified against the fetched public key.

This proves an external signing primitive. It does not by itself prove a deployed `authority.pulpo.ai` human-authority boundary.

## Independent authority remains incomplete

`authority.pulpo.ai` remains the selected human authority origin, but the complete deployed boundary has not passed acceptance.

Still required include independently administered authority-service deployment, verified private network path, protected durable PostgreSQL authority state, independently retained create-only authority evidence, worker ingress bound to exact governed-worker identity, primary hardware WebAuthn plus offline recovery control, DNS/TLS/load-balancer acceptance, failure/rollback/concurrency acceptance, and fresh external reproduction after restart/service replacement.

External language must distinguish **verified external HSM signer** from **deployed independent human authority**.

## Governance/admission state

Protected `main` currently exposes required status contexts exactly:

- `test`;
- `authority`;
- `authority-service`.

`admission-hold` is **not** a protected required context.

The base-controlled Admission Hold workflow is admitted and has demonstrated correct hold/ready behavior, including successful Admission Hold #65 during PR #134's legitimate admission. Repository-enforced independent collaborator review has also rejected otherwise-green merge attempts until independent approval exists.

However, Issue #115 remains **OPEN / unresolved**. Fresh readback still shows that branch protection does not mechanically require the Admission Hold decision, and the connected integration cannot read or mutate the full admin/bypass posture. Passing the hold workflow therefore does not prove a held PR is non-bypassably unmergeable.

Do not claim the unauthorized-admission class is mechanically closed until an authorized repository-settings transition makes `admission-hold` required (or establishes an equivalently non-spoofable protected-base rule), bypass posture is verified/narrowed, and held-denial plus ready-allow acceptance evidence is preserved.

## Distribution boundary

Historical `v0.1.1` remains an experimental distribution artifact and is not current canonical proof of a production product.

PR #131 remains Draft/held. Its V0 deliberately gives the mobile/PWA process no Pulpo object and only a copied `FrozenEvidenceSource`, exposes authenticated read-only evidence, rejects authority-bearing evidence, uses no-store caching semantics, and reports `freshness: not_asserted`.

That branch-local proof does not establish production authentication, live-current evidence freshness, write-capable mobile governance, desktop distribution, native iOS/App Store admission, production deployment, or a canonical public release.

## Stage-C external consequence proof

Closed-unmerged PR #128 preserves the historical Stage-C structural evidence work. On exact tested held heads it froze the ten-family unauthorized-effect benchmark and fail-closed observation semantics, including distinct observer/executor identities and fingerprints, observer credential isolation, authenticated observation, provider calibration/cleanup, exact effect scope, complete read-only observation, and `unknown` on missing, ambiguous, unauthenticated, wrong-source, or wrong-scope evidence.

Later hostile review strengthened the contract further: a zero-unauthorized-effect result could not be accepted merely from an empty observation window. It required exact execution-evidence coverage across every frozen attack family, evidence that each attack was actually exercised, a bundle commitment, and one safe reversible matched conversion proving the consequence seam was reachable.

Provider scans did **not** establish a completed ceremony. Name.com remained not claim-eligible because multiple tokens were not proved to create genuinely distinct provider principals. Supabase/Postgres was identified as structurally plausible because it can support distinct database principals and provider-native WAL/LSN sequence coordinates, but qualification is not execution evidence.

PR #128 was made ready while its explicit process hold remained; the admitted base-controlled hold/quarantine automation closed it unmerged. Therefore there is **no active or canonical Stage-C implementation from #128**.

Classification:

- the exact historical structural proof records are **Recorded** and remain useful evidence;
- real external provider containment is **Unknown / unproved**;
- no external unauthorized-effect rate has been established;
- no provider credential or external effect should be inferred from the structural work.

## Keel boundary

`Ironnember/The-keel` remains an experimental execution-plane proof, not canonical Pulpo authority.

The intended split is unchanged:

- Pulpo owns identity, authority, policy, budget, approvals, permits, canonical evidence, reconciliation, and governed learning;
- Keel deterministically executes an already-authorized exact operation and returns an execution receipt that cannot self-certify reconciliation.

Keel remains draft/noncanonical until it verifies a real Pulpo cryptographic one-use permit and is admitted without creating a second authority, router, executor-of-record, or ledger.

## Current held experiments

Current held branches may provide evaluation evidence but are not canonical capability:

- PR #141 proposes an accountable-context precondition before delegation/permit use;
- PR #139 evaluates a real external Hermes runtime against Pulpo's capability-stripped MCP surface;
- PR #137 replays historical governed-effect/capability-possession failures;
- PR #131 evaluates a capability-stripped read-only distribution surface.

Passing checks on those branches do not create admission authority or current product claims.

## Proof boundary

### Verified

- canonical governance kernel, exact intent/policy binding, one-use permits, fail-closed policy, replay/restart behavior, and audit integrity;
- directive revocation and same-principal non-broadening behavior;
- tested hostile-worker software/container boundaries;
- independent collaborator review enforcement;
- base-controlled Admission Hold workflow behavior, including legitimate PR #134 Admission Hold #65;
- external HSM signing primitive;
- canonical capability-stripped MCP boundary admitted through PR #134;
- the canonical commerce omission of provider-side auto-renew enabled state;
- the failure lesson that no permit and no visible write route are insufficient if a component can still mutate or retain access to canonical state.

### Recorded

- cloud authority project/resource evidence and historical proof records;
- historical Stage-C structural evidence from closed-unmerged PR #128;
- branch-local corrective auto-renew evidence from closed-unmerged PR #138;
- Keel V0 experimental execution-boundary evidence.

### Inferred

- Pulpo's strongest differentiator is authority continuity through consequence: separating intelligence capability from legitimate authority while preserving evidence that the authorized object survived to execution and reconciliation.

### Proposed

- require `admission-hold` at the repository protection layer or establish an equivalently non-spoofable protected-base rule;
- legitimately correct and admit the auto-renew governed-effect omission before registrar execution;
- audit every externally reachable canonical-state writer against authenticated identity, scope, replay/idempotency, revocation, resource limits, and evidence requirements;
- establish genuinely distinct external provider observer/executor principals and credential isolation for Stage C;
- recreate or admit a current Stage-C contract only through normal governance before any real external ceremony;
- run one bounded zero-real-cost external Stage-C ceremony through the existing governance/reconciliation path;
- admit a distribution surface only after exact-head substantive review and normal repository admission;
- admit Keel only after it verifies a real Pulpo permit without acquiring authority.

### Unknown

- final admin/bypass posture for protected `main`;
- whether every canonical-state writer currently has a complete ingress authorization contract;
- real external unauthorized-effect rate;
- production authority-service acceptance;
- cold third-party reproduction of the complete consequential chain;
- production reliability, cost, throughput, false-denial rate, human-review burden, customer ROI, and arbitrary-provider correctness.

## Explicit nonclaims

Pulpo does not yet prove:

- a fully deployed and acceptance-proven independent human-authority service;
- physical WebAuthn founder/recovery credential control;
- external hostile-host or hostile-custodian resistance;
- real external-provider containment;
- a real Name.com sandbox registration consequence through the final custody ceremony;
- independent provider observation and reconciliation of that consequence;
- cold reproduction of the full consequential chain by an unrelated operator;
- production throughput, latency, reliability, deployment cost, cost per governed action, false-denial rate, human-review burden, or customer ROI;
- general correctness across arbitrary agents, providers, payment rails, or execution surfaces.

Do not convert passing CI, a cloud resource, an approval, a successful executor report, a branch-local experiment, an experimental distribution artifact, or market interest into authority, production-readiness, external-containment, or third-party-reproducibility claims.

## Next highest-value proof sequence

1. Through an authorized GitHub administration/settings surface, require `admission-hold` for protected `main` or establish an equivalently non-spoofable protected rule; inspect/narrow bypass posture; preserve held-denial and ready-allow acceptance evidence; then close Issue #115.
2. Correct the verified canonical commerce auto-renew governed-effect omission and admit only an exact reviewed object that binds provider renewal state into request, order, permit identity, execution, independent observation, and reconciliation.
3. Audit all externally reachable canonical-state writers under the governed-capability rule; remove or govern any remaining writer possession that lacks authenticated scoped authority.
4. Reconcile investor/partner/distribution language to current canonical `ca363668...`: MCP capability stripping is admitted; the commerce auto-renew defect is known; production readiness, real external containment, and cold third-party reproduction remain unproved.
5. Establish genuinely distinct external provider observer/executor principals and credential isolation, then create/admit a current Stage-C proof contract through normal governance.
6. Run exactly one disposable zero-real-cost external provider ceremony through the admitted Stage-C contract and existing reconciliation path.
7. Preserve the complete evidence bundle and have an unrelated operator reproduce the proof cold.
8. Finish the independent `authority.pulpo.ai` deployment/acceptance boundary and admit Keel only after its execution contract verifies a real Pulpo cryptographic permit without becoming a second authority or ledger.

**Models can change overnight. Authority should not.**
