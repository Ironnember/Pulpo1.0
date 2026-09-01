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

Pulpo governs more than external tool execution. A governed effect includes an external consequence **or** a canonical state transition that can alter the future consequence surface.

Canonical invariants now include:

- `NO_PERMIT != NO_GOVERNED_EFFECT`;
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`;
- `NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`;
- `authority_effect=none` does not imply `governed_effect=none`.

The practical rule is that a component does not become non-authoritative merely because it cannot mint a permit. Possession of a canonical writer is itself a governed capability.

The doctrine remains:

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

PR #134 is now canonical and closes both failures at the tested V0 object boundary.

Canonical MCP behavior now:

- trusted Pulpo may freeze primitive evidence metadata into exact-type `MCPReadSnapshot`;
- the MCP projection/server accepts only that capability-free immutable snapshot;
- it retains no kernel, orchestrator, state backend, authority client, executor, policy object, trusted clock, or ledger reference;
- proposals are ephemeral and return no permit and no canonical target hash;
- proposal hashing uses the kernel's deterministic static hash function without retaining a kernel instance;
- evidence/proposal output explicitly reports `freshness=frozen`, `canonical_state_mutation=false`, `governed_effect=none`, and `authority_effect=none`;
- later canonical writes cannot appear through an already-frozen MCP evidence object;
- injection of write-capable Pulpo objects is denied by exact-type boundaries and tests.

This is **Verified canonical behavior** at current `main`.

It does not prove hostile same-process memory isolation, live read-only IPC, authenticated remote MCP hosting, production deployment, live evidence freshness, or a complete authenticated ingress contract for every canonical-state writer.

### Bounded commerce and Name.com contracts

Canonical tests prove exact domain/registrar/owner/privacy/upsell/price/renewal constraints, the USD 30 pilot ceiling, request/quote/order binding, reservation/reconciliation semantics, provider idempotency binding, and denial of production execution when a hard provider charge cap is unavailable.

A separate read-only Name.com sandbox readiness proof exists. Name.com sandbox remains a credible zero-real-charge Stage-C candidate, but observer/executor principal separation, provider-side observation identity/window semantics, and credential isolation are not yet established. No Name.com registrar write or completed external purchase is established.

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

PR #128 remains Draft/held at exact head `b24e1f42ec19f844fd6955d2a94127c954e31516`.

Its structural contract freezes the ten-family unauthorized-effect benchmark and requires distinct observer/executor identities and principal fingerprints, observer credential isolation from the hostile worker, authenticated observer assertion, provider-side calibration and cleanup, exact effect scope, complete read-only observation, and fail-closed `unknown` when evidence is unavailable, ambiguous, unauthenticated, wrong-source, wrong-scope, or otherwise insufficient.

This is **Verified structural proof under hold**, not real external containment. No real external provider was mutated or independently observed by PR #128, and no external unauthorized-effect rate is established.

## Keel boundary

`Ironnember/The-keel` remains an experimental execution-plane proof, not canonical Pulpo authority.

The intended split is unchanged:

- Pulpo owns identity, authority, policy, budget, approvals, permits, canonical evidence, reconciliation, and governed learning;
- Keel deterministically executes an already-authorized exact operation and returns an execution receipt that cannot self-certify reconciliation.

Keel remains draft/noncanonical until it verifies a real Pulpo cryptographic one-use permit and is admitted without creating a second authority, router, executor-of-record, or ledger.

## Proof boundary

### Verified

- canonical governance kernel, exact intent/policy binding, one-use permits, fail-closed policy, replay/restart behavior, and audit integrity;
- directive revocation and same-principal non-broadening behavior;
- tested hostile-worker software/container boundaries;
- independent collaborator review enforcement;
- base-controlled Admission Hold workflow behavior, including legitimate PR #134 Admission Hold #65;
- external HSM signing primitive;
- **canonical capability-stripped MCP boundary admitted through PR #134**;
- the failure lesson that no permit and no visible write route are insufficient if a component can still mutate or retain access to canonical state.

### Recorded

- cloud authority project/resource evidence and historical proof records;
- Keel V0 experimental execution-boundary evidence.

### Inferred

- Pulpo's strongest differentiator is authority continuity through consequence: separating intelligence capability from legitimate authority while preserving evidence that the authorized object survived to execution and reconciliation.

### Proposed

- require `admission-hold` at the repository protection layer or establish an equivalently non-spoofable protected-base rule;
- audit every externally reachable canonical-state writer against authenticated identity, scope, replay/idempotency, revocation, resource limits, and evidence requirements;
- establish genuinely distinct external provider observer/executor principals and credential isolation for Stage C;
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

Do not convert passing CI, a cloud resource, an approval, a successful executor report, an experimental distribution artifact, or market interest into authority, production-readiness, external-containment, or third-party-reproducibility claims.

## Next highest-value proof sequence

1. Through an authorized GitHub administration/settings surface, require `admission-hold` for protected `main` or establish an equivalently non-spoofable protected rule; inspect/narrow bypass posture; preserve held-denial and ready-allow acceptance evidence; then close Issue #115.
2. Audit all externally reachable canonical-state writers under the newly explicit governed-capability rule; remove or govern any remaining writer possession that lacks authenticated scoped authority.
3. Reconcile investor/partner/distribution language to current canonical `ca363668...`: MCP capability stripping is now **admitted**, while production readiness, real external containment, and cold third-party reproduction remain unproved.
4. Establish genuinely distinct external provider observer/executor principals and credential isolation for Stage C.
5. Run exactly one disposable zero-real-cost external provider ceremony through the frozen Stage-C contract and existing reconciliation path.
6. Preserve the complete evidence bundle and have an unrelated operator reproduce the proof cold.
7. Finish the independent `authority.pulpo.ai` deployment/acceptance boundary and admit Keel only after its execution contract verifies a real Pulpo cryptographic permit without becoming a second authority or ledger.

**Correctness does not create authority. Capability possession can.**
