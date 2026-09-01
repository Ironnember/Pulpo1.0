# Pulpo Current State

Status date: 2026-09-01

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is `3fb08a20712b26746e351ceccf5a556fdf6d73de`, the merge of PR #126 after reconciliation with the admitted MCP projection on PR #124. The SHA is an inspection point, not a permanently pinned source-of-truth designation.

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

## Verified in canonical code and CI

### Governance kernel

The current kernel and tests prove fail-closed intent/policy evaluation, exact intent hashing, policy hashing, one-use permits, permit substitution denial, durable SQLite replay protection across restart, audit-chain tamper detection, and bootstrap failure on invalid persisted audit state.

Static `AgentGrant` policy constrains configured principals by action, resource prefix, and cost. Unknown principals fail closed and an agent grant cannot broaden the global policy. This is least-authority policy enforcement; it is not yet a general delegated organizational-authority system.

### Independent approval contract

The approval path uses policy-pinned asymmetric public trust. Approval envelopes bind authority, verifier, key, deployment, approval identity, principal/session, exact intent, exact policy, nonce, issue time, and expiry. Invalid signatures, replay, expiry, clock rollback, trust substitution, or verifier failure deny.

The repository also contains the separately packaged authority service, WebAuthn ceremony logic, worker request/poll surface, Google Cloud KMS P-256 signer adapter, protected-evidence adapter contract, and PostgreSQL authority-state adapter. Passing tests prove those code-side contracts only; they do not prove the production authority deployment exists.

### Governed directive projection

Canonical directive code extends the existing authority/policy/state seam rather than creating a second memory governor or policy engine.

Executable tests prove:

- ordinary chat/retrieval cannot activate an authoritative directive;
- directive activation/revocation requires the existing pinned external approval path;
- approval is bound to the exact directive digest;
- an untrusted issuer is denied;
- an active directive can narrow principal/action/resource/cost while the kernel remains authoritative;
- retrieval relevance or a model summary cannot raise authority;
- substitution with a broadened directive is denied;
- revocation survives SQLite restart;
- a permit bound to a directive is one-use and carries directive identity evidence;
- revocation invalidates an already-issued directive-bound permit at consumption time, including after restart;
- a same-principal child directive must bind the exact active parent and can only narrow action, resource, budget, and time scope;
- parent revocation invalidates child authority at projection and permit-consumption time, including after restart;
- parent activity is revalidated inside the child activation mutation, closing the precheck-to-commit revocation race.

Cross-principal delegation and independent delegated-operator authority minting remain unproved. Canonical code now proves parent-child non-broadening under the existing independently authenticated activation path, not a general organizational delegation hierarchy.

### Hostile-worker consequence boundary

The custody/worker proof establishes a software/container boundary with:

- exact target/order/policy/permit binding;
- live directive revalidation when a permit is consumed;
- custody-side monotonic state and compare-and-swap admission;
- one authoritative attempt under replay/fork/two-worker races;
- durable budget reservation/attempt/reconciliation state;
- no blind retry after an unknown provider outcome;
- provider/executor success remaining a claim until independent observation;
- hostile-worker container denial of custody persistence, Docker socket, governance secrets, and provider executor/observer tokens;
- custody transition obligations projected into the existing canonical Pulpo audit rather than a second ledger.

This proves hostile-worker containment under the tested software/container boundary. It does **not** prove hostile-host, hostile-custodian, HSM/TEE containment, arbitrary-provider correctness, or real external-provider containment.

### Intent persistence and governed learning

Canonical intent-persistence proof requires completion evidence for the exact durable target version. Chat, memory, or retrieval claims cannot manufacture completion. The file-artifact proof binds target hash, intent hash, absolute artifact path, content SHA-256, byte size, trusted observation time, and audit evidence; unresolved/completed state survives SQLite restart.

Canonical contribution doctrine now also requires governed temporal replay for material reusable lessons when applicable historical checkpoints exist. Historical state/evidence may inform present learning, but historical credentials, approvals, permits, budgets, directives, policy expansions, or authority do not reactivate merely because a historical generation is replayed.

### MCP boundary — admitted behavior and discovered defect

PR #124 admitted MCP as a capability/transport projection rather than an authority source. The admitted surface cannot inject a parallel policy, approval, directive, clock, state backend, permit, executor, retrieval score, or model summary, and it cannot directly mint or consume a permit.

A subsequent hostile review discovered a narrower but material defect in the admitted implementation: `PulpoMCPProjection.propose_intent()` calls the canonical target-lock path, which appends a durable `target_locked` event. Therefore the admitted MCP projection can mutate canonical governance state even though it creates no permit and reports `authority_effect=none`.

The correct invariant is now explicit:

- `NO_PERMIT != NO_GOVERNED_EFFECT`;
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`;
- `authority_effect=none` does not imply `governed_effect=none`.

PR #132 at exact head `6b73e8029cc1f602c847c71734129ddf786d1625` contains a branch-local fix that makes MCP proposal construction ephemeral and non-mutating. CI #452 and Constitutional Survival #115 pass on that exact head. The fix remains Draft/held pending independent substantive review and legitimate admission, so it is **Verified on the held branch but not yet canonical**.

### Bounded commerce and Name.com contracts

Canonical tests prove exact domain/registrar/owner/privacy/upsell/price/renewal constraints, the USD 30 pilot ceiling, request/quote/order binding, reservation/reconciliation semantics, provider idempotency binding, and denial of production execution when a hard provider charge cap is unavailable.

A separate read-only Name.com sandbox readiness proof exists. Name.com sandbox remains a credible external zero-real-charge Stage-C candidate, but observer/executor principal separation, provider-side observation identity/window semantics, and credential isolation are not yet established. No Name.com registrar write or completed external purchase is established.

## Recorded and externally verified infrastructure evidence

Issue #90 is the durable deployment record for the independent authority boundary.

The Google Cloud authority project is recorded as:

- project: `dulcet-opus-499511-a5`;
- project number: `286256558392`;
- region: `us-west1`;
- authority key ring: `projects/dulcet-opus-499511-a5/locations/us-west1/keyRings/pulpo-authority`.

The exact non-exportable signer has been created and externally verified:

`projects/dulcet-opus-499511-a5/locations/us-west1/keyRings/pulpo-authority/cryptoKeys/approval-signer/cryptoKeyVersions/1`

Recorded/verified metadata:

- state: `ENABLED`;
- algorithm: `EC_SIGN_P256_SHA256`;
- protection level: `HSM`;
- curve: NIST P-256;
- Pulpo canonical SEC1-point trust fingerprint: `b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127`;
- a live KMS signature over the deterministic proof message verified locally against the independently fetched public key.

This proves the external signing primitive. It does not by itself prove `authority.pulpo.ai`.

The Service Networking API has also been verified enabled. A dedicated private authority VPC/subnet/PSA path was frozen and explicitly authorized, but the durable evidence available here does not establish a fully acceptance-proven production authority network and service boundary.

## Independent authority remains incomplete

`https://authority.pulpo.ai` / RP ID `authority.pulpo.ai` remains the selected human authority origin, but the complete deployed boundary has not passed acceptance.

Still required:

- independently administered authority-service deployment;
- verified private network path;
- protected multi-instance Cloud SQL/PostgreSQL authority state using provider/database time;
- independently retained create-only authority evidence with effective locked retention;
- worker request/poll ingress bound to the exact governed-worker identity;
- primary hardware WebAuthn credential plus separately controlled offline recovery credential;
- exact DNS, TLS, load-balancer/origin acceptance;
- success, denial, replay, rollback, expiry, concurrency, signer-failure, state-failure, evidence-failure, origin/RP, and credential acceptance matrix;
- fresh external reproduction after restart/service replacement.

Until those pass, external language must distinguish **verified external HSM signer** from **deployed independent human authority**.

## Governance/admission state

Protected `main` currently exposes required status contexts exactly `test`, `authority`, and `authority-service` through the branch metadata visible to this integration. `admission-hold` is not currently a protected required context.

PR #109 demonstrated that narrative governance is insufficient: it was merged while its body retained an explicit `DRAFT / DO NOT MERGE` authority boundary. PR #110 restored the exact prior tree without rewriting history.

The admitted base-controlled `Admission Hold` workflow now executes trusted current-base code and fails closed on GitHub draft state, explicit machine hold markers, recognized legacy hold declarations, hold title prefixes, or hold labels. After live failures exposed unsupported Draft conversion and stale-base assumptions, the admitted mitigation now quarantines an exact held non-draft PR by closing it through supported REST semantics while preserving the failing hold signal.

Disposable canary #117 verified this defense-in-depth behavior: reopening a held non-draft PR caused the trusted current-base workflow to close it unmerged while Admission Hold failed as intended.

Repository-enforced independent collaborator review is also Verified: protected merge attempts on otherwise-green exact heads have been rejected until approval from someone other than the last pusher exists.

**Issue #115 remains open.** The stronger repository-level closure is not proved because `admission-hold` is not a required protected status, repository rulesets are absent, and the full admin/bypass posture cannot be read or mutated through the currently connected integration. Do not represent the unauthorized-admission class as non-bypassably closed until the required context or equivalent protected rule and bypass posture are independently verified with held-denial and ready-allow canaries.

## Distribution boundary

Historical `v0.1.1` remains an experimental distribution artifact and is not current canonical proof of a production product.

PR #131 is a held distribution candidate that deliberately gives the mobile/PWA process no kernel, orchestrator, MCP projection, authority client, state backend, executor, or ledger reference. Its current V0 accepts only a copied `FrozenEvidenceSource`, exposes authenticated `GET /api/evidence`, rejects authority-bearing evidence, uses no-store caching semantics, and explicitly reports `freshness: not_asserted`.

The branch-local software proof is green, but the PR remains Draft and requires exact-head substantive review/admission. It does not prove production authentication, live-current evidence freshness, write-capable mobile governance, desktop distribution, native iOS/App Store admission, production deployment, or a canonical public release.

## Stage-C external consequence proof

PR #128 freezes a structural external-provider observation contract over the ten-family unauthorized-effect benchmark. Exact head `b24e1f42ec19f844fd6955d2a94127c954e31516` passes CI and Constitutional Survival under an active hold.

The structural contract requires distinct observer/executor identities and principal fingerprints, observer credential isolation from the hostile worker, provider-side calibration and cleanup, exact frozen effect scope, complete read-only observation, and fail-closed `unknown` when evidence is unavailable, ambiguous, unauthenticated, wrong-source, wrong-scope, or otherwise insufficient.

This is **Verified structural proof under hold**, not real external containment. No real external provider was mutated or independently observed by PR #128, and no external unauthorized-effect rate is established.

## Keel boundary

`Ironnember/The-keel` is an experimental execution-plane proof, not canonical Pulpo authority.

Its V0 draft establishes the intended split:

- Pulpo owns authority, policy, permits, evidence, reconciliation, and governed learning;
- Keel deterministically executes an already-authorized exact operation and returns an execution receipt that cannot self-certify reconciliation.

Eight Keel V0 boundary tests pass, including replay, substitution, expiry, revocation, unknown-outcome restart, and authority-expansion denial. Exact head `07b975c6e7e6a7b65b1b1d2f36673ec7d6636bc5` passes Keel V0 Boundary run #4 across Python 3.11, 3.12, and 3.13, including compile and zero-production-dependency hygiene checks.

Keel remains draft/noncanonical because it has not yet verified a real Pulpo cryptographic one-use permit or been admitted as Pulpo's execution substrate.

## Proof boundary

### Verified

- canonical governance kernel, one-use permit, replay/restart, directive revocation, and tested hostile-worker software/container boundaries;
- same-principal derived-directive non-broadening and parent-live/restart denial;
- independent collaborator review enforcement and Admission Hold REST quarantine defense-in-depth;
- external HSM signing primitive;
- branch-local non-mutating MCP correction on #132 exact head;
- branch-local Stage-C structural observation contract on #128 exact head.

### Recorded

- current cloud authority project/resource evidence and historical proof records referenced above;
- Keel V0 experimental boundary evidence.

### Inferred

- Pulpo's strongest differentiator is increasingly the continuity of independently governed authority and evidence through consequence, rather than generic agent orchestration or policy text.

### Proposed

- admit #132 after independent substantive exact-head review;
- make `admission-hold` repository-required or establish an equivalently non-spoofable protected-base rule and narrow bypass posture;
- execute one bounded real external Stage-C ceremony only after observer/executor separation is independently established;
- admit a distribution surface only after its exact candidate survives substantive review and normal repository admission.

### Unknown

- final admin/bypass posture for protected `main`;
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

1. Complete independent substantive review of PR #132 and admit the non-mutating MCP boundary only if the exact object survives review and normal repository admission.
2. Through an authorized GitHub administration/settings surface, require `admission-hold` for protected `main` or establish an equivalently non-spoofable protected rule; inspect/narrow bypass posture; preserve held-denial and ready-allow acceptance evidence; then close Issue #115.
3. Reconcile investor/partner/distribution language to this exact proof boundary: serious pre-production governance/evidence system, verified software-boundary controls and HSM signer, no claim of production readiness, real external containment, or cold third-party reproduction yet.
4. Establish genuinely distinct external provider observer/executor principals and credential isolation for Stage C.
5. Run exactly one disposable zero-real-cost external provider ceremony through the frozen Stage-C contract and existing reconciliation path.
6. Preserve the complete evidence bundle and have an unrelated operator reproduce the proof cold.
7. Finish the independent `authority.pulpo.ai` deployment/acceptance boundary and admit Keel only after its execution contract verifies a real Pulpo cryptographic permit without becoming a second authority or ledger.

The doctrine remains:

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
