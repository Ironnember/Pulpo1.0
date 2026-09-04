# Pulpo Current State

Status date: 2026-09-04

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is:

`83ccb8b5efbaed310712f131d5df424cbb50b211`

That commit is the merge of PR #156, which removed the accidentally admitted Stage-C readiness proposal artifacts from PR #154 while preserving independently justified dependency stabilization. The SHA is an inspection point, not a permanently pinned source-of-truth designation.

`Iron-Ember/pulpo`, `Ironnember/The-keel`, historical tags/releases, held branches, closed-unmerged proof branches, and other earlier or adjacent repositories remain historical or experimental evidence unless a legitimate governance transition explicitly admits behavior into canonical Pulpo.

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

Do not upgrade `Recorded`, `Inferred`, or `Proposed` claims through repetition.

## Verified in canonical code and CI

Current canonical merge commit `83ccb8b5efbaed310712f131d5df424cbb50b211` completed CI successfully in run `33828820303`, including `test`, `authority`, `authority-service`, `hostile-worker-custody`, and `hostile-worker-container-isolation`.

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

Cross-principal delegation and independent delegated-operator authority minting remain unproved. Canonical code proves parent-child non-broadening under the existing independently authenticated activation path, not a general organizational delegation hierarchy.

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

Canonical contribution doctrine also requires governed temporal replay for material reusable lessons when applicable historical checkpoints exist. Historical state/evidence may inform present learning, but historical credentials, approvals, permits, budgets, directives, policy expansions, or authority do not reactivate merely because a historical generation is replayed.

### MCP boundary — capability-stripped canonical behavior

The earlier admitted MCP implementation exposed a material governed-effect defect: `PulpoMCPProjection.propose_intent()` could append canonical target/audit state even though the surface created no permit and represented itself as non-authoritative. Hostile review then identified the stronger capability-possession issue: route removal alone was insufficient while the untrusted projection retained a canonical writer/orchestrator reference.

The governing invariants are now explicit:

- `NO_PERMIT != NO_GOVERNED_EFFECT`;
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`;
- `NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`.

PR #134, `Proof: governed-effect canonical mutation boundary v0`, was legitimately admitted as merge commit `ca3636680ca50356406519a5722444c0742afb39`. Its exact admitted object strips the MCP projection down to capability-free primitive/frozen input:

- the MCP-side object receives no kernel, orchestrator, state backend, authority client, executor, live policy object, trusted clock, or ledger reference;
- proposal construction is ephemeral and does not append canonical state;
- proposals carry no permit or target hash;
- the MCP projection uses frozen primitive metadata rather than a live canonical writer;
- evidence/proposal outputs report frozen freshness rather than asserting live canonical state;
- later canonical writes do not appear through an already-frozen MCP object.

This is **Verified canonical software-boundary behavior**. It does not prove hostile same-process memory isolation, production remote-MCP authentication, live-current evidence freshness, or arbitrary plugin/runtime containment.

### Bounded commerce and registrar governed-effect gap

Canonical tests prove exact domain/registrar/owner/privacy/upsell/price/renewal-price constraints, the USD 30 pilot ceiling, request/quote/order binding, reservation/reconciliation semantics, provider idempotency binding, and denial of production execution when a hard provider charge cap is unavailable.

A current canonical defect remains: `DomainPurchaseRequest` and `DomainPurchaseOrder` bind renewal price but do **not** bind provider-side auto-renew enablement state. A provider default can therefore create a future renewal capability/charge that is not represented in the exact authorized action object.

Invariant:

`CANONICAL_ACTION_OMISSION != AUTHORIZED_PROVIDER_DEFAULT`

PR #143 contains a branch-local correction that adds and verifies `auto_renew_enabled`, defaults the bounded pilot to `false`, binds it into the exact purchase object/hash, and requires provider observation/reconciliation to treat missing or substituted renewal state as unresolved/failure. That PR remains Draft/held and was built against older canonical base `ca3636680ca50356406519a5722444c0742afb39`; it must not be admitted as-is after subsequent canonical history.

The correct next commerce action is to port the smallest authority-correct auto-renew delta onto current `main`, earn fresh exact-head evidence and substantive review, and admit it through the current repository controls before using the registrar path for Stage C.

No real registrar purchase or externally observed registrar consequence is established.

## Recorded and externally verified infrastructure evidence

Issue #90 remains the durable deployment record for the independent authority boundary.

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

## Governance and repository admission state

Repository admission is now mechanically stronger than the earlier narrative/CI-only state.

### Protected required checks

GitHub protected-branch readback for `main` reports enforcement level `everyone` with the exact required contexts:

- `test`;
- `authority`;
- `authority-service`;
- `admission-hold`.

All four are bound to the GitHub Actions app in the visible branch-protection readback.

### Active ruleset and bypass posture

Active repository ruleset `22241311` targets `refs/heads/main` and reports:

- enforcement: `active`;
- strict required status checks;
- ruleset-required checks: `test`, `authority`, `authority-service`;
- one approving review required;
- stale reviews dismissed on push;
- last-push approval required;
- review-thread resolution required;
- `bypass_actors: []`;
- `current_user_can_bypass: "never"`.

The repository therefore currently uses **overlapping GitHub control surfaces**: the active ruleset requires `test`, `authority`, and `authority-service`, while protected-branch readback additionally requires `admission-hold`. Do not describe this as one consolidated ruleset.

The full legacy branch-protection endpoint remains unreadable through the connected integration and returns `403 Resource not accessible by integration`. Some branch-protection-specific admin metadata therefore remains **Unknown**. This is a visibility limitation, not evidence of an observed bypass.

### Admission incident and recovery

PR #154, `Validation: Stage-C readiness and evidence sufficiency v0`, carried an explicit process hold but was accidentally merged after review. Passing CI did not create admission authority; the merge demonstrated that a correct workflow signal without protected repository enforcement was insufficient.

PR #156 performed the authority-correct recovery. Rather than blindly reverting all of #154, it decomposed the mixed mutation and removed exactly the unauthorized Stage-C readiness artifacts while preserving independently justified AnyIO dependency stabilization.

Current `main` no longer contains:

- `docs/STAGE_C_READINESS.md`;
- `pulpo/stage_c_readiness.py`;
- `tests/test_stage_c_readiness.py`.

Those Stage-C readiness artifacts are historical/proposed evidence only and are **not canonical behavior**.

Recovery invariant:

`MIXED_MUTATION -> DECOMPOSE_BEFORE_REMEDIATION`

with:

`RECOVERY_TARGET = SMALLEST_AUTHORITY_CORRECT_DELTA`

### Issue #115 closure and executable admission proof

Issue #115, `Require base-controlled admission-hold check on protected main`, is closed as **completed** after the repository-level control was configured and exercised.

The decisive canary was PR #158 at exact head:

`2f190fa86763ed4b93b90af47a4d401cd162ca51`

Held-denial proof:

- ordinary CI and Constitutional Survival passed on the exact head;
- a collaborator approval existed on the exact head;
- the explicit Pulpo hold remained present;
- the PR was made ready without changing the code object;
- `admission-hold` failed/quarantined the held object;
- an exact-head squash merge attempt was rejected by GitHub and explicitly named the unsatisfied `admission-hold` requirement among the blockers;
- canonical `main` did not move.

Ready-allow proof on the **same exact head**:

- the PR was reopened;
- only the explicit hold/process-hold metadata was removed;
- no code commit was added;
- a fresh `admission-hold` evaluation passed;
- CI remained green;
- the PR became open/ready/mergeable;
- no merge was performed.

Invariant demonstrated:

`SAME_OBJECT + HOLD_REMOVED -> ADMISSION_SIGNAL_OPEN`

PR #158 has since been closed unmerged and retained as the evidence record.

This proves repository admission for the tested path is not reducible to code correctness or an approval click:

`CORRECTNESS != AUTHORITY`

The claim ceiling remains repository-admission control under the tested GitHub surfaces. It is not proof of production runtime containment or external consequence correctness.

## Distribution boundary

Historical `v0.1.1` remains an experimental distribution artifact and is not current canonical proof of a production product.

PR #131 remains a held distribution candidate that deliberately gives the mobile/PWA process no kernel, orchestrator, MCP projection, authority client, state backend, executor, or ledger reference. Its V0 accepts only a copied `FrozenEvidenceSource`, exposes authenticated `GET /api/evidence`, rejects authority-bearing evidence, uses no-store caching semantics, and explicitly reports `freshness: not_asserted`.

The branch-local software proof may inform future distribution work, but it is not canonical admission and does not prove production authentication, live-current evidence freshness, write-capable mobile governance, desktop distribution, native iOS/App Store admission, production deployment, or a canonical public release.

## Stage-C external consequence proof

Stage C remains **not externally proved**.

Historical/held structural work established a useful contract around distinct executor/observer identities, credential isolation, provider-side calibration and cleanup, exact effect scope, complete read-only observation, attack-family coverage, and fail-closed `Unknown` when evidence is unavailable, ambiguous, unauthenticated, wrong-source, stale, wrong-scope, or otherwise insufficient.

The accidentally admitted Stage-C readiness implementation from PR #154 has been removed by PR #156 and is not canonical. Any later Stage-C readiness/evidence-sufficiency implementation must be treated as a new proposal against current canonical state and pass current repository admission.

The current consequence claim boundary is:

`VALID_AUTHORITY + VALID_PERMIT + EXECUTION_SUCCESS != VERIFIED_CONSEQUENCE`

Issue #153 is the next highest-value executable proof. It requires the existing Pulpo path to demonstrate:

- verified match;
- mismatch despite executor success;
- unknown/evidence failure;
- restart durability of mismatch/unknown without converting to success or retry authority;
- authority freshness across revocation, expiry, substitution, replay, and non-widening constraints;
- memory/retrieval inability to raise authority;
- successful outcome memory only after reconciliation-supported success.

That proof should extend the current authority/policy/permit/evidence/reconciliation path and must not create a second authority service, policy engine, router, executor, evidence ledger, or memory governor.

Real external containment, an external unauthorized-effect rate, and third-party reproduction remain unproved.

## Keel boundary

`Ironnember/The-keel` remains an experimental execution-plane proof, not canonical Pulpo authority.

Its V0 draft establishes the intended split:

- Pulpo owns authority, policy, permits, evidence, reconciliation, and governed learning;
- Keel deterministically executes an already-authorized exact operation and returns an execution receipt that cannot self-certify reconciliation.

Recorded Keel V0 evidence includes replay, substitution, expiry, revocation, unknown-outcome restart, and authority-expansion denial under its stated software boundary.

Keel remains noncanonical because it has not yet been admitted as Pulpo's execution substrate through the current repository path and a real Pulpo cryptographic one-use permit/external consequence ceremony remains unproved.

## Proof boundary

### Verified

- canonical governance kernel, one-use permit, replay/restart, directive revocation, and tested hostile-worker software/container boundaries;
- same-principal derived-directive non-broadening and parent-live/restart denial;
- capability-stripped canonical MCP projection admitted by PR #134;
- protected `main` requires `test`, `authority`, `authority-service`, and `admission-hold` in the visible branch-protection readback;
- active main ruleset has no bypass actors and reports `current_user_can_bypass: never`;
- held-denial and same-head ready-allow repository-admission proofs on PR #158;
- Issue #115 completed;
- PR #156 removed the unauthorized Stage-C readiness artifacts while preserving the separately justified dependency stabilization;
- external HSM signing primitive.

### Recorded

- current cloud authority project/resource evidence and historical proof records referenced above;
- Keel V0 experimental boundary evidence;
- branch-local/historical Stage-C structural evidence;
- branch-local auto-renew corrective object on PR #143, which is not current-main admission evidence.

### Inferred

Pulpo's strongest differentiator is increasingly the continuity of independently governed authority and evidence through consequence, rather than generic agent orchestration or policy text.

A useful compact framing remains:

**Models can change overnight. Authority should not.**

### Proposed

- execute Issue #153 consequence-reconciliation proof on the existing canonical path;
- port the smallest auto-renew governed-effect correction from the historical #143 lineage onto current `main`, then earn fresh exact-head review/admission;
- qualify a real bounded provider with genuinely distinct executor and observer principals/credentials before any Stage-C external ceremony;
- reconcile/freeze the external validation contract against the then-current canonical commit;
- execute one safe bounded external ceremony only under separately authorized consequence scope;
- finish independent `authority.pulpo.ai` deployment/acceptance;
- obtain cold reproduction outside the build loop.

### Unknown

- branch-protection-specific admin metadata hidden by the current integration's `403` response;
- real external unauthorized-effect rate;
- real provider observer/executor separation for the target Stage-C provider;
- production authority-service acceptance;
- cold third-party reproduction of the complete consequential chain;
- production reliability, cost, throughput, false-denial rate, human-review burden, customer ROI, and arbitrary-provider correctness.

## Explicit nonclaims

Pulpo does not yet prove:

- a fully deployed and acceptance-proven independent human-authority service;
- physical WebAuthn founder/recovery credential control;
- external hostile-host or hostile-custodian resistance;
- real external-provider containment;
- a real Name.com or other registrar consequence through the final custody ceremony;
- independent provider observation and reconciliation of that consequence;
- cold reproduction of the full consequential chain by an unrelated operator;
- production throughput, latency, reliability, deployment cost, cost per governed action, false-denial rate, human-review burden, or customer ROI;
- general correctness across arbitrary agents, providers, payment rails, or execution surfaces.

Do not convert passing CI, a cloud resource, an approval, a successful executor report, an experimental distribution artifact, a financing term, a social post, or market interest into authority, production-readiness, external-containment, valuation, compliance, or third-party-reproducibility claims.

## Next highest-value proof sequence

1. Execute Issue #153: prove consequence reconciliation for verified match, mismatch, unknown evidence, restart durability, authority freshness, and successful-outcome-memory gating on the existing canonical path.
2. Restage the smallest auto-renew governed-effect correction onto current `main`; do not admit stale PR #143 as-is. Require fresh exact-head CI, Constitutional Survival, substantive review, `admission-hold`, and protected repository acceptance.
3. Establish genuinely distinct provider executor/observer principals, credential isolation, observation-window semantics, calibration/cleanup, and exact effect scope for the selected Stage-C provider.
4. Freeze a new Stage-C runtime/evidence contract against the then-current canonical commit. Historical PR #154 readiness code is reference material only.
5. Reconcile any external validator SOW/protocol to that exact frozen object before signature/payment/execution authority is granted.
6. Run exactly one safe, bounded, reversible external consequence through the existing authority -> permit -> execution -> evidence -> reconciliation path.
7. Preserve the complete evidence bundle and obtain cold reproduction by an operator outside the build loop.
8. Complete and acceptance-prove the independent `authority.pulpo.ai` deployment and only then expand production-facing authority claims.

The doctrine remains:

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
