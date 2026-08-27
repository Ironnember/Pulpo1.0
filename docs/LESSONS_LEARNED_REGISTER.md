# Pulpo Consolidated Lessons Learned Register

Status date: 2026-08-26
Status: governed Outcome Memory; proposed for canonical admission through review
Related issue: #29

## Constitutional boundary

This register compounds learning without granting authority. It is a projection over stronger evidence, not a second ledger. Executable behavior, tests, canonical repository state, durable runtime evidence, and evidence-linked outcome records outrank this summary when they conflict.

`Learning may improve competence and recommendations. Learning may not grant authority to itself.`

Each lesson should be read as:

`Observation -> Evidence -> Lesson -> Invariant -> Architectural consequence -> Regression proof -> Remaining boundary`

Claim classes: `Verified`, `Recorded`, `Inferred`, `Proposed`, `Unknown`.

## Consolidated lessons

### 1. Capability is not authority
- Observation: tools, credentials, endpoints, and successful prior execution expose capability but do not establish permission.
- Evidence: authority-boundary tests, GitHub capability/authority cases, external Nitter/X case study.
- Lesson: discovered capability cannot bootstrap authority.
- Invariant: `CAPABILITY != AUTHORITY`.
- Architectural consequence: authority and policy evaluation precede permits and execution.
- Regression proof: deny actions lacking independently established authority even when executable.
- Remaining boundary: production enforcement across all execution surfaces.

### 2. Authority cannot authenticate itself
- Observation: cryptographic verification is insufficient if the governed principal controls enrollment, signing, or trust bootstrap.
- Evidence: pinned asymmetric verifier and external authority-service work.
- Lesson: authority establishment must be outside the governed worker boundary.
- Invariant: the principal requesting authority cannot create or impersonate the authority mechanism.
- Architectural consequence: external authority service, pinned verifier trust, protected monotonic state and trusted time.
- Regression proof: deny key, verifier, deployment, signer, time, and trust substitution.
- Remaining boundary: independently deployed production human-authority service remains unproven.

### 3. Learning cannot grant authority
- Observation: competence, confidence, repeated success, and repeated approval can tempt systems to widen permissions automatically.
- Evidence: Outcome Learning Protocol and governed-learning doctrine.
- Lesson: adaptation and constitutional authority are separate.
- Invariant: learning may recommend authority changes but never enact them.
- Architectural consequence: capability, budget, identity scope, approval class, policy power, and execution-surface expansion require separate legitimate authorization.
- Regression proof: successful learning or execution cannot mint a permit or policy transition.
- Remaining boundary: systematic enforcement across future adaptive components.

### 4. Security state must survive restart
- Observation: one-use/replay guarantees fail if consumption state disappears with process memory.
- Evidence: restart-safe replay persistence proof.
- Lesson: restart is an adversarial boundary whenever durable authority matters.
- Invariant: consumed approvals, nonces, permits and relevant evidence remain consumed after restart.
- Architectural consequence: atomic durable state and bootstrap verification.
- Regression proof: replay remains denied after reopening state.
- Remaining boundary: rollback-resistant/protected storage.

### 5. Concurrency is governance correctness
- Observation: concurrent audit appends exposed a race around evidence-chain state.
- Evidence: recorded audit concurrency failure and correction.
- Lesson: sequential correctness is insufficient for shared governance state.
- Invariant: concurrent operations cannot fork canonical evidence or over-reserve governed resources.
- Architectural consequence: transactional serialization and concurrency tests.
- Regression proof: simultaneous operations preserve one valid evidence/state history.
- Remaining boundary: distributed concurrency and multi-host coordination.

### 6. Durable storage is not protected storage
- Observation: SQLite persistence survives ordinary restart but a hostile host may delete, replace, write, or roll back the file.
- Evidence: CURRENT_STATE and commerce persistence reconciliation.
- Lesson: persistence and rollback resistance are distinct claims.
- Invariant: `DURABLE != ROLLBACK_RESISTANT`.
- Architectural consequence: protected monotonic state is required for stronger authority/economic claims.
- Regression proof: ordinary restart proof exists; hostile rollback proof does not.
- Remaining boundary: host-compromise and rollback protection.

### 7. Budget policy must bind the real economic side effect
- Observation: provider APIs may not expose a hard pre-charge maximum even when Pulpo has an internal ceiling.
- Evidence: name.com CORE fail-closed production boundary.
- Lesson: post-charge accounting cannot substitute for pre-execution spending control.
- Invariant: execution must deny when the payment/provider surface cannot enforce the authorized ceiling.
- Architectural consequence: provider contracts must map Pulpo budget semantics to enforceable external behavior.
- Regression proof: production path denies before external execution when a hard cap is unavailable.
- Remaining boundary: live payment-rail enforcement.

### 8. Command success is not outcome success
- Observation: API/CLI success does not prove delivery, acceptance, value, or correct external consequence.
- Evidence: commerce outcome decomposition and Outcome Learning Protocol.
- Lesson: execution evidence and outcome evidence are separate.
- Invariant: `AUTHORIZED != EXECUTED != DELIVERED != ACCEPTED != VALUABLE`.
- Architectural consequence: verification and reconciliation follow execution.
- Regression proof: unresolved external consequence cannot be classified as full success.
- Remaining boundary: independent production outcome verification.

### 9. Reconciliation is a first-class control
- Observation: governance that stops at execution cannot detect cost drift, provider substitution, incomplete delivery, or stale external authority.
- Evidence: canonical lifecycle and outcome protocol.
- Lesson: reconciliation closes intent-to-consequence gaps.
- Invariant: material execution remains unresolved until expected and observed state are compared.
- Architectural consequence: `Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`.
- Regression proof: reconciliation mismatches remain explicit rather than being promoted to success.
- Remaining boundary: automated external-state reconciliation across providers.

### 10. Evidence is not authority
- Observation: receipts, signatures, logs, tests, and provider responses prove facts only within their evidence scope.
- Evidence: authority and evidence contracts.
- Lesson: downstream evidence cannot retroactively legitimize upstream authority.
- Invariant: evidence reports; governance disposes.
- Architectural consequence: evidence references decisions but cannot issue permits.
- Regression proof: evidence surfaces have no authority-granting path.
- Remaining boundary: broader external evidence provenance.

### 11. One governance truth; many projections
- Observation: specialized proof, learning, portability, and multi-agent views create pressure for duplicate ledgers.
- Evidence: proof-bundle and outcome-memory architecture.
- Lesson: useful views should project canonical evidence rather than become competing truth stores.
- Invariant: no second canonical ledger.
- Architectural consequence: read-only evidence projections.
- Regression proof: projections cannot mutate governance truth.
- Remaining boundary: future integrations must preserve this property.

### 12. Multiple authority/router paths create constitutional ambiguity
- Observation: legacy accumulation widened trusted surfaces and duplicated orchestration responsibilities.
- Evidence: clean Pulpo1.0 baseline and migration rules.
- Lesson: architectural convenience can silently multiply authority paths.
- Invariant: one canonical governance/permit path; no second router, executor, ledger, or authority system by implication.
- Architectural consequence: reuse current canonical components before adding new ones.
- Regression proof: legacy behavior enters one behavior at a time behind current interfaces.
- Remaining boundary: continued review as integrations grow.

### 13. Migration can reproduce the failure it intends to remove
- Observation: a legacy migration merged into a historical repository after Pulpo1.0 had been designated canonical, while promised CI proof failed.
- Evidence: OUTCOME_CASE_LEGACY_MIGRATION_REGRESSION.md and merge evidence.
- Lesson: useful code and recent merges do not establish source-of-truth authority.
- Invariant: `MERGED != VERIFIED != CANONICAL`.
- Architectural consequence: behavior-by-behavior admission with adversarial tests.
- Regression proof: historical repositories remain non-canonical absent separate redesignation.
- Remaining boundary: prevent future source-of-truth drift operationally.

### 14. Historical evidence should inform, not govern
- Observation: older repositories contain valuable mechanisms and failures but also stale assumptions and clutter.
- Evidence: CURRENT_STATE forward-development rule.
- Lesson: memory must not silently become policy.
- Invariant: recency, merge status, historical success, or convenience cannot grant canonical authority.
- Architectural consequence: preserve history as evidence/pattern source only.
- Regression proof: canonical state explicitly outranks historical repositories.
- Remaining boundary: automated provenance/precedence tooling.

### 15. Negative tests are primary proof instruments
- Observation: replay, mismatch, expiry, tamper, substitution, concurrency and denied execution reveal controls more strongly than happy paths alone.
- Evidence: kernel, authority, persistence, commerce, and provider contract tests.
- Lesson: security/governance claims require adversarial denial evidence.
- Invariant: material controls require success and relevant denial/failure proofs.
- Architectural consequence: test suites emphasize mismatch, replay, restart, tamper and boundary failure.
- Regression proof: existing canonical tests exercise these classes.
- Remaining boundary: production adversarial testing.

### 16. Test counts are not proof classifications
- Observation: many passing tests can surround the wrong trust boundary.
- Evidence: authority-boundary evolution and explicit CURRENT_STATE claim limits.
- Lesson: proof scope matters more than count.
- Invariant: every test claim identifies invariant, environment, commit and untested boundary.
- Architectural consequence: evidence-bounded language.
- Regression proof: CURRENT_STATE restricts external claims despite passing tests.
- Remaining boundary: independent reproduction.

### 17. CI is part of the evidence system
- Observation: startup failures prevented promised repository-level proof even where code existed.
- Evidence: historical migration workflow failure and canonical CI discipline.
- Lesson: reproducibility infrastructure is evidence infrastructure.
- Invariant: passing CI proves only the identified commit/environment; failed or absent CI cannot be promoted to verified execution.
- Architectural consequence: minimal dependency-free reproducible verification remains a priority.
- Regression proof: canonical verification command and required checks.
- Remaining boundary: broader environment reproduction.

### 18. Authority without capability is blocked; capability without authority is denied
- Observation: GitHub branch protection demonstrated legitimate authorization while the connected surface lacked administrative capability.
- Evidence: Proof Zero BLOCKED_CAPABILITY case.
- Lesson: authority and execution capability are orthogonal.
- Invariant: neither substitutes for the other.
- Architectural consequence: route only to already-authorized capable surfaces; never widen machine authority to escape a block.
- Regression proof: 403/scope failure remains blocked rather than falsely successful.
- Remaining boundary: capability discovery and routing across more surfaces.

### 19. Tools, plugins, models and workers are capabilities, not governors
- Observation: execution surfaces can be powerful and mutable.
- Evidence: canonical three-plane doctrine.
- Lesson: changing or adding a tool must not change constitutional authority.
- Invariant: models/plugins/shells/APIs/providers cannot grant themselves authority.
- Architectural consequence: all execution surfaces remain subordinate to Pulpo policy/permits.
- Regression proof: authority is bound outside the execution adapter.
- Remaining boundary: enforcement around all future plugins and remote workers.

### 20. UI state is not security evidence
- Observation: prototypes can display security states without corresponding enforcement.
- Evidence: quarantined prototype lessons and evidence doctrine.
- Lesson: presentation cannot establish a control.
- Invariant: `DISPLAYED != ENFORCED != VERIFIED`.
- Architectural consequence: UI consumes evidence rather than inventing it.
- Regression proof: unsupported security claims remain non-canonical.
- Remaining boundary: production UI/evidence binding.

### 21. Measure the state change claimed
- Observation: generated explanation, task completion, or engagement does not by itself prove learning or value.
- Evidence: Master Teacher/governed-learning reasoning and Outcome Learning Protocol.
- Lesson: acceptance/value need explicit measurement.
- Invariant: claimed outcome requires evidence of the corresponding state change.
- Architectural consequence: diagnose/attempt/feedback/transfer/evidence/reconciliation for learning; analogous acceptance criteria elsewhere.
- Regression proof: accepted/value states remain separate from execution.
- Remaining boundary: domain-specific outcome metrics.

### 22. Outcome Memory should preserve consequences, not transcripts
- Observation: raw conversation is noisy, privacy-expensive, and weaker than durable evidence.
- Evidence: Outcome Learning Protocol.
- Lesson: memory should retain verified outcomes, conditions, failures, provenance and reusable paths.
- Invariant: stronger evidence outranks conversational summary.
- Architectural consequence: evidence-linked compact memory records.
- Regression proof: canonical memory schema references evidence IDs/commits/receipts/policy versions.
- Remaining boundary: durable production memory implementation and retention policy.

### 23. Failure is valuable only when reconciled
- Observation: failures become repeated waste unless converted into durable invariants and regression proofs.
- Evidence: audit race, authority gaps, CI failures, migration regression and provider limitations.
- Lesson: failure should compound competence, not authority.
- Invariant: `failure -> evidence -> root cause -> invariant -> correction -> regression proof -> memory`.
- Architectural consequence: governed outcome learning.
- Regression proof: legacy migration regression is preserved rather than erased.
- Remaining boundary: automate safe extraction without over-generalization.

### 24. Simulated proof must remain explicitly simulated
- Observation: mocks, sandboxes and simulators validate semantics but not production boundaries.
- Evidence: authority-service fixtures, name.com sandbox, prototype/quantum reasoning.
- Lesson: simulation scope must be explicit.
- Invariant: `SIMULATED != DEPLOYED != PRODUCTION_VERIFIED`.
- Architectural consequence: claim classifications distinguish protocol proof from production consequence.
- Regression proof: CURRENT_STATE explicitly denies live-purchase and production-authority claims.
- Remaining boundary: external workloads and independent evaluation.

### 25. External authority and provider conditions drift over time
- Observation: execution methods can remain technically functional while terms, credentials, API behavior, law, or provider policy changes.
- Evidence: external Nitter/X case study, classified `Inferred` for Pulpo architectural relevance rather than internal Pulpo proof.
- Lesson: historical success cannot create permanent execution entitlement.
- Invariant: external authority/environment changes require reconciliation before continued consequential execution.
- Architectural consequence: proposed authority-drift detection/invalidation mechanism.
- Regression proof: not yet implemented as a general mechanism.
- Remaining boundary: formal authority-drift watchers, revocation propagation and policy refresh.

### 26. Portability means governed state continuity, not hidden-mind copying
- Observation: opaque model reasoning/session state is not a reliable portable authority artifact.
- Evidence: portability and evidence-contract reasoning.
- Lesson: migrate explicit Pulpo-owned contracts, checkpoints, evidence and authority references.
- Invariant: hidden provider state is not canonical governance state.
- Architectural consequence: provider-neutral explicit state bundles.
- Regression proof: substitution must not change authority/order/task/evidence binding.
- Remaining boundary: broader cross-provider execution proof.

### 27. Efficiency remains subordinate to proof
- Observation: caching, compression and routing can reduce work but can also reuse stale evidence or hide changed risk.
- Evidence: verification and evidence doctrine.
- Lesson: optimize computation only after equivalence and risk are established.
- Invariant: minimum sufficient computation, never minimum sufficient evidence.
- Architectural consequence: high-risk changes re-prove relevant boundaries.
- Regression proof: evidence reuse requires equivalent governed inputs.
- Remaining boundary: formal cache/evidence invalidation rules.

### 28. External providers cannot become implicit policy authorities
- Observation: provider API semantics often differ from Pulpo's required authority/budget/evidence semantics.
- Evidence: name.com CORE boundary and GitHub capability cases.
- Lesson: provider capability must be translated into Pulpo-governed contracts.
- Invariant: provider behavior cannot widen Pulpo authority.
- Architectural consequence: fail closed when provider guarantees are weaker than policy.
- Regression proof: name.com production execution denial without enforceable hard cap.
- Remaining boundary: provider-specific production contracts.

### 29. Humans belong at authority boundaries, not every keystroke
- Observation: constant micro-approval destroys useful autonomy while broad ambient authority destroys control.
- Evidence: Proof Zero and external-authority architecture.
- Lesson: humans should establish purpose, consequential boundaries, exceptions and authority transitions while machines execute bounded work.
- Invariant: legitimate human authority remains separable from machine competence.
- Architectural consequence: request/poll approval boundary and one-use permits.
- Regression proof: worker cannot substitute its own approval.
- Remaining boundary: deployed ergonomic human-authority flow.

### 30. Evidence constrains humans and machines
- Observation: humans, models, providers and interfaces can all overstate success or misunderstand system state.
- Evidence: accumulated regressions and evidence-bounded claim discipline.
- Lesson: governance needs independently inspectable evidence, not trusted narration.
- Invariant: material claims remain classified and bounded by reproducible evidence.
- Architectural consequence: `Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation teaches.`
- Regression proof: canonical CURRENT_STATE explicitly lists what is and is not proven.
- Remaining boundary: independent external reproduction and customer outcomes.

## External case study: Nitter / X authority drift

Classification: `Recorded external event` plus `Inferred Pulpo lesson`; not an internal Pulpo proof.

Reported 2026-08-25/26 events around X Corp.'s cease-and-desist against Nitter illustrate a useful governance distinction: long-running technical capability and repeated successful access do not themselves establish durable authority to continue an execution method. Terms, credentials, platform controls, legal assertions, and provider policy can change independently of technical competence.

Proposed Pulpo invariant:

`HISTORICAL_SUCCESS != CURRENT_AUTHORITY`

Proposed mechanism: when a material external authority, provider contract, credential, API policy, legal constraint, or execution condition changes, affected authority should be reconciled and stale permits/assumptions invalidated or reauthorized before consequential execution continues.

This mechanism is not yet claimed as generally implemented.

## Canonical synthesis

Pulpo is the governance and evidence plane between intelligence and consequential execution.

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

`Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation teaches.`

Reconciliation teaches, but it does not legislate.

## Admission and update rule

Future lessons should be appended only when evidence supports a new observation or materially changes an existing one. Do not promote a chat summary, external analogy, successful execution, test count, repository merge, or newer timestamp into canonical truth by itself.

For every material update:

1. identify the strongest evidence;
2. classify the claim;
3. state the lesson narrowly;
4. derive the invariant;
5. identify the architectural consequence;
6. add or reference an executable regression proof where possible;
7. state the remaining boundary;
8. require separate authorization for any authority expansion.
