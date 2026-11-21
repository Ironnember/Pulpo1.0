# Phase 2: synthetic GPIO adapter contract

Issue #320 Phase 1 evidence was reviewed before this candidate was prepared.
Phase 1 Pi archive SHA-256:
`77cc9301299c7703a90a3329003b13149123bef259a667349b7737b72df86256`.
The archive integrity was Verified locally; its ARM64 execution history is
Recorded evidence from the supplied Pi artifacts, not remote attestation.

## Scope and authority

This is a Proposed Phase 2 adapter contract based on canonical main
`6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`. It has no GPIO library,
hardware backend, hardware mode, device-file access, credential lookup,
network call, subprocess-based adapter, service, or autostart configuration.
BCM pin numbers are synthetic data only; no physical pin is selected or driven.

`pulpo.node_dry_run` adds a frozen `DryRunOutput` (synthetic endpoint, BCM pin,
level, dry-run mode) and a synthetic `set_output` / `observe` interface. Its
in-memory output is the consequence sink only, not an authority or evidence
ledger. The adapter retains no kernel, signer, policy, or state writer.

The execution seam resolves the canonical locked target, checks its intent
against the complete output object, and calls `GovernanceKernel.consume` before
calling the adapter. Approvals and permit issuance remain exclusively in
`evaluate_locked_target_with_approval` / `GovernanceKernel`.
No changes are made to canonical kernel/state semantics or physical authority.

## State and evidence boundary

The fixture locks targets in canonical SQLite state; the canonical kernel
verifies test approvals, issues permits, tracks approval replay and permit
consumption, and records its existing audit events. The only new audit event is
`node_gpio_dry_run_observed`, appended through the same `KernelState` after
consumption and synthetic readback. It binds the exact output, target/version,
intent, policy, and canonical consumption record hash; no raw permit is exported.
This append is a governed state mutation despite `authority_effect=none`.
Its writer remains inside the trusted execution fixture, never a transport/UI
surface. No new state tables, router, permit issuer, or independent ledger exist.

Reconciliation is a non-mutating projection of the canonical chain and supplied
synthetic observation. It requires one matching event and its preceding exact
consumption record. Missing evidence is UNKNOWN; mismatched or duplicate
evidence is MISMATCH. Neither projection grants authority nor writes completion
state. Adapter success without canonical evidence is insufficient.

The adapter's readback is a same-process synthetic observation, not independent
physical evidence. Anyone with arbitrary Python execution or canonical writer
access is outside this proof's trust boundary. Direct sink calls are possible
and do not acquire governed provenance. There is no physical backend to bypass.
This is not a production executor or no-alternate-route/custody claim.

If consumption succeeds but the adapter, observation, or evidence append fails,
the permit remains spent and the result is UNKNOWN. There is no retry,
replacement permit, or success inference. A crash between consumption and the
adapter call can leave no output; this safety/liveness tradeoff is explicit.
The contract is serialized and single-process. Concurrent audit capture,
process isolation, and exactly-once execution under arbitrary crashes are not
proved. Restart tests close/reopen the canonical SQLite state with the same
test verifier and kernel secret; they do not restart the OS or attest hardware.
Fresh distinct approvals can authorize further calls; the bound is per permit,
not a global one-call quota. Aggregate authority remains outside this proof.

## Required proof and adversarial cases

The contract suite tests all eight Issue #320 cases: no permit, forged approval,
target substitution, exact approval/one call, approval replay before execution,
permit replay, SQLite reopen/replay, and canonical evidence reconciliation.
Additional cases cover pin/level/endpoint substitution, expired/wrong actor
approvals, malformed output, missing/wrong readback, direct ungoverned sink calls,
duplicate observations, incorrect consumption links, broken audit integrity,
and adapter/observer/audit-write failure with spent-permit replay denial.

The Phase 2 runner requires an exact Git revision and clean source before/after.
It emits JSON with timestamps, revision, statuses, case count, and test log.
Each test uses a separate temporary canonical SQLite database. Fixture state
mutations are isolated from production state. Authority fixtures come from
`tests/authority_support.py`; no human/production signing material is used.

```bash
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s tests -p 'test_pulpo_node_dry_run_gpio.py' -v
python3 proofs/pulpo-node/dry_run_gpio_proof.py \
  --expected-revision "$(git rev-parse HEAD)" \
  --output /path/outside/repository/phase2-dry-run-gpio-result.json
```

The existing Phase 1 Ultra candidate stays unchanged; CI runs the separate
Phase 2 contract after it. A Phase 1 Ultra pass does not imply a Phase 2 pass.
For the Pi, use a fresh exact candidate checkout; retain the Phase 1 tree and
evidence. Run sequentially with output outside the repository. No package
installation or privilege escalation is required. Available memory should be
checked again; these tests do not establish a peak memory bound for the Pi.

## Eight-pass adversarial review

Purpose: test a future GPIO-shaped interface using synthetic outputs only.
Requested outcome: reviewed Phase 2 contract; no physical consequence.

| Pass | Finding and boundary |
| --- | --- |
| Flip | Hostile inputs cannot alter pin, level, endpoint, mode, or target through this seam using an exact permit; substitution is tested. Arbitrary process control is not contained. |
| Reverse | A governed adapter call requires exact target resolution and canonical permit consumption. Reject mismatches before the sink; audit consumption can still be a state consequence even if a later call fails. |
| Invert | A direct synthetic sink call cannot reconcile without canonical consumption evidence. Successful output is not proof of governed provenance. |
| Inside-Out | The adapter owns no signer/kernel/writer. The trusted fixture owns kernel access; malicious canonical writers and same-process observation are explicit trust limitations. |
| Darken | Failure after consumption can leave an unobserved or absent synthetic output. UNKNOWN, spent-permit replay denial, and no automatic retry are tested. No physical surface is present. |
| Lighten | Cooperative exact approval produces one synthetic call and matching canonical evidence. It does not establish independent authority or hardware behavior. |
| Amplify | Repeated approval/permit replay and restart replay do not add calls. Distinct approvals and concurrent multi-permit aggregates require a separate proof. |
| Negate | A synthetic sink tests the interface without GPIO dependencies, physical access, new credentials, or service installation. |

Pairwise/boss case: valid permit + adapter call + observer outage + SQLite reopen
+ replay remains UNKNOWN and does not invoke the adapter again. Audit append
failure is also tested with reopen/replay; it cannot become success.

Continue decision: run only the bounded synthetic contract. No physical custody
claim follows. Phase 3 requires separately explicit authorization.

## Claim and temporal boundaries

Verified: only tests actually observed on the exact candidate revision and host
reported in their execution evidence. Pi Phase 2 execution remains Unknown until
observed on that exact candidate. Production authority, physical safety, GPIO
custody, independent hardware observation, and alternate-route containment remain
Unknown even when the synthetic suite passes.

This is a new contract candidate, not a reusable organizational lesson or a
claim of historical competence transfer. No temporal-transfer result is claimed.
The Phase 1 virtual-lamp fixture and canonical target/kernel/state interfaces
are the behavior references; no legacy authority or ledger is copied.
