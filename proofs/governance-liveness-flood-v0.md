# Governance Liveness Under Request Flood Proof V0

Status: PROPOSED until exact-head executable evidence passes.

Parents: red-team Issue #189 and adaptive-poisoning Draft PR #193 exact green head `1ba6e8495c5d3966acf58c66d8cdc1e8cd44e3af`.

## Purpose

Attack Pulpo's fail-closed posture as a denial-of-service surface.

The failure under test is not unauthorized execution. It is a hostile request flood that consumes enough verification capacity to delay or starve higher-priority safety transitions such as revocation and reconciliation.

Core invariants:

```text
FAIL_CLOSED_SECURITY != UNBOUNDED_VERIFICATION_COST
REQUEST_FLOOD_MUST_NOT_STARVE_REVOCATION
REQUEST_FLOOD_MUST_NOT_STARVE_RECONCILIATION
OVERLOAD_MUST_NOT_CREATE_AUTHORITY
DEGRADED_MODE_DENIES_NEW_CONSEQUENCE
CONTROL_LIVENESS != CONTROL_AUTHORITY
```

## Proof shape

This is a proof-only deterministic scheduler around existing Pulpo callbacks. It is not canonical routing logic and is intentionally kept outside production modules.

The harness has two bounded classes of work:

- `control`: already-authorized safety/control transitions such as revocation or reconciliation;
- `request`: ordinary proposal/admissibility work.

Rules:

1. request admission is capped per principal and globally before expensive work begins;
2. overflow is rejected/contained without invoking expensive semantic evaluation;
3. control work has reserved capacity and deterministic precedence over request work;
4. overload/degraded state denies new consequential request admission but does not disable revocation or reconciliation;
5. the queue itself cannot issue permits, create authority, activate directives, or classify reconciliation success.

## Frozen adversarial matrix

### L01 — flood cannot starve revocation

- Create an active directive-bound one-use permit using existing kernel/state semantics.
- Fill the request queue to capacity and attempt thousands of additional submissions.
- Enqueue an already-authorized revocation callback after the flood.
- Revocation must execute on the next scheduler step before any queued request work.
- Consumption of the pre-revocation permit must then fail because live directive state is revoked.

### L02 — flood cannot starve reconciliation

- Represent one already-transmitted effect awaiting independent observation.
- Saturate the request queue.
- Enqueue a reconciliation callback using existing `reconcile_effects` semantics over a frozen local proof surface.
- Reconciliation must execute before queued request work and produce the expected result.

### L03 — degraded mode denies new consequence

Once request capacity is exhausted:

- new consequential requests are rejected/contained at ingress;
- no kernel evaluation occurs for rejected overflow;
- no permit is created;
- no execution/provider callback occurs.

### L04 — expensive semantic work is bounded

A proof-only expensive evaluator counter is attached to admitted request work.

- thousands of overflow requests must not call it;
- only bounded admitted work may reach it;
- control work remains independent of that evaluator.

### L05 — malicious principal cannot consume all tenant capacity

Per-principal quotas must leave capacity available for another principal until the global request bound is legitimately reached.

### L06 — control flood is also bounded

Reserved control capacity is finite. Overflow must fail closed rather than grow without bound. A failed control enqueue does not convert the control operation into success or authority.

### L07 — request processing cannot outrank newly arrived safety work

After one ordinary request step, enqueue revocation/reconciliation while requests remain queued. The next step must service control work first.

### L08 — unavailable control callback remains explicit failure

If a revocation/reconciliation callback raises or cannot complete:

- the scheduler records failure;
- no request authority is widened;
- degraded mode remains fail-closed for new consequence;
- failure is not silently converted to successful revocation/reconciliation.

## Claim boundary

A PASS may establish only:

> In the exact deterministic proof harness, bounded request queues and reserved control capacity prevent the tested request floods from starving already-authorized revocation and reconciliation callbacks, while overload rejects new consequential work before expensive evaluation and without creating authority.

It does not establish production throughput, distributed fairness, real-time latency bounds, hostile-host resistance, network-level DoS resistance, production queue correctness, or external-provider availability.

## Authority / admission

`authority_effect=none`

`governed_effect=none`

`provider_effect=none`

The scheduler is proof infrastructure only. It does not become a second router, executor, policy engine, authority service, reconciler, or ledger.

Passing evidence is not merge, deployment, policy, or execution authority.
