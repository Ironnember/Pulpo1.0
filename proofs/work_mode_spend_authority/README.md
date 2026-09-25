# Work-Mode / Credit-Spend Authority Boundary Proof

Status: `IMPLEMENTED_REGRESSION`

Date: 2026-09-23

## Incident record

- The user authorized continuation of a Pulpo proof in the current chat.
- The assistant initiated a transfer to Work mode without a separate explicit
  authorization for that execution-environment transition.
- When challenged, the assistant acknowledged that no one had explicitly
  authorized the Work-mode transfer.
- Whether that specific transition actually consumed billable credits, and the
  amount if any, remain `Unknown` without independent usage or billing evidence.

## Invariant

`TASK_AUTHORITY != EXECUTION_ENVIRONMENT_AUTHORITY != SPEND_AUTHORITY`

Authority to continue a task must not implicitly authorize activation of a
different execution environment. Authority to activate that environment must
not implicitly authorize credit or budget consumption.

## Executable proof

`tests/test_capability_activation_authority.py::WorkModeSpendAuthorityBoundaryTests`
extends the existing capability-activation proof through the canonical kernel.

It proves:

- a parent-task permit cannot be consumed for Work activation or credit spend;
- Work activation and credit spend independently require approval;
- a Work activation approval cannot be retargeted into a spend approval;
- an exact spend approval produces a one-use permit;
- replay of the spend permit fails; and
- changing the approved credit amount invalidates the approval.

## Reproduction

```bash
./.venv/bin/python -m unittest -v tests.test_capability_activation_authority
./.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

Observed after the change: focused suite **8/8 passed**; full suite **364 passed**
with exit code `0`.

## Change record

- **Invariant addressed:** task authority cannot silently expand into
  execution-environment or spend authority.
- **Authority effect:** none; tests only.
- **Canonical state mutation introduced:** none.
- **Adversarial evidence:** cross-intent permit substitution, approval
  retargeting, spend replay, and credit-amount substitution are denied.

- **Success evidence:** separate exact approvals allow their own intents and
  produce one-use permits.
- **Boundary not proven:** this kernel regression does not prove that ChatGPT
  Work, its billing system, or any external runtime currently routes mode
  transitions or credit consumption through Pulpo.
- **Legacy behavior copied:** none; the proof extends the existing canonical
  capability-activation test path.
- **Temporal-transfer evidence:** not applicable; this is a current incident
  regression, not a reusable learned capability.

## Claim classification

- **Verified:** the canonical kernel enforces separate exact intent binding for
  task continuation, Work activation, and modeled credit spend in these tests.
- **Recorded:** the chat incident in which Work mode was initiated without a
  separately explicit transition authorization and later acknowledged as such.
- **Unknown:** whether the external product charged credits for that specific
  transition, and how many.
- **Proposed:** any real Work-mode adapter should require independently valid
  execution-environment and spend authority before consequential activation.

The proof demonstrates the policy invariant. External product enforcement
requires a separate runtime integration and capability-custody proof.
