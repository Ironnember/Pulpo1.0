# Change record — 2026-11-17 — Revocation evidence stated in the README

## 1. Invariant or failure addressed

Public-evidence gap, not a code defect. Revocation at consume time —
revoking a directive or policy invalidates permits already issued under it,
re-checked when a permit is consumed — is implemented and tested in the
canonical suite, but the README's "Proven now" list did not state it. A
reader grading Pulpo from the public record alone (as an external prior-art
scan did on 2026-11-17) could not see the mechanism. This change states it,
at exactly the strength the executable evidence carries.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. Documentation only: one README bullet and this record. No code,
no policy, no permit path is touched.

## 3. Canonical state mutations introduced or exposed

None. No interface is added, removed, or altered; no governed capability is
introduced or exposed.

## 4. Success and adversarial evidence

At canonical main `c42aad6` (the merge of PR #359), run 2026-11-17:

- Full suite: 800 tests, OK, skipped=13
  (`python -W error -m unittest discover -s tests`, full clone).
- Revocation-specific tests, all passing, including:
  - `tests/test_directives.py` —
    `test_revoked_directive_invalidates_previously_issued_permit`,
    `test_preissued_permit_stays_invalid_after_revocation_and_restart`,
    `test_parent_revocation_invalidates_child_and_preissued_child_permit`,
    `test_parent_revocation_keeps_child_permit_invalid_after_restart`;
  - `tests/test_expense_workflow.py` —
    `test_revocation_after_issue_prevents_effect_and_survives_restart`;
  - `tests/test_context_custody_gladiator.py` —
    `test_kernel_policy_revocation_before_release_denies_old_permit`,
    `test_policy_revocation_during_permit_consumption_denies` (the
    policy is replaced after `kernel.consume` returns; the test proves
    the later release is denied under the new policy — post-consumption
    denial, not reversal of the consumption);
  - `tests/test_inmemory_consume_concurrency.py` —
    `test_revoke_cannot_land_inside_consume` (proves serialized,
    linearized ordering: a revocation never precedes an admitted
    consumption in the audit record, and a consumption attempted after
    the revocation is recorded is denied; it does not show an admitted
    consumption being invalidated).

Adversarial check applied to the wording itself: the bullet claims only
behavior those tests exercise — consume-time re-check, restart persistence,
parent-to-child invalidation, and the serialized ordering of concurrent
revocation and consumption. It does not claim revocation semantics for
any surface the suite does not test.

Correction (2026-11-17, after independent review): an earlier draft of
the README bullet also claimed invalidation "while consumption is in
flight." That wording overstated the evidence above — the concurrency
test proves linearized ordering, not in-flight invalidation — and was
removed before merge; the serialized-ordering statement replaces it.

## 5. Boundary the evidence does not prove

This record covers the canonical kernel's tested behavior only. It does not
prove revocation behavior across a service boundary (Phase 3, Item 3B) or
for a permit presented by anyone other than its issued presenter (Phase 3,
Item 4B); both remain unbuilt and unclaimed.

## 6. Claim classification

**Verified** — executable evidence at the exact commit, run 2026-11-17.

## 7. Legacy behavior source

None used. The older `Iron-Ember/pulpo` repository was not consulted for
this change.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this claim: the bullet
describes current canonical main only, and no earlier state is asserted.
The dated external trigger is the 2026-11-17 prior-art scan, which graded
the README's revocation coverage as thin against the suite's actual
evidence.
