# Admission Hold Held-Denial Canary V0

Status: **negative proof canary only — do not merge**.

Purpose: provide one inert repository object for proving that protected `main` mechanically rejects admission while the pull request is held.

This file changes no runtime behavior, authority, policy, budget, identity scope, credential, permit, executor, provider integration, reconciliation logic, deployment state, or external consequence.

Expected proof sequence:

1. Ordinary CI evaluates this exact head.
2. `admission-hold` remains unsatisfied while the PR carries the explicit hold marker.
3. The PR is made ready without removing the hold.
4. A merge attempt against the exact head must be rejected by GitHub protection.
5. No bypass is permitted.

Invariant:

`HELD_OBJECT != ADMISSIBLE_OBJECT`

Claim ceiling: repository-admission negative proof only.
