# Admission Hold Merge-Refusal Canary V1

Status: **negative proof canary only — do not merge**.

Purpose: provide one inert repository object for proving that protected `main` rejects an exact-head merge request while the pull request remains explicitly held and `admission-hold` is unsatisfied.

This file changes no runtime behavior, authority, policy, budget, identity scope, credential, permit, executor, provider integration, reconciliation logic, deployment state, or external consequence.

Expected proof sequence:

1. Ordinary required CI passes on this exact head.
2. A qualifying independent GitHub approval exists on this exact head.
3. The PR retains the explicit Pulpo admission hold.
4. The PR is marked ready without removing the hold.
5. A squash-merge attempt against the exact head is rejected by GitHub while `admission-hold` is failing.
6. No bypass is used.

Invariant:

`HELD_OBJECT != ADMISSIBLE_OBJECT`

Claim ceiling: repository-admission negative proof only.
