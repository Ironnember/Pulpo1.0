# Time Machine Differential V1 — Attempt 1 Result

Status: **FAILED CLOSED / hypothesis corrected**

Run: `33268639014`
Head: `d95c5562b34ba7615f77d2424b2e5cade9f3fa32`

## Result

- 12 frozen historical cases executed.
- 10 matched the frozen expectation.
- 2 contradicted the frozen expectation.
- `authority_effect=none`.
- no provider write attempted.

## Falsified assumptions

### A. PR #55 checkpoint did not yet contain the PR #44 revocation fix

At merge commit `fc941266a608d7b654cc647532ac965f81582535`, the frozen sequence

`activate -> issue permit -> revoke -> consume`

still consumed the stale permit.

This is not evidence that the later PR #44 fix regressed. The PR #55 merge occurred earlier in canonical history; the verified PR #44 fix existed on its own branch before it was later reconciled and admitted to `main`.

### B. PR #44 merge commit already contained target lock

At `ec91f6f51a115f0fda6e163b9012518c97b322a0`, the exact target mismatch control was already present and failed closed before authority evaluation.

The mistaken expectation treated PR #44 as if its merge commit represented the older branch base. It does not. The merge happened onto a later `main` that already contained PR #55 Target Lock V0.

## Lesson

**PR number, branch creation date, and branch-local fix date are not canonical chronology. Git ancestry is.**

Time Machine comparisons must distinguish:
- branch-local candidate behavior;
- canonical-main behavior at a given merge point;
- later convergence of parallel proven controls.

The original `FROZEN_CONTRACT.md` and failed run are retained unchanged as evidence of the falsified hypothesis. V1.1 freezes a corrected DAG-aware contract rather than rewriting this result.
