# Project governance

## Canonical rule

`Ironnember/Pulpo1.0` is the only forward-development repository. The legacy repository is historical evidence and a pattern source, never a merge source.

## Claim discipline

- **Proven:** behavior covered by an executable test in this repository.
- **Implemented:** code exists but its boundary is not yet independently proven.
- **Planned:** design intent only.

README and release claims must use these labels honestly.

## Change gates

Every pull request must state the governed behavior, threat or failure addressed, tests added, and boundary not covered. Changes to policy semantics require review. CI stays dependency-free until a dependency has a documented reason and owner.

Canonical `main` must be protected as part of Pulpo's constitutional change-control boundary. The required repository policy is:

- changes enter `main` through pull requests rather than direct pushes;
- force pushes and branch deletion are disabled;
- the existing `test`, `authority`, and `authority-service` CI jobs are required before merge;
- authority-, policy-, and governance-semantic changes require an explicit human review before merge;
- required checks must evaluate the exact candidate merge state rather than an older branch state;
- repository administration is not itself treated as Pulpo runtime authority, but weakening these protections is an authority-relevant governance change and must be recorded as such.

Until GitHub reports those controls as enabled, canonical branch protection is **Blocked**, not **Proven**. Documentation or workflow files must not imply that CI is merge-enforced merely because CI exists.

## Reconciliation before admission

Passing CI demonstrates candidate behavior. It does not prove that the candidate is the correct constitutional mechanism to admit.

Before a Ready/open candidate is admitted, reviewers must check the current open-proof surface for overlapping or competing implementations that touch the same authority, evidence, state, canonicalization, custody, or audit invariant.

When overlap exists:

1. identify the shared invariant and the exact competing mechanisms;
2. select one mechanism, synthesize one bounded replacement, or explicitly supersede the redundant candidate;
3. restage/retest the selected object against the current canonical head when required;
4. preserve one canonical authority/state/evidence truth;
5. record the disposition of the losing/redundant branch;
6. do not merge both merely because both pass.

Examples include competing semantic-provenance primitives, audit fast paths, portability paths, provider adapters, or duplicate evidence projections.

`TWO_GREEN_IMPLEMENTATIONS != TWO_CANONICAL_TRUTHS`

Performance, portability, and convenience changes may introduce non-authoritative indexes, caches, projections, or bounded helpers, but they may not silently become a second authority source, ledger, replay state, reconciliation truth, or historical-integrity root.

## Phase-transition discipline

A project phase transition is a governance change in priority, not an expansion of runtime authority.

A phase contract may:

- define proof priorities;
- freeze new feature families;
- order admission/reproduction work;
- state exit criteria;
- narrow public claim language.

A phase contract may not:

- authorize provider mutation;
- authorize spending;
- issue or consume a runtime permit;
- waive repository admission gates;
- convert held/recorded evidence into canonical or Verified evidence;
- transfer historical credentials, approvals, or authority into future executions.

Current Phase II is defined in [NEXT_PHASE.md](NEXT_PHASE.md).

## Proposal automation

An automation identity may prepare a reviewable change, but it cannot convert
its own proposal into a governance decision. The bounded GitHub App contract,
credential rules, stop conditions, and proof requirements are defined in
[GitHub Proposal Bot Operating Contract](GITHUB_PROPOSAL_BOT.md).

## Legacy intake

Carry forward one behavior at a time. Rewrite it behind the current interface, add adversarial tests, and record the proof. Do not copy generated evidence, startup programs, task backlogs, local-machine scripts, historical plans, or CI workarounds.
