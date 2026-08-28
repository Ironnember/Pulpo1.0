# Canonical Consequence Pivot

Status: **Proposed for protected-main admission**
Decision date: 2026-08-27
Authorized direction: explicit user instruction to record this reasoning as a pivot point for future projects.
Canonical base at decision time: `48874a811e147e3673dc769d330d93039ec66ce7`

## Decision

Iron & Ember projects should not measure progress by the rate at which experiments, lessons, branches, or evidence artifacts accumulate.

The default measure of progress is **canonical consequence**: the strongest currently supported invariant must be reconciled into the current canonical path, reverified against that path, and admitted through legitimate governance before unrelated frontier expansion outruns it.

Compact form:

> **When research velocity outruns canonical control admission, consolidate before expanding.**

This rule does not let evidence authorize itself. A passing experiment, strong inference, or successful branch can raise priority and competence, but it cannot grant its own merge, authority, budget, scope, or canonical status.

## How this understanding was reached

This pivot came from reconciling the repository rather than extending the project narrative.

### 1. The project proved governed learning on a real external state surface

Protected `main` admitted PR #42, which demonstrated field-level recursive transfer on reversible GitHub state. The experiment produced a real external effect, reconciled the exact effect version against a later interleaving mutation, extracted a new verification lesson, and used that lesson to improve the completeness of verification on a second deterministic field effect from 7/10 to 10/10 while `authority_effect = none`.

That established an important property: execution evidence can improve later competence without granting authority.

### 2. A more consequential constitutional defect was already known

PR #44 froze and reproduced a stale-authority failure:

`activate D1 -> issue P1 -> revoke D1 -> consume P1`

The pre-fix behavior allowed the permit to execute after its authorizing directive had been revoked. The candidate fix bound the permit to the exact directive identity/version/hash/validity interval and rechecked live directive state at consumption. Its branch evidence showed revocation denial, restart persistence of that denial, one-use behavior for live directives, and reconciliation into the existing audit chain.

This was not another research preference. It was a direct execution-time authority invariant.

### 3. The constitutional fix remained outside canonical main while the frontier kept moving

After PR #44 was produced, subsequent experimental generations extended temporal transfer and cross-model reasoning research. Those experiments generated useful evidence, including strong failure-reconciliation behavior, but they did not retire a boundary more consequential than stale authority surviving until execution.

At the assessment point, PR #44 had diverged from current `main`: its five proof commits were ahead of their original base while current canonical `main` had moved seventeen commits beyond their merge base.

The consequence was structural: **the project had more knowledge about how to learn while its strongest execution-time authority improvement was still noncanonical.**

### 4. The latest frontier experiment reinforced the priority inversion

The latest cross-model generation correctly reconciled its own execution failure without expanding authority, but produced zero successful model inference calls and therefore no cross-model lift claim.

That failure was good governance evidence. It was also a signal that another frontier generation had lower expected value than reconciling the already-demonstrated authority control into the canonical path.

### 5. The governing insight

The limiting factor had changed.

Earlier, Pulpo's bottleneck was discovering the right architecture and invariants. Once those invariants became executable, the bottleneck became **canonical admission of consequence-bearing controls**.

Continuing to maximize research velocity at that point creates a new form of drift:

- evidence can become deeper than the canonical system that is supposed to embody it;
- branches can accumulate mutually useful but increasingly expensive lineages;
- the project can appear to advance while its highest-value control remains outside the production path;
- later work increases reconciliation cost and makes the strongest proof harder, not easier, to admit.

The corrective principle is therefore not "stop learning." It is:

> **Learning should compound into the canonical control path before the project spends heavily on another frontier generation.**

## Canonical Consequence Rule

For Pulpo and future Iron & Ember projects, apply this default rule:

1. Identify the highest-consequence unresolved invariant on the current canonical path.
2. If a verified or strongly supported candidate control exists outside that path, prefer reconciling it over unrelated frontier expansion.
3. Reconstruct or reapply the smallest control change against current canonical state; do not blindly merge stale branch history.
4. Re-run the original success and denial proof plus current repository-wide required checks.
5. Preserve the authority boundary: evidence may justify priority or recommend admission, but only legitimate governance can authorize canonicalization.
6. After admission, verify at least one real or appropriately bounded external consequence when the invariant concerns execution.
7. Reconcile the result into the existing evidence and outcome-memory chain before beginning the next major research generation.

An explicit separately authorized decision may override this default when a different action has higher consequential value, but the override must state why.

## Frontier-to-canonical gate

Before opening another major experimental generation, ask:

- Is there a higher-consequence verified candidate still outside canonical state?
- Has current `main` moved enough that the candidate's proof could be stale or integration-invalid?
- Would another experiment increase evidence faster than it reduces the primary unresolved boundary?
- Can the next unit of work produce a canonical success/denial proof instead?

If the first three answers indicate drift and the fourth is yes, the default action is **reconciliation and canonical consequence**, not another frontier experiment.

## Future-project inheritance

This is intended as a project-bootstrap rule, not a Pulpo-only implementation detail.

Every new Iron & Ember project should begin by defining:

- its canonical source and admission path;
- its authority boundary and who may change it;
- its claim/evidence classes;
- the highest-consequence unresolved invariant;
- the smallest proof that can retire that uncertainty;
- a reconciliation rule preventing experimental evidence from silently becoming canonical truth;
- a canonical-consequence gate that prevents research, prototypes, or branches from outrunning admission of stronger controls.

Future project instructions should carry the following invariant unless a separately authorized governance decision replaces it:

> **Do not optimize for accumulated evidence. Optimize for the highest-value verified consequence that can be safely reconciled into canonical state. When frontier work outruns canonical control admission, consolidate before expanding.**

The reusable seed for new repositories is `docs/FUTURE_PROJECT_BOOTSTRAP.md`.

## Relationship to existing Pulpo doctrine

This pivot does not replace the Pulpo lifecycle:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

It sharpens the project-management meaning of **Reconciliation -> Memory -> Adaptation**.

Evidence becomes useful learning only after it is reconciled against current canonical state. Learning may improve competence and priority selection, but may not grant itself authority. Adaptation should improve the canonical control system rather than create a growing parallel universe of experiments.

The doctrine remains:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

The pivot adds:

> **Reconciliation consolidates before intelligence expands again.**

## First live application

The pivot was tested by its own admission attempt rather than accepted as narrative truth.

PR #50 changed only doctrine/current-state guidance, yet its required `test` job exposed an existing concurrency proof failure. The duplicate approval remained fail-closed, but the losing decision was classified as `approval_nonce_replayed` instead of the frozen `approval_id_replayed` precedence. A rerun reproduced the same failure.

The project did not weaken the test, dismiss the discrepancy, merge the doctrine anyway, or continue to another frontier experiment. Reconciliation traced the cause to `SQLiteKernelState._approval_replay_reason()`: approval ID and nonce were checked in two separate autocommit reads, allowing a concurrent approval commit to land between the two snapshots.

PR #51 was therefore created directly from current protected `main` with one production-file change: classify both replay fields in one SQLite statement snapshot while keeping the duplicate authority denial unchanged. At its exact head, `test`, `authority`, and `authority-service` all pass. Human review is requested; the fix remains noncanonical until legitimate admission.

This is the rule operating on itself:

`new evidence -> stop expansion -> identify stronger canonical inconsistency -> smallest fix -> rerun full proof -> await independent admission`

## Immediate Pulpo application

After the replay-classification inconsistency is legitimately admitted, the highest-value application remains reconciling the execution-time directive revocation proof onto current protected `main`, rerunning its frozen stale-permit regression and all required current checks, obtaining legitimate protected-main admission, then proving the same boundary on a bounded external effect.

That work should take priority over additional unrelated frontier-learning generations unless a separately authorized decision changes the priority.

## Claim classification

**Verified:** protected `main` has admitted the field-level governed recursive-transfer experiment; PR #44 recorded a reproduced stale-permit revocation failure and a passing candidate fix; the #44 lineage has diverged from current `main`; the latest recorded cross-model generation produced zero successful inference calls while preserving authority; PR #50's admission attempt exposed a reproducible replay-classification race; PR #51's exact head passes all three protected suites with the one-statement candidate fix.

**Inferred:** research velocity had begun to outrun canonical admission, increasing integration debt and reducing the marginal value of another frontier experiment relative to the directive-revocation proof. The first live application provides additional evidence that the consolidation rule catches real canonical inconsistencies rather than merely reorganizing documentation.

**Authorized / Proposed for canonicalization:** make the Canonical Consequence Rule a default project-priority doctrine and an inheritance rule for future Iron & Ember projects.

**Not proved:** that this priority rule is globally optimal for every future project, that PR #51 is canonical before independent review/admission, or that the PR #44 candidate remains correct after reconciliation onto current `main`. Those claims require their respective governance and current-path execution evidence.
