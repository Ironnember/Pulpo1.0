# Outcome Case: Legacy Migration Merged Without Proof

Status date: 2026-08-26  
Canonical repository: `Ironnember/Pulpo1.0`  
Historical repository: `Iron-Ember/pulpo`  
Historical change: PR #52, merge commit `e03a941e423977e8ea1ae6b12139ad669d4fc24a`

## Summary

After `Ironnember/Pulpo1.0` had been designated the sole canonical source for forward development, the branch `migration/bootstrap-pulpo-core` was merged into the historical `Iron-Ember/pulpo` repository as PR #52.

The change proposed a clean `pulpo-core` migration and a persistent Mac Codex worker. Its only pull-request workflow run ended in `startup_failure`, so the promised Python 3.10 and 3.12 GitHub Actions proof did not execute. The merge nevertheless entered the historical repository's `main`.

Static inspection then showed that the proposed worker sends `codex exec -` through the authority RPC. The existing control plane performs `subprocess.run()` with `cwd=self.root` on the control-plane host. The supplied Mac workspace path is recorded in the request's execution context but does not select the process execution directory. The change therefore does not prove local Mac execution.

This event is preserved rather than reverted because it is useful governance evidence. It does not regain forward authority merely because it merged.

## Outcome classification

Primary outcome:

`GOVERNANCE_REGRESSION`

Secondary outcome:

`EVIDENCE_FAILURE`

Root-cause tags:

- source-of-truth drift;
- evidence incomplete;
- CI/startup failure;
- implementation assumption;
- execution-location mismatch;
- human-process failure.

## Constitutional invariant

`MERGED != VERIFIED != CANONICAL`

A merge records that a provider accepted a repository mutation. It does not prove the proposed behavior, satisfy acceptance criteria, or designate a source of truth.

A historical repository cannot reacquire canonical authority through new commits, successful tests, merge status, recency, or operational convenience. Redesignation requires a separate legitimate governance decision.

## Lifecycle reconciliation

### Purpose

Create a clean Pulpo core and establish a persistent Mac Codex execution path.

### Intent

Bootstrap a new `Iron-Ember/pulpo-core` repository from selected legacy runtime files and branch documents, then use a worker adapter to dispatch governed Codex tasks.

### Authority

The merge was accepted by GitHub through a repository principal with write capability.

Whether a separate human governance decision authorized superseding `Pulpo1.0` is **Unknown**. No such redesignation is recorded in the canonical repository.

Repository write capability is not source-of-truth authority.

### Policy

Canonical policy already stated:

- `Ironnember/Pulpo1.0` is the sole forward-development repository;
- the older `Iron-Ember/pulpo` repository is historical reference;
- legacy behavior may enter only one behavior at a time;
- behavior must be rewritten behind the current interface with adversarial tests;
- no second canonical router, executor, ledger, or repository path may arise by implication.

### Decision

PR #52 was merged in the historical repository.

No canonical decision promoted `Iron-Ember/pulpo`, the deleted migration branch, or the proposed `Iron-Ember/pulpo-core` repository.

### Execution

GitHub created merge commit `e03a941e423977e8ea1ae6b12139ad669d4fc24a`.

The only pull-request workflow run for head `8b52d9dfa6a63200dde4a9975b5c9c4ad4b39161` completed with `startup_failure`.

The merged worker implementation constructs an authority RPC request. It does not itself run Codex in the supplied Mac workspace. The control-plane process remains the execution surface in the inspected implementation.

### Evidence

Durable external references:

1. [Historical PR #52](https://github.com/Iron-Ember/pulpo/pull/52)
2. [Historical merge commit](https://github.com/Iron-Ember/pulpo/commit/e03a941e423977e8ea1ae6b12139ad669d4fc24a)
3. Pull-request workflow run `32654003623`: `startup_failure`
4. PR head `8b52d9dfa6a63200dde4a9975b5c9c4ad4b39161`
5. Canonical `Pulpo1.0` current-state and canonicalization records

The PR description and migration proof document are narrative evidence of intended behavior. They are not executable proof that the Mac worker, clean repository, passkey path, or end-to-end lifecycle worked.

### Reconciliation

Expected state:

- one canonical forward-development repository;
- clean intake of one behavior at a time;
- successful Python 3.10 and 3.12 CI;
- local Mac Codex execution;
- exact task claim before execution;
- real authority and evidence linkage;
- explicit promotion only after dogfood proof.

Observed state:

- work merged into the historical repository;
- a third repository path was proposed;
- CI ended in `startup_failure`;
- no real Mac-host execution was demonstrated;
- unit tests used a fake RPC client;
- the inspected process execution remained on the control-plane host;
- no canonical redesignation occurred.

Result:

`MERGED = true`

`CI_PROOF = false`

`MAC_EXECUTION_PROOF = false`

`CANONICAL_AUTHORITY = false`

### Memory

Preserve the event, code, PR, failed workflow, and analysis as historical evidence.

Do not bulk-import or replay the migration. Do not infer that the historical repository is current merely because its merge is newer than a canonical commit.

### Adaptation

- keep `Ironnember/Pulpo1.0` canonical;
- treat PR #52 as superseded historical evidence;
- freeze or archive the historical repository when a capable GitHub administrative surface is available;
- ensure no automation, deployment, or worker consumes historical `main` as current state;
- extract only narrow worker invariants that survive reconciliation;
- reimplement those invariants behind `Pulpo1.0`'s current authority, permit, durable state, and evidence path;
- require local worker execution evidence and independent reconciliation before describing a Mac worker as proven.

Learning from this event may improve repository routing, review gates, worker design, and proof selection. It does not authorize a new repository, executor, worker capability, or authority path.

## Claim classification

### Verified

- `Ironnember/Pulpo1.0` is the recorded canonical source.
- PR #52 merged into `Iron-Ember/pulpo`.
- Its only pull-request workflow run ended in `startup_failure`.
- The merged worker sends an RPC request rather than directly executing Codex locally.
- The inspected control-plane implementation executes subprocesses with `cwd=self.root`.
- The focused worker tests use a fake RPC client.

### Recorded

- PR #52 intended to prove a clean repository and persistent Mac worker.
- Its own promotion gates said real Mac dogfood, authority, and approval remained required.
- The event and its resulting lesson are preserved here.

### Inferred

- Merging without successful CI was possible because merge enforcement did not require the promised workflow result.
- The repository mutation was treated as more complete than its evidence justified.
- Leaving multiple apparent forward paths active increases future source-selection error.

### Proposed

- archive or freeze `Iron-Ember/pulpo`;
- add a narrow, local-execution worker proof to `Pulpo1.0` only after higher-priority authority and protected-state boundaries are satisfied;
- require repository checks to distinguish a merged change from a verified change.

### Unknown

- whether the historical merge was accompanied by a separate explicit human governance decision;
- whether any unrecorded local Mac execution occurred;
- whether any local test run reproduced the PR's intended full-suite proof.

Unknown evidence must remain unknown.

## Reusable failure signature

`legacy_repo_newer_than_canonical + ci_not_successful + promotion_language`

Required response:

1. stop automatic promotion;
2. identify the already-designated canonical source;
3. inspect actual execution behavior and workflow evidence;
4. preserve the event;
5. classify the outcome;
6. deny source-of-truth transfer;
7. reconcile only the smallest useful behavior into the canonical path.

## Durable lesson

> Recency does not create authority. Merge status does not create proof. A migration earns promotion only when canonical governance authorizes it and evidence establishes the claimed consequence.

Pulpo should remember the difference permanently.
