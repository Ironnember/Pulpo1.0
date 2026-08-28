# Field Governed Compounding Contract

Status: frozen before external field execution.

## Purpose

Move the recursive governed-compounding mechanism out of a deterministic-only harness and into a real, low-risk, reversible external GitHub effect without touching protected `main`, adding authority, or creating a second governance path.

The field sequence is:

`K5 -> real external effect F1 -> independent reconciliation -> bounded lesson K6 if evidence supports one -> deterministic F2 selection -> K5 baseline vs K5+K6 verification`

This is an experiment, not canonical product state.

## Canonical and experimental lineage

- Canonical repository: `Ironnember/Pulpo1.0`.
- Canonical base: `main` at `81338eed28ec32fe214c7eee086a82840ca0923f`.
- Knowledge source: PR #41 head `72f556554cf803d3fe24e84d5822514bc4e14667`.
- Imported authority: none.
- Authority effect: `none`.

K5 is used only as experimental knowledge. PR #41 is not silently promoted to canonical state by this field test.

## F1 real external effect

Create branch `field/recursive-compounding-target-2026-08-27` from the exact canonical base. Create `field_proofs/compounding_effect.json` with the precommitted field marker. Record the provider acknowledgement commit SHA as command evidence, not outcome proof.

Before reconciling F1, create a separate unrelated file `field_proofs/interleaving_noise_f1.txt` on the same target branch. This intentionally moves the branch tip after the target effect and before verification.

F1 verification must then distinguish:

1. the target-effect commit returned by the write;
2. the later branch-tip commit created by the interleaving mutation;
3. the target object's content at the exact effect commit;
4. the target object's content at the later branch tip;
5. the fact that canonical `main` did not receive the field artifact;
6. a separate/public read surface where available.

## Lesson extraction rule

Do not predeclare K6. After F1 reconciliation, extract at most one compact lesson, and only if the observed evidence establishes a reusable distinction not already exhausted by K5. The lesson must include evidence references, scope, invalidation conditions, remaining boundary, and `authority_effect: none`.

If F1 produces no new trustworthy lesson, record that result and do not manufacture K6.

## F2 selection and evaluation

The follow-up task pool and selection rule are frozen in `task_pool.json` before F1. Select F2 using:

`int(F1_effect_commit_sha[0:8], 16) mod 3`

The K5-only baseline and K5+K6 transfer are evaluated against the frozen rubric. K6 may contribute only controls justified by F1 evidence. Passing evidence cannot authorize merge, authority expansion, or canonicalization.

## Safety and authority boundaries

- No writes to protected `main`.
- No production credentials, payments, registrar actions, or secrets.
- No branch merge.
- No policy, permit, router, executor, ledger, or authority changes.
- All target branches are isolated experiment surfaces.
- A command success response is evidence of command acceptance only.
- The experiment stops if target identity, repository state, or authority becomes ambiguous.

## Claim boundary

A successful run may support only a field-level claim about governed knowledge transfer and external-effect reconciliation in GitHub. It does not prove production autonomous learning, model-weight change, hidden-context isolation, OS containment, payment-rail safety, or production recursive compounding.
