# Pulpo × AgentFactory Consequence-Custody Challenge

Status: `SPECIFIED_BLOCKED_ON_268`

Issue: #272

Base SHA: `ab08c5bbee1a2e6dc329ccea9c36db5e68bc02be`

## Purpose

Prepare a third-party interoperability proof in which an external governed agent/workflow system proposes a consequential software-deployment action while Pulpo remains the independent authority, permit, custody, evidence, and reconciliation plane.

This branch is preparatory only. It MUST NOT be merged or used to execute the challenge until #268 and its post-run reconciliation are complete.

## Reuse rule

Reuse the existing Pulpo seams:

- `pulpo/directives.py`
- `pulpo/custody.py`
- `pulpo/custody_executor.py`
- `pulpo/custody_reconcile.py`
- `proofs/github_actions_custody/*`
- `.github/workflows/pulpo-github-actions-custody.yml`

Do not create a parallel authority service, policy engine, replay store, executor, memory governor, or evidence ledger.

## External input boundary

AgentFactory or any substitute external workflow may provide:

- request/work-order context;
- proposed action;
- validation results;
- human approval evidence;
- external receipts.

Those inputs are evidence/context only.

They MUST NOT become Pulpo authority merely because they are signed, approved, retrieved, repeated, or produced by a trusted partner.

## First proving action

One exact reviewed commit -> one exact workflow -> one exact non-production target -> one execution before expiry.

Minimum normalized fields:

```text
action_type
repository
commit_sha
workflow_id
target_environment
deployment_parameters_hash
requesting_system
requesting_identity
authorizer_identity
policy_version
approval_evidence_hash
expiry
permit_nonce
```

## Required negative paths

1. missing Pulpo permit;
2. commit substitution;
3. destination substitution;
4. permit/signature substitution;
5. consumed-permit replay;
6. replay after restart;
7. authority revocation/supersession before execution;
8. evidence/receipt inflation;
9. alternate-route execution bypass.

Every negative path must produce zero unauthorized consequence.

The positive path must produce exactly one authorized consequence followed by independent provider readback and Pulpo reconciliation.

## Hold condition

No merge to `main`, protected-environment mutation, workflow dispatch, external deployment, credential use, or Gate2ASI integration is authorized by this file.

`PREPARATION != AUTHORITY`

`EXTERNAL_APPROVAL != PULPO_PERMIT`

`EVIDENCE != PERMISSION`
