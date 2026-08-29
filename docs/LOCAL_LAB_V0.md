# Pulpo Local Lab V0

## Purpose

Create a local-first operating surface where the operator works through Pulpo while tools remain subordinate capability surfaces.

Local Lab V0 starts with bounded read-only workspace access and adds one bounded reversible write primitive: replace exactly one existing UTF-8 file only when its current SHA-256 matches the operator-supplied expected hash and a one-use Pulpo permit authorizes the exact replacement object.

It deliberately does not add arbitrary shell execution, file creation/deletion, network access, new authority, a second router, a second ledger, or a memory governor.

## Current surface

`pulpo-lab` exposes:

- `list [path]` — deterministic directory listing;
- `read <path>` — bounded UTF-8 text read with SHA-256 content hash;
- `digest <path>` — SHA-256 digest of one file;
- `edit <path> --expect <sha256> --from <proposal-file>` — govern one exact existing-file replacement using replacement text read from another UTF-8 file inside the same workspace.

Read-only results carry `authority_effect=none`.

The edit command reports the Pulpo decision, exact edit hash, prior expected hash, replacement hash, fresh observed hash, reconciliation result, replay result, and proof-bundle hash. It never treats the executor return value alone as proof of completion.

## Read-only boundaries

The workspace capability fails closed on:

- absolute paths;
- parent traversal;
- symlink traversal;
- missing paths;
- directory/file type mismatch;
- text files larger than 1 MiB;
- non-UTF-8 content for text reads;
- directory listings above 1000 entries.

Symlinks may be reported by directory listing but are never followed by read or digest operations.

## Edit boundaries

An edit binds:

- exact relative path;
- current expected SHA-256;
- exact replacement SHA-256 and byte count;
- existing-file-only semantics;
- no symlink traversal;
- the canonical Pulpo intent hash;
- a one-use permit.

The executor checks the current file hash before consuming the permit, then checks it again after permit consumption before writing. A stale precondition therefore fails before consuming authority; a detected concurrent change after permit consumption fails closed and is not retried automatically.

The replacement is written to a new sibling temporary file and atomically moved over the target. A fresh filesystem read then observes the result. Reconciliation upgrades the result to `verified` only when the observed bytes match the exact authorized replacement. Permit replay is tested without making a second write attempt.

This remains a same-host development proof. It does not prove containment against a hostile local administrator, kernel-level tampering, or every possible filesystem race.

## Architecture

The Local Lab is not a new authority plane.

`operator -> Pulpo -> local capability -> evidence -> Pulpo`

Read-only workspace access requires no permit because it creates no filesystem consequence under this V0 contract. The edit path uses the existing Pulpo kernel for policy, decision, one-use permit issuance, consumption, audit evidence, fresh observation, and reconciliation.

Future Local Lab capabilities should be admitted by risk tier:

1. intelligence-only/read-only;
2. bounded reversible local effects through Pulpo permits;
3. external or high-consequence effects only after stronger authority and verification proofs.

## Operator flow

A safe edit starts by digesting the target and preparing replacement content in a separate workspace file:

```bash
pulpo-lab digest README.md
pulpo-lab edit README.md --expect <current-sha256> --from proposal.txt
```

If the target changed after the digest was taken, the edit is denied rather than overwriting newer work.

## Claim discipline

This branch is an experimental capability surface stacked on Local Effect V0 and Local Lab read-only V0. It is not canonical merely because its tests pass. Canonical admission must follow reconciliation of the existing stacked dependency chain against protected `main` and separate review.
