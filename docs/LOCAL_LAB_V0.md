# Pulpo Local Lab V0

## Purpose

Create a local-first operating surface where the operator works through Pulpo while tools remain subordinate capability surfaces.

Local Lab V0 begins with the lowest-risk capability: bounded read-only workspace access. It deliberately does not add shell execution, arbitrary writes, network access, new authority, a second router, a second ledger, or a memory governor.

## Current surface

`pulpo-lab` exposes three read-only operations against one operator-selected root:

- `list [path]` — deterministic directory listing;
- `read <path>` — bounded UTF-8 text read with SHA-256 content hash;
- `digest <path>` — SHA-256 digest of one file.

Every result carries `authority_effect=none`.

## Boundaries

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

## Architecture

The Local Lab is not a new authority plane.

`operator -> Pulpo -> local capability -> evidence -> Pulpo`

Read-only workspace access requires no permit because it creates no filesystem consequence under this V0 contract. Consequential local operations continue to use the existing Pulpo permit/execution/evidence/reconciliation path proven by Local Effect V0.

Future Local Lab capabilities should be admitted by risk tier:

1. intelligence-only/read-only;
2. bounded reversible local effects through Pulpo permits;
3. external or high-consequence effects only after stronger authority and verification proofs.

## Claim discipline

This branch is an experimental capability surface stacked on Local Effect V0. It is not canonical merely because its tests pass. Canonical admission must follow reconciliation of the existing stacked dependency chain against protected `main` and separate review.
