# Pulpo Documentation Index

Status date: 2026-09-04

This index is a navigation layer. It does not create authority, admit code, or replace executable evidence.

## Start here

1. [`CURRENT_STATE.md`](CURRENT_STATE.md) — current claim boundary, canonical software state, open proof boundaries, and next sequence.
2. [`CANONICALIZATION.md`](CANONICALIZATION.md) — source-of-truth and legacy-intake rules.
3. [`REPOSITORY_MAP.md`](REPOSITORY_MAP.md) — classification of Pulpo-adjacent repositories and their permitted roles.
4. [`ARCHITECTURE.md`](ARCHITECTURE.md) — canonical architecture and separation of intelligence, governance, and execution.
5. [`GOVERNANCE.md`](GOVERNANCE.md) — governance rules and constitutional constraints.
6. [`AUTHORITY.md`](AUTHORITY.md) — approval and authority boundary.

## Current canonical references

These documents describe current behavior or current governance when they agree with executable behavior and `CURRENT_STATE.md`:

- [`CURRENT_STATE.md`](CURRENT_STATE.md)
- [`CANONICALIZATION.md`](CANONICALIZATION.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`GOVERNANCE.md`](GOVERNANCE.md)
- [`AUTHORITY.md`](AUTHORITY.md)
- [`AGENTS_AND_PLUGINS.md`](AGENTS_AND_PLUGINS.md)
- [`PERSISTENCE.md`](PERSISTENCE.md)
- [`OUTCOME_LEARNING_PROTOCOL.md`](OUTCOME_LEARNING_PROTOCOL.md)

## Boundary and contract references

These documents define constrained interfaces or proof obligations. They do not independently prove deployment or external consequence:

- [`AUTHORITY_BOUNDARY_DECISION.md`](AUTHORITY_BOUNDARY_DECISION.md)
- [`AUTHORITY_SERVICE_CONTRACT.md`](AUTHORITY_SERVICE_CONTRACT.md)
- [`AUTHORITY_SERVICE_PROOF.md`](AUTHORITY_SERVICE_PROOF.md)
- [`INDEPENDENT_AUTHORITY_PROOF.md`](INDEPENDENT_AUTHORITY_PROOF.md)
- [`COMMERCE_PROOF.md`](COMMERCE_PROOF.md)
- [`EXACT_TARGET_PROOF.md`](EXACT_TARGET_PROOF.md)

## Historical, directional, and dated records

Dated focus resets, migration records, proposal documents, incident records, superseded current-state drafts, and other historical proof objects remain evidence or reference only unless current executable behavior and a legitimate repository-admission transition make them canonical.

Unlisted documentation must not be treated as current merely because it exists in this repository. When status is ambiguous, classify it as historical/reference until `CURRENT_STATE.md` or executable evidence establishes otherwise.

## Repository directories

- `pulpo/` — canonical governance/evidence implementation.
- `authority-service/` — authority-service reference implementation inside the canonical repository; deployment claims remain separately bounded.
- `custody-service/` — custody/execution-boundary implementation inside the canonical repository.
- `tests/` — executable proof and regression coverage.
- `experiments/` — noncanonical research and trial work. See [`../experiments/README.md`](../experiments/README.md).
- `proofs/` — reproducible proof specifications and harness material, not a second evidence ledger. See [`../proofs/README.md`](../proofs/README.md).

## Evidence precedence

For current claims, use this order:

1. executable behavior and tests at the exact canonical commit;
2. current reviewed canonical code;
3. durable runtime/provider evidence;
4. `CURRENT_STATE.md` and explicit current decisions;
5. architecture and governance documents;
6. historical records, screenshots, prototypes, summaries, and marketing.

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
