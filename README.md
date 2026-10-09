# Pulpo

Pulpo is the governance and evidence plane between AI intelligence and consequential execution. It turns explicit intent into deterministic governance, binds allowed work to narrowly scoped one-use permits, and preserves durable evidence for verification and reconciliation.

This repository is the clean canonical Pulpo project. The older `Iron-Ember/pulpo` repository remains historical reference material; its accumulated plans, generated evidence, machine-specific scripts, and CI workarounds are intentionally not imported here.

## Proven now

The base dependency-free suite and optional asymmetric-authority suite prove:

- unknown, incomplete, and over-budget intents fail closed;
- selected high-impact actions require a verifier-backed approval envelope;
- authority policy pins verifier, key, algorithm, public-key fingerprint,
  deployment, and maximum approval lifetime;
- optional Ed25519 verification contains public material only and exposes no
  signer;
- caller-controlled boolean approval and authorization timestamps are absent
  from the evaluation API;
- permits are bound to the exact intent and cannot be replayed;
- an optional SQLite state backend preserves approval-ID, nonce, permit, and
  audit state across process restart in the same canonical kernel;
- persisted audit-chain tampering fails closed when the kernel restarts;
- configured agent roles cannot exceed their action, resource, or cost grant.
- a bounded domain order is bound to its full request, quote, reserved budget, and one-use permit.
- a configured external verifier checks v2 approval envelopes bound to trust,
  deployment, intent, policy, principal, session, nonce, issue time, and expiry
  using the kernel's trusted clock.
- transactional SQLite commerce state preserves reservations, attempted orders,
  reconciliation, and spend across restart.

PulpoGit provides a read-only clarity projection for local source state. It
distinguishes canonical, proposal, stale, diverged, detached, and dirty
checkouts without inferring tests or authority. See the
[PulpoGit clarity proof](proofs/git_clarity/README.md).

```bash
python -m unittest discover -s tests -v
```

## SQLite reconciliation scans

**Verified:** `SQLiteKernelState.append_unique()` streams the complete ordered
audit scan and deterministically closes its SELECT cursor, including when
malformed JSON raises and the caller retains the exception traceback. It keeps
`BEGIN IMMEDIATE`, original replay payloads without writes, ambiguity rejection,
and the existing canonical append and commit/rollback path.

**Verified in local tests:** The malformed-nonfinal-row regression checks
rollback and a successful second-connection COMMIT while the traceback remains
retained. WSL2 Linux with Python 3.12.14 / SQLite 3.53.1 passes 34 focused and
381 core tests with warnings treated as errors. Native Windows with Python
3.12.10 / SQLite 3.49.1 passes all eight unique-scan tests; its broader suite
has the same failing tests on the original and revised PR head.

**Verified in the local allocation benchmark:** At 10,000 same-event rows,
Python allocation peak is 7,640 bytes with cursor cleanup, compared with
7,504 bytes for the original streaming scan and 11,354,317 bytes for `fetchall()`.
This measures Python allocations; general throughput and physical power-loss
durability remain **Unknown**. See the [unique-scan tests](tests/test_unique_audit_scan.py),
[benchmark](scripts/benchmark_unique_audit_scan.py), and
[original streaming change record](docs/UNIQUE_AUDIT_SCAN_STREAMING.md).

## Minimal example

```python
from pulpo import GovernanceKernel, Intent, Policy

kernel = GovernanceKernel(
    Policy(
        allowed_actions=frozenset({"read", "write"}),
        max_cost=100,
    )
)

intent = Intent("agent:builder", "write", "repo:README.md", cost=5)
decision = kernel.evaluate(intent)

if decision.outcome == "allow":
    assert kernel.consume(decision.permit, intent)
```

## Boundary

Pulpo currently proves governance, pinned asymmetric external-verifier contract
semantics, local restart-safe kernel replay state, and restart-durable bounded-
commerce state with dependency-free SQLite backends. It does not yet claim an
independently deployed human signer, trusted verifier bootstrap, rollback-proof
host storage, a real payment rail, network isolation, hostile-code sandboxing,
distributed identity, or production readiness.

See [project source baseline](docs/PROJECT_SOURCE_BASELINE.md), [architecture](docs/ARCHITECTURE.md), [project governance](docs/GOVERNANCE.md),
[current state](docs/CURRENT_STATE.md), [canonicalization](docs/CANONICALIZATION.md),
and [agents and plugins](docs/AGENTS_AND_PLUGINS.md).
The bounded transaction proof and its remaining live-execution gates are in
[commerce proof](docs/COMMERCE_PROOF.md).
The external approval contract and its still-open signer boundary are in
[authority](docs/AUTHORITY.md).
The mandatory deployment tests before claiming independent human authority are
in [independent authority proof](docs/INDEPENDENT_AUTHORITY_PROOF.md).
The selected founder-passkey boundary and the worker-visible external service
contract are in [authority boundary decision](docs/AUTHORITY_BOUNDARY_DECISION.md)
and [authority service contract](docs/AUTHORITY_SERVICE_CONTRACT.md).
The separately packaged executable reference and its remaining production gate
are in [authority service proof](docs/AUTHORITY_SERVICE_PROOF.md).
The restart-safe state proof and its storage boundary are in
[persistence](docs/PERSISTENCE.md).
The governed success-and-failure learning rules are in the
[outcome learning protocol](docs/OUTCOME_LEARNING_PROTOCOL.md), including the
[legacy migration regression case](docs/OUTCOME_CASE_LEGACY_MIGRATION_REGRESSION.md).
