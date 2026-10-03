> **Unofficial Pulpo Preview — testing snapshot, 2026-10-03.**
> This is spikediegel-prog's preview of unreleased PRs awaiting upstream review.
> Read [preview contents, test evidence, and limitations](PREVIEW.md) before testing.
> Official Pulpo development/releases: https://github.com/Ironnember/Pulpo1.0.

# PULPO

### Give AI intelligence. Never give it authority.

**Pulpo is a governance and execution-control layer for AI and autonomous systems—built so intelligence can propose actions without gaining the authority to execute them.**

> **Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

Pulpo puts a deterministic governance boundary between AI reasoning and real-world consequences. Policies, authority, approvals, one-use permits, execution, evidence, and reconciliation remain separate from the intelligence making recommendations.

**Built for consequential AI:** autonomous agents · robotics · drones · infrastructure · on-prem systems · governed commerce

### Why Pulpo?

Most AI systems ask: **“What should the AI do?”**

Pulpo asks a different question:

**“Even if the AI wants to do it, who gave it the authority?”**

Learning does not grant authority.<br>
Success does not grant authority.<br>
Memory does not grant authority.<br>
Intelligence does not grant authority.

**Capability without authority is just a proposal.**

Pulpo turns explicit intent into deterministic governance, binds allowed work to narrowly scoped one-use permits, and preserves durable evidence for verification and reconciliation.

This repository is the clean canonical Pulpo project. The older `Iron-Ember/pulpo` repository remains historical reference material; its accumulated plans, generated evidence, machine-specific scripts, and CI workarounds are intentionally not imported here.

## Quick test drive

For testers and developers, Pulpo can bootstrap a machine-bound performance profile
without changing governance semantics.

After installing the package in your environment:

```powershell
pulpo setup --json-report perf-results\pulpo-setup-report.json
```

`pulpo setup`:

- detects the current OS, Python version, and logical CPU count;
- reuses an existing matching performance profile when available;
- rejects stale or mismatched profiles;
- otherwise runs bounded local calibration over synthetic audit data;
- verifies that a valid audit passes and a tampered hash fails;
- saves the local performance profile for later adaptive verification.

If you already have a benchmark artifact, setup can build from that instead of
recalibrating:

```powershell
pulpo setup --benchmark perf-results\memory-scaling-ddr4-3200-cl14-batched.json
```

The setup path reports `Authority changes ........ NONE`. It is a test/developer
bootstrap and does not claim production readiness.

## How Pulpo changes the model

Pulpo separates three responsibilities that are often collapsed into one AI system:

| Plane | Responsibility |
| --- | --- |
| **Intelligence** | Reasons, plans, learns, and proposes. It does not create authority. |
| **Governance** | Resolves identity, policy, budget, approval, permits, evidence, reconciliation, and governed memory. |
| **Execution** | Performs only the exact consequence authorized by a valid permit. |

The lifecycle is explicit:

`Purpose → Intent → Authority → Policy → Decision → Permit → Execution → Evidence → Reconciliation → Memory → Adaptation → Purpose`

The invariant is simple: **better intelligence can improve a proposal, but it cannot promote itself into greater authority.**

## What the repository proves

The executable test and proof surfaces cover controls including:

- fail-closed handling of unknown, incomplete, over-budget, expired, revoked, mismatched, and replayed requests;
- exact-intent binding and one-use permits;
- verifier-backed approval envelopes with pinned trust, key, algorithm, deployment, and lifetime constraints;
- restart-safe SQLite governance state for approval IDs, nonces, permits, audit history, commerce state, and reconciliation;
- persisted audit-chain tamper detection;
- bounded agent grants that cannot exceed configured action, resource, or cost scope;
- bounded commerce objects tied to request, quote, reserved budget, exact target, and permit;
- independent custody/evidence paths for consequential execution proofs;
- reconciliation that distinguishes verified consequences from failure and unresolved external reality;
- governed outcome memory that records evidence without converting learning into authority.

PulpoGit also provides a read-only clarity projection for local source state. It distinguishes canonical, proposal, stale, diverged, detached, and dirty checkouts without inferring tests or authority. See the [PulpoGit clarity proof](proofs/git_clarity/README.md).

```bash
python -m unittest discover -s tests -v
```

## Performance without moving the trust boundary

Pulpo's governance boundary does not require every read-only calculation to remain single-core.

This branch adds opt-in performance paths for:

- **multi-core audit verification** — worker processes can decode immutable audit payloads and calculate expected hashes;
- **bounded audit digest caching** — exact-input calculations can be reused while current chain links and stored hashes are still checked;
- **parallel evidence collection** — independent read-only evidence surfaces can be collected concurrently;
- **sharded evidence-digest caching** — identical canonical snapshot calculations can be reused without treating cached data as fresh observation.
- **bounded self-tuning** — a machine-bound performance profile can select worker count and batch size by workload without changing governance semantics.

Workers do **not** issue permits, change policy, grant authority, bypass replay protection, reconcile consequences, or append canonical evidence.

Historical development measurements recorded about **2.7× faster** verification for a 10,000-record synthetic audit with four warm workers, plus lower repeated-check latency with caching. Those figures are development measurements, not universal performance guarantees. See [multi-core audit verification](docs/AUDIT_CPU_WORKERS.md).

### Performance engineering

**Proposed engineering standard:** benchmarks are Pulpo's feedback loop for
determining whether SQL, memory, audit, batching, serialization, concurrency,
and other component changes improve overall system efficiency. The core measure
is how efficiently Pulpo converts CPU, memory, storage, and I/O into governed
record processing while preserving governance guarantees.

Evaluate changes against comparable workloads and record these dimensions:

- **Throughput:** records or operations processed per second.
- **CPU efficiency:** CPU time per record or per 1,000 records.
- **Memory efficiency:** peak memory and memory growth as record history increases.
- **Latency:** typical latency and p95/p99 tail latency under load.
- **Scaling:** capacity across increasing record histories and hardware/core configurations.
- **Governance/evidence overhead:** CPU, memory, storage, and I/O cost of governance and audit evidence per record.
- **Correctness under load:** preservation of governance invariants, including restart and failure behavior.

An optimization can be worthwhile even if one operation consumes slightly more
resources when overall governed processing capacity improves. No performance
gain counts if replay protection, durability, rollback, permit semantics,
audit-chain verification, tamper detection, or other governance invariants are
weakened. Report measured gains with their workload, configuration, and evidence
boundaries; unverified gains remain **Unknown**.

## Designed for consequential systems

Pulpo's architecture is intended for systems where an AI recommendation can eventually reach something that matters: infrastructure, autonomous agents, robotics, drones, governed transactions, APIs, databases, and on-prem execution.

The point is not to make the model less capable.

The point is to make **capability and authority different things**.

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

Pulpo is an active technical governance proof and implementation, not a claim that every production deployment is automatically contained. Repository tests and bounded provider proofs establish specific controls in their tested topology; they do not by themselves prove universal cloud, model-provider, operating-system, hardware, or external-world custody.

Production deployments still require their own trusted bootstrap, capability isolation, credential custody, durable storage guarantees, independent observation, provider-specific integration, and exact-topology validation.

That distinction is intentional: **architecture is not proof, execution is not authority, and evidence is not permission.**

## Host bound and Pulpo bound
Pulpo is only as secure as the host it is running on. The kernel, permit store, and evidence journal assume that host is still the host that was installed and that it is still enforcing process, file, and boot policy. Pulpo does not own the boot chain, firmware, NVRAM, unused or hidden partitions, storage-controller firmware, the management controller, service-account privileges, or the decision to keep operating a machine that can no longer be measured. An OS reimage, snapshot, or rollback does not restore those layers. A compromised host can skip the process, replace local state, or omit a record. That is an operator incident, not a Pulpo control failure.
Pulpo is accountable for the contract it states, on a host that is still enforcing it: unknown, incomplete, and over-budget intents fail closed; a permit is bound to one exact intent and cannot be replayed; loss of contact does not widen a grant; uncertain execution remains unknown and does not become retry authority; a visible broken audit chain fails closed. A defect in that contract is a Pulpo failure. Survival of host compromise, rollback-proof storage, trusted verifier bootstrap, network isolation, and hostile-code sandboxing are not part of that contract.

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


## Current development status

The capabilities above describe the current `main` branch. Recent pull requests show the next development direction, but the following work is still proposed and is not part of `main` while its PR remains open:

- [#250 — Consolidate recent governance, security, portability, and performance hardening](https://github.com/Ironnember/Pulpo1.0/pull/250) proposes a reviewed integration of bounded permit expiry, constrained local intelligence execution, bounded untrusted inputs, narrower custody packaging, HTTP admission controls, MCP portability, canonical delta logging, and faster audit verification. Its linked implementation PRs are not independently treated here as landed changes.
- [#258 — Feature/gpu governance audit](https://github.com/Ironnember/Pulpo1.0/pull/258) proposes custody approval-envelope compatibility, descriptor-relative MCP snapshot publication, repaired constitutional mutation checks, and isolated KMS and Cloud SQL probe-container proofs. These probes are verification artifacts; they do not establish production service deployment.
- [#267 — Portable GPU audit integrity acceleration](https://github.com/Ironnember/Pulpo1.0/pull/267) proposes PyTorch eager and Triton implementations for recomputing audit-record SHA-256 hashes on ROCm/HIP and CUDA. CPU remains authoritative for chain linkage, final verification, governance, permits, and durable state. The PR reports correctness-checked RX 7900 XT measurements near CPU parity, not a speedup; canonicalization and host-side work remain performance bottlenecks.

These PRs make the current direction explicit: strengthen governance and custody boundaries, make audit and benchmark evidence more reproducible, and evaluate optional acceleration without moving authorization or canonical evidence authority off the CPU. Recheck PR status before treating any proposed item as part of the released/current branch.
