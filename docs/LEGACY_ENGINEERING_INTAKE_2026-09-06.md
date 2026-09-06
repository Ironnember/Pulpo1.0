# Legacy Engineering Intake — Copilot / Keel / Project Avalon

Date: 2026-09-06

Status: **Recorded provenance / Proposed proof work. Not canonical implementation authority.**

This intake preserves older Copilot/engineer material as architectural provenance without importing historical code, names, or claims into canonical Pulpo by default.

Canonical rule applied here:

> Extract the invariant, validate the source, map the minimum useful behavior onto the current seam, and require fresh executable proof before promotion to `Verified`.

No item in this document authorizes a merge, production deployment, new authority service, second router, second executor, or second ledger.

## Sources under intake

1. Historical Copilot / Keel engineering notes previously supplied to the project.
2. Engineer-supplied `Project_Avalon.pdf` received 2026-09-06.
3. Current canonical Pulpo repository and doctrine, which outrank the historical notes when architecture conflicts.
4. External technical references listed in the source-validation register below.

The raw historical notes are treated as provenance artifacts, not canonical source code.

## Consistent architectural through-line

Across the older material, the recurring useful structure is:

- mediate intelligence before consequence;
- reduce direct credential/capability exposure;
- keep execution constrained;
- separate proposal from execution;
- fail closed when required state is unavailable;
- preserve execution evidence;
- observe external effects independently where possible;
- reconcile what was intended/authorized against what occurred;
- preserve provider/model independence;
- prefer small deterministic trusted surfaces over broad dynamic runtimes.

These themes are consistent with current Pulpo, but current Pulpo is stricter about **where authority may live**.

## Current constitutional mapping

| Historical concept | Current Pulpo / Keel interpretation | Intake status |
| --- | --- | --- |
| Unified proxy/gateway | Mediation surface; never canonical authority | `Recorded` continuity |
| Virtual API keys / RBAC | Identity + scoped capability input; insufficient alone for authority | `Recorded` continuity |
| Circuit breakers / fail-fast | Fail-closed execution/resilience | `Recorded` continuity |
| Logging / telemetry | Evidence input; not automatically proof or authority | `Recorded` continuity |
| Multi-provider routing | Intelligence/execution portability; routing relevance cannot increase authority | `Recorded` continuity |
| Capability token | Exact, bounded, one-use permit | `Recorded` continuity; current Pulpo has stronger executable proof |
| Minimal runtime / execution proxy | Keel execution-plane candidate | `Proposed` |
| Guardian | Historical supervisor/custody concept; not a new canonical governor | `Recorded` terminology only |
| Observer | Independent evidence surface | `Recorded` continuity |
| Reconciler | Pulpo reconciliation | `Recorded` continuity |
| Signed ExecutionClaim | Execution evidence claim requiring independent reconciliation | `Proposed` naming/format |
| Merkle/audit-chain idea | Integrity/evidence objective; exact mechanism must be proven before claim | `Recorded` objective |

## Project Avalon intake

The engineer-supplied Avalon note proposes:

- minimal Linux / Alpine-like base;
- read-only root filesystem;
- BusyBox or minimal POSIX shell;
- no exposed package manager;
- no Python, npm, cargo, compilers, or general-purpose interpreter in the execution image;
- Rust or C execution proxy;
- one-use capability token injected with the requested action;
- strict syscall/filesystem/network/process constraints (for example seccomp);
- no outbound network or a narrowly fixed communication path;
- signed execution claim returned from the executor;
- Observer + Reconciler after execution.

### Avalon invariant worth preserving

> **The execution environment itself should contain no more capability than is required to perform the exact authorized effect.**

This is compatible with current capability-custody work and is a strong candidate for Keel.

### Required constitutional correction

Avalon states that the execution proxy becomes the place where Pulpo's authority should live. That wording is rejected.

Correct boundary:

- **Pulpo Governance** resolves authority, policy, budget, approval, and issues the exact bounded permit.
- **Keel / execution substrate** creates the constrained environment.
- **Execution proxy** verifies and enforces the already-issued permit; it does not originate, broaden, or redefine authority.
- **Observer** produces independent evidence where available.
- **Pulpo Reconciler** binds authorization, execution evidence, and observed reality.

The proxy may enforce authority. It must not become the source of authority.

## Source-validation register

Validation here establishes that a cited technology/source exists and supports the narrow engineering proposition attributed to it. It does **not** promote any legacy performance/security/compliance claim into canonical Pulpo evidence.

| Source / claim | Validation | Intake disposition |
| --- | --- | --- |
| Nayjest `lm-proxy` provides an OpenAI-compatible multi-provider proxy/gateway pattern | **Validated.** Public repository describes OpenAI-compatible access across OpenAI, Anthropic, Google and local inference, routing, streaming and virtual API key management. Source: https://github.com/Nayjest/lm-proxy | Historical reference only; not canonical Pulpo dependency |
| Teachings `FastAgentAPI` demonstrates an OpenAI-compatible FastAPI/LangGraph wrapper with tool handling/logging/Docker | **Validated.** Source: https://github.com/Teachings/FastAgentAPI | Historical reference only |
| FastAPI supports trusted forwarded proxy headers and `--forwarded-allow-ips` | **Validated.** Official source: https://fastapi.tiangolo.com/advanced/behind-a-proxy/ | General proxy implementation reference only |
| pgvector supports exact search plus HNSW and IVFFlat ANN indexes; HNSW uses more memory/slower builds but offers a stronger speed/recall tradeoff than IVFFlat | **Validated.** Official repository: https://github.com/pgvector/pgvector | Mechanism validated; no legacy performance number promoted |
| SQLAlchemy supports PostgreSQL via the asyncpg asyncio dialect and `postgresql+asyncpg://...` | **Validated.** Official docs: https://docs.sqlalchemy.org/en/21/dialects/postgresql.html | General implementation reference only |
| Timescale `pgai` was a real PostgreSQL/RAG/agentic toolkit | **Validated historically.** Repository states the Python project is no longer maintained/supported as of Feb 2026 and the repository was archived May 27, 2026. Source: https://github.com/timescale/pgai | Preserve as historical source; reject as new production dependency recommendation without a fresh replacement decision |
| `Fable5` / `Mythos5` abrupt shutdown on 2026-06-12 | **Unsupported from available evidence.** No credible primary source established in this intake. | Remove from technical rationale unless a primary source is supplied |

## Legacy claim downgrades

The following historical claims must not be repeated as current facts without dedicated evidence:

- "sub-millisecond retrieval over millions of vectors" — benchmark-dependent; mechanism sources do not prove this number;
- "one worker can concurrently handle thousands of upstream connections" — workload/configuration dependent;
- Pydantic `extra='ignore'` as a general injection-defense guarantee — configuration behavior is not a complete injection security proof;
- encrypted/hashed secrets as satisfying enterprise compliance by themselves — security control is not compliance certification;
- "indestructible foundation" or equivalent absolute resilience language — marketing, not engineering evidence.

## Implementation intake rule

No legacy behavior is to be reintroduced wholesale.

For each candidate behavior:

1. State the narrow invariant in current Pulpo terminology.
2. Identify the current canonical seam it would extend.
3. Confirm it does not create a parallel authority source, router, executor, memory governor, or evidence ledger.
4. Implement the minimum behavior on a proof branch.
5. Add an executable success case and meaningful negative cases.
6. Add restart/durability testing when state matters.
7. Add tamper/mismatch testing when exact binding matters.
8. State all unproven boundaries.
9. Promote to `Verified` only from executable/current evidence.

## Highest-value reusable candidate: Keel minimal execution substrate

### Proposed invariant

> A hostile worker inside the execution environment cannot cause an operation outside the exact externally issued Pulpo permit, even if it intentionally attempts command, path, process, network, token, or restart bypasses.

### Proposed proof matrix

- unauthorized command -> denied;
- command class substitution -> denied;
- path/resource substitution -> denied;
- malformed/tampered permit -> denied;
- reused permit -> denied;
- expired/revoked permit -> denied;
- process creation outside permitted profile -> denied;
- network destination outside permitted route -> denied;
- attempt to invoke missing interpreter/compiler/package manager -> unavailable;
- valid exact permit -> exactly one authorized effect/attempt;
- restart -> spent authority remains spent;
- executor-generated ExecutionClaim -> remains an execution claim until independent observation/reconciliation establishes external reality.

### Required evidence before promotion

- exact image digest;
- exact proxy binary digest;
- syscall/network/filesystem policy artifact;
- exact permit/object digest;
- negative-test results;
- evidence of unavailable alternate runtime/tooling in the tested image;
- restart/replay evidence;
- independent observation where the effect crosses the VM boundary;
- reconciliation result;
- explicit host/hypervisor/container/cloud boundaries left unproven.

Until those tests execute successfully, the microVM/POSIX/Keel design remains `Proposed`, not `Verified`.

## Relationship to current capability-custody proof

The current capability-custody work tests whether hostile intelligence can bypass Pulpo and reach a protected provider directly.

The proposed Keel/Avalon proof tests a lower layer:

> **Even after a valid execution capability reaches the execution plane, can the execution environment itself be repurposed beyond that capability?**

These proofs are complementary and should remain distinct:

- Pulpo custody: **Can intelligence reach consequence without governance?**
- Keel containment: **Can the executor exceed the exact capability governance granted?**
- Evidence/reconciliation: **Can execution or observation unilaterally define final reality?**

## Admission posture

This document preserves provenance and proposes a proof target. It does not add runtime behavior and does not authorize implementation or merge.

**Historical consistency is evidence of provenance, not proof of current correctness.**
