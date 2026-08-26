# Pulpo Project Source Baseline

Status date: 2026-08-26

Canonical repository assessed: `Ironnember/Pulpo1.0` at `91424e0794f9cedce04262c458f9bad7cae5fd66`

Historical repository assessed: `Iron-Ember/pulpo` at `17a6784cf0157d8ee1ec417ce33b18f4cea8cb69`

## Authority of this document

This document defines what the clean Pulpo project starts from, what the legacy repository contributes, and how legacy material may enter forward development.

`Ironnember/Pulpo1.0` on `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, evidence boundaries, and forward development. `Iron-Ember/pulpo` is historical evidence and a behavior-level pattern source only. It is not a merge source, runtime source, release source, or authority for current claims.

The project carries forward verified behaviors—not the old repository tree, accumulated plans, generated receipts, machine-specific state, or workarounds.

## Constitutional foundation

Pulpo is the governance plane between intelligence and consequence.

The canonical lifecycle is:

> Purpose → Intent → Authority → Policy → Decision → Permit → Execution → Evidence → Reconciliation → Memory → Adaptation → Purpose

The three planes remain separate:

| Plane | Responsibility |
| --- | --- |
| Intelligence | Reason, research, plan, propose, and learn |
| Governance — Pulpo | Identity, authority, policy, budget, approval, permits, evidence, reconciliation, and outcome memory |
| Execution | APIs, shells, browsers, cloud services, payment rails, infrastructure, and machines |

The governing doctrine is:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

The constitutional invariant is:

> Learning may improve competence and recommend authority changes. Learning may never grant authority to itself.

Any change that expands capability, budget, identity scope, execution surface, or approval class requires a separately authorized policy transition.

## What the clean project starts with

The canonical repository begins with a deliberately small, dependency-free governance kernel and one authority path. At the assessed commit it contains 24 files totaling 124,866 bytes:

| Area | Files | Stored bytes | Role |
| --- | ---: | ---: | --- |
| Kernel code | 7 | 50,720 | Authority, policy evaluation, one-use permits, durable state, decision evidence, bounded commerce |
| Tests | 5 | 46,456 | Success, denial, replay, tamper, malformed authority, persistence, and commerce semantics |
| Documentation | 8 | 24,069 | Architecture, authority, persistence, commerce proof, governance, and current boundaries |
| CI and root configuration | 4 | 3,621 | Dependency-free verification and package definition |

The implemented starting proof includes:

- fail-closed handling for incomplete, unknown, invalid-cost, and over-budget intent;
- explicit high-impact approval requirements;
- an external-verifier contract bound to authority, approval, session, principal, exact intent, exact policy, nonce, expiry, and trusted kernel time;
- exact-intent, one-use permits with replay denial;
- optional SQLite persistence for approval IDs, nonces, issued and spent permits, and the canonical audit chain;
- restart detection of persisted audit tampering;
- agent grants that can narrow but never exceed canonical policy;
- bounded domain-commerce semantics for request, quote, budget reservation, authorization, attempted execution, charge reconciliation, delivery, acceptance, and continuing value;
- one governance kernel, one decision path, one state seam, and one canonical evidence chain.

This is a stronger starting point for forward proof because the trusted core is explicit, small, deterministic, and falsifiable.

## What the clean project does not yet prove

The clean start is intentionally narrower than a production system. It does not yet prove:

- independently deployed and authenticated human signing authority;
- trusted verifier bootstrap and protected trusted time;
- durable commerce budget reservation across restart;
- payment-rail enforcement;
- filesystem, network, process, or secret isolation enforced by the host;
- hostile-code containment;
- protection against rollback of an older valid SQLite snapshot or host compromise;
- distributed identity or multi-principal signer separation;
- an external production workload, independently reproduced result, or customer outcome;
- production readiness.

These are forward proof gates, not features to paper over with documentation or simulated state.

## Comparison with the historical repository

At the assessed commit, the historical repository contains 104 files totaling 726,957 bytes—4.3 times as many files and 5.8 times as many stored bytes as the canonical repository.

| Dimension | Clean `Pulpo1.0` | Historical `Iron-Ember/pulpo` | Assessment |
| --- | --- | --- | --- |
| Governing shape | Small deterministic kernel | Broad self-hosting control plane | The clean project makes the authority boundary easier to inspect and test |
| Code | 7 files / 50,720 bytes | 14 files / 328,445 bytes | The historical runtime has broader behavior and a much larger trusted surface |
| Tests | 5 files / 46,456 bytes | 13 files / 146,800 bytes | Historical tests preserve useful cases, but must be admitted behavior by behavior |
| Documentation | 8 files / 24,069 bytes | 24 files / 158,052 bytes | Historical documentation mixes current state, dated evidence, strategy, plans, and proof claims |
| Additional surfaces | None inside the trusted core | CLI, loopback RPC, task queue, source registry, credit estimates, repository operations, UI endpoints, scripts, startup program | Valuable product patterns are coupled to governance and execution concerns in the old tree |
| Authority path | One kernel and verifier path | Authority, authority gateway, control plane, approvals, CLI/RPC orchestration | Historical overlap increases the risk of competing or ambiguous control paths |
| Persistence | One `KernelState` seam with optional SQLite | SQLite/WAL accounting across a broader control plane | Clean persistence is narrower and clearer; historical durability patterns remain reference material |
| Evidence discipline | Current claims tied to canonical behavior and explicit boundaries | Dated evidence, generated plans, dogfood records, receipts, and live code coexist | Historical evidence is useful only when its date, environment, and implementation are preserved |
| Product maturity | Narrow executable proof | Broader developer-preview surface | The historical project is broader; the clean project is more defensible |

The old repository is not worthless. It contains substantial prior learning in authority handling, transaction semantics, economics, delegation, portability, performance, outcome memory, task packets, source intake, work receipts, repository governance, and self-hosting. The problem is architectural concentration: too many concerns accumulated before the central governance boundary had one canonical, independently testable form.

## Legacy intake rule

No legacy folder, module, or subsystem is copied wholesale.

For each proposed legacy mechanism:

1. Name the invariant, failure, or user outcome it addresses.
2. Identify the exact historical implementation and the evidence attached to it.
3. Classify its claims as **Verified**, **Recorded**, **Inferred**, or **Proposed**.
4. Reimplement the smallest necessary behavior behind the current Pulpo interface.
5. Keep it subordinate to the existing kernel, state seam, permit path, and evidence chain.
6. Add adversarial success, denial, replay, tamper, malformed-input, restart, and failure tests as applicable.
7. Document what the new evidence proves and what remains outside its boundary.
8. Admit it only through review in the canonical repository.

The following are prohibited:

- bulk-merging the historical repository;
- creating a second router, executor, ledger, memory system, or authority path;
- treating generated receipts or historical screenshots as current proof;
- importing machine-specific runtime state, private source material, simulated UI state, task backlogs, or CI workarounds;
- expanding an agent's authority through learning, adaptation, role configuration, or plugin installation;
- allowing adapters, models, execution hosts, or payment rails to issue their own governance truth.

## Source precedence

When sources conflict, use this order:

1. executable behavior and adversarial tests at the exact canonical commit;
2. durable runtime evidence tied to that commit and environment;
3. the canonical repository's current-state and architecture documents;
4. this source baseline and approved governance doctrine;
5. dated legacy evidence and implementation patterns;
6. chat summaries, screenshots, plans, prototypes, and marketing claims.

Historical records remain intact as historical evidence. They do not override current canonical state.

## Starting assessment

Pulpo is not starting over. It is restarting from a higher-quality abstraction.

The historical repository proved that many useful governance-adjacent mechanisms could be built. The clean repository begins after the more important architectural lesson was learned: intelligence, authority, execution, and evidence must not be allowed to collapse into one self-hosting control surface.

Therefore the correct starting asset is not the 727 KB historical tree. It is the smaller executable constitutional core, plus a disciplined intake process for recovering only those historical behaviors that strengthen the canonical lifecycle without creating competing control paths.

The next proof sequence remains:

1. preserve reproducible dependency-free kernel verification;
2. deploy independently authenticated signing authority, trusted verifier bootstrap, and trusted time outside the governed worker boundary;
3. extend the existing state seam to durable commerce budget reservation without another ledger;
4. enforce host filesystem, network, process, and secret boundaries;
5. run one external bounded workload through the complete Pulpo lifecycle and publish an inspectable evidence bundle.

Pulpo earns broader authority only when the preceding boundary is supported by executable denial and success evidence.
