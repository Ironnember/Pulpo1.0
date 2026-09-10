# Pulpo Repository Map

Status date: 2026-09-04

This map records repository role and permitted use. It does not transfer authority, redesignate canonical state, archive repositories, or admit behavior into Pulpo.

The sole forward-development Pulpo repository remains `Ironnember/Pulpo1.0` on protected `main`.

| Repository | Classification | Authority role | Canonical write capability | Permitted use | Next action |
| --- | --- | --- | --- | --- | --- |
| `Ironnember/Pulpo1.0` | **CANONICAL** | Governance and evidence plane | Yes, only through the repository's governed admission process | Current code, tests, documentation, releases, and forward development | Keep canonical; do not fork authority into another Pulpo repo |
| `Iron-Ember/pulpo` | **HISTORICAL / REFERENCE** | None | No | Read-only evidence review and behavior-level pattern intake | Preserve history; do not resume forward development |
| `Ironnember/pulpo` | **HISTORICAL SELF-HOSTING PREVIEW / ARCHIVE CANDIDATE** | None for current Pulpo | No | Historical self-hosting/control-plane evidence and pattern review only | Audit unique implementation/evidence, then consider archival through separate approval |
| `Ironnember/Pulpo-V.3` | **UI / DISTRIBUTION PROTOTYPE** | None | No | Interaction, operator-dashboard, and presentation research only | Keep separated from governance truth; rename or retire only after separate review |
| `Ironnember/matrix-ui` | **UI PROTOTYPE CANDIDATE** | None | No | UI comparison and interaction research only | Compare with the selected UI path before any consolidation |
| `Ironnember/The-keel` | **EXECUTION-PLANE EXPERIMENT / REFERENCE** | None | No | Execution-contract experiments and execution-plane reference work | May inform an exact execution contract; must not become a second authority, policy engine, or ledger |
| `Ironnember/Govenator` | **UNCLASSIFIED / PLACEHOLDER** | None unless separately admitted | No | No Pulpo governance claim may depend on it | Define purpose and boundary before any integration or archival decision |

## Classification rules

### Canonical

Only `Ironnember/Pulpo1.0` may define current Pulpo code, tests, architecture, governance, and forward development. A branch, pull request, prototype, historical repository, cloud service, plugin, UI, executor, or experiment does not become canonical merely because it is newer or functional.

### Historical / reference

Historical repositories may preserve provenance, evidence, design lessons, or implementation patterns. They are not merge sources of truth. Useful behavior must be re-expressed through the current canonical interfaces, tested again, and legitimately admitted.

### UI / distribution

UI and distribution surfaces may present or transport proposals and evidence. They are not authority sources and must not retain or recreate a kernel, policy engine, canonical state backend, trusted clock, executor authority, governance secret, or ledger unless a separately governed proof explicitly requires it.

### Execution plane

Keel or any other executor may perform only the exact permitted consequence and return execution evidence. Executor success cannot self-certify reconciliation and may not grant itself authority.

## Consolidation gate

Before any repository is archived, renamed, merged, transferred, or designated as a replacement:

1. record its default branch and final commit;
2. inspect unique code, tests, evidence, and provenance;
3. preserve unique material that remains valuable without silently importing stale authority assumptions;
4. verify the canonical replacement still builds and proves the required invariants;
5. update references deliberately;
6. obtain separate explicit authorization for the repository mutation.

`MERGED != VERIFIED != CANONICAL`
