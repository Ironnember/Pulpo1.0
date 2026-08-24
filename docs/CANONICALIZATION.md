# Pulpo Repository Canonicalization

Effective date: 2026-08-24

## Decision

`Ironnember/Pulpo1.0` is the only forward-development Pulpo repository. Its `main` branch is the canonical integration branch.

The previous `Iron-Ember/pulpo` repository is a historical evidence and pattern source. It is not a merge source, release source, runtime source of truth, or destination for new Pulpo development.

## Why this separation exists

The earlier repository accumulated valuable architecture, tests, evidence records, plans, machine-specific scripts, and CI workarounds. Bulk migration would also import stale assumptions, duplicate control paths, and claims whose original environments cannot be reproduced from the clean repository.

The new repository therefore carries forward proven behaviors, not repository history or clutter.

## Intake rule

For each legacy mechanism:

1. state the invariant or failure it addresses;
2. reimplement the smallest behavior behind the current Pulpo interface;
3. add success, denial, replay, tamper, and malformed-input tests as applicable;
4. run the dependency-free suite;
5. document what the evidence proves and what remains outside the boundary;
6. merge only through the current repository’s review process.

Do not import generated receipts as current proof. New evidence must be produced by the canonical implementation and tied to its exact commit and environment.

## Source disposition

| Source | Status | Permitted use |
| --- | --- | --- |
| `Ironnember/Pulpo1.0` | Canonical | Current code, tests, documentation, releases, and forward development |
| `Iron-Ember/pulpo` | Historical | Read-only evidence review and behavior-level pattern intake |
| Earlier archives | Historical snapshot | Reproduce a dated mechanism only after recording checksum and environment |
| UI and routing prototypes | Prototype reference | Interaction research only; never governance or security truth |
| Dated evidence documents | Historical evidence | Preserve original claims with their dates; do not treat them as live status |

## Claim precedence

For current claims, precedence is:

1. executable behavior and tests at the exact canonical commit;
2. this repository’s `docs/CURRENT_STATE.md`;
3. this repository’s architecture and governance documents;
4. dated evidence and legacy material as historical context only.

Conflicting older statements must remain intact as historical records but are superseded for live status by the canonical repository and current-state document.
