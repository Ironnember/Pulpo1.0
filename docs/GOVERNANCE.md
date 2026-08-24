# Project governance

## Canonical rule

`Ironnember/Pulpo1.0` is the only forward-development repository. The legacy repository is historical evidence and a pattern source, never a merge source.

## Claim discipline

- **Proven:** behavior covered by an executable test in this repository.
- **Implemented:** code exists but its boundary is not yet independently proven.
- **Planned:** design intent only.

README and release claims must use these labels honestly.

## Change gates

Every pull request must state the governed behavior, threat or failure addressed, tests added, and boundary not covered. Changes to policy semantics require review. CI stays dependency-free until a dependency has a documented reason and owner.

## Legacy intake

Carry forward one behavior at a time. Rewrite it behind the current interface, add adversarial tests, and record the proof. Do not copy generated evidence, startup programs, task backlogs, local-machine scripts, historical plans, or CI workarounds.
