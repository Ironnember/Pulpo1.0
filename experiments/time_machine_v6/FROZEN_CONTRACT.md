# Time Machine Governed-Effect V6 — Frozen Contract

## Purpose

Replay a new governed-effect probe set across Pulpo's canonical first-parent Git history after the MCP defect proved that absence of a permit does not imply absence of a governed effect.

Git ancestry is the temporal authority. Do not use PR numbering, branch timestamps, chat chronology, or later descriptions as substitutes for the exact historical tree.

Frozen canonical reference:

`ca3636680ca50356406519a5722444c0742afb39`

## Hypothesis frozen before execution

The original Time Machine catalog could report healthy historical controls while missing a later-discovered class: an untrusted transport could create no permit yet still mutate canonical state or retain a canonical writer.

V6 therefore freezes three additional software-boundary invariants:

1. `K15_MCP_NO_CANONICAL_MUTATION` — an MCP proposal transport must leave canonical state unchanged.
2. `K16_MCP_CAPABILITY_STRIPPED` — an MCP projection must not retain a kernel, orchestrator, state backend, authority client, executor, policy object, trusted clock, ledger, or equivalent canonical writer.
3. `K17_MCP_FROZEN_READ_ISOLATION` — a frozen read projection must not gain future canonical state through a hidden live reference and must identify its freshness as frozen.

V6 also records one diagnostic:

`D01_CANONICAL_MUTATION_WITHOUT_PERMIT` — whether canonical target locking is observable while no execution permit exists. This diagnostic establishes why `NO_PERMIT != NO_GOVERNED_EFFECT`; its presence is not itself classified as a safety success.

## Expected falsification opportunity

If the historical MCP implementation introduced by the earlier MCP admission can mutate canonical target/audit state or retains the canonical orchestrator, V6 must report `fail` at those exact historical checkpoints rather than reinterpret them using the current doctrine.

If the later capability-stripped MCP admission truly closes that class, V6 must report `hold` at the exact admitted checkpoint and no later regression through the frozen reference.

## Isolation

Historical checkpoints execute only in detached temporary worktrees. The experiment must not:

- rewrite any historical tree;
- mutate protected `main`;
- call a provider;
- use production credentials;
- issue a real permit or consequential command;
- create another router, executor, authority service, policy engine, memory governor, or ledger.

`authority_effect=none`
`provider_write_attempted=false`

## Success condition

The experiment succeeds only if:

- the frozen canonical reference holds K15, K16, and K17;
- there are zero probe errors for any checkpoint where a probe is available;
- after an invariant first reaches `hold`, it never later falls to `fail` or `error` through the frozen reference;
- the historical defect window, if present, is preserved rather than hidden.

## Claim boundary

A successful V6 run proves only an exact historical software-boundary differential for these frozen probes and commits. It does not prove external containment, production security, repository admission enforcement, third-party reproduction, or external-provider consequence.
