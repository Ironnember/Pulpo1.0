# Experiments

`experiments/` contains noncanonical research, exploratory harnesses, and trial implementations.

An experiment may discover a useful invariant, expose a defect, or demonstrate a candidate mechanism. It does **not** create current Pulpo authority, current product claims, canonical behavior, or production evidence merely because it passes locally or produces a convincing result.

## Rules

- Experiments are noncanonical by default.
- Experimental code must not be treated as an authority source.
- Experimental success does not expand capability, budget, identity scope, policy power, approval class, canonical-write scope, or execution rights.
- Generated receipts, screenshots, logs, or benchmark outputs remain evidence artifacts, not canonical truth by themselves.
- A simulator or structural contract must not be described as real external containment.
- Missing or ambiguous external observation resolves to `Unknown`, not zero unauthorized effect.

## Promotion into canonical Pulpo

To carry a lesson from an experiment into current Pulpo:

1. state the exact invariant, defect, or failure class the experiment exposed;
2. reimplement the smallest necessary behavior through the existing canonical seam;
3. add the relevant success, denial, substitution, replay, expiry, restart/durability, race, and evidence-mismatch tests;
4. state the exact claim boundary;
5. obtain substantive review of the exact object;
6. admit it only through the protected canonical repository process.

Do not bulk-import an experiment or its authority assumptions simply to preserve apparent progress.

The governing rule remains:

`EXPERIMENTAL_SUCCESS != AUTHORITY != CANONICAL`
