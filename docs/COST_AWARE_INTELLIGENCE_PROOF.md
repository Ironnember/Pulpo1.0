# Cost-Aware Intelligence Escalation V0

Status: proposed; noncanonical until reviewed and merged.

## Purpose

Make frontier inference an escalation tier rather than Pulpo's default cost center.

## Invariant

`INTELLIGENCE_SELECTION != AUTHORITY`

`CHEAPER_MODEL != LOWER_AUTHORITY`

`EXPENSIVE_MODEL != HIGHER_AUTHORITY`

A model/provider is an untrusted intelligence surface. Selecting one cannot issue a permit, expand budget, change policy, approve an action, or execute a consequence.

## V0 flow

`deterministic -> local model -> commodity API -> frontier API`

The selector receives explicit uncertainty, consequence, budget, remote-use constraints, and a frozen set of intelligence options. It returns the lowest-cost sufficient option or `None` when no option satisfies all constraints.

V0 deliberately does not call any provider. It proves the selection boundary before adding provider adapters.

## Frozen regressions

The tests require:

1. deterministic computation wins when sufficient;
2. local inference wins before remote inference when sufficient;
3. commodity inference wins before frontier inference when sufficient;
4. frontier inference is selected only when lower tiers are insufficient;
5. insufficient budget fails closed rather than overspending;
6. remote prohibition fails closed when local intelligence is insufficient;
7. selection minimizes sufficient cost rather than maximizing capability;
8. malformed request bounds are rejected;
9. every returned plan has `authority_effect: none`.

## Architectural boundary

This is not a second router. It does not route consequential execution. It is a deterministic proposal function inside the intelligence plane. Pulpo's existing governance kernel remains the only decision/permit authority for consequences.

Provider credentials remain execution/intelligence credentials, never authority credentials.

## Next proof after V0

After exact-head CI and independent review, the next generation should compare the same frozen task across at least two real intelligence tiers and record:

- actual cost;
- latency;
- uncertainty retired;
- correctness/evidence score;
- escalation reason;
- reusable governed lesson produced.

Only then should Pulpo learn when a cheaper tier is sufficient. Learned routing competence may recommend a tier; it may not expand provider access, spend budget, or authority.
