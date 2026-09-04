# Proofs

`proofs/` contains reproducible proof specifications, harnesses, fixtures, and instructions used to test Pulpo claims.

It is **not** a second evidence ledger, authority service, policy engine, canonical state store, or runtime source of truth.

## Evidence ladder

Pulpo consequence claims should advance in this order:

1. **Software-boundary proof** — executable behavior and adversarial tests at an exact commit.
2. **Independent/local provider simulation** — useful when it tests integration semantics without claiming real external containment.
3. **Real external provider proof** — distinct executor and observer identities/credentials, exact action binding, preserved provider evidence, and reconciliation of the same consequence boundary.
4. **Cold reproduction** — someone outside the build loop reproduces the frozen proof object and evidence path.

A lower rung must not be described as a higher one.

## Proof requirements

A material proof should identify:

- exact purpose and claim;
- exact code/ref/environment;
- authority and policy assumptions;
- expected allowed behavior;
- denial behavior;
- substitution/replay/expiry/revocation behavior where applicable;
- restart/durability behavior where state matters;
- race/concurrency behavior where relevant;
- evidence source and trust boundary;
- reconciliation result;
- explicit nonclaims.

Missing, stale, wrong-source, ambiguous, or unauthenticated external observation resolves to `Unknown` rather than zero unauthorized effect.

## Generated evidence

Large receipts, provider exports, screenshots, raw logs, and external evidence bundles should normally be preserved through durable artifact/provider storage and referenced by exact IDs/hashes. Do not turn this source repository into a parallel evidence database merely for convenience.

## Admission

A proof can support canonical claims only when the behavior it tests exists in the canonical path and the relevant change has legitimately passed the protected repository admission process.

`PASSING_PROOF != ADMISSION_AUTHORITY`
