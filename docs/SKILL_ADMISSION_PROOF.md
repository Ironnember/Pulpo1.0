# Pulpo Skill Admission Boundary

Status: Proposed proof on `proof/skill-admission-boundary` until CI and review complete.

## Purpose

Treat external agent skills as untrusted capability artifacts. A skill may improve competence, but it cannot create, widen, or preserve authority for itself.

The boundary extends the existing Pulpo authority/policy seam. It does not create a second router, executor, policy engine, or evidence ledger.

## Flow

`discover -> resolve exact source/revision -> hash artifact -> admit scoped capability -> Pulpo policy evaluation -> permit -> execution-time revalidation -> existing evidence/reconciliation`

## Executable invariants in this proof

1. Unapproved skills are denied.
2. An upstream content change invalidates the pinned admission digest.
3. A revision mismatch is denied even when content is unchanged.
4. A skill cannot widen its admitted action scope.
5. A skill cannot widen its admitted resource scope.
6. A skill cannot widen its admitted budget.
7. Passing skill admission is insufficient by itself: the existing GovernanceKernel retains final policy authority.
8. Revocation is revalidated at consequential execution time, so a permit issued before revocation cannot bypass the changed admission projection.
9. Existing kernel permit replay protection remains authoritative and is reused rather than duplicated.

## External catalog posture

`VoltAgent/awesome-agent-skills` is an external discovery surface only. Catalog membership, popularity, semantic retrieval score, maintainer identity, generated summaries, or previous successful use do not raise authority.

Candidate skills should be resolved to an exact upstream source and immutable revision before admission. The exact artifact bytes are SHA-256 pinned. A changed digest or revision requires a new separately authorized admission transition.

## Initial candidate set for later vetting

Prioritize narrow skills that advance current proofs or durable operating needs rather than bulk installation:

- Trail of Bits: static analysis, differential review, insecure defaults, property-based testing, variant analysis, testing guidance.
- Supabase/Postgres: database best-practice guidance relevant to durable state.
- Stripe: payment-integration guidance relevant to bounded commerce.
- OpenAI/browser testing: controlled browser and PR workflows when they materially advance a named proof.
- Sentry/Microsoft observability: runtime evidence and failure telemetry when required by a named proof.

None are admitted by this document. Admission requires exact-source inspection, immutable pinning, explicit scope, and executable denial tests.

## Remaining proof gap

This branch proves deterministic admission and execution-time revocation at the library boundary. It does not yet prove sandbox isolation of filesystem/network/secrets access for arbitrary third-party skill code, nor does it persist a signed admission policy across process restart. Those are separate consequential proofs and should reuse Pulpo's existing durable state and authority mechanisms rather than create a new skill ledger.
