# Public Proof Lab V0

## Purpose

Give external users a safe way to experience Pulpo's canonical governance kernel without exposing an executor, external credentials, arbitrary prompts, or an authority-expanding path.

## Boundary

The lab accepts one exact scenario identifier from a fixed set. It runs the canonical `GovernanceKernel`, displays the decision, and for the harmless allow case consumes the one-use permit and deliberately proves replay rejection. It never passes the permit to an external executor and performs no external side effect.

`PUBLIC_INPUT != AUTHORITY`

`PERMIT != EXECUTION`

`USAGE != POLICY`

`LEARNING != AUTHORITY_EXPANSION`

## Public learning

The API emits one privacy-minimized structured event to deployment logs after a successful proof request. The application event contains only scenario, outcome, reason, replay result, authority effect, schema, and an event hash. It deliberately excludes free-form prompts, email, IP, user agent, cookies, and stable user identifiers.

Provider infrastructure may independently retain standard request metadata under its own configuration. Do not describe the deployment as anonymous unless that infrastructure boundary is separately verified.

Public usage is evidence for product learning, not an authority source. Usage can recommend scenario, UX, policy, or product changes; it cannot change Pulpo policy or grant itself new execution capability.

## Commercial boundary

The V0 call to action requests a bounded design-partner pilot. Payment is intentionally not coupled to the Pulpo authority path. A hosted payment link may replace the contact link once an approved merchant/payment account and exact offer are configured.

## Claim classification

- Fixed-scenario kernel evaluation and replay proof: Verified when branch tests and deployment proof pass.
- Public deployment: Proposed until independently fetched and exercised.
- Public usage learning: Proposed until real usage events exist.
- Paid pilot checkout: Proposed until a payment destination is configured.
- Production readiness: Not claimed.
