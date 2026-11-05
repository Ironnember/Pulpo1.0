# Plugin skill lessons

Status: Proposed learning artifact. Authority effect: none.

Pulpo may learn engineering and operating patterns from plugin skills, but a
skill is an untrusted intelligence/capability source. Reading or successfully
using a skill does not install authority, expand policy, create a connector,
or make its recommendations canonical.

## Admission rule

A skill-derived lesson may influence planning or a proof only when it is:

1. attributed to its exact source skill and inspected version/context;
2. translated into a Pulpo-local invariant or testable hypothesis;
3. checked against current canonical executable behavior and doctrine;
4. rejected if stale, irrelevant, authority-expanding, or duplicative;
5. proven through the existing canonical path before any implementation claim;
6. separately authorized if adoption would expand capability, identity, budget,
   approval class, policy power, or execution surface.

`SKILL KNOWLEDGE != AUTHORITY`

`SUCCESSFUL TOOL USE != CANONICAL ADMISSION`

## Lessons admitted for experimentation

### 1. Smallest runnable proof before orchestration breadth

Source: OpenAI Developers / Agents SDK skill.

Useful pattern: begin with one agent and a clear contract, add tools
intentionally, keep side effects narrow and schemas explicit, and add
specialists/handoffs/sandboxing only after the workflow proves the need.
Verification should exercise the real path rather than a mock-only contract.

Pulpo translation:

- Prefer the smallest executable governance proof that retires one material
  uncertainty.
- A capability surface should have an explicit input, expected output, allowed
  tools/effects, state boundary, approval gate, and observable verification.
- Do not add another agent/router because orchestration is convenient.
- Evaluation cases should cover success, missing evidence, approval boundaries,
  forbidden calls, state changes, and regressions from observed failures.

This reinforces existing Pulpo doctrine; it does not create a new architecture.

### 2. Deployment readiness is a contract, not a successful build

Source: OpenAI Developers / Agents SDK skill.

Useful pattern: a deployable service should expose a stable entrypoint and
health/readiness signal, then be verified after deployment rather than treating
deployment initiation as success.

Pulpo translation:

For a deployed Pulpo surface, distinguish at least:

`build -> deploy_attempt -> readiness -> governed_exercise -> observed_effect -> reconciliation`

A green build or provider deployment status is evidence about infrastructure,
not proof that the governed consequence path works.

### 3. Classify trust failures before repairing them

Source: Build macOS Apps / Signing & Entitlements skill.

Useful pattern: inspect the actual artifact, read its trust/signing metadata,
classify the failure, then apply the minimum repair. Do not invent entitlements
or conflate local-development trust with distribution trust.

Pulpo translation:

Before repairing an authority/trust failure:

`inspect exact artifact/state -> collect trust evidence -> classify failure -> minimum fix -> reverify`

Useful failure classes generalize beyond macOS signing:

- absent/untrusted identity;
- wrong identity or trust root;
- scope/entitlement mismatch;
- execution-environment mismatch;
- nested/delegated trust mismatch;
- distribution/deployment prerequisite failure.

Pulpo must not silently broaden policy to make a failing capability work.

## Reusable compound lesson

The two inspected skill families converge on a useful operating principle:

> Make the contract explicit, inspect the exact artifact at the trust boundary,
> classify failure before repair, introduce the minimum capability required,
> and verify the real deployed path after the change.

For Pulpo this becomes:

`contract -> exact object -> trust evidence -> decision -> minimum permitted effect -> independent verification -> reconciliation -> lesson`

This is competence guidance only. Learning may recommend a policy or capability
change; it may never authorize that change.

## Negative-transfer tests for future skill ingestion

Any future skill-derived lesson should be rejected when:

- it asks an intelligence/tool/plugin to become canonical authority;
- it creates a second router, executor, policy truth, or evidence ledger;
- it recommends broad permissions merely to make integration easier;
- it treats provider success as consequence verification;
- it conflicts with newer executable Pulpo evidence;
- it is specific to an environment Pulpo is not operating in and has no valid
  generalized invariant;
- it cannot identify the exact capability or uncertainty it is intended to
  improve.

## Next proof

Use these lessons when evaluating the next canonical admission and deployment
work. The immediate application is to treat Target Lock, independent authority,
and public/deployed surfaces as explicit contracts with exact objects, narrow
capabilities, classified trust failures, health/readiness evidence, real-path
negative tests, and reconciliation.
