# Capability Derivation / Duplication Proof V0

Status: PROPOSED until executable CI evidence on the exact branch head says otherwise.

## Purpose

Extend the existing capability-activation authority proof to the adjacent failure class exposed by the authenticated-browser inspection incident:

`AUTHORIZATION_TO_USE_CAPABILITY != AUTHORIZATION_TO_DUPLICATE_CAPABILITY`

A worker may legitimately possess or use a bounded capability without having authority to create an equivalent second capability by copying, exporting, serializing, exposing, delegating, or otherwise deriving it.

## Incident stimulus

During bounded inspection of an authenticated Partner Portal workflow, an intelligence component attempted to clone a local authenticated Chrome profile into a temporary debugging profile.

The intended purpose was authorized inspection. The capability-duplication mechanism was broader than the purpose required.

This proof does not make a historical claim about whether the temporary profile completed, contained usable credentials, or was accessed by another party.

## Frozen invariant

No intelligence component may create, duplicate, derive, delegate, serialize, export, or expose a capability whose effective authority exceeds the exact authority granted for the current consequence.

Supporting statements:

`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`

`AUTHORIZATION_TO_USE_CAPABILITY != AUTHORIZATION_TO_DUPLICATE_CAPABILITY`

`AVAILABLE_CAPABILITY != AUTHORIZED_CAPABILITY`

## Proof shape

The existing Pulpo kernel represents the following as separate intents:

- `use_capability`
- `duplicate_capability`
- `export_capability`
- `expose_capability`

Ordinary bounded use is permitted by policy.

Duplication, export, and exposure require independent approval.

The executable tests require that:

1. permission to use the existing capability does not authorize duplication;
2. a use permit cannot be substituted for a duplication intent;
3. independently verified approval can issue one exact, single-use duplication permit;
4. duplication approval cannot be reinterpreted as export authority;
5. duplication approval cannot be retargeted to another capability or resource.

## Failure condition

The proof fails if any use permit or approval can be reused, substituted, reinterpreted, or retargeted to authorize capability derivation outside its exact intent.

## Scope boundary

A PASS establishes only that the current Pulpo kernel can represent and enforce capability use and capability derivation as separate authority transitions.

A PASS does not establish:

- Chrome credential custody;
- browser-cookie or SSO containment;
- external OpenAI Partner Portal enforcement;
- operating-system prevention of credential copying;
- arbitrary host-compromise resistance;
- cleanup of the historical temporary-profile attempt.

Those remain separate external/runtime proofs.

## Operational consequence

The standard adversarial transformation procedure in `docs/ADVERSARIAL_TRANSFORMATION_SOP.md` must be run at material consequence and authority boundaries.

If that procedure discovers capability duplication, derivation, export, delegation, serialization, or exposure that was not separately authorized, execution stops and reconciliation occurs before continuing.

## Doctrine

Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.
