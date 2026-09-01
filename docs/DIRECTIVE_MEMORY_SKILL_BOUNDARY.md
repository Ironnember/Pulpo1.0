# Directive Memory Skill Boundary V0

Status: branch-local proof; noncanonical until independently reviewed and admitted.

## Purpose

Prove a capability boundary for an untrusted conversational `Directive Memory`
surface without making the conversational surface a memory governor, authority
service, policy engine, canonical writer, executor, or ledger.

The skill may inspect a frozen primitive projection and construct candidate
intents. It must not possess the canonical capability needed to activate,
revoke, supersede, or otherwise mutate directive state.

## Invariants

`CHAT_OR_RETRIEVAL != DIRECTIVE_AUTHORITY`

`FROZEN_MEMORY != LIVE_AUTHORITY`

`NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`

`CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`

A conversationally useful surface is not trusted merely because its API omits a
write command. It must also lack the kernel, state backend, directive authority
controller, approval verifier/signer, authority client, executor, clock, and
ledger references that could perform or authorize a canonical mutation.

## V0 object boundary

Trusted Pulpo may call `freeze_directive_memory_snapshot(kernel, directive)`.
That function reads the current directive status and trusted observation time and
copies the relevant metadata into `DirectiveMemoryReadSnapshot`.

The snapshot contains only immutable primitive values. The untrusted
`DirectiveMemorySkillProjection` receives exactly that snapshot and retains no
reference to the kernel or any canonical writer.

The surface exposes only:

- frozen inspection;
- candidate-intent construction;
- a non-authoritative comparison against the frozen directive scope.

Every output explicitly reports:

- `freshness=frozen`;
- `authority=not_asserted`;
- `authority_effect=none`;
- `governed_effect=none`;
- `canonical_state_mutation=false`;
- `requires_canonical_revalidation=true` for candidate intents.

A stale snapshot may continue to report that an intent matched the scope that was
observed earlier. That cannot create authority because the skill surface has no
live authority or write capability. Canonical Pulpo must revalidate policy,
directive status, revocation, trusted time, and permit state before any governed
consequence.

## Adversarial proof targets

The focused tests require:

1. the surface rejects a kernel or `Directive` object in place of the exact
   capability-free snapshot;
2. the surface retains no kernel, state, controller, authority-client,
   approval-verifier, executor, clock, or ledger attribute;
3. repeated inspection/proposal operations leave the canonical audit and
   directive state unchanged;
4. an unactivated directive cannot be promoted to authority by the surface;
5. a request outside frozen budget/scope is only a failed frozen-scope proposal,
   never a directive mutation;
6. the surface exposes no activate/revoke/evaluate/consume/execute/write method;
7. an active snapshot captured before revocation remains explicitly frozen and
   non-authoritative after canonical revocation and restart, while live canonical
   evaluation denies the revoked directive.

## Authority change

None.

This proof deliberately does not add a conversational path for directive
activation or revocation. Existing `DirectiveAuthorityController` remains the
only directive mutation path in this package and continues to require the pinned
external approval verifier.

## Canonical state mutations introduced or exposed

None by the skill projection.

The trusted snapshot-freeze function reads canonical directive status and trusted
time. It does not write canonical state. The untrusted projection receives no
writer reference.

## Claim classification

Before exact-head CI and substantive review:

- capability-stripped skill-surface design: **Proposed**;
- source-level absence of retained canonical writer references: **Recorded** on
  this branch;
- focused behavior: **Unknown** until CI executes the exact head;
- actual ChatGPT `@Directive Memory` runtime using this module: **Unknown**;
- production external authority binding for the live skill: **Unknown**.

After exact-head CI succeeds, the focused software-boundary behavior may be
classified **Verified on the branch only**. It remains noncanonical until normal
repository admission.

## Explicit nonclaims

This V0 does not prove:

- that the current ChatGPT `@Directive Memory` skill is implemented by this
  module;
- hostile same-process memory isolation;
- a live read-only IPC transport;
- production authentication for a skill host;
- independent production human authority;
- external-provider containment or consequence reconciliation;
- that frozen status is current after the snapshot observation time.

The next integration proof must bind the actual user-facing skill/runtime to this
or an equivalently capability-stripped transport and show that no alternate
persistent-memory or canonical-write capability bypasses Pulpo.
