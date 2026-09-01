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

## V0 isolated host / transport boundary

The branch now adds a second boundary beyond in-process object design:

1. trusted Pulpo serializes only `DirectiveMemoryReadSnapshot` plus an
   `inspect` or `propose` request using
   `build_directive_memory_request(...)`;
2. the request crosses a JSON-only subprocess boundary;
3. `skill-host/directive_memory_host.py` runs under Python isolated mode (`-I`)
   with a scrubbed environment in the proof harness;
4. the host imports Python standard-library modules only and has no Pulpo import;
5. the host accepts an exact request-field allowlist and rejects injected
   `kernel`, `authority_client`, `executor`, or `ledger` fields;
6. the host may compare a candidate intent against frozen scope, but its output
   continues to assert no authority and requires canonical revalidation.

This converts the capability-stripping claim from only an object/API shape into a
separate-process software boundary. It is still not evidence that the actual
ChatGPT `@Directive Memory` runtime is deployed behind this transport.

## Adversarial proof targets

The focused tests require:

1. the in-process surface rejects a kernel or `Directive` object in place of the
   exact capability-free snapshot;
2. the in-process surface retains no kernel, state, controller, authority-client,
   approval-verifier, executor, clock, or ledger attribute;
3. repeated inspection/proposal operations leave the canonical audit and
   directive state unchanged;
4. an unactivated directive cannot be promoted to authority by the surface;
5. a request outside frozen budget/scope is only a failed frozen-scope proposal,
   never a directive mutation;
6. the surface exposes no activate/revoke/evaluate/consume/execute/write method;
7. an active snapshot captured before revocation remains explicitly frozen and
   non-authoritative after canonical revocation and restart, while live canonical
   evaluation denies the revoked directive;
8. the isolated host imports only stdlib and contains no Pulpo import;
9. trusted projection and isolated-host proposal results bind the same exact
   intent hash and directive hash;
10. the transport contains no kernel, authority client, verifier, executor,
    ledger, permit, secret, or credential field;
11. injected capability fields fail closed at the host boundary;
12. broadening through the isolated host remains a non-authoritative failure;
13. a stale pre-revocation JSON snapshot cannot override live canonical
    revocation after restart.

## Authority change

None.

This proof deliberately does not add a conversational path for directive
activation or revocation. Existing `DirectiveAuthorityController` remains the
directive mutation path in this package and continues to require pinned external
approval authority.

## Canonical state mutations introduced or exposed

None by the skill projection or isolated host.

The trusted snapshot-freeze function reads canonical directive status and trusted
time. It does not write canonical state. The untrusted projection and host receive
no writer reference.

## Claim classification

For the current draft head before exact-head CI completes:

- capability-stripped object design: **Verified on prior branch head**;
- JSON-only isolated-host design: **Recorded / Proposed**;
- isolated-host focused behavior: **Unknown** until CI executes the exact head;
- actual ChatGPT `@Directive Memory` runtime using this module/transport:
  **Unknown**;
- production skill-host authentication and isolation: **Unknown**;
- production external authority binding for the live skill: **Unknown**.

After exact-head CI succeeds, the isolated-host software-boundary behavior may be
classified **Verified on the branch only**. It remains noncanonical until normal
repository admission.

## Explicit nonclaims

This V0 does not prove:

- that the current ChatGPT `@Directive Memory` skill is implemented by this
  module or host;
- that ChatGPT's production skill runtime uses Python isolated mode or an empty
  environment;
- hostile host-kernel isolation outside the tested subprocess boundary;
- production authentication for a skill host;
- independent production human authority;
- external-provider containment or consequence reconciliation;
- that frozen status is current after the snapshot observation time.

The next decisive integration proof must bind the actual user-facing
`@Directive Memory` runtime to this or an equivalently capability-stripped
transport and show that no alternate persistent-memory, canonical-write,
authority, or execution capability bypasses Pulpo.
