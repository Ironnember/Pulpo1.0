# Integrating Pulpo with an AI coding assistant

Most Pulpo integrations are now written with an AI coding assistant in
the loop. That is a governance fact, not just a workflow one: the
assistant will happily route around a refusal if the integration lets
it — retry with a cheaper intent, catch the exception and proceed,
cache a permit "for performance". The integration prompt in
[INTEGRATION_PROMPT.md](INTEGRATION_PROMPT.md) exists to close those
paths at the moment the code is written. Paste it into the assistant
session before asking for integration code, and keep it in force for
follow-up sessions.

**Claim classification: Proposed** as guidance. The gate behaviors it
relies on are **Verified** at this commit by
`tests/test_permit_gate.py`; the prompt's effect on any given
assistant session is **Unknown** until the produced integration is
reviewed and tested like any other code.

## The integration shape the prompt encodes

```
your code ──► PermitGate.run(intent, action)
                    │
                    ├─ GovernanceKernel.evaluate(intent)
                    │     └─ not "allow" + permit ──► PermitRefused (recorded)
                    ├─ presenter proof (via your proof_provider)
                    └─ GovernanceKernel.consume(permit, intent)
                          └─ not True ──► PermitRefused (recorded)
                    ▼ both pass
                 action()  ← the first side effect happens here
```

Three properties do the work:

- **The intent is the authorization.** `Intent` fields (principal,
  action, resource, cost, session) are hashed exactly; a permit minted
  for one intent spends for no other. The prompt requires the intent
  to be built from the values the action will actually use.
- **Consumption precedes the act.** The gate consumes the permit
  before invoking the action, because a Pulpo permit is spent at the
  moment of the act it authorizes. An integration that executes first
  and consumes afterwards is not governed by the permit, whatever its
  tests say.
- **Refusals terminate, and are evidence.** Every refusal the gate
  raises corresponds to records the kernel already appended
  (`decision`, `permit_rejected`). The correct handling is to surface
  the outcome and reason — not to retry around it.

## What the prompt deliberately does not do

- **It grants nothing.** The prompt is instructions to a coding
  assistant, not a policy, a grant, or an approval. Policy changes it
  might suggest (wider grants, higher ceilings, binding disabled) are
  separate governed decisions for the deployment's owner.
- **It does not cover approval-required actions end to end.** Those
  permits are minted through `evaluate_with_approval` with an envelope
  from the authority service (see
  [AUTHORITY_SERVICE_CONTRACT.md](AUTHORITY_SERVICE_CONTRACT.md)); the
  prompt teaches the assistant to stop at `require_approval` and to
  spend an externally minted permit through `run_with_permit`, never
  to fabricate approval material.
- **It does not replace review.** Assistant-written integration code
  gets the same adversarial review as any other code path that touches
  the consequence surface (see
  [ADVERSARIAL_TRANSFORMATION_SOP.md](ADVERSARIAL_TRANSFORMATION_SOP.md)).
  In particular, check that no route to the underlying effect exists
  outside the gate: a helper the assistant adds "for tests" that calls
  the effect directly is an ungoverned path, not a convenience.

## Using the gate directly

The prompt targets assistant-written integrations, but the gate is a
plain library surface for hand-written code too:

```python
from pulpo import GovernanceKernel, Intent, Policy
from pulpo.permit_gate import PermitGate, PermitRefused

kernel = GovernanceKernel(Policy(frozenset({"deploy.release"}), 1000), secret)
gate = PermitGate(kernel)  # presenter=..., proof_provider=... when bound

intent = Intent("agent:deployer", "deploy.release", "service:api", 10, "s1")
try:
    gate.run(intent, lambda: release("service:api", 10))
except PermitRefused as refused:
    log_refusal(refused.outcome, refused.reason)  # the audit chain holds the record
```

`pulpo/permit_gate.py`'s module docstring is the contract; its tests
are the executable evidence.
