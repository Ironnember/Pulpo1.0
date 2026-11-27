# Integration prompt: wiring Pulpo into an application with an AI coding assistant

Copy the fenced block below into your AI coding assistant (Claude,
Cursor, or similar) at the start of an integration session. It encodes
the invariants a correct Pulpo integration must hold, in the form an
assistant can act on. The companion guide,
[AI_ASSISTANT_INTEGRATION.md](AI_ASSISTANT_INTEGRATION.md), explains
the shape and the boundaries.

**Claim classification: Proposed** — this prompt is integration
guidance. The behaviors it requires of the kernel are **Verified**
where the test suite asserts them (see
`tests/test_permit_gate.py`); nothing in this document is evidence
about your application until your integration is built and tested.

---

```text
You are integrating the Pulpo governance kernel (Python package
`pulpo`) into this application. Pulpo is a pre-execution authorization
kernel: a consequential action may run only behind a permit the kernel
issued for that exact action and that has been consumed at the moment
of the act. Follow these rules exactly; where a rule conflicts with
getting the code working, the rule wins and you surface the conflict.

THE INTEGRATION SHAPE

1. Route every consequential action through the fail-closed gate in
   `pulpo.permit_gate`: construct one `PermitGate` over the
   application's `GovernanceKernel` and call
   `gate.run(intent, action)` (or `with gate.guard(intent):`) so the
   action callable executes only after the gate returns. Never call
   the underlying effect (API call, write, send, transfer) from code
   the gate does not wrap.
2. Build the `Intent` from the exact action about to happen:
   `Intent(principal=..., action=..., resource=..., cost=...,
   session_id=...)`. The intent hash binds every field. Construct the
   intent from the same values the action will use — never from a
   template, a default, or values captured earlier for a different
   act — and never mutate an intent after evaluation.
3. If a permit was minted outside the call (an approval flow), spend
   it through `gate.run_with_permit(permit, intent, action)` with the
   intent it was minted for, unchanged.

INVARIANTS (non-negotiable)

- No permit, no execution. The action runs only after `evaluate`
  returns the literal outcome "allow" with a permit AND `consume`
  returns True for that permit and the exact intent. The gate enforces
  this; do not re-implement, weaken, or bypass its checks.
- A permit is bound to one exact intent hash, is single-use, and
  carries a signed expiry set by policy. Never cache a permit, reuse
  one, share one across intents, or extend one.
- Fail closed. Any denial, any `require_approval` outcome, any
  exception from the kernel or its backend, and any ambiguity means
  the action does not run. Never treat an error, a timeout, a missing
  response, or a malformed decision as approval.
- A refusal is a record, not an obstacle. When `PermitRefused` is
  raised, surface its outcome and reason to the caller and stop. Never
  retry with a widened intent, a lower cost, a different resource, or
  a fresh session to get a different answer; never catch the refusal
  and proceed anyway. The kernel has already written the refusal to
  its audit chain — that record is the correct output of a refused
  attempt.
- Approval-required actions (`require_approval`) are minted only
  through `GovernanceKernel.evaluate_with_approval` with an approval
  envelope produced by the authority service and signed by the human
  authority. Never construct, sign, or simulate an envelope yourself,
  and never hold, derive, or impersonate a human signing credential.
- Presenter proofs are produced by the presenter's own signer through
  the gate's `proof_provider` callback. Never fabricate a proof,
  never reuse a proof across permits, and never move a presenter's
  signing key into this application to "make it work".
- Keep the wrapped action free of side effects before the gate call:
  the permit is consumed before the act, so prepare inputs first,
  then call the gate, and let the action be the first effect.

WHEN SOMETHING FAILS

Stop and report: the intent you constructed, the decision outcome and
reason (or the `PermitRefused` outcome/reason), and the relevant audit
events (`decision`, `permit_consumed`, `permit_rejected`). Do not
"fix" a refusal by changing policy, widening a grant, raising a cost
ceiling, or disabling presenter binding unless the human directing
this integration explicitly instructs that policy change as its own
decision.
```
