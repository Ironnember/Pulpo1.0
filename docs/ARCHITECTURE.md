# Architecture

Pulpo sits between an agent's intent and an external side effect.

1. Normalize a complete intent: principal, action, resource, and declared cost.
2. Evaluate it against explicit policy. Unknown actions fail closed.
3. Require human approval for configured high-impact actions.
4. Bind an allowed intent to a signed, one-use permit.
5. Consume the permit only for that exact intent.
6. Append every decision and consumption attempt to a tamper-evident audit chain.

Optional `AgentGrant` records further restrict named agent principals by action,
resource namespace, and per-intent cost. They are evaluated inside step 2, so
role specialization cannot bypass the canonical policy or create another router.

The commerce layer remains subordinate to the kernel. It evaluates a quote,
binds the complete request and quote to an exact order hash, reserves the quoted
amount, and submits that hash through the normal intent and one-use permit path.
Payment, delivery, acceptance, and value remain distinct evidence states.

Approval-gated actions may use an `ApprovalVerifier` configured on the trusted
kernel. Its signed envelope binds the exact intent and policy plus authority,
session, principal, nonce, and expiry. The verifier produces permit authority
through the same kernel; it is not a second router or audit ledger.

The kernel is deliberately small and deterministic. Adapters, APIs, persistence, model routing, and host isolation belong outside this trusted core and must earn inclusion through tests and evidence.

## Security boundary

This kernel governs authorization decisions. It is not an operating-system sandbox, network firewall, identity provider, or billing system. Those claims require separate implementations and proof.
