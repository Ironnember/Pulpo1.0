# Architecture

Pulpo sits between intelligence and any governed effect: both canonical state
transitions and external side effects.

1. Normalize a complete intent: principal, session, action, resource, and declared cost.
2. Evaluate it against explicit policy. Unknown actions fail closed.
3. Require a verified external approval envelope for configured high-impact actions.
4. Bind an allowed intent to a signed, one-use permit.
5. Consume the permit only for that exact intent.
6. Append every decision and consumption attempt to a tamper-evident audit chain.

## Governed effects

Pulpo distinguishes authority expansion from governed effect.

`NO_PERMIT != NO_GOVERNED_EFFECT`

A call may mint no permit and perform no external execution while still changing
what the system can do next. Target locks, budget reservations, directive state,
reconciliation state, canonical audit events, and other durable canonical writes
can change the future consequence surface.

`CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`

Any interface that can mutate canonical Pulpo state therefore possesses a
governed capability. Such a capability may leave `authority_effect=none`, but it
must not be exposed to intelligence, transport, UI, plugin, MCP, or distribution
surfaces merely because the operation is called a proposal, memory update,
metadata write, or audit event.

Ephemeral reasoning and proposal construction may remain outside the mutation
boundary. A projection is read-only only when repeated, malformed, replayed, and
substituted calls leave canonical state unchanged. Committing an ephemeral
proposal into a durable target is a separate canonical mutation and must occur
through a governed path.

`KernelState` is the storage seam beneath those same steps. The default backend
keeps the original ephemeral behavior; `SQLiteKernelState` atomically persists
approval replay guards, issued and spent permits, and audit records. Reopening
that state does not create another decision path or ledger: `GovernanceKernel`
remains the only authority and its audit chain remains the canonical evidence.

Optional `AgentGrant` records further restrict named agent principals by action,
resource namespace, and per-intent cost. They are evaluated inside step 2, so
role specialization cannot bypass the canonical policy or create another router.

The commerce layer remains subordinate to the kernel. It evaluates a quote,
binds the complete request and quote to an exact order hash, reserves the quoted
amount, and submits that hash through the normal intent and one-use permit path.
Payment, delivery, acceptance, and value remain distinct evidence states.
`SQLiteBudgetAccount` can preserve the bounded pilot's reservation, attempted,
reconciled, and spent state transactionally across restart and concurrent
workers. It is operational state behind the same commerce path, not a second
router, audit ledger, payment rail, or source of authority.

Approval-gated actions require an `ApprovalVerifier` configured on the trusted
kernel. `AuthorityTrust` binds the permitted verifier, public key fingerprint,
algorithm, deployment, and maximum approval lifetime into policy. Its signed v2
envelope binds that trust to the exact intent and policy plus authority,
verifier, key, session, principal, nonce, issue time, and expiry. Session comes
from the intent and time is evaluated with the kernel's bootstrapped clock;
neither is supplied by the evaluation caller. The verifier produces permit
authority through the same kernel; it is not a signer, second router, or audit
ledger.

The selected deployment boundary places WebAuthn human authentication and the
approval signer in an external trust domain. The worker may request an approval
and poll for the resulting envelope; it cannot sign, enroll, rotate, recover,
revoke, or alter trust. The external service's security state supports the
authority boundary but does not replace Pulpo policy, permits, decisions, or
canonical governance evidence. See
[the authority service contract](AUTHORITY_SERVICE_CONTRACT.md).

The kernel is deliberately small and deterministic. Adapters, APIs, model
routing, and host isolation belong outside this trusted core and must earn
inclusion through tests and evidence. The SQLite backend proves local restart
semantics, not trusted hosting or independent storage authority.

PulpoGit is a read-only evidence projection beside that kernel, not inside its
authority path. It observes local repository identity, source refs, committed
proposal history, and worktree path status; binds the projection to one
deterministic hash; and explicitly records that no tests ran. It cannot fetch,
push, merge, grant authority, issue permits, or append audit state. A PulpoGit
report may be attached to an existing governed work receipt only after the
normal kernel path authorizes that consequence.

MCP follows the same rule. It may construct an exact ephemeral proposal and read
canonical evidence metadata, but it may not lock a target or append canonical
state. A target hash exists only after a separately governed canonical target
commitment records the trusted lock time.

## Security boundary

This kernel governs authorization decisions and canonical governance state. It
is not an operating-system sandbox, network firewall, identity provider, or
billing system. Those claims require separate implementations and proof.
