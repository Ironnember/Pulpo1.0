# Architecture

Pulpo sits between intelligence and any governed effect: both canonical state
transitions and external side effects.

1. Normalize a complete intent: principal, session, action, resource, and declared cost.
2. Evaluate it against explicit policy. Unknown actions fail closed.
3. Require a verified external approval envelope for configured high-impact actions.
4. Bind an allowed intent to a signed, one-use permit.
5. Consume the permit only for that exact intent.
6. Append every decision and consumption attempt to a tamper-evident audit chain.
7. For consequential claims, obtain evidence sufficient to establish the relevant external state rather than relying only on executor self-report.
8. Reconcile authorized intent, execution evidence, observed consequence, and acceptance criteria.
9. Admit only appropriately reconciled outcomes into reusable outcome memory; learning may recommend authority changes but cannot grant them.

## Consequence closure

Pulpo separates authorization, execution, and consequence.

`VALID_AUTHORITY + VALID_PERMIT + EXECUTION_SUCCESS != VERIFIED_CONSEQUENCE`

Authority proves that an exact action was legitimately allowed under current
policy. A permit proves that bounded execution capability was issued. An executor
receipt may prove an invocation attempt or execution claim. None of those alone
establishes that the authorized external consequence actually occurred.

`EXECUTION_RECEIPT != VERIFIED_CONSEQUENCE`

For a consequential claim, Pulpo therefore keeps three facts distinct:

1. the **authority fact**: whether the exact action remained legitimately
   authorized under the applicable identity, directive, policy, budget, scope,
   expiry, revocation, and permit constraints;
2. the **execution fact**: what the execution surface attempted or reported; and
3. the **consequence fact**: what independently observable state exists after
   the action.

Reconciliation compares those facts. It must not infer consequence from prior
authorization and must not treat an executor's own success assertion as
independent consequence proof merely because that assertion is signed. The
required observer independence depends on the consequence and threat model. When
sufficient evidence is unavailable or ambiguous, preserve an unknown/evidence
failure state. When observed state disagrees with authorized or expected state,
preserve a reconciliation mismatch. Neither state is successful outcome memory.

See [consequence reconciliation position](CONSEQUENCE_RECONCILIATION_POSITION.md)
for the cross-project doctrine, market-convergence implications, and proof
priority.

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

`NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`

Capability possession matters independently of declared routes or methods. A
process that retains the kernel, orchestrator, executor, state backend, or
another canonical writer is not a read-only trust domain merely because its
public API omits write endpoints.

Ephemeral reasoning and proposal construction may remain outside the mutation
boundary. A projection is read-only only when repeated, malformed, replayed, and
substituted calls leave canonical state unchanged and the projection itself does
not retain a writer. Committing an ephemeral proposal into a durable target is a
separate canonical mutation and must occur through a governed path.

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

MCP follows the same rule. The trusted Pulpo side may freeze primitive policy and
audit metadata into an `MCPReadSnapshot`. The MCP projection and SDK server
accept only that exact capability-free snapshot and retain no kernel,
orchestrator, state backend, authority client, executor, policy object, clock, or
ledger reference. Intent hashes are computed by the kernel's deterministic static
hash function without a kernel instance. Proposal and evidence outputs are
explicitly marked `freshness=frozen`; they cannot masquerade as live-current
canonical state. A target hash exists only after a separately governed canonical
target commitment records the trusted lock time.

This V0 capability stripping proves the object/surface boundary, not hostile
same-process memory isolation or a live read-only IPC transport. A future live
MCP evidence path must prove freshness and read-only transport without returning
a canonical writer to the MCP host.

## Security boundary

This kernel governs authorization decisions and canonical governance state. It
is not an operating-system sandbox, network firewall, identity provider, or
billing system. Those claims require separate implementations and proof.
