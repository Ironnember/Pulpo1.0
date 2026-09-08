# Telegram ingress v0

Status: Proposed candidate on `feature/telegram-ingress-v0`

Bot identity: `@PulpoGovernanceBot`

Tracking issue: #208

## Purpose

Add Telegram as a bounded communication surface without allowing chat content,
Telegram identity, bot commands, or the bot token to become Pulpo authority.

The governing invariant is:

`TELEGRAM_MESSAGE != AUTHORITY`

The integration extends the existing capability-stripped projection pattern. It
does not add a router, executor, ledger, policy engine, memory governor, or
second authority plane.

## Boundary

The v0 ingress accepts only Telegram private-message updates and retains only a
frozen `MCPReadSnapshot`. It does not retain or receive a `GovernanceKernel`,
`PulpoOrchestrator`, canonical state backend, authority client, executor, policy
object, trusted clock, ledger, provider credential, or Telegram bot token.

Allowed command surface:

- `/start`
- `/status`
- `/request <text>`
- `/evidence`
- `/help`

Explicitly denied authority-shaped commands:

- `/approve`
- `/authorize`
- `/grant`
- `/permit`

Ordinary chat text also does not create a proposal. A request must be explicit
through `/request`, and the returned request object remains ephemeral and
non-authoritative.

## Request semantics

A `/request` update produces `pulpo.telegram-request.v0` with:

- Telegram update, chat, and sender identifiers;
- the request text;
- a deterministic SHA-256 request identifier;
- the frozen policy hash as informational context;
- `requires_governance=true`;
- `canonical_state_mutation=false`;
- `governed_effect=none`;
- `authority_effect=none`.

The request object contains no approval, directive, permit, target lock, or
canonical write. A later trusted component may choose to present the proposal to
the existing Pulpo governance path, but that handoff is intentionally outside
this ingress and requires its own governed transition.

## Replay behavior

Replaying the same Telegram update yields the same deterministic request ID and
still produces no canonical mutation. A changed update ID produces a different
request ID. This v0 property makes update replay incapable of duplicating a
consequential Pulpo effect because the ingress owns no consequence capability.

The current candidate does not claim durable Telegram transport deduplication or
exactly-once reply delivery across process restart.

## Evidence/status semantics

`/status` and `/evidence` report only the frozen primitive snapshot supplied by
trusted Pulpo. They cannot follow later canonical mutations and therefore must
be labeled frozen rather than current live authority state.

## Secret boundary

The Telegram bot token is not part of this candidate and must not enter source
control, issue/PR text, logs, CI fixtures, generated evidence, or chat. A future
transport runtime must obtain it from a designated runtime secret mechanism,
fail closed if it is absent or invalid, and expose no fallback route.

## Proof matrix in this candidate

1. Capability-bearing dependencies cannot be injected into the ingress.
2. `/start` and `/help` remain read-only.
3. `/status` and `/evidence` use only frozen snapshot data.
4. `/request` creates only an ephemeral non-authoritative proposal.
5. Replaying an identical update is deterministic and non-mutating.
6. `/approve`, `/authorize`, `/grant`, and `/permit` are denied.
7. Plain text such as `I authorize ...` cannot create authority or a proposal.
8. Unknown commands, wrong bot mentions, malformed senders, and non-private
   chats fail closed without canonical mutation.
9. Snapshot reconstruction and proposal serialization retain the no-authority,
   no-governed-effect markers.

## Claim classification

### Verified by exact-head tests only after CI succeeds

- Telegram projection behavior described by the executable tests on that exact
  branch head.

### Recorded

- `@PulpoGovernanceBot` is the operator-supplied bot identity.

### Proposed

- live Telegram transport using the private bot token;
- deployment/runtime secret custody;
- live `/start`, `/status`, `/request`, `/evidence`, and `/help` delivery;
- trusted handoff of an ephemeral request into canonical Pulpo governance.

### Unknown

- whether the supplied Telegram bot is live and controlled by the intended
  operator until independently verified with the provider;
- bot token custody and rotation behavior;
- webhook or long-polling deployment behavior;
- Telegram outage/retry behavior in the deployed runtime;
- restart-safe reply deduplication;
- end-to-end live request delivery.

## Acceptance boundary

Do not call the Telegram integration governed merely because BotFather accepts
commands or the bot can reply. The governed claim requires executable negative
evidence that Telegram retains no canonical write or authority capability and a
separate live proof that the transport cannot bypass Pulpo to reach a
consequential executor/provider.
