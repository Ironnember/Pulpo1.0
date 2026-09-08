# Telegram ingress v0

Status: Proposed candidate on `feature/telegram-ingress-v0`

Bot identity: `@PulpoGovernanceBot`

Tracking issue: #208

## Purpose

Add Telegram as a bounded communication surface without allowing chat content,
Telegram identity, bot commands, the requester allowlist, or the bot token to
become Pulpo authority.

The governing invariant is:

`TELEGRAM_MESSAGE != AUTHORITY`

The integration extends the existing capability-stripped projection pattern. It
does not add a router, executor, ledger, policy engine, memory governor, or
second authority plane.

## Boundary

The v0 ingress accepts only Telegram private-message updates and retains only:

- a frozen `MCPReadSnapshot`;
- a non-empty frozen allowlist of positive numeric private-chat IDs.

It does not retain or receive a `GovernanceKernel`, `PulpoOrchestrator`,
canonical state backend, authority client, executor, policy object, trusted
clock, ledger, provider credential, or Telegram bot token.

The chat allowlist is a disclosure and request-intake boundary only. Matching an
allowlisted chat never upgrades Telegram identity or message content into Pulpo
approval, authority, policy, a directive, or a permit.

For an accepted private update, v0 also requires the numeric sender ID to equal
the numeric private-chat ID. A mismatch is ignored rather than guessed. This is
an application projection invariant, not a claim that a future webhook or
polling transport has authenticated Telegram; provider-transport authenticity
remains a separate deployment proof.

Updates from non-allowlisted private chats or sender/chat mismatches return an
internal `ignored` projection with `reply_allowed=false`. They expose no status,
evidence, proposal, or reply text.

Allowed command surface for an allowlisted private chat:

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

A valid allowlisted `/request` update produces `pulpo.telegram-request.v0` with:

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
trusted Pulpo and only after the private-chat disclosure gate passes. They cannot
follow later canonical mutations and therefore must be labeled frozen rather
than current live authority state.

## Outbound reply boundary

`reply_allowed=true` means only that the inbound projection considers a bounded
reply suitable for the allowlisted requester. It is not permission to call the
Telegram Bot API.

Any live outbound reply remains an external effect and should be composed with
the existing exact-object Telegram send/custody work rather than giving the
proposal worker a second direct `sendMessage` route.

## Secret and runtime boundary

The Telegram bot token is not part of this candidate and must not enter source
control, issue/PR text, logs, CI fixtures, generated evidence, or chat. A future
transport runtime must obtain it from a designated runtime secret mechanism,
fail closed if it is absent or invalid, and expose no fallback route.

The live runtime must also receive its private-chat allowlist from trusted local
or deployment configuration. Numeric identifiers may be discovered locally via
the separately recorded Telegram live-handoff experiment, but that experiment
is not silently imported into this candidate.

## Proof matrix in this candidate

1. Capability-bearing dependencies cannot be injected into the ingress.
2. The requester allowlist must be a non-empty immutable set of positive numeric
   private-chat IDs.
3. Non-allowlisted private chats are ignored without reply, evidence, or
   proposal projection.
4. Private sender/chat identity mismatch is ignored before command projection.
5. Matching the allowlist does not create authority; authority-shaped commands
   remain denied.
6. `/start` and `/help` remain read-only.
7. `/status` and `/evidence` use only frozen snapshot data.
8. `/request` creates only an ephemeral non-authoritative proposal.
9. Replaying an identical update is deterministic and non-mutating.
10. `/approve`, `/authorize`, `/grant`, and `/permit` are denied.
11. Plain text such as `I authorize ...` cannot create authority or a proposal.
12. Unknown commands, wrong bot mentions, malformed senders, and non-private
    chats fail closed without canonical mutation.
13. Snapshot reconstruction and proposal serialization retain the no-authority,
    no-governed-effect markers.

## Claim classification

### Verified only after exact-head executable evidence succeeds

- Telegram projection behavior described by the tests on that exact candidate
  head.

### Recorded

- `@PulpoGovernanceBot` is the operator-supplied bot identity;
- earlier same-day Telegram experiment objects exist for exact outbound message
  gating, custody transport, and secret-safe local live handoff.

### Proposed

- live Telegram transport using the private bot token;
- deployment/runtime secret and allowlist custody;
- live `/start`, `/status`, `/request`, `/evidence`, and `/help` delivery;
- trusted handoff of an ephemeral request into canonical Pulpo governance;
- composition of reply delivery through the already-proven exact-object/custody
  pattern rather than a parallel direct send route.

### Unknown

- whether the supplied Telegram bot is live and controlled by the intended
  operator until independently verified with the provider;
- bot token custody and rotation behavior;
- webhook or long-polling authentication/deployment behavior;
- Telegram outage/retry behavior in the deployed runtime;
- restart-safe reply deduplication;
- end-to-end live request and reply delivery;
- deployed route isolation from alternate Telegram consequence paths.

## Acceptance boundary

Do not call the Telegram integration governed merely because BotFather accepts
commands or the bot can reply. The governed claim requires executable negative
evidence that Telegram ingress retains no canonical write or authority
capability, that requester disclosure fails closed, and a separate live proof
that the transport cannot bypass Pulpo to reach a consequential executor or
provider.
