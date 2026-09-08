# Telegram Custody Transport V0

Status: **PROPOSED** until exact-head executable evidence says otherwise.

## Purpose

Extend the governed Telegram message projection into a custody-only provider
adapter without expanding canonical Pulpo authority or placing a Telegram bot
token in the intelligence/model-facing process.

This is a stacked experiment on top of `telegram-governed-bot-v0`.

## Provider boundary

V0 is frozen to:

- provider origin: `https://api.telegram.org`;
- method: `sendMessage` only;
- one bot identity pinned by `PULPO_TELEGRAM_EXPECTED_BOT_ID`;
- one numeric chat ID pinned by `PULPO_TELEGRAM_ALLOWED_CHAT_ID`;
- token supplied only as `PULPO_TELEGRAM_BOT_TOKEN` inside custody;
- plain text only through `pulpo.telegram.TelegramOutboundMessage`;
- five-second network timeout;
- minimized provider claim with no token or message text.

The Bot API URL is not configurable by environment variable. A model or worker
cannot redirect custody to an arbitrary provider endpoint by changing runtime
input.

## Token identity pin

Telegram bot tokens carry a numeric bot identity before the `:` separator. V0
requires that identity to equal the separately configured expected bot ID before
the transport can be constructed.

This validates configuration consistency. It does **not** independently prove
that the token is valid, current, or held exclusively by this custody process.

## Destination pin

The custody transport accepts exactly one non-zero numeric chat ID. Username
chat references such as `@channel` are rejected in this proof because Telegram
may return a numeric chat ID for a username-addressed request, complicating the
exact destination comparison. A later separately governed transition can add a
reviewed canonicalization rule if needed.

## Provider claim

After a successful provider response, V0 returns only:

- provider name;
- method;
- Telegram message ID;
- numeric chat ID;
- provider timestamp;
- Pulpo message hash;
- `claim_class=provider_claim`.

The echoed message body is intentionally not projected into evidence.

`provider_claim` is **not** independent observation and does not establish
reconciled external reality.

## Required success case

For the pinned numeric chat and expected bot identity, a valid outbound message
must produce one HTTPS POST to the hard-coded Telegram Bot API `sendMessage`
method and return a minimized provider claim.

## Required negative cases

1. Missing token -> configuration fails closed.
2. Token bot identity differs from expected bot ID -> configuration fails.
3. Non-numeric destination -> configuration or transport fails.
4. Message destination differs from pinned chat -> zero network calls.
5. Username destination -> zero network calls.
6. Telegram HTTP/network failure -> sanitized error with no token.
7. Telegram `ok=false` -> fail closed.
8. Provider response reports a different chat -> fail closed.
9. Invalid or oversized provider response -> fail closed.
10. Transport repr and returned provider claim contain no token.
11. Returned provider claim contains no message text.

## Authority effect

**None.**

This transport does not issue permits, activate directives, sign approvals,
change policy, or create a new authority source. It is an execution-side
capability that remains unusable without upstream governed release.

No deployment policy is expanded by this experiment.

## Canonical state mutation

None is introduced by the transport itself. Permit and governance state remain
owned by the existing Pulpo kernel/state path in the parent proof.

## Privacy boundary

The adapter sends only the exact outbound `chat_id` and plain `text` necessary
for Telegram `sendMessage`. It does not implement inbound webhook ingestion or
forward Telegram user content to an LLM.

## What a PASS proves

A PASS proves the reviewed custody adapter's configuration, destination pin,
request construction, error sanitization, response minimization, and fail-closed
provider-response behavior using a mocked network boundary at the exact commit.

## What a PASS does not prove

A PASS does **not** prove:

- possession of a valid real Telegram bot token;
- exclusive token custody against a hostile worker;
- a real Telegram API transmission;
- network route isolation from the intelligence process;
- webhook authenticity;
- Telegram-side independent observation or reconciliation;
- host/cloud compromise resistance;
- production deployment security;
- privacy compliance for inbound AI processing.

## Next proof

The next consequential proof is a dedicated test bot and private test chat where:

`hostile worker -> Pulpo -> custody -> api.telegram.org`

and, in the same executable run:

- custody can reach Telegram with the privately supplied test token;
- worker has no token;
- worker has no direct Telegram provider route;
- no permit causes zero `sendMessage` transmissions;
- exact valid permit causes exactly one transmission;
- replay/substitution causes zero additional transmissions;
- Telegram's provider claim is recorded as a claim, not self-certified external
  truth.

Do not place the bot token in chat, repository contents, fixtures, CI logs, or
model-visible environment state.
