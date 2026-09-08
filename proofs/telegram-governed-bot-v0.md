# Telegram Governed Bot V0

Status: **PROPOSED** until exact-head CI evidence says otherwise.

## Purpose

Prove the smallest Pulpo-native Telegram consequence boundary without adding a
second router, authority service, policy engine, executor, memory system, or
ledger.

V0 governs one effect only:

`telegram.sendMessage(chat_id, plain_text)`

The Telegram bot token and network transport remain outside the model-facing
projection. The intelligence may propose an outbound message. The existing
Pulpo `GovernanceKernel` determines whether the exact intent receives a permit.
A transport may be invoked only after that exact one-use permit is consumed.

## Frozen object

The governed consequence object is:

- schema: `pulpo.telegram-send-message.v0`
- exact `chat_id`
- exact plain `text`

Its canonical SHA-256 hash is embedded in the Pulpo resource namespace:

`telegram:sendMessage:<chat_id>:<message_hash>`

The resulting Pulpo intent is bound to:

- principal
- action `telegram_send_message`
- exact resource above
- cost `0`
- session ID

Any change to text, chat, principal, or session changes the intent and therefore
cannot consume the original permit.

## Required success case

1. Construct an exact outbound message.
2. Evaluate its intent through the canonical kernel.
3. Receive an `allow` decision and one-use permit under an explicit Telegram
   agent grant.
4. Consume the permit for that exact message.
5. Invoke the execution-side transport exactly once.

## Required adversarial cases

1. Reuse the same permit -> no second transport call.
2. Substitute message text -> no transport call.
3. Substitute destination chat -> no transport call.
4. Substitute principal -> no transport call.
5. Substitute session -> no transport call.
6. Unknown principal -> no permit and no transport call.
7. Missing permit -> no transport call.
8. Empty/oversized/malformed message -> rejected before consequence release.
9. Transport failure after permit consumption -> spent permit remains spent;
   retry requires a new governed decision rather than resurrecting authority.

## Authority effect

This experiment introduces **no new authority source**.

The Telegram adapter cannot sign approvals, expand policy, create directives,
or grant itself additional capability. It delegates authorization to the
existing `GovernanceKernel`.

The new policy action/resource namespace is only a test-declared capability
until separately admitted into a deployment policy.

## Canonical state mutations

The only canonical mutations exercised by V0 are the existing kernel's normal
permit issuance/decision audit records and permit consumption/rejection records.
No Telegram-specific state backend or evidence ledger is introduced.

## Privacy boundary

V0 does not forward inbound Telegram user content to an LLM and does not store
Telegram user data. Any later inbound-message/LLM integration must define and
prove its data-minimization and disclosure policy separately before deployment.

## What a PASS proves

A PASS verifies, at the tested commit, that the model-facing Telegram message
projection cannot release the test transport unless the exact Pulpo permit for
that exact message, chat, principal, and session is successfully consumed, and
that replay/substitution attempts do not cause additional transport calls.

## What a PASS does not prove

A PASS does **not** prove:

- possession or custody isolation of a real Telegram bot token;
- real Telegram Bot API transmission;
- webhook authenticity or ingress isolation;
- model-process network containment;
- host or cloud isolation;
- production deployment security;
- Telegram-side observation or reconciliation;
- privacy compliance for forwarding Telegram content to third-party AI models;
- directive-memory integration;
- moderation, payments, media, keyboards, rich messages, or administrative bot
  capabilities.

Those remain separate proof boundaries.

## Next proof after admission decision

If this V0 exact-object gate passes review, the next smallest proof is a runtime
custody topology in which:

`hostile intelligence -> Pulpo -> Telegram custody -> Telegram Bot API`

and the hostile intelligence has neither the Telegram bot token nor a direct
network-capable provider path. Use a dedicated test bot and a private test chat;
do not begin with a production/community bot.
