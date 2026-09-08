# Telegram Live Handoff V0

Status: **PREPARED, NOT EXECUTED AGAINST TELEGRAM**.

## Purpose

Provide a secret-safe local operator path for the first real Telegram
`sendMessage` consequence without placing the bot token in ChatGPT, repository
contents, command-line arguments, environment variables, CI, or printed
evidence.

This is a stacked experiment on top of:

1. `telegram-governed-bot-v0` — exact object and one-use permit gate; and
2. `telegram-custody-transport-v0` — custody-only Telegram provider adapter.

## Local secret boundary

`scripts/telegram_live_handoff_v0.py` obtains the bot token using Python
`getpass` from the local terminal. The token is never accepted through a CLI
flag. It is passed directly into the custody transport in process memory and is
not printed into the result artifact.

Do **not** paste a Telegram bot token into chat, an issue, a PR comment, a shell
command, or a repository file.

## Exact effect

The handoff authorizes only one low-risk plain-text `sendMessage` to one numeric
private test chat.

Before the provider call, the script displays:

- expected bot ID;
- pinned chat ID;
- exact message text;
- Pulpo message hash;
- Pulpo intent hash;
- maximum provider transmissions authorized by the permit: `1`.

The operator must type a confirmation string containing the frozen message hash
prefix. A mismatch causes zero provider calls.

## Governance behavior

The script constructs one narrow local test policy:

- principal: `agent:telegram-live-probe-v0`;
- action: `telegram_send_message`;
- resource prefix pinned to the exact numeric chat;
- cost ceiling: `0`.

The existing `GovernanceKernel` issues a one-use permit for the exact message.
The existing `GovernedTelegramSender` consumes that permit before the custody
transport can call Telegram.

This is **not independent authority**. The local operator confirmation is the
explicit authorization for this one low-risk test effect. Do not generalize the
result to higher-consequence Telegram capabilities.

## Unknown-outcome rule

If the provider/network call errors after permit consumption, the script reports:

`EXTERNAL_REALITY_UNKNOWN`

It does not automatically retry. A timeout or broken response does not prove
that Telegram failed to commit the message.

This preserves the Pulpo distinction:

`AUTHORIZED_TRANSMISSION_ATTEMPT != VERIFIED_EXTERNAL_REALITY`

## Restart/replay check

After the first send attempt, the script closes the SQLite kernel state, reopens
it in a new `GovernanceKernel`, and attempts to consume the same permit again.
The expected result is:

`replay_succeeded_after_state_reopen = false`

It also verifies the reopened audit chain.

No second Telegram provider call is made for this replay check.

## Sanitized evidence

The local script prints JSON containing only:

- provider status;
- minimized provider claim, if received;
- sanitized provider error, if any;
- exact message and intent hashes;
- principal/session references;
- replay-after-reopen result;
- audit validity;
- automatic-retry flag;
- explicit statement that no token was projected;
- explicit statement that independent observation is still false.

## What a successful local run can establish

If the operator receives `PROVIDER_CLAIM_RECEIVED`, sees the Telegram message in
the pinned private test chat, and the replay-after-reopen field is false, the
run provides evidence that one real external Telegram effect was attempted
through the Pulpo permit gate and that the same permit did not survive for
reuse.

The Telegram API response itself remains a provider claim. Visual/manual
observation by the operator is useful evidence but is not yet the stronger
independent observer architecture Pulpo ultimately targets.

## What remains unproved even after one successful run

- hostile intelligence cannot reach `api.telegram.org` directly;
- hostile intelligence cannot obtain the bot token by another host path;
- webhook ingress is authentic and replay-safe;
- a model cannot bypass custody in the deployed topology;
- independent Telegram observation/reconciliation;
- host/cloud compromise resistance;
- inbound user-message privacy and third-party AI processing compliance;
- production bot readiness.

## Operator prerequisite

Use a dedicated Telegram **test bot** and a private test chat. The user should
obtain the bot token locally from Telegram/BotFather and keep it out of ChatGPT.
The numeric bot ID and private chat ID are identifiers, not bearer secrets, but
they should still be handled with ordinary privacy hygiene.

## Admission posture

Preparing and even successfully executing this handoff does not authorize merge
of the stacked experiments. External evidence must be reconciled and reviewed
separately.
