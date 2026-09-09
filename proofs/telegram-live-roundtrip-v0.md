# Telegram Live Roundtrip V0

Status: **PREPARED CANDIDATE — NOT YET EXECUTED AGAINST TELEGRAM**

Bot identity: `@PulpoGovernanceBot`

Parent candidate: `feature/telegram-ingress-v0` / PR #209

Reference experiments re-proved in this branch: PR #186 exact-object send gate and PR #187 custody transport. Their existence is evidence, not admission authority.

## Purpose

Prove the smallest real end-to-end Telegram interaction without allowing Telegram chat content, bot identity, or transport credentials to become Pulpo authority.

V0 handles exactly one pending private `/start` update and at most one plain-text reply.

The intended path is:

`Telegram /start -> capability-stripped ingress -> bounded reply projection -> local operator release -> canonical one-use permit -> custody-only sendMessage -> minimized provider claim`

The governing inbound invariant remains:

`TELEGRAM_MESSAGE != AUTHORITY`

The governing outbound invariant remains:

`PULPO_AWARE_BOT != PULPO_GOVERNED_BOT`

## Why this is one-shot

A persistent polling bot would introduce additional restart, update-offset, retry, outage, credential-custody, and duplicate-delivery obligations. Those are not silently bundled into the first live proof.

This ceremony exits after one selected `/start` update and one possible reply.

## Secret boundary

`scripts/telegram_live_roundtrip_v0.py` reads the real bot token only through a hidden local `getpass` prompt.

The token is not accepted through:

- command-line arguments;
- environment variables;
- repository files;
- GitHub Actions or CI secrets;
- printed evidence;
- chat.

The script uses the token locally for `getMe`, `getUpdates`, and construction of the custody-side `TelegramBotApiTransport`. The model-facing ingress never receives the token or the transport object.

## Provider identity and requester selection

Before any reply can be planned:

1. `getMe` must return a positive numeric bot ID;
2. Telegram must report `is_bot=true`;
3. the exact username must be `PulpoGovernanceBot`;
4. `getUpdates` is filtered locally to pending `message` updates;
5. the candidate update must be a private chat;
6. numeric `from.id` must equal numeric `chat.id`;
7. the text must be exactly `/start` or `/start@PulpoGovernanceBot`;
8. the operator selects the numeric private chat locally.

Candidate selection prints only numeric chat/update identifiers. It does not print Telegram names, usernames, captions, or arbitrary message text.

These checks are disclosure and intake constraints. They do not make Telegram identity an authority credential.

## Inbound governance projection

The selected raw update is handed to `TelegramIngress` with:

- one frozen `MCPReadSnapshot`;
- one frozen allowlisted private chat ID.

The live ceremony requires the result to remain:

- `outcome=read`;
- `command=start`;
- `reply_allowed=true`;
- `authority_effect=none`;
- `canonical_state_mutation=false`.

Any other projection stops before provider execution.

## Outbound consequence boundary

The exact reply text is frozen into `TelegramOutboundMessage` and SHA-256 bound to the selected numeric private chat.

Before provider execution, the operator sees:

- bot username and numeric bot ID;
- numeric private chat ID;
- source Telegram update ID;
- ingress outcome and authority effect;
- exact reply message hash;
- exact reply text;
- maximum provider transmissions for this ceremony: `1`.

The operator must type a confirmation string bound to the reply message hash. A mismatch causes zero provider writes.

After local confirmation, the existing `GovernanceKernel` may issue one permit under a narrow ephemeral test policy for:

- principal `agent:telegram-live-roundtrip-v0`;
- action `telegram_send_message`;
- resource prefix pinned to the selected numeric chat;
- cost `0`.

The exact permit is consumed before the custody transport may call Telegram. Text, chat, principal, session, or permit substitution cannot reuse the exact authorization object.

This local operator ceremony is **not independent authority infrastructure** and must not be generalized to higher-consequence capabilities.

## Custody-side Telegram transport

The custody transport is restricted to:

- official `https://api.telegram.org` origin;
- the bot identity derived from the token prefix and independently pinned by `getMe`;
- one numeric destination chat;
- `sendMessage` only;
- plain text only;
- bounded response size and timeout;
- minimized returned provider claim;
- sanitized provider failures.

The transport cannot issue approvals, directives, grants, or permits.

## Retry and external-reality rule

The permit is consumed before the provider call.

If the Telegram network/provider outcome is ambiguous, the ceremony reports:

`EXTERNAL_REALITY_UNKNOWN`

and performs **no automatic retry**.

After the first attempt, SQLite state is reopened and the same permit is consumed again only as a replay check. Expected result:

`replay_succeeded_after_state_reopen=false`

The replay check makes no second Telegram provider call.

## Evidence semantics

The printed evidence intentionally excludes the token and arbitrary inbound Telegram content. It records:

- source update/chat identifiers;
- ingress outcome and no-authority/no-mutation markers;
- exact outbound message and intent hashes;
- minimized provider claim or sanitized provider error;
- replay-after-restart result;
- audit validity;
- automatic retry flag;
- local authority scope;
- explicit `independent_observation=false`.

A Telegram `sendMessage` success response is a **provider claim**, not independent observation or final reconciliation.

## What a successful live run would prove

A successful run would establish that one real pending `/start` update for `@PulpoGovernanceBot` can:

1. cross a capability-stripped inbound projection without creating authority;
2. produce one exact bounded reply object;
3. require explicit local operator release;
4. cross the existing one-use Pulpo permit gate;
5. reach a custody-only real Telegram `sendMessage` provider call;
6. remain replay-denied after state reopen;
7. produce sanitized evidence without projecting the bot token.

## What remains unproven

Even after a successful run, this proof does **not** establish:

- persistent bot deployment;
- webhook authenticity;
- durable polling offset ownership;
- exactly-once reply delivery across process restart;
- Telegram outage/retry orchestration;
- exclusive token custody against host compromise;
- hostile-worker network isolation to Telegram;
- trusted handoff of `/request` proposals into canonical production governance;
- independent Telegram-side observation or reconciliation;
- production authority infrastructure for outbound replies;
- privacy policy for forwarding arbitrary Telegram content to an LLM;
- multi-user or group-chat operation.

Those remain separate proof boundaries.

## Admission posture

**Draft / experiment.** Passing CI or even one successful live roundtrip is evidence, not merge authority. The parent ingress candidate and this composed proof must be separately reviewed and admitted according to Pulpo governance.
