# Governed Operations Bot v0

## Purpose

Provide one Telegram-facing worker for three bounded workflows without creating a second authority plane, executor, ledger, or memory system:

1. payment reconciliation;
2. scheduling proposals;
3. lead-procurement proposals.

The bot is intentionally capability-free. It may compare supplied records and construct exact proposals. It does not move money, issue refunds, create calendar events, purchase lead data, send outreach, mutate canonical Pulpo state, hold an authority credential, or mint/consume permits.

## Commands

### Payment reconciliation

`/reconcile <JSON>`

Expected object:

```json
{
  "ledger": [
    {"reference": "inv-123", "amount": "125.00", "currency": "USD"}
  ],
  "processor": [
    {"reference": "inv-123", "amount": "125.00", "currency": "USD"}
  ]
}
```

The bot matches only exact unique references and surfaces amount mismatch, currency mismatch, missing records, and duplicate references. It never guesses, edits a ledger, refunds, charges, or settles a payment.

### Scheduling

`/schedule <ISO-8601 start>|<minutes>|<title>|<comma-separated attendees>`

Example:

```text
/schedule 2026-09-10T14:00:00-07:00|30|CIO discovery|buyer@example.com
```

The result is an immutable proposal hash with `authority_effect=none` and `execution_effect=none`. A separate governed transition must later bind the exact object to live calendar authority before any event is written.

### Lead procurement

`/leads <company profile>|<buyer role>|<geography>|<limit>`

Example:

```text
/leads US companies deploying autonomous agents|CIO|United States|10
```

The result is a research-only proposal. Purchase and outreach are explicitly prohibited in the proposal payload. A later adapter may retrieve candidate data only through a separately governed capability.

## Telegram transport

`pulpo.telegram_ops_bot` uses Telegram Bot API long polling and requires:

- `PULPO_TELEGRAM_BOT_TOKEN`
- `PULPO_TELEGRAM_ALLOWED_CHAT_IDS`

The allowlist is mandatory. Messages from any other chat are ignored. The token is runtime-only and must not be committed to the repository.

## Consequence boundary

The bot's outputs are proposal/evidence objects, not permission. To cross a consequence boundary, the exact proposal must be transformed by a trusted service into the canonical Pulpo lifecycle:

`Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation`

Provider-specific live adapters should therefore remain narrow execution surfaces. Recommended initial bindings:

- payment source: read-only transaction/ledger exports for reconciliation;
- calendar: Google Calendar create/update only after exact-object authorization;
- leads: approved search/data provider with a hard result and spend bound, with outreach governed separately.

## Proof status

- **Verified locally in isolated module tests:** deterministic reconciliation, amount drift detection, duplicate-reference denial, timezone requirement, deterministic proposal hashing, proposal-only scheduling, no-purchase/no-outreach lead proposals, unknown-command denial, mandatory Telegram chat allowlist.
- **Recorded in branch:** implementation and tests under `feature/governed-ops-bot-v0`.
- **Unknown until CI runs on the branch:** full repository regression status.
- **Not proven:** live Telegram delivery, payment-provider access, calendar execution, lead-provider execution, outreach, or external consequence containment.
