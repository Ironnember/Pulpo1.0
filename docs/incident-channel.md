# Incident-reporting + near-miss channel

WIC *Frontier AI Safety and Governance 2026*, indicator 3.2 (risk incident
reporting and near-miss sharing): only about a quarter of the 24 countries
assessed have stable arrangements here, and Pulpo had none — it recorded the
unknown an incident report would cite, but had no reporting channel and no
near-miss log. This module (`pulpo/incident_channel.py`) is that channel's
first half: the record, derived from outcomes Pulpo already records.

It reports to nobody by itself. There is no external reporting, no sharing,
no notification, no network call. A human — or a later, separately governed
step — reads the frozen report and decides what leaves the machine.

## Definitions

- **Incident**: a consequential effect that was executed, or may have been
  executed, whose outcome is unknown or wrong.
- **Near-miss**: a governed action refused or caught before any consequential
  effect, OR an unknown that later resolved cleanly. No effect happened, or
  the effect is verified fine.

Both are derived, read-only projections of the canonical audit chain and the
custody store. There is **no lifecycle**: no open/close states, no triage, no
acknowledgement. Whether a record needs a lifecycle is an open question (see
below), not a decision this module makes.

## Feed table

| Source | Source detail | Kind | Resolution | Anchor | Integrity |
|---|---|---|---|---|---|
| canonical audit | `purchase_consequence_unknown` | incident | unresolved | audit record hash | hash chain (`verify_audit`) |
| canonical audit | `purchase_consequence_unknown` + custody attempt `reconciled_success` | near-miss | resolved_cleanly | audit record hash + custody authorization hash | hash chain + HMAC receipt |
| canonical audit | `purchase_consequence_unknown` + custody attempt `reconciled_failure` | incident | confirmed_wrong | audit record hash + custody authorization hash | hash chain + HMAC receipt |
| canonical audit | `purchase_consequence_unknown` + custody attempt in any other state | incident | unresolved | audit record hash + custody authorization hash | hash chain + HMAC receipt |
| canonical audit | `purchase_revalidation_failed` | near-miss | not_applicable | audit record hash | hash chain |
| canonical audit | `permit_rejected` | near-miss | not_applicable | audit record hash | hash chain |
| canonical audit | `decision` with outcome `deny` | near-miss | not_applicable | audit record hash | hash chain |
| canonical audit | `approval_rejected` | near-miss | not_applicable | audit record hash | hash chain |
| custody store | attempt `unresolved` | incident | unresolved | attempt authorization hash | HMAC-signed transition receipts |
| custody store | attempt `reconciliation_required` | incident | unresolved | attempt authorization hash | HMAC-signed transition receipts |
| custody store | attempt `attempt_authorized` / `attempt_claimed` / `request_transmitted` (latest state, no later state) | incident | unresolved | attempt authorization hash | HMAC-signed transition receipts |
| custody store | attempt `reconciled_failure` | incident | confirmed_wrong | attempt authorization hash | HMAC-signed transition receipts |
| custody store | attempt `reconciled_success` | — (no record) | — | — | resolver only |

Rules:

- One record per source audit event (`incident:<audit-record-hash>` or
  `near-miss:<audit-record-hash>`); one record per custody attempt
  (`incident:custody:<attempt_id>`, the attempt id already being a hash).
- Merge: when a custody attempt has a `purchase_consequence_unknown` audit
  event carrying its `custody_attempt_id`, exactly one record is emitted,
  anchored on the audit event, with resolution taken from the attempt's
  latest state. An attempt with no such audit event gets its own
  custody-anchored record. A `reconciled_success` attempt with no audit
  event referencing it emits nothing.
- Records sort by (`first_seen_ns`, `record_id`). There is no cap on
  records: incidents are rare, and silently dropping one would be worse
  than a large report.
- Only hashes cross into a record as anchors — never authority material.
  The permit itself never appears; only its hash, exactly as the canonical
  audit already records it.
- `freeze_incident_report` is read-only: it appends nothing to the audit
  and writes nothing to the custody store. With `custody=None` the feed is
  audit-only; custody resolution of an unknown needs the store passed in.

## Integrity levels

A record's anchor is only as strong as its source, and every record carries
its `source` so a reader can tell which anchor backs it:

- **Audit-derived** records are anchored by the audit record hash and the
  hash chain. The report carries `audit_valid` from `kernel.verify_audit()`
  and derives regardless, flagging a broken chain rather than hiding it.
- **Custody-derived** records are anchored by the attempt authorization hash
  and the HMAC-signed transition receipts. They are **not** hash-chained to
  the canonical audit. Do not present custody-derived records as
  audit-backed.

Custody transitions never reach the canonical audit in production: the
`TrustedDomainExecutor` takes an `evidence_projector` callback that is only
wired in tests. The custody feed therefore reads the custody store directly
(`SQLiteGovernanceCustody.attempts()`, a read-only SELECT-only enumeration),
and the channel says so on every record via its `source` field.

## Custody time is a bound, not a timestamp

The custody store records **no per-attempt timestamp**.
`created_epoch` / `updated_epoch` are head-epoch counters (1, 2, 3, ...),
not seconds, so there is no epoch-to-nanosecond conversion to apply;
converting one would fabricate a time. A custody-sourced record instead
carries the store head's `custody_time_ns` at freeze time as both
`first_seen_ns` and `last_seen_ns`: the time of the store's latest
transition, an upper bound on the attempt's last transition, not the
attempt's own time. A merged record keeps the audit timestamp as
`first_seen_ns` and takes `last_seen_ns` as the later of the audit
timestamp and the custody head time.

## What the channel does not do

- No authorization, no permits, no keys. Freezing a report grants nothing.
- No lifecycle / open-close states (open question, below).
- No external reporting or sharing, no network calls, no notification.
- No mismatch feed beyond custody `reconciled_failure`: `reconcile_effects`
  (`pulpo/effect_reconcile.py`) runs only from scripts/proofs/tests, never
  from the live path, and its results are never persisted. There is no
  durable mismatch feed to derive from. If effect-reconciliation results
  become durable, they belong here as a third feed.
- No CLI subcommand and no Control Center page yet. Evidence export today
  is library API, not a CLI subcommand; this channel matches that shape
  (library API only).
- No custody-transition projection into the audit. Until the
  evidence-projector wiring exists, custody state is visible here only
  because the channel reads the store directly.

## Two consequences to know about

1. **The live path never reconciles custody attempts.** Nothing on the live
   path calls `reconcile_observed` (or cancels an attempt), so a coordinator
   purchase leaves its custody attempt in `attempt_authorized` even when the
   purchase succeeded. The channel reports such an attempt as an unresolved
   incident — correctly, by its own definition (an authorized attempt with
   no terminal state has an unknown outcome), but noisily: every
   unreconciled coordinator attempt shows up until reconciliation (or
   cancellation) is wired into the trusted path. Likewise, a
   `purchase_revalidation_failed` refusal leaves its custody attempt
   dangling: the merge rule consumes an attempt only for a
   `purchase_consequence_unknown` event, so a refused purchase yields two
   records — the near-miss and the unresolved custody incident.
2. **Unknown custody states fail closed toward reporting.** An attempt in a
   state the channel does not recognise is reported as an unresolved
   incident, never silently dropped.

## Porting note

This channel was ported to canonical Pulpo1.0 from Pulpo-Preview PR #119
(merge commit `4b7a2cf`). The channel itself depends only on the canonical
audit columns, the custody store (including the `attempts()` read-only
enumeration ported with it), and the frozen-file snapshot boundary
(`_publish_snapshot` / `read_snapshot_document`, factored out of canonical's
existing MCP export/load code) — no schema change on either side. Canonical
adaptations, each disclosed in the port PR: the frozen report's `source_id`
falls back to the module's process-scoped hash when the SQLite connection
carries no `activity_id` (canonical has no `ObservedConnection`); one ported
test constructs its kernel without Preview's signed policy envelope
(Preview PR #117, a separate sequenced port); and this note replaces the
Preview-side porting note, which described the trip in the other direction.

## Open questions

- Human report path: who reads the frozen report, and what (if anything)
  is sent where? Nothing in this module answers that.
- Lifecycle: do records need open/close states, triage, acknowledgement?
- CLI subcommand (`pulpo incidents`?) and/or a Control Center Evidence
  page for the report.
- Evidence-projector wiring so custody transitions reach the canonical
  audit (then the custody feed could be audit-derived instead of
  store-derived).
- Reconciliation / cancellation wiring on the live path, so successful or
  refused coordinator attempts reach a terminal custody state instead of
  lingering as unresolved incidents.
