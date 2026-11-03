# Reciprocal External Review — Pulpo × Tether (SHAETHON AI)

Status date: 2026-11-03
Record type: external evidence record. **This document grants no authority.**
It records two independent, reciprocal black-box test efforts between two
unaffiliated builders of permit-gated execution systems, with the claims of
each side classified under this repository's claim discipline
(**Verified / Recorded / Inferred / Proposed / Unknown**).

## Summary

- **Direction 1 — Recorded.** SHAETHON AI (Michael Dill) independently tested
  the **Pulpo-Preview source release, commit `ec52708` (2026-10-31)**. This
  was **not** canonical `main` (`6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`),
  and no result in Direction 1 certifies canonical state.
- **Direction 2 — Verified (executed from this side).** Iron & Ember tested
  the live Tether pilot gate (`gate.shaethonai.com`, `tether-worker` 0.1.0)
  over HTTP under the gate owner's written rules of engagement. The gate's
  dispatch is a receipt-only stub; Direction 2 establishes authorization
  behavior, not custody of any real-world effect.
- Both directions: the tested system's published claims **held** under the
  other party's battery. Each direction carries one disclosed open item
  (Direction 1: environment-sensitive suite failures; Direction 2: one
  unreproduced concurrency anomaly). Neither open item is a reproduced break.

## Parties and affiliation disclosure

- Iron & Ember LLC (Arizona) — builder of Pulpo. Tester in Direction 2.
- SHAETHON AI (Michael Dill, Phoenix, AZ) — builder of Tether. Tester in
  Direction 1.
- The parties are **direct competitors** in permit-gated execution. The
  exchange was reciprocal, unpaid, and black-box in both directions
  (behavior and outcomes only; no internals were shared or inspected).
  This record is not a partnership, endorsement, or integration agreement,
  and neither party's results speak for the other party's system beyond the
  exact objects tested.

## Direction 1 — SHAETHON AI tested Pulpo-Preview (Recorded)

Object: Pulpo-Preview evaluation source release, commit `ec52708`,
released 2026-10-31. The tester verified the release archive's SHA-256
against the publisher's stated hash before running anything, in a clean
sandbox (Python 3.12.3). No Pulpo system, account, or file of Iron & Ember
was accessed or modified.

Suite reproduction: of the release's published 1,030 tests, 1,024 ran in
~76 seconds — 936 passed, 60 skipped, 4 failed, 24 errored. **No failure
sat in the permit, governance, or verifier suites.** The failures cluster
in environment-sensitive tests (root-refusal tests, WSL-desktop-specific
tests, a live-git-checkout requirement, root ignoring file-permission
bits). The tester classed the open item "environmental, not logical," and
accepted a second pass (non-root user, live git checkout), results to be
documented either way they land. That second pass is **outstanding** at
the date of this record.

Boundary battery: 31 adversarial probes against the governance kernel
through its public API, plus one direct audit-tamper check — **31 held,
0 broke**, covering:

- single use: baseline execution; sequential replay denied; 20 concurrent
  spends of one permit → exactly 1 executed, 19 denied; spent permit dead
  after kernel restart (SQLite); unspent permit survives restart, still
  single-use; two permits for one intent are distinct;
- exact-intent binding: resource, action, cost, principal, and session
  substitution each denied;
- forgery: fabricated permit denied; self-minted permit (attacker key)
  denied; body, nonce, and signature tampering each denied, genuine
  permit unaffected; cross-kernel permits rejected;
- denials issue nothing: unknown action, over-budget cost, incomplete
  intent, negative cost, and boolean-cost type confusion each denied with
  no permit issued;
- grants and expiry: action, budget, and resource grant overruns denied;
  unknown principal denied; expired permit rejected at spend time;
- audit: chain verified clean after every attack; direct tampering with
  one audit record detected.

Evidence held by: SHAETHON AI (tester's packet, SHA-256 in the artifact
index below; raw harness and logs to follow under the mutual test
standard, §Shared standard).

## Direction 2 — Iron & Ember tested the Tether gate (Verified from this side)

Object: live Tether pilot gate, `https://gate.shaethonai.com`
(`tether-worker` 0.1.0), tested 2026-11-03 under the owner's written
authorization and rules: authorization attacks only; no flooding or load
testing; concurrency bounded to the replay race (≤20 simultaneous).
Identities `austin-test` and `austin-test-2` were throwaway Ed25519 key
pairs registered through the gate's dev-mode onboarding. ~250 requests
total. The gate's dispatch is receipt-only ("demo dispatch: receipt only,
no side effects"), so `executed` below means *the gate authorized the
action* — the only claim Tether makes for this endpoint.

Control (run first, per the owner's specification): issue → 200;
execute once → 200 `executed:true`; same permit again → 403
`PermitReplayed: permit already consumed`; ledger verification →
`ledger.valid: true`, `anchored.valid: true`. The control behaved exactly
as specified, and the battery proceeded.

Battery results (~45 cases):

- **Replay:** sequential replay 403. Two permits for the same intent each
  executed exactly once. Concurrent replay reproduced across five fresh
  permits (100 spends): exactly 1 execution each. Refused attempts do not
  consume a permit (genuine execute succeeded after seven refusals).
- **Forgery:** fabricated permit 403; self-minted permit (caller key) 403;
  null permit 400.
- **Tampering (original signature kept):** target, authorized flag,
  expiry (+1 year), client id, and confidence alterations each 403;
  genuine permit unaffected afterward.
- **Target mutation at execute:** case, trailing space, double slash,
  dot-segment, trailing slash, Unicode homoglyph, action swap — all 403.
- **Expiry:** 2-second-TTL permit presented after expiry → 403.
- **Duplicate request_id:** second submission 409; two simultaneous
  submissions → one issued, one 409.
- **Governance edges:** confidence 0.70 issued (documented boundary);
  0.69 → 403; confidence absent (defaults to 0) → 403; confidence in
  `requirements` honored per the documented fallback; `risk_to_life:
  IMMEDIATE` → 403; `property_damage_risk` set → 403; `ttl_seconds` 0
  and 3601 → 400.
- **Issue-time identity:** request signed with a non-credential key 403;
  garbage signature 403; a caller name already registered under another
  key cannot be claimed with a new key (403).
- **Franken-permits:** cross-spliced signature and target/nonce hybrids
  both 403; genuine permits unaffected.
- **Route/shape:** wrong method 405; trailing slash 404; wrong
  Content-Type 400; empty body object 400; single 256 KB oversized body
  400; issue request missing its signature field 400.
- **Ledger:** verified after every phase — 265 → 512 records,
  `ledger.valid: true` and `anchored.valid: true` at every check,
  including after the full battery.

Disclosed anomaly (flag, not a break): in one early 20-way race, the
test harness counted 2 responses as `executed:true` (the remainder were
403 PermitReplayed; one was a transport failure). That race's full
response bodies were not retained, so the receipts could not be
inspected. Five identical re-runs with full capture produced exactly 1
execution each (100 spends). Under the standard both parties apply — an
unreproduced result is not a finding — this is recorded as an
**unreproduced anomaly**, with the gate's own ledger (which verified
clean) identified as the ground truth for the window (2026-11-03
~20:10 UTC, caller `austin-test-2`).

Observation (deployment surface): the CDN in front of the gate
(Cloudflare error 1010) refuses POSTs from non-browser user agents.
Machine callers must present as browsers to reach the gate at all.

Addendum — the Tether owner's self-disclosed flags (**Recorded**):
on 2026-11-03, after Direction 2 was run blind, SHAETHON AI disclosed in
writing the results of its own black-box re-attack of the live gate
(39 scenarios, the night of 2026-11-02: 36 held, 0 broke, 3 flags; ledger
valid and anchored afterward, 261 records / 257 anchored at that time).
The three flags, in the owner's classification:

1. **Non-finite confidence:** a permit request with `confidence` set to
   `1e999` (JSON-parses as infinity) returns a 500 server error instead of
   a clean refusal. No permit is issued; the gate stays closed. Owner's
   scoped fix: a finite-number check before governance reads the value.
   *Direction 2 mapping: not covered by the battery — and
   **independently confirmed** in a follow-up probe the same day
   (2026-11-03): the literal `1e999` request returned HTTP 500
   ("internal gate error"), no permit issued.*
2. **Governance enums are exact-match and case-sensitive:** the
   life-safety deny rule trips on `risk_to_life` exactly `IMMEDIATE`;
   sent lowercase (`immediate`), the rule does not trip and a permit was
   issued at high confidence. The signed-permit gate itself is unaffected.
   Owner's scoped fix: normalize before comparison; pin the exact enum in
   the client contract. *Direction 2 mapping: adjacent in the battery
   (exact value sent; documented denial observed) — and
   **independently confirmed end-to-end** in a follow-up probe the same
   day: the lowercase request was issued a permit (200) and the permit
   executed (200, receipt-only dispatch), while the paired exact-case
   control was refused (403, "Immediate risk to life: autonomous
   execution refused"). Casing alone flips the outcome.*
3. **Dev-mode onboarding name-claiming:** a first-seen caller can register
   a privileged name (the owner's test registered `admin` and was issued
   a permit). The name carries no authority; governance, exact-match
   targets, and the signature gate are unaffected. Owner's fix:
   production onboarding with pre-registered identities and reserved
   names, landing with the production build. *Direction 2 mapping:
   partially bounded — this battery verified the complement (a name
   already registered cannot be re-claimed under a different key, 403);
   fresh-name claiming was not tested.*

On Flag 2, Iron & Ember records a classification **dissent**: the
callers of a gate like this are agents, and agents produce casing
variance as ordinary input — a governance read that fails open on casing
is break-shaped even where the signature gate behind it holds. SHAETHON
AI keeps its flag classification (the signed-permit gate itself held)
and, on 2026-11-03, recorded this dissent alongside it; the fix follows
the dissent's prescription (normalize before comparison; pin the enum in
the client contract).

All three fixes are scoped by the owner and, at the date of this record,
deliberately **undeployed** — the gate Direction 2 attacked is the gate
as the owner tested it. The Direction 2 concurrency anomaly does not
correspond to any of the three flags and remains a separate open item.

## Shared standard

Both directions were run under the same evidentiary rules, which the
parties are formalizing as a mutual test document:

1. a control sequence, specified in advance, must behave exactly as
   documented before any battery result is interpreted;
2. every attempt is logged with request, response, and verdict;
3. a break requires exact reproduction steps — if it cannot be
   reproduced, it did not happen;
4. anomalies and environment artifacts are disclosed, not rounded away;
5. results are reported to the other party either way they land.

## What this record does not establish

- It does **not** establish independent reproduction of canonical Pulpo at
  `6b3caac`. Direction 1 tested a preview release. The formal reproduction
  package at `6b3caac` still has no independent executor.
- It does **not** establish production readiness, deployment custody, or
  real-world effect custody for either system. Direction 2's target
  dispatches receipts only; Direction 1 ran in a sandbox.
- It does **not** address Pulpo's known ceremony gap (admission gates on
  signature validity and bindings; no kernel-checked evidence of a human
  ceremony), which neither battery was designed to test.
- It does **not** inspect Tether's internals, revocation behavior between
  issuance and execution beyond the observable surface, or its single
  human-escalation path beyond documented escalation outcomes (403).
- Executable behavior at an exact commit outranks this document. This
  record is evidence about two bounded test events, not a certification.

## Required change record

1. **Invariant/failure addressed:** none in code. This record addresses an
   evidence gap: the absence of any independent, adversarial, third-party
   test record for Pulpo's governed boundary (and, reciprocally, for
   Tether's). It changes no kernel behavior.
2. **Authority:** gained, narrowed, or delegated — **none**. This document
   grants no authority to any party, agent, or process.
3. **Canonical state mutations introduced or exposed:** none. The change
   adds one documentation file. No interface, route, writer, ledger, or
   capability is added, and nothing in this record is an input the kernel
   reads.
4. **Exact success and adversarial evidence:** the two batteries above;
   artifacts indexed below by SHA-256.
5. **Boundary the evidence does not prove:** see "What this record does
   not establish."
6. **Claim classification:** Direction 1 — **Recorded** (an identified
   third party's documented attestation; underlying harness and logs not
   yet in this repository's custody). Direction 2 — **Verified** as to
   what was sent and received (executed by Iron & Ember under the repo
   owner's authorization, logs retained and hashed); the interpretation
   of Tether's internal state remains **Inferred** from black-box
   responses. The concurrency anomaly is **Recorded** as unreproduced.
7. **Legacy behavior source:** none used.
8. **Temporal replay:** no historical checkpoint is applicable to this
   external evidence record; no lesson is generalized from it beyond the
   exact objects tested. Recorded explicitly per the replay boundary.

## Artifact index (SHA-256)

- SHAETHON AI test packet (Dill → Irvan, 2026-11-03; PDF):
  `5b5d40bcedaad8efd34073ff592a9e5370f829d8efff3e86ae7fa56a67427462`
- Direction 2 battery log, first run:
  `11967cceb219a343a8679ebc3ebc84cbda16f763717b86c6d1a77097f16c7310`
- Direction 2 battery log, rerun (transport-inconclusive cases):
  `898807fec2a91a2d864bfd39d4fd2b2f96ad2c80ee348fefb4cd75e84df274c3`
- Direction 2 concurrency reproduction (5 rounds × 20):
  `2e82fb56f55d3aa2c17d68df157be3ea7d18254a11dec8b7be1a88970eba3e4d`
- Direction 2 franken-permit log:
  `de254102432739638473724ec73af53edf65c84b669214f07ae2d0d0c1930d0d`
- Direction 2 flag-confirmation probes (Flags 1–2, 2026-11-03):
  `592eb4762caf6ec0aace2934acafbf63c464b527e9760c3d4ef05837273b3a4c`

Raw logs are retained by Iron & Ember outside this repository (they
contain third-party test material) and are available to the signatories.

## Sign-off

By signing, each party attests that its own direction's results above are
accurately recorded, and consents to this record's publication in the
Ironnember/Pulpo1.0 repository. Neither signature certifies the other
party's system.

**Direction 2 tester / Pulpo publisher:**
Austin Irvan, Founder, Iron & Ember LLC
Sign-off: given to his agent in session, 2026-11-03 (record retained by Iron & Ember)

**Direction 1 tester / Tether publisher:**
Michael Dill, Founder, SHAETHON AI
Signature: ______________________________  Date: ____________
