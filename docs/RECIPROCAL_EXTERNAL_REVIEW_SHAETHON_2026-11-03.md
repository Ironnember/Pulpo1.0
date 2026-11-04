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
  other party's battery, and neither direction produced a reproduced
  break. Open items, stated in full: Direction 1 — environment-sensitive
  suite failures, with the tester's second pass outstanding. Direction 2 —
  one unreproduced concurrency anomaly (open on both sides), and three
  flags the gate owner disclosed from his own testing, with fixes scoped
  but deliberately undeployed at the date of this record (two of the three
  independently confirmed from this side; the publishing side's dissent on
  Flag 2's classification is recorded in the Direction 2 addendum).

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
**unreproduced anomaly** (window 2026-11-03 ~20:10 UTC, caller
`austin-test-2`). SHAETHON AI checked the ledger from its side on
2026-11-03 (517 records, valid and anchored) and reports that the
pilot's public verification proves the chain's integrity but does not
enumerate per-permit receipts, so that window cannot be replayed from
the gate side either. The anomaly therefore stands exactly as filed —
open, not a break — with a joint supervised concurrency soak agreed as
part of the patched-gate re-run.

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

**Adversarial transformation review** (required by AGENTS.md for
material evidence records and consequential near-misses; analytical
only, grants no authority):

- **Flip** (swap tester and tested): had Iron & Ember authored
  Direction 1's account of its own system, it would be self-attestation
  and classified accordingly. It is not: Direction 1 is a competitor's
  independent attestation — which is why it is Recorded rather than
  dismissed, and why it is not Verified either, its harness and logs not
  yet being in this repository's custody.
- **Reverse** (read the sequence backward): sign-off followed the
  completed record; the flag disclosures followed the blind battery they
  describe; no step in the exchange depended on a later step having gone
  well. A reversed reading surfaces no retrofitted step.
- **Invert** (assume the record is wrong): the most plausible error
  sites are (i) the anomaly being a genuine double execution
  misclassified as open — bounded by five clean reproduction rounds and
  by the gate ledger's integrity check, and kept open rather than closed
  for exactly this reason; and (ii) Direction 1's numbers being
  inaccurate — bounded by their Recorded class and the outstanding
  harness transfer.
- **Inside-Out** (read as a diligence outsider): the Summary and the
  non-claims section bound every result to its exact tested object; no
  sentence in this record claims production readiness, canonical-main
  verification, or custody of real-world effects.
- **Darken** (worst case): if the anomaly reproduces on the patched
  gate, Direction 2 gains a confirmed break and this record is amended,
  not rewritten — the anomaly's disclosure here is what makes that
  amendment cheap and credible.
- **Lighten** (best case): every claim is exactly as strong as its class
  states, and the two directions' open items close by the agreed re-runs
  without amendment to any result recorded here.
- **Amplify** (scale the record's reach): if this document were the
  public face of both systems, its strongest sentence — that each
  system's published claims held under a competitor's battery — remains
  true only with its scoping attached (a Preview release; a receipt-only
  pilot gate). That scoping sits in the Summary's first two bullets, not
  in a footnote.
- **Negate** (what the record is not): not a certification, not a
  partnership, not evidence about canonical main, not evidence about
  ceremony, and not a claim about either system's production deployment.
  Stated again in the non-claims section.

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
- Direction 2 anomaly packet (request shape, ledger positions,
  retention gaps, reproduction data; prepared for SHAETHON AI
  2026-11-03):
  `16dcad84dffa0e99eeb47386ab0ad1243997229e6e73d49618365558a6e1d1d9`

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
Sign-off: given by email, 2026-11-03 — "The record reads true to me —
both directions, the limits, the anomaly, the flags, and the Preview
scoping on my side's evidence. That's my sign-off; put it in as-is."

---

## Addendum (2026-11-03, evening) — Anomaly reconciliation: closed, harness-side

The disclosed anomaly above was reconciled by SHAETHON AI from the ledger
side and the reconciliation was checked by Iron & Ember against its own
retained files. The original disclosure stands unchanged as the record of
what was filed; this addendum records what the reconciliation established.

**Verdict (SHAETHON AI, by email 2026-11-03):** the gate executed that
permit exactly once. The anomaly resolves to the test-harness and
write-up layer on the Iron & Ember side. It is closed — not a break, and
not a gate defect.

**Verified** (Iron & Ember, against its own retained artifacts):

- The battery-1 B1 entry in `battery_log.json` (2026-11-03T20:02:43Z)
  records twenty responses: nineteen HTTP 403 and one null, with a stored
  result of "executed count = 0". No retained log records a count of 2.
- The battery-1 verdict rule (`run_battery.py`) counted a win only on
  HTTP 200 with `executed: true` and marked the race BROKEN whenever the
  count was not exactly 1 — so a count of 0 produced the BROKEN verdict.
- The rerun B1 entry (`battery_log_rerun.json`, full capture) records
  nineteen 403s and one 200, `executed=1`, verdict HELD; the rerun script
  (`run_battery2.py`) classifies a zero count as `SAFE-SIDE-ANOMALY`.
- The "2 responses counted as executed" figure and the ~20:10 UTC window
  appear only in the return report's and the anomaly packet's prose;
  the prose conflated the battery-1 race (20:02:43 UTC, window
  265 → 347) with the rerun window (347 → 420).
- Five full-capture reproduction rounds each produced exactly 1
  execution (100 spends), as originally recorded.

**Inferred:** nineteen `PermitReplayed` refusals are reachable only after
the permit's nonce has been claimed once, inside the gate; the race's
one null response is consistent with the executed 200 having been lost
in transport (connection resets were observed and recorded during that
session), so the counter saw zero wins for a race the gate held. This
reading is the only one consistent with all retained responses.

**Recorded** (SHAETHON AI's reconciliation, from its email): rebuilding
the gate's accounting rules from its source and running Iron & Ember's
recorded checkpoints against them matched exactly in four windows
(rerun, race reproduction, franken-permit, flag probes — records and
anchor counts both). Stated limits from the same email: the pilot
surface does not enumerate ledger records one by one, so the
reconciliation rests on the gate code path, the logged data, and the
counts; the battery-1 window also carries a two-record residual in
baseline bookkeeping around the pre-battery control, which touches no
test segment (the B1 segment is 22 records under any reading).

**Consequence:** the anomaly line in the Direction 2 record is amended
from "unreproduced anomaly (open)" to **closed — harness-side counting
and write-up error**. The joint supervised concurrency soak remains
agreed as part of the patched-gate phase; it is no longer load-bearing
for this anomaly. A full SHAETHON memo with the window-by-window table
exists and has been requested for the record.

**Change record (this addendum):** documentation only; no authority
gained, narrowed, or exercised; no canonical state mutation beyond this
file; no legacy behavior source used; no temporal replay applies to an
external-evidence addendum.

**Sign-off for this addendum:**

- Austin Irvan, Founder, Iron & Ember LLC — given in session, 2026-11-03.
- Michael Dill, Founder, SHAETHON AI — given by email, 2026-11-03:
  "The addendum reads true to me — the verdict, what each side
  verified, the Inferred grade on the transport reading, and the
  limits as stated. That is my sign-off; record it in the document
  and merge PR #339 as-is." His full reconciliation memo
  (window-by-window table) was delivered with the same email and is
  held in Iron & Ember custody alongside the battery files
  (SHA-256 ddd77a10e5b39988ad138edfffc4512ce51911bd254a987c4d2ebee955b20ef3).

**Adversarial transformation review of this closure** (required by
AGENTS.md for consequential near-misses; the review at lines 280–297
assessed keeping the anomaly open and cannot cover the opposite
decision; analytical only, grants no authority):

- **Flip** (swap tester and tested): had SHAETHON reported a count of
  2 against Pulpo in prose while its own logs showed 0, Iron & Ember
  would require exactly this reconciliation before accepting closure —
  the standard applied here is the one we would demand.
- **Reverse** (read the evidence backward): start from the ledger
  counts and predict the harness logs — four windows match exactly,
  and the B1 segment is 22 records under any reading of the residual;
  the reconstruction predicts the retained data rather than merely
  accommodating it.
- **Invert** (assume the opposite verdict): a genuine double execution
  would require a second execution record and anchor movement the
  ledger does not show, plus a second 200 in logs that hold none.
  The inversion needs evidence that does not exist in either side's
  custody.
- **Inside-Out** (each side audits the other): Iron & Ember verified
  SHAETHON's claims about Iron & Ember's files from the files
  themselves; SHAETHON derived its expectations from its gate source,
  not from Iron & Ember's summary. Neither side graded its own paper.
- **Darken** (worst case): if a double execution someday reproduces
  under the supervised soak, this closure is falsified by design — the
  original disclosure text is preserved above, unedited, precisely so
  a future break can be recorded against it.
- **Lighten** (best case): the gate's replay refusal being reachable
  only after a single claim is a design property worth the record;
  the closure documents it without upgrading it to a proof about any
  other permit or window.
- **Amplify** (scale the claim): nothing here generalizes beyond the
  one permit, one race, one window. The closure claims exactly that
  event and no class of events.
- **Negate** (remove each support in turn): remove the ledger
  reconstruction and the retained logs still show a count of 0 with a
  clean rerun; remove the logs and the ledger counts still admit only
  one execution. The verdict does not rest on a single leg.

---

## Addendum 2026-11-04 — canonical pass recorded; evidence packages published

This addendum records two events that postdate the signed record above.
The original text and the 2026-11-03 anomaly addendum are unedited,
including the scope sentence in the original body stating that Direction 1
did not establish independent reproduction of canonical Pulpo at
`6b3caac`. That sentence was true when written. This addendum records
what happened next.

### The canonical pass (2026-11-03, reported 22:27 Phoenix)

After the reciprocal batteries above, SHAETHON AI executed the
commissioned independent reproduction of canonical Pulpo at
`6b3caacbc28a7b40ebf5ea6295bc8058804de6e3` under Iron & Ember's written
protocol (`INDEPENDENT_REPRODUCTION.md`), on an independent host, and
reported the same night:

- Fresh clone, detached checkout; HEAD `6b3caac` and tree
  `df6310dc0b6eaec50b7870832dd8cb379096f778` verified before and after
  the run. Iron & Ember independently confirmed that tree hash matches
  its own tree at `6b3caac`.
- Suite: 422 tests ran, OK, 4 skipped — the 3 Ed25519 authority tests
  skipped in the bare environment were run separately with
  `cryptography==50.0.1` per protocol, 3/3 OK; the macOS Seatbelt test
  reported as untested on Linux, not passed.
- Gladiator: PASS_WITH_BOUNDARIES — 138 test executions, 10,600
  scheduled mixed operations, no failures; `source_unchanged` and
  `clean_tree_after` both true.
- Incident proof: PASS, 14/14 checks, remediation count exactly 1.
- Stated scope (tester's own limits): the service and container CI
  suites were not run; no separate SHAETHON adversarial battery was
  layered on canonical main, so the 31-probe battery remains a
  Direction 1 (Preview) artifact. The tester offered a separate
  probes-on-main pass as its own artifact; that offer stands open.

**Claim classification:** the canonical pass is **Recorded** — an
identified competitor's attestation, executed under a written protocol,
with the tree-hash cross-check above performed by Iron & Ember itself.

### The evidence packages (received and published 2026-11-04)

On 2026-11-03 the tester offered his full evidence package "as-is,"
to publish alongside this review. Iron & Ember accepted on 2026-11-04.
The package arrived the same morning in two parts, sender-stated
SHA-256 hashes recomputed and matched by Iron & Ember on receipt:

- `pulpo-evidence-package-2026-11-03.zip` —
  `cd420b6eef8f310d905bdeb2a58a8851eff2e289bea8a8e65112783ff15f0229`
  Bit-identical to the package taken into custody on 2026-11-03.
- `canonical-pass-evidence-2026-11-03.zip` —
  `24c1bacce85ac5131ebcff92a9db380896f74ba5b7433da760b0336c32107e14`
  The canonical pass's memo, raw logs, tournament results, and incident
  database.

Both are published unedited in `docs/evidence/shaethon-2026-11-03/`
with a custody and verification index. Iron & Ember's log-level checks
on receipt are recorded there. Publication establishes custody,
integrity, and internal consistency of the artifacts; it does not
convert the tester's attestation into Iron & Ember's own observation,
and it changes no claim class in this record except this one:

- The canonical pass's standing moves from *reported by email* to
  *reported with raw artifacts in public custody, hash-verified against
  the sender's stated hashes, and spot-checked against the reported
  results*. It remains **Recorded**, for the reason the original record
  gives for Direction 1: it is a competitor's independent attestation,
  which is what makes it worth having — and worth grading as exactly
  what it is.

**Change record for this addendum:** invariant — a desirable observed
state is not proof that the transition producing it was legitimate; this
addendum therefore records provenance (offer, acceptance, receipt,
hashes) before results. Authority change: none. Canonical state
mutations: none (docs and evidence files only). Evidence: the two
packages in `docs/evidence/shaethon-2026-11-03/` and the tester's
2026-11-03 and 2026-11-04 emails. Boundary the evidence does not cross:
Iron & Ember did not witness either run; the supervised concurrency
soak remains outstanding and is the named falsifier for the anomaly
closure above.
