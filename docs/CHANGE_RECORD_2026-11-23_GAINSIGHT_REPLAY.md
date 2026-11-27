# Change record — Gainsight / Salesforce connected-app replay

**Date:** 2026-11-23
**Artifact:** `tests/test_gainsight_incident_scenario.py` (scenario test
only; no kernel change)
**Base state:** canonical `main` @
`2726e59e0aed6f3ba9c6c1108712fbab26bc1f36` (suite 1036 OK, skipped=13 in
CI; reproduced locally in this VM as 1036 OK, skipped=25 — the skip delta
is environmental and identical at base and at head)
**Correction (2026-11-23, on review):** the incident chronology in
the original version of this record and of the scenario docstring
was a year off — the incident is November 2025, not November
2026 — and the investigation was described as ongoing when it had
concluded (Gainsight, January 2026). Both files are corrected; the
original token-leak vector remains Unknown. The replay substance
is unchanged.

## 1. Invariant or failure mode addressed

The Gainsight / Salesforce connected-app abuse, publicized 2025-11-20
(Salesforce security advisory; Gainsight customer FAQ). Attackers abused
the trusted connection between Gainsight-published applications and
customers' Salesforce instances — a standing, broadly scoped,
long-lived connected-app/OAuth trust path, the same playbook as the
August 2025 Salesloft Drift campaign — to reach customer data far
outside the app's intended function. Salesforce states there is no
indication the issue resulted from any vulnerability in the Salesforce
platform; the activity appears related to the app's external
connection. Salesforce revoked the access and refresh tokens for all
Gainsight applications, removed them from AppExchange, and disabled
the connections on 2025-11-20; affected customers were notified
2025-11-21; Gainsight engaged Mandiant. Per Salesforce's indicators of
compromise shared through the FAQ, the first unauthorized access dates
to 2025-11-08. Google Threat Intelligence (Austin Larsen, via
reporting) puts potentially affected Salesforce instances at more than
200. The Scattered Lapsus$ Hunters collective claimed responsibility
(via DataBreaches.net reporting). How the app's connection was abused
at the root — the original token-leak vector — is still not
public (Unknown). The investigation itself has concluded
(Gainsight's January 2026 technical explanation).

The failure is a trust-scope failure, not an authentication failure:
the connection was genuine, its holder reached the platform
legitimately, and the platform answered because the connection existed
— not because the specific act was authorized. A connected app's
OAuth grant binds neither the exact act (which object, which
operation, which org) nor the presenter who must prove, per use, that
the use is the app's own governed act rather than a token holder's.

Pulpo's invariant under test is unchanged and pre-existing:
**`NO_PERMIT != NO_GOVERNED_EFFECT`** (AGENTS.md), together with the
exact-intent binding and the presenter binding (Phase 3, Item 4B): a
permit is bound to the exact intent hash and to a registered
presenter, is single-use, and no other artifact — not an approval for
a different act, not a genuine permit in a different presenter's
hands, not a standing connection token — confers the act.

## 2. Authority gained, narrowed, or unchanged

**Unchanged.** This change adds a test module and this record only. No
kernel code, policy, state, audit format, or public API changes. No new
authority is created, delegated, or widened; no existing authority is
narrowed.

The scenario models the app as holding exactly one accountable
authorization: one exact read — the customer-success sync for its own
org, the declared integration function — issued through a verified
approval envelope and bound to the app as presenter. Every incident
act is attempted against that single authorization (or against no
authorization at all), and none executes.

## 3. Canonical state mutations and governed capability boundary

None in production code. Within the test process only:

- A `GovernanceKernel` (in-memory state) issues one permit for the
  sync intent, bound to presenter `app:gainsight-connected-app`; the
  harness's `ConsequenceLedger` records a governed external
  consequence only on a successful `consume`.
- Denied attempts append audit records to the in-memory audit chain,
  per the audit-growth classification in §4. No capability accrues
  from them.
- A second kernel over the same in-memory state, with the app removed
  from its presenter registry, models the platform's revocation of
  the app (step 9). The state is shared deliberately: the permit
  token and audit history are unchanged; only the registry differs,
  isolating the registry as the control that ends the app's spend
  authority.

The governed capability boundary exercised is the kernel's public
surface only: `evaluate`, `evaluate_with_approval` (with `presenter`),
`consume` (with `presenter` / `presenter_proof`), `verify_audit`, the
`kernel.audit` read path, and the incident channel's
`freeze_incident_report`. The scenario reproduces neither Salesforce,
nor Gainsight, nor any connected app, customer data, or network
behavior.

## 4. Exact success evidence and adversarial evidence

Scenario module: 11 tests, all passing at the branch head and,
identically, at the base checkpoint (§8).

Success evidence (the governed path works):

- Positive control: the presenter-bound sync executes exactly once —
  the app spends its own permit, with its own valid proof, for the
  exact approved intent; a second presentation of the same permit is
  denied (single-use).
- Step 9's contrast: after the revocation refusal, the same unspent
  permit still spends on the kernel where the app remains registered —
  the refusal was the registry change, not token death.

Adversarial evidence (every incident route denied):

- **Step 1 — connection is not a permit.** A bare `evaluate` of the
  cases bulk export returns `require_approval` /
  `approval_required` and mints nothing; the standing connection
  token string presented as a permit is rejected
  (`permit_signature_invalid`). Consequence ledger empty.
- **Step 2 — out-of-intent acts under the genuine permit.** Bulk
  exports of cases, of accounts, and of every object; the declared
  sync aimed at another customer's org (cross-org reach — one
  vendor-side compromise reaching every installed org); and the sync
  with its scope widened to all objects. All five denied
  (`permit_intent_mismatch`), presented by the app itself with valid
  proofs, so the intent binding is the only control that can deny
  them. The permit is not burned: the exact sync still executes
  afterwards.
- **Step 3 — stolen permit token.** The genuine token presented (a)
  with no presenter, (b) by a different registered presenter with
  that presenter's own valid proof, and (c) under the app's identity
  with a forged proof — denied
  (`permit_presenter_proof_required`, `permit_presenter_mismatch`,
  `permit_presenter_mismatch`). Possession of the token string is
  not possession of the act. The permit remains spendable by the app.
- **Step 4 — spent permit replay.** The consumed permit re-presented
  for the same sync and for an export: both denied. A consumed
  permit is not a refresh token; the standing connection's
  reusability is the property single-use consumption removes.
- **Step 5 — forged and mismatched approvals.** An envelope for the
  export signed with an unauthorized key is denied
  (`approval_signature_invalid`); the genuine sync envelope presented
  for the export intent is denied (`approval_intent_mismatch`). The
  genuine pair still admits afterwards.
- **Step 6 — reconciliation.** The vendor's activity claim (the sync
  as the only consequence, silence about the rest) reconciles
  `ok=False` with `undisclosed_attempts` equal to exactly the five
  out-of-intent intent hashes; a claim promoting the cases export to
  a consequence yields exactly that hash as
  `unbacked_consequences`; a claim disclosing every attempt and
  exactly the consumed consequence reconciles `ok=True`.
  Reconciliation verifies the audit chain first and fails closed.
- **Step 7 — incident channel.** Over the full compressed campaign
  (every out-of-intent act on every route, both presenter attacks,
  both envelope attempts, both spent-permit replays, plus the one
  legitimate execution): 14 `permit_rejected`, 2
  `approval_rejected`, 2 denied decisions, 5 `require_approval`
  decisions in the canonical audit; the derived report carries
  exactly 18 near-miss records (14 + 2 + 2), 0 incidents, all kind
  `near_miss` / classification `Recorded`, and freezing the report
  appends nothing to the audit.
- **Step 8 — later session.** On a fresh kernel in a later session,
  the standing connection token mints and spends exactly nothing; it
  was never a permit and its survival in the holder's hands changes
  nothing about what it is.
- **Step 9 — platform revocation.** A kernel over the same state
  whose presenter registry no longer contains the app refuses the
  genuine, unspent permit with a well-formed app proof
  (`permit_presenter_unverifiable`) — the model of Salesforce
  revoking the apps and removing them from AppExchange. The token
  did not expire and was not spent; the platform's act is what ended
  it.
- **Negative control.** With consume unguarded at both layers (a
  kernel double skipping token authentication, intent binding, and
  presenter binding, over a state double ignoring the store's
  binding), the bulk export **executes** under the sync permit — the
  incident's own shape. The denials above therefore come from the
  real consume path's binding checks, not from a harness that denies
  by construction. The same attempt against the real kernel is
  denied in the same test.

Audit-growth classification (per AGENTS.md): a denied attempt is not
"no state changed." A bare `evaluate` returning `require_approval`
appends one decision record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope evaluation
appends two records (an `approval_rejected` record and a denied
decision record). That growth is itself a governed effect — evidence
production — bounded at two records per attempt, append-only,
`authority_effect=none`, and it does not accumulate capability. It is
classified separately from governed external consequences (the
permitted consume) throughout the module.

Full suite at branch head (local, this VM): **1047 tests, OK
(skipped=25)** — baseline 1036 plus the 11 scenario tests. The
skipped=25 vs CI's skipped=13 delta is environmental and identical at
base and head (§8).

## 5. Boundary the evidence does not prove

- This proves kernel behavior at this commit for these action
  classes (Verified, executable evidence). It proves nothing about
  any deployed platform or integration that does not route its reads
  through this kernel. A connection that answers first and checks
  the act never (or checks it against nothing) is governed by
  nothing here. A control not on the execution path governs
  nothing.
- The incident-channel boundary, stated exactly as it holds: the
  channel derives near-misses from `permit_rejected` events,
  `approval_rejected` events, and denied decisions. A bare
  `evaluate` returning `require_approval` is audit-recorded but is
  **not** derived as a near-miss (the open surfacing gap tracked in
  issue #375). Step 7 pins both halves of that statement; this
  replay does not smooth it over and does not change it.
- Reconciliation here is test-level, against the public
  `kernel.audit` read path, as in the filename-deception and Mythos
  scenarios. The shipped reconcilers reconcile filesystem effects
  and custody-domain outcomes, not a vendor-claimed history against
  the kernel audit trail. No shipped reconciliation API is claimed.
- Presenter binding is modeled with the repository's HMAC test
  presenters. The scenario proves the kernel's binding and refusal
  semantics; it does not prove any production presenter's key
  custody, device attestation, or enrollment ceremony.
- The incident facts are as publicized by Salesforce and Gainsight
  on 2025-11-20 (Recorded). The root cause of how the app's
  connection was abused is still not public (Unknown); the replay
  exercises the trust-scope failure both sources describe, not a
  reconstructed exploit chain. No claim is made about what Pulpo
  would have done inside any real Salesforce org — no such
  deployment exists in evidence.

## 6. Claim classification

- Kernel behavior in the scenario (denials, single-use, presenter
  binding, revocation-by-registry, reconciliation outcomes,
  incident-channel counts): **Verified** — executable evidence, this
  module, at the stated commits.
- Incident facts (revocation, AppExchange removal, notification
  dates, Mandiant engagement, first-access date, affected-instance
  estimate, claim of responsibility): **Recorded** — Salesforce
  security advisory and Gainsight customer FAQ, 2025-11-20, and
  reporting citing Google Threat Intelligence and DataBreaches.net.
- Root cause of the connection's abuse: **Unknown** — the
  investigation has concluded (Gainsight, January 2026) without
  the original token-leak vector becoming public.
- Any application of this evidence to a real Salesforce/Gainsight
  deployment: **Proposed** at most — no such deployment is in
  evidence.

## 7. Legacy or prior behavior relied on as source

- The scenario reuses the canonical kernel API and the repository's
  existing test support verbatim in kind: `tests/authority_support.py`
  (`HmacTestVerifier`, `signed_envelope`, `trust_for`) and
  `tests/presenter_support.py` (`HmacPresenterVerifier`, `proof_for`),
  and the incident channel (`pulpo.incident_channel`) as shipped at
  the base commit.
- Presenter binding (token v3, Phase 3 Item 4B) is pre-existing
  kernel behavior at the base commit; this replay is its first
  incident-scenario exercise. The presenter gate runs after token
  authentication and intent-digest comparison and before the store,
  so a presenter refusal never burns the permit — relied on in steps
  3 and 9 and asserted by their outcomes.
- The reconciliation compared-sets definition (consequences =
  `permit_consumed` intent hashes; attempts = `permit_rejected`
  intent hashes plus `require_approval` / `deny` decision intent
  hashes; fail-closed on `verify_audit()`) is the test-level pattern
  established by `tests/test_filename_deception_incident_scenario.py`
  and carried through the Mythos and Entra scenarios; it is
  duplicated per module by house design, not imported.
- The negative-control doubles (`_IntentBlindState`,
  `_UnguardedConsumeKernel`) follow the pattern established by the
  Entra scenario at the base commit.
- No legacy or Preview behavior is relied on. Pulpo-Preview is not a
  source of truth for canonical work and nothing here derives from
  it.

## 8. Temporal-transfer evidence

Method (per AGENTS.md): the scenario module was copied, unmodified,
onto a fresh checkout reconstructed at the exact historical
checkpoint — canonical `main` @
`2726e59e0aed6f3ba9c6c1108712fbab26bc1f36` — with no tree rewriting
(the base checkout's only deviation from the checkpoint tree is the
added scenario file itself, untracked). The scenario and the full
suite were run at both states.

| State | Scenario module | Full suite |
|---|---|---|
| Base checkpoint `2726e59` (+ scenario file only) | 11 tests, OK | 1047 tests, OK (skipped=25) |
| Branch head (base + scenario + this record) | 11 tests, OK | 1047 tests, OK (skipped=25) |

Classification:

- **TRANSFERS:** all 11 scenario tests pass identically at the base
  checkpoint. The behavior exercised — exact-intent binding,
  presenter binding, single-use consumption, approval verification,
  test-level reconciliation, incident-channel derivation — is
  entirely pre-existing kernel behavior at `2726e59`; the replay
  adds no behavior, so nothing about it depends on any later state.
- **NO EFFECT:** none identified beyond the transfer itself — the
  module changes no production code at either state.
- **NEGATIVE TRANSFER:** none. In particular, the issue-#375
  surfacing boundary (bare `require_approval` decisions are
  audit-recorded but not channel-derived) is identical at both
  states and is pinned identically by step 7 in both runs.

## Adversarial transformation review (eight passes) and stop/continue

Per `docs/ADVERSARIAL_TRANSFORMATION_SOP.md`, applied to the
Gainsight / Salesforce connected-app incident. **Stop/continue
decision: CONTINUE in the governed kernel path only** — exactly one
governed external consequence is permitted in the scenario, and any
non-kernel connection path (the incident's own class) remains outside
this evidence and open.

1. **Flip** (the attacker becomes the defender / the defender's tool
   becomes the attack surface). *Attack:* the genuine sync permit,
   legitimately issued to the app, is the attack surface — whoever
   holds it holds the act. *Result:* possession is not sufficient.
   The permit is bound to the app as presenter; a holder without the
   app's proof spends nothing (step 3), and the platform can end the
   app's spend authority by deregistering the presenter without
   touching the token (step 9). The defender's own incident channel
   is likewise flipped in step 7: it is derived only from the audit,
   is read-only, and appends nothing — the monitoring tool cannot be
   used to write history.
2. **Reverse** (run the causal chain backwards). *Attack:* work
   backwards from the desired end state — "the export appears in the
   vendor's activity report as a legitimate consequence" — to what
   must be true: a `permit_consumed` record for the export's intent
   hash. Forging that record requires breaking the audit chain, and
   reconciliation verifies the chain first and fails closed; the
   inflated claim in step 6 is caught as an unbacked consequence
   precisely because the backwards chain has no consume to stand on.
3. **Invert** (swap the roles of components). *Attack:* make the
   connection itself the authority — present the OAuth token where a
   permit belongs (steps 1 and 8). *Result:* the kernel has no verb
   that derives read authority from an integration's existence; the
   token is a fabricated token and is rejected as one, in the install
   session and in a later session alike. Inverting verifier and
   presenter also fails: the token holder's own valid proof verifies
   — for the wrong identity — and is refused as a mismatch (step 3b).
4. **Inside-Out** (the boundary moves; the insider is the threat).
   *Attack:* the threat is not an outsider breaching the platform but
   the trusted app itself, or whoever stands where the app stands,
   reaching across every org that installed it. *Result:* the org is
   inside the bound resource identity, so the declared function
   aimed at another customer's org is a different intent and is
   denied under the genuine permit (step 2). Vendor-side compromise
   yields, per org, exactly the permits that org's approvals issued
   — each bound to its exact act — not a master key.
5. **Darken** (remove visibility; act where no one is watching).
   *Attack:* run the campaign where the customer cannot see it — the
   incident's actual condition for eleven days. *Result:* every
   route appends to the canonical audit whether it succeeds or not,
   and the claim-versus-record gap is mechanically computable: step
   6 names the silent campaign as exactly five undisclosed attempts,
   and step 7 shows 18 of the campaign's events surfacing as
   near-misses without any human filing a report. The one darkened
   corner is named, not hidden: bare `require_approval` decisions
   are audit-recorded but not channel-derived (issue #375).
6. **Lighten** (flood the zone; hide the signal in volume). *Attack:*
   bury the five extraction attempts inside the app's legitimate
   traffic and the noise of a platform-wide integration. *Result:*
   reconciliation and the channel count by intent hash and event
   class, not by narrative: the undisclosed-attempt set is exact at
   any volume, and the near-miss count is an exact sum of the
   derived event classes. Volume changes the counts, not the
   verdicts. (Asserted here for the scenario's volumes; a claim
   about adversarial volume beyond the suite's evidence would be
   Proposed, and none is made.)
7. **Amplify** (scale the act up). *Attack:* widen the one approved
   sync to every object (the scope-widened resource in step 2), or
   replay the one permit at scale. *Result:* the widening rides
   inside the hashed resource identity and is denied as a different
   intent; replay is denied by single-use consumption (steps 4 and
   7). Amplification requires new approvals, per act, per org —
   which is the authorization the incident never had.
8. **Negate** (assume the control is absent; check the claim still
   discriminates). *Attack:* remove the binding layers — the
   negative control's unguarded consume over an intent-blind state.
   *Result:* the bulk export **executes** under the sync permit.
   The scenario's denials are therefore attributable to the kernel's
   token authentication, intent binding, and presenter binding, and
   the scenario would fail loudly if any of them regressed. Negating
   the audit instead is covered by construction: reconciliation
   fails closed on an invalid chain rather than reconciling against
   fabricated provenance.

**Stop/continue:** CONTINUE in the governed kernel path only.
Exactly one governed external consequence is permitted (the approved
sync, spent once, by its bound presenter). Every non-kernel path —
the standing connection answering on existence alone — is the
incident's own class, remains outside this evidence, and stays open.
