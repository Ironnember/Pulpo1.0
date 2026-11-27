# Change record — Incident replay: SonicWall SonicOS CVE-2026-19868 SAML MFA bypass via alternate auth (2026-11-06)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 evening run (a catch-up
find; the advisory is dated 2026-11-06); Austin
approved building all five replays on 2026-11-24.
Test-only change: one scenario module plus this
record. No production code is touched.

## 1. Invariant or failure addressed

Incident (the flaw Verified — SonicWall advisory
SNWLID-2026-0014 plus the CISA Known Exploited
Vulnerabilities listing; exploitation Recorded — the
KEV listing and SonicWall's statement only, reported
at The Hacker News, 2026-11-06): SonicWall disclosed
CVE-2026-19868, a flaw in SonicOS under which a user
holding valid credentials for an ALTERNATE
authentication method could bypass SAML authentication
controls on SSL-VPN, skipping the MFA that the SAML
path enforces. The flaw affects Gen7 firmware up to
7.3.3-7015 and Gen8 firmware up to 8.2.2-8015, and
only where SAML is enabled for SSL-VPN logins (the
advisory's own scope note). On remediation: the
advisory as first published (2026-11-06) stated
there was no workaround; the advisory was revised
on 2026-11-09 to add an interim workaround for SAML
deployments that cannot upgrade — disable or delete
any active LDAP, RADIUS, and TACACS+ authentication
servers configured on the firewall (Recorded,
advisory as revised; the "no workaround" form in
the original text of this record was advisory
v1.0's statement, corrected in the §9 fix pass).
SonicWall investigated a report indicating potential
exploitation; CISA added the CVE to the Known
Exploited Vulnerabilities catalog on 2026-11-06, with
a federal remediation due date of November 20. No
victim is named and no attack specifics are disclosed.

Failure addressed: **a credential genuine in one
authentication domain is not authority on a different
path.** The alternate method's credential was accepted
as satisfying the SAML path, whose whole point was the
stronger check (SAML-enforced MFA):
``AUTHENTICATED_BY_SOME_METHOD !=
AUTHORIZED_ON_THIS_PATH``. The bypass is on the
authorization path, not the front door. A credential
from another domain binds no approval by this path's
authority, names no accountable approver for this act
on this path, and carries no scope for the session it
was used to open; nobody on the governed path
authorized anything, because a different domain merely
authenticated someone, somehow. The governing
invariants are the fail-closed rule of AGENTS.md
(unknown, malformed, untrusted, expired, replayed, or
unavailable authority fails closed through the
canonical kernel) and exact-intent binding itself —
including, through the enrolled verifier and key,
binding of the authority to the path: under the
kernel, a consequential act requires a permit issued
only after an approval whose signature verifies
against the value computed from the payload under the
ENROLLED path authority's key, bound to the exact
intent — principal, action, resource, cost, session —
and spent exactly once at consume, where the token is
itself authenticated and its state row re-checked. A
genuine credential from another domain is none of
those things on any route: not a token the kernel
issued (consume refuses an inert bearer string), not
a signature the path's authority made (evaluation
refuses the alternate-domain envelope), and not a
scope (a genuine approval for one act refuses to
stretch to another, even from the right authority).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_FallbackAcceptingVerifier`) exists solely as
the negative control, is test-local, and is never
imported by runtime code — the same pattern as PRs
#346 and #362–#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `SslVpnGatewayExecutor` is a test
harness: it records a consequence only after a
successful kernel consume and holds no canonical
state. The incident-channel freeze is asserted
read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is
classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records — a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
denied `evaluate` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_sonicwall_saml_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one legitimate act
  (establishing a VPN session) executes exactly once
  under a genuine, well-formed verified approval
  envelope from the enrolled SAML authority; replay of
  the spent permit is denied; the audit chain verifies.
- step 1: with no credential at all, `evaluate`
  returns `require_approval` with no permit minted, and
  nothing executes — reachability of the gateway is not
  an approval. An act the gateway's policy does not
  contain (`administer_gateway`) is denied outright
  (`action_not_allowed`).
- step 2: an inert stand-in bearer string (never
  issued) presented as a permit at the dispatch
  boundary is refused for both the session act and the
  bounded status act (`permit_rejected`, reason
  `permit_signature_invalid`, bound to the exact intent
  hash each time). No state row stands behind it and no
  genuine token signature does either, so possession
  of the string is not an issuance.
- step 3 (the incident's core): an approval envelope
  for the session act signed under the ALTERNATE
  domain's key — structurally perfect, genuinely
  signed, by the wrong authority for this path — is
  denied (`approval_signature_invalid`): the governed
  verifier computes the expected signature under the
  ENROLLED SAML authority's key, and a valid signature
  from another domain is not it. A fabricated signature
  is denied the same way (`approval_signature_invalid`);
  an empty signature is denied earlier and separately
  (`approval_signature_missing`). The governed path
  does not distinguish a genuine credential from the
  wrong domain from an invented one; neither is the
  enrolled authority's approval.
- step 4: the genuine SAML envelope for a different
  bounded act (a read of the gateway's public status
  resource) presented for the session act is denied
  (`approval_intent_mismatch`), and the genuine issued
  permit for that act presented against the session act
  at consume is refused (`permit_intent_mismatch`); the
  denials do not poison the path — the same permit then
  performs its own act exactly once. Path binding
  (step 3) and intent binding (this step) are separate
  refusals: even the RIGHT authority's approval does
  not stretch across acts.
- step 5: the incident channel sees the attempts —
  freezing a report over the full attempt sequence in
  the incident's own order (the no-credential probe,
  the wrong-verb probe, the inert bearer string spent
  as a permit, the alternate-domain envelope offered
  for the session act, the genuine SAML envelope
  stretched to the session act, the genuine SAML
  session permit spent against a different act, the one
  legitimate session execution, and the spent-permit
  replay) yields zero incidents and exactly the
  near-miss records the channel's derivation produces
  from the audit: 3 `permit_rejected`, 2
  `approval_rejected`, and 3 denied `decision` records
  (8 near-misses in total), each classified Recorded
  under a valid audit chain; the freeze appends
  nothing. The step also pins the surfacing boundary
  stated in §5: the sequence's 1 `require_approval`
  decision is present in the audit and contributes zero
  near-miss records. The counts are from the executed
  run at this head, not estimates.
- negative control: with the verifier swapped for the
  incident's own shape — a fallback-accepting verifier
  whose `verify` returns True if the signature verifies
  under EITHER the enrolled SAML key OR the alternate
  domain's key — the alternate-domain envelope for the
  session act VERIFIES, a permit mints, and the session
  EXECUTES, with no MFA-path approval ever existing.
  Under the same double, a fabricated string is still
  denied: it verifies under neither key. The double's
  flaw is precisely domain confusion, not universal
  acceptance — the incident's shape, reproduced at the
  exact layer it happened. The denials in the steps
  above therefore come from the governed verification's
  shape (a computed expected signature under the
  enrolled path authority's key only, bound to the
  exact intent), not from a harness that denies by
  construction.

Full suite at the worktree head: **1113 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `9aca02e` is 1106 OK
(skipped=25); the delta is exactly the 7 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip of the
  authentication direction: the weaker configured
  method, not the stronger SAML path, decides who gets
  the session, and the MFA the strong path exists to
  enforce is the thing skipped. No control on the
  governed path depends on which domain a presenter
  authenticated in: no credential (step 1), an inert
  bearer string (step 2), a genuine alternate-domain
  signature (step 3), and a fabricated signature
  (step 3) are the same denial, and flipping the
  presenter changes nothing without the enrolled path
  authority's key.
- Reverse — the consequence (an established VPN
  session) requires a consumed permit; the permit
  requires a verified approval; the approval requires
  a signature computed from the payload under the
  enrolled SAML authority's key by an accountable
  approver, bound to the exact intent. The earliest
  point at which the consequence becomes unreachable
  is the credential itself, and the chain does not
  collapse to one control: the inert string fails at
  token authentication at consume (step 2), the
  alternate-domain and fabricated artifacts fail at
  signature verification at evaluate (step 3), the
  genuine article fails to stretch at intent binding
  on both boundaries (step 4), and the spent permit
  cannot be replayed (positive control, step 5).
- Invert — outcome is not legitimacy: inside the
  incident, a successfully established session was an
  outcome-success and a legitimacy failure throughout —
  the path that authorized it was not the path whose
  check the session was supposed to satisfy. The
  governed record supports credit only for consumed
  acts under verified approvals from the enrolled path
  authority, so a fallback-accepted session would stand
  in the record as a consequence with no SAML-path
  approval behind it, visible as such; the negative
  control produces exactly that shape, under the double
  rather than the kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; an alternate domain's key cannot
  produce an approval the governed verifier accepts or
  ceremony evidence at all; the test double is
  test-only; the orchestrator surface used for the
  incident report is read-only and its freeze is
  asserted to append nothing (step 5).
- Darken — worst credible bounded case (a threat case,
  not a claim): the bypass needs only valid credentials
  for a weaker configured method — credentials a user
  may legitimately hold — and skips the MFA that is
  often the only barrier between a phished password and
  a network foothold; remediation at the time of the
  original advisory was upgrade-only (the 2026-11-09
  revision added the interim workaround recorded in
  §1), and CISA's KEV listing records the flaw as
  exploited. Inside the governed path the maximum
  consequence per approval remains the one authorized
  act; every unauthorized attempt produces audit
  records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected`
  record and a denied decision record) on the denied
  approval-envelope route — and zero consequences.
  Outside the governed path stands the incident's real
  worst case — deployed gateways whose alternate method
  satisfies the SAML path — and this replay does not
  mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: no victim
  is named, no attack specifics are disclosed, and
  exploitation is recorded only via the KEV listing and
  SonicWall's statement about a report it investigated;
  an alternate authentication method is a legitimate
  configuration in itself, and a user authenticating
  through it may have intended nothing beyond signing
  in. The replay grades the mechanism — one domain's
  authentication treated as another path's
  authorization — not any user, and claims no harm the
  record does not show.
- Amplify — the flaw is fleet-shaped within the
  affected configurations: Gen7 and Gen8 devices at or
  below the affected versions WITH SAML enabled for
  SSL-VPN logins (the advisory's scope) carry the same
  confusion, and one set of alternate-method
  credentials is reusable against an appliance only
  where that appliance accepts the same alternate
  authentication backend/account — across a fleet
  sharing a credential domain, not against every
  device in the version range. (Scoped in the §9 fix
  pass; the original text claimed every device and
  every credential set.) Approvals are per-intent,
  per-path-authority, and permits single-use, so
  replication multiplies attempts, never authority;
  denial volume produces audit growth only, bounded
  per attempt.
- Negate — the smallest clean path: a consequential
  session needs no fallback-accepting route at all. A
  verified approval bound to the exact intent, checked
  against a value computed under the enrolled path
  authority's key only, achieves the legitimate
  purpose — users the SAML path approves get exactly
  the sessions they are approved for — with no second
  domain whose genuine credential silently satisfies
  the path. Remove cross-domain fallback acceptance
  and the incident class does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models credentials and approval artifacts
presented at a governed SSL-VPN gateway boundary. It
proves nothing about SonicOS, SAML, any real identity
provider, or any deployed gateway, and it reproduces
no part of any real exploitation, device, or
credential — the alternate domain is a second test key,
the signature strings are inert stand-ins, and the
verifier double is a test-local model faithful only in
the property the scenario names (verification that
succeeds under either of two domains' keys). Pulpo's
claim here is only about the gate it sits on: had the
alternate-method credential been presented at a gateway
routing its session establishment through this kernel,
the alternate-domain envelope, the fabricated
signature, the inert bearer string, and the stretched
permit would each have failed closed, for the reasons
the steps record. The replay also does not speak to
the parts of the incident outside the gate: how the
alternate credentials were obtained, whether any real
session was established, or what followed one — no
victim or attack specifics are disclosed, and the
kernel governs the consequential act, not the
authentication attempts that precede it. And it proves
nothing about non-governed paths: a gateway that
accepts an alternate domain's credential as satisfying
its SAML path is governed by nothing here — a control
not on the execution path governs nothing. Whether any
given production gateway's verification is
fallback-shaped is an audit question for that gateway;
this scenario pins only that the canonical kernel's
shape gives a wrong-domain credential nothing to act
with.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 5's pinned counts): a bare `evaluate` that returns
`require_approval` — the kernel declining to mint a
permit without approval — appends a decision record to
the canonical audit, where it is complete and
chain-verified, but the incident channel does NOT derive
a near-miss record from it; the channel derives
near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is
still stopped — no permit exists to spend — so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375). Whether
a `require_approval` decision should also surface as a
near-miss is a design question for the channel's
maintainers; this replay records the behavior exactly
as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- The flaw (CVE-2026-19868; SAML authentication
  controls on SSL-VPN bypassable with valid credentials
  for an alternate authentication method, skipping
  SAML-enforced MFA; Gen7 ≤7.3.3-7015 and Gen8
  ≤8.2.2-8015 affected, only where SAML is enabled for
  SSL-VPN logins): **Verified** (SonicWall advisory
  SNWLID-2026-0014; CISA KEV listing 2026-11-06).
- Remediation: upgrade, per the advisory; the
  advisory as first published (2026-11-06) stated no
  workaround existed, and the 2026-11-09 revision
  added the interim workaround (disable or delete
  active LDAP, RADIUS, and TACACS+ authentication
  servers) for SAML deployments that cannot upgrade:
  **Recorded** (advisory as revised; verified against
  the advisory in the §9 fix pass). The unqualified
  "no workaround" in the original text was advisory
  v1.0's statement and is superseded.
- Fleet-wide credential portability (one credential
  set working across many appliances): **Inferred** —
  it holds only where the appliances share the same
  alternate authentication backend/account (a shared
  credential domain); the advisory establishes the
  per-device mechanism and the SAML-enabled scope,
  not fleet-wide portability.
- Exploitation: **Recorded** (the CISA KEV listing and
  SonicWall's statement that it investigated a report
  indicating potential exploitation; no victim or
  attack specifics disclosed).
- Victim identity: **Unknown** (none named in the
  advisory, the KEV listing, or the reporting).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 5).
- The mapping from the incident's pattern to kernel
  artifacts (the SAML identity provider's approver
  modeled as the enrolled verifier; the alternate
  authentication method modeled as a second key domain;
  session establishment modeled as the consequential
  act): **Inferred** — the harness's modeling choices,
  stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346 and #362–#388, including their
per-module helper-duplication pattern, the
reporting-coverage construction of PR #378's step 6 as
amended, and the negative-control double construction
of PR #386.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `9aca02e`: the
bindings and verification checks the scenario exercises
(exact-intent binding, single-use consumption, token
authentication at consume, approval verification with an
exact-`True` verdict, the approval-envelope structural
checks) all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has been
run.

Method: a clean worktree was reconstructed at exactly
`9aca02e` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `9aca02e`
without the lesson in this environment is 1106 OK
(skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 7 scenario tests pass identically at
  `9aca02e` — the positive control executing exactly
  once, the no-credential and wrong-verb denials, the
  inert-bearer consume refusals, the alternate-domain /
  fabricated / missing-signature denials, the genuine
  article's refusal to stretch on both boundaries, the
  incident channel's 0 incidents / 8 near-misses, and
  the negative control executing under the
  fallback-accepting double. Full suite at
  checkpoint-plus-lesson: 1113 OK (skipped=25),
  identical to the worktree head; the delta over the
  1106 baseline is exactly the 7 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `9aca02e` exactly as at the
  head — the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Post-review fix pass (Codex P2 x2 on PR #400, 2026-11-25)

Two Codex findings on the original head `724c3a0`,
both verified against the primary source (advisory
SNWLID-2026-0014 as it currently stands: first
published 2026-11-06, last updated 2026-11-09,
Workaround: true) and fixed; wording only, no code
or test logic changed (`authority_effect=none`).

- **The no-workaround claim was obsolete.** The
  original text presented "no workaround" as a
  current Verified fact. That was advisory v1.0's
  statement (2026-11-06); the 2026-11-09 revision
  added an interim workaround for SAML deployments
  that cannot upgrade — disable or delete any active
  LDAP, RADIUS, and TACACS+ authentication servers
  configured on the firewall. §1, §4 (Darken), §6,
  and the module docstring now carry the
  time-scoped, corrected statement, classified
  Recorded (advisory as revised).
- **The fleet amplification was overgeneralized.**
  §4's Amplify pass claimed every Gen7/Gen8 device
  in the version range carries the confusion and
  one credential set works against each. The
  advisory scopes the vulnerability to devices
  where SAML is enabled for SSL-VPN logins, and a
  credential is reusable only where appliances
  accept the same alternate authentication
  backend/account. Amplify and §6 now state the
  scoped form, and §6 classifies fleet-wide
  credential portability as **Inferred** (shared
  credential domain only).

Re-verification at the fix-pass head: scenario 7/7;
full suite **1113 tests, OK (skipped=13)** in this
environment — identical totals to the pre-pass head,
as expected for a wording-only change.

## 10. Pin refresh — #413 near-miss derivation shift (2026-11-27)

Addendum to §9: PR #413 (merged 2026-11-26 as
`b1cea2f`, fixing issue #375) changed the incident
channel's near-miss derivation so a bare-evaluate
`require_approval` decision now surfaces as a
near-miss. This scenario's step-5 sequence contains
one such decision, so its pinned incident-channel
count moves from 8 to 9 near-misses (0 incidents
unchanged). This is an expectation shift from the
#413 derivation change, not a behavior change in
this scenario: all allow/deny assertions are
unchanged. The step-5 accounting assertions now
include the `require_approval` decision in the
near-miss sum and in the `decision` detail count,
matching the pattern used by the scenarios updated
in #413 itself. No kernel or production code is
changed (`authority_effect=none`).
