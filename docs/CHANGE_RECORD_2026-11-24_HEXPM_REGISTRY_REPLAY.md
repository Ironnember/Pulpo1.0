# Change record — Incident replay: Hex.pm registry unauthenticated RCE via pre-auth Erlang term decoding (2026-11-23; disclosed 2026-11-24)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 evening run; Austin
approved building all five replays on 2026-11-24.
Test-only change: one scenario module plus this
record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Verified, from Hex's own incident report,
https://hex.pm/blog/security-incident-on-hexpm;
CVE-2026-129514, Recorded): on 2026-11-23,
18:16–18:29 UTC, an unauthenticated attacker sent 69
requests whose bodies were Erlang terms decoded by
the request-body parser BEFORE routing or
authentication; forged structs (a map with a
`__struct__` key) reached error reporting whose
`inspect()` dispatched through Ecto/DBConnection to
an attacker-supplied {module, function, args} tuple,
executing OS commands on six web servers. Hex
blocked traffic and patched within ~20 minutes. No
packages were modified, no DB changes were made, and
no persistence was found — but DB reads are not
logged, so reads of emails, bcrypt password hashes,
API-key hashes, 2FA secrets, sessions and audit logs
cannot be ruled out (Unknown). The registry signing
key has NOT yet been rotated (Recorded: a new signing
system is due in coming days). Disclosed 2026-11-24.

Failure addressed: **bytes were executed because
they decoded into a trusted internal shape before
any authentication or authorization existed.**
``DECODED_FORMAT_TRUST != AUTHORIZATION``. Class:
trusted-path execution. A forged struct binds no
intent, names no accountable approver, and carries
no scope; nobody authorized anything, because the
bytes merely parsed. The governing invariants are
the fail-closed rule of AGENTS.md (unknown,
malformed, untrusted, expired, replayed, or
unavailable authority fails closed through the
canonical kernel) and exact-intent binding itself:
under the kernel, a consequential act requires a
permit issued only after an approval whose signature
verifies against the value computed from the payload
under the enrolled authority's key, bound to the
exact intent — principal, action, resource, cost,
session — and spent exactly once at consume, where
the token is itself authenticated and its state row
re-checked. A string that decodes into a trusted
shape is none of those things on any route: not a
token the kernel issued (consume refuses it), not a
signature the authority made (evaluation refuses
it), and not a scope (a genuine approval for one act
refuses to stretch to another).

What actually stopped the real incident was Hex
blocking traffic and patching — Hex's control. This
replay claims nothing about that control; §5 states
the boundary in full, including the signing-key
exposure this replay cannot close.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_DecodeThenTrustVerifier`) exists solely as
the negative control, is test-local, and is never
imported by runtime code — the same pattern as PRs
#346 and #362–#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `RegistryDispatchExecutor` is a test
harness: it records a consequence only after a
successful kernel consume and holds no canonical
state. The incident-channel freeze is asserted
read-only in the scenario itself (audit length
unchanged across the freeze). The step-6 reconciliation
is test-level, against the public `kernel.audit` read
path (see §4 and §5): it introduces no reconciler and
no state mutation. Audit growth is classified in the
module docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied attempt appends
audit records — a governed effect (evidence
production), append-only, with `authority_effect=none`
and no capability accumulation — assessed separately
from governed external consequences throughout. The
count is per route, not uniformly one: a bare
`evaluate` returning `require_approval` appends one
decision record; a denied `evaluate` appends one
decision record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records — an
`approval_rejected` record and a denied decision
record. Growth stays bounded per attempt (at most two
records), which is the invariant the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_hexpm_registry_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (an
  authorized publish into the maintainer's own package
  namespace) executes exactly once under a genuine,
  well-formed verified approval envelope; replay of the
  spent permit is denied; the audit chain verifies.
- step 1: with no artifact at all, `evaluate` returns
  `require_approval` with no permit minted, and nothing
  executes — reachability of the dispatch boundary is
  not an approval. An act the policy does not contain
  (`delete_release` into another maintainer's
  namespace, a verb the boundary has never been given)
  is denied outright (`action_not_allowed`).
- step 2: the forged struct presented as a permit at
  the dispatch boundary is refused for both the target
  act and the legitimate act (`permit_rejected`, reason
  `permit_signature_invalid`, bound to the exact intent
  hash each time). The struct was never issued: no state
  row stands behind it and no genuine token signature
  does either, so decoding into the shape is not an
  issuance.
- step 3: the forged struct offered as an approval
  signature, a garbage/malformed string offered the
  same way, and an envelope signed with an unauthorized
  key are each denied (`approval_signature_invalid`);
  an empty signature is denied earlier and separately
  (`approval_signature_missing`). The governed path
  does not distinguish a correctly-shaped non-authority
  from a shapeless one.
- step 4: the genuine envelope for the maintainer's
  own publish presented for the OS-command act is
  denied (`approval_intent_mismatch`), and the genuine
  issued permit presented against the target act at
  consume is refused (`permit_intent_mismatch`); the
  denials do not poison the path — the same permit then
  performs its own act exactly once.
- step 5: the incident channel sees the attempts —
  freezing a report over the full attempt sequence in
  the incident's own order (the no-artifact probe, the
  unlisted-act probe, the forged struct spent as a
  permit, the garbage signature offered as an approval,
  the genuine envelope stretched to the target act, the
  genuine permit spent against the target act, the one
  legitimate execution, and the spent-permit replay)
  yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the
  audit: 3 `permit_rejected`, 2 `approval_rejected`,
  and 3 denied `decision` records (8 near-misses in
  total), each classified Recorded under a valid audit
  chain; the freeze appends nothing. The step also pins
  the surfacing boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the audit
  and contributes zero near-miss records. The counts are
  from the executed run at this head, not estimates.
- step 6 (reconciliation, Hex-specific): after the
  full attack sequence, the consequence ledger contains
  exactly the one legitimate effect (one
  `permit_consumed` record, for the legitimate intent
  hash only; the target intent hash is present in the
  audited attempts and absent from the audited
  consequences). A test-level reconciliation of a
  claimed state against the kernel audit — verifying
  the audit chain first, then comparing consumed
  consequences and disclosed attempts, as in the
  gainsight, filename-deception and Mythos scenarios —
  reconciles exactly for the honest claim (no
  undisclosed attempts, no unbacked or missing
  consequences, no phantom attempts). A claim asserting
  the target act happened — the "read" position Hex
  cannot rule out for its own database — fails by name
  (`unbacked_consequences` = the target intent hash),
  and a claim omitting the attempts fails by name
  (`undisclosed_attempts` = the full audited attempt
  set). What this proves, precisely: on the governed
  path, no package/state mutation occurred that the
  audit cannot account for. It proves it by the
  test-level construction described here, not by a
  shipped reconciler: the shipped `def reconcile`
  APIs (`pulpo.effect_reconcile.reconcile_effects`,
  `pulpo.custody_reconcile`, the commerce budget
  reconciler) reconcile filesystem effects,
  custody-domain outcomes, and payment evidence —
  none of them takes a claimed consequence ledger
  against a kernel audit — so this step follows the
  prior scenarios' test-level pattern and claims
  exactly its semantics, no more.
- negative control: with the verifier swapped for the
  incident's own shape — a verifier whose `verify`
  accepts the forged-struct token itself as a valid
  signature — the forged struct VERIFIES as an approval
  signature, a permit mints, and the OS-command act
  EXECUTES. Under the same double, a different garbage
  string and the genuine authority's real HMAC
  signature are both denied: only the correctly-shaped
  forgery verifies, because format-shape is the whole
  check — the incident's precision, reproduced at the
  exact layer it happened. The denials in the steps
  above therefore come from the governed verification's
  shape (a computed expected signature under the
  enrolled key, bound to the exact intent), not from a
  harness that denies by construction.

Full suite at the worktree head: **1114 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `9aca02e` is 1106 OK
(skipped=25); the delta is exactly the 8 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip of the trust
  direction: the helpful component (the request-body
  parser and error reporting, built to describe
  requests and failures) is the execution path, and
  its fidelity is the attack — it decoded faithfully
  and reported faithfully, straight into dispatch.
  No control on the governed path depends on the
  parser's or reporter's cooperation: no artifact
  (step 1), the forged struct (steps 2, 3), a garbage
  string (step 3), and a forged key (step 3) are the
  same denial, and flipping the presenter
  (legitimate maintainer vs. unauthenticated peer)
  changes nothing without the enrolled key.
- Reverse — the consequence (an OS command executed,
  a release published) requires a consumed permit; the
  permit requires a verified approval; the approval
  requires a signature computed from the payload under
  the enrolled key by an accountable approver, bound
  to the exact intent. The earliest point at which the
  consequence becomes unreachable is the artifact
  itself, and the chain does not collapse to one
  control: the forged struct fails at token
  authentication at consume (step 2) and at signature
  verification at evaluate (step 3), the garbage and
  forged artifacts fail at verification (step 3), the
  genuine article fails to stretch at intent binding on
  both boundaries (step 4), and the spent permit cannot
  be replayed (positive control, step 5).
- Invert — outcome is not legitimacy: inside the
  incident, the attacker's "successes" (the terms
  decoded, the struct materialized, the tuple
  dispatched) were outcome-successes at every layer and
  legitimacy failures throughout — nothing in the chain
  had authorized anything. The governed record supports
  credit only for consumed acts under verified
  approvals, so a decode-accepted execution would stand
  in the record as a consequence with no approval
  behind it, visible as such; the negative control
  produces exactly that shape, under the double rather
  than the kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; decoded bytes cannot produce an
  approval envelope or ceremony evidence at all; the
  test double is test-only; the orchestrator surface
  used for the incident report is read-only and its
  freeze is asserted to append nothing (step 5); the
  step-6 reconciliation reads the audit and asserts —
  it writes nothing.
- Darken — worst credible bounded case (a threat case,
  not a claim): the technique costs 69 unauthenticated
  requests in 13 minutes and no credentials at all, and
  it reached OS command execution on six production web
  servers. Had the dispatch boundary been the only
  control and the reads the attacker may have made been
  of signing or session material, the blast radius
  extends past the window. Inside the governed path the
  maximum consequence per approval remains the one
  authorized act; every unauthorized attempt produces
  audit records only — one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero consequences. Outside the governed path stands
  the incident's real worst case — pre-auth decoding
  into trusted shapes, anywhere it still exists — and
  this replay does not mitigate it; it is the boundary
  in §5. The unrotated registry signing key (§5) is
  part of this case, not an afterthought.
- Lighten — minimum benign interpretation: Hex's own
  report finds no packages modified, no DB changes, and
  no persistence, and Hex blocked and patched within
  ~20 minutes; the attacker's purpose beyond the RCE
  itself, and whether any DB read actually occurred,
  are not established (Unknown — reads are not logged).
  The replay grades the mechanism — decoded format
  treated as authority — not the attacker, and claims
  no harm the record does not show.
- Amplify — the attempt is free to replicate: many
  forged structs, many registries, many parsers, in
  parallel, each run minutes long. Approvals are
  per-intent and permits single-use, so replication
  multiplies attempts, never authority; denial volume
  produces audit growth only, bounded per attempt, and
  step 6's reconciliation still accounts for every
  consequence exactly.
- Negate — the smallest clean path: a consequential
  registry act needs no decode-then-trust route at all.
  Decode to inert data; authorize separately. A verified
  approval bound to the exact intent, checked against a
  value computed under the enrolled key, achieves the
  legitimate purpose — maintainers publish exactly what
  they are authorized to publish — with no internal
  shape whose mere materialization performs acts.
  Remove format-trust-as-authority and the incident
  class does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models artifacts presented at a governed
registry dispatch boundary. It proves nothing about
Erlang term decoding, Ecto, DBConnection, error
reporting, the real Hex.pm registry, or any deployed
registry, and it reproduces no part of the attack —
the forged-struct string is an inert stand-in that is
never decoded or executed, and the verifier double is
a test-local model faithful only in the property the
scenario names (verification that accepts the
correctly-shaped forgery itself). In particular: the
containment that stopped the real incident was Hex
blocking traffic and patching — Hex's control — and
this replay neither reproduces nor claims it. Pulpo's
claim here is only about the gate it sits on: had the
attacker reached a dispatch boundary routing its
consequential acts through this kernel, the forged
struct, the garbage string, and the stretched permit
would each have failed closed, for the reasons the
steps record. The replay also does not speak to the
parts of the incident outside the gate: the probing,
the choice of error-reporting path, or any DB read
that may have occurred — the kernel governs the
consequential act, not the parsing that precedes it.
And it proves nothing about non-governed paths: a
registry that decodes into trusted shapes before
authentication is governed by nothing here — a control
not on the execution path governs nothing.

Two exposures are stated plainly rather than closed
by this evidence. First, the signing key: Hex's
registry signing key has NOT yet been rotated
(Recorded, per Hex's report; a new signing system is
due in coming days). This replay cannot rotate Hex's
key, and no kernel evidence here bears on it: the
unrotated key is an open exposure that stands exactly
as Hex left it, and reconciling the governed record
(step 6) does nothing to close it — step 6 reconciles
packages and state inside this scenario's audit, and
the key exposure is outside that audit entirely.
Second, the DB-read question in the real incident
remains Unknown for the reason Hex gave (reads are
not logged); step 6 shows the governed path can make
the assertion Hex could not, for acts routed through
it — it does not retroactively make the assertion
about Hex's database.

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

- Incident narrative: **Verified** (Hex's own
  incident report, published 2026-11-24:
  https://hex.pm/blog/security-incident-on-hexpm —
  the 2026-11-23 18:16–18:29 UTC window, the 69
  unauthenticated requests, pre-routing/pre-auth
  Erlang term decoding, the forged `__struct__` maps
  reaching error reporting, the `inspect()` dispatch
  through Ecto/DBConnection to an attacker-supplied
  {module, function, args} tuple, OS command execution
  on six web servers, traffic blocked and a patch
  within ~20 minutes, no packages modified, no DB
  changes, no persistence found).
- CVE identifier (CVE-2026-129514): **Recorded**.
- The possibility of DB reads (emails, bcrypt password
  hashes, API-key hashes, 2FA secrets, sessions, audit
  logs): **Unknown** (Hex states reads are not logged
  and cannot be ruled out).
- Signing-key rotation status (not yet rotated; a new
  signing system due in coming days): **Recorded**
  (per Hex's report).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 5).
- The step-6 reconciliation semantics (test-level,
  against the public audit read path; the shipped
  reconcilers' actual scopes as described in §4):
  **Verified** (the construction and its results are
  executable at this head; the shipped APIs' scopes
  are read from their source at the base commit).
- The mapping from the incident's pattern to kernel
  artifacts (the OS-command act modeled as the
  consequential act; the forged struct modeled in its
  three positions — presented permit, presented
  approval signature, accepted shape under the double;
  the legitimate publish modeled as the one authorized
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
amended, the test-level reconciliation construction of
the gainsight / filename-deception / Mythos scenarios,
and the negative-control double construction of
PR #386.

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

- TRANSFERS: all 8 scenario tests pass identically at
  `9aca02e` — the positive control executing exactly
  once, the no-artifact and unlisted-act denials, the
  forged-struct consume refusals, the forged / garbage /
  unauthorized-key / missing-signature denials, the
  genuine article's refusal to stretch on both
  boundaries, the incident channel's 0 incidents / 8
  near-misses, the step-6 reconciliation reconciling
  the honest claim and failing the inflated and quiet
  claims by name, and the negative control executing
  under the decode-then-trust double. Full suite at
  checkpoint-plus-lesson: 1114 OK (skipped=25),
  identical to the worktree head; the delta over the
  1106 baseline is exactly the 8 scenario tests.
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

## 9. Fix pass — 2026-11-25 (Codex review of PR #396; multiplicity pass)

Review finding (Codex, P2, on
`tests/test_hexpm_registry_incident_scenario.py`):
preserve event multiplicity during reconciliation. The
step-6 reconciliation derived **sets** of intent hashes
from the audit and converted the claimed values to sets
as well, collapsing every occurrence of a hash to one. A
claimed history listing a hash once therefore reconciled
successfully even when the audit held further attempts —
or further executions under separately issued permits —
for that same hash: the claim could underreport repeated
activity while returning `ok=True`. The finding is
correct, and it is the forgery class this replay exists
to expose, pointed at the replay's own checker. It was
reproduced before the fix at head `24d142b`: three
forged-struct attempts on the target intent and two
legitimate publishes under separate permits (audit truth:
attempts {target: 3}, consequences {legit: 2}) reconciled
`ok=True` under a claim listing each hash once.

Change (test module only; no production code, no claim
narrowed — the reconciliation claim is strengthened, and
the prior presence-only limitation is recorded here
rather than smoothed over):

- `audited_sets` is replaced by `audited_counts`: the
  audit side now yields occurrence counts (multisets) per
  intent hash for consequences and attempts alike.
- `reconcile_against_audit` counts the claim's lists the
  same way (a hash listed twice claims two occurrences)
  and flags a hash in each direction whenever the counts
  diverge: underreported attempts are
  `undisclosed_attempts`, underreported executions are
  `missing_consequences`, and overreported claims are
  `phantom_attempts` / `unbacked_consequences`. `ok`
  requires exact count equality for every hash, on top of
  the unchanged fail-closed audit-chain verification.
- New step 6b pins the behavior: the forged struct
  presented as a permit three times (3 rejections, one
  hash) and the legitimate publish executed twice under
  two separately issued permits (2 consumptions, one
  hash). A claim collapsing each hash to a single listing
  fails on exactly the two underreported hashes; the same
  history with multiplicity reported honestly reconciles
  exactly; overreporting fails in each direction on its
  own hash. Step 6's assertions were updated to the count
  form (each count 1) without weakening.

Evidence (Verified, executed at the fix-pass head):

- Scenario: **9/9 pass** (was 8/8 at head `24d142b`;
  the delta is exactly step 6b). The pre-fix reproduction
  now fails reconciliation on exactly the two
  underreported hashes.
- Full suite at the fix-pass head: **1115 tests ran, OK
  (skipped=13)** in this environment; the pristine
  original head measured in the same environment at
  **1114 ran, OK (skipped=13)** — the delta is again
  exactly the new test. (§4's "1114 OK (skipped=25)" was
  recorded in a different environment; skip counts are
  environment-dependent, the +1 test delta is not.)
- Temporal replay of the fix, per §8's method: a clean
  worktree reconstructed at exactly `9aca02e` with the
  updated module copied in (the only delta) passes the
  scenario identically, 9/9; the full suite at
  checkpoint-plus-lesson is **1115 ran, OK (skipped=13)**,
  identical to the fix-pass head. The multiplicity
  comparison is a property of this branch's test-level
  helper over the public audit read path; no kernel
  behavior is exercised differently at the two states,
  and consequential authority is unchanged
  (`authority_effect=none`).
