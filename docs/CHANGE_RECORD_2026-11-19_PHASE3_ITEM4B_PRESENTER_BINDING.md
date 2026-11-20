# Change record — Phase 3, Item 4B: presenter binding (token v3)

Queue position: the last named Phase 3 item. Phase 3 Item 3B
(service boundary) is PR #371, in review; this PR is built on
canonical main `fc51e71` and touches no service code — the
interplay is stated in §5. Design authority: the Phase 2 Item 4
change record §5 ("Presenter binding (4B) remains required before
any cross-domain consumer is claimed governed") and the
revocation-evidence record §5 ("a permit presented by anyone other
than its issued presenter (Phase 3, Item 4B)"), under Austin's
2026-11-13 rulings (Item 4 = token v2; 4B to Phase 3). Build
authorized by Austin, 2026-11-19 ("Proceed"). Base suite: 930 OK,
skipped=13.

## 1. Invariant or failure addressed

A permit was a bearer <redacted> inside its TTL window: possession of
the token string plus the exact intent spent it, whoever presented
it. Item 4 bounded the window in time; nothing bound the
*presenter*. A token copied the minute it was issued — from a
permit file, a log, a message — was spendable by the copyist for
its full window.

The fix, in full:

- **Token v3.** The signed claims gain a presenter field: the
  SHA-256 of the bound presenter identity, or of the empty string
  for an unbound permit. The field is inside the HMAC, so the
  binding can neither be stripped nor swapped without the kernel
  secret. v2 strings fail closed at consume (hard cutover, the
  Item 4 precedent).
- **Issuance binding.** `evaluate`, `evaluate_with_approval`,
  `evaluate_locked_target`, and the directive projection accept
  `presenter=`; the issuance funnel binds it into the token and
  refuses — with a recorded decision — to mint for a presenter with
  no registered verifier (`presenter_not_registered`), because
  such a permit would be unspendable by construction.
- **Consume gate.** `consume` accepts `presenter=` /
  `presenter_proof=`; for a bound token it requires the named
  presenter's valid proof — a signature over the canonical payload
  binding the exact token and intent digest
  (`pulpo.presenter-proof.v1`) — verified against the verifier
  registered for that identity at kernel construction. The gate
  runs at the kernel layer, after intent binding and before the
  store, so a failed presenter attempt is recorded
  (`permit_rejected` with a distinct reason) and never burns the
  permit.
- **Policy requirement.** `Policy.require_presenter_binding`
  (default false, bound into the policy hash only when true — the
  Item 2/Item 4 default-split pattern) retires the bearer posture
  for a policy: unbound permits are neither minted
  (`presenter_binding_required` at the funnel) nor spent
  (`permit_presenter_unbound` at consume).

## 2. Authority gained, narrowed, or left unchanged

- **Gained:** no new authority is created. A presenter gains
  nothing it did not have: binding only ever *narrows* who can
  spend a permit the kernel already decided to issue. The
  presenter registry is deployment configuration injected at
  kernel construction (the approval verifier's pattern); there is
  no runtime verb that registers a presenter, and the registry
  never enters policy or the audit chain.
- **Narrowed:** the class of parties who can spend a bound permit
  shrinks from "any holder of the token string" to "the holder of
  the token string who also holds the bound presenter's key."
  Theft now requires two independent artifacts. Under a requiring
  policy, the bearer class disappears entirely.
- **Unchanged:** every Decision on the bearer path; issuance,
  expiry, intent binding, single-use, revocation, and the
  cumulative budget; the store schema (no column is added — see
  §5); directive semantics (the projection passes `presenter`
  through and is never consulted about it as authority).

## 3. Canonical state mutations introduced or exposed

None in the store. The binding lives entirely in the signed token
and in kernel-layer verification, following the 2026-11-13
intent-binding layering precedent: the authenticated token is the
statement a state-file writer cannot alter, so it is the statement
the presenter claim is checked against. No state schema change,
no migration, no new audit event type — presenter refusals append
the existing `permit_rejected` event with new reason tokens
(`permit_presenter_proof_required`, `permit_presenter_mismatch`,
`permit_presenter_unverifiable`, `permit_presenter_unbound`), and
issuance refusals append the existing `decision` event
(`presenter_binding_required`, `presenter_not_registered`,
`presenter_invalid`).

Policy hash: a policy that sets `require_presenter_binding=True`
hashes differently (the field binds in only when non-default);
default policies keep the exact pre-4B hash, pinned by the
unmodified ceremony and policy suites.

## 4. Exact success and adversarial evidence

New tests: `tests/test_presenter_binding.py` (17 tests) with
`tests/presenter_support.py` (the HMAC presenter double, mirroring
`tests/authority_support.py`). Full suite at this branch's head:
**947 OK (skipped=13)** — the 930 at base plus the 17 new, with
exactly two pre-existing files modified (below).

Pinned behavior:

- Bound permit spends for its presenter with a valid proof, and
  single-use still holds afterward.
- Missing proof / wrong presenter (a registered attacker with its
  own valid key) / wrong key: refused with distinct reasons, and
  **the permit is not burned** — the bound presenter can still
  spend it after each failed attempt.
- A proof is bound to the exact permit and intent: a proof
  captured for one permit verifies for no other.
- Tampering with the presenter claim (swapping in another
  identity's hash) fails authentication as
  `permit_signature_invalid`; the genuine token still spends.
- A bound permit on a kernel with no registered verifier for the
  identity refuses `permit_presenter_unverifiable` — never a
  silent fall back to bearer.
- Issuance to an unregistered presenter (or with no registry at
  all) is denied `presenter_not_registered`; no permit is minted.
- Requiring policy: unbound issuance denied and recorded; a
  bearer token minted by a sibling kernel over the same state is
  refused at consume as `permit_presenter_unbound`; bound
  issuance + spend works end to end; the requiring policy's hash
  differs from the default policy's.
- Cutover: a genuine v2 token with a real store row is refused
  `permit_signature_invalid`.
- Governed paths: the approval path binds (`evaluate_with_approval`
  with a presenter; consume enforces), and the directive
  projection passes the presenter through to a bound permit.

Pre-existing files modified, and why:

- `tests/test_permit_ttl.py` — format-follow only: token splits
  move from five fields to six, the part-count assertions follow,
  and the shape test additionally asserts the unbound presenter
  claim. Every expiry assertion is unchanged in substance. (The
  Item 4 PR made the same kind of edit at the v1→v2 cutover.)
- `tests/test_issue_153_consequence_reconciliation_v0.py` — one
  assertion: the projection's parameter tuple gains `presenter`.
  The test pins that the projection's inputs are closed over
  authority inputs; `presenter` is not one — it is never consulted
  as evidence for a decision and can only narrow the issued
  permit. The pin's substance (no memory/chat/success input) is
  preserved and the reasoning is recorded at the assertion.

Constitutional mutation added: `presenter_binding_check_removed`
(the consume gate neutralized), killed by the new tests. Full run
at this head: **25/25 killed** (24 at base + 1 new).

## 5. Boundary the evidence does not prove

- **Two artifacts, not invulnerability.** A thief who steals the
  token *and* the presenter's key inside the window can spend the
  permit once. Binding raises the theft requirement from one
  artifact to two independent ones; it does not police the bound
  presenter itself, whose spends are its issued authority working
  as intended. Key custody for presenters is the deployment's,
  in the same class as authority-key custody.
- **The kernel-secret holder is not bound** (Item 4 §5, unchanged):
  whoever holds the HMAC key can mint tokens with any presenter
  claim.
- **No store-layer re-check, deliberately.** Expiry has a
  store-layer second check because expiry is recorded in the
  permit row at issuance. The presenter claim is *not* recorded in
  the row: the row is writer-controlled state outside the audit
  chain, and the layering precedent (PR #355) is that bindings are
  checked against the signed token, not the row. The direct-handle
  residual is therefore exactly the standing one: code that holds
  the state handle and calls `consume_permit` directly bypasses
  kernel-layer checks — the Item 3A-priced class, closed for
  sibling components by the facade and, across a process, by
  Item 3B — not a new gap introduced here.
- **3B interplay (stated, not built).** PR #371 is not in this
  PR's base. When both land, the service's consume/evaluate
  envelopes can carry the presenter fields as additive optional
  members, and the server-side kernel enforces the same gate; no
  protocol change is required by anything in this PR, and none is
  claimed.
- **The ops CLI presents bearer permits only.** Under a requiring
  policy, consumption flows through the deployment's presenter
  channel; CLI presenter flags are follow-up tooling, not kernel
  semantics.
- **Approval-path ordering.** A presenter refusal at the issuance
  funnel on the approval path lands after the ceremony record is
  appended and before the approval is recorded as used; an
  external authority's challenge may already be consumed on its
  side. The refusal is recorded and no permit exists — the
  operator re-runs with a registered presenter.

## 6. Claim classification

- **Verified** (executed at this branch's head): the 17 new
  tests; the full suite at 947 OK; 25/25 constitutional mutations
  killed; the v2 cutover refusal against a hand-minted v2 token
  with a real store row.
- **Recorded:** the Item 4 and revocation-evidence records naming
  4B and its cross-domain gate; Austin's 2026-11-13 Item 4 ruling
  and his 2026-11-19 build authorization.
- **Inferred:** that the presenter registry's construction-time
  injection is the right trust placement — it follows the approval
  verifier's established pattern in this codebase rather than a
  new argument.
- **Proposed:** nothing in this PR.
- **Unknown:** production presenter-key custody arrangements (no
  production presenter exists yet); whether any deployment holds
  v2 permits at upgrade time (each drains or re-issues, as at
  Item 4).

## 7. Legacy behavior source

The legacy behavior is token v2 at `fc51e71` — bearer inside the
window — read from the Item 4 change record and the consume path
at the base. It is carried forward exactly where the design says
it is: for unbound permits under non-requiring policies, the
bearer posture is unchanged by deliberate design (memo 4C's
accepted posture), and the v2 *format* is not carried forward at
all (hard cutover). The legacy artifacts preserved are the
Decision surface and, for default policies, the policy hash.

## 8. Temporal-transfer evidence

Two lessons are transferred from named checkpoints, and both were
evaluated against the current tree rather than assumed:

- **Item 4's cutover and default-split** (checkpoint: PR #358's
  head and its change record §8): a format change refuses
  outstanding old-format tokens, and a new policy field binds into
  the policy hash only when non-default. Applied to v2→v3 and to
  `require_presenter_binding`; the unchanged ceremony/policy
  suites at this head are the evaluation.
- **The intent-binding layering lesson** (checkpoint: the Codex P1
  fix on PR #355, 2026-11-13): a binding checked against a
  store-row column is forgeable by the row's writer; bindings are
  therefore checked at the kernel layer against the signed token.
  Applied to the presenter claim — it lives in the token, never in
  the row — and the tamper test in §4 is the evaluation: swapping
  the claim fails authentication, where a row-column design would
  have accepted the writer's edit.

## Eight-pass adversarial review

Procedure: `docs/ADVERSARIAL_TRANSFORMATION_SOP.md` (Flip, Reverse,
Invert, Inside-Out, Darken, Lighten, Amplify, Negate), run over
the fix before treating the path as governed.

- **Flip** (reverse the actor): if the *presenter* is the thief,
  binding is the whole control and it holds — the token alone no
  longer spends. If the *issuer* is hostile, it holds the kernel
  secret and binding binds nothing (§5, the Item 4 posture). If a
  *registered presenter* turns hostile, it can spend permits bound
  to itself — that is its issued authority, and revoking the
  permits, not the binding, is the control.
- **Reverse** (from the consequence): spending a bound permit
  requires the token, the exact intent, the presenter identity,
  and a valid proof over token + intent. The proof is
  single-purpose (it names the token) and the permit single-use,
  so a captured proof replays nowhere — verified by the
  proof-binding test.
- **Invert** (success through an unauthorized path): registering a
  rogue presenter would invert the gate — but registration exists
  only as kernel-construction configuration held by the deployment
  owner; no verb, envelope, or directive can add one at runtime,
  and issuance to an unregistered identity is refused in the
  funnel before any token exists.
- **Inside-Out** (the enforcer as originator): the kernel verifies
  against a registry it was handed at construction — it is its own
  registry authority, the same posture as the approval verifier.
  The auditable commitment is the *policy's* requirement, which is
  in the policy hash; the key material itself stays configuration,
  as authority keys do.
- **Darken** (worst credible bounded case): token + presenter key
  stolen together inside the window — one spend, bounded by TTL
  and single-use, identical in shape to any two-possession scheme.
  A whole-directory writer still wins at the store (Item 3 class)
  but cannot re-bind a token: the claim is signed, and the tamper
  test shows the swap failing authentication.
- **Lighten** (minimum benign interpretation): most presenter
  refusals in practice will be misconfiguration — a rotated key, a
  mistyped identity, a sibling kernel without the registry. The
  four distinct reasons keep those legible, and because the gate
  runs before the store, none of them burns the permit: the
  honest presenter spends after the mix-up is fixed (pinned).
- **Amplify** (scale/repeat): a bound consume costs one hash and
  one signature verification; bearer consumes pay nothing new. The
  cutover cost amplifies exactly as Item 4's did — each deployment
  drains or re-issues outstanding v2 permits once.
- **Negate** (is the mechanism necessary): could the store enforce
  presenter binding from a row column? No — Item 4's Negate,
  applied again: the token is what crosses processes, and a row
  column is writer-controlled (the PR #355 lesson). Could TTL
  alone suffice? It bounds *when*, never *who* — the two records
  that name this item require the presenter bound before a
  cross-domain claim, and no time bound answers a presenter
  question.

Invariants checked: `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS` (binding authorizes no new
means of spending; it removes one — spending by non-presenters);
`AUTHORIZATION_TO_USE_CAPABILITY !=
AUTHORIZATION_TO_DUPLICATE_CAPABILITY` (a proof is bound to one
token and intent and duplicates nothing; the token remains
copyable as data and useless to the copyist); `NO_PERMIT !=
NO_GOVERNED_EFFECT` (every presenter refusal and issuance denial
appends its record); `GOVERNED_PATH + UNGOVERNED_ALTERNATE_PATH !=
GOVERNED_SYSTEM` (the direct-handle path is named in §5 at its
standing price, not presented as governed).

Stop/continue decision: **continue** — no stop condition fired.
The build is authorized; the merge is Austin's separate decision,
as with every authority-semantics item.

## Addendum — post-review fix: literal True from presenter verifiers (2026-11-20)

Source: Codex P1 on PR #373, "Require a literal True from
presenter verifiers" — the one unresolved review thread after
dual human approval. Verified against the code at `abac49b`
before fixing: `_presenter_refusal` branched on the truthiness
of `verifier.verify(...)`, so a verifier returning `1` or
`"yes"` spent a bound permit, while the approval path
(`evaluate_with_approval`) has always required
`signature_valid is not True` to refuse. This addendum is the
change record for the fix, in the same eight sections.

### A1. Invariant or failure addressed

A presenter verifier's non-bool return was treated as a
verification verdict. The gate now applies the approval path's
discipline: only the literal `True` is a verdict in favor.
The refusal mapping, all recorded as `permit_rejected` and none
of them burning the permit:

- verifier returns `True` — proceed;
- verifier returns `False` — the proof was verified and
  refused: `permit_presenter_mismatch` (unchanged);
- verifier returns anything else (truthy or falsy non-bool) —
  no verdict exists: `permit_presenter_unverifiable`;
- verifier raises — no verdict exists:
  `permit_presenter_unverifiable` (previously the exception was
  folded into `False` and misrecorded as a mismatch).

### A2. Authority gained, narrowed, or left unchanged

None gained. Narrowed: the set of verifier behaviors that can
spend a bound permit shrinks from "any truthy return" to "the
literal True". Unchanged: every Decision, the bearer path, the
no-verifier-registered refusal (already
`permit_presenter_unverifiable`), and the outcome of the
exception path (refusal before and after; only its recorded
reason is corrected).

### A3. Canonical state mutations introduced or exposed

None new. The same `permit_rejected` event now records
`permit_presenter_unverifiable` for two failure shapes that
previously recorded `permit_presenter_mismatch` (verifier
exception) or recorded nothing at all because the consume
succeeded (truthy non-bool return). No event type, payload
field, or store behavior changes.

### A4. Exact success and adversarial evidence

One regression test added:
`test_truthy_verifier_result_refused_and_permit_not_burned`
(a `TruthyPresenterVerifier` double whose `verify` returns
`1`): the consume refuses with
`permit_presenter_unverifiable`, and after the registry entry
is restored to the HMAC verifier the bound presenter spends
the same permit — the failed attempt did not burn it.
Full suite at the fixed head: **948 OK (skipped=13)** — the
947 at `abac49b` plus the one new test, no existing test
modified. Constitutional mutations: **25/25 killed**,
unchanged — no new mutation is added, because the fix
strengthens a check inside the existing gate and the standing
`presenter_binding_check_removed` mutation (the whole gate
neutralized) is still killed by the bound-consume tests.

### A5. Boundary the evidence does not prove

- The fix governs the kernel's treatment of verifier returns,
  not any verifier's honesty: a verifier that returns `True`
  for a bad proof still spends the permit. Verifier correctness
  and key custody remain the deployment's, as in §5.
- No production presenter verifier exists yet; the doubles are
  same-process HMAC, as throughout this record.
- **Observed, deliberately not fixed here:** the audit-anchor
  signature check in `verify_audit_report` calls
  `signer.verify(...)` under a truthiness branch — the same
  shape against a different, base-era path (Items 1/2). It is
  outside this PR's scope and outside the Codex thread; it is
  recorded here so it is not lost, and it belongs to a separate
  item if Austin wants it closed.

### A6. Claim classification

- **Verified** (executed at the fixed head): the new regression
  test; the full suite at 948 OK; 25/25 constitutional
  mutations killed.
- **Recorded:** the Codex P1 thread on PR #373; the pre-fix
  truthiness behavior at `abac49b`, read from the code.
- **Inferred:** that `permit_presenter_unverifiable` is the
  right token for a non-verdict — it is the gate's existing
  token for "verification could not be performed" (no
  registered verifier), extended to "the verifier produced no
  bool verdict".
- **Proposed / Unknown:** nothing.

### A7. Legacy behavior source

The pre-fix gate at `abac49b` (truthiness, exception folded to
`False`). The discipline copied is the approval path's
`is not True` check at `fc51e71` — a pattern transfer, not a
control-path copy: the presenter gate keeps its own reason
vocabulary and its kernel-layer placement.

### A8. Temporal-transfer evidence

The transferred lesson is the approval path's literal-True
discipline, in force at the base checkpoint `fc51e71` and
traced to the Item 4-era approval verification. Evaluated
against the current tree rather than assumed: a grep over
every `verify(` call site in `pulpo/kernel.py` at the fixed
head shows the presenter gate was the one authority-bearing
site not applying it (the approval sites already did; the
audit-anchor site is the §A5 observation, a reporting path,
not an authorization gate). Where the lesson transfers: any
future verifier-shaped dependency consulted by an
authorization gate. Where it does not: nothing in this fix
changes reporting-path behavior.

### Eight-pass adversarial review of the fix

- **Flip:** if the *verifier* is the hostile party, it could
  always return `True` — the fix does not pretend otherwise;
  it removes the accidental-ally case, where a sloppy or
  coerced non-bool return spent a permit without any verifier
  ever deciding to approve.
- **Reverse:** from the consequence — a bound spend now
  requires a chain of literal verdicts: token authentic,
  intent bound, presenter hash matched, verifier returned
  `True`. Every earlier refusal in the chain is unchanged.
- **Invert:** could the stricter check invert into a denial
  oracle or a lockout? A misbehaving verifier now fails its
  own presenter closed, with a legible reason, and the permit
  is not burned — the honest presenter spends once the
  verifier is fixed (pinned by the regression test).
- **Inside-Out:** the kernel is still its own registry
  authority (§8 posture); the fix adds no registry verb and
  no runtime surface.
- **Darken:** worst case after the fix is the standing one —
  token + presenter key + a verifier willing to return `True`
  spends once inside the window. The truthiness side door,
  which needed no key compromise at all, is closed.
- **Lighten:** the benign reading of the old code was "Python
  convention" — but this codebase's approval path had already
  settled the convention the other way; the fix is the
  presenter gate joining the house rule, not a new rule.
- **Amplify:** one `is` comparison per bound consume; no new
  state, no new audit volume beyond refusals that previously
  succeeded silently.
- **Negate:** is the literal-True requirement necessary, or
  would documenting "verifiers must return bool" do? No —
  the registry accepts any object with a `verify` method, and
  an unenforced contract at an authorization gate is the
  failure this item exists to remove. The check is one line;
  the contract alone is none.

Invariants checked: `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS` (a truthy return was an
arbitrary means of reaching the authorized outcome; it no
longer reaches it); `NO_PERMIT != NO_GOVERNED_EFFECT` (the
new refusals append their records; the previously silent
success now leaves evidence when it fails).

Stop/continue decision: **continue** — the fix is inside the
PR's existing scope (the consume gate it built), no new
authority, no new state. The merge remains Austin's separate
decision; this push dismisses the standing approvals, which
must be re-given on the new head.
