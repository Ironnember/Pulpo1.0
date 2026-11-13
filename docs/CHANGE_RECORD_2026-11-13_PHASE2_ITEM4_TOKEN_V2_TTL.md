# Change record — Phase 2, Item 4: permit token v2 — signed expiry and the policy TTL cap

Base: `origin/main` at `1a03f0c` (PR #357, Item 1). Authority: Austin's
ruling of 2026-11-13 03:45 (adopt all six Phase 2 recommendations; one
PR per item; sequence Item 2 → Item 1 → Item 4 → Item 3A), rulings
Q4/Q5/Q6 of the Phase 2 design memo dated 2026-11-13. Build authorized;
the merge is Austin's separate decision.

## 1. Invariant or failure addressed

Design repro 4 (`repro_p2_4_bearer_token.py`, run against the pre-fix
tree at `1a03f0c`):

- A permit token was `digest:nonce:signature` — three fields, no
  expiry anywhere: not in the token, not in the store row, not in any
  consume check. The only time input to `consume_permit` was compared
  against issuance for *ordering*, never for *validity*.
- **Gap confirmed at `1a03f0c`:** a kernel issues a permit at T0; a
  second kernel, constructed fresh with the same secret and the same
  SQLite state file and a clock ten years later, consumes the bare
  token string: **stolen token consumed 10 years later: True**. The
  only things presented are the string and the asserted intent.
  Controls in the same run: substituted session intent False, exact
  intent True, replay False — single-use and intent binding held;
  *time* was the unbounded dimension.

A bearer artifact that never expires makes every permit ever issued a
permanent credential for its exact intent: every leaked string, every
backup, every permit file left in a deployment directory is live
forever. Failure addressed: **permit authority had no temporal bound.**

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed:** the spend side of permit authority is now bounded in
  time. A permit authorizes its exact intent only inside the window
  `[issued_at, expires_at)` stamped at issuance from the policy's TTL
  cap. After the window, possession of the token authorizes nothing.
- **Unchanged:** issuance authority (the same governors, approvals,
  and policy checks mint permits; nothing new can mint); intent
  binding, single-use, revocation, and the audit path are untouched in
  semantics. Policy gains one field, `max_permit_ttl_ns`, which is
  part of policy identity **only when set to a non-default value**
  (the Item 2 ceremony split: the field enters `policy_hash` only when
  it differs from the default, so policies that do not set it keep
  their pre-Item-4 hash and existing ceremony records over them
  verify unchanged; a policy that sets a cap is a different policy
  and hashes differently).
- **Gained by no one:** the token remains a bearer string; no new
  holder, presenter, or verifier role is created. Presenter binding
  (memo 4B) is Phase 3 and is **not** built here.

## 3. Canonical state mutations introduced or exposed

- **Token format (v2):** `digest:nonce:issued_at_ns:expires_at_ns:
  signature`, where the signature is `HMAC(secret, "digest:nonce:
  issued_at_ns:expires_at_ns")` — the expiry is inside the
  authenticated payload, so extending it invalidates the token. The
  kernel authenticates by recomputing over the fields exactly as
  presented; time fields must be digit-only non-negative integers and
  `expires_at > issued_at`, else the token is inauthentic.
- **Issuance:** `_issue_permit` stamps `issued_at` from the kernel
  clock and `expires_at = issued_at + policy.max_permit_ttl_ns`. The
  cap is enforced structurally — the kernel never stamps a lifetime
  beyond the policy cap, so there is nothing to refuse or clamp at
  issuance; a policy whose cap exceeds the absolute ceiling
  (`PERMIT_TTL_CEILING_NS`, 24 hours) or is not a positive integer is
  refused at `Policy` construction. Default cap
  (`DEFAULT_MAX_PERMIT_TTL_NS`) is 4 hours.
- **Kernel consume:** after signature verification, `consume` checks
  the signed expiry against a single clock read: at or after expiry
  it appends `permit_rejected` with reason `permit_expired` and
  returns False — the same fail-closed shape as revocation. The
  timestamp handed to the state layer is that same clock read.
- **State layer (second layer):** `issue_permit` gains an optional
  `expires_at_ns`. The in-memory backend records it in a side map;
  the SQLite backend stores it in a new `permits.expires_at_ns`
  column (additive migration in the existing schema-gated block, same
  pattern as Item 1's `audit.signature` column; pre-v2 rows keep
  NULL). `consume_permit` on both backends refuses a consume at or
  after a **recorded** expiry, with the rejection payload carrying
  `permit_status: permit_expired`. The kernel is the only caller of
  these methods in the tree.
- **Boundary of the second layer (stated, not hidden):** the store
  enforces a *recorded* expiry only. A store row with no recorded
  expiry (NULL) is not refused at the store: the store cannot
  distinguish a pre-v2 row from a direct store-level issuance, and
  store rows are writer-controlled in the first place (Item 3's
  boundary). The authoritative v1 cutover is the kernel's format
  check (§4), and every kernel-issued permit records an expiry. The
  store layer's job is narrower: a direct handle-level consume call
  cannot spend a kernel-issued permit after its recorded expiry.
- No new routes, writers, ledgers, or capability surfaces. The
  `KernelState` protocol gains one optional parameter; no new
  governed capability is exposed.

## 4. Exact success and adversarial evidence

- **Pre-fix repro (gap):** `repro_p2_4_bearer_token.py` at `1a03f0c`:
  token shape `[64, 32, 64]`; stolen token consumed 10 years later:
  **True**; substituted-session control False; exact-intent True;
  replay False.
- **Post-fix repro (same script shape, fixed tree):** token is 5
  parts with lifetime exactly the policy cap; stolen token at
  T0 + 10 years: **False**, reason `permit_expired`; stolen token
  with the expiry field extended a century (original signature):
  **False**, reason `permit_signature_invalid`; hand-minted v1 token
  (`digest:nonce:signature`) with a genuine store row: **False**,
  reason `permit_signature_invalid`; controls: substituted session
  False, exact intent inside TTL True, replay False.
- **New tests** (`tests/test_permit_ttl.py`, 15 tests): v2 shape and
  stamped lifetime equal to the policy cap; default cap is 4 hours;
  cap validation at construction (0, negative, bool, string, and
  ceiling+1 all refused; ceiling admitted); consume at expiry refused
  with `permit_expired` recorded; consume one nanosecond before
  expiry succeeds; the ten-year case refused; tampered expiry and
  tampered issued-at both refused as inauthentic and the genuine
  token still consumable afterwards; v1 token refused on both
  backends; store second layer refuses at recorded expiry and
  consumes before it on both backends; SQLite migration adds the
  column and preserves NULL on legacy rows; ops lifecycle end-to-end
  (init → authorize → permit file is a 5-part v2 token → CLI consume
  succeeds once → a fresh kernel over the same deployment files ten
  years later refuses with `permit_expired`).
- **Full suite:** baseline at `1a03f0c` 769 OK (skipped=13); at this
  branch's head: **784 OK (skipped=13)** — the 15 new tests, zero
  existing tests modified.
- **Constitutional mutations:** three added —
  `permit_expiry_check_removed` (kernel),
  `permit_store_expiry_check_removed_inmemory`,
  `permit_store_expiry_check_removed_sqlite` — each killed by its
  pinning test. Full run: **19/19 killed, 0 survived, 0 invalid.**
- **Review fix (Codex P2 on PR #358, reproduced before fixing):**
  the first head parsed time fields with `str.isdigit()` + `int()`;
  Unicode digit characters (`²` passes `isdigit()`, `int()` rejects
  it) and fields beyond Python's integer-conversion limit made
  `consume` **raise** `ValueError` instead of failing closed through
  the recorded rejection path (AGENTS.md: malformed authority fails
  closed through the canonical kernel). Reproduced on all three
  shapes pre-fix; post-fix all return False with `permit_rejected`
  recorded. The parse is now a strict guard (`_token_time_ns`: ASCII
  digits only, at most 20), pinned by `MalformedTokenTests`.

## 5. Boundary the evidence does not prove

- **Bearer inside the window is the accepted posture (memo 4C), and
  this PR does not change it.** Possession + deployment access spends
  a permit for its exact authorized intent, once, inside its TTL
  window. TTL bounds *dormant* leakage — a permit file left on disk
  (owner-only `0700`/`0600`) is dead after its window — it does not
  stop *live* interception and use inside the window. Presenter
  binding (4B) remains **required before any cross-domain consumer
  is claimed governed** and is deferred to Phase 3 (Item 3B service
  boundary). Nothing here supports a cross-domain claim.
- **The clock is deployment-domain trust.** Expiry is enforced
  against the kernel's injected clock; a process that controls the
  consume-side clock controls the comparison. That is the same trust
  domain as the state file and the secret (Item 3's boundary), not a
  new assumption — but no claim is made against a hostile clock.
- **The kernel-secret holder is not bound by TTL.** Whoever holds
  the HMAC key can mint tokens with any fields; TTL binds token
  *possession*, not the key holder.
- **Upgrade semantics:** the v1 cutover is a hard cutover. Permits
  outstanding at upgrade time become unconsumable (fail closed, by
  ruling Q4). Deployments must drain or re-issue; no dual-acceptance
  window exists.
- **Availability cost:** policies with short caps will refuse slow
  operator workflows (`permit_expired` is recorded distinctly so the
  refusal is not misread as tampering). The 4-hour default and the
  24-hour ceiling are judgment values from the ruling ("on the order
  of hours"), not derived constants.

## 6. Claim classification

- **Verified** (executed at this branch's head): the §4 repro
  verdicts before and after; the 15 new tests; the full suite at
  784 OK; 19/19 mutations killed; the migration behavior on a
  hand-built pre-v2 database.
- **Recorded:** Austin's 2026-11-13 ruling and memo Q4/Q5/Q6 as the
  design authority; the pre-fix gap verdict as originally reproduced
  in the design memo's work (re-run and confirmed at `1a03f0c` for
  this PR).
- **Inferred:** that the 4-hour default is operationally tolerable
  for current deployments (no production TTL telemetry exists).
- **Proposed:** nothing in this PR.
- **Unknown:** real-world clock quality across operator machines;
  whether any deployment holds v1 permits at upgrade time (each
  deployment drains or re-issues on its own schedule).

## 7. Legacy behavior source

The v1 token format and its consume path are the legacy behavior,
read at `1a03f0c` and deliberately **not** carried forward: v1 tokens
fail closed at the cutover rather than being accepted beside v2. The
schema migration follows Item 1's gated additive-column pattern; the
policy-hash default-split follows Item 2's ceremony pattern; neither
copies a legacy control path — both are current-tree precedents
applied to a new field.

## 8. Temporal transfer

One material lesson is transferred: **policy-identity fields split
on their default** (Item 2, verified at `1e3c266`): a new policy field
enters `policy_hash` only when non-default, so existing policies and
their ceremony records keep their hashes. Applied here to
`max_permit_ttl_ns` and pinned by the unchanged suite (all ceremony
hash tests pass unmodified at this head). Where it does not
transfer: Item 2's field was witness configuration; this field
changes issuance behavior, so policies that *set* a cap hash
differently and must be deployed as new policies — recorded here
rather than silently generalized. No other historical checkpoint is
material to this change; the TTL design itself is new at this ruling
and no temporal proof is manufactured for it.

## 9. Adversarial transformation review (AGENTS.md)

Purpose: permit tokens carry a signed expiry under a policy TTL cap,
so permit authority is bounded in time. Exact requested outcome: an
expired, tampered, or pre-v2 token fails closed at consume.
Authority boundary: the kernel stamps and enforces; policy caps; the
state layer re-checks what was recorded; no governed transition is
created or altered.

- **Flip** (reverse the actor): if the *issuer* is hostile, it holds
  the HMAC key and TTL binds nothing (§5). If the *presenter* is the
  thief, TTL is the whole control — and it works only after the
  window. Survival: the claim is worded at possession strength; the
  window is the priced residual, named in §5 and in the operator
  docs.
- **Reverse** (from the consequence): spending a permit after its
  intended lifetime requires (a) presenting inside the window
  (bounded by the cap), (b) the kernel secret (to re-sign an extended
  expiry), or (c) store/clock control (deployment domain, Item 3).
  The earliest boundary that makes (b)-without-key and
  post-window-(a) unreachable is the kernel's authenticate-then-
  expiry check, in that order: an unauthenticated expiry is never
  trusted, because the check reads only signed fields.
- **Invert** (success through an unauthorized path): a thief who
  spends inside the window gets an outcome-identical success — that
  is precisely the accepted 4C residual, stated rather than hidden.
  The other inversion is availability: a legitimate operator whose
  workflow outlives the cap gets a refusal that looks like failure;
  the distinct `permit_expired` reason keeps it legible.
- **Inside-Out** (the enforcer as originator): the kernel stamps the
  expiry it later enforces, from its own clock — it is its own time
  authority. No external time source is introduced; clock integrity
  stays inside the deployment trust domain (§5), consistent with how
  the kernel already owns issuance ordering.
- **Darken** (worst credible bounded case): a permit file exfiltrated
  the minute it is issued is live for up to the policy cap (≤ 24h by
  the ceiling, 4h by default) — versus *forever* pre-fix. A
  whole-directory writer still wins at the store (Item 3), but can
  no longer resurrect an *expired kernel-issued* permit through the
  kernel path, and the store's recorded-expiry check refuses the
  direct-handle path for it too.
- **Lighten** (minimum benign interpretation): an expired-permit
  refusal is most likely a slow human workflow, not an attack; a v1
  refusal after upgrade is the designed cutover, not corruption.
  Both carry distinct audit reasons so the benign reading is the
  easy one.
- **Amplify** (scale/repeat): the cap is per-policy and the ceiling
  is global; one deployment's long cap cannot leak into another
  (per-deployment secrets, per-deployment policy). Verification cost
  is one HMAC and one comparison per consume — no scaling change.
  Cutover cost amplifies across deployments holding live v1 permits:
  each drains or re-issues once (§5).
- **Negate** (is the mechanism necessary): could the store alone
  enforce expiry without changing the token? No — the token is what
  crosses processes (permit files, copied strings); the store row
  cannot authenticate *when the token itself* was supposed to die,
  and a v1 row is indistinguishable from a no-expiry issuance. The
  signed field is the smallest mechanism that makes the cutover and
  the expiry decidable at the point of presentation. Could TTL
  replace single-use or intent binding? No — it bounds one dimension
  (time) and the other checks are untouched.

Invariants checked: `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS` (TTL authorizes no new means of
spending, only a shorter window for the existing one);
`AUTHORIZATION_TO_USE_CAPABILITY != AUTHORIZATION_TO_DUPLICATE_CAPABILITY`
(the token remains copyable by design — bearer — but a copy now
expires; no capability duplication surface is added);
`AVAILABLE_CAPABILITY != AUTHORIZED_CAPABILITY` (direct store
consume remains available until 3A — now expiry-bound where an
expiry was recorded, and the residual is stated in §3/§5);
`GOVERNED_PATH + UNGOVERNED_ALTERNATE_PATH != GOVERNED_SYSTEM` (the
alternate store path is named and bounded, not presented as governed;
3A remains the item that closes it).

Stop/continue decision: **continue** — no stop condition fired. No
alternate provider route appeared; no credential-bearing state was
copied, exported, or exposed (tests and repros use test secrets
only); no workaround created a new capability surface (the store
parameter is optional and kernel-driven); the execution mechanism
did not change after approval (the build is authorized; the merge is
Austin's separate decision). Smallest next proof: this PR's CI run,
plus the merge gate's own re-verification of the suite on the merged
main. Remaining unknowns: §6's — none block this PR.
