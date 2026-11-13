# Change record — Phase 2 item 1: signed audit records (2026-11-13)

Required change record (repo AGENTS.md) for signing audit records at
append in the state layer, on branch `phase2/signed-audit` at base
`1e3c266` (canonical main, PR #356 merge). The design is option 1A of
the Phase 2 design memo's Item 1 (held with the PR's working papers),
adopted by the repository owner's ruling of 2026-11-13 together with
the memo's other five recommendations. The gap was reproduced at
`1e3c266` before any fix was written (memo repro
`repro_p2_1_midchain_delete_rehash.py`, verdict Verified — the repro
was re-executed at the new main; it confirms identically to its
`d0b5ceb` run).

## 1. Invariant / failure addressed

Audit records were `{event, payload, previous_hash, timestamp_ns,
hash}` with `hash` an **unkeyed** SHA-256 over the canonical body
(`state.py` `_audit_record`). No record carried a signature, a writer
identity, or any keyed material, on either backend. A writer with only
filesystem access to the state file could delete a mid-chain record
and recompute every following hash with the chain's own public
algorithm — and a fresh kernel booted, `verify_audit()` returned True,
and the deleted decision left no trace. Consistent tampering was
indistinguishable from an honest shorter chain to every in-library
check. The only existing detection was the anchor witness (Item 2),
and only over anchored prefixes.

This change gives every record appended after signing is enabled an
HMAC over its own hash under a dedicated per-deployment
`audit-secret`, verified at boot and by `verify_audit()`. Signing
changes **acceptance**, not writing: a file writer can still write
bytes, but forged bytes no longer verify. "Prevention" in this record
means prevention of acceptance, per the memo.

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed:** `verify_audit()` can no longer ratify a consistently
  rewritten history in a signed deployment. A record past the legacy
  prefix whose signature is missing fails as
  `audit_signature_missing`; a present-but-wrong one as
  `audit_signature_invalid`. Kernel boot refuses a tampered signed
  store (`StateIntegrityError`).
- **Left unchanged:** no surface gains authority over governed
  transitions. Signing attests records; it mints nothing, consumes
  nothing, and evaluates nothing (`authority_effect=none`). The
  `enable-audit-signing` command is an operator-attested deployment
  configuration change, not a governed transition: it appends nothing
  to the audit chain.
- The `audit-secret` is a new deployment secret, but it is an
  attestation key, not an approval or permit credential, and it is
  deliberately distinct from `kernel-secret` and from
  `anchor-secret`: one key must not carry both permit authentication
  and history attestation.

## 3. Canonical state mutations introduced or exposed

No new governed mutation. The audit record format gains one field:

- `signature` — HMAC-SHA256 hex over the record's `hash`, stored as a
  sibling field excluded from the hashed body (the exact pattern
  `AuditAnchor` uses: `signing_payload()` excludes `signature`). The
  unkeyed chain math is unchanged; a legacy verifier recomputing the
  body agrees on the hash of a signed record (pinned by test).
- SQLite `audit` gains a nullable `signature` column (migration on
  first open, following the `permit_directives` precedent). Existing
  records keep NULL signatures — they are the legacy prefix.
- The custody-evidence convergence — the one append route into the
  canonical audit that does not go through a `KernelState` — accepts
  the same signer and refuses, before writing, to project without one
  into a chain that already holds signed records.

Deployment-directory file effects, all outside the audit chain:

- `audit-secret` created owner-only (`0600`, `O_EXCL`) by `init`, or
  by `enable-audit-signing` on a legacy deployment — the provisioning
  half of the #355 load/provision split. The read-only projections
  (`verify` / `status` / `anchor`) take the load-only half for this
  secret exactly as for the kernel and anchor secrets: they never
  create or repair it (pinned by tests, including "creates nothing"
  assertions).
- `policy.json` gains `audit_signing: {enabled, legacy_records}`.
  New deployments are enabled from birth (`legacy_records: 0`).
  Legacy deployments enable explicitly via `enable-audit-signing`,
  which records the enablement and the length of the unsigned legacy
  prefix in that config — outside the state file — so a state-file
  writer who strips signatures cannot re-label the whole chain as
  legacy. Mutating commands (`authorize` / `consume`) do NOT silently
  enable signing (pinned by test); the migration is a deliberate
  operator action, and the command tells the operator to witness the
  prefix with `anchor` at enablement time.

## 4. Success and adversarial evidence (at the fixed tree)

- Full suite: **758 tests OK, 13 skipped** (726 at base `1e3c266` +
  32 new; zero existing tests deleted or weakened; one existing test
  re-pinned — see §7).
- Design repro re-executed at the fixed tree (mid-chain delete +
  honest rehash, both in-memory and SQLite, through the real kernel
  and through raw sqlite3): the fresh kernel refuses to boot
  (`StateIntegrityError`), and `verify_audit_report()` names the
  refusal (`audit_signature_invalid` when stale signatures are kept,
  `audit_signature_missing` when they are stripped). Verdict: gap
  CLOSED for signed deployments.
- New tests in `tests/test_audit_signing.py` pin: signer round-trip
  and wrong-key/malformed-signature refusal; signed records on both
  backends with a reopen round-trip; reopen under a wrong signer
  refuses boot; the kernel-level signer argument and its conflict
  with a supplied state; legacy mode unchanged (unsigned states verify
  exactly as before); the legacy prefix verifies and reports its
  unsigned count, and post-enablement appends are signed; mid-chain
  deletion with rehash refused (both stale-signature and
  stripped-signature variants, in-memory and SQLite); payload edit
  with rehash refused; a single stripped or garbage signature refused
  with the named reason; **tail truncation still verifies** (the
  honest boundary — Item 2's coverage, not this item's); the
  signature is excluded from the hashed body; custody-evidence
  projection with a signer appends a signed record, without one into
  a signed chain refuses before writing, and without one into an
  unsigned chain is unchanged.
- New ops tests in the same file pin: `init` provisions a distinct
  owner-only `audit-secret` and enables signing from birth;
  end-to-end authorize→consume→verify reports signed coverage;
  stripped signatures fail `verify` closed; a deleted audit secret
  fails the projections closed and the projections create nothing;
  projections create nothing on a legacy deployment and `status`
  warns `audit_signing_not_enabled`; a legacy deployment enables
  signing with its legacy prefix counted, verifies with the prefix
  reported unsigned, then appends signed records, and the prefix is
  anchorable (`anchored_prefix_verified`); enablement is idempotent;
  enablement refuses a tampered legacy chain and provisions nothing;
  mutating commands do not silently enable signing; a malformed
  `audit_signing` config fails closed; a signed chain anchors and
  verifies end to end.
- The Mythos scenario's gap tests
  (`tests/test_mythos_laundering_scenario.py`) are untouched and now
  characterize **legacy (unsigned) mode**: they construct unsigned
  states, so the delete-and-rehash chain still verifies there, by
  design. The signed-mode counterparts live in the new test file.
  The scenario's module docstring still says closure "requires an
  external anchored head" — that sentence is now incomplete for
  signed deployments (record signatures also close the mid-chain
  rehash case) and is noted here rather than edited into the
  scenario file, so the scenario's own record stays intact.
- Constitutional-survival proof
  (`scripts/run_constitutional_mutations.py`): refactoring
  `verify_audit()` into `verify_audit_report()` moved the hash check
  the `audit_record_hash_check_removed` mutation anchors on, so the
  mutation went `invalid` on the first CI run of this PR. The anchor
  was updated to the new code, and two mutations were added for the
  new controls — `audit_record_signature_check_removed` (killed by
  the garbage-signature test) and
  `audit_record_signature_required_check_removed` (killed by the
  stripped-signature test). Local run of the script at the fixed
  tree: **16/16 killed, 0 survived, 0 invalid** (result `pass`).

## 5. Boundary the evidence does not prove

- Signing proves the deployment's **state layer** wrote the record.
  It does not prove the kernel governed the write: any caller who can
  make the state append gets a valid signature (Item 3's handles).
  The provenance claim is worded at state-layer strength throughout
  this record and the code; Item 3A narrows who can ask for
  signatures, and only then does the claim strengthen.
- Tail truncation is untouched by this item: signatures do not bind
  the chain's length. A signed chain truncated at the tail still
  verifies (pinned by test). The pair (Item 1 + Item 2) is the unit
  of coverage against a state-file writer, exactly as the memo
  prices it.
- A thief of the `audit-secret` forges history wholesale. Key
  separation (audit ≠ kernel ≠ anchor) means no single theft yields
  both minting and history forgery, but the audit secret alone is
  sufficient for undetectable forgery of the unanchored record layer;
  only an anchor taken before the theft witnesses against it, and
  only over the anchored prefix.
- A whole-directory writer who can also rewrite `policy.json` and
  delete the audit secret can re-label a signed chain as legacy (the
  Item 2 gate's residual, same shape). The maneuver is not silent —
  the secret file disappears and the config changes — but no alarm
  fires on it. That writer is outside this layer's scope.
- Custody-evidence boundary: the projection guard keys on signed
  records already in the chain, so an **empty** signed chain cannot
  tell the projection it is signed. A projection without a signer
  into an empty signed chain appends an unsigned record — and the
  next kernel boot refuses it, fail-closed, never silently accepted
  (pinned by test). The failure mode there is availability, not
  silent corruption.
- The `AuditSigner` object holds the secret in-process: a holder of
  the state object can reach it by convention only (private
  attribute). In-process enforcement against a determined caller is
  Item 3B's claim (service boundary), not this item's.

## 6. Claim classification

- The Item 1 gap at `1e3c266`: **Verified** (design-memo repro,
  re-executed at the new main before this build).
- The fix's effect: **Verified** by the suite and the adapted repro
  re-executed at the fixed tree, as cited in §4.
- Adoption of design 1A and of the enablement / legacy postures
  (memo Questions 1–2): a decision by the repository owner (Austin),
  2026-11-13 — **Recorded**.
- Everything else in this record: **Verified** at the fixed tree.

## 7. Legacy behavior source

The secret helpers from PRs #355/#356 were reused in place
(`_read_secret_file` / `_provision_secret_file`, parameterized by
label and size); the audit pair are wrappers with identical error
strings, modes, and `O_EXCL` semantics, pinned by the unmodified
#355/#356 projection-purity tests. The anchor library API was used
exactly as shipped — `anchor._chain_valid` gained only the
`signature` exclusion from its hashed body, mirroring the kernel's;
no anchor code was copied, forked, or reimplemented. The one existing
test modified is `test_persistence.py`'s overlapping-connections
observer, whose `_audit_record` wrapper must accept and forward the
new optional `signer` argument or the patched call raises; the change
is mechanical (no assertion weakened) and is commented as a re-pin
in place.

## 8. Temporal transfer

Applicable historical checkpoints, exact commits: `7f2a7c9`
(diagnosis Repro B: mid-chain delete + rehash verifies), `d0b5ceb`
(Phase 2 memo repro: the same outcome re-confirmed on the Phase 1
tree), `1e3c266` (this PR's base: repro re-executed, gap CONFIRMED
before the build). The lesson — "an unkeyed chain cannot distinguish
consistent tampering from honest history; acceptance must be keyed"
— transfers at the fixed tree for the stated reason: the same repro
now refuses at boot with a named signature reason. The lesson does
**not** transfer to tail truncation (still verifies — Item 2's
coverage) or to deployments that never enable signing (legacy mode,
by design). No future authority, approval, or credential was carried
into any historical state; the replay changed no consequential
authority.

## 9. Adversarial transformation review (AGENTS.md)

Purpose: signed audit records in the state layer, so a state-file
writer can no longer delete/rehash history that verifies. Exact
requested outcome: forged records fail acceptance at boot/verify.
Authority boundary: the state layer signs; the kernel verifies; the
operator enables; no governed transition is created or altered.

- **Flip** (reverse the actor): if the state layer itself were
  hostile, the signer signs whatever it is asked to append — the
  control depends on the appender being the legitimate state layer
  (Item 3's handle problem, stated in §5). If the audit-secret holder
  is hostile, forgery is wholesale (§5). Survival: partial and
  priced — the claim is worded at state-layer strength, and key
  separation bounds a single theft to one layer.
- **Reverse** (from the consequence): a laundered history that
  verifies requires (a) the state file plus the audit secret, (b)
  stripped signatures plus a rewritten `policy.json`, or (c) tail
  truncation without an anchor. The earliest boundary that makes
  (a)-without-secret and (b)-without-config unreachable is the
  boot/verify signature check; (c) remains the anchor's job.
- **Invert** (success through an unauthorized path): a deployment
  whose `verify` passes because signing was never enabled is outcome
  -correct but provenance-absent. The verify/status reports
  distinguish it (`signing_enabled: false`, warning
  `audit_signing_not_enabled`) so it cannot be read as provenanced
  success. Enablement over a tampered chain would be apparent
  success through a broken path — refused by the pre-enablement boot
  check.
- **Inside-Out** (the enforcer as originator): the state layer both
  signs records and stores them — it is its own attester. The kernel
  verifies signatures but holds no independent truth about what was
  appended. Trust-domain note: this is why the claim is state-layer
  strength, not kernel truth; the operator is the trust root for
  enablement (operator-attested, like the Item 2 migration).
- **Darken** (worst credible bounded case): audit-secret theft gives
  wholesale forgery that verifies (only a pre-theft anchor witnesses
  against it, over the anchored prefix only). A whole-directory writer
  re-labels the chain as legacy by deleting the secret and editing
  the config (§5). The custody-evidence empty-chain edge bricks the
  next boot (availability loss, fail-closed).
- **Lighten** (minimum benign interpretation): an unsigned prefix is
  normal history, not evidence of tampering; a missing audit secret
  on a signed deployment is most likely operator error (deleted file,
  wrong directory) — but the posture is still fail-closed, and the
  error names what is missing.
- **Amplify** (scale/repeat): secrets are generated per deployment
  (`token_bytes`, `O_EXCL`), so one theft does not cascade across
  deployments. Enablement is idempotent. Verification is O(n) HMAC
  per record at boot — linear, same order as the hash check it joins.
- **Negate** (is the mechanism necessary): without a keyed
  attestation the chain is public and unkeyed, so no — the purpose
  cannot be achieved without the credential. Ed25519 (memo 1C) would
  give verifier-without-forge but costs a new dependency in every
  writing process; HMAC is the smallest path, and the signature field
  is algorithm-agile for that upgrade.

Invariants checked: `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS` (signing authorizes no
transition); `AUTHORIZATION_TO_USE_CAPABILITY !=
AUTHORIZATION_TO_DUPLICATE_CAPABILITY` (the secret is never exported
or duplicated; the signer object is an in-process capability — §5);
`AVAILABLE_CAPABILITY != AUTHORIZED_CAPABILITY` (the state can sign
anything it is asked to append until 3A — stated, not hidden);
`GOVERNED_PATH + UNGOVERNED_ALTERNATE_PATH != GOVERNED_SYSTEM` (the
custody-evidence append route was threaded with the signer and
guarded, not left as the alternate path).

Stop/continue decision: **continue** — no stop condition fired. No
alternate provider route appeared; no credential-bearing state was
copied, exported, or exposed (the secret never leaves the deployment
directory; tests use test secrets); no workaround created a new
capability surface; the execution mechanism did not change after
approval (the build is authorized; the merge is a separate decision).
Smallest next proof: the PR's CI run on this branch, plus the merge
gate's own re-verification of the suite on the merged main.
Remaining unknowns: none introduced by this change; the open Phase 2
items (Item 4 token TTL, Item 3A capability facade) are named in the
memo and unaffected by this PR.
