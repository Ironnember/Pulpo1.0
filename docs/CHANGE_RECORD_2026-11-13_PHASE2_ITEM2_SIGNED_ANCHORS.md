# Change record — Phase 2 item 2: signed anchors in the ops deployment form (2026-11-13)

Required change record (repo AGENTS.md) for wiring anchor signing into
the ops deployment form, on branch `phase2/signed-anchors` at base
`d0b5ceb` (canonical main, PR #355 merge). The design is option 2A of
the Phase 2 design memo's Item 2 (held with the PR's working papers),
adopted by the repository owner's ruling of 2026-11-13 together with
the memo's other five recommendations. The gap was reproduced at
`d0b5ceb` before any fix was written (memo repro
`repro_p2_2_anchor_file_rewrite.py`, verdict Verified).

## 1. Invariant / failure addressed

The anchor cryptography already existed and was sound when used
(`AuditAnchor.signature`, `HmacAnchorSigner`, fail-closed
`verify_anchored_audit`). The failure was wiring and defaults in the
deployment form — the only form an operator actually runs:

- `ops init` provisioned no anchor key; the ops CLI never anchored;
  `_anchored_check` called `verify_anchored_audit(..., verifier=None)`,
  under which unsigned anchors verify. The witness was therefore
  **state, not provenance**: a writer who truncated the audit tail and
  rewrote `anchors.jsonl` wholesale to match was ratified
  (`anchored_prefix_verified`, memo repro at `d0b5ceb`).
- Symmetrically, an honest **signed** deployment failed ops `verify`
  as `anchor_verifier_unavailable`: ops could not consume the signed
  form at all.

This change gives the deployment form a key, a default, and a
verifier: `init` provisions a distinct `anchor-secret`; a new
`anchor` command appends signed anchors by default; `_anchored_check`
builds a real verifier from the deployment's anchor secret; and an
anchor file that is present but unsigned — or signed under a key the
deployment does not hold, or unverifiable for want of the secret —
fails `verify` closed with an anchor-specific reason, reported
separately from the audit-chain verdict.

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed:** `ops verify` can no longer ratify unsigned witness
  state. The unsigned-acceptance path that the library leaves to the
  caller's policy is closed in the deployment form: with an anchor
  secret configured, unsigned anchors fail as
  `anchor_signature_missing`; with none configured, an unsigned file
  fails under the named `anchor_unsigned` posture and a signed file as
  `anchor_verifier_unavailable`.
- **Left unchanged:** no surface gains authority over governed
  transitions. The `anchor` command delegates to
  `pulpo.anchor.anchor_records` over a read-only kernel projection; it
  appends nothing to the canonical audit chain, mints nothing, and
  consumes nothing (anchor.py: anchoring is observation, not
  governance). `authority_effect=none`.
- The `anchor-secret` is a new deployment secret, but it is a witness
  key, not an approval or permit credential, and it is deliberately
  distinct from `kernel-secret`: anchor.py's trust separation requires
  the witness key never be the kernel's permit secret.

## 3. Canonical state mutations introduced or exposed

No mutation of canonical state is introduced. Deployment-directory
file effects, all outside the audit chain:

- `anchor-secret` created owner-only (`0600`, `O_EXCL`) by `init`,
  or by the first `anchor` run on a legacy deployment that predates
  it — the provisioning half of the #355 load/provision split. The
  read-only projections (`verify` / `status`) take the load-only half
  for this secret exactly as for the kernel secret: they never create
  or repair it (pinned by tests, including "creates nothing"
  assertions over the full directory listing).
- `anchors.jsonl` appended by the `anchor` command only, through
  `FileAnchorStore`'s locked, extension-checked append.
- One-time migration: a legacy unsigned `anchors.jsonl` is rotated
  byte-for-byte to `anchors.jsonl.legacy-unsigned` by the first
  `anchor` run and the signed history starts at the current head. The
  rotation is operator-attested by running the command, is reported
  in the command output as a migration, and refuses to repeat if the
  preserved file already exists. Signatures attest from the new
  anchor forward, never retroactively.

## 4. Success and adversarial evidence (at the fixed tree)

- Full suite: **723 tests OK, 13 skipped** (715 at base `d0b5ceb` +
  8 new; zero existing tests deleted, weakened, or modified — the
  test-file diff is purely additive).
- Adapted repro (drives the real ops lifecycle; script and output
  held with the PR's working papers): init provisions both secrets →
  governed records → `ops anchor` (signed, record_count 4) →
  `ops verify` ok / `anchored_prefix_verified` → tail truncation
  refused (`anchor_beyond_trail`) → tail truncation **plus wholesale
  anchor-file rewrite refused** (`anchor_signature_missing`,
  `chain_valid` still true — the refusal is the witness layer's and
  is reported as such). Verdict: gap CLOSED on the ops path.
- Control in the same repro: the fabricated file still passes the
  library call with `verifier=None`. The library default did not
  change; this fix is deployment-form wiring, exactly as designed.
- New tests in `tests/test_ops_cli.py` pin: init provisions the
  anchor secret owner-only and distinct from the kernel secret;
  `anchor` signs and `verify` reports anchored coverage, `status`
  reports the last anchor as signed with no warning; the rewrite
  attack fails with `anchor_signature_missing`; a present-but-unsigned
  anchor file fails closed (`anchor_signature_missing`, with
  `status` warning `anchor_unsigned`); anchors signed under a foreign
  key fail (`anchor_signature_invalid`); a legacy deployment with no
  anchor file behaves exactly as before and the projections create
  nothing; signed anchors with the anchor secret deleted fail closed
  (`anchor_verifier_unavailable`) and the projections create nothing;
  the migration rotation preserves the legacy file byte-for-byte,
  provisions the secret, starts a verifying signed history, and
  extends normally on the second run.
- The #355 projection-purity tests (legacy kernel-secret deployments,
  read-only mounts, loose-permission non-repair) pass unmodified over
  the generalized secret helpers.

## 5. Boundary the evidence does not prove

anchor.py's trust scope, carried forward verbatim: anchoring "does
not protect against a writer who can also rewrite the anchor store
and, for signed anchors, holds the anchor key; that writer is outside
this layer's scope." Concretely for this change:

- Both secrets ship in one deployment directory on one host for
  operability (owner's ruling on memo Question 3). Distinct keys make
  separate custody *possible*; the separation is realized only when
  the anchoring job runs under separate process/OS custody. Against a
  host-level writer holding both files, signed anchors are not a
  control, and nothing here claims otherwise.
- The claim earned is narrower and exact: the **single-file writer**
  of the demonstrated attack — who rewrites `state.db` and
  `anchors.jsonl` but holds neither secret — can no longer ratify a
  truncated or rewritten history through the ops form.
- The unanchored tail after the latest anchor, and the honesty of the
  chain before the first anchor, are unchanged and already documented
  in anchor.py. Migration signatures do not reach backward: the
  preserved unsigned file remains unverified state.
- Phase 2 items 1 (audit-record signing), 3 (capability-gated
  handles), and 4 (bearer-token semantics) are untouched and remain
  open on their own records.

## 6. Claim classification

- The Item 2 gap at `d0b5ceb`: **Verified** (design-memo repro,
  executed before this build).
- The fix's effect: **Verified** by the suite and the adapted repro
  re-executed at the fixed tree, as cited in §4.
- Adoption of design 2A and of the anchor-key custody / fail-closed
  postures (memo Question 3): a decision by the repository owner
  (Austin), 2026-11-13 — **Recorded**.
- Everything else in this record: **Verified** at the fixed tree.

## 7. Legacy behavior source

The kernel-secret helpers from PR #355 were generalized in place
(`_read_secret_file` / `_provision_secret_file`, parameterized by
label and size); the kernel pair remain as wrappers with identical
error strings, modes, and `O_EXCL` semantics, and their behavior is
pinned by the unmodified #355 tests. The library anchor API was used
exactly as shipped — no anchor code was copied, forked, or
reimplemented in ops, and no legacy control path was carried into
production code.

## 8. Temporal transfer

Applicable historical checkpoints, exact commits: `7f2a7c9`
(diagnosis Repro B: truncation + unsigned anchor-file rewrite
ratified), `d0b5ceb` (Phase 2 memo repro: the same outcome
re-confirmed on the ops-era tree, and the signed-path controls
passing only when a verifier is manually supplied). The lesson —
"an unsigned witness is state, not provenance; the deployment form
must hold the key, sign by default, and verify for real" — transfers
at the fixed tree for the stated reason: the ops path now refuses
the rewrite because no signature it carries is ratified by the
deployment's anchor key. The lesson does **not** transfer to the
library layer, whose caller-chosen verifier policy is unchanged at
every checkpoint (repro control), and no claim is made for
deployments that never run the ops form. No future authority,
approval, or credential was carried into any historical state; the
replay changed no consequential authority.

## Addendum — 2026-11-13: the migration gate (review finding on PR #356)

### Finding (Verified by independent reproduction at head `9b24f6e`)

The one-time migration in §3 rotated **any** all-unsigned
`anchors.jsonl`, keyed on nothing but the file's own unsignedness. In
a deployment that already held an `anchor-secret` and a signed
witness history, that made the `anchor` command itself the laundering
step of the §1 attack: truncate the audit tail, replace the signed
anchor file with a fabricated unsigned one covering the truncated
head, run `ops anchor` — the fabricated file was rotated to
`anchors.jsonl.legacy-unsigned` as "legacy", a signed anchor over the
truncated head was appended under the deployment's real key, and
`ops verify` returned `ok` / `anchored_prefix_verified`. Reproduced
end-to-end through the real ops lifecycle (script and output held
with the PR's working papers): pre-attack verify
`anchored_prefix_verified`; truncated-with-honest-anchors refused
(`anchor_beyond_trail`); truncated-with-fabricated-anchors refused by
`verify` (`anchor_signature_missing`) — then ratified after the
`anchor` run. Verdict: **Verified**, the claim reproduced exactly as
filed.

### Fix

The rotation is a migration *into* a signed deployment, so it is now
reachable only in the state that defines a legacy deployment: the
deployment holds **no** `anchor-secret`. `_cmd_anchor` decides with
the load-only helper (`_load_anchor_secret`) — the gate itself
creates and repairs nothing, and a malformed secret fails closed at
the gate. The adjacent shapes are decided, not left to drift:

- **Secret present + all-unsigned anchor file** → the `anchor`
  command fails closed (`anchor_unsigned`), leaving both files
  byte-identical. An unsigned file inside a signed deployment is a
  replaced witness, not a pre-wiring artifact.
- **No secret + signed anchor file** (case b) → the command fails
  closed (`anchor_verifier_unavailable`): it cannot verify the
  history it would extend, and provisioning a fresh key there would
  silently re-key the witness. Nothing is provisioned, nothing is
  rotated; the operator restores the key.
- **Partially signed (mixed) file** (case c) → never rotated:
  rotation requires the *whole* file unsigned **and** no secret. A
  mixed file with no secret takes the case-(b) refusal; with the
  secret present it is ordinary (possibly foreign or damaged)
  history, which `verify` adjudicates.
- **Secret present + no anchor file** (case a) → unchanged: the
  command starts the signed history normally; this is not a
  rotation.
- **No secret + all-unsigned file** → the genuine migration is
  unchanged: byte-for-byte rotation, provisioning, signed history
  from the current head (pinned by the pre-existing migration test,
  unmodified).

### Evidence

- The reproduction above re-executed at the fixed tree: the `anchor`
  run now exits non-zero with the `anchor_unsigned` refusal; no
  legacy file is created; the fabricated file and the anchor secret
  are byte-identical after the run; `verify` still fails closed
  (`anchor_signature_missing`). Verdict: attack **Refuted** at the
  fixed tree.
- Three new tests in `tests/test_ops_cli.py` pin the exact attack
  (refusal, files untouched, verify still closed), the
  signed-without-secret refusal (no provisioning, no rotation), and
  the mixed-file rule. The pre-existing migration test passes
  unmodified — the genuine legacy path is a tested behavior, not a
  casualty of the gate.
- Full suite at the fixed tree: **726 tests OK, 13 skipped** (723 +
  3 new; zero existing tests deleted, weakened, or modified).

### Boundary this addendum does not prove

The gate reads witness-key *presence* from the deployment directory.
A writer with whole-directory write access can delete `anchor-secret`
and thereby re-enter the legacy shape — but that writer already
holds the custody this layer's scope statement (§5) places out of
scope, and the maneuver is neither silent nor free: the "migration"
is reported in the command output, and the fabricated file is
preserved byte-for-byte as `anchors.jsonl.legacy-unsigned` rather
than destroyed, so the substitution leaves its own evidence behind.
What the gate closes is the demonstrated single-purpose abuse: a
*replaced anchor file alone*, in an intact signed deployment, can no
longer be ratified by the deployment's own anchor command. Claim
classification: finding and fix **Verified** at the stated trees;
the review finding itself is **Recorded** as filed by the reviewer.
