# Change record — Ed25519 audit signer (dual-era audit verification)

Date: 2026-11-27. Branch: `audit-signer-2026-11-27`, base `b1cea2f`.
Authorization: Austin Irvan, 2026-11-27 ~06:55 MST ("get the audit
signer in scope"), with his explicit proceed on this clone at ~07:07
MST after the clone's execution-risk flag was surfaced to him.

## 1. Invariant / failure addressed

The audit chain's only signer was symmetric HMAC-SHA256
(`AuditSigner`, Phase 2 Item 1). Verification therefore requires the
deployment's audit secret itself: **no publishable verification key
exists**, so no third party can verify a chain without being handed
the very secret whose compromise enables undetectable history
forgery. The `AuditSigner` docstring named this fix in advance
("a future Ed25519 signer can replace this class behind the same
record shape"). This change is that signer.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. The new classes attest audit records; they hold no kernel
capability, mint nothing, and grant nothing. No governed agent gains
any route to a human signing credential: the audit key is deployment
attestation material of the same class as the existing `audit-secret`
(which ops already provisions by generation), not a human credential.
The verification-only half (`Ed25519AuditVerifier`) cannot sign —
its `sign` raises — so publishing or sharing it duplicates no
capability (AUTHORIZATION_TO_USE_CAPABILITY !=
AUTHORIZATION_TO_DUPLICATE_CAPABILITY, checked in the adversarial
pass).

## 3. Canonical state mutations introduced or exposed

None to existing state. The audit record shape is unchanged: the
signature remains a sibling field excluded from the hashed body, in
the same SQLite `signature` TEXT column / in-memory field. The only
format change is in values written *after* a deployment configures
the new signer: Ed25519 signatures are stored tagged
(`ed25519:<128 hex>`) so each record's era is read off its own
signature form. HMAC signatures remain the bare 64-hex they have
always been — **no existing record's bytes change**, and the unkeyed
chain math is untouched. Era is classified by
`audit_signature_algorithm()` in `pulpo/state.py`.

Governed capability boundary: signing/verification stays behind the
existing `AuditSigningKey` seam on the state backends — the same
single audit source, no second ledger, evidence plane, or writer.

## 4. Exact success and adversarial evidence

Baseline at `b1cea2f`: 1166 tests OK (skipped=13). After: see PR
description for the final count (24 new tests in
`tests/test_audit_signing_ed25519.py`, all pre-existing suites green,
including the full HMAC-era suite unmodified).

Success evidence:
- Pure Ed25519 chains (in-memory and SQLite) sign, persist, reopen,
  and verify; the report shape is unchanged.
- A chain verifies **from the public key alone**: a verify-only
  composite built from the published artifact (JSON round-tripped)
  boots a kernel over an Ed25519 chain. Artifact substitution (key
  swapped under a copied fingerprint, wrong algorithm) is refused at
  artifact load.
- Mixed chains verify end to end: unsigned legacy prefix → HMAC →
  Ed25519 (three-era chain), and HMAC → Ed25519 across a SQLite
  close/reopen transition.
- Custody: the signing key saves to a new owner-only (0600) file,
  refuses overwrite, loads back with the same fingerprint.

Adversarial evidence:
- Tampered Ed25519 record (payload edit + honest rehash, stale
  signature) → `audit_signature_invalid`, boot refused.
- Wrong public key → chain refused; wrong private key → SQLite
  reopen boot refused.
- Mid-chain removal in the Ed25519 era still detected after rehash.
- Downgrade refused twice over: a genuinely HMAC-signed record
  appended after the transition fails verification as
  `audit_signature_downgrade` on its era claim alone, whether it is
  spliced in memory or appended through the state layer on disk.
- Wrong-era records refused: an Ed25519-signed record spliced into
  an HMAC segment fails under both an HMAC-only verifier
  (`audit_signature_invalid`) and the dual-era verifier (the
  following HMAC records become downgrades); an HMAC value with the
  `ed25519:` tag glued on fails; a tag-stripped Ed25519 signature
  classifies as no era and verifies under neither.
- A mixed chain under a verifier never configured for the HMAC era
  is refused at the first HMAC record — unconfigured eras are not
  skipped.
- Cross-era signer-level refusal: each era's verifier rejects the
  other era's signature form outright; malformed values (None, "",
  non-string, uppercase, wrong length, bare tag) never verify.

Throwaway-state gate proof (scratch directory only; the live gate
chain was never opened): custody file provisioned at 0600; a
2-record HMAC chain transitioned to Ed25519 (eras
`[hmac-sha256, hmac-sha256, ed25519, ed25519]`, report ok, 4/4
signed); the mixed chain re-verified with the artifact-built
verifier for the Ed25519 segment; a from-genesis Ed25519 chain
verified from the artifact alone with no secret in the process; a
wrong published key refused at boot (`StateIntegrityError`).

## 5. Boundary the evidence does not prove

- Record signing does not bind chain length: tail truncation of an
  Ed25519 chain still verifies, exactly as in the HMAC era (pinned
  by test). Anchors remain that coverage.
- Signing prevents *acceptance* of forgeries at verification/boot;
  it does not prevent a file writer from writing bytes. The state
  layer remains writer-controlled; refusals land at verification,
  as before.
- The live gate flip is NOT in this change: ops still provisions and
  loads only the HMAC signer, and the deployed gate's chain is
  untouched. Wiring `ops` to provision an `audit-ed25519-secret`,
  select the era in deployment config, and transition the live chain
  is the sequenced follow-up after this PR merges (audit-byte
  discipline: the flip is a deliberate operator act, like
  `enable-audit-signing` was for the HMAC era).
- Key rotation/revocation for the Ed25519 audit key is not designed
  here; a transition is one-way (no downgrade), so a compromised
  Ed25519 audit key is a re-genesis event, not a rotation. Recorded
  as an open design item, not silently implied.

## 6. Claim classification

Verified (executable evidence at the branch head): all behavior
claims in §4. Recorded: the authorization and sequencing statements
in the header and §5. Proposed: the ops wiring follow-up in §5.

## 7. Legacy behavior source

The HMAC era's own design (Phase 2, Item 1: signature as a sibling
field over the record hash, enablement recorded outside the state
file, legacy prefix counted in config) is the control path this
change extends; it is reused, not copied — `AuditSigner` is
untouched except a wrong-era guard in its `verify`, and every
pre-existing HMAC test passes unmodified. The Ed25519 verifier
conventions (32-byte raw public key, 128-char lowercase hex
signatures, sha256 key fingerprint) follow `authority.py`'s
`Ed25519ApprovalVerifier` pattern, behind the same lazy
`cryptography` import and the same `pulpo[authority]` extra.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson: the
Ed25519 audit era has no prior canonical state to replay against —
the HMAC enablement (PRs #355/#357) is the nearest analogue and its
behavior is preserved by the unmodified pre-existing suite rather
than by a temporal replay. Recorded explicitly per the repo rule;
no temporal proof is manufactured.
