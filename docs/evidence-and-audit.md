# Evidence and audit: verifying a Pulpo decision record offline

Every Pulpo decision — allow, deny, approval-required, consumption,
refusal — is appended to the kernel's audit chain at the moment it is
made. This document describes that record as the code at this commit
actually implements it, and how a third party verifies it **offline**:
no call to the vendor, no account, no live kernel on the write path.

**Claim classification: Verified** for the mechanisms below, as
implemented in `pulpo/kernel.py`, `pulpo/state.py`, and
`pulpo/anchor.py` and exercised by `tests/test_evidence_verification.py`
and `tests/test_audit_signing.py` — except the well-known key location
in the last section, which is **Proposed and not implemented**, and is
labeled as such there.

## The record

Each audit record is a JSON object with these fields:

| Field | Meaning |
|---|---|
| `event` | What happened: `decision`, `permit_consumed`, `permit_rejected`, `approval_verified`, `permit_bound_to_directive`, and others (directive, target, and lease lifecycles have their own events). |
| `payload` | The event's facts. A `decision` payload is `{outcome, reason, intent_hash}`; consumption and rejection payloads carry the `intent_hash` and, for rejections, the specific `reason` (`permit_expired`, `permit_intent_mismatch`, `permit_signature_invalid`, presenter-binding reasons, …). |
| `previous_hash` | The previous record's `hash` — the chain link. The first record's is 64 zero characters. |
| `timestamp_ns` | Append time, nanoseconds, from the kernel's clock. |
| `hash` | SHA-256 of the record's canonical body (below). |
| `signature` | Present only in signed deployments (below). A sibling of `hash`, never part of the hashed body. |

The hashed body is every field except `hash` and `signature`,
serialized as canonical JSON (keys sorted, `,`/`:` separators — the
same encoder the kernel uses everywhere) and hashed with SHA-256.
Because each body commits to the previous record's hash, editing any
record, deleting a mid-chain record, or reordering records breaks
every recomputation from that point on.

The `intent_hash` in decision payloads is the SHA-256 of the canonical
intent — principal, action, resource, cost, session — so a record
binds the *exact* act that was decided. The chain stores the hash, not
the intent itself: saying which act a record concerns requires the
intent fields, which the caller (or the deployment's own logs) must
supply. Verification of a hash is exact or it fails; there is no
approximate matching.

**Refusals are records too.** A denied evaluation appends its
`decision`; a refused consumption appends `permit_rejected` with the
reason. The evidence trail therefore accounts for attempts that did
*not* execute, not only for successes — an auditor reconciling effects
against this chain treats a consumption with no matching effect, and
an effect with no matching consumption, as findings in both
directions (the worked example is
`examples/wire_authorization/check_evidence.py`).

## Signing: what exists today, stated plainly

A deployment may enable audit signing (`AuditSigner` in
`pulpo/state.py`). Each appended record then carries an
**HMAC-SHA256** signature over its `hash`, keyed by a dedicated
per-deployment *audit secret* — deliberately not the kernel secret, so
one theft does not yield both permit minting and undetectable history
forgery. `GovernanceKernel.verify_audit_report()` reports the
coverage: `signing_enabled`, and per-chain counts of signed, unsigned,
and legacy (pre-enablement) records. A record at or after the legacy
prefix that is missing its signature fails verification, as does a
present-but-wrong one.

The honest limit: **HMAC is symmetric. There is no public verification
key for audit signatures today, and none can be published** — the
verification key *is* the signing secret. The record shape is
algorithm-agile (the signature is a sibling field, excluded from the
chain math), and the state module's own docstring names an asymmetric
(Ed25519) signer as the future replacement behind the same shape —
but that signer does not exist in this codebase yet. What this means
for third parties:

- The **hash chain is publicly verifiable by anyone** holding the
  records — it is unkeyed (Snippet 2 below).
- **Signature verification requires the deployment's audit secret.**
  A verifier kernel constructed *without* the signer over a signed
  chain does not ignore the signatures — it fails closed
  (`audit_signature_invalid`), because a signature that cannot be
  checked is treated as an anomaly, not as decoration. Deployments
  that want third-party signature checks today must share the secret
  under their own custody decision, or share anchors (below).
- Anchors (`pulpo/anchor.py`) are the external-witness mechanism:
  an anchor pins the chain's head hash and record count in a store
  outside the kernel, closing the two gaps the chain alone cannot —
  tail truncation and delete-and-rehash — relative to the anchor
  history the verifier holds. `verify_anchored_audit` checks that
  history and every anchor's prefix against the presented records,
  offline. Anchor signing at this commit is also HMAC
  (`HmacAnchorSigner`), so signed-anchor verification has the same
  shared-secret property; the anchors' `(record_count, head_hash)`
  commitments themselves are checkable without any key.

## Offline verification

### Snippet 1 — verify a deployment's state file (kernel's own math)

The endorsed pattern (also used by
`examples/wire_authorization/check_evidence.py`): verify a **snapshot
copy**, through a verifier kernel with an inert policy, so the
artifact is never opened writable and the chain math is the kernel's
own rather than a second implementation. For an unsigned deployment
this needs no key of any kind.

The snapshot is taken with SQLite's **backup API**, not by copying
the database file. A deployment running SQLite in WAL mode can hold
committed audit records only in the `state.db-wal` sidecar, not yet
checkpointed into the main file; copying the main file alone would
produce a snapshot missing those records — and a truncated chain
verifies on its own internal terms, potentially as a valid
zero-record chain. The backup API reads through the source
connection, so the snapshot is one consistent database that includes
committed WAL contents, taken correctly even while the deployment's
writer connection is still open.

```python
import sqlite3, tempfile
from pathlib import Path
from pulpo import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState

def verify_state_file(state_path, *, audit_signer=None):
    with tempfile.TemporaryDirectory() as snapshot_dir:
        snapshot = Path(snapshot_dir) / "state.db"
        source = sqlite3.connect(
            f"{Path(state_path).resolve().as_uri()}?mode=ro", uri=True)
        try:
            destination = sqlite3.connect(snapshot)
            try:
                source.backup(destination)
            finally:
                destination.close()
        finally:
            source.close()
        state = SQLiteKernelState(snapshot, audit_signer=audit_signer,
                                  migrate_schema=False)
        try:
            kernel = GovernanceKernel(
                Policy(allowed_actions=frozenset({"verify"}), max_cost=0),
                state=state,
            )
            return kernel.verify_audit_report()
        finally:
            state.close()
```

Kernel construction itself verifies the chain and raises
`StateIntegrityError` on an invalid one — that raise *is* the negative
verdict. For a signed deployment, pass the deployment's
`AuditSigner` as `audit_signer`; without it (or with the wrong secret)
construction fails closed, as described above.

### Snippet 2 — recompute the chain from exported records

When all you hold is the records themselves (a JSON export), the
unkeyed chain can be recomputed directly. This is the only keyless
check available against a *signed* deployment's export, and its
boundary is exact: it proves the records shown are internally
consistent — untampered since their hashes were computed — and it
proves nothing about their signatures or about records you were not
shown.

```python
import json
from hashlib import sha256

def verify_exported_records(records):
    previous = "0" * 64
    for record in records:
        body = {k: v for k, v in record.items() if k not in ("hash", "signature")}
        if body.get("previous_hash") != previous:
            return False
        expected = sha256(json.dumps(body, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()
        if expected != record.get("hash"):
            return False
        previous = record["hash"]
    return True
```

Both snippets are executed, in this form, by
`tests/test_evidence_verification.py` — including the negative cases:
a tampered payload fails both; a removed mid-chain record fails
recomputation; a signed chain verified with the wrong secret, or with
no signer, fails closed.

## What verification does not prove

- **Completeness.** A shortened chain is internally consistent.
  Only anchors held independently of the audit store speak to whether
  the records shown are *all* the records, and only up to the latest
  anchor's coverage.
- **Wisdom.** Verification proves a decision was made and recorded as
  shown — not that it should have been made, nor that the approver
  was uncompromised.
- **Anything against a writer who holds everything.** A writer who
  can rewrite the audit store *and* the anchor store *and* holds the
  relevant secrets can produce a consistent forgery. That writer is
  outside this layer's scope; custody separation is what keeps such a
  writer from existing.

## Well-known verification-key location — Proposed, not implemented

Specified here so a future implementation has a fixed target:

```
https://<deployment-host>/.well-known/pulpo-evidence.json
```

intended to carry the deployment's audit algorithm, signer algorithm,
**public** verification key (once an asymmetric audit signer exists),
and anchor-store location.

**Status: this document is not served or consumed by any code in this
repository today, and there is no public key to put in it** — the
audit signer is symmetric HMAC (above). Treat any
`pulpo-evidence.json` found in the wild as unverified decoration, and
treat its absence as no evidence either way. Verification today is
Snippets 1 and 2 and, where a deployment shares them, anchors.
