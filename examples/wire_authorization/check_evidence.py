"""Standalone evidence checker for wire-authorization artifacts.

Run as::

    python -m examples.wire_authorization.check_evidence \
        --state STATE.db --ledger LEDGER.jsonl [--anchors ANCHORS.jsonl] \
        [--principal PRINCIPAL] [--session-id SESSION]

The checker works from the artifacts alone — the kernel's SQLite state
file and the mock rail's JSON-lines ledger. It holds no kernel secret,
no verifier, and no rail handle, and it never evaluates an intent or
consumes a permit: it reads, verifies, and reconciles. Its verdict is a
JSON object ``{ok, failures, transfers_checked, anchored}`` printed to
stdout; the exit code is 0 iff ``ok``.

What it proves, and how:

1. **Audit chain integrity.** The chain is verified by reusing
   ``GovernanceKernel.verify_audit``: a kernel is constructed over the
   loaded ``SQLiteKernelState`` with an inert policy (only
   ``initiate_wire`` allowed, a budget no artifact can exceed) purely as
   a chain verifier. Construction reads and verifies the audit trail and
   issues nothing; the checker makes no ``evaluate``/``consume`` call,
   so the policy's contents cannot mint, deny, or mutate anything.
   (Recomputing the SHA-256 chain locally instead would duplicate the
   kernel's canonicalization in a second implementation — exactly the
   kind of parallel evidence logic this repository avoids.) The state
   file itself is never opened writable: the checker first probes it
   through a read-only SQLite connection and fails files that are not
   kernel state databases at all — an empty file fails as malformed
   rather than being initialized into an empty database whose empty
   trail would vacuously pass — and then verifies a snapshot copy, so
   the artifact under examination is byte-identical after the check.
2. **Every mock transfer was governed.** For each ledger record the
   checker reconstructs the exact intent — action ``initiate_wire``,
   resource ``wire:<payee>`` and ``cost`` from the record, principal and
   session from ``--principal``/``--session-id`` — and requires: the
   record's ``transfer_id`` is the deterministic derivation of the
   reconstructed intent hash; the record is marked as a mock; exactly
   one ``permit_consumed`` audit record carries that intent hash; and
   the intent carries authorization evidence — at least one
   ``approval_verified`` record, OR a complete directive authorization
   chain: a ``directive_activated`` record, a ``permit_bound_to_directive``
   record binding a permit for this intent to that exact directive
   (id, version, hash), and the ``permit_consumed`` record itself
   carrying the same binding with ``directive_status`` ``"active"`` —
   the kernel's consume-time re-check of the live directive. The
   directive path is the service's documented second entry point
   (standing directive, no per-wire approval envelope), so its chain is
   first-class evidence, held to the same exactness: any missing or
   mismatched link fails the transfer.
3. **No phantom effects.** Every ``permit_consumed`` record that is not
   a directive-authority consumption must correspond to exactly one
   ledger transfer. Directive-authority consumptions (activation /
   revocation) are identified from the ``authority_evidence`` intent
   hashes recorded in ``directive_activated`` / ``directive_revoked``
   audit records. This is a closed-world classification, stated plainly:
   within this example the only permit consumptions are wire effects and
   directive-authority operations, so any other consumption is reported
   rather than waved through — the checker fails closed on effects it
   cannot account for.
4. **Anchoring, when available.** ``verify_anchored_audit`` is used only
   if ``pulpo.anchor`` is importable (WS1, sibling PR #352 — not in this
   build) *and* an anchors file is supplied. The verdict's ``anchored``
   field is then the verification boolean; supplying anchors this build
   cannot verify is a failure, not a pass. Without an anchors file,
   ``anchored`` is ``false`` when the anchor module exists (a checkable
   trail that simply was not anchored) and ``"unavailable"`` in this
   build.

Why principal/session are parameters: an intent hash binds principal,
action, resource, cost, and session, but the artifacts store those
fields only inside the hash — the ledger carries payee and amount, the
audit carries hashes. Reconstructing the preimage therefore requires
the deployment's principal and session as inputs; they default to the
reference deployment's illustrative values (``operator:treasury`` /
``default``). A checker run with the wrong principal fails closed with
transfer-id mismatches, which is the intended behavior: reconstruction
is exact or it does not pass.

Boundary: a passing verdict proves the artifacts are mutually
consistent — chain intact, transfers and consumptions in exact
correspondence, approvals present. It does not prove the transfers were
*wise*, that the approver was uncompromised, or that no writer bypassed
every artifact at once; a writer who can rewrite the state file, the
ledger, and (when present) the anchor store in a mutually consistent
way is outside this checker's — and this layer's — scope. Anchoring
(WS1) is the control that narrows exactly that gap.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Any

from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.state import SQLiteKernelState

from .service import EXAMPLE_PRINCIPAL, WIRE_ACTION, WIRE_RESOURCE_PREFIX, transfer_id_for


def _state_schema_failure(state_file: Path) -> str | None:
    """Probe the state file through a READ-ONLY connection.

    Returns ``None`` when the file is a SQLite database carrying the
    kernel's audit table, else a failure description. The connection
    uses SQLite's ``mode=ro`` URI, so probing cannot create schema,
    run migrations, or otherwise mutate the evidence — the mutation
    this guards against is ``SQLiteKernelState`` construction, whose
    ``CREATE TABLE IF NOT EXISTS`` would silently turn an empty or
    legacy file into a populated database before verification.
    """
    try:
        connection = sqlite3.connect(f"{state_file.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return f"state_unreadable: {exc}"
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    except sqlite3.Error as exc:
        return f"state_malformed: {exc}"
    finally:
        connection.close()
    if "audit" not in tables:
        return "state_malformed: no audit table (not a kernel state file)"
    return None


def _directive_authorization_chain(audit: list[dict[str, Any]], digest: str) -> bool:
    """Whether the audit carries a complete directive chain for a digest.

    The chain, in audit order: a ``directive_activated`` record; a
    ``permit_bound_to_directive`` record binding a permit for this
    intent to that exact directive (id, version, hash); and a
    ``permit_consumed`` record for this intent carrying the same
    binding fields with ``directive_status`` ``"active"`` — the
    kernel's record of its consume-time re-check that the directive
    was live when the permit was spent. Every link must match exactly;
    a partial or mismatched chain is not evidence.
    """
    binding_fields = ("directive_id", "directive_version", "directive_hash")
    for consumed_index, record in enumerate(audit):
        payload = record.get("payload") or {}
        if record.get("event") != "permit_consumed" or payload.get("intent_hash") != digest:
            continue
        if payload.get("directive_status") != "active":
            continue
        if any(payload.get(field) is None for field in binding_fields):
            continue
        for bound_index in range(consumed_index):
            bound = audit[bound_index]
            bound_payload = bound.get("payload") or {}
            if bound.get("event") != "permit_bound_to_directive":
                continue
            if bound_payload.get("intent_hash") != digest:
                continue
            if any(bound_payload.get(field) != payload.get(field) for field in binding_fields):
                continue
            for activated in audit[:bound_index]:
                activated_payload = activated.get("payload") or {}
                if activated.get("event") != "directive_activated":
                    continue
                if (
                    activated_payload.get("directive_id") == payload.get("directive_id")
                    and activated_payload.get("version") == payload.get("directive_version")
                    and activated_payload.get("directive_hash") == payload.get("directive_hash")
                ):
                    return True
    return False


def _load_ledger(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ledger line is not valid JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError("ledger line is not a JSON object")
        records.append(record)
    return records


def _reconstructed_hash(record: dict[str, Any], *, principal: str, session_id: str) -> str:
    intent = Intent(
        principal=principal,
        action=WIRE_ACTION,
        resource=f"{WIRE_RESOURCE_PREFIX}{record.get('payee')}",
        cost=record.get("amount_cents"),
        session_id=session_id,
    )
    return GovernanceKernel.intent_hash(intent)


def check(
    state_path: str | Path,
    ledger_path: str | Path,
    anchors_path: str | Path | None = None,
    *,
    principal: str = EXAMPLE_PRINCIPAL,
    session_id: str = "default",
) -> dict[str, Any]:
    """Reconcile one state/ledger artifact pair; return the verdict dict."""
    failures: list[str] = []
    state_file = Path(state_path)
    ledger_file = Path(ledger_path)

    transfers: list[dict[str, Any]] = []
    if not ledger_file.exists():
        failures.append(f"ledger_not_found: {ledger_file}")
    else:
        try:
            transfers = _load_ledger(ledger_file)
        except ValueError as exc:
            failures.append(f"ledger_malformed: {exc}")

    audit: list[dict[str, Any]] = []
    if not state_file.exists():
        failures.append(f"state_not_found: {state_file}")
    else:
        schema_failure = _state_schema_failure(state_file)
        if schema_failure is not None:
            failures.append(schema_failure)
        else:
            # Verify a snapshot copy: SQLiteKernelState construction
            # runs CREATE TABLE IF NOT EXISTS and migrations, which is
            # initialization the artifact under examination must never
            # receive. The copy absorbs it; the original is only ever
            # read (probe above, copy here).
            with tempfile.TemporaryDirectory() as snapshot_dir:
                snapshot = Path(snapshot_dir) / state_file.name
                shutil.copyfile(state_file, snapshot)
                wal_sidecar = state_file.with_name(state_file.name + "-wal")
                if wal_sidecar.exists():
                    shutil.copyfile(
                        wal_sidecar, Path(snapshot_dir) / (state_file.name + "-wal")
                    )
                state = SQLiteKernelState(snapshot)
                try:
                    try:
                        audit = state.audit
                        verifier_kernel = GovernanceKernel(
                            Policy(
                                allowed_actions=frozenset({WIRE_ACTION}),
                                max_cost=10**18,
                            ),
                            state=state,
                        )
                        if not verifier_kernel.verify_audit():
                            failures.append("audit_chain_invalid")
                    except Exception as exc:  # kernel construction itself verifies the chain
                        failures.append(f"audit_chain_invalid: {exc}")
                finally:
                    state.close()

    def payloads(event: str) -> list[dict[str, Any]]:
        return [record["payload"] for record in audit if record.get("event") == event]

    consumed = payloads("permit_consumed")
    verified = payloads("approval_verified")
    directive_authority_hashes = {
        record["payload"].get("authority_evidence", {}).get("intent_hash")
        for record in audit
        if record.get("event") in ("directive_activated", "directive_revoked")
    }

    reconstructed: list[str] = []
    for index, record in enumerate(transfers):
        label = f"transfer[{index}]"
        try:
            digest = _reconstructed_hash(record, principal=principal, session_id=session_id)
        except Exception as exc:
            failures.append(f"{label}: intent reconstruction failed: {exc}")
            continue
        reconstructed.append(digest)
        if record.get("transfer_id") != transfer_id_for(digest):
            failures.append(
                f"{label}: transfer_id {record.get('transfer_id')!r} does not match "
                f"the derivation from its reconstructed intent hash"
            )
        if record.get("rail") != "MOCK-NO-REAL-FUNDS" or record.get("mock") is not True:
            failures.append(f"{label}: transfer is not marked as a mock")
        consumed_count = sum(1 for payload in consumed if payload.get("intent_hash") == digest)
        if consumed_count != 1:
            failures.append(
                f"{label}: expected exactly one permit_consumed for its intent hash, "
                f"found {consumed_count}"
            )
        verified_count = sum(1 for payload in verified if payload.get("intent_hash") == digest)
        if verified_count < 1 and not _directive_authorization_chain(audit, digest):
            failures.append(
                f"{label}: no approval_verified record and no complete "
                f"directive authorization chain for its intent hash"
            )

    for payload in consumed:
        digest = payload.get("intent_hash")
        if digest in directive_authority_hashes:
            continue
        matches = sum(1 for candidate in reconstructed if candidate == digest)
        if matches != 1:
            failures.append(
                f"permit_consumed for intent_hash {digest} has {matches} ledger "
                f"transfers (expected exactly one): phantom or unmatched effect"
            )

    anchored: bool | str
    try:
        from pulpo.anchor import FileAnchorStore, verify_anchored_audit

        anchor_available = True
    except ImportError:
        anchor_available = False
    if anchors_path is None:
        anchored = False if anchor_available else "unavailable"
    elif not anchor_available:
        anchored = "unavailable"
        failures.append("anchors supplied but anchor verification is unavailable in this build")
    else:
        try:
            anchors = FileAnchorStore(anchors_path).anchors()
            result = verify_anchored_audit(audit, anchors)
            anchored = bool(result.ok)
            if not result.ok:
                failures.append(f"anchor_verification_failed: {result.reason}")
        except Exception as exc:
            anchored = False
            failures.append(f"anchor_verification_failed: {exc}")

    return {
        "ok": not failures,
        "failures": failures,
        "transfers_checked": len(transfers),
        "anchored": anchored,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_evidence",
        description="Reconcile wire-authorization artifacts (kernel audit vs mock rail ledger).",
    )
    parser.add_argument("--state", required=True, help="SQLite kernel state file")
    parser.add_argument("--ledger", required=True, help="mock rail JSON-lines ledger")
    parser.add_argument("--anchors", default=None, help="optional WS1 anchor JSON-lines file")
    parser.add_argument("--principal", default=EXAMPLE_PRINCIPAL, help="wire principal used for intent reconstruction")
    parser.add_argument("--session-id", default="default", help="wire session used for intent reconstruction")
    args = parser.parse_args(argv)
    verdict = check(
        args.state,
        args.ledger,
        args.anchors,
        principal=args.principal,
        session_id=args.session_id,
    )
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
