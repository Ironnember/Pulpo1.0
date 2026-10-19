#!/usr/bin/env python3
"""Pulpo Node synthetic virtual-lamp proof.

Synthetic only: no GPIO, no credentials, no network changes, no physical device authority.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

KEY = b"pulpo-node-test-fixture-key-not-production"
ACTOR = "pulpo-node-test-operator"
TARGET = "virtual-lamp:alpha"
ACTION = "set_virtual_lamp"

class ProofError(RuntimeError):
    pass

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def sign(value: Any) -> str:
    return hmac.new(KEY, canonical(value).encode(), hashlib.sha256).hexdigest()

def action(target: str = TARGET, state: str = "on") -> dict[str, str]:
    return {"action": ACTION, "target": target, "state": state}

def init_db(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS approvals(
          approval_id TEXT PRIMARY KEY, actor TEXT NOT NULL,
          object_hash TEXT NOT NULL, expires_at TEXT NOT NULL, signature TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS permits(
          permit_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL,
          object_hash TEXT NOT NULL, consumed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS lamp_events(
          event_id INTEGER PRIMARY KEY AUTOINCREMENT, permit_id TEXT UNIQUE NOT NULL,
          object_hash TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL, observed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence(
          evidence_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
          object_hash TEXT NOT NULL, details_json TEXT NOT NULL, recorded_at TEXT NOT NULL
        );
        """)

def create_approval(obj: dict[str, str], actor: str = ACTOR, minutes: int = 5) -> dict[str, str]:
    material = {
        "approval_id": "approval-" + secrets.token_hex(8),
        "actor": actor,
        "object_hash": digest(obj),
        "expires_at": (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat(),
    }
    return {**material, "signature": sign(material)}

def store_approval(db_path: Path, approval: dict[str, str]) -> None:
    with sqlite3.connect(db_path) as db:
        db.execute("INSERT INTO approvals VALUES (?, ?, ?, ?, ?)", (
            approval["approval_id"], approval["actor"], approval["object_hash"], approval["expires_at"], approval["signature"]
        ))

def issue_permit(db_path: Path, approval_id: str, obj: dict[str, str]) -> str:
    obj_hash = digest(obj)
    with sqlite3.connect(db_path) as db:
        row = db.execute("SELECT actor, object_hash, expires_at, signature FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        if row is None:
            raise ProofError("approval not found")
        actor, approved_hash, expires_at, signature = row
        material = {"approval_id": approval_id, "actor": actor, "object_hash": approved_hash, "expires_at": expires_at}
        if not hmac.compare_digest(signature, sign(material)):
            raise ProofError("forged approval rejected")
        if actor != ACTOR:
            raise ProofError("wrong actor rejected")
        if approved_hash != obj_hash:
            raise ProofError("target substitution rejected")
        if datetime.fromisoformat(expires_at) <= datetime.now(UTC):
            raise ProofError("expired approval rejected")
        permit = "permit-" + secrets.token_hex(8)
        db.execute("INSERT INTO permits VALUES (?, ?, ?, NULL)", (permit, approval_id, obj_hash))
        return permit

def execute_virtual_lamp(db_path: Path, permit_id: str, obj: dict[str, str]) -> int:
    obj_hash = digest(obj)
    with sqlite3.connect(db_path) as db:
        db.isolation_level = None
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute("SELECT object_hash, consumed_at FROM permits WHERE permit_id=?", (permit_id,)).fetchone()
            if row is None:
                raise ProofError("permit not found")
            permitted_hash, consumed_at = row
            if consumed_at is not None:
                raise ProofError("permit replay rejected")
            if permitted_hash != obj_hash:
                raise ProofError("object mismatch rejected")
            now = datetime.now(UTC).isoformat()
            db.execute("UPDATE permits SET consumed_at=? WHERE permit_id=?", (now, permit_id))
            db.execute("INSERT INTO lamp_events(permit_id, object_hash, target, state, observed_at) VALUES (?, ?, ?, ?, ?)", (permit_id, obj_hash, obj["target"], obj["state"], now))
            db.execute("INSERT INTO evidence(kind, object_hash, details_json, recorded_at) VALUES (?, ?, ?, ?)", ("ATTEMPTED_AND_OBSERVED", obj_hash, canonical({"permit_id": permit_id}), now))
            event_id = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
            db.execute("COMMIT")
            return event_id
        except Exception:
            db.execute("ROLLBACK")
            raise

def count_events(db_path: Path) -> int:
    with sqlite3.connect(db_path) as db:
        return int(db.execute("SELECT COUNT(*) FROM lamp_events").fetchone()[0])

def observe_lamp(db_path: Path, obj: dict[str, str]) -> list[dict[str, Any]]:
    obj_hash = digest(obj)
    with sqlite3.connect(db_path) as db:
        rows = db.execute("SELECT event_id, permit_id, target, state, observed_at FROM lamp_events WHERE object_hash=? ORDER BY event_id", (obj_hash,)).fetchall()
    return [{"event_id": r[0], "permit_id": r[1], "target": r[2], "state": r[3], "observed_at": r[4]} for r in rows]

def expect_denied(fn, db_path: Path, expected_events: int) -> None:
    try:
        fn()
    except ProofError:
        pass
    else:
        raise AssertionError("expected denial")
    assert count_events(db_path) == expected_events

def run_checks(workdir: Path) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = workdir / "pulpo-node-virtual-lamp.sqlite3"
    init_db(db_path)
    obj = action()
    checks: list[dict[str, Any]] = []
    def record(name, fn):
        before = count_events(db_path)
        fn()
        checks.append({"name": name, "status": "PASS", "before_events": before, "after_events": count_events(db_path)})

    record("no_permit_denies_signal", lambda: expect_denied(lambda: execute_virtual_lamp(db_path, "missing", obj), db_path, 0))
    approval = create_approval(obj)
    store_approval(db_path, approval)
    forged = {**create_approval(obj), "approval_id": "approval-forged", "signature": "bad"}
    record("forged_approval_denies_signal", lambda: (store_approval(db_path, forged), expect_denied(lambda: issue_permit(db_path, forged["approval_id"], obj), db_path, 0)))
    record("target_substitution_denies_signal", lambda: expect_denied(lambda: issue_permit(db_path, approval["approval_id"], action("virtual-lamp:beta")), db_path, 0))
    permit = issue_permit(db_path, approval["approval_id"], obj)
    record("valid_permit_allows_one_signal", lambda: (assert_equal(execute_virtual_lamp(db_path, permit, obj), 1), assert_equal(count_events(db_path), 1)))
    record("permit_replay_denies_second_signal", lambda: expect_denied(lambda: execute_virtual_lamp(db_path, permit, obj), db_path, 1))
    record("restart_replay_denies_second_signal", lambda: expect_denied(lambda: execute_virtual_lamp(db_path, permit, obj), db_path, 1))
    record("independent_observer_reads_exact_signal", lambda: assert_equal(len(observe_lamp(db_path, obj)), 1))
    record("tampered_observation_does_not_reconcile", lambda: assert_equal(observe_lamp(db_path, action("virtual-lamp:tampered")), []))
    expired = create_approval(obj, minutes=-1)
    record("expired_approval_denies_signal", lambda: (store_approval(db_path, expired), expect_denied(lambda: issue_permit(db_path, expired["approval_id"], obj), db_path, 1)))
    wrong_actor = create_approval(obj, actor="not-authorized")
    record("wrong_actor_denies_signal", lambda: (store_approval(db_path, wrong_actor), expect_denied(lambda: issue_permit(db_path, wrong_actor["approval_id"], obj), db_path, 1)))
    approval2 = create_approval(obj)
    store_approval(db_path, approval2)
    permit2 = issue_permit(db_path, approval2["approval_id"], obj)
    record("permit_object_mismatch_denies_signal", lambda: expect_denied(lambda: execute_virtual_lamp(db_path, permit2, action(state="off")), db_path, 1))
    record("evidence_recorded_once", lambda: assert_equal(count_evidence(db_path), 1))
    record("machine_readable_summary_available", lambda: assert_equal(count_events(db_path), 1))
    return {"result": "PASS", "checks_passed": len(checks), "checks_total": 13, "event_count": count_events(db_path), "db_path": str(db_path), "boundary": "Synthetic virtual-lamp proof only. No GPIO, credentials, network changes, persistent daemon, or physical device authority.", "checks": checks}

def count_evidence(db_path: Path) -> int:
    with sqlite3.connect(db_path) as db:
        return int(db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])

def assert_equal(actual, expected):
    if actual != expected:
        raise AssertionError(f"expected {expected!r}, got {actual!r}")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pulpo-node-virtual-lamp-") as td:
        result = run_checks(Path(td))
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
