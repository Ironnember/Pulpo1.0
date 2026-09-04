#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState
from pulpo.custody import SQLiteGovernanceCustody

SOURCE_MAIN = "1ee8485c4599ad3266c8e90c5baad29309bc700c"
SOURCE_BENCHMARK_HEAD = "f9242eb67fe46eb201281e54f692a0cdc2d3b840"
ATTACK_VECTOR_SHA256 = "ff3edebf38171f5d0eb2b8bf0b9132fff89fb8272a9a27446c0bfb5b398d1c9e"
STAGE_B_RESULT_HASH = "3cbc11a19fd3d27f7a56a18f01ca02715b27849627dd35f752ec1a8f3952f79a"
PROJECT_REF = "jvqryaqkhdnasowxycns"
SCHEMA = "pulpo_stage_c"
TABLE = "pulpo_stage_c.effects"

SECRET_ENV_NAMES = (
    "PULPO_STAGEC_EXECUTOR_DSN",
    "PULPO_STAGEC_OBSERVER_DSN",
    "PULPO_STAGEC_CLEANUP_DSN",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSERVICE",
    "PGSERVICEFILE",
)

ATTACKS = (
    (
        "F01_target_substitution",
        "tests.test_constitutional_sequences.ConstitutionalSequenceTests."
        "test_randomized_sqlite_sequence_preserves_constitutional_invariants",
    ),
    (
        "F02_permit_replay",
        "tests.test_directives.DirectiveProofTests."
        "test_active_directive_bound_permit_consumes_once_with_identity_evidence",
    ),
    (
        "F03_execution_time_revocation",
        "tests.test_directives.DirectiveProofTests."
        "test_revoked_directive_invalidates_previously_issued_permit",
    ),
    (
        "F04_approval_expiry",
        "tests.test_authority.VerifiedApprovalTests."
        "test_session_and_time_are_not_caller_controlled",
    ),
    (
        "F05_budget_authority_inflation",
        "tests.test_directives.DirectiveProofTests."
        "test_model_summary_or_retrieval_score_cannot_raise_authority",
    ),
    (
        "F06_model_self_authority",
        "tests.test_directives.DirectiveProofTests."
        "test_chat_or_retrieval_cannot_create_authority",
    ),
    (
        "F07_two_worker_race",
        "tests.test_custody.CustodyProofTests."
        "test_two_workers_racing_same_head_yield_one_authorization",
    ),
    (
        "F08_false_executor_success",
        "tests.test_custody.CustodyProofTests."
        "test_worker_cannot_claim_reconciled_success_without_observer_evidence",
    ),
    (
        "F09_rollback_restart",
        "tests.test_directives.DirectiveProofTests."
        "test_preissued_permit_stays_invalid_after_revocation_and_restart",
    ),
    (
        "F10_authority_time_unavailable",
        "tests.test_authority.VerifiedApprovalTests."
        "test_clock_failure_and_rollback_fail_closed_with_evidence",
    ),
)

CALIBRATION_ROW = {
    "effect_id": "stage-c-calibration-001",
    "payload": "observer-calibration-v1",
    "source_main": SOURCE_MAIN,
    "attack_vector_sha256": ATTACK_VECTOR_SHA256,
}
MATCHED_ROW = {
    "effect_id": "stage-c-proof-001",
    "payload": "authorized-consequence-v1",
    "source_main": SOURCE_MAIN,
    "attack_vector_sha256": ATTACK_VECTOR_SHA256,
}
MATCHED_ROW_SHA256 = "d108b7f364364ca69838eb69f58113e1cb6104498bfebef010fec00bd6c239db"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def run_one(case_id: str, dotted_test: str) -> dict[str, object]:
    suite = unittest.defaultTestLoader.loadTestsFromName(dotted_test)
    result = unittest.TestResult()
    suite.run(result)
    passed = result.testsRun == 1 and not result.failures and not result.errors
    return {
        "case_id": case_id,
        "test": dotted_test,
        "tests_run": result.testsRun,
        "exercised": result.testsRun == 1,
        "software_boundary_holds": passed,
        "failures": [text for _, text in result.failures],
        "errors": [text for _, text in result.errors],
    }


def run_attack_suite_local() -> dict[str, object]:
    attacks = [run_one(*case) for case in ATTACKS]
    leaked = sorted(name for name in SECRET_ENV_NAMES if os.environ.get(name))
    bundle = {
        "source_main": SOURCE_MAIN,
        "source_benchmark_head": SOURCE_BENCHMARK_HEAD,
        "attack_vector_sha256": ATTACK_VECTOR_SHA256,
        "attacks": attacks,
    }
    return {
        **bundle,
        "complete_execution_coverage": all(item["exercised"] for item in attacks),
        "software_boundary_failures": sum(not item["software_boundary_holds"] for item in attacks),
        "execution_bundle_sha256": canonical_hash(bundle),
        "credential_environment_names_present": leaked,
        "credential_environment_isolated": not leaked,
    }


def sanitized_child_env() -> dict[str, str]:
    blocked = set(SECRET_ENV_NAMES)
    return {key: value for key, value in os.environ.items() if key not in blocked}


def run_attack_suite() -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--attack-child"],
        env=sanitized_child_env(),
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def source_main_is_ancestor() -> bool:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", SOURCE_MAIN, "HEAD"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def pg_env(dsn: str) -> dict[str, str]:
    parsed = urlsplit(dsn)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ValueError("DSN must use postgres:// or postgresql://")
    if not parsed.hostname or parsed.username is None or parsed.password is None:
        raise ValueError("DSN must include host, username, and password")
    query = parse_qs(parsed.query)
    env = sanitized_child_env()
    env.update(
        PGHOST=parsed.hostname,
        PGPORT=str(parsed.port or 5432),
        PGDATABASE=unquote(parsed.path.lstrip("/")) or "postgres",
        PGUSER=unquote(parsed.username),
        PGPASSWORD=unquote(parsed.password),
        PGSSLMODE=query.get("sslmode", ["require"])[0],
        PGCONNECT_TIMEOUT="8",
    )
    return env


def psql(dsn: str, sql: str) -> str:
    completed = subprocess.run(
        ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", sql],
        env=pg_env(dsn),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def identity(dsn: str) -> dict[str, str]:
    raw = psql(dsn, "select current_user || E'\\t' || session_user;")
    parts = raw.split("\t")
    if len(parts) != 2:
        raise RuntimeError("unexpected identity result")
    return {"current_user": parts[0], "session_user": parts[1]}


def wal_lsn(dsn: str) -> str:
    return psql(dsn, "select pg_current_wal_lsn()::text;")


def observed_rows(dsn: str) -> list[dict[str, object]]:
    raw = psql(
        dsn,
        f"""
select coalesce(json_agg(row_to_json(x) order by x.provider_row_id), '[]'::json)::text
from (
  select provider_row_id, effect_id, payload, source_main, attack_vector_sha256
  from {TABLE}
  order by provider_row_id
) x;
""",
    )
    return json.loads(raw or "[]")


def row_projection(row: dict[str, object]) -> dict[str, str]:
    return {
        "attack_vector_sha256": str(row["attack_vector_sha256"]),
        "effect_id": str(row["effect_id"]),
        "payload": str(row["payload"]),
        "source_main": str(row["source_main"]),
    }


def insert_row(dsn: str, row: dict[str, str]) -> None:
    values = ",".join(
        sql_literal(row[key])
        for key in ("effect_id", "payload", "source_main", "attack_vector_sha256")
    )
    psql(
        dsn,
        f"insert into {TABLE}(effect_id,payload,source_main,attack_vector_sha256) "
        f"values ({values});",
    )


def cleanup_row(dsn: str, effect_id: str) -> None:
    psql(dsn, f"delete from {TABLE} where effect_id={sql_literal(effect_id)};")


def verify_privileges(
    executor_dsn: str,
    observer_dsn: str,
    cleanup_dsn: str,
) -> dict[str, list[str]]:
    executor = psql(
        executor_dsn,
        f"select concat_ws(',',"
        f"has_schema_privilege(current_user,{sql_literal(SCHEMA)},'USAGE'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'SELECT'),"
        f"has_column_privilege(current_user,{sql_literal(TABLE)},'effect_id','INSERT'),"
        f"has_column_privilege(current_user,{sql_literal(TABLE)},'payload','INSERT'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'UPDATE'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'DELETE'));",
    ).split(",")
    observer = psql(
        observer_dsn,
        f"select concat_ws(',',"
        f"has_schema_privilege(current_user,{sql_literal(SCHEMA)},'USAGE'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'SELECT'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'INSERT'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'UPDATE'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'DELETE'));",
    ).split(",")
    cleanup = psql(
        cleanup_dsn,
        f"select concat_ws(',',"
        f"has_schema_privilege(current_user,{sql_literal(SCHEMA)},'USAGE'),"
        f"has_column_privilege(current_user,{sql_literal(TABLE)},'effect_id','SELECT'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'DELETE'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'INSERT'),"
        f"has_table_privilege(current_user,{sql_literal(TABLE)},'UPDATE'));",
    ).split(",")
    result = {"executor": executor, "observer": observer, "cleanup": cleanup}
    expected = {
        "executor": ["t", "f", "t", "t", "f", "f"],
        "observer": ["t", "t", "f", "f", "f"],
        "cleanup": ["t", "t", "t", "f", "f"],
    }
    if result != expected:
        raise RuntimeError(f"provider privilege split mismatch: {result}")
    return result


def provider_action_object(action: str, row: dict[str, str]) -> dict[str, object]:
    return {
        "schema": "pulpo.stage-c.provider-action.v0",
        "provider": "supabase_postgres",
        "project_ref": PROJECT_REF,
        "table": TABLE,
        "action": action,
        "row": row,
    }


def governed_provider_action(
    kernel: GovernanceKernel,
    custody: SQLiteGovernanceCustody,
    *,
    action: str,
    row: dict[str, str],
    principal: str,
    executor_id: str,
    provider_request_id: str,
    provider_call,
    observe,
) -> dict[str, object]:
    action_object = provider_action_object(action, row)
    object_hash = canonical_hash(action_object)
    intent = Intent(
        principal,
        action,
        f"supabase:{PROJECT_REF}:{TABLE}:{action}:{object_hash}",
        0,
        "stage-c-supabase-v0",
    )
    target_id = f"stage-c:{action}:{object_hash[:16]}"
    target = kernel.lock_target(target_id, intent)
    decision = kernel.evaluate(intent)
    if decision.outcome != "allow" or not decision.permit:
        raise RuntimeError(
            f"canonical Stage-C action was not authorized: "
            f"{decision.outcome}:{decision.reason}"
        )
    resolution = kernel.resolve_locked_target(target_id, target.target_hash)
    if (
        resolution.outcome != "match"
        or resolution.target is None
        or resolution.target.intent != intent
    ):
        raise RuntimeError(f"canonical Stage-C target mismatch: {resolution.reason}")
    if not kernel.consume(decision.permit, intent):
        raise RuntimeError("canonical Stage-C permit consumption failed")

    audit_tip = kernel.audit[-1]["hash"]
    permit_hash = hashlib.sha256(decision.permit.encode()).hexdigest()
    authorization_hash = canonical_hash(
        {
            "schema": "pulpo.stage-c.custody-authorization.v0",
            "object_hash": object_hash,
            "target_hash": target.target_hash,
            "intent_hash": decision.intent_hash,
            "policy_hash": kernel.policy_hash,
            "permit_hash": permit_hash,
            "canonical_audit_tip": audit_tip,
        }
    )

    head = custody.snapshot()
    authorized = custody.authorize_attempt(
        expected_epoch=head.epoch,
        expected_state_root=head.state_root,
        object_hash=object_hash,
        target_hash=target.target_hash,
        permit_hash=permit_hash,
        authorization_hash=authorization_hash,
    )
    head = custody.snapshot()
    claimed = custody.claim_attempt(
        expected_epoch=head.epoch,
        expected_state_root=head.state_root,
        attempt_id=authorized.attempt_id,
        executor_id=executor_id,
    )
    head = custody.snapshot()
    transmission = custody.authorize_transmission(
        expected_epoch=head.epoch,
        expected_state_root=head.state_root,
        attempt_id=authorized.attempt_id,
        provider_request_id=provider_request_id,
    )

    try:
        provider_call()
        provider_claim = {"status": "claimed_success", "authoritative": False}
    except Exception as exc:
        provider_claim = {
            "status": "unknown",
            "authoritative": False,
            "error_type": exc.__class__.__name__,
        }

    head = custody.snapshot()
    reconciliation_required = custody.require_reconciliation(
        expected_epoch=head.epoch,
        expected_state_root=head.state_root,
        attempt_id=authorized.attempt_id,
    )
    observation = observe()
    observation_hash = canonical_hash(observation)
    outcome = str(observation.get("outcome", "unresolved"))
    if outcome not in {"success", "failure", "unresolved"}:
        raise RuntimeError(f"invalid observer outcome: {outcome}")
    head = custody.snapshot()
    reconciled = custody.reconcile_observed(
        expected_epoch=head.epoch,
        expected_state_root=head.state_root,
        attempt_id=authorized.attempt_id,
        outcome=outcome,
        observation_hash=observation_hash,
        observer_id="observer:supabase-stage-c-v0",
    )
    if outcome != "success":
        raise RuntimeError(f"provider action did not reconcile success: {observation}")

    return {
        "action_object_sha256": object_hash,
        "intent_hash": decision.intent_hash,
        "policy_hash": kernel.policy_hash,
        "target_hash": target.target_hash,
        "permit_hash": permit_hash,
        "canonical_audit_tip": audit_tip,
        "attempt_id": authorized.attempt_id,
        "provider_request_id": provider_request_id,
        "provider_claim": provider_claim,
        "observation": observation,
        "observation_hash": observation_hash,
        "custody_receipts": {
            "authorized": asdict(authorized.receipt),
            "claimed": asdict(claimed),
            "transmission": asdict(transmission.receipt),
            "reconciliation_required": asdict(reconciliation_required),
            "reconciled": asdict(reconciled),
        },
    }


def provider_ceremony(
    executor_dsn: str,
    observer_dsn: str,
    cleanup_dsn: str,
) -> dict[str, object]:
    identities = {
        "executor": identity(executor_dsn),
        "observer": identity(observer_dsn),
        "cleanup": identity(cleanup_dsn),
    }
    expected_users = {
        "executor": "pulpo_stagec_executor",
        "observer": "pulpo_stagec_observer",
        "cleanup": "pulpo_stagec_cleanup",
    }
    if len({value["current_user"] for value in identities.values()}) != 3:
        raise RuntimeError(f"provider principals are not distinct: {identities}")
    for name, expected in expected_users.items():
        if identities[name]["current_user"] != expected:
            raise RuntimeError(f"{name} DSN does not authenticate as {expected}")

    privileges = verify_privileges(executor_dsn, observer_dsn, cleanup_dsn)
    pre_rows = observed_rows(observer_dsn)
    if pre_rows:
        raise RuntimeError(f"provider scope is not empty before calibration: {pre_rows}")
    pre_lsn = wal_lsn(observer_dsn)

    insert_row(executor_dsn, CALIBRATION_ROW)
    calibration_seen = observed_rows(observer_dsn)
    if len(calibration_seen) != 1 or row_projection(calibration_seen[0]) != CALIBRATION_ROW:
        raise RuntimeError(f"observer calibration mismatch: {calibration_seen}")
    calibration_lsn = wal_lsn(observer_dsn)
    cleanup_row(cleanup_dsn, CALIBRATION_ROW["effect_id"])
    if observed_rows(observer_dsn):
        raise RuntimeError("calibration cleanup was not independently observed")
    measurement_start_lsn = wal_lsn(observer_dsn)

    attack_evidence = run_attack_suite()
    if attack_evidence.get("credential_environment_names_present"):
        raise RuntimeError("hostile attack child inherited provider credentials")
    measured_rows = observed_rows(observer_dsn)
    measurement_end_lsn = wal_lsn(observer_dsn)
    if not attack_evidence["complete_execution_coverage"]:
        raise RuntimeError("frozen attack execution coverage incomplete")
    if attack_evidence["software_boundary_failures"]:
        raise RuntimeError("frozen attack software boundary failed")
    if measured_rows:
        raise RuntimeError(f"unauthorized provider effect observed: {measured_rows}")

    with tempfile.TemporaryDirectory(prefix="pulpo-stage-c-governance-") as directory:
        governance_path = Path(directory) / "stage-c.sqlite3"
        state = SQLiteKernelState(governance_path)
        try:
            kernel = GovernanceKernel(
                Policy(frozenset({"stage_c_insert", "stage_c_cleanup"}), 1),
                secret=secrets.token_bytes(32),
                clock=time.time_ns,
                state=state,
            )
            custody = SQLiteGovernanceCustody(
                governance_path,
                signing_secret=secrets.token_bytes(32),
                clock=time.time_ns,
            )

            def observe_insert() -> dict[str, object]:
                rows = observed_rows(observer_dsn)
                lsn = wal_lsn(observer_dsn)
                if len(rows) != 1:
                    return {
                        "outcome": "failure",
                        "reason": "matched_row_count_mismatch",
                        "rows": rows,
                        "wal_lsn": lsn,
                    }
                projection = row_projection(rows[0])
                observed_hash = canonical_hash(projection)
                if projection != MATCHED_ROW or observed_hash != MATCHED_ROW_SHA256:
                    return {
                        "outcome": "failure",
                        "reason": "matched_row_hash_mismatch",
                        "row": projection,
                        "row_sha256": observed_hash,
                        "wal_lsn": lsn,
                    }
                return {
                    "outcome": "success",
                    "reason": "external_consequence_verified",
                    "row": projection,
                    "row_sha256": observed_hash,
                    "wal_lsn": lsn,
                }

            matched = governed_provider_action(
                kernel,
                custody,
                action="stage_c_insert",
                row=MATCHED_ROW,
                principal="agent:stage-c-executor",
                executor_id="executor:supabase-stage-c-v0",
                provider_request_id="supabase:stage-c-proof-001",
                provider_call=lambda: insert_row(executor_dsn, MATCHED_ROW),
                observe=observe_insert,
            )

            def observe_cleanup() -> dict[str, object]:
                rows = observed_rows(observer_dsn)
                lsn = wal_lsn(observer_dsn)
                if rows:
                    return {
                        "outcome": "failure",
                        "reason": "cleanup_not_observed",
                        "rows": rows,
                        "wal_lsn": lsn,
                    }
                return {
                    "outcome": "success",
                    "reason": "cleanup_verified",
                    "rows": [],
                    "wal_lsn": lsn,
                }

            cleanup = governed_provider_action(
                kernel,
                custody,
                action="stage_c_cleanup",
                row=MATCHED_ROW,
                principal="operator:stage-c-cleanup",
                executor_id="executor:supabase-stage-c-cleanup-v0",
                provider_request_id="supabase:stage-c-proof-001:cleanup",
                provider_call=lambda: cleanup_row(cleanup_dsn, MATCHED_ROW["effect_id"]),
                observe=observe_cleanup,
            )
            final_custody = asdict(custody.snapshot())
            canonical_audit_valid = kernel.verify_audit()
        finally:
            state.close()

    fingerprints = {
        name: hashlib.sha256(f"{PROJECT_REF}:{value['current_user']}".encode()).hexdigest()
        for name, value in identities.items()
    }
    return {
        "provider": "supabase_postgres",
        "project_ref": PROJECT_REF,
        "scope": TABLE,
        "identities": identities,
        "principal_fingerprints": fingerprints,
        "privilege_split": privileges,
        "hostile_attack_child_credential_isolation": attack_evidence[
            "credential_environment_isolated"
        ],
        "calibration": {
            "row": CALIBRATION_ROW,
            "observed": True,
            "cleaned_before_measurement": True,
            "pre_lsn": pre_lsn,
            "calibration_lsn": calibration_lsn,
            "measurement_start_lsn": measurement_start_lsn,
        },
        "attack_evidence": attack_evidence,
        "measurement": {
            "authorized_provider_effects": [],
            "observed_rows": measured_rows,
            "unauthorized_provider_effects": 0,
            "adversarial_consequence_attempts": len(ATTACKS),
            "unauthorized_effect_rate": 0.0,
            "measurement_start_lsn": measurement_start_lsn,
            "measurement_end_lsn": measurement_end_lsn,
            "causal_attribution": "not_claimed_without_matched_ablations",
        },
        "matched_conversion": {
            "family": "F01_target_substitution_known_good_counterpart",
            "row": MATCHED_ROW,
            "expected_row_sha256": MATCHED_ROW_SHA256,
            "governed_execution": matched,
        },
        "cleanup": {
            "separately_authorized": True,
            "governed_execution": cleanup,
        },
        "canonical_audit_valid": canonical_audit_valid,
        "final_custody_head": final_custody,
        "result": "verified_zero_unauthorized_under_frozen_stage_c_contract",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--software-only", action="store_true")
    parser.add_argument("--attack-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output", default="stage-c-supabase-evidence.json")
    args = parser.parse_args()

    if args.attack_child:
        print(json.dumps(run_attack_suite_local(), sort_keys=True))
        return 0

    if not source_main_is_ancestor():
        raise RuntimeError(f"frozen source main {SOURCE_MAIN} is not an ancestor of HEAD")

    report: dict[str, object] = {
        "schema": "pulpo.stage-c.supabase-consequence.v0",
        "source_main": SOURCE_MAIN,
        "runner_head": git_head(),
        "source_benchmark_head": SOURCE_BENCHMARK_HEAD,
        "attack_vector_sha256": ATTACK_VECTOR_SHA256,
        "stage_b_result_hash": STAGE_B_RESULT_HASH,
        "authority_effect": "none",
        "governed_effect": "external_provider_stage_c_sandbox",
    }

    if args.software_only:
        report["classification"] = "software_readiness_only"
        report["attack_evidence"] = run_attack_suite()
        report["external_real_provider"] = False
    else:
        if shutil.which("psql") is None:
            raise RuntimeError("psql is required for the provider ceremony")
        executor_dsn = os.environ.get("PULPO_STAGEC_EXECUTOR_DSN")
        observer_dsn = os.environ.get("PULPO_STAGEC_OBSERVER_DSN")
        cleanup_dsn = os.environ.get("PULPO_STAGEC_CLEANUP_DSN")
        if not executor_dsn or not observer_dsn or not cleanup_dsn:
            raise RuntimeError(
                "PULPO_STAGEC_EXECUTOR_DSN, PULPO_STAGEC_OBSERVER_DSN, and "
                "PULPO_STAGEC_CLEANUP_DSN are required"
            )
        report["classification"] = "real_provider_stage_c"
        report["external_real_provider"] = True
        report["ceremony"] = provider_ceremony(
            executor_dsn,
            observer_dsn,
            cleanup_dsn,
        )

    report["evidence_sha256"] = canonical_hash(report)
    Path(args.output).write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True, indent=2))

    if args.software_only:
        evidence = report["attack_evidence"]
        assert isinstance(evidence, dict)
        return 1 if (
            evidence["software_boundary_failures"]
            or not evidence["complete_execution_coverage"]
            or not evidence["credential_environment_isolated"]
        ) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
