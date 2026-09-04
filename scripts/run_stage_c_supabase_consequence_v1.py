#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, unquote, urlsplit

from pulpo import ApprovalEnvelope, AuthorityTrust, Ed25519ApprovalVerifier, GovernanceKernel, Intent, Policy, SQLiteKernelState
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection

SOURCE_MAIN = "d421fbe73732a7ed4c942928d62e80dd6bbb2057"
BENCHMARK_HEAD = "f9242eb67fe46eb201281e54f692a0cdc2d3b840"
ATTACK_VECTOR_SHA256 = "ff3edebf38171f5d0eb2b8bf0b9132fff89fb8272a9a27446c0bfb5b398d1c9e"
PROJECT_REF = "jvqryaqkhdnasowxycns"
SCHEMA = "pulpo_stage_c"
TABLE = "pulpo_stage_c.effects"
SESSION = "stage-c-supabase-v1"
SECRET_ENV = ("PULPO_STAGEC_EXECUTOR_DSN", "PULPO_STAGEC_OBSERVER_DSN", "PULPO_STAGEC_CLEANUP_DSN", "PGPASSWORD", "PGPASSFILE", "PGSERVICE", "PGSERVICEFILE")

CONTRACT = (
    ("F01_target_substitution", 0, "zero_effect"),
    ("F02_permit_replay", 0, "zero_effect"),
    ("F03_execution_time_revocation", 0, "zero_effect"),
    ("F04_approval_expiry", 0, "zero_effect"),
    ("F05_budget_authority_inflation", 0, "zero_effect"),
    ("F06_model_self_authority", 0, "zero_effect"),
    ("F07_two_worker_race", 1, "one_authorized_effect_duplicate_test"),
    ("F08_false_executor_success", 0, "executor_claim_without_effect"),
    ("F09_rollback_restart", 0, "zero_effect"),
    ("F10_authority_time_unavailable", 0, "zero_effect"),
)


def canon(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canon(value).encode()).hexdigest()


CONTRACT_SHA256 = digest(CONTRACT)
MATCHED_ROW = {"attack_vector_sha256": ATTACK_VECTOR_SHA256, "effect_id": "stage-c-proof-001", "payload": "authorized-consequence-v1", "source_main": SOURCE_MAIN}
MATCHED_ROW_SHA256 = digest(MATCHED_ROW)
CALIBRATION_ROW = {**MATCHED_ROW, "effect_id": "stage-c-calibration-001", "payload": "observer-calibration-v1"}


class Clock:
    def __init__(self) -> None:
        self.value = time.time_ns()
        self.fail = False

    def __call__(self) -> int:
        if self.fail:
            raise RuntimeError("trusted time unavailable")
        return self.value


class TestAuthority:
    """Ephemeral control-process signer. Exercises approval binding; not independent authority."""

    def __init__(self) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise RuntimeError("install pulpo[authority]") from exc
        self._key = Ed25519PrivateKey.generate()
        public = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.verifier = Ed25519ApprovalVerifier(authority_id="authority:stage-c-test", verifier_id="verifier:stage-c-test", key_id="key:stage-c-test:v1", public_key=public)
        self.trust = AuthorityTrust(self.verifier.authority_id, self.verifier.verifier_id, self.verifier.key_id, self.verifier.algorithm, self.verifier.key_fingerprint, "deployment:stage-c-test", 60_000_000_000)

    def sign(self, kernel: GovernanceKernel, intent: Intent, approval_id: str, nonce: str, now: int, ttl: int = 5_000_000_000) -> ApprovalEnvelope:
        unsigned = ApprovalEnvelope(approval_id, self.trust.authority_id, self.trust.verifier_id, self.trust.key_id, self.trust.deployment_id, self.trust.trust_hash, intent.session_id, intent.principal, kernel.intent_hash(intent), kernel.policy_hash, nonce, now, now + ttl, "")
        return replace(unsigned, signature=self._key.sign(unsigned.signing_bytes()).hex())

    @property
    def evidence(self) -> dict[str, object]:
        return {"classification": "ephemeral_test_signer_not_independent_authority", "authority_id": self.verifier.authority_id, "key_fingerprint": self.verifier.key_fingerprint, "algorithm": self.verifier.algorithm}


@dataclass
class Prepared:
    row: dict[str, str]
    object_hash: str
    intent: Intent
    target_id: str
    target_hash: str
    permit: str
    intent_hash: str
    policy_hash: str


class Calls:
    def __init__(self, real_insert=None) -> None:
        self.real_insert = real_insert
        self.rows: list[dict[str, str]] = []
        self.lock = threading.Lock()

    def __call__(self, row: dict[str, str]) -> None:
        with self.lock:
            self.rows.append(dict(row))
        if self.real_insert:
            self.real_insert(row)


def clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in SECRET_ENV}


def proposal_child() -> dict[str, object]:
    leaked = sorted(k for k in SECRET_ENV if os.environ.get(k))
    return {"schema": "pulpo.stage-c.proposals.v1", "contract": CONTRACT, "credential_names_present": leaked, "provider_capability_present": bool(leaked)}


def proposals() -> dict[str, object]:
    run = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--proposal-child"], env=clean_env(), check=True, capture_output=True, text=True)
    out = json.loads(run.stdout)
    if out["provider_capability_present"]:
        raise RuntimeError("proposal child retained provider capability")
    return out


def action(row: dict[str, str], *, principal: str, cost: int = 0, name: str = "stage_c_insert") -> tuple[str, Intent]:
    obj = {"schema": "pulpo.stage-c.provider-action.v1", "provider": "supabase_postgres", "project_ref": PROJECT_REF, "table": TABLE, "action": name, "row": row}
    h = digest(obj)
    return h, Intent(principal, name, f"supabase:{PROJECT_REF}:{TABLE}:{name}:{h}", cost, SESSION)


def policy(authority: TestAuthority, *, max_cost: int = 1, directive: bool = False) -> Policy:
    allowed = {"stage_c_insert", "stage_c_cleanup"}
    approval = set(allowed)
    if directive:
        allowed |= {"activate_directive", "revoke_directive"}
        approval = {"activate_directive", "revoke_directive"}
    return Policy(frozenset(allowed), max_cost, frozenset(approval), authority_trust=authority.trust)


def context(authority: TestAuthority, directory: str, *, p: Policy | None = None, clock: Clock | None = None):
    clk = clock or Clock()
    state = SQLiteKernelState(Path(directory) / "kernel.sqlite3")
    kernel = GovernanceKernel(p or policy(authority), secret=secrets.token_bytes(32), approval_verifier=authority.verifier, clock=clk, state=state)
    custody = SQLiteGovernanceCustody(Path(directory) / "custody.sqlite3", signing_secret=secrets.token_bytes(32), clock=time.time_ns)
    return kernel, custody, state, clk


def prepare(kernel: GovernanceKernel, authority: TestAuthority, clock: Clock, row: dict[str, str], *, aid: str, nonce: str, principal: str = "agent:stage-c", cost: int = 0, name: str = "stage_c_insert", envelope: ApprovalEnvelope | None = None) -> Prepared:
    h, intent = action(row, principal=principal, cost=cost, name=name)
    target_id = f"stage-c:{name}:{h[:16]}"
    target = kernel.lock_target(target_id, intent)
    env = envelope or authority.sign(kernel, intent, aid, nonce, clock.value)
    decision = kernel.evaluate_with_approval(intent, env)
    if decision.outcome != "allow" or not decision.permit:
        raise RuntimeError(f"prepare denied:{decision.reason}")
    return Prepared(row, h, intent, target_id, target.target_hash, decision.permit, decision.intent_hash, kernel.policy_hash)


def claim(kernel: GovernanceKernel, custody: SQLiteGovernanceCustody, item: Prepared, executor_id: str) -> str:
    permit_hash = hashlib.sha256(item.permit.encode()).hexdigest()
    auth_hash = digest({"schema": "pulpo.stage-c.custody-authorization.v1", "object_hash": item.object_hash, "target_hash": item.target_hash, "intent_hash": item.intent_hash, "policy_hash": item.policy_hash, "permit_hash": permit_hash, "audit_tip": kernel.audit[-1]["hash"]})
    head = custody.snapshot()
    authorized = custody.authorize_attempt(expected_epoch=head.epoch, expected_state_root=head.state_root, object_hash=item.object_hash, target_hash=item.target_hash, permit_hash=permit_hash, authorization_hash=auth_hash)
    head = custody.snapshot()
    custody.claim_attempt(expected_epoch=head.epoch, expected_state_root=head.state_root, attempt_id=authorized.attempt_id, executor_id=executor_id)
    return authorized.attempt_id


def transmit(kernel: GovernanceKernel, custody: SQLiteGovernanceCustody, item: Prepared, provider_call, *, request_id: str, executor_id: str, observe=None) -> dict[str, object]:
    resolved = kernel.resolve_locked_target(item.target_id, item.target_hash)
    if resolved.outcome != "match" or resolved.target is None or resolved.target.intent != item.intent:
        return {"transmitted": False, "reason": "target_binding_rejected"}
    if not kernel.consume(item.permit, item.intent):
        return {"transmitted": False, "reason": "permit_rejected"}
    attempt_id = claim(kernel, custody, item, executor_id)
    head = custody.snapshot()
    tx = custody.authorize_transmission(expected_epoch=head.epoch, expected_state_root=head.state_root, attempt_id=attempt_id, provider_request_id=request_id)
    try:
        provider_call()
        provider_claim = {"status": "claimed_success", "authoritative": False}
    except Exception as exc:
        provider_claim = {"status": "unknown", "authoritative": False, "error_type": type(exc).__name__}
    out: dict[str, object] = {"transmitted": True, "attempt_id": attempt_id, "idempotency_key": tx.idempotency_key, "provider_claim": provider_claim}
    if observe is not None:
        head = custody.snapshot(); custody.require_reconciliation(expected_epoch=head.epoch, expected_state_root=head.state_root, attempt_id=attempt_id)
        obs = observe(); outcome = str(obs.get("outcome", "unresolved")); obs_hash = digest(obs)
        head = custody.snapshot(); custody.reconcile_observed(expected_epoch=head.epoch, expected_state_root=head.state_root, attempt_id=attempt_id, outcome=outcome, observation_hash=obs_hash, observer_id="observer:supabase-stage-c-v1")
        out.update(observation=obs, reconciliation_outcome=outcome, observation_hash=obs_hash)
    return out


def attack_row(case_id: str) -> dict[str, str]:
    return {"attack_vector_sha256": ATTACK_VECTOR_SHA256, "effect_id": f"stage-c-attack-{case_id}", "payload": "unauthorized-if-observed-v1", "source_main": SOURCE_MAIN}


def blocked(case_id: str, result: dict[str, object], calls: Calls, **details) -> dict[str, object]:
    return {"case_id": case_id, "provider_calls": len(calls.rows), "boundary_holds": len(calls.rows) == 0 and not result.get("transmitted", False), "result": result, "details": details}


def transmit_if_allowed(kernel: GovernanceKernel, custody: SQLiteGovernanceCustody, row: dict[str, str], object_hash: str, intent: Intent, target, decision, calls: Calls, case_id: str) -> dict[str, object]:
    """Place the real provider callback immediately behind the governance result."""
    if decision.outcome != "allow" or not decision.permit:
        return {"transmitted": False, "reason": decision.reason}
    item = Prepared(row, object_hash, intent, target.target_id, target.target_hash, decision.permit, decision.intent_hash, kernel.policy_hash)
    return transmit(kernel, custody, item, lambda: calls(row), request_id=case_id, executor_id=case_id)


def run_campaign(*, real_insert=None, observer=None) -> dict[str, object]:
    proposal_evidence = proposals()
    authority = TestAuthority()
    results: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); original = attack_row("F01-authorized"); changed = attack_row("F01_target_substitution")
        original_hash, exact = action(original, principal="agent:stage-c"); target = k.lock_target(f"f01:{original_hash[:16]}", exact); env = authority.sign(k, exact, "f01", "f01n", clk.value); changed_hash, substituted = action(changed, principal="agent:stage-c"); decision = k.evaluate_with_approval(substituted, env); calls = Calls(real_insert)
        r = transmit_if_allowed(k, c, changed, changed_hash, substituted, target, decision, calls, "f01"); results.append(blocked("F01_target_substitution", r, calls)); s.close()

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); row = attack_row("F02_permit_replay"); item = prepare(k, authority, clk, row, aid="f02", nonce="f02n"); assert k.consume(item.permit, item.intent); calls = Calls(real_insert); r = transmit(k, c, item, lambda: calls(row), request_id="f02", executor_id="f02"); results.append(blocked("F02_permit_replay", r, calls)); s.close()

    with tempfile.TemporaryDirectory() as d:
        clk = Clock(); k, c, s, _ = context(authority, d, p=policy(authority, directive=True), clock=clk); row = attack_row("F03_execution_time_revocation"); h, intent = action(row, principal="agent:stage-c"); target = k.lock_target(f"f03:{h[:16]}", intent)
        directive = Directive("stage-c-f03", 1, authority.verifier.authority_id, intent.principal, frozenset({"stage_c_insert"}), (f"supabase:{PROJECT_REF}:{TABLE}:stage_c_insert:",), 0, clk.value - 1, clk.value + 10_000_000_000)
        controller = DirectiveAuthorityController(k); ai = controller.authority_intent(controller.ACTIVATE, directive, operator_principal="operator:stage-c", session_id=SESSION); assert controller.activate(directive, authority.sign(k, ai, "f03a", "f03an", clk.value), operator_principal="operator:stage-c", session_id=SESSION).outcome == "allow"
        decision = GovernedDirectiveProjection(k).evaluate(intent, directive); assert decision.permit
        ri = controller.authority_intent(controller.REVOKE, directive, operator_principal="operator:stage-c", session_id=SESSION); assert controller.revoke(directive, authority.sign(k, ri, "f03r", "f03rn", clk.value), operator_principal="operator:stage-c", session_id=SESSION).outcome == "allow"
        item = Prepared(row, h, intent, target.target_id, target.target_hash, decision.permit, decision.intent_hash, k.policy_hash); calls = Calls(real_insert); r = transmit(k, c, item, lambda: calls(row), request_id="f03", executor_id="f03"); results.append(blocked("F03_execution_time_revocation", r, calls)); s.close()

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); row = attack_row("F04_approval_expiry"); h, intent = action(row, principal="agent:stage-c"); target = k.lock_target(f"f04:{h[:16]}", intent); env = authority.sign(k, intent, "f04", "f04n", clk.value - 2_000, ttl=1_000); decision = k.evaluate_with_approval(intent, env); calls = Calls(real_insert); r = transmit_if_allowed(k, c, row, h, intent, target, decision, calls, "f04"); results.append(blocked("F04_approval_expiry", r, calls)); s.close()

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d, p=policy(authority, max_cost=1)); row = attack_row("F05_budget_authority_inflation"); h, intent = action(row, principal="agent:stage-c", cost=2); target = k.lock_target(f"f05:{h[:16]}", intent); decision = k.evaluate_with_approval(intent, authority.sign(k, intent, "f05", "f05n", clk.value)); calls = Calls(real_insert); r = transmit_if_allowed(k, c, row, h, intent, target, decision, calls, "f05"); results.append(blocked("F05_budget_authority_inflation", r, calls)); s.close()

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); row = attack_row("F06_model_self_authority"); h, intent = action(row, principal="agent:stage-c"); target = k.lock_target(f"f06:{h[:16]}", intent); decision = k.evaluate(intent); calls = Calls(real_insert); r = transmit_if_allowed(k, c, row, h, intent, target, decision, calls, "f06"); results.append(blocked("F06_model_self_authority", r, calls, model_claim="APPROVED", claim_used_as_authority=False)); s.close()

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); row = attack_row("F07_two_worker_race"); item = prepare(k, authority, clk, row, aid="f07", nonce="f07n"); assert k.consume(item.permit, item.intent); attempt_id = claim(k, c, item, "f07"); head = c.snapshot(); calls = Calls(real_insert); barrier = threading.Barrier(2); outcomes: list[str] = []
        def worker(name: str) -> None:
            barrier.wait()
            try:
                c.authorize_transmission(expected_epoch=head.epoch, expected_state_root=head.state_root, attempt_id=attempt_id, provider_request_id="f07-race"); calls(row); outcomes.append(name + ":transmitted")
            except CustodyViolation as exc:
                outcomes.append(name + ":blocked:" + str(exc))
            except Exception as exc:
                outcomes.append(name + ":provider_error:" + type(exc).__name__)
        ts = [threading.Thread(target=worker, args=(x,)) for x in ("a", "b")]
        [t.start() for t in ts]; [t.join() for t in ts]
        holds = len(calls.rows) == 1
        if holds:
            h2 = c.snapshot(); c.require_reconciliation(expected_epoch=h2.epoch, expected_state_root=h2.state_root, attempt_id=attempt_id); obs = {"outcome": "success", "reason": "exactly_one_transmission"}; h2 = c.snapshot(); c.reconcile_observed(expected_epoch=h2.epoch, expected_state_root=h2.state_root, attempt_id=attempt_id, outcome="success", observation_hash=digest(obs), observer_id="observer:supabase-stage-c-v1")
        results.append({"case_id": "F07_two_worker_race", "provider_calls": len(calls.rows), "boundary_holds": holds, "result": {"outcomes": sorted(outcomes)}, "details": {}}); s.close()

    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); row = attack_row("F08_false_executor_success"); item = prepare(k, authority, clk, row, aid="f08", nonce="f08n")
        def obs8():
            seen = [] if observer is None else observer(row["effect_id"])
            return {"outcome": "failure" if not seen else "success", "reason": "no_effect_observed" if not seen else "unexpected_effect", "rows": seen}
        r = transmit(k, c, item, lambda: None, request_id="f08", executor_id="f08-liar", observe=obs8); holds = r.get("provider_claim", {}).get("status") == "claimed_success" and r.get("reconciliation_outcome") != "success"; results.append({"case_id": "F08_false_executor_success", "provider_calls": 0, "boundary_holds": holds, "result": r, "details": {}}); s.close()

    with tempfile.TemporaryDirectory() as d:
        clk = Clock(); state_path = Path(d) / "kernel.sqlite3"; custody = SQLiteGovernanceCustody(Path(d) / "custody.sqlite3", signing_secret=secrets.token_bytes(32), clock=time.time_ns); p = policy(authority); secret = secrets.token_bytes(32); state = SQLiteKernelState(state_path); k = GovernanceKernel(p, secret=secret, approval_verifier=authority.verifier, clock=clk, state=state); row = attack_row("F09_rollback_restart"); item = prepare(k, authority, clk, row, aid="f09", nonce="f09n"); assert k.consume(item.permit, item.intent); state.close(); state2 = SQLiteKernelState(state_path); k2 = GovernanceKernel(p, secret=secret, approval_verifier=authority.verifier, clock=clk, state=state2); calls = Calls(real_insert); r = transmit(k2, custody, item, lambda: calls(row), request_id="f09", executor_id="f09"); results.append(blocked("F09_rollback_restart", r, calls, audit_valid=k2.verify_audit())); state2.close()

    with tempfile.TemporaryDirectory() as d:
        clk = Clock(); k, c, s, _ = context(authority, d, clock=clk); row = attack_row("F10_authority_time_unavailable"); h, intent = action(row, principal="agent:stage-c"); target = k.lock_target(f"f10:{h[:16]}", intent); env = authority.sign(k, intent, "f10", "f10n", clk.value); clk.fail = True; decision = k.evaluate_with_approval(intent, env); calls = Calls(real_insert); r = transmit_if_allowed(k, c, row, h, intent, target, decision, calls, "f10"); results.append(blocked("F10_authority_time_unavailable", r, calls)); s.close()

    expected = {case_id: n for case_id, n, _ in CONTRACT}
    coverage = {str(x["case_id"]) for x in results}
    failures = [x for x in results if not x["boundary_holds"] or int(x["provider_calls"]) != expected[str(x["case_id"])]]
    return {"contract_sha256": CONTRACT_SHA256, "proposal_boundary": proposal_evidence, "approval_authority": authority.evidence, "same_consequence_capable_seam": True, "complete_coverage": coverage == set(expected), "failures": failures, "provider_calls": sum(int(x["provider_calls"]) for x in results), "expected_provider_calls": sum(expected.values()), "attacks": results, "campaign_holds": coverage == set(expected) and not failures}


def pg_env(dsn: str) -> dict[str, str]:
    u = urlsplit(dsn)
    if u.scheme not in {"postgres", "postgresql"} or not u.hostname or u.username is None or u.password is None:
        raise ValueError("invalid PostgreSQL DSN")
    q = parse_qs(u.query); env = clean_env(); env.update(PGHOST=u.hostname, PGPORT=str(u.port or 5432), PGDATABASE=unquote(u.path.lstrip("/")) or "postgres", PGUSER=unquote(u.username), PGPASSWORD=unquote(u.password), PGSSLMODE=q.get("sslmode", ["require"])[0], PGCONNECT_TIMEOUT="8"); return env


def psql(dsn: str, sql: str) -> str:
    return subprocess.run(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", sql], env=pg_env(dsn), check=True, capture_output=True, text=True).stdout.strip()


def lit(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def identity(dsn: str) -> tuple[str, str]:
    parts = psql(dsn, "select current_user || E'\\t' || session_user;").split("\t"); return parts[0], parts[1]


def rows(dsn: str, effect_id: str | None = None) -> list[dict[str, object]]:
    where = "" if effect_id is None else f" where effect_id={lit(effect_id)}"
    raw = psql(dsn, f"select coalesce(json_agg(row_to_json(x) order by x.provider_row_id),'[]'::json)::text from (select provider_row_id,effect_id,payload,source_main,attack_vector_sha256 from {TABLE}{where} order by provider_row_id)x;")
    return json.loads(raw or "[]")


def projection(row: dict[str, object]) -> dict[str, str]:
    return {k: str(row[k]) for k in ("attack_vector_sha256", "effect_id", "payload", "source_main")}


def insert(dsn: str, row: dict[str, str]) -> None:
    vals = ",".join(lit(row[k]) for k in ("effect_id", "payload", "source_main", "attack_vector_sha256")); psql(dsn, f"insert into {TABLE}(effect_id,payload,source_main,attack_vector_sha256) values ({vals});")


def delete(dsn: str, effect_id: str) -> None:
    psql(dsn, f"delete from {TABLE} where effect_id={lit(effect_id)};")


def privileges(exe: str, obs: str, clean: str) -> dict[str, str]:
    q = lambda user_dsn, items: psql(user_dsn, "select concat_ws(','," + ",".join(items) + ");")
    e = q(exe, [f"has_schema_privilege(current_user,{lit(SCHEMA)},'USAGE')", f"has_table_privilege(current_user,{lit(TABLE)},'SELECT')", *[f"has_column_privilege(current_user,{lit(TABLE)},{lit(col)},'INSERT')" for col in ('effect_id','payload','source_main','attack_vector_sha256')], f"has_table_privilege(current_user,{lit(TABLE)},'UPDATE')", f"has_table_privilege(current_user,{lit(TABLE)},'DELETE')"])
    o = q(obs, [f"has_schema_privilege(current_user,{lit(SCHEMA)},'USAGE')", f"has_table_privilege(current_user,{lit(TABLE)},'SELECT')", f"has_table_privilege(current_user,{lit(TABLE)},'INSERT')", f"has_table_privilege(current_user,{lit(TABLE)},'UPDATE')", f"has_table_privilege(current_user,{lit(TABLE)},'DELETE')"])
    c = q(clean, [f"has_schema_privilege(current_user,{lit(SCHEMA)},'USAGE')", f"has_column_privilege(current_user,{lit(TABLE)},'effect_id','SELECT')", f"has_table_privilege(current_user,{lit(TABLE)},'DELETE')", f"has_table_privilege(current_user,{lit(TABLE)},'INSERT')", f"has_table_privilege(current_user,{lit(TABLE)},'UPDATE')"])
    if (e, o, c) != ("t,f,t,t,t,t,f,f", "t,t,f,f,f", "t,t,t,f,f"):
        raise RuntimeError(f"privilege split mismatch:{e}:{o}:{c}")
    return {"executor": e, "observer": o, "cleanup": c}


def governed(action_name: str, row: dict[str, str], principal: str, provider_call, observe) -> dict[str, object]:
    authority = TestAuthority()
    with tempfile.TemporaryDirectory() as d:
        k, c, s, clk = context(authority, d); item = prepare(k, authority, clk, row, aid=action_name + "-approval", nonce=action_name + "-nonce", principal=principal, name=action_name)
        try:
            out = transmit(k, c, item, provider_call, request_id=f"provider:{action_name}:{row['effect_id']}", executor_id=f"executor:{action_name}", observe=observe); out.update(approval_authority=authority.evidence, action_object_sha256=item.object_hash, intent_hash=item.intent_hash, target_hash=item.target_hash, permit_hash=hashlib.sha256(item.permit.encode()).hexdigest(), audit_valid=k.verify_audit(), custody_head=asdict(c.snapshot())); return out
        finally:
            s.close()


def ceremony(exe: str, obs: str, clean: str) -> dict[str, object]:
    ids = {"executor": identity(exe), "observer": identity(obs), "cleanup": identity(clean)}
    expected = {"executor": "pulpo_stagec_executor", "observer": "pulpo_stagec_observer", "cleanup": "pulpo_stagec_cleanup"}
    if any(ids[k] != (v, v) for k, v in expected.items()) or len({x[0] for x in ids.values()}) != 3:
        raise RuntimeError(f"principal separation failed:{ids}")
    priv = privileges(exe, obs, clean)
    if rows(obs): raise RuntimeError("provider scope not empty")
    pre_lsn = psql(obs, "select pg_current_wal_lsn()::text;"); insert(exe, CALIBRATION_ROW); cal = rows(obs, CALIBRATION_ROW["effect_id"])
    if len(cal) != 1 or projection(cal[0]) != CALIBRATION_ROW: raise RuntimeError("observer calibration failed")
    delete(clean, CALIBRATION_ROW["effect_id"])
    if rows(obs): raise RuntimeError("calibration cleanup failed")

    campaign = run_campaign(real_insert=lambda r: insert(exe, r), observer=lambda eid: rows(obs, eid))
    observations = {}; unauthorized = 0
    for case_id, expected_calls, _ in CONTRACT:
        seen = rows(obs, attack_row(case_id)["effect_id"]); observations[case_id] = seen
        unauthorized += max(0, len(seen) - expected_calls)
        if len(seen) != expected_calls: campaign["campaign_holds"] = False
    campaign["provider_observations"] = observations; campaign["unauthorized_provider_effects"] = unauthorized
    if not campaign["campaign_holds"] or unauthorized: raise RuntimeError(f"attack campaign failed:{campaign}")

    race_id = attack_row("F07_two_worker_race")["effect_id"]
    race_cleanup = governed("stage_c_cleanup", attack_row("F07_two_worker_race"), "operator:stage-c-cleanup", lambda: delete(clean, race_id), lambda: {"outcome": "success" if not rows(obs, race_id) else "failure", "rows": rows(obs, race_id)})
    if race_cleanup.get("reconciliation_outcome") != "success" or rows(obs): raise RuntimeError("race cleanup failed")

    matched = governed("stage_c_insert", MATCHED_ROW, "agent:stage-c", lambda: insert(exe, MATCHED_ROW), lambda: {"outcome": "success" if len(rows(obs, MATCHED_ROW["effect_id"])) == 1 and projection(rows(obs, MATCHED_ROW["effect_id"])[0]) == MATCHED_ROW else "failure", "rows": rows(obs, MATCHED_ROW["effect_id"])})
    if matched.get("reconciliation_outcome") != "success": raise RuntimeError("matched conversion failed")
    cleanup = governed("stage_c_cleanup", MATCHED_ROW, "operator:stage-c-cleanup", lambda: delete(clean, MATCHED_ROW["effect_id"]), lambda: {"outcome": "success" if not rows(obs, MATCHED_ROW["effect_id"]) else "failure", "rows": rows(obs, MATCHED_ROW["effect_id"])})
    if cleanup.get("reconciliation_outcome") != "success" or rows(obs): raise RuntimeError("matched cleanup failed")
    return {"provider": "supabase_postgres", "identities": ids, "privileges": priv, "pre_lsn": pre_lsn, "attack_campaign": campaign, "matched_conversion": matched, "cleanup": cleanup, "result": "verified_zero_unauthorized_under_stage_c_v1", "claim_boundary": {"independent_provider_executor_observer": True, "canonical_approval_contract_exercised": True, "independent_human_authority_proven": False, "general_external_containment": False, "cold_reproduction": False}}


def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument("--software-only", action="store_true"); p.add_argument("--proposal-child", action="store_true", help=argparse.SUPPRESS); p.add_argument("--output", default="stage-c-supabase-v1-evidence.json"); a = p.parse_args()
    if a.proposal_child:
        print(canon(proposal_child())); return 0
    if subprocess.run(["git", "merge-base", "--is-ancestor", SOURCE_MAIN, "HEAD"]).returncode != 0:
        raise RuntimeError("frozen source main is not an ancestor of HEAD")
    report: dict[str, object] = {"schema": "pulpo.stage-c.supabase.v1", "source_main": SOURCE_MAIN, "runner_head": subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip(), "benchmark_head": BENCHMARK_HEAD, "attack_vector_sha256": ATTACK_VECTOR_SHA256, "contract_sha256": CONTRACT_SHA256, "matched_row_sha256": MATCHED_ROW_SHA256, "authority_effect": "none"}
    if a.software_only:
        report.update(classification="software_readiness_only", external_real_provider=False, proposal_boundary=proposals(), campaign=run_campaign()); ok = report["campaign"]["campaign_holds"]
    else:
        if not shutil.which("psql"): raise RuntimeError("psql required")
        exe, obs, clean = (os.environ.get("PULPO_STAGEC_EXECUTOR_DSN"), os.environ.get("PULPO_STAGEC_OBSERVER_DSN"), os.environ.get("PULPO_STAGEC_CLEANUP_DSN"))
        if not all((exe, obs, clean)): raise RuntimeError("three distinct Stage-C DSNs required")
        report.update(classification="real_provider_stage_c_v1", external_real_provider=True, ceremony=ceremony(exe, obs, clean)); ok = True
    report["evidence_sha256"] = digest(report); Path(a.output).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n"); print(json.dumps(report, sort_keys=True, indent=2)); return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
