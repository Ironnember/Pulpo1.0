from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from pulpo.behavior_telemetry import BehaviorObservation, BehaviorTelemetry
from pulpo.kernel import AgentGrant, GovernanceKernel, Intent, Policy


@dataclass(frozen=True)
class SemanticNonVeto:
    schema: str
    intent_hash: str
    session_id: str
    assessment_id: str
    issued_at_ns: int
    expires_at_ns: int
    vetoed: bool
    reason: str
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if self.schema != "pulpo.semantic-nonveto.proof.v0":
            raise ValueError("unsupported semantic statement schema")
        if len(self.intent_hash) != 64 or not self.session_id or not self.assessment_id:
            raise ValueError("semantic statement must bind an exact object/session")
        if self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("semantic statement time bounds invalid")
        if not self.reason:
            raise ValueError("semantic statement reason required")
        if self.authority_effect != "none":
            raise ValueError("semantic statement cannot carry authority")


@dataclass(frozen=True)
class GateResult:
    outcome: str
    reason: str
    attempted: bool = False
    effect_succeeded: bool = False
    authority_effect: str = "none"


class MutableClock:
    def __init__(self, now_ns: int = 1_900_000_000_000_000_000) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns

    def advance(self, delta_ns: int) -> None:
        self.now_ns += delta_ns


class SemanticGuard:
    def __init__(self, *, corrupted: bool, clock: MutableClock) -> None:
        self.corrupted = corrupted
        self.clock = clock
        self.counter = 0

    def assess(self, intent: Intent, *, ttl_ns: int = 1_000_000_000) -> SemanticNonVeto:
        self.counter += 1
        forbidden = intent.resource.startswith("proof:forbidden:")
        vetoed = forbidden and not self.corrupted
        return SemanticNonVeto(
            schema="pulpo.semantic-nonveto.proof.v0",
            intent_hash=GovernanceKernel.intent_hash(intent),
            session_id=intent.session_id,
            assessment_id=f"assessment:{self.counter}",
            issued_at_ns=self.clock(),
            expires_at_ns=self.clock() + ttl_ns,
            vetoed=vetoed,
            reason="semantic_veto_forbidden_target" if vetoed else "semantic_nonveto",
        )


class LocalEffectSurface:
    def __init__(self) -> None:
        self.effects: list[str] = []

    def apply(self, intent: Intent) -> tuple[bool, str]:
        self.effects.append(intent.resource)
        return True, "local_effect_committed"


class DualControlGate:
    """Proof-only intersection gate; not canonical Pulpo production routing."""

    def __init__(
        self,
        kernel: GovernanceKernel,
        *,
        clock: MutableClock,
        effect_callback,
        independent_effect_constraint=None,
    ) -> None:
        self.kernel = kernel
        self.clock = clock
        self.effect_callback = effect_callback
        self.independent_effect_constraint = independent_effect_constraint
        self.used_assessments: set[str] = set()

    def release(
        self,
        intent: Intent,
        permit: str | None,
        semantic: SemanticNonVeto | None,
    ) -> GateResult:
        if permit is None:
            return GateResult("blocked", "governance_permit_missing")
        if semantic is None:
            return GateResult("blocked", "semantic_nonveto_missing")
        if semantic.authority_effect != "none":
            return GateResult("blocked", "semantic_authority_invalid")
        if semantic.vetoed:
            return GateResult("blocked", "semantic_veto")
        digest = GovernanceKernel.intent_hash(intent)
        if semantic.intent_hash != digest or semantic.session_id != intent.session_id:
            return GateResult("blocked", "semantic_object_mismatch")
        now_ns = self.clock()
        if not (semantic.issued_at_ns <= now_ns < semantic.expires_at_ns):
            return GateResult("blocked", "semantic_statement_stale")
        if semantic.assessment_id in self.used_assessments:
            return GateResult("blocked", "semantic_statement_replayed")
        if self.independent_effect_constraint is not None and not self.independent_effect_constraint(intent):
            return GateResult("blocked", "independent_effect_constraint_denied")
        if not self.kernel.consume(permit, intent):
            return GateResult("blocked", "governance_permit_invalid")
        self.used_assessments.add(semantic.assessment_id)
        succeeded, reason = self.effect_callback(intent)
        return GateResult(
            "effect_succeeded" if succeeded else "effect_failed",
            reason,
            attempted=True,
            effect_succeeded=bool(succeeded),
        )


class ProviderResult:
    def __init__(self, status: int, payload: dict[str, object]) -> None:
        self.status = status
        self.payload = payload


class InvertedDualControlProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.port = cls._free_port()
        service = Path(__file__).with_name("toctou_provider_service_v0.py")
        cls.provider_process = subprocess.Popen(
            [sys.executable, "-I", str(service), "--port", str(cls.port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.provider_base = f"http://127.0.0.1:{cls.port}"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.provider_process.poll() is not None:
                stderr = cls.provider_process.stderr.read() if cls.provider_process.stderr else ""
                raise RuntimeError(f"proof provider exited early: {stderr}")
            try:
                result = cls._provider_request_static(cls.provider_base, "GET", "/capabilities")
            except OSError:
                time.sleep(0.05)
                continue
            if result.status == 200:
                return
        cls.provider_process.terminate()
        raise RuntimeError("proof provider did not become ready")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.provider_process.terminate()
        try:
            cls.provider_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.provider_process.kill()
            cls.provider_process.wait(timeout=3)
        if cls.provider_process.stderr:
            cls.provider_process.stderr.close()

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def honest_policy() -> Policy:
        return Policy(
            allowed_actions=frozenset({"write"}),
            max_cost=10,
            agent_grants=(
                AgentGrant(
                    principal="worker:dual",
                    allowed_actions=frozenset({"write"}),
                    resource_prefixes=("proof:safe:",),
                    max_cost=10,
                ),
            ),
        )

    @staticmethod
    def corrupted_policy() -> Policy:
        # Fault injection: same kernel semantics, intentionally widened grant.
        return Policy(
            allowed_actions=frozenset({"write"}),
            max_cost=10,
            agent_grants=(
                AgentGrant(
                    principal="worker:dual",
                    allowed_actions=frozenset({"write"}),
                    resource_prefixes=("proof:",),
                    max_cost=10,
                ),
            ),
        )

    @staticmethod
    def safe_intent(session: str = "session:safe") -> Intent:
        return Intent("worker:dual", "write", "proof:safe:effect", 1, session)

    @staticmethod
    def forbidden_intent(session: str = "session:forbidden") -> Intent:
        return Intent("worker:dual", "write", "proof:forbidden:effect", 1, session)

    @staticmethod
    def _provider_request_static(
        base: str,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> ProviderResult:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return ProviderResult(response.status, json.loads(response.read()))
        except urllib.error.HTTPError as exc:
            return ProviderResult(exc.code, json.loads(exc.read()))

    def provider_request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> ProviderResult:
        return self._provider_request_static(self.provider_base, method, path, payload)

    def provider_state(self, object_id: str) -> dict[str, object]:
        result = self.provider_request(
            "GET",
            "/state?" + urllib.parse.urlencode({"object_id": object_id}),
        )
        self.assertEqual(result.status, 200)
        return result.payload

    @staticmethod
    def provider_reconciliation_matches(
        provider_result: dict[str, object],
        observed: dict[str, object],
        *,
        object_id: str,
        expected_value: str,
    ) -> bool:
        return (
            provider_result.get("ok") is True
            and provider_result.get("object_id") == object_id
            and provider_result.get("value") == expected_value
            and observed.get("object_id") == object_id
            and observed.get("value") == expected_value
            and provider_result.get("version") == observed.get("version")
        )

    def test_honest_governance_and_honest_intelligence_release_exact_effect_once(self) -> None:
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        intelligence = SemanticGuard(corrupted=False, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(kernel, clock=clock, effect_callback=surface.apply)
        intent = self.safe_intent()
        decision = kernel.evaluate(intent)
        self.assertEqual(decision.outcome, "allow")
        semantic = intelligence.assess(intent)
        self.assertFalse(semantic.vetoed)

        first = gate.release(intent, decision.permit, semantic)
        self.assertEqual(first.outcome, "effect_succeeded")
        self.assertTrue(first.effect_succeeded)
        self.assertEqual(surface.effects, [intent.resource])
        replay = gate.release(intent, decision.permit, semantic)
        self.assertEqual(replay.outcome, "blocked")
        self.assertEqual(len(surface.effects), 1)

    def test_honest_governance_blocks_corrupted_intelligence_from_widening_authority(self) -> None:
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        malicious_intelligence = SemanticGuard(corrupted=True, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(kernel, clock=clock, effect_callback=surface.apply)
        forbidden = self.forbidden_intent()
        decision = kernel.evaluate(forbidden)
        self.assertEqual(decision.outcome, "deny")
        semantic = malicious_intelligence.assess(forbidden)
        self.assertFalse(semantic.vetoed)
        result = gate.release(forbidden, decision.permit, semantic)
        self.assertEqual(result.reason, "governance_permit_missing")
        self.assertEqual(surface.effects, [])

    def test_honest_intelligence_veto_blocks_corrupted_governance_authorization(self) -> None:
        clock = MutableClock()
        corrupted_governance = GovernanceKernel(self.corrupted_policy(), clock=clock)
        honest_intelligence = SemanticGuard(corrupted=False, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(corrupted_governance, clock=clock, effect_callback=surface.apply)
        forbidden = self.forbidden_intent()
        decision = corrupted_governance.evaluate(forbidden)
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)
        semantic = honest_intelligence.assess(forbidden)
        self.assertTrue(semantic.vetoed)
        result = gate.release(forbidden, decision.permit, semantic)
        self.assertEqual(result.reason, "semantic_veto")
        self.assertFalse(result.attempted)
        self.assertEqual(surface.effects, [])

    def test_governance_unavailable_means_nonveto_alone_cannot_execute(self) -> None:
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        intelligence = SemanticGuard(corrupted=True, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(kernel, clock=clock, effect_callback=surface.apply)
        intent = self.forbidden_intent()
        semantic = intelligence.assess(intent)
        result = gate.release(intent, None, semantic)
        self.assertEqual(result.reason, "governance_permit_missing")
        self.assertEqual(surface.effects, [])

    def test_intelligence_unavailable_denies_without_silent_governance_only_fallback(self) -> None:
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(kernel, clock=clock, effect_callback=surface.apply)
        intent = self.safe_intent("session:no-intelligence")
        decision = kernel.evaluate(intent)
        self.assertEqual(decision.outcome, "allow")
        result = gate.release(intent, decision.permit, None)
        self.assertEqual(result.reason, "semantic_nonveto_missing")
        self.assertEqual(surface.effects, [])
        # Denial by the semantic gate did not rewrite governance authority. A fresh
        # exact semantic statement may still use the original one-use permit.
        intelligence = SemanticGuard(corrupted=False, clock=clock)
        recovered = gate.release(intent, decision.permit, intelligence.assess(intent))
        self.assertTrue(recovered.effect_succeeded)
        self.assertEqual(len(surface.effects), 1)

    def test_semantic_object_substitution_denies_without_consuming_exact_permit(self) -> None:
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        intelligence = SemanticGuard(corrupted=False, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(kernel, clock=clock, effect_callback=surface.apply)
        intent_a = self.safe_intent("session:a")
        intent_b = Intent("worker:dual", "write", "proof:safe:effect-b", 1, "session:b")
        decision_b = kernel.evaluate(intent_b)
        semantic_a = intelligence.assess(intent_a)
        mismatch = gate.release(intent_b, decision_b.permit, semantic_a)
        self.assertEqual(mismatch.reason, "semantic_object_mismatch")
        self.assertEqual(surface.effects, [])
        exact = gate.release(intent_b, decision_b.permit, intelligence.assess(intent_b))
        self.assertTrue(exact.effect_succeeded)
        self.assertEqual(surface.effects, [intent_b.resource])

    def test_stale_semantic_statement_fails_closed_without_authority_expansion(self) -> None:
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        intelligence = SemanticGuard(corrupted=False, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(kernel, clock=clock, effect_callback=surface.apply)
        intent = self.safe_intent("session:stale")
        decision = kernel.evaluate(intent)
        semantic = intelligence.assess(intent, ttl_ns=10)
        clock.advance(11)
        result = gate.release(intent, decision.permit, semantic)
        self.assertEqual(result.reason, "semantic_statement_stale")
        self.assertEqual(result.authority_effect, "none")
        self.assertEqual(surface.effects, [])

    def test_external_state_change_still_requires_provider_atomic_precondition(self) -> None:
        object_id = "dual-control-toctou"
        initial = self.provider_state(object_id)
        self.assertEqual(initial["version"], 1)
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        intelligence = SemanticGuard(corrupted=False, clock=clock)
        intent = Intent(
            "worker:dual",
            "write",
            f"proof:safe:provider:{object_id}@version:1",
            1,
            "session:provider-stale",
        )
        decision = kernel.evaluate(intent)
        semantic = intelligence.assess(intent)
        changed = self.provider_request(
            "POST",
            "/out-of-band",
            {"object_id": object_id, "value": "external-v2"},
        )
        self.assertEqual(changed.status, 200)
        self.assertEqual(changed.payload["version"], 2)

        def conditional_effect(_intent: Intent) -> tuple[bool, str]:
            result = self.provider_request(
                "POST",
                "/conditional",
                {"object_id": object_id, "expected_version": 1, "value": "dual-control-write"},
            )
            self.assertEqual(result.status, 412)
            return False, "provider_version_precondition_failed"

        gate = DualControlGate(kernel, clock=clock, effect_callback=conditional_effect)
        result = gate.release(intent, decision.permit, semantic)
        self.assertEqual(result.outcome, "effect_failed")
        self.assertTrue(result.attempted)
        self.assertFalse(result.effect_succeeded)
        final = self.provider_state(object_id)
        self.assertEqual(final["version"], 2)
        self.assertEqual(final["value"], "external-v2")
        self.assertEqual(final["governed_effects"], 0)

    def test_forged_observation_cannot_create_verified_provider_reconciliation(self) -> None:
        object_id = "dual-control-observer"
        initial = self.provider_state(object_id)
        self.assertEqual(initial["version"], 1)
        clock = MutableClock()
        kernel = GovernanceKernel(self.honest_policy(), clock=clock)
        intelligence = SemanticGuard(corrupted=False, clock=clock)
        intent = Intent(
            "worker:dual",
            "write",
            f"proof:safe:provider:{object_id}@version:1",
            1,
            "session:observer",
        )
        decision = kernel.evaluate(intent)
        semantic = intelligence.assess(intent)
        holder: dict[str, ProviderResult] = {}

        def effect(_intent: Intent) -> tuple[bool, str]:
            provider_result = self.provider_request(
                "POST",
                "/conditional",
                {"object_id": object_id, "expected_version": 1, "value": "observed-value"},
            )
            holder["provider"] = provider_result
            return provider_result.status == 200, "provider_response"

        gate = DualControlGate(kernel, clock=clock, effect_callback=effect)
        result = gate.release(intent, decision.permit, semantic)
        self.assertTrue(result.effect_succeeded)
        provider_result = holder["provider"].payload
        real_observation = self.provider_state(object_id)
        self.assertTrue(
            self.provider_reconciliation_matches(
                provider_result,
                real_observation,
                object_id=object_id,
                expected_value="observed-value",
            )
        )
        forged = dict(real_observation)
        forged["version"] = int(real_observation["version"]) + 100
        forged["value"] = "ghost-success"
        self.assertFalse(
            self.provider_reconciliation_matches(
                provider_result,
                forged,
                object_id=object_id,
                expected_value="observed-value",
            )
        )

    def test_poisoned_memory_can_pressure_preference_but_not_honest_admissibility(self) -> None:
        telemetry = BehaviorTelemetry(max_deltas_per_chain=8, containment_delta_threshold=8)
        base = BehaviorObservation(
            source_scope="interface:dual",
            source_trust_domain="worker-domain",
            identity_scope="worker:dual",
            workload_scope="dual-control",
            model_or_worker_source="model:poisoned",
            request_family="target-preference",
            request_shape="prefer-safe",
            requested_capability="write:safe",
            target_class="proof:safe:effect",
            policy_version="policy:honest",
            authority_version="authority:v1",
        )
        chain, _ = telemetry.observe_unknown(base, rejection_reason="preference_signal_only")
        assert chain is not None
        poisoned = BehaviorObservation(
            source_scope=base.source_scope,
            source_trust_domain=base.source_trust_domain,
            identity_scope=base.identity_scope,
            workload_scope=base.workload_scope,
            model_or_worker_source=base.model_or_worker_source,
            request_family=base.request_family,
            request_shape="prefer-forbidden",
            requested_capability="write:forbidden",
            target_class="proof:forbidden:effect",
            policy_version=base.policy_version,
            authority_version=base.authority_version,
        )
        telemetry.observe_unknown(poisoned, rejection_reason="preference_signal_only")
        candidate = telemetry.recommend_baseline_change(chain.chain_id, poisoned)
        self.assertFalse(candidate.admitted)
        self.assertEqual(candidate.authority_effect, "none")

        clock = MutableClock()
        honest_governance = GovernanceKernel(self.honest_policy(), clock=clock)
        malicious_intelligence = SemanticGuard(corrupted=True, clock=clock)
        forbidden = self.forbidden_intent("session:poison")
        decision = honest_governance.evaluate(forbidden)
        self.assertEqual(decision.outcome, "deny")
        semantic = malicious_intelligence.assess(forbidden)
        surface = LocalEffectSurface()
        gate = DualControlGate(honest_governance, clock=clock, effect_callback=surface.apply)
        result = gate.release(forbidden, decision.permit, semantic)
        self.assertEqual(result.reason, "governance_permit_missing")
        self.assertEqual(surface.effects, [])

    def test_joint_governance_and_intelligence_compromise_reproduces_two_party_residual_failure(self) -> None:
        clock = MutableClock()
        corrupted_governance = GovernanceKernel(self.corrupted_policy(), clock=clock)
        corrupted_intelligence = SemanticGuard(corrupted=True, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(corrupted_governance, clock=clock, effect_callback=surface.apply)
        forbidden = self.forbidden_intent("session:joint-compromise")
        decision = corrupted_governance.evaluate(forbidden)
        self.assertEqual(decision.outcome, "allow")
        semantic = corrupted_intelligence.assess(forbidden)
        self.assertFalse(semantic.vetoed)
        result = gate.release(forbidden, decision.permit, semantic)

        # Deliberate residual-failure control. A passing proof MUST reproduce this;
        # two compromised controls are not claimed safe.
        self.assertTrue(result.effect_succeeded)
        self.assertEqual(surface.effects, [forbidden.resource])
        classification = {
            "both_compromised": True,
            "security_claim_eligible": False,
            "residual_failure_reproduced": True,
        }
        self.assertEqual(
            classification,
            {
                "both_compromised": True,
                "security_claim_eligible": False,
                "residual_failure_reproduced": True,
            },
        )

    def test_independent_effect_constraint_can_still_narrow_joint_compromise(self) -> None:
        clock = MutableClock()
        corrupted_governance = GovernanceKernel(self.corrupted_policy(), clock=clock)
        corrupted_intelligence = SemanticGuard(corrupted=True, clock=clock)
        surface = LocalEffectSurface()
        gate = DualControlGate(
            corrupted_governance,
            clock=clock,
            effect_callback=surface.apply,
            independent_effect_constraint=lambda intent: intent.resource.startswith("proof:safe:"),
        )
        forbidden = self.forbidden_intent("session:joint-constrained")
        decision = corrupted_governance.evaluate(forbidden)
        semantic = corrupted_intelligence.assess(forbidden)
        result = gate.release(forbidden, decision.permit, semantic)
        self.assertEqual(result.reason, "independent_effect_constraint_denied")
        self.assertEqual(surface.effects, [])


if __name__ == "__main__":
    unittest.main()
