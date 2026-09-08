from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import hmac
import json
import unittest


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class ObserverIdentity:
    observer_id: str
    credential_id: str
    process_domain: str
    control_plane: str
    upstream_trust_domain: str

    def __post_init__(self) -> None:
        if not all(
            (
                self.observer_id,
                self.credential_id,
                self.process_domain,
                self.control_plane,
                self.upstream_trust_domain,
            )
        ):
            raise ValueError("observer identity fields must be non-empty")


@dataclass(frozen=True)
class Observation:
    schema: str
    observation_id: str
    identity: ObserverIdentity
    object_id: str
    version: int
    value: str
    source_event_id: str
    observed_at_ns: int
    expires_at_ns: int
    signature: str = ""

    def __post_init__(self) -> None:
        if self.schema != "pulpo.observation-independence.proof.v0":
            raise ValueError("unsupported observation schema")
        if not self.observation_id or not self.object_id or self.version <= 0:
            raise ValueError("observation object identity invalid")
        if not self.source_event_id or not self.value:
            raise ValueError("observation evidence fields must be non-empty")
        if self.observed_at_ns <= 0 or self.expires_at_ns <= self.observed_at_ns:
            raise ValueError("observation time bounds invalid")

    def signing_bytes(self) -> bytes:
        payload = asdict(self)
        payload.pop("signature")
        return _canonical(payload)


class ObservationSigner:
    def __init__(self, identity: ObserverIdentity, secret: bytes) -> None:
        if not secret:
            raise ValueError("proof signing secret required")
        self.identity = identity
        self.secret = secret
        self.counter = 0

    def observe(
        self,
        *,
        object_id: str,
        version: int,
        value: str,
        source_event_id: str,
        now_ns: int,
        ttl_ns: int = 1_000_000,
    ) -> Observation:
        self.counter += 1
        unsigned = Observation(
            schema="pulpo.observation-independence.proof.v0",
            observation_id=f"{self.identity.observer_id}:{self.counter}",
            identity=self.identity,
            object_id=object_id,
            version=version,
            value=value,
            source_event_id=source_event_id,
            observed_at_ns=now_ns,
            expires_at_ns=now_ns + ttl_ns,
        )
        signature = hmac.new(self.secret, unsigned.signing_bytes(), sha256).hexdigest()
        return replace(unsigned, signature=signature)


@dataclass(frozen=True)
class IndependenceProfile:
    require_distinct_credentials: bool = True
    require_distinct_processes: bool = True
    require_distinct_control_planes: bool = True
    require_distinct_upstream_domains: bool = True


@dataclass(frozen=True)
class EvidenceDecision:
    outcome: str
    reason: str
    credential_independent: bool
    process_independent: bool
    control_plane_independent: bool
    upstream_independent: bool
    eligible_for_reconciliation: bool
    objective_reality_claim_eligible: bool = False


class ObservationVerifier:
    """Proof-only verifier with an identity registry bound to each credential."""

    def __init__(self, registry: dict[str, tuple[ObserverIdentity, bytes]]) -> None:
        self.registry = dict(registry)

    def verify(self, observation: Observation) -> bool:
        entry = self.registry.get(observation.identity.credential_id)
        if entry is None:
            return False
        expected_identity, secret = entry
        if observation.identity != expected_identity:
            return False
        expected = hmac.new(secret, observation.signing_bytes(), sha256).hexdigest()
        return hmac.compare_digest(expected, observation.signature)


class ObservationReconciler:
    """Classifies evidence sufficiency; it does not manufacture objective truth."""

    def __init__(
        self,
        verifier: ObservationVerifier,
        *,
        profile: IndependenceProfile | None = None,
        required_observers: int = 2,
    ) -> None:
        self.verifier = verifier
        self.profile = profile or IndependenceProfile()
        self.required_observers = required_observers

    @staticmethod
    def _independence(observations: list[Observation]) -> tuple[bool, bool, bool, bool]:
        count = len(observations)
        credentials = len({item.identity.credential_id for item in observations}) == count
        processes = len({item.identity.process_domain for item in observations}) == count
        controls = len({item.identity.control_plane for item in observations}) == count
        upstreams = len({item.identity.upstream_trust_domain for item in observations}) == count
        return credentials, processes, controls, upstreams

    def classify(
        self,
        observations: list[Observation],
        *,
        expected_object_id: str,
        expected_version: int,
        expected_value: str,
        now_ns: int,
    ) -> EvidenceDecision:
        empty = (False, False, False, False)
        if len(observations) < self.required_observers:
            return EvidenceDecision(
                "unknown",
                "required_observer_unavailable",
                *empty,
                eligible_for_reconciliation=False,
            )
        if len({item.observation_id for item in observations}) != len(observations):
            return EvidenceDecision(
                "unknown",
                "duplicate_observation",
                *empty,
                eligible_for_reconciliation=False,
            )
        if any(not self.verifier.verify(item) for item in observations):
            return EvidenceDecision(
                "unknown",
                "observation_signature_or_identity_invalid",
                *empty,
                eligible_for_reconciliation=False,
            )
        independence = self._independence(observations)
        if any(not (item.observed_at_ns <= now_ns < item.expires_at_ns) for item in observations):
            return EvidenceDecision(
                "unknown",
                "observation_stale",
                *independence,
                eligible_for_reconciliation=False,
            )

        exact_claims = {
            (item.object_id, item.version, item.value, item.source_event_id)
            for item in observations
        }
        if len(exact_claims) != 1:
            return EvidenceDecision(
                "mismatch",
                "observer_claims_disagree",
                *independence,
                eligible_for_reconciliation=False,
            )
        claim = next(iter(exact_claims))
        if claim[:3] != (expected_object_id, expected_version, expected_value):
            return EvidenceDecision(
                "mismatch",
                "observation_does_not_match_expected_effect",
                *independence,
                eligible_for_reconciliation=False,
            )

        required = (
            (self.profile.require_distinct_credentials, independence[0], "credential"),
            (self.profile.require_distinct_processes, independence[1], "process"),
            (self.profile.require_distinct_control_planes, independence[2], "control_plane"),
            (self.profile.require_distinct_upstream_domains, independence[3], "upstream_trust_domain"),
        )
        for enabled, satisfied, label in required:
            if enabled and not satisfied:
                return EvidenceDecision(
                    "unknown",
                    f"insufficient_independence:{label}",
                    *independence,
                    eligible_for_reconciliation=False,
                )

        return EvidenceDecision(
            "eligible",
            "declared_independence_profile_satisfied",
            *independence,
            eligible_for_reconciliation=True,
            objective_reality_claim_eligible=False,
        )


class ObserverIndependenceProof(unittest.TestCase):
    NOW = 1_900_000_000_000_000_000
    OBJECT = "proof:effect:observer-independence"
    VERSION = 7
    VALUE = "committed-value"
    EVENT = "provider-event:7"

    @staticmethod
    def identity(
        name: str,
        *,
        credential: str | None = None,
        process: str | None = None,
        control: str | None = None,
        upstream: str | None = None,
    ) -> ObserverIdentity:
        return ObserverIdentity(
            observer_id=f"observer:{name}",
            credential_id=credential or f"credential:{name}",
            process_domain=process or f"process:{name}",
            control_plane=control or f"control:{name}",
            upstream_trust_domain=upstream or f"upstream:{name}",
        )

    def make_reconciler(
        self,
        identities: list[ObserverIdentity],
        *,
        profile: IndependenceProfile | None = None,
    ) -> tuple[ObservationReconciler, list[ObservationSigner]]:
        signers: list[ObservationSigner] = []
        registry: dict[str, tuple[ObserverIdentity, bytes]] = {}
        for index, identity in enumerate(identities, start=1):
            secret = sha256(f"proof-secret:{index}:{identity.credential_id}".encode()).digest()
            signers.append(ObservationSigner(identity, secret))
            registry[identity.credential_id] = (identity, secret)
        return ObservationReconciler(ObservationVerifier(registry), profile=profile), signers

    def observation(self, signer: ObservationSigner, **overrides: object) -> Observation:
        fields: dict[str, object] = {
            "object_id": self.OBJECT,
            "version": self.VERSION,
            "value": self.VALUE,
            "source_event_id": self.EVENT,
            "now_ns": self.NOW,
        }
        fields.update(overrides)
        return signer.observe(**fields)  # type: ignore[arg-type]

    def classify(
        self,
        reconciler: ObservationReconciler,
        observations: list[Observation],
        **overrides: object,
    ) -> EvidenceDecision:
        fields: dict[str, object] = {
            "expected_object_id": self.OBJECT,
            "expected_version": self.VERSION,
            "expected_value": self.VALUE,
            "now_ns": self.NOW + 1,
        }
        fields.update(overrides)
        return reconciler.classify(observations, **fields)  # type: ignore[arg-type]

    def test_distinct_keys_same_process_are_not_process_independent(self) -> None:
        first = self.identity("a", process="process:shared")
        second = self.identity("b", process="process:shared")
        reconciler, signers = self.make_reconciler([first, second])
        decision = self.classify(reconciler, [self.observation(signers[0]), self.observation(signers[1])])
        self.assertEqual(decision.outcome, "unknown")
        self.assertEqual(decision.reason, "insufficient_independence:process")
        self.assertTrue(decision.credential_independent)
        self.assertFalse(decision.process_independent)

    def test_distinct_processes_same_control_plane_are_not_control_independent(self) -> None:
        first = self.identity("a", control="control:shared")
        second = self.identity("b", control="control:shared")
        reconciler, signers = self.make_reconciler([first, second])
        decision = self.classify(reconciler, [self.observation(signers[0]), self.observation(signers[1])])
        self.assertEqual(decision.reason, "insufficient_independence:control_plane")
        self.assertFalse(decision.control_plane_independent)

    def test_distinct_control_planes_same_upstream_are_not_upstream_independent(self) -> None:
        first = self.identity("a", upstream="provider-admin-api:shared")
        second = self.identity("b", upstream="provider-admin-api:shared")
        reconciler, signers = self.make_reconciler([first, second])
        decision = self.classify(reconciler, [self.observation(signers[0]), self.observation(signers[1])])
        self.assertEqual(decision.reason, "insufficient_independence:upstream_trust_domain")
        self.assertFalse(decision.upstream_independent)

    def test_two_matching_signed_receipts_from_same_liar_source_remain_unknown(self) -> None:
        first = self.identity("a", upstream="liar:shared")
        second = self.identity("b", upstream="liar:shared")
        reconciler, signers = self.make_reconciler([first, second])
        observations = [
            self.observation(signers[0], value="fabricated"),
            self.observation(signers[1], value="fabricated"),
        ]
        decision = self.classify(reconciler, observations, expected_value="fabricated")
        self.assertEqual(decision.outcome, "unknown")
        self.assertFalse(decision.eligible_for_reconciliation)
        self.assertFalse(decision.objective_reality_claim_eligible)

    def test_duplicate_receipt_cannot_create_quorum(self) -> None:
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        receipt = self.observation(signers[0])
        decision = self.classify(reconciler, [receipt, receipt])
        self.assertEqual(decision.reason, "duplicate_observation")
        self.assertFalse(decision.eligible_for_reconciliation)

    def test_contradictory_independent_receipts_are_mismatch(self) -> None:
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        observations = [
            self.observation(signers[0]),
            self.observation(signers[1], value="different-value"),
        ]
        decision = self.classify(reconciler, observations)
        self.assertEqual(decision.outcome, "mismatch")
        self.assertEqual(decision.reason, "observer_claims_disagree")

    def test_missing_required_observer_is_unknown(self) -> None:
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        decision = self.classify(reconciler, [self.observation(signers[0])])
        self.assertEqual(decision.reason, "required_observer_unavailable")
        self.assertFalse(decision.eligible_for_reconciliation)

    def test_tampered_independence_metadata_invalidates_signature_and_registry_binding(self) -> None:
        first = self.identity("a", upstream="upstream:shared")
        second = self.identity("b", upstream="upstream:shared")
        reconciler, signers = self.make_reconciler([first, second])
        honest = self.observation(signers[0])
        forged_identity = replace(honest.identity, upstream_trust_domain="upstream:pretend-independent")
        tampered = replace(honest, identity=forged_identity)
        decision = self.classify(reconciler, [tampered, self.observation(signers[1])])
        self.assertEqual(decision.reason, "observation_signature_or_identity_invalid")

    def test_replayed_old_receipt_is_stale(self) -> None:
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        observations = [self.observation(signers[0]), self.observation(signers[1])]
        decision = self.classify(reconciler, observations, now_ns=self.NOW + 1_000_001)
        self.assertEqual(decision.reason, "observation_stale")
        self.assertFalse(decision.eligible_for_reconciliation)

    def test_matching_exact_claim_with_declared_disjoint_domains_is_evidence_eligible(self) -> None:
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        decision = self.classify(reconciler, [self.observation(signers[0]), self.observation(signers[1])])
        self.assertEqual(decision.outcome, "eligible")
        self.assertTrue(decision.credential_independent)
        self.assertTrue(decision.process_independent)
        self.assertTrue(decision.control_plane_independent)
        self.assertTrue(decision.upstream_independent)
        self.assertTrue(decision.eligible_for_reconciliation)
        self.assertFalse(decision.objective_reality_claim_eligible)

    def test_matching_but_wrong_effect_is_mismatch_even_with_disjoint_domains(self) -> None:
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        observations = [
            self.observation(signers[0], value="wrong"),
            self.observation(signers[1], value="wrong"),
        ]
        decision = self.classify(reconciler, observations)
        self.assertEqual(decision.outcome, "mismatch")
        self.assertEqual(decision.reason, "observation_does_not_match_expected_effect")

    def test_fully_distinct_colluding_receipts_still_cannot_prove_objective_reality(self) -> None:
        # Epistemic residual control: even declared-disjoint signers can collude or
        # share a false premise outside the modeled metadata. The classifier may
        # accept the declared evidence profile, but it must never convert that
        # cryptographic consistency into an objective-reality claim.
        hidden_reality = "actual-world-value"
        collusive_claim = "coordinated-false-value"
        first = self.identity("a")
        second = self.identity("b")
        reconciler, signers = self.make_reconciler([first, second])
        observations = [
            self.observation(signers[0], value=collusive_claim),
            self.observation(signers[1], value=collusive_claim),
        ]
        decision = self.classify(reconciler, observations, expected_value=collusive_claim)
        self.assertEqual(decision.outcome, "eligible")
        self.assertNotEqual(hidden_reality, collusive_claim)
        self.assertFalse(decision.objective_reality_claim_eligible)


if __name__ == "__main__":
    unittest.main()
