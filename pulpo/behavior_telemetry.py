"""Bounded adaptive-governance telemetry with no execution authority.

This module records and compresses rejected/unknown behavior for governance
analysis.  It is deliberately not a router, policy engine, authority service,
executor, memory governor, or evidence ledger.  Its outputs may change
attention and recommendations; they cannot issue permits, mutate policy, or
admit their own baselines.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from typing import Any, Callable, Iterable, Mapping


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class BehaviorObservation:
    source_scope: str
    source_trust_domain: str
    identity_scope: str
    workload_scope: str
    model_or_worker_source: str
    request_family: str
    request_shape: str
    requested_capability: str
    target_class: str
    policy_version: str
    authority_version: str

    def __post_init__(self) -> None:
        for value in asdict(self).values():
            if not isinstance(value, str) or not value:
                raise ValueError("behavior observation fields must be non-empty strings")

    @property
    def fingerprint(self) -> str:
        return _hash({"schema": "pulpo.behavior-observation.v0", **asdict(self)})

    @property
    def chain_key(self) -> str:
        # A chain groups the same request family inside the same accountable
        # context while allowing material fields to become explicit deltas.
        return _hash(
            {
                "schema": "pulpo.behavior-chain-key.v0",
                "source_scope": self.source_scope,
                "identity_scope": self.identity_scope,
                "workload_scope": self.workload_scope,
                "model_or_worker_source": self.model_or_worker_source,
                "request_family": self.request_family,
            }
        )


@dataclass(frozen=True)
class BaselineEvent:
    chain_id: str
    observation: BehaviorObservation
    rejection_reason: str
    execution_attempted: bool = False
    immutable: bool = True

    def __post_init__(self) -> None:
        if not self.chain_id or not self.rejection_reason:
            raise ValueError("baseline identity and rejection reason are required")
        if self.execution_attempted:
            raise ValueError("rejected baseline cannot represent execution")
        if not self.immutable:
            raise ValueError("baseline must be immutable")

    @property
    def event_hash(self) -> str:
        return _hash(
            {
                "schema": "pulpo.behavior-baseline.v0",
                "chain_id": self.chain_id,
                "observation": asdict(self.observation),
                "rejection_reason": self.rejection_reason,
                "execution_attempted": self.execution_attempted,
                "immutable": self.immutable,
            }
        )


@dataclass(frozen=True)
class DeltaEvent:
    chain_id: str
    baseline_event_hash: str
    previous_event_hash: str
    observation: BehaviorObservation
    changed_fields: tuple[tuple[str, str, str], ...]
    materiality_class: str
    anomaly_score: float
    execution_attempted: bool = False

    def __post_init__(self) -> None:
        if not self.changed_fields:
            raise ValueError("delta must contain a material change")
        if self.materiality_class not in {"low", "medium", "high"}:
            raise ValueError("invalid materiality class")
        if not (0 <= self.anomaly_score <= 1):
            raise ValueError("anomaly score must be bounded")
        if self.execution_attempted:
            raise ValueError("rejected delta cannot represent execution")

    @property
    def event_hash(self) -> str:
        return _hash(
            {
                "schema": "pulpo.behavior-delta.v0",
                "chain_id": self.chain_id,
                "baseline_event_hash": self.baseline_event_hash,
                "previous_event_hash": self.previous_event_hash,
                "observation": asdict(self.observation),
                "changed_fields": self.changed_fields,
                "materiality_class": self.materiality_class,
                "anomaly_score": self.anomaly_score,
                "execution_attempted": self.execution_attempted,
            }
        )


@dataclass(frozen=True)
class Checkpoint:
    chain_id: str
    baseline_event_hash: str
    covered_delta_hashes: tuple[str, ...]
    repeat_count: int
    delta_overflow_count: int
    current_event_hash: str
    snapshot_hash: str

    @classmethod
    def build(
        cls,
        *,
        chain_id: str,
        baseline_event_hash: str,
        covered_delta_hashes: Iterable[str],
        repeat_count: int,
        delta_overflow_count: int,
        current_event_hash: str,
    ) -> "Checkpoint":
        covered = tuple(covered_delta_hashes)
        payload = {
            "schema": "pulpo.behavior-checkpoint.v0",
            "chain_id": chain_id,
            "baseline_event_hash": baseline_event_hash,
            "covered_delta_hashes": covered,
            "repeat_count": repeat_count,
            "delta_overflow_count": delta_overflow_count,
            "current_event_hash": current_event_hash,
        }
        return cls(
            chain_id=chain_id,
            baseline_event_hash=baseline_event_hash,
            covered_delta_hashes=covered,
            repeat_count=repeat_count,
            delta_overflow_count=delta_overflow_count,
            current_event_hash=current_event_hash,
            snapshot_hash=_hash(payload),
        )

    def verify(self) -> bool:
        expected = Checkpoint.build(
            chain_id=self.chain_id,
            baseline_event_hash=self.baseline_event_hash,
            covered_delta_hashes=self.covered_delta_hashes,
            repeat_count=self.repeat_count,
            delta_overflow_count=self.delta_overflow_count,
            current_event_hash=self.current_event_hash,
        )
        return expected.snapshot_hash == self.snapshot_hash


@dataclass(frozen=True)
class ContextualBaseline:
    workload_scope: str
    version: int
    expected_unknown_rate: float
    tolerance: float
    admission_ref: str

    def __post_init__(self) -> None:
        if not self.workload_scope or self.version <= 0 or not self.admission_ref:
            raise ValueError("contextual baseline identity is required")
        if not (0 <= self.expected_unknown_rate <= 1):
            raise ValueError("expected rate must be bounded")
        if not (0 <= self.tolerance <= 1):
            raise ValueError("tolerance must be bounded")

    @property
    def baseline_hash(self) -> str:
        return _hash({"schema": "pulpo.contextual-baseline.v0", **asdict(self)})


@dataclass(frozen=True)
class AnomalySignal:
    scope: str
    score: float
    reason: str
    evidence_status: str
    authority_effect: str = "none"
    execution_allowed: bool = False

    def __post_init__(self) -> None:
        if not (0 <= self.score <= 1):
            raise ValueError("anomaly score must be bounded")
        if self.evidence_status not in {"observed", "unknown"}:
            raise ValueError("invalid evidence status")
        if self.authority_effect != "none" or self.execution_allowed:
            raise ValueError("anomaly signals are non-authoritative")


@dataclass(frozen=True)
class ContainmentDisposition:
    scope: str
    action: str
    reason: str
    execution_attempted: bool = False
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if self.action not in {"reject", "contain"}:
            raise ValueError("containment may only reject or contain")
        if self.execution_attempted:
            raise ValueError("unknown behavior may not reach execution")
        if self.authority_effect != "none":
            raise ValueError("containment cannot expand authority")


@dataclass(frozen=True)
class BaselineCandidate:
    candidate_id: str
    chain_id: str
    active_baseline_hash: str
    proposed_fingerprint: str
    changed_fields: tuple[tuple[str, str, str], ...]
    evidence_refs: tuple[str, ...]
    source_trust_domains: tuple[str, ...]
    poisoning_flags: tuple[str, ...]
    proposed_version: int
    admitted: bool = False
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if self.proposed_version <= 1:
            raise ValueError("candidate must propose a later version")
        if self.admitted or self.authority_effect != "none":
            raise ValueError("telemetry candidate cannot admit or authorize itself")


@dataclass(frozen=True)
class BaselineState:
    """Projection of a baseline already admitted by an external authority path.

    This object does not validate or create authority.  `admission_ref` must
    identify the separately governed transition that already occurred.
    """

    workload_scope: str
    version: int
    baseline_hash: str
    admission_ref: str

    def __post_init__(self) -> None:
        if not self.workload_scope or self.version <= 0 or not self.baseline_hash or not self.admission_ref:
            raise ValueError("admitted baseline projection requires explicit transition reference")


@dataclass
class BehaviorChain:
    baseline: BaselineEvent
    last_observation: BehaviorObservation
    deltas: list[DeltaEvent] = field(default_factory=list)
    checkpoints: list[Checkpoint] = field(default_factory=list)
    repeat_count: int = 0
    delta_overflow_count: int = 0
    contained: bool = False
    source_trust_domains: set[str] = field(default_factory=set)

    @property
    def chain_id(self) -> str:
        return self.baseline.chain_id

    @property
    def current_event_hash(self) -> str:
        return self.deltas[-1].event_hash if self.deltas else self.baseline.event_hash


class BehaviorTelemetry:
    """Bounded evidence projection for rejected behavior.

    The class has no executor, kernel, policy, permit, directive, or authority
    references.  `execution_callback` exists only so tests/callers can prove it
    is never invoked for rejected unknown behavior.
    """

    _HIGH_MATERIALITY_FIELDS = {
        "requested_capability",
        "target_class",
        "policy_version",
        "authority_version",
        "identity_scope",
    }

    def __init__(
        self,
        *,
        max_contexts: int = 32,
        max_deltas_per_chain: int = 32,
        checkpoint_every: int = 8,
        containment_delta_threshold: int = 12,
        repeat_pressure_threshold: int = 1000,
    ) -> None:
        if min(max_contexts, max_deltas_per_chain, checkpoint_every, containment_delta_threshold, repeat_pressure_threshold) <= 0:
            raise ValueError("telemetry bounds must be positive")
        self.max_contexts = max_contexts
        self.max_deltas_per_chain = max_deltas_per_chain
        self.checkpoint_every = checkpoint_every
        self.containment_delta_threshold = containment_delta_threshold
        self.repeat_pressure_threshold = repeat_pressure_threshold
        self._chains: dict[str, BehaviorChain] = {}
        self._contexts: set[tuple[str, str]] = set()
        self.context_overflow_count = 0

    @property
    def chains(self) -> Mapping[str, BehaviorChain]:
        return dict(self._chains)

    def observe_unknown(
        self,
        observation: BehaviorObservation,
        *,
        rejection_reason: str,
        execution_callback: Callable[[BehaviorObservation], object] | None = None,
    ) -> tuple[BehaviorChain | None, ContainmentDisposition]:
        del execution_callback  # Unknown/rejected telemetry never reaches execution.
        if not rejection_reason:
            raise ValueError("rejection reason is required")

        context = (observation.source_scope, observation.workload_scope)
        if context not in self._contexts and len(self._contexts) >= self.max_contexts:
            self.context_overflow_count += 1
            return None, ContainmentDisposition(
                scope=observation.workload_scope,
                action="contain",
                reason="context_cardinality_overflow",
            )
        self._contexts.add(context)

        chain = self._chains.get(observation.chain_key)
        if chain is None:
            baseline = BaselineEvent(
                chain_id=observation.chain_key,
                observation=observation,
                rejection_reason=rejection_reason,
            )
            chain = BehaviorChain(
                baseline=baseline,
                last_observation=observation,
                source_trust_domains={observation.source_trust_domain},
            )
            self._chains[observation.chain_key] = chain
            return chain, ContainmentDisposition(
                scope=observation.workload_scope,
                action="reject",
                reason=rejection_reason,
            )

        chain.source_trust_domains.add(observation.source_trust_domain)
        if observation.fingerprint == chain.last_observation.fingerprint:
            chain.repeat_count += 1
            if chain.repeat_count >= self.repeat_pressure_threshold:
                chain.contained = True
            return chain, ContainmentDisposition(
                scope=observation.workload_scope,
                action="contain" if chain.contained else "reject",
                reason="repeat_pressure" if chain.contained else rejection_reason,
            )

        changed = self._changed_fields(chain.last_observation, observation)
        if len(chain.deltas) >= self.max_deltas_per_chain:
            chain.delta_overflow_count += 1
            chain.contained = True
            chain.last_observation = observation
            return chain, ContainmentDisposition(
                scope=observation.workload_scope,
                action="contain",
                reason="delta_rate_bounded",
            )

        materiality = "high" if any(name in self._HIGH_MATERIALITY_FIELDS for name, _, _ in changed) else "medium"
        score = 0.9 if materiality == "high" else 0.5
        delta = DeltaEvent(
            chain_id=chain.chain_id,
            baseline_event_hash=chain.baseline.event_hash,
            previous_event_hash=chain.current_event_hash,
            observation=observation,
            changed_fields=changed,
            materiality_class=materiality,
            anomaly_score=score,
        )
        chain.deltas.append(delta)
        chain.last_observation = observation
        if len(chain.deltas) >= self.containment_delta_threshold:
            chain.contained = True
        if len(chain.deltas) % self.checkpoint_every == 0:
            chain.checkpoints.append(self._checkpoint(chain))
        return chain, ContainmentDisposition(
            scope=observation.workload_scope,
            action="contain" if chain.contained else "reject",
            reason="material_drift_contained" if chain.contained else rejection_reason,
        )

    @staticmethod
    def _changed_fields(
        previous: BehaviorObservation,
        current: BehaviorObservation,
    ) -> tuple[tuple[str, str, str], ...]:
        previous_values = asdict(previous)
        current_values = asdict(current)
        return tuple(
            (name, str(previous_values[name]), str(current_values[name]))
            for name in sorted(previous_values)
            if previous_values[name] != current_values[name]
        )

    @staticmethod
    def _checkpoint(chain: BehaviorChain) -> Checkpoint:
        return Checkpoint.build(
            chain_id=chain.chain_id,
            baseline_event_hash=chain.baseline.event_hash,
            covered_delta_hashes=(delta.event_hash for delta in chain.deltas),
            repeat_count=chain.repeat_count,
            delta_overflow_count=chain.delta_overflow_count,
            current_event_hash=chain.current_event_hash,
        )

    def checkpoint_now(self, chain_id: str) -> Checkpoint:
        chain = self._chains[chain_id]
        checkpoint = self._checkpoint(chain)
        chain.checkpoints.append(checkpoint)
        return checkpoint

    def verify_checkpoint(self, chain_id: str, checkpoint: Checkpoint) -> bool:
        chain = self._chains.get(chain_id)
        if chain is None or not checkpoint.verify():
            return False
        if checkpoint.baseline_event_hash != chain.baseline.event_hash:
            return False
        covered = tuple(delta.event_hash for delta in chain.deltas[: len(checkpoint.covered_delta_hashes)])
        return covered == checkpoint.covered_delta_hashes

    def recommend_baseline_change(
        self,
        chain_id: str,
        proposed: BehaviorObservation,
        *,
        proposed_version: int = 2,
    ) -> BaselineCandidate:
        chain = self._chains[chain_id]
        changed = self._changed_fields(chain.baseline.observation, proposed)
        evidence_refs = (chain.baseline.event_hash, *(delta.event_hash for delta in chain.deltas))
        flags: list[str] = []
        if len(chain.source_trust_domains) < 2:
            flags.append("single_trust_domain")
        if chain.delta_overflow_count:
            flags.append("delta_overflow")
        if chain.repeat_count >= self.repeat_pressure_threshold:
            flags.append("repeat_pressure")
        if not changed:
            flags.append("no_material_baseline_change")
        candidate_payload = {
            "schema": "pulpo.baseline-candidate.v0",
            "chain_id": chain_id,
            "active_baseline_hash": chain.baseline.event_hash,
            "proposed_fingerprint": proposed.fingerprint,
            "changed_fields": changed,
            "evidence_refs": evidence_refs,
            "source_trust_domains": sorted(chain.source_trust_domains),
            "poisoning_flags": sorted(flags),
            "proposed_version": proposed_version,
            "admitted": False,
            "authority_effect": "none",
        }
        return BaselineCandidate(
            candidate_id=_hash(candidate_payload),
            chain_id=chain_id,
            active_baseline_hash=chain.baseline.event_hash,
            proposed_fingerprint=proposed.fingerprint,
            changed_fields=changed,
            evidence_refs=tuple(evidence_refs),
            source_trust_domains=tuple(sorted(chain.source_trust_domains)),
            poisoning_flags=tuple(sorted(flags)),
            proposed_version=proposed_version,
        )

    @staticmethod
    def contextual_rate_signal(
        observed_rate: float,
        baseline: ContextualBaseline,
    ) -> AnomalySignal:
        if not (0 <= observed_rate <= 1):
            raise ValueError("observed rate must be bounded")
        distance = abs(observed_rate - baseline.expected_unknown_rate)
        score = min(1.0, distance / max(baseline.tolerance, 0.000001))
        return AnomalySignal(
            scope=baseline.workload_scope,
            score=score,
            reason="contextual_unknown_rate_deviation",
            evidence_status="observed",
        )

    @staticmethod
    def missing_evidence_signal(scope: str) -> AnomalySignal:
        if not scope:
            raise ValueError("scope is required")
        return AnomalySignal(
            scope=scope,
            score=1.0,
            reason="telemetry_missing_unknown_state",
            evidence_status="unknown",
        )

    @staticmethod
    def anomaly_from_chain(chain: BehaviorChain) -> AnomalySignal:
        score = 0.0
        if chain.deltas:
            score = max(delta.anomaly_score for delta in chain.deltas)
        if chain.contained:
            score = max(score, 0.95)
        return AnomalySignal(
            scope=chain.baseline.observation.workload_scope,
            score=score,
            reason="behavior_chain_attention_signal",
            evidence_status="observed",
        )
