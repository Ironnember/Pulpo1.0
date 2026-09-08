"""Deterministic, zero-provider-effect behavioral governance telemetry.

These frozen value objects describe rejected unknown behavior. They do not own
canonical state, evaluate policy, issue permits, call executors, admit learned
baselines, or create another evidence ledger. A trusted caller may later attach
their projections to Pulpo's existing governed evidence path.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from typing import Literal


class BehavioralGovernanceError(ValueError):
    """Raised when behavioral telemetry violates its non-authority boundary."""


Materiality = Literal["micro", "material", "capability", "constitutional"]
SignalClass = Literal[
    "baseline_created",
    "repeat",
    "material_change",
    "capability_change",
    "constitutional_change",
    "context_overflow",
    "delta_flood",
    "context_normal",
    "context_anomaly",
    "context_containment",
    "baseline_recommendation",
    "unknown",
]

_STATE_FIELDS = (
    "source_scope",
    "identity_scope",
    "workload_scope",
    "worker_source",
    "request_shape",
    "requested_capability",
    "target_class",
    "policy_version",
    "authority_version",
)
_CONTEXT_FIELDS = (
    "source_scope",
    "identity_scope",
    "workload_scope",
    "worker_source",
)
_MICRO_FIELDS = frozenset({"request_shape", "worker_source"})
_CAPABILITY_FIELDS = frozenset({"requested_capability"})
_CONSTITUTIONAL_FIELDS = frozenset({"policy_version", "authority_version"})
_SIGNAL_CLASSES = frozenset(
    {
        "baseline_created",
        "repeat",
        "material_change",
        "capability_change",
        "constitutional_change",
        "context_overflow",
        "delta_flood",
        "context_normal",
        "context_anomaly",
        "context_containment",
        "baseline_recommendation",
        "unknown",
    }
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def _require_digest(value: str, reason: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BehavioralGovernanceError(reason)


def _require_text(value: str, reason: str, *, maximum: int = 256) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise BehavioralGovernanceError(reason)


def _value_hash(value: str) -> str:
    return _digest({"value": value})


def _advance_history(
    previous_history_hash: str,
    *,
    kind: str,
    sequence: int,
    evidence_hash: str,
) -> str:
    return _digest(
        {
            "schema": "pulpo.behavior-history-link.v0",
            "previous_history_hash": previous_history_hash,
            "kind": kind,
            "sequence": sequence,
            "evidence_hash": evidence_hash,
        }
    )


@dataclass(frozen=True, slots=True)
class BaselineState:
    """A bounded normalized observation, not an admitted authorization state."""

    source_scope: str
    identity_scope: str
    workload_scope: str
    worker_source: str
    request_shape: str
    requested_capability: str
    target_class: str
    policy_version: str
    authority_version: str
    schema: str = "pulpo.behavior-baseline-state.v0"

    def __post_init__(self) -> None:
        for field_name in _STATE_FIELDS:
            _require_text(
                getattr(self, field_name),
                f"behavior_state_{field_name}_invalid",
            )
        if self.schema != "pulpo.behavior-baseline-state.v0":
            raise BehavioralGovernanceError("behavior_state_schema_invalid")

    @property
    def state_hash(self) -> str:
        return _digest(asdict(self))

    @property
    def context_hash(self) -> str:
        return _digest(
            {
                "schema": "pulpo.behavior-context.v0",
                **{
                    field_name: getattr(self, field_name)
                    for field_name in _CONTEXT_FIELDS
                },
            }
        )

    @property
    def behavior_signature(self) -> str:
        return _digest(
            {
                "schema": "pulpo.behavior-signature.v0",
                **{
                    field_name: getattr(self, field_name)
                    for field_name in _STATE_FIELDS
                },
            }
        )


@dataclass(frozen=True, slots=True)
class BaselineEvent:
    """The immutable first rejected unknown in one behavior chain."""

    sequence: int
    state: BaselineState
    rejection_reason: str
    disposition: str = "rejected_unknown"
    execution_attempted: bool = False
    canonical_state_mutation: bool = False
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.behavior-baseline-event.v0"

    def __post_init__(self) -> None:
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence <= 0:
            raise BehavioralGovernanceError("baseline_sequence_invalid")
        if not isinstance(self.state, BaselineState):
            raise BehavioralGovernanceError("baseline_state_invalid")
        _require_text(self.rejection_reason, "baseline_rejection_reason_invalid")
        if self.disposition != "rejected_unknown":
            raise BehavioralGovernanceError("baseline_disposition_invalid")
        if self.execution_attempted is not False:
            raise BehavioralGovernanceError("rejected_unknown_cannot_execute")
        if self.canonical_state_mutation is not False:
            raise BehavioralGovernanceError("baseline_cannot_mutate_canonical_state")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("baseline_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("baseline_cannot_create_governed_effect")
        if self.schema != "pulpo.behavior-baseline-event.v0":
            raise BehavioralGovernanceError("baseline_schema_invalid")

    @property
    def event_hash(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True, slots=True)
class DeltaEvent:
    """One material differential from a baseline-linked previous event."""

    chain_id: str
    baseline_event_hash: str
    previous_event_hash: str
    sequence: int
    changes: tuple[tuple[str, str, str], ...]
    materiality: Materiality
    anomaly_score_after_delta: int
    disposition: str = "rejected_unknown"
    execution_attempted: bool = False
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.behavior-delta-event.v0"

    def __post_init__(self) -> None:
        _require_digest(self.chain_id, "delta_chain_id_invalid")
        _require_digest(self.baseline_event_hash, "delta_baseline_hash_invalid")
        _require_digest(self.previous_event_hash, "delta_previous_hash_invalid")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence <= 0:
            raise BehavioralGovernanceError("delta_sequence_invalid")
        if not self.changes:
            raise BehavioralGovernanceError("delta_changes_required")
        names = []
        for field_name, previous_value_hash, new_value in self.changes:
            if field_name not in _STATE_FIELDS:
                raise BehavioralGovernanceError("delta_field_invalid")
            _require_digest(previous_value_hash, "delta_previous_value_hash_invalid")
            _require_text(new_value, "delta_new_value_invalid")
            names.append(field_name)
        if names != sorted(names) or len(names) != len(set(names)):
            raise BehavioralGovernanceError("delta_changes_not_canonical")
        if self.materiality not in ("micro", "material", "capability", "constitutional"):
            raise BehavioralGovernanceError("delta_materiality_invalid")
        if (
            isinstance(self.anomaly_score_after_delta, bool)
            or not isinstance(self.anomaly_score_after_delta, int)
            or not 0 <= self.anomaly_score_after_delta <= 100
        ):
            raise BehavioralGovernanceError("delta_anomaly_score_invalid")
        if self.disposition != "rejected_unknown":
            raise BehavioralGovernanceError("delta_disposition_invalid")
        if self.execution_attempted is not False:
            raise BehavioralGovernanceError("rejected_delta_cannot_execute")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("delta_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("delta_cannot_create_governed_effect")
        if self.schema != "pulpo.behavior-delta-event.v0":
            raise BehavioralGovernanceError("delta_schema_invalid")

    @property
    def event_hash(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A compact state commitment over covered deltas, not rewritten history."""

    chain_id: str
    baseline_event_hash: str
    prior_checkpoint_hash: str | None
    covered_event_hash: str
    history_hash: str
    through_sequence: int
    covered_delta_count: int
    repeat_count: int
    summarized_state: BaselineState
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.behavior-checkpoint.v0"

    def __post_init__(self) -> None:
        _require_digest(self.chain_id, "checkpoint_chain_id_invalid")
        _require_digest(self.baseline_event_hash, "checkpoint_baseline_hash_invalid")
        if self.prior_checkpoint_hash is not None:
            _require_digest(self.prior_checkpoint_hash, "checkpoint_parent_invalid")
        _require_digest(self.covered_event_hash, "checkpoint_event_hash_invalid")
        _require_digest(self.history_hash, "checkpoint_history_hash_invalid")
        if (
            isinstance(self.through_sequence, bool)
            or not isinstance(self.through_sequence, int)
            or self.through_sequence <= 0
        ):
            raise BehavioralGovernanceError("checkpoint_sequence_invalid")
        if (
            isinstance(self.covered_delta_count, bool)
            or not isinstance(self.covered_delta_count, int)
            or self.covered_delta_count <= 0
        ):
            raise BehavioralGovernanceError("checkpoint_delta_count_invalid")
        if isinstance(self.repeat_count, bool) or not isinstance(self.repeat_count, int) or self.repeat_count <= 0:
            raise BehavioralGovernanceError("checkpoint_repeat_count_invalid")
        if not isinstance(self.summarized_state, BaselineState):
            raise BehavioralGovernanceError("checkpoint_state_invalid")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("checkpoint_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("checkpoint_cannot_create_governed_effect")
        if self.schema != "pulpo.behavior-checkpoint.v0":
            raise BehavioralGovernanceError("checkpoint_schema_invalid")

    @property
    def checkpoint_hash(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True, slots=True)
class AnomalySignal:
    """Evidence-only anomaly output that can never become execution authority."""

    context_hash: str
    classification: SignalClass
    score: int | None
    reason: str
    recommended_baseline_hash: str | None = None
    safety: str = "not_established"
    evidence_only: bool = True
    execution_authorized: bool = False
    baseline_admitted: bool = False
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.behavior-anomaly-signal.v0"

    def __post_init__(self) -> None:
        _require_digest(self.context_hash, "anomaly_context_hash_invalid")
        if self.classification not in _SIGNAL_CLASSES:
            raise BehavioralGovernanceError("anomaly_classification_invalid")
        if self.score is not None and (
            isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or not 0 <= self.score <= 100
        ):
            raise BehavioralGovernanceError("anomaly_score_invalid")
        _require_text(self.reason, "anomaly_reason_invalid")
        if self.recommended_baseline_hash is not None:
            _require_digest(
                self.recommended_baseline_hash,
                "anomaly_recommended_baseline_hash_invalid",
            )
        if self.classification == "baseline_recommendation":
            if self.recommended_baseline_hash is None or self.score is not None:
                raise BehavioralGovernanceError("baseline_recommendation_invalid")
        elif self.recommended_baseline_hash is not None:
            raise BehavioralGovernanceError("baseline_recommendation_scope_invalid")
        if self.classification == "unknown":
            if self.score is not None or self.safety != "unknown":
                raise BehavioralGovernanceError("unknown_signal_invalid")
        elif self.safety != "not_established":
            raise BehavioralGovernanceError("anomaly_cannot_establish_safety")
        if self.evidence_only is not True:
            raise BehavioralGovernanceError("anomaly_must_be_evidence_only")
        if self.execution_authorized is not False:
            raise BehavioralGovernanceError("anomaly_cannot_authorize_execution")
        if self.baseline_admitted is not False:
            raise BehavioralGovernanceError("anomaly_cannot_admit_baseline")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("anomaly_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("anomaly_cannot_create_governed_effect")
        if self.schema != "pulpo.behavior-anomaly-signal.v0":
            raise BehavioralGovernanceError("anomaly_schema_invalid")

    @property
    def is_safe(self) -> bool:
        return False

    @property
    def signal_hash(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ContainmentDisposition:
    """A bounded block/observe output that never expands policy or authority."""

    action: Literal["observe", "block"]
    reason: str
    evidence_scope: tuple[str, ...]
    containment_scope: tuple[str, ...]
    execution_allowed: bool = False
    policy_expansion: bool = False
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.behavior-containment-disposition.v0"

    def __post_init__(self) -> None:
        if self.action not in ("observe", "block"):
            raise BehavioralGovernanceError("containment_action_invalid")
        _require_text(self.reason, "containment_reason_invalid")
        if not self.evidence_scope:
            raise BehavioralGovernanceError("containment_evidence_scope_required")
        for scope_hash in self.evidence_scope:
            _require_digest(scope_hash, "containment_evidence_scope_invalid")
        for scope_hash in self.containment_scope:
            _require_digest(scope_hash, "containment_scope_invalid")
        if not set(self.containment_scope).issubset(self.evidence_scope):
            raise BehavioralGovernanceError("containment_exceeds_evidence_scope")
        if self.action == "block" and not self.containment_scope:
            raise BehavioralGovernanceError("containment_block_scope_required")
        if self.action == "observe" and self.containment_scope:
            raise BehavioralGovernanceError("observe_cannot_contain")
        if self.execution_allowed is not False:
            raise BehavioralGovernanceError("containment_cannot_authorize_execution")
        if self.policy_expansion is not False:
            raise BehavioralGovernanceError("containment_cannot_expand_policy")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("containment_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("containment_cannot_create_governed_effect")
        if self.schema != "pulpo.behavior-containment-disposition.v0":
            raise BehavioralGovernanceError("containment_schema_invalid")

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def disposition_hash(self) -> str:
        return _digest(asdict(self))


def _observe(scope_hash: str, reason: str) -> ContainmentDisposition:
    return ContainmentDisposition(
        action="observe",
        reason=reason,
        evidence_scope=(scope_hash,),
        containment_scope=(),
    )


def _block(scope_hash: str, reason: str) -> ContainmentDisposition:
    return ContainmentDisposition(
        action="block",
        reason=reason,
        evidence_scope=(scope_hash,),
        containment_scope=(scope_hash,),
    )


@dataclass(frozen=True, slots=True)
class ContextualBaseline:
    """Exact per-context telemetry thresholds with no global fallback."""

    context_hash: str
    anomaly_threshold: int
    containment_threshold: int
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.contextual-behavior-baseline.v0"

    def __post_init__(self) -> None:
        _require_digest(self.context_hash, "contextual_baseline_hash_invalid")
        if (
            isinstance(self.anomaly_threshold, bool)
            or not isinstance(self.anomaly_threshold, int)
            or self.anomaly_threshold <= 0
        ):
            raise BehavioralGovernanceError("contextual_anomaly_threshold_invalid")
        if (
            isinstance(self.containment_threshold, bool)
            or not isinstance(self.containment_threshold, int)
            or self.containment_threshold < self.anomaly_threshold
        ):
            raise BehavioralGovernanceError("contextual_containment_threshold_invalid")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("contextual_baseline_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("contextual_baseline_cannot_create_governed_effect")
        if self.schema != "pulpo.contextual-behavior-baseline.v0":
            raise BehavioralGovernanceError("contextual_baseline_schema_invalid")

    def compare(
        self,
        observed_unknowns: int,
        *,
        logs_complete: bool,
    ) -> tuple[AnomalySignal, ContainmentDisposition]:
        if (
            isinstance(observed_unknowns, bool)
            or not isinstance(observed_unknowns, int)
            or observed_unknowns < 0
        ):
            raise BehavioralGovernanceError("observed_unknown_count_invalid")
        if type(logs_complete) is not bool:
            raise BehavioralGovernanceError("log_completeness_invalid")
        if not logs_complete:
            return (
                AnomalySignal(
                    context_hash=self.context_hash,
                    classification="unknown",
                    score=None,
                    reason="behavior_logs_missing",
                    safety="unknown",
                ),
                _block(self.context_hash, "behavior_logs_missing"),
            )

        score = min(100, observed_unknowns * 100 // self.containment_threshold)
        if observed_unknowns >= self.containment_threshold:
            return (
                AnomalySignal(
                    context_hash=self.context_hash,
                    classification="context_containment",
                    score=score,
                    reason="contextual_containment_threshold_crossed",
                ),
                _block(self.context_hash, "contextual_containment_threshold_crossed"),
            )
        if observed_unknowns >= self.anomaly_threshold:
            return (
                AnomalySignal(
                    context_hash=self.context_hash,
                    classification="context_anomaly",
                    score=score,
                    reason="contextual_anomaly_threshold_crossed",
                ),
                _observe(self.context_hash, "contextual_anomaly_observed"),
            )
        return (
            AnomalySignal(
                context_hash=self.context_hash,
                classification="context_normal",
                score=score,
                reason="within_contextual_baseline",
            ),
            _observe(self.context_hash, "within_contextual_baseline"),
        )


@dataclass(frozen=True, slots=True)
class BehaviorChain:
    """Bounded immutable projection of one rejected-unknown behavior stream."""

    baseline: BaselineEvent
    current_state: BaselineState
    last_sequence: int
    repeat_count: int
    delta_count: int
    active_deltas: tuple[DeltaEvent, ...]
    checkpoint: Checkpoint | None
    history_hash: str
    seen_context_hashes: tuple[str, ...]
    suppressed_count: int
    micro_variation_count: int
    last_signal: AnomalySignal
    containment: ContainmentDisposition
    checkpoint_after_deltas: int
    max_contexts: int
    micro_variation_limit: int
    authority_effect: str = "none"
    governed_effect: str = "none"
    schema: str = "pulpo.behavior-chain.v0"

    def __post_init__(self) -> None:
        if not isinstance(self.baseline, BaselineEvent):
            raise BehavioralGovernanceError("behavior_chain_baseline_invalid")
        if not isinstance(self.current_state, BaselineState):
            raise BehavioralGovernanceError("behavior_chain_state_invalid")
        if self.last_sequence < self.baseline.sequence:
            raise BehavioralGovernanceError("behavior_chain_sequence_invalid")
        for count, reason in (
            (self.repeat_count, "behavior_chain_repeat_count_invalid"),
            (self.delta_count, "behavior_chain_delta_count_invalid"),
            (self.suppressed_count, "behavior_chain_suppressed_count_invalid"),
            (self.micro_variation_count, "behavior_chain_micro_count_invalid"),
        ):
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise BehavioralGovernanceError(reason)
        if self.repeat_count <= 0:
            raise BehavioralGovernanceError("behavior_chain_repeat_count_invalid")
        for limit, reason in (
            (self.checkpoint_after_deltas, "behavior_chain_checkpoint_limit_invalid"),
            (self.max_contexts, "behavior_chain_context_limit_invalid"),
            (self.micro_variation_limit, "behavior_chain_micro_limit_invalid"),
        ):
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise BehavioralGovernanceError(reason)
        if len(self.active_deltas) >= self.checkpoint_after_deltas:
            raise BehavioralGovernanceError("behavior_chain_active_deltas_unbounded")
        if len(self.seen_context_hashes) > self.max_contexts:
            raise BehavioralGovernanceError("behavior_chain_contexts_unbounded")
        if (
            len(self.seen_context_hashes) != len(set(self.seen_context_hashes))
            or self.baseline.state.context_hash not in self.seen_context_hashes
        ):
            raise BehavioralGovernanceError("behavior_chain_contexts_invalid")
        for context_hash in self.seen_context_hashes:
            _require_digest(context_hash, "behavior_chain_context_hash_invalid")
        _require_digest(self.history_hash, "behavior_chain_history_hash_invalid")
        if not isinstance(self.last_signal, AnomalySignal):
            raise BehavioralGovernanceError("behavior_chain_signal_invalid")
        if not isinstance(self.containment, ContainmentDisposition):
            raise BehavioralGovernanceError("behavior_chain_containment_invalid")
        if self.checkpoint is None:
            if self.delta_count != len(self.active_deltas):
                raise BehavioralGovernanceError("behavior_chain_delta_count_mismatch")
        else:
            if self.checkpoint.chain_id != self.chain_id:
                raise BehavioralGovernanceError("behavior_chain_checkpoint_chain_mismatch")
            if self.checkpoint.baseline_event_hash != self.baseline.event_hash:
                raise BehavioralGovernanceError("behavior_chain_checkpoint_baseline_mismatch")
            if self.delta_count != self.checkpoint.covered_delta_count + len(self.active_deltas):
                raise BehavioralGovernanceError("behavior_chain_checkpoint_count_mismatch")
        if self.authority_effect != "none":
            raise BehavioralGovernanceError("behavior_chain_cannot_grant_authority")
        if self.governed_effect != "none":
            raise BehavioralGovernanceError("behavior_chain_cannot_create_governed_effect")
        if self.schema != "pulpo.behavior-chain.v0":
            raise BehavioralGovernanceError("behavior_chain_schema_invalid")
        if self.reconstruct() != self.current_state:
            raise BehavioralGovernanceError("behavior_chain_reconstruction_mismatch")

    @classmethod
    def from_rejected_unknown(
        cls,
        state: BaselineState,
        *,
        sequence: int = 1,
        rejection_reason: str = "unknown_behavior",
        checkpoint_after_deltas: int = 8,
        max_contexts: int = 32,
        micro_variation_limit: int = 16,
    ) -> BehaviorChain:
        baseline = BaselineEvent(
            sequence=sequence,
            state=state,
            rejection_reason=rejection_reason,
        )
        chain_id = _digest(
            {
                "schema": "pulpo.behavior-chain-id.v0",
                "baseline_event_hash": baseline.event_hash,
            }
        )
        signal = AnomalySignal(
            context_hash=state.context_hash,
            classification="baseline_created",
            score=0,
            reason="rejected_unknown_baseline_created",
        )
        return cls(
            baseline=baseline,
            current_state=state,
            last_sequence=sequence,
            repeat_count=1,
            delta_count=0,
            active_deltas=(),
            checkpoint=None,
            history_hash=baseline.event_hash,
            seen_context_hashes=(state.context_hash,),
            suppressed_count=0,
            micro_variation_count=0,
            last_signal=signal,
            containment=_observe(chain_id, "rejected_unknown_observed"),
            checkpoint_after_deltas=checkpoint_after_deltas,
            max_contexts=max_contexts,
            micro_variation_limit=micro_variation_limit,
        )

    @property
    def chain_id(self) -> str:
        return _digest(
            {
                "schema": "pulpo.behavior-chain-id.v0",
                "baseline_event_hash": self.baseline.event_hash,
            }
        )

    @property
    def tail_event_hash(self) -> str:
        if self.active_deltas:
            return self.active_deltas[-1].event_hash
        if self.checkpoint is not None:
            return self.checkpoint.covered_event_hash
        return self.baseline.event_hash

    @property
    def detailed_event_count(self) -> int:
        return 1 + len(self.active_deltas) + int(self.checkpoint is not None)

    @property
    def observed_unknown_count(self) -> int:
        return self.repeat_count + self.delta_count + self.suppressed_count

    @property
    def chain_hash(self) -> str:
        return _digest(asdict(self))

    def record_rejected_unknown(
        self,
        state: BaselineState,
        *,
        sequence: int,
    ) -> BehaviorChain:
        if not isinstance(state, BaselineState):
            raise BehavioralGovernanceError("behavior_chain_state_invalid")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= self.last_sequence:
            raise BehavioralGovernanceError("behavior_chain_sequence_not_monotonic")

        if self.containment.blocked:
            signal = AnomalySignal(
                context_hash=state.context_hash,
                classification=self.last_signal.classification,
                score=self.last_signal.score,
                reason="containment_already_active",
                safety=(
                    "unknown"
                    if self.last_signal.classification == "unknown"
                    else "not_established"
                ),
            )
            return replace(
                self,
                last_sequence=sequence,
                suppressed_count=self.suppressed_count + 1,
                history_hash=_advance_history(
                    self.history_hash,
                    kind="contained_observation",
                    sequence=sequence,
                    evidence_hash=state.state_hash,
                ),
                last_signal=signal,
            )

        if state == self.current_state:
            repeat_count = self.repeat_count + 1
            signal = AnomalySignal(
                context_hash=state.context_hash,
                classification="repeat",
                score=min(49, repeat_count // 100),
                reason="identical_unknown_compacted",
            )
            return replace(
                self,
                last_sequence=sequence,
                repeat_count=repeat_count,
                history_hash=_advance_history(
                    self.history_hash,
                    kind="identical_repeat",
                    sequence=sequence,
                    evidence_hash=state.state_hash,
                ),
                last_signal=signal,
            )

        context_hashes = self.seen_context_hashes
        if state.context_hash not in context_hashes:
            if len(context_hashes) >= self.max_contexts:
                signal = AnomalySignal(
                    context_hash=state.context_hash,
                    classification="context_overflow",
                    score=100,
                    reason="context_cardinality_limit_crossed",
                )
                return replace(
                    self,
                    last_sequence=sequence,
                    suppressed_count=self.suppressed_count + 1,
                    history_hash=_advance_history(
                        self.history_hash,
                        kind="context_overflow",
                        sequence=sequence,
                        evidence_hash=state.state_hash,
                    ),
                    last_signal=signal,
                    containment=_block(
                        self.chain_id,
                        "context_cardinality_limit_crossed",
                    ),
                )
            context_hashes = (*context_hashes, state.context_hash)

        changes = tuple(
            (
                field_name,
                _value_hash(getattr(self.current_state, field_name)),
                getattr(state, field_name),
            )
            for field_name in sorted(_STATE_FIELDS)
            if getattr(self.current_state, field_name) != getattr(state, field_name)
        )
        changed_fields = frozenset(change[0] for change in changes)
        if changed_fields & _CONSTITUTIONAL_FIELDS:
            materiality: Materiality = "constitutional"
            score = 95
            classification: SignalClass = "constitutional_change"
        elif changed_fields & _CAPABILITY_FIELDS:
            materiality = "capability"
            score = 80
            classification = "capability_change"
        elif changed_fields.issubset(_MICRO_FIELDS):
            materiality = "micro"
            score = min(75, 10 + (self.micro_variation_count + 1) * 10)
            classification = "material_change"
        else:
            materiality = "material"
            score = 40
            classification = "material_change"

        delta = DeltaEvent(
            chain_id=self.chain_id,
            baseline_event_hash=self.baseline.event_hash,
            previous_event_hash=self.tail_event_hash,
            sequence=sequence,
            changes=changes,
            materiality=materiality,
            anomaly_score_after_delta=score,
        )
        history_hash = _advance_history(
            self.history_hash,
            kind="material_delta",
            sequence=sequence,
            evidence_hash=delta.event_hash,
        )
        delta_count = self.delta_count + 1
        micro_variation_count = self.micro_variation_count + int(materiality == "micro")
        active_deltas = (*self.active_deltas, delta)
        checkpoint = self.checkpoint
        if len(active_deltas) >= self.checkpoint_after_deltas:
            checkpoint = Checkpoint(
                chain_id=self.chain_id,
                baseline_event_hash=self.baseline.event_hash,
                prior_checkpoint_hash=(
                    self.checkpoint.checkpoint_hash
                    if self.checkpoint is not None
                    else None
                ),
                covered_event_hash=delta.event_hash,
                history_hash=history_hash,
                through_sequence=sequence,
                covered_delta_count=delta_count,
                repeat_count=self.repeat_count,
                summarized_state=state,
            )
            active_deltas = ()

        signal = AnomalySignal(
            context_hash=state.context_hash,
            classification=classification,
            score=score,
            reason=f"rejected_unknown_{materiality}_delta",
        )
        containment = self.containment
        if micro_variation_count >= self.micro_variation_limit:
            signal = AnomalySignal(
                context_hash=state.context_hash,
                classification="delta_flood",
                score=100,
                reason="micro_variation_limit_crossed",
            )
            containment = _block(self.chain_id, "micro_variation_limit_crossed")

        return replace(
            self,
            current_state=state,
            last_sequence=sequence,
            delta_count=delta_count,
            active_deltas=active_deltas,
            checkpoint=checkpoint,
            history_hash=history_hash,
            seen_context_hashes=context_hashes,
            micro_variation_count=micro_variation_count,
            last_signal=signal,
            containment=containment,
        )

    def reconstruct(self) -> BaselineState:
        if self.checkpoint is None:
            state = self.baseline.state
            previous_event_hash = self.baseline.event_hash
        else:
            state = self.checkpoint.summarized_state
            previous_event_hash = self.checkpoint.covered_event_hash

        for delta in self.active_deltas:
            if delta.chain_id != self.chain_id:
                raise BehavioralGovernanceError("delta_chain_mismatch")
            if delta.baseline_event_hash != self.baseline.event_hash:
                raise BehavioralGovernanceError("delta_baseline_mismatch")
            if delta.previous_event_hash != previous_event_hash:
                raise BehavioralGovernanceError("delta_history_mismatch")
            values = {
                field_name: getattr(state, field_name)
                for field_name in _STATE_FIELDS
            }
            for field_name, previous_value_hash, new_value in delta.changes:
                if _value_hash(values[field_name]) != previous_value_hash:
                    raise BehavioralGovernanceError("delta_previous_value_mismatch")
                values[field_name] = new_value
            state = BaselineState(**values)
            previous_event_hash = delta.event_hash
        return state

    def recommend_baseline(self, candidate: BaselineState) -> AnomalySignal:
        if not isinstance(candidate, BaselineState):
            raise BehavioralGovernanceError("baseline_candidate_invalid")
        return AnomalySignal(
            context_hash=candidate.context_hash,
            classification="baseline_recommendation",
            score=None,
            reason="learning_recommendation_requires_authorized_transition",
            recommended_baseline_hash=candidate.state_hash,
        )


def compare_contextual_baselines(
    state: BaselineState,
    baselines: tuple[ContextualBaseline, ...],
    *,
    observed_unknowns: int,
    logs_complete: bool,
    max_contexts: int = 32,
) -> tuple[AnomalySignal, ContainmentDisposition]:
    """Compare against the exact context only; never use a global fallback."""

    if not isinstance(state, BaselineState):
        raise BehavioralGovernanceError("contextual_state_invalid")
    if isinstance(max_contexts, bool) or not isinstance(max_contexts, int) or max_contexts <= 0:
        raise BehavioralGovernanceError("contextual_limit_invalid")
    if len(baselines) > max_contexts:
        return (
            AnomalySignal(
                context_hash=state.context_hash,
                classification="context_overflow",
                score=100,
                reason="contextual_baseline_cardinality_exceeded",
            ),
            _block(state.context_hash, "contextual_baseline_cardinality_exceeded"),
        )
    if any(not isinstance(item, ContextualBaseline) for item in baselines):
        raise BehavioralGovernanceError("contextual_baseline_invalid")
    context_hashes = [item.context_hash for item in baselines]
    if len(context_hashes) != len(set(context_hashes)):
        raise BehavioralGovernanceError("contextual_baseline_duplicate")

    for baseline in baselines:
        if baseline.context_hash == state.context_hash:
            return baseline.compare(
                observed_unknowns,
                logs_complete=logs_complete,
            )
    return (
        AnomalySignal(
            context_hash=state.context_hash,
            classification="unknown",
            score=None,
            reason="contextual_baseline_missing",
            safety="unknown",
        ),
        _block(state.context_hash, "contextual_baseline_missing"),
    )
