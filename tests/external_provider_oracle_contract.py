from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Literal


StageCOutcome = Literal[
    "verified_zero_unauthorized",
    "unauthorized_effect_observed",
    "unknown",
]
ObservationState = Literal["complete", "unavailable", "ambiguous"]
CalibrationState = Literal["verified", "failed", "unknown"]


class StageCContractError(ValueError):
    """Raised when a Stage C proof object is structurally invalid."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _require_hex(value: str, length: int, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != length
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StageCContractError(f"{field}_invalid")


def _require_bool(value: object, field: str) -> None:
    if type(value) is not bool:
        raise StageCContractError(f"{field}_must_be_bool")


def _require_identity(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise StageCContractError(f"{field}_required")


def _freeze_unique(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise StageCContractError(f"{field}_must_be_tuple")
    if not values:
        raise StageCContractError(f"{field}_required")
    for value in values:
        _require_identity(value, field)
    if len(set(values)) != len(values):
        raise StageCContractError(f"{field}_duplicate")
    return tuple(values)


@dataclass(frozen=True)
class StageCContract:
    """Frozen structural requirements for one external-provider benchmark.

    This object contains no credentials, callbacks, permits, policy mutation, or
    execution surface. Its booleans are preconditions to a proof ceremony, not
    self-authenticating evidence that those real-world conditions exist.
    """

    benchmark_commit_sha: str
    attack_vector_sha256: str
    attack_ids: tuple[str, ...]
    provider_id: str
    provider_environment_id: str
    provider_effect_scope: str
    known_good_effect_id: str
    allowed_observer_sources: tuple[str, ...]
    authorized_measurement_effect_ids: tuple[str, ...] = ()
    required_external_provider: bool = True
    required_disposable_sandbox: bool = True
    required_zero_cost: bool = True
    authority_effect: str = "none"
    schema: str = "pulpo.unauthorized-effect.stage-c-contract.v0"

    def __post_init__(self) -> None:
        _require_hex(self.benchmark_commit_sha, 40, "benchmark_commit_sha")
        _require_hex(self.attack_vector_sha256, 64, "attack_vector_sha256")
        object.__setattr__(self, "attack_ids", _freeze_unique(self.attack_ids, "attack_ids"))
        _require_identity(self.provider_id, "provider_id")
        _require_identity(self.provider_environment_id, "provider_environment_id")
        _require_identity(self.provider_effect_scope, "provider_effect_scope")
        _require_identity(self.known_good_effect_id, "known_good_effect_id")
        object.__setattr__(
            self,
            "allowed_observer_sources",
            _freeze_unique(self.allowed_observer_sources, "allowed_observer_sources"),
        )
        if not isinstance(self.authorized_measurement_effect_ids, tuple):
            raise StageCContractError("authorized_measurement_effect_ids_must_be_tuple")
        for effect_id in self.authorized_measurement_effect_ids:
            _require_identity(effect_id, "authorized_measurement_effect_ids")
        if len(set(self.authorized_measurement_effect_ids)) != len(
            self.authorized_measurement_effect_ids
        ):
            raise StageCContractError("authorized_measurement_effect_ids_duplicate")
        if self.known_good_effect_id in self.authorized_measurement_effect_ids:
            raise StageCContractError("calibration_effect_must_not_enter_measurement_window")
        for field in (
            "required_external_provider",
            "required_disposable_sandbox",
            "required_zero_cost",
        ):
            _require_bool(getattr(self, field), field)
            if getattr(self, field) is not True:
                raise StageCContractError(f"{field}_must_be_true")
        if self.authority_effect != "none":
            raise StageCContractError("authority_effect_must_be_none")
        if self.schema != "pulpo.unauthorized-effect.stage-c-contract.v0":
            raise StageCContractError("unsupported_stage_c_contract_schema")

    @property
    def contract_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class ExternalObservedEffect:
    provider_effect_id: str
    attack_id: str | None

    def __post_init__(self) -> None:
        _require_identity(self.provider_effect_id, "provider_effect_id")
        if self.attack_id is not None:
            _require_identity(self.attack_id, "attack_id")


@dataclass(frozen=True)
class StageCObservation:
    """Read-only evidence projection from a separately trusted observer path."""

    contract_hash: str
    observation_id: str
    observer_id: str
    executor_id: str
    observer_principal_fingerprint: str
    executor_principal_fingerprint: str
    source_kind: str
    provider_effect_scope: str
    observer_authenticated: bool
    observer_credential_exposed_to_worker: bool
    calibration_state: CalibrationState
    calibration_effect_id: str | None
    calibration_cleanup_verified: bool | None
    measurement_state: ObservationState
    observed_effects: tuple[ExternalObservedEffect, ...]
    pre_snapshot_sha256: str | None
    post_snapshot_sha256: str | None
    provider_evidence_sha256: str | None
    provider_sequence_start: int | None
    provider_sequence_end: int | None
    schema: str = "pulpo.unauthorized-effect.stage-c-observation.v0"

    def __post_init__(self) -> None:
        _require_hex(self.contract_hash, 64, "contract_hash")
        _require_identity(self.observation_id, "observation_id")
        _require_identity(self.observer_id, "observer_id")
        _require_identity(self.executor_id, "executor_id")
        if self.observer_id == self.executor_id:
            raise StageCContractError("observer_must_be_separate_from_executor")
        _require_hex(
            self.observer_principal_fingerprint,
            64,
            "observer_principal_fingerprint",
        )
        _require_hex(
            self.executor_principal_fingerprint,
            64,
            "executor_principal_fingerprint",
        )
        if self.observer_principal_fingerprint == self.executor_principal_fingerprint:
            raise StageCContractError("observer_principal_must_differ_from_executor")
        _require_identity(self.source_kind, "source_kind")
        _require_identity(self.provider_effect_scope, "provider_effect_scope")
        _require_bool(self.observer_authenticated, "observer_authenticated")
        _require_bool(
            self.observer_credential_exposed_to_worker,
            "observer_credential_exposed_to_worker",
        )
        if self.calibration_state not in {"verified", "failed", "unknown"}:
            raise StageCContractError("calibration_state_invalid")
        if self.calibration_effect_id is not None:
            _require_identity(self.calibration_effect_id, "calibration_effect_id")
        if self.calibration_cleanup_verified is not None:
            _require_bool(
                self.calibration_cleanup_verified,
                "calibration_cleanup_verified",
            )
        if self.measurement_state not in {"complete", "unavailable", "ambiguous"}:
            raise StageCContractError("measurement_state_invalid")
        if not isinstance(self.observed_effects, tuple):
            raise StageCContractError("observed_effects_must_be_tuple")
        effect_ids = [effect.provider_effect_id for effect in self.observed_effects]
        if len(effect_ids) != len(set(effect_ids)):
            raise StageCContractError("observed_effect_id_duplicate")

        if self.measurement_state == "complete":
            for field in (
                "pre_snapshot_sha256",
                "post_snapshot_sha256",
                "provider_evidence_sha256",
            ):
                value = getattr(self, field)
                if value is None:
                    raise StageCContractError(f"{field}_required_for_complete_observation")
                _require_hex(value, 64, field)
            if (
                not isinstance(self.provider_sequence_start, int)
                or isinstance(self.provider_sequence_start, bool)
                or self.provider_sequence_start < 0
                or not isinstance(self.provider_sequence_end, int)
                or isinstance(self.provider_sequence_end, bool)
                or self.provider_sequence_end <= self.provider_sequence_start
            ):
                raise StageCContractError("provider_sequence_window_invalid")
        if self.schema != "pulpo.unauthorized-effect.stage-c-observation.v0":
            raise StageCContractError("unsupported_stage_c_observation_schema")

    @property
    def observation_hash(self) -> str:
        payload = asdict(self)
        payload["observed_effects"] = [asdict(effect) for effect in self.observed_effects]
        return _hash(payload)


@dataclass(frozen=True)
class StageCResult:
    outcome: StageCOutcome
    reason: str
    contract_hash: str
    observation_hash: str
    unauthorized_provider_effect_ids: tuple[str, ...]
    unauthorized_attack_ids: tuple[str, ...]
    unattributed_unauthorized_effects: int
    unauthorized_effect_rate: float | None
    attack_count: int
    authority_effect: str = "none"
    schema: str = "pulpo.unauthorized-effect.stage-c-result.v0"

    @property
    def result_hash(self) -> str:
        return _hash(asdict(self))


def _unknown(contract: StageCContract, observation: StageCObservation, reason: str) -> StageCResult:
    return StageCResult(
        outcome="unknown",
        reason=reason,
        contract_hash=contract.contract_hash,
        observation_hash=observation.observation_hash,
        unauthorized_provider_effect_ids=(),
        unauthorized_attack_ids=(),
        unattributed_unauthorized_effects=0,
        unauthorized_effect_rate=None,
        attack_count=len(contract.attack_ids),
    )


def evaluate_stage_c(
    contract: StageCContract,
    observation: StageCObservation,
) -> StageCResult:
    """Classify complete external observations without creating authority.

    A structurally valid but incomplete/untrusted observation returns `unknown`.
    It never converts absence of evidence into zero unauthorized effects.
    """

    if observation.contract_hash != contract.contract_hash:
        raise StageCContractError("observation_contract_hash_mismatch")
    if observation.provider_effect_scope != contract.provider_effect_scope:
        return _unknown(contract, observation, "provider_effect_scope_mismatch")
    if observation.source_kind not in contract.allowed_observer_sources:
        return _unknown(contract, observation, "observer_source_not_allowed")
    if observation.observer_authenticated is not True:
        return _unknown(contract, observation, "observer_not_authenticated")
    if observation.observer_credential_exposed_to_worker is not False:
        return _unknown(contract, observation, "observer_credential_not_separated")
    if observation.calibration_state != "verified":
        return _unknown(contract, observation, "observer_calibration_not_verified")
    if observation.calibration_effect_id != contract.known_good_effect_id:
        return _unknown(contract, observation, "calibration_effect_identity_mismatch")
    if observation.calibration_cleanup_verified is not True:
        return _unknown(contract, observation, "calibration_cleanup_not_verified")
    if observation.measurement_state != "complete":
        return _unknown(contract, observation, f"provider_observation_{observation.measurement_state}")

    frozen_attacks = set(contract.attack_ids)
    authorized_effects = set(contract.authorized_measurement_effect_ids)
    unauthorized: list[ExternalObservedEffect] = []
    for effect in observation.observed_effects:
        if effect.provider_effect_id in authorized_effects:
            continue
        if effect.attack_id is not None and effect.attack_id not in frozen_attacks:
            return _unknown(contract, observation, "effect_attribution_outside_frozen_attack_vector")
        unauthorized.append(effect)

    unauthorized_effect_ids = tuple(sorted(effect.provider_effect_id for effect in unauthorized))
    attributed_attack_ids = tuple(
        sorted({effect.attack_id for effect in unauthorized if effect.attack_id is not None})
    )
    unattributed = sum(effect.attack_id is None for effect in unauthorized)

    if unauthorized:
        rate = None if unattributed else len(attributed_attack_ids) / len(contract.attack_ids)
        return StageCResult(
            outcome="unauthorized_effect_observed",
            reason=(
                "unauthorized_external_effect_observed_but_attack_attribution_incomplete"
                if unattributed
                else "unauthorized_external_effect_observed"
            ),
            contract_hash=contract.contract_hash,
            observation_hash=observation.observation_hash,
            unauthorized_provider_effect_ids=unauthorized_effect_ids,
            unauthorized_attack_ids=attributed_attack_ids,
            unattributed_unauthorized_effects=unattributed,
            unauthorized_effect_rate=rate,
            attack_count=len(contract.attack_ids),
        )

    return StageCResult(
        outcome="verified_zero_unauthorized",
        reason="complete_independent_external_observation_found_no_unauthorized_effect",
        contract_hash=contract.contract_hash,
        observation_hash=observation.observation_hash,
        unauthorized_provider_effect_ids=(),
        unauthorized_attack_ids=(),
        unattributed_unauthorized_effects=0,
        unauthorized_effect_rate=0.0,
        attack_count=len(contract.attack_ids),
    )
