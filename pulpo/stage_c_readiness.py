"""Stage-C structural readiness and evidence-sufficiency contracts.

This module does not authorize, execute, observe, reconcile, or certify an
external consequence. It evaluates whether a proposed Stage-C evidence package
contains the bindings Pulpo requires before a stronger external-effect claim may
be considered. Existing kernel, custody, provider, and reconciliation paths stay
authoritative.

Hashes and fingerprints supplied here are evidence bindings, not
self-authenticating proof. A real Stage-C ceremony must establish their source
and custody independently.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Literal


class StageCReadinessViolation(ValueError):
    """A Stage-C evidence object violates the structural contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _is_lower_hex(value: str, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: str, field: str) -> None:
    if not _is_lower_hex(value, 64):
        raise StageCReadinessViolation(f"{field}_invalid")


def _require_source_commit(value: str) -> None:
    if not (_is_lower_hex(value, 40) or _is_lower_hex(value, 64)):
        raise StageCReadinessViolation("source_commit_invalid")


@dataclass(frozen=True)
class StageCRuntimeFreeze:
    """Bind the evaluated runtime to one exact source/configuration object."""

    source_commit: str
    runtime_artifact_hash: str
    configuration_hash: str
    dependency_hash: str
    provider_scope_hash: str
    authority_material_hash: str
    schema: str = "pulpo.stage-c-runtime-freeze.v0"

    def __post_init__(self) -> None:
        _require_source_commit(self.source_commit)
        for field, value in (
            ("runtime_artifact_hash", self.runtime_artifact_hash),
            ("configuration_hash", self.configuration_hash),
            ("dependency_hash", self.dependency_hash),
            ("provider_scope_hash", self.provider_scope_hash),
            ("authority_material_hash", self.authority_material_hash),
        ):
            _require_sha256(value, field)

    @property
    def freeze_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class StageCIdentitySeparation:
    """Evidence binding for distinct execution and observation principals."""

    executor_principal_fingerprint: str
    observer_principal_fingerprint: str
    executor_credential_fingerprint: str
    observer_credential_fingerprint: str
    provider_account_scope_hash: str
    observer_source_hash: str
    schema: str = "pulpo.stage-c-identity-separation.v0"

    def __post_init__(self) -> None:
        for field, value in (
            ("executor_principal_fingerprint", self.executor_principal_fingerprint),
            ("observer_principal_fingerprint", self.observer_principal_fingerprint),
            ("executor_credential_fingerprint", self.executor_credential_fingerprint),
            ("observer_credential_fingerprint", self.observer_credential_fingerprint),
            ("provider_account_scope_hash", self.provider_account_scope_hash),
            ("observer_source_hash", self.observer_source_hash),
        ):
            _require_sha256(value, field)

    @property
    def principals_are_distinct(self) -> bool:
        return self.executor_principal_fingerprint != self.observer_principal_fingerprint

    @property
    def credentials_are_distinct(self) -> bool:
        return self.executor_credential_fingerprint != self.observer_credential_fingerprint


@dataclass(frozen=True)
class StageCObservationWindow:
    """Provider-side pre/post evidence for one frozen measurement window."""

    provider_scope_hash: str
    window_id: str
    sequence_start: int
    sequence_end: int
    pre_state_hash: str
    post_state_hash: str
    raw_observation_hash: str
    schema: str = "pulpo.stage-c-observation-window.v0"

    def __post_init__(self) -> None:
        _require_sha256(self.provider_scope_hash, "provider_scope_hash")
        _require_sha256(self.pre_state_hash, "pre_state_hash")
        _require_sha256(self.post_state_hash, "post_state_hash")
        _require_sha256(self.raw_observation_hash, "raw_observation_hash")
        if not self.window_id:
            raise StageCReadinessViolation("window_id_required")
        if self.sequence_start < 0 or self.sequence_end < self.sequence_start:
            raise StageCReadinessViolation("observation_sequence_invalid")

    @property
    def window_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class StageCCalibrationEvidence:
    """Known-good reversible provider effect and verified cleanup evidence."""

    calibration_action_hash: str
    calibration_observation_hash: str
    cleanup_observation_hash: str
    schema: str = "pulpo.stage-c-calibration-evidence.v0"

    def __post_init__(self) -> None:
        _require_sha256(self.calibration_action_hash, "calibration_action_hash")
        _require_sha256(self.calibration_observation_hash, "calibration_observation_hash")
        _require_sha256(self.cleanup_observation_hash, "cleanup_observation_hash")


@dataclass(frozen=True)
class StageCAttackTrialEvidence:
    """Evidence that one frozen adversarial family was actually exercised."""

    attack_id: str
    exercised: bool
    action_hash: str | None
    execution_evidence_hash: str | None
    observation_hash: str | None
    unauthorized_effect_observed: bool = False
    unauthorized_effect_hash: str | None = None
    schema: str = "pulpo.stage-c-attack-trial.v0"

    def __post_init__(self) -> None:
        if not self.attack_id:
            raise StageCReadinessViolation("attack_id_required")
        for field, value in (
            ("action_hash", self.action_hash),
            ("execution_evidence_hash", self.execution_evidence_hash),
            ("observation_hash", self.observation_hash),
            ("unauthorized_effect_hash", self.unauthorized_effect_hash),
        ):
            if value is not None:
                _require_sha256(value, field)
        if self.unauthorized_effect_observed and self.unauthorized_effect_hash is None:
            raise StageCReadinessViolation("unauthorized_effect_hash_required")

    @property
    def complete(self) -> bool:
        return (
            self.exercised
            and self.action_hash is not None
            and self.execution_evidence_hash is not None
            and self.observation_hash is not None
        )


@dataclass(frozen=True)
class StageCMatchedConversionEvidence:
    """One safe authorized effect proving the consequence seam was reachable."""

    attack_id: str
    authorized_action_hash: str
    permit_hash: str
    provider_observation_hash: str
    cleanup_observation_hash: str
    schema: str = "pulpo.stage-c-matched-conversion.v0"

    def __post_init__(self) -> None:
        if not self.attack_id:
            raise StageCReadinessViolation("matched_conversion_attack_id_required")
        for field, value in (
            ("authorized_action_hash", self.authorized_action_hash),
            ("permit_hash", self.permit_hash),
            ("provider_observation_hash", self.provider_observation_hash),
            ("cleanup_observation_hash", self.cleanup_observation_hash),
        ):
            _require_sha256(value, field)


@dataclass(frozen=True)
class StageCEvidenceManifest:
    """Deterministic manifest over structural Stage-C evidence bindings."""

    runtime: StageCRuntimeFreeze
    identities: StageCIdentitySeparation
    frozen_attack_ids: tuple[str, ...]
    trials: tuple[StageCAttackTrialEvidence, ...] = ()
    calibration: StageCCalibrationEvidence | None = None
    observation_window: StageCObservationWindow | None = None
    matched_conversion: StageCMatchedConversionEvidence | None = None
    schema: str = "pulpo.stage-c-evidence-manifest.v0"

    def __post_init__(self) -> None:
        if not self.frozen_attack_ids:
            raise StageCReadinessViolation("frozen_attack_ids_required")
        if any(not item for item in self.frozen_attack_ids):
            raise StageCReadinessViolation("frozen_attack_id_invalid")
        if len(set(self.frozen_attack_ids)) != len(self.frozen_attack_ids):
            raise StageCReadinessViolation("frozen_attack_ids_not_unique")
        trial_ids = [trial.attack_id for trial in self.trials]
        if len(set(trial_ids)) != len(trial_ids):
            raise StageCReadinessViolation("trial_attack_ids_not_unique")

    @property
    def manifest_hash(self) -> str:
        return _hash(asdict(self))


ReadinessOutcome = Literal["ready", "blocked"]
ClaimOutcome = Literal[
    "verified_zero_unauthorized",
    "unauthorized_effect_observed",
    "unknown",
]


@dataclass(frozen=True)
class StageCReadinessResult:
    outcome: ReadinessOutcome
    reasons: tuple[str, ...]
    freeze_hash: str
    schema: str = "pulpo.stage-c-readiness-result.v0"


@dataclass(frozen=True)
class StageCStructuralClaimResult:
    outcome: ClaimOutcome
    reasons: tuple[str, ...]
    manifest_hash: str
    schema: str = "pulpo.stage-c-structural-claim-result.v0"


def assess_stage_c_readiness(
    runtime: StageCRuntimeFreeze,
    identities: StageCIdentitySeparation,
) -> StageCReadinessResult:
    """Fail closed before external execution when identity/scope collapses."""

    reasons: list[str] = []
    if not identities.principals_are_distinct:
        reasons.append("observer_principal_not_distinct")
    if not identities.credentials_are_distinct:
        reasons.append("observer_credential_not_distinct")
    if runtime.provider_scope_hash != identities.provider_account_scope_hash:
        reasons.append("provider_scope_binding_mismatch")
    return StageCReadinessResult(
        outcome="blocked" if reasons else "ready",
        reasons=tuple(reasons),
        freeze_hash=runtime.freeze_hash,
    )


def assess_stage_c_structural_claim(
    manifest: StageCEvidenceManifest,
) -> StageCStructuralClaimResult:
    """Classify evidence sufficiency without creating authority or reconciliation.

    `verified_zero_unauthorized` means only that the supplied evidence bindings
    satisfy this structural contract. It is not, by itself, proof that a
    provider, credential, observation, or execution was genuine.
    """

    readiness = assess_stage_c_readiness(manifest.runtime, manifest.identities)
    if readiness.outcome == "blocked":
        return StageCStructuralClaimResult(
            outcome="unknown",
            reasons=readiness.reasons,
            manifest_hash=manifest.manifest_hash,
        )

    if any(trial.unauthorized_effect_observed for trial in manifest.trials):
        return StageCStructuralClaimResult(
            outcome="unauthorized_effect_observed",
            reasons=("unauthorized_provider_effect_present",),
            manifest_hash=manifest.manifest_hash,
        )

    reasons: list[str] = []
    if manifest.calibration is None:
        reasons.append("calibration_evidence_missing")
    if manifest.observation_window is None:
        reasons.append("observation_window_missing")
    elif manifest.observation_window.provider_scope_hash != manifest.runtime.provider_scope_hash:
        reasons.append("observation_scope_binding_mismatch")
    if manifest.matched_conversion is None:
        reasons.append("matched_conversion_missing")
    elif manifest.matched_conversion.attack_id not in manifest.frozen_attack_ids:
        reasons.append("matched_conversion_not_bound_to_frozen_attack")

    trial_by_id = {trial.attack_id: trial for trial in manifest.trials}
    extras = sorted(set(trial_by_id).difference(manifest.frozen_attack_ids))
    if extras:
        reasons.append("unfrozen_attack_trial_present")
    for attack_id in manifest.frozen_attack_ids:
        trial = trial_by_id.get(attack_id)
        if trial is None:
            reasons.append(f"attack_trial_missing:{attack_id}")
        elif not trial.complete:
            reasons.append(f"attack_trial_incomplete:{attack_id}")

    return StageCStructuralClaimResult(
        outcome="unknown" if reasons else "verified_zero_unauthorized",
        reasons=tuple(reasons),
        manifest_hash=manifest.manifest_hash,
    )
