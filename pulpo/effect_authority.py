"""Exact remote-effect authority binding on top of Pulpo's existing permit path.

This module does not issue authority. It makes a remote side effect an exact,
canonical object, binds that object into ``Intent.resource``, verifies #227's
independently observed execution context, and only then delegates one-use
permit consumption to the existing ``GovernanceKernel``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
from contextlib import closing
from pathlib import Path
import sqlite3
from typing import Iterable

from .execution_context import ExecutionContext, verify_execution_context
from .kernel import GovernanceKernel, Intent


_EFFECT_SCHEMA = "pulpo.remote-effect.v0"
_AUTHORITY_SCHEMA = "pulpo.effect-authority.v0"
_RESOURCE_MARKER = "#pulpo-effect-authority="


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hash(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _canonical_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field}_invalid")


def _nonnegative_int(value: int, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field}_invalid")


@dataclass(frozen=True)
class ConsequenceVector:
    mutations: int = 0
    notifications: int = 0
    compute_units: int = 0
    spend_cents: int = 0

    def __post_init__(self) -> None:
        for value, field in (
            (self.mutations, "mutations"),
            (self.notifications, "notifications"),
            (self.compute_units, "compute_units"),
            (self.spend_cents, "spend_cents"),
        ):
            _nonnegative_int(value, field)

    def __add__(self, other: "ConsequenceVector") -> "ConsequenceVector":
        if not isinstance(other, ConsequenceVector):
            return NotImplemented
        return ConsequenceVector(
            mutations=self.mutations + other.mutations,
            notifications=self.notifications + other.notifications,
            compute_units=self.compute_units + other.compute_units,
            spend_cents=self.spend_cents + other.spend_cents,
        )

    def within(self, ceiling: "ConsequenceVector") -> bool:
        return (
            self.mutations <= ceiling.mutations
            and self.notifications <= ceiling.notifications
            and self.compute_units <= ceiling.compute_units
            and self.spend_cents <= ceiling.spend_cents
        )

    def exceeded_fields(self, ceiling: "ConsequenceVector") -> tuple[str, ...]:
        fields = []
        for field in ("mutations", "notifications", "compute_units", "spend_cents"):
            if getattr(self, field) > getattr(ceiling, field):
                fields.append(field)
        return tuple(fields)


@dataclass(frozen=True)
class RemoteEffect:
    surface: str
    authority_scope: str
    operation: str
    resource: str
    expected_pre_state: str
    desired_post_state: str
    parameters: tuple[tuple[str, str], ...] = ()
    schema: str = _EFFECT_SCHEMA

    def __post_init__(self) -> None:
        for value, field in (
            (self.surface, "surface"),
            (self.authority_scope, "authority_scope"),
            (self.operation, "operation"),
            (self.resource, "resource"),
            (self.expected_pre_state, "expected_pre_state"),
            (self.desired_post_state, "desired_post_state"),
        ):
            _canonical_text(value, field)
        if self.schema != _EFFECT_SCHEMA:
            raise ValueError("unsupported_effect_schema")
        normalized: list[tuple[str, str]] = []
        seen: set[str] = set()
        for pair in self.parameters:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("effect_parameter_invalid")
            key, value = pair
            _canonical_text(key, "effect_parameter_key")
            if not isinstance(value, str):
                raise ValueError("effect_parameter_value_invalid")
            if key in seen:
                raise ValueError("effect_parameter_duplicate")
            seen.add(key)
            normalized.append((key, value))
        object.__setattr__(self, "parameters", tuple(sorted(normalized)))

    @property
    def effect_hash(self) -> str:
        return _hash(asdict(self))


class AggregateConsequenceViolation(ValueError):
    """Durable aggregate consequence custody rejected an attempted effect."""


@dataclass(frozen=True)
class AggregateConsequenceAuthority:
    sequence_id: str
    principal: str
    session_id: str
    surface: str
    authority_scope: str
    ceiling: ConsequenceVector
    expires_at_ns: int
    schema: str = "pulpo.aggregate-consequence.v0"

    def __post_init__(self) -> None:
        for value, field in (
            (self.sequence_id, "sequence_id"),
            (self.principal, "principal"),
            (self.session_id, "session_id"),
            (self.surface, "surface"),
            (self.authority_scope, "authority_scope"),
        ):
            _canonical_text(value, field)
        if not isinstance(self.ceiling, ConsequenceVector):
            raise TypeError("aggregate_consequence_ceiling_required")
        if isinstance(self.expires_at_ns, bool) or not isinstance(self.expires_at_ns, int) or self.expires_at_ns <= 0:
            raise ValueError("aggregate_consequence_expiry_invalid")
        if self.schema != "pulpo.aggregate-consequence.v0":
            raise ValueError("unsupported_aggregate_consequence_schema")

    @property
    def authority_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class AggregateConsequenceReceipt:
    authority_hash: str
    effect_hash: str
    permit_hash: str
    consequence: ConsequenceVector
    aggregate_after: ConsequenceVector
    receipt_hash: str


@dataclass(frozen=True)
class AggregateRemoteEffectAuthorization:
    outcome: str
    reason: str
    permit_consumed: bool
    execution_authorized: bool
    aggregate_receipt: AggregateConsequenceReceipt | None = None
    authority_effect: str = "none"


class SQLiteAggregateConsequenceBudget:
    """Restart-durable aggregate consequence custody in the governance state DB.

    This is operational state analogous to Pulpo's commerce budget, not a second
    authority engine or evidence ledger. It never grants authority: it can only
    deny an otherwise valid effect when the shared ceiling would be exceeded.
    """

    def __init__(self, path: str | Path, authority: AggregateConsequenceAuthority) -> None:
        if not isinstance(authority, AggregateConsequenceAuthority):
            raise TypeError("aggregate_consequence_authority_required")
        if not str(path) or str(path) == ":memory:":
            raise AggregateConsequenceViolation("aggregate_budget_requires_durable_path")
        self.path = Path(path)
        if not self.path.parent.is_dir():
            raise AggregateConsequenceViolation("aggregate_budget_parent_missing")
        if self.path.exists() and not self.path.is_file():
            raise AggregateConsequenceViolation("aggregate_budget_path_invalid")
        self.authority = authority
        try:
            with closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS effect_aggregate_authority (
                        authority_hash TEXT PRIMARY KEY,
                        sequence_id TEXT NOT NULL UNIQUE,
                        principal TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        surface TEXT NOT NULL,
                        authority_scope TEXT NOT NULL,
                        mutations INTEGER NOT NULL CHECK (mutations >= 0),
                        notifications INTEGER NOT NULL CHECK (notifications >= 0),
                        compute_units INTEGER NOT NULL CHECK (compute_units >= 0),
                        spend_cents INTEGER NOT NULL CHECK (spend_cents >= 0),
                        expires_at_ns INTEGER NOT NULL CHECK (expires_at_ns > 0)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS effect_aggregate_consumption (
                        authority_hash TEXT NOT NULL,
                        effect_hash TEXT NOT NULL,
                        permit_hash TEXT NOT NULL,
                        mutations INTEGER NOT NULL CHECK (mutations >= 0),
                        notifications INTEGER NOT NULL CHECK (notifications >= 0),
                        compute_units INTEGER NOT NULL CHECK (compute_units >= 0),
                        spend_cents INTEGER NOT NULL CHECK (spend_cents >= 0),
                        PRIMARY KEY (authority_hash, effect_hash),
                        UNIQUE (authority_hash, permit_hash),
                        FOREIGN KEY (authority_hash) REFERENCES effect_aggregate_authority(authority_hash)
                    )
                    """
                )
                row = connection.execute(
                    "SELECT authority_hash, principal, session_id, surface, authority_scope, mutations, notifications, compute_units, spend_cents, expires_at_ns "
                    "FROM effect_aggregate_authority WHERE sequence_id = ?",
                    (authority.sequence_id,),
                ).fetchone()
                expected = (
                    authority.authority_hash, authority.principal, authority.session_id, authority.surface, authority.authority_scope,
                    authority.ceiling.mutations, authority.ceiling.notifications,
                    authority.ceiling.compute_units, authority.ceiling.spend_cents, authority.expires_at_ns,
                )
                if row is None:
                    connection.execute(
                        "INSERT INTO effect_aggregate_authority "
                        "(authority_hash, sequence_id, principal, session_id, surface, authority_scope, mutations, notifications, compute_units, spend_cents, expires_at_ns) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (authority.authority_hash, authority.sequence_id, authority.principal, authority.session_id, authority.surface, authority.authority_scope,
                         authority.ceiling.mutations, authority.ceiling.notifications, authority.ceiling.compute_units,
                         authority.ceiling.spend_cents, authority.expires_at_ns),
                    )
                elif tuple(row) != expected:
                    raise AggregateConsequenceViolation("aggregate_authority_mismatch")
        except AggregateConsequenceViolation:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AggregateConsequenceViolation("aggregate_budget_unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _permit_hash(permit: str) -> str:
        if not isinstance(permit, str) or not permit:
            raise AggregateConsequenceViolation("permit_required")
        return sha256(permit.encode("utf-8")).hexdigest()

    def _used(self, connection: sqlite3.Connection) -> ConsequenceVector:
        row = connection.execute(
            "SELECT COALESCE(SUM(mutations),0), COALESCE(SUM(notifications),0), "
            "COALESCE(SUM(compute_units),0), COALESCE(SUM(spend_cents),0) "
            "FROM effect_aggregate_consumption WHERE authority_hash = ?",
            (self.authority.authority_hash,),
        ).fetchone()
        return ConsequenceVector(*map(int, row))

    @property
    def used(self) -> ConsequenceVector:
        try:
            with closing(self._connect()) as connection:
                return self._used(connection)
        except (OSError, sqlite3.Error, TypeError) as exc:
            raise AggregateConsequenceViolation("aggregate_budget_unavailable") from exc

    def preflight(
        self, effect: RemoteEffect, consequence: ConsequenceVector, *, now_ns: int, permit: str | None = None
    ) -> None:
        if not isinstance(effect, RemoteEffect) or not isinstance(consequence, ConsequenceVector):
            raise AggregateConsequenceViolation("aggregate_effect_invalid")
        if now_ns <= 0 or now_ns >= self.authority.expires_at_ns:
            raise AggregateConsequenceViolation("aggregate_authority_expired")
        if effect.surface != self.authority.surface:
            raise AggregateConsequenceViolation("aggregate_surface_mismatch")
        if effect.authority_scope != self.authority.authority_scope:
            raise AggregateConsequenceViolation("aggregate_scope_mismatch")
        try:
            with closing(self._connect()) as connection:
                if connection.execute(
                    "SELECT 1 FROM effect_aggregate_consumption WHERE authority_hash = ? AND effect_hash = ?",
                    (self.authority.authority_hash, effect.effect_hash),
                ).fetchone():
                    raise AggregateConsequenceViolation("aggregate_effect_already_counted")
                if permit is not None:
                    permit_hash = self._permit_hash(permit)
                    if connection.execute(
                        "SELECT 1 FROM effect_aggregate_consumption WHERE authority_hash = ? AND permit_hash = ?",
                        (self.authority.authority_hash, permit_hash),
                    ).fetchone():
                        raise AggregateConsequenceViolation("aggregate_permit_already_counted")
                candidate = self._used(connection) + consequence
                if not candidate.within(self.authority.ceiling):
                    fields = ",".join(candidate.exceeded_fields(self.authority.ceiling))
                    raise AggregateConsequenceViolation(f"aggregate_ceiling_exceeded:{fields}")
        except AggregateConsequenceViolation:
            raise
        except (OSError, sqlite3.Error, TypeError) as exc:
            raise AggregateConsequenceViolation("aggregate_budget_unavailable") from exc

    def record_attempt(
        self, effect: RemoteEffect, permit: str, consequence: ConsequenceVector, *, now_ns: int
    ) -> AggregateConsequenceReceipt:
        self.preflight(effect, consequence, now_ns=now_ns, permit=permit)
        permit_hash = self._permit_hash(permit)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM effect_aggregate_consumption WHERE authority_hash = ? AND effect_hash = ?",
                    (self.authority.authority_hash, effect.effect_hash),
                ).fetchone():
                    connection.rollback()
                    raise AggregateConsequenceViolation("aggregate_effect_already_counted")
                if connection.execute(
                    "SELECT 1 FROM effect_aggregate_consumption WHERE authority_hash = ? AND permit_hash = ?",
                    (self.authority.authority_hash, permit_hash),
                ).fetchone():
                    connection.rollback()
                    raise AggregateConsequenceViolation("aggregate_permit_already_counted")
                candidate = self._used(connection) + consequence
                if not candidate.within(self.authority.ceiling):
                    connection.rollback()
                    fields = ",".join(candidate.exceeded_fields(self.authority.ceiling))
                    raise AggregateConsequenceViolation(f"aggregate_ceiling_exceeded:{fields}")
                connection.execute(
                    "INSERT INTO effect_aggregate_consumption "
                    "(authority_hash, effect_hash, permit_hash, mutations, notifications, compute_units, spend_cents) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (self.authority.authority_hash, effect.effect_hash, permit_hash, consequence.mutations,
                     consequence.notifications, consequence.compute_units, consequence.spend_cents),
                )
                connection.commit()
        except AggregateConsequenceViolation:
            raise
        except (OSError, sqlite3.Error, TypeError) as exc:
            raise AggregateConsequenceViolation("aggregate_budget_unavailable") from exc
        receipt_hash = _hash({
            "authority_hash": self.authority.authority_hash, "effect_hash": effect.effect_hash,
            "permit_hash": permit_hash, "consequence": asdict(consequence), "aggregate_after": asdict(candidate),
        })
        return AggregateConsequenceReceipt(
            self.authority.authority_hash, effect.effect_hash, permit_hash, consequence, candidate, receipt_hash
        )


@dataclass(frozen=True)
class EffectAuthorityEnvelope:
    effect: RemoteEffect
    allowed_derived_effects: tuple[str, ...]
    planned_consequence: ConsequenceVector
    consequence_ceiling: ConsequenceVector
    expires_at_ns: int
    aggregate_authority: AggregateConsequenceAuthority | None = None
    schema: str = _AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        if not isinstance(self.effect, RemoteEffect):
            raise TypeError("effect_required")
        normalized = []
        seen = set()
        for item in self.allowed_derived_effects:
            _canonical_text(item, "derived_effect")
            if item in seen:
                raise ValueError("derived_effect_duplicate")
            seen.add(item)
            normalized.append(item)
        object.__setattr__(self, "allowed_derived_effects", tuple(sorted(normalized)))
        if not isinstance(self.planned_consequence, ConsequenceVector):
            raise TypeError("planned_consequence_required")
        if not isinstance(self.consequence_ceiling, ConsequenceVector):
            raise TypeError("consequence_ceiling_required")
        if not self.planned_consequence.within(self.consequence_ceiling):
            raise ValueError("planned_consequence_exceeds_ceiling")
        if isinstance(self.expires_at_ns, bool) or not isinstance(self.expires_at_ns, int) or self.expires_at_ns <= 0:
            raise ValueError("effect_authority_expiry_invalid")
        if self.aggregate_authority is not None:
            if not isinstance(self.aggregate_authority, AggregateConsequenceAuthority):
                raise TypeError("aggregate_consequence_authority_invalid")
            if self.effect.surface != self.aggregate_authority.surface:
                raise ValueError("aggregate_effect_surface_mismatch")
            if self.effect.authority_scope != self.aggregate_authority.authority_scope:
                raise ValueError("aggregate_effect_scope_mismatch")
            if not self.planned_consequence.within(self.aggregate_authority.ceiling):
                raise ValueError("planned_consequence_exceeds_aggregate_ceiling")
            if self.expires_at_ns > self.aggregate_authority.expires_at_ns:
                raise ValueError("effect_authority_outlives_aggregate_authority")
        if self.schema != _AUTHORITY_SCHEMA:
            raise ValueError("unsupported_effect_authority_schema")

    @property
    def envelope_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class EffectAuthorityCheck:
    outcome: str
    reason: str
    expected_envelope_hash: str | None
    observed_envelope_hash: str | None
    authority_effect: str = "none"


@dataclass(frozen=True)
class RemoteEffectReconciliation:
    status: str
    reason: str
    envelope_hash: str
    authority_effect: str = "none"


@dataclass(frozen=True)
class SequenceAuthorityCheck:
    outcome: str
    reason: str
    aggregate: ConsequenceVector
    ceiling: ConsequenceVector
    authority_effect: str = "none"


def bind_resource_to_effect_authority(resource: str, envelope: EffectAuthorityEnvelope) -> str:
    if not isinstance(resource, str) or not resource:
        raise ValueError("resource_required")
    if not isinstance(envelope, EffectAuthorityEnvelope):
        raise TypeError("effect_authority_envelope_required")
    if _RESOURCE_MARKER in resource:
        raise ValueError("resource_already_effect_bound")
    return f"{resource}{_RESOURCE_MARKER}{envelope.envelope_hash}"


def required_effect_authority_hash(resource: str) -> str | None:
    if not isinstance(resource, str) or resource.count(_RESOURCE_MARKER) != 1:
        return None
    _prefix, digest = resource.rsplit(_RESOURCE_MARKER, 1)
    if len(digest) != 64:
        return None
    try:
        int(digest, 16)
    except ValueError:
        return None
    return digest


def _effect_mismatch_reason(expected: RemoteEffect, requested: RemoteEffect) -> str | None:
    for field in (
        "surface",
        "authority_scope",
        "operation",
        "resource",
        "expected_pre_state",
        "desired_post_state",
        "parameters",
        "schema",
    ):
        if getattr(expected, field) != getattr(requested, field):
            return f"effect_{field}_mismatch"
    return None


def verify_effect_authority(
    intent: Intent,
    envelope: EffectAuthorityEnvelope | None,
    requested_effect: RemoteEffect | None,
    *,
    observed_pre_state: str | None,
    requested_derived_effects: Iterable[str] = (),
    requested_consequence: ConsequenceVector | None = None,
    now_ns: int,
    observation_complete: bool = True,
) -> EffectAuthorityCheck:
    expected = required_effect_authority_hash(intent.resource)
    if expected is None:
        return EffectAuthorityCheck("deny", "effect_authority_binding_missing", None, None)
    if envelope is None:
        return EffectAuthorityCheck("deny", "effect_authority_envelope_missing", expected, None)
    if not isinstance(envelope, EffectAuthorityEnvelope):
        return EffectAuthorityCheck("deny", "effect_authority_envelope_invalid", expected, None)

    observed_hash = envelope.envelope_hash
    if not hmac.compare_digest(expected, observed_hash):
        return EffectAuthorityCheck("deny", "effect_authority_envelope_mismatch", expected, observed_hash)
    if requested_effect is None or not isinstance(requested_effect, RemoteEffect):
        return EffectAuthorityCheck("deny", "remote_effect_missing", expected, observed_hash)

    mismatch = _effect_mismatch_reason(envelope.effect, requested_effect)
    if mismatch is not None:
        return EffectAuthorityCheck("deny", mismatch, expected, observed_hash)
    if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns <= 0:
        return EffectAuthorityCheck("deny", "effect_authority_clock_invalid", expected, observed_hash)
    if now_ns >= envelope.expires_at_ns:
        return EffectAuthorityCheck("deny", "effect_authority_expired", expected, observed_hash)
    if not observation_complete:
        return EffectAuthorityCheck("uncertain", "pre_execution_observation_incomplete", expected, observed_hash)
    if observed_pre_state is None:
        return EffectAuthorityCheck("uncertain", "pre_state_observation_missing", expected, observed_hash)
    if observed_pre_state != envelope.effect.expected_pre_state:
        return EffectAuthorityCheck("deny", "pre_state_mismatch", expected, observed_hash)

    derived = tuple(sorted(set(requested_derived_effects)))
    if any(item not in envelope.allowed_derived_effects for item in derived):
        return EffectAuthorityCheck("deny", "derived_effect_not_authorized", expected, observed_hash)

    if requested_consequence is None or not isinstance(requested_consequence, ConsequenceVector):
        return EffectAuthorityCheck("deny", "consequence_plan_missing", expected, observed_hash)
    if requested_consequence != envelope.planned_consequence:
        return EffectAuthorityCheck("deny", "consequence_plan_mismatch", expected, observed_hash)
    if not requested_consequence.within(envelope.consequence_ceiling):
        return EffectAuthorityCheck("deny", "consequence_ceiling_exceeded", expected, observed_hash)

    return EffectAuthorityCheck("allow", "exact_effect_authority_match", expected, observed_hash)


def _consume_remote_effect_permit_exact(
    kernel: GovernanceKernel,
    permit: str,
    intent: Intent,
    envelope: EffectAuthorityEnvelope | None,
    requested_effect: RemoteEffect | None,
    observed_context: ExecutionContext | None,
    *,
    observed_pre_state: str | None,
    requested_derived_effects: Iterable[str] = (),
    requested_consequence: ConsequenceVector | None = None,
    now_ns: int,
    observation_complete: bool = True,
) -> tuple[EffectAuthorityCheck, bool]:
    """Consume only after exact context + exact remote-effect authority match."""

    expected_effect_hash = required_effect_authority_hash(intent.resource)
    if expected_effect_hash is None:
        return EffectAuthorityCheck("deny", "effect_authority_binding_missing", None, None), False
    if envelope is None:
        return EffectAuthorityCheck("deny", "effect_authority_envelope_missing", expected_effect_hash, None), False
    if not isinstance(envelope, EffectAuthorityEnvelope):
        return EffectAuthorityCheck("deny", "effect_authority_envelope_invalid", expected_effect_hash, None), False

    context_check = verify_execution_context(intent, observed_context)
    if context_check.outcome != "match":
        return (
            EffectAuthorityCheck(
                "deny",
                context_check.reason,
                expected_effect_hash,
                envelope.envelope_hash,
            ),
            False,
        )
    assert observed_context is not None
    if envelope.effect.surface != observed_context.surface:
        return EffectAuthorityCheck(
            "deny",
            "effect_context_surface_mismatch",
            expected_effect_hash,
            envelope.envelope_hash,
        ), False
    if envelope.effect.authority_scope != observed_context.authority_scope:
        return EffectAuthorityCheck(
            "deny",
            "effect_context_scope_mismatch",
            expected_effect_hash,
            envelope.envelope_hash,
        ), False

    check = verify_effect_authority(
        intent,
        envelope,
        requested_effect,
        observed_pre_state=observed_pre_state,
        requested_derived_effects=requested_derived_effects,
        requested_consequence=requested_consequence,
        now_ns=now_ns,
        observation_complete=observation_complete,
    )
    if check.outcome != "allow":
        return check, False

    if not kernel.consume(permit, intent):
        return EffectAuthorityCheck(
            "deny",
            "permit_unavailable_or_replayed",
            check.expected_envelope_hash,
            check.observed_envelope_hash,
        ), False
    return check, True


def consume_remote_effect_permit(
    kernel: GovernanceKernel,
    permit: str,
    intent: Intent,
    envelope: EffectAuthorityEnvelope | None,
    requested_effect: RemoteEffect | None,
    observed_context: ExecutionContext | None,
    *,
    observed_pre_state: str | None,
    requested_derived_effects: Iterable[str] = (),
    requested_consequence: ConsequenceVector | None = None,
    now_ns: int,
    observation_complete: bool = True,
) -> tuple[EffectAuthorityCheck, bool]:
    """Consume only zero-consequence exact effects through the non-aggregate path.

    Any effect that declares a non-zero consequence must cross the durable
    aggregate-custody path. This prevents an adapter from bypassing sequence
    ceilings by selecting the exact-effect helper directly.
    """

    if isinstance(envelope, EffectAuthorityEnvelope) and envelope.planned_consequence != ConsequenceVector():
        expected = required_effect_authority_hash(intent.resource)
        return (
            EffectAuthorityCheck(
                "deny",
                "aggregate_custody_required",
                expected,
                envelope.envelope_hash,
            ),
            False,
        )
    return _consume_remote_effect_permit_exact(
        kernel,
        permit,
        intent,
        envelope,
        requested_effect,
        observed_context,
        observed_pre_state=observed_pre_state,
        requested_derived_effects=requested_derived_effects,
        requested_consequence=requested_consequence,
        now_ns=now_ns,
        observation_complete=observation_complete,
    )


def reconcile_remote_effect(
    envelope: EffectAuthorityEnvelope,
    *,
    provider_outcome: str,
    observed_post_state: str | None,
    observed_derived_effects: Iterable[str] = (),
    observation_complete: bool = True,
) -> RemoteEffectReconciliation:
    """Classify post-execution evidence without creating retry authority."""

    if not isinstance(envelope, EffectAuthorityEnvelope):
        raise TypeError("effect_authority_envelope_required")
    derived = tuple(sorted(set(observed_derived_effects)))
    if any(item not in envelope.allowed_derived_effects for item in derived):
        return RemoteEffectReconciliation("mismatch", "unexpected_derived_effect", envelope.envelope_hash)
    if not observation_complete:
        return RemoteEffectReconciliation("uncertain", "post_execution_observation_incomplete", envelope.envelope_hash)
    if provider_outcome == "unknown":
        return RemoteEffectReconciliation("uncertain", "provider_commit_outcome_unknown", envelope.envelope_hash)
    if provider_outcome == "failed":
        return RemoteEffectReconciliation("verified_failure", "provider_reported_failure", envelope.envelope_hash)
    if provider_outcome != "succeeded":
        return RemoteEffectReconciliation("uncertain", "provider_outcome_invalid", envelope.envelope_hash)
    if observed_post_state != envelope.effect.desired_post_state:
        return RemoteEffectReconciliation("mismatch", "post_state_mismatch", envelope.envelope_hash)
    return RemoteEffectReconciliation("verified", "remote_effect_verified", envelope.envelope_hash)


def evaluate_sequence_ceiling(
    envelopes: Iterable[EffectAuthorityEnvelope],
    ceiling: ConsequenceVector,
) -> SequenceAuthorityCheck:
    """Fail closed before execution when composed low-severity effects exceed scope."""

    if not isinstance(ceiling, ConsequenceVector):
        raise TypeError("sequence_ceiling_required")
    aggregate = ConsequenceVector()
    seen: set[str] = set()
    for envelope in envelopes:
        if not isinstance(envelope, EffectAuthorityEnvelope):
            raise TypeError("sequence_effect_authority_invalid")
        if envelope.envelope_hash in seen:
            return SequenceAuthorityCheck("deny", "sequence_duplicate_effect", aggregate, ceiling)
        seen.add(envelope.envelope_hash)
        aggregate = aggregate + envelope.planned_consequence
    if not aggregate.within(ceiling):
        fields = ",".join(aggregate.exceeded_fields(ceiling))
        return SequenceAuthorityCheck("deny", f"sequence_ceiling_exceeded:{fields}", aggregate, ceiling)
    return SequenceAuthorityCheck("allow", "sequence_within_ceiling", aggregate, ceiling)


def authorize_remote_effect_attempt_with_aggregate(
    kernel: GovernanceKernel,
    permit: str,
    intent: Intent,
    envelope: EffectAuthorityEnvelope,
    requested_effect: RemoteEffect,
    observed_context: ExecutionContext,
    aggregate_budget: SQLiteAggregateConsequenceBudget,
    *,
    observed_pre_state: str | None,
    requested_derived_effects: Iterable[str] = (),
    requested_consequence: ConsequenceVector | None = None,
    now_ns: int,
    observation_complete: bool = True,
) -> AggregateRemoteEffectAuthorization:
    """Authorize one external attempt under both exact and rolling consequence authority.

    Preflight denies obvious exhaustion without spending the permit. The durable
    record is repeated atomically after permit consumption to close concurrent
    races. If a race exhausts the ceiling after consumption, no external effect
    is authorized and the consumed permit remains spent.
    """

    aggregate = envelope.aggregate_authority
    if aggregate is None:
        return AggregateRemoteEffectAuthorization(
            "deny", "aggregate_authority_missing", False, False
        )
    if aggregate_budget.authority.authority_hash != aggregate.authority_hash:
        return AggregateRemoteEffectAuthorization(
            "deny", "aggregate_budget_authority_mismatch", False, False
        )
    if intent.principal != aggregate.principal:
        return AggregateRemoteEffectAuthorization(
            "deny", "aggregate_principal_mismatch", False, False
        )
    if intent.session_id != aggregate.session_id:
        return AggregateRemoteEffectAuthorization(
            "deny", "aggregate_session_mismatch", False, False
        )
    consequence = requested_consequence
    if consequence is None or not isinstance(consequence, ConsequenceVector):
        return AggregateRemoteEffectAuthorization(
            "deny", "consequence_plan_missing", False, False
        )
    try:
        aggregate_budget.preflight(requested_effect, consequence, now_ns=now_ns, permit=permit)
    except AggregateConsequenceViolation as exc:
        return AggregateRemoteEffectAuthorization("deny", str(exc), False, False)

    check, permit_consumed = _consume_remote_effect_permit_exact(
        kernel, permit, intent, envelope, requested_effect, observed_context,
        observed_pre_state=observed_pre_state,
        requested_derived_effects=requested_derived_effects,
        requested_consequence=consequence,
        now_ns=now_ns,
        observation_complete=observation_complete,
    )
    if not permit_consumed:
        return AggregateRemoteEffectAuthorization(check.outcome, check.reason, False, False)

    try:
        receipt = aggregate_budget.record_attempt(
            requested_effect, permit, consequence, now_ns=now_ns
        )
    except AggregateConsequenceViolation as exc:
        return AggregateRemoteEffectAuthorization(
            "deny", f"{exc}:permit_spent", True, False
        )
    return AggregateRemoteEffectAuthorization(
        "allow", "exact_effect_and_aggregate_authority_match", True, True, receipt
    )
