"""Governed evidence-retention proof built on Pulpo's existing audit state.

This module deliberately does not create another authority system or evidence
ledger.  Evidence inventory is an execution-side object store for this proof;
authority comes from the canonical GovernanceKernel and all material outcomes
are appended to the existing KernelState audit chain.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any

from .kernel import Decision, GovernanceKernel, Intent
from .state import KernelState


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _merkle_root(leaves: list[str]) -> str:
    """Return a deterministic SHA-256 Merkle root for hexadecimal leaf hashes."""
    if not leaves:
        return sha256(b"").hexdigest()
    level = [bytes.fromhex(item) for item in sorted(leaves)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    agency_id: str
    created_at_ns: int
    payload: dict[str, Any]

    @property
    def evidence_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class RetentionPolicy:
    policy_id: str
    agency_id: str
    max_age_ns: int

    def __post_init__(self) -> None:
        if not self.policy_id or not self.agency_id:
            raise ValueError("retention policy identifiers must be non-empty")
        if self.max_age_ns < 0:
            raise ValueError("max_age_ns must be non-negative")


@dataclass(frozen=True)
class RetentionEligibility:
    eligible: bool
    reason: str
    age_ns: int


@dataclass(frozen=True)
class DeletionManifest:
    manifest_id: str
    evidence_id: str
    agency_id: str
    deleted_at_ns: int
    actor: str
    policy_id: str
    eligibility_reason: str
    evidence_hash: str
    merkle_root_before: str
    merkle_root_after: str
    intent_hash: str


class EvidenceInventory:
    """Execution-side evidence inventory for the bounded retention proof."""

    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}

    def put(self, record: EvidenceRecord) -> None:
        if record.evidence_id in self._records:
            raise ValueError("evidence_id already exists")
        self._records[record.evidence_id] = record

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._records.get(evidence_id)

    def delete(self, evidence_id: str) -> EvidenceRecord:
        try:
            return self._records.pop(evidence_id)
        except KeyError as exc:
            raise ValueError("evidence_not_found") from exc

    @property
    def merkle_root(self) -> str:
        leaves = [_hash({"evidence_id": record.evidence_id, "evidence_hash": record.evidence_hash}) for record in self._records.values()]
        return _merkle_root(leaves)


class GovernedRetention:
    """Retention decision and deletion reconciliation using canonical Pulpo authority."""

    def __init__(self, inventory: EvidenceInventory, state: KernelState) -> None:
        self.inventory = inventory
        self._state = state

    def create_evidence(self, record: EvidenceRecord, timestamp_ns: int) -> None:
        self.inventory.put(record)
        self._state.append(
            "evidence_created",
            {
                "evidence_id": record.evidence_id,
                "agency_id": record.agency_id,
                "created_at_ns": record.created_at_ns,
                "evidence_hash": record.evidence_hash,
                "merkle_root": self.inventory.merkle_root,
            },
            timestamp_ns,
        )

    @staticmethod
    def eligibility(record: EvidenceRecord, policy: RetentionPolicy, now_ns: int) -> RetentionEligibility:
        if record.agency_id != policy.agency_id:
            return RetentionEligibility(False, "agency_policy_mismatch", max(0, now_ns - record.created_at_ns))
        if now_ns < record.created_at_ns:
            return RetentionEligibility(False, "clock_before_evidence_creation", 0)
        age_ns = now_ns - record.created_at_ns
        if age_ns <= policy.max_age_ns:
            return RetentionEligibility(False, f"within_retention({age_ns} <= {policy.max_age_ns})", age_ns)
        return RetentionEligibility(True, f"exceeded_max_retention({age_ns} > {policy.max_age_ns})", age_ns)

    def delete_with_permit(
        self,
        *,
        kernel: GovernanceKernel,
        intent: Intent,
        decision: Decision,
        evidence_id: str,
        policy: RetentionPolicy,
        actor: str,
        now_ns: int,
    ) -> DeletionManifest | None:
        expected_resource = f"evidence:{evidence_id}"
        if intent.action != "delete_evidence" or intent.resource != expected_resource or intent.principal != actor:
            self._state.append(
                "deletion_rejected",
                {"evidence_id": evidence_id, "reason": "deletion_intent_mismatch", "intent_hash": kernel.intent_hash(intent)},
                now_ns,
            )
            return None
        if decision.outcome != "allow" or not decision.permit or decision.intent_hash != kernel.intent_hash(intent):
            self._state.append(
                "deletion_rejected",
                {"evidence_id": evidence_id, "reason": "valid_permit_required", "intent_hash": kernel.intent_hash(intent)},
                now_ns,
            )
            return None
        # Consume first.  A denied retention attempt cannot be replayed later after
        # time advances and silently become eligible under an old permit.
        if not kernel.consume(decision.permit, intent):
            self._state.append(
                "deletion_rejected",
                {"evidence_id": evidence_id, "reason": "permit_rejected", "intent_hash": decision.intent_hash},
                now_ns,
            )
            return None

        record = self.inventory.get(evidence_id)
        if record is None:
            self._state.append(
                "deletion_rejected",
                {"evidence_id": evidence_id, "reason": "evidence_not_found", "intent_hash": decision.intent_hash},
                now_ns,
            )
            return None

        eligibility = self.eligibility(record, policy, now_ns)
        self._state.append(
            "retention_evaluated",
            {
                "evidence_id": evidence_id,
                "policy_id": policy.policy_id,
                "eligible": eligibility.eligible,
                "reason": eligibility.reason,
                "age_ns": eligibility.age_ns,
                "intent_hash": decision.intent_hash,
            },
            now_ns,
        )
        if not eligibility.eligible:
            self._state.append(
                "deletion_rejected",
                {"evidence_id": evidence_id, "reason": eligibility.reason, "intent_hash": decision.intent_hash},
                now_ns,
            )
            return None

        root_before = self.inventory.merkle_root
        evidence_hash = record.evidence_hash
        deleted = self.inventory.delete(evidence_id)
        if deleted.evidence_hash != evidence_hash:
            raise RuntimeError("deleted evidence hash changed during execution")
        root_after = self.inventory.merkle_root

        core = {
            "evidence_id": evidence_id,
            "agency_id": record.agency_id,
            "deleted_at_ns": now_ns,
            "actor": actor,
            "policy_id": policy.policy_id,
            "eligibility_reason": eligibility.reason,
            "evidence_hash": evidence_hash,
            "merkle_root_before": root_before,
            "merkle_root_after": root_after,
            "intent_hash": decision.intent_hash,
        }
        manifest = DeletionManifest(manifest_id=_hash({"schema": "pulpo.deletion-manifest.v1", **core}), **core)
        self._state.append("deletion_executed", asdict(manifest), now_ns)
        return manifest
