"""Pure field-expense evidence translation for governed-effect proofs.

This module is intentionally non-authoritative. It owns no kernel, state backend,
policy, permit, executor, approval verifier, or evidence ledger. It only turns
untrusted submission/evidence material into an exact immutable effect object
that can be presented to Pulpo's existing governance path.

Evidence may make an expense not ready for governance. Evidence may never grant,
broaden, revive, or substitute authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .kernel import Intent


EXPENSE_EFFECT_ACTION = "record_reimbursement_ready"
MIN_AUTOMATED_EVIDENCE_CONFIDENCE_PPM = 900_000


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _valid_sha256(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True)
class ExpenseSubmission:
    submission_id: str
    job_id: str
    claimed_amount_cents: int
    receipt_sha256: str | None
    worker_note: str = ""
    schema: str = "pulpo.expense-submission.v0"

    def __post_init__(self) -> None:
        if not self.submission_id or not self.job_id:
            raise ValueError("expense submission identity fields must be non-empty")
        if isinstance(self.claimed_amount_cents, bool) or self.claimed_amount_cents <= 0:
            raise ValueError("expense amount must be a positive integer")
        if self.receipt_sha256 is not None and not _valid_sha256(self.receipt_sha256):
            raise ValueError("expense receipt hash is invalid")
        if self.schema != "pulpo.expense-submission.v0":
            raise ValueError("unsupported expense submission schema")

    @property
    def submission_hash(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class ExpenseEvidenceClaim:
    submission_hash: str
    receipt_sha256: str | None
    extracted_amount_cents: int
    verifier_id: str
    confidence_ppm: int
    discrepancies: tuple[str, ...] = ()
    model_summary: str = ""
    schema: str = "pulpo.expense-evidence-claim.v0"

    def __post_init__(self) -> None:
        if not _valid_sha256(self.submission_hash):
            raise ValueError("expense evidence submission hash is invalid")
        if self.receipt_sha256 is not None and not _valid_sha256(self.receipt_sha256):
            raise ValueError("expense evidence receipt hash is invalid")
        if not self.verifier_id:
            raise ValueError("expense evidence verifier must be non-empty")
        if isinstance(self.extracted_amount_cents, bool) or self.extracted_amount_cents < 0:
            raise ValueError("expense evidence amount must be a non-negative integer")
        if (
            isinstance(self.confidence_ppm, bool)
            or self.confidence_ppm < 0
            or self.confidence_ppm > 1_000_000
        ):
            raise ValueError("expense evidence confidence must be within ppm bounds")
        if any(not item for item in self.discrepancies):
            raise ValueError("expense evidence discrepancies must be non-empty strings")
        if self.schema != "pulpo.expense-evidence-claim.v0":
            raise ValueError("unsupported expense evidence schema")

    @property
    def evidence_hash(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class ExpenseReadiness:
    ready: bool
    reason: str
    submission_hash: str
    evidence_hash: str


class ExpenseEvidenceNotReady(ValueError):
    """Raised when evidence cannot be projected into a governed effect."""


def evaluate_expense_readiness(
    submission: ExpenseSubmission,
    evidence: ExpenseEvidenceClaim,
    *,
    minimum_confidence_ppm: int = MIN_AUTOMATED_EVIDENCE_CONFIDENCE_PPM,
) -> ExpenseReadiness:
    """Return an evidence-only readiness result with no authority effect."""

    if (
        isinstance(minimum_confidence_ppm, bool)
        or minimum_confidence_ppm < 0
        or minimum_confidence_ppm > 1_000_000
    ):
        raise ValueError("minimum confidence must be within ppm bounds")

    reason = "expense_evidence_ready"
    if evidence.submission_hash != submission.submission_hash:
        reason = "expense_submission_hash_mismatch"
    elif submission.receipt_sha256 is None or evidence.receipt_sha256 is None:
        reason = "expense_receipt_missing"
    elif evidence.receipt_sha256 != submission.receipt_sha256:
        reason = "expense_receipt_hash_mismatch"
    elif evidence.extracted_amount_cents != submission.claimed_amount_cents:
        reason = "expense_amount_mismatch"
    elif evidence.discrepancies:
        reason = "expense_evidence_discrepancy"
    elif evidence.confidence_ppm < minimum_confidence_ppm:
        reason = "expense_evidence_confidence_below_threshold"

    return ExpenseReadiness(
        ready=reason == "expense_evidence_ready",
        reason=reason,
        submission_hash=submission.submission_hash,
        evidence_hash=evidence.evidence_hash,
    )


@dataclass(frozen=True)
class ExpenseGovernedEffect:
    submission_id: str
    submission_hash: str
    evidence_hash: str
    job_id: str
    amount_cents: int
    action: str = EXPENSE_EFFECT_ACTION
    schema: str = "pulpo.expense-governed-effect.v0"

    def __post_init__(self) -> None:
        if not self.submission_id or not self.job_id:
            raise ValueError("expense governed effect identity fields must be non-empty")
        if not _valid_sha256(self.submission_hash) or not _valid_sha256(self.evidence_hash):
            raise ValueError("expense governed effect evidence hashes are invalid")
        if isinstance(self.amount_cents, bool) or self.amount_cents <= 0:
            raise ValueError("expense governed effect amount must be positive")
        if self.action != EXPENSE_EFFECT_ACTION:
            raise ValueError("unsupported expense governed effect action")
        if self.schema != "pulpo.expense-governed-effect.v0":
            raise ValueError("unsupported expense governed effect schema")

    @property
    def effect_hash(self) -> str:
        return _digest(asdict(self))

    @property
    def resource(self) -> str:
        return f"expense:{self.job_id}:{self.submission_id}:{self.effect_hash}"

    @property
    def target_id(self) -> str:
        return f"expense-effect:{self.effect_hash}"

    def intent(self, principal: str, *, session_id: str = "default") -> Intent:
        if not principal:
            raise ValueError("expense governed effect principal must be non-empty")
        if not session_id:
            raise ValueError("expense governed effect session must be non-empty")
        return Intent(
            principal=principal,
            action=self.action,
            resource=self.resource,
            cost=self.amount_cents,
            session_id=session_id,
        )


def build_expense_effect(
    submission: ExpenseSubmission,
    evidence: ExpenseEvidenceClaim,
    *,
    minimum_confidence_ppm: int = MIN_AUTOMATED_EVIDENCE_CONFIDENCE_PPM,
) -> ExpenseGovernedEffect:
    """Create an exact effect only when evidence is ready.

    This is not an authorization decision. Successful construction means only
    that the evidence package is internally ready to be presented to governance.
    """

    readiness = evaluate_expense_readiness(
        submission,
        evidence,
        minimum_confidence_ppm=minimum_confidence_ppm,
    )
    if not readiness.ready:
        raise ExpenseEvidenceNotReady(readiness.reason)

    return ExpenseGovernedEffect(
        submission_id=submission.submission_id,
        submission_hash=submission.submission_hash,
        evidence_hash=evidence.evidence_hash,
        job_id=submission.job_id,
        amount_cents=submission.claimed_amount_cents,
    )
