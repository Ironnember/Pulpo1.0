"""Voice-interface contract over Pulpo's existing governed target path.

Voice is an expression and proposal surface.  It does not authenticate a human,
grant authority, mint permits, execute side effects, or establish completion.
The interface resolves exact locked targets and delegates governance to the one
``GovernanceKernel``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .authority import ApprovalEnvelope
from .kernel import Decision, GovernanceKernel, Intent, LockedTarget
from .targets import evaluate_locked_target_with_approval


class Speaker(Protocol):
    """Untrusted output surface for rendered speech."""

    def speak(self, text: str) -> None: ...


@dataclass(frozen=True)
class VoiceProfile:
    """Expression preferences with no identity or authority effect."""

    profile_id: str
    voice_id: str
    style: str = "neutral"
    version: int = 1
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not self.profile_id or not self.voice_id or not self.style or self.version <= 0:
            raise ValueError("voice profile fields must be non-empty and versioned")


@dataclass(frozen=True)
class TargetReference:
    """Exact non-authorizing reference returned after a target is locked."""

    target_id: str
    version: int
    target_hash: str
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not self.target_id or self.version <= 0 or len(self.target_hash) != 64:
            raise ValueError("target reference is invalid")

    @classmethod
    def from_target(cls, target: LockedTarget) -> "TargetReference":
        return cls(target.target_id, target.version, target.target_hash)


@dataclass(frozen=True)
class VoiceResult:
    """Sanitized status suitable for speech; never contains a permit."""

    code: str
    message: str
    target: TargetReference | None = None
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not self.code or not self.message:
            raise ValueError("voice result fields must be non-empty")


class GovernedVoiceInterface:
    """Turns conversational controls into exact governed target operations.

    This object may render status through an injected speaker, but all authority
    decisions remain in ``GovernanceKernel``.  The returned ``Decision`` is kept
    separate from the spoken ``VoiceResult`` so a permit is never embedded in
    speech output.
    """

    def __init__(
        self,
        kernel: GovernanceKernel,
        profile: VoiceProfile,
        *,
        speaker: Speaker | None = None,
    ) -> None:
        self.kernel = kernel
        self.profile = profile
        self.speaker = speaker

    def _emit(self, result: VoiceResult) -> VoiceResult:
        if self.speaker is not None:
            self.speaker.speak(result.message)
        return result

    def lock_target(
        self,
        target_id: str,
        intent: Intent,
        *,
        version: int = 1,
    ) -> VoiceResult:
        target = self.kernel.lock_target(target_id, intent, version=version)
        reference = TargetReference.from_target(target)
        return self._emit(
            VoiceResult(
                "target_locked",
                "Target locked as an exact proposal. No authority has been granted.",
                reference,
            )
        )

    def fire(
        self,
        reference: TargetReference,
        *,
        approval: ApprovalEnvelope | None = None,
    ) -> tuple[VoiceResult, Decision | None]:
        """Request governance for an exact target without executing it."""

        if approval is None:
            resolution, decision = self.kernel.evaluate_locked_target(
                reference.target_id,
                reference.target_hash,
                version=reference.version,
            )
        else:
            resolution, decision = evaluate_locked_target_with_approval(
                self.kernel,
                reference.target_id,
                reference.target_hash,
                approval,
                version=reference.version,
            )

        if resolution.outcome != "match":
            result = VoiceResult(
                "target_denied",
                f"Target denied: {resolution.reason}.",
                reference,
            )
            return self._emit(result), None

        if decision is None:
            result = VoiceResult(
                "governance_unavailable",
                "Governance did not produce a decision. No action is authorized.",
                reference,
            )
            return self._emit(result), None

        if decision.outcome == "allow":
            result = VoiceResult(
                "permit_issued",
                "Permit issued for the exact target. Execution is not yet proven.",
                reference,
            )
        elif decision.outcome == "require_approval":
            result = VoiceResult(
                "approval_required",
                "Approval is required for the exact target. Nothing has executed.",
                reference,
            )
        else:
            result = VoiceResult(
                "governance_denied",
                f"Denied by governance: {decision.reason}.",
                reference,
            )
        return self._emit(result), decision
