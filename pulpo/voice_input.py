"""Fail-closed speech-input contract for Pulpo Voice V0.

A transcript is untrusted observation from an input capability.  It is not a
human identity proof, an approval, a permit, or evidence that an external action
occurred.  This module deliberately recognizes only a tiny exact control grammar
and delegates every governance decision to ``GovernedVoiceInterface``.

The session state here is convenience state only.  It is intentionally
in-memory and authority-neutral: restart loses the staged/active target and
therefore fails closed rather than guessing conversational continuity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import time
from typing import Callable

from .authority import ApprovalEnvelope
from .kernel import Decision, Intent
from .voice import GovernedVoiceInterface, TargetReference, VoiceResult


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _normalize_control_text(text: str) -> str:
    """Normalize formatting only; never infer intent from approximate speech.

    Local STT engines commonly append sentence-final punctuation to short
    utterances.  V0 removes only terminal ``.``, ``!``, and ``?`` characters
    after case/whitespace normalization.  It does not remove or rewrite words,
    internal punctuation, negation, politeness, or surrounding phrases.
    """

    normalized = re.sub(r"\s+", " ", text.strip().casefold())
    return re.sub(r"[.!?]+$", "", normalized).strip()


@dataclass(frozen=True)
class TranscriptArtifact:
    """One untrusted transcript observation with a deterministic evidence hash."""

    text: str
    source: str
    captured_at_ns: int
    sequence: int
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("transcript text must be non-empty")
        if not self.source or self.captured_at_ns <= 0 or self.sequence <= 0:
            raise ValueError("transcript source, time, and sequence must be valid")

    @property
    def transcript_hash(self) -> str:
        return sha256(
            _canonical(
                {
                    "schema": "pulpo.transcript.v0",
                    "text": self.text,
                    "source": self.source,
                    "captured_at_ns": self.captured_at_ns,
                    "sequence": self.sequence,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class StagedTarget:
    """In-memory intelligence proposal awaiting an explicit lock command."""

    target_id: str
    intent: Intent
    version: int = 1
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not self.target_id or self.version <= 0:
            raise ValueError("staged target identity and version must be valid")


@dataclass(frozen=True)
class VoiceInputResult:
    """Sanitized input-session result; never contains a permit."""

    code: str
    message: str
    transcript_hash: str
    target: TargetReference | None = None
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not self.code or not self.message or len(self.transcript_hash) != 64:
            raise ValueError("voice input result fields must be valid")


class VoiceCommandSession:
    """Maps exact control transcripts onto the governed Voice V0 interface.

    Supported commands are intentionally exact after limited formatting
    normalization:

    - ``lock target``: lock the currently staged proposal;
    - ``fire``: request governance for the currently locked exact target;
    - ``cancel target``: forget staged/active convenience state.

    Everything else is non-command speech and has no governance effect.
    """

    LOCK_COMMAND = "lock target"
    FIRE_COMMAND = "fire"
    CANCEL_COMMAND = "cancel target"
    authority_effect = "none"

    def __init__(
        self,
        voice: GovernedVoiceInterface,
        *,
        clock: Callable[[], int] = time.time_ns,
        transcript_source: str = "untrusted-local-stt",
    ) -> None:
        self.voice = voice
        self._clock = clock
        self.transcript_source = transcript_source
        self._sequence = 0
        self._staged: StagedTarget | None = None
        self._active: TargetReference | None = None
        self._handled_transcripts: set[str] = set()

    @property
    def staged_target(self) -> StagedTarget | None:
        return self._staged

    @property
    def active_target(self) -> TargetReference | None:
        return self._active

    def stage(self, target_id: str, intent: Intent, *, version: int = 1) -> StagedTarget:
        """Stage an intelligence proposal without writing governance state."""

        staged = StagedTarget(target_id, intent, version)
        self._staged = staged
        return staged

    def capture(self, text: str) -> TranscriptArtifact:
        """Create one transcript artifact from an untrusted STT observation."""

        self._sequence += 1
        now_ns = self._clock()
        if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns <= 0:
            raise RuntimeError("transcript_clock_invalid")
        return TranscriptArtifact(text, self.transcript_source, now_ns, self._sequence)

    def handle(
        self,
        transcript: TranscriptArtifact,
        *,
        approval: ApprovalEnvelope | None = None,
    ) -> tuple[VoiceInputResult, VoiceResult | None, Decision | None]:
        """Handle one exact control transcript and fail closed on ambiguity/replay."""

        digest = transcript.transcript_hash
        if digest in self._handled_transcripts:
            return (
                VoiceInputResult(
                    "transcript_replay",
                    "Transcript already handled. No governance action was repeated.",
                    digest,
                    self._active,
                ),
                None,
                None,
            )
        self._handled_transcripts.add(digest)

        command = _normalize_control_text(transcript.text)
        if command == self.CANCEL_COMMAND:
            self._staged = None
            self._active = None
            return (
                VoiceInputResult(
                    "target_cancelled",
                    "Voice-session target state cleared. No authority changed.",
                    digest,
                ),
                None,
                None,
            )

        if command == self.LOCK_COMMAND:
            if self._staged is None:
                return (
                    VoiceInputResult(
                        "nothing_staged",
                        "No exact proposal is staged. Nothing was locked.",
                        digest,
                    ),
                    None,
                    None,
                )
            staged = self._staged
            voice_result = self.voice.lock_target(
                staged.target_id,
                staged.intent,
                version=staged.version,
            )
            self._active = voice_result.target
            self._staged = None
            return (
                VoiceInputResult(
                    "target_locked",
                    "Exact target locked. Speech granted no authority.",
                    digest,
                    self._active,
                ),
                voice_result,
                None,
            )

        if command == self.FIRE_COMMAND:
            if self._active is None:
                return (
                    VoiceInputResult(
                        "no_active_target",
                        "No exact locked target is active. Nothing was submitted to governance.",
                        digest,
                    ),
                    None,
                    None,
                )
            reference = self._active
            voice_result, decision = self.voice.fire(reference, approval=approval)

            # Approval-required is intentionally retryable with a separately
            # obtained approval envelope.  Every terminal governance result
            # clears the convenience reference so duplicate speech cannot mint
            # additional permits or silently retry a denial.
            if decision is None or decision.outcome != "require_approval":
                self._active = None

            return (
                VoiceInputResult(
                    "governance_requested",
                    "Exact target submitted to Pulpo governance. Speech itself granted no authority.",
                    digest,
                    reference,
                ),
                voice_result,
                decision,
            )

        return (
            VoiceInputResult(
                "non_command_speech",
                "Transcript was not an exact Pulpo control command. No governance action occurred.",
                digest,
                self._active,
            ),
            None,
            None,
        )
