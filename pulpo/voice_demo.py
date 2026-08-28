"""Safe local two-way Voice V0 proof.

The demo stages one fixed, non-executing read intent, listens for exact control
phrases through the local STT adapter, delegates governance to Pulpo, and renders
sanitized status through the local speaker.  It intentionally has no executor.
A real permit may be issued, but no side effect is performed or claimed.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Callable, Protocol

from .kernel import GovernanceKernel, Intent, Policy
from .local_listen import EmptyTranscriptionError, LocalWhisperMicrophone, MicrophoneUnavailableError
from .local_speech import SpeechUnavailableError, SystemSpeaker
from .voice import GovernedVoiceInterface, VoiceProfile
from .voice_input import VoiceCommandSession


class Transcriber(Protocol):
    def transcribe(self, *, seconds: float = 3.0): ...


class DemoSpeaker(Protocol):
    def speak(self, text: str) -> None: ...


_DEMO_TARGET_ID = "LOCAL-VOICE-DEMO"
_DEMO_INTENT = Intent(
    "human:local-demo",
    "read",
    "demo:voice-loop",
    0,
    "local-voice-demo",
)


def run_demo(
    *,
    transcriber: Transcriber,
    speaker: DemoSpeaker,
    seconds: float = 3.0,
    max_turns: int = 8,
    clock: Callable[[], int] = time.time_ns,
) -> int:
    """Run one non-executing local voice-control proof.

    Return codes:
    - 0: permit issued for the exact demo target, or operator cancelled;
    - 2: local audio/transcription failure;
    - 3: governance denial;
    - 4: turn limit reached without a terminal result.
    """

    kernel = GovernanceKernel(
        Policy(frozenset({"read"}), 0),
        secret=b"pulpo-local-voice-demo-v0",
        clock=clock,
    )
    voice = GovernedVoiceInterface(
        kernel,
        VoiceProfile("pulpo-command-v1", "pulpo-01", "concise"),
        speaker=speaker,
    )
    session = VoiceCommandSession(voice, clock=clock)
    session.stage(_DEMO_TARGET_ID, _DEMO_INTENT)

    speaker.speak(
        "Pulpo local voice demo online. A harmless read target is staged. Say lock target."
    )

    for _turn in range(max_turns):
        try:
            observation = transcriber.transcribe(seconds=seconds)
        except (MicrophoneUnavailableError, EmptyTranscriptionError, RuntimeError, ValueError) as exc:
            print(f"pulpo-voice-demo input failed: {exc}", file=sys.stderr)
            return 2

        # The transcript is useful host evidence, but it is never authority.
        print(f"heard={observation.text}")
        artifact = session.capture(observation.text)
        input_result, voice_result, decision = session.handle(artifact)
        print(f"input_result={input_result.code}")

        # GovernedVoiceInterface already renders recognized lock/fire outcomes.
        # Non-command/session-only outcomes are spoken here so the user receives
        # feedback without elevating the transcript into authority.
        if voice_result is None:
            speaker.speak(input_result.message)

        if input_result.code == "target_cancelled":
            print("demo_result=cancelled")
            return 0

        if decision is not None:
            print(f"decision={decision.outcome}")
            print(f"decision_reason={decision.reason}")
            if decision.outcome == "allow":
                # Do not print or speak the permit.  The demo has no executor.
                print("execution=not_performed")
                return 0
            if decision.outcome == "deny":
                print("execution=not_performed")
                return 3

    speaker.speak("Turn limit reached. No further governance action will be attempted.")
    print("demo_result=turn_limit")
    return 4


def main(
    argv: list[str] | None = None,
    *,
    transcriber: Transcriber | None = None,
    speaker: DemoSpeaker | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pulpo-voice-demo",
        description="Run a safe local two-way Pulpo voice-control proof with no executor.",
    )
    parser.add_argument("--seconds", type=float, default=3.0, help="capture duration per utterance")
    parser.add_argument("--model", default="base.en", help="local faster-whisper model name")
    parser.add_argument("--max-turns", type=int, default=8, help="maximum utterances before fail-closed exit")
    args = parser.parse_args(argv)

    if args.max_turns <= 0:
        print("pulpo-voice-demo failed: max-turns must be positive", file=sys.stderr)
        return 2

    listener = transcriber if transcriber is not None else LocalWhisperMicrophone(model_name=args.model)
    renderer = speaker if speaker is not None else SystemSpeaker()
    try:
        return run_demo(
            transcriber=listener,
            speaker=renderer,
            seconds=args.seconds,
            max_turns=args.max_turns,
        )
    except (SpeechUnavailableError, OSError, ValueError) as exc:
        print(f"pulpo-voice-demo output failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
