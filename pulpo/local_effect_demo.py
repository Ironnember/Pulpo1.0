"""Two-way voice -> governed local consequence -> reconciliation proof.

This proof harness stages one exact bounded file effect in the current Pulpo
checkout. Voice remains an untrusted control surface. The existing governance
kernel decides authority, the local executor consumes the one-use permit, a
fresh read path observes the file, and speech reports success only after exact
reconciliation.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import sys
import time
from typing import Callable, Protocol

from .kernel import GovernanceKernel, Policy
from .local_effect import (
    LocalEffectViolation,
    LocalFileEffect,
    LocalFileExecutor,
    build_local_effect_proof,
    local_file_intent,
    observe_local_file,
    reconcile_local_file,
)
from .local_listen import EmptyTranscriptionError, LocalWhisperMicrophone, MicrophoneUnavailableError
from .local_speech import SpeechUnavailableError, SystemSpeaker
from .voice import GovernedVoiceInterface, VoiceProfile
from .voice_input import VoiceCommandSession


class Transcriber(Protocol):
    def transcribe(self, *, seconds: float = 3.0): ...


class DemoSpeaker(Protocol):
    def speak(self, text: str) -> None: ...


def _require_pulpo_checkout(root: Path) -> Path:
    root = root.resolve()
    if not root.is_dir():
        raise LocalEffectViolation("pulpo_checkout_invalid")
    pyproject = root / "pyproject.toml"
    git_marker = root / ".git"
    if not pyproject.is_file() or not git_marker.exists():
        raise LocalEffectViolation("pulpo_checkout_required")
    try:
        metadata = pyproject.read_text(encoding="utf-8")
    except OSError as exc:
        raise LocalEffectViolation("pulpo_checkout_unreadable") from exc
    if 'name = "pulpo"' not in metadata:
        raise LocalEffectViolation("pulpo_checkout_required")
    return root


def _capture_prompt(session: VoiceCommandSession) -> str:
    if session.staged_target is not None:
        return "Listening. Say lock target."
    if session.active_target is not None:
        return "Listening. Say fire, or cancel target."
    return "Listening for an exact Pulpo control command."


def _new_effect(root: Path, effect_id: str | None = None) -> LocalFileEffect:
    if effect_id is not None:
        candidate = LocalFileEffect(
            effect_id,
            f"Pulpo verified local effect {effect_id}\n",
        )
        if (root / candidate.relative_path).exists():
            raise LocalEffectViolation("effect_target_exists")
        return candidate

    for _ in range(8):
        identifier = secrets.token_hex(8)
        candidate = LocalFileEffect(
            identifier,
            f"Pulpo verified local effect {identifier}\n",
        )
        if not (root / candidate.relative_path).exists():
            return candidate
    raise LocalEffectViolation("effect_id_collision")


def run_effect_demo(
    *,
    transcriber: Transcriber,
    speaker: DemoSpeaker,
    root: str | Path,
    effect_id: str | None = None,
    seconds: float = 3.0,
    max_turns: int = 8,
    max_empty_retries: int = 3,
    clock: Callable[[], int] = time.time_ns,
    executor: LocalFileExecutor | None = None,
) -> int:
    """Run one exact voice-authorized, locally observed consequence proof.

    Return codes:
    - 0: exact effect observed/reconciled, or operator cancelled before execution;
    - 2: local IO/audio/configuration failure;
    - 3: governance denial;
    - 4: turn limit reached;
    - 5: execution occurred or was attempted but reconciliation did not verify it.
    """

    if max_turns <= 0 or max_empty_retries < 0:
        raise ValueError("demo turn and empty-retry limits are invalid")

    root_path = _require_pulpo_checkout(Path(root))
    effect = _new_effect(root_path, effect_id)
    intent = local_file_intent(effect)
    target_id = f"LOCAL-EFFECT-{effect.effect_id}"

    kernel = GovernanceKernel(
        Policy(frozenset({"create_local_file"}), 0),
        secret=b"pulpo-local-effect-demo-v0",
        clock=clock,
    )
    voice = GovernedVoiceInterface(
        kernel,
        VoiceProfile("pulpo-command-v1", "pulpo-01", "concise"),
        speaker=speaker,
    )
    session = VoiceCommandSession(voice, clock=clock)
    session.stage(target_id, intent)
    effect_executor = executor if executor is not None else LocalFileExecutor(clock=clock)

    print(f"effect_path={effect.relative_path}")
    print(f"effect_hash={effect.effect_hash}")
    print(f"expected_content_hash={effect.content_hash}")
    speaker.speak(
        "A bounded local file consequence is staged. Nothing has executed. Say lock target."
    )

    handled_turns = 0
    consecutive_empty = 0
    while handled_turns < max_turns:
        speaker.speak(_capture_prompt(session))
        try:
            observation = transcriber.transcribe(seconds=seconds)
        except EmptyTranscriptionError:
            consecutive_empty += 1
            print("heard=<none>")
            print("input_result=no_speech")
            if consecutive_empty > max_empty_retries:
                speaker.speak(
                    "No speech was captured after the retry limit. No consequence was authorized."
                )
                print("demo_result=input_unavailable")
                return 2
            speaker.speak("I did not catch speech. No governance action occurred. Try again.")
            continue
        except (MicrophoneUnavailableError, RuntimeError, ValueError) as exc:
            print(f"pulpo-effect-demo input failed: {exc}", file=sys.stderr)
            return 2

        consecutive_empty = 0
        handled_turns += 1
        print(f"heard={observation.text}")
        artifact = session.capture(observation.text)
        input_result, voice_result, decision = session.handle(artifact)
        print(f"input_result={input_result.code}")

        if voice_result is None:
            speaker.speak(input_result.message)

        if input_result.code == "target_cancelled":
            print("execution=not_performed")
            print("demo_result=cancelled")
            return 0

        if decision is None:
            continue

        print(f"decision={decision.outcome}")
        print(f"decision_reason={decision.reason}")
        if decision.outcome == "deny":
            print("execution=not_performed")
            return 3
        if decision.outcome != "allow" or decision.permit is None:
            # Approval is not expected in this narrow demo policy. Anything else
            # remains non-executable and fails closed.
            print("execution=not_performed")
            speaker.speak("No executable permit is available. Nothing will be executed.")
            return 3

        try:
            execution = effect_executor.execute(
                kernel,
                effect,
                decision.permit,
                root=root_path,
            )
        except LocalEffectViolation as exc:
            print("execution=not_verified")
            print(f"execution_error={exc}")
            speaker.speak(
                "Execution is not verified. No automatic retry will be attempted."
            )
            return 5

        # Consequence verification is a fresh filesystem read, not the executor's
        # return value. Only reconciliation may upgrade the spoken claim.
        observed = observe_local_file(effect, root=root_path, clock=clock)
        reconciliation = reconcile_local_file(kernel, effect, execution, observed)

        # Deliberately test replay after execution. A second permit consumption
        # must fail, and no second effect attempt is made.
        replay_rejected = not kernel.consume(decision.permit, intent)
        proof = build_local_effect_proof(
            kernel,
            effect,
            execution,
            observed,
            reconciliation,
        )

        print("execution=performed")
        print(f"observed_content_hash={observed.observed_content_hash}")
        print(f"reconciliation={reconciliation.outcome}")
        print(f"reconciliation_reason={reconciliation.reason}")
        print(f"permit_replay={'rejected' if replay_rejected else 'unexpectedly_allowed'}")
        print(f"proof_bundle_hash={proof['bundle_hash']}")

        if reconciliation.verified and replay_rejected:
            speaker.speak(
                "Execution verified. The exact local file consequence matches the authorized target."
            )
            return 0

        speaker.speak(
            "Execution was attempted, but the observed consequence did not verify exactly."
        )
        return 5

    speaker.speak("Turn limit reached. No further governance action will be attempted.")
    print("execution=not_performed")
    print("demo_result=turn_limit")
    return 4


def main(
    argv: list[str] | None = None,
    *,
    transcriber: Transcriber | None = None,
    speaker: DemoSpeaker | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pulpo-effect-demo",
        description="Run one voice-governed local file consequence with verification and reconciliation.",
    )
    parser.add_argument("--seconds", type=float, default=3.0, help="capture duration per utterance")
    parser.add_argument("--model", default="base.en", help="local faster-whisper model name")
    parser.add_argument("--max-turns", type=int, default=8, help="maximum recognized utterances")
    parser.add_argument(
        "--empty-retries",
        type=int,
        default=3,
        help="consecutive empty capture windows allowed before fail-closed exit",
    )
    args = parser.parse_args(argv)

    if args.max_turns <= 0 or args.empty_retries < 0:
        print("pulpo-effect-demo failed: invalid retry/turn limits", file=sys.stderr)
        return 2

    listener = transcriber if transcriber is not None else LocalWhisperMicrophone(model_name=args.model)
    renderer = speaker if speaker is not None else SystemSpeaker()
    try:
        return run_effect_demo(
            transcriber=listener,
            speaker=renderer,
            root=Path.cwd(),
            seconds=args.seconds,
            max_turns=args.max_turns,
            max_empty_retries=args.empty_retries,
        )
    except (LocalEffectViolation, SpeechUnavailableError, OSError, ValueError) as exc:
        print(f"pulpo-effect-demo failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
