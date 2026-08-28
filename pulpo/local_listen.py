"""Optional host-local microphone and Whisper transcription adapter.

Audio capture and speech recognition are untrusted input capabilities.  Their
output is a transcript observation only: it is not identity, authentication,
approval, authority, a permit, or evidence that a governed side effect occurred.

The optional dependencies are imported lazily so the Pulpo governance kernel
keeps its zero-dependency runtime surface.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from hashlib import sha256
import json
import sys
import time
from typing import Callable, Iterable


class MicrophoneUnavailableError(RuntimeError):
    """Raised when optional local microphone/STT dependencies are unavailable."""


class EmptyTranscriptionError(RuntimeError):
    """Raised when the local recognizer produces no usable transcript."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class LocalTranscription:
    """One local STT observation suitable for conversion to a transcript artifact."""

    text: str
    backend: str
    model: str
    sample_rate: int
    duration_seconds: float
    captured_at_ns: int
    authority_effect: str = field(default="none", init=False)

    def __post_init__(self) -> None:
        if not self.text.strip() or not self.backend or not self.model:
            raise ValueError("transcription text/backend/model must be non-empty")
        if self.sample_rate <= 0 or self.duration_seconds <= 0 or self.captured_at_ns <= 0:
            raise ValueError("transcription timing fields must be positive")

    @property
    def observation_hash(self) -> str:
        return sha256(
            _canonical(
                {
                    "schema": "pulpo.local-transcription.v0",
                    "text": self.text,
                    "backend": self.backend,
                    "model": self.model,
                    "sample_rate": self.sample_rate,
                    "duration_seconds": self.duration_seconds,
                    "captured_at_ns": self.captured_at_ns,
                }
            )
        ).hexdigest()


def _flatten_audio(audio: object) -> object:
    reshape = getattr(audio, "reshape", None)
    if callable(reshape):
        return reshape(-1)
    return audio


def _joined_segment_text(segments: Iterable[object]) -> str:
    parts: list[str] = []
    for segment in segments:
        text = getattr(segment, "text", "")
        if isinstance(text, str) and text.strip():
            parts.append(text.strip())
    return " ".join(parts).strip()


class LocalWhisperMicrophone:
    """Fixed-duration microphone capture followed by local faster-whisper STT."""

    authority_effect = "none"

    def __init__(
        self,
        *,
        model_name: str = "base.en",
        sample_rate: int = 16_000,
        device: str = "auto",
        compute_type: str = "auto",
        recorder: Callable[..., object] | None = None,
        waiter: Callable[[], object] | None = None,
        model_factory: Callable[..., object] | None = None,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        if not model_name or sample_rate <= 0 or not device or not compute_type:
            raise ValueError("local transcription configuration is invalid")
        self.model_name = model_name
        self.sample_rate = sample_rate
        self.device = device
        self.compute_type = compute_type
        self._recorder = recorder
        self._waiter = waiter
        self._model_factory = model_factory
        self._clock = clock
        self._model: object | None = None

    def _load_audio_backend(self) -> tuple[Callable[..., object], Callable[[], object]]:
        if self._recorder is not None:
            return self._recorder, self._waiter or (lambda: None)
        try:
            import sounddevice as sd
        except Exception as exc:  # optional dependency and host driver boundary
            raise MicrophoneUnavailableError(
                "local microphone support requires the 'voice' extra and a working audio input device"
            ) from exc
        return sd.rec, sd.wait

    def _load_model(self) -> object:
        if self._model is not None:
            return self._model
        factory = self._model_factory
        if factory is None:
            try:
                from faster_whisper import WhisperModel
            except Exception as exc:  # optional dependency boundary
                raise MicrophoneUnavailableError(
                    "local transcription requires the 'voice' extra"
                ) from exc
            factory = WhisperModel
        self._model = factory(
            self.model_name,
            device=self.device,
            compute_type=self.compute_type,
        )
        return self._model

    def transcribe(self, *, seconds: float = 3.0) -> LocalTranscription:
        """Capture a short utterance and return an authority-neutral transcript."""

        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("capture duration must be numeric")
        seconds = float(seconds)
        if seconds < 0.25 or seconds > 30.0:
            raise ValueError("capture duration must be between 0.25 and 30 seconds")
        frames = int(round(seconds * self.sample_rate))
        recorder, waiter = self._load_audio_backend()
        try:
            audio = recorder(
                frames,
                samplerate=self.sample_rate,
                channels=1,
                dtype="float32",
            )
            waiter()
        except Exception as exc:
            raise MicrophoneUnavailableError("microphone capture failed") from exc

        model = self._load_model()
        try:
            segments, _info = model.transcribe(
                _flatten_audio(audio),
                beam_size=1,
                vad_filter=True,
                language="en",
                condition_on_previous_text=False,
            )
            text = _joined_segment_text(segments)
        except Exception as exc:
            raise MicrophoneUnavailableError("local transcription failed") from exc
        if not text:
            raise EmptyTranscriptionError("no speech was transcribed")

        captured_at_ns = self._clock()
        if isinstance(captured_at_ns, bool) or not isinstance(captured_at_ns, int) or captured_at_ns <= 0:
            raise RuntimeError("transcription_clock_invalid")
        return LocalTranscription(
            text=text,
            backend="faster-whisper",
            model=self.model_name,
            sample_rate=self.sample_rate,
            duration_seconds=seconds,
            captured_at_ns=captured_at_ns,
        )


def main(argv: list[str] | None = None, *, transcriber: LocalWhisperMicrophone | None = None) -> int:
    """Capture one local utterance and print the untrusted transcript observation."""

    parser = argparse.ArgumentParser(
        prog="pulpo-listen",
        description="Capture one local utterance and print an untrusted transcript.",
    )
    parser.add_argument("--seconds", type=float, default=3.0, help="capture duration (0.25-30 seconds)")
    parser.add_argument("--model", default="base.en", help="local faster-whisper model name")
    args = parser.parse_args(argv)
    listener = transcriber if transcriber is not None else LocalWhisperMicrophone(model_name=args.model)
    try:
        observation = listener.transcribe(seconds=args.seconds)
    except (MicrophoneUnavailableError, EmptyTranscriptionError, RuntimeError, ValueError) as exc:
        print(f"pulpo-listen failed: {exc}", file=sys.stderr)
        return 2
    print(observation.text)
    print(f"observation_hash={observation.observation_hash}")
    print("authority_effect=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
