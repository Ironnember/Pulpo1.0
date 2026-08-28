import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pulpo.local_listen import (
    EmptyTranscriptionError,
    LocalTranscription,
    LocalWhisperMicrophone,
    MicrophoneUnavailableError,
    main,
)


class Segment:
    def __init__(self, text):
        self.text = text


class FakeModel:
    def __init__(self, segments):
        self.segments = segments
        self.calls = []

    def transcribe(self, audio, **kwargs):
        self.calls.append((audio, kwargs))
        return iter(self.segments), object()


class FakeListener:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def transcribe(self, *, seconds):
        self.calls.append(seconds)
        if self.error is not None:
            raise self.error
        return self.result


class LocalListenTests(unittest.TestCase):
    def test_local_transcriber_records_fixed_duration_and_returns_untrusted_observation(self):
        calls = []
        model = FakeModel([Segment(" Fire ")])

        def recorder(frames, **kwargs):
            calls.append((frames, kwargs))
            return [0.0, 0.1, -0.1]

        listener = LocalWhisperMicrophone(
            model_name="base.en",
            sample_rate=16_000,
            recorder=recorder,
            waiter=lambda: calls.append("wait"),
            model_factory=lambda *args, **kwargs: model,
            clock=lambda: 1_900_000_000_000_000_000,
        )

        result = listener.transcribe(seconds=2.5)

        self.assertEqual("Fire", result.text)
        self.assertEqual("faster-whisper", result.backend)
        self.assertEqual("none", result.authority_effect)
        self.assertEqual(64, len(result.observation_hash))
        self.assertEqual(40_000, calls[0][0])
        self.assertEqual(
            {"samplerate": 16_000, "channels": 1, "dtype": "float32"},
            calls[0][1],
        )
        self.assertEqual("wait", calls[1])
        _audio, kwargs = model.calls[0]
        self.assertEqual(1, kwargs["beam_size"])
        self.assertTrue(kwargs["vad_filter"])
        self.assertEqual("en", kwargs["language"])
        self.assertFalse(kwargs["condition_on_previous_text"])

    def test_empty_transcription_fails_closed(self):
        model = FakeModel([Segment("   ")])
        listener = LocalWhisperMicrophone(
            recorder=lambda *args, **kwargs: [0.0],
            waiter=lambda: None,
            model_factory=lambda *args, **kwargs: model,
            clock=lambda: 1_900_000_000_000_000_000,
        )

        with self.assertRaises(EmptyTranscriptionError):
            listener.transcribe(seconds=1.0)

    def test_capture_duration_is_bounded(self):
        listener = LocalWhisperMicrophone(
            recorder=lambda *args, **kwargs: [0.0],
            waiter=lambda: None,
            model_factory=lambda *args, **kwargs: FakeModel([Segment("fire")]),
        )

        for value in (0.0, 0.24, 30.01, 60.0):
            with self.assertRaises(ValueError):
                listener.transcribe(seconds=value)

    def test_microphone_errors_are_classified_without_authority_effect(self):
        listener = LocalWhisperMicrophone(
            recorder=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("device failed")),
            waiter=lambda: None,
            model_factory=lambda *args, **kwargs: FakeModel([Segment("fire")]),
        )

        with self.assertRaises(MicrophoneUnavailableError):
            listener.transcribe(seconds=1.0)

    def test_cli_prints_transcript_hash_and_authority_none(self):
        observation = LocalTranscription(
            "fire",
            "faster-whisper",
            "base.en",
            16_000,
            3.0,
            1_900_000_000_000_000_000,
        )
        listener = FakeListener(result=observation)
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(["--seconds", "2"], transcriber=listener)

        output = stdout.getvalue()
        self.assertEqual(0, code)
        self.assertEqual([2.0], listener.calls)
        self.assertIn("fire", output)
        self.assertIn(f"observation_hash={observation.observation_hash}", output)
        self.assertIn("authority_effect=none", output)

    def test_cli_returns_nonzero_when_input_is_unavailable(self):
        listener = FakeListener(error=MicrophoneUnavailableError("no microphone"))
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            code = main([], transcriber=listener)

        self.assertEqual(2, code)
        self.assertIn("no microphone", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
