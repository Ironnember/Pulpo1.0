import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pulpo.local_listen import EmptyTranscriptionError, LocalTranscription
from pulpo.voice_demo import main, run_demo


class SequenceTranscriber:
    def __init__(self, phrases):
        self.phrases = iter(phrases)
        self.sequence = 0

    def transcribe(self, *, seconds=3.0):
        self.sequence += 1
        phrase = next(self.phrases)
        if isinstance(phrase, Exception):
            raise phrase
        return LocalTranscription(
            phrase,
            "faster-whisper",
            "base.en",
            16_000,
            seconds,
            1_900_000_000_000_000_000 + self.sequence,
        )


class RecordingSpeaker:
    authority_effect = "none"

    def __init__(self):
        self.messages = []

    def speak(self, text):
        self.messages.append(text)


class VoiceDemoTests(unittest.TestCase):
    def test_lock_then_fire_produces_real_governance_decision_without_execution_claim(self):
        transcriber = SequenceTranscriber(["Lock target.", "Fire."])
        speaker = RecordingSpeaker()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = run_demo(
                transcriber=transcriber,
                speaker=speaker,
                seconds=1.0,
                clock=lambda: 1_900_000_000_000_000_000,
            )

        output = stdout.getvalue()
        self.assertEqual(0, code)
        self.assertIn("heard=Lock target.", output)
        self.assertIn("heard=Fire.", output)
        self.assertIn("decision=allow", output)
        self.assertIn("execution=not_performed", output)
        self.assertTrue(any("No authority has been granted" in item for item in speaker.messages))
        self.assertTrue(any("Execution is not yet proven" in item for item in speaker.messages))
        self.assertTrue(any(item == "Listening. Say lock target." for item in speaker.messages))
        self.assertTrue(any(item == "Listening. Say fire, or cancel target." for item in speaker.messages))
        self.assertFalse(any(":permit:" in item for item in speaker.messages))

    def test_single_empty_capture_retries_without_consuming_governance_turn(self):
        transcriber = SequenceTranscriber(
            [
                EmptyTranscriptionError("no speech was transcribed"),
                "lock target",
                EmptyTranscriptionError("no speech was transcribed"),
                "fire",
            ]
        )
        speaker = RecordingSpeaker()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = run_demo(
                transcriber=transcriber,
                speaker=speaker,
                seconds=1.0,
                max_turns=2,
                max_empty_retries=2,
                clock=lambda: 1_900_000_000_000_000_000,
            )

        output = stdout.getvalue()
        self.assertEqual(0, code)
        self.assertEqual(2, output.count("input_result=no_speech"))
        self.assertIn("input_result=target_locked", output)
        self.assertIn("decision=allow", output)
        self.assertIn("execution=not_performed", output)
        self.assertTrue(any("I did not catch speech" in item for item in speaker.messages))

    def test_repeated_empty_capture_fails_closed_without_governance(self):
        transcriber = SequenceTranscriber(
            [
                EmptyTranscriptionError("no speech was transcribed"),
                EmptyTranscriptionError("no speech was transcribed"),
                EmptyTranscriptionError("no speech was transcribed"),
            ]
        )
        speaker = RecordingSpeaker()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = run_demo(
                transcriber=transcriber,
                speaker=speaker,
                seconds=1.0,
                max_turns=2,
                max_empty_retries=2,
                clock=lambda: 1_900_000_000_000_000_000,
            )

        output = stdout.getvalue()
        self.assertEqual(2, code)
        self.assertIn("demo_result=input_unavailable", output)
        self.assertNotIn("decision=", output)
        self.assertTrue(any("retry limit" in item for item in speaker.messages))

    def test_negated_fire_does_not_reach_governance(self):
        transcriber = SequenceTranscriber(["lock target", "don't fire", "cancel target"])
        speaker = RecordingSpeaker()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = run_demo(
                transcriber=transcriber,
                speaker=speaker,
                seconds=1.0,
                clock=lambda: 1_900_000_000_000_000_000,
            )

        output = stdout.getvalue()
        self.assertEqual(0, code)
        self.assertIn("input_result=non_command_speech", output)
        self.assertIn("demo_result=cancelled", output)
        self.assertNotIn("decision=allow", output)
        self.assertTrue(any("not an exact Pulpo control command" in item for item in speaker.messages))

    def test_turn_limit_fails_closed_without_governance_action(self):
        transcriber = SequenceTranscriber(["hello", "still talking"])
        speaker = RecordingSpeaker()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = run_demo(
                transcriber=transcriber,
                speaker=speaker,
                seconds=1.0,
                max_turns=2,
                clock=lambda: 1_900_000_000_000_000_000,
            )

        output = stdout.getvalue()
        self.assertEqual(4, code)
        self.assertIn("demo_result=turn_limit", output)
        self.assertNotIn("decision=", output)
        self.assertTrue(any("Turn limit reached" in item for item in speaker.messages))

    def test_cli_rejects_nonpositive_turn_limit_before_audio(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["--max-turns", "0"], transcriber=SequenceTranscriber([]), speaker=RecordingSpeaker())

        self.assertEqual(2, code)
        self.assertIn("max-turns must be positive", stderr.getvalue())

    def test_cli_rejects_negative_empty_retry_limit_before_audio(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["--empty-retries", "-1"], transcriber=SequenceTranscriber([]), speaker=RecordingSpeaker())

        self.assertEqual(2, code)
        self.assertIn("empty-retries must be non-negative", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
