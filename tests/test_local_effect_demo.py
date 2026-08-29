import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from pulpo.local_effect import LocalEffectViolation, LocalFileExecutor
from pulpo.local_effect_demo import run_effect_demo
from pulpo.local_listen import EmptyTranscriptionError, LocalTranscription


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


class FailingExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, *args, **kwargs):
        self.calls += 1
        raise LocalEffectViolation("simulated_failure_after_permit")


class TamperingExecutor:
    def __init__(self, root, now):
        self.root = Path(root)
        self.delegate = LocalFileExecutor(clock=lambda: now + 1)

    def execute(self, kernel, effect, permit, *, root):
        execution = self.delegate.execute(kernel, effect, permit, root=root)
        (self.root / effect.relative_path).write_text("tampered before observation\n")
        return execution


class LocalEffectDemoTests(unittest.TestCase):
    now = 1_900_000_000_000_000_000
    effect_id = "0123456789abcdef"

    def _checkout(self, directory):
        root = Path(directory)
        (root / ".git").mkdir()
        (root / "pyproject.toml").write_text('[project]\nname = "pulpo"\n')
        return root

    def test_lock_fire_executes_once_observes_and_speaks_verified_only_after_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._checkout(directory)
            speaker = RecordingSpeaker()
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = run_effect_demo(
                    transcriber=SequenceTranscriber(["Lock target.", "Fire."]),
                    speaker=speaker,
                    root=root,
                    effect_id=self.effect_id,
                    seconds=1.0,
                    clock=lambda: self.now,
                    executor=LocalFileExecutor(clock=lambda: self.now + 1),
                )

            output = stdout.getvalue()
            target = root / f".pulpo-effect-v0-{self.effect_id}.txt"
            self.assertEqual(0, code)
            self.assertTrue(target.is_file())
            self.assertEqual(
                f"Pulpo verified local effect {self.effect_id}\n",
                target.read_text(),
            )
            self.assertIn("heard=Lock target.", output)
            self.assertIn("input_result=target_locked", output)
            self.assertIn("heard=Fire.", output)
            self.assertIn("input_result=governance_requested", output)
            self.assertIn("decision=allow", output)
            self.assertIn("execution=performed", output)
            self.assertIn("reconciliation=verified", output)
            self.assertIn("reconciliation_reason=effect_verified", output)
            self.assertIn("permit_replay=rejected", output)
            self.assertIn("proof_bundle_hash=", output)
            self.assertTrue(any("Execution is not yet proven" in item for item in speaker.messages))
            self.assertTrue(any(item.startswith("Execution verified.") for item in speaker.messages))
            self.assertFalse(any(":permit:" in item for item in speaker.messages))

    def test_negated_fire_never_executes_and_cancel_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._checkout(directory)
            speaker = RecordingSpeaker()
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = run_effect_demo(
                    transcriber=SequenceTranscriber(
                        ["lock target", "don't fire", "cancel target"]
                    ),
                    speaker=speaker,
                    root=root,
                    effect_id=self.effect_id,
                    seconds=1.0,
                    clock=lambda: self.now,
                )

            output = stdout.getvalue()
            target = root / f".pulpo-effect-v0-{self.effect_id}.txt"
            self.assertEqual(0, code)
            self.assertFalse(target.exists())
            self.assertIn("input_result=non_command_speech", output)
            self.assertIn("execution=not_performed", output)
            self.assertIn("demo_result=cancelled", output)
            self.assertNotIn("decision=allow", output)
            self.assertFalse(any(item.startswith("Execution verified.") for item in speaker.messages))

    def test_empty_capture_can_retry_before_exact_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._checkout(directory)
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = run_effect_demo(
                    transcriber=SequenceTranscriber(
                        [
                            EmptyTranscriptionError("no speech"),
                            "lock target",
                            EmptyTranscriptionError("no speech"),
                            "fire",
                        ]
                    ),
                    speaker=RecordingSpeaker(),
                    root=root,
                    effect_id=self.effect_id,
                    seconds=1.0,
                    max_turns=2,
                    max_empty_retries=2,
                    clock=lambda: self.now,
                    executor=LocalFileExecutor(clock=lambda: self.now + 1),
                )

            self.assertEqual(0, code)
            self.assertEqual(2, stdout.getvalue().count("input_result=no_speech"))

    def test_execution_failure_after_allow_is_not_auto_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._checkout(directory)
            failing = FailingExecutor()
            speaker = RecordingSpeaker()
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = run_effect_demo(
                    transcriber=SequenceTranscriber(["lock target", "fire"]),
                    speaker=speaker,
                    root=root,
                    effect_id=self.effect_id,
                    seconds=1.0,
                    clock=lambda: self.now,
                    executor=failing,
                )

            output = stdout.getvalue()
            self.assertEqual(5, code)
            self.assertEqual(1, failing.calls)
            self.assertIn("decision=allow", output)
            self.assertIn("execution=not_verified", output)
            self.assertIn("simulated_failure_after_permit", output)
            self.assertTrue(any("No automatic retry" in item for item in speaker.messages))
            self.assertFalse(any(item.startswith("Execution verified.") for item in speaker.messages))

    def test_tampered_consequence_is_reported_as_mismatch_not_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._checkout(directory)
            speaker = RecordingSpeaker()
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = run_effect_demo(
                    transcriber=SequenceTranscriber(["lock target", "fire"]),
                    speaker=speaker,
                    root=root,
                    effect_id=self.effect_id,
                    seconds=1.0,
                    clock=lambda: self.now,
                    executor=TamperingExecutor(root, self.now),
                )

            output = stdout.getvalue()
            self.assertEqual(5, code)
            self.assertIn("execution=performed", output)
            self.assertIn("reconciliation=mismatch", output)
            self.assertIn("reconciliation_reason=observed_content_mismatch", output)
            self.assertIn("permit_replay=rejected", output)
            self.assertFalse(any(item.startswith("Execution verified.") for item in speaker.messages))
            self.assertTrue(any("did not verify exactly" in item for item in speaker.messages))

    def test_requires_current_directory_to_be_a_pulpo_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(LocalEffectViolation, "pulpo_checkout_required"):
                run_effect_demo(
                    transcriber=SequenceTranscriber([]),
                    speaker=RecordingSpeaker(),
                    root=directory,
                    effect_id=self.effect_id,
                    clock=lambda: self.now,
                )


if __name__ == "__main__":
    unittest.main()
