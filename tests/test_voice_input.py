import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.voice import GovernedVoiceInterface, VoiceProfile
from pulpo.voice_input import TranscriptArtifact, VoiceCommandSession


class VoiceInputTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000_000_000_000
        self.kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"voice-input-test",
            clock=lambda: self.now,
        )
        self.voice = GovernedVoiceInterface(
            self.kernel,
            VoiceProfile("pulpo-command-v1", "pulpo-01", "concise"),
        )
        self.session = VoiceCommandSession(self.voice, clock=lambda: self.now)
        self.intent = Intent("agent:builder", "write", "repo:README.md", 0, "voice-session")

    def test_lock_target_requires_staged_exact_proposal(self):
        transcript = self.session.capture("lock target")

        result, voice_result, decision = self.session.handle(transcript)

        self.assertEqual("nothing_staged", result.code)
        self.assertIsNone(voice_result)
        self.assertIsNone(decision)
        self.assertIsNone(self.session.active_target)
        self.assertEqual([], self.kernel.audit)

    def test_lock_target_creates_durable_exact_target_but_no_authority(self):
        self.session.stage("VOICE-001", self.intent)
        transcript = self.session.capture("  LOCK   TARGET  ")

        result, voice_result, decision = self.session.handle(transcript)

        self.assertEqual("target_locked", result.code)
        self.assertEqual("target_locked", voice_result.code)
        self.assertIsNone(decision)
        self.assertIsNotNone(self.session.active_target)
        self.assertEqual("none", result.authority_effect)
        self.assertEqual(["target_locked"], [record["event"] for record in self.kernel.audit])

    def test_fire_without_exact_active_target_fails_closed(self):
        transcript = self.session.capture("fire")

        result, voice_result, decision = self.session.handle(transcript)

        self.assertEqual("no_active_target", result.code)
        self.assertIsNone(voice_result)
        self.assertIsNone(decision)
        self.assertEqual([], self.kernel.audit)

    def test_only_exact_control_phrase_can_fire(self):
        self.session.stage("VOICE-002", self.intent)
        self.session.handle(self.session.capture("lock target"))
        decisions_before = sum(record["event"] == "decision" for record in self.kernel.audit)

        for phrase in (
            "don't fire",
            "do not fire",
            "fire target",
            "please fire",
            "fire now",
            "we should fire",
            "not fire",
        ):
            result, voice_result, decision = self.session.handle(self.session.capture(phrase))
            self.assertEqual("non_command_speech", result.code, phrase)
            self.assertIsNone(voice_result, phrase)
            self.assertIsNone(decision, phrase)

        decisions_after = sum(record["event"] == "decision" for record in self.kernel.audit)
        self.assertEqual(decisions_before, decisions_after)
        self.assertIsNotNone(self.session.active_target)

    def test_exact_fire_submits_locked_target_once(self):
        self.session.stage("VOICE-003", self.intent)
        self.session.handle(self.session.capture("lock target"))

        result, voice_result, decision = self.session.handle(self.session.capture("fire"))

        self.assertEqual("governance_requested", result.code)
        self.assertEqual("permit_issued", voice_result.code)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertIn("not yet proven", voice_result.message.lower())
        self.assertIsNone(self.session.active_target)

    def test_handling_same_transcript_artifact_twice_does_not_repeat_governance(self):
        self.session.stage("VOICE-004", self.intent)
        self.session.handle(self.session.capture("lock target"))
        transcript = self.session.capture("fire")

        first_result, _, first_decision = self.session.handle(transcript)
        permits_after_first = sum(record["event"] == "permit_issued" for record in self.kernel.audit)
        second_result, second_voice, second_decision = self.session.handle(transcript)
        permits_after_second = sum(record["event"] == "permit_issued" for record in self.kernel.audit)

        self.assertEqual("governance_requested", first_result.code)
        self.assertEqual("allow", first_decision.outcome)
        self.assertEqual("transcript_replay", second_result.code)
        self.assertIsNone(second_voice)
        self.assertIsNone(second_decision)
        self.assertEqual(permits_after_first, permits_after_second)

    def test_cancel_clears_convenience_state_without_authority_change(self):
        self.session.stage("VOICE-005", self.intent)
        self.session.handle(self.session.capture("lock target"))
        audit_before = list(self.kernel.audit)

        result, voice_result, decision = self.session.handle(self.session.capture("cancel target"))

        self.assertEqual("target_cancelled", result.code)
        self.assertIsNone(voice_result)
        self.assertIsNone(decision)
        self.assertIsNone(self.session.staged_target)
        self.assertIsNone(self.session.active_target)
        self.assertEqual(audit_before, self.kernel.audit)

    def test_transcript_hash_binds_text_source_time_and_sequence(self):
        first = TranscriptArtifact("fire", "untrusted-local-stt", self.now, 1)
        same = TranscriptArtifact("fire", "untrusted-local-stt", self.now, 1)
        different = TranscriptArtifact("fire", "untrusted-local-stt", self.now, 2)

        self.assertEqual(first.transcript_hash, same.transcript_hash)
        self.assertNotEqual(first.transcript_hash, different.transcript_hash)
        self.assertEqual("none", first.authority_effect)

    def test_session_restart_does_not_guess_active_target(self):
        self.session.stage("VOICE-006", self.intent)
        self.session.handle(self.session.capture("lock target"))
        self.assertIsNotNone(self.session.active_target)

        restarted = VoiceCommandSession(self.voice, clock=lambda: self.now + 1)
        result, voice_result, decision = restarted.handle(restarted.capture("fire"))

        self.assertEqual("no_active_target", result.code)
        self.assertIsNone(voice_result)
        self.assertIsNone(decision)


if __name__ == "__main__":
    unittest.main()
