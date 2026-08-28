import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.voice import GovernedVoiceInterface, TargetReference, VoiceProfile
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


class RecordingSpeaker:
    def __init__(self):
        self.messages = []

    def speak(self, text):
        self.messages.append(text)


class VoiceContractTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000_000_000_000
        self.profile = VoiceProfile("pulpo-command-v1", "pulpo-01", "concise")
        self.kernel = GovernanceKernel(
            Policy(frozenset({"read", "write"}), 100),
            secret=b"voice-test-secret",
            clock=lambda: self.now,
        )
        self.speaker = RecordingSpeaker()
        self.voice = GovernedVoiceInterface(self.kernel, self.profile, speaker=self.speaker)

    def test_profile_is_expression_only(self):
        friendly = VoiceProfile("pulpo-cuttlefish-v1", "cuttlefish-01", "friendly")

        self.assertEqual("none", self.profile.authority_effect)
        self.assertEqual("none", friendly.authority_effect)
        self.assertNotEqual(self.profile.profile_id, friendly.profile_id)
        self.assertEqual(
            self.kernel.intent_hash(Intent("agent", "read", "repo:a")),
            self.kernel.intent_hash(Intent("agent", "read", "repo:a")),
        )

    def test_lock_speaks_exact_proposal_without_claiming_authority(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")

        result = self.voice.lock_target("VOICE-001", intent)

        self.assertEqual("target_locked", result.code)
        self.assertIsInstance(result.target, TargetReference)
        self.assertEqual("none", result.authority_effect)
        self.assertIn("No authority has been granted", result.message)
        self.assertEqual([result.message], self.speaker.messages)
        self.assertEqual("none", self.kernel.audit[0]["payload"]["authority_effect"])

    def test_fire_returns_permit_separately_and_never_claims_execution(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        locked = self.voice.lock_target("VOICE-002", intent)

        result, decision = self.voice.fire(locked.target)

        self.assertEqual("permit_issued", result.code)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertNotIn("permit", result.__dict__)
        self.assertNotIn(decision.permit, result.message)
        self.assertIn("Execution is not yet proven", result.message)

    def test_fire_mismatch_fails_before_policy_decision(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        locked = self.voice.lock_target("VOICE-003", intent)
        wrong = TargetReference(locked.target.target_id, locked.target.version, "0" * 64)
        decisions_before = sum(record["event"] == "decision" for record in self.kernel.audit)

        result, decision = self.voice.fire(wrong)

        decisions_after = sum(record["event"] == "decision" for record in self.kernel.audit)
        self.assertEqual("target_denied", result.code)
        self.assertIsNone(decision)
        self.assertEqual(decisions_before, decisions_after)

    def test_approval_required_is_not_spoken_as_execution(self):
        verifier = HmacTestVerifier()
        kernel = GovernanceKernel(
            Policy(
                frozenset({"push"}),
                100,
                approval_actions=frozenset({"push"}),
                authority_trust=trust_for(verifier),
            ),
            secret=b"voice-approval-secret",
            approval_verifier=verifier,
            clock=lambda: self.now,
        )
        voice = GovernedVoiceInterface(kernel, self.profile)
        intent = Intent("agent:builder", "push", "repo:main", 0, "voice-session")
        locked = voice.lock_target("VOICE-004", intent)

        result, decision = voice.fire(locked.target)

        self.assertEqual("approval_required", result.code)
        self.assertEqual("require_approval", decision.outcome)
        self.assertIn("Nothing has executed", result.message)
        self.assertIsNone(decision.permit)

    def test_exact_approval_can_issue_permit_but_voice_still_does_not_claim_completion(self):
        verifier = HmacTestVerifier()
        kernel = GovernanceKernel(
            Policy(
                frozenset({"push"}),
                100,
                approval_actions=frozenset({"push"}),
                authority_trust=trust_for(verifier),
            ),
            secret=b"voice-approval-secret",
            approval_verifier=verifier,
            clock=lambda: self.now,
        )
        speaker = RecordingSpeaker()
        voice = GovernedVoiceInterface(kernel, self.profile, speaker=speaker)
        intent = Intent("agent:builder", "push", "repo:main", 0, "voice-session")
        locked = voice.lock_target("VOICE-005", intent)
        envelope = signed_envelope(kernel, intent, verifier, now_ns=self.now)

        result, decision = voice.fire(locked.target, approval=envelope)

        self.assertEqual("permit_issued", result.code)
        self.assertEqual("allow", decision.outcome)
        self.assertNotIn(decision.permit, result.message)
        self.assertNotIn("complete", result.message.lower())
        self.assertNotIn("executed", result.message.lower())
        self.assertIn("not yet proven", result.message.lower())
        self.assertEqual(result.message, speaker.messages[-1])

    def test_voice_profile_cannot_change_policy_outcome(self):
        intent = Intent("agent:builder", "delete", "repo:README.md", 0, "voice-session")
        command = GovernedVoiceInterface(
            self.kernel,
            VoiceProfile("pulpo-command-v1", "pulpo-01", "concise"),
        )
        friendly = GovernedVoiceInterface(
            self.kernel,
            VoiceProfile("pulpo-cuttlefish-v1", "cuttlefish-01", "friendly"),
        )
        locked = command.lock_target("VOICE-006", intent)

        command_result, command_decision = command.fire(locked.target)
        friendly_result, friendly_decision = friendly.fire(locked.target)

        self.assertEqual("governance_denied", command_result.code)
        self.assertEqual("governance_denied", friendly_result.code)
        self.assertEqual("action_not_allowed", command_decision.reason)
        self.assertEqual(command_decision.reason, friendly_decision.reason)


if __name__ == "__main__":
    unittest.main()
