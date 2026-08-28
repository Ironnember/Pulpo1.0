import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.local_speech import (
    SpeechUnavailableError,
    SystemSpeaker,
    build_speech_invocation,
    main,
)
from pulpo.voice import GovernedVoiceInterface, VoiceProfile


class RecordingRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return object()


class RecordingSpeaker:
    def __init__(self):
        self.messages = []

    def speak(self, text):
        self.messages.append(text)


class FailingSpeaker:
    def speak(self, text):
        raise SpeechUnavailableError("no renderer")


class LocalSpeechTests(unittest.TestCase):
    def test_macos_uses_argv_without_shell(self):
        invocation = build_speech_invocation(
            "Target locked.",
            system_name="Darwin",
            which=lambda name: "/usr/bin/say" if name == "say" else None,
        )

        self.assertEqual("macos-say", invocation.backend)
        self.assertEqual(("/usr/bin/say", "Target locked."), invocation.argv)
        self.assertIsNone(invocation.environment)
        self.assertEqual("none", invocation.authority_effect)

    def test_windows_keeps_untrusted_text_out_of_command_string(self):
        text = "hello'; Remove-Item -Recurse C:\\*; '"
        invocation = build_speech_invocation(
            text,
            system_name="Windows",
            which=lambda name: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            if name == "powershell"
            else None,
            environment={"SAFE": "1"},
        )

        self.assertEqual("windows-system-speech", invocation.backend)
        self.assertNotIn(text, " ".join(invocation.argv))
        self.assertEqual(text, invocation.environment["PULPO_TTS_TEXT"])
        self.assertEqual("1", invocation.environment["SAFE"])

    def test_linux_prefers_first_available_supported_backend(self):
        available = {"espeak-ng": "/usr/bin/espeak-ng", "espeak": "/usr/bin/espeak"}
        invocation = build_speech_invocation(
            "Denied.",
            system_name="Linux",
            which=available.get,
        )

        self.assertEqual("linux-espeak-ng", invocation.backend)
        self.assertEqual(("/usr/bin/espeak-ng", "Denied."), invocation.argv)

    def test_missing_or_unsupported_backend_fails_closed(self):
        with self.assertRaises(SpeechUnavailableError):
            build_speech_invocation("Hello", system_name="Linux", which=lambda name: None)
        with self.assertRaises(SpeechUnavailableError):
            build_speech_invocation("Hello", system_name="Plan9", which=lambda name: None)

    def test_system_speaker_passes_no_shell_flag(self):
        runner = RecordingRunner()
        speaker = SystemSpeaker(
            system_name="Darwin",
            which=lambda name: "/usr/bin/say" if name == "say" else None,
            runner=runner,
        )

        speaker.speak("Permit issued.")

        argv, kwargs = runner.calls[0]
        self.assertEqual(["/usr/bin/say", "Permit issued."], argv)
        self.assertEqual({"check": True}, kwargs)
        self.assertNotIn("shell", kwargs)
        self.assertEqual("none", speaker.authority_effect)

    def test_governed_voice_speaks_sanitized_status_not_permit(self):
        runner = RecordingRunner()
        speaker = SystemSpeaker(
            system_name="Darwin",
            which=lambda name: "/usr/bin/say" if name == "say" else None,
            runner=runner,
        )
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"local-speech-test",
            clock=lambda: 1_900_000_000_000_000_000,
        )
        voice = GovernedVoiceInterface(
            kernel,
            VoiceProfile("pulpo-command-v1", "pulpo-01", "concise"),
            speaker=speaker,
        )
        intent = Intent("agent:builder", "write", "repo:README.md", 0, "voice-session")
        locked = voice.lock_target("SPEECH-001", intent)

        result, decision = voice.fire(locked.target)

        spoken = runner.calls[-1][0][-1]
        self.assertEqual(result.message, spoken)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertNotIn(decision.permit, spoken)
        self.assertIn("not yet proven", spoken.lower())

    def test_pulpo_speak_entrypoint_has_safe_default_and_custom_text(self):
        speaker = RecordingSpeaker()

        default_code = main([], speaker=speaker)
        custom_code = main(["Pulpo check."], speaker=speaker)

        self.assertEqual(0, default_code)
        self.assertEqual(0, custom_code)
        self.assertIn("Voice is expression, not authority", speaker.messages[0])
        self.assertEqual("Pulpo check.", speaker.messages[1])

    def test_pulpo_speak_entrypoint_returns_nonzero_when_renderer_is_unavailable(self):
        self.assertEqual(2, main([], speaker=FailingSpeaker()))


if __name__ == "__main__":
    unittest.main()
