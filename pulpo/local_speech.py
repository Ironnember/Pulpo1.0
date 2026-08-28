"""Host-local speech renderer for sanitized Pulpo voice results.

This module is an untrusted output capability.  It does not perform identity,
authentication, authority evaluation, permit handling, or governed execution.
It invokes a host speech program without a shell and never interpolates spoken
text into executable command strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import platform
import shutil
import subprocess
from typing import Callable


class SpeechUnavailableError(RuntimeError):
    """Raised when the current host has no supported speech renderer."""


@dataclass(frozen=True)
class SpeechInvocation:
    backend: str
    argv: tuple[str, ...]
    environment: dict[str, str] | None = None
    authority_effect: str = field(default="none", init=False)


_WINDOWS_SCRIPT = (
    "$ErrorActionPreference='Stop'; "
    "Add-Type -AssemblyName System.Speech; "
    "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer; "
    "$s.Speak($env:PULPO_TTS_TEXT)"
)


def build_speech_invocation(
    text: str,
    *,
    system_name: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    environment: dict[str, str] | None = None,
) -> SpeechInvocation:
    """Select a native speech backend without treating text as executable input."""

    if not isinstance(text, str) or not text.strip():
        raise ValueError("speech text must be non-empty")
    system = system_name or platform.system()

    if system == "Darwin":
        executable = which("say")
        if executable is None:
            raise SpeechUnavailableError("macOS speech backend 'say' is unavailable")
        return SpeechInvocation("macos-say", (executable, text))

    if system == "Windows":
        executable = which("powershell") or which("pwsh")
        if executable is None:
            raise SpeechUnavailableError("Windows PowerShell speech backend is unavailable")
        env = dict(os.environ if environment is None else environment)
        env["PULPO_TTS_TEXT"] = text
        return SpeechInvocation(
            "windows-system-speech",
            (executable, "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SCRIPT),
            env,
        )

    if system == "Linux":
        for candidate in ("spd-say", "espeak-ng", "espeak"):
            executable = which(candidate)
            if executable is not None:
                return SpeechInvocation(f"linux-{candidate}", (executable, text))
        raise SpeechUnavailableError("no supported Linux speech backend is available")

    raise SpeechUnavailableError(f"unsupported speech host: {system}")


class SystemSpeaker:
    """Speaker adapter that executes only the selected native speech command."""

    authority_effect = "none"

    def __init__(
        self,
        *,
        system_name: str | None = None,
        which: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., object] = subprocess.run,
        environment: dict[str, str] | None = None,
    ) -> None:
        self._system_name = system_name
        self._which = which
        self._runner = runner
        self._environment = environment

    def speak(self, text: str) -> None:
        invocation = build_speech_invocation(
            text,
            system_name=self._system_name,
            which=self._which,
            environment=self._environment,
        )
        kwargs: dict[str, object] = {"check": True}
        if invocation.environment is not None:
            kwargs["env"] = invocation.environment
        self._runner(list(invocation.argv), **kwargs)
