# Local Speech Output V0

Status: proposed; stacked on Voice V0 and noncanonical until reviewed and merged
Branch: `feature/local-speech-output-v0`
Dependency: `feature/voice-contract-v0` / PR #57

## Purpose

Render Pulpo's sanitized voice-status messages through a host-local speech backend without turning the renderer, spoken text, voice choice, or operating system into identity or authority.

This proof addresses **speech output only**. Microphone capture and speech-to-text remain separate work.

## Invariants

`SPEECH_OUTPUT != AUTHORITY`

`VOICE != IDENTITY`

`SPOKEN_PERMIT_STATUS != EXECUTION_PROOF`

`RENDERER != GOVERNANCE`

The renderer receives text that has already been sanitized by the Voice V0 contract. It does not receive or evaluate an `Intent`, approval envelope, policy, permit, authority credential, or reconciliation record.

## Host selection

`SystemSpeaker` detects or is configured for the host family and selects a native backend:

- macOS: `say`;
- Windows: PowerShell plus `System.Speech`;
- Linux: `spd-say`, then `espeak-ng`, then `espeak`.

If no supported backend is available, speech fails closed with `SpeechUnavailableError`.

## Command-injection boundary

The adapter never invokes a shell.

On macOS and Linux, spoken text is passed as a separate argv element.

On Windows, the PowerShell program is a fixed command string and spoken text is passed through the `PULPO_TTS_TEXT` environment variable. Untrusted spoken content is not interpolated into the executable command.

This is an execution-safety property for the renderer. It is not an authentication or authority mechanism.

## One-command host proof

The package exposes an installed command:

```text
pulpo-speak
```

Its default phrase is:

> Pulpo local speech output is online. Voice is expression, not authority.

A custom sanitized phrase can also be supplied as the single positional argument.

The command returns nonzero if no supported renderer exists or the renderer fails. A successful process exit proves only that the selected host speech command returned successfully. The human operator must still confirm that audio was actually audible before recording an audible-speech success claim.

## Success evidence required

Tests must prove:

1. macOS uses an argv-based `say` invocation;
2. Windows keeps adversarial text out of the PowerShell command string;
3. Linux selects the first available supported renderer;
4. unsupported or missing renderers fail closed;
5. `SystemSpeaker` calls its runner without `shell=True`;
6. the speech adapter has `authority_effect: none`;
7. integration with `GovernedVoiceInterface` speaks the sanitized status only;
8. a real kernel permit is never inserted into spoken output;
9. permit issuance remains rendered as `not yet proven` rather than execution or completion;
10. the `pulpo-speak` entrypoint has a safe default phrase, accepts a custom phrase, and returns nonzero when speech is unavailable.

The full inherited CI suites must remain green at the same commit.

## Boundary not proved

This proof does **not** establish:

- that a CI runner contains or successfully plays audio through these host programs;
- microphone capture;
- speech-to-text;
- transcription accuracy;
- wake-word handling;
- persistent voice preferences;
- speaker recognition or voice authentication;
- independently deployed human authority;
- real governed execution;
- evidence/reconciliation of an external consequence.

A local machine must execute `pulpo-speak` and a human must confirm audible output before Pulpo may claim real local speech on that platform.

## Claim classification

Until CI passes:

- renderer implementation: **Recorded**;
- command construction and CLI semantics: **Unknown**;
- real audible host speech: **Unproven**.

After passing CI, tested command-selection, injection-safety, and CLI semantics may be **Verified** for the exact branch commit. Audible local speech remains **Unknown** until exercised on a real host.
