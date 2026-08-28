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
9. permit issuance remains rendered as `not yet proven` rather than execution or completion.

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

A local machine must execute a separate host proof before Pulpo may claim audible speech on that platform.

## Claim classification

Until CI passes:

- renderer implementation: **Recorded**;
- command construction semantics: **Unknown**;
- real audible host speech: **Unproven**.

After passing CI, tested command-selection and injection-safety semantics may be **Verified** for the exact branch commit. Audible local speech remains **Unknown** until exercised on a real host.
