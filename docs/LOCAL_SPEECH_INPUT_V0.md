# Local Speech Input V0

Status: proposed; stacked and noncanonical until reviewed and merged
Branch: `feature/local-speech-input-v0`
Dependency: `feature/local-speech-output-v0` / PR #58

## Purpose

Close the local conversational loop without turning microphone audio, speech recognition, a transcript, a voice match, or conversational familiarity into identity or authority.

The target lifecycle is:

```text
human speech
    |
    v
microphone capture
    |
    v
local Whisper transcription
    |
    | untrusted transcript observation
    v
exact control grammar
    |
    +-- non-exact phrase -> no governance action
    |
    v
exact target reference
    |
    v
Pulpo governance
    |
    +-- deny
    +-- require approval
    +-- allow -> one-use permit
    |
    v
sanitized spoken status
```

The input layer never grants authority and the demo contains no executor.

## Invariants

`SPEECH_INPUT != IDENTITY`

`TRANSCRIPT != AUTHORITY`

`VOICE_MATCH != AUTHENTICATION`

`"FIRE" != PERMIT`

`PERMIT_ISSUED != EXECUTED`

`MODEL_ASSERTION != GOVERNED_STATE`

The local speech recognizer is an untrusted capability surface. Its output can request a governance operation only after matching a deliberately small exact control grammar.

## Transcript evidence

`LocalWhisperMicrophone` records a bounded fixed-duration utterance and transcribes it using the optional local `faster-whisper` adapter.

The resulting `LocalTranscription` records:

- transcript text;
- recognizer backend;
- model name;
- sample rate;
- requested capture duration;
- capture timestamp;
- deterministic observation hash;
- `authority_effect: none`.

The observation hash proves only which metadata/text object Pulpo saw. It does not prove speaker identity, acoustic accuracy, or human intent.

`TranscriptArtifact` separately binds the text, transcript source, capture time, and session sequence. Reusing the exact same artifact is detected and cannot repeat governance.

## Exact command grammar

Voice V0 recognizes only these controls:

```text
lock target
fire
cancel target
```

Normalization is intentionally narrow:

- case is normalized;
- repeated whitespace is collapsed;
- sentence-final `.`, `!`, and `?` are removed because STT commonly adds them.

Words are never inferred, deleted, substituted, or approximately matched.

Therefore examples such as these are non-commands:

```text
don't fire
do not fire
please fire
fire now
fire target
we should fire
```

A non-command transcript performs no policy/approval evaluation and cannot issue a permit.

## Session state

The Voice V0 command session maintains staged and active target references as convenience state only.

Restart intentionally loses that convenience state. A post-restart `fire` therefore fails closed with no active exact target rather than guessing conversational continuity.

The durable target itself remains governed by the Target Lock contract; the voice session does not create a second ledger.

## Optional local dependencies

The governance kernel remains importable and testable without speech packages. Local microphone transcription is installed separately:

```text
pip install -e ".[authority,voice]"
```

The `voice` extra currently provides:

- `sounddevice` for host microphone capture;
- `faster-whisper` for local transcription.

The Whisper model may need to be downloaded on first use. After the model is available locally, transcription runs through the local recognizer. Model acquisition is a capability/dependency operation, not an authority operation.

A functioning host audio-input device and driver are still required. Some Linux environments may require the system PortAudio runtime in addition to the Python package.

## Host commands

### 1. Microphone -> transcript proof

```text
pulpo-listen
```

Default capture duration is three seconds and default model is `base.en`.

For a shorter test:

```text
pulpo-listen --seconds 2
```

Success prints the transcript, an observation hash, and:

```text
authority_effect=none
```

A successful command does not prove transcription accuracy. The human operator must compare the spoken phrase with the observed transcript.

### 2. Safe bidirectional governed voice proof

```text
pulpo-voice-demo
```

The demo stages one fixed harmless intent:

```text
principal: human:local-demo
action: read
resource: demo:voice-loop
cost: 0
session: local-voice-demo
```

It deliberately attaches no executor.

Expected interaction:

```text
Pulpo: A harmless read target is staged. Say lock target.
Human: Lock target.
Pulpo: Target locked as an exact proposal. No authority has been granted.
Human: Fire.
Pulpo: Permit issued for the exact target. Execution is not yet proven.
```

The terminal output records:

```text
decision=allow
execution=not_performed
```

The permit is not spoken or printed.

This is a real governance decision over the exact target, but it is intentionally not a real-world side effect.

## Success evidence required

CI must prove:

1. transcript observations have `authority_effect: none`;
2. capture duration is bounded;
3. empty transcription fails closed;
4. microphone/STT errors fail closed;
5. optional dependencies remain lazy and do not burden the base kernel;
6. `lock target` requires a staged exact proposal;
7. `fire` with no active target performs no governance operation;
8. negated, polite, extended, or approximate fire phrases perform no governance operation;
9. terminal STT punctuation may normalize without semantic rewriting;
10. exact `fire` delegates to the existing target/kernel path;
11. the same transcript artifact cannot repeat governance;
12. terminal governance results clear the active convenience target;
13. restart does not guess conversational target state;
14. the safe local demo may issue a permit but never claims or performs execution;
15. the demo never speaks or prints a permit;
16. all inherited governance, authority, and authority-service tests remain green.

## Boundary not proved by CI

CI cannot establish:

- that a real host microphone captures audio;
- that a specific speaker was the person who spoke;
- that Whisper transcribes a particular speaker accurately;
- that sound was audibly rendered on a real host;
- persistent voice/session preference across restart;
- speaker authentication;
- independent production human authority;
- external execution;
- external evidence/reconciliation;
- production readiness.

Those claims require separate host or production evidence.

## Claim classification

Until CI passes on the exact branch head:

- implementation: **Recorded**;
- transcript/grammar/runtime semantics: **Unknown**;
- real microphone transcription on the operator's host: **Unknown**;
- two-way local governed conversation on the operator's host: **Unknown**.

After CI passes, only the exercised software semantics may be promoted to **Verified** for that exact commit. Real audio input remains a host proof requiring operator observation.
