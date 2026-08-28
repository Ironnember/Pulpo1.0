# Voice V0 Governed Interface Contract

Status: proposed; stacked on Target Lock V0 and noncanonical until reviewed and merged
Branch: `feature/voice-contract-v0`
Dependency: `feature/target-lock-v0` / PR #55

## Purpose

Give Pulpo a conversational expression surface without allowing voice, personality, familiarity, or model-generated workflow language to become identity, authority, execution proof, or outcome evidence.

Voice V0 is intentionally split into two concerns:

1. **governed interface semantics**, implemented and testable without audio hardware;
2. **local speech input/output adapters**, still unimplemented and requiring host-level proof.

This PR addresses only the first concern.

## Core invariants

`VOICE != IDENTITY != AUTHORITY`

`PERSONALITY != AUTHORITY`

`RELATIONSHIP != AUTHORITY`

`"FIRE" != PERMIT`

`PERMIT_ISSUED != EXECUTED`

`MODEL_ASSERTION != GOVERNED_STATE`

A voice profile can affect wording or rendering preferences. It cannot change an intent hash, policy, authority trust, target hash, decision, permit scope, or evidence result.

## Components

### `VoiceProfile`

A versioned expression profile with `authority_effect: none` fixed by construction. It contains display/speech preferences only.

### `TargetReference`

An exact reference to an already locked target:

- target ID;
- version;
- target hash;
- `authority_effect: none`.

It does not contain a permit or approval.

### `VoiceResult`

A sanitized status object suitable for speech output. It intentionally contains no permit.

### `GovernedVoiceInterface`

A thin adapter over the existing target and governance paths:

```text
voice/model proposes structured intent
        |
        v
lock_target(...)
        |
        | exact TargetReference
        v
human/interface says "fire"
        |
        | interface supplies the exact TargetReference
        v
resolve exact target
        |
        +-- mismatch -> deny
        |
        v
existing GovernanceKernel path
        |
        +-- deny
        +-- require_approval
        +-- allow -> Decision contains one-use permit
```

For approval-gated work, Voice V0 uses the exact-target approval adapter from PR #55, which delegates the unchanged locked intent to `GovernanceKernel.evaluate_with_approval()`.

The voice layer never consumes the permit or executes a side effect.

## Spoken-state discipline

Voice V0 may say:

- `Target locked as an exact proposal. No authority has been granted.`
- `Approval is required for the exact target. Nothing has executed.`
- `Permit issued for the exact target. Execution is not yet proven.`
- `Denied by governance: <reason>.`

Voice V0 may **not** infer or announce:

- `executed` from `allow`;
- `complete` from permit issuance;
- `verified` from executor self-report;
- identity from a voice profile;
- authority from a transcript, wake word, relationship, confidence, or repeated prior approval.

Completion language belongs after evidence and reconciliation, not inside this permit-request adapter.

## Success evidence required

Focused tests must prove:

1. voice profiles have fixed `authority_effect: none`;
2. `lock_target` returns an exact target reference and explicitly reports that authority has not been granted;
3. an allowed `fire` returns the governance `Decision` separately from sanitized speech and the spoken result contains no permit;
4. permit issuance is spoken as `execution is not yet proven`, not completion;
5. target mismatch stops before policy evaluation;
6. approval-required state is not spoken as execution;
7. exact approved targets can receive the existing kernel permit without exposing the permit in speech;
8. changing voice/personality profile cannot change a policy denial.

The inherited Target Lock tests and all repository CI suites must remain green on the same commit.

## Boundary not proved

This contract does **not** prove:

- microphone capture;
- speech-to-text accuracy;
- wake-word handling;
- text-to-speech rendering;
- a persistent local voice configuration file;
- speaker recognition;
- voice authentication;
- independently deployed human authority;
- permit delivery to a real executor;
- an external side effect;
- evidence collection or reconciliation;
- restart continuity for interface-only session state;
- production readiness.

Those require separate host-level or external proofs.

## Local implementation direction

After this contract is verified, the next host proof should inject local adapters around it rather than change governance:

```text
microphone -> STT -> intelligence/parser -> Voice V0 contract
                                         -> Pulpo governance
Pulpo status -> TTS -> speaker
```

STT and TTS remain untrusted capability surfaces. A transcript may propose a target reference or approval request, but it cannot manufacture authority.

## Claim classification

Until CI passes on this branch:

- Voice V0 contract implementation: **Recorded**;
- runtime behavior: **Unknown**;
- audio I/O: **Not implemented**;
- production voice identity/authentication: **Blocked / not claimed**.

After passing tests, only the contract semantics exercised by those tests may be classified **Verified** for the exact branch commit.
