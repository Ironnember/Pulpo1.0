# Pulpo Operator iOS v0

`authority_effect=none`

Pulpo Operator is a native SwiftUI control surface for reviewing and opening the existing Pulpo human approval ceremony from an iPhone. It is intentionally not an authority service, executor, policy engine, provider client, credential store, or canonical state backend.

## Boundary

The app accepts only approval URLs with this exact shape:

`https://authority.pulpo.ai/human/approval/<request_id>`

It does not call the worker `/v1` endpoints and stores no provider credentials, governance signing keys, policy state, executor capability, or canonical Pulpo state.

A button tap in the app grants no authority. The server-hosted approval ceremony remains responsible for the WebAuthn assertion and approval decision.

## Status semantics

- `PENDING`: a syntactically valid Pulpo approval URL has been loaded and the local app has not yet handed it to the approval ceremony.
- `APPROVED`: reserved for future authenticated authority evidence. v0 never sets this state locally.
- `UNKNOWN`: the approval ceremony was opened and then dismissed without authenticated readback. v0 intentionally refuses to infer success and does not offer a blind retry from this state.

`BROWSER_DISMISSED != APPROVED`

## Build locally

1. Open `PulpoOperator.xcodeproj` in Xcode.
2. Select the `PulpoOperator` target.
3. For Simulator builds, no signing team is required.
4. For installation on a physical iPhone, select your Apple Developer Team under Signing & Capabilities and use a bundle identifier available to that team.
5. Build and run on an iPhone or simulator running iOS 17 or later.

No Apple account, signing identity, TestFlight app, deployment, or App Store record is created by this scaffold.

## TestFlight preparation

When separately authorized, the next distribution step is to choose the production bundle identifier, configure the Apple Developer team, archive the exact reviewed app head, and upload that archive to TestFlight. That transition is outside this v0 change.

## Current integration limit

The existing authority service exposes a same-origin WebAuthn approval ceremony. This app opens that exact surface in `SFSafariViewController` so the authority service retains verification responsibility.

The current authority API does not expose a mobile read-only endpoint that lets this app independently learn whether the ceremony ended in approval. Until such evidence is legitimately added, v0 moves from `PENDING` to `UNKNOWN` when the ceremony is dismissed rather than manufacturing `APPROVED`.

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
