# Authority Human Flow V0

Status: proposed; noncanonical until reviewed and merged.

## Purpose

Apply the useful interaction lesson from `DMJ786/Elyxer_Flutter` to Pulpo's existing same-origin WebAuthn approval ceremony without importing that application's identity model, backend assumptions, or authority semantics.

The lesson is progressive human verification: show the operator where they are in the trust ceremony, make the exact consequential object legible, and separate review from cryptographic approval.

## Constitutional boundary

`HUMAN-FRIENDLY UX != AUTHORITY`

`OTP != AUTHORITY`

`VERIFIED EMAIL != CONSEQUENTIAL AUTHORITY`

`BIOMETRIC UX != AUTHORITY`

`CLICK != PERMIT`

The existing Pulpo authority service remains the only component that verifies the WebAuthn assertion and releases an approval envelope. This change must not add email OTP, SMS OTP, password login, social login, biometric identity claims, enrollment, recovery, rotation, revocation, or a second approval path.

## Frozen interaction contract

The human ceremony has three visible stages:

1. **Request received** — identify the request as pending, approved, expired, denied, or unavailable.
2. **Review exact consequence** — present principal, action, resource, cost, session, intent hash, policy hash, deployment, and expiry as immutable escaped text.
3. **Verify and approve** — invoke only the existing same-origin WebAuthn challenge/assertion route with `userVerification=required` and an approved hardware authenticator.

The UI may improve hierarchy, readability, responsive layout, progress indication, and status feedback. It may not change the authority decision, hide consequential fields, pre-approve, auto-submit, create a denial route, enumerate credentials, or claim a local biometric modality.

## Success cases

- pending requests show all three stages and enable exactly one approval control;
- completed requests preserve exact request details and disable approval;
- hostile request text remains escaped;
- JavaScript continues to call only the existing challenge/assertion path;
- WebAuthn still requires user verification and discoverable approved hardware credentials;
- security headers remain fail-closed and same-origin;
- no new authority or credential-administration HTTP route appears.

## Source lesson boundary

`DMJ786/Elyxer_Flutter` is used as a learning source only. No source code, branding, design assets, identity claims, OTP authority semantics, or backend API contract are imported into Pulpo.
