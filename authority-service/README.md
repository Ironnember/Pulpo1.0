# Pulpo Independent Authority Service

This directory is a separately packaged reference for the external WebAuthn
authority selected in `docs/AUTHORITY_BOUNDARY_DECISION.md`. It is not installed
with the Pulpo worker package.

The executable core proves immutable request construction, exact challenge
binding, primary/recovery isolation, required user verification, backup-policy
enforcement, service-owned time and sequence, evidence-before-release, and an
exact signed `pulpo.approval.v2` result.

`InMemoryState` and `InMemoryEvidenceSink` are acceptance-proof adapters only.
Production remains **Blocked** until they are replaced by externally protected
durable state and append-only evidence, the signer is backed by a non-exportable
service key, ingress is restricted to the governed worker identity, and the
exact RP ID/origin and hardware credentials are selected and enrolled.

There is deliberately no enrollment, rotation, recovery, revocation, raw-sign,
or trust-configuration API in this package.
