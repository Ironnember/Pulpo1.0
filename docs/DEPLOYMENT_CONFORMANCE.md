# Pulpo deployment conformance evidence

Before deployment, record evidence for the existing governance and execution
boundaries:

1. Secure boot or equivalent host-integrity evidence and a host identity bound
   to the deployment identifier.
2. TLS termination, certificate/hostname validation, network policy, and
   bounded timeout configuration for every enabled adapter.
3. Bootstrap secrets supplied through the deployment secret mechanism, never
   committed, logged, or placed in proposals, evidence bundles, or images.
4. A rollback record containing the exact image/source digest, schema/state
   version, authority policy, and operator approval. Rollback must preserve
   replay protection and fail closed on unknown state.

This repository provides deterministic configuration and contract checks only.
It does not add a signer, credential store, executor, authority plane, secure
boot implementation, host attestation service, or production hardware claim.
Deployment/CI owns attestation and any signature or external provenance.
Evidence is **Recorded** when supplied by deployment; unsupported hardware or
attestation claims remain **Unknown**.
