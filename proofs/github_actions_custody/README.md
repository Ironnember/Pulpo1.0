# GitHub Actions Permit-Only Execution Proof

Status: `IMPLEMENTED_PENDING_EXTERNAL_RUN`

This proof uses GitHub Actions as a free external execution surface.

## Trust split

- The `pulpo-proof-authority` GitHub environment is restricted to protected
  branches and requires an `Ironnember` reviewer.
- The environment holds the Ed25519 private key.
- The repository contains only the pinned public key.
- The `authority` job is the only job that declares the protected environment.
- The `executor` and `adversarial` jobs receive only a signed approval
  envelope and the public verification key.

The approval binds repository, protected ref, exact commit SHA, workflow run ID,
run attempt, artifact name, payload hash, session, policy, issue time, expiry,
and nonce.

## Consequence

The positive consequence is one GitHub Actions artifact whose payload is
materialized only after the canonical Pulpo kernel verifies the exact signed
approval and consumes the resulting one-use permit.

The workflow also proves in the external runner that:

- missing approval is denied;
- exact-object substitution is denied;
- signature substitution is denied; and
- denial paths materialize no artifact payload.

A later rerun of only the executor is intended as the replay test: the original
approval is bound to `GITHUB_RUN_ATTEMPT`, so a new attempt must not accept it.

## Claim boundary

This does **not** yet prove total custody from the repository administrator.
The currently connected GitHub identity has repository-admin capability and the
environment reports `can_admins_bypass=true`. An administrator could alter
environment configuration or repository policy. That alternate administrative
route must remain explicit.

The proof can establish external permit-gated execution and job-level secret
separation. Full Pulpo-enforced custody additionally requires authority
administration to be outside the intelligence path.

## Reproduction

1. Merge the workflow and proof code through protected `main`.
2. Dispatch `Pulpo GitHub Actions Custody Proof` on `main`.
3. Approve the protected authority environment for that exact run.
4. Verify adversarial denials and the single uploaded artifact.
5. Rerun only the executor job and verify the old approval fails because the
   run-attempt binding changed.
6. Record workflow logs, artifact metadata, and the remaining admin boundary.

No paid service is required for the public repository's standard hosted runner.
