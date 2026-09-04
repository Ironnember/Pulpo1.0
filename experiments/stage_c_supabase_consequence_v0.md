# Stage C Supabase Consequence-Custody V0

Status: **EXPERIMENT / PROCESS HOLD / DO NOT MERGE**

`authority_effect=none`

`governed_effect=external_provider_stage_c_sandbox`

This experiment implements the smallest intended real-provider Stage-C ceremony for Pulpo: one disposable Supabase/Postgres table, one narrow executor principal, one read-only observer principal, one cleanup principal, the frozen ten-family unauthorized-effect suite, and one matched known-good conversion.

The real-provider path is intentionally unavailable until the three roles authenticate with distinct credentials. Same-session `SET ROLE`, a shared admin connection, or an observer credential exposed to the hostile attack child is not accepted as Stage-C evidence.

## Frozen objects

- canonical source main: `1ee8485c4599ad3266c8e90c5baad29309bc700c`
- source benchmark head: `f9242eb67fe46eb201281e54f692a0cdc2d3b840`
- attack-vector SHA-256: `ff3edebf38171f5d0eb2b8bf0b9132fff89fb8272a9a27446c0bfb5b398d1c9e`
- Stage-B result hash: `3cbc11a19fd3d27f7a56a18f01ca02715b27849627dd35f752ec1a8f3952f79a`
- matched-row SHA-256: `d108b7f364364ca69838eb69f58113e1cb6104498bfebef010fec00bd6c239db`
- provider project: `jvqryaqkhdnasowxycns`
- provider table: `pulpo_stage_c.effects`

## Real-provider trust split

- `pulpo_stagec_executor`: INSERT-only on the exact effect columns; cannot SELECT/UPDATE/DELETE.
- `pulpo_stagec_observer`: SELECT-only; cannot INSERT/UPDATE/DELETE.
- `pulpo_stagec_cleanup`: DELETE plus effect-id lookup only; cannot INSERT/UPDATE.

The provider table deliberately does **not** make `effect_id` unique. PostgreSQL must not accidentally supply Pulpo's replay defense.

## Runner boundary

`run_stage_c_supabase_consequence.py --software-only` performs no provider writes and emits only readiness evidence.

A real run additionally requires three distinct DSNs in environment variables. The runner strips all provider credential variables before launching the hostile attack child. Individual `psql` subprocesses receive only the one credential required for that exact provider role.

The matched conversion goes through the canonical Pulpo kernel and existing `SQLiteGovernanceCustody` sequence before one provider transmission right is released. The executor's successful return is recorded as a claim, reconciliation is required, and the read-only observer determines whether the expected row actually became real. Cleanup is a separately authorized Pulpo consequence using the separate cleanup principal.

## Claim boundary

A successful run would support only a bounded claim for this exact Supabase/Postgres sandbox and frozen attack set. It would not establish production security, arbitrary-provider correctness, hostile-host resistance, per-mechanism causal attribution without matched ablations, or cold third-party reproduction.

`EXECUTOR_SUCCESS != VERIFIED_CONSEQUENCE`

`OBSERVATION_UNAVAILABLE -> UNKNOWN`

`UNKNOWN != ZERO_UNAUTHORIZED_EFFECT`
