# Local Effect Reconciliation V0

Status: proposed; stacked on Local Speech Input V0 and noncanonical until reviewed and merged
Branch: `feature/local-effect-reconciliation-v0`
Dependency: `feature/local-speech-input-v0` / PR #59

## Purpose

Prove the first real consequence in the local Pulpo voice loop:

`spoken command -> transcript -> exact target -> Pulpo decision -> one-use permit -> bounded executor -> fresh observation -> reconciliation -> spoken verified result`

The consequence is intentionally small and reversible: create one new hidden text file at the root of the current Pulpo checkout.

This proof does not use a shell, network API, money, credentials, or an external service.

## Invariants

`VOICE != AUTHORITY`

`"FIRE" != PERMIT`

`PERMIT != EXECUTION`

`EXECUTOR_REPORT != OBSERVED_CONSEQUENCE`

`OBSERVATION != RECONCILIATION`

`COMPLETE != VERIFIED`

Pulpo may speak a verified-success claim only after the observed file matches the exact authorized effect.

## Exact effect object

`LocalFileEffect` binds:

- schema;
- generated 16-hex effect ID;
- derived root-level filename;
- exact UTF-8 content hash;
- exact byte count;
- `overwrite = false`.

The filename is derived by code:

```text
.pulpo-effect-v0-<effect_id>.txt
```

The caller cannot supply an arbitrary path. Content is limited to 1024 bytes.

The canonical intent binds the exact effect hash:

```text
action = create_local_file
resource = local-effect:<effect_hash>
cost = 0
```

## Executor boundary

`LocalFileExecutor`:

1. requires an existing root directory;
2. refuses an existing target before consuming authority;
3. derives the exact intent from the effect;
4. consumes the Pulpo permit;
5. creates the file with `O_CREAT | O_EXCL` and `O_NOFOLLOW` when available;
6. writes exact bytes directly through the Python filesystem API;
7. fsyncs the file;
8. never shells out;
9. never overwrites;
10. never automatically retries after permit consumption.

If a race or write failure occurs after permit consumption, the result is uncertain/failed and requires reconciliation rather than a blind retry.

## Observation and reconciliation

The executor return value is only an execution claim.

`observe_local_file` performs a fresh filesystem read and records:

- existence;
- relative path;
- observed content SHA-256;
- observed byte count;
- observation time;
- `authority_effect = none`.

`reconcile_local_file` separately compares:

- exact effect hash;
- exact intent hash;
- executor-claimed path/content/byte count;
- fresh observed path/content/byte count.

Only an exact match produces:

```text
reconciliation=verified
reconciliation_reason=effect_verified
```

Deletion, mutation, path mismatch, content mismatch, byte mismatch, or binding mismatch produces `reconciliation=mismatch`.

## Replay proof

After the first consequence has been observed, the demo deliberately attempts to consume the same permit a second time without attempting another filesystem effect.

Expected result:

```text
permit_replay=rejected
```

This is evidence that the authority used for the consequence remains one-use.

## Proof bundle

`build_local_effect_proof` creates a portable read-only projection containing:

- exact effect metadata;
- execution claim;
- fresh observation;
- reconciliation result;
- current kernel audit validity;
- current kernel audit tip;
- deterministic bundle hash.

This projection is not a second ledger and grants no authority.

## Voice behavior

`pulpo-effect-demo` uses the existing `GovernedVoiceInterface` and `VoiceCommandSession`.

It stages one effect and says that nothing has executed. The operator must say the exact commands:

```text
lock target
fire
```

Negated or extended phrases remain non-commands under Voice V0.

After `allow`, the existing voice layer still says that permit issuance does not prove execution.

Only after execution, fresh observation, exact reconciliation, and replay rejection may Pulpo say:

```text
Execution verified. The exact local file consequence matches the authorized target.
```

## Required negative evidence

Tests must establish:

1. a permit for a different effect cannot write the file;
2. an existing target cannot be overwritten and is rejected before permit consumption;
3. a spent permit cannot create the effect again;
4. missing post-execution state fails reconciliation;
5. post-execution tampering fails reconciliation;
6. ambiguous/negated voice commands cannot execute;
7. an execution failure is attempted once and never auto-retried;
8. Pulpo never speaks `verified` after a reconciliation mismatch;
9. empty microphone windows retain the bounded retry behavior from Voice V0;
10. the full inherited governance/authority suites remain green.

## Operator-host proof

From the current Pulpo checkout on this branch:

```text
git pull --ff-only
pip install -e ".[authority,voice]"
pulpo-effect-demo --seconds 3 --empty-retries 3
```

Wait for each `Listening` cue.

Say:

```text
lock target
```

then:

```text
fire
```

A successful run should visibly end with fields equivalent to:

```text
decision=allow
execution=performed
reconciliation=verified
reconciliation_reason=effect_verified
permit_replay=rejected
proof_bundle_hash=<sha256>
```

and should audibly report that the exact local consequence is verified.

The generated `.pulpo-effect-v0-<effect_id>.txt` file is intentionally left in place as the observed consequence. Removing it later is a separate manual cleanup action and is not part of this proof.

## Boundary not proved

This proof does **not** establish:

- speaker identity or voice authentication;
- independently deployed human authority;
- an external execution service;
- filesystem containment against a hostile local host/root user;
- rollback-proof evidence;
- network/API execution;
- money movement;
- external consequence verification by a separate trust domain;
- production readiness.

The observation path is separate code from the executor but runs on the same local host and process trust domain. Therefore this proof demonstrates **fresh consequence observation and exact reconciliation**, not independent external attestation.

## Claim classification

Until CI passes at the exact branch head:

- implementation: **Recorded**;
- local-effect runtime semantics: **Unknown**;
- real operator-host consequence: **Unknown**.

After CI passes, tested semantics may be **Verified** for that exact branch commit. A real operator-host consequence remains **Unknown** until the command is exercised and its resulting file/evidence is observed.
