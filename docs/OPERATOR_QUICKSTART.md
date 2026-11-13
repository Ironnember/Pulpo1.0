# Operator quickstart: running a Pulpo deployment

`pulpo-ops` (module form: `python -m pulpo.ops`) packages one governed
deployment directory: a `policy.json` written at init time, the canonical
`state.db` owned by the kernel, and one permit file per issued permit under
`permits/`. Every command below is executed verbatim by
`tests/test_ops_cli.py`; there are no untested commands in this walkthrough.

The CLI holds no signing key and writes no canonical state directly. Its
declared operations are the governed kernel transitions themselves:
`authorize` is `GovernanceKernel.evaluate_with_approval`, `consume` is
`GovernanceKernel.consume`, and `verify` / `status` are read-only
projections over the kernel audit chain.

## 1. Initialize a deployment (test-only authority flow)

The flow in this section uses the `hmac-test` verifier kind. It is a
**test-only** development flow: the shared secret is read from the
`PULPO_OPS_TEST_AUTHORITY_SECRET` environment variable at authorize time
and is never written to `policy.json` (the file records only the variable
name). It is not evidence of independent authority and must not be used as
production key custody — see "Not yet built" below.

```sh
export PULPO_OPS_TEST_AUTHORITY_SECRET='choose-a-local-test-secret'
python -m pulpo.ops init ./deployment --action deploy.release --max-cost 1000 --session-id default --deployment-id deployment:test-ops --authority-id authority:test-owner --verifier-id verifier:test-only --key-id key:test-only:v1 --algorithm hmac-sha256-test-only --key-fingerprint c0d4282378c959913c7f62a748798a931c7f45ac18527fb1a0b0ca5ec939cf35 --verifier-kind hmac-test
```

This creates `./deployment`, boots a kernel once over the new `state.db`
so the deployment starts from a verified empty audit chain, and writes
`policy.json` (schema `pulpo.ops-policy.v1`) capturing the single allowed
action (`deploy.release`, also the approval action), the cost ceiling, the
session/deployment ids, the pinned authority trust, and the verifier
configuration. Running `init` twice over the same directory refuses rather
than overwriting an existing deployment.

A deployment can also be initialized without any authority trust flags:

```sh
python -m pulpo.ops init ./deployment --action deploy.release --max-cost 1000
```

That deployment supports `status` and `verify`, but `authorize` on it
fails closed with an "authority trust not configured" error and records
nothing — no permit can be minted until the deployment is initialized
with a pinned trust.

For production verifier kinds (`ed25519`, `p256`), `init` instead takes
the authority/verifier/key ids, the algorithm, the key fingerprint, and
`--public-key-hex` with the authority's public key; only public material
is ever stored. The kernel re-checks the verifier against the pinned
trust on every `authorize`.

## 2. Get an approval envelope from your authority

`authorize` consumes an approval envelope JSON file. **Your authority
produces this file** — outside this tool, under the authority's own key,
binding the exact intent hash, policy hash, deployment, session,
principal, nonce, issue time, and expiry. `pulpo-ops` never creates,
signs, or modifies envelopes.

(In the test suite, the envelope is minted by the test-only double in
`tests/authority_support.py` against a throwaway kernel carrying the same
policy/trust, purely so the hashes line up. That is a test fixture, not
an operator step.)

Save the envelope as `./envelope.json`.

## 3. Authorize

```sh
python -m pulpo.ops authorize ./deployment --envelope ./envelope.json --principal alice --action deploy.release --resource service:api --cost 100 --session-id default
```

On allow, the command prints the decision JSON (outcome, reason,
intent hash, policy hash, permit path) and writes the kernel-issued
permit to `./deployment/permits/<intent_hash>--<approval_id>.permit` —
one file per issued permit, since distinct approvals for one intent
share an intent hash but never an approval id. Permit files are bearer
artifacts: the `permits/` directory is owner-only (`0700`) and each
file is created atomically at `0600`, never overwriting an existing
artifact. On deny it prints the kernel's reason and exits non-zero
**without** writing a permit. If the `PULPO_OPS_TEST_AUTHORITY_SECRET`
variable is unset in the hmac-test flow, the command fails closed before
any state is opened. The command also preflights the permits directory
before the kernel is opened, so an unusable destination (for example the
path replaced by a file) refuses before anything is issued; if the write
still fails after issuance, the report fails closed with
`permit_persisted: false` and carries the issued permit string as the
recoverable artifact.

## 4. Consume the permit (exactly once, for the exact intent)

```sh
python -m pulpo.ops consume ./deployment --permit-file ./deployment/permits/<intent_hash>--approval-1.permit --principal alice --action deploy.release --resource service:api --cost 100 --session-id default
```

Replace the permit filename with the permit path printed by
`authorize`. The permit
is single-use and bound to the exact intent: consuming it a second time,
or consuming it with any field changed (for example `--cost 999`), exits
non-zero and the kernel records a `permit_rejected` audit event.

## 5. Verify and inspect

```sh
python -m pulpo.ops verify ./deployment
python -m pulpo.ops status ./deployment
```

`verify` checks the audit hash chain (and, in builds where the
`pulpo.anchor` module is present, the `anchors.jsonl` witness when one
exists — verified against the deployment's `anchor-secret`, so a
present witness that is unsigned or signed under another key fails)
and exits 0 only if every performed check passes. In a build
without `pulpo.anchor`, the output states plainly that anchoring is not
available in this build rather than implying the check ran. Since
audit-record signing, `verify` also verifies every record's signature
against the deployment's `audit-secret` (see §7) and reports the
coverage: how many records are signed, how many are the unsigned
legacy prefix. A record past the legacy prefix whose signature is
missing or wrong fails `verify` closed — the kernel refuses to boot
over it at all, so `verify` reports the open failure rather than a
chain verdict.

`status` prints the audit record count, whether the chain is valid, the
policy hash, event counts (including `permit_consumed`, `permit_rejected`,
and `approval_verified`), the audit-signing coverage (with a named
warning when signing was never enabled), and the last anchor —
including whether it is signed — or the same anchoring note.

## 6. Anchor the audit head

```sh
python -m pulpo.ops anchor ./deployment
```

`anchor` appends a signed witness of the current audit head to
`anchors.jsonl`, signed under the deployment's `anchor-secret`
(created by `init`, owner-only, and distinct from `kernel-secret`).
Run it on whatever cadence should be witnessed; each run extends the
witness history. Truncating or rewriting the audit tail after an
anchor is taken fails `verify` — and so does rewriting the anchor file
itself, because the witness only ratifies history signed under the
deployment's own anchor key.

A deployment whose `anchors.jsonl` predates signed anchoring (an
unsigned witness file, and no `anchor-secret` yet) is migrated by the
first `anchor` run: the unsigned file is preserved byte-for-byte as
`anchors.jsonl.legacy-unsigned`, the anchor secret is provisioned, and
the signed history starts at the current head. Signatures attest from
that anchor forward, never retroactively — the preserved unsigned file
remains unverified state.

Scope, stated plainly (it is `pulpo.anchor`'s own): anchoring detects
tampering with the audit store relative to the anchor history the
verifier holds. It does not protect against a writer who can also
rewrite the anchor store and, for signed anchors, holds the anchor key;
that writer is outside this layer's scope, and the tail after the
latest anchor is witnessed only when the next anchor is taken.

## 7. Audit-record signing

Every record the state layer appends carries an HMAC over its own hash
under the deployment's `audit-secret` — a dedicated key, created by
`init` as an owner-only file, deliberately distinct from both
`kernel-secret` and `anchor-secret`, so no single theft yields both
permit minting and undetectable history forgery. The signature is a
sibling of the record hash, excluded from the hashed body, so the
unkeyed chain math is unchanged. A state-file writer who deletes a
record mid-chain and recomputes every following hash — the attack the
unkeyed chain could not see — now fails: the recomputed hashes carry
no valid signature, and `verify` refuses (the kernel will not boot
over the rewritten store).

Signing is enabled from birth for a deployment created by `init`.
A deployment that predates it enables signing explicitly:

```sh
python -m pulpo.ops enable-audit-signing ./deployment
```

The command first verifies the existing chain, then records the
enablement in `policy.json` — outside the state file — together with
the length of the unsigned legacy prefix (every record present at
enablement). Those records keep verifying by hash alone and are
reported as unsigned, with a count; records appended after enablement
must be signed. Run `anchor` at enablement time to witness the legacy
prefix: the pair (signed records + signed anchors) is the unit of
coverage against a state-file writer. Re-running the command on an
enabled deployment is a no-op.

Scope, stated plainly: signing proves the deployment's state layer
wrote the record. It does not prove the kernel governed the write —
any caller who can make the state append gets a valid signature — and
it does not bind the chain's length, so tail truncation still needs
the anchor (§6). A writer who can also rewrite `policy.json` and
delete the audit secret is the whole-directory writer this layer's
scope already places out of scope, exactly as for the anchor-secret
gate (§6).

## Not yet built

- **Production key custody [not yet built]:** this package stores only
  public verifier material and reads the test secret from the
  environment. HSM/KMS-backed authority operation, key rotation, and
  custody ceremony are out of scope here.
- **Multi-action policies [not yet built]:** one deployment directory
  governs exactly one action. Run separate deployments per action.
- **Executing the consequence [not yet built]:** a consumed permit is
  evidence that a consequence was authorized, not the execution itself.
  Wiring permit consumption to a real executor is a separate, separately
  governed step.
- **Separate-custody anchoring [operator's arrangement]:** the anchor
  secret ships in the deployment directory for operability. The
  witness's trust separation is fully realized only when the anchoring
  job runs under separate process/OS custody from the state writer;
  on a single host, a writer who holds both the state file and the
  anchor key remains outside the anchor layer's scope (see §6).
