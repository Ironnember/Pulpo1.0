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
permit to `./deployment/permits/<intent_hash>.permit`. On deny it prints
the kernel's reason and exits non-zero **without** writing a permit. If
the `PULPO_OPS_TEST_AUTHORITY_SECRET` variable is unset in the hmac-test
flow, the command fails closed before any state is opened.

## 4. Consume the permit (exactly once, for the exact intent)

```sh
python -m pulpo.ops consume ./deployment --permit-file ./deployment/permits/<intent_hash>.permit --principal alice --action deploy.release --resource service:api --cost 100 --session-id default
```

Replace `<intent_hash>` with the hash printed by `authorize`. The permit
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
exists) and exits 0 only if every performed check passes. In a build
without `pulpo.anchor`, the output states plainly that anchoring is not
available in this build rather than implying the check ran.

`status` prints the audit record count, whether the chain is valid, the
policy hash, event counts (including `permit_consumed`, `permit_rejected`,
and `approval_verified`), and the last anchor or the same anchoring note.

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
- **Anchoring operations [not yet built] in this build:** creating
  anchors is the anchor layer's job; this CLI only verifies them when
  the `pulpo.anchor` module ships in the same build.
