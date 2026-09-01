# Pulpo Current State

Status date: 2026-08-31

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is `c15b82da86a1dcd476b283af31870c47fdf4f199`, the merge of PR #110 that restored the exact pre-PR-#109 tree after PR #109 was merged despite its recorded hold boundary. The SHA is an inspection point, not a permanently pinned source-of-truth designation.

`Iron-Ember/pulpo`, `Ironnember/The-keel`, and other earlier or adjacent repositories remain historical or experimental evidence unless a legitimate governance transition explicitly admits a behavior into canonical Pulpo.

Evidence precedence remains:

1. executable behavior and tests;
2. current canonical reviewed code;
3. durable runtime/cloud/provider evidence;
4. current state artifacts and explicit decisions;
5. design documents;
6. summaries, screenshots, prototypes, and marketing.

## Claim classes

- **Verified** — reproduced or directly supported by executable/current evidence.
- **Recorded** — durably captured evidence not independently reproduced in this document update.
- **Inferred** — conclusion from evidence, explicitly identified as inference.
- **Proposed** — intended next design/action, not yet proved.
- **Unknown** — insufficient or conflicting evidence.

## Verified in canonical code and CI

### Governance kernel

The current kernel and tests prove fail-closed intent/policy evaluation, exact intent hashing, policy hashing, one-use permits, permit substitution denial, durable SQLite replay protection across restart, audit-chain tamper detection, and bootstrap failure on invalid persisted audit state.

Static `AgentGrant` policy constrains configured principals by action, resource prefix, and cost. Unknown principals fail closed and an agent grant cannot broaden the global policy. This is least-authority policy enforcement; it is not yet a general delegated organizational-authority system.

### Independent approval contract

The approval path uses policy-pinned asymmetric public trust. Approval envelopes bind authority, verifier, key, deployment, approval identity, principal/session, exact intent, exact policy, nonce, issue time, and expiry. Invalid signatures, replay, expiry, clock rollback, trust substitution, or verifier failure deny.

The repository also contains the separately packaged authority service, WebAuthn ceremony logic, worker request/poll surface, Google Cloud KMS P-256 signer adapter, protected-evidence adapter contract, and PostgreSQL authority-state adapter. Passing tests prove those code-side contracts only; they do not prove the production authority deployment exists.

### Governed directive projection

Canonical directive code extends the existing authority/policy/state seam rather than creating a second memory governor or policy engine.

Executable tests prove:

- ordinary chat/retrieval cannot activate an authoritative directive;
- directive activation/revocation requires the existing pinned external approval path;
- approval is bound to the exact directive digest;
- an untrusted issuer is denied;
- an active directive can narrow principal/action/resource/cost while the kernel remains authoritative;
- retrieval relevance or a model summary cannot raise authority;
- substitution with a broadened directive is denied;
- revocation survives SQLite restart;
- a permit bound to a directive is one-use and carries directive identity evidence;
- revocation invalidates an already-issued directive-bound permit at consumption time, including after restart.

A complete parent-to-child delegated-authority derivation/intersection proof is still open. Existing substitution tests prove non-broadening of an admitted directive version, not a general delegation hierarchy.

### Hostile-worker consequence boundary

The custody/worker proof establishes a software/container boundary with:

- exact target/order/policy/permit binding;
- live directive revalidation when a permit is consumed;
- custody-side monotonic state and compare-and-swap admission;
- one authoritative attempt under replay/fork/two-worker races;
- durable budget reservation/attempt/reconciliation state;
- no blind retry after an unknown provider outcome;
- provider/executor success remaining a claim until independent observation;
- hostile-worker container denial of custody persistence, Docker socket, governance secrets, and provider executor/observer tokens;
- custody transition obligations projected into the existing canonical Pulpo audit rather than a second ledger.

This proves hostile-worker containment under the tested boundary. It does **not** prove hostile-host, hostile-custodian, HSM/TEE containment, or arbitrary-provider correctness.

### Bounded commerce and Name.com contracts

Canonical tests prove exact domain/registrar/owner/privacy/upsell/price/renewal constraints, the USD 30 pilot ceiling, request/quote/order binding, reservation/reconciliation semantics, provider idempotency binding, and denial of production execution when a hard provider charge cap is unavailable.

A separate read-only Name.com sandbox readiness proof exists but remains externally blocked by missing configured sandbox executor/observer credentials. No Name.com registrar write or completed external purchase is established.

## Recorded and externally verified infrastructure evidence

Issue #90 is the durable deployment record for the independent authority boundary.

The Google Cloud authority project is recorded as:

- project: `dulcet-opus-499511-a5`;
- project number: `286256558392`;
- region: `us-west1`;
- authority key ring: `projects/dulcet-opus-499511-a5/locations/us-west1/keyRings/pulpo-authority`.

The exact non-exportable signer has been created and externally verified:

`projects/dulcet-opus-499511-a5/locations/us-west1/keyRings/pulpo-authority/cryptoKeys/approval-signer/cryptoKeyVersions/1`

Recorded/verified metadata:

- state: `ENABLED`;
- algorithm: `EC_SIGN_P256_SHA256`;
- protection level: `HSM`;
- curve: NIST P-256;
- Pulpo canonical SEC1-point trust fingerprint: `b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127`;
- a live KMS signature over the deterministic proof message verified locally against the independently fetched public key.

This proves the external signing primitive. It does not by itself prove `authority.pulpo.ai`.

The Service Networking API has also been verified enabled. A dedicated private authority VPC/subnet/PSA path was frozen and explicitly authorized, but the issue record available at this reconciliation contains authorization rather than post-execution verification of those network objects.

Cloud SQL discovery found no existing instance. The dedicated PostgreSQL authority-state instance remains a frozen/authorized design whose exact private connection prerequisite must be established before the production authority service can depend on it.

## Independent authority remains incomplete

`https://authority.pulpo.ai` / RP ID `authority.pulpo.ai` remains the selected human authority origin, but the complete deployed boundary has not passed acceptance.

Still required:

- independently administered authority-service deployment;
- verified private network path;
- protected multi-instance Cloud SQL/PostgreSQL authority state using provider/database time;
- independently retained create-only authority evidence with effective locked retention;
- worker request/poll ingress bound to the exact governed-worker identity;
- primary hardware WebAuthn credential plus separately controlled offline recovery credential;
- exact DNS, TLS, load-balancer/origin acceptance;
- success, denial, replay, rollback, expiry, concurrency, signer-failure, state-failure, evidence-failure, origin/RP, and credential acceptance matrix;
- fresh external reproduction after restart/service replacement.

Until those pass, external language must distinguish **verified external HSM signer** from **deployed independent human authority**.

## Governance/admission state

Protected `main` currently exposes required status contexts `test`, `authority`, and `authority-service` through the branch metadata visible to this integration.

PR #109 demonstrated that narrative governance is insufficient: it was merged while its body retained an explicit `DRAFT / DO NOT MERGE` authority boundary. PR #110 restored the exact prior tree without rewriting history.

This reconciliation introduces a base-controlled `pull_request_target` workflow named `Admission Hold` plus deterministic tests. The workflow executes only the protected base tree and fails on GitHub draft state, an explicit `<!-- pulpo-admission: hold -->` marker, recognized legacy hold directives, hold title prefixes, or hold labels. It never checks out or executes pull-request head code.

**Important:** the new `admission-hold` context becomes a mechanically blocking merge control only after this change is admitted to `main` and repository protection/rules explicitly require that context with no inappropriate bypass. The current connector cannot verify or mutate the full branch-protection/admin-bypass configuration, so that final protection step must not be represented as already proved.

## Keel boundary

`Ironnember/The-keel` is an experimental execution-plane proof, not canonical Pulpo authority.

Its V0 draft establishes the intended split:

- Pulpo owns authority, policy, permits, evidence, reconciliation, and governed learning;
- Keel deterministically executes an already-authorized exact operation and returns an execution receipt that cannot self-certify reconciliation.

Eight Keel V0 boundary tests pass, including replay, substitution, expiry, revocation, unknown-outcome restart, and authority-expansion denial. Exact head `07b975c6e7e6a7b65b1b1d2f36673ec7d6636bc5` passes Keel V0 Boundary run #4 across Python 3.11, 3.12, and 3.13, including compile and zero-production-dependency hygiene checks. The prior hygiene failure was a checker false positive on the package-relative `from .core` import and was corrected without adding a production dependency.

Keel remains draft/noncanonical because it has not yet verified a real Pulpo cryptographic one-use permit or been admitted as Pulpo's execution substrate.

## Explicit nonclaims

Pulpo does not yet prove:

- a fully deployed and acceptance-proven independent human-authority service;
- physical WebAuthn founder/recovery credential control;
- external hostile-host or hostile-custodian resistance;
- a real Name.com sandbox registration consequence through the final custody ceremony;
- independent provider observation and reconciliation of that consequence;
- cold reproduction of the full consequential chain by an unrelated operator;
- production throughput, latency, reliability, deployment cost, cost per governed action, false-denial rate, human-review burden, or customer ROI;
- general correctness across arbitrary agents, providers, payment rails, or execution surfaces.

Do not convert passing CI, a cloud resource, an approval, a successful executor report, or market interest into authority or production-readiness claims.

## Next highest-value proof sequence

1. Admit the base-controlled admission-hold check and require its status in protected-main rules, closing the demonstrated unauthorized-merge class.
2. Finish and verify the private authority network, Cloud SQL authority state, retained evidence, worker ingress, DNS/TLS, and hardware WebAuthn boundaries around the already-verified HSM signer.
3. Pass the deployed `authority.pulpo.ai` acceptance matrix from a fresh client/service instance.
4. Configure distinct Name.com sandbox executor/observer credentials and run exactly one bounded consequence through:

   `domain -> trusted observation -> ProposalCommitment -> independent human authority -> exact permit -> isolated execution -> independent provider observation -> reconciliation -> restart/replay denial`

5. Preserve the complete evidence bundle and have an unrelated operator reproduce it.
6. Admit Keel only after its execution contract verifies a real Pulpo cryptographic permit without becoming a second authority or ledger.

The doctrine remains:

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
