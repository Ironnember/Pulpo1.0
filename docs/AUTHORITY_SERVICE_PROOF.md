# Independent Authority Service Proof

Status date: 2026-08-29

## Claim classification

- **Verified:** Pulpo's worker package exposes only typed request and poll operations to the authority service.
- **Verified:** the separately packaged reference recomputes the displayed intent hash, constructs service-owned approval metadata, binds a WebAuthn challenge to the exact signing payload, requires user presence and verification, rejects backup-eligible and recovery credentials, checks its signer against pinned trust, writes complete evidence before releasing an envelope, and allows one exact envelope through the canonical kernel.
- **Verified:** HTTP tests exercise request, the escaped human review page, challenge, assertion, poll, malformed input, unknown request, strict browser response headers, completed-request button disabling, and field-substitution behavior.
- **Recorded:** the service uses `webauthn==3.0.0` for server-side assertion validation and separately pins its HTTP/runtime dependencies.
- **Blocked:** production deployment, independent administration, real hardware enrollment, non-exportable service signing, durable monotonic state, append-only evidence, worker ingress isolation, and external reproduction.

## Package boundary

`pulpo/authority_client.py` is part of the governed worker package. Its public interface contains exactly `request_approval` and `poll_approval`. It rejects non-HTTPS service origins and cross-origin human approval URLs.

`authority-service/` is a separate Python distribution. It is not discovered or installed by the root Pulpo package. It contains no enrollment, rotation, recovery, revocation, raw-sign, private-key export, or trust-configuration API. Its signer and state/evidence implementations are injected at the independent service boundary.

## Exact successful proof

The acceptance test constructs one immutable intent request, derives the exact challenge, supplies a simulated fresh hardware assertion, writes the full evidence bundle, signs `pulpo.approval.v2` with an ephemeral test-only Ed25519 fixture, polls the resulting envelope, and passes it to the canonical Pulpo kernel. The kernel verifies pinned public trust and produces one bound permit. A second service approval and a second permit consumption are denied.

Ephemeral test private keys are test fixtures only. They are not deployment keys, credentials, repository secrets, or evidence of independent custody.

## Adversarial proof

The tests fail closed for:

- display fields that disagree with the Pulpo intent hash;
- deployment substitution or excessive TTL;
- HTTP fields outside the exact request schema;
- cross-origin human approval URLs;
- authority-service HTTP redirects and oversized responses;
- credential enumeration or unauthenticated human-denial routes;
- recovery credentials used for ordinary approval;
- unverified, backup-eligible, backed-up, inactive, or unapproved credentials;
- authenticator counter rollback;
- a service signer that does not match pinned Pulpo trust;
- evidence-store failure;
- duplicate ceremony completion;
- invalid RP/origin configuration; and
- unknown authority requests.

The human button is executable reference code, not proof of a real hardware ceremony. No real browser, approved authenticator, enrolled credential, production RP ID/origin, or deployed service participated in the repository tests. WebAuthn requires user verification but does not report the local verification modality to the relying party. Touch ID, Face ID, and phone confirmation therefore remain **Not Tested** and are not claimed.

## Learned deployment discipline

The reusable engineering lessons extracted from plugin skills sharpen the deployment gate without changing authority:

`contract -> exact artifact -> trust evidence -> classify -> minimum change -> real-path verification -> reconcile`

Applied here:

1. **Contract before infrastructure.** Freeze the exact production authority-service contract before choosing hosting: RP ID, HTTPS origin, worker request/poll identity, signer fingerprint, credential classes, state/evidence durability, and failure semantics.
2. **Inspect the exact deployed artifact.** Record immutable application/package revision, dependency lock, configuration digest, TLS/RP/origin identity, service account identity, signer public fingerprint, and evidence-store identity. A provider dashboard saying “deployed” is not consequence evidence.
3. **Classify trust failures before repair.** Distinguish origin/RP mismatch, service identity failure, signer mismatch, credential-policy failure, state rollback, evidence-store failure, and worker-ingress failure. Do not broaden permissions or weaken checks merely to make deployment succeed.
4. **Minimum capability first.** The worker receives only request/poll access. The human surface receives only the ceremony required to approve the exact request. The service receives no general Pulpo execution authority.
5. **Verify the real path.** Health/readiness proves availability only. Production admission additionally requires one real hardware ceremony, one exact approval envelope, one canonical permit, one permitted bounded effect or dry consequence gate, replay denial, restart durability, and independently readable evidence.
6. **Reconcile before learning.** Provider success, HTTP 200, valid signature, or successful WebAuthn ceremony is evidence about one stage; none alone proves the authorized consequence matched intent.

### Deployment anti-patterns

Reject deployment approaches that require any of the following:

- giving the worker access to authority-service private signing material;
- exporting a service signer merely for convenience;
- disabling origin, RP, UV, backup, counter, replay, or evidence checks to fix an environment problem;
- granting broad cloud-admin credentials to the governed worker;
- treating CI, hosting, observability, or a plugin as the authority source;
- adding a second approval service, policy engine, router, executor, or evidence ledger;
- declaring production authority from provider health checks or simulated authenticators.

## Production acceptance gate

Production remains **Blocked** until one exact environment supplies and proves:

1. a permanent RP ID and exact HTTPS origin;
2. an independently administered service account unreachable by the worker;
3. approved primary and offline recovery hardware models and their physical enrollment ceremony;
4. a non-exportable Ed25519-compatible service signer whose public fingerprint is pinned by Pulpo policy;
5. durable transactional request, credential, sequence, revocation, and replay state with rollback detection;
6. independently append-only full assertion/signature evidence;
7. worker ingress restricted to a non-human request/poll identity; and
8. an externally reproduced success plus origin, RP, challenge, credential, UV, backup, replay, rollback, expiry, signer, and evidence-failure tests.

### Required deployment evidence bundle

For the exact admitted deployment version, preserve at minimum:

- source revision and dependency-lock digest;
- deployment artifact/configuration digest;
- exact RP ID and HTTPS origin;
- service-account identity and worker-ingress policy identity;
- signer algorithm and public fingerprint, with evidence that private signing material is non-exportable and outside worker custody;
- enrolled primary/recovery credential identifiers and policy classification without storing private authenticator secrets;
- durable-state backend identity and rollback-detection evidence;
- append-only evidence-store identity;
- real ceremony assertion evidence and resulting approval-envelope identity;
- canonical Pulpo intent, policy, target when applicable, permit, consumption, and reconciliation identifiers;
- denial evidence for replay, mismatch, expiry, invalid credential state, signer mismatch, state rollback, and evidence-store failure.

A deployment artifact is not canonical merely because this checklist is satisfied. Admission still requires separately legitimate review/policy transition and current executable evidence.

Until all eight production gates pass at the exact deployed version, the correct public claim is **executable independent-authority reference**, not deployed independent human authority.
