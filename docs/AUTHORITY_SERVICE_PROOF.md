# Independent Authority Service Proof

Status date: 2026-08-26

## Claim classification

- **Verified:** Pulpo's worker package exposes only typed request and poll
  operations to the authority service.
- **Verified:** the separately packaged reference recomputes the displayed
  intent hash, constructs service-owned approval metadata, binds a WebAuthn
  challenge to the exact signing payload, requires user presence and
  verification, rejects backup-eligible and recovery credentials, checks its
  signer against pinned trust, writes complete evidence before releasing an
  envelope, and allows one exact envelope through the canonical kernel.
- **Verified:** HTTP tests exercise request, display, challenge, assertion,
  poll, malformed input, unknown request, and field-substitution behavior.
- **Recorded:** the service uses `webauthn==3.0.0` for server-side assertion
  validation and separately pins its HTTP/runtime dependencies.
- **Blocked:** production deployment, independent administration, real hardware
  enrollment, non-exportable service signing, durable monotonic state,
  append-only evidence, worker ingress isolation, and external reproduction.

## Package boundary

`pulpo/authority_client.py` is part of the governed worker package. Its public
interface contains exactly `request_approval` and `poll_approval`. It rejects
non-HTTPS service origins and cross-origin human approval URLs.

`authority-service/` is a separate Python distribution. It is not discovered or
installed by the root Pulpo package. It contains no enrollment, rotation,
recovery, revocation, raw-sign, private-key export, or trust-configuration API.
Its signer and state/evidence implementations are injected at the independent
service boundary.

## Exact successful proof

The acceptance test constructs one immutable intent request, derives the exact
challenge, supplies a simulated fresh hardware assertion, writes the full
evidence bundle, signs `pulpo.approval.v2` with an ephemeral test-only Ed25519
fixture, polls the resulting envelope, and passes it to the canonical Pulpo
kernel. The kernel verifies pinned public trust and produces one bound permit.
A second service approval and a second permit consumption are denied.

Ephemeral test private keys are test fixtures only. They are not deployment
keys, credentials, repository secrets, or evidence of independent custody.

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

## Production acceptance gate

Production remains **Blocked** until one exact environment supplies and proves:

1. a permanent RP ID and exact HTTPS origin;
2. an independently administered service account unreachable by the worker;
3. approved primary and offline recovery hardware models and their physical
   enrollment ceremony;
4. a non-exportable Ed25519-compatible service signer whose public fingerprint
   is pinned by Pulpo policy;
5. durable transactional request, credential, sequence, revocation, and replay
   state with rollback detection;
6. independently append-only full assertion/signature evidence;
7. worker ingress restricted to a non-human request/poll identity; and
8. an externally reproduced success plus origin, RP, challenge, credential,
   UV, backup, replay, rollback, expiry, signer, and evidence-failure tests.

Until all eight pass at the exact deployed version, the correct public claim is
**executable independent-authority reference**, not deployed independent human
authority.
