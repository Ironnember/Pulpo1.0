"""Phase 3, Item 3B — the service boundary: one process holds the
state; every other component gets authenticated client verbs, never
the handle.

The 3A change record priced the residual this item retires (ruling
Q5): in-process, a determined caller who constructs a state backend
directly can spend (repro A), activate a directive behind fabricated
evidence (repro B3), or append a forged record (repro C) — against
*that* backend. 3B's claim is the one a process boundary can prove:

- the canonical store lives behind authenticated, freshness-bounded,
  replay-checked serialized verbs; nothing else a client process does
  touches it — a client-side backend construction (A) governs only
  itself, and the canonical audit/budget provably do not move;
- the protocol has no field for authority evidence and no append
  verb, so B3 and C have no surface: directive activation runs the
  server-side controller over a server-side-verified envelope, and a
  fabricated envelope denies with no state change;
- unauthenticated, tampered, replayed, expired, and not-yet-valid
  requests all fail closed with the canonical state untouched;
- the honest flows (evaluate/consume, target locking and completion,
  the full directive lifecycle including the cumulative budget, the
  facade reads) work end to end across the boundary — over a loopback
  transport, and over a real Unix-socket subprocess boundary for the
  core spend path.

The four Codex review findings on PR #371 are covered where they
land: credentials are bound to principals (a credential cannot act
for a principal outside its configured set, a second credential
cannot spend the first principal's permit, and an unbound credential
cannot be constructed); nonces are retained for their whole
validity window (a cache full of live nonces refuses new requests
fail-closed instead of evicting); artifact observation is confined
to configured roots (outside paths, `..` traversal, and the
no-root configuration all refuse before any file is read); and
socket frame reads carry a deadline (a stalled partial frame is
disconnected with nothing dispatched).

Honesty label, as with 3A's fixtures: the approval verifier is a
same-process HMAC test double, not evidence of independent human
authority; the service secrets in these tests are test values.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, DirectiveAuthorityController
from pulpo.kernel import GovernanceKernel as KernelClass
from pulpo.service import (
    KernelService,
    KernelServiceClient,
    ServiceRefusal,
    UnixSocketTransport,
    directive_from_dict,
    directive_to_dict,
    loopback_transport,
    serve_unix_socket,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"
SERVICE_SECRET = b"service-secret-test-only"
CREDENTIAL_ID = "client:primary"
RESTRICTED_CREDENTIAL_ID = "client:auditor"
RESTRICTED_SECRET = b"restricted-secret-test-only"
RESTRICTED_PRINCIPAL = "agent:auditor"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def directive(**overrides):
    values = dict(
        directive_id="deploy-prod",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


class BoundaryFixture:
    """A service and clients wired over the loopback transport.

    The fixture (the test harness, acting as the deployment operator)
    holds the server-side kernel to mint approval envelopes, exactly
    as the 3A fixtures do. The client objects under test hold only
    the transport, their credential id, and that credential's
    secret. The service is configured with two credentials: the
    primary, bound to the operator and the builder agent, and a
    restricted one bound to a different principal only.
    """

    def __init__(self, state=None, clock=None, *, nonce_cache_limit=None, artifact_roots=()):
        self.clock_cell = [NOW]
        self.clock = clock or (lambda: self.clock_cell[0])
        self.verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            policy,
            b"kernel-secret",
            approval_verifier=self.verifier,
            clock=self.clock,
            state=state if state is not None else InMemoryKernelState(),
        )
        service_kwargs = {}
        if nonce_cache_limit is not None:
            service_kwargs["nonce_cache_limit"] = nonce_cache_limit
        self.service = KernelService(
            self.kernel,
            {
                CREDENTIAL_ID: (SERVICE_SECRET, frozenset({OPERATOR, "agent:builder"})),
                RESTRICTED_CREDENTIAL_ID: (RESTRICTED_SECRET, frozenset({RESTRICTED_PRINCIPAL})),
            },
            clock=self.clock,
            max_request_ttl_ns=500_000,
            artifact_roots=artifact_roots,
            **service_kwargs,
        )
        self.client = KernelServiceClient(
            loopback_transport(self.service),
            CREDENTIAL_ID,
            SERVICE_SECRET,
            clock=self.clock,
            request_ttl_ns=400_000,
        )
        self.restricted_client = KernelServiceClient(
            loopback_transport(self.service),
            RESTRICTED_CREDENTIAL_ID,
            RESTRICTED_SECRET,
            clock=self.clock,
            request_ttl_ns=400_000,
        )
        self.controller = DirectiveAuthorityController(self.kernel)

    def envelope_for(self, operation, d, approval_id):
        intent = self.controller.authority_intent(operation, d, operator_principal=OPERATOR)
        return signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=self.clock_cell[0] - 10,
            approval_id=approval_id,
            nonce=f"{approval_id}-nonce",
        )

    def audit_len(self):
        return len(self.client.audit())


class HonestFlowTests(unittest.TestCase):
    def test_evaluate_consume_single_use_across_boundary(self):
        fx = BoundaryFixture()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = fx.client.evaluate(intent)
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)
        self.assertTrue(fx.client.consume(decision.permit, intent))
        # A fresh request spending the same permit again: refused by
        # the kernel's single-use rule, not by the protocol.
        self.assertFalse(fx.client.consume(decision.permit, intent))
        self.assertTrue(fx.client.verify_audit())

    def test_evaluate_with_approval_across_boundary(self):
        fx = BoundaryFixture()
        intent = Intent(OPERATOR, "activate_directive", "directive:x:1:abc", 0, "default")
        plain = fx.client.evaluate(intent)
        self.assertEqual(plain.outcome, "require_approval")
        envelope = signed_envelope(
            fx.kernel, intent, fx.verifier, now_ns=NOW - 10, approval_id="ap-1", nonce="ap-1-nonce"
        )
        decision = fx.client.evaluate_with_approval(intent, envelope)
        self.assertEqual(decision.outcome, "allow")
        self.assertTrue(fx.client.consume(decision.permit, intent))

    def test_directive_lifecycle_and_budget_across_boundary(self):
        fx = BoundaryFixture()
        d = directive(aggregate_budget=8, budget_scope=("directive",))
        activation = fx.client.activate_directive(
            d, fx.envelope_for("activate_directive", d, "act-1"), operator_principal=OPERATOR
        )
        self.assertEqual(activation.outcome, "allow")
        self.assertEqual(
            fx.client.directive_status(d.directive_id, d.version, d.directive_hash), "active"
        )
        intent = Intent("agent:builder", "write", "repo:core", 5, "s1")
        first = fx.client.projection_evaluate(intent, d)
        self.assertEqual(first.outcome, "allow")
        self.assertTrue(fx.client.consume(first.permit, intent))
        scope_key = d.budget_scope_key(intent)
        self.assertEqual(fx.client.budget_spent(scope_key), 5)
        # Second spend of 5 crosses the aggregate budget of 8: the
        # projection's early check refuses issuance across the wire.
        second = fx.client.projection_evaluate(intent, d)
        self.assertEqual(second.outcome, "deny")
        self.assertEqual(second.reason, "directive_aggregate_budget_exceeded")
        # Revocation across the boundary ends the directive.
        revocation = fx.client.revoke_directive(
            d, fx.envelope_for("revoke_directive", d, "rev-1"), operator_principal=OPERATOR
        )
        self.assertEqual(revocation.outcome, "allow")
        self.assertEqual(
            fx.client.directive_status(d.directive_id, d.version, d.directive_hash),
            "directive_revoked",
        )
        after = fx.client.projection_evaluate(intent, d)
        self.assertEqual(after.outcome, "deny")

    def test_locked_target_completion_across_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = BoundaryFixture(artifact_roots=[tmp])
            intent = Intent("agent:builder", "write", "repo:core", 1, "s1")
            target = fx.client.lock_target("deploy-1", intent, version=1)
            fetched = fx.client.get_locked_target("deploy-1", version=1)
            self.assertEqual(fetched.target_hash, target.target_hash)
            resolution, decision = fx.client.evaluate_locked_target("deploy-1", target.target_hash, version=1)
            self.assertEqual(resolution.outcome, "match")
            self.assertEqual(decision.outcome, "allow")
            artifact = Path(tmp) / "artifact.bin"
            artifact.write_bytes(b"governed-bytes")
            completion = fx.client.record_target_completion(
                target_id="deploy-1",
                version=1,
                target_hash=target.target_hash,
                intent_hash=fx.kernel.intent_hash(intent),
                artifact_path=str(artifact),
                timestamp_ns=NOW + 1,
            )
            self.assertEqual(completion["artifact_sha256"], sha256(b"governed-bytes").hexdigest())
            with self.assertRaises(ServiceRefusal) as caught:
                fx.client.record_target_completion(
                    target_id="deploy-1",
                    version=1,
                    target_hash="0" * 64,
                    intent_hash=fx.kernel.intent_hash(intent),
                    artifact_path=str(artifact),
                    timestamp_ns=NOW + 2,
                )
            self.assertEqual(str(caught.exception), "target_hash_mismatch")

    def test_outcome_memory_invented_payload_refused_across_boundary(self):
        fx = BoundaryFixture()
        transition = sha256(b"invented-transition").hexdigest()
        identity = {
            "schema": "pulpo.domain-outcome-memory.v0",
            "attempt_id": "attempt-forged-v0",
            "order_hash": sha256(b"invented-order").hexdigest(),
            "target_hash": sha256(b"invented-target").hexdigest(),
            "intent_hash": sha256(b"invented-intent").hexdigest(),
            "policy_hash": fx.client.policy_hash(),
            "observation_hash": sha256(b"invented-observation").hexdigest(),
            "reconciliation_transition_hash": transition,
            "reconciliation_epoch": 1,
            "reconciliation_outcome": "success",
            "classification": "SUCCESS_VERIFIED",
            "reason": "external_consequence_verified",
            "reusable": True,
            "authority_effect": "none",
            "governed_effect": "canonical_outcome_memory",
        }
        payload = {**identity, "memory_id": sha256(_canonical(identity)).hexdigest(), "recorded_at_ns": NOW}
        before = fx.audit_len()
        with self.assertRaises(ServiceRefusal) as caught:
            fx.client.record_domain_outcome_memory(
                reconciliation_transition_hash=transition, payload=payload, timestamp_ns=NOW
            )
        self.assertTrue(str(caught.exception).startswith("outcome_memory_"))
        self.assertEqual(fx.audit_len(), before)


class AdversarialBoundaryTests(unittest.TestCase):
    def raw_request(self, fx, verb, args, *, secret=SERVICE_SECRET, credential_id=CREDENTIAL_ID, nonce="raw-1", issued=NOW, ttl=400_000):
        import hmac as hmac_module

        body = {
            "schema": "pulpo.service.request.v1",
            "credential_id": credential_id,
            "verb": verb,
            "nonce": nonce,
            "issued_at_ns": issued,
            "expires_at_ns": issued + ttl,
            "args": args,
        }
        body["mac"] = hmac_module.new(
            secret, b"pulpo.service.request.v1\n" + _canonical(body), sha256
        ).hexdigest()
        return _canonical(body)

    def test_repro_a_client_side_backend_governs_nothing_canonical(self):
        fx = BoundaryFixture()
        # The 3A repro A shape, in the client process: construct a
        # backend directly and spend against it. It works — against
        # its own island. The canonical store must not move.
        island = GovernanceKernel(
            fx.kernel.policy,
            b"kernel-secret",
            approval_verifier=fx.verifier,
            clock=fx.clock,
            state=InMemoryKernelState(),
        )
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        island_decision = island.evaluate(intent)
        self.assertTrue(island.consume(island_decision.permit, intent))
        before = fx.audit_len()
        self.assertEqual(fx.audit_len(), before)
        canonical = fx.client.evaluate(intent)
        self.assertEqual(canonical.outcome, "allow")
        self.assertTrue(fx.client.consume(canonical.permit, intent))

    def test_repro_b3_fabricated_evidence_has_no_surface(self):
        fx = BoundaryFixture()
        d = directive()
        # A fabricated envelope (invented signature) plus a smuggled
        # authority_evidence argument: the server runs its controller
        # over the envelope, which does not verify, and the smuggled
        # field is not part of any verb's arguments.
        intent = fx.controller.authority_intent("activate_directive", d, operator_principal=OPERATOR)
        forged = signed_envelope(
            fx.kernel, intent, fx.verifier, now_ns=NOW - 10, approval_id="forged-1", nonce="forged-1-nonce"
        )
        from dataclasses import replace

        forged = replace(forged, signature="0" * 64)
        args = {
            "directive": directive_to_dict(d),
            "envelope": {field: getattr(forged, field) for field in forged.__dataclass_fields__},
            "operator_principal": OPERATOR,
            "session_id": "default",
            "parent_directive": None,
            "authority_evidence": {"operation": "activate_directive", "approver": "no-one"},
        }
        raw = self.raw_request(fx, "activate_directive", args)
        response = json.loads(fx.service.handle(raw))
        self.assertTrue(response["ok"])  # a governed deny is a successful refusal path
        self.assertEqual(response["result"]["outcome"], "deny")
        self.assertNotEqual(
            fx.client.directive_status(d.directive_id, d.version, d.directive_hash), "active"
        )

    def test_repro_c_no_append_verb(self):
        fx = BoundaryFixture()
        before = fx.audit_len()
        raw = self.raw_request(fx, "append", {"event": "decision", "payload": {"forged": True}})
        response = json.loads(fx.service.handle(raw))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "unknown_verb")
        self.assertEqual(fx.audit_len(), before)
        self.assertTrue(fx.client.verify_audit())

    def test_wrong_secret_and_tampered_args_refused_without_state_change(self):
        fx = BoundaryFixture()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        before = fx.audit_len()
        raw = self.raw_request(
            fx,
            "evaluate",
            {"intent": {"principal": "agent:builder", "action": "write", "resource": "repo:core", "cost": 3, "session_id": "s1"}},
            secret=b"the-wrong-secret",
        )
        response = json.loads(fx.service.handle(raw))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "request_mac_invalid")
        # Tamper with a MAC'd request: change the cost, keep the MAC.
        good = json.loads(
            self.raw_request(
                fx,
                "evaluate",
                {"intent": {"principal": "agent:builder", "action": "write", "resource": "repo:core", "cost": 3, "session_id": "s1"}},
                nonce="raw-2",
            )
        )
        good["args"]["intent"]["cost"] = 1
        response = json.loads(fx.service.handle(_canonical(good)))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "request_mac_invalid")
        self.assertEqual(fx.audit_len(), before)
        self.assertEqual(intent.cost, 3)

    def test_replayed_request_refused(self):
        fx = BoundaryFixture()
        transport = loopback_transport(fx.service)
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = fx.client.evaluate(intent)
        # Capture one raw consume frame and deliver it twice.
        captured = []
        recording_client = KernelServiceClient(
            lambda raw: (captured.append(raw), transport(raw))[1],
            CREDENTIAL_ID,
            SERVICE_SECRET,
            clock=fx.clock,
            request_ttl_ns=400_000,
        )
        self.assertTrue(recording_client.consume(decision.permit, intent))
        replay = json.loads(transport(captured[0]))
        self.assertFalse(replay["ok"])
        self.assertEqual(replay["error"], "request_replayed")

    def test_unknown_credential_refused(self):
        fx = BoundaryFixture()
        before = fx.audit_len()
        raw = self.raw_request(
            fx, "verify_audit", {}, credential_id="client:ghost", secret=b"ghost-secret"
        )
        response = json.loads(fx.service.handle(raw))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "request_credential_unknown")
        self.assertEqual(fx.audit_len(), before)

    def test_nonce_cache_full_of_live_nonces_fails_closed_without_eviction(self):
        fx = BoundaryFixture(nonce_cache_limit=4)
        frames = []
        for index in range(4):
            raw = self.raw_request(fx, "verify_audit", {}, nonce=f"fill-{index}")
            frames.append(raw)
            response = json.loads(fx.service.handle(raw))
            self.assertTrue(response["ok"])
        # The cache is now full of unexpired nonces. The oldest one
        # is still replay-proof: it was retained for its whole
        # validity window, not evicted to make room.
        replay = json.loads(fx.service.handle(frames[0]))
        self.assertFalse(replay["ok"])
        self.assertEqual(replay["error"], "request_replayed")
        # A fresh request is refused fail-closed rather than
        # displacing a live nonce — and it is never dispatched, so
        # the canonical audit does not move.
        before = len(fx.kernel.audit)
        fresh = self.raw_request(
            fx,
            "evaluate",
            {"intent": {"principal": "agent:builder", "action": "write", "resource": "repo:core", "cost": 3, "session_id": "s1"}},
            nonce="fill-fresh",
        )
        response = json.loads(fx.service.handle(fresh))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "request_nonce_capacity")
        self.assertEqual(len(fx.kernel.audit), before)

    def test_expired_and_not_yet_valid_requests_refused(self):
        fx = BoundaryFixture()
        raw = self.raw_request(fx, "verify_audit", {}, issued=NOW - 10_000_000, ttl=400_000)
        response = json.loads(fx.service.handle(raw))
        self.assertEqual(response["error"], "request_expired")
        raw = self.raw_request(fx, "verify_audit", {}, nonce="raw-future", issued=NOW + 10_000_000)
        response = json.loads(fx.service.handle(raw))
        self.assertEqual(response["error"], "request_not_yet_valid")

    def test_response_tampering_detected_by_client(self):
        fx = BoundaryFixture()

        def tampering_transport(raw):
            response = bytearray(fx.service.handle(raw))
            response[-20] ^= 0x01
            return bytes(response)

        client = KernelServiceClient(
            tampering_transport, CREDENTIAL_ID, SERVICE_SECRET, clock=fx.clock, request_ttl_ns=400_000
        )
        with self.assertRaises(ServiceRefusal) as caught:
            client.verify_audit()
        self.assertIn(str(caught.exception), {"response_mac_invalid", "response_malformed"})


class StructuralPinTests(unittest.TestCase):
    def test_client_holds_no_kernel_or_state(self):
        fx = BoundaryFixture()
        for value in vars(fx.client).values():
            self.assertNotIsInstance(value, KernelClass)
            self.assertNotIsInstance(value, InMemoryKernelState)
        self.assertEqual(fx.client._credential_id, CREDENTIAL_ID)
        socket_client_transport = UnixSocketTransport("/nonexistent/service.sock")
        self.assertEqual(vars(socket_client_transport), {"_path": "/nonexistent/service.sock"})

    def test_service_module_constructs_no_authority_evidence(self):
        source = (REPO_ROOT / "pulpo" / "service.py").read_text()
        self.assertNotIn("VerifiedAuthorityEvidence(", source)
        self.assertNotIn('"append"', source)

    def test_directive_serialization_preserves_hash(self):
        plain = directive()
        self.assertEqual(directive_from_dict(directive_to_dict(plain)).directive_hash, plain.directive_hash)
        budgeted = directive(aggregate_budget=8, budget_scope=("directive", "principal"))
        self.assertEqual(
            directive_from_dict(directive_to_dict(budgeted)).directive_hash, budgeted.directive_hash
        )
        tampered = directive_to_dict(plain)
        tampered["max_cost"] = 999
        with self.assertRaises(ValueError):
            directive_from_dict(tampered)


class CredentialBindingTests(unittest.TestCase):
    """Codex P1 on PR #371: a credential authenticates its holder
    for its bound principals only — the envelope's claimed principal
    is no longer self-asserted authority."""

    def test_credential_cannot_act_for_unbound_principal(self):
        fx = BoundaryFixture()
        before = len(fx.kernel.audit)
        with self.assertRaises(ServiceRefusal) as caught:
            fx.restricted_client.evaluate(Intent("agent:builder", "write", "repo:core", 3, "s1"))
        self.assertEqual(str(caught.exception), "request_principal_not_bound")
        self.assertEqual(len(fx.kernel.audit), before)
        # The same credential acting for its own bound principal works:
        # the binding is per-principal, not a per-credential verb ban.
        decision = fx.restricted_client.evaluate(
            Intent(RESTRICTED_PRINCIPAL, "write", "repo:core", 3, "s1")
        )
        self.assertEqual(decision.outcome, "allow")

    def test_second_credential_cannot_spend_first_principals_permit(self):
        fx = BoundaryFixture()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = fx.client.evaluate(intent)
        self.assertEqual(decision.outcome, "allow")
        # The restricted credential holds a valid service credential
        # and the genuine permit string — but the intent's principal
        # is outside its bound set, so the request is refused at the
        # protocol layer, before dispatch.
        with self.assertRaises(ServiceRefusal) as caught:
            fx.restricted_client.consume(decision.permit, intent)
        self.assertEqual(str(caught.exception), "request_principal_not_bound")
        # The refusal burned nothing: the permit is still spendable
        # by the credential bound to its principal.
        self.assertTrue(fx.client.consume(decision.permit, intent))

    def test_unbound_credential_configuration_fails_closed(self):
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100), b"kernel-secret", state=InMemoryKernelState()
        )
        with self.assertRaises(ValueError):
            KernelService(kernel, {})
        # A bare secret — the pre-binding shape — names no principals
        # and must never silently mean "all principals".
        with self.assertRaises(ValueError):
            KernelService(kernel, {"client:x": SERVICE_SECRET})
        with self.assertRaises(ValueError):
            KernelService(kernel, {"client:x": (SERVICE_SECRET, frozenset())})
        with self.assertRaises(ValueError):
            KernelService(kernel, {"client:x": (SERVICE_SECRET, "agent:builder")})


class ArtifactRootTests(unittest.TestCase):
    """Codex P2 on PR #371: artifact observation is confined to the
    deployment's configured roots, checked before any file is read."""

    def _locked_fixture(self, artifact_roots):
        fx = BoundaryFixture(artifact_roots=artifact_roots)
        intent = Intent("agent:builder", "write", "repo:core", 1, "s1")
        target = fx.client.lock_target("deploy-1", intent, version=1)
        return fx, intent, target

    def _completion(self, fx, intent, target, artifact_path):
        return fx.client.record_target_completion(
            target_id="deploy-1",
            version=1,
            target_hash=target.target_hash,
            intent_hash=fx.kernel.intent_hash(intent),
            artifact_path=str(artifact_path),
            timestamp_ns=NOW + 1,
        )

    def test_artifact_outside_configured_root_refused(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            fx, intent, target = self._locked_fixture([root])
            artifact = Path(outside) / "artifact.bin"
            artifact.write_bytes(b"outside-bytes")
            before = len(fx.kernel.audit)
            with self.assertRaises(ServiceRefusal) as caught:
                self._completion(fx, intent, target, artifact)
            self.assertEqual(str(caught.exception), "artifact_path_not_authorized")
            self.assertEqual(len(fx.kernel.audit), before)

    def test_artifact_traversal_escaping_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            secret_file = Path(tmp) / "secret.bin"
            secret_file.write_bytes(b"not-an-artifact")
            fx, intent, target = self._locked_fixture([root])
            traversal = root / ".." / "secret.bin"
            with self.assertRaises(ServiceRefusal) as caught:
                self._completion(fx, intent, target, traversal)
            self.assertEqual(str(caught.exception), "artifact_path_not_authorized")

    def test_artifact_refused_when_no_root_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx, intent, target = self._locked_fixture(())
            artifact = Path(tmp) / "artifact.bin"
            artifact.write_bytes(b"governed-bytes")
            with self.assertRaises(ServiceRefusal) as caught:
                self._completion(fx, intent, target, artifact)
            self.assertEqual(str(caught.exception), "artifact_roots_not_configured")


class SocketDeadlineTests(unittest.TestCase):
    """Codex P2 on PR #371: a stalled partial frame cannot hold the
    sequential serve loop; it is disconnected at the read deadline
    with nothing dispatched."""

    def test_stalled_partial_frame_disconnects_and_dispatches_nothing(self):
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100), b"kernel-secret", state=InMemoryKernelState()
        )
        service = KernelService(
            kernel, {CREDENTIAL_ID: (SERVICE_SECRET, frozenset({"agent:builder"}))}
        )
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = os.path.join(tmp, "pulpo-service.sock")
            server_thread = threading.Thread(
                target=serve_unix_socket,
                args=(service, sock_path),
                kwargs={"read_timeout_s": 0.2},
                daemon=True,
            )
            server_thread.start()
            deadline = time.time() + 10
            while not os.path.exists(sock_path):
                if time.time() > deadline:
                    self.fail("socket server did not start")
                time.sleep(0.05)
            before = len(kernel.audit)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stalled:
                stalled.connect(sock_path)
                stalled.sendall(b"\x00\x00\x00")  # partial frame header, then stall
                stalled.settimeout(10)
                # The read deadline closes the connection: recv sees
                # the close without any request being dispatched.
                self.assertEqual(stalled.recv(1), b"")
            self.assertEqual(len(kernel.audit), before)
            # The sequential loop survived the stall and still serves
            # a legitimate client.
            client = KernelServiceClient(UnixSocketTransport(sock_path), CREDENTIAL_ID, SERVICE_SECRET)
            self.assertTrue(client.verify_audit())


class SubprocessBoundaryTests(unittest.TestCase):
    def test_core_spend_path_across_a_real_process_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            sock = os.path.join(tmp, "pulpo-service.sock")
            db = os.path.join(tmp, "pulpo-state.db")
            bootstrap = Path(tmp) / "serve.py"
            bootstrap.write_text(
                "import sys\n"
                "from pulpo import GovernanceKernel, Policy\n"
                "from pulpo.service import KernelService, serve_unix_socket\n"
                "from pulpo.state import SQLiteKernelState\n"
                "policy = Policy(frozenset({'write'}), 100)\n"
                "kernel = GovernanceKernel(policy, 'kernel-secret'.encode(), state=SQLiteKernelState(sys.argv[2]))\n"
                "credentials = {'client:subprocess': (b'service-secret-test-only', frozenset({'agent:builder'}))}\n"
                "serve_unix_socket(KernelService(kernel, credentials), sys.argv[1])\n"
            )
            env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
            proc = subprocess.Popen(
                [sys.executable, str(bootstrap), sock, db],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.time() + 30
                while not os.path.exists(sock):
                    if proc.poll() is not None or time.time() > deadline:
                        self.fail("service subprocess did not start")
                    time.sleep(0.05)
                client = KernelServiceClient(UnixSocketTransport(sock), "client:subprocess", SERVICE_SECRET)
                intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
                decision = client.evaluate(intent)
                self.assertEqual(decision.outcome, "allow")
                self.assertTrue(client.consume(decision.permit, intent))
                self.assertFalse(client.consume(decision.permit, intent))
                self.assertTrue(client.verify_audit())
                self.assertGreaterEqual(len(client.audit()), 2)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
