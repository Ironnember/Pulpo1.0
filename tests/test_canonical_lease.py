"""Canonical Lease port, PR 1 — kernel-bound physical actuation leases.

The failure addressed (diff check §5.4): the Autonomous physical
layer's leases were locally mintable dataclasses — any caller could
construct one and an execution tracker would act on it without a
kernel permit ever being issued. PR 1 is the binding: a lease is
minted only by the kernel, from an evaluated intent under an active
directive, always bound to a named device presenter, with its full
claim set inside the signed token's digest.

Acceptance tests are numbered as in the port spec §11: test 1
(forged lease), 2 (replay), 4 (expiry), 6 (command swap), and —
added on external review — 11 (modified signed lease), 12 (wrong
presenter), 13 (positive control: legitimate authority passes, up
to the budget). A system that rejects everything is trivially
"secure"; test 13 is the proof the boundary also admits.

Two further classes pin the Codex review fixes on this PR:
LeaseApprovalBindingTests (P1 — a lease approval must bind every
authority-bearing claim the lease will carry, not only the intent)
and LeaseStoreFloorTests (P2 — the store's own consume transition
enforces the signed sequence floor in both backends, without the
kernel funnel in front of it).

Honesty label: presenter verifiers here are same-process HMAC test
doubles (tests/presenter_support.py), as with the permit fixtures.
"""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Lease, LeaseCommand, Policy
from pulpo.directives import Directive, DirectiveAuthorityController
from pulpo.kernel import DEFAULT_MAX_PERMIT_TTL_NS
from pulpo.state import AuditSigner, InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.presenter_support import HmacPresenterVerifier


NOW = 2_000_000
SECRET = b"lease-test-secret"
OPERATOR = "operator:owner"
DEVICE = "device:actuator-1"
OTHER_DEVICE = "device:actuator-2"
PAYLOAD = b"rotate-valve:open:42"
PAYLOAD_DIGEST = sha256(PAYLOAD).hexdigest()
INTENT = Intent("agent:builder", "actuate", "device:valve-1", 1, "s1")


def make_directive(**overrides):
    values = dict(
        directive_id="deploy-mine",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"actuate"}),
        resource_prefixes=("device:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


def governed_kernel(state=None, clock=None, policy=None, verifier=None):
    verifier = verifier or HmacTestVerifier()
    policy = policy or Policy(
        frozenset({"actuate", "activate_directive", "revoke_directive"}),
        100,
        frozenset({"activate_directive", "revoke_directive"}),
        authority_trust=trust_for(verifier),
    )
    registry = {
        DEVICE: HmacPresenterVerifier(b"device-secret"),
        OTHER_DEVICE: HmacPresenterVerifier(b"other-device-secret"),
    }
    kernel = GovernanceKernel(
        policy,
        SECRET,
        approval_verifier=verifier,
        clock=clock or (lambda: NOW),
        state=state if state is not None else InMemoryKernelState(),
        presenter_verifiers=registry,
    )
    return kernel, verifier


def activate(kernel, verifier, d, approval_id="activate-1", nonce="activate-nonce-1"):
    controller = DirectiveAuthorityController(kernel)
    intent = DirectiveAuthorityController.authority_intent(
        controller.ACTIVATE, d, operator_principal=OPERATOR
    )
    envelope = signed_envelope(
        kernel, intent, verifier, now_ns=NOW - 10, approval_id=approval_id, nonce=nonce
    )
    decision = controller.activate(d, envelope, operator_principal=OPERATOR)
    if decision.outcome != "allow":
        raise AssertionError(f"activation failed: {decision}")
    return controller


def issue(kernel, d, **overrides):
    params = dict(
        presenter=DEVICE,
        payload_digest=PAYLOAD_DIGEST,
        max_commands=3,
        max_disconnected_ns=600_000_000_000,
        safe_fallback="valve:close-and-hold",
        deployment_id="deployment:mine-1",
        boot_counter=7,
    )
    params.update(overrides)
    return kernel.issue_lease(INTENT, d, **params)


def command(sequence=0, **overrides):
    values = dict(
        action="actuate",
        resource="device:valve-1",
        payload_digest=PAYLOAD_DIGEST,
        sequence=sequence,
    )
    values.update(overrides)
    return LeaseCommand(**values)


def proof_for(kernel, lease, cmd, presenter=DEVICE):
    verifier = kernel._presenter_verifiers[presenter]
    payload = GovernanceKernel.lease_proof_payload(
        lease.token, cmd.command_hash, presenter, cmd.sequence
    )
    return verifier.sign(payload)


def rejection_reasons(kernel):
    return [
        record["payload"]["reason"]
        for record in kernel.audit
        if record["event"] == "lease_rejected"
    ]


def events(kernel, event):
    return [record for record in kernel.audit if record["event"] == event]


class LeaseIssuanceTests(unittest.TestCase):
    def test_lease_issues_under_active_directive_and_is_recorded(self):
        kernel, verifier = governed_kernel()
        d = make_directive()
        activate(kernel, verifier, d)
        decision = issue(kernel, d)
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.lease)
        lease = decision.lease
        self.assertEqual(lease.presenter, DEVICE)
        self.assertEqual(lease.directive_hash, d.directive_hash)
        self.assertEqual(len(lease.token.split(":")), 6)
        issued = events(kernel, "lease_issued")
        self.assertEqual(len(issued), 1)
        self.assertEqual(issued[0]["payload"]["lease_digest"], lease.lease_digest)
        self.assertEqual(issued[0]["payload"]["safe_fallback"], "valve:close-and-hold")

    def test_issuance_requires_an_active_directive(self):
        kernel, _verifier = governed_kernel()
        decision = issue(kernel, make_directive())
        self.assertEqual((decision.outcome, decision.reason), ("deny", "directive_not_authorized"))
        self.assertIsNone(decision.lease)
        denials = events(kernel, "directive_denial")
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["payload"]["reason"], "directive_not_authorized")

    def test_issuance_respects_the_directive_mandate(self):
        kernel, verifier = governed_kernel()
        d = make_directive(resource_prefixes=("other:",))
        activate(kernel, verifier, d)
        decision = issue(kernel, d)
        self.assertEqual((decision.outcome, decision.reason), ("deny", "directive_resource_not_allowed"))

    def test_issuance_requires_a_registered_presenter_and_a_fallback(self):
        kernel, verifier = governed_kernel()
        d = make_directive()
        activate(kernel, verifier, d)
        decision = issue(kernel, d, presenter=None)
        self.assertEqual((decision.outcome, decision.reason), ("deny", "presenter_binding_required"))
        decision = issue(kernel, d, presenter="device:unknown")
        self.assertEqual((decision.outcome, decision.reason), ("deny", "presenter_not_registered"))
        decision = issue(kernel, d, safe_fallback="")
        self.assertEqual((decision.outcome, decision.reason), ("deny", "lease_safe_fallback_required"))
        self.assertEqual(events(kernel, "lease_issued"), [])

    def test_lease_ttl_is_clamped_by_the_policy_cap(self):
        kernel, verifier = governed_kernel()
        d = make_directive()
        activate(kernel, verifier, d)
        decision = issue(kernel, d, ttl_ns=100 * DEFAULT_MAX_PERMIT_TTL_NS)
        self.assertEqual(decision.outcome, "allow")
        lease = decision.lease
        self.assertEqual(lease.expires_at_ns - lease.issued_at_ns, DEFAULT_MAX_PERMIT_TTL_NS)

    def test_lease_under_an_aggregate_budgeted_directive_is_refused(self):
        # PR 1 boundary: lease commands debit the lease's own budget,
        # never the directive's cumulative ceiling — issuing under a
        # budgeted directive would let actuation escape the ceiling.
        kernel, verifier = governed_kernel()
        d = make_directive(aggregate_budget=10)
        activate(kernel, verifier, d)
        decision = issue(kernel, d)
        self.assertEqual(
            (decision.outcome, decision.reason), ("deny", "lease_directive_budget_unsupported")
        )

    def test_approval_action_mints_only_through_the_approval_path(self):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"actuate", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"actuate", "activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel, _ = governed_kernel(policy=policy, verifier=verifier)
        d = make_directive()
        activate(kernel, verifier, d)
        decision = issue(kernel, d)
        self.assertEqual(
            (decision.outcome, decision.reason), ("require_approval", "approval_required")
        )
        params = dict(
            presenter=DEVICE,
            payload_digest=PAYLOAD_DIGEST,
            max_commands=2,
            max_disconnected_ns=600_000_000_000,
            safe_fallback="valve:close-and-hold",
            deployment_id="deployment:mine-1",
            boot_counter=7,
        )
        # The envelope must bind the lease approval hash of the exact
        # claim set: an envelope binding only the bare intent hash
        # (the pre-Codex-P1 shape) authenticates the intent but none
        # of the claims the lease will carry, and no longer issues.
        bare = signed_envelope(
            kernel, INTENT, verifier, now_ns=NOW - 10,
            approval_id="lease-approval-bare", nonce="lease-nonce-bare",
        )
        decision = kernel.issue_lease_with_approval(INTENT, d, bare, **params)
        self.assertEqual(
            (decision.outcome, decision.reason), ("deny", "approval_intent_mismatch")
        )
        self.assertIsNone(decision.lease)
        envelope = signed_envelope(
            kernel, INTENT, verifier, now_ns=NOW - 10,
            approval_id="lease-approval-1", nonce="lease-nonce-1",
            intent_hash=GovernanceKernel.lease_approval_hash(INTENT, d, **params),
        )
        decision = kernel.issue_lease_with_approval(INTENT, d, envelope, **params)
        self.assertEqual(decision.outcome, "allow")
        cmd = command(0)
        self.assertTrue(
            kernel.consume_lease_command(
                decision.lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, decision.lease, cmd)
            )
        )


class LeaseApprovalBindingTests(unittest.TestCase):
    """Codex P1 on PR #383: the approval binds every lease claim.

    An approval envelope authenticates the digest in its
    ``intent_hash`` field. For a lease that digest must be the lease
    approval hash of the exact claim set — otherwise a caller
    holding one genuine approval could choose an unapproved payload
    digest, an arbitrarily large command budget, a different
    presenter, or a different deployment after verification and
    still receive a genuine consumable lease.
    """

    CLAIMS = dict(
        presenter=DEVICE,
        payload_digest=PAYLOAD_DIGEST,
        max_commands=2,
        max_disconnected_ns=600_000_000_000,
        safe_fallback="valve:close-and-hold",
        deployment_id="deployment:mine-1",
        boot_counter=7,
    )

    def setUp(self):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"actuate", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"actuate", "activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        self.kernel, _ = governed_kernel(policy=policy, verifier=verifier)
        self.verifier = verifier
        self.directive = make_directive()
        activate(self.kernel, verifier, self.directive)
        self.counter = 0

    def envelope_for(self, claims):
        self.counter += 1
        return signed_envelope(
            self.kernel,
            INTENT,
            self.verifier,
            now_ns=NOW - 10,
            approval_id=f"lease-approval-{self.counter}",
            nonce=f"lease-nonce-{self.counter}",
            intent_hash=GovernanceKernel.lease_approval_hash(
                INTENT, self.directive, **claims
            ),
        )

    def test_approval_for_the_exact_claims_issues_a_consumable_lease(self):
        kernel = self.kernel
        envelope = self.envelope_for(self.CLAIMS)
        decision = kernel.issue_lease_with_approval(
            INTENT, self.directive, envelope, **self.CLAIMS
        )
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.lease)
        cmd = command(0)
        self.assertTrue(
            kernel.consume_lease_command(
                decision.lease,
                cmd,
                presenter=DEVICE,
                presenter_proof=proof_for(kernel, decision.lease, cmd),
            )
        )

    def test_each_altered_claim_under_a_genuine_approval_is_refused(self):
        kernel = self.kernel
        alterations = {
            "max_commands": 99,
            "presenter": OTHER_DEVICE,
            "deployment_id": "deployment:mine-2",
            "payload_digest": sha256(b"rotate-valve:open:43").hexdigest(),
        }
        for field, value in alterations.items():
            with self.subTest(field=field):
                altered = dict(self.CLAIMS, **{field: value})
                # A genuine, validly signed approval — for the
                # ORIGINAL claims. Issuing with any one claim altered
                # must fail the approval binding, before any lease
                # exists.
                envelope = self.envelope_for(self.CLAIMS)
                decision = kernel.issue_lease_with_approval(
                    INTENT, self.directive, envelope, **altered
                )
                self.assertEqual(
                    (decision.outcome, decision.reason),
                    ("deny", "approval_intent_mismatch"),
                )
                self.assertIsNone(decision.lease)
        self.assertEqual(events(kernel, "lease_issued"), [])


class LeaseAcceptanceTests(unittest.TestCase):
    """Spec §11 tests 1, 2, 4, 6, 11, 12, 13 (PR 1 subset)."""

    def setUp(self):
        self.kernel, self.verifier = governed_kernel()
        self.directive = make_directive()
        activate(self.kernel, self.verifier, self.directive)

    def test_1_forged_lease_fails_verification(self):
        # The Autonomous shape: a locally assembled lease object with
        # plausible claims and a fabricated token. Its digest is
        # honestly computed — the one thing the forger cannot produce
        # is the kernel's signature over it.
        kernel = self.kernel
        forged = Lease(
            intent_hash=kernel.intent_hash(INTENT),
            principal=INTENT.principal,
            action=INTENT.action,
            resource=INTENT.resource,
            payload_digest=PAYLOAD_DIGEST,
            directive_id=self.directive.directive_id,
            directive_version=self.directive.version,
            directive_hash=self.directive.directive_hash,
            parent_directive_hash=None,
            policy_hash=kernel.policy_hash,
            deployment_id="deployment:mine-1",
            presenter=DEVICE,
            session_id=INTENT.session_id,
            nonce="ab" * 16,
            max_commands=3,
            max_disconnected_ns=600_000_000_000,
            safe_fallback="valve:close-and-hold",
            sequence_floor=0,
            boot_counter=7,
            issued_at_ns=NOW,
            expires_at_ns=NOW + 100_000,
            token="placeholder",
        )
        presenter_hash = sha256(DEVICE.encode()).hexdigest()
        fabricated = (
            f"{forged.lease_digest}:{'ab' * 16}:{NOW}:{NOW + 100_000}"
            f":{presenter_hash}:{'00' * 32}"
        )
        forged = replace(forged, token=fabricated)
        cmd = command(0)
        proof = proof_for(kernel, forged, cmd)
        self.assertFalse(
            kernel.consume_lease_command(forged, cmd, presenter=DEVICE, presenter_proof=proof)
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_signature_invalid"])
        self.assertEqual(events(kernel, "lease_command_consumed"), [])

    def test_11_modified_signed_lease_is_rejected_at_the_signature_step(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive).lease
        # Alter the budget of a genuine lease without re-signing: the
        # token still authenticates the ORIGINAL digest, and the
        # recomputed digest of the altered claims no longer matches.
        inflated = replace(lease, max_commands=99)
        cmd = command(0)
        proof = proof_for(kernel, inflated, cmd)
        self.assertFalse(
            kernel.consume_lease_command(inflated, cmd, presenter=DEVICE, presenter_proof=proof)
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_signature_invalid"])
        # Altering the expiry digits fails identically.
        extended = replace(lease, expires_at_ns=lease.expires_at_ns + 10**12)
        proof = proof_for(kernel, extended, cmd)
        self.assertFalse(
            kernel.consume_lease_command(extended, cmd, presenter=DEVICE, presenter_proof=proof)
        )
        self.assertEqual(
            rejection_reasons(kernel), ["lease_signature_invalid", "lease_signature_invalid"]
        )
        # The genuine lease is untouched by the attempts.
        self.assertTrue(
            kernel.consume_lease_command(lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd))
        )

    def test_12_wrong_presenter_is_rejected_at_presenter_binding(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive).lease
        cmd = command(0)
        # A registered device with a valid key — for its own identity,
        # not the lease's named presenter.
        foreign_proof = proof_for(kernel, lease, cmd, presenter=OTHER_DEVICE)
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd, presenter=OTHER_DEVICE, presenter_proof=foreign_proof
            )
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_presenter_mismatch"])
        # The named presenter without a proof is refused too.
        self.assertFalse(kernel.consume_lease_command(lease, cmd, presenter=DEVICE))
        self.assertEqual(
            rejection_reasons(kernel),
            ["lease_presenter_mismatch", "lease_presenter_proof_required"],
        )
        # Neither attempt debited the budget: the genuine command
        # still spends as command one.
        self.assertTrue(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        consumed = events(kernel, "lease_command_consumed")
        self.assertEqual(len(consumed), 1)
        self.assertEqual(consumed[0]["payload"]["commands_used"], 1)

    def test_13_positive_control_genuine_lease_consumes_up_to_budget(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive, max_commands=3).lease
        for sequence in range(3):
            cmd = command(sequence)
            self.assertTrue(
                kernel.consume_lease_command(
                    lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
                ),
                f"genuine command {sequence} must verify and consume",
            )
        consumed = events(kernel, "lease_command_consumed")
        self.assertEqual([r["payload"]["commands_remaining"] for r in consumed], [2, 1, 0])
        self.assertTrue(kernel.verify_audit())

    def test_2_replayed_command_is_rejected(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive).lease
        cmd = command(0)
        proof = proof_for(kernel, lease, cmd)
        self.assertTrue(
            kernel.consume_lease_command(lease, cmd, presenter=DEVICE, presenter_proof=proof)
        )
        self.assertFalse(
            kernel.consume_lease_command(lease, cmd, presenter=DEVICE, presenter_proof=proof)
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_replayed"])
        # An older sequence after a newer one is a replay too.
        cmd2 = command(2)
        self.assertTrue(
            kernel.consume_lease_command(
                lease, cmd2, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd2)
            )
        )
        cmd1 = command(1)
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd1, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd1)
            )
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_replayed", "lease_replayed"])

    def test_4_expired_lease_fails_and_journals_the_fallback(self):
        clock = [NOW]
        kernel, verifier = governed_kernel(clock=lambda: clock[0])
        d = make_directive()
        activate(kernel, verifier, d)
        lease = issue(kernel, d, ttl_ns=100).lease
        clock[0] = NOW + 100
        cmd = command(0)
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_expired"])
        # Layer pin (constitutional mutation lease_expiry_check_removed):
        # the refusal above must come from the KERNEL's signed-expiry
        # check, which fires before the store is consulted (spec §4
        # step 2). A store-layer refusal carries the store transition's
        # markers (directive_status / lease_status) in its rejection
        # payload; the kernel's rejection payload never does. Without
        # this assertion the store's second layer produces an identical
        # evidence trail and the kernel check is unprovable.
        rejections = events(kernel, "lease_rejected")
        self.assertEqual(len(rejections), 1)
        self.assertNotIn("directive_status", rejections[0]["payload"])
        self.assertNotIn("lease_status", rejections[0]["payload"])
        fallbacks = events(kernel, "lease_fallback")
        self.assertEqual(len(fallbacks), 1)
        self.assertEqual(fallbacks[0]["payload"]["cause"], "lease_expired")
        self.assertEqual(fallbacks[0]["payload"]["safe_fallback"], "valve:close-and-hold")

    def test_6_same_length_command_swap_is_rejected_at_intent_binding(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive).lease
        swapped_payload = b"rotate-valve:open:43"
        self.assertEqual(len(swapped_payload), len(PAYLOAD))
        cmd = command(0, payload_digest=sha256(swapped_payload).hexdigest())
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_command_mismatch"])
        self.assertEqual(events(kernel, "lease_command_consumed"), [])

    def test_budget_exhaustion_terminates_into_the_safe_fallback(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive, max_commands=1).lease
        cmd = command(0)
        self.assertTrue(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        cmd = command(1)
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_budget_exhausted"])
        fallbacks = events(kernel, "lease_fallback")
        self.assertEqual(len(fallbacks), 1)
        self.assertEqual(fallbacks[0]["payload"]["cause"], "lease_budget_exhausted")

    def test_revoked_directive_blocks_consumption(self):
        kernel, verifier = governed_kernel()
        d = make_directive()
        controller = activate(kernel, verifier, d)
        lease = issue(kernel, d).lease
        intent = DirectiveAuthorityController.authority_intent(
            controller.REVOKE, d, operator_principal=OPERATOR
        )
        envelope = signed_envelope(
            kernel, intent, verifier, now_ns=NOW - 10,
            approval_id="revoke-1", nonce="revoke-nonce-1",
        )
        decision = controller.revoke(d, envelope, operator_principal=OPERATOR)
        self.assertEqual(decision.outcome, "allow")
        cmd = command(0)
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        rejected = events(kernel, "lease_rejected")
        self.assertEqual(rejected[-1]["payload"]["directive_status"], "directive_revoked")

    def test_sequence_floor_is_enforced(self):
        kernel = self.kernel
        lease = issue(kernel, self.directive, sequence_floor=5).lease
        cmd = command(3)
        self.assertFalse(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        self.assertEqual(rejection_reasons(kernel), ["lease_sequence_below_floor"])
        cmd = command(5)
        self.assertTrue(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )

    def test_lease_records_are_signed_when_signing_is_enabled(self):
        signer = AuditSigner(b"lease-audit-secret")
        state = InMemoryKernelState(audit_signer=signer)
        kernel, verifier = governed_kernel(state=state)
        d = make_directive()
        activate(kernel, verifier, d)
        lease = issue(kernel, d).lease
        cmd = command(0)
        self.assertTrue(
            kernel.consume_lease_command(
                lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
            )
        )
        report = kernel.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertTrue(report["signing_enabled"])


class LeaseStoreFloorTests(unittest.TestCase):
    """Codex P2 on PR #383: the store transition enforces the floor.

    These call the public ``KernelState.consume_lease_command``
    surface directly, bypassing the kernel funnel (which already
    checks the floor at spec §4 step 4). The store is a governed
    capability in its own right, so its atomic transition must
    refuse a first consume below the lease's signed sequence floor
    rather than record canonical consumption evidence outside the
    lease's sequence bounds — in both backends.
    """

    def assert_store_floor_enforced(self, kernel, directive):
        lease = issue(kernel, directive, sequence_floor=5).lease
        state = kernel._state
        self.assertFalse(
            state.consume_lease_command(
                lease.token, lease.lease_digest, lease.intent_hash, 3, NOW
            )
        )
        rejected = events(kernel, "lease_rejected")
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            rejected[0]["payload"]["reason"], "lease_sequence_below_floor"
        )
        # The refused attempt debited nothing: the first in-bounds
        # consume at the floor spends as command one.
        self.assertTrue(
            state.consume_lease_command(
                lease.token, lease.lease_digest, lease.intent_hash, 5, NOW
            )
        )
        consumed = events(kernel, "lease_command_consumed")
        self.assertEqual(len(consumed), 1)
        self.assertEqual(consumed[0]["payload"]["commands_used"], 1)

    def test_inmemory_store_rejects_first_consume_below_floor(self):
        kernel, verifier = governed_kernel()
        directive = make_directive()
        activate(kernel, verifier, directive)
        self.assert_store_floor_enforced(kernel, directive)

    def test_sqlite_store_rejects_first_consume_below_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            state = SQLiteKernelState(f"{directory}/lease-state.db")
            kernel, verifier = governed_kernel(state=state)
            directive = make_directive()
            activate(kernel, verifier, directive)
            self.assert_store_floor_enforced(kernel, directive)
            state.close()


class SQLiteLeaseTests(unittest.TestCase):
    def test_sqlite_round_trip_and_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/lease-state.db"
            state = SQLiteKernelState(path)
            kernel, verifier = governed_kernel(state=state)
            d = make_directive()
            activate(kernel, verifier, d)
            lease = issue(kernel, d).lease
            cmd = command(0)
            self.assertTrue(
                kernel.consume_lease_command(
                    lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
                )
            )
            self.assertFalse(
                kernel.consume_lease_command(
                    lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, lease, cmd)
                )
            )
            state.close()

            # Reopen: the budget and sequence counters are canonical
            # state, not process memory — command 1 spends, command 0
            # is still a replay.
            state2 = SQLiteKernelState(path)
            kernel2, _ = governed_kernel(state=state2)
            cmd1 = command(1)
            self.assertTrue(
                kernel2.consume_lease_command(
                    lease, cmd1, presenter=DEVICE, presenter_proof=proof_for(kernel2, lease, cmd1)
                )
            )
            self.assertFalse(
                kernel2.consume_lease_command(
                    lease, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel2, lease, cmd)
                )
            )
            self.assertTrue(kernel2.verify_audit())
            state2.close()

    def test_sqlite_forged_lease_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            state = SQLiteKernelState(f"{directory}/lease-state.db")
            kernel, verifier = governed_kernel(state=state)
            d = make_directive()
            activate(kernel, verifier, d)
            lease = issue(kernel, d).lease
            inflated = replace(lease, max_commands=99)
            cmd = command(0)
            self.assertFalse(
                kernel.consume_lease_command(
                    inflated, cmd, presenter=DEVICE, presenter_proof=proof_for(kernel, inflated, cmd)
                )
            )
            self.assertEqual(rejection_reasons(kernel), ["lease_signature_invalid"])
            state.close()


if __name__ == "__main__":
    unittest.main()
