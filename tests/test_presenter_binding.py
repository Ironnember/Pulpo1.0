"""Phase 3, Item 4B — presenter binding (token v3).

The gap (Phase 2, Item 4 record §5; revocation-evidence record §5):
a permit was a bearer <redacted> inside its TTL window — possession of
the token string plus the exact intent spent it, whoever presented
it. Item 4 bounded the window; the presenter was unbound, and 4B was
recorded as required before any cross-domain consumer is claimed
governed.

The fix pinned here: a permit may be bound at issuance to one
registered presenter identity; the token's signed claims (v3) carry
the identity's hash, and consume requires that presenter's proof —
a signature over the exact token and intent digest — verified
against the verifier registered for the identity. Policies may
require binding (``require_presenter_binding``), which retires the
bearer posture for that policy: unbound permits are neither minted
nor spent. Default policies keep the v2 bearer posture, and v2
token strings fail closed at the cutover.

Honesty label: presenter verifiers here are same-process HMAC test
doubles (tests/presenter_support.py), as with the approval
fixtures.
"""

from __future__ import annotations

from hashlib import sha256
import hmac
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.presenter_support import HmacPresenterVerifier, proof_for


NOW = 2_000_000
SECRET = b"kernel-secret"
INTENT = Intent("agent:builder", "write", "repo:core", 3, "s1")
PRESENTER = "executor:prod"
OTHER = "executor:other"


def make_kernel(policy=None, state=None, verifiers=True):
    registry = None
    if verifiers:
        registry = {
            PRESENTER: HmacPresenterVerifier(b"presenter-secret"),
            OTHER: HmacPresenterVerifier(b"other-secret"),
        }
    return GovernanceKernel(
        policy or Policy(frozenset({"write"}), 100),
        SECRET,
        clock=lambda: NOW,
        state=state if state is not None else InMemoryKernelState(),
        presenter_verifiers=registry,
    )


def rejection_reasons(kernel):
    return [
        record["payload"]["reason"]
        for record in kernel.audit
        if record["event"] == "permit_rejected"
    ]


class TruthyPresenterVerifier:
    """A misbehaving presenter verifier: verify() returns 1.

    Truthy, but not the literal True — the Codex P1 shape. Under
    the pre-fix gate this return spent the permit.
    """

    def verify(self, payload, signature):
        return 1


class BoundConsumeTests(unittest.TestCase):
    def test_bound_permit_spends_for_its_presenter_with_valid_proof(self):
        kernel = make_kernel()
        decision = kernel.evaluate(INTENT, presenter=PRESENTER)
        self.assertEqual(decision.outcome, "allow")
        proof = proof_for(kernel, kernel._presenter_verifiers[PRESENTER], decision.permit, INTENT, PRESENTER)
        self.assertTrue(
            kernel.consume(decision.permit, INTENT, presenter=PRESENTER, presenter_proof=proof)
        )
        # Single-use still holds after a bound spend.
        self.assertFalse(
            kernel.consume(decision.permit, INTENT, presenter=PRESENTER, presenter_proof=proof)
        )

    def test_missing_proof_refused_and_permit_not_burned(self):
        kernel = make_kernel()
        token = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        self.assertFalse(kernel.consume(token, INTENT))
        self.assertFalse(kernel.consume(token, INTENT, presenter=PRESENTER))
        self.assertEqual(
            rejection_reasons(kernel),
            ["permit_presenter_proof_required", "permit_presenter_proof_required"],
        )
        proof = proof_for(kernel, kernel._presenter_verifiers[PRESENTER], token, INTENT, PRESENTER)
        self.assertTrue(kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof))

    def test_wrong_presenter_refused_and_permit_not_burned(self):
        # The stolen-token case: the attacker holds the token string
        # and the exact intent, and is itself a registered presenter
        # with a valid key — for its own identity, not the bound one.
        kernel = make_kernel()
        token = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        attacker_proof = proof_for(
            kernel, kernel._presenter_verifiers[OTHER], token, INTENT, OTHER
        )
        self.assertFalse(
            kernel.consume(token, INTENT, presenter=OTHER, presenter_proof=attacker_proof)
        )
        self.assertEqual(rejection_reasons(kernel), ["permit_presenter_mismatch"])
        proof = proof_for(kernel, kernel._presenter_verifiers[PRESENTER], token, INTENT, PRESENTER)
        self.assertTrue(kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof))

    def test_proof_under_wrong_key_refused(self):
        kernel = make_kernel()
        token = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        forged = proof_for(kernel, HmacPresenterVerifier(b"not-the-key"), token, INTENT, PRESENTER)
        self.assertFalse(
            kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=forged)
        )
        self.assertEqual(rejection_reasons(kernel), ["permit_presenter_mismatch"])

    def test_proof_is_bound_to_the_exact_permit_and_intent(self):
        kernel = make_kernel()
        first = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        other_intent = Intent("agent:builder", "write", "repo:core", 3, "s2")
        second = kernel.evaluate(other_intent, presenter=PRESENTER).permit
        proof_first = proof_for(
            kernel, kernel._presenter_verifiers[PRESENTER], first, INTENT, PRESENTER
        )
        # A proof captured for one permit/intent verifies for no other.
        self.assertFalse(
            kernel.consume(second, other_intent, presenter=PRESENTER, presenter_proof=proof_first)
        )
        self.assertEqual(rejection_reasons(kernel), ["permit_presenter_mismatch"])
        self.assertTrue(
            kernel.consume(first, INTENT, presenter=PRESENTER, presenter_proof=proof_first)
        )

    def test_tampered_presenter_claim_is_inauthentic(self):
        kernel = make_kernel()
        token = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        parts = token.split(":")
        parts[4] = sha256(OTHER.encode()).hexdigest()
        forged = ":".join(parts)
        self.assertFalse(kernel.consume(forged, INTENT, presenter=OTHER, presenter_proof="x"))
        self.assertEqual(rejection_reasons(kernel), ["permit_signature_invalid"])
        # The genuine token is untouched by the attempt.
        proof = proof_for(kernel, kernel._presenter_verifiers[PRESENTER], token, INTENT, PRESENTER)
        self.assertTrue(kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof))

    def test_bound_permit_unverifiable_without_a_registered_verifier(self):
        state = InMemoryKernelState()
        issuer = make_kernel(state=state)
        token = issuer.evaluate(INTENT, presenter=PRESENTER).permit
        bare = make_kernel(state=state, verifiers=False)
        proof = proof_for(issuer, issuer._presenter_verifiers[PRESENTER], token, INTENT, PRESENTER)
        self.assertFalse(bare.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof))
        self.assertEqual(rejection_reasons(bare), ["permit_presenter_unverifiable"])

    def test_truthy_verifier_result_refused_and_permit_not_burned(self):
        # Codex P1 on PR #373: the gate accepted any truthy
        # verify() return. A return of 1 is not the literal True,
        # so the verifier has not verified: the refusal is
        # permit_presenter_unverifiable, and the permit survives
        # for a subsequent spend under a proper verifier.
        kernel = make_kernel()
        token = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        proof = proof_for(
            kernel, kernel._presenter_verifiers[PRESENTER], token, INTENT, PRESENTER
        )
        kernel._presenter_verifiers[PRESENTER] = TruthyPresenterVerifier()
        self.assertFalse(
            kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof)
        )
        self.assertEqual(rejection_reasons(kernel), ["permit_presenter_unverifiable"])
        kernel._presenter_verifiers[PRESENTER] = HmacPresenterVerifier(b"presenter-secret")
        self.assertTrue(
            kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof)
        )


class IssuanceBindingTests(unittest.TestCase):
    def test_unregistered_presenter_is_not_minted(self):
        kernel = make_kernel()
        decision = kernel.evaluate(INTENT, presenter="executor:ghost")
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "presenter_not_registered")
        self.assertIsNone(decision.permit)

    def test_presenter_without_any_registry_is_not_minted(self):
        kernel = make_kernel(verifiers=False)
        decision = kernel.evaluate(INTENT, presenter=PRESENTER)
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "presenter_not_registered")

    def test_bearer_posture_unchanged_under_default_policy(self):
        kernel = make_kernel()
        token = kernel.evaluate(INTENT).permit
        self.assertTrue(kernel.consume(token, INTENT))


class RequiringPolicyTests(unittest.TestCase):
    def policy(self):
        return Policy(frozenset({"write"}), 100, require_presenter_binding=True)

    def test_unbound_issuance_denied_and_recorded(self):
        kernel = make_kernel(policy=self.policy())
        decision = kernel.evaluate(INTENT)
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "presenter_binding_required")
        self.assertIsNone(decision.permit)
        decisions = [r for r in kernel.audit if r["event"] == "decision"]
        self.assertEqual(decisions[-1]["payload"]["reason"], "presenter_binding_required")

    def test_bound_issuance_and_spend_under_requiring_policy(self):
        kernel = make_kernel(policy=self.policy())
        token = kernel.evaluate(INTENT, presenter=PRESENTER).permit
        self.assertIsNotNone(token)
        proof = proof_for(kernel, kernel._presenter_verifiers[PRESENTER], token, INTENT, PRESENTER)
        self.assertTrue(kernel.consume(token, INTENT, presenter=PRESENTER, presenter_proof=proof))

    def test_unbound_token_refused_at_consume_under_requiring_policy(self):
        # A bearer token minted by a sibling kernel (same secret and
        # state, non-requiring policy) is refused by the requiring
        # kernel: the requirement is enforced at both ends.
        state = InMemoryKernelState()
        bearer_issuer = make_kernel(state=state)
        token = bearer_issuer.evaluate(INTENT).permit
        requiring = make_kernel(policy=self.policy(), state=state)
        self.assertFalse(requiring.consume(token, INTENT))
        self.assertEqual(rejection_reasons(requiring), ["permit_presenter_unbound"])

    def test_requiring_policy_hashes_differently(self):
        default = Policy(frozenset({"write"}), 100)
        requiring = self.policy()
        self.assertNotEqual(
            GovernanceKernel(default, SECRET, clock=lambda: NOW).policy_hash,
            GovernanceKernel(requiring, SECRET, clock=lambda: NOW).policy_hash,
        )


class CutoverTests(unittest.TestCase):
    def test_v2_token_refused_at_the_cutover(self):
        # A genuine v2 token (five fields, HMAC over the first four)
        # with a real store row: refused, never silently accepted —
        # the Item 4 precedent applied to v2.
        state = InMemoryKernelState()
        kernel = make_kernel(state=state)
        digest = kernel.intent_hash(INTENT)
        nonce = "cd" * 16
        issued = NOW - 10
        expires = NOW + 3600
        signature = hmac.new(
            SECRET, f"{digest}:{nonce}:{issued}:{expires}".encode(), sha256
        ).hexdigest()
        token = f"{digest}:{nonce}:{issued}:{expires}:{signature}"
        state.issue_permit(token, digest, "policy_satisfied", issued, expires_at_ns=expires)
        self.assertFalse(kernel.consume(token, INTENT))
        self.assertEqual(rejection_reasons(kernel), ["permit_signature_invalid"])


class GovernedPathBindingTests(unittest.TestCase):
    def test_approval_path_binds_the_presenter(self):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write"}),
            100,
            frozenset({"write"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            SECRET,
            approval_verifier=verifier,
            clock=lambda: NOW,
            presenter_verifiers={PRESENTER: HmacPresenterVerifier(b"presenter-secret")},
        )
        envelope = signed_envelope(
            kernel, INTENT, verifier, now_ns=NOW - 10, approval_id="ap-1", nonce="n-1"
        )
        decision = kernel.evaluate_with_approval(INTENT, envelope, presenter=PRESENTER)
        self.assertEqual(decision.outcome, "allow")
        self.assertFalse(kernel.consume(decision.permit, INTENT))
        proof = proof_for(
            kernel, kernel._presenter_verifiers[PRESENTER], decision.permit, INTENT, PRESENTER
        )
        self.assertTrue(
            kernel.consume(decision.permit, INTENT, presenter=PRESENTER, presenter_proof=proof)
        )

    def test_projection_passes_the_presenter_through(self):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            SECRET,
            approval_verifier=verifier,
            clock=lambda: NOW,
            presenter_verifiers={PRESENTER: HmacPresenterVerifier(b"presenter-secret")},
        )
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        d = Directive(
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
        authority_intent = controller.authority_intent(
            "activate_directive", d, operator_principal="operator:owner"
        )
        envelope = signed_envelope(
            kernel, authority_intent, verifier, now_ns=NOW - 10, approval_id="act-1", nonce="an-1"
        )
        activated = controller.activate(d, envelope, operator_principal="operator:owner")
        self.assertEqual(activated.outcome, "allow")
        decision = projection.evaluate(INTENT, d, presenter=PRESENTER)
        self.assertEqual(decision.outcome, "allow")
        self.assertFalse(kernel.consume(decision.permit, INTENT))
        proof = proof_for(
            kernel, kernel._presenter_verifiers[PRESENTER], decision.permit, INTENT, PRESENTER
        )
        self.assertTrue(
            kernel.consume(decision.permit, INTENT, presenter=PRESENTER, presenter_proof=proof)
        )


if __name__ == "__main__":
    unittest.main()
