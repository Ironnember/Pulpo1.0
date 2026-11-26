"""Scenario test: the Binance wallet-signing heist
(2026-10-29; Binance's initial incident report published
2026-11-03).

Incident (Recorded, from Binance's own initial incident
report): a five-month campaign. In June 2026 a Wallet
DevOps engineer downloaded a tampered Homebrew installer
while seeking a popular AI coding tool -- a supply-chain
entry; the device was replaced and credentials rotated,
but the attackers learned the wallet team's org chart.
In September a second engineer fell for a fake-recruitment
interview and ran a malicious coding "assignment" that
replaced pyenv with a poisoned binary. On Oct 20 the
attackers used a compromised machine and an internal AI
tool to take control of two engineers' computers. On
Oct 29, 17:15-19:56 (the report states this window with
no timezone; its UTC labels attach to specific
transaction times elsewhere), the attackers used
Engineer A's container-deployment token ON Engineer C's machine to
deploy a container and trigger a script that exploited
unauthorized access to the internal wallet-signing
service, moving ~$6.34B (233.46M XRP in 4 minutes;
EIP-7702 delegation abuse on ETH; a final 2,961.9 ETH at
23:56 UTC). ~$2.85B was frozen/intercepted. The FBI
attributes the campaign to DPRK (TraderTraitor), as
reported by Binance. Binance does not explain how the
internal AI tool was used for the lateral movement
(Unknown).

The failure is that authority for one act was treated
by the environment as a path to a categorically
different act: ``AUTHORIZATION_TO_DEPLOY !=
AUTHORIZATION_TO_SIGN``. A token legitimately issued
to deploy a container was used, from a different
engineer's machine, to reach the wallet-signing
service and sign transactions transferring funds --
an act no approval for deployment ever covered. A
deployment credential binds, in the incident's
environment, no effective limit the signing service
consulted: not the exact intent, not single use at
that service, and not a live revocation the signing
act would check.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Binance's
systems, the supply-chain compromises, the social
engineering, the internal AI tool, or any real token.
The mapping (Inferred, stated here so it can be argued
with): the consequential act is signing a wallet
transaction via the internal wallet-signing service --
the act the deployment token was stretched to reach.
The deployment token appears in the positions the
incident's shape puts it in: presented as a permit at
the dispatch boundary (in this scenario, a stand-in
string that was never issued here), presented as the
signature on an approval envelope, and -- in the
negative control -- held as the whole verification
check, the environment's shape in the incident. The
only route from a request to a consequence is a
successful ``GovernanceKernel.consume`` of a permit
bound to the exact intent hash: principal, action,
resource, cost, session.

Setup: exactly one act is legitimate in this scenario
-- deploying a container to the wallet infrastructure
under a genuine verified approval (the deployment
token's real purpose), executed exactly once. The
incident's act is then attempted on every route the
governed path has: with no credential at all, with an
act the policy does not contain, with the stolen
bearer-token stand-in spent as a permit, with forged
and fabricated approval artifacts, with the one
genuine deployment permit and envelope stretched to
the signing act, and with a genuine directive-bound
permit presented after its directive is revoked. The
kernel must deny each one, the consequence ledger
must stay empty for all of them, and every denial
must land in the audit record. The genuine approval
authorizes exactly one execution of exactly its own
act, and then spends.

Incident-channel surfacing (Verified at this commit,
by executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A
bare ``evaluate`` that returns ``require_approval`` --
the kernel declining to mint without approval --
appends a decision record to the canonical audit but is
NOT derived as a near-miss by the channel. The scenario
asserts both halves of that statement exactly as they
hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit
for these action classes (Verified, executable
evidence). It proves nothing about Binance's real
systems or any deployed wallet service that does not
route its consequential acts through this kernel --
a signing service that a deployment credential can
reach is governed by nothing here. The supply-chain
entry, the fake-recruitment social engineering, and
the internal AI tool's role in lateral movement are
all outside the gate; the replay models only the
authorization failure at the signing service. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
deployment-credential path to a signing act (the
incident's own class) remains outside this evidence
and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed." A denied attempt appends audit records,
counted per route: a bare evaluate returning
``require_approval`` appends one decision record; a
``consume`` rejection appends one ``permit_rejected``
record; a denied approval-envelope evaluation appends
two records -- an ``approval_rejected`` record and a
denied decision record. That growth is itself a
governed effect -- evidence production -- bounded at
two records per attempt, append-only, and it does not
alter authority (``authority_effect=none``) or
accumulate capability. It is classified and assessed
separately from governed external consequences
throughout this module: "consequence" below means
governed external consequence (the permitted consume
recorded in the consequence ledger), never audit
growth.
"""

from __future__ import annotations

import hmac
import unittest
from dataclasses import replace

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The wallet platform's dispatch boundary: every intent
# below is an act this boundary would perform; a holder
# of deployment material proposes, the boundary must not
# perform a signing act without a permit bound to it.
PLATFORM = "agent:binance-wallet-platform"
OPERATOR = "operator:owner"
SESSION = "wallet-session-2026-10-29"

# The one legitimate act: deploying a container to the
# wallet infrastructure -- the deployment token's real
# purpose, under a genuine verified approval.
LEGIT_INTENT = Intent(
    PLATFORM, "deploy_container", "binance:wallet-infra/container-deployment", 25, SESSION
)
# The incident's target act: signing a wallet
# transaction / transferring funds via the internal
# wallet-signing service -- the act no approval ever
# covered.
TARGET_INTENT = Intent(
    PLATFORM, "sign_transaction", "binance:wallet-signing-service", 25, SESSION
)
# An act the policy does not contain at all.
UNKNOWN_INTENT = Intent(
    PLATFORM, "export_signing_keys", "binance:wallet-signing-service", 25, SESSION
)

# An inert stand-in for the stolen deployment token: a
# bearer string legitimately issued (in the incident)
# for deployment, never issued by anyone here as a
# permit or an approval signature.
DEPLOYMENT_TOKEN = "token:deployment:stolen-bearer-stand-in"
# A fabricated signature string, made up by the presenter.
FABRICATED_SIGNATURE = "signature:fabricated:made-up"


class _Clock:
    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns

    def advance_to(self, now_ns: int) -> None:
        self.now_ns = now_ns


class _StandingTokenVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by possession of the deployment
    credential, the incident environment's shape: the
    deployment token itself, presented as the signature,
    is the whole check, for ANY envelope -- including an
    envelope naming the signing act. Whoever holds the
    deployment credential verifies, whatever act the
    envelope names. Under this double even the genuine
    authority's HMAC signature fails -- it is not the
    deployment token -- and a fabricated string fails
    too; only the deployment credential verifies.
    Test-local; never imported by runtime code.
    """

    stored_token = DEPLOYMENT_TOKEN

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(signature, self.stored_token)


class WalletExecutor:
    """Consequences on wallet systems, reachable only via consume.

    The harness records an effect only when the kernel
    consumes a permit for the exact intent. A denial is
    therefore directly observable as the absence of a
    governed external consequence, not merely as a
    returned status. (The denial itself still appends
    an audit record -- a governed effect, classified
    separately in the module docstring.)
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class BinanceWalletIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = WalletExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"deploy_container", "sign_transaction"}),
            10_000,
            frozenset({"deploy_container", "sign_transaction"}),
            authority_trust=trust_for(verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )

    def _issue_permit(
        self,
        kernel: GovernanceKernel,
        intent: Intent,
        *,
        approval_id: str = "approval-1",
        nonce: str = "approval-nonce-1",
    ) -> str:
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    def _envelope_with_signature(
        self,
        kernel: GovernanceKernel,
        intent: Intent,
        signature: str,
        *,
        approval_id: str,
        nonce: str,
    ):
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        return replace(envelope, signature=signature)

    # -- directive helpers for the revocation step -------------------------

    def _directive_setup(self):
        clock = _Clock(NOW)
        policy = Policy(
            frozenset({"deploy_container", "activate_directive", "revoke_directive"}),
            10_000,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
            max_permit_ttl_ns=20_000,
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=clock,
        )
        directive = Directive(
            directive_id="wallet-deployment-engagement",
            version=1,
            issuer_authority_id=self.verifier.authority_id,
            principal=PLATFORM,
            allowed_actions=frozenset({"deploy_container"}),
            resource_prefixes=("binance:wallet-infra/",),
            max_cost=100,
            issued_at_ns=NOW,
            expires_at_ns=NOW + 100_000,
        )
        return clock, kernel, directive

    def _authority_envelope(self, kernel, directive, operation, approval_id, nonce, now_ns):
        intent = DirectiveAuthorityController.authority_intent(
            operation, directive, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel, intent, self.verifier, now_ns=now_ns,
            approval_id=approval_id, nonce=nonce,
        )

    def _activate(self, kernel, directive, now_ns) -> None:
        controller = DirectiveAuthorityController(kernel)
        envelope = self._authority_envelope(
            kernel, directive, controller.ACTIVATE, "activate-1", "activate-nonce-1", now_ns
        )
        decision = controller.activate(directive, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

    def _revoke(self, kernel, directive, now_ns) -> None:
        controller = DirectiveAuthorityController(kernel)
        envelope = self._authority_envelope(
            kernel, directive, controller.REVOKE, "revoke-1", "revoke-nonce-1", now_ns
        )
        decision = controller.revoke(directive, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, LEGIT_INTENT)
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("deploy_container", "binance:wallet-infra/container-deployment")],
            self.executor.effects,
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("deploy_container", "binance:wallet-infra/container-deployment")],
            self.executor.effects,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no credential at all, and an act the policy lacks -----------

    def test_step1_no_credential_and_unknown_act_denied(self) -> None:
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, TARGET_INTENT))
        decision = self.kernel.evaluate(UNKNOWN_INTENT)
        self.assertEqual(
            ("deny", "action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, UNKNOWN_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = {
            record["payload"]["outcome"] for record in _events(self.kernel, "decision")
        }
        self.assertEqual({"require_approval", "deny"}, decisions)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the stolen deployment token, spent as a permit --------------

    def test_step2_stolen_deployment_token_consumes_nothing(self) -> None:
        self.assertFalse(self.executor.execute(self.kernel, DEPLOYMENT_TOKEN, TARGET_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TARGET_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        self.assertFalse(self.executor.execute(self.kernel, DEPLOYMENT_TOKEN, LEGIT_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(LEGIT_INTENT), rejected[1]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: forged and fabricated approval artifacts ---------------------

    def test_step3_forged_and_fabricated_approvals_denied(self) -> None:
        # (a) The deployment token offered as an approval
        # signature for the signing act.
        token_signed = self._envelope_with_signature(
            self.kernel, TARGET_INTENT, DEPLOYMENT_TOKEN,
            approval_id="approval-token", nonce="nonce-token",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, token_signed)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A made-up signature string.
        fabricated = self._envelope_with_signature(
            self.kernel, TARGET_INTENT, FABRICATED_SIGNATURE,
            approval_id="approval-fabricated", nonce="nonce-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, fabricated)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) An envelope signed with an unauthorized key.
        forged = signed_envelope(
            self.kernel, TARGET_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW,
            approval_id="approval-forged", nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, forged)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (d) No signature at all.
        empty = self._envelope_with_signature(
            self.kernel, TARGET_INTENT, "",
            approval_id="approval-empty", nonce="nonce-empty",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, empty)
        self.assertEqual(
            ("deny", "approval_signature_missing"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(4, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the genuine deployment authority does not stretch ------------

    def test_step4_genuine_deployment_permit_and_envelope_do_not_stretch(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, LEGIT_INTENT, self.verifier, now_ns=NOW,
            approval_id="approval-legit", nonce="nonce-legit",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        permit = self._issue_permit(
            self.kernel, LEGIT_INTENT, approval_id="approval-legit-2", nonce="nonce-legit-2"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, TARGET_INTENT))
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == self.kernel.intent_hash(TARGET_INTENT)
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_intent_mismatch", rejected[0]["payload"]["reason"])
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("deploy_container", "binance:wallet-infra/container-deployment")],
            self.executor.effects,
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: revocation at consume ---------------------------------------
    #
    # The governed revocation path in this kernel is
    # directive revocation: a permit bound to a directive
    # through GovernedDirectiveProjection is re-checked
    # against the directive's live status at consume.
    # Issue a genuine permit for the bounded deployment
    # act, revoke its directive through
    # DirectiveAuthorityController, then present the
    # permit: consume refuses it, and the rejection
    # record carries directive_status "directive_revoked"
    # (observed in the executed run; the store's
    # consume_permit payload names the status, not a
    # separate reason field on this route).

    def test_step5_revocation_at_consume_retires_unspent_permit(self) -> None:
        clock, kernel, directive = self._directive_setup()
        self._activate(kernel, directive, NOW)
        clock.advance_to(NOW + 100)
        decision = GovernedDirectiveProjection(kernel).evaluate(LEGIT_INTENT, directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        permit = decision.permit
        clock.advance_to(NOW + 200)
        self._revoke(kernel, directive, NOW + 200)
        self.assertEqual(
            "directive_revoked",
            kernel.directive_status(
                directive.directive_id, directive.version, directive.directive_hash
            ),
        )
        clock.advance_to(NOW + 300)
        executor = WalletExecutor()
        self.assertFalse(executor.execute(kernel, permit, LEGIT_INTENT))
        self.assertEqual([], executor.effects)
        rejected = [
            record
            for record in _events(kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == kernel.intent_hash(LEGIT_INTENT)
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("directive_revoked", rejected[0]["payload"].get("directive_status"))
        consumed_for_legit = [
            record
            for record in _events(kernel, "permit_consumed")
            if record["payload"]["intent_hash"] == kernel.intent_hash(LEGIT_INTENT)
        ]
        self.assertEqual(0, len(consumed_for_legit))
        self.assertTrue(kernel.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(UNKNOWN_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(self.executor.execute(self.kernel, DEPLOYMENT_TOKEN, TARGET_INTENT))
        fabricated = self._envelope_with_signature(
            self.kernel, TARGET_INTENT, FABRICATED_SIGNATURE,
            approval_id="approval-seq-fabricated", nonce="nonce-seq-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, fabricated)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_envelope = signed_envelope(
            self.kernel, LEGIT_INTENT, self.verifier, now_ns=NOW,
            approval_id="approval-seq-genuine", nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        permit = self._issue_permit(
            self.kernel, LEGIT_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, TARGET_INTENT))
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("deploy_container", "binance:wallet-infra/container-deployment")],
            self.executor.effects,
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("deploy_container", "binance:wallet-infra/container-deployment")],
            self.executor.effects,
        )

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertTrue(report.audit_valid)
        self.assertEqual(0, report.incidents)

        permit_rejected = _events(self.kernel, "permit_rejected")
        approval_rejected = _events(self.kernel, "approval_rejected")
        denied_decisions = [
            record
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "deny"
        ]
        require_approval_decisions = [
            record
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(3, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(3, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(8, report.near_misses)
        self.assertEqual(report.near_misses, len(report.records))
        for record in report.records:
            self.assertEqual("near_miss", record.kind)
            self.assertEqual("Recorded", record.claim_classification)
        detail_counts: dict[str, int] = {}
        for record in report.records:
            detail_counts[record.source_detail] = detail_counts.get(record.source_detail, 0) + 1
        self.assertEqual(
            {
                "permit_rejected": len(permit_rejected),
                "approval_rejected": len(approval_rejected),
                "decision": len(denied_decisions),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_standing_token_verification_would_execute(self) -> None:
        # Same scenario, one component swapped: a verifier
        # for which possession of the deployment credential
        # is the whole check. An envelope for the SIGNING
        # act "signed" with the deployment-token stand-in
        # verifies, a permit mints, and the signing act
        # EXECUTES. That is the incident's core, reproduced
        # at the exact layer it happened: the environment
        # treated deployment authority as a path to signing.
        double = _StandingTokenVerifier()
        blind_kernel = self._kernel(verifier=double)
        token_signed = signed_envelope(
            blind_kernel, TARGET_INTENT, self.verifier, now_ns=NOW,
            approval_id="approval-nc-token", nonce="nonce-nc-token",
        )
        token_signed = replace(token_signed, signature=DEPLOYMENT_TOKEN)
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, token_signed)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, TARGET_INTENT))
        self.assertEqual(
            [("sign_transaction", "binance:wallet-signing-service")], self.executor.effects
        )
        # Under the same double, nothing else gets in: a
        # fabricated string is not the deployment token,
        # and neither is the genuine authority's real HMAC
        # signature. Only the deployment credential
        # verifies, because possession is the whole check.
        for signature, approval_id in (
            (FABRICATED_SIGNATURE, "approval-nc-fabricated"),
            (None, "approval-nc-genuine"),
        ):
            attempt = signed_envelope(
                blind_kernel, TARGET_INTENT, self.verifier, now_ns=NOW,
                approval_id=approval_id, nonce=f"nonce-{approval_id}",
            )
            if signature is not None:
                attempt = replace(attempt, signature=signature)
            decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, attempt)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_signature_invalid", decision.reason)
        # Contrast, the identical token-signed envelope
        # against the governed kernel: denied (step 3a's
        # route).
        governed = self._envelope_with_signature(
            self.kernel, TARGET_INTENT, DEPLOYMENT_TOKEN,
            approval_id="approval-nc-contrast", nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
