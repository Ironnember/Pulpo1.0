"""Scenario test: the SonicWall SonicOS SAML/MFA bypass
(CVE-2026-19868, advisory SNWLID-2026-0014, 2026-11-06;
CISA Known Exploited Vulnerabilities listing
2026-11-06).

Incident (the flaw Verified -- vendor advisory plus
CISA KEV listing; exploitation Recorded -- the KEV
listing and SonicWall's statement only): SonicWall
disclosed that a user holding valid credentials for an
ALTERNATE authentication method could bypass SAML
authentication controls on SSL-VPN, skipping the MFA
that the SAML path enforces. The flaw affects Gen7
firmware up to 7.3.3-7015 and Gen8 firmware up to
8.2.2-8015, only where SAML is enabled for SSL-VPN
logins. The advisory as first published (2026-11-06)
stated there was no workaround; the 2026-11-09
revision added an interim workaround for SAML
deployments that cannot upgrade (disable or delete
active LDAP, RADIUS, and TACACS+ authentication
servers). SonicWall investigated a report indicating
potential exploitation; CISA added the CVE to the
Known Exploited Vulnerabilities catalog on 2026-11-06,
with a federal remediation due date of November 20.
No victim is named and no attack specifics are
disclosed (victim identity Unknown); exploitation is
confirmed only via the KEV listing and SonicWall's
statement.

The failure is that a credential genuine in one
authentication domain was accepted as satisfying a
different path whose whole point was the stronger
check: ``AUTHENTICATED_BY_SOME_METHOD !=
AUTHORIZED_ON_THIS_PATH``. The bypass is on the
authorization path, not the front door. A credential
for the alternate method binds no approval by the
SAML path's authority, names no accountable approver
for this act on this path, and carries no scope for
the session it was used to open: nobody on the
governed path authorized anything; a different domain
merely authenticated someone, somehow. This replay
models that counterfactual half: the same alternate-
domain credential, presented at a gateway that routes
its consequential acts through this kernel, where the
enrolled authority for the path is the SAML identity
provider's approver and approval must bind the exact
intent -- including, through the enrolled verifier
and key, the path itself.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce SonicOS,
SAML, any real identity provider, or any real
credential. The mapping (Inferred, stated here so it
can be argued with): the consequential act is the
SSL-VPN gateway establishing a VPN session -- the act
the alternate method was presented to unlock, skipping
the SAML path's MFA. The SAML+MFA path's enrolled
authority is modeled by the standard HmacTestVerifier.
The alternate authentication method is modeled by a
second HmacTestVerifier with a different key -- a
separate authentication domain whose credentials are
genuine there and enrolled nowhere on the governed
path. The alternate-domain approval appears in the
positions the incident's shape puts it in: signed as
an approval envelope for the session act (structurally
perfect, genuinely signed, by the wrong authority for
this path), and -- in the negative control -- accepted
by a fallback-accepting verifier double whose verify
succeeds under either domain's key. An inert stand-in
bearer string appears as a permit that was never
issued. A fabricated signature string is a signature
nobody made.

Setup: exactly one act is legitimate in this
scenario's positive control -- establishing a VPN
session, executed once, under a permit issued through
a verified approval envelope from the enrolled SAML
authority: the accountable per-action authorization
actually granted on the governed path. The incident's
acts are then attempted on every route the governed
path has: with no credential at all, with an act the
gateway's policy does not contain, with an inert
bearer string spent as a permit, with alternate-domain,
fabricated, and missing approval artifacts, and with
the one genuine SAML permit and envelope for a
different bounded act stretched to the session act.
The kernel must deny each one, the consequence ledger
must stay empty for all of them, and every denial must
land in the audit record. The genuine SAML approval
for the session authorizes exactly one execution of
exactly its own act, and then spends; the genuine
SAML approval for the different act does the same for
that act only.

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
evidence). It proves nothing about real SonicWall
devices, any deployed SSL-VPN gateway, or any real
SAML deployment that does not route its consequential
acts through this kernel -- a gateway that accepts an
alternate domain's credential as satisfying its SAML
path is governed by nothing here. A control not on
the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
fallback-accepting path (the incident's own class)
remains outside this evidence and open.

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

import unittest
from dataclasses import replace

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The SSL-VPN gateway's session boundary: the dispatch
# boundary the alternate-method credential fed into.
# Every intent below is an act this gateway would
# perform; a user proposes, the gateway must not
# perform anything without a permit bound to the act
# and to the path's enrolled authority.
GATEWAY = "agent:sonicwall-sslvpn"
# The session of the attempt, in the harness's naming.
# Session identity is part of the bound intent; it is
# not itself authority for anything.
SESSION = "sslvpn-session-2026-11-06"

# The governed act: establishing a VPN session on the
# SSL-VPN resource -- the act the SAML path's MFA
# guards, the act the positive control performs under a
# genuine SAML approval, and the act the alternate
# method was presented to unlock without one.
SESSION_INTENT = Intent(GATEWAY, "establish_session", "sonicwall:ssl-vpn", 25, SESSION)
# A different bounded act under the same enrolled SAML
# authority: a read of the gateway's public status
# resource. Genuine for its own act; it must not
# stretch to the session act.
STATUS_INTENT = Intent(GATEWAY, "read_resource", "sonicwall:gateway/public-status", 25, SESSION)
# An act the gateway's policy does not contain at all:
# administering the gateway -- a verb the gateway has
# never been given for anyone on this path.
ADMIN_INTENT = Intent(GATEWAY, "administer_gateway", "sonicwall:ssl-vpn", 25, SESSION)

# An inert stand-in bearer string, presented as a
# permit: it was never issued by anyone here.
INERT_PERMIT = "permit:inert:never-issued"
# A fabricated signature: a string nobody made, offered
# as an approval signature. Also inert.
FABRICATED_SIGNATURE = "signature:fabricated:made-up"

# The alternate authentication domain's key material:
# credentials genuine under this key are genuine in
# that domain only. Enrolled nowhere on the governed
# path.
ALTERNATE_KEY = b"alternate-auth-key"


class _FallbackAcceptingVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    The SonicWall shape: ``verify`` returns True if the
    signature verifies under EITHER the enrolled SAML
    key OR the alternate domain's key -- any valid
    credential from any configured method satisfies the
    path. The double's flaw is precisely domain
    confusion, not universal acceptance: a fabricated
    string verifies under neither key and is still
    denied. Test-local; never imported by runtime code.
    """

    def __init__(self) -> None:
        super().__init__()
        self._alternate = HmacTestVerifier(ALTERNATE_KEY)

    def verify(self, payload: bytes, signature: str) -> bool:
        return super().verify(payload, signature) or self._alternate.verify(
            payload, signature
        )


class SslVpnGatewayExecutor:
    """Consequences on the gateway, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's gateway did not interpose
    between an alternate-domain credential and a
    performed act: in the incident's shape, presenting an
    accepted alternate credential WAS the execution path.
    Here the harness records an effect only when the
    kernel consumes a permit for the exact intent. A
    denial is therefore directly observable as the
    absence of a governed external consequence, not
    merely as a returned status. (The denial itself still
    appends an audit record -- a governed effect,
    classified separately in the module docstring.)
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


class SonicWallSamlIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.alternate = HmacTestVerifier(ALTERNATE_KEY)
        self.kernel = self._kernel()
        self.executor = SslVpnGatewayExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"establish_session", "read_resource"}),
            10_000,
            frozenset({"establish_session", "read_resource"}),
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
        """A genuine envelope in every field but the signature.

        Every structural field -- authority, verifier,
        key, deployment, trust, session, principal,
        intent, policy, timing -- is the real one, so the
        ONLY check that can deny the attempt is the
        signature verification itself. That is the
        incident's isolation: the session machinery was
        all genuine too; the one thing presented that was
        never authority for this path was the credential
        from the other domain.
        """
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        return replace(envelope, signature=signature)

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_saml_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, SESSION_INTENT)
        # The one legitimate act: establishing the VPN
        # session under a genuine, well-formed, verified
        # approval from the enrolled SAML authority
        # executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, SESSION_INTENT))
        self.assertEqual(
            [("establish_session", "sonicwall:ssl-vpn")], self.executor.effects
        )
        # The same permit cannot perform the same act
        # twice -- a verified approval is not a standing
        # credential, however many times it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, SESSION_INTENT))
        self.assertEqual(
            [("establish_session", "sonicwall:ssl-vpn")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no credential at all, and a verb the gateway lacks ---------

    def test_step1_no_credential_and_wrong_verb_denied(self) -> None:
        # A request with no approval at all. The kernel
        # declines to mint: no approval envelope exists
        # for the session act, and the ability to reach
        # the gateway is not one.
        decision = self.kernel.evaluate(SESSION_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, SESSION_INTENT))
        # And an act the gateway's policy does not
        # contain: the policy contains no such verb for
        # anyone, so the attempt is denied outright rather
        # than held for an approval that could never
        # legitimately arrive.
        decision = self.kernel.evaluate(ADMIN_INTENT)
        self.assertEqual(
            ("deny", "action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, ADMIN_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = {
            record["payload"]["outcome"] for record in _events(self.kernel, "decision")
        }
        self.assertEqual({"require_approval", "deny"}, decisions)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: an inert bearer string, spent as a permit --------------------
    #
    # The bypass shape at the dispatch boundary: a string
    # presented as a permit that was never issued. No
    # state row stands behind it and no genuine token
    # signature does either, so consume refuses it --
    # possession of the string is not an issuance. The
    # refusal is recorded against the exact intent the
    # string was presented for.

    def test_step2_inert_bearer_permit_consumes_nothing(self) -> None:
        self.assertFalse(self.executor.execute(self.kernel, INERT_PERMIT, SESSION_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(SESSION_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # The string buys nothing on the bounded act
        # either: it is not a weaker permit for a smaller
        # act, it is not a permit at all.
        self.assertFalse(self.executor.execute(self.kernel, INERT_PERMIT, STATUS_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(STATUS_INTENT), rejected[1]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the incident's core -- alternate-domain authority ------------

    def test_step3_alternate_domain_and_fabricated_signatures_denied(self) -> None:
        # (a) The incident's core: an approval envelope
        # for the session act signed under the ALTERNATE
        # domain's key -- structurally perfect, genuinely
        # signed, by the wrong authority for this path.
        # The governed verifier computes the expected
        # signature under the ENROLLED SAML authority's
        # key; a valid signature from another domain is
        # not it. Authenticating by some method is not
        # authorization on this path.
        alternate = signed_envelope(
            self.kernel, SESSION_INTENT, self.alternate, now_ns=NOW,
            approval_id="approval-alternate", nonce="nonce-alternate",
        )
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, alternate)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A fabricated signature: a string nobody
        # made. A made-up name is not a signature, and the
        # denial is the same as for the alternate domain --
        # the governed path does not distinguish a genuine
        # credential from the wrong domain from an invented
        # one; neither is the enrolled authority's approval.
        fabricated = self._envelope_with_signature(
            self.kernel,
            SESSION_INTENT,
            FABRICATED_SIGNATURE,
            approval_id="approval-fabricated",
            nonce="nonce-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, fabricated)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) And no signature at all is its own recorded
        # denial, before verification is even attempted:
        # absence is not a weaker form of a credential.
        empty = self._envelope_with_signature(
            self.kernel,
            SESSION_INTENT,
            "",
            approval_id="approval-empty",
            nonce="nonce-empty",
        )
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, empty)
        self.assertEqual(
            ("deny", "approval_signature_missing"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(3, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the genuine article does not stretch -------------------------

    def test_step4_genuine_saml_permit_and_envelope_do_not_stretch(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel,
            STATUS_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-status",
            nonce="nonce-status",
        )
        # (a) The genuine SAML envelope for the public-
        # status read presented for the session act: even
        # the RIGHT authority's approval for a bounded act
        # is not approval for the consequential one. Path
        # binding (step 3) and intent binding (this step)
        # are separate refusals.
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine article admitted for its own
        # act, then the issued permit presented against
        # the session act at the dispatch boundary:
        # exact-intent binding refuses the spend, and the
        # refusal names the mismatch.
        permit = self._issue_permit(
            self.kernel, STATUS_INTENT, approval_id="approval-status-2", nonce="nonce-status-2"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, SESSION_INTENT))
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == self.kernel.intent_hash(SESSION_INTENT)
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_intent_mismatch", rejected[0]["payload"]["reason"])
        # (c) The denials did not poison the path: the
        # same permit still performs its own act, exactly
        # once.
        self.assertTrue(self.executor.execute(self.kernel, permit, STATUS_INTENT))
        self.assertEqual(
            [("read_resource", "sonicwall:gateway/public-status")], self.executor.effects
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, STATUS_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: the incident channel sees the attempts ----------------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit: every consume rejection, every approval
    # rejection, and every denied decision in the sequence
    # becomes a near-miss record in the derived incident
    # report. The bare require_approval decision is in the
    # canonical audit (and counted below) but is NOT
    # derived as a near-miss -- the expected near-miss
    # count is built from the event classes the channel
    # actually derives, so this test pins the boundary
    # instead of papering over it.
    #
    # The frozen sequence is the full attempt sequence
    # exercisable on one kernel, in the incident's own
    # order: the no-credential probe, the wrong-verb
    # probe, the inert bearer string spent as a permit,
    # the alternate-domain envelope offered for the
    # session act, the genuine SAML envelope stretched to
    # the session act, the genuine SAML session permit
    # spent against a different act, the one legitimate
    # session execution, and the spent-permit replay.

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        decision = self.kernel.evaluate(SESSION_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(ADMIN_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(self.executor.execute(self.kernel, INERT_PERMIT, SESSION_INTENT))
        alternate = signed_envelope(
            self.kernel, SESSION_INTENT, self.alternate, now_ns=NOW,
            approval_id="approval-seq-alternate", nonce="nonce-seq-alternate",
        )
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, alternate)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_envelope = signed_envelope(
            self.kernel,
            STATUS_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        permit = self._issue_permit(
            self.kernel, SESSION_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, STATUS_INTENT))
        # The one legitimate execution still lands; the
        # bypass attempts did not.
        self.assertTrue(self.executor.execute(self.kernel, permit, SESSION_INTENT))
        self.assertEqual(
            [("establish_session", "sonicwall:ssl-vpn")], self.executor.effects
        )
        # The spent permit re-presented: a verified
        # approval is single-use, not a credential that
        # keeps working for as long as it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, SESSION_INTENT))
        self.assertEqual(
            [("establish_session", "sonicwall:ssl-vpn")], self.executor.effects
        )

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report
        # appends nothing.
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
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The require_approval decision above is an
        # audit-recorded attempt that contributes zero
        # near-miss records at this commit.
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

    def test_negative_control_fallback_acceptance_would_execute(self) -> None:
        # Same scenario, one component swapped: a verifier
        # that accepts a signature verifying under EITHER
        # the enrolled SAML key OR the alternate domain's
        # key -- the SonicWall shape, in which any valid
        # credential from any configured method satisfies
        # the path. The alternate-domain envelope for the
        # session act VERIFIES, a permit mints, and the
        # session EXECUTES -- with no MFA-path approval
        # ever existing. That is the incident, reproduced
        # at the exact layer it happened: not the network,
        # not the executor -- the verification comparison.
        # The denials in the steps above therefore come
        # from the governed verification's shape (an
        # accountable approval whose signature is computed
        # under the enrolled path authority's key only,
        # bound to the exact intent), not from a harness
        # that denies by construction.
        double = _FallbackAcceptingVerifier()
        blind_kernel = self._kernel(verifier=double)
        alternate = signed_envelope(
            blind_kernel,
            SESSION_INTENT,
            self.alternate,
            now_ns=NOW,
            approval_id="approval-nc-alternate",
            nonce="nonce-nc-alternate",
        )
        decision = blind_kernel.evaluate_with_approval(SESSION_INTENT, alternate)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, SESSION_INTENT))
        self.assertEqual(
            [("establish_session", "sonicwall:ssl-vpn")], self.executor.effects
        )
        # Under the same double, a fabricated string is
        # still denied: it verifies under neither key. The
        # double's flaw is precisely domain confusion, not
        # universal acceptance.
        fabricated = signed_envelope(
            blind_kernel,
            SESSION_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-fabricated",
            nonce="nonce-nc-fabricated",
        )
        fabricated = replace(fabricated, signature=FABRICATED_SIGNATURE)
        decision = blind_kernel.evaluate_with_approval(SESSION_INTENT, fabricated)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Contrast, the identical alternate-domain envelope
        # against the governed kernel: denied (step 3a's
        # route).
        governed = signed_envelope(
            self.kernel, SESSION_INTENT, self.alternate, now_ns=NOW,
            approval_id="approval-nc-contrast", nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(SESSION_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
