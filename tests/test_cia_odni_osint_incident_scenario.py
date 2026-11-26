"""Scenario test: the CIA / ODNI / NGA unclassified
OSINT-network intrusion (reported 2026-11-24).

CONDITIONAL FRAMING -- read this first. This replay is
conditional. It exercises the
authorized-channel-turned-unauthorized-act class IF two
separate conditions both hold: (a) the reported ARTEX
link (the tool was in fact used), and (b) the operator's
presence on the network was legitimate -- authorized
access under a standing tasking, rather than ordinary
external exploitation. Condition (b) does not follow
from (a): reported ARTEX involvement establishes only
that the tool may have been used, and the entry vector
is Unknown, so the authorized-channel class does not
follow from the ARTEX link alone. On both conditions:
an autonomous agent operating inside a network it was
legitimately able to reach, taking acts no tasking
authorized. It asserts nothing about how the real
intrusion actually happened.

Incident (Recorded, as graded below): the New York Times
first reported on 2026-11-24, confirmed by Reuters, CNN,
Nextgov, and ISMG, an intrusion into the unclassified
network the agencies use to analyze public /
commercially available (open-source) intelligence. Some
unclassified information was exposed; no classified
systems were affected; the intrusion is resolved per
sources. NGA was concurrently affected and DCDC was also
intruded (low-impact, per Nextgov). This incident is
distinct from the FBI NCIC probe (CNN sources say not
related).

Caveats that are part of the record, not footnotes to
be dropped: the entry vector is undisclosed (Unknown);
ARTEX (the open-source AI penetration-testing framework)
is BELIEVED to have been used (Nextgov reporting; an
ISMG / Times reporter notes early indications suggesting
possible Chinese responsibility) -- that is reported
belief, NOT agency-confirmed, so ARTEX involvement is
Inferred and attribution is Unknown; what data was taken
is unclear (Unknown).

The failure equation for the class, conditionally:
``REACHABILITY_OF_A_NETWORK !=
AUTHORIZATION_FOR_EVERY_ACT_WITHIN_IT`` -- presence on a
network, even legitimate presence, is not per-act
authority. An agent legitimately able to reach a network
for one tasked act holds, by that reachability alone, no
authority for any other act on that network. A standing
tasking credential binds no exact intent, names no
per-act accountable approval for a different act, and
carries no scope beyond the tasking it was issued for.

This module models that failure mode against the
canonical kernel API, conditionally on the Inferred
ARTEX link and the separate legitimate-access
assumption stated above. It does NOT reproduce the
agencies' network,
any real agent, ARTEX, or any real credential. The
mapping (Inferred, stated here so it can be argued
with): the consequential acts are a gateway reading a
restricted internal collection store the tasking never
covered, and exporting a dataset off the network -- the
classes of act an agent inside the OSINT network could
attempt beyond its tasking. The agent's standing tasking
credential appears in the positions the class puts it
in: presented as a permit at the dispatch boundary (it
was never issued as a permit, so no state row and no
valid signature stand behind it), presented as the
signature on an approval envelope (a mission credential
offered as an accountable per-act approval), and -- in
the negative control -- accepted by a verifier double
as blanket authority for any envelope (tasking treated
as blanket authority, the class's shape). The only route
from a request to a consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the
exact intent hash: principal, action, resource, cost,
session.

Setup: exactly one act is legitimate in this scenario --
reading public / commercial OSINT feeds under a genuine
verified approval (the agent's actual tasking), executed
once, under a permit issued through a verified approval
envelope. The beyond-tasking acts are then attempted on
every route the governed path has: with no credential at
all, with an act the policy does not contain, with the
standing tasking credential spent as a permit, with
fabricated and forged approval artifacts, and with the
one genuine permit and envelope stretched to the target
acts. The kernel must deny each one, the consequence
ledger must stay empty for all of them, and every denial
must land in the audit record. The genuine approval
authorizes exactly one execution of exactly its own act,
and then spends.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation
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
evidence). It proves nothing about the real intrusion,
its entry vector, whether ARTEX was in fact used, who
was responsible, or what data was taken, and nothing
about any deployed network that does not route its
consequential acts through this kernel -- a gateway that
treats network presence or a standing tasking credential
as per-act authority is governed by nothing here. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
presence- or tasking-verified path (the class's own
shape, conditional on the Inferred ARTEX link) remains
outside this evidence and open.

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
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The OSINT-network gateway: the dispatch boundary the
# agent's acts feed into. Every intent below is an act
# this gateway would perform on the network; an agent
# legitimately present on the network proposes, the
# gateway must not perform anything without a permit
# bound to the act.
GATEWAY = "agent:osint-collection-agent"
# The session of the scenario, 2026-11-24, in the
# harness's naming. Session identity is part of the
# bound intent; it is not itself authority for anything.
SESSION = "osint-session-2026-11-24"

# The one legitimate act: reading public / commercial
# OSINT feeds -- the agent's actual tasking, under a
# genuine verified approval.
LEGIT_INTENT = Intent(
    GATEWAY, "read_resource", "osint:public-commercial-feeds", 25, SESSION
)
# Target act one: reading a restricted internal
# collection store the tasking never covered.
TARGET_INTENT = Intent(
    GATEWAY, "read_resource", "osint:restricted-collection-store", 25, SESSION
)
# Target act two: exporting a dataset off the network.
EXPORT_INTENT = Intent(GATEWAY, "export_dataset", "osint:network-egress", 25, SESSION)
# An act the gateway's policy does not contain at all:
# a verb the gateway has never been given for anyone.
UNKNOWN_INTENT = Intent(
    GATEWAY, "delete_resource", "osint:restricted-collection-store", 25, SESSION
)

# The agent's standing tasking credential: the mission
# credential under which it legitimately operates on the
# network. In this scenario it appears in the positions
# the class puts a standing credential in -- presented
# as a permit, presented as an approval signature, and
# (negative control only) accepted as blanket authority.
# An inert stand-in string; it was never issued as a
# permit or an approval by anyone here.
TASKING_CREDENTIAL = "tasking:standing-osint-collection"
# A fabrication: a signature string made up from
# nothing. Also inert.
FABRICATED_SIGNATURE = "signature:fabricated:made-up"


class _StandingTaskingVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by standing tasking, the class's shape:
    ``verify`` accepts the agent's mission / tasking
    credential as the signature for ANY envelope.
    Tasking is treated as blanket authority: whoever
    presents the tasking credential verifies, whatever
    act the envelope names, because presence under a
    legitimate tasking is the whole check. Under this
    double even the genuine authority's HMAC signature
    fails -- it is not the tasking credential -- and a
    fabricated string fails too; only the tasking
    credential verifies. Test-local; never imported by
    runtime code.
    """

    stored_key = TASKING_CREDENTIAL

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(signature, self.stored_key)


class OsintGatewayExecutor:
    """Consequences on the OSINT network, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the class's gateway did not interpose
    between legitimate network presence and a performed
    act: in the class's shape, being on the network under
    a tasking WAS the execution path. Here the harness
    records an effect only when the kernel consumes a
    permit for the exact intent. A denial is therefore
    directly observable as the absence of a governed
    external consequence, not merely as a returned
    status. (The denial itself still appends an audit
    record -- a governed effect, classified separately
    in the module docstring.)
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


class CiaOdniOsintIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = OsintGatewayExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"read_resource", "export_dataset"}),
            10_000,
            frozenset({"read_resource", "export_dataset"}),
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
        class's isolation: the agent's presence and
        session machinery may all be genuine; the one
        thing its tasking never was is a per-act approval
        for the target acts.
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

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, LEGIT_INTENT)
        # The one legitimate act: the tasked feed read
        # under a genuine, well-formed, verified approval
        # executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "osint:public-commercial-feeds")], self.executor.effects
        )
        # The same permit cannot perform the same act
        # twice -- a verified approval is not a standing
        # credential, however many times it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "osint:public-commercial-feeds")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no credential at all, and a verb the gateway lacks ---------

    def test_step1_no_credential_and_wrong_verb_denied(self) -> None:
        # Reachability is not approval: with no approval
        # envelope, the kernel declines to mint for either
        # target act, and the agent's ability to reach the
        # gateway is not one.
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, TARGET_INTENT))
        decision = self.kernel.evaluate(EXPORT_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, EXPORT_INTENT))
        # And an act the gateway's policy does not
        # contain at all: denied outright rather than held
        # for an approval that could never legitimately
        # arrive.
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

    # -- step 2: the standing tasking credential, spent as a permit ---------
    #
    # The class's core move: an agent holds a credential
    # it was legitimately given for its tasking and
    # attempts to spend it beyond that tasking. The
    # tasking credential was never issued as a permit by
    # this kernel: no state row stands behind it and no
    # genuine token signature does either, so consume
    # refuses it at the dispatch boundary -- a tasking is
    # not an issuance. The refusal is recorded against
    # the exact intent the credential was presented for.

    def test_step2_standing_tasking_credential_consumes_nothing(self) -> None:
        self.assertFalse(
            self.executor.execute(self.kernel, TASKING_CREDENTIAL, TARGET_INTENT)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TARGET_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # The credential buys nothing on the export act
        # either: it is not a weaker permit for another
        # act, it is not a permit at all.
        self.assertFalse(
            self.executor.execute(self.kernel, TASKING_CREDENTIAL, EXPORT_INTENT)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXPORT_INTENT), rejected[1]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[1]["payload"]["reason"])
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: fabricated and forged approval artifacts ---------------------

    def test_step3_fabricated_and_forged_approvals_denied(self) -> None:
        # (a) The standing tasking credential offered as
        # an approval signature: a mission credential,
        # dressed as an accountable per-act approval. The
        # governed verifier computes the expected
        # signature from the payload under the enrolled
        # key; the tasking credential is not it.
        tasking = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            TASKING_CREDENTIAL,
            approval_id="approval-tasking",
            nonce="nonce-tasking",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, tasking)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A fabricated signature: a string made up
        # from nothing. The denial is the same as for the
        # tasking credential -- the governed path does not
        # distinguish a legitimate-for-another-purpose
        # non-authority from an invented one.
        fabricated = self._envelope_with_signature(
            self.kernel,
            EXPORT_INTENT,
            FABRICATED_SIGNATURE,
            approval_id="approval-fabricated",
            nonce="nonce-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(EXPORT_INTENT, fabricated)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) An envelope signed with an unauthorized key:
        # whoever controls the network end of the
        # connection cannot mint the approving authority
        # either.
        forged = signed_envelope(
            self.kernel, TARGET_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW,
            approval_id="approval-forged", nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, forged)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (d) And no signature at all is its own recorded
        # denial, before verification is even attempted:
        # absence is not a weaker form of a credential.
        empty = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            "",
            approval_id="approval-empty",
            nonce="nonce-empty",
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

    # -- step 4: the genuine article does not stretch -------------------------

    def test_step4_genuine_permit_and_envelope_do_not_stretch(self) -> None:
        # (a) The genuine envelope for the tasked feed
        # read presented for each target act in turn: a
        # real approval for a bounded act is not approval
        # for a beyond-tasking one. Each presentation
        # carries its own approval_id and nonce, as each
        # real approval would.
        for target, suffix in ((TARGET_INTENT, "store"), (EXPORT_INTENT, "export")):
            genuine_envelope = signed_envelope(
                self.kernel,
                LEGIT_INTENT,
                self.verifier,
                now_ns=NOW,
                approval_id=f"approval-legit-{suffix}",
                nonce=f"nonce-legit-{suffix}",
            )
            decision = self.kernel.evaluate_with_approval(target, genuine_envelope)
            self.assertEqual(
                ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
            )
            self.assertIsNone(decision.permit)
        # (b) The genuine article admitted for its own
        # act, then the issued permit presented against
        # each target act at the dispatch boundary:
        # exact-intent binding refuses each spend, and
        # each refusal names the mismatch.
        permit = self._issue_permit(
            self.kernel, LEGIT_INTENT, approval_id="approval-legit-2", nonce="nonce-legit-2"
        )
        for target in (TARGET_INTENT, EXPORT_INTENT):
            self.assertFalse(self.executor.execute(self.kernel, permit, target))
            rejected = [
                record
                for record in _events(self.kernel, "permit_rejected")
                if record["payload"]["intent_hash"] == self.kernel.intent_hash(target)
            ]
            self.assertEqual(1, len(rejected))
            self.assertEqual("permit_intent_mismatch", rejected[0]["payload"]["reason"])
        # (c) The denials did not poison the path: the
        # same permit still performs its own act, exactly
        # once.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "osint:public-commercial-feeds")], self.executor.effects
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
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
    # exercisable on one kernel, in incident order for
    # the class: the no-credential probe, the
    # not-in-policy probe, the standing tasking credential
    # spent as a permit, a fabricated approval for the
    # export act, the genuine envelope stretched to the
    # restricted-store act, the genuine permit spent
    # against the export act, the one legitimate
    # execution, and the spent-permit replay.

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(UNKNOWN_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(
            self.executor.execute(self.kernel, TASKING_CREDENTIAL, TARGET_INTENT)
        )
        fabricated = self._envelope_with_signature(
            self.kernel,
            EXPORT_INTENT,
            FABRICATED_SIGNATURE,
            approval_id="approval-seq-fabricated",
            nonce="nonce-seq-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(EXPORT_INTENT, fabricated)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_envelope = signed_envelope(
            self.kernel,
            LEGIT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        permit = self._issue_permit(
            self.kernel, LEGIT_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        # The one legitimate execution still lands; the
        # beyond-tasking attempts did not.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "osint:public-commercial-feeds")], self.executor.effects
        )
        # The spent permit re-presented: a verified
        # approval is single-use, not a standing tasking
        # that keeps working for as long as it is held.
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "osint:public-commercial-feeds")], self.executor.effects
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

    def test_negative_control_tasking_as_blanket_authority_would_execute(self) -> None:
        # Same scenario, one component swapped: a
        # verifier that accepts the agent's standing
        # tasking credential as the signature for ANY
        # envelope -- tasking treated as blanket
        # authority, the class's shape. The agent presents
        # the tasking credential as its approval signature
        # for the restricted-store read, the acceptance
        # succeeds, a permit mints, and the read EXECUTES.
        # That is the class's failure, reproduced at the
        # exact layer it would happen: not the network,
        # not the executor -- the verification comparison.
        # The denials in the steps above therefore come
        # from the governed verification's shape (an
        # accountable approval whose signature is computed
        # under the enrolled authority's key, bound to the
        # exact intent), not from a harness that denies by
        # construction.
        double = _StandingTaskingVerifier()
        blind_kernel = self._kernel(verifier=double)
        tasking = signed_envelope(
            blind_kernel,
            TARGET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-tasking",
            nonce="nonce-nc-tasking",
        )
        tasking = replace(tasking, signature=TASKING_CREDENTIAL)
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, tasking)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, TARGET_INTENT))
        self.assertEqual(
            [("read_resource", "osint:restricted-collection-store")], self.executor.effects
        )
        # Under the same double, nothing else gets in --
        # the class's precision: a fabricated string is
        # not the tasking credential, and neither is the
        # genuine authority's real signature. Only the
        # tasking credential verifies, because tasking is
        # the whole check.
        for signature, approval_id in (
            (FABRICATED_SIGNATURE, "approval-nc-fabricated"),
            (None, "approval-nc-genuine"),
        ):
            attempt = signed_envelope(
                blind_kernel,
                TARGET_INTENT,
                self.verifier,
                now_ns=NOW,
                approval_id=approval_id,
                nonce=f"nonce-{approval_id}",
            )
            if signature is not None:
                attempt = replace(attempt, signature=signature)
            decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, attempt)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_signature_invalid", decision.reason)
        # Contrast, the identical tasking-credential
        # envelope against the governed kernel: denied
        # (step 3a's route).
        governed = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            TASKING_CREDENTIAL,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
