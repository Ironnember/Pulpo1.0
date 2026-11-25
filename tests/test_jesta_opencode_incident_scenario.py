"""Scenario test: the Jesta / OpenCode agent-led intrusion
attempt (attempt 2026-11-16; Jesta's report publicized
2026-11-24).

Incident (Recorded, from The Register's reporting of the
report by Jesta, a Tel Aviv security firm that builds
defensive tools against autonomous AI attacks; Jesta
declined to name the customer, a major financial services
firm): on 2026-11-16 at 4:24:57 a.m. ET, an operator in
Bucharest pointed OpenCode -- a free, open-source coding
agent, nothing in which was built for hacking -- at the
firm's systems, using only a Chrome browser and the curl
that ships with every Mac. The first request, for a
system's front page, was refused; six seconds later the
same address retried presenting itself as an Android
Pixel 10 phone, and was refused again. The agent then
asked the system for its API definition, which was also
refused -- but a different address it tried was a decoy
set up by Jesta, and the decoy answered with a readable
file defining how the API works. The agent read the
document and followed a link it contained. At 4:26:01
a.m. ET Jesta's defenses marked the visitor as an AI
agent, opened a case, and from then on everything the
agent accessed was contained inside a fake environment
built to trick intruders -- including a phony key the
environment served it. The agent worked like a developer:
it read the API docs and did what they said, included the
planted key in a command-line request, and tested three
scenarios -- using the decoy key, no key, and a
fabricated key of its own -- to determine whether what it
had found was legit. It tried multiple URLs, identified a
valid endpoint, and attempted to read from one that
accepts only data submissions, so that request was
blocked too. Five minutes and 44 seconds after the first
request it gave up; nothing was stolen, and Jesta and its
customer disclosed the activity to law enforcement. Jesta
does not know which model the attacker ran behind
OpenCode -- nothing in the traffic named it (Unknown);
OpenCode's web fetch tool named the agent itself. Jesta's
co-founder stated the counterfactual plainly: if that key
had been real, the agent would have been in.

The failure is that a discovered credential was treated
as authority: ``POSSESSION_OF_A_CREDENTIAL !=
AUTHORIZATION_FOR_THE_ACT``. The agent found a key and
used it, and in any system whose verification is
possession -- present the key, perform the act -- that is
the whole attack. A found key binds no intent, names no
accountable approver, and carries no scope: it does not
say which act, on which resource, it supposedly
authorizes, because nobody authorized anything; the key
existed to be found. What actually stopped this incident
was the decoy environment -- Jesta's control, exercised
before the agent ever reached a real system. This replay
claims nothing about that control. It models the other
half of the counterfactual: the same agent, the same
found key, the same fabricated key, pointed at a gateway
that routes its consequential acts through this kernel.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce OpenCode, the
firm's systems, the decoy environment, or any real key.
The mapping (Inferred, stated here so it can be argued
with): the consequential act is the firm's API gateway
reading customer records -- the class of act the found
key was presented to unlock. The found key appears in the
three positions the incident put it in: presented as a
permit at the dispatch boundary (it was never issued, so
no state row and no valid signature stand behind it),
presented as the signature on an approval envelope (the
agent's credential, offered as an accountable approval),
and -- in the negative control -- held as a gateway's
stored credential, the counterfactual in which the key
was real. The agent's fabricated key is a signature
string it made up. The only route from a request to a
consequence is a successful ``GovernanceKernel.consume``
of a permit bound to the exact intent hash: principal,
action, resource, cost, session.

Setup: exactly one act is legitimate in this scenario --
an authorized read of the firm's public-status resource,
executed once, under a permit issued through a verified
approval envelope: the accountable per-action
authorization actually granted to a legitimate consumer.
The incident's acts are then attempted on every route the
governed path has: with no credential at all, with an act
the gateway's policy does not contain, with the found key
spent as a permit, with fabricated and forged approval
artifacts, and with the one genuine permit and envelope
stretched to the customer-records act. The kernel must
deny each one, the consequence ledger must stay empty for
all of them, and every denial must land in the audit
record. The genuine approval authorizes exactly one
execution of exactly its own act, and then spends.

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
evidence). It proves nothing about the real firm, the
real agent run, or any deployed API gateway that does
not route its consequential acts through this kernel --
a gateway that verifies by possession is governed by
nothing here. The containment that stopped the real
incident was the firm's decoy environment, and this
replay neither reproduces nor claims it; the replay
models the gate the found key would have faced, not the
trap that actually caught the agent. A control not on
the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
possession-verified path (the incident's own class)
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
# The firm's API gateway: the dispatch boundary the
# agent's requests fed into. Every intent below is an
# act this gateway would perform on the firm's systems;
# an unauthenticated network peer proposes, the gateway
# must not perform anything without a permit bound to
# the act.
GATEWAY = "agent:jesta-target-api"
# The session of the attempt, 2026-11-16, in the
# harness's naming. Session identity is part of the
# bound intent; it is not itself authority for anything.
SESSION = "api-session-2026-11-16"

# The one legitimate act: an authorized read of the
# firm's public-status resource -- the accountable
# per-action authorization a legitimate consumer holds.
LEGIT_INTENT = Intent(GATEWAY, "read_resource", "jesta:api/public-status", 25, SESSION)
# The incident's target act: reading customer records --
# the class of act the found key was presented to
# unlock, and the act no one approved.
TARGET_INTENT = Intent(GATEWAY, "read_resource", "jesta:api/customer-records", 25, SESSION)
# An act the gateway's policy does not contain at all:
# the agent's attempt to operate an endpoint in a mode
# it does not accept (in the incident, a read against a
# submissions-only endpoint), modeled as a verb the
# gateway has never been given for anyone.
SUBMIT_INTENT = Intent(GATEWAY, "submit_data", "jesta:api/customer-records", 25, SESSION)

# The found key: the phony credential the decoy
# environment served from its API definition file. In
# this scenario it appears in the three positions the
# incident's shape puts a found key in -- presented as
# a permit, presented as an approval signature, and
# (negative control only) held as a stored credential.
# An inert stand-in; it was never issued by anyone here.
DECOY_KEY = "key:decoy:from-api-definition"
# The agent's own fabrication: a key it made up to test
# whether the lock was real. Also inert.
FABRICATED_KEY = "key:fabricated:agent-made-up"


class _PossessionVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by possession, the incident's
    counterfactual shape: the verifier holds a stored
    credential, and the stored credential is the found
    key -- the environment's own key, the one the agent
    discovered in the API definition. ``verify`` compares
    the presented signature against the stored key. Whoever
    presents the found key verifies, whatever act the
    envelope names: possession is the whole check, exactly
    the property that would have let the agent in had the
    key been real. Under this double even the genuine
    authority's HMAC signature fails -- it is not the found
    key -- and a fabricated different key fails too; only
    the discovered key verifies. Test-local; never imported
    by runtime code.
    """

    stored_key = DECOY_KEY

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(signature, self.stored_key)


class ApiGatewayExecutor:
    """Consequences on the firm's systems, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's gateway did not interpose
    between a presented key and a performed act: in the
    incident's shape, presenting an accepted key WAS the
    execution path. Here the harness records an effect
    only when the kernel consumes a permit for the exact
    intent. A denial is therefore directly observable as
    the absence of a governed external consequence, not
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


class JestaOpenCodeIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = ApiGatewayExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"read_resource"}),
            10_000,
            frozenset({"read_resource"}),
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
        incident's isolation: the agent's session
        machinery was all genuine too; the one thing it
        held that was never authority was the key.
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
        # The one legitimate act: the authorized read
        # under a genuine, well-formed, verified approval
        # executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "jesta:api/public-status")], self.executor.effects
        )
        # The same permit cannot perform the same act
        # twice -- a verified approval is not a standing
        # credential, however many times it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "jesta:api/public-status")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no credential at all, and a verb the gateway lacks ---------

    def test_step1_no_credential_and_wrong_verb_denied(self) -> None:
        # The incident's opening probes: requests with no
        # key at all. The kernel declines to mint: no
        # approval envelope exists for the customer-records
        # read, and the peer's ability to reach the gateway
        # is not one.
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, TARGET_INTENT))
        # And an act in a mode the gateway does not have:
        # the policy contains no such verb for anyone, so
        # the attempt is denied outright rather than held
        # for an approval that could never legitimately
        # arrive.
        decision = self.kernel.evaluate(SUBMIT_INTENT)
        self.assertEqual(
            ("deny", "action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, SUBMIT_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = {
            record["payload"]["outcome"] for record in _events(self.kernel, "decision")
        }
        self.assertEqual({"require_approval", "deny"}, decisions)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the discovered key, spent as a permit ------------------------
    #
    # Task step (a): the agent finds a credential it was
    # never granted and attempts to use it. The found key
    # was never issued by this kernel: no state row stands
    # behind it and no genuine token signature does
    # either, so consume refuses it at the dispatch
    # boundary -- possession of the string is not an
    # issuance. The refusal is recorded against the exact
    # intent the key was presented for.

    def test_step2_discovered_decoy_key_consumes_nothing(self) -> None:
        self.assertFalse(self.executor.execute(self.kernel, DECOY_KEY, TARGET_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TARGET_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # The key buys nothing on the legitimate act
        # either: it is not a weaker permit for a smaller
        # act, it is not a permit at all.
        self.assertFalse(self.executor.execute(self.kernel, DECOY_KEY, LEGIT_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(LEGIT_INTENT), rejected[1]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: fabricated and forged approval artifacts ---------------------

    def test_step3_fabricated_and_forged_keys_denied(self) -> None:
        # (a) The found key offered as an approval
        # signature: the agent's credential, dressed as an
        # accountable approval. The governed verifier
        # computes the expected signature from the payload
        # under the enrolled key; the found key is not it.
        found = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            DECOY_KEY,
            approval_id="approval-found-key",
            nonce="nonce-found-key",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, found)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The fabricated key: a string the agent made
        # up to test whether the lock was real. A made-up
        # name is not a signature, and the denial is the
        # same as for the found key -- the governed path
        # does not distinguish a discovered non-authority
        # from an invented one.
        fabricated = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            FABRICATED_KEY,
            approval_id="approval-fabricated",
            nonce="nonce-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, fabricated)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) An envelope signed with an unauthorized key:
        # whoever controls the network end of the
        # connection cannot mint the firm's authority
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
        genuine_envelope = signed_envelope(
            self.kernel,
            LEGIT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-legit",
            nonce="nonce-legit",
        )
        # (a) The genuine envelope for the public-status
        # read presented for the customer-records read: a
        # real approval for a bounded act is not approval
        # for the consequential one.
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine article admitted for its own
        # act, then the issued permit presented against
        # the target act at the dispatch boundary:
        # exact-intent binding refuses the spend, and the
        # refusal names the mismatch.
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
        # (c) The denials did not poison the path: the
        # same permit still performs its own act, exactly
        # once.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "jesta:api/public-status")], self.executor.effects
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
    # exercisable on one kernel, in the incident's own
    # order: the no-key probe, the wrong-verb probe, the
    # found key spent as a permit, the fabricated key
    # offered as an approval, the genuine envelope
    # stretched to the target act, the genuine permit
    # spent against the target act, the one legitimate
    # execution, and the spent-permit replay.

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(SUBMIT_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(self.executor.execute(self.kernel, DECOY_KEY, TARGET_INTENT))
        fabricated = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            FABRICATED_KEY,
            approval_id="approval-seq-fabricated",
            nonce="nonce-seq-fabricated",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, fabricated)
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
        self.assertFalse(self.executor.execute(self.kernel, permit, TARGET_INTENT))
        # The one legitimate execution still lands; the
        # intrusion attempts did not.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "jesta:api/public-status")], self.executor.effects
        )
        # The spent permit re-presented: a verified
        # approval is single-use, not a found key that
        # keeps working for as long as it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "jesta:api/public-status")], self.executor.effects
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

    def test_negative_control_possession_verification_would_execute(self) -> None:
        # Same scenario, one component swapped: a
        # verifier that checks a presented credential by
        # comparing it against a stored key, where the
        # stored key is the found key -- the environment's
        # own key, the counterfactual in which the key the
        # agent discovered was real. The agent presents
        # the found key as its approval signature, the
        # comparison succeeds, a permit mints, and the
        # customer-records read EXECUTES. That is the
        # incident's stated counterfactual, reproduced at
        # the exact layer it would have happened: not the
        # browser, not the network, not the executor --
        # the verification comparison. The denials in the
        # steps above therefore come from the governed
        # verification's shape (an accountable approval
        # whose signature is computed under the enrolled
        # authority's key, bound to the exact intent), not
        # from a harness that denies by construction.
        double = _PossessionVerifier()
        blind_kernel = self._kernel(verifier=double)
        found = signed_envelope(
            blind_kernel,
            TARGET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-found",
            nonce="nonce-nc-found",
        )
        found = replace(found, signature=DECOY_KEY)
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, found)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, TARGET_INTENT))
        self.assertEqual(
            [("read_resource", "jesta:api/customer-records")], self.executor.effects
        )
        # Under the same double, nothing else gets in --
        # the counterfactual's precision: the fabricated
        # key is not the environment's key, and neither is
        # the genuine authority's real signature. Only the
        # discovered key verifies, because possession is
        # the whole check.
        for signature, approval_id in (
            (FABRICATED_KEY, "approval-nc-fabricated"),
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
        # Contrast, the identical found-key envelope
        # against the governed kernel: denied (step 3a's
        # route).
        governed = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            DECOY_KEY,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
