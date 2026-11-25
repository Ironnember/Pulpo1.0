"""Scenario test: the portal consent-default failure
class.

The class (Recorded: a real instance of this class is
known to the authors; identifying details are withheld
by design -- this scenario models the class, not the
instance, and names no property, vendor, company, unit,
or person): a resident-services portal records
``permission_to_enter = Yes`` for a dwelling unit,
sourced from a user-interface default in the
service-request filing flow. The flow offered the
resident no way to decline; the same system records
``Permission to Enter: No`` on other orders, so the
field can hold "No" -- it simply was not offered here.
The resident performed no affirmative consent act: no
signature, no confirmation, no appointment. The "Yes"
is a default the interface manufactured and the record
then attributed to the resident. A maintenance actor
later attempts physical entry into the unit relying on
that record as its authority.

The failure is that a stored field was treated as an
authorization: ``RECORDED_STATE != AUTHORIZATION``.
Class: manufactured consent. The record binds no
intent (it does not say which actor, for what purpose,
in what window), names no accountable approver (the
resident never acted), and has no provenance (its
source is a default, not a decision). State is
evidence; state is not provenance; provenance is not
authority. The portal had the state. It never had the
provenance, so it never had the authority.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce any real
portal, property-management system, or entry hardware.
The mapping (Inferred, stated here so it can be argued
with): the consequential act is physical entry into
the dwelling unit, gated by this kernel. The portal
record appears in the positions the class puts it in:
presented as a permit at the entry boundary (it was
never issued, so no state row and no genuine token
signature stand behind it), presented as the signature
on an approval envelope (a stored field, offered as an
accountable approval), signed over by the portal
system's own key (the portal cannot grant what only
the resident can), and -- in the negative control --
accepted by a record-trusting verifier double whose
whole check is the record itself. The only route from
a request to a consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the
exact intent hash: principal, action, resource, cost,
session.

Setup: exactly one act is legitimate in this scenario
-- entry by the maintenance dispatch for one specific
appointment the resident affirmatively approved (named
actor, purpose, and session; the approval envelope's
issue/expiry bounds the window), executed once. The
class's acts are then attempted on every route the
governed path has: with no artifact at all, with an
act the policy does not contain, with the portal
record spent as a permit, with the record and other
non-authorities offered as approvals, with the one
genuine grant stretched to an unscheduled entry and
past its window, and with the record carried across a
system migration. The kernel must deny each one, the
consequence ledger must stay empty for all of them, and
every denial must land in the audit record. The genuine
approval authorizes exactly one execution of exactly
its own appointment, and then spends. The genuine
grant's own behavior under migration is asserted
separately, exactly as it holds in step 5: a faithful
migration -- canonical state carried intact -- carries
the issued grant with it (it spends there, once) and
manufactures nothing for the record; a replacement
that discards the state drops the unspent grant with
the ledger, which proves a reset, not a migration.

Reconciliation (class-specific): the portal's standing
"Yes" is a claim about the unit -- entry stands
permitted -- that persists in the system of record
independent of any event. Step 7 therefore reconciles
claims against the kernel audit after the attempt
sequence: a claim reading the standing "Yes" the way
the portal reads it (entry authorized, unbound to the
one genuine appointment) fails by name as unbacked --
no authorization in the ledger matches it -- while an
honest claim (exactly the consequences that executed
under genuine grants, every attempt disclosed)
reconciles exactly. That is the assertion a
record-of-defaults cannot make about itself: which of
its standing permissions a real act of consent ever
stood behind.

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
evidence). It proves nothing about any real portal,
property, or entry system, and nothing about a deployed
entry path that does not route its consequential acts
through this kernel -- a door that opens on a stored
default is governed by nothing here. A control not on
the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this class is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
record-trusting path (the class's own shape) remains
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

Dedication: For my Ember — I love you forever. I'll
always fight for this family.
"""

from __future__ import annotations

import hmac
import unittest
from collections import Counter
from dataclasses import dataclass, replace

from pulpo import (
    GovernanceKernel,
    InMemoryKernelState,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The entry boundary: the point at which, in the class,
# a maintenance actor presents the portal record and
# expects a door to open. Every intent below is an act
# this boundary would perform; the actor proposes, the
# boundary must not perform anything without a permit
# bound to the act.
DISPATCH = "agent:maintenance-dispatch"
# The session of the one legitimate appointment, in the
# harness's naming. Session identity is part of the
# bound intent; it is not itself authority for anything.
APPOINTMENT_SESSION = "appointment-window-1"

# The one legitimate act: entry into the unit for the
# specific appointment the resident affirmatively
# approved -- the accountable per-action authorization
# a resident can actually give.
APPOINTMENT_INTENT = Intent(
    DISPATCH, "enter_unit", "dwelling:unit", 10, APPOINTMENT_SESSION
)
# The class's target act: the same entry, attempted
# outside any appointment the resident approved -- the
# entry the portal record, read as the portal reads it
# (permission, full stop), purports to authorize.
UNSCHEDULED_INTENT = Intent(
    DISPATCH, "enter_unit", "dwelling:unit", 10, "unscheduled-arrival"
)
# An act the entry policy does not contain at all:
# duplicating the resident's key, modeled as a verb the
# boundary has never been given for anyone.
UNLISTED_INTENT = Intent(
    DISPATCH, "duplicate_key", "dwelling:unit", 10, APPOINTMENT_SESSION
)

# The portal record: the stored field and its provenance,
# as the system of record carries it -- permission
# asserted, source a user-interface default. In this
# scenario it appears in the positions the class puts it
# in -- presented as a permit, presented as an approval
# signature, and (negative control only) accepted by a
# verifier whose whole check is the record itself. An
# inert stand-in string; it opens nothing here.
PORTAL_RECORD = "portal-record:permission_to_enter=Yes;source=ui-default"
# A different garbage string: bytes that are neither a
# record nor a signature.
GARBAGE = "garbage:not-a-record-not-a-signature"


class _RecordTrustingVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by stored record, the class's own
    shape: ``verify`` accepts the portal record itself
    as a valid signature. Whoever presents the record
    verifies, whatever act the envelope names: the
    stored field is the whole check, exactly the
    property that opens doors in the class. Under this
    double even the resident authority's HMAC signature
    fails -- it is not the record -- and a different
    garbage string fails too; only the record itself
    verifies. Test-local; never imported by runtime code.
    """

    trusted_record = PORTAL_RECORD

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(signature, self.trusted_record)


class UnitEntryExecutor:
    """Consequences at the entry boundary, reachable only via consume.

    This is the scenario's execution path -- the door
    the class's portal did not interpose between a
    stored record and a performed entry: in the class's
    shape, the record WAS the execution path. Here the
    harness records an effect only when the kernel
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


# -- test-level reconciliation against the kernel audit --------------------
#
# Compared multisets, defined once and used for the kernel
# audit throughout. Multiplicity is load-bearing, not a
# refinement: distinct audited events that share one intent
# hash are DISTINCT attempts -- a bare evaluation's
# decision, a rejected permit, and a denied decision for
# the same intent are three events, not one -- so a claim
# discloses the audit only by accounting for each hash's
# full count. Under a set construction, a claim
# could disclose a hash once and silently absorb every
# other attempt recorded under it; that collapse is the
# same shape as the class itself (a record standing in for
# acts it does not enumerate), and step 7 pins its refusal.
#   consequences -- acts that executed, counted per
#                   permit_consumed record
#   attempts     -- acts that did NOT execute and must be
#                   disclosed, counted per permit_rejected
#                   record and per decision record with
#                   outcome require_approval / deny
# Authorization-side records (approval_verified, allow
# decisions) are the authority's own trail, not entry
# acts, and are excluded by design. This reconciliation is
# TEST-LEVEL, implemented against the public ``kernel.audit``
# read path, as in the gainsight, filename-deception,
# Mythos and hexpm scenarios: the shipped reconcilers
# (``pulpo.effect_reconcile``, ``pulpo.custody_reconcile``)
# reconcile filesystem effects and custody-domain outcomes,
# not a claimed state against the kernel audit trail. No
# shipped ``def reconcile`` API takes a claimed consequence
# ledger and a kernel audit and returns a divergence
# verdict; following the API as it actually is means this
# step proves exactly what the test-level construction
# proves, stated in step 7 and in the change record, and
# no more.


def audited_sets(audit: list[dict]) -> tuple[Counter, Counter]:
    consequences: Counter = Counter()
    attempts: Counter = Counter()
    for record in audit:
        payload = record.get("payload") or {}
        intent_hash = payload.get("intent_hash")
        if intent_hash is None:
            continue
        if record["event"] == "permit_consumed":
            consequences[intent_hash] += 1
        elif record["event"] == "permit_rejected":
            attempts[intent_hash] += 1
        elif record["event"] == "decision" and payload.get("outcome") in {
            "require_approval",
            "deny",
        }:
            attempts[intent_hash] += 1
    return consequences, attempts


def _multiplicity(value) -> Counter:
    """The multiplicity a claim discloses for one category.

    A mapping (hash -> count) states counts directly; any
    other iterable of hashes counts its occurrences, so a
    plain set discloses each hash exactly once -- which is
    precisely the under-disclosure the multiset comparison
    exists to catch when the audit holds more than one
    distinct attempt under the same hash.
    """
    if value is None:
        return Counter()
    if isinstance(value, dict):
        return Counter(
            {key: int(count) for key, count in value.items() if count}
        )
    return Counter(value)


@dataclass(frozen=True)
class ClaimReconciliation:
    # Each field names the intent hashes at which the
    # claim's disclosed multiplicity diverges from the
    # audit's in that direction: undisclosed / missing
    # (the audit holds more than the claim accounts for),
    # unbacked / phantom (the claim asserts more than the
    # audit holds). A hash appears when ANY event under
    # it is unaccounted for, not only when it is absent
    # outright.
    ok: bool
    undisclosed_attempts: frozenset[str]
    unbacked_consequences: frozenset[str]
    missing_consequences: frozenset[str]
    phantom_attempts: frozenset[str]
    audit_valid: bool = True


def reconcile_against_audit(kernel: GovernanceKernel, claim: dict) -> ClaimReconciliation:
    # Fail closed: reconciliation must verify the audit chain
    # FIRST. Deriving sets from an invalid chain would accept
    # fabricated provenance -- the exact defect (a record
    # asserting consent no act ever stood behind) this
    # scenario exists to close for the governed path.
    try:
        audit_valid = kernel.verify_audit()
    except Exception:
        audit_valid = False
    consequences, attempts = audited_sets(kernel.audit)
    claimed_consequences = _multiplicity(claim.get("consequences"))
    claimed_attempts = _multiplicity(claim.get("attempts"))
    undisclosed = frozenset(
        intent_hash
        for intent_hash, count in attempts.items()
        if claimed_attempts[intent_hash] < count
    )
    unbacked = frozenset(
        intent_hash
        for intent_hash, count in claimed_consequences.items()
        if count > consequences[intent_hash]
    )
    missing = frozenset(
        intent_hash
        for intent_hash, count in consequences.items()
        if claimed_consequences[intent_hash] < count
    )
    phantom = frozenset(
        intent_hash
        for intent_hash, count in claimed_attempts.items()
        if count > attempts[intent_hash]
    )
    ok = audit_valid and not (undisclosed or unbacked or missing or phantom)
    return ClaimReconciliation(
        ok=ok,
        undisclosed_attempts=undisclosed,
        unbacked_consequences=unbacked,
        missing_consequences=missing,
        phantom_attempts=phantom,
        audit_valid=audit_valid,
    )


class PortalConsentDefaultIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = UnitEntryExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
        clock_now: int = NOW,
        state: InMemoryKernelState | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"enter_unit"}),
            10_000,
            frozenset({"enter_unit"}),
            authority_trust=trust_for(verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=verifier,
            clock=lambda: clock_now,
            state=state,
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
        class's isolation: the portal's machinery reached
        the boundary too; the one thing it held that was
        never authority was the resident's consent, which
        it replaced with a default.
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

    def test_positive_control_genuine_appointment_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, APPOINTMENT_INTENT)
        # The one legitimate act: entry for the
        # appointment the resident affirmatively approved,
        # under a genuine, well-formed, verified approval
        # envelope, executes once -- the governed path
        # permits the legitimate flow end to end.
        self.assertTrue(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)
        # The same permit cannot perform the same entry
        # twice -- a verified approval for one appointment
        # is not a standing credential, however many times
        # it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no artifact at all, and a verb the policy lacks ------------

    def test_step1_no_artifact_and_unlisted_act_denied(self) -> None:
        # The class's opening position: an actor at the
        # door with no artifact at all -- in the class,
        # the portal record is back at the office; here,
        # nothing has been presented. The kernel declines
        # to mint: no approval envelope exists for the
        # entry, and the actor's presence at the boundary
        # is not one.
        decision = self.kernel.evaluate(APPOINTMENT_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.executor.execute(self.kernel, decision.permit, APPOINTMENT_INTENT)
        )
        # And an act the policy does not contain at all:
        # duplicating the resident's key is a verb the
        # boundary has never been given for anyone, so the
        # attempt is denied outright rather than held for
        # an approval that could never legitimately arrive.
        decision = self.kernel.evaluate(UNLISTED_INTENT)
        self.assertEqual(
            ("deny", "action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.executor.execute(self.kernel, decision.permit, UNLISTED_INTENT)
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = {
            record["payload"]["outcome"] for record in _events(self.kernel, "decision")
        }
        self.assertEqual({"require_approval", "deny"}, decisions)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the portal record, spent as a permit -------------------------
    #
    # The actor presents the record itself at the entry
    # boundary: the system of record says permission is
    # "Yes", and in the class that is the whole of the
    # authority offered. The record was never issued by
    # this kernel as a permit: no state row stands behind
    # it and no genuine token signature does either, so
    # consume refuses it -- a stored field is not an
    # issuance. The refusal is recorded against the exact
    # intent the record was presented for.

    def test_step2_portal_record_consumes_nothing(self) -> None:
        self.assertFalse(
            self.executor.execute(self.kernel, PORTAL_RECORD, UNSCHEDULED_INTENT)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(UNSCHEDULED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # The record buys nothing on the legitimate
        # appointment either: it is not a weaker permit for
        # a smaller act, it is not a permit at all.
        self.assertFalse(
            self.executor.execute(self.kernel, PORTAL_RECORD, APPOINTMENT_INTENT)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(APPOINTMENT_INTENT),
            rejected[1]["payload"]["intent_hash"],
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the record and other non-authorities, offered as approvals ---

    def test_step3_record_and_non_authority_approvals_denied(self) -> None:
        # (a) The portal record offered as an approval
        # signature: a stored field, dressed as an
        # accountable approval. The governed verifier
        # computes the expected signature from the payload
        # under the enrolled key; the record is not it.
        record_signed = self._envelope_with_signature(
            self.kernel,
            APPOINTMENT_INTENT,
            PORTAL_RECORD,
            approval_id="approval-record",
            nonce="nonce-record",
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, record_signed)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A garbage string as signature: bytes that are
        # neither the record nor a signature. The denial is
        # the same as for the record -- the governed path
        # does not distinguish a correctly-formatted
        # non-authority from a formless one.
        garbage = self._envelope_with_signature(
            self.kernel,
            APPOINTMENT_INTENT,
            GARBAGE,
            approval_id="approval-garbage",
            nonce="nonce-garbage",
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, garbage)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) An envelope signed with the portal system's
        # own key: the portal attesting to its own record.
        # Whoever runs the system of record cannot mint
        # the resident's consent either -- the consent is
        # the resident's to give, and the portal's key is
        # not enrolled as that authority.
        portal_key = HmacTestVerifier(b"portal-system-key")
        portal_signed = signed_envelope(
            self.kernel, APPOINTMENT_INTENT, self.verifier, now_ns=NOW,
            approval_id="approval-portal-key", nonce="nonce-portal-key",
        )
        portal_signed = replace(
            portal_signed, signature=portal_key.sign(portal_signed.signing_bytes())
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, portal_signed)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (d) And no signature at all is its own recorded
        # denial, before verification is even attempted:
        # absence is not a weaker form of consent -- it is
        # the class's own condition, and it fails closed
        # here instead of defaulting to "Yes".
        empty = self._envelope_with_signature(
            self.kernel,
            APPOINTMENT_INTENT,
            "",
            approval_id="approval-empty",
            nonce="nonce-empty",
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, empty)
        self.assertEqual(
            ("deny", "approval_signature_missing"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(4, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the genuine grant does not stretch ---------------------------

    def test_step4_genuine_grant_does_not_stretch(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel,
            APPOINTMENT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-appointment",
            nonce="nonce-appointment",
        )
        # (a) The genuine envelope for the approved
        # appointment presented for an unscheduled entry:
        # a real approval for a bounded appointment is not
        # approval for entry at another time. The session
        # binding refuses it before anything else can.
        decision = self.kernel.evaluate_with_approval(UNSCHEDULED_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_session_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine article admitted for its own
        # appointment, then the issued permit presented
        # against the unscheduled entry at the boundary:
        # exact-intent binding refuses the spend, and the
        # refusal names the mismatch.
        permit = self._issue_permit(
            self.kernel,
            APPOINTMENT_INTENT,
            approval_id="approval-appointment-2",
            nonce="nonce-appointment-2",
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, UNSCHEDULED_INTENT))
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"]
            == self.kernel.intent_hash(UNSCHEDULED_INTENT)
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_intent_mismatch", rejected[0]["payload"]["reason"])
        # (c) The same genuine envelope evaluated after
        # its window has passed: the approval was bounded
        # in time as well as in scope, and a late
        # presentation is denied as expired -- a grant for
        # Tuesday's appointment is not a grant for
        # Thursday.
        late_kernel = self._kernel(clock_now=NOW + 5_000)
        late_envelope = signed_envelope(
            late_kernel,
            APPOINTMENT_INTENT,
            self.verifier,
            now_ns=NOW,
            ttl_ns=1_000,
            approval_id="approval-appointment-late",
            nonce="nonce-appointment-late",
        )
        decision = late_kernel.evaluate_with_approval(APPOINTMENT_INTENT, late_envelope)
        self.assertEqual(
            ("deny", "approval_expired"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (d) The denials did not poison the path: the
        # same permit still performs its own appointment,
        # exactly once.
        self.assertTrue(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)
        self.assertFalse(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: migration carries state; it manufactures nothing -------------
    #
    # The class's systems change hands, in two shapes
    # that must not be conflated:
    #
    # (i) A FAITHFUL migration: the new system is built
    # over the old system's canonical state backend,
    # carried across intact, with the same policy, the
    # same enrolled resident authority, and the same
    # deployment secret. What the kernel issued, it still
    # honors -- that continuity is what makes the
    # migration faithful. The question is whether the
    # portal record, copied across with the portal's own
    # data, gains anything from the move. It does not: it
    # was never in the canonical state as an issuance,
    # and carrying the state that exists does not add it.
    #
    # (ii) A LEDGER-DISCARDING replacement: a new system
    # with a fresh, empty state. There the old system's
    # unspent permit refuses -- but the refusal proves
    # only that discarding the authority ledger drops its
    # issuance rows. A state reset is not evidence about
    # migration. The two shapes are asserted separately,
    # for exactly what each proves.

    def test_step5_migration_carryover_still_refuses(self) -> None:
        # The old system, on an explicit state backend so
        # the backend itself can be carried across.
        state = InMemoryKernelState()
        old = self._kernel(state=state)
        old_executor = UnitEntryExecutor()
        # A genuine permit issued in the old system, for
        # the legitimate appointment.
        old_permit = self._issue_permit(
            old,
            APPOINTMENT_INTENT,
            approval_id="approval-pre-migration",
            nonce="nonce-pre-migration",
        )
        # (i) The faithful migration: a new kernel over
        # the SAME carried backend -- same policy, same
        # enrolled resident authority, same deployment
        # secret. Everything the old system canonically
        # stored arrives, because it never left.
        migrated = self._kernel(state=state)
        migrated_executor = UnitEntryExecutor()
        # (a) The standing record, copied across with the
        # portal's data, presented as a permit in the new
        # system: refused exactly as in the old -- the
        # record is not in the carried state as an
        # issuance, and carrying the state does not add it.
        self.assertFalse(
            migrated_executor.execute(migrated, PORTAL_RECORD, UNSCHEDULED_INTENT)
        )
        rejected = [
            record
            for record in _events(migrated, "permit_rejected")
            if record["payload"]["intent_hash"]
            == migrated.intent_hash(UNSCHEDULED_INTENT)
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # (b) The record offered as an approval signature
        # in the new system: denied exactly as in the old.
        record_signed = self._envelope_with_signature(
            migrated,
            APPOINTMENT_INTENT,
            PORTAL_RECORD,
            approval_id="approval-migrated-record",
            nonce="nonce-migrated-record",
        )
        decision = migrated.evaluate_with_approval(APPOINTMENT_INTENT, record_signed)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        # (c) The genuine permit, under the same faithful
        # migration, DOES spend -- exactly once, and the
        # replay of it refuses. That is the honest
        # contrast, asserted rather than smoothed over: a
        # faithful migration carries authority the kernel
        # actually issued, because the issuance row is
        # part of the state carried. What migration cannot
        # carry is authority the record never had. The
        # dividing line is issued-vs-recorded, not
        # old-system-vs-new.
        self.assertTrue(
            migrated_executor.execute(migrated, old_permit, APPOINTMENT_INTENT)
        )
        self.assertFalse(
            migrated_executor.execute(migrated, old_permit, APPOINTMENT_INTENT)
        )
        self.assertEqual(
            [("enter_unit", "dwelling:unit")], migrated_executor.effects
        )
        # (d) The migrated system also mints under a fresh
        # approval: the resident approves the appointment
        # in the new system, and the entry executes exactly
        # once. The migration is a live system, not a
        # museum of the old one.
        new_permit = self._issue_permit(
            migrated,
            APPOINTMENT_INTENT,
            approval_id="approval-post-migration",
            nonce="nonce-post-migration",
        )
        self.assertTrue(
            migrated_executor.execute(migrated, new_permit, APPOINTMENT_INTENT)
        )
        self.assertEqual(
            [("enter_unit", "dwelling:unit")] * 2, migrated_executor.effects
        )
        # (ii) The ledger-discarding replacement: a new
        # kernel with a fresh, empty state -- same policy,
        # same authority, same secret, but the canonical
        # state was NOT carried. A second genuine permit
        # from the old system, unspent, does not spend
        # here: no issuance row stands behind it in this
        # system, and consume re-checks the row. The
        # refusal is recorded against the intent with no
        # signature-failure reason -- a state absence, not
        # a forgery. What this shape proves is only that
        # discarding the ledger drops unspent issuance
        # rows; it is asserted as a reset, not as evidence
        # about faithful migration.
        stranded_permit = self._issue_permit(
            old,
            APPOINTMENT_INTENT,
            approval_id="approval-pre-migration-2",
            nonce="nonce-pre-migration-2",
        )
        reset = self._kernel()
        reset_executor = UnitEntryExecutor()
        self.assertFalse(
            reset_executor.execute(reset, stranded_permit, APPOINTMENT_INTENT)
        )
        rejected = [
            record
            for record in _events(reset, "permit_rejected")
            if record["payload"]["intent_hash"] == reset.intent_hash(APPOINTMENT_INTENT)
        ]
        self.assertEqual(1, len(rejected))
        self.assertIsNone(rejected[0]["payload"].get("reason"))
        self.assertEqual([], reset_executor.effects)
        # And the stranded permit still spends in the old
        # system, where its issuance row lives: the
        # replacement changed which system holds the
        # state, not what the grant was.
        self.assertTrue(old_executor.execute(old, stranded_permit, APPOINTMENT_INTENT))
        self.assertTrue(migrated.verify_audit())
        self.assertTrue(old.verify_audit())
        self.assertTrue(reset.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------
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
    # exercisable on one kernel, in the class's own
    # order: the no-artifact probe, the unlisted-act
    # probe, the portal record spent as a permit, the
    # record offered as an approval, the genuine envelope
    # stretched to an unscheduled entry, the genuine
    # permit spent against the unscheduled entry, the one
    # legitimate execution, and the spent-permit replay.

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        decision = self.kernel.evaluate(APPOINTMENT_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(UNLISTED_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(
            self.executor.execute(self.kernel, PORTAL_RECORD, APPOINTMENT_INTENT)
        )
        record_signed = self._envelope_with_signature(
            self.kernel,
            APPOINTMENT_INTENT,
            PORTAL_RECORD,
            approval_id="approval-seq-record",
            nonce="nonce-seq-record",
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, record_signed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_envelope = signed_envelope(
            self.kernel,
            APPOINTMENT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(UNSCHEDULED_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_session_mismatch", decision.reason)
        permit = self._issue_permit(
            self.kernel,
            APPOINTMENT_INTENT,
            approval_id="approval-seq-run",
            nonce="nonce-seq-run",
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, UNSCHEDULED_INTENT))
        # The one legitimate execution still lands; the
        # class's attempts did not.
        self.assertTrue(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)
        # The spent permit re-presented: a verified
        # approval is single-use, not a stored field that
        # keeps working for as long as it is displayed.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)

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

    # -- step 7: reconciliation flags the standing "Yes" ----------------------
    #
    # The property the class's system of record cannot
    # assert about itself: its standing "Yes" claims
    # entry is permitted, and nothing in the portal can
    # say which standing permissions a real act of
    # consent ever stood behind. On the governed path
    # every consequence and every attempt is in the
    # audit, so a claim can be reconciled against it
    # exactly -- and the standing "Yes", read the way
    # the portal reads it, fails reconciliation by name.

    def test_step7_reconciliation_flags_the_standing_yes(self) -> None:
        # The attempt sequence, in the class's order, on
        # this kernel:
        decision = self.kernel.evaluate(APPOINTMENT_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        self.assertFalse(
            self.executor.execute(self.kernel, PORTAL_RECORD, APPOINTMENT_INTENT)
        )
        record_signed = self._envelope_with_signature(
            self.kernel,
            APPOINTMENT_INTENT,
            PORTAL_RECORD,
            approval_id="approval-rec-record",
            nonce="nonce-rec-record",
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, record_signed)
        self.assertEqual("deny", decision.outcome)
        permit = self._issue_permit(
            self.kernel,
            APPOINTMENT_INTENT,
            approval_id="approval-rec-run",
            nonce="nonce-rec-run",
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, UNSCHEDULED_INTENT))
        self.assertTrue(self.executor.execute(self.kernel, permit, APPOINTMENT_INTENT))

        # The consequence ledger contains exactly the one
        # legitimate effect: the approved appointment.
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        consequences, attempts = audited_sets(self.kernel.audit)
        appointment_hash = self.kernel.intent_hash(APPOINTMENT_INTENT)
        unscheduled_hash = self.kernel.intent_hash(UNSCHEDULED_INTENT)
        self.assertEqual(Counter({appointment_hash: 1}), consequences)
        # Attempts are a multiset: the appointment intent
        # carries THREE distinct audited attempt events --
        # the bare evaluation's require_approval decision,
        # the record spent as a permit (permit_rejected),
        # and the denied decision that accompanies the
        # rejected approval -- not one. Collapsing them to
        # a set would let a claim disclose the hash once
        # and silently absorb the other two.
        self.assertEqual(
            Counter({appointment_hash: 3, unscheduled_hash: 1}), attempts
        )
        self.assertIn(unscheduled_hash, attempts)
        self.assertNotIn(unscheduled_hash, consequences)

        # An honest claim -- exactly the one consequence,
        # every attempt disclosed -- reconciles exactly:
        # no divergence between the claimed state and the
        # audit.
        honest_claim = {"consequences": consequences, "attempts": attempts}
        result = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual(frozenset(), result.undisclosed_attempts)
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # The portal's own claim -- the standing "Yes"
        # read as the portal reads it: permission to
        # enter, unbound to the one appointment the
        # resident actually approved, so the unscheduled
        # entry stands authorized too -- does NOT
        # reconcile: no authorization in the ledger backs
        # it. The standing permission is a claim with no
        # matching authorization, surfaced by name rather
        # than silently accepted.
        portal_claim = {
            "consequences": {appointment_hash, unscheduled_hash},
            "attempts": attempts,
        }
        result = reconcile_against_audit(self.kernel, portal_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({unscheduled_hash}), result.unbacked_consequences)

        # And a claim that omits the attempts -- the
        # record was always "Yes", on paper, and nothing
        # else ever happened -- does NOT reconcile either:
        # the attempts are undisclosed.
        quiet_claim = {"consequences": {appointment_hash}, "attempts": set()}
        result = reconcile_against_audit(self.kernel, quiet_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset(attempts), result.undisclosed_attempts)

        # And a claim that discloses the appointment hash
        # ONCE -- the set-shaped claim -- does NOT
        # reconcile either: three distinct audited attempts
        # stand under that hash, and disclosing it once
        # accounts for one of them. The other two are
        # undisclosed, by count. Under a set construction
        # this claim reconciled; the multiset exists to
        # close exactly that collapse.
        once_claim = {
            "consequences": {appointment_hash: 1},
            "attempts": {appointment_hash: 1, unscheduled_hash: 1},
        }
        result = reconcile_against_audit(self.kernel, once_claim)
        self.assertFalse(result.ok)
        self.assertEqual(
            frozenset({appointment_hash}), result.undisclosed_attempts
        )
        self.assertEqual(frozenset(), result.phantom_attempts)
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_record_trusting_would_execute(self) -> None:
        # Same scenario, one component swapped: a
        # verifier that accepts the portal record itself
        # as a valid signature -- record-trusting, the
        # class's own shape. The actor presents the record
        # as its approval signature, the stored-field check
        # succeeds, a permit mints, and the unscheduled
        # entry EXECUTES. That is the class, reproduced at
        # the exact layer it happens: not the door, not the
        # actor -- the trust decision about a stored field.
        # The denials in the steps above therefore come
        # from the governed verification's shape (an
        # accountable approval whose signature is computed
        # under the enrolled authority's key, bound to the
        # exact intent), not from a harness that denies by
        # construction.
        double = _RecordTrustingVerifier()
        blind_kernel = self._kernel(verifier=double)
        forged = signed_envelope(
            blind_kernel,
            UNSCHEDULED_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-record",
            nonce="nonce-nc-record",
        )
        forged = replace(forged, signature=PORTAL_RECORD)
        decision = blind_kernel.evaluate_with_approval(UNSCHEDULED_INTENT, forged)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, UNSCHEDULED_INTENT))
        self.assertEqual([("enter_unit", "dwelling:unit")], self.executor.effects)
        # Under the same double, nothing else gets in --
        # the class's precision: a garbage string is not
        # the stored record, and neither is the resident
        # authority's real signature. Only the record
        # itself verifies, because the stored field is the
        # whole check.
        for signature, approval_id in (
            (GARBAGE, "approval-nc-garbage"),
            (None, "approval-nc-genuine"),
        ):
            attempt = signed_envelope(
                blind_kernel,
                UNSCHEDULED_INTENT,
                self.verifier,
                now_ns=NOW,
                approval_id=approval_id,
                nonce=f"nonce-{approval_id}",
            )
            if signature is not None:
                attempt = replace(attempt, signature=signature)
            decision = blind_kernel.evaluate_with_approval(UNSCHEDULED_INTENT, attempt)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_signature_invalid", decision.reason)
        # Contrast, the identical record-signed envelope
        # against the governed kernel: denied (step 3a's
        # route).
        governed = self._envelope_with_signature(
            self.kernel,
            APPOINTMENT_INTENT,
            PORTAL_RECORD,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(APPOINTMENT_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
