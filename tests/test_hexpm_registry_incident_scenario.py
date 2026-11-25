"""Scenario test: the Hex.pm registry unauthenticated
remote-code-execution incident (2026-11-23; disclosed
2026-11-24).

Incident (Verified, from Hex's own incident report,
https://hex.pm/blog/security-incident-on-hexpm,
CVE-2026-129514 Recorded): on 2026-11-23, 18:16-18:29
UTC, an unauthenticated attacker sent 69 requests whose
bodies were Erlang terms decoded by the request-body
parser BEFORE routing or authentication; forged structs
(a map with a ``__struct__`` key) reached error reporting
whose ``inspect()`` dispatched through Ecto/DBConnection
to an attacker-supplied {module, function, args} tuple,
executing OS commands on six web servers. Hex blocked
traffic and patched within ~20 minutes. No packages were
modified, no DB changes were made, and no persistence was
found -- but DB reads are not logged, so reads of emails,
bcrypt password hashes, API-key hashes, 2FA secrets,
sessions and audit logs cannot be ruled out (Unknown).
The registry signing key has NOT yet been rotated
(Recorded: a new signing system is due in coming days).
Disclosed 2026-11-24.

The failure is that bytes were executed because they
decoded into a trusted internal shape before any
authentication or authorization existed:
``DECODED_FORMAT_TRUST != AUTHORIZATION``. Class:
trusted-path execution. A forged struct binds no intent,
names no accountable approver, and carries no scope: it
does not say which act, on which resource, it supposedly
authorizes, because nobody authorized anything; the bytes
merely parsed. What actually stopped this incident was
Hex blocking traffic and patching -- Hex's control. This
replay claims nothing about that control. It models the
other half: the same forged struct, pointed at a registry
dispatch boundary that routes its consequential acts
through this kernel.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Erlang term
decoding, Ecto, DBConnection, error reporting, or any real
registry. The mapping (Inferred, stated here so it can be
argued with): the consequential acts are the registry
dispatch boundary executing an OS command on a web server
-- the act the forged struct reached -- gated by this
kernel. The forged struct appears in the positions the
incident's shape puts it in: presented as a permit at the
dispatch boundary (it was never issued, so no state row
and no valid signature stand behind it), presented as the
signature on an approval envelope (decoded bytes, offered
as an accountable approval), and -- in the negative
control -- accepted by a decode-then-trust verifier double
whose whole check is the forged shape itself. The only
route from a request to a consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the
exact intent hash: principal, action, resource, cost,
session.

Setup: exactly one act is legitimate in this scenario --
an authorized package publish by a package maintainer
under a genuine verified approval, executed once. The
incident's acts are then attempted on every route the
governed path has: with no artifact at all, with an act
the policy does not contain, with the forged struct spent
as a permit, with forged and malformed approval artifacts,
and with the one genuine permit and envelope stretched to
the OS-command act. The kernel must deny each one, the
consequence ledger must stay empty for all of them, and
every denial must land in the audit record. The genuine
approval authorizes exactly one execution of exactly its
own act, and then spends.

Reconciliation (Hex-specific): Hex could assert no
packages were modified and no DB changes were made, but
could NOT assert that no DB reads occurred, because reads
are not logged. Step 6 therefore reconciles the governed
record after the full attack sequence: the consequence
ledger contains exactly the one legitimate effect, and a
test-level reconciliation of the claimed state against
the kernel audit (see the reconciliation section below
for why test-level, and what the shipped reconcilers do
instead) shows no divergence -- no package/state mutation
the audit cannot account for. That is the property a
governed dispatch boundary can assert and an unlogged
read path cannot.

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
evidence). It proves nothing about the real Hex.pm
registry, the real attack, or any deployed registry that
does not route its consequential acts through this
kernel -- a dispatch path that executes decoded bytes
before authentication is governed by nothing here. The
patch that stopped the real incident was Hex's, and this
replay neither reproduces nor claims it. The replay also
cannot rotate Hex's registry signing key: the unrotated
key is an open exposure the kernel evidence does not
close (see the change record, section 5). A control not
on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
decode-then-trust path (the incident's own class)
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
from collections import Counter
from dataclasses import dataclass, replace

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The registry's request-dispatch boundary: the point at
# which, in the incident, unauthenticated request bodies
# were decoded and reached a trusted path. Every intent
# below is an act this boundary would perform; an
# unauthenticated network peer proposes, the boundary
# must not perform anything without a permit bound to
# the act.
GATEWAY = "agent:hexpm-registry"
# The session of the attempt, 2026-11-23, in the
# harness's naming. Session identity is part of the
# bound intent; it is not itself authority for anything.
SESSION = "registry-session-2026-11-23"

# The one legitimate act: an authorized publish of a
# release into the maintainer's own package namespace --
# the accountable per-action authorization a legitimate
# maintainer holds.
LEGIT_INTENT = Intent(GATEWAY, "publish_release", "hexpm:package/maintainer-own", 25, SESSION)
# The incident's target act: executing an OS command on
# a registry web server -- the act the forged struct
# reached without any authorization.
TARGET_INTENT = Intent(GATEWAY, "execute_command", "hexpm:web-server", 25, SESSION)
# An act the registry policy does not contain at all:
# deleting a release from another maintainer's package
# namespace, modeled as a verb the boundary has never
# been given for anyone.
UNLISTED_INTENT = Intent(GATEWAY, "delete_release", "hexpm:package/other-maintainer", 25, SESSION)

# The forged struct: a serialized Erlang-term-style map
# carrying a ``__struct__`` key and an attacker-supplied
# {module, function, args} tuple. In this scenario it
# appears in the three positions the incident's shape
# puts decoded bytes in -- presented as a permit,
# presented as an approval signature, and (negative
# control only) accepted by a verifier whose whole check
# is the forged shape. An inert stand-in string; it is
# never decoded or executed here.
FORGED_STRUCT = "forged:%{__struct__:Ecto.Query,mfa:{os,cmd,[id]}}"
# A different garbage string: malformed bytes that do
# not even carry the forged shape.
GARBAGE = "garbage:not-a-struct-not-a-signature"


class _DecodeThenTrustVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by decoded shape, the incident's own
    shape: ``verify`` accepts the forged-struct token
    itself as a valid signature. Whoever presents bytes
    in the correctly forged shape verifies, whatever act
    the envelope names: format-shape is the whole check,
    exactly the property that executed OS commands in
    the incident. Under this double even the genuine
    authority's HMAC signature fails -- it is not the
    forged struct -- and a different garbage string fails
    too; only the correctly-shaped forgery verifies.
    Test-local; never imported by runtime code.
    """

    trusted_shape = FORGED_STRUCT

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(signature, self.trusted_shape)


class RegistryDispatchExecutor:
    """Consequences at the registry boundary, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's registry did not interpose
    between decoded bytes and a performed act: in the
    incident's shape, decoding into the trusted shape WAS
    the execution path. Here the harness records an effect
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


# -- test-level reconciliation against the kernel audit --------------------
#
# Compared occurrence counts (multisets), defined once and
# used for the kernel audit throughout:
#   consequences -- acts that executed (audit:
#                   permit_consumed records)
#   attempts     -- acts that did NOT execute and must be
#                   disclosed (audit: permit_rejected
#                   records, plus decision records with
#                   outcome require_approval / deny)
# Counts, not mere presence: the incident fired the same
# forged shape 69 times in 13 minutes, and a maintainer may
# legitimately publish more than once under separately
# issued permits, so an intent attempted three times, or
# executed twice, contributes that many occurrences, and a
# claim reconciles only if it reports the same count for
# every hash. A presence-only (set) comparison would
# collapse repeats to one and let a claim underreport
# repeated activity while still returning ok -- the failure
# the Codex review of this module identified, and the one
# step 6b pins shut.
# Authorization-side records (approval_verified, allow
# decisions) are the authority's own trail, not registry
# acts, and are excluded by design. This reconciliation is
# TEST-LEVEL, implemented against the public ``kernel.audit``
# read path, as in the gainsight, filename-deception and
# Mythos scenarios: the shipped reconcilers
# (``pulpo.effect_reconcile``, ``pulpo.custody_reconcile``)
# reconcile filesystem effects and custody-domain outcomes,
# not a claimed registry state against the kernel audit
# trail. No shipped ``def reconcile`` API takes a claimed
# consequence ledger and a kernel audit and returns a
# divergence verdict; following the API as it actually is
# means this step proves exactly what the test-level
# construction proves, stated in step 6 and in the change
# record, and no more.


def audited_counts(audit: list[dict]) -> tuple[Counter, Counter]:
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


@dataclass(frozen=True)
class ClaimReconciliation:
    ok: bool
    undisclosed_attempts: frozenset[str]  # in the record, missing or undercounted in the claim
    unbacked_consequences: frozenset[str]  # claimed beyond the record's executed count
    missing_consequences: frozenset[str]  # executed per the record, missing or undercounted in the claim
    phantom_attempts: frozenset[str]  # claimed as attempted beyond the record's count
    audit_valid: bool = True


def reconcile_against_audit(kernel: GovernanceKernel, claim: dict) -> ClaimReconciliation:
    # Fail closed: reconciliation must verify the audit chain
    # FIRST. Deriving counts from an invalid chain would accept
    # fabricated provenance -- the exact gap (unlogged reads
    # that cannot be ruled out) this scenario exists to close
    # for the governed path.
    try:
        audit_valid = kernel.verify_audit()
    except Exception:
        audit_valid = False
    consequences, attempts = audited_counts(kernel.audit)
    # The claim's lists carry multiplicity by repetition: a hash
    # listed twice claims two occurrences. Compare counts per
    # hash, so a claim that lists a repeated hash only once
    # underreports it and fails.
    claimed_consequences = Counter(claim.get("consequences", ()))
    claimed_attempts = Counter(claim.get("attempts", ()))
    undisclosed = frozenset(
        intent_hash
        for intent_hash, count in attempts.items()
        if claimed_attempts[intent_hash] < count
    )
    unbacked = frozenset(
        intent_hash
        for intent_hash, count in claimed_consequences.items()
        if consequences[intent_hash] < count
    )
    missing = frozenset(
        intent_hash
        for intent_hash, count in consequences.items()
        if claimed_consequences[intent_hash] < count
    )
    phantom = frozenset(
        intent_hash
        for intent_hash, count in claimed_attempts.items()
        if attempts[intent_hash] < count
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


class HexpmRegistryIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = RegistryDispatchExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"publish_release", "execute_command"}),
            10_000,
            frozenset({"publish_release", "execute_command"}),
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
        incident's isolation: the attacker's request
        machinery reached the trusted path too; the one
        thing it held that was never authority was the
        forged struct.
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
        # The one legitimate act: the authorized publish
        # under a genuine, well-formed, verified approval
        # executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("publish_release", "hexpm:package/maintainer-own")], self.executor.effects
        )
        # The same permit cannot perform the same act
        # twice -- a verified approval is not a standing
        # credential, however many times it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("publish_release", "hexpm:package/maintainer-own")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no artifact at all, and a verb the policy lacks ------------

    def test_step1_no_artifact_and_unlisted_act_denied(self) -> None:
        # The incident's opening position: an
        # unauthenticated request with no artifact at all.
        # The kernel declines to mint: no approval envelope
        # exists for the OS-command act, and the peer's
        # ability to reach the boundary is not one.
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, TARGET_INTENT))
        # And an act the policy does not contain at all:
        # the policy contains no such verb for anyone, so
        # the attempt is denied outright rather than held
        # for an approval that could never legitimately
        # arrive.
        decision = self.kernel.evaluate(UNLISTED_INTENT)
        self.assertEqual(
            ("deny", "action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, UNLISTED_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = {
            record["payload"]["outcome"] for record in _events(self.kernel, "decision")
        }
        self.assertEqual({"require_approval", "deny"}, decisions)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the forged struct, spent as a permit -------------------------
    #
    # The attacker sends bytes that decode into a trusted
    # internal shape. The forged struct was never issued by
    # this kernel: no state row stands behind it and no
    # genuine token signature does either, so consume
    # refuses it at the dispatch boundary -- decoding into
    # the shape is not an issuance. The refusal is recorded
    # against the exact intent the struct was presented for.

    def test_step2_forged_struct_consumes_nothing(self) -> None:
        self.assertFalse(self.executor.execute(self.kernel, FORGED_STRUCT, TARGET_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TARGET_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # The struct buys nothing on the legitimate act
        # either: it is not a weaker permit for a smaller
        # act, it is not a permit at all.
        self.assertFalse(self.executor.execute(self.kernel, FORGED_STRUCT, LEGIT_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(LEGIT_INTENT), rejected[1]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: forged and malformed approval artifacts ----------------------

    def test_step3_forged_and_malformed_approvals_denied(self) -> None:
        # (a) The forged struct offered as an approval
        # signature: decoded bytes, dressed as an
        # accountable approval. The governed verifier
        # computes the expected signature from the payload
        # under the enrolled key; the forged struct is not it.
        forged = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            FORGED_STRUCT,
            approval_id="approval-forged-struct",
            nonce="nonce-forged-struct",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, forged)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A garbage / malformed string as signature:
        # bytes that do not even carry the forged shape.
        # A malformed string is not a signature, and the
        # denial is the same as for the forged struct --
        # the governed path does not distinguish a
        # correctly-shaped non-authority from a shapeless one.
        garbage = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            GARBAGE,
            approval_id="approval-garbage",
            nonce="nonce-garbage",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, garbage)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) An envelope signed with an unauthorized key:
        # whoever controls the network end of the
        # connection cannot mint the registry's authority
        # either.
        unauthorized = signed_envelope(
            self.kernel, TARGET_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW,
            approval_id="approval-unauthorized", nonce="nonce-unauthorized",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, unauthorized)
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
        # (a) The genuine envelope for the maintainer's
        # own publish presented for the OS-command act: a
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
            [("publish_release", "hexpm:package/maintainer-own")], self.executor.effects
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
    # order: the no-artifact probe, the unlisted-act probe,
    # the forged struct spent as a permit, the garbage
    # signature offered as an approval, the genuine
    # envelope stretched to the target act, the genuine
    # permit spent against the target act, the one
    # legitimate execution, and the spent-permit replay.

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(UNLISTED_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(self.executor.execute(self.kernel, FORGED_STRUCT, TARGET_INTENT))
        garbage = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            GARBAGE,
            approval_id="approval-seq-garbage",
            nonce="nonce-seq-garbage",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, garbage)
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
        # attack attempts did not.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("publish_release", "hexpm:package/maintainer-own")], self.executor.effects
        )
        # The spent permit re-presented: a verified
        # approval is single-use, not a decoded shape that
        # keeps working for as long as it is presented.
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("publish_release", "hexpm:package/maintainer-own")], self.executor.effects
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

    # -- step 6: reconciliation after the full attack sequence ----------------
    #
    # The property Hex could NOT assert about its database:
    # reads are not logged, so a read cannot be ruled out.
    # On the governed path every consequence and every
    # attempt is in the audit, so a claimed state can be
    # reconciled against it exactly -- and a claim that
    # smuggles in the target act, or omits the attempts,
    # fails reconciliation by name.

    def test_step6_reconciliation_no_unaccounted_state(self) -> None:
        # The full attack sequence, in incident order,
        # on this kernel:
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        self.assertFalse(self.executor.execute(self.kernel, FORGED_STRUCT, TARGET_INTENT))
        forged = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            FORGED_STRUCT,
            approval_id="approval-rec-forged",
            nonce="nonce-rec-forged",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, forged)
        self.assertEqual("deny", decision.outcome)
        permit = self._issue_permit(
            self.kernel, LEGIT_INTENT, approval_id="approval-rec-run", nonce="nonce-rec-run"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, TARGET_INTENT))
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))

        # The consequence ledger contains exactly the one
        # legitimate effect.
        self.assertEqual(
            [("publish_release", "hexpm:package/maintainer-own")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        consequences, attempts = audited_counts(self.kernel.audit)
        legit_hash = self.kernel.intent_hash(LEGIT_INTENT)
        target_hash = self.kernel.intent_hash(TARGET_INTENT)
        self.assertEqual({legit_hash: 1}, dict(consequences))
        self.assertIn(target_hash, attempts)
        self.assertNotIn(target_hash, consequences)

        # An honest claim -- exactly the one consequence,
        # every attempt disclosed -- reconciles exactly:
        # no divergence between the claimed canonical
        # state and the audit.
        honest_claim = {
            "consequences": sorted(consequences.elements()),
            "attempts": sorted(attempts.elements()),
        }
        result = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual(frozenset(), result.undisclosed_attempts)
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # A claim in Hex's unlogged position -- asserting
        # the target act happened (a "read" no record can
        # support) -- does NOT reconcile: the consequence
        # is unbacked by any consumed permit.
        inflated_claim = {
            "consequences": [legit_hash, target_hash],
            "attempts": sorted(attempts.elements()),
        }
        result = reconcile_against_audit(self.kernel, inflated_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({target_hash}), result.unbacked_consequences)

        # And a claim that omits the attempts -- the
        # attack never happened, on paper -- does NOT
        # reconcile either: the attempts are undisclosed.
        quiet_claim = {"consequences": [legit_hash], "attempts": []}
        result = reconcile_against_audit(self.kernel, quiet_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset(attempts), result.undisclosed_attempts)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6b: reconciliation preserves multiplicity -----------------------
    #
    # The incident did not strike once: the same forged
    # shape arrived 69 times in 13 minutes, and a maintainer
    # may legitimately publish more than once under
    # separately issued permits. Reconciliation must
    # therefore compare occurrence counts, not mere
    # presence: a claim that lists a thrice-attempted intent
    # once, or a twice-executed publish once, underreports
    # the record and must fail -- in both directions, on
    # exactly the underreported hashes.

    def test_step6b_reconciliation_preserves_multiplicity(self) -> None:
        # The governed record: the forged struct presented
        # as a permit three times (3 rejections, one hash),
        # and the legitimate publish executed twice under
        # two separately issued permits (2 consumptions,
        # one hash).
        for _ in range(3):
            self.assertFalse(
                self.executor.execute(self.kernel, FORGED_STRUCT, TARGET_INTENT)
            )
        for i in (1, 2):
            permit = self._issue_permit(
                self.kernel,
                LEGIT_INTENT,
                approval_id=f"approval-rec6b-{i}",
                nonce=f"nonce-rec6b-{i}",
            )
            self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("publish_release", "hexpm:package/maintainer-own")] * 2,
            self.executor.effects,
        )

        legit_hash = self.kernel.intent_hash(LEGIT_INTENT)
        target_hash = self.kernel.intent_hash(TARGET_INTENT)
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({legit_hash: 2}, dict(consequences))
        self.assertEqual({target_hash: 3}, dict(attempts))

        # A claim collapsing each hash to a single listing
        # -- the presence-only history -- does NOT
        # reconcile: it underreports both the attempts and
        # the executions, flagged on exactly those hashes.
        collapsed_claim = {"consequences": [legit_hash], "attempts": [target_hash]}
        result = reconcile_against_audit(self.kernel, collapsed_claim)
        self.assertFalse(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual(frozenset({target_hash}), result.undisclosed_attempts)
        self.assertEqual(frozenset({legit_hash}), result.missing_consequences)
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # The same history with multiplicity reported
        # honestly -- each hash listed once per occurrence
        # -- reconciles exactly.
        honest_claim = {
            "consequences": [legit_hash, legit_hash],
            "attempts": [target_hash, target_hash, target_hash],
        }
        result = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(result.ok)
        self.assertEqual(frozenset(), result.undisclosed_attempts)
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # Overreporting fails too, in each direction on its
        # own hash: a fourth claimed attempt is a phantom,
        # a third claimed execution is unbacked.
        padded_attempts = {
            "consequences": [legit_hash, legit_hash],
            "attempts": [target_hash] * 4,
        }
        result = reconcile_against_audit(self.kernel, padded_attempts)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({target_hash}), result.phantom_attempts)
        padded_consequences = {
            "consequences": [legit_hash] * 3,
            "attempts": [target_hash] * 3,
        }
        result = reconcile_against_audit(self.kernel, padded_consequences)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({legit_hash}), result.unbacked_consequences)
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_decode_then_trust_would_execute(self) -> None:
        # Same scenario, one component swapped: a
        # verifier that accepts the forged-struct token
        # itself as a valid signature -- decode-then-trust,
        # the incident's own shape. The attacker presents
        # the forged struct as its approval signature, the
        # shape check succeeds, a permit mints, and the
        # OS-command act EXECUTES. That is the incident,
        # reproduced at the exact layer it happened: not
        # the network, not the executor -- the trust
        # decision about decoded bytes. The denials in the
        # steps above therefore come from the governed
        # verification's shape (an accountable approval
        # whose signature is computed under the enrolled
        # authority's key, bound to the exact intent), not
        # from a harness that denies by construction.
        double = _DecodeThenTrustVerifier()
        blind_kernel = self._kernel(verifier=double)
        forged = signed_envelope(
            blind_kernel,
            TARGET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-forged",
            nonce="nonce-nc-forged",
        )
        forged = replace(forged, signature=FORGED_STRUCT)
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, forged)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, TARGET_INTENT))
        self.assertEqual(
            [("execute_command", "hexpm:web-server")], self.executor.effects
        )
        # Under the same double, nothing else gets in --
        # the incident's precision: a different garbage
        # string is not the correctly forged shape, and
        # neither is the genuine authority's real
        # signature. Only the correctly-shaped forgery
        # verifies, because format-shape is the whole check.
        for signature, approval_id in (
            (GARBAGE, "approval-nc-garbage"),
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
        # Contrast, the identical forged-struct envelope
        # against the governed kernel: denied (step 3a's
        # route).
        governed = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            FORGED_STRUCT,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
