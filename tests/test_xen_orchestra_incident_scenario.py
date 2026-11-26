"""Scenario test: the Xen Orchestra VSA-2026-062
authentication bypass (Vates advisory VSA-2026-062,
disclosed 2026-11-10; CVE-2026-133469 published
2026-11-23, CVSS 9.8).

Incident (Verified, from the Vates advisory and the
CVE record; reported at
https://thehackernews.com/2026/11/hackers-exploit-critical-xen-orchestra.html):
a REST cookie-parsing flaw in Xen Orchestra let an
unauthenticated attacker send
``authenticationToken=j:{}`` -- the value decoded to an
EMPTY OBJECT, which was passed to the token provider as
an unfiltered lookup that returned the FIRST STORED
TOKEN -- and sign in as admin with no password. Vates
confirmed active exploitation (an attacker IP and a Tor
domain observed; a pivot VM; persistence files) and
that the same actor chained VSA-2026-063 (a VM-import
authorization flaw) to compromise XCP-ng hosts as root.
A successful bypass leaves NO log entry. No victim is
named (Unknown) and the scale of exploitation is
undisclosed (Unknown).

The failure is that a malformed credential that decodes
to nothing was resolved into a real identity:
``A_MALFORMED_CREDENTIAL_THAT_DECODES !=
AN_AUTHENTICATED_IDENTITY``. An empty object -- the
absence of a credential -- was passed to an unfiltered
lookup, and the lookup returned the first stored token,
so absence became the strongest credential in the
store: it worked for everything the first token's owner
could do, and it left no log entry because, to the
system, a legitimate admin had signed in. What the
replay must exercise is therefore threefold: fail
closed on malformed credentials, bind every approval
and permit to the exact intent, and make reconciliation
the detection layer -- because the real bypass left no
logs, the governed counterpart must show that every
attempt is witnessed and that reconciliation can prove
the consequence set is exactly the authorized set.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Xen
Orchestra, its cookie parsing, its token provider, or
any real token. The mapping (Inferred, stated here so
it can be argued with): the consequential boundary is
the Xen Orchestra console's dispatch boundary. The one
legitimate act is an authorized administrator's bounded
read of VM inventory. The target act is a host-level
administrative act on the XCP-ng hosts -- the
root-compromise end of the VSA-2026-062 ->
VSA-2026-063 chain. The empty-object token appears as
the inert stand-in string ``j:{}`` in the positions the
incident put the decoded empty object in: presented as
a permit at consume (the lookup's answer spent
directly), presented as the signature on an approval
envelope (the lookup's answer dressed as an accountable
approval), and -- in the negative control -- held as a
verifier's stored token, reached by presenting the
empty object itself, which the double's modeled
provider lookup resolves to the first stored token:
the attacker never possesses the token's value. The only route from a request to a
consequence is a successful ``GovernanceKernel.consume``
of a permit bound to the exact intent hash: principal,
action, resource, cost, session.

Setup: exactly one act is legitimate in this scenario --
an authorized administrator's bounded read of VM
inventory, executed once, under a permit issued through
a verified approval envelope. That genuine permit is
kept hold of: in the negative control it plays the role
of "the first stored token" -- the real credential the
unfiltered lookup returned for the empty object. The
incident's acts are then attempted on every route the
governed path has: with no credential at all, with an
act the policy does not contain, with the empty-object
token spent as a permit, with the empty-object token
and forged artifacts offered as approvals, and with the
one genuine permit and envelope stretched to the host
act. The kernel must deny each one, the consequence
ledger must stay empty for all of them, and every
denial must land in the audit record.

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
evidence). It proves nothing about Xen Orchestra, any
deployed console, or any gateway that does not route
its consequential acts through this kernel -- a console
whose token lookup resolves an empty object to the
first stored token is governed by nothing here. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
unfiltered-lookup path (the incident's own class)
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
# The Xen Orchestra console's dispatch boundary: every
# intent below is an act this console would perform;
# an unauthenticated network peer proposes, the console
# must not perform anything without a permit bound to
# the act.
CONSOLE = "agent:xen-orchestra-console"
SESSION = "xo-session-2026-11-10"

# The one legitimate act: an authorized administrator's
# bounded read of VM inventory.
LEGIT_INTENT = Intent(CONSOLE, "read_resource", "xo:vm-inventory", 25, SESSION)
# The incident's target act: a host-level administrative
# act on the XCP-ng hosts -- the root-compromise end of
# the VSA-2026-062 -> VSA-2026-063 chain.
TARGET_INTENT = Intent(CONSOLE, "administer_host", "xo:xcp-ng-hosts", 25, SESSION)
# An act the console's policy does not contain at all.
UNKNOWN_INTENT = Intent(CONSOLE, "purge_host", "xo:xcp-ng-hosts", 25, SESSION)

# The empty-object token: the value the attacker sent,
# ``authenticationToken=j:{}``, decoded to an empty
# object and resolved by an unfiltered lookup to the
# first stored token. Here it is an inert stand-in
# string; it was never issued by anyone here.
EMPTY_OBJECT_TOKEN = "j:{}"


class _UnfilteredLookupVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    The incident's token provider modeled at the
    verification layer, in the incident's own two
    steps. The provider step (``lookup``): the
    presented value is used as a lookup key, and the
    empty object -- the incident's ``j:{}`` -- is an
    empty filter, so the UNFILTERED lookup returns
    the first stored token; any other value resolves
    to itself. The check (``verify``): whatever the
    lookup returns is accepted if it is a stored
    token, for ANY envelope. The lookup is the whole
    check: an attacker who presents only the empty
    object -- who never possesses any stored token's
    value -- is resolved by the provider to the first
    stored token and verifies, whatever act the
    envelope names. Under this double a random string
    is denied (it resolves to itself and matches no
    stored token); only the empty object (through the
    lookup) or a genuinely stored token verifies.
    Test-local; never imported by runtime code.
    """

    stored_tokens: tuple[str, ...] = ()

    def lookup(self, presented: str) -> str:
        # The provider step, modeled explicitly: the
        # empty object is an empty filter, and an
        # unfiltered lookup returns the FIRST stored
        # token. Any other presented value resolves to
        # itself.
        if presented == EMPTY_OBJECT_TOKEN and self.stored_tokens:
            return self.stored_tokens[0]
        return presented

    def verify(self, payload: bytes, signature: str) -> bool:
        resolved = self.lookup(signature)
        return bool(resolved) and any(
            hmac.compare_digest(resolved, token) for token in self.stored_tokens
        )


class ConsoleExecutor:
    """Consequences on the console, reachable only via consume.

    The harness records an effect only when the kernel
    consumes a permit for the exact intent. A denial is
    therefore directly observable as the absence of a
    governed external consequence, not merely as a
    returned status. (The denial itself still appends an
    audit record -- a governed effect, classified
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
# Compared occurrence counts (multisets), defined once and
# used for the kernel audit throughout:
#   consequences -- acts that executed (audit:
#                   permit_consumed records)
#   attempts     -- acts that did NOT execute and must be
#                   disclosed (audit: permit_rejected
#                   records, plus decision records with
#                   outcome require_approval / deny)
# Counts, not mere presence: an intent attempted three
# times, or executed twice under separately issued
# permits, contributes that many occurrences, and a claim
# reconciles only if it reports the same count for every
# hash. A presence-only (set) comparison would collapse
# repeats to one and let a claim underreport repeated
# activity while still returning ok -- the failure the
# Codex review of this module identified, and the one
# step 5b pins shut. (Step 5's own sequence already
# exercises this: the target intent is attempted six
# times there, under a single hash.)
# Authorization-side records (approval_verified, allow
# decisions) are the authority's own trail, not console
# acts, and are excluded by design. This reconciliation is
# TEST-LEVEL, implemented against the public ``kernel.audit``
# read path, as in the gainsight and filename-deception
# scenarios: the shipped reconcilers reconcile filesystem
# effects and custody-domain outcomes, not a claimed
# history against the kernel audit trail.


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
    # fabricated provenance -- the exact failure this scenario
    # exists to expose (in the incident, there was no chain
    # at all: a successful bypass left no log entry).
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


class XenOrchestraIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = ConsoleExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"read_resource", "administer_host"}),
            10_000,
            frozenset({"read_resource", "administer_host"}),
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

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, LEGIT_INTENT)
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "xo:vm-inventory")], self.executor.effects
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "xo:vm-inventory")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no credential at all, and a verb the console lacks ---------

    def test_step1_no_credential_and_wrong_verb_denied(self) -> None:
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

    # -- step 2: the empty-object token, spent as a permit -------------------

    def test_step2_empty_object_token_consumes_nothing(self) -> None:
        self.assertFalse(
            self.executor.execute(self.kernel, EMPTY_OBJECT_TOKEN, TARGET_INTENT)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TARGET_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        # The token buys nothing on the legitimate act
        # either: absence of a credential is not a weaker
        # credential for a smaller act; it is refused at
        # the same boundary.
        self.assertFalse(
            self.executor.execute(self.kernel, EMPTY_OBJECT_TOKEN, LEGIT_INTENT)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(LEGIT_INTENT), rejected[1]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the empty-object token and forgeries as approvals -----------

    def test_step3_empty_object_and_forged_approvals_denied(self) -> None:
        # (a) The empty-object token offered as an approval
        # signature.
        empty_obj = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            EMPTY_OBJECT_TOKEN,
            approval_id="approval-empty-object",
            nonce="nonce-empty-object",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, empty_obj)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A literally empty signature: its own recorded
        # denial, before verification is even attempted.
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
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(3, len(_events(self.kernel, "approval_rejected")))
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
        # (a) The genuine envelope for the inventory read
        # presented for the host act: this is the
        # "first stored token works for everything" move
        # at the approval boundary, refused by intent
        # binding.
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine permit presented at consume for
        # the host act.
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
        # (c) The same permit then performs its own act,
        # exactly once.
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "xo:vm-inventory")], self.executor.effects
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: reconciliation as witness, and the incident channel --------
    #
    # The real bypass left NO log entry: to the system, a
    # legitimate admin had signed in, so there was nothing
    # to reconcile against. The governed counterpart must
    # show the opposite on both halves: every attempt
    # above appended audit records (counted per route
    # below), the audit chain verifies, and reconciliation
    # of the claimed history against the audit proves the
    # consequence set is exactly the authorized set --
    # one legitimate effect, no unlogged consequence.
    # The incident channel is then run over the same full
    # sequence, with the bare-evaluate require_approval
    # boundary (issue #375) pinned exactly as it holds.

    def test_step5_reconciliation_and_incident_channel_witness_every_attempt(self) -> None:
        decision = self.kernel.evaluate(TARGET_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        decision = self.kernel.evaluate(UNKNOWN_INTENT)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertFalse(
            self.executor.execute(self.kernel, EMPTY_OBJECT_TOKEN, TARGET_INTENT)
        )
        empty_obj = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            EMPTY_OBJECT_TOKEN,
            approval_id="approval-seq-empty-object",
            nonce="nonce-seq-empty-object",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, empty_obj)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        empty = self._envelope_with_signature(
            self.kernel,
            TARGET_INTENT,
            "",
            approval_id="approval-seq-empty",
            nonce="nonce-seq-empty",
        )
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, empty)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_missing", decision.reason)
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
        self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "xo:vm-inventory")], self.executor.effects
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "xo:vm-inventory")], self.executor.effects
        )

        # -- reconciliation: the consequence counts are
        # exactly the authorized counts.
        legit_hash = self.kernel.intent_hash(LEGIT_INTENT)
        target_hash = self.kernel.intent_hash(TARGET_INTENT)
        unknown_hash = self.kernel.intent_hash(UNKNOWN_INTENT)
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({legit_hash: 1}, dict(consequences))
        expected_attempts = {
            legit_hash,
            target_hash,
            unknown_hash,
        }
        self.assertEqual(expected_attempts, set(attempts))
        # Multiplicity, counted exactly: the target intent
        # was attempted six times under its one hash (the
        # bare evaluate, the token consume, the three
        # denied envelopes, and the stretched-permit
        # consume); the unknown-act denial and the
        # spent-permit re-execution once each.
        self.assertEqual(
            {legit_hash: 1, target_hash: 6, unknown_hash: 1}, dict(attempts)
        )
        # The executor's ledger and the audit agree: the
        # one effect in the ledger is the one consumed
        # consequence in the record. There is no
        # unlogged consequence -- the incident's "no log
        # entry" outcome is impossible on this path
        # because the effect exists only through the
        # consume that writes the record.
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        # A history that claims only the legitimate effect
        # and silence about the attempts does NOT
        # reconcile: reconciliation names the silence.
        silent_claim = {"consequences": [legit_hash], "attempts": []}
        result = reconcile_against_audit(self.kernel, silent_claim)
        self.assertFalse(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual(expected_attempts, set(result.undisclosed_attempts))
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)
        # A history that promotes the host act to a
        # consequence is unbacked: no consume backs it.
        inflated_claim = {
            "consequences": [legit_hash, target_hash],
            "attempts": sorted(attempts.elements()),
        }
        result = reconcile_against_audit(self.kernel, inflated_claim)
        self.assertFalse(result.ok)
        self.assertEqual({target_hash}, set(result.unbacked_consequences))
        self.assertEqual(frozenset(), result.undisclosed_attempts)
        # A history that discloses the attempts -- at their
        # full multiplicity -- alongside exactly the one
        # genuine consequence reconciles exactly.
        honest_claim = {
            "consequences": [legit_hash],
            "attempts": sorted(attempts.elements()),
        }
        honest = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(honest.ok)
        self.assertTrue(honest.audit_valid)

        # -- incident channel over the full sequence.
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
        self.assertEqual(3, len(approval_rejected))
        self.assertEqual(4, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(10, report.near_misses)
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

    # -- step 5b: reconciliation preserves multiplicity -----------------------
    #
    # A bypass that works once will be retried, and a
    # legitimate read may run more than once under
    # separately issued permits. Reconciliation must
    # therefore compare occurrence counts, not mere
    # presence: a history that lists a thrice-attempted
    # intent once, or a twice-executed read once, is
    # underreporting the record and must fail -- in both
    # directions, on exactly the underreported hashes.

    def test_step5b_reconciliation_preserves_multiplicity(self) -> None:
        # The governed record: the empty-object token
        # presented three times (3 rejections, one hash),
        # and the legitimate inventory read executed twice
        # under two separately issued permits (2
        # consumptions, one hash).
        for _ in range(3):
            self.assertFalse(
                self.executor.execute(self.kernel, EMPTY_OBJECT_TOKEN, TARGET_INTENT)
            )
        for i in (1, 2):
            permit = self._issue_permit(
                self.kernel,
                LEGIT_INTENT,
                approval_id=f"approval-rec5b-{i}",
                nonce=f"nonce-rec5b-{i}",
            )
            self.assertTrue(self.executor.execute(self.kernel, permit, LEGIT_INTENT))
        self.assertEqual(
            [("read_resource", "xo:vm-inventory")] * 2,
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

    def test_negative_control_unfiltered_lookup_would_execute(self) -> None:
        # First, the genuine permit for the inventory read
        # on the governed kernel: this is "the first
        # stored token" -- the real credential the
        # incident's unfiltered lookup returned when the
        # empty object was passed to the token provider.
        genuine_permit = self._issue_permit(
            self.kernel, LEGIT_INTENT, approval_id="approval-nc-genuine", nonce="nonce-nc-genuine"
        )
        # Same scenario, one component swapped: a verifier
        # modeling the token provider's unfiltered lookup.
        # It holds the stored token (the genuine permit)
        # in its store. The attacker presents ONLY the
        # empty object -- the incident's exact input,
        # ``j:{}`` -- as the "signature" on an envelope
        # for the HOST act; the attacker never possesses
        # the stored token's value. The double's lookup
        # resolves the empty object to the first stored
        # token (asserted directly below), and that
        # resolution verifies. A permit mints, and the
        # host act EXECUTES. That is the incident
        # reproduced at its exact layer: not the cookie
        # parsing, not the executor -- the lookup that
        # was the whole check.
        double = _UnfilteredLookupVerifier()
        double.stored_tokens = (genuine_permit,)
        self.assertEqual(genuine_permit, double.lookup(EMPTY_OBJECT_TOKEN))
        blind_kernel = self._kernel(verifier=double)
        attack = signed_envelope(
            blind_kernel,
            TARGET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-attack",
            nonce="nonce-nc-attack",
        )
        attack = replace(attack, signature=EMPTY_OBJECT_TOKEN)
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, attack)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, TARGET_INTENT))
        self.assertEqual(
            [("administer_host", "xo:xcp-ng-hosts")], self.executor.effects
        )
        # Under the same double, a random string and an
        # empty string are denied: the random string
        # resolves through the lookup to itself and
        # matches no stored token, because the lookup is
        # the whole check. (The empty string is denied
        # as missing before verification.)
        random_attempt = signed_envelope(
            blind_kernel,
            TARGET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-random",
            nonce="nonce-nc-random",
        )
        random_attempt = replace(random_attempt, signature="random-string-not-stored")
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, random_attempt)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        empty_attempt = signed_envelope(
            blind_kernel,
            TARGET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-empty",
            nonce="nonce-nc-empty",
        )
        empty_attempt = replace(empty_attempt, signature="")
        decision = blind_kernel.evaluate_with_approval(TARGET_INTENT, empty_attempt)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_missing", decision.reason)
        # Contrast, the identical attack envelope against
        # the governed kernel: denied -- the stored permit
        # is not a signature over this envelope's payload.
        decision = self.kernel.evaluate_with_approval(TARGET_INTENT, attack)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
