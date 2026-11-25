"""Scenario test: the Fusionist ACE bridge unbacked-mint
and reserve-release incident (2026-11-22).

Incident (Recorded, from Bitquery's on-chain
investigation as carried by the iTokenly Hack Registry
entry for this incident, retrieved 2026-11-24; the
registry's own change log marks its figures provisional
until Fusionist publishes its own): the bridge that
carries ACE, the coin of Fusionist's Endurance chain, to
BNB Chain minted ACE that nobody had paid for. Bitquery
counted 62 unbacked mints between 17:55 UTC on
2026-11-22 and early on 2026-11-23, starting with 60
million ACE -- more than all the wrapped ACE then in
existence -- and ending in amounts of trillions and
more. Each mint carried the signatures of all three
keys the bridge uses to request, approve, and execute a
mint, the same keys behind more than 3,300 genuine
mints since 2023. Blockaid flagged the attack at 19:08
UTC; Fusionist asked users at 19:30 UTC to stop trading,
sending, and bridging ACE on BNB Chain. The thieves
sold the unbacked ACE as its price collapsed; Bitquery
counts $1.73 million of their DEX sales, with proceeds
of 1,150.9 ETH (about $1.97 million) deposited into
Tornado Cash. Then the crashed tokens were sent back
through the bridge, whose burn key approved the release
of 53.7 million real ACE on Endurance within about two
hours, emptying the bridge's backing down to 148 ACE;
Grafa values the released real ACE at about $3.7
million. The $5.7 million total loss figure is
SlowMist's, as recorded by the registry -- an estimate,
not an audited figure. Bitquery also found six
Fusionist wallets, including the bridge keys, swept the
next morning. How the keys were obtained has not been
stated; Fusionist has published neither a loss figure
nor a cause, and nothing has been reported recovered.

The failure is not a signature failure. The signatures
were genuine -- the bridge's own keys, the keys that
had signed every legitimate mint for three years. The
failure is a provenance failure: the signed acts had no
source record behind them. No ACE was locked or burned
on the source side for any of the 62 mints, and no step
on the bridge's execution path asked whether one had
been. Authority artifacts existed in perfect form;
authority for the acts did not, because a mint is
legitimate only against a reconciled source event, and
there was none. The release leg compounded it: the
bridge's burn-and-release path honored the unbacked
tokens as if their existence were backing, and paid out
the real reserves behind them. Signatures are not
provenance, and provenance is not authority.

This module models that failure mode against the
canonical kernel API plus a dispatch-boundary
reconciliation gate, in the repo's established scenario
idiom. It does NOT reproduce any chain, bridge, token
contract, key material, or transaction from the
incident. The bridge is an abstract mint/release model:
a source ledger (the harness's stand-in for the source
chain's records), a dispatcher (the only route from a
mint or release request to a consequence), and amounts
that are small stand-ins -- the incident's amounts
(60 million, then trillions; 53.7 million released) are
narrative scale, and nothing in the failure turns on
the size of the numbers.

Setup: the dispatcher reconciles BEFORE it consumes.
For a mint, it requires a source record -- a lock on
the source side -- that matches the intent exactly
(record identity, amount, target) and is unspent. For
a release, it requires that the backing mints it is
presented with are distinct -- a repeated identifier
is a malformed presentation, not additional backing --
that every one of them actually executed through the
governed path, that their amounts sum exactly to the
release amount, and that none of them has already
backed a release. Only then does the dispatcher present the
permit to ``GovernanceKernel.consume``, and only a
successful consume records a consequence. The incident's
acts are then attempted on every route: unbacked mints
with no permit, with a fabricated token, and -- the
incident's exact shape -- with genuine permits issued
through verified approval envelopes, the model's form
of the bridge keys' genuine signatures; a wave of 62
unbacked mints; amount- and target-mismatched mints
against a real lock; a second mint against a spent
lock; a release whose backing is the unbacked mints
themselves; and forged and mismatched approval
envelopes. The governed path must refuse each one, and
the legitimate path -- a mint backed by a real,
reconciled lock, under a single-use permit bound to the
exact amount and target -- must execute exactly once.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules):
the derived incident report turns ``permit_rejected``
events, ``approval_rejected`` events, and denied
decisions into near-miss records. Two classes of refusal
in this scenario are NOT derived as near-misses, and the
scenario asserts both exactly as they hold rather than
smoothing either over. A bare ``evaluate`` returning
``require_approval`` appends a decision record to the
canonical audit but is not derived (the known channel
boundary, issue #375). And a reconciliation refusal
happens at the dispatch boundary, before any consume is
attempted: it appends nothing to the canonical audit at
all, and is recorded only in the dispatcher's own
reconciliation log -- harness evidence in this scenario;
in a deployment, the dispatcher would be governed
infrastructure whose log is its own evidence surface.
The kernel-visible attempts are what the channel sees,
and step 9 counts them exactly.

Boundary: this proves kernel-plus-dispatcher behavior
at this commit for these action classes (Verified,
executable evidence). It proves nothing about any
deployed bridge that does not route its mints and
releases through a reconciliation gate and this kernel
-- a bridge that executes signed requests because they
are signed is governed by nothing here. The replay
models the reconciliation step the bridge skipped, not
bridge internals. A control not on the execution path
governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed path
only -- exactly one governed external consequence is
permitted per correctly scoped, reconciled permit, and
any dispatch path without the reconciliation gate (the
incident's own class) remains outside this evidence and
open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed" -- but WHERE the state changes depends on
the route, and this scenario keeps the routes distinct.
A kernel-route denial appends audit records, counted per
route as in the sibling scenarios: a bare evaluate
returning ``require_approval`` appends one decision
record; a ``consume`` rejection appends one
``permit_rejected`` record; a denied approval-envelope
evaluation appends two records -- an
``approval_rejected`` record and a denied decision
record. A reconciliation-route refusal appends nothing
to the canonical audit; its only growth is one entry in
the dispatcher's reconciliation log. Both growths are
governed effects -- evidence production -- append-only,
with ``authority_effect=none`` and no capability
accumulation, assessed separately from governed
external consequences throughout this module:
"consequence" below means a mint or release recorded in
the dispatcher's consequence ledger after a successful
consume, never audit or log growth.
"""

from __future__ import annotations

import unittest

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The bridge executor: the principal whose dispatch path
# mints and releases. Every intent below is an act this
# bridge would perform; a requester proposes, the bridge
# must not execute without reconciliation and a permit
# bound to the act.
BRIDGE = "agent:ace-bridge"
# The bridge route of the incident, in the harness's
# naming. Route identity is part of the bound intent; it
# is not itself authority for anything.
ROUTE = "endurance-to-bnb"

# Targets, as harness labels. A mint's target is part of
# its exact intent and part of what its source record
# must match: a lock taken for one destination backs no
# mint to another.
TARGET_A = "bnb-wallet-a"
TARGET_B = "bnb-wallet-b"
RESERVE_TARGET = "endurance-reserve"

# Amounts are stand-ins (see the module docstring). The
# one legitimate mint in this scenario is 100 units
# against lock-1; the mismatch probes move one field at
# a time off that exact triple.
LEGIT_AMOUNT = 100


def _mint_resource(lock_id: str, amount: int, target: str) -> str:
    return f"ace:mint/to:{target}/amount:{amount}/backing:{lock_id}"


def _release_resource(presentation_id: str, amount: int, target: str) -> str:
    return f"ace:release/to:{target}/amount:{amount}/presentation:{presentation_id}"


def _mint_intent(lock_id: str, amount: int, target: str) -> Intent:
    return Intent(BRIDGE, "mint", _mint_resource(lock_id, amount, target), amount, ROUTE)


def _release_intent(presentation_id: str, amount: int, target: str) -> Intent:
    return Intent(
        BRIDGE, "release", _release_resource(presentation_id, amount, target), amount, ROUTE
    )


# The bridge keys' genuine signatures, presented as if a
# signature were a permit. The signatures in the incident
# were real; as authority to skip reconciliation that is
# exactly what they were worth, and the kernel must treat
# this string as what it is at the consume boundary: a
# fabricated token.
KEYS_SIGNED_TOKEN = "ace-bridge:request+approve+execute-keys-signed"


class SourceLedger:
    """Harness stand-in for the source chain's records.

    A lock is a source event: real value taken in on the
    source side, naming the amount and the destination it
    was taken in for. This ledger is the external world
    the dispatcher reconciles against; it holds no
    canonical Pulpo state, and nothing in the kernel can
    write to it -- which is the point: provenance lives
    outside the authority artifacts, and has to be
    checked, not signed into existence.
    """

    def __init__(self) -> None:
        self._locks: dict[str, dict] = {}

    def record_lock(self, lock_id: str, amount: int, target: str) -> None:
        self._locks[lock_id] = {"amount": amount, "target": target, "spent": False}

    def lock_state(self, lock_id: str) -> dict | None:
        return self._locks.get(lock_id)

    def spend_lock(self, lock_id: str) -> None:
        # Tolerant of unknown ids: the negative control's
        # unguarded dispatcher reaches this line for a
        # lock that was never recorded -- which is its
        # defect, exercised deliberately there.
        if lock_id in self._locks:
            self._locks[lock_id]["spent"] = True


class BridgeDispatcher:
    """Mints and releases, reachable only via reconcile-then-consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's bridge did not have. The
    reconciliation gate runs FIRST: an act whose source
    backing does not reconcile is refused before any
    permit is presented to the kernel, so the refusal
    spends nothing and appends nothing to the canonical
    audit; it is recorded in this dispatcher's
    reconciliation log. Only a reconciled act reaches
    ``consume``, and only a successful consume records a
    consequence and spends the backing.
    """

    def __init__(self, ledger: SourceLedger) -> None:
        self.ledger = ledger
        self.effects: list[tuple[str, str]] = []
        # Governed executions only: mint_id -> amount. A
        # mint that never executed through this path is
        # not in this map, which is what a release's
        # backing is checked against. One governed
        # execution per mint_id: dispatch refuses an ID
        # that has already executed, so an entry in this
        # map is never overwritten.
        self.executed_mints: dict[str, int] = {}
        self._release_spent_mints: set[str] = set()
        self._released_presentations: set[str] = set()
        # (action, subject, reason) per reconciliation
        # refusal, in order.
        self.reconciliation_log: list[tuple[str, str, str]] = []

    # -- reconciliation gates -------------------------------------------

    def _mint_refusal(self, lock_id: str, amount: int, target: str) -> str | None:
        state = self.ledger.lock_state(lock_id)
        if state is None:
            return "no_matching_source_record"
        if state["spent"]:
            return "backing_already_spent"
        if state["amount"] != amount or state["target"] != target:
            return "no_matching_source_record"
        return None

    def _release_refusal(
        self, presentation_id: str, mint_ids: list[str], amount: int
    ) -> str | None:
        # Malformed before semantic: a repeated identifier
        # would be counted once per occurrence by the
        # backing sum below but recorded once by the spent
        # set, so one executed mint could satisfy a release
        # worth multiples of its value. A duplicate is not
        # more backing; the presentation is rejected as
        # malformed before any backing is evaluated.
        if len(set(mint_ids)) != len(mint_ids):
            return "backing_duplicate_mint"
        if presentation_id in self._released_presentations:
            return "backing_already_released"
        if any(mint_id not in self.executed_mints for mint_id in mint_ids):
            return "backing_not_executed"
        if any(mint_id in self._release_spent_mints for mint_id in mint_ids):
            return "backing_already_released"
        if sum(self.executed_mints[mint_id] for mint_id in mint_ids) != amount:
            return "backing_amount_mismatch"
        return None

    # -- dispatch ---------------------------------------------------------

    def dispatch_mint(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        *,
        mint_id: str,
        lock_id: str,
        amount: int,
        target: str,
    ) -> bool:
        intent = _mint_intent(lock_id, amount, target)
        # Identity before backing: a mint_id names ONE
        # governed execution. A second dispatch reusing an
        # executed ID would overwrite the recorded backing
        # (executed_mints is keyed by ID), silently
        # destroying the first mint's backing record while
        # both mints stand in the effects log. Refused at
        # reconciliation, before any consume: identity
        # reuse is not a second mint under this ID.
        refusal = (
            "mint_already_executed"
            if mint_id in self.executed_mints
            else self._mint_refusal(lock_id, amount, target)
        )
        if refusal is not None:
            self.reconciliation_log.append(("mint", mint_id, refusal))
            return False
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.ledger.spend_lock(lock_id)
        self.executed_mints[mint_id] = amount
        self.effects.append(("mint", intent.resource))
        return True

    def dispatch_release(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        *,
        presentation_id: str,
        mint_ids: list[str],
        amount: int,
        target: str,
    ) -> bool:
        intent = _release_intent(presentation_id, amount, target)
        refusal = self._release_refusal(presentation_id, mint_ids, amount)
        if refusal is not None:
            self.reconciliation_log.append(("release", presentation_id, refusal))
            return False
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self._released_presentations.add(presentation_id)
        self._release_spent_mints.update(mint_ids)
        self.effects.append(("release", intent.resource))
        return True


class _UnreconciledDispatcher(BridgeDispatcher):
    """Deliberately unguarded double for the negative control.

    Its reconciliation gates always pass: dispatch is
    consume-only. That is the incident's own shape -- the
    keys signed, the bridge executed, and no step asked
    whether a source record backed the act. Under this
    double the unbacked mint must EXECUTE, or the
    scenario's refusals would be construction, not
    control.
    """

    def _mint_refusal(self, lock_id: str, amount: int, target: str) -> str | None:
        return None

    def _release_refusal(
        self, presentation_id: str, mint_ids: list[str], amount: int
    ) -> str | None:
        return None


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class FusionistAceIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"mint", "release"}),
            10_000,
            frozenset({"mint", "release"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = SourceLedger()
        self.dispatcher = BridgeDispatcher(self.ledger)

    def _kernel(self) -> GovernanceKernel:
        return GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )

    def _issue_permit(
        self,
        kernel: GovernanceKernel,
        intent: Intent,
        *,
        approval_id: str,
        nonce: str,
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

    # -- positive control -------------------------------------------------

    def test_positive_control_backed_mint_executes_exactly_once(self) -> None:
        self.ledger.record_lock("lock-1", LEGIT_AMOUNT, TARGET_A)
        intent = _mint_intent("lock-1", LEGIT_AMOUNT, TARGET_A)
        permit = self._issue_permit(
            self.kernel, intent, approval_id="approval-legit", nonce="nonce-legit"
        )
        # The one legitimate mint: a real lock on the
        # source side, reconciled, under a permit bound to
        # the exact record, amount, and target.
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit,
                mint_id="mint-legit",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([("mint", intent.resource)], self.dispatcher.effects)
        self.assertEqual({"mint-legit": LEGIT_AMOUNT}, self.dispatcher.executed_mints)
        self.assertTrue(self.ledger.lock_state("lock-1")["spent"])
        # The kernel layer itself refuses the replay: the
        # same permit presented to consume again, against
        # the same intent, is rejected -- single-use does
        # not depend on the dispatcher's gate.
        self.assertFalse(self.kernel.consume(permit, intent))
        self.assertEqual([("mint", intent.resource)], self.dispatcher.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual([], self.dispatcher.reconciliation_log)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the unbacked mint, no-permit routes ------------------------

    def test_step1_unbacked_mint_refused_before_any_permit_route(self) -> None:
        intent = _mint_intent("lock-ghost", LEGIT_AMOUNT, TARGET_A)
        # No lock exists. The kernel declines to mint
        # without approval...
        decision = self.kernel.evaluate(intent)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        # ...and the dispatcher refuses the act itself,
        # with no permit and with the bridge keys'
        # signatures presented as one. Both refusals are
        # reconciliation refusals: they happen before any
        # consume, so the canonical audit gains no
        # permit_rejected from them -- the only audit
        # record of the whole step is the evaluate's
        # decision.
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                decision.permit,
                mint_id="mint-ghost",
                lock_id="lock-ghost",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                KEYS_SIGNED_TOKEN,
                mint_id="mint-ghost",
                lock_id="lock-ghost",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual({}, self.dispatcher.executed_mints)
        self.assertEqual(
            [
                ("mint", "mint-ghost", "no_matching_source_record"),
                ("mint", "mint-ghost", "no_matching_source_record"),
            ],
            self.dispatcher.reconciliation_log,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "decision")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: a genuine permit cannot execute an unbacked mint -----------

    def test_step2_genuine_permit_cannot_execute_unbacked_mint(self) -> None:
        intent = _mint_intent("lock-9", LEGIT_AMOUNT, TARGET_A)
        # The incident's exact shape, in kernel form: a
        # genuine permit, issued through a verified
        # approval envelope -- the model's form of all
        # three bridge keys signing. The signature layer
        # is in perfect order. There is still no lock.
        permit = self._issue_permit(
            self.kernel, intent, approval_id="approval-9", nonce="nonce-9"
        )
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit,
                mint_id="mint-9",
                lock_id="lock-9",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual(
            [("mint", "mint-9", "no_matching_source_record")],
            self.dispatcher.reconciliation_log,
        )
        # The refusal spent nothing: no consume was
        # attempted, so the permit is unspent and the
        # audit shows neither a consumption nor a
        # rejection.
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        # The discrimination: record the real lock now,
        # and the SAME permit executes the mint exactly
        # once. What was missing was never the signature
        # -- it was the source record. Signatures are not
        # provenance, and provenance is not authority.
        self.ledger.record_lock("lock-9", LEGIT_AMOUNT, TARGET_A)
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit,
                mint_id="mint-9",
                lock_id="lock-9",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([("mint", intent.resource)], self.dispatcher.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: a fabricated permit on a backed intent ----------------------

    def test_step3_fabricated_permit_rejected_at_consume_on_backed_intent(self) -> None:
        self.ledger.record_lock("lock-1", LEGIT_AMOUNT, TARGET_A)
        intent = _mint_intent("lock-1", LEGIT_AMOUNT, TARGET_A)
        # The backing reconciles, so dispatch reaches the
        # kernel -- and the keys-signed string is rejected
        # there as the fabricated token it is. A signature
        # is not a permit either.
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                KEYS_SIGNED_TOKEN,
                mint_id="mint-1",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual([], self.dispatcher.reconciliation_log)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(intent), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The rejection did not spend the backing or
        # poison the path: the genuine permit still
        # executes the mint.
        self.assertFalse(self.ledger.lock_state("lock-1")["spent"])
        permit = self._issue_permit(
            self.kernel, intent, approval_id="approval-1", nonce="nonce-1"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit,
                mint_id="mint-1",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([("mint", intent.resource)], self.dispatcher.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: a spent lock backs no second mint ---------------------------

    def test_step4_spent_lock_backs_no_second_mint(self) -> None:
        self.ledger.record_lock("lock-1", LEGIT_AMOUNT, TARGET_A)
        intent = _mint_intent("lock-1", LEGIT_AMOUNT, TARGET_A)
        first = self._issue_permit(
            self.kernel, intent, approval_id="approval-first", nonce="nonce-first"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                first,
                mint_id="mint-first",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        # A second, freshly approved permit for the same
        # intent -- new signatures, in the incident's
        # terms -- meets a spent lock. One source record
        # backs exactly one mint; the reconciliation gate
        # refuses before consume, so this refusal also
        # spends nothing.
        audit_len_before = len(self.kernel.audit)
        second = self._issue_permit(
            self.kernel, intent, approval_id="approval-second", nonce="nonce-second"
        )
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                second,
                mint_id="mint-second",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual(
            [("mint", "mint-second", "backing_already_spent")],
            self.dispatcher.reconciliation_log,
        )
        self.assertEqual([("mint", intent.resource)], self.dispatcher.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        # The only audit growth since the snapshot is the
        # second permit's own issuance (approval_verified
        # + decision): the refused dispatch added none.
        self.assertEqual(audit_len_before + 2, len(self.kernel.audit))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: amount and target must match the record exactly -------------

    def test_step5_amount_and_target_mismatch_refused(self) -> None:
        self.ledger.record_lock("lock-5", LEGIT_AMOUNT, TARGET_A)
        # Same record, more value: a lock of 100 backs no
        # mint of 150. (The incident's wave escalated from
        # 60 million to trillions against no records at
        # all; against a real record, escalation is a
        # mismatch, not a detail.)
        big_intent = _mint_intent("lock-5", 150, TARGET_A)
        big_permit = self._issue_permit(
            self.kernel, big_intent, approval_id="approval-big", nonce="nonce-big"
        )
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                big_permit,
                mint_id="mint-big",
                lock_id="lock-5",
                amount=150,
                target=TARGET_A,
            )
        )
        # Same record, same amount, different destination:
        # a lock taken in for one target backs no mint to
        # another.
        elsewhere_intent = _mint_intent("lock-5", LEGIT_AMOUNT, TARGET_B)
        elsewhere_permit = self._issue_permit(
            self.kernel,
            elsewhere_intent,
            approval_id="approval-elsewhere",
            nonce="nonce-elsewhere",
        )
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                elsewhere_permit,
                mint_id="mint-elsewhere",
                lock_id="lock-5",
                amount=LEGIT_AMOUNT,
                target=TARGET_B,
            )
        )
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual(
            [
                ("mint", "mint-big", "no_matching_source_record"),
                ("mint", "mint-elsewhere", "no_matching_source_record"),
            ],
            self.dispatcher.reconciliation_log,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The exact triple still executes: the refusals
        # were precision, not lockout.
        exact_intent = _mint_intent("lock-5", LEGIT_AMOUNT, TARGET_A)
        exact_permit = self._issue_permit(
            self.kernel, exact_intent, approval_id="approval-exact", nonce="nonce-exact"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                exact_permit,
                mint_id="mint-exact",
                lock_id="lock-5",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([("mint", exact_intent.resource)], self.dispatcher.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the release leg -- unbacked tokens are not backing ----------

    def test_step6_release_against_unbacked_mints_refused(self) -> None:
        # The incident's first act, compressed: three
        # unbacked mints, each under a genuine permit.
        # All three are refused at reconciliation (step
        # 2's route), so none of them ever executes.
        fake_amounts = [40, 30, 30]
        for index, amount in enumerate(fake_amounts, start=1):
            lock_id = f"lock-fake-{index}"
            intent = _mint_intent(lock_id, amount, TARGET_A)
            permit = self._issue_permit(
                self.kernel,
                intent,
                approval_id=f"approval-fake-{index}",
                nonce=f"nonce-fake-{index}",
            )
            self.assertFalse(
                self.dispatcher.dispatch_mint(
                    self.kernel,
                    permit,
                    mint_id=f"mint-fake-{index}",
                    lock_id=lock_id,
                    amount=amount,
                    target=TARGET_A,
                )
            )
        self.assertEqual({}, self.dispatcher.executed_mints)
        # The incident's second act: the unbacked tokens
        # are presented back, and the release of real
        # reserves is requested against them -- amounts
        # summing exactly, under a genuine release permit.
        # The only failing condition is the one that
        # mattered: the backing mints never executed,
        # because there was never anything behind them.
        # Existence is not backing.
        release_intent = _release_intent("pres-1", 100, RESERVE_TARGET)
        release_permit = self._issue_permit(
            self.kernel,
            release_intent,
            approval_id="approval-release-1",
            nonce="nonce-release-1",
        )
        self.assertFalse(
            self.dispatcher.dispatch_release(
                self.kernel,
                release_permit,
                presentation_id="pres-1",
                mint_ids=["mint-fake-1", "mint-fake-2", "mint-fake-3"],
                amount=100,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual(
            ("release", "pres-1", "backing_not_executed"),
            self.dispatcher.reconciliation_log[-1],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The governed counterpart: a real mint executes,
        # and a release backed by exactly that executed
        # mint -- and nothing else -- executes once.
        self.ledger.record_lock("lock-real", LEGIT_AMOUNT, TARGET_A)
        mint_intent = _mint_intent("lock-real", LEGIT_AMOUNT, TARGET_A)
        mint_permit = self._issue_permit(
            self.kernel, mint_intent, approval_id="approval-real", nonce="nonce-real"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                mint_permit,
                mint_id="mint-real",
                lock_id="lock-real",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        good_release_intent = _release_intent("pres-2", LEGIT_AMOUNT, RESERVE_TARGET)
        good_release_permit = self._issue_permit(
            self.kernel,
            good_release_intent,
            approval_id="approval-release-2",
            nonce="nonce-release-2",
        )
        self.assertTrue(
            self.dispatcher.dispatch_release(
                self.kernel,
                good_release_permit,
                presentation_id="pres-2",
                mint_ids=["mint-real"],
                amount=LEGIT_AMOUNT,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual(
            [("mint", mint_intent.resource), ("release", good_release_intent.resource)],
            self.dispatcher.effects,
        )
        # The same executed mint backs no second release,
        # under a fresh presentation and a fresh permit:
        # the reserve cannot be drained twice through one
        # backing, which is the whole of the incident's
        # second act stated as a refusal.
        again_intent = _release_intent("pres-3", LEGIT_AMOUNT, RESERVE_TARGET)
        again_permit = self._issue_permit(
            self.kernel,
            again_intent,
            approval_id="approval-release-3",
            nonce="nonce-release-3",
        )
        self.assertFalse(
            self.dispatcher.dispatch_release(
                self.kernel,
                again_permit,
                presentation_id="pres-3",
                mint_ids=["mint-real"],
                amount=LEGIT_AMOUNT,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual(
            ("release", "pres-3", "backing_already_released"),
            self.dispatcher.reconciliation_log[-1],
        )
        self.assertEqual(2, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6b: a duplicated backing mint is not more backing --------------

    def test_step6b_duplicated_backing_mint_refused_as_malformed(self) -> None:
        # One genuine mint of 50 units, executed through
        # the governed path.
        self.ledger.record_lock("lock-50", 50, TARGET_A)
        mint_intent = _mint_intent("lock-50", 50, TARGET_A)
        mint_permit = self._issue_permit(
            self.kernel, mint_intent, approval_id="approval-50", nonce="nonce-50"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                mint_permit,
                mint_id="mint-50",
                lock_id="lock-50",
                amount=50,
                target=TARGET_A,
            )
        )
        # The same executed mint presented TWICE as the
        # backing for a release of 100 -- double its real
        # value -- under a genuine release permit. Summed
        # naively, the presentation reaches 100; counted
        # honestly, the backing is one mint of 50. A
        # repeated identifier is a malformed presentation,
        # refused at reconciliation before any consume:
        # repetition is not backing.
        dup_intent = _release_intent("pres-dup", 100, RESERVE_TARGET)
        dup_permit = self._issue_permit(
            self.kernel,
            dup_intent,
            approval_id="approval-release-dup",
            nonce="nonce-release-dup",
        )
        self.assertFalse(
            self.dispatcher.dispatch_release(
                self.kernel,
                dup_permit,
                presentation_id="pres-dup",
                mint_ids=["mint-50", "mint-50"],
                amount=100,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual(
            ("release", "pres-dup", "backing_duplicate_mint"),
            self.dispatcher.reconciliation_log[-1],
        )
        self.assertEqual([("mint", mint_intent.resource)], self.dispatcher.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        # The refusal spent nothing: the same mint,
        # presented once, still backs a release of exactly
        # its own amount.
        single_intent = _release_intent("pres-single", 50, RESERVE_TARGET)
        single_permit = self._issue_permit(
            self.kernel,
            single_intent,
            approval_id="approval-release-single",
            nonce="nonce-release-single",
        )
        self.assertTrue(
            self.dispatcher.dispatch_release(
                self.kernel,
                single_permit,
                presentation_id="pres-single",
                mint_ids=["mint-50"],
                amount=50,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual(
            [("mint", mint_intent.resource), ("release", single_intent.resource)],
            self.dispatcher.effects,
        )
        self.assertEqual(2, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    def test_step6c_reused_mint_id_refused_backing_record_intact(self) -> None:
        # Two genuine source locks, two genuine permits --
        # and the second mint presented under the FIRST
        # mint's identifier. Executed naively, both mints
        # stand in the effects log (100 + 250 = 350 minted)
        # while the backing record, keyed by mint_id, keeps
        # only the last write (250): the first mint's
        # backing is destroyed, a release of the true total
        # no longer reconciles, and only the surviving
        # entry's amount does. Identity reuse is refused at
        # reconciliation instead, before any consume.
        self.ledger.record_lock("lock-a", 100, TARGET_A)
        self.ledger.record_lock("lock-b", 250, TARGET_A)
        intent_a = _mint_intent("lock-a", 100, TARGET_A)
        permit_a = self._issue_permit(
            self.kernel, intent_a, approval_id="approval-a", nonce="nonce-a"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit_a,
                mint_id="mint-x",
                lock_id="lock-a",
                amount=100,
                target=TARGET_A,
            )
        )
        intent_b = _mint_intent("lock-b", 250, TARGET_A)
        permit_b = self._issue_permit(
            self.kernel, intent_b, approval_id="approval-b", nonce="nonce-b"
        )
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit_b,
                mint_id="mint-x",
                lock_id="lock-b",
                amount=250,
                target=TARGET_A,
            )
        )
        self.assertEqual(
            ("mint", "mint-x", "mint_already_executed"),
            self.dispatcher.reconciliation_log[-1],
        )
        # The first mint's backing record is intact, and it
        # is the only mint effect.
        self.assertEqual({"mint-x": 100}, self.dispatcher.executed_mints)
        self.assertEqual([("mint", intent_a.resource)], self.dispatcher.effects)
        # A release of the combined 350 the reused ID tried
        # to manufacture is a mismatch against the one
        # governed mint; a release of exactly the first
        # mint's amount reconciles.
        total_intent = _release_intent("pres-total", 350, RESERVE_TARGET)
        total_permit = self._issue_permit(
            self.kernel,
            total_intent,
            approval_id="approval-release-total",
            nonce="nonce-release-total",
        )
        self.assertFalse(
            self.dispatcher.dispatch_release(
                self.kernel,
                total_permit,
                presentation_id="pres-total",
                mint_ids=["mint-x"],
                amount=350,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual(
            ("release", "pres-total", "backing_amount_mismatch"),
            self.dispatcher.reconciliation_log[-1],
        )
        exact_intent = _release_intent("pres-exact", 100, RESERVE_TARGET)
        exact_permit = self._issue_permit(
            self.kernel,
            exact_intent,
            approval_id="approval-release-exact",
            nonce="nonce-release-exact",
        )
        self.assertTrue(
            self.dispatcher.dispatch_release(
                self.kernel,
                exact_permit,
                presentation_id="pres-exact",
                mint_ids=["mint-x"],
                amount=100,
                target=RESERVE_TARGET,
            )
        )
        # The refusal spent nothing: lock-b was never spent
        # and its permit never consumed, so the second mint
        # still executes under its OWN identifier.
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit_b,
                mint_id="mint-y",
                lock_id="lock-b",
                amount=250,
                target=TARGET_A,
            )
        )
        self.assertEqual(
            {"mint-x": 100, "mint-y": 250}, self.dispatcher.executed_mints
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: forged and mismatched approvals ----------------------------

    def test_step7_forged_and_mismatched_approvals_denied(self) -> None:
        mint_intent = _mint_intent("lock-1", LEGIT_AMOUNT, TARGET_A)
        genuine_release_envelope = signed_envelope(
            self.kernel,
            _release_intent("pres-1", LEGIT_AMOUNT, RESERVE_TARGET),
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-release",
            nonce="nonce-genuine-release",
        )
        # (a) An envelope for the mint signed with an
        # unauthorized key: whoever holds the bridge's
        # request path cannot mint the approver's
        # authority. (In the incident the genuine keys
        # were the problem; a forged one is refused
        # earlier and more cheaply, and both refusals are
        # needed -- step 2 covers the genuine case.)
        forged_envelope = signed_envelope(
            self.kernel,
            mint_intent,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(mint_intent, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine release envelope presented for
        # the mint intent: a real approval for one bridge
        # act is not approval for the other.
        decision = self.kernel.evaluate_with_approval(
            mint_intent, genuine_release_envelope
        )
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_signature_invalid", "approval_intent_mismatch"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine
        # pair still admits.
        decision = self.kernel.evaluate_with_approval(
            _release_intent("pres-1", LEGIT_AMOUNT, RESERVE_TARGET),
            genuine_release_envelope,
        )
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 8: the wave -- 62 unbacked mints, all refused ------------------

    def test_step8_wave_of_62_unbacked_mints_all_refused(self) -> None:
        # The incident's headline count, at stand-in
        # amounts: 62 mints, each signed in perfect form
        # (a genuine permit per mint, each with its own
        # approval identity, as each real approval would
        # carry), none with a source record behind it.
        # Volume is not backing: all 62 are refused at
        # reconciliation, none reaches the kernel's spend
        # path, and the consequence ledger stays empty.
        for index in range(1, 63):
            lock_id = f"lock-wave-{index}"
            intent = _mint_intent(lock_id, LEGIT_AMOUNT, TARGET_A)
            permit = self._issue_permit(
                self.kernel,
                intent,
                approval_id=f"approval-wave-{index}",
                nonce=f"nonce-wave-{index}",
            )
            self.assertFalse(
                self.dispatcher.dispatch_mint(
                    self.kernel,
                    permit,
                    mint_id=f"mint-wave-{index}",
                    lock_id=lock_id,
                    amount=LEGIT_AMOUNT,
                    target=TARGET_A,
                )
            )
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual({}, self.dispatcher.executed_mints)
        self.assertEqual(62, len(self.dispatcher.reconciliation_log))
        self.assertTrue(
            all(
                reason == "no_matching_source_record"
                for _, _, reason in self.dispatcher.reconciliation_log
            )
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(62, len(_events(self.kernel, "approval_verified")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 9: the incident channel sees the kernel-visible attempts -------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit. The frozen sequence below replays every
    # kernel-visible variant the scenario exercises: the
    # no-permit evaluation (step 1), the fabricated token
    # on a backed intent (step 3), both approval-envelope
    # attempts (step 7), the one legitimate execution, and
    # its replay. It also includes one reconciliation
    # refusal (step 2's route) to pin the second boundary
    # stated in the module docstring: that refusal appends
    # nothing to the canonical audit and contributes zero
    # near-miss records -- its evidence lives in the
    # dispatcher's reconciliation log, asserted here from
    # that log, not from the channel.

    def test_step9_incident_channel_surfaces_kernel_visible_attempts(self) -> None:
        self.ledger.record_lock("lock-1", LEGIT_AMOUNT, TARGET_A)
        mint_intent = _mint_intent("lock-1", LEGIT_AMOUNT, TARGET_A)
        # Step 1's route: no approval exists for the mint.
        decision = self.kernel.evaluate(mint_intent)
        self.assertEqual("require_approval", decision.outcome)
        # Step 3's route: the keys-signed string on the
        # backed intent, rejected at consume.
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                KEYS_SIGNED_TOKEN,
                mint_id="mint-1",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        # Step 7's routes: forged and mismatched envelopes.
        forged_envelope = signed_envelope(
            self.kernel,
            mint_intent,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(mint_intent, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_release_envelope = signed_envelope(
            self.kernel,
            _release_intent("pres-1", LEGIT_AMOUNT, RESERVE_TARGET),
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-release",
            nonce="nonce-genuine-release",
        )
        decision = self.kernel.evaluate_with_approval(
            mint_intent, genuine_release_envelope
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # Step 2's route, included to pin its boundary:
        # a genuine permit for an unbacked mint, refused
        # at reconciliation. The canonical audit must not
        # grow across this dispatch.
        ghost_intent = _mint_intent("lock-ghost", LEGIT_AMOUNT, TARGET_A)
        ghost_permit = self._issue_permit(
            self.kernel,
            ghost_intent,
            approval_id="approval-ghost",
            nonce="nonce-ghost",
        )
        audit_len_before = len(self.kernel.audit)
        self.assertFalse(
            self.dispatcher.dispatch_mint(
                self.kernel,
                ghost_permit,
                mint_id="mint-ghost",
                lock_id="lock-ghost",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertEqual(
            [("mint", "mint-ghost", "no_matching_source_record")],
            self.dispatcher.reconciliation_log,
        )
        # The one legitimate execution, and its replay.
        permit = self._issue_permit(
            self.kernel, mint_intent, approval_id="approval-legit", nonce="nonce-legit"
        )
        self.assertTrue(
            self.dispatcher.dispatch_mint(
                self.kernel,
                permit,
                mint_id="mint-legit",
                lock_id="lock-1",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertFalse(self.kernel.consume(permit, mint_intent))
        self.assertEqual([("mint", mint_intent.resource)], self.dispatcher.effects)

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
        self.assertEqual(2, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The require_approval decision and the
        # reconciliation refusal above are both real,
        # recorded refusals that contribute zero near-miss
        # records at this commit, each for its stated
        # reason.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(6, report.near_misses)
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

    def test_negative_control_unreconciled_dispatch_would_execute(self) -> None:
        # Same scenario, dispatch without the
        # reconciliation gate: the unbacked mint EXECUTES
        # under a genuine permit, and the release against
        # it executes too -- the incident's full shape,
        # both acts, in miniature: signed in perfect form,
        # backed by nothing, paid out anyway. The refusals
        # in the steps above therefore come from the
        # reconciliation gate (and, where exercised, the
        # kernel's binding), not from a harness that
        # refuses by construction.
        unguarded = _UnreconciledDispatcher(self.ledger)
        mint_intent = _mint_intent("lock-ghost", LEGIT_AMOUNT, TARGET_A)
        permit = self._issue_permit(
            self.kernel, mint_intent, approval_id="approval-ghost", nonce="nonce-ghost"
        )
        self.assertTrue(
            unguarded.dispatch_mint(
                self.kernel,
                permit,
                mint_id="mint-ghost",
                lock_id="lock-ghost",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        release_intent = _release_intent("pres-ghost", LEGIT_AMOUNT, RESERVE_TARGET)
        release_permit = self._issue_permit(
            self.kernel,
            release_intent,
            approval_id="approval-release-ghost",
            nonce="nonce-release-ghost",
        )
        self.assertTrue(
            unguarded.dispatch_release(
                self.kernel,
                release_permit,
                presentation_id="pres-ghost",
                mint_ids=["mint-ghost"],
                amount=LEGIT_AMOUNT,
                target=RESERVE_TARGET,
            )
        )
        self.assertEqual(
            [("mint", mint_intent.resource), ("release", release_intent.resource)],
            unguarded.effects,
        )
        # Contrast, identical attempts against the real
        # dispatcher on a fresh kernel: both refused, at
        # reconciliation, before any consume.
        real_kernel = self._kernel()
        real_dispatcher = BridgeDispatcher(self.ledger)
        real_permit = self._issue_permit(
            real_kernel, mint_intent, approval_id="approval-real", nonce="nonce-real"
        )
        self.assertFalse(
            real_dispatcher.dispatch_mint(
                real_kernel,
                real_permit,
                mint_id="mint-ghost",
                lock_id="lock-ghost",
                amount=LEGIT_AMOUNT,
                target=TARGET_A,
            )
        )
        self.assertEqual([], real_dispatcher.effects)
        self.assertEqual(
            [("mint", "mint-ghost", "no_matching_source_record")],
            real_dispatcher.reconciliation_log,
        )


if __name__ == "__main__":
    unittest.main()
