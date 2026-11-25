"""Scenario test: the Cyber bridge forged-message
exploit (incident 2026-11-21; root cause confirmed by
Cyber's postmortem 2026-11-24).

Incident (Recorded, from Cyber's own postmortem --
the disclosing party and primary source):
an attacker stole the signing key of the verifier for
the Cyber-to-Solana bridge route and forged cross-chain
messages with it. The route trusted a single verifier
(DVN 168): one signature sufficed for a message to be
treated as authentic on the destination side. Two forged
messages, numbered 330 and 331, were executed on the
destination side although no corresponding send existed
on the source side -- the source message counter had
reached only 329. In total 5,213,000 CYBER was minted
against the forged messages and sold for roughly
575 ETH. Cyber revoked the compromised keys, burned an
equivalent amount of CYBER, and notified the FBI. How
the key was stolen -- the cloud entry vector -- has not
been stated and is Unknown.

The failure is not a signature failure. The signatures
on messages 330 and 331 were VALID -- made with the
genuine verifier key, they verify exactly as a genuine
message's signature does. Signature validity was never
the thing that should have decided execution. The
failure is a provenance failure compounded by a
trust-model failure: the destination executed a message
with no source record behind it, because the only check
on the execution path was the channel attestation, and
one attestation sufficed. A signature proves a key
signed a message. It does not prove the message's act
ever happened on the source side, and it is not
authority to execute anything. Signatures are not
provenance, and provenance is not authority.

This module models that failure mode against the
canonical kernel API plus a dispatch-boundary
reconciliation gate, in the repo's established scenario
idiom. It does NOT reproduce any chain, bridge, token
contract, key material, or transaction from the
incident. The bridge is an abstract model: a source
ledger (the harness's stand-in for the reconciled
source-side record -- the sends that actually happened,
with their sequence numbers), a dispatcher (the only
route from an execution request to a consequence), and
amounts that are stand-ins except where the incident's
own figures are used as narrative scale (the two forged
messages below carry amounts summing to the incident's
5,213,000; nothing in the failure turns on the size of
the numbers).

Setup: the source ledger records the route's genuine
sends up to sequence 329 -- the tail of the sequence is
recorded explicitly (327, 328, 329), so the reconciled
source counter is 329. The dispatcher reconciles BEFORE
it consumes. For an execution request it requires a
source record whose sequence does not exceed the
reconciled counter and that matches the presented
message exactly (sequence, amount, recipient) and is
unspent. A sequence beyond the counter is refused by
construction -- there is no record it could match. The
reconcile-check and the spend are atomic with respect
to concurrent dispatches through this dispatcher: the
dispatcher holds its dispatch lock across the whole
reconcile -> reserve -> consume -> record sequence,
reserves the source record before presenting the
permit to ``GovernanceKernel.consume``, and rolls the
reservation back if the consume fails -- so two valid
permits for the same message, dispatched concurrently,
cannot both observe the record unspent and execute it
twice, and a failed consume neither spends the record
nor locks it against the message's genuine permit.
Only a successful consume records a consequence. The forged messages are then
attempted on every route: at the gated dispatcher with
no permit and with a genuine permit; and at the kernel
directly -- with no permit, with the message's own valid
attestation presented as the permit, with a genuine
permit for a different message, with a genuine permit
presented against a mutated message, and with forged
and mismatched approval envelopes. The governed path
must refuse each one, and the legitimate path -- a
message matching its source record exactly, under a
single-use permit bound to that exact act -- must
execute exactly once, sequentially and under concurrent
dispatch alike (step 7). The atomicity the scenario
proves is scoped to this one dispatch boundary: a
single dispatcher instance mediating every execution
against its ledger. Two independent dispatchers sharing
a ledger across processes would need the reservation
itself to live in the shared store; that shape is
outside this evidence, and the scenario claims nothing
about it.

Distinction from the Fusionist ACE replay (built the
same day from the same scan): there, the bridge's OWN
keys signed the unbacked acts in perfect form, and the
gate is per-act record matching. Here the attestation
itself is the attack surface -- it verifies, because
the key was stolen -- and the reconciled source state
is a monotone counter, so the forged messages are
refused not by any signature check (they pass every
signature check) but because the counter says the acts
they claim never happened. The scenario asserts the
forged attestations are VALID before it asserts they
are refused; a replay that only refused badly-signed
messages would prove nothing about this incident.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules):
the derived incident report turns ``permit_rejected``
events, ``approval_rejected`` events, and denied
decisions into near-miss records. Two classes of refusal
in this scenario are NOT derived as near-misses, and
the scenario asserts both exactly as they hold rather
than smoothing either over. A bare ``evaluate``
returning ``require_approval`` appends a decision record
to the canonical audit but is not derived (the known
channel boundary, issue #375). And a reconciliation
refusal happens at the dispatch boundary, before any
consume is attempted: it appends nothing to the
canonical audit at all, and is recorded only in the
dispatcher's own reconciliation log -- harness evidence
in this scenario; in a deployment, the dispatcher would
be governed infrastructure whose log is its own
evidence surface. The kernel-visible attempts are what
the channel sees, and step 6 counts them exactly.

Boundary: this proves kernel-plus-dispatcher behavior
at this commit for these action classes (Verified,
executable evidence). It proves nothing about any
deployed bridge that does not route its executions
through a reconciliation gate and this kernel -- a
bridge that executes validly-signed messages because
they are validly signed is governed by nothing here.
The replay models the reconciliation step the bridge
skipped, not bridge internals. A control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly scoped permit against a
reconciled source record, and any non-kernel dispatch
path (the incident's own class) remains outside this
evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed." A denied KERNEL-VISIBLE attempt appends
audit records, counted per route: a bare evaluate
returning ``require_approval`` appends one decision
record; a ``consume`` rejection appends one
``permit_rejected`` record; a denied approval-envelope
evaluation appends two records -- an
``approval_rejected`` record and a denied decision
record. That growth is itself a governed effect --
evidence production -- bounded at two records per
attempt, append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. A
RECONCILIATION refusal appends nothing to the kernel
audit; its growth is in the dispatcher's reconciliation
log, classified separately wherever it is counted. Both
classes are assessed separately from governed external
consequences throughout this module: "consequence"
below means governed external consequence (the permitted
consume recorded by the dispatcher), never audit growth
and never log growth.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import unittest
from dataclasses import dataclass

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
# The destination-side bridge executor: the principal
# whose acts the forged messages are aimed at. Every
# intent below is an execution this executor would
# perform; the message proposes, the executor must not
# execute without a reconciled source record and a
# permit bound to the act.
BRIDGE = "agent:cyber-bridge-destination"
# The route of the incident, in the harness's naming.
# Route identity is part of the bound intent; it is not
# itself authority for anything.
ROUTE = "cyber-to-solana"

# The verifier key, as a stand-in byte string. The
# incident's attacker STOLE the genuine key, so in this
# harness the attacker signs with this very key: the
# forged attestations below are made with it and verify
# with it. That is the point -- the scenario refuses
# messages whose signatures are valid.
VERIFIER_KEY = b"dvn-verifier-key-stand-in"


@dataclass(frozen=True)
class BridgeMessage:
    """A destination-side execution request, as presented.

    The fields are the message as the destination sees
    it: a sequence number, an amount, a recipient. The
    message carries no authority; its identity in every
    intent is the SHA-256 digest of these exact fields,
    derived by the dispatch boundary from the message
    actually presented -- never a caller-supplied label,
    because the incident's messages were decorated with
    genuine-looking sequence numbers.
    """

    seq: int
    amount: int
    recipient: str


def _message_digest(message: BridgeMessage) -> str:
    canonical = f"{message.seq}|{message.amount}|{message.recipient}"
    return hashlib.sha256(canonical.encode()).hexdigest()


def _message_resource(message: BridgeMessage) -> str:
    return f"cyber-bridge:message/{message.seq}/sha256:{_message_digest(message)}"


def _intent_for(message: BridgeMessage) -> Intent:
    return Intent(
        BRIDGE, "execute_bridge_message", _message_resource(message), 25, ROUTE
    )


def _attestation_for(message: BridgeMessage) -> str:
    """The channel attestation over a message, DVN-style.

    An HMAC over the message's canonical fields under
    the verifier key -- the harness's stand-in for the
    route verifier's signature. It attests that a key
    signed these fields. Nothing more: in the incident,
    treating this as execution authority was the failure.
    """
    canonical = f"{message.seq}|{message.amount}|{message.recipient}"
    return hmac.new(VERIFIER_KEY, canonical.encode(), hashlib.sha256).hexdigest()


def _attestation_valid(message: BridgeMessage, attestation: str) -> bool:
    return hmac.compare_digest(_attestation_for(message), attestation)


# The route's genuine sends, tail of the sequence: the
# source ledger in setUp records exactly these, so the
# reconciled source counter is 329 -- as it was on the
# incident's source side when messages 330 and 331 were
# executed against nothing.
SEND_327 = BridgeMessage(327, 125_000, "solana-recipient-a")
SEND_328 = BridgeMessage(328, 250_000, "solana-recipient-b")
SEND_329 = BridgeMessage(329, 500_000, "solana-recipient-c")

# The incident's forged messages. Their amounts sum to
# the incident's minted total (Recorded); their sequence
# numbers are the incident's own. Both carry attestations
# made with the genuine key -- they verify.
FORGED_330 = BridgeMessage(330, 3_000_000, "solana-attacker-wallet")
FORGED_331 = BridgeMessage(331, 2_213_000, "solana-attacker-wallet")

# An in-range sequence that was never sent: the counter
# has passed it, but no source record exists for it at
# all. A validly-signed request for it must be refused
# the same way -- the counter alone is not a record.
GAP_200 = BridgeMessage(200, 500_000, "solana-recipient-c")

# Message 329's sequence and recipient carrying an
# inflated amount: a source record exists for the
# sequence, but this message is not that record's act.
MUTATED_329 = BridgeMessage(329, 5_213_000, "solana-recipient-c")

INTENT_329 = _intent_for(SEND_329)
INTENT_330 = _intent_for(FORGED_330)
INTENT_MUTATED_329 = _intent_for(MUTATED_329)


class SourceLedger:
    """The reconciled source-side record, as the dispatcher holds it.

    Stand-in for what a destination bridge can know from
    the source side: the sends that actually happened,
    each with its sequence, amount, and recipient, and
    whether it has already backed an execution. The
    counter is the highest recorded sequence -- the
    incident's destination had every means to know the
    source counter was 329; it executed 330 anyway,
    because it never asked.
    """

    def __init__(self) -> None:
        self._records: dict[int, list] = {}

    def record_send(self, message: BridgeMessage) -> None:
        self._records[message.seq] = [message.amount, message.recipient, False]

    @property
    def counter(self) -> int:
        return max(self._records) if self._records else 0

    def lookup(self, seq: int) -> tuple[int, str, bool] | None:
        record = self._records.get(seq)
        if record is None:
            return None
        return (record[0], record[1], record[2])

    def mark_spent(self, seq: int) -> None:
        self._records[seq][2] = True

    def mark_unspent(self, seq: int) -> None:
        # Release a reservation the dispatcher took before
        # presenting a permit whose consume then failed.
        # Only the dispatcher calls this, and only while
        # holding its dispatch lock, so a release can never
        # un-spend a record whose execution was recorded.
        self._records[seq][2] = False


class BridgeDispatcher:
    """Consequences on the destination side, reachable only via reconciliation + consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's bridge did not have. The
    dispatcher reconciles BEFORE it consumes: an
    execution request must name a source record that
    exists, matches it exactly, and is unspent. Only then
    is the permit presented to the kernel, and only a
    successful consume records an effect. The check and
    the spend are atomic: the dispatcher holds its
    dispatch lock across reconcile, reservation, consume,
    and effect recording, reserves the source record
    before the permit is presented, and rolls the
    reservation back if the consume fails. Two permits
    for the same message therefore cannot both pass the
    unspent check under concurrency (step 7), and a
    failed consume leaves the record unspent rather than
    locked (step 7). A reconciliation refusal is recorded
    in this dispatcher's own log and touches the kernel
    not at all -- the module docstring classifies that
    growth separately, and step 6 pins it.
    """

    def __init__(self, ledger: SourceLedger) -> None:
        self.ledger = ledger
        self.effects: list[tuple[int, int, str]] = []
        self.reconciliation_log: list[tuple[int, str]] = []
        self._dispatch_lock = threading.Lock()

    def reconcile(self, message: BridgeMessage) -> str | None:
        """None if the message reconciles; otherwise the refusal reason."""
        if message.seq > self.ledger.counter:
            return "sequence_beyond_source_counter"
        record = self.ledger.lookup(message.seq)
        if record is None:
            return "no_source_record"
        amount, recipient, spent = record
        if (amount, recipient) != (message.amount, message.recipient):
            return "source_record_mismatch"
        if spent:
            return "source_record_spent"
        return None

    def dispatch(
        self, kernel: GovernanceKernel, permit: str | None, message: BridgeMessage
    ) -> bool:
        # The lock is held across the whole sequence so
        # the reconcile-check, the reservation, the
        # consume, and the effect recording are one atomic
        # step with respect to any other dispatch through
        # this dispatcher: no second dispatch can observe
        # this message's source record between the check
        # and the spend.
        with self._dispatch_lock:
            reason = self.reconcile(message)
            if reason is not None:
                self.reconciliation_log.append((message.seq, reason))
                return False
            if permit is None:
                return False
            # Reserve the source record before the permit
            # is presented; roll the reservation back if
            # consumption fails, so a denied consume is
            # neither a spend nor a lockout of the record.
            self.ledger.mark_spent(message.seq)
            if not kernel.consume(permit, _intent_for(message)):
                self.ledger.mark_unspent(message.seq)
                return False
            self.effects.append((message.seq, message.amount, message.recipient))
            return True


class _AttestationOnlyExecutor:
    """Deliberately unguarded double for the negative control.

    The incident's own dispatch shape: a message whose
    channel attestation verifies is executed -- no source
    record consulted, no permit, no reconciliation. It
    exists only to prove the scenario's refusals
    discriminate: under this double the forged message
    must EXECUTE, or the scenario would be refusing by
    construction rather than by the governed path.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[int, int, str]] = []

    def dispatch(self, message: BridgeMessage, attestation: str) -> bool:
        if not _attestation_valid(message, attestation):
            return False
        self.effects.append((message.seq, message.amount, message.recipient))
        return True


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued,
    unspent permit spends for any intent. It exists only
    to prove the scenario's denial assertions discriminate
    -- under this double a genuine permit must spend on
    the forged message's intent, or the scenario would be
    denying by construction rather than by the kernel's
    binding.
    """

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        valid = permit in self._issued and permit not in self._spent
        if valid:
            self._spent.add(permit)
        self.append(
            "permit_consumed" if valid else "permit_rejected",
            {"intent_hash": intent_hash},
            timestamp_ns,
        )
        return valid


class _UnguardedConsumeKernel(GovernanceKernel):
    """Deliberately unguarded kernel double for the negative control.

    Its consume() performs none of the kernel's spend-path
    checks -- neither token authentication nor the
    token-to-intent binding -- and delegates straight to
    the state. Paired with the intent-blind state double
    above, no layer binds the permit to the presented
    intent, so a genuine permit must spend on the forged
    message here. This is the kernel-side half of the
    incident's shape: authority artifacts honored without
    the binding that makes them authority for THIS act.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


class _RendezvousConsumeKernel:
    """Timing double wrapping the real kernel, for step 7.

    The first consume call waits at a two-party barrier
    for a second concurrent consume call, so if two
    racing dispatches both reach the spend path, both are
    inside it at once and both permits spend -- the race
    is forced to overlap rather than left to scheduler
    luck. If only one dispatch reaches consume (the
    governed shape), the barrier times out and that
    single consume proceeds alone. Every decision is
    still made by the wrapped real kernel; the wrapper
    controls nothing but timing.
    """

    def __init__(self, kernel: GovernanceKernel) -> None:
        self._kernel = kernel
        self._barrier = threading.Barrier(2)

    def consume(self, permit: str, intent: Intent) -> bool:
        try:
            self._barrier.wait(timeout=1.0)
        except threading.BrokenBarrierError:
            pass
        return self._kernel.consume(permit, intent)


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class CyberBridgeIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"execute_bridge_message"}),
            10_000,
            frozenset({"execute_bridge_message"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = SourceLedger()
        for send in (SEND_327, SEND_328, SEND_329):
            self.ledger.record_send(send)
        self.dispatcher = BridgeDispatcher(self.ledger)

    def _kernel(
        self,
        state: InMemoryKernelState | None = None,
        *,
        kernel_class: type[GovernanceKernel] = GovernanceKernel,
    ) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
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

    # -- positive control -------------------------------------------------

    def test_positive_control_reconciled_message_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, _intent_for(SEND_328))
        # The one legitimate execution in this control: a
        # message that matches its source record exactly,
        # dispatched under a permit bound to that exact
        # act, executes once.
        self.assertTrue(self.dispatcher.dispatch(self.kernel, permit, SEND_328))
        self.assertEqual(
            [(328, 250_000, "solana-recipient-b")], self.dispatcher.effects
        )
        # The same message cannot execute twice: the
        # source record is spent, so the replay is refused
        # at reconciliation before the kernel is touched,
        # and the spent permit itself is rejected at
        # consume on the raw route.
        audit_len_before = len(self.kernel.audit)
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit, SEND_328))
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertEqual(
            [(328, "source_record_spent")], self.dispatcher.reconciliation_log
        )
        self.assertFalse(self.kernel.consume(permit, _intent_for(SEND_328)))
        self.assertEqual(
            [(328, 250_000, "solana-recipient-b")], self.dispatcher.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1 (case a): sequence beyond the reconciled counter ------------

    def test_step1_forged_message_beyond_source_counter_refused(self) -> None:
        # The incident's exact precondition, asserted
        # before any refusal: the forged messages'
        # attestations are VALID. The attacker holds the
        # genuine verifier key (stolen), so both forged
        # messages sign exactly as genuine ones do. Any
        # refusal below therefore cannot be credited to a
        # signature check -- the signatures pass.
        self.assertTrue(_attestation_valid(FORGED_330, _attestation_for(FORGED_330)))
        self.assertTrue(_attestation_valid(FORGED_331, _attestation_for(FORGED_331)))
        self.assertEqual(329, self.ledger.counter)
        # At the governed dispatcher, both forged messages
        # are refused at reconciliation -- with no permit,
        # and with a genuine permit for the real message
        # 329. The counter says these acts never happened
        # on the source side; there is no record either
        # could match. The refusal precedes any consume:
        # the kernel audit does not grow across the gated
        # attempts.
        permit_329 = self._issue_permit(self.kernel, INTENT_329)
        audit_len_before = len(self.kernel.audit)
        self.assertFalse(self.dispatcher.dispatch(self.kernel, None, FORGED_330))
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit_329, FORGED_330))
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit_329, FORGED_331))
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertEqual(
            [
                (330, "sequence_beyond_source_counter"),
                (330, "sequence_beyond_source_counter"),
                (331, "sequence_beyond_source_counter"),
            ],
            self.dispatcher.reconciliation_log,
        )
        self.assertEqual([], self.dispatcher.effects)
        # On the kernel-visible routes the forged message
        # is refused too. Bare evaluate: the kernel
        # declines to mint without approval.
        decision = self.kernel.evaluate(INTENT_330)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        # The message's own valid attestation, presented
        # as if it were a permit -- the incident's exact
        # move, a channel signature treated as execution
        # authority. As a permit it is a fabricated token,
        # and the kernel treats it as one.
        self.assertFalse(
            self.kernel.consume(_attestation_for(FORGED_330), INTENT_330)
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(INTENT_330),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual([], self.dispatcher.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2 (case b): no source record at all ----------------------------

    def test_step2_message_with_no_source_record_refused(self) -> None:
        # A validly-signed request for an in-range sequence
        # that was never sent: the counter has passed 200,
        # but no source record exists for it at all. The
        # counter alone is not a record, and a signature
        # over a send that never happened is a signature
        # over nothing.
        self.assertTrue(_attestation_valid(GAP_200, _attestation_for(GAP_200)))
        self.assertIsNone(self.ledger.lookup(200))
        self.assertFalse(self.dispatcher.dispatch(self.kernel, None, GAP_200))
        self.assertEqual(
            [(200, "no_source_record")], self.dispatcher.reconciliation_log
        )
        decision = self.kernel.evaluate(_intent_for(GAP_200))
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.kernel.consume(_attestation_for(GAP_200), _intent_for(GAP_200))
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual([], self.dispatcher.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3 (case c): source record exists, message differs --------------

    def test_step3_message_differing_from_source_record_refused_at_binding(self) -> None:
        permit = self._issue_permit(self.kernel, INTENT_329)
        # The gated route: sequence 329 has a source
        # record, but this message is not that record's
        # act -- the amount is the incident's whole minted
        # total wearing a genuine sequence number. The
        # dispatcher refuses it at reconciliation.
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit, MUTATED_329))
        self.assertEqual(
            [(329, "source_record_mismatch")], self.dispatcher.reconciliation_log
        )
        # The raw kernel route: the genuine permit for the
        # true message, presented against the mutated
        # message. The dispatcher derives the intent from
        # the message actually presented, so the permit is
        # bound to a different intent and spends on this
        # one not at all. A source record for the sequence
        # does not launder a different amount.
        self.assertFalse(self.kernel.consume(permit, INTENT_MUTATED_329))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(INTENT_MUTATED_329),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual([], self.dispatcher.effects)
        # The denials were binding, not lockout: the true
        # message still executes under the same permit.
        self.assertTrue(self.dispatcher.dispatch(self.kernel, permit, SEND_329))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4 (case d): the legitimate path, exactly once -------------------

    def test_step4_legitimate_message_executes_once_replay_refused(self) -> None:
        permit = self._issue_permit(self.kernel, INTENT_329)
        # A message matching a real source record exactly,
        # carried by a single-use permit bound to that
        # exact act, executes -- once.
        self.assertTrue(self.dispatcher.dispatch(self.kernel, permit, SEND_329))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        # Replay of the same message under the same permit
        # is refused at both layers: reconciliation sees
        # the spent source record, and the spent permit is
        # rejected at consume. A bridge message is not a
        # reusable credential.
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit, SEND_329))
        self.assertEqual(
            [(329, "source_record_spent")], self.dispatcher.reconciliation_log
        )
        self.assertFalse(self.kernel.consume(permit, INTENT_329))
        # Re-aimed at the forged message, the spent permit
        # is likewise rejected on the raw route (the gated
        # route refuses 330 at reconciliation regardless).
        self.assertFalse(self.kernel.consume(permit, INTENT_330))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ------------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, INTENT_329, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the forged message signed
        # with an unauthorized key: whoever holds the
        # channel's verifier key does not thereby hold the
        # approval authority's key, and cannot mint the
        # bridge's approval.
        forged_envelope = signed_envelope(
            self.kernel, INTENT_330, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(INTENT_330, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine envelope for message 329
        # presented for the forged message: a real approval
        # for a real act is not approval for a forged one.
        decision = self.kernel.evaluate_with_approval(INTENT_330, genuine_envelope)
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
        decision = self.kernel.evaluate_with_approval(INTENT_329, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the attempt sequence ---------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit: every consume rejection, every approval
    # rejection, and every denied decision in the sequence
    # becomes a near-miss record in the derived incident
    # report. The bare require_approval decision is in the
    # canonical audit (and counted below) but is NOT
    # derived as a near-miss -- the expected near-miss
    # count is built from the event classes the channel
    # actually derives. The two reconciliation refusals in
    # the sequence are likewise NOT near-misses: they
    # append nothing to the kernel audit (asserted inline,
    # by audit length, at the moment each occurs) and live
    # only in the dispatcher's reconciliation log, which
    # this step counts separately. The step pins both
    # boundaries instead of papering over either.
    #
    # The frozen sequence below is the full attempt
    # sequence of steps 1-5, not a subset: the
    # beyond-counter evaluation and attestation-as-permit
    # route (step 1), the gated attempt under another
    # message's permit (step 1's route, at the dispatcher),
    # that permit on the raw route, the mutated-bytes
    # dispatch (step 3), both approval-envelope attempts
    # (step 5), the one legitimate execution, the
    # spent-record replay at the dispatcher, and the
    # spent-permit replay at consume (step 4).
    #
    # Counts below were derived analytically from the
    # event classes the channel derives and the audit
    # growth each route produces, mirroring the executed
    # counts of PR #386's step 7 route-for-route, and are
    # pinned from the executed run at this head
    # (2026-11-24): the assertions below passed exactly
    # as derived, so the derived counts are the executed
    # counts.

    def test_step6_incident_channel_surfaces_the_forged_message_sequence(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        permit_329 = self._issue_permit(
            self.kernel, INTENT_329, approval_id="approval-329", nonce="nonce-329"
        )
        permit_328 = self._issue_permit(
            self.kernel,
            _intent_for(SEND_328),
            approval_id="approval-328",
            nonce="nonce-328",
        )
        # The forged message, attempted on every route:
        # its own say-so, its valid attestation as a
        # permit, and a genuine permit for another message
        # -- at the gated dispatcher first (refused at
        # reconciliation, kernel untouched), then raw.
        self.kernel.evaluate(INTENT_330)
        self.assertFalse(self.kernel.consume(_attestation_for(FORGED_330), INTENT_330))
        audit_len_before = len(self.kernel.audit)
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit_328, FORGED_330))
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertFalse(self.kernel.consume(permit_328, INTENT_330))
        # The mutated message under the genuine permit.
        self.assertFalse(self.kernel.consume(permit_329, INTENT_MUTATED_329))
        forged_envelope = signed_envelope(
            self.kernel,
            INTENT_330,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(INTENT_330, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the
        # genuine envelope for message 329 presented for
        # the forged message. A real approval for a real
        # act is not approval for a forged one; the
        # decision is a denial and the rejection lands in
        # the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            INTENT_329,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(INTENT_330, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate execution still lands; the
        # forged campaign did not.
        self.assertTrue(self.dispatcher.dispatch(self.kernel, permit_329, SEND_329))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        # Step 4's replays, also in the frozen sequence:
        # the same message re-presented at the dispatcher
        # (refused at reconciliation -- the source record
        # is spent -- with the kernel audit untouched), and
        # the spent permit re-presented at consume.
        audit_len_before = len(self.kernel.audit)
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit_329, SEND_329))
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertFalse(self.kernel.consume(permit_329, INTENT_329))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        self.assertEqual(
            [
                (330, "sequence_beyond_source_counter"),
                (329, "source_record_spent"),
            ],
            self.dispatcher.reconciliation_log,
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
        # The four counts below are the analytically
        # derived expectations (see the step comment
        # above), pinned from the executed run at this
        # head (2026-11-24).
        self.assertEqual(4, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The require_approval decision above and
        # the two reconciliation refusals are recorded
        # attempts that contribute zero near-miss records
        # at this commit.
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

    # -- step 7: concurrent dispatch and reservation rollback -----------------
    #
    # The sequential tests above pin exactly-once for
    # replayed presentations. Exactly-once must also hold
    # when the presentations are concurrent: two distinct
    # valid permits for the same source message, dispatched
    # at the same time, are two approvals of the same act,
    # not two acts. Before the fix pass this scenario's
    # dispatcher checked the record's spent flag, consumed,
    # and only then marked the record spent, so both
    # dispatches could observe the record unspent and both
    # execute -- reproduced at the pre-fix head with a
    # barrier-wrapped kernel: both dispatches returned
    # True and message 329 appeared twice in the effects.
    # These two tests pin the governed shape: the spend is
    # atomic with the check, and a failed consume rolls
    # its reservation back.

    def test_step7_concurrent_dispatches_of_one_source_record_execute_once(self) -> None:
        permit_a = self._issue_permit(
            self.kernel, INTENT_329, approval_id="approval-329-a", nonce="nonce-329-a"
        )
        permit_b = self._issue_permit(
            self.kernel, INTENT_329, approval_id="approval-329-b", nonce="nonce-329-b"
        )
        # The rendezvous wrapper forces any two consumes
        # that both reach the spend path to overlap inside
        # it: on the unfixed dispatcher both permits spend
        # and the message executes twice.
        racing_kernel = _RendezvousConsumeKernel(self.kernel)
        results: list[bool] = []
        threads = [
            threading.Thread(
                target=lambda p=p: results.append(
                    self.dispatcher.dispatch(racing_kernel, p, SEND_329)
                )
            )
            for p in (permit_a, permit_b)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Exactly one dispatch executes the message. The
        # loser is refused at reconciliation -- by the time
        # it can look, the source record is spent -- and
        # never reaches consume at all: its permit is
        # neither consumed nor rejected, because the gate,
        # not the kernel, turned it away.
        self.assertEqual([False, True], sorted(results))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        self.assertEqual(
            [(329, "source_record_spent")], self.dispatcher.reconciliation_log
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    def test_step7_failed_consume_rolls_back_the_source_reservation(self) -> None:
        permit_328 = self._issue_permit(
            self.kernel,
            _intent_for(SEND_328),
            approval_id="approval-328-r",
            nonce="nonce-328-r",
        )
        permit_329 = self._issue_permit(
            self.kernel, INTENT_329, approval_id="approval-329-r", nonce="nonce-329-r"
        )
        # Message 329 reconciles, so the dispatcher
        # reserves its source record and presents the
        # permit -- the wrong message's permit, which
        # consume rejects on the intent binding. The
        # reservation must roll back: a failed consume is
        # a denial, not a spend, and not a lockout of the
        # record against the message's genuine permit.
        self.assertFalse(self.dispatcher.dispatch(self.kernel, permit_328, SEND_329))
        self.assertEqual([], self.dispatcher.effects)
        self.assertEqual([], self.dispatcher.reconciliation_log)
        self.assertEqual(
            (500_000, "solana-recipient-c", False), self.ledger.lookup(329)
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        # The true message still executes under its own
        # permit, exactly once.
        self.assertTrue(self.dispatcher.dispatch(self.kernel, permit_329, SEND_329))
        self.assertEqual(
            [(329, 500_000, "solana-recipient-c")], self.dispatcher.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ------------------------------------------------------

    def test_negative_control_unguarded_paths_would_execute(self) -> None:
        # The incident's own dispatch shape, first: an
        # executor that checks only the channel attestation
        # EXECUTES the forged message, because its
        # attestation is valid. That is precisely what the
        # destination bridge did. The governed dispatcher
        # refuses the same message at reconciliation.
        attestation_only = _AttestationOnlyExecutor()
        self.assertTrue(
            attestation_only.dispatch(FORGED_330, _attestation_for(FORGED_330))
        )
        self.assertEqual(
            [(330, 3_000_000, "solana-attacker-wallet")], attestation_only.effects
        )
        self.assertFalse(self.dispatcher.dispatch(self.kernel, None, FORGED_330))
        self.assertEqual([], self.dispatcher.effects)
        # The kernel-side half: with consume unguarded at
        # BOTH layers -- a kernel double whose consume skips
        # token authentication and the token-to-intent
        # binding, over a state double whose consume ignores
        # the store's binding -- a genuine permit for the
        # real message spends on the forged message's
        # intent. No layer asks whether the act was ever
        # sourced or whether the permit names this act.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        blind_permit = self._issue_permit(blind_kernel, INTENT_329)
        self.assertTrue(blind_kernel.consume(blind_permit, INTENT_330))
        # Contrast, same attempt against the real backend:
        # denied (step 1's and step 6's route).
        real_permit = self._issue_permit(self.kernel, INTENT_329)
        self.assertFalse(self.kernel.consume(real_permit, INTENT_330))
        self.assertEqual([], self.dispatcher.effects)


if __name__ == "__main__":
    unittest.main()
