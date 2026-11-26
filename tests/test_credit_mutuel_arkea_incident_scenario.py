"""Scenario test: the Crédit Mutuel Arkéa fraudulent
transfers (November 2026) -- payment orders issued
from the bank's own account through a compromised
service provider, after the connection was cut.

Incident (Recorded, from the bank's published
statement of November 4, 2026 as quoted in reporting,
and convergent reporting of the same facts): attackers
reached the French cooperative bank Crédit Mutuel
Arkéa's network through a service provider's platform;
Arkéa Capital, the group's private-equity arm, was
the entry point. Les Echos has since named the
provider as B4Finance, a French SaaS vendor serving
asset managers and private-equity firms (Recorded,
not bank-confirmed). The bank detected signs of
provider compromise on October 27, 2026, cut the
connection and alerted the authorities -- but on
November 1 payment orders went out from the bank's
own account anyway, using fake IBANs in the name of
Fortuneo (the group's online bank), sent as instant
transfers to accounts the fraudsters had opened at
other European banks and then converted to
cryptocurrency. Bitquery traced about $108.8M in USDC
withdrawn from Kraken, Crypto.com and OKX over 21
hours on November 1-2. The bank gave a provisional
estimate of about EUR 100M; ZachXBT estimated up to
about EUR 118M / $133M -- the bank validates only
"the order of magnitude." Customer accounts were not
touched. Paris prosecutors opened an investigation.
The first public alarm was raised November 2 by
on-chain investigator ZachXBT; the bank's statement
followed November 4.

The failure class (authorization failure, with a
supply-chain entry): the provider held standing
access that the bank's systems treated as payment
authority. The bank revoked the *connection* -- it
detected the compromise, cut the link, and alerted
the authorities -- and the authority survived the
revocation: five days later the bank's own account
issued payment orders nobody at the bank had
approved, to payees nobody at the bank had approved.
Disconnect is not revocation. A channel going dark
says nothing about whether the authority that flowed
through it is still spendable; here it was, and it
was spent. The exact technique that turned provider
access into payment authority is **Unknown** (the
bank's investigation is ongoing) and this scenario
does not invent one: it models only the authority
shape the record establishes -- standing provider
access, treated as payment authority, still usable
after the relationship was terminated.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Arkéa's
systems, the provider's platform, any payment rail,
or any real account. The mapping (Inferred, stated
here so it can be argued with): the consequential
act is executing a payment order from the bank's
account. That act requires a permit bound to the
exact payment -- payee IBAN, amount, and beneficiary
name, all carried in the intent's resource string,
so the kernel's exact-intent hash binds all three.
An approval for one payment therefore cannot
authorize a different payment arriving through the
same provider gateway: the same amount addressed to
a substituted payee (the incident's fake-IBAN shape)
makes a different intent whose approval does not
exist. Revocation is modeled three ways, because the
incident turns on it: as the end of an approval's
validity window (an authorization granted while the
provider relationship lived is refused after the
window ends -- the governed counterpart of the
October 27 disconnect); as execution-time revocation
of an already-issued permit, demonstrated as its own
case (step 2b): where the permit's signed lifetime
is tied to the relationship window, the genuine
permit retained across the termination moment is
refused at ``consume`` after the window ends -- a
permit minted under the policy's default lifetime,
which is not tied to the window, is not tested
across that boundary and no revocation claim is
made for it; and as the refusal of the provider's
standing access artifact itself at the dispatch
boundary (standing access is not a permit, before
revocation or after it). And the provider
cannot mint the missing approval: approval authority
belongs to a named accountable human's key at the
bank, which control of the provider platform does
not confer. The only route from a payment order to
an executed payment is a successful
``GovernanceKernel.consume`` of a permit issued
through a verified approval envelope for that exact
payment.

A note on the payment identities, stated plainly
(the wording discipline of PR #403 applied from the
start): the reporting publishes no real IBAN, amount
per order, or beneficiary record for any fraudulent
order -- the fake IBANs are described only as being
in Fortuneo's name. The identities below are
therefore harness constructions in the incident's
shape (a verified supplier payment, the same amount
re-addressed to a Fortuneo-named account, a further
unapproved order), not recovered Arkéa artifacts.
The binding proof is a proof about the kernel's
treatment of exact identities, and it claims nothing
about any real Arkéa payment, IBAN, or amount. The
incident's figures (about EUR 100M, order of
magnitude only) are likewise not asserted per-order
anywhere in this module.

Setup: exactly one act is legitimate in this
scenario -- executing one exact payment, once, under
a permit issued through a verified approval
envelope: the accountable per-action authorization
actually granted. The incident's routes are then
attempted: a November 1 order with no approval at
all (standing access is its own authority, as the
bank's systems treated it); the relationship-era
authorization presented after the revocation moment,
the genuine issued permit retained and presented at
consume after termination under a permit lifetime
tied to the relationship window, and the provider's
standing access artifact presented as a permit; the
genuine approval for the
verified payment presented for the same amount
re-addressed to the fake Fortuneo-named IBAN; and
the consumed approval and its spent permit
re-presented for a second execution. The kernel must
deny each one, the consequence ledger must stay
empty for all of them, and every denial must land in
the audit record. A genuine, well-formed approval
for the exact payment verifies and authorizes
exactly one execution, and then spends.

Multiplicity discipline: reconciliation in this
scenario is per-item counted (``Counter`` / multiset),
never set-based. A dedicated probe presents the same
payment twice: a spent permit re-presented does not
pay twice, and a claimed-payments list that counts
the same consumed payment twice reconciles as a
phantom duplicate of count exactly 1, not as a
match. A fraudulent batch that lists one instruction
twice is likewise counted per occurrence -- a
duplicate instruction must not ride on one approval,
and must not vanish into a set.

Incident-channel surfacing (Verified at this commit,
by executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records.
A bare ``evaluate`` that returns ``require_approval``
-- the kernel declining to mint without approval --
appends a decision record to the canonical audit but
is NOT derived as a near-miss by the channel. The
scenario asserts both halves of that statement
exactly as they hold; it does not smooth the second
half over.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable
evidence). It proves nothing about any bank, payment
rail, SEPA scheme, or service-provider platform that
does not route payment execution through this kernel
-- a system that treats a provider's standing access
as payment authority is governed by nothing here. It
governs the payment before it executes, not the
intrusion afterward: the provider compromise, the
order submission path inside the bank's network, and
the conversion to cryptocurrency were consequences
of authority already treated as live, and are
described from the reporting, not reproduced. The
exact technique that turned provider access into
payment authority is Unknown and is not modeled. A
control not on the execution path governs nothing.

Adversarial transformation review: the full
eight-pass review (Flip, Reverse, Invert, Inside-Out,
Darken, Lighten, Amplify, Negate) for this incident
is recorded in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed
kernel path only -- exactly one governed external
consequence is permitted per correctly verified
approval bound to the exact payment, and any payment
path that executes orders on standing provider
access alone (the incident's own class) remains
outside this evidence and open.

Audit-growth classification (per AGENTS.md,
``NO_PERMIT != NO_GOVERNED_EFFECT``): a denied
attempt is not "no state changed." A denied attempt
appends audit records, counted per route: a bare
evaluate returning ``require_approval`` appends one
decision record; a ``consume`` rejection appends one
``permit_rejected`` record; a denied approval-envelope
evaluation appends two records -- an
``approval_rejected`` record and a denied decision
record. That growth is itself a governed effect --
evidence production -- bounded at two records per
attempt, append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability.
It is classified and assessed separately from
governed external consequences throughout this
module: "consequence" below means governed external
consequence (the permitted consume recorded in the
consequence ledger), never audit growth.
"""

from __future__ import annotations

from collections import Counter
import unittest

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The relationship window for the execution-time
# revocation case (step 2b): a permit issued while
# the provider relationship lived carries this signed
# lifetime, so its life ends with the relationship.
# The termination advance in step 2b (NOW + 2_000,
# the same advance step 2 uses) is past this window;
# the in-window control consume (NOW + 1_000) is
# inside it. Under the policy's default permit
# lifetime (4 hours) a permit is NOT tied to the
# window -- step 2b makes no claim for that
# configuration, and the module docstring says so.
RELATIONSHIP_PERMIT_TTL_NS = 1_500
# The service provider's payment gateway: the channel
# through which payment orders arrived at the bank.
# Every intent below is an act proposed under this
# gateway identity; in the incident the orders DID
# arrive through the provider's platform -- that was
# the problem, not a mitigating fact. Principal and
# session identity are part of the bound intent; they
# are not themselves authority for anything.
GATEWAY = "agent:service-provider-payment-gateway"
# The session of the November 1 orders, in the
# harness's naming.
SESSION = "provider-gateway-session-2026-11-01"
# The enrolled provider identity: the one presenter
# the negative control's standing-access rule accepts.
PROVIDER = "enrolled-service-provider"

ACTION = "execute_payment"

# The exact payments, each identity carrying payee
# IBAN, amount, and beneficiary name -- the fields a
# provider session cannot stand in for. Harness
# constructions (see the module docstring): the
# reporting publishes no real IBAN or per-order
# amount for any order, fraudulent or legitimate.
VERIFIED_IBAN = "FR7611112222333344445555666"
FORTUNEO_NAMED_IBAN = "FR7699998888777766665555444"
FRAUD_IBAN = "FR7655554444333322221111000"

# The one legitimate payment: a verified supplier
# payment a named accountable human at the bank has
# approved for execution in this scenario.
APPROVED_PAYMENT = (
    f"arkea:sepa-instant/iban:{VERIFIED_IBAN}"
    ":amount_eur:4800000:beneficiary:verified-supplier"
)
# The incident's fake-IBAN shape: the SAME amount,
# re-addressed to a Fortuneo-named account at another
# bank. Every channel signal -- gateway, session,
# amount -- is identical to the approved payment.
# Only the payee differs, and the exact-intent
# binding compares the whole payment identity, so
# the approval does not travel.
SUBSTITUTED_PAYMENT = (
    f"arkea:sepa-instant/iban:{FORTUNEO_NAMED_IBAN}"
    ":amount_eur:4800000:beneficiary:fortuneo-named-account"
)
# A November 1 order in the incident's shape: a
# further payment to a Fortuneo-named fake IBAN, for
# which no approval of any kind exists. Standing
# provider access is the only thing ever offered
# for it.
FRAUD_PAYMENT = (
    f"arkea:sepa-instant/iban:{FRAUD_IBAN}"
    ":amount_eur:7300000:beneficiary:fortuneo-named-account"
)

APPROVED_INTENT = Intent(GATEWAY, ACTION, APPROVED_PAYMENT, 25, SESSION)
SUBSTITUTED_INTENT = Intent(GATEWAY, ACTION, SUBSTITUTED_PAYMENT, 25, SESSION)
FRAUD_INTENT = Intent(GATEWAY, ACTION, FRAUD_PAYMENT, 40, SESSION)

# The provider's standing access artifact itself, as
# an inert stand-in string. In the incident this
# standing access was the whole payment authority:
# the bank's systems accepted its presence as
# authorization, before the disconnect and -- the
# failure -- after it. Here it is presented at the
# dispatch boundary as if it were a permit.
PROVIDER_ACCESS_TOKEN = "provider-standing-access-inert-9c41"


def reconcile_payments(kernel: GovernanceKernel, claimed_hashes: list[str]) -> dict:
    """Per-item (multiset) reconciliation of claimed payments.

    ``claimed_hashes`` is a list of intent hashes, one
    entry per claimed payment occurrence. Consumed
    occurrences are counted from the kernel audit with
    a ``Counter`` -- never a set -- so a duplicate
    claim for the same payment is a phantom of count
    exactly (claimed - consumed), and an omitted
    occurrence is unreported by its exact count. A
    set-based check would collapse duplicates and pass
    them.
    """
    consumed_counts = Counter(
        record["payload"]["intent_hash"]
        for record in kernel.audit
        if record["event"] == "permit_consumed"
    )
    claimed_counts = Counter(claimed_hashes)
    phantom = claimed_counts - consumed_counts
    unreported = consumed_counts - claimed_counts
    return {
        "ok": not phantom and not unreported,
        "phantom_counts": dict(phantom),
        "unreported_counts": dict(unreported),
        "consumed_counts": dict(consumed_counts),
    }


class PaymentExecutor:
    """Payment execution, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the incident's payment path did
    not have: in the incident, the provider's standing
    access WAS the execution path, and the orders
    followed immediately. Here the harness records an
    effect only when the kernel consumes a permit for
    the exact intent. A denial is therefore directly
    observable as the absence of a governed external
    consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a
    governed effect, classified separately in the
    module docstring.) Every presentation is recorded
    in ``attempts`` as well, so step 6 can reconcile
    attempts against effects as multisets: per item,
    counted, duplicates included.
    """

    def __init__(self) -> None:
        self.attempts: list[tuple[str, str]] = []
        self.effects: list[tuple[str, str]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        self.attempts.append((intent.action, intent.resource))
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


class StandingAccessExecutor:
    """The incident's ungoverned baseline, as a test-local double.

    Authorizes payment by the presenting provider's
    standing access alone -- the rule the bank's
    systems effectively ran: if the order arrives
    under the enrolled provider's access, it pays.
    The payment's approval is never consulted, and
    neither is the relationship's state: the double
    accepts a ``relationship_terminated`` fact and
    does not read it, which is the incident exactly --
    the connection was cut on October 27 and the
    access still paid on November 1, because nothing
    on the payment path treated termination as
    revocation. A batch listing one instruction twice
    pays twice, because nothing counts occurrences
    either. Test-local; never imported by runtime
    code.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def pay(
        self,
        presenter: str,
        intent: Intent,
        *,
        relationship_terminated: bool = False,
    ) -> bool:
        # The termination fact is accepted and ignored:
        # the check below is the whole rule, and the
        # rule never consults it. That omission is the
        # incident.
        _ = relationship_terminated
        if presenter != PROVIDER:
            return False
        self.effects.append((intent.action, intent.resource))
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class CreditMutuelArkeaIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = PaymentExecutor()

    def _kernel(self, *, clock=None, permit_ttl_ns=None) -> GovernanceKernel:
        policy_kwargs = {}
        if permit_ttl_ns is not None:
            policy_kwargs["max_permit_ttl_ns"] = permit_ttl_ns
        policy = Policy(
            frozenset({ACTION}),
            10_000,
            frozenset({ACTION}),
            authority_trust=trust_for(self.verifier),
            **policy_kwargs,
        )
        return GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=(lambda: NOW) if clock is None else clock,
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

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_INTENT)
        # The one legitimate act: execution of the exact
        # approved payment under a genuine, well-formed,
        # verified approval executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)
        # The same permit cannot pay it twice -- a
        # verified approval is not a standing payment
        # permission for the gateway or the provider.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all ----------------------------------------

    def test_step1_no_approval_at_all_denied(self) -> None:
        # The incident's baseline route: the order
        # arrives through the provider's gateway and the
        # bank's account pays. On the governed path an
        # order is not an approval: the kernel declines
        # to mint, and nothing pays.
        decision = self.kernel.evaluate(FRAUD_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, FRAUD_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: after the disconnect, the prior authority is refused --------
    #
    # The incident's core failure, inverted. The bank
    # detected the compromise on October 27, cut the
    # connection, and alerted the authorities -- and on
    # November 1 the standing access still paid. On the
    # governed path, revocation is not a network event:
    # it is the end of the authority itself. An approval
    # granted while the provider relationship lived
    # carries a validity window; after the window ends
    # (the revocation moment), the same artifact is
    # refused even for the payment it genuinely
    # approved, and the provider's standing access
    # artifact presented at the dispatch boundary is
    # rejected as what it always was: not a permit.

    def test_step2_revoked_relationship_authority_refused(self) -> None:
        clock_cell = [NOW]
        kernel = self._kernel(clock=lambda: clock_cell[0])
        envelope = signed_envelope(
            kernel,
            APPROVED_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-relationship-era",
            nonce="nonce-relationship-era",
        )
        # While the relationship lived: the genuine
        # approval verifies and a permit mints. Standing
        # arrangements were real authority while they
        # lasted -- the incident is not that the provider
        # was never trusted, it is that the trust
        # outlived its revocation.
        decision = kernel.evaluate_with_approval(APPROVED_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        # The revocation moment: the clock passes the end
        # of the approval's window (October 27, in the
        # incident's naming -- detection, disconnect,
        # authorities alerted).
        clock_cell[0] = NOW + 2_000
        # The same envelope, for its own payment, after
        # revocation: expired. Terminated authority
        # authorizes nothing -- not a new order, and not
        # even the payment it was honestly issued for.
        decision = kernel.evaluate_with_approval(APPROVED_INTENT, envelope)
        self.assertEqual(("deny", "approval_expired"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)
        # And the provider's standing access artifact,
        # presented at the dispatch boundary for a
        # November 1 order, is what it was before the
        # disconnect too: not a permit. The November 1
        # route -- standing access, post-termination --
        # reaches no execution path.
        self.assertFalse(
            self.executor.execute(kernel, PROVIDER_ACCESS_TOKEN, FRAUD_INTENT)
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(1, len(_events(kernel, "approval_verified")))
        self.assertEqual(0, len(_events(kernel, "permit_consumed")))
        rejected = _events(kernel, "approval_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual("approval_expired", rejected[0]["payload"]["reason"])
        self.assertEqual(1, len(_events(kernel, "permit_rejected")))
        self.assertTrue(kernel.verify_audit())

    # -- step 2b: the issued permit itself, consumed after termination -------
    #
    # Execution-time revocation, as its own case --
    # separate from step 2's approval expiry. Step 2
    # never retained a permit across the revocation
    # moment: it re-presented the approval envelope
    # after its window ended (refused at evaluation,
    # ``approval_expired``) and presented the provider's
    # standing access artifact at consume (refused as a
    # malformed token). Neither attempt presented the
    # genuinely issued permit after termination, so the
    # claimed revocation-at-consume evidence did not
    # cover the one artifact that could actually have
    # paid (Codex P1 on PR #406, Verified by probe at
    # the pre-fix head: under the scenario policy's
    # default 4-hour permit lifetime, the genuine
    # permit consumed successfully 2,000 ns after
    # issuance). This case closes that gap in the only
    # configuration in which the kernel ties a permit's
    # life to the relationship: the policy's permit
    # lifetime is set to the relationship window, the
    # genuine permit is retained -- not discarded --
    # across the termination moment, and consumption of
    # the identical authorized payment is then required
    # to refuse.

    def test_step2b_issued_permit_refused_after_relationship_termination(self) -> None:
        clock_cell = [NOW]
        kernel = self._kernel(
            clock=lambda: clock_cell[0],
            permit_ttl_ns=RELATIONSHIP_PERMIT_TTL_NS,
        )
        executor = PaymentExecutor()
        # While the relationship lived: the genuine
        # approval verifies and a permit mints for the
        # exact approved payment. The permit is RETAINED
        # here -- the artifact step 2 discarded.
        permit = self._issue_permit(
            kernel,
            APPROVED_INTENT,
            approval_id="approval-revocation-consume",
            nonce="nonce-revocation-consume",
        )
        # In-window control, on a parallel kernel under
        # the identical tied-lifetime policy: the same
        # genuine permit shape, consumed before the
        # termination moment, pays exactly once. The
        # post-termination refusal below is therefore a
        # revocation refusal, not a permit that was dead
        # on arrival.
        control_clock = [NOW]
        control_kernel = self._kernel(
            clock=lambda: control_clock[0],
            permit_ttl_ns=RELATIONSHIP_PERMIT_TTL_NS,
        )
        control_executor = PaymentExecutor()
        control_permit = self._issue_permit(
            control_kernel,
            APPROVED_INTENT,
            approval_id="approval-revocation-control",
            nonce="nonce-revocation-control",
        )
        control_clock[0] = NOW + 1_000
        self.assertTrue(
            control_executor.execute(control_kernel, control_permit, APPROVED_INTENT)
        )
        self.assertEqual(
            [(ACTION, APPROVED_PAYMENT)], control_executor.effects
        )
        # The termination moment (October 27, in the
        # incident's naming): the clock passes the end
        # of the relationship window the permit's signed
        # lifetime was tied to -- the same NOW + 2_000
        # advance step 2 uses for the approval window.
        clock_cell[0] = NOW + 2_000
        # The retained genuine permit, presented at
        # consume for the identical payment it genuinely
        # authorized: refused. Already-issued payment
        # authority does not survive the termination of
        # the relationship that governed it.
        self.assertFalse(executor.execute(kernel, permit, APPROVED_INTENT))
        self.assertEqual([], executor.effects)
        self.assertEqual(1, len(_events(kernel, "approval_verified")))
        self.assertEqual(0, len(_events(kernel, "permit_consumed")))
        rejected = _events(kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_expired", rejected[0]["payload"]["reason"])
        self.assertTrue(kernel.verify_audit())
        self.assertTrue(control_kernel.verify_audit())

    # -- step 3: the genuine approval, a substituted payee -------------------
    #
    # The incident's fake-IBAN shape: an order for the
    # approved amount, addressed to a Fortuneo-named
    # account instead of the verified supplier. Same
    # gateway, same session, same amount -- everything
    # the bank's payment path saw in the incident is
    # identical except the payee. The exact-intent
    # binding compares the whole payment identity, so
    # the approval does not travel, and the genuine
    # permit itself, presented at the dispatch boundary
    # for the substituted payment, is rejected: a
    # permit spends on its own payment or not at all.

    def test_step3_substituted_payee_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, APPROVED_INTENT, self.verifier, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(SUBSTITUTED_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        permit = self._issue_permit(
            self.kernel,
            APPROVED_INTENT,
            approval_id="approval-payee-2",
            nonce="nonce-payee-2",
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, SUBSTITUTED_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        # The denial did not poison the path: the genuine
        # pair still admits.
        decision = self.kernel.evaluate_with_approval(APPROVED_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: a consumed approval cannot be reused -------------------------
    #
    # Single-use at both layers. The permit spends once
    # (the positive control); here the approval itself
    # is re-presented after its permit was consumed, to
    # mint a second permit for the same payment -- the
    # batch-resubmission shape, in which an already-paid
    # instruction is sent again under its original
    # authorization. The kernel refuses the replayed
    # approval outright: an approval authorizes one
    # execution, and having authorized it, it is spent
    # as an artifact, not merely as a permit.

    def test_step4_consumed_approval_cannot_be_reused(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            APPROVED_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-single-use",
            nonce="nonce-single-use",
        )
        decision = self.kernel.evaluate_with_approval(APPROVED_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.executor.execute(self.kernel, decision.permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)
        # The same approval envelope re-presented: no
        # second permit mints.
        decision = self.kernel.evaluate_with_approval(APPROVED_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_id_replayed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "approval_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual("approval_id_replayed", rejected[0]["payload"]["reason"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: multiplicity -- duplicates never double-count ---------------

    def test_step5_duplicate_instructions_counted_per_occurrence(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_INTENT)
        self.assertTrue(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        # A batch that lists the same instruction a
        # second time: the second presentation under the
        # spent permit pays nothing and consumes nothing.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)
        approved_hash = self.kernel.intent_hash(APPROVED_INTENT)
        # An exact per-item claim reconciles.
        exact = reconcile_payments(self.kernel, [approved_hash])
        self.assertTrue(exact["ok"])
        self.assertEqual({}, exact["phantom_counts"])
        self.assertEqual({}, exact["unreported_counts"])
        self.assertEqual({approved_hash: 1}, exact["consumed_counts"])
        # The duplicate probe: the same payment claimed
        # twice is a phantom of count exactly 1 under
        # multiset reconciliation. A set-based check
        # would collapse the duplicate and report a
        # match -- the double-count this probe exists to
        # catch, and the shape a duplicated batch line
        # would hide behind.
        duplicated = reconcile_payments(self.kernel, [approved_hash, approved_hash])
        self.assertFalse(duplicated["ok"])
        self.assertEqual({approved_hash: 1}, duplicated["phantom_counts"])
        self.assertEqual({}, duplicated["unreported_counts"])
        # And an empty claim under-reports by exactly 1.
        omitted = reconcile_payments(self.kernel, [])
        self.assertFalse(omitted["ok"])
        self.assertEqual({approved_hash: 1}, omitted["unreported_counts"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        # The full attempt sequence exercisable on one
        # kernel: the no-approval evaluation (step 1),
        # the genuine approval presented for the
        # substituted payee TWICE -- the identical
        # artifact, the duplicate-item probe (step 3's
        # route) -- the provider's standing access
        # artifact presented TWICE at the dispatch
        # boundary (steps 1-2's route), the one
        # legitimate execution, and the spent-permit
        # replay. The revocation route (step 2) requires
        # a moving clock and is pinned on its own kernel
        # there; its denial is the same
        # approval_rejected event class counted here and
        # would derive identically.
        self.kernel.evaluate(FRAUD_INTENT)
        duplicate = signed_envelope(
            self.kernel,
            APPROVED_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-reviewed",
            nonce="nonce-seq-reviewed",
        )
        for _ in range(2):
            decision = self.kernel.evaluate_with_approval(SUBSTITUTED_INTENT, duplicate)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_intent_mismatch", decision.reason)
        for _ in range(2):
            self.assertFalse(
                self.executor.execute(self.kernel, PROVIDER_ACCESS_TOKEN, FRAUD_INTENT)
            )
        # The one legitimate payment still lands; the
        # incident's routes did not.
        permit = self._issue_permit(
            self.kernel,
            APPROVED_INTENT,
            approval_id="approval-seq-run",
            nonce="nonce-seq-run",
        )
        self.assertTrue(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)
        # The spent permit re-presented: single-use.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_PAYMENT)], self.executor.effects)

        # Attempts and effects, reconciled as multisets:
        # every presented item is accounted for, the
        # duplicates counted per occurrence, and exactly
        # one item -- the authorized payment -- executed,
        # exactly once.
        self.assertEqual(
            Counter({(ACTION, FRAUD_PAYMENT): 2, (ACTION, APPROVED_PAYMENT): 2}),
            Counter(self.executor.attempts),
        )
        self.assertEqual(
            Counter({(ACTION, APPROVED_PAYMENT): 1}),
            Counter(self.executor.effects),
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
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # The duplicate probe, pinned: the identical
        # mismatched envelope was denied twice, and the
        # counted reconciliation reports the mismatch
        # reason twice. A set-based reconciliation would
        # report it once and lose exactly the duplicate.
        self.assertEqual(
            Counter({"approval_intent_mismatch": 2}),
            Counter(record["payload"]["reason"] for record in approval_rejected),
        )
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more,
        # no fewer. The require_approval decision above
        # contributes zero near-miss records at this
        # commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(7, report.near_misses)
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

    def test_negative_control_standing_access_pays_after_disconnect(self) -> None:
        # Same scenario, the governed boundary swapped
        # for the incident's own rule: authorize payment
        # by the presenting provider's standing access
        # alone, as the bank's payment path effectively
        # did. The relationship has been terminated --
        # the fact is handed to the rule and the rule
        # does not consult it -- so the November 1 order
        # PAYS, from the bank's own account, five days
        # after the disconnect. And a batch listing the
        # approved instruction twice pays twice, because
        # the rule counts nothing either. That is the
        # incident, reproduced at the exact layer it
        # happened: not the provider compromise (Unknown),
        # not the network -- the authorization check that
        # treated standing access as payment authority
        # and never learned that the authority had been
        # revoked. The denials in the steps above
        # therefore come from revocation-at-consume and
        # the exact payment binding, not from a harness
        # that denies by construction.
        blind = StandingAccessExecutor()
        self.assertTrue(
            blind.pay(PROVIDER, FRAUD_INTENT, relationship_terminated=True)
        )
        self.assertTrue(
            blind.pay(PROVIDER, APPROVED_INTENT, relationship_terminated=True)
        )
        self.assertTrue(
            blind.pay(PROVIDER, APPROVED_INTENT, relationship_terminated=True)
        )
        self.assertEqual(
            [
                (ACTION, FRAUD_PAYMENT),
                (ACTION, APPROVED_PAYMENT),
                (ACTION, APPROVED_PAYMENT),
            ],
            blind.effects,
        )
        # The standing-access rule is not indiscriminate
        # -- an outside presenter does not pass it. Its
        # defect is that provider access is ALL it
        # checks: it cannot tell an approved payment from
        # a fraudulent one, and it cannot hear a
        # revocation, which are the two distinctions the
        # incident turned on.
        self.assertFalse(
            blind.pay("outside-presenter", FRAUD_INTENT, relationship_terminated=True)
        )
        # Contrast, the identical November 1 route
        # against the governed kernel: no approval exists
        # for it, and none is minted (step 1's route).
        decision = self.kernel.evaluate(FRAUD_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        self.assertEqual("approval_required", decision.reason)


if __name__ == "__main__":
    unittest.main()
