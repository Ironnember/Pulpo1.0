"""Scenario test: the Gainsight / Salesforce connected-app
abuse (publicized 2025-11-20).

Incident (Recorded, from Salesforce's security advisory of
2025-11-20 and Gainsight's customer FAQ, first posted
2025-11-20): Salesforce identified unusual activity
involving Gainsight-published applications connected to
Salesforce, and assessed that the activity may have enabled
unauthorized access to certain customers' Salesforce data
through the app's connection. Salesforce states there is no
indication the issue resulted from any vulnerability in the
Salesforce platform; the activity appears related to the
app's external connection. As a precaution Salesforce
revoked the access and refresh tokens for all Gainsight
applications, removed them from AppExchange, and disabled
the connections on 2025-11-20. Gainsight's FAQ records that
Salesforce initially listed 3 impacted customers, that the
list was then expanded to a larger undisclosed number, and
that affected customers were notified by Salesforce on
2025-11-21; Gainsight engaged Mandiant for the forensic
investigation, and its Customer Success, Community,
Customer Education, Skilljar, and Staircase products
temporarily lost Salesforce read/write. Per Salesforce's
indicators of compromise shared through the FAQ, the first
unauthorized access dates to 2025-11-08. Google Threat
Intelligence (Austin Larsen, via reporting) puts
potentially affected Salesforce instances at more than
200. The Scattered Lapsus$ Hunters collective claimed
responsibility (via DataBreaches.net reporting). How the
app's connection was abused at the root -- the original
token-leak vector -- is still not public (Unknown). The
investigation itself has concluded (Gainsight's January
2026 technical explanation). The pattern is
the August Salesloft Drift campaign's: a third-party app's
standing, broadly scoped connection into each customer's
org, exercised far outside the app's intended function --
and Gainsight had itself been a victim of that campaign.

The failure is a trust-scope failure, not an authentication
failure: the connection was genuine, its holder reached the
platform legitimately, and the platform answered because
the connection existed -- not because the specific act was
authorized. A connected app's OAuth grant is a standing,
reusable, broadly scoped credential: it binds neither the
exact act (which object, which operation, which org) nor
the presenter who must prove, per use, that the use is the
app's own governed act rather than a token holder's.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce Salesforce, Gainsight,
any connected app, any customer data, or any network
behavior. The "app" is this harness holding intents; the
only route from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash AND bound to the app as presenter (Phase 3,
Item 4B), spent by that presenter with a valid proof. The
OAuth connection token is modeled as exactly what it is in
Pulpo's terms -- evidence that the app is connected. It is
not an approval envelope, not ceremony evidence, and not a
permit, and the kernel has no verb that derives read
authority from an integration's existence.

Setup: the app holds exactly one legitimate permit: one
exact read -- the customer-success sync for its own org,
the declared integration function -- issued through a
verified approval envelope and bound to the app as
presenter: the accountable per-action authorization
actually granted. The incident's acts are then attempted,
in sequence: bulk exports of cases, of accounts, and of
every object; the same sync against another customer's
org (one vendor-side compromise reaching every installed
org); the sync with its scope widened to all objects; the
genuine permit token presented by a token holder who is
not the app; forged and mismatched approvals; and the
spent permit replayed (the standing token's reusability,
which is the property that made the real connection
durable). The kernel must deny each one, the consequence
ledger must stay empty for all of them, and every denial
must land in the audit record.

Reconciliation (test-level, as in the filename-deception
and Mythos scenarios): the app's activity claim -- what
the vendor reports to a customer about what it did in the
customer's org -- is reconciled against the audit. A claim
that reports only the legitimate sync leaves the whole
extraction campaign as undisclosed attempts; a claim that
asserts an extraction as a consequence is unbacked; only a
claim that discloses every attempt and exactly the
consumed consequences reconciles. In the incident, the
gap between what the connection did and what anyone could
see it doing is what turned days of access into a
platform-wide revocation; reconciliation is the mechanism
that makes that gap a finding instead of a surprise.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules):
the derived incident report turns ``permit_rejected``
events, ``approval_rejected`` events, and denied decisions
into near-miss records. A bare ``evaluate`` that returns
``require_approval`` -- the kernel declining to mint without
approval -- appends a decision record to the canonical
audit but is derived as a near-miss by the channel since the issue #375 fix.
The scenario asserts both halves of that statement exactly as
they hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any deployed platform or integration
that does not route its reads through this kernel -- a
connection that answers first and checks the act never (or
checks it against nothing) is governed by nothing here. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken, Lighten,
Amplify, Negate) for this incident is recorded in this
scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence is
permitted, and any non-kernel connection path (the
incident's own class) remains outside this evidence and
open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." A denied attempt appends audit records, counted
per route: a bare evaluate returning ``require_approval``
appends one decision record; a ``consume`` rejection
appends one ``permit_rejected`` record; a denied
approval-envelope evaluation appends two records -- an
``approval_rejected`` record and a denied decision record.
That growth is itself a governed effect -- evidence
production -- bounded at two records per attempt,
append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. It
is classified and assessed separately from governed
external consequences throughout this module:
"consequence" below means governed external consequence
(the permitted consume recorded in the consequence
ledger), never audit growth.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
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
from tests.presenter_support import HmacPresenterVerifier, proof_for


NOW = 1_000_000
APP = "agent:gainsight-connected-app"
APP_PRESENTER = "app:gainsight-connected-app"
TOKEN_HOLDER_PRESENTER = "app:token-holder"
SESSION = "install-org-self-2026-08"
LATER_SESSION = "install-org-self-2027-01"

# The one act actually authorized: the app syncs
# customer-success data for the org that installed it --
# the declared integration function, and nothing else. The
# resource identity names the exact act; every object,
# operation, or org beyond it is a different resource and
# therefore a different intent.
SYNC_RESOURCE = "salesforce:org-self/customer-success/sync"
SYNC_INTENT = Intent(APP, "read_records", SYNC_RESOURCE, 25, SESSION)

# The incident's acts. None of them has an approval; each
# was answered in the incident because the platform checked
# that the connection existed, not that the holder was
# authorized for the specific act.
CASES_EXPORT_INTENT = Intent(
    APP, "read_records", "salesforce:org-self/cases/bulk-export", 25, SESSION
)
ACCOUNTS_EXPORT_INTENT = Intent(
    APP, "read_records", "salesforce:org-self/accounts/bulk-export", 25, SESSION
)
ALL_OBJECTS_EXPORT_INTENT = Intent(
    APP, "read_records", "salesforce:org-self/all-objects/bulk-export", 25, SESSION
)
# The declared function itself, aimed at another customer's
# org: one vendor-side compromise reaching every org that
# installed the app. The org is inside the bound resource
# identity, so this is a different intent, not a wider use
# of the same one.
CROSS_ORG_INTENT = Intent(
    APP, "read_records", "salesforce:org-other/customer-success/sync", 25, SESSION
)
# The permitted sync with its scope widened to every object
# -- the standing grant's real shape, one connection
# answering any query. The widening rides in the resource
# identity, inside the hashed intent, so it cannot pass as
# the approved sync.
WIDENED_SYNC_INTENT = Intent(
    APP,
    "read_records",
    "salesforce:org-self/customer-success/sync/scope-all-objects",
    25,
    SESSION,
)
OUT_OF_INTENT = (
    CASES_EXPORT_INTENT,
    ACCOUNTS_EXPORT_INTENT,
    ALL_OBJECTS_EXPORT_INTENT,
    CROSS_ORG_INTENT,
    WIDENED_SYNC_INTENT,
)

# The standing connection credential itself, presented as
# if it were a permit. Being connected is not authority
# for an act; the kernel must treat this string as a
# fabricated token, because that is what it is.
OAUTH_TOKEN = "gainsight-sfdc-connector:oauth-access-and-refresh-token"


class ConsequenceLedger:
    """Effects on the customer record, reachable only through a successful consume.

    This is the scenario's execution path: the harness
    executes an action (records its consequence) only when
    the kernel consumes a permit for that exact intent,
    presented as required. A denial is therefore directly
    observable as the absence of a governed external
    consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a
    governed effect, classified separately in the module
    docstring.)
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        *,
        presenter: str | None = None,
        presenter_proof: str | None = None,
    ) -> bool:
        if permit is None:
            return False
        if not kernel.consume(
            permit, intent, presenter=presenter, presenter_proof=presenter_proof
        ):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


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
# Counts, not mere presence: the same intent may be
# attempted repeatedly (in step 6, each out-of-intent act
# is attempted on three routes, so each attempt hash occurs
# 3 times in the audit), and a claim reconciles only if it
# reports the same count for every hash. A presence-only
# (set) comparison would collapse repeats to one and let a
# claim underreport repeated activity while still returning
# ok -- the failure the multiplicity pass identified in
# this module, and the one step 6b pins shut.
# Authorization-side records (approval_verified, allow
# decisions) are the authority's own trail, not app acts,
# and are excluded by design. This reconciliation is
# TEST-LEVEL, implemented against the public ``kernel.audit``
# read path, as in the filename-deception and Mythos
# scenarios: the shipped reconcilers reconcile filesystem
# effects and custody-domain outcomes, not a vendor-claimed
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
    audit_valid: bool = True  # False when verify_audit() fails / the chain is invalid


def reconcile_against_audit(kernel: GovernanceKernel, claim: dict) -> ClaimReconciliation:
    # Fail closed: reconciliation must verify the audit chain
    # FIRST. Deriving counts from an invalid chain would accept
    # fabricated provenance -- the exact failure this scenario
    # exists to expose.
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


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued,
    unspent permit spends for any intent. It exists only to
    prove the scenario's denial assertions discriminate --
    under this double the bulk export must EXECUTE, or the
    scenario would be denying by construction rather than by
    the kernel's binding.
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
    checks -- neither token authentication, nor the
    token-to-intent binding, nor the presenter binding --
    and delegates straight to the state. Paired with the
    intent-blind state double above, no layer binds the
    permit to the presented intent or presenter, so the
    bulk export must EXECUTE here, or the scenario's
    denials would be coming from the harness rather than
    from the binding layers. This is the incident's own
    shape: a connection that answers whatever its holder
    asks.
    """

    def consume(self, permit: str, intent: Intent, **kwargs) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


def _rejection_reasons(kernel: GovernanceKernel) -> list[str]:
    return [
        record["payload"].get("reason")
        for record in _events(kernel, "permit_rejected")
    ]


class GainsightIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.app_verifier = HmacPresenterVerifier(b"gainsight-app-secret")
        self.holder_verifier = HmacPresenterVerifier(b"token-holder-secret")
        self.policy = Policy(
            frozenset({"read_records"}),
            10_000,
            frozenset({"read_records"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()

    def _kernel(
        self,
        state: InMemoryKernelState | None = None,
        *,
        kernel_class: type[GovernanceKernel] = GovernanceKernel,
        presenters: dict | None = None,
    ) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        registry = (
            {
                APP_PRESENTER: self.app_verifier,
                TOKEN_HOLDER_PRESENTER: self.holder_verifier,
            }
            if presenters is None
            else presenters
        )
        return kernel_class(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            presenter_verifiers=registry,
            **kwargs,
        )

    def _issue_sync_permit(
        self,
        kernel: GovernanceKernel,
        *,
        approval_id: str = "approval-1",
        nonce: str = "approval-nonce-1",
    ) -> str:
        envelope = signed_envelope(
            kernel,
            SYNC_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        decision = kernel.evaluate_with_approval(
            SYNC_INTENT, envelope, presenter=APP_PRESENTER
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    def _app_proof(self, kernel: GovernanceKernel, permit: str, intent: Intent) -> str:
        return proof_for(kernel, self.app_verifier, permit, intent, APP_PRESENTER)

    def _spend_as_app(
        self, kernel: GovernanceKernel, permit: str, intent: Intent, ledger: ConsequenceLedger
    ) -> bool:
        return ledger.execute(
            kernel,
            permit,
            intent,
            presenter=APP_PRESENTER,
            presenter_proof=self._app_proof(kernel, permit, intent),
        )

    # -- positive control -------------------------------------------------

    def test_positive_control_sync_executes_exactly_once_for_its_presenter(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same sync twice --
        # a per-act authorization is not a standing connection.
        self.assertFalse(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the bulk export has no permit ------------------------------

    def test_step1_bulk_export_denied_connection_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for the cases export, and being connected is
        # not one.
        decision = self.kernel.evaluate(CASES_EXPORT_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, CASES_EXPORT_INTENT))
        # The holder presents the standing connection token
        # itself as its permit. The kernel treats it as what
        # it is: a fabricated token. The connection existed
        # in the incident; authority for this act did not.
        self.assertFalse(self.ledger.execute(self.kernel, OAUTH_TOKEN, CASES_EXPORT_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(CASES_EXPORT_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the incident's acts under the genuine sync permit ----------

    def test_step2_out_of_intent_acts_denied_under_genuine_sync_permit(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        # Presented by the app itself, with the app's own
        # valid proofs -- so the only thing that can deny
        # these is the intent binding. Each is a different
        # intent from the approved sync: a bulk export of
        # cases, of accounts, of every object; the declared
        # function aimed at another customer's org; and the
        # sync with its scope widened to all objects (the
        # standing grant's real shape). The one permit spends
        # on none of them.
        for intent in OUT_OF_INTENT:
            self.assertFalse(self._spend_as_app(self.kernel, permit, intent, self.ledger))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(5, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in OUT_OF_INTENT},
            rejected_hashes,
        )
        self.assertEqual(
            ["permit_intent_mismatch"] * 5, _rejection_reasons(self.kernel)
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denials were scope, not lockout: the permit
        # still spends on the exact act it was issued for,
        # by its own presenter.
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the stolen permit token spends nothing for a token holder --
    #
    # The incident's durable property was possession: whoever
    # held the connection's tokens could use the connection.
    # A Pulpo permit token is bound at issuance to its
    # presenter, and consume requires that presenter's proof
    # over the exact token and intent. Possession of the
    # token string -- the whole of what a token theft yields
    # -- is therefore not possession of the act.

    def test_step3_stolen_permit_token_does_not_spend_for_a_token_holder(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        # (a) The holder presents the genuine token with no
        # presenter at all -- the bearer posture.
        self.assertFalse(self.ledger.execute(self.kernel, permit, SYNC_INTENT))
        # (b) The holder presents it as a different,
        # registered presenter, with that presenter's own
        # valid proof: a real key, for the wrong identity.
        holder_proof = proof_for(
            self.kernel, self.holder_verifier, permit, SYNC_INTENT, TOKEN_HOLDER_PRESENTER
        )
        self.assertFalse(
            self.ledger.execute(
                self.kernel,
                permit,
                SYNC_INTENT,
                presenter=TOKEN_HOLDER_PRESENTER,
                presenter_proof=holder_proof,
            )
        )
        # (c) The holder claims the app's own identity and
        # forges the proof under a key it controls.
        forged_proof = proof_for(
            self.kernel,
            HmacPresenterVerifier(b"token-holder-secret"),
            permit,
            SYNC_INTENT,
            APP_PRESENTER,
        )
        self.assertFalse(
            self.ledger.execute(
                self.kernel,
                permit,
                SYNC_INTENT,
                presenter=APP_PRESENTER,
                presenter_proof=forged_proof,
            )
        )
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(
            [
                "permit_presenter_proof_required",
                "permit_presenter_mismatch",
                "permit_presenter_mismatch",
            ],
            _rejection_reasons(self.kernel),
        )
        # None of the attempts burned the permit: the app
        # itself still spends it, with its own proof.
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing ------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        # A consumed permit is not a refresh token:
        # re-presenting it for the same sync gets nothing,
        # and re-presenting it for an export gets nothing
        # either. The standing connection's reusability --
        # the property that let one compromise run for
        # days -- is the property single-use consumption
        # removes.
        self.assertFalse(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertFalse(
            self._spend_as_app(self.kernel, permit, CASES_EXPORT_INTENT, self.ledger)
        )
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals -----------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, SYNC_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the cases export signed with an
        # unauthorized key: whoever holds the connection
        # cannot mint the customer's authority.
        forged_envelope = signed_envelope(
            self.kernel, CASES_EXPORT_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(
            CASES_EXPORT_INTENT, forged_envelope, presenter=APP_PRESENTER
        )
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine sync envelope presented for the
        # export intent: a real approval for the declared
        # function is not approval for an extraction.
        decision = self.kernel.evaluate_with_approval(
            CASES_EXPORT_INTENT, genuine_envelope, presenter=APP_PRESENTER
        )
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)
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
            SYNC_INTENT, genuine_envelope, presenter=APP_PRESENTER
        )
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation -- the claim meets the record ----------------
    #
    # After the fact, the customer asks the question the
    # incident's customers had to ask Salesforce: what did
    # this connection actually do in our org? The vendor's
    # answer is a claim; the audit is the record. A claim
    # that reports the app's declared activity and nothing
    # else leaves every extraction attempt undisclosed --
    # which is exactly the visibility gap the incident ran
    # on. A claim that promotes an extraction to a
    # consequence is unbacked. Only the claim that discloses
    # the attempts and exactly the consumed consequences
    # reconciles.

    def test_step6_reconciliation_flags_the_campaign(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        # The one legitimate act executes.
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        # The campaign: every out-of-intent act attempted on
        # the routes the holder has -- its own say-so at
        # evaluate, the connection token as a token, and the
        # (now spent) genuine permit.
        for intent in OUT_OF_INTENT:
            self.kernel.evaluate(intent)
            self.assertFalse(self.ledger.execute(self.kernel, OAUTH_TOKEN, intent))
            self.assertFalse(self._spend_as_app(self.kernel, permit, intent, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)

        sync_hash = self.kernel.intent_hash(SYNC_INTENT)
        attempt_hashes = {
            self.kernel.intent_hash(intent) for intent in OUT_OF_INTENT
        }
        # True counts (re-derived): each of the 5 attempt
        # hashes occurs 3 times in the audit -- once per
        # route above (bare evaluate, connection token as a
        # token, spent genuine permit) -- for 15 attempt
        # records in total, against exactly 1 consequence.
        # The shipped claim below previously listed each
        # attempt hash ONCE and passed only because the
        # set-based checker collapsed the counts.
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({sync_hash: 1}, dict(consequences))
        self.assertEqual(
            {intent_hash: 3 for intent_hash in attempt_hashes}, dict(attempts)
        )
        self.assertEqual(15, sum(attempts.values()))
        # The corrected honest claim: every attempt hash
        # listed 3 times, the consequence listed once.
        honest_attempts = sorted(
            intent_hash for intent_hash in attempt_hashes for _ in range(3)
        )

        # The vendor's activity report: the sync, and
        # silence about everything else. Reconciliation
        # names the silence precisely.
        vendor_claim = {"consequences": [sync_hash], "attempts": []}
        result = reconcile_against_audit(self.kernel, vendor_claim)
        self.assertFalse(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual(attempt_hashes, set(result.undisclosed_attempts))
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # A claim that promotes the cases export to an
        # authorized consequence is unbacked: no consume
        # backs it, whatever the connection's logs say.
        inflated_claim = {
            "consequences": [sync_hash, self.kernel.intent_hash(CASES_EXPORT_INTENT)],
            "attempts": honest_attempts,
        }
        result = reconcile_against_audit(self.kernel, inflated_claim)
        self.assertFalse(result.ok)
        self.assertEqual(
            {self.kernel.intent_hash(CASES_EXPORT_INTENT)},
            set(result.unbacked_consequences),
        )
        self.assertEqual(frozenset(), result.undisclosed_attempts)

        # Reconciliation is not a trap: a history that
        # DISCLOSES the attempts alongside the genuine
        # consequence reconciles exactly.
        honest_claim = {
            "consequences": [sync_hash],
            "attempts": honest_attempts,
        }
        honest = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(honest.ok)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6b: reconciliation preserves multiplicity -----------------------
    #
    # Each out-of-intent act in step 6 is attempted on three
    # routes, so the true audit holds each attempt hash 3
    # times (5 hashes x 3 = 15 attempt records, 1
    # consequence). Reconciliation must compare occurrence
    # counts, not mere presence: a claim that lists each
    # hash once underreports the record and must fail, a
    # claim that adds an extra copy must fail, and only the
    # claim that reports the true 3x multiplicity reconciles.

    def test_step6b_reconciliation_preserves_multiplicity(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        for intent in OUT_OF_INTENT:
            self.kernel.evaluate(intent)
            self.assertFalse(self.ledger.execute(self.kernel, OAUTH_TOKEN, intent))
            self.assertFalse(self._spend_as_app(self.kernel, permit, intent, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)

        sync_hash = self.kernel.intent_hash(SYNC_INTENT)
        attempt_hashes = {
            self.kernel.intent_hash(intent) for intent in OUT_OF_INTENT
        }
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({sync_hash: 1}, dict(consequences))
        self.assertEqual(
            {intent_hash: 3 for intent_hash in attempt_hashes}, dict(attempts)
        )
        honest_attempts = sorted(
            intent_hash for intent_hash in attempt_hashes for _ in range(3)
        )

        # LEGITIMATELY REPEATED event -> reconciliation PASSES:
        # the corrected honest claim lists every attempt hash
        # 3 times and the one consequence once.
        honest_claim = {"consequences": [sync_hash], "attempts": honest_attempts}
        result = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual(frozenset(), result.undisclosed_attempts)
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # MISSING event -> reconciliation FAILS: the claim
        # drops one occurrence of one attempt hash (lists it
        # twice instead of 3 times). That hash is undisclosed
        # in count, on exactly that hash.
        missing_hash = self.kernel.intent_hash(CASES_EXPORT_INTENT)
        missing_attempts = list(honest_attempts)
        missing_attempts.remove(missing_hash)
        missing_claim = {"consequences": [sync_hash], "attempts": missing_attempts}
        result = reconcile_against_audit(self.kernel, missing_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({missing_hash}), result.undisclosed_attempts)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # The collapsed shipped claim -- each attempt hash
        # listed ONCE -- is the extreme form of the missing
        # case: it fails on every attempt hash.
        collapsed_claim = {
            "consequences": [sync_hash],
            "attempts": sorted(attempt_hashes),
        }
        result = reconcile_against_audit(self.kernel, collapsed_claim)
        self.assertFalse(result.ok)
        self.assertEqual(attempt_hashes, set(result.undisclosed_attempts))

        # EXTRA COPY -> reconciliation FAILS: the claim adds
        # a fourth copy of one attempt hash. That hash is a
        # phantom attempt, on exactly that hash.
        extra_claim = {
            "consequences": [sync_hash],
            "attempts": honest_attempts + [missing_hash],
        }
        result = reconcile_against_audit(self.kernel, extra_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({missing_hash}), result.phantom_attempts)
        self.assertEqual(frozenset(), result.undisclosed_attempts)

        # Extra copy in the consequence direction also fails:
        # a second claimed sync execution is unbacked.
        extra_consequence_claim = {
            "consequences": [sync_hash, sync_hash],
            "attempts": honest_attempts,
        }
        result = reconcile_against_audit(self.kernel, extra_consequence_claim)
        self.assertFalse(result.ok)
        self.assertEqual(frozenset({sync_hash}), result.unbacked_consequences)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the campaign ----------------------
    #
    # Surfacing, asserted exactly as it holds at this commit:
    # every consume rejection, every approval rejection, and
    # every denied decision in the sequence becomes a
    # near-miss record in the derived incident report. The
    # bare require_approval decisions are in the canonical
    # audit (and counted below) but are derived as near-misses (issue #375) -- the expected near-miss count is built
    # from the event classes the channel actually derives,
    # so this test pins the boundary instead of papering
    # over it.
    #
    # The frozen sequence below is the full attempt sequence
    # of steps 1-5, not a subset: every out-of-intent act on
    # every route (steps 1-2), the token holder's three
    # presentations of the genuine permit (step 3, compressed
    # to the two that carry distinct presenter postures --
    # no-proof and wrong-presenter -- without changing any
    # count class), both approval-envelope attempts (step 5),
    # and the spent-permit replays (step 4, replayed after
    # the one legitimate execution below). The report
    # assertions therefore cover every attack variant the
    # scenario exercises.

    def test_step7_incident_channel_surfaces_the_abuse_campaign(self) -> None:
        permit = self._issue_sync_permit(self.kernel)
        # The campaign, compressed: each out-of-intent act
        # attempted on every route the holder has -- its own
        # say-so, the connection token as a token, and the
        # genuine permit presented by the app itself.
        for intent in OUT_OF_INTENT:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(OAUTH_TOKEN, intent))
            self.assertFalse(
                self._spend_as_app(self.kernel, permit, intent, ConsequenceLedger())
            )
        # The token holder's routes against the unspent
        # permit for the exact sync intent: no presenter, and
        # the wrong presenter with its own valid proof.
        self.assertFalse(self.kernel.consume(permit, SYNC_INTENT))
        holder_proof = proof_for(
            self.kernel, self.holder_verifier, permit, SYNC_INTENT, TOKEN_HOLDER_PRESENTER
        )
        self.assertFalse(
            self.kernel.consume(
                permit,
                SYNC_INTENT,
                presenter=TOKEN_HOLDER_PRESENTER,
                presenter_proof=holder_proof,
            )
        )
        # Each envelope in this compressed sequence carries
        # its own approval_id and nonce, as each real approval
        # would: the helper's fixed defaults would collide
        # with the permit issuance above and turn the forgery
        # denial below into a replay denial, misattributing
        # the control that rejected it.
        forged_envelope = signed_envelope(
            self.kernel,
            CASES_EXPORT_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(
            CASES_EXPORT_INTENT, forged_envelope, presenter=APP_PRESENTER
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the genuine
        # sync envelope presented for the export intent. A
        # real approval for the declared function is not
        # approval for an extraction; the decision is a denial
        # and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            SYNC_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(
            CASES_EXPORT_INTENT, genuine_envelope, presenter=APP_PRESENTER
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate act still executes; the campaign
        # did not.
        self.assertTrue(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for the
        # same sync and for an export. A consumed permit is
        # not a refresh token; both re-presentations are
        # rejected at consume.
        self.assertFalse(self._spend_as_app(self.kernel, permit, SYNC_INTENT, self.ledger))
        self.assertFalse(
            self._spend_as_app(self.kernel, permit, CASES_EXPORT_INTENT, self.ledger)
        )
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends
        # nothing.
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
        self.assertEqual(14, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(5, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The five require_approval decisions above
        # are audit-recorded attempts that each contribute one near-miss
        # record per occurrence (issue #375).
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions)
            + len(require_approval_decisions),
            report.near_misses,
        )
        self.assertEqual(23, report.near_misses)
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
                "decision": len(denied_decisions) + len(require_approval_decisions),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 8: the standing token outlives nothing --------------------------
    #
    # The real connection's tokens were minted once and
    # usable for months, across sessions, until Salesforce
    # revoked them platform-side. In a later session on a
    # fresh kernel, the same token string presented as
    # authority mints exactly as much as it should: none --
    # it is not a permit, was never issued for any act, and
    # its survival in the holder's hands changes nothing
    # about what it is.

    def test_step8_standing_connection_token_is_not_authority_in_a_later_session(self) -> None:
        later_sync = Intent(APP, "read_records", SYNC_RESOURCE, 25, LATER_SESSION)
        fresh = self._kernel()
        fresh_ledger = ConsequenceLedger()
        decision = fresh.evaluate(later_sync)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(fresh_ledger.execute(fresh, OAUTH_TOKEN, later_sync))
        self.assertEqual([], fresh_ledger.effects)
        self.assertEqual(0, len(_events(fresh, "permit_consumed")))
        self.assertEqual(1, len(_events(fresh, "permit_rejected")))
        self.assertTrue(fresh.verify_audit())

    # -- step 9: platform revocation -- the app is pulled ---------------------
    #
    # The incident ended when Salesforce revoked the apps'
    # tokens and removed the apps: the platform withdrew the
    # presenter. Modeled here as a second kernel over the
    # SAME canonical state whose presenter registry no longer
    # contains the app: the genuine, unspent permit token
    # still exists as a string, and the app's proof is still
    # well-formed -- but there is no registered verifier for
    # the app, so the spend fails closed as unverifiable.
    # The token did not expire and was not spent; the
    # platform's act is what ended it. And the control is
    # the registry, not the string: on the kernel where the
    # app remains registered, the same permit still spends.

    def test_step9_platform_revocation_deregisters_the_presenter(self) -> None:
        state = InMemoryKernelState()
        platform = self._kernel(state=state)
        permit = self._issue_sync_permit(platform)
        proof = self._app_proof(platform, permit, SYNC_INTENT)
        # The platform pulls the app: same state, same secret,
        # a registry with the token holder only -- the app is
        # gone from it.
        pulled = self._kernel(
            state=state, presenters={TOKEN_HOLDER_PRESENTER: self.holder_verifier}
        )
        pulled_ledger = ConsequenceLedger()
        self.assertFalse(
            pulled_ledger.execute(
                pulled,
                permit,
                SYNC_INTENT,
                presenter=APP_PRESENTER,
                presenter_proof=proof,
            )
        )
        self.assertEqual([], pulled_ledger.effects)
        rejected = _events(pulled, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            "permit_presenter_unverifiable", rejected[0]["payload"]["reason"]
        )
        self.assertEqual(0, len(_events(pulled, "permit_consumed")))
        # The refusal did not burn the permit or rewrite
        # history: where the app remains registered, the same
        # permit spends on its exact act.
        self.assertTrue(self._spend_as_app(platform, permit, SYNC_INTENT, self.ledger))
        self.assertEqual([("read_records", SYNC_RESOURCE)], self.ledger.effects)
        self.assertTrue(platform.verify_audit())

    # -- negative control ------------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a
        # kernel double whose consume skips token
        # authentication, the token-to-intent binding, and the
        # presenter binding, over a state double whose consume
        # ignores the store's binding: the bulk export
        # EXECUTES under the sync permit. That is the
        # incident's own shape -- a connection that answers
        # whatever its holder presents. The denials in the
        # steps above therefore come from the real consume
        # path's binding checks, not from a harness that
        # denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_sync_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, CASES_EXPORT_INTENT))
        self.assertEqual(
            [("read_records", CASES_EXPORT_INTENT.resource)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route, here with the export).
        real_permit = self._issue_sync_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(
            self._spend_as_app(self.kernel, real_permit, CASES_EXPORT_INTENT, real_ledger)
        )
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()
