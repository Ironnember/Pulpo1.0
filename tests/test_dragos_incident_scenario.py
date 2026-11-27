"""Scenario test: the 2026 Dragos / HD Moore AI inference canary
investigation's authorization failure mode.

Incident (Recorded, from Dragos's disclosure, "AI Supply Chain
Security: What Canary Tokens Found," HD Moore, Dragos blog, 2026):
over five months from July through November 2026 the researchers
sent approximately two million prompts containing unique canary
credentials and URLs to widely used AI inference services, then
watched where the secrets surfaced. Three findings matter here.
First, at least three providers were compromised: in the largest
breach a couple hundred of the seeded AWS keys -- each sent in
exactly one request to one provider, all within a few short
windows in late October -- were stolen, some of them from
requests the provider rejected before a model ever ran, which
told the researchers the attacker was copying requests at the
provider's front door. The thieves tested each key for liveness,
in some cases within hours; then went looking for data, listing
S3 buckets and searching Secrets Manager and Parameter Store;
then tried to persist, enabling hosted models in AWS Bedrock,
creating Bedrock API keys, and adding their own IAM users. The
bait keys were used for tens of thousands of AWS API calls in
total. On November 1 the same attacker added ARTEX, an LLM-driven
penetration-testing framework, which made a handful of calls to
confirm keys already held were still live. Second, marketplace
resellers needed no exploit at all: they could view and retain
customer prompts using standard logging capabilities, and
individuals working from home connections used what they found --
opening the secret URLs and trying passwords taken from prompts
as root over SSH. Third, privacy settings were not honored: one
Chinese AI lab's systems fetched the secret URLs from more than
half of the prompts sent to its models, including roughly
two-thirds of the requests marked Zero Data Retention, and
twenty-four days after one prompt was sent to a U.S.-based
provider with the ZDR flag set, its secret link was posted into a
Feishu chat channel from what had to be a stored copy of the full
prompt. The canary property is the detection: a canary secret
exists in exactly one place, so any use of it ties back to the
exact prompt, model, router, and privacy setting that carried it.

This module models that failure mode against the canonical kernel
API. It does NOT reproduce any provider, router, marketplace, or
cloud API, and it uses no real credential material: every "secret"
below is a string in this file. The only route from intent to
consequence is a successful ``GovernanceKernel.consume`` of a
permit bound to the exact intent hash.

Setup: the incident's three holder classes -- the front-door
thief, the marketplace reseller reading its own logs, the lab
scraping URLs it was never supposed to retain -- collapse into
one holder principal, because the kernel question is identical
for each: possession of a secret that arrived through a trusted
channel versus authority for the act the secret enables. The
holder has exactly one legitimate permit: to serve one inference
request, the act its role in the chain actually authorizes,
issued through a verified approval envelope. The incident's
consequential uses of the canary material are then attempted in
the order the disclosure records them: test the stolen key for
liveness, hunt for data (list buckets, search the secret stores),
persist (create an IAM user), and the parallel trusted-channel
uses -- fetch the secret URL the ZDR flag said would not be
retained, and log in as root with a password taken from a prompt.
The kernel must deny each one, the consequence ledger must stay
empty for all of them, and every denial must land in the audit
record, where the incident channel -- this scenario's canary, an
observation independent of the holder's own account -- must
account for every attempt that presented anything.

Incident-channel surfacing (Verified at this commit, by executable
probe and by the channel's derivation rules): the derived incident
report turns ``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A bare
``evaluate`` that returns ``require_approval`` -- the kernel
declining to mint without approval -- appends a decision record to
the canonical audit but is derived as a near-miss by the channel since the issue #375 fix.
The scenario asserts both halves of that statement exactly
as they hold; it does not smooth the second half over. This is the
same surfacing boundary the Cairn replay recorded (issue #375),
observed again here, neither introduced nor widened by this change.

Boundary: this proves kernel behavior at this commit for these
action classes (Verified, executable evidence). It proves nothing
about any deployed system that does not route its consequences
through this kernel. In the real incident the stolen keys were
used directly against cloud APIs with the raw credentials --
entirely off any governed path -- and the canary caught the uses
only because the researchers owned the bait accounts and logged
everything: the victim's instrumentation, not a control on the
act. A control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path only
-- exactly one governed external consequence is permitted, and any
non-kernel use path (raw credentials presented directly to a cloud
API, the incident's actual route) remains outside this evidence
and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state changed."
Each denied evaluate/consume appends exactly one audit record.
That growth is itself a governed effect -- evidence production --
bounded at one record per attempt, append-only, and it does not
alter authority (``authority_effect=none``) or accumulate
capability. It is classified and assessed separately from governed
external consequences throughout this module: "consequence" below
means governed external consequence (the permitted consume
recorded in the consequence ledger), never audit growth.
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
AGENT = "agent:inference-marketplace-seller"
SESSION = "dragos-canary-2026-10"

# The one act the holder's role actually authorized: serve one
# inference request through the marketplace.
SERVE_RESOURCE = "inference-marketplace:serve/request-001"
# The incident's consequential uses of the canary material, in the
# disclosure's order: test the stolen key, hunt for data, persist,
# and the parallel trusted-channel uses (the ZDR-defying URL fetch,
# the root login with a password taken from a prompt).
KEY_TEST_RESOURCE = "aws:sts/get-caller-identity"
S3_RESOURCE = "aws:s3/list-buckets"
SECRETS_RESOURCE = "aws:secretsmanager/search"
IAM_RESOURCE = "aws:iam/create-user"
URL_RESOURCE = "canary:secret-url/seed-001"
SSH_RESOURCE = "canary:ssh/root-login"

SERVE_INTENT = Intent(AGENT, "api_call", SERVE_RESOURCE, 0, SESSION)
KEY_TEST_INTENT = Intent(AGENT, "api_call", KEY_TEST_RESOURCE, 0, SESSION)
S3_INTENT = Intent(AGENT, "api_call", S3_RESOURCE, 0, SESSION)
SECRETS_INTENT = Intent(AGENT, "api_call", SECRETS_RESOURCE, 0, SESSION)
IAM_INTENT = Intent(AGENT, "api_call", IAM_RESOURCE, 0, SESSION)
URL_INTENT = Intent(AGENT, "fetch_url", URL_RESOURCE, 0, SESSION)
SSH_INTENT = Intent(AGENT, "login", SSH_RESOURCE, 0, SESSION)
ATTACK_INTENTS = (
    KEY_TEST_INTENT,
    S3_INTENT,
    SECRETS_INTENT,
    IAM_INTENT,
    URL_INTENT,
    SSH_INTENT,
)

# The stolen canary credential itself, presented by the holder as if
# possession were a permit. Possession is not a permit; the kernel
# must treat this string as a fabricated token, because that is what
# it is.
CANARY_KEY_TOKEN = "canary:aws-key:seed-001"

# The disclosure records the bait keys were used for "tens of
# thousands of AWS API calls" (Recorded). The volume test runs the
# low end of that recorded range in full.
BAIT_CALL_VOLUME = 10_000


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume.

    This is the scenario's execution path: the harness executes an action
    (records its consequence) only when the kernel consumes a permit for
    that exact intent. A denial is therefore directly observable as the
    absence of a governed external consequence, not merely as a returned
    status. (The denial itself still appends an audit record -- a governed
    effect, classified separately in the module docstring.)
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


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent permit
    spends for any intent. It exists only to prove the scenario's denial
    assertions discriminate -- under this double the out-of-scope attempt
    must EXECUTE, or the scenario would be denying by construction rather
    than by the kernel's binding.
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

    Its consume() performs none of the kernel's spend-path checks --
    neither token authentication nor the token-to-intent binding --
    and delegates straight to the state. Paired with the intent-blind
    state double above, no layer binds the permit to the presented
    intent, so the substituted spend must EXECUTE here, or the
    scenario's denials would be coming from the harness rather than
    from the binding layers.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class DragosIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"api_call", "fetch_url", "login"}),
            100,
            frozenset({"api_call", "fetch_url", "login"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()

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

    def _issue_serve_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, SERVE_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(SERVE_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_serve_executes_exactly_once(self) -> None:
        permit = self._issue_serve_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        self.assertEqual([("api_call", SERVE_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same action twice.
        self.assertFalse(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        self.assertEqual([("api_call", SERVE_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the canary secret is not a permit ---------------------------

    def test_step1_canary_secret_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope exists for
        # using the stolen key, and the prompt the key arrived in is
        # not one.
        decision = self.kernel.evaluate(KEY_TEST_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, KEY_TEST_INTENT))
        # The holder presents the stolen credential itself as its
        # permit. The kernel treats it as what it is: a fabricated
        # token. Possession of the key is not authority to test it.
        self.assertFalse(self.ledger.execute(self.kernel, CANARY_KEY_TOKEN, KEY_TEST_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(KEY_TEST_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the liveness test under the serve permit --------------------

    def test_step2_key_liveness_test_with_serve_permit_denied(self) -> None:
        permit = self._issue_serve_permit(self.kernel)
        # The one permit the holder has binds the serve intent exactly;
        # it does not spend on testing a stolen key against a cloud
        # account, the first thing the thieves did with every key.
        self.assertFalse(self.ledger.execute(self.kernel, permit, KEY_TEST_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(KEY_TEST_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still spends on
        # the exact act it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        self.assertEqual([("api_call", SERVE_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: hunting for data -------------------------------------------

    def test_step3_data_hunting_calls_denied_on_every_route(self) -> None:
        permit = self._issue_serve_permit(self.kernel)
        # After the liveness test, the thieves went looking for data:
        # listing S3 buckets and searching the secret stores. Each is
        # its own exact intent; nothing the holder has authorizes
        # either, on any route.
        for intent in (S3_INTENT, SECRETS_INTENT):
            decision = self.kernel.evaluate(intent)
            self.assertEqual(
                ("require_approval", "approval_required"),
                (decision.outcome, decision.reason),
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
            self.assertFalse(self.ledger.execute(self.kernel, CANARY_KEY_TOKEN, intent))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(4, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {self.kernel.intent_hash(S3_INTENT), self.kernel.intent_hash(SECRETS_INTENT)},
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # Binding is exact, not a global lockout after denied attempts.
        self.assertTrue(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: persistence -- keeping the access ---------------------------

    def test_step4_persistence_call_denied_on_every_route(self) -> None:
        permit = self._issue_serve_permit(self.kernel)
        # The final stage of the recorded sequence: adding the
        # attacker's own IAM user, so the access survives the stolen
        # key. Creating an account identity is a separate, graver act
        # class in consequence if not in name; nothing the holder has
        # authorizes it.
        decision = self.kernel.evaluate(IAM_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, IAM_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, CANARY_KEY_TOKEN, IAM_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, IAM_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual({self.kernel.intent_hash(IAM_INTENT)}, rejected_hashes)
        # The serve permit survived the denied persistence attempts and
        # still spends on its own exact intent: the authority to serve
        # a request was never authority over the account, in either
        # direction.
        self.assertTrue(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        self.assertEqual([("api_call", SERVE_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals for the persistence act -----

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, SERVE_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the IAM act signed with the holder's own
        # key: the holder cannot mint its own authority.
        forged_envelope = signed_envelope(
            self.kernel, IAM_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(IAM_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine serve envelope presented for the IAM intent:
        # a real approval for one act is not approval for another.
        decision = self.kernel.evaluate_with_approval(IAM_INTENT, genuine_envelope)
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
        # The denials did not poison the path: the genuine pair still admits.
        decision = self.kernel.evaluate_with_approval(SERVE_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the canary sees the campaign --------------------------------
    #
    # Reconciliation, asserted exactly as it holds at this commit: the
    # canary's whole value is that the observation is independent of
    # the holder's account of itself. Here the incident channel plays
    # that role over the kernel audit: every consume rejection, every
    # approval rejection, and every denied decision in the sequence
    # becomes a near-miss record, and every rejected consume's intent
    # hash ties the attempt back to the exact seeded act -- the same
    # tie-back the researchers got from their canaries. The bare
    # require_approval decisions are in the canonical audit (and
    # counted below) but are derived as near-misses (issue #375) -- the
    # expected near-miss count is built from the event classes the
    # channel actually derives, so this test pins the boundary
    # instead of papering over it.

    def test_step6_incident_channel_surfaces_every_presented_use(self) -> None:
        permit = self._issue_serve_permit(self.kernel)
        # The campaign, compressed: each consequential use attempted on
        # every route the holder has.
        for intent in ATTACK_INTENTS:
            decision = self.kernel.evaluate(intent)
            self.assertEqual("require_approval", decision.outcome)
            self.assertFalse(self.kernel.consume(CANARY_KEY_TOKEN, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        forged_envelope = signed_envelope(
            self.kernel, KEY_TEST_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(KEY_TEST_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        # The one legitimate act still executes; the campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        self.assertEqual([("api_call", SERVE_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends nothing.
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
        self.assertEqual(12, len(permit_rejected))
        self.assertEqual(1, len(approval_rejected))
        self.assertEqual(1, len(denied_decisions))
        self.assertEqual(6, len(require_approval_decisions))
        # The canary tie-back: every rejected consume names, by intent
        # hash, exactly which seeded act was attempted -- all six, no
        # others.
        rejected_hashes = {record["payload"]["intent_hash"] for record in permit_rejected}
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in ATTACK_INTENTS},
            rejected_hashes,
        )
        # Every derived near-miss is accounted for by the event classes
        # the channel derives -- no more, no fewer. The six
        # require_approval decisions above are audit-recorded attempts
        # that each contribute one near-miss record (issue #375).
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions)
            + len(require_approval_decisions),
            report.near_misses,
        )
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

    # -- volume: the bait keys' tempo, complete record -----------------------
    #
    # Classification: exactly one GOVERNED EXTERNAL consequence is
    # expected (the permitted serve). The 10,000 denied attempts are
    # NOT "no state changed": each appends exactly one audit record --
    # a governed effect (evidence production), bounded at one record
    # per attempt, append-only, with authority_effect=none and no
    # capability accumulation.

    def test_volume_10000_bait_key_calls_complete_audit_no_consequence(self) -> None:
        permit = self._issue_serve_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, SERVE_INTENT))
        audit_before = len(self.kernel.audit)
        attempts = 0
        for i in range(BAIT_CALL_VOLUME):
            intent = ATTACK_INTENTS[i % len(ATTACK_INTENTS)]
            route = i % 3
            if route == 0:
                decision = self.kernel.evaluate(intent)
                self.assertEqual("require_approval", decision.outcome)
                self.assertIsNone(decision.permit)
            elif route == 1:
                self.assertFalse(self.kernel.consume("permit:fabricated:token", intent))
            else:
                self.assertFalse(self.kernel.consume(CANARY_KEY_TOKEN, intent))
            attempts += 1
        self.assertEqual(
            [("api_call", SERVE_RESOURCE)],
            self.ledger.effects,
            "expected exactly one governed external consequence (the permitted consume)",
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(
            attempts,
            len(self.kernel.audit) - audit_before,
            "expected exactly one audit record per denied attempt "
            "(bounded, append-only audit growth; authority_effect=none)",
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a kernel
        # double whose consume skips token authentication and the
        # kernel's token-to-intent binding, over a state double whose
        # consume ignores the store's binding: the stolen key's
        # liveness test EXECUTES under the serve permit. The denials in
        # the steps above therefore come from the real consume path's
        # binding checks, not from a harness that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_serve_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, KEY_TEST_INTENT))
        self.assertEqual([("api_call", KEY_TEST_RESOURCE)], self.ledger.effects)
        # Contrast, same attempt against the real backend: denied (step 2).
        real_permit = self._issue_serve_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, KEY_TEST_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()
