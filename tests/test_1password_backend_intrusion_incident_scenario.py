"""Scenario test: the 1Password backend intrusion
(November 2026; 1Password's own incident update).

Incident (Recorded, from 1Password's published update
on the incident): on November 19, 2026, 1Password
began investigating indications that an attacker had
gained access to an employee's corporate GitHub
account. The actor used the account to access source
code and push malicious code to backend services;
the pushed code downloaded administrative data
pertaining to customers. The downloaded account
records covered a subset of users and included names
and email addresses; account and user identifiers,
and account creation and last sign-in times; public
keys (public by design); Secure Remote Password
protocol parameters (which, per the post, cannot be
used to access an account); tokens present in certain
emailed links for invitations, provisioning, and
account recovery (usable, per the post, only combined
with an SSO sign-in or a code sent to the user's
registered email); and other non-secret account
metadata. The attacker also copied source code from
private repositories and gained access to the CI/CD
system, which holds infrastructure-related secrets;
1Password triggered a rotation of all credentials
which may have been exposed. What was NOT affected
(Recorded, same source): customer vaults and the
items in them; the keys that protect vaults (the
account password and Secret Key are not stored by
1Password); account recovery keys; and the 1Password
apps and browser extensions. The post's remediation
records that the affected GitHub account was
disabled, a stolen token revoked, and the access the
attacker created removed; it also records validation
of no internal evidence of user account takeovers
using the exposed provisioning tokens. How the
attacker first gained access to the GitHub account
is not stated in the post -- **Unknown**. This
scenario does not model the account compromise; it
models the boundary that must hold even when an
account is fully controlled by an attacker.

The failure class (trusted-path execution): code was
pushed to production backend services and executed
after arriving through a trusted channel -- a
genuine corporate account on the corporate code host.
What the post establishes (Recorded) is the push and
its consequences: the actor used the compromised
account to push malicious code to backend services,
and the pushed code ran and downloaded data. The
post does NOT describe the deployment pipeline's
authorization mechanism: that the channel's trust
was itself the authorization -- that a push from the
right account deployed automatically, with no
per-action authorization by a named accountable
human bound to the exact change being deployed --
is **Inferred**, and it is the model this scenario
tests, not a verified property of 1Password's
pipeline. On that model, account identity answered
"who pushed"; nothing answered "was THIS change,
exactly, approved by the human accountable for it"
-- and under full account compromise the first
answer is the attacker's to give.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce
1Password's systems, any backend service, the
malicious code, or the data download. The mapping
(Inferred, stated here so it can be argued with):
the consequential act is deploying a code change to
a backend service. That act requires a permit bound
to the exact change -- service repository, commit,
source, and content hash, all carried in the intent's
resource string, so the kernel's exact-intent hash
binds all four. An approval for one reviewed change
therefore cannot authorize deploying a different
change pushed through the same trusted account: a
different commit, or the reviewed commit identifier
carrying substituted content, makes a different
intent whose approval does not exist. And the
account itself cannot mint the missing approval:
approval authority belongs to a named accountable
human's key, which account control does not confer.
The only route from a push to a deployment is a
successful ``GovernanceKernel.consume`` of a permit
issued through a verified approval envelope for that
exact change -- and the executor does not take the
intent's declared identity on faith: it hashes the
actual artifact bytes presented at the consequence
boundary and compares the derived hash against the
content hash bound in the intent, so the approved
label presented with different bytes is refused
before any permit is consumed.

A note on the artifact identities, stated plainly
(the wording discipline of PR #403 applied from the
start): the incident post publishes no commit SHA
and no content hash for either the reviewed changes
or the attacker's push -- a Recorded absence. The
identities below are therefore harness constructions
in the incident's shape (a corporate repository, a
reviewed commit, an attacker's commit through the
same account), not recovered 1Password artifacts.
The binding proof is a proof about the kernel's
treatment of exact identities, and it claims nothing
about any real 1Password commit or hash.

Setup: exactly one act is legitimate in this
scenario -- deploying one exact, reviewed, approved
change to the backend service, once, under a permit
issued through a verified approval envelope: the
accountable per-action authorization actually
granted. The incident's routes are then attempted:
deployment with no approval at all (the push is its
own authority, as the trusted channel treated it);
the genuine approval for the reviewed change
presented for the attacker's change pushed through
the same account; the reviewed commit identifier
presented with the attacker's content substituted
under it; and an approval for the attacker's change
signed with an unauthorized (attacker) key. The
kernel must deny each one, the consequence ledger
must stay empty for all of them, and every denial
must land in the audit record. A genuine, well-formed
approval for the exact change verifies and authorizes
exactly one deployment, and then spends.

Multiplicity discipline: reconciliation in this
scenario is per-item counted (``Counter`` / multiset),
never set-based. A dedicated probe presents the same
change twice: a spent permit re-presented does not
deploy twice, and a claimed-deploys list that counts
the same consumed change twice reconciles as a
phantom duplicate of count exactly 1, not as a match.

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
evidence). It proves nothing about GitHub, any code
host, CI/CD system, or deployment pipeline that does
not route deployment through this kernel -- a
pipeline that deploys on the strength of an account's
push is governed by nothing here. It governs the
deployment before it happens, not the compromise
afterward: the data download and the CI/CD reach
were consequences of code already running, and are
described from the source, not reproduced. How the
GitHub account was accessed is Unknown and is not
modeled. A control not on the execution path governs
nothing.

Adversarial transformation review: the full
eight-pass review (Flip, Reverse, Invert, Inside-Out,
Darken, Lighten, Amplify, Negate) for this incident
is recorded in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed
kernel path only -- exactly one governed external
consequence is permitted per correctly verified
approval bound to the exact change, and any deploy
path that executes pushed code on channel trust
alone (the incident's own class) remains outside
this evidence and open.

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
import hashlib
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
# The backend deployment pipeline: the dispatch
# boundary the incident's push fed into. Every intent
# below is an act this pipeline would perform; a push
# proposes, the pipeline must not deploy anything
# without a permit bound to the exact change.
DEPLOYER = "agent:backend-deploy-pipeline"
# The deploy session of the day 1Password's
# investigation began, 2026-11-19, in the harness's
# naming. Session identity is part of the bound
# intent; it is not itself authority for anything.
SESSION = "backend-deploy-session-2026-11-19"
# The trusted account of the incident: a genuine
# employee corporate GitHub account. In the negative
# control it is the ONLY thing checked -- which is
# the incident, on the inferred model.
TRUSTED_ACCOUNT = "employee-corporate-github-account"

ACTION = "deploy_backend_code"

# The exact changes, each identity carrying
# repository, commit, source, and content hash -- the
# fields a trusted account name cannot stand in for.
# Harness constructions (see the module docstring):
# the incident post publishes no commit or hash for
# any change, reviewed or malicious.
REVIEWED_COMMIT = "3f8a1c94b7d2e6059a4f1c8b3d7e9a0b5c6d2e4f"
MALICIOUS_COMMIT = "c41d77a02b9e83f5a6d1c0e2948b3f57a6d9e1c3"
# The artifact byte strings themselves (harness
# constructions). The content hashes are their real
# SHA-256 digests, computed here -- not declared
# strings -- so the deploy executor can derive an
# artifact's identity from the bytes actually
# presented at the consequence boundary instead of
# trusting caller-supplied metadata.
REVIEWED_ARTIFACT = b"reviewed backend change (harness bytes)"
MALICIOUS_ARTIFACT = b"attacker backend change (harness bytes)"
REVIEWED_HASH = hashlib.sha256(REVIEWED_ARTIFACT).hexdigest()
MALICIOUS_HASH = hashlib.sha256(MALICIOUS_ARTIFACT).hexdigest()

# The reviewed change: the one change a named
# accountable human has reviewed and approved for
# deployment in this scenario.
APPROVED_CHANGE = (
    f"github:1password/backend-services@{REVIEWED_COMMIT}:repo:sha256:{REVIEWED_HASH}"
)
# The attacker's change: a different commit pushed
# through the SAME trusted account to the SAME
# repository -- the incident's route exactly. The
# channel, the account, and the repository are all
# legitimate; the change was never reviewed.
MALICIOUS_CHANGE = (
    f"github:1password/backend-services@{MALICIOUS_COMMIT}:repo:sha256:{MALICIOUS_HASH}"
)
# The reviewed commit identifier with the attacker's
# content substituted under it: the label a reviewer
# saw, carrying content no reviewer saw.
HASH_SUBSTITUTED_CHANGE = (
    f"github:1password/backend-services@{REVIEWED_COMMIT}:repo:sha256:{MALICIOUS_HASH}"
)

APPROVED_INTENT = Intent(DEPLOYER, ACTION, APPROVED_CHANGE, 25, SESSION)
MALICIOUS_INTENT = Intent(DEPLOYER, ACTION, MALICIOUS_CHANGE, 25, SESSION)
HASH_SUBSTITUTED_INTENT = Intent(
    DEPLOYER, ACTION, HASH_SUBSTITUTED_CHANGE, 25, SESSION
)


def reconcile_deploys(kernel: GovernanceKernel, claimed_hashes: list[str]) -> dict:
    """Per-item (multiset) reconciliation of claimed deploys.

    ``claimed_hashes`` is a list of intent hashes, one
    entry per claimed deployment occurrence. Consumed
    occurrences are counted from the kernel audit with
    a ``Counter`` -- never a set -- so a duplicate
    claim for the same change is a phantom of count
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


class DeployExecutor:
    """Backend deployment, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary that, under the inferred model
    of the incident, the incident's pipeline lacked:
    on that model the trusted account's push WAS the
    deployment path, and the code followed
    immediately. Here the harness records an effect
    only when the kernel consumes a permit for the
    exact intent. A denial is therefore directly
    observable as the absence of a governed external
    consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a
    governed effect, classified separately in the
    module docstring.)

    The executor does not trust the intent's declared
    identity. It derives the artifact identity from
    the actual bytes presented at the consequence
    boundary -- SHA-256 over ``artifact`` -- and
    compares it against the content hash bound in the
    intent's resource string. Declared metadata that
    disagrees with the bytes is refused before any
    permit is consumed, and the refusal spends
    nothing: the genuine bytes can still deploy under
    the same permit afterward.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        artifact: bytes,
    ) -> bool:
        if permit is None:
            return False
        derived_hash = hashlib.sha256(artifact).hexdigest()
        bound_hash = intent.resource.rsplit("sha256:", 1)[-1]
        if derived_hash != bound_hash:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


class AccountTrustDeployer:
    """The incident's ungoverned baseline, as a test-local double.

    Authorizes deployment by the pushing ACCOUNT
    alone -- the trusted-channel rule of the inferred
    model of the incident (the post does not establish
    that account trust was the pipeline's authorization
    mechanism; see the module docstring). The change
    being pushed is never consulted: no commit, no
    hash, no approval. Any change the genuine
    corporate account pushes deploys, which is why an
    attacker holding that account needed nothing else.
    Test-local; never imported by runtime code.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def deploy(self, account: str, intent: Intent) -> bool:
        if account != TRUSTED_ACCOUNT:
            return False
        self.effects.append((intent.action, intent.resource))
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class OnePasswordBackendIntrusionIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = DeployExecutor()

    def _kernel(self) -> GovernanceKernel:
        policy = Policy(
            frozenset({ACTION}),
            10_000,
            frozenset({ACTION}),
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
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

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_INTENT)
        # The one legitimate act: deployment of the
        # exact reviewed change under a genuine,
        # well-formed, verified approval executes once.
        self.assertTrue(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        self.assertEqual([(ACTION, APPROVED_CHANGE)], self.executor.effects)
        # The same permit cannot deploy it twice -- a
        # verified approval is not a standing deploy
        # permission for the account or the pipeline.
        self.assertFalse(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        self.assertEqual([(ACTION, APPROVED_CHANGE)], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all ----------------------------------------

    def test_step1_no_approval_at_all_denied(self) -> None:
        # The incident's baseline route: the trusted
        # account pushes and the code deploys. On the
        # governed path a push is not an approval: the
        # kernel declines to mint, and nothing deploys.
        decision = self.kernel.evaluate(MALICIOUS_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.executor.execute(
                self.kernel, decision.permit, MALICIOUS_INTENT, MALICIOUS_ARTIFACT
            )
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the attacker's change through the trusted account -----------
    #
    # The genuine approval for the reviewed change,
    # presented for the attacker's change. Same account,
    # same repository, same channel -- everything the
    # incident's pipeline checked is identical. Only the
    # change differs, and the exact-intent binding
    # compares the whole change identity, so the
    # approval does not travel.

    def test_step2_attacker_change_under_genuine_approval_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, APPROVED_INTENT, self.verifier, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(MALICIOUS_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.executor.execute(
                self.kernel, decision.permit, MALICIOUS_INTENT, MALICIOUS_ARTIFACT
            )
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        # The denial did not poison the path: the genuine
        # pair still admits.
        decision = self.kernel.evaluate_with_approval(APPROVED_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the reviewed commit, substituted content ---------------------
    #
    # The substitution in both of its forms. Declared:
    # an intent naming the reviewed commit identifier
    # carrying the attacker's content hash -- a
    # different intent, which the genuine approval does
    # not cover. Undeclared, and more dangerous: the
    # approved intent itself, with its genuine permit,
    # but the bytes actually handed to the deployer are
    # the attacker's -- every declared signal (account,
    # repository, commit, permit) genuine, only the
    # content false. A boundary that trusts the
    # declared identity deploys it; this executor
    # derives the identity from the bytes and refuses
    # before consume.

    def test_step3_reviewed_commit_substituted_content_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, APPROVED_INTENT, self.verifier, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(
            HASH_SUBSTITUTED_INTENT, genuine_envelope
        )
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        # Undeclared substitution at the consequence
        # boundary: the genuine permit for the approved
        # intent, presented with the attacker's bytes.
        permit = self._issue_permit(self.kernel, APPROVED_INTENT)
        self.assertFalse(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, MALICIOUS_ARTIFACT)
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The boundary refusal spent nothing: the
        # genuine bytes still deploy under the same
        # permit, exactly once.
        self.assertTrue(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        self.assertEqual([(ACTION, APPROVED_CHANGE)], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: forged approval for the attacker's change --------------------

    def test_step4_forged_approval_for_attacker_change_denied(self) -> None:
        # An envelope for the attacker's change signed
        # with an unauthorized key: whoever controls the
        # GitHub account cannot mint the deploy
        # authority. Account control is not approval
        # authority -- the accountable human's key is a
        # different thing from the account's session,
        # and holding the second gives no route to the
        # first.
        forged_envelope = signed_envelope(
            self.kernel, MALICIOUS_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(MALICIOUS_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: multiplicity -- duplicates never double-count ---------------

    def test_step5_duplicate_presentation_never_double_counts(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_INTENT)
        self.assertTrue(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        # The same change presented a second time under
        # the same (spent) permit: no second deployment,
        # no second consumption.
        self.assertFalse(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        self.assertEqual([(ACTION, APPROVED_CHANGE)], self.executor.effects)
        approved_hash = self.kernel.intent_hash(APPROVED_INTENT)
        # An exact per-item claim reconciles.
        exact = reconcile_deploys(self.kernel, [approved_hash])
        self.assertTrue(exact["ok"])
        self.assertEqual({}, exact["phantom_counts"])
        self.assertEqual({}, exact["unreported_counts"])
        self.assertEqual({approved_hash: 1}, exact["consumed_counts"])
        # The duplicate probe: the same change claimed
        # twice is a phantom of count exactly 1 under
        # multiset reconciliation. A set-based check
        # would collapse the duplicate and report a
        # match -- the double-count this probe exists to
        # catch.
        duplicated = reconcile_deploys(self.kernel, [approved_hash, approved_hash])
        self.assertFalse(duplicated["ok"])
        self.assertEqual({approved_hash: 1}, duplicated["phantom_counts"])
        self.assertEqual({}, duplicated["unreported_counts"])
        # And an empty claim under-reports by exactly 1.
        omitted = reconcile_deploys(self.kernel, [])
        self.assertFalse(omitted["ok"])
        self.assertEqual({approved_hash: 1}, omitted["unreported_counts"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would.
        self.kernel.evaluate(MALICIOUS_INTENT)
        redirect_envelope = signed_envelope(
            self.kernel,
            APPROVED_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-reviewed",
            nonce="nonce-seq-reviewed",
        )
        decision = self.kernel.evaluate_with_approval(MALICIOUS_INTENT, redirect_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        forged_envelope = signed_envelope(
            self.kernel,
            MALICIOUS_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-seq-forged",
            nonce="nonce-seq-forged",
        )
        decision = self.kernel.evaluate_with_approval(MALICIOUS_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # The trusted account's name presented as a
        # permit at the dispatch boundary: an account
        # name is not a permit either, and consume
        # rejects it. This is the incident's whole
        # confusion, presented at the boundary in its
        # purest form.
        self.assertFalse(
            self.executor.execute(
                self.kernel, TRUSTED_ACCOUNT, MALICIOUS_INTENT, MALICIOUS_ARTIFACT
            )
        )
        # The one legitimate deployment still lands; the
        # attack routes did not.
        permit = self._issue_permit(
            self.kernel,
            APPROVED_INTENT,
            approval_id="approval-seq-run",
            nonce="nonce-seq-run",
        )
        self.assertTrue(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        self.assertEqual([(ACTION, APPROVED_CHANGE)], self.executor.effects)
        # The spent permit re-presented: single-use.
        self.assertFalse(
            self.executor.execute(self.kernel, permit, APPROVED_INTENT, REVIEWED_ARTIFACT)
        )
        self.assertEqual([(ACTION, APPROVED_CHANGE)], self.executor.effects)

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
        # event classes the channel derives -- no more,
        # no fewer. The require_approval decision above
        # contributes zero near-miss records at this
        # commit.
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

    def test_negative_control_account_trust_deployer_would_execute(self) -> None:
        # Same scenario, the governed boundary swapped
        # for the inferred model of the incident:
        # authorize deployment by the pushing account
        # alone, as a trusted-channel pipeline on that
        # model does. The account is genuine, so the
        # attacker's change DEPLOYS -- and so does the
        # reviewed commit carrying substituted content.
        # That is the incident under the inferred model,
        # reproduced at the layer the model locates it:
        # not the account compromise (Unknown), not the
        # network -- the authorization check that
        # consulted an identity instead of the change.
        # The denials in the steps above therefore come
        # from the exact binding (repository + commit +
        # source + hash), not from a harness that denies
        # by construction.
        blind = AccountTrustDeployer()
        self.assertTrue(blind.deploy(TRUSTED_ACCOUNT, MALICIOUS_INTENT))
        self.assertTrue(blind.deploy(TRUSTED_ACCOUNT, HASH_SUBSTITUTED_INTENT))
        self.assertEqual(
            [(ACTION, MALICIOUS_CHANGE), (ACTION, HASH_SUBSTITUTED_CHANGE)],
            blind.effects,
        )
        # The account-trust rule is not indiscriminate --
        # an outside account does not pass it. Its defect
        # is that the account is ALL it checks: it cannot
        # tell a reviewed change from an attacker's
        # change arriving through the same genuine
        # account, which is the one distinction the
        # incident turned on.
        self.assertFalse(blind.deploy("external-contributor-account", MALICIOUS_INTENT))
        # Contrast, the identical attacker route against
        # the governed kernel: denied (step 2's route).
        genuine_envelope = signed_envelope(
            self.kernel, APPROVED_INTENT, self.verifier, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(MALICIOUS_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)


if __name__ == "__main__":
    unittest.main()
