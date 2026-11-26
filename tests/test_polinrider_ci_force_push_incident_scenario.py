"""Scenario test: the PolinRider CI force-push wave -- the
loader force-pushed into open pull requests and executed in
CircuitVerse's desktop release-build CI (Corgea update,
2026-11-26).

Relationship to PR #390 (stated explicitly, because the two
replays share a campaign and must not be read as duplicates):
PR #390 replays PolinRider's EARLIER phase -- the Python
loader planted across GitHub repositories and executed at
import time through a trusted import channel (``utils``
packages, a root ``conftest.py``), plus its forged "removal"
commits. This module replays the NEW phase only: the same
campaign's JavaScript loader force-pushed into pull requests
that were still open at other people's projects, executed
through trusted-path CI, and shipped inside published
release artifacts. Different delivery (a force-push that
rewrites an open PR's head after review), different execution
path (a project's release-build CI, not a developer's import),
different consequence (poisoned published installers, not a
payload run on a workstation). No test, intent, or claim from
#390 is repeated here; where the two share a mechanism --
exact-intent binding -- this module exercises it at the
build/release boundary #390 never touched.

Incident (Recorded-per-Corgea, from Corgea's research note
"PolinRider expands from npm into Go, Packagist, and Chrome
extension supply-chain poisoning," update of 2026-11-26;
figures below are Corgea's reporting of the maintainers' and
StepSecurity's accounts, not independently re-derived here):
the GitHub account ``Eternity0207`` opened 217 pull requests
across open-source projects, 145 of them merged. On
2026-10-19 it force-pushed rewritten commits carrying the
JavaScript loader into pull requests that were still open:
two at AsyncAPI Generator, ten at CircuitVerse
``cv-frontend-vue``, and four at Open Food Facts
``openfoodfacts-explorer``. The loader is the campaign's
``api.js``: one line pushed off-screen by hundreds of tabs,
wired in through a ``node api.js && `` prefix on the
``build``/``dev`` scripts in ``package.json`` (and, at
CircuitVerse, a folder-open VS Code task). What happened in
CI depended on each project's fork settings. AsyncAPI
requires maintainer approval for fork pull-request
workflows, so nothing ran there. At CircuitVerse the pull
request workflows, including the desktop release build, ran
without approval, and a CircuitVerse maintainer confirmed
the loader ran in the desktop build CI. The workflow's
artifact pages then offered 40 Windows, Linux and macOS
installers built after the loader ran, until the team
deleted them on 2026-11-25. Open Food Facts' CI ran
``pnpm build`` on each poisoned commit (all four runs
failed) and its maintainers rotated a secret. GitHub gives
fork ``pull_request`` workflows no repository secrets and a
read-only ``GITHUB_TOKEN``, and no project has reported
stolen secrets: the damage was not credential theft, it was
execution -- unreviewed code ran in a release build, and
what the build produced was published as the project's own
artifacts. By 2026-11-25 GitHub had suspended the account
and removed its pull requests; on 2026-11-26 CircuitVerse
merged a change so fork pull requests can no longer publish
builds.

The failure is twofold, and both halves are the same shape.
First, trusted-path execution: code arrived through a
trusted channel -- an open pull request from an account
with previously merged PRs -- and the release build
executed whatever the PR head currently contained, because
the channel was trusted, not because the specific content
was authorized: ``TRUSTED_PR_CHANNEL !=
AUTHORIZATION_FOR_THE_BUILD``. Second, and sharper: a
force-push after review changes the act itself. Whatever a
maintainer reviewed (or a workflow was set running against)
was the head at that moment; the force-push substituted a
different tree under the same pull request, and the build
ran the substituted tree as if it were the reviewed one.
The presented act was no longer the approved act, and
nothing on the path compared them.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the loader, any real
repository, any real CI system, or any real artifact. The
mapping (Inferred, stated here so it can be argued with):
the consequential acts are building a desktop release from
an exact PR head tree, and publishing the installers that
build produced. Each intent's resource string names the
exact head tree the act applies to, so the kernel's
exact-intent hash binds the tree identity: an approval for
the reviewed tree is an approval for that tree only, and
the force-pushed tree -- same pull request, same workflow,
different content -- is a different intent whose approval
does not exist. The loader's execution inside the build is
modeled as its own process-execution intent, the act no one
approved however it arrived. Tree labels, PR numbers, and
artifact names below are harness constructions in the
incident's shape, not recovered CircuitVerse artifacts;
the incident's 40-installer figure is Corgea's count,
carried as a count in the negative control's model output,
not as a claim about any artifact this harness produces.
The only route from a request to a consequence is a
successful ``GovernanceKernel.consume`` of a permit bound
to the exact intent hash: principal, action, resource,
cost, session.

Setup: exactly two acts are legitimate in this scenario --
building the release from the one reviewed head tree, and
publishing the artifact set that exact build produced --
each once, each under its own permit issued through a
verified approval envelope: the accountable per-action
authorizations actually granted. The incident's acts are
then attempted: the force-pushed build presented under the
reviewed build's approval (at the envelope boundary and at
consume), the loader executing under the genuine build
permit, the poisoned artifact set presented for
publication, a forged approval for the substituted build,
and the spent permits re-presented. The kernel must deny
each one, the consequence ledger must stay empty for all
of them, and every denial must land in the audit record.
The approved build's artifact set must reconcile exactly
against the audit; a claimed release record that presents
the poisoned installers as legitimate consequences fails
reconciliation in both directions.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules):
the derived incident report turns ``permit_rejected``
events, ``approval_rejected`` events, and denied decisions
into near-miss records. A bare ``evaluate`` that returns
``require_approval`` -- the kernel declining to mint
without approval -- appends a decision record to the
canonical audit but is NOT derived as a near-miss by the
channel. The scenario asserts both halves of that
statement exactly as they hold; it does not smooth the
second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any real CI system, forge, or release
pipeline that does not route its builds and publications
through this kernel -- a workflow that executes whatever a
PR head currently contains is governed by nothing here.
The replay models the authorization step the incident's
CI never performed, not GitHub Actions internals, and it
detects or removes no loader. A control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed build and one governed
publication are permitted per correctly verified approval
bound to the exact head tree, and any CI path that builds
or publishes whatever a trusted channel currently holds
(the incident's own class) remains outside this evidence
and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed." A denied attempt appends audit records,
counted per route: a bare evaluate returning
``require_approval`` appends one decision record; a
``consume`` rejection appends one ``permit_rejected``
record; a denied approval-envelope evaluation appends two
records -- an ``approval_rejected`` record and a denied
decision record. That growth is itself a governed effect
-- evidence production -- bounded at two records per
attempt, append-only, and it does not alter authority
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
# The desktop release-build CI runner: the dispatch
# boundary the incident's loader fed into. Every intent
# below is an act this runner would perform; a pull
# request proposes content, the runner must not build,
# execute, or publish anything without a permit bound to
# the exact act.
RUNNER = "agent:desktop-release-ci"
# The session of the force-push wave, 2026-10-19, in the
# harness's naming. Session identity is part of the bound
# intent; it is not itself authority for anything.
SESSION = "ci-session-2026-10-19"
ACTIONS = frozenset({"build_release", "publish_release", "execute_process"})

# The two head trees of the same open pull request. The
# reviewed tree is the content a maintainer saw when the
# build was authorized; the force-pushed tree is what the
# account substituted afterward, carrying the loader. The
# labels are harness constructions; what the binding proof
# turns on is only that they are DIFFERENT identities
# inside the hashed intent, as the two real trees were.
APPROVED_TREE = "head-tree-reviewed-clean"
SUBSTITUTED_TREE = "head-tree-force-pushed-loader"

# The legitimate acts. The build's resource identity names
# the exact reviewed head tree; the publication's resource
# identity names the artifact set of that exact build.
# Neither identity can stretch to cover the substituted
# tree or anything built from it.
BUILD_RESOURCE = f"repo:desktop-release-build/pr-head/{APPROVED_TREE}"
BUILD_INTENT = Intent(RUNNER, "build_release", BUILD_RESOURCE, 25, SESSION)
PUBLISH_RESOURCE = f"release:desktop-installers/from-{APPROVED_TREE}"
PUBLISH_INTENT = Intent(RUNNER, "publish_release", PUBLISH_RESOURCE, 25, SESSION)

# The artifact set the approved build produces in this
# harness: one installer per platform family. (The
# incident's published set was 40 installers across
# Windows, Linux and macOS -- Recorded-per-Corgea; the
# harness set is a construction, sized for assertion, and
# claims nothing about the real set's composition.)
APPROVED_ARTIFACTS = (
    "installer-windows@head-tree-reviewed-clean",
    "installer-linux@head-tree-reviewed-clean",
    "installer-macos@head-tree-reviewed-clean",
)

# The substituted artifact set: what a build of the
# force-pushed tree would produce, named in the same
# shape as the approved set but bound to the substituted
# tree. Used by the publication-binding regressions
# (steps 3b/3c) as the output a caller might present in
# place of the governed build's observed output.
POISONED_ARTIFACTS = (
    "installer-windows@head-tree-force-pushed-loader",
    "installer-linux@head-tree-force-pushed-loader",
    "installer-macos@head-tree-force-pushed-loader",
)


def artifact_digest(artifacts: tuple[str, ...]) -> str:
    """Digest of an exact artifact set, in presentation order."""
    return hashlib.sha256("\n".join(artifacts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BuildEvidence:
    """Evidence of a governed build's observed output.

    Carries the digest of the exact artifact set the
    build produced, the artifact set itself, and the
    provenance of that output -- the exact build resource
    (the reviewed head tree) whose governed execution
    produced it. Publication is bound to this evidence:
    a digest alone, detached from the artifacts and the
    build that produced them, proves nothing.
    """

    artifact_digest: str
    artifacts: tuple[str, ...]
    build_resource: str

# The incident's acts. The substituted build is the SAME
# action, principal, and session as the approved build --
# the same pull request and the same workflow -- aimed at
# the tree the force-push substituted. Same verb, same
# channel, different intent: the presented act is not the
# approved act.
SUBSTITUTED_BUILD_INTENT = Intent(
    RUNNER, "build_release", f"repo:desktop-release-build/pr-head/{SUBSTITUTED_TREE}", 25, SESSION
)
# The loader executing inside the build: the campaign's
# api.js, run by the build script's `node api.js && `
# prefix. Nobody approved this execution; it happened
# because the build ran the head's scripts.
LOADER_INTENT = Intent(
    RUNNER,
    "execute_process",
    "payload:api-js/node-api-js-loader/wallet-0x1eef0849eda15d87f64e51c73c8442cf3c8bcef3",
    25,
    SESSION,
)
# Publication of the poisoned set: the installers a build
# of the substituted tree would produce, offered on the
# project's own artifact pages as the project's own
# release -- the incident's realized consequence.
POISONED_PUBLISH_INTENT = Intent(
    RUNNER, "publish_release", f"release:desktop-installers/from-{SUBSTITUTED_TREE}", 25, SESSION
)

# The trusted channel itself, presented as if it were a
# permit: the force-push event on the open pull request.
# The PR was open, the account had merged PRs before, the
# workflow triggered -- that is the incident's whole
# authorization theory. The kernel must treat this string
# as a fabricated token, because that is what it is.
PR_CHANNEL_TOKEN = "pull-request-force-push:open-pr-head-updated:2026-10-19"


class ReleaseLedger:
    """Consequences of the release pipeline, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's CI did not have: in the
    incident, the workflow triggering WAS the execution
    path, and the build and publication followed
    immediately. Here the harness records an effect (and,
    for a build, its artifact set) only when the kernel
    consumes a permit for the exact intent. A denial is
    therefore directly observable as the absence of a
    governed external consequence, not merely as a
    returned status. (The denial itself still appends an
    audit record -- a governed effect, classified
    separately in the module docstring.)

    Publication is additionally bound to the governed
    build's observed output: recording a publication
    effect for the exact publication intent requires
    build evidence -- the observed artifact digest and
    provenance produced by this ledger's own governed
    build execution -- presented at the publication
    boundary and checked before the publication permit
    is consumed. Publication presented before any
    governed build, with caller-fabricated evidence, or
    with substituted output (an artifact set whose
    digest is not the observed build's digest) is
    refused without consuming the permit and without
    recording an effect.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []
        self.artifacts: list[str] = []
        # The build evidence this ledger has itself
        # observed: set only when a governed build
        # executes through this ledger, from the output
        # that build actually produced. Caller-presented
        # evidence is never adopted as observed evidence.
        self.build_evidence: BuildEvidence | None = None

    def _publication_evidence_matches(self, evidence: BuildEvidence | None) -> bool:
        # Publication is bound to the governed build's
        # observed output (Codex P2 fix pass, PR #408):
        # the presented evidence must exist, must be the
        # evidence this ledger observed from its own
        # governed build execution, must carry the
        # provenance of the exact approved build, and its
        # digest must match the artifact set presented
        # with it. Any missing, fabricated, or substituted
        # evidence fails closed here, BEFORE any permit
        # is consumed or any effect is recorded.
        if evidence is None or self.build_evidence is None:
            return False
        if evidence.build_resource != BUILD_RESOURCE:
            return False
        if evidence.artifact_digest != artifact_digest(evidence.artifacts):
            return False
        return evidence == self.build_evidence

    def execute(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        *,
        build_evidence: BuildEvidence | None = None,
    ) -> bool:
        if intent == PUBLISH_INTENT and not self._publication_evidence_matches(
            build_evidence
        ):
            return False
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        if intent == BUILD_INTENT:
            self.artifacts.extend(APPROVED_ARTIFACTS)
            self.build_evidence = BuildEvidence(
                artifact_digest(tuple(APPROVED_ARTIFACTS)),
                tuple(APPROVED_ARTIFACTS),
                BUILD_RESOURCE,
            )
        return True


class UngovernedReleaseCI:
    """The incident's CI shape, as a test-local model for the negative control.

    A release pipeline with no authorization step at all:
    it holds a pull request's CURRENT head -- a mutable
    pointer the PR author can rewrite at any time -- and
    its build executes whatever scripts the current head
    contains, then publishes whatever the build produced.
    Nothing compares the content being built against any
    reviewed or approved content, because there is no such
    comparison in the model, exactly as there was none on
    the incident's path. Faithful in exactly the property
    that mattered: the build's input is "whatever the head
    currently is," so a force-push between review and build
    silently substitutes the build's content. Test-local;
    never imported by runtime code.
    """

    # The build hook the loader rode in on, as recorded in
    # the incident reporting: the `build` script gained a
    # `node api.js && ` prefix.
    LOADER_HOOK = "node api.js && "

    def __init__(self, head_build_script: str) -> None:
        self.head_build_script = head_build_script
        self.loader_executions = 0
        self.published_artifacts: list[str] = []

    def force_push(self, head_build_script: str) -> None:
        # A force-push rewrites the open PR's head. The
        # pipeline neither notices nor re-reviews: the
        # pointer it will build from has simply moved.
        self.head_build_script = head_build_script

    def run_release_build(self) -> None:
        # The build runs the current head's build script,
        # whatever it now says, and publishes the result
        # under the project's name. If the loader hook is
        # in the script, the loader executes as part of
        # the build -- that is what a build script IS in
        # this model, an instruction the runner obeys.
        if self.LOADER_HOOK in self.head_build_script:
            self.loader_executions += 1
            # The incident's published set: 40 installers
            # built after the loader ran
            # (Recorded-per-Corgea). The model emits that
            # count of poisoned artifacts so the contrast
            # with the governed path is stated in the
            # incident's own terms.
            self.published_artifacts = [
                f"installer-{index}@head-tree-force-pushed-loader" for index in range(40)
            ]
        else:
            self.published_artifacts = list(APPROVED_ARTIFACTS)


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


# -- test-level reconciliation ------------------------------------------------
#
# Compared occurrence counts (multisets), defined once and used for the
# kernel audit throughout:
#   consequences  -- steps that executed (audit: permit_consumed records)
#   attempts      -- runner steps that did NOT execute and must be disclosed
#                   (audit: permit_rejected records, plus decision records
#                   with outcome require_approval / deny)
# Counts, not mere presence: an intent attempted three times, or executed
# twice under separately issued permits, contributes that many occurrences,
# and a claim reconciles only if it reports the same count for every hash.
# Authorization-side records (approval_verified, allow decisions) are the
# authority's own trail, not runner steps, and are excluded by design.
# This reconciliation is TEST-LEVEL, implemented against the public
# ``kernel.audit`` read path, as in the filename-deception, Mythos, and
# PR #390 scenarios: the shipped reconcilers reconcile filesystem effects
# and custody-domain outcomes, not a claimed release record against the
# kernel audit trail.


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
    # Fail closed: reconciliation must verify the audit chain FIRST.
    # Deriving counts from an invalid chain would accept fabricated
    # provenance -- the exact failure this scenario exists to expose.
    try:
        audit_valid = kernel.verify_audit()
    except Exception:
        audit_valid = False
    consequences, attempts = audited_counts(kernel.audit)
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


class PolinriderCIForcePushIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = ReleaseLedger()

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

    def _build_permit(self, kernel: GovernanceKernel) -> str:
        return self._issue_permit(
            kernel, BUILD_INTENT, approval_id="approval-build-1", nonce="nonce-build-1"
        )

    def _publish_permit(self, kernel: GovernanceKernel) -> str:
        return self._issue_permit(
            kernel, PUBLISH_INTENT, approval_id="approval-publish-1", nonce="nonce-publish-1"
        )

    # -- positive control -------------------------------------------------

    def test_positive_control_approved_head_builds_and_publishes_once(self) -> None:
        build_permit = self._build_permit(self.kernel)
        publish_permit = self._publish_permit(self.kernel)
        # The two legitimate acts: the release built from
        # the exact reviewed head tree, and the artifact
        # set of that exact build published. Each executes
        # exactly once under its own verified approval.
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        self.assertTrue(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=self.ledger.build_evidence,
            )
        )
        self.assertEqual(
            [("build_release", BUILD_RESOURCE), ("publish_release", PUBLISH_RESOURCE)],
            self.ledger.effects,
        )
        # Neither permit is a standing CI credential: each
        # re-presentation is rejected, and nothing further
        # is built or published.
        self.assertFalse(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertFalse(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=self.ledger.build_evidence,
            )
        )
        self.assertEqual(2, len(self.ledger.effects))
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        self.assertEqual(2, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        # The artifact set reconciles exactly: the claimed
        # release record that lists precisely the two
        # consumed acts -- and discloses the two spent
        # replays as attempts -- matches the audit count
        # for count.
        build_hash = self.kernel.intent_hash(BUILD_INTENT)
        publish_hash = self.kernel.intent_hash(PUBLISH_INTENT)
        honest_claim = {
            "consequences": sorted([build_hash, publish_hash]),
            "attempts": sorted([build_hash, publish_hash]),
        }
        result = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the force-push substitution --------------------------------
    #
    # The incident's core move. The approval was granted
    # against the reviewed head tree; the force-push then
    # rewrote the head. Presented with the substituted
    # build, the governed path compares the presented act
    # against the approved act at BOTH boundaries: the
    # genuine approval envelope, re-presented for the
    # substituted intent, fails the exact-intent binding
    # (approval_intent_mismatch), and the genuine build
    # permit, consumed against the substituted intent, is
    # rejected at consume. The build of the substituted
    # content does not execute on either route.

    def test_step1_force_pushed_build_is_not_the_approved_act(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel,
            BUILD_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-build-1",
            nonce="nonce-build-1",
        )
        # (a) The envelope boundary: a real approval for
        # the reviewed build, presented after the
        # force-push for the substituted build, is a
        # mismatch, not a transfer. The approval bound the
        # tree it was granted against; the tree changed.
        decision = self.kernel.evaluate_with_approval(
            SUBSTITUTED_BUILD_INTENT, genuine_envelope
        )
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The consume boundary: the permit the genuine
        # envelope issued, spent against the substituted
        # intent, is rejected bound to the substituted
        # intent's hash.
        permit = self._issue_permit(
            self.kernel,
            BUILD_INTENT,
            approval_id="approval-build-2",
            nonce="nonce-build-2",
        )
        self.assertFalse(self.ledger.execute(self.kernel, permit, SUBSTITUTED_BUILD_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual([], self.ledger.artifacts)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(SUBSTITUTED_BUILD_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The refusal was substitution, not lockout: the
        # same permit still spends on the exact approved
        # build it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("build_release", BUILD_RESOURCE)], self.ledger.effects)
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the loader under the genuine build permit -------------------

    def test_step2_loader_execution_denied_on_every_route(self) -> None:
        # No approval at all: the kernel declines to mint
        # for executing the fetched loader, and the PR's
        # presence in a trusted repository is not one.
        decision = self.kernel.evaluate(LOADER_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, LOADER_INTENT))
        # The trusted channel itself presented as a
        # permit: the PR was open, the workflow triggered,
        # the head updated. The kernel treats the
        # force-push event string as what it is -- a
        # fabricated token.
        self.assertFalse(self.ledger.execute(self.kernel, PR_CHANNEL_TOKEN, LOADER_INTENT))
        # The genuine build permit, re-aimed at the loader
        # the substituted tree carries: the build's
        # approval covers building the reviewed tree, not
        # executing whatever a later tree delivers.
        permit = self._build_permit(self.kernel)
        self.assertFalse(self.ledger.execute(self.kernel, permit, LOADER_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual({self.kernel.intent_hash(LOADER_INTENT)}, rejected_hashes)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denials were scope, not lockout: the permit
        # still spends on the exact approved build.
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("build_release", BUILD_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the poisoned artifact set cannot be published ---------------

    def test_step3_poisoned_publication_denied(self) -> None:
        # No approval exists for publishing a substituted
        # tree's output, and none can be borrowed: the
        # build permit does not cover any publication, and
        # the genuine publication permit -- issued for the
        # approved build's artifact set -- does not cover
        # the poisoned set, a different intent.
        decision = self.kernel.evaluate(POISONED_PUBLISH_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        build_permit = self._build_permit(self.kernel)
        publish_permit = self._publish_permit(self.kernel)
        self.assertFalse(
            self.ledger.execute(self.kernel, build_permit, POISONED_PUBLISH_INTENT)
        )
        self.assertFalse(
            self.ledger.execute(self.kernel, publish_permit, POISONED_PUBLISH_INTENT)
        )
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {self.kernel.intent_hash(POISONED_PUBLISH_INTENT)}, rejected_hashes
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The governed release still completes: build the
        # approved tree, publish its set, and only its set.
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertTrue(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=self.ledger.build_evidence,
            )
        )
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        self.assertTrue(self.kernel.verify_audit())

    # -- steps 3b/3c: publication is bound to the build's observed output -----
    #
    # Codex P2 fix pass (PR #408): the publication
    # boundary previously recorded a publication effect
    # from the intent's action and resource alone, without
    # accepting or checking the artifacts the governed
    # build produced -- so the exact publication intent
    # consumed before any build, or after outputs were
    # substituted, still returned success with the ledger's
    # artifact set empty or unrelated. The boundary now
    # requires the governed build's observed evidence
    # (artifact digest, artifact set, and build
    # provenance), checked before the permit is consumed.

    def test_step3b_publication_without_build_evidence_refused(self) -> None:
        build_permit = self._build_permit(self.kernel)
        publish_permit = self._publish_permit(self.kernel)
        # (a) No evidence at all, presented before any
        # build has run: the publication permit is valid
        # for the exact intent, but there is no governed
        # build output to publish.
        self.assertIsNone(self.ledger.build_evidence)
        self.assertFalse(
            self.ledger.execute(self.kernel, publish_permit, PUBLISH_INTENT)
        )
        # (b) Caller-fabricated evidence that names the
        # approved artifacts and their correct digest, but
        # was never observed from a governed build through
        # this ledger: correctly shaped metadata is not
        # build evidence.
        fabricated = BuildEvidence(
            artifact_digest(APPROVED_ARTIFACTS),
            tuple(APPROVED_ARTIFACTS),
            BUILD_RESOURCE,
        )
        self.assertFalse(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=fabricated,
            )
        )
        # Both refusals happened BEFORE consume: no effect
        # was recorded, no permit was consumed or rejected,
        # and the publication permit is unspent.
        self.assertEqual([], self.ledger.effects)
        self.assertEqual([], self.ledger.artifacts)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        # The honest path still completes with the same
        # permit once the governed build has produced its
        # observed evidence.
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertTrue(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=self.ledger.build_evidence,
            )
        )
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        self.assertTrue(self.kernel.verify_audit())

    def test_step3c_publication_with_substituted_output_refused(self) -> None:
        build_permit = self._build_permit(self.kernel)
        publish_permit = self._publish_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        observed = self.ledger.build_evidence
        self.assertIsNotNone(observed)
        # (a) Substituted output with its own self-consistent
        # digest: the poisoned artifact set, digested
        # correctly as itself, is still not the output the
        # governed build produced.
        substituted = BuildEvidence(
            artifact_digest(POISONED_ARTIFACTS),
            POISONED_ARTIFACTS,
            BUILD_RESOURCE,
        )
        self.assertFalse(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=substituted,
            )
        )
        # (b) Substituted output carrying the observed
        # build's digest: the digest does not match the
        # artifact set presented with it.
        mismatched = BuildEvidence(
            observed.artifact_digest,  # type: ignore[union-attr]
            POISONED_ARTIFACTS,
            BUILD_RESOURCE,
        )
        self.assertFalse(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=mismatched,
            )
        )
        # Both refusals happened BEFORE consume: only the
        # build effect exists, and the publication permit
        # is unspent.
        self.assertEqual([("build_release", BUILD_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(0, len(_events(self.kernel, "permit_rejected")))
        # The honest publication -- the observed evidence
        # of the governed build -- still succeeds with the
        # same permit.
        self.assertTrue(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=observed,
            )
        )
        self.assertEqual(
            [("build_release", BUILD_RESOURCE), ("publish_release", PUBLISH_RESOURCE)],
            self.ledger.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: a forged approval for the substituted build ------------------

    def test_step4_forged_approval_for_substituted_build_denied(self) -> None:
        # Whoever controls the PR branch cannot mint the
        # maintainer's authority over the release: an
        # envelope for the substituted build signed with
        # an unauthorized key is denied at verification.
        forged_envelope = signed_envelope(
            self.kernel,
            SUBSTITUTED_BUILD_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(
            SUBSTITUTED_BUILD_INTENT, forged_envelope
        )
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        # The denial did not poison the path: the genuine
        # pair still admits.
        permit = self._build_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: the spent permits replay for nothing --------------------------

    def test_step5_spent_permits_replay_denied(self) -> None:
        build_permit = self._build_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        # A consumed build permit is not a standing CI
        # credential the next workflow run can reuse: it
        # re-presents for nothing -- not for the same
        # approved build, and not for the substituted
        # build the force-push is waiting to feed it.
        self.assertFalse(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertFalse(
            self.ledger.execute(self.kernel, build_permit, SUBSTITUTED_BUILD_INTENT)
        )
        self.assertEqual([("build_release", BUILD_RESOURCE)], self.ledger.effects)
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation -- the claimed release record ------------------
    #
    # The incident's second-order failure: after the
    # poisoned installers were published, the project's own
    # artifact pages presented them as the project's
    # legitimate release -- repository state claiming a
    # provenance the acts never had. Reconciliation
    # compares that claimed release record against the
    # canonical audit in both directions: a claim is no
    # more free to hide attempts than it is to invent
    # consequences. State is evidence; state is not
    # provenance.

    def test_step6_reconciliation_exposes_poisoned_release_claim(self) -> None:
        build_permit = self._build_permit(self.kernel)
        publish_permit = self._publish_permit(self.kernel)
        # The governed record: the loader attempt rejected
        # at consume, the substituted build declined at
        # evaluate, and the two legitimate acts consumed.
        self.assertFalse(self.ledger.execute(self.kernel, build_permit, LOADER_INTENT))
        decision = self.kernel.evaluate(SUBSTITUTED_BUILD_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertTrue(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=self.ledger.build_evidence,
            )
        )
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)

        build_hash = self.kernel.intent_hash(BUILD_INTENT)
        publish_hash = self.kernel.intent_hash(PUBLISH_INTENT)
        loader_hash = self.kernel.intent_hash(LOADER_INTENT)
        substituted_hash = self.kernel.intent_hash(SUBSTITUTED_BUILD_INTENT)
        poisoned_hash = self.kernel.intent_hash(POISONED_PUBLISH_INTENT)
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({build_hash: 1, publish_hash: 1}, dict(consequences))
        self.assertEqual({loader_hash: 1, substituted_hash: 1}, dict(attempts))

        # The release record as the poisoned publication
        # would present it: the approved build and publish,
        # PLUS the poisoned publication as a third
        # legitimate consequence -- and no attempts at all.
        # No loader ever ran; no tree was ever substituted.
        # The record flags both halves: the attempts the
        # claim hides, and the poisoned consequence it
        # invents, an act that never passed the kernel and
        # has no provenance behind it.
        forged_claim = {
            "consequences": sorted([build_hash, publish_hash, poisoned_hash]),
            "attempts": [],
        }
        result = reconcile_against_audit(self.kernel, forged_claim)
        self.assertFalse(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual({loader_hash, substituted_hash}, set(result.undisclosed_attempts))
        self.assertEqual({poisoned_hash}, set(result.unbacked_consequences))
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # Reconciliation is not a trap: a release record
        # that lists exactly the two consumed acts and
        # DISCLOSES both attempts reconciles exactly.
        honest_claim = {
            "consequences": sorted([build_hash, publish_hash]),
            "attempts": sorted([loader_hash, substituted_hash]),
        }
        honest = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(honest.ok)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the wave ----------------------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit: every consume rejection, every approval
    # rejection, and every denied decision in the sequence
    # becomes a near-miss record in the derived incident
    # report. The bare require_approval decisions are in
    # the canonical audit (and counted below) but are NOT
    # derived as near-misses -- the expected near-miss
    # count is built from the event classes the channel
    # actually derives, so this test pins the boundary
    # instead of papering over it.
    #
    # The frozen sequence is the full attempt sequence of
    # steps 1-5 exercisable on one kernel: the substituted
    # build on the envelope route and the consume route,
    # the loader on the bare-evaluate, channel-token, and
    # genuine-permit routes, the poisoned publication on
    # both genuine permits, the forged envelope, the two
    # legitimate acts, and the spent build permit replayed
    # against the substituted build.

    def test_step7_incident_channel_surfaces_the_wave(self) -> None:
        build_permit = self._build_permit(self.kernel)
        publish_permit = self._publish_permit(self.kernel)
        # Step 1a, replayed: the genuine build envelope
        # presented for the substituted intent after the
        # force-push. Each envelope in this sequence
        # carries its own approval_id and nonce, as each
        # real approval would: the helper's fixed defaults
        # would collide with the issuances above and turn
        # a later denial into a replay denial,
        # misattributing the control that rejected it.
        genuine_envelope = signed_envelope(
            self.kernel,
            BUILD_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(
            SUBSTITUTED_BUILD_INTENT, genuine_envelope
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # Step 1b: the genuine build permit consumed
        # against the substituted intent.
        self.assertFalse(
            self.ledger.execute(self.kernel, build_permit, SUBSTITUTED_BUILD_INTENT)
        )
        # Step 2: the loader on its bare-evaluate,
        # channel-token, and genuine-permit routes.
        self.kernel.evaluate(LOADER_INTENT)
        self.assertFalse(self.kernel.consume(PR_CHANNEL_TOKEN, LOADER_INTENT))
        self.assertFalse(self.kernel.consume(build_permit, LOADER_INTENT))
        # Step 3: the poisoned publication under both
        # genuine permits.
        self.assertFalse(self.kernel.consume(build_permit, POISONED_PUBLISH_INTENT))
        self.assertFalse(self.kernel.consume(publish_permit, POISONED_PUBLISH_INTENT))
        # Step 4: the forged envelope for the substituted
        # build.
        forged_envelope = signed_envelope(
            self.kernel,
            SUBSTITUTED_BUILD_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-seq-forged",
            nonce="nonce-seq-forged",
        )
        decision = self.kernel.evaluate_with_approval(
            SUBSTITUTED_BUILD_INTENT, forged_envelope
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # The two legitimate acts still land; the wave
        # did not.
        self.assertTrue(self.ledger.execute(self.kernel, build_permit, BUILD_INTENT))
        self.assertTrue(
            self.ledger.execute(
                self.kernel,
                publish_permit,
                PUBLISH_INTENT,
                build_evidence=self.ledger.build_evidence,
            )
        )
        self.assertEqual(list(APPROVED_ARTIFACTS), self.ledger.artifacts)
        # Step 5, replayed: the now-spent build permit
        # re-presented for the substituted build.
        self.assertFalse(self.kernel.consume(build_permit, SUBSTITUTED_BUILD_INTENT))
        self.assertEqual(2, len(self.ledger.effects))

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
        self.assertEqual(6, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
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

    # -- negative control -------------------------------------------------------

    def test_negative_control_ungoverned_ci_publishes_poisoned_artifacts(self) -> None:
        # Same incident, the authorization step removed: a
        # CI model that builds whatever the PR head
        # currently contains. Before the force-push it
        # builds the reviewed tree and publishes the clean
        # set, exactly as the governed path does -- the
        # model is not broken in general. The force-push
        # then rewrites the head, the next build runs the
        # substituted tree's build script, the loader
        # EXECUTES inside the release build, and 40
        # poisoned installers are published under the
        # project's name. That is the incident, reproduced
        # at the exact layer it happened: not the forge,
        # not the network -- the missing comparison
        # between what was reviewed and what was built.
        ci = UngovernedReleaseCI("npm run compile")
        ci.run_release_build()
        self.assertEqual(0, ci.loader_executions)
        self.assertEqual(list(APPROVED_ARTIFACTS), ci.published_artifacts)
        ci.force_push("node api.js && npm run compile")
        ci.run_release_build()
        self.assertEqual(1, ci.loader_executions)
        self.assertEqual(40, len(ci.published_artifacts))
        self.assertTrue(
            all(
                artifact.endswith("@head-tree-force-pushed-loader")
                for artifact in ci.published_artifacts
            )
        )
        # Contrast, the identical substitution against the
        # governed path: the presented build is not the
        # approved build, and nothing executes (step 1's
        # route, here at the envelope boundary).
        genuine_envelope = signed_envelope(
            self.kernel,
            BUILD_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-genuine",
            nonce="nonce-nc-genuine",
        )
        decision = self.kernel.evaluate_with_approval(
            SUBSTITUTED_BUILD_INTENT, genuine_envelope
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        self.assertEqual([], self.ledger.effects)


if __name__ == "__main__":
    unittest.main()
