"""Scenario test: the November 2026 WPPConnect npm compromise,
modeled against the canonical kernel API.

Incident (Recorded, from StepSecurity's published analysis,
"WPPConnect Compromised: Malicious Releases Steal Secrets and
WhatsApp Sessions Through the Project's Own Pipeline," covering
2026-11-15 to 2026-11-17): on 2026-11-15 at 22:34 UTC, two unsigned
commits were pushed directly to the master branch of
wppconnect-team/wppconnect — no pull request, no review — through
the joaosouz4dev account (how that access was obtained is not
established in the source). The commits added
``src/utils/diagnostics.ts``, a module that on import copies
environment variables, .env/config files, and WhatsApp session
tokens and uploads them to a Telegram bot, and imported it. The
release workflow was then dispatched by hand and the package
published to npm through a GitHub Actions trusted publisher
carrying a VALID SLSA provenance attestation: StepSecurity decoded
it and every field is accurate (workflow ``publish.yml``, ref
``refs/tags/v2.4.1``, commit ``dee571e``) — and the commit is the
malicious one. In their words: "Provenance proves where a package
was built, not whether anyone reviewed the source." The publish
workflow at the release commit had no ``environment:`` key, so no
reviewer approval stood between tag and registry. The server
package (@wppconnect/server) received the same treatment — a push
to main auto-triggered release 2.10.82 — and Docker images and the
GitHub nightly release carried the payload too. After an external
researcher opened public issues, both default branches were
force-pushed within about 30 seconds and the v2.4.1 tag was
rewritten to a look-alike commit with the same message and
timestamp but WITHOUT the payload, so the source visible on GitHub
did not match the tarball npm served; the tags were deleted on
2026-11-17. The bad versions were ``latest`` for about 4.5 hours;
npm recorded at least 155 downloads of 2.4.1 (a floor).

This module does NOT reproduce WPPConnect, the payload, or any
part of the exfiltration module. The malicious "tree" below is a
synthetic byte string that merely names the diagnostics module;
no payload code exists in this file. The "publisher" is this
harness holding intents; the only route from intent to a published
release is a successful ``GovernanceKernel.consume`` of a permit
bound to the exact intent hash, and the intent names the release's
source tree by its SHA-256 hash — the permit binds the package,
the version, AND the exact tree to be published.

The distinct contribution of this scenario, against the existing
incident battery: **attestation is not authorization.** In the
incident every origin signal was genuine — a trusted-publisher
identity, a valid SLSA provenance attestation whose fields all
check out — and none of it was an approval of the act by an
authority entitled to approve it. Provenance is evidence about
origin; it is not a permit. Setup A's step 3 is the sharp edge:
an approval envelope that is validly signed and internally
consistent under the release pipeline's OWN key (the
trusted-publisher analog) is denied at evaluation, because that
key is not the reviewer authority. Origin credentials cannot
substitute for a permit, however authentic they are.

Setup A (approval path): a release requires the reviewer
authority's approval of the exact tree. The incident's acts are
then attempted: a publish with no permit, the malicious tree
presented under the reviewed tree's permit, the pipeline-key
envelope for the malicious tree, and replay of the spent publish
permit. An observer then reconciles: the registry's recorded
artifact tree hash and the repository tag's current tree hash are
checked against the kernel audit record — the history that cannot
be force-pushed — so the incident's cover-up (repointing the tag
to a look-alike tree after the fact) is flagged as a mismatch
instead of replacing the record.

Setup B (directive path): the release pipeline publishes under
the maintainer's standing directive, scoped to the package. A
publish permit is issued under it; the maintainer then revokes
the directive (the incident-response move, once the compromise
was reported). The previously issued, unconsumed permit must
fail at consume with the directive recorded as revoked, and a
directive-issued permit must not spend on the malicious tree.

Boundary: this proves kernel behavior at this commit for this
action class (Verified, executable evidence). It proves nothing
about npm, GitHub, or SLSA themselves; it does not model how the
account access was obtained (Unknown in the source), and it
models only the main package's npm publish — the server package,
Docker images, and nightly release are further distribution acts
of the same class, not separately modeled. A pipeline that does
not route its publishes through the gate is governed by nothing
here: a control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's pull
request per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only — exactly the reviewer-approved publishes are permitted,
and any non-kernel publish path (the known direct-writer class)
remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): each denied attempt appends exactly one
audit record — a governed effect (evidence production), bounded
at one record per attempt, append-only, ``authority_effect=none``.
"Consequence" below means governed external consequence — a
release actually recorded by the registry — never audit growth.
"""

from __future__ import annotations

import hashlib
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import (
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_directives import OPERATOR, directive


NOW = 3_000_000
AGENT = "agent:release-pipeline"
SESSION = "wppconnect-release-2026-11"

PACKAGE = "@wppconnect-team/wppconnect"
VERSION = "v2.4.1"

# Synthetic byte strings standing in for source trees. Only their
# hashes enter intents; the malicious tree merely NAMES the module
# from the incident — it contains no payload code.
REVIEWED = b"wppconnect tree | src/index.ts | reviewed release, no diagnostics module"
MALICIOUS = b"wppconnect tree | src/index.ts + src/utils/diagnostics.ts (imported) | UNREVIEWED"
LOOKALIKE = b"wppconnect tree | src/index.ts | rewritten tag, same message/timestamp, no diagnostics"

ACTIONS = frozenset({"publish_release"})


def tree_hash(tree: bytes) -> str:
    return hashlib.sha256(tree).hexdigest()


def intent_for(package: str, version: str, tree: bytes) -> Intent:
    """The publish intent names the package, the version, AND the
    exact source tree by hash."""
    return Intent(
        AGENT,
        "publish_release",
        f"npm:{package}@{version}#tree={tree_hash(tree)}",
        len(tree),
        SESSION,
    )


class PipelineTestVerifier(HmacTestVerifier):
    """Test-only double for the release pipeline's own automation
    key — the trusted-publisher analog. A genuine, working signer
    with its own identity and key; it is simply not the reviewer
    authority. Its signatures verify under its own key; they
    authorize nothing here."""

    authority_id = "authority:release-pipeline"
    verifier_id = "verifier:pipeline-automation"
    key_id = "key:pipeline-automation:v1"
    key_fingerprint = hashlib.sha256(b"pulpo-test-pipeline-key").hexdigest()

    def __init__(self, secret=b"pipeline-automation-key"):
        super().__init__(secret)


class Registry:
    """What the package registry actually published — the
    consequence surface. A release is recorded only through a
    successful consume."""

    def __init__(self) -> None:
        self.published: dict[tuple[str, str], str] = {}

    def publish(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        package: str,
        version: str,
        tree: bytes,
    ) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.published[(package, version)] = tree_hash(tree)
        return True


class TagBook:
    """The repository's version tags as an outside observer sees
    them NOW. Unlike the audit record, a tag is mutable — the
    incident's cover-up rewrote one."""

    def __init__(self) -> None:
        self.tags: dict[str, str] = {}

    def point(self, version: str, tree: bytes) -> None:
        self.tags[version] = tree_hash(tree)

    def current(self, version: str) -> str | None:
        return self.tags.get(version)


def audit_supported_publishes(
    kernel: GovernanceKernel,
    package: str,
    version: str,
    candidate_trees: list[bytes],
) -> set[tuple[str, str]]:
    """The (version, tree hash) pairs the kernel audit actually
    consumed a publish for — ground truth read from the audit
    record, the history that cannot be force-pushed."""
    consumed = {
        record["payload"]["intent_hash"]
        for record in kernel.audit
        if record["event"] == "permit_consumed"
    }
    return {
        (version, tree_hash(tree))
        for tree in candidate_trees
        if kernel.intent_hash(intent_for(package, version, tree)) in consumed
    }


def reconcile_release(
    registry_pair: tuple[str, str],
    tag_pair: tuple[str, str],
    supported: set[tuple[str, str]],
) -> dict:
    """Test-level reconciliation. Directions stated explicitly
    (the PR #362 lesson): ``false_claims`` is claims minus
    audit-consumed publishes — a claim (here, the tag's current
    target presented as "what this version is") with no consumed
    publish behind it is a false claim; ``tag_mismatch`` is the
    tag's target diverging from the artifact the registry
    actually recorded."""
    return {
        "ok": registry_pair in supported and tag_pair == registry_pair,
        "tag_mismatch": tag_pair != registry_pair,
        "false_claims": {tag_pair} - supported,
    }


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control (see
    the canonical incident scenarios): its consume ignores the
    intent binding, so the substituted publish must EXECUTE under
    it, proving the scenario's denials come from the kernel's
    binding."""

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
    """Deliberately unguarded kernel double for the negative control."""

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


class WppconnectApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.registry = Registry()

    def _kernel(self, state=None, *, kernel_class=GovernanceKernel) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret=b"wppconnect-scenario-kernel-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
        )

    def _issue(self, kernel: GovernanceKernel, intent: Intent) -> str:
        self._issue_count = getattr(self, "_issue_count", 0) + 1
        n = self._issue_count
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=f"approval-{n}",
            nonce=f"approval-nonce-{n}",
        )
        decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit

    # -- positive control -------------------------------------------------

    def test_positive_control_reviewed_publish_executes_exactly_once(self) -> None:
        permit = self._issue(self.kernel, intent_for(PACKAGE, VERSION, REVIEWED))
        intent = intent_for(PACKAGE, VERSION, REVIEWED)
        self.assertTrue(
            self.registry.publish(self.kernel, permit, intent, PACKAGE, VERSION, REVIEWED)
        )
        self.assertEqual(
            {(PACKAGE, VERSION): tree_hash(REVIEWED)}, self.registry.published
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: publish with no permit ------------------------------------

    def test_step1_publish_without_permit_refused(self) -> None:
        self.assertFalse(
            self.registry.publish(
                self.kernel,
                None,
                intent_for(PACKAGE, VERSION, REVIEWED),
                PACKAGE,
                VERSION,
                REVIEWED,
            )
        )
        self.assertEqual({}, self.registry.published)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: malicious tree under the reviewed tree's permit -----------

    def test_step2_malicious_tree_under_reviewed_permit_denied(self) -> None:
        permit = self._issue(self.kernel, intent_for(PACKAGE, VERSION, REVIEWED))
        self.assertFalse(
            self.registry.publish(
                self.kernel,
                permit,
                intent_for(PACKAGE, VERSION, MALICIOUS),
                PACKAGE,
                VERSION,
                MALICIOUS,
            )
        )
        self.assertEqual({}, self.registry.published)
        # The denial consumed nothing: the reviewed tree still publishes.
        self.assertTrue(
            self.registry.publish(
                self.kernel,
                permit,
                intent_for(PACKAGE, VERSION, REVIEWED),
                PACKAGE,
                VERSION,
                REVIEWED,
            )
        )
        self.assertEqual(
            {(PACKAGE, VERSION): tree_hash(REVIEWED)}, self.registry.published
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the pipeline's own key — valid signature, wrong authority --

    def test_step3_pipeline_key_envelope_denied_wrong_authority(self) -> None:
        pipeline = PipelineTestVerifier()
        pipeline_trust = trust_for(pipeline)
        intent = intent_for(PACKAGE, VERSION, MALICIOUS)
        envelope = signed_envelope(
            self.kernel,
            intent,
            pipeline,
            now_ns=NOW,
            approval_id="pipeline-approval-1",
            nonce="pipeline-nonce-1",
            authority_id=pipeline_trust.authority_id,
            verifier_id=pipeline_trust.verifier_id,
            key_id=pipeline_trust.key_id,
            deployment_id=pipeline_trust.deployment_id,
            trust_hash=pipeline_trust.trust_hash,
        )
        # The envelope is genuine: its signature verifies under the
        # pipeline's own key, and every identity field is the
        # pipeline's own. This is the trusted-publisher analog —
        # authentic origin credentials, exactly as the incident's
        # SLSA attestation was authentic.
        self.assertTrue(pipeline.verify(envelope.signing_bytes(), envelope.signature))
        # Authenticity is not authority: the pipeline key is not the
        # reviewer authority, so no permit is minted.
        decision = self.kernel.evaluate_with_approval(intent, envelope)
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)
        self.assertEqual({}, self.registry.published)

    # -- step 4: replay of the spent publish permit -------------------------

    def test_step4_replay_of_spent_publish_permit_denied(self) -> None:
        permit = self._issue(self.kernel, intent_for(PACKAGE, VERSION, REVIEWED))
        intent = intent_for(PACKAGE, VERSION, REVIEWED)
        self.assertTrue(
            self.registry.publish(self.kernel, permit, intent, PACKAGE, VERSION, REVIEWED)
        )
        self.assertFalse(
            self.registry.publish(self.kernel, permit, intent, PACKAGE, VERSION, REVIEWED)
        )
        self.assertEqual(
            {(PACKAGE, VERSION): tree_hash(REVIEWED)}, self.registry.published
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: reconciliation defeats the tag rewrite ---------------------

    def test_step5_reconciliation_defeats_tag_rewrite(self) -> None:
        permit = self._issue(self.kernel, intent_for(PACKAGE, VERSION, REVIEWED))
        self.assertTrue(
            self.registry.publish(
                self.kernel,
                permit,
                intent_for(PACKAGE, VERSION, REVIEWED),
                PACKAGE,
                VERSION,
                REVIEWED,
            )
        )
        tags = TagBook()
        tags.point(VERSION, REVIEWED)

        supported = audit_supported_publishes(
            self.kernel, PACKAGE, VERSION, [REVIEWED, MALICIOUS, LOOKALIKE]
        )
        self.assertEqual({(VERSION, tree_hash(REVIEWED))}, supported)
        registry_pair = (VERSION, self.registry.published[(PACKAGE, VERSION)])

        # Honest state: the tag points at exactly the tree the audit
        # consumed a publish for and the registry recorded.
        result = reconcile_release(registry_pair, (VERSION, tags.current(VERSION)), supported)
        self.assertTrue(result["ok"])
        self.assertFalse(result["tag_mismatch"])
        self.assertEqual(set(), result["false_claims"])

        # The cover-up: the tag is force-repointed to a look-alike
        # tree — same version label, different bytes — so the visible
        # source no longer matches what was actually published.
        tags.point(VERSION, LOOKALIKE)
        result = reconcile_release(registry_pair, (VERSION, tags.current(VERSION)), supported)
        self.assertFalse(result["ok"])
        self.assertTrue(result["tag_mismatch"])
        # Claims minus consumed: the look-alike tree was never the
        # published tree, and the audit record still says so.
        self.assertEqual({(VERSION, tree_hash(LOOKALIKE))}, result["false_claims"])
        # The rewrite touched only the tag: the registry's record of
        # what was published is unchanged.
        self.assertEqual(
            {(PACKAGE, VERSION): tree_hash(REVIEWED)}, self.registry.published
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ---------------------------------------------------

    def test_negative_control_unguarded_kernel_publishes_malicious_tree(self) -> None:
        kernel = self._kernel(_IntentBlindState(), kernel_class=_UnguardedConsumeKernel)
        registry = Registry()
        permit = self._issue(kernel, intent_for(PACKAGE, VERSION, REVIEWED))
        self.assertTrue(
            registry.publish(
                kernel,
                permit,
                intent_for(PACKAGE, VERSION, MALICIOUS),
                PACKAGE,
                VERSION,
                MALICIOUS,
            )
        )
        self.assertEqual(
            {(PACKAGE, VERSION): tree_hash(MALICIOUS)}, registry.published
        )


class WppconnectRevocationTests(unittest.TestCase):
    """Setup B: revocation of the maintainer's directive kills a
    previously issued, unconsumed publish permit at consume time,
    and a directive-issued permit does not spend on the malicious
    tree.

    The activation/revocation scaffolding mirrors DirectiveProofTests
    (tests/test_directives.py) by composition of the same public
    helpers, with the kernel policy's action set covering this
    scenario's action; it does not inherit that suite.
    """

    def _governed(self, state):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"publish_release", "activate_directive", "revoke_directive"}),
            10_000,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"wppconnect-directive-scenario-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def _directive(self):
        return directive(
            directive_id="wppconnect-release-authority",
            principal=AGENT,
            allowed_actions=frozenset({"publish_release"}),
            resource_prefixes=(f"npm:{PACKAGE}",),
            max_cost=10_000,
            issued_at_ns=1_000_000,
            expires_at_ns=9_000_000,
        )

    def _approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation, d, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def _activate(self, state, d):
        kernel, verifier = self._governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self._approve(
            kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1"
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def test_revoked_directive_invalidates_issued_publish_permit(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(intent_for(PACKAGE, VERSION, REVIEWED), d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revoke_envelope = self._approve(
            kernel, verifier, controller.REVOKE, d, "revoke-1", "revoke-nonce-1"
        )
        revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", revoke.outcome)

        registry = Registry()
        self.assertFalse(
            registry.publish(
                kernel,
                decision.permit,
                intent_for(PACKAGE, VERSION, REVIEWED),
                PACKAGE,
                VERSION,
                REVIEWED,
            )
        )
        self.assertEqual({}, registry.published)
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])

    def test_directive_permit_does_not_spend_on_malicious_tree(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(intent_for(PACKAGE, VERSION, REVIEWED), d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        registry = Registry()
        self.assertFalse(
            registry.publish(
                kernel,
                decision.permit,
                intent_for(PACKAGE, VERSION, MALICIOUS),
                PACKAGE,
                VERSION,
                MALICIOUS,
            )
        )
        self.assertEqual({}, registry.published)
        self.assertTrue(
            registry.publish(
                kernel,
                decision.permit,
                intent_for(PACKAGE, VERSION, REVIEWED),
                PACKAGE,
                VERSION,
                REVIEWED,
            )
        )
        self.assertEqual(
            {(PACKAGE, VERSION): tree_hash(REVIEWED)}, registry.published
        )


if __name__ == "__main__":
    unittest.main()
