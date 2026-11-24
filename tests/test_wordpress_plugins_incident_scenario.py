"""Scenario test: the WP connect WordPress plugins supply-chain
backdoor (publicized 2026-11-23).

Incident (Recorded, from Wordfence's report, "Supply Chain
Compromise Backdoors Six WP Connect Plugins," 2026-11-23 --
the disclosing researcher's primary statement): on
2026-11-22, over roughly two hours (about 4:30-5:40 PM ET),
backdoored releases of six WordPress plugins from the same
connect-plugin family were committed to WordPress.org from
the developer's own account: Air WP Sync (``air-wp-sync``)
2.9.1-2.9.4, WP Sync for Notion (``wp-sync-for-notion``)
1.7.4, Add-on Brevo for Gravity Forms 2.6.3, Add-On for
Contact Form 7 to Airtable 2.5.4, Add-On for Contact Form 7
to Notion 1.6.4, and Orders Sync to Airtable for WooCommerce
1.0.2 -- more than 3,600 active installs combined. Each
backdoored release added one file,
``includes/airwp-online.php``, plus one ``require_once``
line. The added module hooks ``init`` and a half-hourly cron
event, POSTs a site fingerprint (site URL, PHP, WordPress
and OS versions, server user) to tascredit-pay.com with TLS
certificate verification disabled, and ``eval()``s whatever
PHP the server returns; the reported command set includes
shell execution, file read/write/delete, database dump
including password hashes, webshell drop, and hourly
persistence. CVE-2026-135202, CVSS 9.8.

Attribution grading, stated exactly: that the developer's
WordPress.org account was compromised is Recorded/reported,
not Verified -- Wordfence states the evidence "strongly
suggests" the account was compromised and the developer
reports that it was; the details are pending. This scenario
does not depend on the attribution: whether the releases
were pushed by an attacker holding the account or by anyone
else holding it, the failure modeled here is identical --
the account's possession was the only authority the
distribution path asked for.

THE CAVEAT, FIRST (Verified, from the same Wordfence
report): the backdoored versions were NEVER released to
sites. WordPress.org's Protect The Shire cooling-off
release hold, together with its Gandalf automated reviewer,
stopped the releases; all six plugins were closed the same
evening, and no exploitation of live sites has been
reported. Nothing in this scenario claims Pulpo caught, or
would have caught, anything in the real event. The release
hold is the real-world analogue of the gate this scenario
models: a pre-distribution check that does not take the
publisher's say-so as the release's authority. This replay
is of the mechanism, with the caveat carried, per the
caught-before-distribution precedent of PR #380.

The failure modes the incident documents:

1. Account possession treated as release authority. Whoever
   held the developer's WordPress.org account could publish
   arbitrary code as official updates to more than 3,600
   sites. The account authenticated the publisher; nothing
   authorized the specific release.
2. Artifact substitution under a genuine label. The
   backdoored releases presented as ordinary version bumps
   (2.9.1, 2.9.2, ...) from the genuine account. Nothing on
   the distribution path bound the release to the exact
   artifact bytes anyone had reviewed or approved, so a
   tampered artifact inherited the label's trust.
3. The update channel as trusted path. Sites install plugin
   updates because the channel is trusted, not because the
   specific act -- this artifact, this version, to these
   sites -- was authorized. Had the hold not intervened, the
   channel itself would have delivered the backdoor at
   update tempo.

This module models those failure modes against the
canonical kernel API. It does NOT reproduce WordPress,
WordPress.org, any plugin, any site, or any network
behavior. The scope is narrower and exact: had the publish
of each release been a governed act -- a permit bound to
the exact intent (the plugin, the version, and the digest
of the artifact's actual bytes), rechecked at consequence
time and consumed on use -- the account credential alone
would have minted nothing, and the backdoored artifact
would have failed the digest binding at the distribution
gate, before any site saw it: the same point in the path
where the real release hold stopped it.

How the artifact binding is modeled, exactly: the artifact
in this module is an actual byte string (a release manifest:
the archive's file list plus its patch lines), and the
digest bound in the intent is the SHA-256 of those exact
bytes, derived from them -- never a caller-supplied label
for them. The scenario's distribution boundary
(``DistributionGate``) is presented with three things: the
permit, the intent the caller claims to be executing, and
the actual artifact bytes about to be distributed. The
boundary derives the digest of those bytes at distribution
time and submits the act the bytes actually constitute: if
the derived digest is not the digest bound in the presented
intent, the intent is rebuilt from the derived digest
before anything is consumed, so a tampered artifact is
authorized, if at all, as itself -- never under the
approved artifact's label.

Setup: the release publisher holds exactly one legitimate
permit: one exact release -- one exact plugin, one exact
version (2.9.0, the last clean ``air-wp-sync`` release
before the backdoored 2.9.1-2.9.4 sequence), one exact
artifact -- issued through a verified approval envelope.
Its plugin scope is set by an AgentGrant naming the exact
plugin identity as its sole resource prefix (see the
module-level note on prefix matching below). The incident's
acts are then attempted, in sequence: a publish presenting
the developer's account credential as its permit (the
possession shape), the backdoored artifact presented under
the genuine permit (the substitution shape), a different
version and a different plugin under the genuine permit
(the re-aiming shapes), and the permitted release replayed
after use. The kernel must deny each one, the distribution
gate must record no distribution for any of them, and every
denial must land in the audit record.

A note on resource matching, stated plainly (Verified at
this commit, from the kernel source and pinned by step 3):
AgentGrant resource matching is prefix-based
(``str.startswith``). The grant in this scenario names the
exact plugin identity as its only prefix, so a resource
that merely shares a string prefix with the authorized
release identity -- the release identity with a suffix
appended -- also passes the grant layer. The scenario does
not hide that: step 3 exercises exactly that case and pins
where it is and is not stopped (the grant passes it; the
exact-intent permit binding denies it, because a suffixed
resource is a different intent). The different-plugin
denial in step 3 is claimed only for the genuinely distinct
plugin identity, which shares no prefix with the authorized
one. Whether grant matching should be exact-equality rather
than prefix is a kernel design question (surfaced by PR
#381's review); this replay records the behavior exactly as
it stands and claims no more scope than the executed run
proves.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules): the
derived incident report turns ``permit_rejected`` events,
``approval_rejected`` events, and denied decisions into
near-miss records. A bare ``evaluate`` that returns
``require_approval`` -- the kernel declining to mint without
approval -- appends a decision record to the canonical audit
but is NOT derived as a near-miss by the channel. The
scenario asserts both halves of that statement exactly as
they hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any deployed distribution path that
does not route its publishes through this kernel, nothing
about WordPress.org's actual review pipeline, and nothing
about the real event beyond the mechanism modeled -- in
which, to say it once more, the backdoor was stopped by
WordPress.org's own hold and never reached a site. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is permitted,
and any non-kernel distribution path (the incident's own class)
remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." A denied attempt appends audit records, counted
per route: a bare evaluate returning ``require_approval``
appends one decision record; a policy-denied evaluate
appends one denied decision record; a ``consume`` rejection
appends one ``permit_rejected`` record; a denied
approval-envelope evaluation appends two records -- an
``approval_rejected`` record and a denied decision record.
That growth is itself a governed effect --
evidence production -- bounded at two records per attempt,
append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. It is
classified and assessed separately from governed external
consequences throughout this module: "consequence" below means
governed external consequence (the permitted consume recorded
in the distribution gate), never audit growth.
"""

from __future__ import annotations

import hashlib
import unittest

from pulpo import (
    AgentGrant,
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
AGENT = "agent:release-publisher"
SESSION = "release-session-2026-11-22"
ACTION = "publish_release"

# The one act actually authorized: publish of one exact
# release -- one exact plugin, one exact version, one exact
# artifact. The resource identity names the plugin, the
# version, and the artifact digest together; any other
# artifact, any other version, or any other plugin is a
# different resource and therefore a different intent.
#
# The artifact is an actual byte string (the release
# manifest: the archive's file list plus its patch lines),
# and the digest bound in the intent is derived from those
# bytes with SHA-256 -- a function of the artifact itself,
# not a label a caller supplies for it.
ARTIFACT_BYTES = (
    b"air-wp-sync-2.9.0.zip\n"
    b"air-wp-sync/air-wp-sync.php\n"
    b"air-wp-sync/includes/class-air-wp-sync.php\n"
    b"air-wp-sync/includes/class-sync-engine.php\n"
    b"air-wp-sync/readme.txt\n"
)
ARTIFACT_DIGEST = "sha256:" + hashlib.sha256(ARTIFACT_BYTES).hexdigest()
PLUGIN = "plugin:air-wp-sync"
RELEASE_RESOURCE = f"{PLUGIN}/version:2.9.0/artifact:{ARTIFACT_DIGEST}"
RELEASE_INTENT = Intent(AGENT, ACTION, RELEASE_RESOURCE, 25, SESSION)

# The incident's acts. None of them has an approval.
#
# The backdoored artifact: the same release, presented under
# the same plugin and the approved version's label, with the
# incident's own additions in the bytes -- the added module
# file ``includes/airwp-online.php`` and the ``require_once``
# patch line that loads it. The presenting account and the
# version label are exactly as genuine-looking as they were
# in the incident; only the bytes differ, and the derived
# digest is a function of the bytes. BACKDOORED_INTENT is
# the intent those bytes actually constitute -- the act the
# distribution boundary derives from the bytes presented,
# whether or not the caller labels it so.
BACKDOORED_BYTES = ARTIFACT_BYTES + (
    b"air-wp-sync/includes/airwp-online.php\n"
    b"air-wp-sync/air-wp-sync.php:+require_once includes/airwp-online.php\n"
)
assert BACKDOORED_BYTES != ARTIFACT_BYTES
BACKDOORED_DIGEST = "sha256:" + hashlib.sha256(BACKDOORED_BYTES).hexdigest()
BACKDOORED_RESOURCE = f"{PLUGIN}/version:2.9.0/artifact:{BACKDOORED_DIGEST}"
BACKDOORED_INTENT = Intent(AGENT, ACTION, BACKDOORED_RESOURCE, 25, SESSION)
# The re-aimed version: the approved artifact's exact bytes
# published as version 2.9.1 -- the first version number of
# the incident's backdoored sequence. Version is part of the
# bound identity, so this is a different intent from the
# approved 2.9.0 release even though the artifact bytes are
# byte-identical to the approved ones.
VERSION_RESOURCE = f"{PLUGIN}/version:2.9.1/artifact:{ARTIFACT_DIGEST}"
VERSION_INTENT = Intent(AGENT, ACTION, VERSION_RESOURCE, 25, SESSION)
# The different plugin: WP Sync for Notion, one of the six
# backdoored plugins in the incident, at its backdoored
# version. Its identity is genuinely distinct from the
# authorized plugin's: it shares no string prefix with it,
# which is what the step-3 scope claim is limited to (see
# the module-level note on prefix matching).
OTHER_PLUGIN_RESOURCE = (
    f"plugin:wp-sync-for-notion/version:1.7.4/artifact:{ARTIFACT_DIGEST}"
)
OTHER_PLUGIN_INTENT = Intent(AGENT, ACTION, OTHER_PLUGIN_RESOURCE, 25, SESSION)
# The authorized release identity with a suffix appended.
# This resource passes the grant's prefix check -- that is
# pinned, not hidden -- and must still be denied, by the
# exact-intent permit binding.
SUFFIXED_RESOURCE = f"{RELEASE_RESOURCE}/staging"
SUFFIXED_INTENT = Intent(AGENT, ACTION, SUFFIXED_RESOURCE, 25, SESSION)

ATTACK_INTENTS = (
    BACKDOORED_INTENT,
    VERSION_INTENT,
    OTHER_PLUGIN_INTENT,
    SUFFIXED_INTENT,
)

# The developer's WordPress.org account credential, presented
# as if it were a permit. Holding the account is evidence the
# caller can reach the publishing path; it is not an approval
# envelope and not a permit, and the kernel has no verb that
# derives publish authority from it. In the incident, this
# credential -- or whoever held it -- was the only authority
# artifact the distribution path ever saw.
ACCOUNT_CREDENTIAL = "wordpress.org:developer-account-credential"


class DistributionGate:
    """The governed distribution boundary, and what it actually released.

    A publish is presented to this boundary as three things:
    a permit, the intent the caller claims to be executing,
    and the ACTUAL artifact bytes about to be distributed.
    The boundary does not trust the caller's label for the
    artifact. It derives the SHA-256 digest of the bytes
    presented, at the boundary, and compares it against the
    digest bound in the presented intent. On a mismatch, the
    act actually being attempted is the publish of the
    derived artifact, so the boundary rebuilds the intent
    from the derived digest and submits THAT act to the
    kernel: a tampered artifact cannot ride the approved
    intent's label, and the genuine permit -- bound to the
    approved intent -- rejects the derived act at consume,
    where the rejection lands in the audit. On an exact match
    the presented intent is submitted as-is; plugin scope,
    version, and the remaining bindings are the kernel's to
    check, as they are on every route. The boundary holds no
    authority of its own: it cannot mint, approve, or spend
    except through ``kernel.consume``.

    A distribution (a governed external consequence) is
    recorded only when the kernel consumes a permit for the
    submitted intent, and the record names the submitted
    intent -- so this gate can never record the approved
    resource for bytes that were not the approved bytes. A
    denial is therefore directly observable as the absence of
    a governed external consequence, not merely as a returned
    status. (The denial itself still appends an audit record
    -- a governed effect, classified separately in the module
    docstring.)
    """

    def __init__(self) -> None:
        self.distributed: list[tuple[str, str]] = []

    @staticmethod
    def _bound_digest(resource: str) -> str | None:
        _, sep, bound = resource.partition("/artifact:")
        if not sep:
            return None
        return bound.split("/", 1)[0]

    def distribute(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        artifact: bytes,
    ) -> bool:
        if permit is None:
            return False
        bound = self._bound_digest(intent.resource)
        if bound is None:
            return False
        derived = "sha256:" + hashlib.sha256(artifact).hexdigest()
        submitted = intent
        if derived != bound:
            prefix = intent.resource.split("/artifact:", 1)[0]
            submitted = Intent(
                intent.principal,
                intent.action,
                f"{prefix}/artifact:{derived}",
                intent.cost,
                intent.session_id,
            )
        if not kernel.consume(permit, submitted):
            return False
        self.distributed.append((submitted.action, submitted.resource))
        return True


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent
    permit spends for any intent. It exists only to prove the
    scenario's denial assertions discriminate -- under this
    double the backdoored release must DISTRIBUTE, or the
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
    checks -- neither token authentication nor the
    token-to-intent binding -- and delegates straight to the
    state. Paired with the intent-blind state double above, no
    layer binds the permit to the presented intent, so the
    backdoored release must DISTRIBUTE here, or the scenario's
    denials would be coming from the harness rather than from
    the binding layers. This is the incident's own shape: a
    distribution path that publishes whatever the account
    presents, tampered or not, under whatever label it
    carries.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class WordPressPluginsIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        # The plugin scope: the publisher's grant names the
        # one authorized plugin identity as its sole resource
        # prefix. Matching is prefix-based (see the module
        # docstring); the claims in this scenario are worded
        # to exactly what that configuration proves.
        grant = AgentGrant(
            AGENT,
            frozenset({ACTION}),
            (PLUGIN,),
            10_000,
        )
        self.policy = Policy(
            frozenset({ACTION}),
            10_000,
            frozenset({ACTION}),
            agent_grants=(grant,),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.gate = DistributionGate()

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

    def _issue_release_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, RELEASE_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(RELEASE_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_release_distributes_exactly_once(self) -> None:
        permit = self._issue_release_permit(self.kernel)
        self.assertTrue(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)
        # The same permit cannot distribute the same release
        # twice -- a publish authorization is not a standing
        # publishing credential.
        self.assertFalse(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the unapproved publish has no permit ----------------------

    def test_step1_unapproved_publish_denied_account_credential_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for this publish, and holding the developer's
        # account is not one.
        decision = self.kernel.evaluate(BACKDOORED_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.gate.distribute(
                self.kernel, decision.permit, BACKDOORED_INTENT, BACKDOORED_BYTES
            )
        )
        # The caller presents its account credential itself as
        # its permit -- the incident's exact shape, in which
        # the account was the only authority artifact on the
        # path. The kernel treats it as what it is: a
        # fabricated token. Possession of the account existed
        # in the incident; authority for this publish did not.
        self.assertFalse(
            self.gate.distribute(
                self.kernel, ACCOUNT_CREDENTIAL, BACKDOORED_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertEqual([], self.gate.distributed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(BACKDOORED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the backdoored artifact under the genuine permit ---------------

    def test_step2_backdoored_artifact_with_genuine_permit_denied(self) -> None:
        permit = self._issue_release_permit(self.kernel)
        # The incident's core act, in its real shape: the
        # publisher presents the APPROVED intent and the
        # GENUINE permit at the distribution gate, but the
        # artifact bytes it is about to distribute are the
        # backdoored ones -- the added module file and its
        # require_once line, the incident's own additions.
        # Nothing about the presented label changed; only the
        # bytes did. The gate derives the digest of the bytes
        # actually presented, so the act submitted is the
        # backdoored publish itself, and the one permit the
        # publisher holds -- bound to the approved artifact's
        # intent -- rejects it. The substitution fails at
        # distribution time, before any site sees it -- the
        # same point in the path where the real release hold
        # stopped it.
        self.assertNotEqual(ARTIFACT_BYTES, BACKDOORED_BYTES)
        self.assertFalse(
            self.gate.distribute(
                self.kernel, permit, RELEASE_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertEqual([], self.gate.distributed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        # The rejection is bound to the hash of the intent the
        # backdoored bytes actually constitute -- derived at
        # the gate from the bytes -- not to the approved
        # intent's hash.
        self.assertEqual(
            self.kernel.intent_hash(BACKDOORED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was binding, not lockout: the permit still
        # spends on the exact release it was issued for, when
        # the bytes presented are the bytes that were approved.
        self.assertTrue(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the re-aimed version, the different plugin, and scope -----------

    def test_step3_version_and_other_plugin_denied_and_suffixed_denied_at_binding(self) -> None:
        permit = self._issue_release_permit(self.kernel)
        # (a) The re-aimed version: the approved artifact's
        # exact bytes published as 2.9.1. The bare evaluate
        # reaches require_approval -- plugin and action are in
        # scope -- but version is part of the bound identity,
        # so the genuine permit rejects it at consume. A permit
        # for the 2.9.0 release is not a permit for the next
        # version number, even with identical bytes.
        decision = self.kernel.evaluate(VERSION_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertFalse(
            self.gate.distribute(self.kernel, permit, VERSION_INTENT, ARTIFACT_BYTES)
        )
        # (b) The different plugin: WP Sync for Notion is
        # outside the grant's plugin scope, so the kernel
        # denies its bare evaluate outright -- it does not even
        # reach require_approval. One denied decision record;
        # no permit exists to spend, and the genuine permit
        # rejects it at consume as well.
        decision = self.kernel.evaluate(OTHER_PLUGIN_INTENT)
        self.assertEqual(
            ("deny", "agent_resource_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.gate.distribute(
                self.kernel, decision.permit, OTHER_PLUGIN_INTENT, ARTIFACT_BYTES
            )
        )
        self.assertFalse(
            self.gate.distribute(
                self.kernel, permit, OTHER_PLUGIN_INTENT, ARTIFACT_BYTES
            )
        )
        # (c) The suffixed resource: the authorized release
        # identity with a suffix appended. Pinned exactly as
        # it holds: this resource PASSES the grant layer,
        # because grant matching is prefix-based -- its bare
        # evaluate reaches require_approval rather than the
        # scope denial above -- and it is still denied, at
        # consume, by the exact-intent permit binding. The
        # scenario claims the other plugin's scope denial for
        # genuinely distinct plugin identities only; for
        # prefix-sharing resources the binding layer, not the
        # grant layer, is what stops the publish at this
        # commit.
        decision = self.kernel.evaluate(SUFFIXED_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertFalse(
            self.gate.distribute(self.kernel, permit, SUFFIXED_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([], self.gate.distributed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(3, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(VERSION_INTENT),
                self.kernel.intent_hash(OTHER_PLUGIN_INTENT),
                self.kernel.intent_hash(SUFFIXED_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        denied = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "deny"
        ]
        self.assertEqual(1, len(denied))
        self.assertEqual("agent_resource_not_allowed", denied[0]["reason"])
        # The denials did not burn the permit: the exact
        # approved release still spends.
        self.assertTrue(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing ------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_release_permit(self.kernel)
        self.assertTrue(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        # A consumed permit is not a reusable publishing
        # credential: re-presenting it for the same release
        # gets nothing, and re-presenting it with the
        # backdoored artifact's bytes -- the approved label
        # over tampered bytes, which the gate derives into the
        # backdoored intent -- gets nothing either.
        self.assertFalse(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertFalse(
            self.gate.distribute(
                self.kernel, permit, RELEASE_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ------------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, RELEASE_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the release signed with an
        # unauthorized key: whoever holds the publishing
        # account cannot mint the approver's authority.
        forged_envelope = signed_envelope(
            self.kernel, RELEASE_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(RELEASE_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine envelope presented for the backdoored
        # artifact's intent: a real approval for one artifact
        # is not approval for another.
        decision = self.kernel.evaluate_with_approval(BACKDOORED_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.gate.distributed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_signature_invalid", "approval_intent_mismatch"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine pair
        # still admits.
        decision = self.kernel.evaluate_with_approval(RELEASE_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign -----------------------
    #
    # Surfacing, asserted exactly as it holds at this commit:
    # every consume rejection, every approval rejection, and
    # every denied decision in the sequence becomes a near-miss
    # record in the derived incident report. The bare
    # require_approval decisions are in the canonical audit (and
    # counted below) but are NOT derived as near-misses -- the
    # expected near-miss count is built from the event classes
    # the channel actually derives, so this test pins the
    # boundary instead of papering over it.
    #
    # The frozen sequence below is the full attempt sequence of
    # steps 1-5 and 7, not a subset: every attack intent on
    # every route (steps 1-3, including the scope-denied bare
    # evaluate for the different plugin), the governed-gate
    # route of step 2 (the approved intent and genuine permit
    # presented with the backdoored artifact bytes), the
    # spent-permit replays (step 4, replayed after the one
    # legitimate distribution below), and both approval-envelope
    # attempts (step 5). The report assertions therefore cover
    # every denial route the scenario exercises, including the
    # bare-evaluate route on both of its shapes:
    # require_approval (audit-only, zero near-misses) and the
    # policy denial agent_resource_not_allowed (a denied
    # decision, derived as a near-miss).

    def test_step6_incident_channel_surfaces_the_publishing_campaign(self) -> None:
        permit = self._issue_release_permit(self.kernel)
        # The campaign, compressed: each attack intent
        # attempted on every route the caller has -- its own
        # say-so (bare evaluate), its account credential as a
        # token, and the one genuine permit.
        for intent in ATTACK_INTENTS:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(ACCOUNT_CREDENTIAL, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        # Each envelope in this compressed sequence carries its
        # own approval_id and nonce, as each real approval
        # would: the helper's fixed defaults would collide with
        # the permit issuance above and turn the forgery denial
        # below into a replay denial, misattributing the
        # control that rejected it.
        forged_envelope = signed_envelope(
            self.kernel,
            RELEASE_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(RELEASE_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the genuine
        # release envelope presented for the backdoored
        # artifact's intent. A real approval for one artifact
        # is not approval for another; the decision is a denial
        # and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            RELEASE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(BACKDOORED_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # Step 2's route, also replayed into the frozen
        # sequence: the approved intent and the genuine permit
        # presented at the governed distribution gate with the
        # backdoored artifact bytes. The gate derives the
        # backdoored intent from the bytes actually presented,
        # and the genuine permit rejects that act at consume --
        # one further permit_rejected record, derived as a
        # near-miss like every other consume rejection in the
        # sequence.
        self.assertFalse(
            self.gate.distribute(
                self.kernel, permit, RELEASE_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertEqual([], self.gate.distributed)
        # The one legitimate release still distributes; the
        # campaign did not.
        self.assertTrue(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for the
        # same release and for the backdoored artifact. A
        # consumed permit is not a reusable publishing
        # credential; both re-presentations are rejected at
        # consume.
        self.assertFalse(self.kernel.consume(permit, RELEASE_INTENT))
        self.assertFalse(self.kernel.consume(permit, BACKDOORED_INTENT))
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)

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
        self.assertEqual(11, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(3, len(denied_decisions))
        self.assertEqual(3, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. The
        # three require_approval decisions above are
        # audit-recorded attempts that contribute zero near-miss
        # records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(16, report.near_misses)
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

    # -- step 7: reconciliation ------------------------------------------------
    #
    # The incident's evidentiary shape, stated plainly: after
    # the fact, the question a distribution platform must
    # answer is which artifacts were actually authorized and
    # which were merely submitted. This step derives that
    # answer from the canonical audit alone -- the set of
    # intent hashes that appear in ``permit_consumed`` records
    # (what was permitted and spent) against the set that
    # appear in ``permit_rejected`` records (what was
    # submitted and refused) -- and pins the reconciliation:
    # the tampered artifact's intent appears only in
    # rejections, never in a consumption; the one consumption
    # is the one approved release; and every submitted act in
    # the sequence is accounted for by one set or the other,
    # with no act in both.

    def test_step7_reconciliation_permitted_vs_submitted(self) -> None:
        permit = self._issue_release_permit(self.kernel)
        # The submitted side of the ledger: the backdoored
        # artifact under the genuine permit (the gate derives
        # its intent from its bytes), the backdoored artifact
        # under the account credential, and the re-aimed
        # version under the genuine permit. All refused.
        self.assertFalse(
            self.gate.distribute(
                self.kernel, permit, RELEASE_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertFalse(
            self.gate.distribute(
                self.kernel, ACCOUNT_CREDENTIAL, BACKDOORED_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertFalse(
            self.gate.distribute(self.kernel, permit, VERSION_INTENT, ARTIFACT_BYTES)
        )
        # The permitted side: exactly one distribution, the
        # approved release.
        self.assertTrue(
            self.gate.distribute(self.kernel, permit, RELEASE_INTENT, ARTIFACT_BYTES)
        )
        self.assertEqual([(ACTION, RELEASE_RESOURCE)], self.gate.distributed)

        consumed_hashes = [
            record["payload"]["intent_hash"]
            for record in _events(self.kernel, "permit_consumed")
        ]
        rejected_hashes = [
            record["payload"]["intent_hash"]
            for record in _events(self.kernel, "permit_rejected")
        ]
        release_hash = self.kernel.intent_hash(RELEASE_INTENT)
        backdoored_hash = self.kernel.intent_hash(BACKDOORED_INTENT)
        version_hash = self.kernel.intent_hash(VERSION_INTENT)
        # What was permitted and spent: the approved release,
        # exactly once.
        self.assertEqual([release_hash], consumed_hashes)
        # What was submitted and refused: the backdoored
        # artifact on both of its routes, and the re-aimed
        # version -- and nothing else.
        self.assertEqual(3, len(rejected_hashes))
        self.assertEqual({backdoored_hash, version_hash}, set(rejected_hashes))
        self.assertEqual(2, rejected_hashes.count(backdoored_hash))
        # The reconciliation itself: the tampered artifact's
        # digest-derived intent appears only in rejections,
        # never in a consumption, and the permitted and
        # submitted sets are disjoint and jointly complete --
        # every act the audit records as presented at consume
        # is accounted for as either the one permitted release
        # or a refusal.
        self.assertNotIn(backdoored_hash, consumed_hashes)
        self.assertTrue(set(consumed_hashes).isdisjoint(rejected_hashes))
        self.assertEqual(
            {release_hash, backdoored_hash, version_hash},
            set(consumed_hashes) | set(rejected_hashes),
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control -------------------------------------------------------

    def test_negative_control_unguarded_consume_would_distribute(self) -> None:
        # The identical presentation as step 2 -- the approved
        # intent, the genuine permit, and the backdoored bytes
        # at the same governed gate -- but with consume
        # unguarded at BOTH layers: a kernel double whose
        # consume skips token authentication and the kernel's
        # token-to-intent binding, over a state double whose
        # consume ignores the store's binding. The gate still
        # derives the backdoored intent from the bytes; no
        # layer binds the permit to that intent, so the
        # backdoored release DISTRIBUTES under the genuine
        # permit. That is the incident's own shape -- a
        # distribution path that publishes whatever the account
        # presents, tampered or not. Step 2's denial therefore
        # comes from the real consume path's binding, not from
        # the gate's derivation or a harness that denies by
        # construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_release_permit(blind_kernel)
        self.assertTrue(
            self.gate.distribute(
                blind_kernel, permit, RELEASE_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertEqual(
            [(ACTION, BACKDOORED_INTENT.resource)], self.gate.distributed
        )
        # Contrast, the identical presentation against the real
        # backend: denied (step 2's route).
        real_permit = self._issue_release_permit(self.kernel)
        real_gate = DistributionGate()
        self.assertFalse(
            real_gate.distribute(
                self.kernel, real_permit, RELEASE_INTENT, BACKDOORED_BYTES
            )
        )
        self.assertEqual([], real_gate.distributed)


if __name__ == "__main__":
    unittest.main()
