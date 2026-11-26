"""Scenario test: the web3-mev-error-decoder npm
supply-chain attack (GHSA-hvqj-jrfw-r9mh, published
2026-11-25; package published 2026-11-09).

Incident (Recorded, from the Endor Labs write-up of the
incident, converged with the GitHub advisory
GHSA-hvqj-jrfw-r9mh / MAL-2026-20610): the npm package
``web3-mev-error-decoder@0.1.0`` was published on
2026-11-09. Its own tarball was clean -- it contained
no install hook and no malicious code (Verified in the
Endor Labs review of a copy of the tarball whose hashes
match the pre-takedown registry metadata; tarball
SHA-256
``05d193d87e03221b68cac57c7048c45c82cb55a43e9c56f600ca973add67c8ed``).
Its only consequential content was one dependency
declaration:

    "multicall-error-decoder":
        "github:outgoingyang/multicall-error-decoder"

A ``github:`` specifier tells npm to fetch a GitHub
repository instead of a registry tarball, and the
fetched repository's ``package.json`` carried an
install hook, ``node dist/error-decoder/handlers.js``.
Kitsunox recorded that repository at commit
``240aa9b685e2`` (2026-11-12): the hook was a downloader
that decrypted its strings with AES at runtime
(``crypto.createDecipheriv('aes-256-cbc', ...)``), then
branched by platform -- on Windows it downloaded an
archive and launched the executable inside it
(detached, so it outlived the install process); on
macOS it piped a remote script into the shell. Linux
behavior is not described in the sources.

The misdirection: two days earlier, on 2026-11-07, the
attacker had published a clean package named
``multicall-error-decoder@0.1.0`` to the npm registry
(tarball SHA-256
``62405e794b8cb35d52589f783ffda8eb758e04263ab5aa6eef803a8a348457d9``)
-- real, working, hook-free code under exactly the
dependency's name. Anyone checking the dependency by
name, and any scanner that only inspects registry
tarballs, found a legitimate library. The harmful code
never appeared on npm at all. Kitsunox, the scanner
that recorded the sample, at first raised a single
MEDIUM finding on the non-registry specifier; its
deeper stages read the release tarball and never saw
the dependency's code.

GitHub published GHSA-hvqj-jrfw-r9mh on 2026-11-25 at
16:13 UTC and npm replaced the package with a security
holder one minute later: an exposure window of about
16 days. The GitHub account, repository, and commit
have since been deleted (all return 404), so the
second-stage payload the hook downloaded was never
recovered or analyzed -- its behavior is **Unknown**.
No victims are confirmed in the sources. The headline
download figures are not a victim count: the npm
downloads API as reported shows 9,735,029 downloads on
a single day (2026-11-11) against roughly 60 to 4,089
on other days, which the Endor Labs write-up reads as
count inflation, with mirrors and scanners further
inflating even the smaller figures; deps.dev reports
no registry dependents, so exposure came from direct
installs.

The failure class (Class 1, supply-chain /
trusted-path execution): code executed at install time
because the package channel was trusted. The package
declaration alone -- a name in a manifest -- was
treated as sufficient authority to fetch code from a
different source entirely and run it, on the
installing machine, with that machine's credentials.
No named accountable human authorized that execution,
and no authorization was bound to the artifact that
actually ran: the artifact reviewed (the registry
decoy, or the clean top-level tarball) was not the
artifact executed (the GitHub copy at the same name).

This module models that failure mode against the
canonical kernel API. It does NOT reproduce npm, any
package, the install hook, or the payload. The mapping
(Inferred, stated here so it can be argued with): the
consequential act is executing install-time code
fetched for a package install. That act requires a
permit bound to the artifact's identity -- name,
version, source, and hash, all carried in the intent's
resource string, so the kernel's exact-intent hash
binds the identity as stated. For the reviewed
registry artifact that identity is exact and complete:
its hash is a real SHA-256, and the hash limb of the
binding is proven against the registry artifacts
(the hash-substitution step below, where both hashes
are real). The GitHub payload's recorded identity is
narrower, and this module does not pretend otherwise:
it carries the package name, the ``github:`` source,
and the abbreviated commit ``240aa9b685e2`` Kitsunox
observed on 2026-11-12, and its content hash is
**Unknown** -- never recovered, because the
repository was deleted. An approval for the reviewed
registry artifact (the decoy identity) therefore
cannot authorize execution of the GitHub artifact at
the same name: the ``github:`` redirect changes the
source, and a hash substitution changes the hash, and
either change makes a different intent whose approval
does not exist. The Git-redirect step proves the
source limb only; it proves nothing about a hash for
the Git payload, and the recorded commit does not
cover other revisions the dependency's
default-branch resolution may have fetched during
the exposure window. The
only route from an install request to a consequence is
a successful ``GovernanceKernel.consume`` of a permit
issued through a verified approval envelope for that
exact artifact.

Setup: exactly one act is legitimate in this scenario
-- executing the install hook of one exact, reviewed,
approved artifact, once, under a permit issued through
a verified approval envelope: the accountable
per-action authorization actually granted. The
incident's routes are then attempted: install-time
execution with no approval at all; the genuine
approval for the registry artifact presented for the
GitHub artifact (the ``github:`` redirect -- the
source-limb test); the
same-name decoy in its second form, an approval for
the reviewed artifact presented for an artifact at the
same name, version, and source but with a substituted
hash; and an approval for the GitHub artifact signed
with an unauthorized (attacker) key. The kernel must
deny each one, the consequence ledger must stay empty
for all of them, and every denial must land in the
audit record. A genuine, well-formed approval for the
exact artifact verifies and authorizes exactly one
execution, and then spends.

Multiplicity discipline: reconciliation in this
scenario is per-item counted (``Counter`` / multiset),
never set-based. A dedicated probe presents the same
artifact twice: a spent permit re-presented does not
execute twice, and a claimed-installs list that counts
the same consumed artifact twice reconciles as a
phantom duplicate of count exactly 1, not as a match.

Incident-channel surfacing (Verified at this commit,
by executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A
bare ``evaluate`` that returns ``require_approval`` --
the kernel declining to mint without approval --
appends a decision record to the canonical audit but
is NOT derived as a near-miss by the channel. The
scenario asserts both halves of that statement exactly
as they hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable evidence).
It proves nothing about npm, any registry, scanner, or
installer that does not route install-time execution
through this kernel -- an installer that runs hooks on
the strength of a manifest declaration is governed by
nothing here. Stage-2 behavior is Unknown (never
recovered) and is not modeled. A control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is
recorded in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed
kernel path only -- exactly one governed external
consequence is permitted per correctly verified
approval bound to the exact artifact, and any
install path that executes fetched code on a package
declaration alone (the incident's own class) remains
outside this evidence and open.

Audit-growth classification (per AGENTS.md,
``NO_PERMIT != NO_GOVERNED_EFFECT``): a denied attempt
is not "no state changed." A denied attempt appends
audit records, counted per route: a bare evaluate
returning ``require_approval`` appends one decision
record; a ``consume`` rejection appends one
``permit_rejected`` record; a denied approval-envelope
evaluation appends two records -- an
``approval_rejected`` record and a denied decision
record. That growth is itself a governed effect --
evidence production -- bounded at two records per
attempt, append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability.
It is classified and assessed separately from governed
external consequences throughout this module:
"consequence" below means governed external
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
# The installing machine's executor: the dispatch
# boundary the incident's install hook fed into. Every
# intent below is an act this executor would perform;
# a package manifest proposes, the executor must not
# run anything without a permit bound to the exact
# artifact.
INSTALLER = "agent:npm-installer"
# The install session of the malicious package's
# publication day, 2026-11-09, in the harness's naming.
# Session identity is part of the bound intent; it is
# not itself authority for anything.
SESSION = "install-session-2026-11-09"

ACTION = "execute_install_hook"

# The artifact identities. The registry identities
# carry name, version, source, and hash -- the four
# fields the incident proved a name alone cannot
# stand in for -- with real SHA-256 hashes. The
# GitHub payload's identity carries name, source, and
# the abbreviated commit recorded on 2026-11-12; its
# content hash is Unknown (see its definition below),
# so no hash claim is made for it anywhere in this
# module.
DECOY_HASH = "62405e794b8cb35d52589f783ffda8eb758e04263ab5aa6eef803a8a348457d9"
WEB3_HASH = "05d193d87e03221b68cac57c7048c45c82cb55a43e9c56f600ca973add67c8ed"

# The reviewed registry artifact: the clean decoy
# identity. This is the one artifact a named accountable
# human has reviewed and approved for install-time
# execution in this scenario.
APPROVED_ARTIFACT = (
    f"npm:multicall-error-decoder@0.1.0:registry:sha256:{DECOY_HASH}"
)
# The payload carrier: same package name, fetched from
# a GitHub repository instead of the registry, at the
# abbreviated commit Kitsunox recorded on 2026-11-12.
# Its content hash was never recovered (the repository
# is deleted), which is itself part of the point:
# nothing about it was ever reviewed. The identity is
# therefore name + source + recorded commit only --
# the ``sha256:unknown`` field states that the hash is
# Unknown; it is not a digest -- and it does not cover
# other revisions the default-branch resolution may
# have fetched during the exposure window.
GIT_ARTIFACT = (
    "github:outgoingyang/multicall-error-decoder"
    "@240aa9b685e2:git:sha256:unknown"
)
# The same name, version, and source as the approved
# artifact, with the hash of a different tarball
# substituted (the web3-mev-error-decoder tarball's
# hash): a same-name artifact that is not the reviewed
# artifact.
HASH_SUBSTITUTED_ARTIFACT = (
    f"npm:multicall-error-decoder@0.1.0:registry:sha256:{WEB3_HASH}"
)

APPROVED_INTENT = Intent(INSTALLER, ACTION, APPROVED_ARTIFACT, 25, SESSION)
GIT_INTENT = Intent(INSTALLER, ACTION, GIT_ARTIFACT, 25, SESSION)
HASH_SUBSTITUTED_INTENT = Intent(
    INSTALLER, ACTION, HASH_SUBSTITUTED_ARTIFACT, 25, SESSION
)


def reconcile_installs(kernel: GovernanceKernel, claimed_hashes: list[str]) -> dict:
    """Per-item (multiset) reconciliation of claimed installs.

    ``claimed_hashes`` is a list of intent hashes, one
    entry per claimed install occurrence. Consumed
    occurrences are counted from the kernel audit with
    a ``Counter`` -- never a set -- so a duplicate claim
    for the same artifact is a phantom of count exactly
    (claimed - consumed), and an omitted occurrence is
    unreported by its exact count. A set-based check
    would collapse both duplicates and pass them.
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


class InstallExecutor:
    """Install-time execution, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the incident's installer did not
    have: in the incident, the manifest declaration WAS
    the execution path, and the hook followed
    immediately. Here the harness records an effect
    only when the kernel consumes a permit for the
    exact intent. A denial is therefore directly
    observable as the absence of a governed external
    consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a
    governed effect, classified separately in the
    module docstring.)
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


class NameOnlyInstaller:
    """The incident's ungoverned baseline, as a test-local double.

    Authorizes install-time execution by package NAME
    alone -- the registry-only view the decoy was built
    to defeat. Source and hash are never consulted, so
    the GitHub artifact at the decoy's name executes
    exactly as the decoy would. Test-local; never
    imported by runtime code.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def install(self, package_name: str, intent: Intent) -> bool:
        if package_name != "multicall-error-decoder":
            return False
        self.effects.append((intent.action, intent.resource))
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class Web3MevErrorDecoderIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = InstallExecutor()

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
        # The one legitimate act: install-time execution
        # of the exact reviewed artifact under a genuine,
        # well-formed, verified approval executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_ARTIFACT)], self.executor.effects)
        # The same permit cannot run it twice -- a
        # verified approval is not a standing install
        # permission.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_ARTIFACT)], self.executor.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all ----------------------------------------

    def test_step1_no_approval_at_all_denied(self) -> None:
        # The incident's baseline route: a manifest
        # declares the dependency and the hook runs. On
        # the governed path a declaration is not an
        # approval: the kernel declines to mint, and
        # nothing executes.
        decision = self.kernel.evaluate(GIT_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, GIT_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the github: redirect ---------------------------------------
    #
    # The genuine approval for the reviewed registry
    # artifact, presented for the GitHub artifact at the
    # same name. The redirect changes the source (and
    # the content) while keeping the name the reviewer
    # saw; the exact-intent binding compares the whole
    # artifact identity, so the approval does not travel.
    # This is the source-limb test: the Git identity's
    # hash field is Unknown, not a digest, so this step
    # proves nothing about a hash for the Git payload --
    # the hash limb is proven only by step 3, where both
    # registry hashes are real SHA-256s.

    def test_step2_github_redirect_fails_the_binding(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, APPROVED_INTENT, self.verifier, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(GIT_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, GIT_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        # The denial did not poison the path: the genuine
        # pair still admits.
        decision = self.kernel.evaluate_with_approval(APPROVED_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the same-name decoy, hash form ------------------------------
    #
    # Same name, same version, same source as the
    # approved artifact -- only the hash differs. A
    # name-based (or name+version-based) check passes
    # this; the exact binding does not, because the
    # artifact presented is not the artifact reviewed.

    def test_step3_same_name_hash_substitution_fails_the_binding(self) -> None:
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
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: forged approval for the payload artifact --------------------

    def test_step4_forged_approval_for_git_artifact_denied(self) -> None:
        # An envelope for the GitHub artifact signed with
        # an unauthorized key: whoever controls the
        # package cannot mint the installer's authority.
        forged_envelope = signed_envelope(
            self.kernel, GIT_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(GIT_INTENT, forged_envelope)
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
        self.assertTrue(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        # The same artifact presented a second time under
        # the same (spent) permit: no second execution,
        # no second consumption.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_ARTIFACT)], self.executor.effects)
        approved_hash = self.kernel.intent_hash(APPROVED_INTENT)
        # An exact per-item claim reconciles.
        exact = reconcile_installs(self.kernel, [approved_hash])
        self.assertTrue(exact["ok"])
        self.assertEqual({}, exact["phantom_counts"])
        self.assertEqual({}, exact["unreported_counts"])
        self.assertEqual({approved_hash: 1}, exact["consumed_counts"])
        # The duplicate probe: the same artifact claimed
        # twice is a phantom of count exactly 1 under
        # multiset reconciliation. A set-based check
        # would collapse the duplicate and report a
        # match -- the double-count this probe exists to
        # catch.
        duplicated = reconcile_installs(self.kernel, [approved_hash, approved_hash])
        self.assertFalse(duplicated["ok"])
        self.assertEqual({approved_hash: 1}, duplicated["phantom_counts"])
        self.assertEqual({}, duplicated["unreported_counts"])
        # And an empty claim under-reports by exactly 1.
        omitted = reconcile_installs(self.kernel, [])
        self.assertFalse(omitted["ok"])
        self.assertEqual({approved_hash: 1}, omitted["unreported_counts"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would.
        self.kernel.evaluate(GIT_INTENT)
        redirect_envelope = signed_envelope(
            self.kernel,
            APPROVED_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-redirect",
            nonce="nonce-seq-redirect",
        )
        decision = self.kernel.evaluate_with_approval(GIT_INTENT, redirect_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        forged_envelope = signed_envelope(
            self.kernel,
            GIT_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-seq-forged",
            nonce="nonce-seq-forged",
        )
        decision = self.kernel.evaluate_with_approval(GIT_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # The payload artifact's name presented as a
        # permit at the dispatch boundary: a name is not
        # a permit either, and consume rejects it.
        self.assertFalse(
            self.executor.execute(self.kernel, "multicall-error-decoder", GIT_INTENT)
        )
        # The one legitimate execution still lands; the
        # attack routes did not.
        permit = self._issue_permit(
            self.kernel,
            APPROVED_INTENT,
            approval_id="approval-seq-run",
            nonce="nonce-seq-run",
        )
        self.assertTrue(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_ARTIFACT)], self.executor.effects)
        # The spent permit re-presented: single-use.
        self.assertFalse(self.executor.execute(self.kernel, permit, APPROVED_INTENT))
        self.assertEqual([(ACTION, APPROVED_ARTIFACT)], self.executor.effects)

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

    def test_negative_control_name_only_installer_would_execute(self) -> None:
        # Same scenario, the governed boundary swapped
        # for the incident's own rule: authorize by
        # package name alone, as a registry-only scan
        # effectively does. The GitHub payload artifact
        # carries the decoy's name, so it EXECUTES --
        # and so does the hash-substituted artifact.
        # That is the incident, reproduced at the exact
        # layer it happened: not the network, not the
        # hook -- the authorization check that consulted
        # a name instead of the artifact. The denials in
        # the steps above therefore come from the exact
        # binding over the stated identity -- the source
        # limb for the GitHub route, the hash limb for
        # the registry substitution -- not from a harness
        # that denies by construction.
        blind = NameOnlyInstaller()
        self.assertTrue(blind.install("multicall-error-decoder", GIT_INTENT))
        self.assertTrue(blind.install("multicall-error-decoder", HASH_SUBSTITUTED_INTENT))
        self.assertEqual(
            [(ACTION, GIT_ARTIFACT), (ACTION, HASH_SUBSTITUTED_ARTIFACT)],
            blind.effects,
        )
        # The name-only rule is not indiscriminate --
        # an unrelated name does not pass it. Its defect
        # is precision, exactly the decoy's design
        # target: it cannot tell the reviewed artifact
        # from any other artifact at the same name.
        self.assertFalse(blind.install("some-other-package", GIT_INTENT))
        # Contrast, the identical GitHub route against
        # the governed kernel: denied (step 2's route).
        genuine_envelope = signed_envelope(
            self.kernel, APPROVED_INTENT, self.verifier, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(GIT_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)


if __name__ == "__main__":
    unittest.main()
