"""Scenario test: the Railway October 2026 incident --
a build-server credential accepted as a trusted
Temporal client, an erroneously defined OIDC trust
binding, and the decryption of customer environment
variables (Railway's full incident report published
2026-11-10; incident 2026-10-20/21).

Incident (Recorded, from Railway's own incident
report, "Incident Report: October 21st Security
Attack," published 2026-11-10): Railway's build
infrastructure ran multiple customer builds on the
same virtual machine. At 07:28 UTC on 2026-10-20 the
attacker exploited a previously unknown vulnerability
to partially escape filesystem isolation and read
files on the host, obtaining a credential the build
servers use to authenticate to a subset of internal
systems, including pushing images after a build
completes. Railway's report states the credential
"was intended to authorize only work needed to
complete builds, such as registry pushes, and nothing
else. However, our internal Temporal instance used
for builds accepted it as a trusted client." Through
Temporal APIs the attacker read stored histories of
other builds -- 353 build histories between 13:50 and
15:30 UTC on 2026-10-20, sealed variables included;
the histories also carried build variables, metadata,
and a read-only GitHub app token scoped to a single
repository. Because the same credential could fetch
snapshots of the repository state of builds, the
attacker retrieved a copy of Railway's internal
monorepo from a recent build of an internal service.
An alert on anomalous calls to a registry service
paged the on-call engineer at 13:58 UTC; that evening,
at 17:28 UTC on 2026-10-20, Railway revoked and
replaced the build credential, and the attacker's
later attempts to escalate out of build isolation
failed. But the copied codebase outlived the revoked
credential: scanning it, the attacker found an
erroneously defined OIDC binding configuration in one
of Railway's cloud environments, and at 03:26 UTC on
2026-10-21 obtained one of the CI/CD system's
short-lived cloud credentials through it. With that
credential the attacker retrieved internal credentials
from the cloud environment -- among them an SSH
private key used by the CD system and a longer-lived
credential -- connected by SSH to an orchestration
machine, and found on its disk a longer-lived
credential that allowed decryption of encrypted
variables. Between 04:07 and 05:21 UTC the attacker
retrieved encrypted variable envelopes from the
production database, prioritizing AI provider keys;
between 04:42 and 07:15 UTC they used the longer-lived
credential against the key management service to
decrypt some of them. At 07:14 UTC on 2026-10-21
Railway disabled all active cloud credentials and the
decryption service; the attacker was fully evicted by
09:24 UTC. Railway's forensics bound the impact at:
at most 1.85% of workspaces, about 100,000, could have
had any environment variables decrypted (an upper
bound -- the logs identify environments, not
individual variables); the 353 build histories above;
linked-account tokens (BYOK agent keys and GitHub
OAuth tokens) for 1,852 users in the decrypted data,
all reset; and unauthorized spend on the stolen keys
estimated by Railway to reach ~$740,000 (the report
states the estimate; the estimation method is not
stated in it). The report records no indication that
customer databases were accessed or customer
repositories downloaded.

The failure is an authorization failure with a single
shape repeated at every hop: a system asked "is this
a credential we recognize, arriving on a channel we
trust?" and never "was this exact act authorized, at
this moment, by the accountable authority?" The build
credential's scope existed only in the intent of its
designers; the receiving systems supplied their own --
Temporal read "build credential" as "trusted client,"
the OIDC binding read "workload identity" as "issue a
production cloud credential," and the orchestration
machine's disk read "this credential exists" as "this
bearer may decrypt customer variables." Possession
was treated as authorization, three times, and each
hop's output became the next hop's input.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Railway,
Temporal, OIDC, SSH, or any credential system. The
mapping (Inferred, stated here so it can be argued
with): the consequential acts are the ones the
incident's hops performed -- reading stored build
histories, fetching a repository snapshot, and
decrypting customer variables -- plus the one act the
stolen credential was actually for, pushing a built
image to the registry. Each act requires a permit
bound to its exact intent hash: principal, action,
resource, cost, session. The stolen build credential
is modeled in its three governed counterparts: as a
genuine approval envelope for the push intent (real
authority, for that intent only), as the raw
credential string presented at the dispatch boundary
(possession, offered as if it were a permit), and --
in the negative control -- as the only thing a
trusting verifier checks. The erroneously defined
OIDC binding is modeled as approval envelopes minted
under trust configurations that are not the enrolled
trust: one asserting the binding's own deployment,
one carrying the hash of a trust defined with a far
wider approval window. Revocation is modeled as the
end of the approval's validity window: Railway
revoked the build credential at 17:28 UTC, and on the
governed path an approval artifact past its window is
refused even for its own act -- a revoked credential
authorizes nothing, and nothing derived from
presenting it can be spent afterward either, because
permits are single-use and bound to one intent.

Setup: exactly one act is legitimate in this scenario
-- a registry push, once, under a permit issued
through a verified approval envelope: the accountable
per-action authorization actually granted. The
incident's chain is then attempted hop by hop: with
no approval at all, with the raw credential as a
permit, with the genuine push approval stretched to
the history read, to the snapshot fetch, and to the
decryption, with approvals minted under the erroneous
binding, and with the push approval re-presented
after its window has ended. The kernel must deny each
one, the consequence ledger must show only the one
legitimate push, and every denial must land in the
audit record. A genuine, well-formed approval
verifies and authorizes exactly one execution, and
then spends.

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

Reconciliation discipline (the multiplicity pass,
2026-11-25): every reconciliation in this module is
per-item counted -- multisets (``Counter``), never
sets. Step 6 presents the identical mismatched
envelope twice and the identical raw credential twice
on purpose: a set-based reconciliation would collapse
each duplicate pair to one and under-report the
attempt volume by exactly the duplicates; the counted
reconciliation must report each occurrence, and the
audit, the derived near-miss records, and the
executor's attempt/effect ledgers must agree as
multisets.

Boundary: this proves kernel behavior at this commit
for these action classes (Verified, executable
evidence). It proves nothing about any deployed build
platform, workflow cluster, federation binding, or key
service that does not route its authorization through
this kernel -- a system that accepts a recognized
credential as authorization for whatever it is
presented for is governed by nothing here. The replay
models the authorization step each of the incident's
systems skipped, not Railway's or Temporal's
internals. It also does not model the copying of
knowledge: the monorepo the attacker carried past the
revocation was information, and no authorization
kernel revokes what an attacker has already read; the
governed claim is only that the copied material would
have bought no governed consequence, because every
later act still needs its own verified approval. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
system that treats a recognized credential or a trust
binding as authorization for an unapproved act (the
incident's own class) remains outside this evidence
and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed." A denied attempt appends audit records,
counted per route: a bare evaluate returning
``require_approval`` appends one decision record; a
``consume`` rejection appends one ``permit_rejected``
record; a denied approval-envelope evaluation appends
two records -- an ``approval_rejected`` record and a
denied decision record. That growth is itself a
governed effect -- evidence production -- bounded at
two records per attempt, append-only, and it does not
alter authority (``authority_effect=none``) or
accumulate capability. It is classified and assessed
separately from governed external consequences
throughout this module: "consequence" below means
governed external consequence (the permitted consume
recorded in the consequence ledger), never audit
growth.
"""

from __future__ import annotations

import unittest
from collections import Counter
from dataclasses import replace

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The build-server identity: every intent below is an
# act proposed under the build session the attacker
# operated from. The requests in the incident DID
# arrive authenticated as the build server -- that was
# the problem, not a mitigating fact. Session and
# principal identity are part of the bound intent; they
# are not themselves authority for anything.
BUILDER = "agent:railway-build-server"
# The incident's build session, 2026-10-20, in the
# harness's naming.
SESSION = "build-session-2026-10-20"

ACTIONS = frozenset(
    {"push_image", "read_build_history", "fetch_repo_snapshot", "decrypt_variables"}
)

# The one act the stolen credential was actually for:
# push a built image to the registry. Real authority
# exists for this intent and no other.
PUSH_INTENT = Intent(BUILDER, "push_image", "railway:registry/oci-image", 25, SESSION)
# Hop 1: read stored histories of other builds from
# the workflow cluster (353 histories, 13:50-15:30 UTC
# on 2026-10-20, sealed variables included).
HISTORY_INTENT = Intent(
    BUILDER, "read_build_history", "railway:temporal/build-histories", 40, SESSION
)
# Hop 2: fetch a build's repository snapshot from the
# build cache -- the retrieval that yielded the
# internal monorepo.
SNAPSHOT_INTENT = Intent(
    BUILDER, "fetch_repo_snapshot", "railway:build-cache/repo-snapshot", 40, SESSION
)
# The endgame: decrypt customer environment variables
# through the key service (2026-10-21, 04:42-07:15
# UTC, after the OIDC hop and the SSH hop put the
# longer-lived decryption credential in the attacker's
# hands).
DECRYPT_INTENT = Intent(
    BUILDER, "decrypt_variables", "railway:kms/customer-env-vars", 60, SESSION
)

# The stolen build credential itself, as an inert
# stand-in string. In the incident this artifact was
# the whole attack for two hops: systems accepted its
# possession as authorization. Here it is presented at
# the dispatch boundary as if it were a permit, and --
# in the negative control -- as the signature a
# trusting verifier checks for.
BUILD_CREDENTIAL = "railway-build-credential-inert-7f3a"

# The erroneous binding's deployment: a trust
# configuration that existed in one cloud environment
# and should not have. Approvals minted under it carry
# its deployment and its trust hash, not the enrolled
# ones.
BINDING_DEPLOYMENT = "deployment:railway-cloud-cicd"


class _TrustedClientVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by credential recognition, the
    incident's exact shape: ``verify`` asks only
    whether the presented signature IS the build
    credential -- the check the internal Temporal
    instance effectively performed when it accepted
    the build credential as a trusted client. The
    payload, the intent, and the accountable
    authority's signature are never consulted: any
    envelope, for any act, verifies if the bearer
    holds the credential, and nothing verifies without
    it. Test-local; never imported by runtime code.
    """

    def verify(self, payload: bytes, signature: str) -> bool:
        return signature == BUILD_CREDENTIAL


class PlatformExecutor:
    """Consequences on the platform, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the incident's internal systems
    did not have: in the incident, a recognized
    credential WAS the execution path, and the history
    read, the snapshot fetch, and the decryption
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


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class RailwayIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.executor = PlatformExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
        clock=None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
            authority_trust=trust_for(verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=verifier,
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

    def _push_envelope(
        self,
        kernel: GovernanceKernel,
        *,
        approval_id: str,
        nonce: str,
    ):
        """A genuine approval envelope for the push intent.

        Real authority, honestly issued -- for the
        registry push. Every structural field is the
        enrolled one and the signature verifies; the
        ONLY thing wrong with presenting it for another
        intent is that it does not approve that intent.
        That is the incident's isolation: the build
        credential was genuine too; the failure was
        systems accepting it beyond its scope.
        """
        return signed_envelope(
            kernel,
            PUSH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, PUSH_INTENT)
        # The one legitimate act: the registry push
        # under a genuine, well-formed, verified
        # approval executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, PUSH_INTENT))
        self.assertEqual(
            [("push_image", "railway:registry/oci-image")], self.executor.effects
        )
        # The same permit cannot push twice -- a verified
        # approval is not a standing credential.
        self.assertFalse(self.executor.execute(self.kernel, permit, PUSH_INTENT))
        self.assertEqual(
            [("push_image", "railway:registry/oci-image")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all, and the raw credential -----------------

    def test_step1_no_approval_and_raw_credential_denied(self) -> None:
        # The kernel declines to mint: no approval
        # envelope exists for the history read, and the
        # attacker's presence inside the build session
        # is not one.
        decision = self.kernel.evaluate(HISTORY_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, HISTORY_INTENT))
        # The stolen credential itself, presented at the
        # dispatch boundary as if possession were a
        # permit: consume rejects it, bound to the
        # history intent's hash. A recognized credential
        # is not a permit.
        self.assertFalse(self.executor.execute(self.kernel, BUILD_CREDENTIAL, HISTORY_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the scoped approval stretched to the cluster read ----------
    #
    # Hop 1 of the incident: the build credential,
    # scoped to registry pushes, was accepted by the
    # internal Temporal instance as a trusted client,
    # and 353 build histories were read through its
    # APIs. On the governed path the scope is not a
    # property the receiving system supplies: the
    # approval binds the exact intent hash, so the
    # genuine push approval presented for the history
    # read is denied as a mismatch, and the genuine
    # push permit presented at the dispatch boundary
    # for the history read is rejected -- the permit is
    # spent only on the act it was minted for.

    def test_step2_scoped_approval_does_not_authorize_cluster_read(self) -> None:
        push_envelope = self._push_envelope(
            self.kernel, approval_id="approval-push-for-history", nonce="nonce-push-for-history"
        )
        decision = self.kernel.evaluate_with_approval(HISTORY_INTENT, push_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # The genuine push permit itself, presented at
        # the dispatch boundary for the history read:
        # a permit is not a credential either -- it
        # spends on its own intent or not at all.
        permit = self._issue_permit(
            self.kernel, PUSH_INTENT, approval_id="approval-push-2", nonce="nonce-push-2"
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, HISTORY_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the same stretch at the later hops ---------------------------
    #
    # Hops 2 and the endgame: the same credential
    # fetched the repository snapshot that yielded the
    # monorepo, and the chain ended at decryption of
    # customer variables. The stretch must fail at
    # every hop, not just the first: a control that
    # stops the history read but waves the snapshot
    # fetch through has governed nothing that matters,
    # because the snapshot is what armed the second
    # entry.

    def test_step3_scoped_approval_does_not_authorize_snapshot_or_decrypt(self) -> None:
        snapshot_attempt = self._push_envelope(
            self.kernel,
            approval_id="approval-push-for-snapshot",
            nonce="nonce-push-for-snapshot",
        )
        decision = self.kernel.evaluate_with_approval(SNAPSHOT_INTENT, snapshot_attempt)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        decrypt_attempt = self._push_envelope(
            self.kernel,
            approval_id="approval-push-for-decrypt",
            nonce="nonce-push-for-decrypt",
        )
        decision = self.kernel.evaluate_with_approval(DECRYPT_INTENT, decrypt_attempt)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejected = _events(self.kernel, "approval_rejected")
        self.assertEqual(2, len(rejected))
        # Counted, not collapsed: both denials carry the
        # same reason, and the reconciliation reports
        # the reason twice -- once per occurrence.
        self.assertEqual(
            Counter({"approval_intent_mismatch": 2}),
            Counter(record["payload"]["reason"] for record in rejected),
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the erroneous trust binding --------------------------------
    #
    # Hop 3 of the incident: an erroneously defined
    # OIDC binding, found by reading the copied code,
    # exchanged a workload identity for a short-lived
    # production cloud credential -- a consequential
    # credential minted by a configuration, with no
    # accountable human approving that act at that
    # moment. On the governed path there is exactly one
    # enrolled trust, fixed by policy before work
    # begins. An approval minted under any other trust
    # configuration -- the binding's own deployment, or
    # a trust defined with a far wider approval window
    # than the enrolled one -- is refused on the trust
    # limb itself, before intent or signature are ever
    # reached: a binding is not an approval, however
    # correctly it is configured, and an erroneously
    # defined one is not even that.

    def test_step4_erroneous_trust_binding_does_not_authorize(self) -> None:
        # (a) The binding's own deployment: every named
        # field of the binding's trust, genuinely signed
        # by the test verifier -- refused at the
        # deployment limb of the enrolled trust.
        binding_trust = trust_for(self.verifier, deployment_id=BINDING_DEPLOYMENT)
        binding_envelope = signed_envelope(
            self.kernel,
            DECRYPT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-binding-deployment",
            nonce="nonce-binding-deployment",
            deployment_id=BINDING_DEPLOYMENT,
            trust_hash=binding_trust.trust_hash,
        )
        decision = self.kernel.evaluate_with_approval(DECRYPT_INTENT, binding_envelope)
        self.assertEqual(
            ("deny", "approval_deployment_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The enrolled deployment, but a trust
        # defined with a far wider approval window --
        # the binding as a quiet widening of the trust
        # itself. The named fields all match; the trust
        # hash does not, and the refusal lands there.
        wide_trust = trust_for(self.verifier, max_approval_ttl_ns=86_400_000_000_000)
        widened_envelope = signed_envelope(
            self.kernel,
            DECRYPT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-binding-widened",
            nonce="nonce-binding-widened",
            trust_hash=wide_trust.trust_hash,
        )
        decision = self.kernel.evaluate_with_approval(DECRYPT_INTENT, widened_envelope)
        self.assertEqual(
            ("deny", "approval_trust_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejected = _events(self.kernel, "approval_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            Counter({"approval_deployment_mismatch": 1, "approval_trust_mismatch": 1}),
            Counter(record["payload"]["reason"] for record in rejected),
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: revocation timing -------------------------------------------
    #
    # At 17:28 UTC on 2026-10-20 Railway revoked and
    # replaced the build credential. The governed
    # counterpart of revocation is the end of the
    # approval's validity window, and the kernel's
    # answer after that moment is not scoped to the
    # attacker's intents: the artifact is refused even
    # for its OWN act. Before the window ends, the
    # genuine push verifies and executes -- builds
    # pushed before 17:28 were legitimate work. After
    # it ends, the same envelope is an expired artifact,
    # the raw credential is still not a permit, and
    # nothing the credential ever touched can be spent,
    # because the one permit it minted was single-use
    # and is already spent.

    def test_step5_revoked_credential_authorizes_nothing(self) -> None:
        clock_cell = [NOW]
        kernel = self._kernel(clock=lambda: clock_cell[0])
        envelope = signed_envelope(
            kernel,
            PUSH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-revocation",
            nonce="nonce-revocation",
        )
        # Before revocation: the genuine approval
        # verifies and the one legitimate act executes.
        decision = kernel.evaluate_with_approval(PUSH_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.executor.execute(kernel, decision.permit, PUSH_INTENT))
        self.assertEqual(
            [("push_image", "railway:registry/oci-image")], self.executor.effects
        )
        # The revocation moment: the clock passes the
        # end of the approval's window (17:28 UTC, in
        # the incident's naming).
        clock_cell[0] = NOW + 2_000
        # The same envelope, for its own act, after
        # revocation: expired. A revoked credential
        # authorizes nothing -- not a new hop, and not
        # even the scope it was honestly issued for.
        decision = kernel.evaluate_with_approval(PUSH_INTENT, envelope)
        self.assertEqual(("deny", "approval_expired"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)
        # And the raw credential after revocation is
        # what it was before it: not a permit.
        self.assertFalse(self.executor.execute(kernel, BUILD_CREDENTIAL, PUSH_INTENT))
        self.assertEqual(
            [("push_image", "railway:registry/oci-image")], self.executor.effects
        )
        self.assertEqual(1, len(_events(kernel, "approval_verified")))
        self.assertEqual(1, len(_events(kernel, "permit_consumed")))
        rejected = _events(kernel, "approval_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual("approval_expired", rejected[0]["payload"]["reason"])
        self.assertEqual(1, len(_events(kernel, "permit_rejected")))
        self.assertTrue(kernel.verify_audit())

    # -- step 6: the incident channel, reconciled per item -------------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit, and reconciled the way the multiplicity
    # pass requires: counted per item, duplicates
    # included. The frozen sequence is the full attempt
    # sequence exercisable on one kernel: the
    # no-approval evaluation (step 1), the mismatched
    # envelope presented TWICE -- the identical
    # artifact, the duplicate-item probe (step 2's
    # route) -- the raw credential presented TWICE at
    # the dispatch boundary (step 1's route), the
    # binding envelope (step 4's route), the one
    # legitimate execution, and the spent-permit replay.
    # The revocation route (step 5) requires a moving
    # clock and is pinned on its own kernel there; its
    # denial is the same approval_rejected event class
    # counted here and would derive identically.

    def test_step6_incident_channel_and_counted_reconciliation(self) -> None:
        self.kernel.evaluate(HISTORY_INTENT)
        duplicate = self._push_envelope(
            self.kernel, approval_id="approval-seq-duplicate", nonce="nonce-seq-duplicate"
        )
        for _ in range(2):
            decision = self.kernel.evaluate_with_approval(HISTORY_INTENT, duplicate)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_intent_mismatch", decision.reason)
        for _ in range(2):
            self.assertFalse(
                self.executor.execute(self.kernel, BUILD_CREDENTIAL, HISTORY_INTENT)
            )
        binding_trust = trust_for(self.verifier, deployment_id=BINDING_DEPLOYMENT)
        binding_envelope = signed_envelope(
            self.kernel,
            DECRYPT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-binding",
            nonce="nonce-seq-binding",
            deployment_id=BINDING_DEPLOYMENT,
            trust_hash=binding_trust.trust_hash,
        )
        decision = self.kernel.evaluate_with_approval(DECRYPT_INTENT, binding_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_deployment_mismatch", decision.reason)
        # The one legitimate execution still lands; the
        # chain's attempts did not.
        permit = self._issue_permit(
            self.kernel, PUSH_INTENT, approval_id="approval-seq-push", nonce="nonce-seq-push"
        )
        self.assertTrue(self.executor.execute(self.kernel, permit, PUSH_INTENT))
        # The spent permit re-presented: a verified
        # approval is single-use, not a session
        # credential.
        self.assertFalse(self.executor.execute(self.kernel, permit, PUSH_INTENT))

        # Attempts and effects, reconciled as multisets:
        # every presented item is accounted for, the
        # duplicates counted per occurrence, and exactly
        # one item -- the authorized push -- executed,
        # exactly once.
        self.assertEqual(
            Counter(
                {
                    ("read_build_history", "railway:temporal/build-histories"): 2,
                    ("push_image", "railway:registry/oci-image"): 2,
                }
            ),
            Counter(self.executor.attempts),
        )
        self.assertEqual(
            Counter({("push_image", "railway:registry/oci-image"): 1}),
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
        self.assertEqual(3, len(approval_rejected))
        self.assertEqual(3, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # The duplicate probe, pinned: the identical
        # mismatched envelope was denied twice, and the
        # counted reconciliation reports the mismatch
        # reason twice. A set-based reconciliation would
        # report it once and lose exactly the duplicate.
        self.assertEqual(
            Counter({"approval_intent_mismatch": 2, "approval_deployment_mismatch": 1}),
            Counter(record["payload"]["reason"] for record in approval_rejected),
        )
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more,
        # no fewer, counted per item on both sides. The
        # require_approval decision above is an
        # audit-recorded attempt that contributes zero
        # near-miss records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(9, report.near_misses)
        self.assertEqual(report.near_misses, len(report.records))
        for record in report.records:
            self.assertEqual("near_miss", record.kind)
            self.assertEqual("Recorded", record.claim_classification)
        detail_counts: Counter = Counter()
        for record in report.records:
            detail_counts[record.source_detail] += 1
        self.assertEqual(
            Counter(
                {
                    "permit_rejected": len(permit_rejected),
                    "approval_rejected": len(approval_rejected),
                    "decision": len(denied_decisions),
                }
            ),
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_trusted_client_would_execute(self) -> None:
        # Same scenario, one component swapped: a
        # verifier that checks a presented artifact by
        # recognizing the build credential -- the check
        # the internal Temporal instance effectively
        # performed. An envelope for the history read
        # carrying the credential as its signature
        # VERIFIES, a permit mints, and the history read
        # EXECUTES; the decryption follows through the
        # same door, because a verifier that authenticates
        # a credential has nothing left to say about
        # scope. That is the incident, reproduced at the
        # exact layer it happened: not the isolation
        # escape, not the network, not the executor --
        # the authorization check that asked "do we
        # recognize this credential?" instead of "did
        # the accountable authority approve this act?"
        # The denials in the steps above therefore come
        # from the governed verification's shape (an
        # exact-intent approval, signed by the enrolled
        # authority, under the one enrolled trust), not
        # from a harness that denies by construction.
        double = _TrustedClientVerifier()
        blind_kernel = self._kernel(verifier=double)
        history_attempt = signed_envelope(
            blind_kernel,
            HISTORY_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-history",
            nonce="nonce-nc-history",
        )
        history_attempt = replace(history_attempt, signature=BUILD_CREDENTIAL)
        decision = blind_kernel.evaluate_with_approval(HISTORY_INTENT, history_attempt)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, HISTORY_INTENT))
        decrypt_attempt = signed_envelope(
            blind_kernel,
            DECRYPT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-decrypt",
            nonce="nonce-nc-decrypt",
        )
        decrypt_attempt = replace(decrypt_attempt, signature=BUILD_CREDENTIAL)
        decision = blind_kernel.evaluate_with_approval(DECRYPT_INTENT, decrypt_attempt)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, DECRYPT_INTENT))
        self.assertEqual(
            [
                ("read_build_history", "railway:temporal/build-histories"),
                ("decrypt_variables", "railway:kms/customer-env-vars"),
            ],
            self.executor.effects,
        )
        # Under the same double, a wrong token is
        # refused -- the incident's precision: the check
        # was real, it just authenticated the wrong
        # thing. Possession of the credential was the
        # entire test.
        wrong_attempt = signed_envelope(
            blind_kernel,
            HISTORY_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-wrong",
            nonce="nonce-nc-wrong",
        )
        wrong_attempt = replace(wrong_attempt, signature="not-the-build-credential")
        decision = blind_kernel.evaluate_with_approval(HISTORY_INTENT, wrong_attempt)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Contrast, the identical credential-carrying
        # artifact against the governed kernel: denied
        # (the credential is not the accountable
        # authority's signature over this intent).
        governed_attempt = signed_envelope(
            self.kernel,
            HISTORY_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        governed_attempt = replace(governed_attempt, signature=BUILD_CREDENTIAL)
        decision = self.kernel.evaluate_with_approval(HISTORY_INTENT, governed_attempt)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
