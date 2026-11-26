"""Scenario test: the OpenSSH "SSHole" authentication
bypass, CVE-2026-123158 (disclosed 2026-11-05;
exploitation observed from 2026-11-07).

Incident (Recorded, from BleepingComputer's reporting
of the disclosure and of GreyNoise's and Previdian's
sensor observations, converged with CISA's Known
Exploited Vulnerabilities listing of the CVE and the
OpenSSH fix): on Linux systems built against the musl
C library, where sshd does not use PAM, sshd verifies a
password by hashing the presented password with libc
``crypt()`` and comparing the result to the account's
stored field in ``/etc/shadow``. For an oversized
password (longer than 256 bytes; the working range
reported is 257-1024 bytes), musl's ``crypt()`` fails
and returns the sentinel ``*``. An account with no
password set -- password logins disabled -- also stores
``*`` in its shadow field. sshd compared the two and
treated the sentinel as a match: anyone who could reach
the port could log in to a passwordless account,
including root where that account was reachable.
Researcher Ozgün Kültekin disclosed the flaw; OpenSSH
released 10.6p2 on 2026-11-05 with a workaround in sshd
(a minimum-length check on the stored field, so the
comparison can no longer succeed against the sentinel),
and exploit code was public within about four hours.
glibc-based systems and PAM configurations are not
affected. CISA added CVE-2026-123158 (CVSS 8.1) to the
KEV catalog on 2026-11-09.

GreyNoise recorded the first successful exploitation of
one of its sensors on 2026-11-07 at 00:46 UTC, about 40
hours after the fix. Its tracker (sensor-observed, not
a census of the internet) listed 48 confirmed
post-exploitation events from 10 attacker addresses as
of 2026-11-18: system and container reconnaissance,
cloud metadata queries, reads of ``/etc/shadow``,
attacker keys written into ``authorized_keys``, a
doas-enabled backdoor account, a second sshd started on
port 2222 with forwarding enabled, and a Python
command-and-control implant (TAC Agent) installed as a
service. watchTowr associated other observed
exploitation with botnets and cryptomining. Every one
of those consequences began at the same first step: a
verification that returned the placeholder for "no
credential" and was read as "credential verified."

The failure is a fail-open credential verification: a
sentinel value whose meaning is "no credential is set"
was produced by the verification function on malformed
input and then treated as a successful verification,
because the check compared the function's output
against a stored field that legitimately held the same
sentinel. Two distinct defects had to hold at once --
the hash function answered an oversized input with the
placeholder instead of an error, and the comparison had
a stored placeholder for that answer to collide with.
Remove either one and the bypass does not exist.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce OpenSSH,
sshd, musl, ``crypt()``, or any password handling. The
mapping (Inferred, stated here so it can be argued
with): the consequential act is running a command as
root on the target host -- the first thing the
incident's intruders did with their logins. That act
requires an approval, and the approval artifact is the
credential presented for verification. The incident's
oversized password is an oversized approval signature
(512 characters, inside the incident's 257-1024 working
range); the incident's sentinel is the same character,
``*``, presented as a signature, returned as a verdict,
and -- in the negative control -- held as a verifier's
stored credential. Under the governed path the kernel's
verification compares the presented signature against
the signature computed from the payload under the
enrolled key: there is no stored placeholder anywhere
on that path, so the sentinel collision has no
counterpart, and the kernel additionally accepts no
verdict other than exactly ``True`` -- a verifier that
answers with the placeholder has not verified anything.
The only route from a request to a consequence is a
successful ``GovernanceKernel.consume`` of a permit
bound to the exact intent hash: principal, action,
resource, cost, session.

Setup: exactly one act is legitimate in this scenario
-- a root command on the target host, run once, under a
permit issued through a verified approval envelope: the
accountable per-action authorization actually granted.
The incident's verification bypass is then attempted on
every route the governed path has: with no approval at
all, with an oversized approval signature, with the
sentinel itself presented as the signature, with no
signature, with a verifier whose verdict is the
sentinel, and with forged and mismatched approval
envelopes. The kernel must deny each one, the
consequence ledger must stay empty for all of them, and
every denial must land in the audit record. A genuine,
well-formed approval verifies and authorizes exactly
one execution, and then spends.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A
bare ``evaluate`` that returns ``require_approval`` --
the kernel declining to mint without approval --
appends a decision record to the canonical audit but is
NOT derived as a near-miss by the channel. The scenario
asserts both halves of that statement exactly as they
hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit
for these action classes (Verified, executable
evidence). It proves nothing about any deployed SSH
server, password verifier, or libc that does not route
its authentication through this kernel -- a verifier
that compares against a stored placeholder is governed
by nothing here. The replay models the verification
step the incident's sshd got wrong, not OpenSSH
internals. A control not on the execution path governs
nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, and any
verification path that treats a placeholder as a match
(the incident's own class) remains outside this
evidence and open.

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

import hashlib
import unittest
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
# The target host's command executor: the dispatch
# boundary the incident's logins fed into. Every intent
# below is an act this executor would perform; an
# unauthenticated network peer proposes, the executor
# must not run anything without a permit bound to the
# act.
HOST = "agent:sshole-target-host"
# The session of the first observed exploitation,
# 2026-11-07, in the harness's naming. Session identity
# is part of the bound intent; it is not itself
# authority for anything.
SESSION = "ssh-session-2026-11-07"

# The incident's consequential act: run a command as
# root on the target host -- the capability every
# observed intrusion exercised first (reconnaissance,
# key injection, the second sshd, the implant all ran
# as the logged-in account, root where reachable).
COMMAND_INTENT = Intent(HOST, "execute_command", "sshole:host/root", 25, SESSION)
# A genuine but different act: run a command in the
# host's unprivileged diagnostic context. An approval
# for this is real authority -- for this intent.
DIAGNOSTIC_INTENT = Intent(
    HOST, "execute_command", "sshole:host/unprivileged-diagnostic", 25, SESSION
)

# The sentinel: the value that means "no credential is
# set" in the incident's stored field, and the value
# musl's crypt() returned on oversized input. In this
# scenario it appears in the three places it appeared
# in the incident's shape -- presented as a credential,
# returned as a verification result, and (negative
# control only) held as a stored credential.
SENTINEL = "*"

# The incident's oversized password, as an approval
# signature: 512 characters, inside the reported
# 257-1024 working range -- long enough to break the
# incident's hash function, carrying no authority of
# its own.
OVERSIZED_SIGNATURE = "A" * 512


def _crypt_like(presented: str) -> str:
    """The incident's hash function, as a test-local model.

    Faithful in exactly the property that mattered: an
    oversized input does not produce an error or a
    digest -- it produces the sentinel, the same value
    that means "no credential set." Any other input
    produces an ordinary digest that can never equal
    the sentinel.
    """
    if len(presented) > 256:
        return SENTINEL
    return hashlib.sha256(presented.encode()).hexdigest()


class _MuslCryptVerifier(HmacTestVerifier):
    """Deliberately vulnerable verifier double for the negative control.

    Verification by stored-field comparison, the
    incident's exact shape: the verifier holds a stored
    credential for the approval authority, and that
    stored credential is the sentinel -- no credential
    was ever set. ``verify`` hashes the presented
    signature with the incident's hash model and
    compares the result against the stored field. An
    oversized signature hashes to the sentinel, the
    stored field is the sentinel, and the comparison
    succeeds: a placeholder has verified a login. Any
    non-oversized input -- including the sentinel
    itself, and including a genuine signature --
    produces a digest that does not match, so under
    this double only the oversized artifact verifies,
    exactly as only the oversized password logged
    anyone in. Test-local; never imported by runtime
    code.
    """

    stored_field = SENTINEL

    def verify(self, payload: bytes, signature: str) -> bool:
        return _crypt_like(signature) == self.stored_field


class _SentinelVerdictVerifier(HmacTestVerifier):
    """Verifier double whose verdict is the sentinel, not a boolean.

    Models a verification layer that reports its
    "no credential / could not verify" placeholder as
    its result -- a truthy string in place of a verdict.
    Any caller that treats truthiness as success (the
    incident's comparison did the equivalent) is
    bypassed by construction. The canonical kernel is
    not such a caller; step 4 pins what it does instead.
    """

    def verify(self, payload: bytes, signature: str):  # type: ignore[override]
        return SENTINEL


class CommandExecutor:
    """Consequences on the target host, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the incident's sshd did not have:
    in the incident, a successful "verification" WAS the
    execution path, and the shell followed immediately.
    Here the harness records an effect only when the
    kernel consumes a permit for the exact intent. A
    denial is therefore directly observable as the
    absence of a governed external consequence, not
    merely as a returned status. (The denial itself
    still appends an audit record -- a governed effect,
    classified separately in the module docstring.)
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


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class SSHoleIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"execute_command"}),
            10_000,
            frozenset({"execute_command"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.executor = CommandExecutor()

    def _kernel(
        self,
        *,
        verifier: HmacTestVerifier | None = None,
    ) -> GovernanceKernel:
        verifier = self.verifier if verifier is None else verifier
        policy = Policy(
            frozenset({"execute_command"}),
            10_000,
            frozenset({"execute_command"}),
            authority_trust=trust_for(verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=verifier,
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

    def _envelope_with_signature(
        self,
        kernel: GovernanceKernel,
        intent: Intent,
        signature: str,
        *,
        approval_id: str,
        nonce: str,
    ):
        """A genuine envelope in every field but the signature.

        Every structural field -- authority, verifier,
        key, deployment, trust, session, principal,
        intent, policy, timing -- is the real one, so the
        ONLY check that can deny the attempt is the
        signature verification itself. That is the
        incident's isolation: sshd's session machinery
        was all genuine too; the one broken step was the
        credential comparison.
        """
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        return replace(envelope, signature=signature)

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_approval_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, COMMAND_INTENT)
        # The one legitimate act: the root command under
        # a genuine, well-formed, verified approval
        # executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, COMMAND_INTENT))
        self.assertEqual(
            [("execute_command", "sshole:host/root")], self.executor.effects
        )
        # The same permit cannot run the same command
        # twice -- a verified approval is not a standing
        # login.
        self.assertFalse(self.executor.execute(self.kernel, permit, COMMAND_INTENT))
        self.assertEqual(
            [("execute_command", "sshole:host/root")], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all ----------------------------------------

    def test_step1_no_approval_at_all_denied(self) -> None:
        # The kernel declines to mint: no approval
        # envelope exists for the root command, and the
        # peer's ability to reach the port is not one.
        # (Task step (c): no approval at all -> denied and
        # recorded.)
        decision = self.kernel.evaluate(COMMAND_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, COMMAND_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the oversized artifact -------------------------------------
    #
    # Task step (a): a consequential act attempted with
    # an oversized/malformed approval artifact is
    # rejected at the boundary, fail-closed. In the
    # incident the oversized password never faced a real
    # comparison: the hash function collapsed it to the
    # sentinel before any credential was checked, and
    # the sentinel then "matched." On the governed path
    # there is no comparison it can collapse into -- the
    # verifier computes the expected signature from the
    # payload under the enrolled key and compares the
    # presented artifact against that, so an oversized
    # artifact is simply a wrong signature of unusual
    # length, denied like any other.

    def test_step2_oversized_approval_artifact_denied(self) -> None:
        self.assertEqual(512, len(OVERSIZED_SIGNATURE))
        self.assertTrue(257 <= len(OVERSIZED_SIGNATURE) <= 1024)
        oversized = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            OVERSIZED_SIGNATURE,
            approval_id="approval-oversized",
            nonce="nonce-oversized",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, oversized)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # An even longer artifact fares no better: length
        # is not a route around the comparison.
        huge = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            "B" * 4096,
            approval_id="approval-huge",
            nonce="nonce-huge",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, huge)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(2, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the sentinel presented as the credential -------------------

    def test_step3_sentinel_presented_as_signature_denied(self) -> None:
        # The literal "no credential" value, presented AS
        # the credential. In the incident this value was
        # the stored field and the hash output; here it is
        # offered as a signature, and the governed
        # comparison is against a computed HMAC it cannot
        # equal. A placeholder must never verify --
        # including when it is the entire artifact.
        sentinel_envelope = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            SENTINEL,
            approval_id="approval-sentinel",
            nonce="nonce-sentinel",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, sentinel_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # And no signature at all is its own recorded
        # denial, before verification is even attempted:
        # absence is not a weaker form of the sentinel,
        # it is a missing credential.
        empty = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            "",
            approval_id="approval-empty",
            nonce="nonce-empty",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, empty)
        self.assertEqual(
            ("deny", "approval_signature_missing"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(2, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: a sentinel verdict never verifies ---------------------------
    #
    # Task step (b): an act attempted where verification
    # yields a sentinel/placeholder result is denied,
    # never allowed. The double's verify() returns the
    # sentinel string -- truthy, and exactly the value a
    # careless caller would read as "the check produced
    # the account's value, so it matched." The canonical
    # kernel accepts no verdict other than exactly True:
    # ``signature_valid is not True`` denies. A
    # placeholder result is not a verification, however
    # it is dressed.

    def test_step4_sentinel_verdict_never_verifies(self) -> None:
        sentinel_kernel = self._kernel(verifier=_SentinelVerdictVerifier())
        envelope = signed_envelope(
            sentinel_kernel,
            COMMAND_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-verdict",
            nonce="nonce-verdict",
        )
        decision = sentinel_kernel.evaluate_with_approval(COMMAND_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(sentinel_kernel, "approval_verified")))
        self.assertEqual(1, len(_events(sentinel_kernel, "approval_rejected")))
        self.assertTrue(sentinel_kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ----------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, DIAGNOSTIC_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the root command signed with
        # an unauthorized key: whoever controls the
        # network end of the connection cannot mint the
        # host's authority.
        forged_envelope = signed_envelope(
            self.kernel, COMMAND_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine diagnostic envelope presented
        # for the root intent: a real approval for a
        # bounded act is not approval for the
        # consequential one.
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
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
        decision = self.kernel.evaluate_with_approval(DIAGNOSTIC_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit: every consume rejection, every approval
    # rejection, and every denied decision in the sequence
    # becomes a near-miss record in the derived incident
    # report. The bare require_approval decision is in the
    # canonical audit (and counted below) but is NOT
    # derived as a near-miss -- the expected near-miss
    # count is built from the event classes the channel
    # actually derives, so this test pins the boundary
    # instead of papering over it.
    #
    # The frozen sequence is the full attempt sequence
    # exercisable on one kernel: the no-approval route
    # (step 1), the oversized artifact (step 2), the
    # sentinel presented as a signature and as a permit
    # (step 3's value on both boundaries), the mismatched
    # envelope (step 5b), the one legitimate execution,
    # and the spent-permit replay. The sentinel-verdict
    # route (step 4) requires a differently configured
    # kernel -- one kernel holds one approval verifier --
    # so it is pinned on its own kernel in step 4; its
    # denial is the same approval_rejected event class
    # counted here and would derive identically.

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(COMMAND_INTENT)
        oversized = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            OVERSIZED_SIGNATURE,
            approval_id="approval-seq-oversized",
            nonce="nonce-seq-oversized",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, oversized)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        sentinel_envelope = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            SENTINEL,
            approval_id="approval-seq-sentinel",
            nonce="nonce-seq-sentinel",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, sentinel_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_envelope = signed_envelope(
            self.kernel,
            DIAGNOSTIC_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The sentinel presented as a permit at the
        # dispatch boundary: the placeholder is not a
        # permit either, and consume rejects it bound to
        # the command's intent hash.
        self.assertFalse(self.executor.execute(self.kernel, SENTINEL, COMMAND_INTENT))
        # The one legitimate execution still lands; the
        # bypass attempts did not.
        permit = self._issue_permit(
            self.kernel, COMMAND_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.executor.execute(self.kernel, permit, COMMAND_INTENT))
        self.assertEqual(
            [("execute_command", "sshole:host/root")], self.executor.effects
        )
        # The spent permit re-presented: a verified
        # approval is single-use, not a session login.
        self.assertFalse(self.executor.execute(self.kernel, permit, COMMAND_INTENT))
        self.assertEqual(
            [("execute_command", "sshole:host/root")], self.executor.effects
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
        self.assertEqual(2, len(permit_rejected))
        self.assertEqual(3, len(approval_rejected))
        self.assertEqual(3, len(denied_decisions))
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

    # -- negative control ----------------------------------------------------

    def test_negative_control_sentinel_comparison_would_execute(self) -> None:
        # Same scenario, one component swapped: a
        # verifier that checks a presented credential by
        # hashing it and comparing the result against a
        # stored field, where the stored field is the
        # sentinel because no credential was ever set.
        # The oversized artifact hashes to the sentinel,
        # the field is the sentinel, the comparison
        # succeeds, a permit mints, and the root command
        # EXECUTES. That is the incident, reproduced at
        # the exact layer it happened: not the session,
        # not the network, not the executor -- the
        # verification comparison. The denials in the
        # steps above therefore come from the governed
        # verification's shape (a computed expected value,
        # no stored placeholder, an exact-True verdict),
        # not from a harness that denies by construction.
        double = _MuslCryptVerifier()
        blind_kernel = self._kernel(verifier=double)
        oversized = signed_envelope(
            blind_kernel,
            COMMAND_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-oversized",
            nonce="nonce-nc-oversized",
        )
        oversized = replace(oversized, signature=OVERSIZED_SIGNATURE)
        decision = blind_kernel.evaluate_with_approval(COMMAND_INTENT, oversized)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.executor.execute(blind_kernel, decision.permit, COMMAND_INTENT))
        self.assertEqual(
            [("execute_command", "sshole:host/root")], self.executor.effects
        )
        # Under the same double, nothing else gets in --
        # the incident's precision: a non-oversized wrong
        # signature hashes to an ordinary digest that
        # does not match the sentinel field, and the
        # sentinel itself, hashed, is also just a digest.
        # Only the oversized artifact produces the
        # placeholder, and only the placeholder matches.
        for signature, approval_id in (
            ("wrong-but-ordinary-signature", "approval-nc-ordinary"),
            (SENTINEL, "approval-nc-sentinel"),
        ):
            attempt = signed_envelope(
                blind_kernel,
                COMMAND_INTENT,
                self.verifier,
                now_ns=NOW,
                approval_id=approval_id,
                nonce=f"nonce-{approval_id}",
            )
            attempt = replace(attempt, signature=signature)
            decision = blind_kernel.evaluate_with_approval(COMMAND_INTENT, attempt)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_signature_invalid", decision.reason)
        # Contrast, the identical oversized artifact
        # against the governed kernel: denied (step 2's
        # route).
        governed = self._envelope_with_signature(
            self.kernel,
            COMMAND_INTENT,
            OVERSIZED_SIGNATURE,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(COMMAND_INTENT, governed)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)


if __name__ == "__main__":
    unittest.main()
