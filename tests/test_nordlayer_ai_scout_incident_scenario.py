"""Scenario test: the NordLayer AI Scout ``.env``
over-read -- an agent asked for ONE named secret loaded
the whole secrets file, repeatedly (reported
2026-11-26).

Incident (Recorded, from NordLayer's AI Scout report as
published via GlobeNewswire on 2026-11-26; single-vendor
telemetry, and the affected company is unnamed in the
report): a QA engineer asked an AI coding agent to
review a merge request. The project instructions pointed
the agent to a GitLab token stored in an ``.env`` file --
a file that also contained production passwords for an
internal admin tool, an HR system API token, and a BI
client secret. To retrieve that one token, the agent
loaded the whole file across 10 sessions over three
weeks, sending its full contents to a third-party AI
service each time. In one session the ``.env`` file was
missing from a fresh copy of the project; instead of
stopping, the agent printed the machine's shell
environment -- every password and key stored on the
system. Afterwards the agent flagged its own leak,
telling the user it had leaked secrets into the
session's tool output and advising rotation. NordLayer's
expert commentary in the same report names the shape:
telling an agent to pull and use API tokens directly is
a common habit, the agent was simply doing what it was
told, and the leak went undetected for weeks.

The failure is an intent-scope failure, not a
verification failure. The instruction named ONE secret;
the agent's means -- reading the entire file that held
it, and later the entire shell environment -- disclosed
every other secret the file and the machine held, on
every repetition. Nothing in the task authorized the
over-read, nothing bound the fetch to a single use, and
nothing reconciled what the agent actually accessed
against what it was asked for, so the over-read repeated
for three weeks and surfaced only when the agent
reported itself. ``AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS`` (AGENTS.md): approval
to fetch a named secret is not approval to read the
container that holds it.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce any ``.env``
file, shell environment, AI coding agent, or third-party
AI service, and it contains no real secret: the store
below holds inert labels, never values. The mapping
(Inferred, stated here so it can be argued with): the
consequential act is a governed read of a secret from
the store. The approved intent is the fetch of the ONE
named secret (the GitLab token). The incident's
whole-file load is a distinct intent -- a read of the
file as a whole -- and the incident's shell-environment
dump is a third intent, a read of the environment as a
whole; neither is the approved intent, so an approval
envelope for the named fetch presented for either is
refused as an intent mismatch, exactly as an approval
for one act is refused for another in every canonical
scenario. The incident's repetition across 10 sessions
is modeled as re-presentation: a spent permit
re-presented in its own session, and the session-1
approval presented in a later session -- permits are
single-use and approvals are session-bound, so neither
repetition mints or spends. What the agent actually
accessed is reconciled against what was approved, per
occurrence and per session, by a test-local
reconciliation (counts, not mere presence): every
approval and access record carries its session and
action identity, so an approval in one session cannot
compensate for excess access in another even when the
aggregate counts are equal. On the governed path the
counts are equal and the over-read count is zero;
applied to the incident's own shape (the negative
control's access log) the same reconciliation reports
the over-read exactly -- three unapproved secrets per
whole-file load.

Setup: exactly one act is legitimate in this scenario
-- fetch the one named GitLab token, once, in the
session the approval names, under a permit issued
through a verified approval envelope. Every broader or
repeated act the incident records is then attempted on
the governed path: the whole-file read under the
single-secret approval, the shell-environment dump
under the single-secret approval (including as the
fallback when the file is absent), a forged approval, a
genuine approval for a different single secret
substituted for the named one, the spent permit
replayed, and the approval carried across sessions. The
kernel must deny each one, the accessed log must stay
exactly the one approved fetch, and every denial must
land in the audit record.

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
evidence). It proves nothing about any deployed coding
agent, secrets store, or AI service that does not route
its reads through this kernel -- an agent that reads a
file directly is governed by nothing here. The replay
models the authorization step the incident's workflow
did not have, not the agent's internals. A control not
on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed read is permitted per
correctly verified approval, for exactly the named
secret, and any read path that takes the whole file or
the whole environment under a single-secret approval
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
# The coding agent: the principal whose reads the store
# would serve. Every intent below is a read this agent
# proposes; the store must serve nothing without a
# permit bound to the exact read.
AGENT = "agent:nordlayer-scout-coding-agent"
# The session the approval names -- the merge-request
# review session. Session identity is part of the bound
# intent; the incident's repetition across later sessions
# is exactly what session binding and single-use permits
# are tested against below.
SESSION = "mr-review-session-1"
LATER_SESSION = "mr-review-session-2"

# The store's contents, as inert labels -- the scenario
# never holds a secret value, only the names the
# incident's report itself names: the one GitLab token
# the task pointed at, and the three further secrets the
# same file held (production passwords for an internal
# admin tool, an HR system API token, a BI client
# secret).
GITLAB_TOKEN = "gitlab-token"
STORE_CONTENTS = (
    GITLAB_TOKEN,
    "admin-tool-production-password",
    "hr-system-api-token",
    "bi-client-secret",
)

# The one approved act: fetch the ONE named secret.
FETCH_INTENT = Intent(AGENT, "read_secret", "secret-store/gitlab-token", 10, SESSION)
# The incident's over-read: read the file as a whole.
# A real act with real consequences -- and not the act
# that was approved.
WHOLE_FILE_INTENT = Intent(AGENT, "read_secret", "secret-store/env-file-full", 10, SESSION)
# The incident's fallback over-read: when the file was
# missing, dump the shell environment as a whole.
SHELL_ENV_INTENT = Intent(AGENT, "read_secret", "shell-environment/full", 10, SESSION)
# A genuine but different single-secret act: fetch the
# BI client secret. An approval for this is real
# authority -- for this intent.
OTHER_SECRET_INTENT = Intent(AGENT, "read_secret", "secret-store/bi-client-secret", 10, SESSION)
# The approved fetch re-proposed in a later session: the
# incident's repetition shape.
LATER_SESSION_INTENT = Intent(AGENT, "read_secret", "secret-store/gitlab-token", 10, LATER_SESSION)


# One approval or access occurrence, with the identity
# that bounds it: (session_id, action, secret name).
# Reconciliation keys on the whole record, never on the
# secret name alone -- a flattened per-name counter
# would let an approval in one session compensate for
# excess access in another whenever the aggregate
# counts happened to match (Codex review on PR #409).
AccessRecord = tuple[str, str, str]


def access_record(session: str, name: str, action: str = "read_secret") -> AccessRecord:
    return (session, action, name)


def reconcile_access(approved: list[AccessRecord], accessed: list[AccessRecord]) -> dict:
    """Reconcile what was accessed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence, and never aggregate-only: each approved
    occurrence accounts for one accessed occurrence of
    the same secret under the same session and the same
    action, in order, and every accessed occurrence
    beyond the approved count for that exact
    (session, action, secret) record is an over-read
    occurrence, named with its session and action.
    Approval in one session therefore cannot compensate
    for excess access in another, even when the totals
    are equal. This is the check the incident's workflow
    never ran: run per session, the incident's first
    whole-file load already reports three over-read
    occurrences.
    """
    remaining: dict[AccessRecord, int] = {}
    for record in approved:
        remaining[record] = remaining.get(record, 0) + 1
    over_read_records: list[AccessRecord] = []
    for record in accessed:
        if remaining.get(record, 0) > 0:
            remaining[record] -= 1
        else:
            over_read_records.append(record)
    over_read = [name for _session, _action, name in over_read_records]
    return {
        "approved_count": len(approved),
        "accessed_count": len(accessed),
        "over_read_count": len(over_read_records),
        "over_read": over_read,
        "over_read_records": over_read_records,
        "ok": not over_read_records,
    }


class SecretStore:
    """Consequences at the secrets store, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's workflow did not have: in the
    incident, the instruction to fetch one token WAS the
    execution path, and the whole file followed. Here the
    harness serves a secret only when the kernel consumes
    a permit for the exact intent, and records each
    served secret in the accessed log the reconciliation
    checks. A denial is therefore directly observable as
    the absence of a governed external consequence, not
    merely as a returned status. (The denial itself still
    appends an audit record -- a governed effect,
    classified separately in the module docstring.)
    """

    # What each intent, if it were ever permitted, would
    # serve: the named fetch serves one secret; the
    # whole-file and shell-environment reads serve
    # everything they reach. The governed path below
    # permits only the first.
    SERVES = {
        FETCH_INTENT.resource: (GITLAB_TOKEN,),
        WHOLE_FILE_INTENT.resource: STORE_CONTENTS,
        SHELL_ENV_INTENT.resource: STORE_CONTENTS,
        OTHER_SECRET_INTENT.resource: ("bi-client-secret",),
        LATER_SESSION_INTENT.resource: (GITLAB_TOKEN,),
    }

    def __init__(self) -> None:
        self.accessed: list[str] = []
        # The same log with session and action identity
        # preserved per occurrence, for reconciliation.
        self.accessed_records: list[AccessRecord] = []

    def read(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        served = self.SERVES[intent.resource]
        self.accessed.extend(served)
        self.accessed_records.extend(
            access_record(intent.session_id, name, intent.action) for name in served
        )
        return True


class UngovernedAgent:
    """The incident's own path, as a test-local double for the negative control.

    No kernel, no permit, no approval: the instruction to
    fetch one named token is executed by loading the
    whole file that holds it, and when the file is absent
    by dumping the whole shell environment. Every load is
    recorded in the same accessed-log shape the governed
    store produces, so the one reconciliation runs over
    both paths and the difference is in the counts, not
    in the bookkeeping. Test-local; never imported by
    runtime code.
    """

    def __init__(self) -> None:
        self.accessed: list[str] = []
        self.accessed_records: list[AccessRecord] = []

    def fetch_named_token(
        self, *, file_present: bool = True, session: str = SESSION
    ) -> list[str]:
        if file_present:
            loaded = list(STORE_CONTENTS)
        else:
            # The file is missing; instead of stopping,
            # the agent prints the shell environment --
            # every secret the machine holds.
            loaded = list(STORE_CONTENTS)
        self.accessed.extend(loaded)
        self.accessed_records.extend(
            access_record(session, name) for name in loaded
        )
        return loaded


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class NordLayerAiScoutIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.store = SecretStore()

    def _kernel(self) -> GovernanceKernel:
        policy = Policy(
            frozenset({"read_secret"}),
            10_000,
            frozenset({"read_secret"}),
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

    def test_positive_control_named_fetch_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, FETCH_INTENT)
        # The one legitimate act: fetch the one named
        # token under a genuine, well-formed verified
        # approval.
        self.assertTrue(self.store.read(self.kernel, permit, FETCH_INTENT))
        self.assertEqual([GITLAB_TOKEN], self.store.accessed)
        # The same permit cannot fetch it twice -- an
        # approved fetch is not a standing read of the
        # store.
        self.assertFalse(self.store.read(self.kernel, permit, FETCH_INTENT))
        self.assertEqual([GITLAB_TOKEN], self.store.accessed)
        # Reconciliation: what was accessed is exactly
        # what was approved, per occurrence.
        result = reconcile_access(
            [access_record(SESSION, GITLAB_TOKEN)], self.store.accessed_records
        )
        self.assertEqual(
            {"approved_count": 1, "accessed_count": 1, "over_read_count": 0,
             "over_read": [], "over_read_records": [], "ok": True},
            result,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all ----------------------------------------

    def test_step1_no_approval_at_all_denied(self) -> None:
        # The kernel declines to mint: no approval
        # envelope exists for the fetch, and the project
        # instructions pointing at the token are not one.
        decision = self.kernel.evaluate(FETCH_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.store.read(self.kernel, decision.permit, FETCH_INTENT))
        self.assertEqual([], self.store.accessed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the whole-file read under the single-secret approval -------
    #
    # The incident's core act. The approval is genuine in
    # every field -- authority, verifier, key, session,
    # principal, policy, timing -- and it approves the
    # fetch of ONE named secret. Presented for the
    # whole-file read, the only check that can deny the
    # attempt is the exact-intent binding itself: the
    # envelope's intent hash is the fetch's, not the
    # file's. AUTHORIZED_OUTCOME (the token, in hand) !=
    # AUTHORIZATION_FOR_ARBITRARY_MEANS (the file it
    # lives in).

    def test_step2_whole_file_read_under_single_secret_approval_denied(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            FETCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-fetch",
            nonce="nonce-fetch",
        )
        decision = self.kernel.evaluate_with_approval(WHOLE_FILE_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.store.read(self.kernel, decision.permit, WHOLE_FILE_INTENT))
        self.assertEqual([], self.store.accessed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the shell-environment dump under the same approval ---------

    def test_step3_shell_environment_dump_denied_file_present_or_missing(self) -> None:
        # The incident's fallback: the file was missing
        # from a fresh copy of the project, and the agent
        # printed the shell environment instead of
        # stopping. On the governed path the fallback is
        # an intent of its own, broader than the file read,
        # and the single-secret approval no more covers it
        # than it covers the file -- whether the file is
        # present (the dump as an alternative route) or
        # missing (the dump as the fallback).
        envelope = signed_envelope(
            self.kernel,
            FETCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-fetch-env",
            nonce="nonce-fetch-env",
        )
        for _ in range(2):
            decision = self.kernel.evaluate_with_approval(SHELL_ENV_INTENT, envelope)
            self.assertEqual(
                ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.store.read(self.kernel, decision.permit, SHELL_ENV_INTENT))
        self.assertEqual([], self.store.accessed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(2, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: repetition -- spent permit and cross-session replay --------
    #
    # The incident's duration came from repetition: the
    # same over-read, session after session, for three
    # weeks. Two bindings close repetition on the governed
    # path. A permit is single-use: once the approved
    # fetch has executed, re-presenting the permit spends
    # nothing more. And an approval is bound to its
    # session: the session-1 envelope presented for the
    # same fetch proposed in a later session is refused
    # before it can mint -- a later session needs its own
    # approval, it does not inherit an earlier one.

    def test_step4_replay_spent_permit_and_cross_session_denied(self) -> None:
        permit = self._issue_permit(
            self.kernel, FETCH_INTENT, approval_id="approval-s1", nonce="nonce-s1"
        )
        self.assertTrue(self.store.read(self.kernel, permit, FETCH_INTENT))
        # Re-presentation of the spent permit, in its own
        # session and in a later one: refused at consume
        # both times.
        self.assertFalse(self.store.read(self.kernel, permit, FETCH_INTENT))
        self.assertFalse(self.store.read(self.kernel, permit, LATER_SESSION_INTENT))
        # The session-1 approval envelope carried into a
        # later session for the identical fetch: refused
        # as a session mismatch, minting nothing.
        envelope = signed_envelope(
            self.kernel,
            FETCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-s1-env",
            nonce="nonce-s1-env",
        )
        decision = self.kernel.evaluate_with_approval(LATER_SESSION_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_session_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([GITLAB_TOKEN], self.store.accessed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        result = reconcile_access(
            [access_record(SESSION, GITLAB_TOKEN)], self.store.accessed_records
        )
        self.assertTrue(result["ok"])
        self.assertEqual(0, result["over_read_count"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: substitution and forgery ------------------------------------

    def test_step5_substituted_and_forged_approvals_denied(self) -> None:
        # (a) A genuine approval for a DIFFERENT single
        # secret, presented for the named fetch: real
        # authority for one secret is not authority for
        # another, however similar the acts look.
        other_envelope = signed_envelope(
            self.kernel,
            OTHER_SECRET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-other",
            nonce="nonce-other",
        )
        decision = self.kernel.evaluate_with_approval(FETCH_INTENT, other_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) An envelope for the named fetch signed with
        # an unauthorized key: whoever holds the file
        # cannot mint the store's authority.
        forged_envelope = signed_envelope(
            self.kernel, FETCH_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW,
            approval_id="approval-forged", nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(FETCH_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.store.accessed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_intent_mismatch", "approval_signature_invalid"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine
        # pair still admits.
        permit = self._issue_permit(
            self.kernel, FETCH_INTENT, approval_id="approval-real", nonce="nonce-real"
        )
        self.assertTrue(self.store.read(self.kernel, permit, FETCH_INTENT))
        self.assertEqual([GITLAB_TOKEN], self.store.accessed)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation over the governed sequence -------------------
    #
    # The incident ran three weeks because nothing
    # compared what the agent accessed with what it was
    # asked for. This step runs that comparison over a
    # governed sequence shaped like the incident's first
    # session: one approved fetch, then the whole-file
    # read and the shell-environment dump each attempted
    # under that approval. Every over-read attempt is
    # denied, so the accessed log stays exactly the
    # approved fetch and reconciliation reports equality
    # -- zero over-read occurrences, not merely "the file
    # was touched." The same reconciliation applied to
    # the incident's reported shape is pinned in the
    # negative control, where it reports the over-read
    # counts the governed path never produces.

    def test_step6_reconciliation_governed_sequence_zero_over_read(self) -> None:
        permit = self._issue_permit(
            self.kernel, FETCH_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertTrue(self.store.read(self.kernel, permit, FETCH_INTENT))
        envelope = signed_envelope(
            self.kernel,
            FETCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-rec-env",
            nonce="nonce-rec-env",
        )
        for intent in (WHOLE_FILE_INTENT, SHELL_ENV_INTENT, WHOLE_FILE_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual("deny", decision.outcome)
            self.assertFalse(self.store.read(self.kernel, decision.permit, intent))
        result = reconcile_access(
            [access_record(SESSION, GITLAB_TOKEN)], self.store.accessed_records
        )
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(1, result["accessed_count"])
        self.assertEqual(0, result["over_read_count"])
        self.assertEqual([], result["over_read"])
        self.assertTrue(result["ok"])
        self.assertEqual(3, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6b: reconciliation preserves session boundaries ----------------
    #
    # Regression for the Codex finding on PR #409: the
    # earlier reconciliation took flattened secret names
    # and kept one global per-name counter, so an
    # approval in one session could consume an excess
    # access in another whenever the aggregate counts
    # matched. The counterexample below is exact:
    # session A is authorized 1 access and observes 2;
    # session B is authorized 1 and observes 0; the
    # aggregate totals are equal (2 = 2), yet session A
    # overreached and reconciliation must say so.

    def test_step6b_reconciliation_cross_session_aggregate_does_not_mask_overreach(self) -> None:
        session_a = "session-a"
        session_b = "session-b"
        approved = [
            access_record(session_a, GITLAB_TOKEN),
            access_record(session_b, GITLAB_TOKEN),
        ]
        accessed = [
            access_record(session_a, GITLAB_TOKEN),
            access_record(session_a, GITLAB_TOKEN),
        ]
        result = reconcile_access(approved, accessed)
        self.assertEqual(2, result["approved_count"])
        self.assertEqual(2, result["accessed_count"])
        self.assertEqual(1, result["over_read_count"])
        self.assertEqual([GITLAB_TOKEN], result["over_read"])
        self.assertEqual(
            [access_record(session_a, GITLAB_TOKEN)], result["over_read_records"]
        )
        self.assertFalse(result["ok"])
        # Action identity is part of the boundary too:
        # the same secret in the same session under a
        # different action is not covered by the read
        # approval.
        result = reconcile_access(
            [access_record(session_a, GITLAB_TOKEN)],
            [access_record(session_a, GITLAB_TOKEN, action="export_secret")],
        )
        self.assertEqual(1, result["over_read_count"])
        self.assertFalse(result["ok"])
        # The honest cross-session path still reconciles
        # clean: one authorized access in each session,
        # observed exactly once in each.
        honest_accessed = [
            access_record(session_a, GITLAB_TOKEN),
            access_record(session_b, GITLAB_TOKEN),
        ]
        result = reconcile_access(approved, honest_accessed)
        self.assertEqual(0, result["over_read_count"])
        self.assertEqual([], result["over_read_records"])
        self.assertTrue(result["ok"])

    # -- step 7: the incident channel sees the attempts ----------------------
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

    def test_step7_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(FETCH_INTENT)
        envelope = signed_envelope(
            self.kernel,
            FETCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-fetch",
            nonce="nonce-seq-fetch",
        )
        for intent in (WHOLE_FILE_INTENT, SHELL_ENV_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_intent_mismatch", decision.reason)
        other_envelope = signed_envelope(
            self.kernel,
            OTHER_SECRET_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-other",
            nonce="nonce-seq-other",
        )
        decision = self.kernel.evaluate_with_approval(FETCH_INTENT, other_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate fetch still lands; the
        # over-reads did not.
        permit = self._issue_permit(
            self.kernel, FETCH_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.store.read(self.kernel, permit, FETCH_INTENT))
        self.assertEqual([GITLAB_TOKEN], self.store.accessed)
        # The spent permit re-presented: the incident's
        # repetition, refused.
        self.assertFalse(self.store.read(self.kernel, permit, FETCH_INTENT))
        self.assertEqual([GITLAB_TOKEN], self.store.accessed)

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
        self.assertEqual(1, len(permit_rejected))
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

    def test_negative_control_ungoverned_agent_over_reads(self) -> None:
        # Same task, no governor: the agent is told to
        # fetch the one named token and does it the
        # incident's way -- by loading the whole file.
        # The token arrives (the outcome is "correct"),
        # and so does everything else in the file. That is
        # the incident, reproduced at the exact layer it
        # happened: not the store, not the token -- the
        # absence of an intent boundary between the named
        # fetch and the container that holds it.
        agent = UngovernedAgent()
        loaded = agent.fetch_named_token()
        self.assertIn(GITLAB_TOKEN, loaded)
        self.assertEqual(list(STORE_CONTENTS), loaded)
        # Per-occurrence reconciliation of the very first
        # load already surfaces the over-read, by count
        # and by name -- the check whose absence let the
        # incident run for weeks.
        result = reconcile_access([access_record(SESSION, GITLAB_TOKEN)], agent.accessed_records)
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(4, result["accessed_count"])
        self.assertEqual(3, result["over_read_count"])
        self.assertEqual(
            ["admin-tool-production-password", "hr-system-api-token", "bi-client-secret"],
            result["over_read"],
        )
        self.assertFalse(result["ok"])
        # The incident's fallback, ungoverned: the file is
        # missing, and instead of stopping the agent dumps
        # the shell environment -- the same full exposure
        # by the other route.
        fallback = UngovernedAgent()
        loaded = fallback.fetch_named_token(file_present=False)
        self.assertEqual(list(STORE_CONTENTS), loaded)
        result = reconcile_access(
            [access_record(SESSION, GITLAB_TOKEN)], fallback.accessed_records
        )
        self.assertEqual(3, result["over_read_count"])
        self.assertFalse(result["ok"])
        # The incident's full reported shape: the load
        # repeated across 10 sessions. Approved across the
        # whole run: the one named token, once per session.
        # Accessed: the whole file, every session.
        # Reconciliation reports the repetition exactly --
        # 30 over-read occurrences -- where a
        # presence-only check would report only that the
        # file "was accessed."
        repeater = UngovernedAgent()
        repeater_sessions = [f"mr-review-session-{i}" for i in range(1, 11)]
        for session in repeater_sessions:
            repeater.fetch_named_token(session=session)
        result = reconcile_access(
            [access_record(session, GITLAB_TOKEN) for session in repeater_sessions],
            repeater.accessed_records,
        )
        self.assertEqual(10, result["approved_count"])
        self.assertEqual(40, result["accessed_count"])
        self.assertEqual(30, result["over_read_count"])
        self.assertFalse(result["ok"])
        # Contrast, the identical task on the governed
        # path: the named fetch executes, the whole-file
        # read under its approval is denied (step 2's
        # route), and reconciliation reports zero
        # over-read.
        envelope = signed_envelope(
            self.kernel,
            FETCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(WHOLE_FILE_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)


if __name__ == "__main__":
    unittest.main()
