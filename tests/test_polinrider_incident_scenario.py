"""Scenario test: the Polinrider GitHub-repo Python loader wave
(publicized 2026-11-24; SafeDep analysis).

Incident (Recorded, from SafeDep's analysis, "Polinrider:
Python Loader Delivered via Ethereum Calldata," 2026-11-24;
first reported the same day by Jay Maier in issue #96 of
meSingh/polinrider-scanner): a 58-line Python loader was
planted across 375 GitHub repositories and accounts, hidden
in ``utils`` packages or in a root ``conftest.py`` -- files
that Python tooling imports automatically. On import, the
loader reads the newest self-sent transaction from the
Ethereum wallet
``0x3b1574417524c11a7403c4b232CAcBb320CceBC6``, hex-decodes
the transaction's input data as JavaScript, and executes it
via Node.js (build 4, marker ``A9-10502``). The JavaScript
pulls a command-and-control server at 95.135.181.84 and
spawns an interactive ``node -i`` shell. The planting
commits were forged, including fake "removal" commits --
history rewritten to claim the loader was gone. Grades:
the wave's shape and mechanism are Recorded from SafeDep's
primary analysis; no confirmed victim count exists, and
the operator behind the wallet is Unknown.

The failure is trusted-path execution: code ran because
the channel it arrived through was trusted, not because
the specific act was authorized. A ``conftest.py`` import
is a loading mechanism, not an approval:
``TRUSTED_IMPORT_CHANNEL != AUTHORIZATION_FOR_THE_ACT``.
Nothing in the path asked whether *this* execution -- of
*this* remotely fetched payload, on *this* machine -- was
authorized by anyone; the import itself was treated as the
authority. The forged commits are the same failure pointed
at the record: repository state (history) claimed acts
happened and were undone with no provenance behind either
claim -- state is evidence, state is not provenance, and
provenance is not authority.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the loader, the payload,
any blockchain read, any network behavior, or any real
repository. The "runner" is this harness holding intents;
the only route from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash. The import channel itself -- the fact that a
``conftest.py`` or ``utils`` package was imported -- is
modeled as exactly what it is in Pulpo's terms: it is not
an approval envelope, not ceremony evidence, and not a
permit, and the kernel has no verb that derives consequence
authority from a file having been loaded.

Setup: the runner holds exactly one legitimate permit: one
exact act -- the project's own pinned Node build-check
step, the act the repository maintainer actually
authorized -- issued through a verified approval envelope.
The incident's acts are then attempted, in sequence:
executing the remotely fetched payload (the same action
class as the legitimate build step, aimed at a resource no
one approved), spawning the interactive shell against the
command server, and the permitted build step re-presented
with the payload appended to its resource identity. The
kernel must deny each one, the consequence ledger must stay
empty for all of them, and every denial must land in the
audit record. Step 6 then reconciles the forged history:
the attacker's rewritten history claims a clean record
(the legitimate build, a "removal" that never passed the
kernel, and no attempts at all), and reconciliation against
the audit flags both directions of the forgery -- attempts
the history hides, and a consequence the history invents.
Reconciliation compares occurrence counts per intent hash,
not mere presence, so a history cannot pass by listing a
repeated act once (step 6b).

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
proves nothing about the real repositories, the real
operator, or any real import path that does not route its
consequential acts through this kernel, and it claims
nothing about the real wave beyond the graded narrative
above. A control not on the execution path governs
nothing -- and an import hook is an execution path.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence is
permitted, and any non-kernel import path (the incident's
own class) remains outside this evidence and open.

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


NOW = 1_000_000
RUNNER = "agent:ci-runner"
MAINTAINER = "operator:repo-maintainer"
SESSION = "import-session-2026-11-24"
ACTIONS = frozenset(
    {"execute_process", "spawn_interactive_shell", "remove_file"}
)

# The one act actually authorized: the project's own pinned
# Node build-check step -- a reviewed, fixed script, the act
# the repository maintainer actually approved, and nothing
# else. The resource identity names the exact pinned step;
# every act beyond it is a different resource or a different
# action and therefore a different intent.
BUILD_RESOURCE = "repo:ci/pinned/node-build-check"
BUILD_INTENT = Intent(RUNNER, "execute_process", BUILD_RESOURCE, 25, SESSION)

# The incident's acts. None of them has an approval; each
# ran in the incident because the import channel was
# trusted. The payload execution is deliberately the SAME
# action class as the authorized build step -- executing a
# process via Node -- aimed at a resource nobody approved:
# code fetched from a blockchain transaction, decoded at
# import time. Same verb, different intent.
PAYLOAD_RESOURCE = (
    "payload:eth-calldata/0x3b1574417524c11a7403c4b232cacebc6/latest"
)
PAYLOAD_INTENT = Intent(
    RUNNER, "execute_process", PAYLOAD_RESOURCE, 25, SESSION
)
SHELL_INTENT = Intent(
    RUNNER,
    "spawn_interactive_shell",
    "c2:95.135.181.84/node-interactive",
    25,
    SESSION,
)
# The permitted build step re-presented with the payload
# appended -- the incident's implicit claim, that the
# channel's trust in the build covered whatever the import
# brought with it. The widening rides in the resource
# identity, inside the hashed intent, so it cannot pass as
# the approved build step.
WIDENED_INTENT = Intent(
    RUNNER,
    "execute_process",
    "repo:ci/pinned/node-build-check/and-payload-eth-calldata-latest",
    25,
    SESSION,
)
# The forged "removal": the rewritten history claims the
# loader was removed. No such act was ever presented to the
# kernel, let alone consumed -- it exists only as a claim,
# which is exactly what step 6 reconciles.
REMOVAL_INTENT = Intent(
    RUNNER,
    "remove_file",
    "repo:target/conftest.py/polinrider-loader",
    25,
    SESSION,
)
ATTACK_INTENTS = (PAYLOAD_INTENT, SHELL_INTENT, WIDENED_INTENT)

# The import channel itself, presented as if it were a
# permit: the marker string the loader carried (build 4,
# A9-10502) together with the channel that delivered it.
# The file was imported, so the code ran -- that is the
# incident's whole authorization theory. The kernel must
# treat this string as a fabricated token, because that is
# what it is.
CHANNEL_TOKEN = (
    "conftest.py-import-hook:"
    "0x3b1574417524c11a7403c4b232cacebc6:A9-10502"
)


class ConsequenceLedger:
    """Effects on the host, reachable only through a successful consume.

    This is the scenario's execution path: the harness
    executes an action (records its consequence) only when
    the kernel consumes a permit for that exact intent. A
    denial is therefore directly observable as the absence
    of a governed external consequence, not merely as a
    returned status. (The denial itself still appends an
    audit record -- a governed effect, classified
    separately in the module docstring.)
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

    Its consume ignores the intent binding: any issued,
    unspent permit spends for any intent. It exists only
    to prove the scenario's denial assertions discriminate
    -- under this double the payload execution must
    EXECUTE, or the scenario would be denying by
    construction rather than by the kernel's binding.
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
    token-to-intent binding -- and delegates straight to
    the state. Paired with the intent-blind state double
    above, no layer binds the permit to the presented
    intent, so the payload execution must EXECUTE here, or
    the scenario's denials would be coming from the
    harness rather than from the binding layers. This is
    the incident's own shape: an import path that executes
    whatever it loads, because the channel was trusted.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


# -- test-level reconciliation ------------------------------------------------
#
# Compared occurrence counts (multisets), defined once and used for the
# kernel audit throughout:
#   consequences  — steps that executed (audit: permit_consumed records)
#   attempts      — runner steps that did NOT execute and must be disclosed
#                   (audit: permit_rejected records, plus decision records
#                   with outcome require_approval / deny)
# Counts, not mere presence: an intent attempted three times, or executed
# twice under separately issued permits, contributes that many occurrences,
# and a claim reconciles only if it reports the same count for every hash.
# A presence-only (set) comparison would collapse repeats to one and let a
# claim underreport repeated activity while still returning ok -- the
# failure the Codex review of this module identified, and the one step 6b
# pins shut.
# Authorization-side records (approval_verified, allow decisions) are the
# authority's own trail, not runner steps, and are excluded by design.
# This reconciliation is TEST-LEVEL, implemented against the public
# ``kernel.audit`` read path, as in the filename-deception and Mythos
# scenarios: the shipped reconcilers reconcile filesystem effects and
# custody-domain outcomes, not a claimed history against the kernel
# audit trail.


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
    # Deriving sets from an invalid chain would accept fabricated
    # provenance — the exact failure this scenario exists to expose.
    try:
        audit_valid = kernel.verify_audit()
    except Exception:
        audit_valid = False
    consequences, attempts = audited_counts(kernel.audit)
    # The claim's lists carry multiplicity by repetition: a hash listed
    # twice claims two occurrences. Compare counts per hash, so a claim
    # that lists a repeated hash only once underreports it and fails.
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


class PolinriderIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
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
            secret=b"polinrider-scenario-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
        )

    def _issue_build_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, BUILD_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(BUILD_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    def _issue_second_build_permit(self, kernel: GovernanceKernel) -> str:
        # A second, separately approved issuance for the same
        # build intent, carrying its own approval_id and
        # nonce as a second real approval would: the
        # helper's fixed defaults would collide with the
        # first issuance and be denied as an approval replay.
        envelope = signed_envelope(
            kernel,
            BUILD_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-2",
            nonce="nonce-2",
        )
        decision = kernel.evaluate_with_approval(BUILD_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_build_executes_exactly_once(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same build step
        # twice -- a build authorization is not a standing
        # one, and the import channel re-firing changes
        # nothing.
        self.assertFalse(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the payload execution has no permit ------------------------

    def test_step1_payload_execution_denied_channel_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for executing the fetched payload, and the
        # import channel's trust is not one. The payload is
        # a separate consequential act from any act the
        # channel legitimately carries.
        decision = self.kernel.evaluate(PAYLOAD_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, PAYLOAD_INTENT))
        # The harness presents the import channel itself as
        # the permit: the file was in conftest.py, Python
        # imported it, so the code runs. The kernel treats
        # it as what it is: a fabricated token. Reach
        # existed in the incident; authority for this act
        # did not.
        self.assertFalse(self.ledger.execute(self.kernel, CHANNEL_TOKEN, PAYLOAD_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(PAYLOAD_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the payload and the shell under the genuine permit ----------

    def test_step2_payload_and_shell_with_build_permit_denied(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        # The incident's acts: executing the decoded payload,
        # and the interactive shell it spawns against the
        # command server. A different resource, and a
        # different action against a different resource, are
        # different intents, and the one permit the runner
        # holds binds the pinned build step exactly.
        self.assertFalse(self.ledger.execute(self.kernel, permit, PAYLOAD_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, SHELL_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(PAYLOAD_INTENT),
                self.kernel.intent_hash(SHELL_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit
        # still spends on the exact build step it was issued
        # for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the widened build -------------------------------------------

    def test_step3_widened_build_denied(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        # The permitted build step re-presented with the
        # payload appended to its resource identity -- the
        # incident's core claim, that the channel's trust in
        # the build step covered whatever the import
        # delivered alongside it. The widening is inside the
        # hashed intent, so it cannot pass as the approved
        # build.
        self.assertFalse(self.ledger.execute(self.kernel, permit, WIDENED_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(WIDENED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial did not burn the permit: the exact
        # approved build step still spends.
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing ---------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        # A consumed permit is not a reusable channel
        # credential: re-presenting it for the same build
        # step gets nothing -- an import that fires twice
        # authorizes nothing the second time -- and
        # re-presenting it for the payload execution gets
        # nothing either.
        self.assertFalse(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, PAYLOAD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ---------------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, BUILD_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the payload execution signed
        # with an unauthorized key: whoever planted the
        # loader cannot mint the maintainer's authority.
        forged_envelope = signed_envelope(
            self.kernel, PAYLOAD_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(PAYLOAD_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine build envelope presented for the
        # payload intent: a real approval for one act is
        # not approval for the act the import delivered
        # under it.
        decision = self.kernel.evaluate_with_approval(PAYLOAD_INTENT, genuine_envelope)
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
        decision = self.kernel.evaluate_with_approval(BUILD_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation -- the forged history ---------------------------
    #
    # The incident's second failure: the planting commits
    # were forged, including fake "removal" commits, so the
    # repository's own history -- its visible state --
    # claims a clean record. Reconciliation compares that
    # claimed history against the canonical audit in both
    # directions: a claim is no more free to hide attempts
    # than it is to invent consequences. State is evidence;
    # state is not provenance.

    def test_step6_reconciliation_exposes_forged_history(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        # The governed record: the payload attempt rejected
        # at consume, the shell attempt declined at
        # evaluate, and the one legitimate build executed.
        self.assertFalse(self.ledger.execute(self.kernel, permit, PAYLOAD_INTENT))
        decision = self.kernel.evaluate(SHELL_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)

        build_hash = self.kernel.intent_hash(BUILD_INTENT)
        payload_hash = self.kernel.intent_hash(PAYLOAD_INTENT)
        shell_hash = self.kernel.intent_hash(SHELL_INTENT)
        removal_hash = self.kernel.intent_hash(REMOVAL_INTENT)
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({build_hash: 1}, dict(consequences))
        self.assertEqual({payload_hash: 1, shell_hash: 1}, dict(attempts))

        # The history as the forged commits present it: the
        # clean build, a "removal" of the loader -- and
        # nothing else. No payload ever ran; nothing was
        # ever attempted. The record flags both halves of
        # the forgery: the attempts the history hides, and
        # the removal it invents, an act that never passed
        # the kernel and has no provenance behind it.
        forged_claim = {
            "consequences": sorted([build_hash, removal_hash]),
            "attempts": [],
        }
        result = reconcile_against_audit(self.kernel, forged_claim)
        self.assertFalse(result.ok)
        self.assertTrue(result.audit_valid)
        self.assertEqual({payload_hash, shell_hash}, set(result.undisclosed_attempts))
        self.assertEqual({removal_hash}, set(result.unbacked_consequences))
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

        # Reconciliation is not a trap: a history that
        # DISCLOSES the attempts alongside the genuine
        # consequence -- and claims no removal that never
        # happened -- reconciles exactly.
        honest_claim = {
            "consequences": sorted([build_hash]),
            "attempts": sorted([payload_hash, shell_hash]),
        }
        honest = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(honest.ok)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6b: reconciliation preserves multiplicity -------------------------
    #
    # The wave did not strike once per repository: the same
    # loader fired on every import, and a maintainer may
    # legitimately run the approved build more than once
    # under separately issued permits. Reconciliation must
    # therefore compare occurrence counts, not mere
    # presence: a history that lists a thrice-attempted
    # intent once, or a twice-executed build once, is
    # underreporting the record and must fail -- in both
    # directions, since overreporting is the same forgery
    # with the sign flipped.

    def test_step6b_reconciliation_preserves_multiplicity(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        second_permit = self._issue_second_build_permit(self.kernel)
        # The payload attempted three times on the channel
        # route: three rejections, one intent hash.
        for _ in range(3):
            self.assertFalse(
                self.ledger.execute(self.kernel, CHANNEL_TOKEN, PAYLOAD_INTENT)
            )
        # The approved build executed twice, once under each
        # separately issued permit: two consumptions, one
        # intent hash.
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertTrue(self.ledger.execute(self.kernel, second_permit, BUILD_INTENT))
        self.assertEqual(
            [("execute_process", BUILD_RESOURCE)] * 2, self.ledger.effects
        )

        build_hash = self.kernel.intent_hash(BUILD_INTENT)
        payload_hash = self.kernel.intent_hash(PAYLOAD_INTENT)
        consequences, attempts = audited_counts(self.kernel.audit)
        self.assertEqual({build_hash: 2}, dict(consequences))
        self.assertEqual({payload_hash: 3}, dict(attempts))

        # A history that collapses each repeated hash to a
        # single listing underreports both the attempts and
        # the consequences, and fails on exactly those two
        # hashes.
        collapsed_claim = {
            "consequences": [build_hash],
            "attempts": [payload_hash],
        }
        collapsed = reconcile_against_audit(self.kernel, collapsed_claim)
        self.assertFalse(collapsed.ok)
        self.assertTrue(collapsed.audit_valid)
        self.assertEqual({payload_hash}, set(collapsed.undisclosed_attempts))
        self.assertEqual({build_hash}, set(collapsed.missing_consequences))
        self.assertEqual(frozenset(), collapsed.unbacked_consequences)
        self.assertEqual(frozenset(), collapsed.phantom_attempts)

        # The same history with multiplicity reported
        # honestly -- each hash listed once per occurrence --
        # reconciles exactly.
        full_claim = {
            "consequences": [build_hash, build_hash],
            "attempts": [payload_hash, payload_hash, payload_hash],
        }
        self.assertTrue(reconcile_against_audit(self.kernel, full_claim).ok)

        # Overreporting is forgery too: a fourth claimed
        # attempt is phantom, a third claimed execution is
        # unbacked, and each fails on its own hash.
        inflated_attempts = {
            "consequences": [build_hash, build_hash],
            "attempts": [payload_hash] * 4,
        }
        inflated_a = reconcile_against_audit(self.kernel, inflated_attempts)
        self.assertFalse(inflated_a.ok)
        self.assertEqual({payload_hash}, set(inflated_a.phantom_attempts))
        inflated_consequences = {
            "consequences": [build_hash] * 3,
            "attempts": [payload_hash] * 3,
        }
        inflated_c = reconcile_against_audit(self.kernel, inflated_consequences)
        self.assertFalse(inflated_c.ok)
        self.assertEqual({build_hash}, set(inflated_c.unbacked_consequences))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the wave ------------------------------
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
    # The frozen sequence below is the full attempt
    # sequence of steps 1-5, not a subset: every attack act
    # on every route (steps 1-3), the spent-permit replays
    # (step 4, replayed after the one legitimate execution
    # below), and both approval-envelope attempts -- the
    # forged envelope and the genuine envelope presented
    # for the wrong intent (step 5). The report assertions
    # therefore cover every attack variant the scenario
    # exercises. (Step 6's reconciliation runs on its own
    # sequence and is pinned there.)

    def test_step7_incident_channel_surfaces_the_wave(self) -> None:
        permit = self._issue_build_permit(self.kernel)
        # The wave, compressed: each attack act attempted on
        # every route the harness has -- its own say-so, the
        # channel token, and the one genuine permit.
        for intent in ATTACK_INTENTS:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(CHANNEL_TOKEN, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        # Each envelope in this compressed sequence carries
        # its own approval_id and nonce, as each real
        # approval would: the helper's fixed defaults would
        # collide with the permit issuance above and turn
        # the forgery denial below into a replay denial,
        # misattributing the control that rejected it.
        forged_envelope = signed_envelope(
            self.kernel,
            PAYLOAD_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(PAYLOAD_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the
        # genuine build envelope presented for the payload
        # intent. A real approval for one act is not
        # approval for another; the decision is a denial
        # and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            BUILD_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(PAYLOAD_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate build step still executes; the
        # wave did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, BUILD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for
        # the same build step and for the payload execution.
        # A consumed permit is not a reusable channel
        # credential; both re-presentations are rejected at
        # consume.
        self.assertFalse(self.kernel.consume(permit, BUILD_INTENT))
        self.assertFalse(self.kernel.consume(permit, PAYLOAD_INTENT))
        self.assertEqual([("execute_process", BUILD_RESOURCE)], self.ledger.effects)

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
        self.assertEqual(8, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(3, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The three require_approval decisions above
        # are audit-recorded attempts that contribute zero
        # near-miss records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(12, report.near_misses)
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

    # -- negative control -----------------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers --
        # a kernel double whose consume skips token
        # authentication and the kernel's token-to-intent
        # binding, over a state double whose consume ignores
        # the store's binding: the payload execution
        # EXECUTES under the build permit. That is the
        # incident's own shape -- an import path that
        # executes whatever it loads because the channel was
        # trusted. The denials in the steps above therefore
        # come from the real consume path's binding checks,
        # not from a harness that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_build_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, PAYLOAD_INTENT))
        self.assertEqual(
            [("execute_process", PAYLOAD_INTENT.resource)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route, here with the payload
        # execution).
        real_permit = self._issue_build_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, PAYLOAD_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()
