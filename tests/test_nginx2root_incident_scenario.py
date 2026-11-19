"""Scenario test: the November 2026 NGINX2Root agent-driven vulnerability
research failure mode, modeled against the canonical kernel API.

Incident (Recorded, from F5's published security advisories and the
disclosing teams' write-ups, 2026-11-18): five memory-safety flaws in
NGINX (CVE-2026-123007, CVE-2026-123633, CVE-2026-121810,
CVE-2026-123634, CVE-2026-113425), each rated CVSS 4.0 9.2, were
discovered independently by multiple research teams (Xint/Theori, Wiz,
Ikotas Labs, Metnir, Rapid7) using AI agents and automated
code-scanning harnesses; F5 shipped fixes in NGINX 1.30.7 / 1.31.9 the
same day. The defensive runs were authorized research on code the
teams were permitted to audit. The failure mode this scenario models
is the mirror image: the same agent capability, pointed at systems
outside the authorized scope — probing production servers it does not
own, continuing after its mandate is revoked, and reporting findings
its record cannot support. CVE-2026-123007 is wormable in principle:
one unauthorized act class that replicates is precisely the case
where revocation must bite at consume time, not at issue time.

This module does NOT reproduce NGINX, any exploit, or any scanner.
The "agent" is this harness holding intents; the only route from
intent to consequence is a successful ``GovernanceKernel.consume`` of
a permit bound to the exact intent hash.

Setup A (approval path): the research agent receives permits for
exactly three acts against a local checkout it is authorized to
audit — run an audit scan, probe the local target, and submit the
findings report (the ceremony-gated act: disclosure is the
accountable human step). The incident's acts are then attempted: a
probe of a production server under the local permit, replay of the
spent probe permit, a forged approval for the production probe, and
a findings report claiming a discovery from the production probe
that never executed.

Setup B (directive path): the research run operates under an active
directive scoped to the lab. A probe permit is issued under it; the
operator then revokes the directive mid-run (scope drift observed).
The previously issued, unconsumed permit must fail at consume with
the directive recorded as revoked — the kill switch for a runaway
research run.

Boundary: this proves kernel behavior at this commit for these
action classes (Verified, executable evidence). It proves nothing
about NGINX, exploitability, scanner quality, or non-governed paths:
an agent holding ambient network authority is governed by nothing
here, which is the incident's real lesson — a control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass review (Flip,
Reverse, Invert, Inside-Out, Darken, Lighten, Amplify, Negate) for
this incident is recorded in this scenario's pull request per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``. Stop/continue decision:
CONTINUE in the governed kernel path only — exactly the three
authorized consequences are permitted, and any non-kernel execution
path (the known direct-writer class) remains outside this evidence
and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): each denied attempt appends exactly one audit
record — a governed effect (evidence production), bounded at one
record per attempt, append-only, ``authority_effect=none``.
"Consequence" below means governed external consequence recorded in
the consequence ledger, never audit growth.
"""

from __future__ import annotations

import hashlib
import hmac
import unittest
from dataclasses import replace

from pulpo import (
    CeremonyEvidence,
    CeremonyTrust,
    GovernanceKernel,
    Intent,
    Policy,
)
from pulpo.directives import GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_directives import OPERATOR, directive


NOW = 3_000_000
AGENT = "agent:vuln-research"
SESSION = "nginx-audit-2026-11"

LOCAL = "lab:nginx-checkout-1.31.8"
PROD = "prod:nginx-public-server"
REPORT = "report:nginx2root-disclosure"

SCAN_INTENT = Intent(AGENT, "run_audit_scan", LOCAL, 0, SESSION)
PROBE_INTENT = Intent(AGENT, "probe_target", LOCAL, 0, SESSION)
SUBMIT_INTENT = Intent(AGENT, "submit_finding", REPORT, 0, SESSION)
PROBE_PROD_INTENT = Intent(AGENT, "probe_target", PROD, 0, SESSION)

ACTIONS = frozenset({"run_audit_scan", "probe_target", "submit_finding"})


class HmacCeremonyTestVerifier:
    """Test-only ceremony signer/verifier; never import this as a ceremony."""

    authority_id = "ceremony:test-owner"
    verifier_id = "ceremony-verifier:test-only"
    key_id = "ceremony-key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"pulpo-test-ceremony-key").hexdigest()

    def __init__(self, secret=b"external-test-ceremony"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def ceremony_trust_for(verifier, *, method="test-ceremony", max_evidence_ttl_ns=10_000):
    return CeremonyTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        method=method,
        max_evidence_ttl_ns=max_evidence_ttl_ns,
    )


def signed_evidence(kernel, intent, envelope, ceremony_verifier, *, now_ns, ttl_ns=1_000, signer=None, **changes):
    trust = kernel.policy.ceremony_trust
    values = {
        "evidence_id": "ceremony-evidence-1",
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "key_id": trust.key_id,
        "method": trust.method,
        "trust_hash": trust.trust_hash,
        "approval_id": envelope.approval_id,
        "envelope_hash": envelope.envelope_hash,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "principal": intent.principal,
        "session_id": intent.session_id,
        "approval_nonce": envelope.nonce,
        "issued_at_ns": now_ns,
        "expires_at_ns": now_ns + ttl_ns,
        "signature": "",
    }
    values.update(changes)
    unsigned = CeremonyEvidence(**values)
    return replace(unsigned, signature=(signer or ceremony_verifier).sign(unsigned.signing_bytes()))


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume."""

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
    """Deliberately unguarded double for the negative control (see the
    canonical incident scenarios): its consume ignores the intent
    binding, so the out-of-scope probe must EXECUTE under it, proving
    the scenario's denials come from the kernel's binding."""

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


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


def reconcile_findings(kernel: GovernanceKernel, claimed_probe_hashes: set[str]) -> dict:
    """Test-level reconciliation: a claimed finding is supported only
    by a consumed probe act in the audit record. A claim whose probe
    was denied — or never presented — is a phantom finding. Only
    consumed records for the scenario's probe_target intents count
    as support: consumed non-probe acts (the audit scan, the
    findings submission) never enter the evidence set, so a report
    cannot borrow their intent hashes to launder a finding."""
    probe_hashes = {
        kernel.intent_hash(PROBE_INTENT),
        kernel.intent_hash(PROBE_PROD_INTENT),
    }
    attempts = {
        record["payload"]["intent_hash"]
        for record in kernel.audit
        if record["event"] == "permit_consumed"
        and record["payload"]["intent_hash"] in probe_hashes
    }
    phantom = claimed_probe_hashes - attempts
    return {"ok": not phantom, "phantom_findings": phantom, "attempts": attempts}


class Nginx2RootApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.ceremony = HmacCeremonyTestVerifier()
        self.policy = Policy(
            ACTIONS,
            100,
            ACTIONS,
            authority_trust=trust_for(self.verifier),
            ceremony_actions=frozenset({"submit_finding"}),
            ceremony_trust=ceremony_trust_for(self.ceremony),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()

    def _kernel(self, state=None, *, kernel_class=GovernanceKernel) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret=b"nginx2root-scenario-kernel-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            ceremony_verifier=self.ceremony,
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
        if intent.action in self.policy.ceremony_actions:
            evidence = signed_evidence(kernel, intent, envelope, self.ceremony, now_ns=NOW)
            decision = kernel.evaluate_with_approval(intent, envelope, ceremony_evidence=evidence)
        else:
            decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit

    # -- positive control -------------------------------------------------

    def test_positive_control_authorized_research_executes_exactly_once(self) -> None:
        scan = self._issue(self.kernel, SCAN_INTENT)
        probe = self._issue(self.kernel, PROBE_INTENT)
        submit = self._issue(self.kernel, SUBMIT_INTENT)
        self.assertTrue(self.ledger.execute(self.kernel, scan, SCAN_INTENT))
        self.assertTrue(self.ledger.execute(self.kernel, probe, PROBE_INTENT))
        self.assertTrue(self.ledger.execute(self.kernel, submit, SUBMIT_INTENT))
        self.assertEqual(
            [
                ("run_audit_scan", LOCAL),
                ("probe_target", LOCAL),
                ("submit_finding", REPORT),
            ],
            self.ledger.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: scope escape — production probe under the local permit ---

    def test_step1_production_probe_under_local_permit_denied(self) -> None:
        probe = self._issue(self.kernel, PROBE_INTENT)
        self.assertFalse(self.ledger.execute(self.kernel, probe, PROBE_PROD_INTENT))
        self.assertEqual([], self.ledger.effects)
        # The denial consumed nothing: the genuine probe still spends.
        self.assertTrue(self.ledger.execute(self.kernel, probe, PROBE_INTENT))
        self.assertEqual([("probe_target", LOCAL)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: replay of the spent probe permit --------------------------

    def test_step2_replay_of_spent_probe_permit_denied(self) -> None:
        probe = self._issue(self.kernel, PROBE_INTENT)
        self.assertTrue(self.ledger.execute(self.kernel, probe, PROBE_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, probe, PROBE_INTENT))
        self.assertEqual([("probe_target", LOCAL)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: forged approval for the production probe ------------------

    def test_step3_forged_approval_for_production_probe_denied(self) -> None:
        attacker = HmacTestVerifier(b"attacker-authority-key")
        forged = signed_envelope(self.kernel, PROBE_PROD_INTENT, attacker, now_ns=NOW)
        decision = self.kernel.evaluate_with_approval(PROBE_PROD_INTENT, forged)
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)

    # -- step 4: phantom finding — a claimed discovery with no executed act

    def test_step4_phantom_finding_rejected_by_reconciliation(self) -> None:
        probe = self._issue(self.kernel, PROBE_INTENT)
        self.assertTrue(self.ledger.execute(self.kernel, probe, PROBE_INTENT))
        # The agent also tried the production probe and was denied.
        probe2 = self._issue(self.kernel, PROBE_INTENT)
        self.assertFalse(self.ledger.execute(self.kernel, probe2, PROBE_PROD_INTENT))

        honest = {self.kernel.intent_hash(PROBE_INTENT)}
        result = reconcile_findings(self.kernel, honest)
        self.assertTrue(result["ok"])

        claimed = honest | {self.kernel.intent_hash(PROBE_PROD_INTENT)}
        result = reconcile_findings(self.kernel, claimed)
        self.assertFalse(result["ok"])
        self.assertEqual(
            {self.kernel.intent_hash(PROBE_PROD_INTENT)}, result["phantom_findings"]
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4b: consumed non-probe acts are not probe evidence ----------

    def test_step4b_scan_and_submit_hashes_do_not_support_a_finding(self) -> None:
        scan = self._issue(self.kernel, SCAN_INTENT)
        probe = self._issue(self.kernel, PROBE_INTENT)
        submit = self._issue(self.kernel, SUBMIT_INTENT)
        self.assertTrue(self.ledger.execute(self.kernel, scan, SCAN_INTENT))
        self.assertTrue(self.ledger.execute(self.kernel, probe, PROBE_INTENT))
        self.assertTrue(self.ledger.execute(self.kernel, submit, SUBMIT_INTENT))

        # The honest probe claim still reconciles.
        honest = {self.kernel.intent_hash(PROBE_INTENT)}
        result = reconcile_findings(self.kernel, honest)
        self.assertTrue(result["ok"])

        # A hostile report borrowing the legitimately consumed scan
        # or submission hash as a "finding" reconciles nothing:
        # neither act was a probe, so each borrowed hash is flagged
        # as a phantom finding.
        for borrowed in (SCAN_INTENT, SUBMIT_INTENT):
            claimed = {self.kernel.intent_hash(borrowed)}
            result = reconcile_findings(self.kernel, claimed)
            self.assertFalse(result["ok"])
            self.assertEqual(claimed, result["phantom_findings"])
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ---------------------------------------------------

    def test_negative_control_unguarded_kernel_executes_production_probe(self) -> None:
        kernel = self._kernel(_IntentBlindState(), kernel_class=_UnguardedConsumeKernel)
        ledger = ConsequenceLedger()
        probe = self._issue(kernel, PROBE_INTENT)
        self.assertTrue(ledger.execute(kernel, probe, PROBE_PROD_INTENT))
        self.assertEqual([("probe_target", PROD)], ledger.effects)


class Nginx2RootRevocationTests(unittest.TestCase):
    """Setup B: revocation of the research run's directive kills a
    previously issued, unconsumed probe permit at consume time.

    The activation/revocation scaffolding mirrors
    DirectiveProofTests (tests/test_directives.py) by composition of
    the same public helpers, with the kernel policy's action set
    covering this scenario's action; it does not inherit that suite.
    """

    def _governed(self, state):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"probe_target", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"nginx2root-directive-scenario-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def _approve(self, kernel, verifier, operation, d, approval_id, nonce):
        from pulpo.directives import DirectiveAuthorityController

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
        from pulpo.directives import DirectiveAuthorityController

        kernel, verifier = self._governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self._approve(
            kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1"
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def test_revoked_directive_invalidates_issued_probe_permit(self) -> None:
        state = InMemoryKernelState()
        d = directive(
            directive_id="vuln-research-run",
            principal=AGENT,
            allowed_actions=frozenset({"probe_target"}),
            resource_prefixes=("lab:",),
            issued_at_ns=1_000_000,
            expires_at_ns=9_000_000,
        )
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(PROBE_INTENT, d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revoke_envelope = self._approve(
            kernel, verifier, controller.REVOKE, d, "revoke-1", "revoke-nonce-1"
        )
        revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", revoke.outcome)

        self.assertFalse(kernel.consume(decision.permit, PROBE_INTENT))
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])


if __name__ == "__main__":
    unittest.main()
