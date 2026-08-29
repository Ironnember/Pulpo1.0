#!/usr/bin/env python3
"""Executable Pulpo orchestrator boundary demo.

This deliberately uses the repository's HMAC test authority. It demonstrates
workflow semantics only; it is not evidence of deployed independent human
authority, protected storage, or production containment.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pulpo.authority_client import AuthorityPoll
from pulpo.directives import Directive, DirectiveAuthorityController
from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.orchestrator import PulpoOrchestrator
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 9_000_000
OPERATOR = "operator:owner"


class DemoAuthorityClient:
    def __init__(self, kernel, verifier):
        self.kernel = kernel
        self.verifier = verifier
        self.request = None
        self.polls = 0

    def request_approval(self, request):
        self.request = request
        return "demo-request", "https://authority.pulpo.ai/human/approval/demo-request"

    def poll_approval(self, request_id):
        assert request_id == "demo-request"
        assert self.request is not None
        self.polls += 1
        intent = Intent(
            self.request.principal,
            self.request.action,
            self.request.resource,
            self.request.cost,
            self.request.session_id,
        )
        envelope = signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW - 10,
            approval_id="approval-demo-target",
            nonce="nonce-demo-target",
        )
        return AuthorityPoll("approved", envelope)


def directive_envelope(kernel, verifier, operation, directive, approval_id, nonce):
    intent = DirectiveAuthorityController.authority_intent(
        operation,
        directive,
        operator_principal=OPERATOR,
    )
    return signed_envelope(
        kernel,
        intent,
        verifier,
        now_ns=NOW - 10,
        approval_id=approval_id,
        nonce=nonce,
    )


def main() -> None:
    state = InMemoryKernelState()
    verifier = HmacTestVerifier()
    policy = Policy(
        frozenset({"deploy", "write", "activate_directive", "revoke_directive"}),
        100,
        frozenset({"deploy", "activate_directive", "revoke_directive"}),
        authority_trust=trust_for(verifier),
    )
    kernel = GovernanceKernel(
        policy,
        secret=b"orchestrator-demo",
        approval_verifier=verifier,
        clock=lambda: NOW,
        state=state,
    )
    client = DemoAuthorityClient(kernel, verifier)
    orchestrator = PulpoOrchestrator(
        kernel,
        authority_client=client,
        directive_state=state,
        clock=lambda: NOW,
    )

    # Exact consequential target: tampered identity stops before external
    # authority is polled. Deploy is intentionally approval-gated here, while
    # directive-scoped write remains governed by the directive + kernel path.
    intent = Intent("agent:builder", "deploy", "repo:demo.txt", 1, "session:demo")
    target = orchestrator.lock_target("demo-deploy", intent)
    handle = orchestrator.request_target_approval(target, requested_ttl_ns=500)
    tampered = orchestrator.authorize_target(replace(handle, target_hash="0" * 64))
    assert tampered.resolution.reason == "target_hash_mismatch"
    assert client.polls == 0

    # Exact target: verified envelope reaches the kernel; capability is one-use.
    approved = orchestrator.authorize_target(handle)
    assert approved.decision is not None and approved.decision.outcome == "allow"
    first_consume = orchestrator.consume_authorized_target(approved)
    replay_consume = orchestrator.consume_authorized_target(approved)
    assert first_consume is True and replay_consume is False

    # Directive: activation needs separate authority; once active it constrains
    # an otherwise policy-allowed write. Revocation then invalidates the already
    # issued directive-bound permit at execution time.
    directive = Directive(
        directive_id="demo-directive",
        version=1,
        issuer_authority_id=verifier.authority_id,
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=NOW - 1_000,
        expires_at_ns=NOW + 10_000,
    )
    activation = directive_envelope(
        kernel,
        verifier,
        DirectiveAuthorityController.ACTIVATE,
        directive,
        "approval-demo-activate",
        "nonce-demo-activate",
    )
    assert orchestrator.activate_directive(
        directive,
        activation,
        operator_principal=OPERATOR,
    ).outcome == "allow"

    directive_intent = Intent("agent:builder", "write", "repo:directive.txt", 1)
    preissued = orchestrator.evaluate_directive(directive_intent, directive)
    assert preissued.outcome == "allow" and preissued.permit is not None

    revocation = directive_envelope(
        kernel,
        verifier,
        DirectiveAuthorityController.REVOKE,
        directive,
        "approval-demo-revoke",
        "nonce-demo-revoke",
    )
    assert orchestrator.revoke_directive(
        directive,
        revocation,
        operator_principal=OPERATOR,
    ).outcome == "allow"
    revoked_preissued_permit = kernel.consume(preissued.permit, directive_intent)
    assert revoked_preissued_permit is False

    evidence = orchestrator.evidence_snapshot()
    assert evidence.audit_valid is True
    print(
        json.dumps(
            {
                "schema": "pulpo.orchestrator-demo.result.v0",
                "target_mismatch_denied": tampered.resolution.reason,
                "authority_polls_after_tamper": 0,
                "exact_target_authorized": approved.decision.outcome,
                "first_permit_consume": first_consume,
                "replay_permit_consume": replay_consume,
                "revoked_preissued_directive_permit": revoked_preissued_permit,
                "audit_valid": evidence.audit_valid,
                "audit_records": evidence.audit_records,
                "audit_tip": evidence.audit_tip,
                "claim_boundary": (
                    "test-only authority semantics; no deployed independent authority, "
                    "protected storage, external containment, or production execution"
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
