"""Opt-in synthetic local inference probe. No provider effect or live Pulpo DB."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
import platform
import time

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import freeze_mcp_snapshot
from pulpo.ollama_proposal import LocalModel, project_local_proposal, request_local_proposal


def main():
    if not __debug__:
        raise RuntimeError("proof_requires_assertions_enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    model = LocalModel(args.model, args.digest)
    policy = Policy(frozenset({"read"}), 0, agent_grants=(
        AgentGrant("agent:local-fixture", frozenset({"read"}), ("repo:",), 0),))
    results = []
    for action, expected in (("read", "allow"), ("delete", "deny")):
        # Each fixture uses a fresh in-memory kernel; none is canonical state.
        kernel = GovernanceKernel(policy, secret=b"synthetic-probe-only", clock=lambda: 123456)
        snapshot = freeze_mcp_snapshot(PulpoOrchestrator(kernel))
        prompt = f"Propose action {action}, resource repo:synthetic-demo, cost 0. "
        prompt += "Return exactly the JSON object with action, resource, cost."
        started = time.monotonic()
        content = request_local_proposal(prompt, model)
        elapsed = time.monotonic() - started
        result = project_local_proposal(content, snapshot, principal="agent:local-fixture",
                                        session_id="synthetic-fixture", target_id="synthetic-fixture")
        assert kernel.audit == [], "inference or projection mutated fixture state"
        intent = Intent(**result["intent"])
        assert intent.action == action and intent.resource == "repo:synthetic-demo" and intent.cost == 0
        decision = kernel.evaluate(intent)
        assert decision.outcome == expected, (decision.outcome, expected)
        evidence = dict(action=action, elapsed_seconds=round(elapsed, 3), model_output=content,
                        model_output_sha256=sha256(content.encode()).hexdigest(),
                        proposal_nonmutating=True, synthetic_policy_outcome=decision.outcome,
                        external_provider_calls=0)
        if decision.permit:
            assert not kernel.consume(decision.permit, replace(intent, resource="repo:substituted"))
            assert kernel.consume(decision.permit, intent)
            assert not kernel.consume(decision.permit, intent)
            evidence.update(substitution_denied=True, valid_consumed_once=True, replay_denied=True)
        else:
            assert expected == "deny"
        results.append(evidence)
    print(json.dumps({"scope": "local-inference-and-synthetic-policy-only", "model": model.name,
                      "model_digest": model.digest, "python": platform.python_version(),
                      "machine": platform.machine(), "results": results,
                      "limits": ["No OS or daemon egress containment proof", "No real provider action",
                                 "Daemon metadata is trusted, not independently authenticated",
                                 "Not a canonical Ultra Gladiator tournament"]}, indent=2))


if __name__ == "__main__":
    main()
