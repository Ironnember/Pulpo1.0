# Pulpo

Pulpo is a small governance kernel for agentic execution. It turns explicit intent into a deterministic decision, binds allowed work to a one-use permit, and records the result in a tamper-evident audit chain.

This repository is the clean canonical Pulpo project. The older `Iron-Ember/pulpo` repository remains historical reference material; its accumulated plans, generated evidence, machine-specific scripts, and CI workarounds are intentionally not imported here.

## Proven now

The dependency-free test suite proves:

- unknown, incomplete, and over-budget intents fail closed;
- selected high-impact actions require explicit approval;
- permits are bound to the exact intent and cannot be replayed;
- audit-chain tampering is detected.
- configured agent roles cannot exceed their action, resource, or cost grant.
- a bounded domain order is bound to its full request, quote, reserved budget, and one-use permit.

```bash
python -m unittest discover -s tests -v
```

## Minimal example

```python
from pulpo import GovernanceKernel, Intent, Policy

kernel = GovernanceKernel(
    Policy(
        allowed_actions=frozenset({"read", "write", "push"}),
        max_cost=100,
        approval_actions=frozenset({"push"}),
    )
)

intent = Intent("agent:builder", "write", "repo:README.md", cost=5)
decision = kernel.evaluate(intent)

if decision.outcome == "allow":
    assert kernel.consume(decision.permit, intent)
```

## Boundary

Pulpo currently proves governance semantics in process. It does not yet claim durable storage, network isolation, hostile-code sandboxing, distributed identity, or production readiness.

See [architecture](docs/ARCHITECTURE.md), [project governance](docs/GOVERNANCE.md),
[current state](docs/CURRENT_STATE.md), [canonicalization](docs/CANONICALIZATION.md),
and [agents and plugins](docs/AGENTS_AND_PLUGINS.md).
The bounded transaction proof and its remaining live-execution gates are in
[commerce proof](docs/COMMERCE_PROOF.md).
