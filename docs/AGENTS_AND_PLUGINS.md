# Agents and plugins

## Agent model

Pulpo uses one governance kernel. Agents are named, least-authority principals
evaluated by that kernel; they are not independent routers, ledgers, or approval
authorities.

The initial profiles are intentionally small:

| Principal | Purpose | Allowed actions | Boundary |
|---|---|---|---|
| `agent:planner` | turn source and intent into a bounded plan | `read`, `plan` | repository, docs, declared sources, and read-only GitHub |
| `agent:builder` | implement and test an approved slice | `read`, `write`, `test` | repository only |
| `agent:verifier` | independently challenge results and evidence | `read`, `test`, `verify` | repository, evidence, and read-only GitHub |
| `agent:commerce` | submit one exact bounded domain order | `purchase_domain` | hashed domain orders, maximum 3,000 USD cents |

No agent is a human approver. `agent:commerce` remains subject to the kernel's
configured `purchase_domain` approval action. No default agent can push, deploy, enroll an
authority credential, or widen its own policy.

`AgentGrant` is enforced during the normal `GovernanceKernel.evaluate()` path.
When grants are configured, an unknown principal, action, resource namespace,
or per-agent budget fails closed.

## Plugin sequence

Plugin profiles are declarations of intended use. A profile is **not** evidence
that a ChatGPT plugin, runtime adapter, credential, webhook, or external account
is installed or connected.

1. **GitHub — current.** Canonical source, review, CI, and release evidence.
2. **Sentry — next.** Runtime errors and traces once a real service exists.
3. **Cloudflare — deployment.** Edge and ingress controls when Pulpo exposes a
   public endpoint.

Do not add a broad plugin bundle preemptively. Every connector increases the
reachable authority surface. Add one adapter only when its task contract,
credential owner, allowed read/write operations, budget, failure behavior, and
evidence mapping are defined.

All connector writes require explicit approval by default. Deployment and
authority-management actions additionally require independently authenticated
human approval once that boundary exists.

## Current boundary

The caller-provided approval boolean has been removed for every kernel.
Approval-gated work can receive a permit only through a verified envelope, and
the evaluation caller cannot override its session or the kernel time used for
expiry. This does not prove independent human identity until the verifier,
signer, clock, and trust bootstrap are deployed outside the governed worker
boundary. Plugin writes remain blocked from live use until that deployment
evidence exists.

The legacy CryoAgent correctly detects exact repetition, short oscillation, and
a configured depth limit in its unit tests. It is not yet imported because its
old Pentagon orchestrator creates a duplicate state file and bypasses Pulpo's
canonical permit and audit path. Its loop-breaker should return later as an
execution guard subordinate to a governed runner.
