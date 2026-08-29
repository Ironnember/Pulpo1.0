# Google Agent Ecosystem Assessment — 2026-08-29

Status: research/strategy input; not a new authority source, policy engine, executor, memory governor, or ledger.

## Purpose

Assess Google's current developer and enterprise-agent ecosystem as a potential Pulpo integration and proof surface without changing Pulpo's constitutional authority boundary.

## Verified external facts

As of 2026-08-29, Google's developer and enterprise-agent ecosystem includes:

- Google Developer Program Builders Hub with personalized developer discovery across Google developer products.
- GEAR (Gemini Enterprise Agent Ready), a no-cost program focused on building, deploying, governing, and scaling production agents.
- GEAR learning paths covering agent fundamentals, ADK development, production deployment, enterprise scaling, and multi-agent systems.
- Gemini Enterprise Agent Platform as an end-to-end environment for building, scaling, governing, and optimizing agents.
- Agent Development Kit (ADK), an open-source framework for building, orchestrating, evaluating, and deploying agents in Python, TypeScript, Go, and Java.
- Agent Runtime and managed deployment paths, including Google Cloud runtime options, Cloud Run, and GKE.
- Agent Registry for cataloging agents, MCP servers, tools, and endpoints.
- Agent Identity for assigning independently trackable workload identities to agents.
- Agent Gateway as a network enforcement point for interactions between users, agents, tools, MCP servers, endpoints, and other agents.
- IAM allow/deny policies and semantic governance policies that can be enforced through Agent Gateway.
- Memory Bank for long-term generated memories, including immutable revision resources for memory-version history.
- MCP and Agent2Agent (A2A) as interoperability surfaces.
- Gen AI evaluation and Cloud observability as agent-quality and runtime-evidence surfaces.

Current public feature-state signals from Google's release notes/documentation include:

- Agent Identity: generally available.
- Agent Registry: public preview.
- Agent Gateway: private preview.
- Memory Bank: supports immutable memory revision history and event-driven memory generation.
- Semantic governance policies: natural-language constraints evaluated at runtime to align proposed tool calls with user intent and organizational business constraints; Google explicitly positions this as complementary to baseline access control rather than a replacement for IAM/network controls.

Current GEAR Get Certified Edition 3 application window: 2026-08-19 through 2026-09-16; training begins the week of 2026-10-12. Tracks include Generative AI Leader, Associate Cloud Engineer, and Professional Cloud Architect.

Primary sources:

- https://developers.google.com/program
- https://developers.google.com/program/gear
- https://developers.google.com/program/gear/getcertified
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/agents
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/adk
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/overview
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/release-notes
- https://cloud.google.com/blog/products/ai-machine-learning/the-new-gemini-enterprise-one-platform-for-agent-development

## Verified Pulpo state relevant to this assessment

Current canonical source: `Ironnember/Pulpo1.0` on `main`.

The 2026-08-29 main head includes merged PR #70, which binds a one-use kernel permit to the exact directive identity/version/hash and checks live directive status again at permit consumption. A revoked, mismatched, expired, or otherwise inactive directive therefore cannot continue authorizing execution merely because a permit was previously issued.

Relevant evidence:

- main commit: `58885776a65d5b1c74e1e8134d46663f74853651`
- PR #70: `reconcile/execution-time-directive-revocation-current-main`
- implementation: `pulpo/directives.py`, `pulpo/state.py`
- regression coverage includes active one-use consumption, post-issuance revocation denial, restart persistence of the denial, and audit-chain validity after restart denial.

This is directly relevant because an external agent framework can propose or prepare actions while Pulpo still revalidates governed authority at the consequential execution boundary.

## Reconciled position

### Verified

Google now exposes a broad agent stack spanning intelligence, orchestration, memory, identity, deployment, observability, evaluation, tool registration, network enforcement, and enterprise governance controls.

Pulpo's canonical architecture requires external models, agent frameworks, runtimes, plugins, cloud services, and CI systems to remain capability/evidence surfaces rather than canonical authority.

### Inferred

Google is strategically more useful to Pulpo as a strong external integration target than as an architectural dependency.

Google's new governance stack makes it a stronger constitutional test, not a reason to collapse Pulpo into Google. In particular, Agent Identity, Agent Registry, Agent Gateway, IAM policies, semantic governance, and Memory Bank now overlap with categories that Pulpo also reasons about. That overlap is useful because Pulpo can prove a distinct boundary:

- Google identity may authenticate an external workload, but does not by itself establish Pulpo authority.
- Google IAM or semantic policy may restrict execution further, but cannot increase Pulpo authority.
- Google Memory Bank may preserve useful generated memories and revision history, but memory relevance/history cannot create or raise directive authority.
- Google Agent Gateway may serve as an additional enforcement surface, but Pulpo remains the independent decision/permit authority for Pulpo-governed consequential actions.
- Google observability/audit output is evidence input, not the canonical Pulpo evidence ledger.

This is complementary rather than duplicative only if the boundary remains:

`Google intelligence/orchestration -> Pulpo authority/policy/permit -> Google execution/enforcement -> independent evidence -> Pulpo reconciliation`

Google-native identity, policy, memory, and governance controls may be consumed as evidence, execution constraints, or defense-in-depth, but they must not silently become Pulpo's source of authority or canonical policy state.

### Important distinction: Google semantic governance vs Pulpo directive authority

Google's semantic governance policy is an intelligent runtime gate that evaluates proposed model/tool actions against natural-language user intent and configured business constraints. That is useful defense-in-depth, but it is not equivalent to Pulpo's directive boundary.

Pulpo's target invariant is stronger and differently scoped: authority must come from authenticated provenance, explicit scope/delegation, immutable/versioned directive state, revocation/supersession, deterministic precedence, narrowly bound permits, execution-time revalidation, and reconciliation into the existing canonical evidence chain. Retrieval relevance, model confidence, generated summaries, platform memory, or semantic similarity must never raise authority.

Therefore Pulpo should not compete by reimplementing Google's semantic policy layer. It should prove that a Google semantic-policy allow decision is still insufficient to execute when Pulpo authority is absent, revoked, mismatched, expired, or otherwise invalid.

### Proposed

Use Google as one future external-runtime proof after the current higher-priority authority/deployment boundaries are sufficiently proven.

Smallest useful proof:

1. An ADK or Gemini-backed agent proposes one narrow consequential action.
2. Pulpo receives the exact action object and evaluates it against independently governed authority/policy/directive state.
3. Pulpo issues one narrowly bound, one-use permit.
4. The Google execution surface receives only the permitted action.
5. Revoke or supersede the governing directive after permit issuance but before execution; execution must fail closed even if Google IAM/semantic governance would otherwise permit the call.
6. Re-authorize with the correct active directive and execute successfully.
7. Capture Google-side runtime/audit evidence and independently verify the side effect.
8. Reconcile the receipt/evidence into the existing Pulpo evidence chain.
9. Prove that Google Memory Bank, retrieval relevance, agent identity, semantic-policy verdicts, orchestration state, or model confidence cannot raise Pulpo authority.

## Negative invariants

The Google integration must prove at least these denials:

- Google/ADK conversational, session, or Memory Bank state cannot create a Pulpo directive.
- Google Agent Identity cannot substitute for an independently authenticated Pulpo authorizer.
- A Google-side delegated agent cannot broaden the scope of a Pulpo directive.
- A revoked/superseded Pulpo directive cannot authorize execution, including after restart.
- Google retrieval rank, memory revision, model confidence, generated summary, or semantic-policy verdict cannot increase authority.
- A Google-side tool call cannot bypass Pulpo execution-time permit/directive validation.
- Google Cloud IAM, Agent Gateway, or Gemini Enterprise policy cannot silently become the canonical Pulpo authority source.
- External receipts and Cloud audit output must reconcile into Pulpo's existing evidence chain rather than creating a parallel Google-backed ledger.

## Priority assessment

Strategic value: high.

Immediate architecture change: none required.

Immediate proof priority: below the current independent-authority / protected-state / host-isolation boundaries, but high as an external reproduction target once those gates permit it.

Immediate operating opportunity: high. GEAR can provide structured training, current platform knowledge, production-agent patterns, certification opportunities, and direct exposure to how a hyperscaler is implementing agent identity, gateways, semantic policy, memory, and enterprise governance.

Competitive implication: Google increasingly covers platform-local agent governance. Pulpo should not position itself as 'governance features Google lacks.' The defensible distinction is independent, model/runtime/cloud-agnostic constitutional authority and evidence across heterogeneous execution surfaces, including when those surfaces already contain their own local guardrails.

## Decision rule

Adopt Google capabilities where they improve intelligence, interoperability, deployment, evaluation, observability, authentication evidence, or defense-in-depth. Do not delegate Pulpo's constitutional authority, directive precedence, permit issuance, or canonical evidence/reconciliation to Google.

Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.
