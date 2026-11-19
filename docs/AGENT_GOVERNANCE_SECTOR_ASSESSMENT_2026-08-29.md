# Agent Governance Sector Assessment — 2026-08-29

Status: research/strategy input only. This document is not a source of authority, a policy engine, an executor, a memory governor, or a ledger.

## Purpose

Assess the current AI-agent governance / control-plane sector against Pulpo's canonical architecture, identify where the market is converging, determine which Pulpo claims remain defensible, identify material competitive threats, and define the smallest external proof that would distinguish Pulpo through executable evidence rather than positioning language.

## Canonical Pulpo reference

Current canonical repository: `Ironnember/Pulpo1.0` on `main`.

Current main head at assessment time: `58885776a65d5b1c74e1e8134d46663f74853651` (merged PR #70).

PR #70 binds a one-use kernel permit to exact directive identity/version/hash and validity, revalidates directive state at permit consumption, denies execution if the directive has been revoked or become inactive, preserves the denial across SQLite restart, and keeps exact directive identity/status in the existing audit chain.

Canonical doctrine remains:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

and:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

## Executive finding

### Verified external market direction

The sector is rapidly converging on a recognizable **agent control plane** category. Major cloud, enterprise software, data, identity, and security vendors are adding combinations of:

- agent discovery / inventory;
- agent identity;
- scoped authorization;
- runtime policy enforcement;
- tool/MCP gateways;
- delegated user context;
- guardrails and semantic policy;
- approvals;
- observability and audit;
- cost controls;
- lifecycle management;
- agent evaluation;
- memory controls;
- centralized governance dashboards.

Independent analysts and institutions are also using this control-plane framing. BCG describes an Enterprise AI Control Plane above heterogeneous platforms; Forrester has described an agent control plane distinct from build and orchestration planes and argues vendor-agnostic control planes are inevitable; the World Economic Forum's 2026 agent playbook emphasizes deployment-level authorization, delegation, enforceability, and auditability.

### Material correction to Pulpo positioning

`Model-agnostic`, `cross-cloud`, `runtime governance`, `agent identity`, `tool authorization`, `auditability`, and even `agent control plane` are no longer sufficiently differentiated claims by themselves.

Multiple large vendors now publicly claim some or all of those capabilities.

Pulpo's defensible position must therefore be narrower and stronger:

> **Pulpo is an independent constitutional authority and evidence plane between intelligence and consequential execution.**

The differentiation is not merely that Pulpo can enforce policy. It is that Pulpo is intended to preserve an independent chain of authenticated authority, deterministic policy state, narrowly bound permits, execution-time reauthorization, side-effect evidence, and reconciliation across heterogeneous intelligence and execution systems — while refusing to let platform identity, memory, retrieval relevance, model confidence, local guardrails, or successful prior execution silently increase authority.

That distinction is only valuable if it is reproduced against external runtimes.

## Sector map

### 1. Amazon Web Services — Bedrock AgentCore Policy

**Verified public capabilities**

AWS AgentCore Policy is a centralized policy engine attached to AgentCore Gateway. It evaluates agent-tool calls in real time using Cedar policy. Public documentation describes:

- policy external to agent code;
- fine-grained principal/action/resource authorization;
- default-deny behavior;
- forbid-wins semantics;
- Gateway interception before tool invocation;
- OAuth/user authorization context propagation;
- LOG_ONLY and ENFORCE modes;
- temporal/stateful authorization patterns based on prior session events.

**Assessment**

This is one of the strongest direct technical comparisons for Pulpo. AWS already demonstrates that runtime authorization should sit outside model reasoning and that agent history can matter to authorization.

**Pulpo boundary**

Pulpo should not compete by building a generic policy DSL simply because AWS has Cedar. The stronger proof is that an AWS allow decision remains insufficient when Pulpo's independently governed directive/permit chain is absent, revoked, superseded, mismatched, expired, or otherwise invalid.

A local AWS deny should also remain a deny even when Pulpo would otherwise authorize the action. The correct composition rule is restrictive intersection, not authority substitution.

Primary sources:
- https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-create-engine.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-scope.html
- https://aws.amazon.com/blogs/machine-learning/securing-ai-agents-with-temporal-policies-in-amazon-bedrock-agentcore/
- https://aws.amazon.com/blogs/security/propagate-user-authorization-context-in-ai-agents-with-amazon-bedrock-agentcore/

### 2. Microsoft — Agent 365 / Entra Agent ID

**Verified public capabilities**

Microsoft describes Agent 365 as an identity-first control plane for agents, with:

- first-class agent identities through Entra Agent ID;
- centralized policy and governance;
- lifecycle management;
- auditing / observability;
- security controls for high-risk behavior;
- integration with Microsoft Purview, Defender, Intune, SharePoint, and admin controls;
- an SDK / OpenTelemetry path for observing agents built on other platforms.

Microsoft's 2026 startup guidance explicitly separates agent runtime, identity provider, policy layer, tool layer, resource APIs, and audit pipeline, and states that the agent should not decide authorization by itself.

**Assessment**

This strongly validates Pulpo's separation thesis while also removing `separate intelligence from authorization` as a unique claim.

**Pulpo boundary**

Microsoft is especially strong in enterprise identity and estate management. Pulpo must not attempt to replace Entra. Instead, Entra identity can be authenticated provenance/evidence presented to Pulpo; Pulpo then independently resolves whether that actor actually has authority for the exact consequential action and current directive state.

Primary sources:
- https://learn.microsoft.com/en-us/microsoft-agent-365/leadership/why-agent-365-for-enterprise
- https://learn.microsoft.com/en-us/microsoft-agent-365/leadership/govern-agents-support-innovation
- https://learn.microsoft.com/en-us/startups/build/identity-management/identity-fundamentals-ai-agents
- https://learn.microsoft.com/en-us/startups/build/identity-management/enterprise-readiness-ai-agent-identity

### 3. Google — Gemini Enterprise Agent Platform

**Verified public capabilities**

Google's current agent platform includes Agent Identity, Agent Registry, Agent Gateway, IAM policies, semantic governance policies, Memory Bank, managed runtimes, ADK, MCP/A2A interoperability, evaluation, and observability.

**Assessment**

Google is a strong external-runtime target because its stack spans nearly every layer that could otherwise be confused with Pulpo authority.

**Pulpo boundary**

Google identity may authenticate an actor, semantic governance may restrict a proposed call, Memory Bank may preserve useful state, and Agent Gateway may enforce additional controls. None may silently become Pulpo's canonical authority, directive state, or evidence ledger.

See companion research record:
`docs/GOOGLE_AGENT_ECOSYSTEM_ASSESSMENT_2026-08-29.md` on its isolated research branch.

### 4. Databricks — Unity AI Gateway / Unity Catalog

**Verified public capabilities**

As of August 2026, Unity AI Gateway is generally available. Databricks describes it as the control plane for AI and states that it can:

- route model and MCP traffic;
- enforce rate limits, cost controls, and service policies;
- record usage;
- govern models, MCP servers, functions, and related assets through Unity Catalog;
- govern external coding agents including Claude Code, Cursor, Codex, and Gemini CLI;
- govern external models from OpenAI, Anthropic, and Google.

**Assessment**

This materially weakens `provider-agnostic gateway` or `cross-model governance` as Pulpo differentiation.

**Pulpo boundary**

Databricks is strongest where AI traffic intersects governed enterprise data, assets, cost, and model/MCP routing. Pulpo must prove a different invariant: authorization provenance and execution permission remain independently governed even when the request is already inside a cross-provider AI gateway.

Primary sources:
- https://docs.databricks.com/aws/en/ai-gateway/ai-governance
- https://docs.databricks.com/aws/en/release-notes/product/2026/august

### 5. IBM — watsonx Orchestrate Agentic Control Plane / watsonx.governance

**Verified public capabilities**

IBM's current agentic control plane includes centralized agent dashboards, deployment/quality/evaluation visibility, AgentOps, and governance integration. In August 2026 IBM introduced Enforcement Tracking for watsonx Orchestrate, automatically recording agent evaluation metrics as governance enforcement evidence.

**Assessment**

IBM is a serious comparator for Pulpo's `evidence` language. The market is moving from governance documentation toward continuously recorded governance evidence.

**Pulpo boundary**

Pulpo's claim must be stronger than `we have audit logs` or `we collect evidence.` The relevant distinction is whether evidence proves that the exact executed side effect remained bound to the exact authorized intent/directive/permit and is reconciled independently of the execution platform.

Primary sources:
- https://www.ibm.com/new/announcements/from-governance-policies-to-governance-proof-with-enforcement-tracking-for-watsonx-orchestrate
- https://community.ibm.com/community/user/blogs/watsonx-watsonx-orchestrate-blog-team/2026/08/13/whats-new-in-watsonx-orchestrate-august-2026-mid

### 6. ServiceNow — AI Control Tower

**Verified public capabilities**

ServiceNow positions AI Control Tower as enterprise governance for AI assets with inventory, centralized controls, ROI/visibility, and runtime governance for AI agents at scale.

**Assessment**

ServiceNow has a major distribution advantage because it already sits inside enterprise workflow, risk, IT, and governance operations.

**Pulpo boundary**

Pulpo should not compete as another enterprise dashboard or GRC inventory layer. ServiceNow can be a policy/approval/evidence source or downstream workflow surface while Pulpo proves the narrower authorization-to-consequence chain.

Primary source:
- https://info.servicenow.com/WBR-MA00016339_Q3-FY26-Global-AICT-Executive-Webinar_MT00003765_LP.html

### 7. Salesforce — Agentforce / Agentforce 360

**Verified public capabilities**

Salesforce describes Agentforce as a platform for autonomous agents operating across Salesforce and external systems. Its trust and governance materials emphasize the Einstein Trust Layer, real-time policies and data checks, agent guardrails, human handoffs, least privilege, monitoring, and Audit Trail.

**Assessment**

Agentforce is strongest when consequential actions occur inside business application workflows and Salesforce-owned context.

**Pulpo boundary**

Pulpo should treat Salesforce controls as local defense-in-depth. A Salesforce agent or trust-layer allow decision must not create Pulpo authority for an externally consequential action.

Primary sources:
- https://help.salesforce.com/s/articleView?id=005315874&language=en_US&type=1
- https://www.salesforce.com/blog/data-governance-for-the-agentic-era/
- https://trailhead.salesforce.com/content/learn/modules/trusted-agentic-ai/explore-agentforce-guardrails-and-trust-patterns

### 8. Palo Alto Networks — Prisma AIRS / Portkey AI Gateway

**Verified public capabilities**

Palo Alto Networks completed its acquisition of Portkey in 2026 and is integrating the gateway into Prisma AIRS. Palo Alto describes a unified AI control plane capable of identifying, authenticating, and authorizing agentic interactions in real time across AI applications, enterprise agents, agentic endpoints, and agentic browsers.

**Assessment**

This is a direct competitive threat to broad `independent control plane` language. Palo Alto has existing security distribution, network/endpoint telemetry, enterprise trust, and a gateway acquisition.

**Pulpo boundary**

Pulpo's distinction cannot be `we sit in the middle and authorize agent calls.` It must be the constitutional semantics of who may authorize what, under which versioned/revocable directive, with exact-object permits and independent reconciliation after consequence.

Primary sources:
- https://www.paloaltonetworks.com/blog/2026/05/securing-and-governing-ai-agents-at-scale-through-a-unified-ai-gateway/
- https://www.paloaltonetworks.com/resources/whitepapers/secure-the-ai-enterprise

### 9. Cisco — Zero Trust for Agentic AI / AGNTCY direction

**Verified public capabilities**

Cisco is extending Zero Trust concepts to agent identity, access, behavior, tool/action governance, interaction governance, and cross-enterprise connectivity. Cisco/Outshift materials also discuss portable/verifiable agent identity, Task-Based Access Control, and cross-application access patterns.

**Assessment**

Cisco is another example of identity/security infrastructure expanding into agent governance.

**Pulpo boundary**

Portable identity and task-based access can strengthen Pulpo provenance and execution constraints. They still should not define Pulpo's canonical directive precedence or self-authorize authority expansion.

Primary sources:
- https://www.cisco.com/c/en/us/solutions/collateral/artificial-intelligence/security/zero-trust-agentic-ai-sb.html
- https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m02/cisco-redefines-security-for-the-agentic-era.html
- https://outshift.cisco.com/blog/why-enterprises-cant-govern-ai-agents

### 10. Ory — Agent Security

**Verified public capabilities**

Ory launched an agent IAM control plane in June 2026 focused on identity/access controls at the point agents invoke tools, execute commands, access data, or interact with business systems.

**Assessment**

Ory is a useful specialist comparator because it targets the execution boundary directly rather than only model safety or governance reporting.

**Pulpo boundary**

Pulpo must show that IAM identity and access policy are inputs to a broader authority lifecycle rather than equivalent to authority itself.

Primary source:
- https://www.ory.com/blog/ory-launches-agent-security

### 11. Snowflake — Agentic Control Plane

**Verified public positioning**

Snowflake now explicitly describes an agentic control plane as a centralized layer for identity, runtime policy, governed context, tool access, versions, execution, and auditability across an agent estate.

**Assessment**

This is another direct signal that `agentic control plane` is becoming category language rather than Pulpo-specific language.

**Pulpo boundary**

Pulpo should avoid relying on the noun `control plane` as the moat. The moat, if proven, is independent constitutional authority continuity and evidence reconciliation across control planes.

Primary source:
- https://www.snowflake.com/en/artificial-intelligence/ai-governance/control-plane/

### 12. OpenAI and Anthropic — intelligence platforms with growing execution controls

**Verified public capabilities**

OpenAI's agent ecosystem includes tools, guardrails, tracing, approvals, sandboxes, connector/app action controls, RBAC, action constraints, workspace agent administration, and version/activity visibility.

Anthropic publicly emphasizes containment, blast-radius reduction, enterprise admin controls, compliance/audit visibility, prompt-injection defenses, permissions, and trustworthy-agent design.

**Assessment**

These vendors remain better classified as intelligence / agent-runtime providers than full independent enterprise authority planes, but their local governance surfaces are expanding quickly.

**Pulpo boundary**

They are ideal upstream intelligence providers and adversarial integration targets. Pulpo should remain model-independent while proving that their local approval/guardrail/containment mechanisms neither grant nor override Pulpo authority.

Primary sources:
- https://openai.com/index/new-tools-for-building-agents/
- https://help.openai.com/en/articles/20001143-chatgpt-workspace-agents-for-enterprise-and-business
- https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-in-connectors-enterprise-edu-and-team
- https://www.anthropic.com/research/trustworthy-agents
- https://www.anthropic.com/engineering/how-we-contain-claude

## Competitive convergence

The market is converging on six common layers:

1. **Discovery and identity** — know which agents exist and who/what they represent.
2. **Access and authorization** — determine which tools/resources they may touch.
3. **Runtime enforcement** — intercept consequential calls and permit/deny them.
4. **Observation and evidence** — record behavior, decisions, evaluations, and outcomes.
5. **Lifecycle / estate governance** — version, deploy, monitor, retire, and govern agents at scale.
6. **Security / containment** — constrain blast radius, detect abuse, protect data, and stop anomalous behavior.

Pulpo overlaps with all six. Therefore overlap itself is not differentiation.

## Pulpo's strongest remaining differentiation hypothesis

### 1. Authority is not identity

Identity proves who/what an actor is. Pulpo separately resolves whether that actor may authorize this exact action under current scope, delegation, policy, and directive state.

### 2. Authority is not memory or retrieval

Conversation memory, vector retrieval, platform memory, generated summaries, confidence, semantic relevance, or successful prior behavior can inform intelligence but cannot raise authority.

### 3. Authority is versioned and revocable through execution

A permit is not permanently valid merely because authorization was valid when the permit was issued. Consequential execution must remain bound to current directive/authority state.

PR #70 provides current local evidence for this invariant.

### 4. Exact-object continuity

The valuable invariant is not merely `policy allowed tool X.` It is that purpose/intent, authenticated authority, policy decision, approval, permit, executed object, receipt, and reconciliation all refer to the same bounded consequential object — or the action fails closed.

### 5. Platform governance can only restrict, never enlarge Pulpo authority

External IAM, semantic policy, local guardrails, network policy, cloud gateway decisions, and application permissions are defense-in-depth constraints. Their `allow` decisions cannot increase Pulpo authority. Their `deny` decisions can still prevent execution.

This produces restrictive intersection semantics:

`effective permission = Pulpo authorization AND execution-surface authorization AND all required downstream constraints`

No subordinate surface may turn a Pulpo deny into an allow.

### 6. Evidence is independently reconciled

Cloud logs, traces, gateway records, model traces, and application audit trails are evidence inputs. They are not automatically canonical truth. Pulpo must independently determine whether the observed side effect matched authorized intent and record that reconciliation into its existing evidence chain.

### 7. Learning cannot self-authorize

The market increasingly includes self-improving agents and optimization loops. Pulpo's constitutional invariant remains strategically important:

> Learning may change competence. Learning may recommend authority changes. Learning may not grant authority to itself.

## Threat assessment

### High: hyperscaler feature compression

AWS, Google, and Microsoft can rapidly absorb policy, identity, temporal authorization, observability, and governance features into existing clouds.

**Implication:** Pulpo cannot win by matching feature checklists.

### High: security-vendor distribution

Palo Alto, Cisco, Ory, identity vendors, and related security companies already own enterprise security relationships and enforcement infrastructure.

**Implication:** Pulpo needs proof that its authority semantics add a control property those products can consume rather than another security dashboard they must replace.

### High: enterprise-platform ownership

ServiceNow, Salesforce, IBM, Databricks, Snowflake, and Microsoft already sit beside systems of record, enterprise workflows, data, or IT governance.

**Implication:** Pulpo should integrate rather than attempt to displace those systems.

### Medium-high: category commoditization

`AI control plane`, `agent control plane`, `agent governance`, and `agent identity` are becoming common category terms.

**Implication:** Pulpo's language must become evidence-specific and invariant-specific.

### Medium: standards reduce integration moat

MCP, A2A, emerging agent identity standards, and authorization standards make interoperability easier for everyone.

**Implication:** interoperability should be embraced; it is not the moat. The moat must reside in governance semantics, proof quality, trusted operation, and reproducibility.

### Current Pulpo weakness

Pulpo's strongest constitutional claims are currently better proven locally than externally. It does not yet have the hyperscaler distribution, enterprise installed base, broad hosted runtime, or independently reproduced cross-platform proof of the large incumbents.

That must remain explicit in public positioning.

## External category validation

### BCG — Enterprise AI Control Plane

BCG's August 14, 2026 analysis argues that platform-by-platform agent governance creates fragmented oversight and that enterprises need a common control plane above heterogeneous agent platforms, unifying identity, policy enforcement, visibility, and governance.

Source:
- https://www.bcg.com/publications/2026/how-cios-govern-ai-agents-at-scale

### Forrester — agent control plane as separate plane

Forrester's 2026 market framing distinguishes build, orchestration, and control planes and states that governance must sit outside build and orchestration environments as heterogeneous agents proliferate.

Source:
- https://www.forrester.com/blogs/agent-control-planes-still-need-a-robust-standards-stack/

### World Economic Forum — authorization as deployment governance

The WEF/Capgemini 2026 playbook introduces an Agent Capability and Authorization Profile encompassing delegation policy, system design, operational oversight, enforceability, and auditability.

Source:
- https://www.weforum.org/reports/ai-agents-in-action-a-playbook-for-trusted-adoption-authorization-and-scaling

These sources validate the problem category. They do not validate Pulpo's implementation or superiority.

## Highest-value sector proof

### Proposed: cross-control-plane authority dominance test

Do not build ten integrations. Build the smallest two-surface conformance proof that can falsify Pulpo's independence claim.

Use one exact consequential action object and two materially different external agent/control environments.

Suggested first pair after current admission gates are ready:

- one hyperscaler agent stack (AWS AgentCore or Google Gemini Enterprise Agent Platform), and
- one independent intelligence/runtime surface (OpenAI/Codex, Anthropic/Claude, or equivalent).

For each environment prove:

1. The external model/agent proposes the exact same action object.
2. External/local governance says `allow`.
3. Pulpo has no valid directive -> execution is denied.
4. Pulpo has a valid directive -> one-use permit is issued.
5. Revoke/supersede the directive after issuance -> execution is denied at consumption.
6. Restore a legitimate active directive -> execution succeeds once.
7. Replay the permit -> denied.
8. Change action arguments, destination, amount, identity, or scope -> denied.
9. External retrieval/memory/model confidence/local governance `allow` cannot raise Pulpo authority.
10. External/local governance `deny` still prevents execution even if Pulpo authorizes.
11. Independent observation confirms the actual side effect.
12. External receipts/logs are reconciled into the existing Pulpo evidence chain.
13. Restart and reproduce the critical denial/replay behavior.

### Why this is the highest-value proof

A single external integration proves compatibility.

Two heterogeneous control environments running the same constitutional test begin to prove **independence from the underlying intelligence and execution/control platform**.

That directly addresses the largest strategic uncertainty created by the sector's convergence.

## Positioning change recommended

Avoid leading with:

- AI governance platform;
- agent control plane;
- model-agnostic governance;
- cross-cloud agent security;
- agent identity and audit;
- guardrails for autonomous agents.

Those phrases now describe crowded product categories.

Lead with the narrower testable claim:

> **Pulpo independently proves who had authority for a consequential AI action, what exact action was authorized, whether that authority was still valid when execution occurred, and whether the resulting side effect matched the authorization — regardless of which model, agent framework, cloud, gateway, or application performed the work.**

Until the cross-platform proof is executed, classify that as the product thesis / proposed external property, not as a universally verified production claim.

## Decision

**Strategic sector relevance:** extremely high.

**Market validation:** strong. The control-plane problem is now explicitly recognized by major vendors, analysts, and institutions.

**Competitive intensity:** high and accelerating.

**Immediate architecture change:** none recommended solely because competitors added overlapping features.

**Immediate strategic change:** sharpen positioning away from generic governance/control-plane language and toward independently provable authority continuity and reconciliation.

**Highest-value future external proof:** two-surface authority-dominance conformance test after current canonical authority/deployment gates permit it.

**Do not:** create a second router, executor, policy engine, memory governor, identity system, or ledger merely to imitate sector features.
