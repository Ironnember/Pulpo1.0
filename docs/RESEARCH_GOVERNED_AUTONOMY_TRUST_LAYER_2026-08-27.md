# Governed Autonomy Trust-Layer Research

Status date: 2026-08-27
Claim posture: external findings are **Recorded**; Pulpo comparisons are **Inferred**; implementation consequences are **Proposed** unless already proven by repository tests.

## Research question

Could Pulpo plausibly become a general trust layer for consequential machine action rather than merely an agent framework, and which external standards or security developments support, contradict, or constrain that thesis?

## Result

The strongest current external signals support the architectural direction, but they do not prove Pulpo's product-market outcome or production readiness.

Across NIST, IETF OAuth work, MCP authorization, and OWASP agentic-security guidance, the same requirements recur:

1. agents and workloads need independently meaningful identity;
2. authorization must be narrow, revocable, and bound to target resources and transaction context;
3. delegation must preserve authority provenance rather than allowing downstream actors to manufacture broader permission;
4. high-impact execution needs controls beyond model intent or user-visible approval theater;
5. persistent memory is an attack surface and must not silently become policy or authority;
6. execution and tool chains require auditable, tamper-resistant evidence and non-repudiation;
7. agent ecosystems create confused-deputy, privilege-escalation, replay, supply-chain, and cross-system failure risks;
8. interoperability standards are emerging, but they largely stop at identity, authorization transport, protocol context, or risk guidance rather than closing the full intent-to-outcome reconciliation loop.

Pulpo's existing constitutional lifecycle remains:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

The external research therefore strengthens the case for extending the existing Pulpo seam; it does **not** justify creating another authority service, policy engine, memory governor, router, executor, or evidence ledger.

---

## 1. NIST: agent identity and authority are becoming a standards problem

### Recorded

NIST's February 2026 NCCoE concept paper, *Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization*, explicitly asks how organizations should handle agent identification, strong authentication, key issuance/rotation/revocation, least privilege, dynamic authorization, proof of authority for a specific action, intent communication, delegated "on behalf of" authority, human-agent identity binding, tamper-proof/verifiable auditing, non-repudiation, and prompt-injection containment.

NIST subsequently announced an AI Agent Standards Initiative intended to support secure, interoperable agents acting on behalf of users.

Sources:
- https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents
- https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
- https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure

### Inferred Pulpo relevance

NIST's question set maps unusually closely to Pulpo's existing authority seam:

- agent identity -> Pulpo principal/session identity;
- proof of authority for an exact action -> signed approval envelope plus exact-intent permit binding;
- delegation -> scoped authority that cannot be broadened by the delegated operator;
- least privilege -> minimum-sufficient permits and bounded action/resource/budget scope;
- non-repudiation -> canonical evidence chain plus external authority evidence;
- prompt injection containment -> intelligence remains unable to self-authorize even when reasoning is compromised.

This is external alignment, not validation of Pulpo's implementation quality.

---

## 2. IETF OAuth Transaction Tokens: transaction-bound context is converging toward Pulpo's permit thesis

### Recorded

The July 2026 IETF OAuth Transaction Tokens draft defines short-lived signed tokens that carry user/workload identity and authorization context through a call chain. It emphasizes narrowly defined transaction purpose, immutable transaction context, short lifetimes, accounting/auditing context, and one logical Transaction Token Service per trust domain. It also deliberately separates transaction context from authentication credentials and OAuth access tokens.

Source:
- https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/

### Inferred Pulpo relevance

The draft reinforces several Pulpo design choices:

- authorization context should be transaction-specific rather than ambient;
- immutable context should travel with the transaction;
- authorization and authentication are distinct concepts;
- short-lived scope reduces replay/lateral-movement exposure;
- there should not be multiple competing canonical issuers inside one trust domain.

Important distinction: an IETF Transaction Token is not equivalent to a Pulpo permit. The draft is primarily concerned with preserving authorization context across service call chains. Pulpo additionally attempts to bind decision, consequence, evidence, reconciliation, and governed learning. Pulpo should therefore remain interoperable with such standards rather than replacing them.

### Proposed compatibility rule

When Pulpo eventually integrates transaction-token ecosystems, imported transaction context should be treated as authenticated input to Pulpo's authority/policy evaluation, never as self-sufficient authority to bypass Pulpo's exact-action decision and permit path.

---

## 3. MCP: the execution ecosystem is hardening around audience-bound authorization

### Recorded

The Model Context Protocol authorization specification uses OAuth-based authorization for HTTP transports and requires resource/audience binding, access-token validation, authorization on each HTTP request, short-lived/secure token practices, and rejection of token passthrough. Its security guidance explicitly addresses the confused-deputy problem. The July 28, 2026 MCP release further hardened authorization behavior.

Sources:
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://blog.modelcontextprotocol.io/posts/2026-07-28/

### Inferred Pulpo relevance

MCP is evidence that tool connectivity is becoming standardized while authorization remains a substantial integration problem. It strengthens Pulpo's positioning as a governance layer **above or around** tool protocols rather than as another tool protocol.

MCP's OAuth token answers questions such as "may this client access this resource?" Pulpo's intended additional question is "is this exact consequential action still authorized under the current purpose, policy, budget, directive version, approval state, and execution context?"

### Proposed invariant

MCP authorization may establish transport/resource capability, but **MCP possession must never bootstrap Pulpo authority**. A valid MCP token can prove capability to reach a resource; Pulpo must still independently decide whether the consequential action is authorized.

This preserves the existing Pulpo distinction:

`capability != authority`

---

## 4. OWASP: memory, tools, privileges, and autonomy are now explicit agentic attack surfaces

### Recorded

OWASP's 2026 agentic-security guidance identifies major risks including goal hijacking, tool misuse, identity and privilege abuse, supply-chain compromise, unexpected code execution, memory/context poisoning, excessive autonomy, high-impact-action abuse, approval manipulation, cascading failures, and denial-of-wallet behavior.

Its AI Agent Security Cheat Sheet recommends adversarial testing of unauthorized tool use, privilege escalation, memory poisoning, exfiltration, recursive tool abuse, and high-impact execution. OWASP's memory guidance treats persistent memory as untrusted data that should be scoped, integrity-checked, and distinguished by provenance rather than treated as privileged instructions.

Sources:
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/

### Inferred Pulpo relevance

This strongly supports Pulpo's constitutional separation of intelligence, governance, and execution. A model can be goal-hijacked or memory-poisoned without gaining authority if the governance layer is independently authenticated and exact-action enforcement remains outside the model's trust domain.

It also strengthens the recent Directive Memory boundary:

- retrieved text is information, not authority;
- semantic relevance cannot raise authority;
- persistent memory must carry provenance and scope;
- directive state must remain versioned/revocable through the existing policy/authority seam;
- consequential actions must re-check authority at execution time.

---

## 5. What appears missing in the emerging ecosystem

### Inferred

The standards landscape contains strong pieces, but no reviewed source in this research establishes one generally adopted system that closes all of the following in one governance lifecycle:

`purpose -> exact intent -> independent authority -> policy -> bounded permit -> side effect -> independently inspectable evidence -> reconciliation -> governed outcome memory -> adaptation without self-authorization`

Existing standards generally specialize:

- NIST: standards questions, architecture concerns, risk framing;
- OAuth/IETF: identity, delegation, access, authorization context, transaction propagation;
- MCP: tool/resource protocol authorization;
- OWASP: threats and mitigations;
- conventional IAM: identities, roles, policies, credentials, resource access;
- observability/audit systems: downstream evidence of what systems report happened.

Pulpo's potentially distinctive seam is the **closed constitutional loop around consequential execution**, especially the explicit separation between evidence and permission and the requirement to reconcile intended, authorized, executed, and achieved outcomes.

This remains an **Inferred differentiation**, not a verified market uniqueness claim. A formal competitor/prior-art survey would be required before claiming uniqueness.

---

## 6. Pulpo's plausible end-state

### Proposed positioning

Pulpo should continue to be developed as:

> **The independent trust and governance layer that allows humans and organizations to delegate consequential action to machine intelligence without allowing intelligence, memory, tools, or execution infrastructure to manufacture their own authority.**

A shorter technical description is:

> **Governed authorization, bounded execution, evidence, and reconciliation for autonomous systems.**

This positioning preserves the canonical doctrine:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

### What Pulpo should not become

- another agent framework competing primarily on reasoning loops;
- another MCP server/router;
- a conversational-memory product;
- a generic IAM replacement;
- another observability platform;
- a policy engine whose policy truth competes with the current kernel;
- a ledger whose evidence truth competes with the canonical evidence chain.

Pulpo should integrate these systems as capabilities, standards, adapters, or evidence surfaces when they advance a concrete proof.

---

## 7. Research-derived invariants to preserve

The following are **Proposed** as explicit test targets or compatibility invariants where not already covered:

1. **Protocol capability cannot grant governance authority.** A valid MCP/OAuth credential cannot by itself mint a Pulpo permit.
2. **Delegation is monotonic-narrowing.** A delegated actor can preserve or reduce scope but cannot expand action, resource, budget, duration, or principal authority without a separately authorized transition.
3. **Transaction context cannot become identity.** Transaction/permit context must not substitute for independently authenticated principal/workload identity.
4. **Imported authorization context is evidence/input, not constitutional truth.** External authorization systems can inform Pulpo evaluation but cannot silently override current Pulpo policy.
5. **Memory authority is provenance-bound.** Chat, RAG, embeddings, summaries, tool output, and learned state cannot create or elevate directive authority.
6. **Execution-time reauthorization is mandatory for consequential actions.** Relevant directive/policy/authority versions must still be valid when the side effect is attempted.
7. **Audience/resource binding is exact.** Authority issued for one executor/resource cannot be replayed against another.
8. **Cross-domain delegation requires a new governed boundary decision.** Authority cannot flow across trust domains merely because protocols can exchange tokens.
9. **Evidence cannot retroactively legitimize execution.** Successful side effects and valid receipts do not convert unauthorized execution into authorized execution.
10. **Reconciliation closes the transaction.** Command success, provider acceptance, charge, delivery, acceptance, and intended outcome remain distinct states.

These extend existing canonical principles; they do not create a new governance plane.

---

## 8. Highest-value next proof

### Proposed

Do **not** add a broad "trust-layer" subsystem merely because the research supports the thesis.

The highest-value proof remains the current canonical production boundary:

1. deploy independently authenticated authority outside the governed worker;
2. prove protected time/monotonic state and verifier bootstrap;
3. prove the governed worker cannot obtain or impersonate the authority credential;
4. issue one exact-action authorization through the external authority boundary;
5. consume it through the existing one-use permit path;
6. restart and prove replay/revocation behavior;
7. execute one bounded external workload;
8. reconcile intent, authorization, side effect, cost, receipt, and outcome into the existing evidence chain;
9. publish an independently inspectable evidence bundle.

Why this proof: external standards increasingly validate the **problem class**. Pulpo now needs to prove the **boundary** rather than accumulate more conceptual agreement.

---

## 9. Claim discipline after this research

### Verified

Only repository behavior supported by executable current tests and evidence should be labeled Verified.

### Recorded

NIST, IETF, MCP, and OWASP are independently converging on agent identity, narrow authorization, delegation, resource binding, auditability, memory risk, and high-impact-action controls.

### Inferred

Pulpo's existing architecture is directionally well aligned with those requirements and may occupy a broader trust-layer seam than conventional agent frameworks or transport authorization alone.

### Proposed

Position Pulpo as governed authorization + bounded execution + evidence + reconciliation for autonomous systems, and make standards interoperability subordinate to the existing canonical authority/policy/permit/evidence path.

### Unknown

- whether Pulpo will become a widely adopted protocol or infrastructure layer;
- whether customers will pay for the complete governance loop;
- whether existing or emerging competitors already implement materially equivalent end-to-end semantics;
- whether the production trust boundary will withstand independent adversarial evaluation;
- whether standards bodies will converge on concepts that map cleanly to Pulpo's permit/evidence/reconciliation semantics.

Those remain research and execution questions, not claims.
