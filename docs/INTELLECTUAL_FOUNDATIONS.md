# Pulpo Intellectual Foundations

Status: proposed; noncanonical until reviewed and merged
Status date: 2026-08-28
Canonical repository: `Ironnember/Pulpo1.0`

## Purpose

Pulpo is an engineering system, not a philosophical proof. This document records the established disciplines that help explain why Pulpo separates intelligence, authority, execution, evidence, reconciliation, and learning.

The purpose is to give the architecture a defensible intellectual foundation without pretending that a book, analogy, academic field, or standards document independently proves Pulpo correct.

Pulpo's canonical lifecycle remains:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

The compact operating doctrine remains:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation teaches.

## Epistemic rule

This document separates three kinds of statements:

1. **Established source concept** — supported by the cited external literature or standard.
2. **Pulpo architectural mapping** — an inference about how that concept informs Pulpo design.
3. **Pulpo verified behavior** — supported only by executable evidence in the canonical repository at a specific commit.

External scholarship and standards can motivate or challenge an architecture. They do not convert proposed Pulpo behavior into verified behavior.

`SOURCE_SUPPORT != PULPO_EXECUTABLE_PROOF`

`ANALOGY != EVIDENCE`

## Core thesis

A sufficiently capable intelligence may be able to propose, plan, predict, persuade, and execute consequential actions while still being an inappropriate source of its own authority and an unreliable reporter of its own consequences.

Pulpo therefore separates five questions that agent systems often blur:

1. **What can be done?** — capability and intelligence.
2. **What may be done?** — authority and policy.
3. **What exact action was permitted?** — decision and one-use permit.
4. **What actually happened?** — execution evidence and independent observation.
5. **What should be learned from the outcome?** — reconciliation and governed memory.

The architecture is strongest when those questions remain separable even as models, interfaces, tools, and execution surfaces change.

---

## 1. Philosophy: capability does not imply permission

### Established source concept

David Hume's discussion of the transition from statements about what *is* to statements about what *ought* to be is a foundational warning against silently deriving normative conclusions from descriptive premises. The Stanford Encyclopedia of Philosophy notes the long-standing interpretation that evaluative conclusions cannot simply be inferred from purely factual premises.

Source:

- Stanford Encyclopedia of Philosophy, **Hume's Moral Philosophy**, section "Is and ought": https://plato.stanford.edu/entries/hume-moral/

### Pulpo architectural mapping

An intelligence may correctly predict that an action is possible, efficient, profitable, likely to succeed, or consistent with a goal. None of those descriptive or predictive claims establish that the intelligence has legitimate authority to cause the action.

Pulpo expresses the distinction operationally:

`CAN != MAY`

`CAPABILITY != AUTHORITY`

`PREDICTION != PERMISSION`

### Design consequence

The intelligence plane may recommend an action. Authority and policy must independently determine whether the proposed consequence is permitted.

---

## 2. Psychology and human factors: confidence is not a control

### Established source concept

Tversky and Kahneman showed that human judgments under uncertainty often rely on heuristics such as representativeness, availability, and anchoring. These shortcuts are often useful but can produce systematic and predictable errors.

Source:

- Amos Tversky and Daniel Kahneman, **Judgment under Uncertainty: Heuristics and Biases**, *Science* 185 (1974), 1124-1131: https://doi.org/10.1126/science.185.4157.1124
- PubMed record and abstract: https://pubmed.ncbi.nlm.nih.gov/17835457/

### Pulpo architectural mapping

Humans should remain legitimate authority sources where policy assigns them authority, but human confidence, conversational familiarity, urgency, interface convenience, and repeated past approval are not substitutes for exact authorization state.

This matters especially for natural-language and voice interfaces. A person may intend "yes" while the system resolves a different object, scope, price, repository, identity, or time boundary.

Pulpo therefore treats the human as an authority principal, not as an infallible parser.

`HUMAN_CONFIDENCE != EXACT_AUTHORIZATION`

`FAMILIARITY != AUTHORITY`

### Design consequence

High-consequence approval should bind the human decision to the exact object being authorized, with identity, scope, policy, time, and replay state represented explicitly rather than inferred from conversational tone.

---

## 3. AI risk governance: intelligence requires an independent management function

### Established source concept

NIST's AI Risk Management Framework organizes AI risk management around the functions **Govern, Map, Measure, and Manage**, with governance as a cross-cutting function throughout the AI lifecycle. NIST describes risk management as continuous and lifecycle-wide rather than a one-time model check.

Sources:

- NIST AI RMF Core: https://airc.nist.gov/airmf-resources/airmf/5-sec-core/
- NIST AI RMF Playbook: https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook

### Pulpo architectural mapping

Pulpo is not a claim of compliance with the AI RMF. The relevance is architectural: intelligence behavior and AI risk management need not occupy the same trust role.

Pulpo makes this separation stronger at execution time:

- intelligence proposes;
- governance resolves authority and policy;
- execution consumes a narrowly bound permit;
- evidence is reconciled before outcome memory is trusted.

`MODEL_OUTPUT != AUTHORITY`

### Design consequence

Pulpo should remain model-independent. A model upgrade, replacement, ensemble, or local model may improve intelligence without changing the constitutional authority boundary.

---

## 4. Security engineering: least privilege and separation of duties

### Established source concept

NIST SP 800-53 includes **AC-5 Separation of Duties** and **AC-6 Least Privilege** among its access-control mechanisms. The least-privilege principle restricts access to what is necessary for assigned tasks; separation of duties reduces the concentration of incompatible powers in one actor or process.

Sources:

- NIST SP 800-53 Rev. 5, **Security and Privacy Controls for Information Systems and Organizations**: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST access-control assessment catalog identifying AC-5 and AC-6: https://csrc.nist.gov/projects/risk-management/about-rmf/assess-step/assessment-cases-download-page

### Pulpo architectural mapping

Pulpo applies the same security instinct to consequential intelligence:

- the proposer should not automatically be the approver;
- the approver should not automatically be the executor;
- the executor should not determine its own authority;
- possession of a tool or credential surface should not imply permission to use it arbitrarily.

Pulpo narrows authority further by binding allowed work to the exact intent and one-use permit.

`CAPABILITY_SURFACE != AUTHORITY_SOURCE`

`APPROVER != EXECUTOR BY DEFAULT`

### Design consequence

Agent specialization must narrow permissions rather than create parallel authority systems. New execution surfaces require separately authorized policy transitions when they expand scope.

---

## 5. Digital identity: voice and biometrics are not authority by themselves

### Established source concept

NIST SP 800-63B distinguishes authentication from capability and explicitly states that a biometric characteristic is not recognized as an authenticator by itself; at higher assurance levels it is combined with possession/control of a physical or cryptographic authenticator. The guidance also requires replay resistance for stronger authentication processes.

Source:

- NIST SP 800-63B, Digital Identity Guidelines — Authentication and Authenticator Management: https://pages.nist.gov/800-63-4/sp800-63b.html

### Pulpo architectural mapping

A voice can be an excellent interaction modality and may eventually contribute to identity signals, but a recording, imitation, transcription, confidence score, or voice match must not independently manufacture consequential authority.

`VOICE != IDENTITY`

`IDENTITY != AUTHORITY`

`SPEECH_CONTENT != PERMIT`

### Design consequence

Pulpo Voice should keep three state classes separate:

1. **expression** — voice, personality, relationship style;
2. **identity/authentication** — who is interacting and with what assurance;
3. **authority** — what that authenticated principal is permitted to authorize now.

The voice layer may request action. It may not silently promote itself into an authority service.

---

## 6. Systems engineering and control: intended state must be verified against realized state

### Established source concept

NASA systems engineering distinguishes product verification from validation and treats verification and validation as explicit processes with requirements, methods, evidence, and acceptance criteria. NASA's V&V guidance includes analysis, inspection, demonstration, testing, end-item integration, system integration, and acceptance testing.

Sources:

- NASA Systems Engineering Handbook, fundamentals and verification/validation distinctions: https://www.nasa.gov/reference/2-0-fundamentals-of-systems-engineering/
- NASA Systems Engineering Handbook, V&V appendices and matrices: https://www.nasa.gov/reference/system-engineering-handbook-appendix/

### Pulpo architectural mapping

Pulpo treats consequential execution as a closed-loop system rather than a one-way instruction pipeline.

A permit establishes what may be attempted. It does not establish that the external consequence occurred correctly.

`AUTHORIZED != EXECUTED`

`EXECUTED != DELIVERED`

`DELIVERED != ACCEPTED`

`EXPECTED_STATE != OBSERVED_STATE`

### Design consequence

The product should increasingly make the full loop explicit:

```text
Purpose
  -> proposed intent
  -> authority and policy
  -> exact permit
  -> execution
  -> evidence
  -> external observation
  -> reconciliation
  -> governed outcome memory
  -> adaptation
```

Pulpo is therefore closer to a governance-and-feedback control plane than to a conventional tool router.

---

## 7. Forensic science: claims about consequence require preserved evidence

### Established source concept

NIST defines chain of custody as tracking evidence through collection, safeguarding, analysis, transfer, and handling. NIST forensic guidance emphasizes evidence preservation, integrity, uncertainty, interpretation, and communication of findings. NIST also identifies errors arising from cognitive bias, broken chain of custody, contamination, mislabeling, misinterpretation, poor documentation, and unvalidated methods.

Sources:

- NIST CSRC glossary, **chain of custody**: https://csrc.nist.gov/glossary/term/chain_of_custody
- NIST, **Evidence Management**: https://www.nist.gov/forensic-science/interdisciplinary-topics/evidence-management
- NIST, **Evidential Statistics**: https://www.nist.gov/spo/forensic-science-program/forensic-science-research/evidential-statistics
- NIST, **Human Factors in Forensic Science**: https://www.nist.gov/forensic-science/human-factors-forensic-science

### Pulpo architectural mapping

An executor's statement that work succeeded is evidence, but it should not be the final authority on what external state now exists.

The same applies to model self-reporting.

`MODEL_ASSERTION != GOVERNED_STATE`

`EXECUTOR_REPORT != EXTERNAL_CONSEQUENCE`

`CLAIMED_EXECUTION != RECONCILED_EXECUTION`

### Design consequence

Pulpo should bind evidence to the exact authorized action object and preserve enough provenance to answer:

- what was authorized;
- what permit was consumed;
- which execution surface acted;
- what it reported;
- what external state was independently observed;
- whether observed state matched expected state;
- which claims are established, disputed, partial, or unknown.

This is the conceptual foundation for evidence-linked outcome memory.

---

## 8. Quantum physics: a discipline in separating model, probability, measurement, and interpretation

### Established source concept

Quantum physics distinguishes mathematical descriptions of systems, probabilistic predictions, experimental measurement, and competing interpretations of what those observations imply. Rebecca Mileham's public description of *Quantum Physics* organizes the subject around the historical breakdown of classical explanations, quantum theory, quantum chemistry, particle physics, quantum calculations and entanglement, tunneling, interpretations, quantum technologies, and unresolved future questions.

Source:

- Rebecca Mileham, **Quantum Physics: my new book is about the mind-bending science that's changing how we understand space, time, matter and reality**: https://rebeccamileham.com/quantum-physics-my-new-book-is-about-the-mind-bending-science-thats-changing-how-we-understand-space-time-matter-and-reality/

### Pulpo architectural mapping

This is an analogy about epistemic discipline, not a claim that Pulpo uses quantum mechanics or derives from quantum theory.

The useful lesson is to keep representation, prediction, measurement, and interpretation distinct.

`MODEL_STATE != OBSERVED_STATE`

`PREDICTED_OUTCOME != MEASURED_OUTCOME`

### Design consequence

Do not use "quantum" as marketing theater. If quantum computers become execution surfaces, Pulpo's rule remains unchanged: greater computational capability does not create greater authority.

---

## Foundation-to-invariant map

| Pulpo invariant | Intellectual support | Engineering consequence |
| --- | --- | --- |
| `CAPABILITY != AUTHORITY` | philosophy; least privilege | models and tools propose/use capability only inside explicit policy |
| `CAN != MAY` | is/ought distinction | optimization does not mint permission |
| `MODEL_OUTPUT != AUTHORITY` | AI risk governance; separation of duties | model replacement does not change authority source |
| `HUMAN_CONFIDENCE != EXACT_AUTHORIZATION` | judgment under uncertainty | approval binds an exact object, not conversational confidence |
| `VOICE != IDENTITY != AUTHORITY` | digital identity assurance | voice remains an interface; authentication and authorization stay separate |
| `"FIRE" != PERMIT` | replay resistance; exact authorization | a command resolves a durable object and requests governance evaluation |
| `AUTHORIZED != EXECUTED` | systems engineering V&V | authorization and realization are separate states |
| `MODEL_ASSERTION != GOVERNED_STATE` | forensic evidence discipline | conversational claims never outrank durable evidence |
| `CLAIMED_EXECUTION != RECONCILED_EXECUTION` | forensics; V&V | external observation is required before strong completion claims |
| `LEARNING != AUTHORITY_EXPANSION` | separation of duties; governance | adaptation may improve competence but policy expansion requires separate authority |
| `MODEL_STATE != OBSERVED_STATE` | measurement discipline | prediction cannot replace observation |

---

## Product implications

### 1. Exact Target becomes the human/computer contract

A conversational target should resolve to an immutable, versioned object before consequential evaluation.

The proposed Target Lock V0 work in PR #55 is consistent with this foundation, but remains noncanonical until separately reviewed and merged.

A future interface may present:

```text
LOCK TARGET
-> exact target object
-> target hash
-> authority effect: none

FIRE
-> reference exact target
-> governance evaluation
-> deny / require approval / permit
```

The command is ergonomic. The durable object is authoritative state.

### 2. One-use permits are the consequence boundary

A successful policy decision should grant only the minimum bounded capability necessary for the exact intended consequence and should resist reuse or substitution.

The permit is not a general endorsement of the model, agent, session, or user request category.

### 3. Reconciliation is a first-class product feature

Pulpo should not stop at `allow` or `deny`.

The differentiated product is the complete loop:

`propose -> authorize -> permit -> execute -> observe -> reconcile -> remember`

Reconciliation is where execution evidence becomes governed outcome knowledge.

### 4. Outcome memory must be evidence-linked

Memory that affects future routing or recommendations should point back to durable evidence, policy versions, permit state, observed consequences, and acceptance results.

Conversational summaries can aid intelligence but should never silently become stronger than the evidence they summarize.

### 5. Voice and relationship are expression layers

Pulpo may become highly personalized: voice, cadence, personality, familiarity, and relationship continuity can make the system substantially easier to use.

Those features should be powerful precisely because they do not need to carry authority.

`RELATIONSHIP != AUTHORITY`

A warm companion interface and a terse command interface may use the same governance kernel without changing the constitutional boundary.

### 6. Intelligence must remain replaceable

The company should optimize for a world in which intelligence providers improve quickly and unpredictably.

Pulpo should be able to govern:

- frontier hosted models;
- local models;
- specialized ensembles;
- deterministic planners;
- human-originated intents;
- scheduled processes;
- future computational substrates.

The intelligence implementation may change. The authority/evidence contract should remain stable.

---

## What this foundation does not claim

This document does not claim:

- that Hume, Tversky, Kahneman, NIST, NASA, forensic science, or quantum physics endorse Pulpo;
- that Pulpo is compliant with NIST AI RMF, SP 800-53, SP 800-63, NASA engineering standards, or forensic standards;
- that analogies to control theory, forensics, or quantum measurement constitute implementation evidence;
- that current Pulpo provides production human authority, host isolation, protected storage, or production readiness;
- that a voice interface is implemented or that voice can authenticate or authorize a consequential action;
- that Target Lock V0 is canonical while PR #55 remains unmerged.

External concepts explain why particular separations are reasonable. Only Pulpo's executable tests and reconciled runtime evidence establish what Pulpo itself actually does.

---

## Reading catalysts

The bookstore reading set that prompted this synthesis is useful as a cross-disciplinary introduction, not as Pulpo's normative source of truth:

- artificial intelligence — capability, learning, reasoning, language, and automation;
- psychology — cognition, bias, identity, decision-making, and human factors;
- philosophy — knowledge, values, rights, duties, skepticism, and the is/ought distinction;
- engineering — control, risk, failure, verification, feedback, and system boundaries;
- forensic science — evidence integrity, provenance, uncertainty, interpretation, and reporting;
- quantum physics — measurement, uncertainty, model/observation distinction, and future computational capability.

When stronger primary standards, peer-reviewed research, or executable evidence exists, it outranks introductory texts.

---

## Company-level formulation

Pulpo's product category can be stated without depending on any particular model vendor:

> Pulpo is the governed execution layer between intelligence and consequential action: the place where a proposed action becomes an authorized, bounded, observable, and reconciled consequence.

The architectural wager is that increasing intelligence capability makes this separation more valuable rather than less valuable.

A more capable intelligence can propose better actions. It still should not be allowed to grant itself authority or declare its own consequences canonical without evidence.

## Review rule

Treat this document as design doctrine only after review and canonical merge.

Any claim derived from it must still be classified as `Verified`, `Recorded`, `Inferred`, `Proposed`, `Blocked`, or `Unknown` according to the strongest available Pulpo evidence.

Learning from these disciplines may improve Pulpo's competence, terminology, proof design, and product framing. It may not expand Pulpo authority by itself.
