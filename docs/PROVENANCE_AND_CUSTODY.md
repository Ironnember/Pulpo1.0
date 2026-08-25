# Provenance and custody doctrine

Status: design doctrine / not a claim of deployed government capability
Date: 2026-08-25

## Origin

A real-world records discussion exposed a useful governance failure mode: a consequential physical record can leave one authority domain while the person handling the originating process cannot explain its eventual physical disposition. That observation is not evidence about any specific government's archival practice. It is a design prompt for Pulpo.

## Core invariant

**Same data != same provenance != same authority.**

Possession, transcription, scanning, or reproduction of evidence must never confer the authority of the evidence issuer. A verifier must establish provenance, integrity, scope, issuer authority, validity, and applicable replay/revocation state independently of the presented content.

Related invariant:

**Consequence != record of consequence != certified proof of consequence.**

Pulpo must keep the underlying event or state transition, the record describing it, and an authoritative/certified representation of that record conceptually distinct.

## Governed custody lifecycle

For a cross-institution record transfer, the target model is:

`originating event -> authoritative record -> transfer authorization -> custody handoff -> recipient acknowledgement -> archival/disposition state -> certified derivative -> verifier -> downstream consequence -> reconciliation`

Each consequential transition should resolve to:

- record/object identity;
- originating authority domain;
- authorized custodian or recipient;
- policy/version governing the transition;
- expected destination/state;
- execution evidence;
- recipient acknowledgement where applicable;
- integrity reference/hash where appropriate;
- retention/disposition policy;
- current known state;
- reconciliation status and unresolved variance.

## Reconciliation rule

A send event is not proof of receipt. Receipt is not proof of correct filing. Filing is not proof of continuing validity. A certified derivative is not the underlying event.

Therefore Pulpo should preserve distinctions such as:

`AUTHORIZED != SENT != RECEIVED != FILED != CERTIFIED != ACCEPTED`

This extends the commerce doctrine:

`AUTHORIZED != PAID != DELIVERED != ACCEPTED != VALUABLE`

When expected state and observed state diverge, Pulpo should create a reconciliation exception rather than silently treating execution as completion.

## Physical and digital records

Pulpo does not require physical artifacts to exist forever. If an authorized retention policy permits destruction, transfer, archival migration, or supersession, the disposition itself should be an attributable governed transition. The system should report the evidence-backed disposition rather than imply the original still exists.

Digital copies likewise do not become authoritative merely because their bytes or visible content match an authoritative record.

## Federated government application

Pulpo should not become a universal government database or sovereign authority. County, state, federal, tribal, municipal, judicial, and other legitimate domains retain their own authority roots and legal responsibilities.

Pulpo's role is the portable governance/evidence contract between domains: who authorized a transition, what was permitted, what occurred, what evidence supports it, what the receiving domain acknowledged, and whether the resulting state reconciles.

## Machine-verifiable certified derivatives

A future certified derivative could bind, subject to applicable law and privacy requirements:

- authoritative record reference;
- issuing authority/key identifier;
- certified fields or claims;
- issuance time;
- validity/expiry where applicable;
- revocation/supersession status;
- integrity digest;
- minimal-disclosure verification data.

This supplements rather than presumes replacement of statutory paper, seal, notary, records-retention, evidentiary, or identity requirements.

## AI/agent implication

The same rule applies to machine authority. An agent that can read an approval, permit, certificate, receipt, or credential must not thereby gain the ability to mint or impersonate its issuer.

The governed agent may request authority. It may not create, derive, invoke, enroll, or impersonate the independent mechanism that grants that authority.

## Canonical mapping

This doctrine maps onto Pulpo's existing sequence:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

Custody transfer is execution. Recipient acknowledgement is evidence. Expected-state versus observed-state comparison is reconciliation. Durable disposition and outcome history become memory. Any policy change remains subject to legitimate authority rather than being self-granted by an agent.

## Proof status

- **Proven:** Pulpo1.0 contains executable governance mechanisms only where separately covered by repository tests.
- **Implemented:** this document records no new runtime mechanism by itself.
- **Planned:** generalized cross-domain custody tracking, certified-derivative verification, retention/disposition reconciliation, and government adapters remain design targets until implemented and tested.

## Reusable design test

For every future integration involving documents, money, credentials, deployments, physical assets, government records, healthcare records, scientific artifacts, or other consequential state, ask:

1. What is the underlying consequence?
2. What record represents it?
3. Who has legitimate authority to certify that record?
4. Can possession of the record be confused with authority to issue it?
5. What state is expected after execution?
6. What independent evidence establishes the observed state?
7. Who currently has custody or responsibility?
8. What happens if acknowledgement never arrives?
9. What retention/disposition rule applies?
10. Can an outside verifier distinguish authorized, executed, evidenced, reconciled, and accepted states?
