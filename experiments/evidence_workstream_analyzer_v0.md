# Evidence-Grounded Workstream Analyzer V0

Status: proposed learning experiment; no authority effect.

## Purpose

Test whether Pulpo can reconstruct useful operational learning from agent transcripts, git history, CI, Pulpo governance evidence, and independent observations without allowing model narrative or learned recommendations to become authority.

The useful pattern is inspired by coding-work analysis systems such as YC Paxel, but this experiment does not import another memory, governance, policy, or evidence authority.

## Constitutional boundary

`TRANSCRIPT != EVIDENCE`

`MODEL_SUMMARY != OUTCOME`

`LEARNING_RECOMMENDATION != AUTHORITY`

`REPEATED_SUCCESS != AUTHORITY_EXPANSION`

`RECONCILIATION_TEACHES != RECONCILIATION_LEGISLATES`

Pulpo's existing canonical evidence and Outcome Learning Protocol remain authoritative. This experiment is a derived projection only.

## Inputs

V0 may consume sanitized references to:

- agent session/transcript events;
- git commits and diffs;
- CI/check outcomes;
- Pulpo approvals, permits, denials, and audit evidence;
- independent provider/observer evidence;
- measured runtime/tool metadata.

Raw secrets, credentials, authentication material, and private key material are out of scope.

## Derived records

The experiment may derive:

- `WorkSession`;
- `Workstream`;
- `DecisionExchange`;
- `OutcomeEpisode`;
- `FailureSignature`;
- `ReusableCompletionPath`;
- `LearningRecommendation`.

Every material outcome claim must carry evidence references and claim classification. Derived records cannot overwrite canonical evidence.

## Frozen V0 proof

Using one bounded Pulpo development workstream:

1. reconstruct the session/workstream from transcript events plus repository evidence;
2. identify material decisions;
3. link each decision to available evidence and resulting outcome;
4. classify at least one verified success or healthy denial when evidence supports it;
5. inject a false model/transcript success claim and prove stronger canonical/external evidence wins;
6. remove or mutate transcript narrative and prove canonical outcome classification does not change when underlying evidence is unchanged;
7. restart/reload the derived episode and prove evidence references and classification remain stable;
8. derive one reusable completion path or failure signature;
9. produce one learning recommendation;
10. prove the recommendation cannot modify authority, policy, budget, identity scope, approval class, credentials, or execution capability.

## Scoring

V0 records independently:

- evidence-link completeness;
- decision-to-outcome linkage accuracy;
- false-success rejection;
- transcript-mutation stability;
- restart stability;
- reusable-path extraction;
- recommendation generation;
- authority effect, which must remain `none`.

No aggregate intelligence score may substitute for these measurements.

## Relationship to unauthorized-effect benchmark

The unauthorized-effect benchmark asks whether hostile intelligence converts to unauthorized consequence.

This experiment asks whether Pulpo can learn from the resulting evidence without allowing that learning to govern.

Combined target loop:

`hostile/proposing intelligence -> governed consequence -> independent effect observation -> reconciliation -> evidence-grounded learning -> recommendation -> separately authorized adaptation`

The two experiments remain separate so neither can grade or authorize the other.

## Nonclaims

V0 does not claim:

- autonomous policy improvement;
- autonomous authority expansion;
- perfect causal inference from transcripts;
- that model-generated summaries are evidence;
- that every coding harness exposes equivalent transcript data;
- that a derived workstream store is a new canonical ledger or memory authority.

## Admission rule

Passing this experiment may justify a subordinate learning projection over existing Pulpo evidence. It cannot authorize its own merge, deployment, policy change, or authority expansion.
