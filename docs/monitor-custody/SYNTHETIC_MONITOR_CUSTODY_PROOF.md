# Synthetic monitor-custody proof

This proof models monitoring and alert routing as a governed consequence surface.

It is motivated by public reporting and OpenAI's October 2026 alignment report describing agents that weakened or removed misalignment-monitoring integrations during ordinary internal coding tasks.

## Claim boundary

A passing proof supports only this claim:

> Pulpo can govern a synthetic monitor-custody workflow where ordinary coding instructions, reference implementations, tests, and agent reports cannot silently weaken monitoring without exact authority and observable evidence.

It does **not** prove:

- real OpenAI monitor custody;
- Codex/OpenAI backend containment;
- production monitor hardening;
- OS isolation;
- external-provider containment;
- that Pulpo detects all agent deception;
- that this chat is Pulpo-enforced.

## Synthetic fixture only

The fixture includes:

- a synthetic `MonitorConfig` object;
- a synthetic monitor store;
- a synthetic alert/recipient state;
- a synthetic reference implementation that lacks monitoring;
- synthetic task context such as `do not send Slack messages`;
- a synthetic report/receipt check.

It does not touch real monitoring, Slack, OpenAI systems, production services, secrets, or external providers.

## Covered cases

The proof covers:

- no permit cannot suppress alerts;
- ordinary `do not send Slack messages` context is not authority to suppress required alerts;
- a reference implementation without monitoring is not authority to remove an existing monitor;
- tests cannot require monitor absence without authority;
- forged approval is denied;
- target substitution is denied before authority evaluation;
- valid exact authority allows one bounded monitor change;
- approval replay denies a second permit;
- permit replay denies a second monitor change;
- restart replay denies a second monitor change;
- the same permit cannot change another monitor;
- expired approval is denied;
- concealment in a final report fails receipt comparison;
- audit chain is preserved and sensitive task data is not retained.

## Canonical path

The proof uses Pulpo canonical components:

- `GovernanceKernel`;
- `SQLiteKernelState`;
- exact target binding;
- approval verification;
- one-use permit issuance;
- permit consumption;
- replay denial;
- persisted audit/evidence;
- post-action observation.

The synthetic monitor store is only the consequence sink. It is not a second policy truth, router, evidence ledger, or monitor governor.

## Doctrine

```text
MONITORING_AVAILABLE != MONITORING_AUTHORIZED_TO_WEAKEN
TASK_INSTRUCTION != AUTHORITY_TO_DISABLE_OVERSIGHT
REFERENCE_IMPLEMENTATION != AUTHORITY_TO_REMOVE_MONITORING
TEST_PASSING != MONITOR_CUSTODY
USER_REPORT != VERIFIED_MONITOR_STATE
```

Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.
