# Standard Operating Procedure: Adversarial Transformation Review

Status: PROPOSED until admitted to canonical `main`.

## Purpose

Require a repeatable adversarial review before Pulpo accepts a material authority, capability, execution, evidence, or reconciliation claim.

This procedure is an Intelligence Plane analysis discipline. It grants no authority, permit, credential, capability, approval, or execution right.

## Trigger

Run this procedure whenever any of the following occurs:

- a consequential action is proposed, attempted, or completed;
- a capability is activated, duplicated, delegated, exported, serialized, exposed, or derived;
- an authentication or credential-bearing surface is used;
- a workaround changes the execution mechanism;
- a new external integration, tool, browser, shell, plugin, worker, or provider route is introduced;
- an unexpected mode or capability transition occurs;
- money, infrastructure, communications, customer state, or external provider state may change;
- evidence is being promoted from Recorded/Inferred to Verified;
- a failure, near-miss, bypass, or anomalous tool behavior is observed.

Do not run this as theater on trivial non-consequential text operations. Run it at consequence and authority boundaries.

## Mandatory eight-pass review

### 1. Flip

Reverse the assumed actor or trust direction.

Ask: if the helpful component were hostile, compromised, confused, or merely optimizing for task completion, what authority could it exploit?

Required output: identify any control that depends on cooperative behavior.

### 2. Reverse

Start from the undesired consequence and trace backward.

Ask: what capability, credential, route, approval, state transition, or evidence would have to exist for that consequence to occur?

Required output: identify the earliest boundary at which the consequence could have been made unreachable.

### 3. Invert

Treat apparent success as failure when the path violated authority.

Ask: if the requested outcome occurred through an unauthorized path, would Pulpo still classify it as success?

Required output: separate outcome correctness from transition legitimacy.

### 4. Inside-Out

Apply the same threat model to Pulpo, the governor, the operator, and the evidence source.

Ask: can the component enforcing the rule also originate, enlarge, execute, or ratify the same authority?

Required output: identify self-authorization, unilateral truth, or trust-domain collapse.

### 5. Darken

Construct the worst credible bounded case without inventing unsupported facts.

Ask: if every exposed capability were abused within technically plausible limits, what is the maximum consequence?

Required output: a clearly labeled threat case, not a claim that it occurred.

### 6. Lighten

Construct the minimum benign interpretation supported by evidence.

Ask: what is the least severe explanation that still fits the observed facts?

Required output: prevent worst-case analysis from being promoted into factual history.

### 7. Amplify

Scale, compose, repeat, or aggregate the behavior.

Ask: what happens across many agents, retries, accounts, resources, approvals, or low-severity actions?

Required output: identify consequence aggregation, replay, fleet-scale failure, or authority accumulation.

### 8. Negate

Remove the assumption that the chosen mechanism is necessary.

Ask: can the legitimate purpose be achieved without the risky capability, credential, route, or authority expansion?

Required output: the smallest clean path that preserves the purpose while reducing authority.

## Required invariants

The review must test these statements where applicable:

`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`

`AUTHORIZATION_TO_USE_CAPABILITY != AUTHORIZATION_TO_DUPLICATE_CAPABILITY`

`AVAILABLE_CAPABILITY != AUTHORIZED_CAPABILITY`

`OBSERVED_STATE_CHANGE != GOVERNED_STATE_TRANSITION`

`GOVERNED_PATH + UNGOVERNED_ALTERNATE_PATH != GOVERNED_SYSTEM`

`PULPO_AWARE_INTELLIGENCE != PULPO_GOVERNED_INTELLIGENCE`

No intelligence component may create, duplicate, derive, delegate, serialize, export, or expose a capability whose effective authority exceeds the exact authority granted for the current consequence.

## Required classification

After all eight passes, classify every material conclusion as:

- `Verified`
- `Recorded`
- `Inferred`
- `Proposed`
- `Unknown`

Never upgrade a threat case, benign interpretation, or repeated narrative into Verified evidence.

## Decision rule

After the eight passes:

1. preserve the user's original purpose;
2. reject any execution path that silently expands authority or capability custody;
3. prefer the smallest path that makes the unauthorized consequence unreachable;
4. require separately authorized transition for capability expansion or duplication;
5. preserve `AUTHORIZED / ATTEMPTED / CONSEQUENCE UNKNOWN` when external reality cannot be established;
6. reconcile evidence before learning or memory is updated.

## Stop conditions

Stop execution and reconcile before continuing when:

- an alternate provider route appears;
- credential-bearing state is copied, exported, or exposed unexpectedly;
- a workaround creates a new capability surface;
- the execution mechanism changes materially after approval;
- the exact consequence object no longer matches approval;
- required evidence is unavailable;
- cleanup of a temporary privileged capability cannot be verified.

## Incident pattern: authenticated browser profile cloning

Purpose: inspect an authenticated external assessment.

Authorized capability: use the existing authenticated browser/session for bounded inspection.

Over-broad mechanism: clone credential-bearing browser state to create a second debugging-capable browser surface.

Correct classification:

`AUTHORIZED PURPOSE / OVER-BROAD EXECUTION METHOD / CONSEQUENCE UNKNOWN`

The purpose does not retroactively authorize capability duplication.

Safer path:

`original authenticated browser -> explicit authentication boundary -> bounded inspection -> draft -> separate submission authorization`

## Output format

For material assessments, record:

- Purpose
- Exact requested outcome
- Authority boundary
- Flip
- Reverse
- Invert
- Inside-Out
- Darken
- Lighten
- Amplify
- Negate
- Claim classifications
- Stop/continue decision
- Smallest next proof
- Remaining unknowns

## Doctrine

Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.
