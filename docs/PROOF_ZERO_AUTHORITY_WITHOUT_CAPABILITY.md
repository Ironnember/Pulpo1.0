# Proof Zero Case: Authority Without Capability

Status date: 2026-08-26
Repository: `Ironnember/Pulpo1.0`
Case: GitHub canonical `main` branch protection

## Summary

This case records a real governance event in which legitimate human authority existed, the requested change was explicitly authorized, the execution surface lacked the capability needed to carry out that change, and the resulting failure was preserved rather than converted into a false success claim.

It is evidence for one of Pulpo's core constitutional distinctions:

> Authority and capability are different things.

A human principal may legitimately authorize an outcome. A particular executor may still be unable to perform it. Pulpo's job is not to erase that distinction. Pulpo should preserve it, fail closed where necessary, and reconcile the authorized state against the observed execution state.

## Canonical governance mapping

Pulpo's canonical lifecycle is:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

This case maps to that lifecycle as follows.

### Purpose

Protect the canonical Pulpo repository so changes to `main` cannot bypass the review and evidence path expected by Pulpo's constitutional doctrine.

### Intent

Enable repository controls requiring pull-request-mediated changes to `main`, disable force pushes and branch deletion, require the existing `test`, `authority`, and `authority-service` CI jobs, and require human review for authority-, policy-, and governance-semantic changes.

### Authority

GitHub reported the `Ironnember` principal as having `admin` permission on `Ironnember/Pulpo1.0`.

The human owner then explicitly authorized enabling the requested protection.

This establishes that the human decision existed and came from a repository administrator.

### Policy

The governance requirement is recorded in PR #21 and on its branch:

- changes enter `main` through pull requests;
- force pushes are disabled;
- branch deletion is disabled;
- `test`, `authority`, and `authority-service` must pass before merge;
- authority-, policy-, and governance-semantic changes require explicit human review;
- checks should evaluate the exact candidate merge state.

### Decision

The requested repository hardening was authorized by the human owner.

### Execution

The connected GitHub integration attempted to reach the repository branch-protection administration boundary.

GitHub returned:

`403 Resource not accessible by integration`

The failure was attributed to the connected execution surface's integration scope, not to absence of human administrative authority.

### Evidence

The evidence chain includes:

1. GitHub repository permission result showing `Ironnember` has `admin` permission.
2. GitHub branch metadata showing canonical `main` is currently `protected: false` and required status-check enforcement is off.
3. Existing `.github/workflows/ci.yml` defining the `test`, `authority`, and `authority-service` jobs.
4. The branch-protection administration attempt returning HTTP 403 from the connected integration.
5. PR #21 recording the required repository governance state.
6. The owner's explicit authorization recorded as a durable PR comment.
7. No evidence that GitHub branch protection has yet become enabled.

### Reconciliation

Expected state:

`human_authorized = true`

`repository_admin_authority = true`

`main_protected = true`

Observed state:

`human_authorized = true`

`repository_admin_authority = true`

`connector_admin_capability = insufficient`

`main_protected = false`

Result:

`AUTHORIZED != EXECUTED`

The authorized outcome did not occur because the selected execution surface lacked the necessary administrative capability.

### Memory

The durable lesson is not "try harder until the action succeeds." The durable lesson is:

> Legitimate authority must not be confused with executor capability, and executor failure must not be rewritten as successful consequence.

The event therefore belongs in Pulpo's Outcome Memory as a blocked execution with preserved human authorization and an identified capability gap.

### Adaptation

The appropriate adaptation is to use an execution surface that actually possesses the required GitHub administrative scope, while preserving the same human authorization and repository policy objective.

The adaptation must not grant the current connector additional authority by assumption. Its capability must be changed through the external provider's legitimate administrative mechanism and then independently verified.

## Claim classification

### Verified

- The canonical repository is `Ironnember/Pulpo1.0`.
- GitHub reports `Ironnember` has admin permission on the repository.
- GitHub reports canonical `main` is not currently protected.
- Existing CI defines `test`, `authority`, and `authority-service` jobs.
- The branch-protection administration attempt returned HTTP 403 from the connected integration.
- PR #21 exists and records the target governance requirement.
- The human owner explicitly authorized the branch-protection change and that authorization was recorded on PR #21.

### Recorded

- The owner authorization is durably present in the PR discussion.
- The governance requirement is durably present in the PR branch documentation.

### Inferred

- The 403 resulted from the connected integration's administrative scope rather than the owner's repository permission. This inference is supported by the verified admin-permission result and the integration-specific failure.

### Proposed

- Enable the required protection through a GitHub administrative surface that possesses sufficient scope.
- Verify afterward that GitHub reports `protected: true` and the expected required checks and review rules are active.

### Blocked

- Claiming branch protection as enforced before GitHub itself reports the controls enabled.

## Why this matters beyond GitHub

This case is a compact example of a general governed-agency problem.

A principal may authorize an agent to spend money, deploy software, operate infrastructure, or invoke a service. That authorization does not guarantee that the selected execution surface can complete the action. Credentials may be missing. A provider may reject the request. A network boundary may deny access. An API scope may be insufficient. The external state may have changed.

A trustworthy governance system therefore cannot stop at authorization.

It must distinguish at least:

`AUTHORIZED != EXECUTED != DELIVERED != ACCEPTED != VALUABLE`

For repository administration in this case:

`AUTHORIZED != PROTECTION_APPLIED != PROTECTION_VERIFIED`

For commerce:

`AUTHORIZED != PAID != DELIVERED != ACCEPTED != VALUABLE`

The same reconciliation structure applies across both domains.

## Stronger Pulpo invariant derived from the case

> Authority determines what may be attempted. Capability determines what can be attempted through a given execution surface. Evidence determines what actually happened. Reconciliation determines whether the authorized objective became an acceptable consequence.

This extends the compact Pulpo doctrine:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

with an operational corollary:

> Governance may authorize execution, but only evidence may establish consequence.

## Anti-theater value

The strongest evidence in this case is not that the requested change succeeded. It did not.

The evidence is that the system preserved the failure boundary accurately:

- legitimate authority was recognized;
- execution capability was checked rather than assumed;
- the external provider refused the operation;
- no workaround was presented as equivalent protection;
- no documentation was allowed to claim `main` was protected;
- the authorization and failure were recorded separately;
- the next action was constrained to obtaining a legitimately capable execution surface.

This is the opposite of governance theater. A weaker system could have conflated an owner's approval with completed enforcement. Pulpo's doctrine requires the opposite: consequence remains unproven until externally observed state matches the authorized target.

## Reusable proof pattern

This case should become a reusable test template for future Pulpo integrations:

1. Establish principal identity and legitimate authority.
2. Record the exact intended consequence.
3. Verify policy permits the attempt.
4. Bind execution to the selected capability surface.
5. Attempt the action.
6. Capture provider/runtime evidence whether success or failure occurs.
7. Independently inspect the resulting external state.
8. Reconcile intended state against observed state.
9. Record success, variance, or blocked outcome without collapsing the states.
10. Permit adaptation only through a legitimate authority path.

## Proof Zero significance

Pulpo's founder case is intended to show a human directing machine capability without surrendering legitimate authority. This event adds a complementary proof:

> Human authority was present, machine execution was bounded by the actual capability of its tool, and evidence prevented either side from pretending that authorization alone changed reality.

That is a concrete instance of governed agency rather than an abstract statement about it.

The case also demonstrates why Pulpo needs both governance and reconciliation. Governance answered whether the change was legitimate. GitHub answered whether this executor could perform it. Evidence showed that it could not. Reconciliation preserved the difference. Outcome Memory records the exact gap so the next attempt can use a properly authorized and capable surface without silently broadening machine authority.

## Graduation condition

This case closes only when an authorized GitHub administrative surface applies the required controls and independent repository inspection verifies:

- `main` is protected;
- pull requests are required;
- force push is disabled;
- branch deletion is disabled;
- required checks include `test`, `authority`, and `authority-service`;
- the expected human-review rule is active for consequential governance changes.

Until that evidence exists, the correct outcome remains:

**Human authority: verified.**

**Human authorization: recorded.**

**Executor capability: insufficient.**

**Repository protection: blocked.**

**No false success claim permitted.**
