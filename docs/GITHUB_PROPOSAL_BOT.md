# GitHub Proposal Bot Operating Contract

Status date: 2026-08-26  
Canonical repository: `Ironnember/Pulpo1.0`  
Governed identity: `Pulpo Proposal Bot`

## Purpose

The proposal bot is a bounded automation identity for creating reviewable pull
requests in the sole canonical repository. It may propose. It may not decide,
approve, merge, administer, deploy, create authority, or treat a provider write
as proof of acceptance.

This identity is not a Pulpo runtime authority path, router, executor, ledger,
worker, or human approver.

## Registered boundary

The externally observed GitHub state is:

- GitHub App ID: `4734310`;
- installation ID: `156907110`;
- repository selection: only `Ironnember/Pulpo1.0`;
- repository permissions: Contents read/write, Pull requests read/write,
  Issues read, and Metadata read;
- webhooks, event subscriptions, OAuth-on-install, and Device Flow disabled;
- one registered public-key fingerprint:
  `SHA256:P5LMYXoIG/5V5KdNc+rZnBvbh73OaIjr1awYug6qQ5Y=`.

The private key remains outside the repository. It must never enter Git,
pull-request text, logs, issue comments, test fixtures, CI, or Pulpo evidence.

GitHub's Contents and Pull requests write permissions are broader than the
single proposal operation. They may provide technical capability beyond this
contract, including later pull-request mutations. That provider capability is
not authority. The bot is prohibited from calling approve, merge, repository
administration, deployment, secret, installation-management, or unrelated
pull-request mutation surfaces.

## Allowed operation

For one separately authorized proposal, the bot may:

1. read the exact current canonical `main` commit;
2. mint one short-lived installation token scoped to the selected repository
   and no broader permissions than the registered boundary;
3. create one namespaced branch from that exact commit;
4. push the reviewed candidate commit to that branch;
5. open one pull request containing the required governance and evidence
   sections;
6. read the resulting pull request and checks for reconciliation; and
7. allow the token to expire without persisting it.

Any new proposal requires a new human instruction and a newly reconciled base.

## Stop conditions

The operation must stop without fallback if:

- canonical `main` differs from the reviewed base commit;
- the local diff differs from the reviewed candidate;
- GitHub reports a different repository, installation, identity, or permission
  boundary;
- a token or private-key value would be printed, persisted, committed, or sent
  through another service;
- branch protection, required checks, or human review are absent or bypassed;
- the bot would need to approve, merge, deploy, administer, or expand scope;
- any runtime, authority-service, worker, commerce, or legacy code enters the
  proposal; or
- external evidence cannot establish the resulting state.

No alternate repository, direct push to `main`, stale-stack merge, or human-
credential fallback is allowed.

## Proof and reconciliation

The proposal path is verified only when GitHub independently reports all of the
following for the exact candidate merge state:

- the pull request was opened by the GitHub App identity;
- its branch descends from the reviewed canonical `main` commit;
- its commit and file diff match the reviewed candidate;
- required checks `test`, `authority`, and `authority-service` succeed;
- the governance change remains blocked pending explicit human review;
- canonical `main` is unchanged; and
- no approval, merge, deployment, purchase, worker execution, or authority-
  service deployment occurred.

Opening a pull request is not sufficient evidence:

`PROPOSED != REVIEWED != MERGED != VERIFIED != CANONICAL`

## Outcome Learning record

Lifecycle state at contract creation:

- intended: yes;
- authorized: app registration, single-key setup, selected-repository
  installation, and preparation of this candidate were separately confirmed;
- permitted: repository proposal capability is installed;
- attempted: registration and installation only;
- executed: clean app and selected-repository installation created;
- externally observed: app, single public key, effective permissions, and sole
  repository selection observed in GitHub;
- bot-authored proposal: `NOT_TESTED` until GitHub reports the pull request;
- human review: `NOT_TESTED` until the proposal reaches that gate;
- merged: no;
- reconciled: partial.

Primary outcome class before the bot-authored pull request:

`SUCCESS_PARTIAL`

Root-cause tags from the local validation path:

- host/environment drift: the shell had no `python` command;
- execution capability mismatch: the default `python3` was 3.9 while the
  project requires Python 3.11 or newer;
- bounded recovery: an already-installed supported interpreter was selected;
- authority unchanged: no permission or policy expansion was used.

Reusable path:

1. verify canonical repository, base commit, and protection state;
2. prepare the minimal candidate in an isolated checkout;
3. run supported local validation and disclose skipped optional coverage;
4. obtain action-specific human confirmation immediately before token minting;
5. mint the shortest-lived, repository-scoped installation token;
6. create one branch and one pull request as the App;
7. reconcile GitHub's actor, diff, checks, review gate, and unchanged `main`;
8. do not approve or merge.

## Evidence

- [Clean replacement App recorded](https://github.com/Ironnember/Pulpo1.0/issues/25#issuecomment-5434274101)
- [Single-key state recorded](https://github.com/Ironnember/Pulpo1.0/issues/25#issuecomment-5434294886)
- [Selected-repository installation recorded](https://github.com/Ironnember/Pulpo1.0/issues/25#issuecomment-5434332570)
- [Capability tracking issue](https://github.com/Ironnember/Pulpo1.0/issues/25)

The eventual pull request, commit, check runs, review requirement, and observed
unchanged `main` must be added as external evidence before the proposal path is
classified `SUCCESS_VERIFIED`.

## Claim classification

### Verified

- the clean App registration, single public key, permission selection, and
  selected-repository installation were externally observed and recorded;
- the private key was validated locally without displaying its contents;
- this candidate imports no legacy runtime code and creates no runtime path.

### Recorded

- the bot is intended only to propose a change for human disposition;
- credential material remains separate from repository evidence.

### Proposed

- create one bot-authored pull request containing this contract;
- require all three candidate-state checks and explicit human review;
- leave the pull request unmerged for human disposition.

### Not tested

- installation-token minting for this clean App;
- GitHub actor attribution on the proposed pull request;
- exact candidate-state check results;
- provider enforcement of the human-review gate for this proposal.

### Unproven boundary

This contract does not prove that the App is incapable of every prohibited API
call. It proves a governed operating boundary only after the observed proposal
matches the authorized operation and forbidden surfaces remain unused. It does
not prove runtime containment, independent human authority, production
readiness, deployment, purchase execution, or Mac-worker behavior.

## Legacy source disposition

No behavior or code is imported from `Iron-Ember/pulpo`. The historical
repository remains evidence only and cannot become current through recency,
automation, or a successful provider write.
