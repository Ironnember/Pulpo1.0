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

Lifecycle state after creation of PR #27:

- intended: yes;
- authorized: app registration, single-key setup, selected-repository
  installation, and preparation of this candidate were separately confirmed;
- permitted: repository proposal capability is installed;
- attempted: registration, installation, token minting, and one proposal;
- executed: clean app, selected-repository installation, one scoped token, one
  branch, one commit, and one pull request created;
- externally observed: app, single public key, effective permissions, and sole
  repository selection observed in GitHub; PR #27 reports the App as author;
- bot-authored proposal: externally observed;
- human review: GitHub reports `REVIEW_REQUIRED` and merge state `BLOCKED`;
- required checks: the first candidate run passed `authority`, failed `test`
  because of two trailing spaces, and had not completed `authority-service` at
  reconciliation time;
- merged: no;
- reconciled: partial.

Primary outcome class before the bot-authored pull request:

`SUCCESS_PARTIAL`

Root-cause tags from the local validation path:

- host/environment drift: the shell had no `python` command;
- execution capability mismatch: the default `python3` was 3.9 while the
  project requires Python 3.11 or newer;
- bounded recovery: an already-installed supported interpreter was selected;
- evidence incomplete: pre-commit `git diff --check` did not inspect the
  untracked new document, so GitHub detected two trailing spaces;
- bounded adaptation: validate the committed candidate or explicitly include
  new files before treating the whitespace check as passed;
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
- [Bot-authored proposal PR #27](https://github.com/Ironnember/Pulpo1.0/pull/27)
- [Initial bot-authored commit](https://github.com/Ironnember/Pulpo1.0/commit/4a82072bbd4c7edbb5d4e8d9452cac9b1067f83c)

The final candidate check runs, review disposition, and observed unchanged
`main` must be reconciled before the proposal path is classified
`SUCCESS_VERIFIED`.

## Claim classification

### Verified

- the clean App registration, single public key, permission selection, and
  selected-repository installation were externally observed and recorded;
- the private key was validated locally without displaying its contents;
- a repository- and permission-scoped installation token created PR #27 as
  `pulpo-proposal-bot[bot]` without persisting the token;
- GitHub reports the proposal as blocked and requiring review;
- this candidate imports no legacy runtime code and creates no runtime path.

### Recorded

- the bot is intended only to propose a change for human disposition;
- credential material remains separate from repository evidence.

### Proposed or pending

- require all three final candidate-state checks and explicit human review;
- leave the pull request unmerged for human disposition.

### Not tested

- successful final candidate-state check results;
- human acceptance or rejection of the proposal;
- any merge consequence, because no merge is authorized by this proof.

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
