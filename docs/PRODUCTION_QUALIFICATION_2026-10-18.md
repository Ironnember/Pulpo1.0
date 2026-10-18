# Production qualification follow-up

Status: candidate; production release remains blocked. Parent source:
`6ec73ff38e05541725b006e66759784a4d188326` (draft PR #314).

## Change and acceptance

The authority CI job previously returned success while four PostgreSQL cases
skipped because no test database was configured. It now declares a disposable
PostgreSQL 16 service and installs the pinned `postgres-test` optional dependency.
The existing job name is retained so its required-check identity does not change.
The new runner rejects missing reset consent, missing configuration, remote or
ambiguous targets, empty suites, failures and skips. Only the named loopback test
database is accepted, and ambient libpq routing variables are removed. Its reset
consent authorizes the existing synthetic tests to drop their test state table;
it is never permission to alter a deployed authority database.

Local reproduction with an already isolated disposable PostgreSQL server:

```sh
python -m pip install '.[authority]' './authority-service[test,postgres-test]'
PULPO_AUTHORITY_TEST_ALLOW_RESET=1 \
PULPO_AUTHORITY_TEST_POSTGRES_DSN='host=127.0.0.1 port=5432 dbname=pulpo_authority_test user=pulpo_test' \
python -W error scripts/run_authority_postgres_proof.py
```

Use a fresh test cluster and dedicated role. The runner's target checks do not
establish whole-host isolation or make a shared database safe to reset. CI uses
an ephemeral service and synthetic credentials; no production secret is needed.

## Release gates and ownership

1. A distinct engineer reproduces the final proposed source and reviews its
   changes. Preserve parent/candidate revisions, dependency versions, logs,
   skips, hashes and explicit findings. Earlier reviews do not approve this tree.
2. The cloud custodian restores the intended environment under an explicit cost
   ceiling. Read-only inventory on October 18 returned no Cloud Run services in
   project `dulcet-opus-499511-a5`, region `us-west1`, and reported
   `pulpo-authority-db` as `SUSPENDED`. These observations do not establish the
   suspension's cause or the state of other projects/regions.
3. Qualify the deployed PostgreSQL driver and IAM/private-network path, roles,
   durable replay/revocation state, restart, outage and restore. The local proof
   uses psycopg; production's Cloud SQL connector uses pg8000. Driver doubles and
   local PostgreSQL execution do not close the managed-provider gate.
4. Independently verify the pinned non-exportable signer, locked evidence
   retention, worker identity, authenticator provenance and human enrollment.
   Real credentials stay with their custodians. Do not use software test fixtures
   to replace the human approval boundary.
5. Run the existing sandbox custody ceremony: missing/revoked/substituted approval
   produces zero transmissions; one exact approval produces one consequence;
   replay and restart/replay produce no additional consequence; direct worker
   provider access is denied; independent observation reconciles the result into
   the existing canonical chain. Preserve unknown outcomes without automatic retry.
6. Require the repository's current protected admission process and an explicit
   release decision. Qualify alerts, readiness, rollback and restoration before
   sending customer traffic. Check live protection state at admission time.

## Required authority and adversarial record

Invariant: a green authority database check must include live database execution.
Authority gained: none in the application. Canonical state transitions, policy,
signer, credentials, executor and evidence ownership are unchanged. The only new
reset surface is an explicit test runner over disposable state. No second ledger
or governor is introduced. Existing test cases are reused without copying their
authority path; no general transferable learning claim is made.

- Flip: treat ambient database configuration as hostile; reject target ambiguity.
- Reverse: deny before discovery can execute destructive database tests.
- Invert: skipped or empty execution cannot qualify as a successful database proof.
- Inside-Out: a green CI job is evidence, not approval or deployed custody.
- Darken: a mistaken database target could delete its state table; isolated
  provisioning and explicit reset consent remain necessary.
- Lighten: the observed earlier gap is test configuration, not evidence of a
  production data-loss incident.
- Amplify: exercise existing independent-connection races and fail every skipped case.
- Negate: use one existing job, state adapter and test suite rather than create
  another authority or deployment service.

Claim classes: source changes and local execution may be Verified in their
recorded environment; hosted runs and cloud inventory are Recorded platform
evidence. Managed-provider acceptance, human approval, protected deployment and
production readiness remain Unknown until their gates have execution receipts.
