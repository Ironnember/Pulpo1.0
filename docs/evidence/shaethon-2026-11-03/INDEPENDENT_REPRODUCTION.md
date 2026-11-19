# Independent human reproduction protocol

Object: Ironnember/Pulpo1.0 commit `6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`.
Expected source tree: `df6310dc0b6eaec50b7870832dd8cb379096f778`.

Purpose: independently reproduce the bounded local software evidence. This protocol does not authorize production changes, provider writes, spending, admission changes, or access to real credentials.

Use a fresh disposable checkout on an ordinary test host. Read that commit's AGENTS.md and applicable instructions before running. Use Python 3.11 and record the OS, interpreter, dependency versions, exact commands, exit codes, skips and warnings. Keep output outside the checkout. Do not suppress failures, replace the runner, or import historical PASS results.

```sh
git clone https://github.com/Ironnember/Pulpo1.0.git pulpo-independent
cd pulpo-independent
git checkout --detach 6b3caacbc28a7b40ebf5ea6295bc8058804de6e3
git rev-parse HEAD 'HEAD^{tree}'
git status --porcelain
python3.11 -W error -m unittest discover -s tests -v
python3.11 -W error scripts/run_gladiator_tournament.py --repo . --expected-revision 6b3caacbc28a7b40ebf5ea6295bc8058804de6e3 --output /tmp/pulpo-independent-gladiator
python3.11 -W error proofs/incident-response/synthetic_incident_response_proof.py --output /tmp/pulpo-independent-incident/result.json
python3.11 -m compileall -q pulpo tests
git diff --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD
git status --porcelain
```

For the separate asymmetric-verifier test, use the reviewed optional dependency `cryptography==50.0.1` in an isolated environment, with the operator's normal package-install authorization. Run `python -W error -m unittest tests.test_authority_crypto -v`. Do not silently omit these tests when the dependency is absent. Service and container suites need their own recorded prerequisites and commands from `.github/workflows/ci.yml`; the core suite does not establish that those suites ran.

Acceptance:

- Exact commit and tree hashes match; tracked source remains unchanged.
- Bounded tournament reports PASS_WITH_BOUNDARIES with 138 test executions, no failures/errors/skips, 10,600 scheduled mixed operations, and source_unchanged/clean_tree_after true. Scheduled operations are not 10,600 unique attacks. The runner's held-out label means fixed source-visible seeds, not independent undisclosed evaluation.
- Synthetic incident proof reports 14/14 checks and exactly one synthetic remediation; preserve the SQLite database with its JSON evidence.
- All broad-suite failures, skips and unsupported prerequisites are explicitly reported. No overall all-tests PASS while any required path remains untested.
- Independently inspect denial, positive control, substitution, replay, revocation/restart and UNKNOWN/no-retry cases; retain full logs and artifact hashes.
- The reviewer identifies themselves through an independently authenticated channel, binds the assessment to this exact source and evidence digest, states independence from the build loop, and gives limitations. A name entered in a report alone does not authenticate independence.

Known local reproduction limitations: restricted chat-host sandbox blocked Unix and TCP socket binding; three asymmetric-verifier cases skipped because the optional dependency was absent. Reproduce these paths on a suitably provisioned test host without altering protections on the user's production device.

The assistant prepared this protocol; no independent reviewer has executed or approved it. No person has been contacted.
