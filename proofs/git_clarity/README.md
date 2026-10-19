# PulpoGit Clarity Proof

Status: `IMPLEMENTED_PROPOSAL`

PulpoGit answers a narrow question: **what can local Git state prove about this
checkout right now?** It emits one deterministic, hash-bound JSON projection of
repository identity, HEAD, the configured canonical ref, branch relationship,
committed proposal changes, and dirty paths.

It does not fetch, push, checkout, merge, run hooks, execute tests, grant
authority, or append another evidence ledger. Local remote-tracking refs may be
stale. Dirty file contents are deliberately not read into or bound by the
report.

## Change record

- **Invariant addressed:** merge state, worktree state, and test state must not
  collapse into one ambiguous claim.
- **Authority effect:** none.
- **Success evidence:** canonical, proposal, dirty, detached, stale, and
  diverged states are represented explicitly and covered by one report hash.
- **Adversarial evidence:** missing refs, repository substitution,
  credential-bearing remotes, malformed Git output, an in-repository output
  path, and report hash mismatches fail closed.
- **Boundary not covered:** current network remote state, dirty file contents,
  authenticity against a party able to rewrite and rehash a report, tests,
  runtime behavior, authority, containment, deployment, customers, or
  production operation.
- **Classification:** the output is `OBSERVED_LOCAL_GIT_STATE`; stronger claims
  remain `NOT_PROVEN`.

## Run

Requirements: Git and Python 3.11 or newer. The command makes no network
request and performs no repository write.

```bash
python3 proofs/git_clarity/run.py
```

To require an exact clean canonical checkout:

```bash
python3 proofs/git_clarity/run.py --require-clean --require-canonical
```

To write a portable local result outside the repository:

```bash
python3 proofs/git_clarity/run.py --output /tmp/pulpo-git-clarity.json
```

The output verifies only when:

```python
from pulpo.git_clarity import verify_git_clarity

assert verify_git_clarity(report)
```

That check is deterministic integrity validation, not a digital signature or
proof of who collected the report.

An output classification such as `proposal_clean`, `canonical_commit_dirty`,
or `diverged_clean` is a Git observation, not a governance decision or test
result.
