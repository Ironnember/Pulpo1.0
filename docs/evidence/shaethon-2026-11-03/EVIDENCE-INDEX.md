# SHAETHON evidence packages — index and custody record

This directory holds the two evidence packages Michael Dill (SHAETHON AI)
sent to Iron & Ember on 2026-11-04, published alongside
`docs/RECIPROCAL_EXTERNAL_REVIEW_SHAETHON_2026-11-03.md` at the sender's
direction ("send the full evidence package as-is… publish as it supports").
Both ZIPs are byte-identical to the attachments as received. Nothing in
either package was edited, re-zipped, or sanitized by Iron & Ember.

## Provenance

- Sender: Michael Dill, SHAETHON AI (`hello@shaethonai.com`).
- Received: 2026-11-04 (email, in reply to Iron & Ember's acceptance of
  the standing offer recorded in the reciprocal review).
- The packages were offered on 2026-11-03, the night the work was done:
  "say the word and the package goes to you as-is." Iron & Ember said the
  word on 2026-11-04.

## Packages and hashes

SHA-256 values below are stated by the sender in his 2026-11-04 email and
independently recomputed by Iron & Ember on receipt; both agree.

1. `pulpo-evidence-package-2026-11-03.zip`
   SHA-256: `cd420b6eef8f310d905bdeb2a58a8851eff2e289bea8a8e65112783ff15f0229`
   Contents (sender's description): the Pulpo-Preview reproduction
   package — cover note, comparison, probe harness, and the raw outputs
   behind the 31 boundary probes (Direction 1 of the review).
   Note: this ZIP is bit-identical to the package Iron & Ember took into
   custody on 2026-11-03, the day the harness results were first
   reported. The 2026-11-04 delivery therefore closes the question of
   whether the package changed between its first delivery and its
   publication here: it did not.

2. `canonical-pass-evidence-2026-11-03.zip`
   SHA-256: `24c1bacce85ac5131ebcff92a9db380896f74ba5b7433da760b0336c32107e14`
   Contents: `RESULTS-MEMO.md`, `env.txt`, `unittest.log`,
   `gladiator.log`, `incident.log`, `crypto.log`,
   `tournament-results.json`, `incident-result.json`, and the incident
   proof's SQLite state file — the raw artifacts of SHAETHON's canonical
   reproduction pass against Pulpo at `6b3caac` on 2026-11-03.

## Verification performed by Iron & Ember on receipt (2026-11-04)

- Both SHA-256 hashes recomputed and matched to the sender's stated
  values.
- The memo's stated tree hash at `6b3caac`
  (`df6310dc0b6eaec50b7870832dd8cb379096f778`) was already confirmed
  identical to Iron & Ember's own tree at that commit on 2026-11-03.
- Log-level spot checks against the reported results:
  `unittest.log` ends "Ran 422 tests… OK (skipped=4)";
  `crypto.log` records 3 tests, OK; `gladiator.log` ends
  "FINAL PASS_WITH_BOUNDARIES 138 10600"; `tournament-results.json`
  records `source_unchanged: true` and `clean_tree_after: true`.

## What this publication does and does not establish

- It establishes custody and integrity: the artifacts in this repository
  are the artifacts the tester produced and sent, unaltered.
- It establishes internal consistency: the raw logs support the summary
  results the review records.
- It does **not** convert the tester's attestation into Iron & Ember's
  own observation. Iron & Ember did not witness the runs. The claim
  classes in the review are unchanged by this publication except where
  the 2026-11-04 addendum to the review states otherwise.
- Direction 1 remains a Preview result (commit `ec52708`), not a result
  about canonical `main`. The canonical pass is a reproduction under a
  written protocol, not an adversarial battery layered on canonical
  main; the tester's own scope limits (service and container CI suites
  not run) stand as recorded.
