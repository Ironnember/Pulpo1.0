# Change record — Incident replay: WPPConnect npm compromise / provenance without authorization (disclosed 2026-11-15–17)

Base: `origin/main` at `7a21eeb` (PR #362 merged; Phase 2 closed;
v0.2.0 released at tag `5879e95`). Authority: Austin directed the
incident-replay battery's continuation on 2026-11-18 ("test them —
if they need to be in pull request, let's put them in pull
request") under the standing directive the same evening: every
publicized real-world incident in Pulpo's classes is surfaced the
day it breaks and assessed for a canonical replay. This incident
was surfaced by the standing incident scan's first run. Build
authorized; the merge is Austin's separate decision. Test-only
change: one scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from StepSecurity's published analysis,
"WPPConnect Compromised: Malicious Releases Steal Secrets and
WhatsApp Sessions Through the Project's Own Pipeline," covering
2026-11-15 to 2026-11-17): on 2026-11-15 at 22:34 UTC, two
unsigned commits were pushed directly to the master branch of
wppconnect-team/wppconnect — no pull request, no review — through
the joaosouz4dev account (how that access was obtained is not
established in the source). The commits added
`src/utils/diagnostics.ts`, a module that on import copies
environment variables, .env/config files, and WhatsApp session
tokens and uploads them to a Telegram bot, and imported it. The
release workflow was dispatched by hand; the package published to
npm through a GitHub Actions trusted publisher carrying a VALID
SLSA provenance attestation — StepSecurity decoded it and every
field is accurate (workflow `publish.yml`, ref
`refs/tags/v2.4.1`, commit `dee571e`) — and the commit is the
malicious one. The publish workflow at the release commit had no
`environment:` key, so no reviewer approval stood between tag and
registry. The server package (@wppconnect/server) received the
same treatment (a push to main auto-triggered release 2.10.82),
and Docker images and the GitHub nightly release carried the
payload too. After an external researcher opened public issues,
both default branches were force-pushed within about 30 seconds
and the v2.4.1 tag was rewritten to a look-alike commit with the
same message and timestamp but without the payload, so the source
visible on GitHub did not match the tarball npm served; the tags
were deleted on 2026-11-17. The bad versions were `latest` for
about 4.5 hours; npm recorded at least 155 downloads of 2.4.1 (a
floor). StepSecurity's summary line: "Provenance proves where a
package was built, not whether anyone reviewed the source."

Failure addressed: **authentic origin evidence was allowed to
stand in for authorization of the act.** Every origin signal was
genuine — trusted-publisher identity, a provenance attestation
whose fields all verify — and none of it was an approval, by an
authority entitled to approve, of publishing that exact source
tree. Nothing in the path bound the release to reviewed code:
unreviewed commits rode the project's own pipeline to the
registry, and the post-hoc history rewrite then tried to make
the record agree with the cover story. The governing invariants
are the exact-intent binding extended to the source tree
(`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`, where
the "means" here are the literal tree published), the separation
of attestation from authority (a credential about origin is an
input to nothing on the consume path), single-use at consumption,
revocation of standing authority killing previously issued,
unconsumed permits at consume time, and reconciliation of the
registry's recorded artifact and the repository tag against the
kernel audit record — the history that cannot be force-pushed.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test module
only: no production surface is added, narrowed, or widened; no
permit, policy, or state behavior changes. The module's
deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative control,
are test-local, and are never imported by runtime code — the same
pattern as PRs #346, #362, and the pending #363/#365. The
`PipelineTestVerifier` is likewise a test-local double: a genuine
signer standing in for the pipeline's automation key, used to
prove that a valid signature from the wrong authority mints
nothing.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing `evaluate`,
`evaluate_with_approval`, `consume`, directive activation /
revocation, projection evaluation, and audit read paths, and adds
no writer, route, ledger, executor, or state backend. The
`Registry` and `TagBook` are test-local doubles: the registry
records a release only after a successful consume, the tag book
is deliberately mutable (it models the incident's rewriteable
tag), and neither is imported by runtime code. Audit growth is
classified in the module docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied attempt appends exactly one
audit record — a governed effect (evidence production), bounded
at one record per attempt, append-only, with
`authority_effect=none` and no capability accumulation — assessed
separately from governed external consequences (a release
actually recorded by the registry) throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_wppconnect_incident_scenario.py`
(10 tests, all passing at the PR head):

- positive control: a reviewer-approved publish of the exact
  reviewed tree executes exactly once; the registry records the
  reviewed tree's hash; the audit chain verifies.
- step 1: a publish attempted with no permit is refused; nothing
  is recorded by the registry.
- step 2: the malicious tree presented under the reviewed tree's
  permit is denied at consume (the intent binds the tree hash, so
  an unreviewed tree is a different intent); the denial consumes
  nothing and the reviewed tree publishes afterward on the same
  permit.
- step 3: an approval envelope for the malicious tree that is
  validly signed and internally consistent under the release
  pipeline's OWN key — the trusted-publisher analog, the
  executable form of the incident's valid SLSA attestation — is
  denied at evaluation; no permit is minted. The test asserts the
  signature verifies under the pipeline key before asserting the
  denial, so the evidence is "authentic but not authority," not
  "malformed."
- step 4: replay of the spent publish permit is denied
  (single-use at consumption).
- step 5: test-level reconciliation against the kernel audit
  record, directions stated explicitly (the PR #362 lesson): the
  honest state reconciles exactly (tag target = registry's
  recorded tree = the tree the audit consumed a publish for);
  after the tag is repointed to a look-alike tree — the
  incident's cover-up — reconciliation flags the tag mismatch and
  the look-alike as exactly the false claim (claims minus
  audit-consumed publishes), while the registry's record of what
  was published is unchanged.
- step 6 (directive path): a publish permit issued under the
  maintainer's active directive fails at consume after the
  maintainer revokes the directive, with `directive_revoked`
  recorded as the directive status on the rejection; nothing is
  recorded by the registry.
- step 7 (directive path): a directive-issued permit presented
  against the malicious tree is denied at consume and then spends
  on the reviewed tree.
- negative control: with consume unguarded at both layers (kernel
  double + intent-blind state double), the malicious tree IS
  published under the reviewed tree's permit — the denials come
  from the binding layers, not from a harness that denies by
  construction.

Full suite at the PR head: **818 tests, OK (skipped=13)** —
baseline at the base commit is 808 OK, skipped=13; the delta is
exactly the 10 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`; full text in the PR
body): Flip — credit flows from the reviewer authority's consumed
permits, never from the artifact's own credentials; the incident
ran the flip in reverse, treating origin evidence as approval.
Reverse — publish first, approve after mints nothing, and the
incident's second reverse (rewrite history afterward) fails
against an append-only, kernel-held record: the repointed tag
diverges from the record instead of replacing it. Invert — a
repository-held record is exactly what the force-push defeated in
the incident; here the record is the kernel audit plus a registry
record written only through consume, and the tag is demoted to a
claim. Inside-Out — no consume-path code interprets the tree
bytes, the resource string, or any attestation; attestation is
not an input to consume at all, so attestation ≠ authorization is
structural, not a configurable check. Darken — cross-session and
cross-principal spend is not separately exercised; it relies on
the kernel's existing binding tests and is recorded as a
reliance, not new evidence (cross-tree substitution and
cross-authority envelopes ARE exercised, steps 2 and 3). Lighten
— a harmless tree change still requires its own approval; the
denial is content-agnostic (composition of step 2; no dedicated
test, stated as composition). Amplify — at registry scale the
controls that matter are per-release tree binding and directive
revocation at consume time; the audit-growth bound at volume is
proven by PR #346's 17,000-attempt test and is not re-run.
Negate — the negative control. Stop/continue decision: CONTINUE
in the governed kernel path only.

## 5. Boundary the evidence does not prove

The scenario models publishes presented for consumption on the
governed path. It proves nothing about npm, GitHub, GitHub
Actions, or SLSA themselves — provenance attestation is genuine
evidence about origin and this record does not claim otherwise;
the claim is only that origin evidence is not an approval. It
does not model how the account access was obtained (Unknown in
the source) or the payload's behavior, and it models only the
main package's npm publish: the server package, Docker images,
and nightly release are further distribution acts of the same
class, not separately modeled. It proves nothing about
non-governed publish routes (a direct write to the registry is
the known direct-writer class): a control not on the execution
path governs nothing. Its evidence covers kernel behavior at the
PR head commit for this action class only.

Post-review addendum (Codex review of the original head): two
findings, both HELD and fixed. (1) P1 "Bind the published bytes
to the consumed intent" — the registry double previously
recorded the caller's independent `tree` argument after consume
accepted the intent, so an approved permit could have published
arbitrary bytes; the double now refuses any intent/bytes
mismatch before consumption (permit unspent), with a regression
test (step 2b) pairing the reviewed intent with malicious
bytes. (2) P2 "Route no-permit attempts through the canonical
kernel" — step 1 previously short-circuited on a `None` permit
inside the double; it now presents a sentinel permit to the
kernel and asserts the recorded `permit_rejected` entry. The
step 5 readback was re-verified against the acceptance
criterion in the same pass: the observed hashes are read by the
observer directly from the registry/tag doubles (reference
resolution), the expected hash set is derived solely from the
kernel audit, and no claimant-supplied value enters either
side of the comparison.

## 6. Claim classification

- Incident narrative: **Recorded** (StepSecurity's published
  analysis of 2026-11-15–17, the primary source named by the
  standing incident scan; the timeline, the decoded provenance
  fields, the force-push/tag-rewrite sequence, and the
  155-download floor are all as StepSecurity reports them).
- How the joaosouz4dev account access was obtained: **Unknown**
  — not established in the source, and not modeled.
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the PR head commit).
- The mapping from the incident's pattern to kernel intents (a
  publish intent names its package, version, and the source
  tree's SHA-256; the reviewer is the approval authority; the
  pipeline's automation key is the trusted-publisher analog; the
  audit record is the un-rewriteable history): **Inferred** —
  the harness's modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this PR.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control
path was copied. Structure, helpers, and assertion style mirror
the canonical scenario modules merged in PRs #346–#350 and #362
and the pending PRs #363–#365, including their per-module
helper-duplication pattern; the directive scaffolding composes
the public helpers of `tests/test_directives.py` without
inheriting that suite.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson as a
replay, and none is manufactured: the bindings the scenario
exercises (exact-intent binding, single-use consumption,
directive revocation at consume time, claim-vs-audit
reconciliation) predate this PR, but the scenario was not run
against historical checkpoints, so no temporal proof is claimed.
The evidence is valid at the PR head commit only; reuse of the
lesson at a later commit requires re-evaluation there. The
replay itself changed no consequential authority
(`authority_effect=none`).
