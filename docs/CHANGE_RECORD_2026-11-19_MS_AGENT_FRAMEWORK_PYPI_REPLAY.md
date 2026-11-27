# Change record — Incident replay: Microsoft agent-framework PyPI compromise / quarantine is not revocation (disclosed 2026-11-17–18)

Base: `origin/main` at `a1bad53` (Phase 2 closed; v0.2.0
released at tag `5879e95`; all six Wave 1 incident-replay PRs
#363–#368 merged). Authority: Austin directed this replay on
2026-11-19 ("Stage the replay") under his standing directive of
2026-11-18: every publicized real-world incident in Pulpo's
classes is surfaced the day it breaks and assessed for a
canonical replay. The standing incident scan surfaced this
incident on 2026-11-19 as a catch-up find — it was publicized
2026-11-17–18, inside the first scan's window, but that run
missed it; the miss is recorded here rather than smoothed over.
Build authorized; the merge is Austin's separate decision.
Test-only change: one scenario module plus this record. No
production code is touched.

## 1. Invariant or failure addressed

Incident (graded from the two primary analyses — StepSecurity's
static analysis of both quarantined wheels, downloaded from the
PyPI file host, corroborated by Wiz's independent analysis):

- **Verified** (StepSecurity; Wiz converges): on 2026-11-17,
  two malicious releases of Microsoft's official
  `agent-framework` Python package were published to PyPI —
  1.26.1 (uploaded 20:35:20 UTC, quarantined 21:06:16 UTC, about
  31 minutes later) and 1.26.2 (uploaded 21:08:39 UTC, about two
  minutes AFTER the first quarantine, itself quarantined at
  21:16:44 UTC). Both wheels carried a credential stealer
  installed as a `.pth` startup hook (`agent_framework_meta.pth`
  in 1.26.1; `af_runtime_diag.pth` in 1.26.2), so the payload
  executed at Python interpreter startup whenever the
  interpreter processed the affected site-packages — no import
  of the package required. The payload harvested environment
  variables and credential files, scraped other processes'
  environments via `/proc/*/environ`, minted fresh identity
  tokens from GitHub Actions OIDC, Azure DevOps OIDC, and Azure
  managed-identity endpoints, and exfiltrated everything to a
  public webhook endpoint. Both malicious wheels were
  wheel-only and carried NO provenance attestation, unlike the
  clean 1.26.0 release (2026-11-12, wheel + sdist).
- **Recorded** (Wiz): of the requests captured at the attacker's
  public webhook, seventeen represented three unique, successful
  cases of victim-data exfiltration.
- **Inferred** (Wiz's account, NOT confirmed by Microsoft): the
  attacker appears to have compromised a client certificate and
  private key for Microsoft's ESRP release pipeline and
  published through it. How the credentials were obtained is
  stated by Wiz as not yet known.
- **Unknown**: the initial access vector and the uploader's
  identity — StepSecurity states its evidence establishes
  neither.

Failures addressed: **(a) channel access stood in for
authorization.** The uploads reached the official index through
the project's own publishing path; nothing in that path bound a
release to an approval, by an authority entitled to approve, of
publishing those exact bytes — and the malicious wheels carried
no provenance attestation at all, where the clean release did.
**(b) Execution was decoupled from install.** The `.pth` hook
made interpreter startup a repeated consequential act that no
install decision ever named: environments that installed the
package executed the stealer at every subsequent Python launch.
**(c) The incident response reached the artifact, not the
authority.** PyPI quarantined 1.26.1 within about 31 minutes —
the correct artifact-level response — and the uploader, whose
publishing access was untouched, uploaded 1.26.2 about two
minutes later. Quarantine is not revocation. The governing
invariants are exact-intent binding extended to the wheel bytes
and the attestation (`AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS`), single-use at consumption,
execution as its own governed act (an install permit does not
silently carry a startup-execution permit), revocation of
standing authority killing previously issued, unconsumed
permits at consume time and refusing new issuance, and
bidirectional reconciliation of index-side observations against
the kernel audit record, with provenance read as bound at
submission time.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test
module only: no production surface is added, narrowed, or
widened; no permit, policy, or state behavior changes. The
module's deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by runtime
code — the same pattern as PRs #346, #362, #363–#368. The
`ReleasePipelineTestVerifier` is likewise a test-local double:
a genuine signer standing in for the release pipeline's own
key, used to prove that a valid signature from the wrong
authority mints nothing.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, directive
activation / revocation, projection evaluation, and audit read
paths, and adds no writer, route, ledger, executor, or state
backend. The `PackageIndex` and `Environment` are test-local
doubles: the index records a release only after a successful
consume, the environment installs bytes only after a successful
consume, and neither is imported by runtime code. Audit growth
is classified in the module docstring per AGENTS.md (`NO_PERMIT
!= NO_GOVERNED_EFFECT`): each denied attempt that reaches the
kernel appends exactly one audit record — a governed effect
(evidence production), bounded at one record per attempt,
append-only, with `authority_effect=none` and no capability
accumulation. The refusals that never reach the kernel are the
index double's own pre-consumption checks (an
intent/presentation mismatch; the artifact quarantine of a
specific version) — assessed separately from governed external
consequences (a release recorded by the index, bytes installed,
data exfiltrated) throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_ms_agent_framework_incident_scenario.py`
(17 tests, all passing at the fix-pass head; 14 at the
original head — the §9 fix pass added three):

Setup A (approval path — each publish and install requires the
reviewer authority's approval of the exact wheel bytes and
attestation):

- positive control: the attested clean release (1.26.0)
  publishes and installs exactly once; the index records the
  wheel and attestation hashes; the independent observer records
  exactly that release; audit-supported publishes and installs
  each equal the observer's record; startup on the clean wheel
  is unremarkable; the audit chain verifies.
- step 2: the hooked 1.26.1 wheel presented under the clean
  release's permit is denied at consume (the intent binds the
  wheel hash and attestation hash, so a substituted wheel is a
  different intent); the denial consumes nothing and the clean
  release publishes afterward on the same permit.
- step 2b: the clean release's approved intent paired with the
  hooked wheel's bytes is refused by the index BEFORE
  consumption — no audit growth, permit unspent, clean publish
  then executes (the fixed Wave 1 pattern from the Codex cycle:
  bytes bound to the consumed intent, never recorded from an
  independent caller argument).
- step 3: a publish attempted with no permit is routed through
  the canonical kernel with a sentinel permit (not
  short-circuited in the double): exactly one `permit_rejected`
  record, for the attempted intent, reason
  `permit_signature_invalid`; nothing is recorded by the index.
  Channel access is not authority.
- step 4: with the hooked wheel's files present in an
  environment (the incident's post-install state), interpreter
  startup attempts the hook's execution as its own governed
  act, routed through the kernel with a sentinel permit:
  exactly one `permit_rejected` record for the execution intent,
  zero credential reads, zero exfiltration. No install
  authorization names a startup execution. The payload effects
  are gated on the consume RESULT, and a dedicated negative
  control proves the gate is the result rather than the
  harness's construction: under a defective kernel double
  whose consume accepts the sentinel, the same startup
  EXECUTES the hook — the credential store is read and its
  contents exfiltrated. (At the original head `startup()`
  discarded the consume result and never performed effects;
  the §9 fix pass corrects that.)
- step 5: the pipeline's key is not the reviewer authority,
  two forms. (i) An approval envelope for the unattested
  hooked release validly signed under the release pipeline's
  OWN key — the ESRP-analog — is denied at evaluation; the
  test first asserts the signature verifies under the
  pipeline key, so the evidence is "authentic but not
  authority," not "malformed." This is a wrong-authority
  rejection, NOT a provenance check (narrowed in the §9 fix
  pass — the original text claimed "missing provenance fails
  closed at evaluation"): no policy constraint in this setup
  requires an attestation, and step 5b proves the boundary —
  the SAME unattested intent signed by the reviewer
  authority evaluates to allow and publishes. Provenance is
  enforced only as part of the exact intent the reviewer
  approves. (ii) The clean release's permit presented with
  the same bytes but the attestation stripped is refused
  before consumption (the attestation is bound into the
  intent; stripping it is a different intent), permit
  unspent, correct presentation then executes.
- step 6: replay of the spent install permit is denied
  (single-use at consumption).
- step 7: reconciliation in both directions, intent class
  restricted to installs, expected set derived solely from the
  kernel audit: the governed run reconciles exactly; a claim
  that 1.26.1 was installed is exactly the rejected (phantom)
  claim — claimed but never authorized; an environment where
  the hooked wheel is installed outside the governed path is
  exactly the unaccounted effect; and an omitted claim is
  reported as an unreported claim and fails reconciliation —
  `ok` requires the claims to equal the audit-supported set
  exactly (at the original head a subset check let an omitted
  claim pass silently; the §9 fix pass corrects that).
- step 7b: provenance bound to submission-time audit order —
  the observer's submission log equals the audit-derived
  supported list; after the index-side log entry is rewritten
  to claim a different attestation, the rewritten log diverges
  from the audit-derived list, which is unchanged.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the hooked wheel
  IS published under the clean release's permit — the denials
  come from the binding layers, not from a harness that denies
  by construction.

Setup B (directive path — publishes and installs under the
publisher's standing directive, scoped to the package):

- step 6-counterfactual (quarantine is not revocation): under
  the active directive, 1.26.1 publishes and installs (the
  compromise plays out inside the delegated scope; the audit
  binds exactly what was authorized — hooked bytes, no
  attestation). The index then quarantines 1.26.1: installs of
  that version stop. But the publisher's authority was never
  revoked, so the second upload, 1.26.2, still publishes. The
  incident's signature failure is reproduced, not assumed away.
- step 6a: with the directive revoked (and the index never
  quarantining the version in this test), a previously issued,
  unconsumed install permit for 1.26.1 fails at consume with
  `directive_revoked` recorded as the directive status on the
  rejection; nothing is installed.
- step 6b: after revocation, a staged (issued, unconsumed)
  publish permit for 1.26.2 is dead at consume with
  `directive_revoked` recorded, and a fresh projection
  evaluation for 1.26.2 is denied with reason
  `directive_revoked` and no permit — revocation reaches the
  publisher's authority itself, producing the outcome the
  incident's quarantine could not.
- directive substitution: a directive-issued permit for the
  clean release does not spend on the hooked wheel, and then
  spends on the clean release.
- directive scope delimitation: the directive's resource
  prefix is delimited to the package (`pypi:agent-framework@`),
  and a publish intent for a look-alike package
  (`pypi:agent-framework-evil@9.9.9`) is denied at projection
  evaluation with reason `directive_resource_not_allowed` and
  no permit. (At the original head the undelimited prefix
  `pypi:agent-framework` scoped the look-alike in — verified
  by probe: the same intent evaluated `allow` under the
  undelimited prefix; the §9 fix pass corrects that.)

Full suite at the PR head: **883 tests, OK (skipped=13)** —
baseline at the base commit is 869 OK, skipped=13; the delta
is exactly the 14 scenario tests. No existing test modified.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`; full text in the PR
body): Flip — authority flows from the reviewer/publisher
authority's consumed permits, never from the artifact's
presence on the official index or the uploader's channel
access; the incident ran the flip in reverse. Reverse —
publish first, authorize after mints nothing, and the
incident's temporal reverse (install now, execute at every
later startup) also fails: execution is its own act with no
permit to spend (step 4). Invert — if the index held the only
record, quarantine-side edits would settle history; here the
record is the kernel audit, observer records are checked
against it in both directions, and a rewritten provenance
entry diverges instead of replacing (steps 7, 7b). Inside-Out
— no consume-path code interprets wheel bytes, version strings,
or provenance semantics; hashes are opaque intent components,
and attestation is evidence bound into the intent, never an
input that mints authority — its absence fails closed at
evaluation because the approving authority's policy binds it,
not because the kernel reads it. Darken — cross-session and
cross-principal spend is not separately exercised; it relies on
the kernel's existing binding tests and is recorded as a
reliance, not new evidence (cross-version substitution, byte
substitution, attestation stripping, and wrong-authority
envelopes ARE exercised). Lighten — a harmless wheel change
still requires its own approval; the denial is content-agnostic
(composition of step 2; no dedicated test, stated as
composition). Amplify — one publish fans out to every
downstream install and every subsequent interpreter startup in
those environments; the controls that matter are per-release
binding and directive revocation halting every unconsumed
permit at consume time regardless of volume; the
one-record-per-denied-attempt audit growth bound at volume is
proven by PR #346's 17,000-attempt test and is not re-run.
Negate — the negative control. Stop/continue decision:
CONTINUE in the governed kernel path only.

## 5. Boundary the evidence does not prove

The scenario models publishes, installs, and startup
executions presented for consumption on the governed path. It
proves nothing about PyPI, Microsoft, or ESRP themselves, and
nothing about whether PyPI would or could run Pulpo: a replay
proves the governed path refuses these acts, not that any real
index adopts the gate. It does not model how the uploader
obtained publishing access (Unknown in the sources) or the
payload's behavior beyond naming its hook files; the credential
store and exfiltration list are effect counters, not a stealer
simulation. The ESRP-certificate account is Inferred (Wiz) and
unconfirmed by Microsoft; step 5's pipeline-key test models the
class (pipeline credentials are not reviewer authority), which
does not depend on that account being true, and this record
does not assert it. On the directive path, the scenario states
plainly what a standing directive is: it delegates the acts
within its scope and does not review content, so a compromised
principal inside the scope publishes until the authority is
revoked — the governed world's protection on that path is the
binding record (the audit states exactly what was authorized)
plus revocation, not prevention of the first bad publish. The
counterfactual test (quarantine alone) therefore shows the
second upload EXECUTING: that is the honest expression of the
incident's lesson, not a gap in the scenario. Only the main
package is modeled; the satellite `agent-framework-*` packages
StepSecurity checked are further acts of the same class.
Non-governed routes (a direct write to the index, an install
that bypasses the gate, an interpreter started outside the
governed environment) are the known direct-writer class: a
control not on the execution path governs nothing. Its
evidence covers kernel behavior at the PR head commit for this
action class only.

## 6. Claim classification

- Incident narrative (versions, timestamps, the `.pth`
  mechanism, the payload's collection and token-minting
  behavior, the quarantine sequence, the absence of provenance
  on the malicious wheels): **Verified** — StepSecurity's
  primary static analysis of both quarantined wheels,
  corroborated by Wiz's independent analysis; every identifier
  used here (versions 1.26.0/1.26.1/1.26.2, the hook file names,
  the UTC times) is stated in one or both sources.
- Three successful victim-data exfiltrations: **Recorded**
  (Wiz's analysis of the captured webhook requests).
- Root cause via a compromised ESRP release-pipeline
  certificate: **Inferred** (Wiz's account; Microsoft has not
  publicly confirmed the mechanism; not stated as fact
  anywhere in this PR).
- How publishing access was obtained; the uploader's identity:
  **Unknown** — not established in either source, and not
  modeled.
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the PR head commit).
- The mapping from the incident's pattern to kernel intents (a
  publish/install intent names its package, version, the
  wheel's SHA-256, and the attestation's hash; the reviewer is
  the approval authority; the pipeline's signing key is the
  ESRP-analog; interpreter startup is a distinct governed act;
  index quarantine is an artifact-level block distinct from
  directive revocation): **Inferred** — the harness's modeling
  choices, stated in the module docstring.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this PR.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control
path was copied. Structure, helpers, and assertion style mirror
the canonical scenario modules merged in PRs #346–#350,
#362–#368 — closest `tests/test_wppconnect_incident_scenario.py`
(pipeline/provenance family) and
`tests/test_optimjack_incident_scenario.py` — including their
per-module helper-duplication pattern and the FIXED patterns
from Wave 1's Codex cycle (bytes bound to the consumed intent
and refused before consumption on mismatch; no-permit attempts
routed through the kernel via a sentinel permit; reconciliation
restricted to the relevant intent class, bidirectional, against
an independent observer; provenance bound to submission-time
audit order). The directive scaffolding composes the public
helpers of `tests/test_directives.py` without inheriting that
suite.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson as a
replay, and none is manufactured: the bindings the scenario
exercises (exact-intent binding, single-use consumption,
directive revocation at consume time, claim-vs-audit
reconciliation) predate this PR, but the scenario was not run
against historical checkpoints, so no temporal proof is
claimed. The evidence is valid at the PR head commit only;
reuse of the lesson at a later commit requires re-evaluation
there. The replay itself changed no consequential authority
(`authority_effect=none`).

## 9. Post-review fix pass (Codex P1 x2 + P2 x2 on PR #370, 2026-11-25)

Four Codex findings from the 2026-11-19 review of head
`a4e9fbf` (the scenario module was unchanged between
that head and `d1cb0e6`, so all four were live). All
four are fixed in the scenario module; no kernel code
is touched and no custody or authority semantics
change (`authority_effect=none` throughout). The
findings, in the review's order:

- **P1 — test provenance rather than only the signer
  identity.** Step 5's denial was caused solely by the
  envelope's signer being the release-pipeline
  verifier, whose identity differs from the policy's
  pinned reviewer; the configured Policy has no
  attestation constraint, so the test did not test
  missing provenance. Disposition: the claim is
  narrowed to what the evidence supports (the
  alternative Codex offered), and the boundary is now
  proven executably. Step 5 is renamed and restated
  as a wrong-authority rejection; new step 5b shows
  the SAME unattested intent, signed by the pinned
  reviewer, evaluating to allow and publishing —
  provenance is enforced only as part of the exact
  intent the reviewer approves (the attestation hash,
  including hash-of-None, is inside the bound intent,
  and step 5(ii)'s strip-downstream refusal stands).
- **P1 — gate startup effects on the consume
  result.** `Environment.startup()` discarded the
  consume result, always returned False, and never
  performed any effect, so step 4's "permit rejection
  prevents startup execution" was true by
  construction. `startup()` now performs the payload
  effects (credential-store read, exfiltration of the
  synthetic contents) if and only if consume returns
  True, and a new negative control
  (`test_negative_control_startup_effects_follow_consume_result`)
  runs the same startup under a defective kernel
  double whose consume accepts the sentinel: the hook
  executes and the effects occur. Step 4's canonical
  assertions are unchanged.
- **P2 — require claims to cover supported
  installs.** `reconcile_installs` used
  `claims <= supported`, so an omitted install claim
  reconciled `ok=True`. It now requires
  `claims == supported` and reports
  `unreported_claims = supported - claims`; step 7
  asserts the empty-claims case fails with the
  supported install named as unreported.
- **P2 — delimit the directive's package prefix.**
  Setup B's directive used the undelimited prefix
  `pypi:agent-framework`; the kernel's prefix match
  therefore also scoped in look-alike packages.
  Reproduced before the fix by probe: a publish
  intent for `pypi:agent-framework-evil@9.9.9`
  evaluated `allow / policy_satisfied` under the
  undelimited prefix. The prefix is now
  `pypi:agent-framework@`, and a new test pins the
  adjacent package's denial
  (`deny / directive_resource_not_allowed`, no
  permit).

Re-verification at the fix-pass head: scenario
**17/17** (14 at the pre-pass head; the delta is
exactly step 5b, the startup negative control, and
the adjacent-package test); full suite **1053
tests, OK (skipped=13)** in this environment.
