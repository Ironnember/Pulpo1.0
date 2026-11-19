# Change record — Incident replay: Optimizely supply-chain compromise / OPTIMJACK (disclosed 2026-11-16)

Base: `origin/main` at `7a21eeb` (PR #362 merged; Phase 2 closed;
v0.2.0 released at tag `5879e95`). Authority: Austin directed this
replay on 2026-11-18 ("stage the same test" for the Optimizely
incident) as the first run of a standing directive the same evening:
every publicized real-world incident in Pulpo's classes is surfaced
the day it breaks and assessed for a canonical replay. Build
authorized; the merge is Austin's separate decision. Test-only
change: one scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Report URI's published disclosure by Scott
Helme, 2026-11-16, Optimizely's own confirmation, and convergent
reporting by Computerworld, Socket, TechTarget, Cato Networks, and
SecurityAffairs): an unauthorized party exploited a vulnerability
in Optimizely's Experimentation account signup flow — per Cato's
analysis of Optimizely's incident report, the flaw allowed
administrator impersonation and unauthorized changes to Project
JavaScript without stolen customer passwords — and injected a
malicious loader into the Project JavaScript of customer projects.
Report URI examined 1,611 Optimizely snippets and found 188
infected snippets belonging to 178 organizations (including Zoom,
the BBC, CNN, Salesforce, GitLab, IKEA, HSBC, and Equifax). The code
was served from Optimizely's CDN — a trusted host with a valid
certificate — to those sites' visitors for most of 16 November 2026
(first injection observed 04:21 UTC; last infected snippet clean by
23:11 UTC per Report URI). The payload swapped cryptocurrency
wallet addresses, skimmed payment cards, stole cookies and
screenshots, and delivered the Coruna and DarkSword iOS exploit
kits; Report URI counted about $7,040 in attacker wallets by
19:25 UTC. The write-ups by Cato Networks and SecurityAffairs name
the campaign OPTIMJACK.

Failure addressed: **platform access was treated as authority over
the consequence.** The attacker held a session, not a mandate; the
consequential act — publish Project JavaScript, one write that fans
out to every visitor of 178 organizations — executed because the
channel was trusted, not because the specific act (this project,
these exact bytes) was authorized. The governing invariants are the
exact-intent binding extended to content
(`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`, where
the "means" here are the literal bytes served), single-use at
consumption, revocation of standing authority killing previously
issued, unconsumed permits at consume time, and reconciliation of
claimed publishes against independently observed served bytes in
both directions — the observer role Report URI played after the
fact, made a governed check instead of a researcher's vigilance.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test module
only: no production surface is added, narrowed, or widened; no
permit, policy, or state behavior changes. The module's deliberately
unguarded doubles (`_IntentBlindState`, `_UnguardedConsumeKernel`)
exist solely as the negative control, are test-local, and are never
imported by runtime code — the same pattern as PRs #346, #362, and
the pending #363.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing `evaluate`,
`evaluate_with_approval`, `consume`, directive activation /
revocation, projection evaluation, and audit read paths, and adds
no writer, route, ledger, executor, or state backend. The
`ServedStore` is a test-local consequence double: it records bytes
only after a successful consume and is never imported by runtime
code. Audit growth is classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied attempt
appends exactly one audit record — a governed effect (evidence
production), bounded at one record per attempt, append-only, with
`authority_effect=none` and no capability accumulation — assessed
separately from governed external consequences (bytes actually
served) throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_optimjack_incident_scenario.py`
(10 tests, all passing at the PR head):

- positive control: an owner-approved publish of exact bytes
  executes exactly once; the observer's hash of the served bytes
  equals the permitted content hash; the audit chain verifies.
- step 1: a publish attempted with no permit is refused; nothing
  is served.
- step 2: the malicious payload presented under the benign
  publish's permit is denied at consume (the intent binds the
  content hash, so different bytes are a different intent); the
  denial consumes nothing and the approved bytes publish afterward
  on the same permit.
- step 2b: the benign permit presented against a different project
  is denied at consume; the permit then spends on its own project.
- step 3: replay of the spent publish permit is denied (single-use
  at consumption).
- step 4: an approval envelope for the malicious publish signed
  with an attacker's key is denied at evaluation; no permit is
  minted.
- step 5: test-level reconciliation of publish claims against
  independently observed served bytes, both directions stated
  explicitly (the PR #362 lesson): the governed run reconciles
  exactly; a claim padded with the never-executed malicious publish
  is flagged as exactly that phantom claim; and served bytes no
  claim accounts for — the incident's detection condition — are
  flagged as exactly that unaccounted effect.
- step 6 (directive path): a publish permit issued under the
  owner's active directive fails at consume after the owner revokes
  the directive, with `directive_revoked` recorded as the directive
  status on the rejection; nothing is served.
- step 7 (directive path): a directive-issued permit presented
  against substituted content is denied at consume and then spends
  on the approved bytes.
- negative control: with consume unguarded at both layers (kernel
  double + intent-blind state double), the malicious payload IS
  served under the benign permit — the denials come from the
  binding layers, not from a harness that denies by construction.

Full suite at the PR head: **818 tests, OK (skipped=13)** —
baseline at the base commit is 808 OK, skipped=13; the delta is
exactly the 10 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`; full text in the PR body):
Flip — the distributor serves only against consumed permits and the
observer reconciles served bytes against claims in both directions;
credit flows from observed bytes traced to consumed acts, never
from the publisher's log. Reverse — serve first, approve after
mints nothing: post-hoc approval cannot account for already-served
bytes, which surface as unaccounted effects (step 5, third case).
Invert — a publisher-held record would make the incident invisible,
as the platform's own account did for most of a day; here the record
is the kernel audit plus an observer that never consults the kernel
or the publisher. Inside-Out — no consume-path code interprets the
resource string's meaning; the content digest is an opaque
component of the intent and binding is hash equality; the store's
routing by project is its own business logic, downstream of
consume, and grants nothing. Darken — cross-session and
cross-principal spend of a publish permit is not separately
exercised in this module; it relies on the kernel's existing
session/principal binding tests and is recorded as a reliance, not
new evidence (cross-project spend IS exercised, step 2b). Lighten —
a merely harmless content change (a comment-only edit) is still a
different intent and requires its own permit; the denial is
content-agnostic (composition of step 2; no dedicated test, stated
as composition). Amplify — at the incident's scale, the controls
that matter are per-project content binding (each project's served
bytes trace to a consumed permit for exactly those bytes) and
directive revocation halting every unconsumed publish at consume
time regardless of volume; the one-record-per-denied-attempt audit
growth bound at volume is proven by PR #346's 17,000-attempt test
and is not re-run. Negate — the negative control. Stop/continue
decision: CONTINUE in the governed kernel path only.

## 5. Boundary the evidence does not prove

The scenario models publishes presented for consumption on the
governed path. It proves nothing about Optimizely's actual systems,
exploitability, or payload behavior; it does not model the signup
flaw or identity proofing (the scenario grants the attacker a
platform session and shows the session is insufficient for the
consequential act — a deployment would still have to route its
publishes through the gate). It proves nothing about visitor-side
runtime behavior of legitimately published code, and nothing about
non-governed publish routes (a direct write to the distribution
store is the known direct-writer class): a control not on the
execution path governs nothing. Its evidence covers kernel behavior
at the PR head commit for this action class only.

## 6. Claim classification

- Incident narrative: **Recorded** (Report URI's disclosure by
  Scott Helme, 2026-11-16; Optimizely's confirmation and incident
  report as analyzed by Cato Networks; convergent reporting by
  Computerworld, Socket, TechTarget, SecurityAffairs, 2026-11-17/18).
  A widely circulated AI-generated summary of this incident was
  graded on 2026-11-18: its core was accurate, but its "34 million
  page visits" figure, its email-guessing mechanism detail, its
  13:34 UTC detection time, and its Mandiant engagement claim are
  uncorroborated by the primary or convergent sources; this record
  follows the primary sources, not the summary.
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the PR head commit).
- The mapping from the incident's pattern to kernel intents (a
  publish intent names its project and the content's SHA-256; a
  platform publish pipeline is the presenting agent; an external
  snippet observer is the reconciliation source): **Inferred** —
  the harness's modeling choices, stated in the module docstring.
  The content-hash-in-intent choice applies, from the start, the
  lesson recorded the same evening in the governed-write harness
  correction (a permit binding target and cost but not content does
  not bind the act).
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this PR.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control path
was copied. Structure, helpers, and assertion style mirror the
canonical scenario modules merged in PRs #346–#350 and #362 and the
pending PRs #363–#364, including their per-module helper-duplication
pattern; the directive scaffolding composes the public helpers of
`tests/test_directives.py` without inheriting that suite.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson as a
replay, and none is manufactured: the bindings the scenario
exercises (exact-intent binding, single-use consumption, directive
revocation at consume time, claim-vs-observation reconciliation)
predate this PR, but the scenario was not run against historical
checkpoints, so no temporal proof is claimed. The evidence is valid
at the PR head commit only; reuse of the lesson at a later commit
requires re-evaluation there. The replay itself changed no
consequential authority (`authority_effect=none`).
