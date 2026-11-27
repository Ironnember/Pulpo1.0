# Change record — Incident replay: Cisco Expressway cluster database service — a static, product-wide credential treated as authority for the act (CVE-2026-76466, disclosed 2026-10-21)

Base: `origin/main` at `f734c97e` (PR #38 merged;
verified by clone at build time, 2026-11-27).
Authority: Austin approved this build on 2026-11-27
("Build all three" — tapped and in words, 16:11 MST),
for the event surfaced the same day in bcouzens'
"Cyber Incidents Top 40" (item #28). Test-only change:
one scenario module plus this record. No production
code is touched.

## 1. Invariant or failure addressed

Event (graded from the public record): Cisco's
security advisory cisco-sa-vcs-static-cred-hr7EWZ8t
(Recorded, vendor advisory, published 2026-10-21;
revision 1.1 dated 2026-11-23) states that a
vulnerability in the database service feature of Cisco
Expressway Series — Expressway Core (Expressway-C) and
Expressway Edge (Expressway-E), virtual and appliance,
when configured in a cluster — could allow an
unauthenticated, remote attacker with network access
to execute arbitrary operating system commands as
root. The advisory attributes the flaw to the use of
persistent cookies, and to insufficient validation of
client certificates when the TLS Verify Mode is set to
Enabled for clustering: an attacker with possession of
the cookies could connect to the database service and
invoke specific remote procedure call (RPC) commands.
The assigned weakness class is CWE-798, use of
hard-coded credentials (Recorded, NVD/CISA
descriptions of CVE-2026-76466, CVSS 9.8 as scored by
Cisco). Affected releases (Recorded, advisory Fixed
Software section): X15.5.3 and earlier, first fixed in
X15.5.20; X14 and earlier must migrate. No workarounds
exist. Cisco credited Stefan Aleksic of Jane Street
with the report. In November 2026 the CVE entered
CISA's Known Exploited Vulnerabilities catalog
(Recorded, advisory revision 1.1; federal remediation
deadline 2026-11-23 as reported); the same revision
records Cisco's statement that it does not have direct
evidence of active exploitation. The security firm F6
reported (Recorded, F6 via The Register and Censys,
2026-11-19) the first observed exploitation case:
root command execution on two internet-facing
Expressway devices, then access to two further cluster
nodes on the victim's internal network, with scripts
prepared for internal scanning and SMB, SQL Server,
WinRM, and GitLab credential hunting; F6 named a
`nodeup 'wombat@127.0.0.1'` entry in the Erlang system
log as an indicator of the mechanism, and reported a
public proof of concept had appeared before the
attacks it observed.

Claim discipline (load-bearing): the two exploitation
statements in the record point in different directions
— Cisco's no-direct-evidence statement and F6's
observed-case report — and this replay carries both as
their sources state them; it adjudicates neither. What
the scenario models is the architectural property the
vendor advisory itself establishes: the cluster
database service admits a presenter on possession of a
static, product-wide credential, and what possession
admits is root command execution on the node — with,
by the product's design, an internal-network position
behind the internal (Expressway-C) nodes. The modeled
pivot command is a scenario construction shaped on
F6's reporting, not a reconstruction of any command
any attacker ran.

Failure addressed: **a static credential everyone can
possess is not approval of the act.** The persistent
cookie was the only artifact the database service
checked, and presenting it (with network access) was
treated as authority for each command it was presented
for — on the first node, and, indistinguishably, on
every internal node the presenter could reach. At no
point did the path ask the separate question: was THIS
command, on THIS node, approved? Under the canonical
kernel, the cookie is not a permit at all — presented
at `consume` it is an unauthenticated string and is
refused. Authority for a command enters only as a
verified approval envelope — signed by an enrolled
authority and bound to the exact intent hash
(principal, action, resource, cost, session) — and
mints a single-use permit for exactly that intent: the
approved command executes under its permit, and a
pivot command presented with that same permit is
refused at consume, the refusal burning nothing. The
governing invariants are
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`
and fail-closed authorization: unknown, malformed,
untrusted, or merely possessed authority mints nothing
and spends nothing.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's
`StaticCredentialBoundary` double exists solely as the
negative control, is test-local, and is never imported
by runtime code — the same pattern as PRs #346 and
#362-#393, #415, #416, #422, #423, #424, #425, and
#426. The scenario's reconciliation helper
(`reconcile_consequences`) is likewise test-local: it
reads the harness's executed log and holds no
canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `ClusterDatabaseBoundary` is a test
harness: it executes a command only after a successful
kernel consume and holds no canonical state; its log
entries are inert resource labels, never commands,
files, or credentials. The incident-channel freeze is
asserted read-only in the scenario itself (audit
length unchanged across the freeze). Audit growth is
classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records — a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_cisco_expressway_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one authorized act (the
  operator-approved RPC — this node, this command,
  this session) executes exactly once under a genuine,
  well-formed verified approval envelope; the permit,
  spent at that consume, cannot execute twice;
  reconciliation of executed-vs-approved reports exact
  equality (1 approved, 1 executed, 0 unauthorized);
  the audit chain verifies.
- step 1: the pivot refused at consume, and the
  refusal is free — the approved permit, presented
  FIRST for the pivot command (a different internal
  node, an act no operator approved), is refused at
  the kernel's intent binding, the rejection naming
  the pivot intent's hash; the refusal consumes
  nothing, and the approved permit then spends on its
  own act, exactly once. Under the disclosed
  architecture this attempt never faces the question:
  the presenter holds the static credential, and the
  credential is the whole check.
- step 2: the static credential presented as a
  permit — the only authorization artifact the
  disclosed architecture checks, in the role it plays
  there — is refused at `consume` for the approved
  command and the pivot alike. A shared secret
  authenticates possession, and authorizes no act.
- step 3: with no artifact presented at all,
  `evaluate` returns `require_approval` for the
  approved command and the pivot alike — being able
  to reach the service confers no route to a permit;
  and an approval envelope for the pivot signed with
  a key the presenter controls is denied
  (`approval_signature_invalid`). The kernel verifies
  against the enrolled authority, and the party
  requesting the command cannot also be the party
  approving it.
- step 4: reconciliation over a governed sequence
  shaped like the event — the approved command
  approved and executed, the pivot attempted under
  the event's two available forms (the approved
  permit stretched, before the approved spend; the
  static credential presented as authority), and the
  spent permit replayed — reports exact equality:
  1 approved, 1 executed, 0 unauthorized occurrences,
  and no refused attempt recorded as fulfilled. The
  comparison the disclosed path never runs, run here,
  is clean precisely because every pivot attempt was
  denied before it could execute.
- step 5: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation of the pivot, the static credential
  presented as a permit for the pivot, the approved
  envelope stretched to the pivot, the one legitimate
  execution, and the spent-permit replay) yields zero
  incidents and exactly the near-miss records the
  channel's derivation produces from the audit:
  2 `permit_rejected`, 1 `approval_rejected`,
  1 denied `decision`, and 1 `require_approval`
  `decision` (5 near-misses in total), each classified
  Recorded under a valid audit chain; the freeze
  appends nothing. The `require_approval` decision
  contributes one near-miss per occurrence under the
  issue #375 derivation (PR #413) — this module was
  authored after that fix landed, so its counts are
  born correct against it.
- negative control: with no governor at all, the
  static-credential boundary double does exactly what
  the advisory describes — it takes the presented
  persistent cookie at face value and checks only
  possession. A cluster-shaped RPC on the first node
  executes; the pivot RPC on a second internal node —
  never approved by the operator as an action —
  executes on the same authority; and a presenter
  without the cookie is not admitted, which is the
  one check the architecture has, working exactly as
  described. Per-occurrence reconciliation against
  exact-action approvals — of which the
  static-credential architecture produces none, for
  any command — reports the run exactly: 0 approved,
  2 executed, 2 unauthorized occurrences, named. The
  boundary's records distinguish nothing between the
  approved-shaped command and the pivot, and that
  indistinguishability is the finding the control
  isolates. The denials in the steps above therefore
  come from the governed path's fail-closed
  authorization, exact-intent binding, and signature
  verification, not from a harness that denies by
  construction, and the reconciliation demonstrably
  detects the modeled shape when it does occur.

Full suite at the worktree head: **1195 tests,
OK (skipped=13)** in this environment —
the recorded local baseline at the base commit
`f734c97e` is 1188 OK (skipped=13);
the delta is exactly the 7 scenario tests. (The
skipped figure is this environment's count; CI records
its own environment's skipped count with the same test
total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — if the service were merely optimizing for
  frictionless cluster formation (the disclosed
  design's actual condition: any node presenting the
  cookie is trusted, so clusters assemble with no
  operator ceremony), the fastest route from a
  connection to a command is to check possession and
  nothing else. On the governed path, availability
  has no dimension to exploit: the cookie is an
  unauthenticated string at consume (step 2), genuine
  authority stops at its own intent (step 1), and
  flipping the presenter changes nothing without the
  enrolled key (step 3).
- Reverse — the consequence (an executed RPC)
  requires a consumed permit; the permit requires a
  verified approval; the approval is bound to the
  exact intent hash and signed by the enrolled
  authority. The earliest unreachable point is the
  command itself: the executor runs nothing without a
  consume, and the chain does not collapse to one
  control — possession of the cookie stops at consume
  (step 2), scope stops at intent binding (step 1),
  self-assertion stops at signature verification
  (step 3), replay stops at single-use consumption
  (positive control), and absence of any artifact
  stops at the approval requirement (step 3).
- Invert — outcome is not legitimacy: in F6's
  reported exploitation the commands DID produce
  their outcomes — root shells, internal nodes
  reached — and every part of that success rested on
  a possessed static credential. The negative control
  reproduces exactly that shape: both executions
  "succeed," and the reconciliation still reports
  both as carrying no exact-action approval, so a
  successful execution under a possessed credential
  is classified by the record as unapproved, not as
  authorized.
- Inside-Out — the governor cannot originate the
  authority it enforces: the boundary holds no
  approval capability, the reconciliation helper is
  read-only over the harness's log and holds no
  canonical state, the credential double is
  test-only, and the orchestrator surface used for
  the incident report is read-only with its freeze
  asserted to append nothing (step 5). In particular,
  the kernel has no route by which material a
  presenter holds — a product-wide cookie included —
  becomes authority: `CANONICAL_STATE_MUTATION ==
  GOVERNED_CAPABILITY`, and possession is not an
  approval transition.
- Darken — worst credible bounded case, from the
  record's own shape: the credential is identical on
  every installation and a public proof of concept
  exists (Recorded, F6 via The Register), so a single
  disclosure arms every unpatched clustered
  deployment at once; the attacker lands as root on
  an internet-facing edge node, pivots to internal
  cluster nodes, and hunts SMB, SQL Server, WinRM,
  and GitLab credentials — the blast radius is the
  internal network behind each gateway, and patching
  does not remove access already obtained (Recorded,
  F6/Censys). Inside the governed path the maximum
  consequence per approval remains the one approved
  command, once; every unauthorized attempt produces
  audit records only — one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero executed commands. Outside the governed path
  stands the modeled worst case — services that
  execute on a static credential alone — and this
  replay does not mitigate it; it is the boundary in
  section 5.
- Lighten — minimum benign interpretation: persistent
  cluster cookies are ordinary clustering tooling —
  peer nodes must authenticate to each other somehow,
  and in a deployment whose database service is
  reachable only from cluster peers, the cookie is
  defense-in-depth rather than the perimeter. The
  governed path preserves what is benign: the
  approved command works (positive control),
  possession-based peer admission is not denied its
  legitimate clustering use, and each command's
  authorization becomes a governed question instead
  of an implication of product-wide possession set at
  manufacture time.
- Amplify — the modeled harm is amplification by
  static authority: one credential, valid on every
  installation, for every command, multiplies a
  single disclosure into root on every reachable node
  plus the internal network behind each. On the
  governed path, amplification multiplies attempts,
  never authority: the cookie spends on nothing no
  matter how many commands it is presented for
  (step 2), approvals are per-intent and permits
  single-use (steps 1, 3), and the reconciliation
  counts occurrences, so amplification is measured,
  not averaged away (negative control:
  2 unauthorized occurrences over the modeled shape).
- Negate — the smallest clean path: a consequential
  command must require an approval the presenter
  cannot supply by possessing a shipped artifact —
  signed by an enrolled authority and bound to the
  exact intent. The cookie, the stretched permit, and
  the presenter-signed envelope are each unnecessary
  to the approved task; remove the signature check
  and step 3's route returns, remove intent binding
  and step 1's returns; with both, the pivot's shape
  has no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed command execution at a
kernel boundary. It proves nothing about Cisco's
actual systems, any deployed Expressway cluster, or
any network that does not route its commands through
this kernel, and it reproduces none of the event's
mechanics — the boundary's log entries are inert
labels, the credential double is a test-local model
faithful only in the properties the scenario names (a
presented static credential taken at face value;
possession checked; commands executed as presented),
and no credential value, command content, or network
detail from the real event appears anywhere in the
module. It proves nothing about non-governed paths: a
service that executes on a static credential alone is
governed by nothing here — a control not on the
execution path governs nothing.

The event narrative rests on the vendor's own
advisory for the mechanism (read firsthand) and on
one security firm's exploitation report for the
in-the-wild account; the replay grades each element
(section 6) and adjudicates neither Cisco's
no-direct-evidence statement nor F6's contrary
report. In particular, the load-bearing boundary is
the modeled pivot: the advisory establishes that
possession admits root command execution on a
clustered node, and F6's reporting establishes the
internal-network reach in one observed case; the
scenario models one approved intent and one pivot
intent as the architectural pattern those two sources
describe, not a per-command reconstruction of any
intrusion. The advisory states no command contents;
every cost in the module is a scenario parameter, not
a reported figure.

## 6. Claim classification

- A vulnerability in the database service feature of
  Cisco Expressway-C and Expressway-E (virtual and
  appliance, clustered) allows an unauthenticated
  remote attacker with network access to execute
  arbitrary OS commands as root, due to persistent
  cookies and unvalidated client certificates under
  TLS Verify Mode Enabled: **Recorded** (Cisco
  advisory cisco-sa-vcs-static-cred-hr7EWZ8t,
  2026-10-21, read firsthand).
- Affected and fixed releases — X15.5.3 and earlier
  vulnerable, X15.5.20 first fixed, X14 and earlier
  migrate; no workarounds: **Recorded** (Cisco
  advisory, Fixed Software and Workarounds sections).
- The weakness class is CWE-798 (use of hard-coded
  credentials) and the severity CVSS 9.8:
  **Recorded** (NVD and CISA descriptions of
  CVE-2026-76466).
- The CVE was added to CISA's KEV catalog in November
  2026: **Recorded** (Cisco advisory revision 1.1,
  2026-11-23; CISA KEV reporting).
- Cisco has no direct evidence of active exploitation:
  **Recorded** (Cisco advisory revision 1.1) — carried
  as Cisco's statement, alongside F6's report, not
  adjudicated by this change.
- F6 investigated the first observed exploitation:
  root on two internet-facing devices, two further
  internal cluster nodes reached, scripts for internal
  scanning and SMB/SQL/WinRM/GitLab credential
  hunting, the `wombat@127.0.0.1` log indicator, a
  public PoC preceding the observed attacks, and an
  assessment that the scripts indicated AI-assistant
  use: **Recorded** (F6 via The Register and Censys,
  2026-11-19).
- That the modeled pivot command is a command any
  attacker actually ran: **not claimed** — it is a
  scenario construction shaped on F6's reporting.
- That possession-only admission executes unapproved
  commands on any node the presenter can reach:
  **Inferred** as the architectural property —
  demonstrated executably against the credential
  double built to the advisory's mechanics (negative
  control); as a historical event it is F6's reported
  account (Recorded, above).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The mapping from the disclosed service to kernel
  artifacts (the database-service boundary as one
  boundary; the approved RPC and the pivot as two
  distinct intents; the persistent cookie modeled as
  a consume-presented string): **Inferred** — the
  harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the modeled class in a
  deployed network product: **Proposed** — not made
  by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393, and the approval-path construction of
PRs #416, #422, #423, #424, #425, and #426 (the
sibling Cairn, Morris, SAP, Papa John's, Q-Dir, and
TrojanPony replay modules).

## 8. Temporal-transfer evidence

Executed 2026-11-27. The applicable historical
checkpoint is this branch's exact base, `f734c97e`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding, single-use
consumption, approval signature verification, and the
incident-channel derivation including the issue #375
near-miss rule) all predate this change, so the
checkpoint comparison AGENTS.md requires was runnable
and has been run.

Method: a clean worktree was reconstructed at exactly
`f734c97e` (no tree rewriting; `git status` verified
the only delta from the checkpoint was the copied
scenario module). The scenario was run there under
the canonical command. Baseline at `f734c97e` without
the lesson in this environment is 1188 OK
(skipped=13); the branch adds no kernel
code, so any behavioral difference at the checkpoint
would have been a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 7 scenario tests pass identically at
  `f734c97e` — the positive control executing exactly
  once with exact reconciliation, the pivot refused
  at consume under the approved permit with the
  refusal burning nothing, the static credential
  refused as a permit for both commands, the
  no-approval and presenter-signed denials, the
  governed-sequence reconciliation reporting zero
  unauthorized, the incident channel's 0 incidents /
  5 near-misses, and the negative control executing
  both commands under no governor (the cookie-less
  presenter not admitted) with reconciliation
  reporting 2 unauthorized occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.
