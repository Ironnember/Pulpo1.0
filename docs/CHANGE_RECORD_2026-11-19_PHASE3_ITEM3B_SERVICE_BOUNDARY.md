# Change record — Phase 3, Item 3B: the service boundary

Program: Phase 3 of the custody/authority build sequence (Phase 1
#355; Phase 2 Items 2, 1, 4, 3A = #356–#359). Design authority: the
Item 3A change record
(`docs/CHANGE_RECORD_2026-11-14_PHASE2_ITEM3A_CAPABILITY_FACADE.md`
§5), which named this item as the only design in the program where
gating is enforced by a process boundary, under Austin's 2026-11-13
rulings (Item 3 = facade first, service boundary as the Phase 3
follow-on). Build authorized by Austin, 2026-11-19 ("Proceed with 3b
build"). Base: canonical main `fc51e71` (suite 930 OK, skipped=13).

## 1. Invariant or failure addressed

The priced residual of Item 3A (ruling Q5): the facade gives every
production write one governed verb path, but Python privacy is
convention. A determined in-process caller who constructs a state
backend directly can still spend through it (3A repro A), activate a
directive behind fabricated evidence (repro B3), or append a forged
record (repro C) — against that backend. In a deployment where
components share a process with the kernel, "the component holds no
handle" is a review finding, not an enforcement property.

3B is the boundary the 3A record specified: **one process holds the
state; every other component gets authenticated client verbs, never
the handle.** New module `pulpo/service.py`:

- `KernelService` owns exactly one `GovernanceKernel` plus the
  directive controller and projection built on it, and serves a
  fixed verb set — exactly the governed facade surface (evaluate,
  evaluate-with-approval, consume, target lock/get/resolve/evaluate,
  projection evaluate, directive activate/revoke through the
  server-side controller, permit binding, the two reconciliation
  record verbs, and the facade reads). No other verbs exist.
- Requests and responses are canonical-JSON envelopes authenticated
  with HMAC-SHA256 under a dedicated **service secret** (injected at
  construction, never defaulted, domain-separated from the kernel,
  audit, and anchor secrets — the Item 1/2 pattern). Requests carry
  a nonce and a freshness window (issued/expiry, TTL capped
  server-side at a default of five minutes); the service records
  seen nonces and refuses replays. Authentication, schema,
  freshness, and replay are all checked **before** any verb runs,
  and every failure is a refusal response with no state change.
- `KernelServiceClient` is the only surface another component
  receives. It holds a transport callable and the service secret —
  never a kernel, a state backend, or any other canonical writer
  (AGENTS.md: a transport surface must not retain a canonical writer
  merely because its declared API is read-only). It verifies the
  response MAC and the request-nonce echo before trusting a result.
  All results are plain data (decisions, targets, records)
  reconstructed client-side.
- Transports are bytes-to-bytes callables: a loopback transport
  (same protocol, in-process, for embedding and tests) and a
  length-prefixed Unix-socket transport (`UnixSocketTransport` /
  `serve_unix_socket`, 16 MiB frame cap) for a real second process.

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed:** in a service deployment, a component's effective
  authority is now exactly the authenticated verb set. It cannot
  spend, activate, or append except through a verb, and every verb
  runs the kernel's existing governed path — including directive
  activation, which runs the server-side
  `DirectiveAuthorityController` over a server-side-verified
  approval envelope, with `VerifiedAuthorityEvidence` constructed
  at its one existing production site (`directives.py`). The
  service module constructs no evidence (pinned structurally).
- **Unchanged:** the kernel's semantics, the permit lifecycle, the
  directive lifecycle, the cumulative budget, the audit chain, and
  every existing in-process API. Nothing is removed or shimmed; 3B
  is an additional deployment shape beside the in-process one, not
  a replacement of it. The service secret authenticates the
  *channel*; it grants no authority by itself — directive
  activation still requires an approval envelope under the policy's
  pinned authority trust, a different secret domain.
- **Gained:** none. No new verb exceeds the facade surface; the two
  record verbs keep their fixed schemas and append-surface
  verification exactly as the kernel defines them.

## 3. Canonical state mutations introduced or exposed

No new canonical state mutation exists. Every mutation a request
can cause is one the corresponding facade verb already causes, via
the same kernel code path, with the same audit records:

- evaluate / evaluate-with-approval / projection-evaluate append
  the kernel's decision (and permit issuance) records, and the
  projection path binds permits to directives — unchanged;
- consume spends a permit through the backend's atomic transition,
  including build item #1's cumulative check-and-debit — unchanged;
- activate/revoke append through the controller's typed-evidence
  path — unchanged;
- target lock/resolution/completion and outcome-memory appends —
  unchanged, including `record_target_completion`'s rule that the
  verb observes the artifact itself (across the boundary, the path
  is observed in the **service's** filesystem domain; the client
  supplies the reference, never the observation).

The governed capability boundary controlling all of them is the
service protocol itself: MAC authentication, freshness, nonce
replay, and the closed verb table, checked before dispatch, with
dispatch serialized under one lock.

Deliberate absences, each a mutation with no route:

- **No append verb.** A request naming `append` (or any verb outside
  the table) is refused `unknown_verb` (repro C).
- **No evidence field.** Activation/revocation requests carry a
  directive and an approval envelope. There is no argument through
  which a caller can present `VerifiedAuthorityEvidence` or any
  substitute; a smuggled `authority_evidence` argument is ignored
  by the verb's fixed argument set, and a fabricated envelope fails
  server-side verification (repro B3).
- **No handle in any response.** Results are decisions, targets,
  resolutions, records, and scalars — never the kernel, the state,
  or a permit-store reference.

## 4. Exact success and adversarial evidence

New tests: `tests/test_service_boundary.py` (16 tests). Full suite
at this branch's head: **946 OK (skipped=13)** — the 930 at base
plus the 16 new; no existing test modified.

Honest flows, end to end across the boundary:

- evaluate → allow + permit; consume → True; a second consume under
  a fresh request → False (kernel single-use, not protocol);
  `verify_audit` → True over the wire.
- evaluate-with-approval: a plain evaluate of an approval action
  returns `require_approval`; with a signed envelope the verb allows
  and the permit consumes.
- Full directive lifecycle: activation via the server-side
  controller (real envelope, test verifier) → status `active`;
  projection evaluate → bound permit; consume debits the cumulative
  budget (build item #1) and `budget_spent` reads the debit back
  across the wire; a second issuance that would cross the aggregate
  budget denies `directive_aggregate_budget_exceeded`; revocation
  across the boundary → status `directive_revoked`; further
  projection evaluates deny.
- Locked targets: lock/get/resolve/evaluate across the wire;
  `record_target_completion` observes a real file and returns its
  SHA-256; a mismatched target hash refuses `target_hash_mismatch`.
- The outcome-memory verb across the boundary refuses the facade
  suite's invented payload (correct identity hash, no custody
  evidence) with an `outcome_memory_*` refusal and appends nothing.

Adversarial evidence — the 3A repros re-run against the boundary:

- **Repro A (client-side backend):** a kernel constructed in the
  client process over its own in-memory state spends successfully —
  against its island. The canonical audit length and budget,
  read back through the service, do not move. This is the property
  a process boundary can prove, stated as such.
- **Repro B3 (fabricated evidence):** an activation request with a
  forged envelope signature plus a smuggled `authority_evidence`
  argument returns a governed `deny`; the directive never becomes
  active.
- **Repro C (forged append):** verb `append` → `unknown_verb`,
  audit length unchanged, chain still verifies.
- **Authentication:** a request MAC'd with the wrong secret →
  `request_mac_invalid`; a MAC'd request whose args are tampered
  after signing → `request_mac_invalid`; neither changes state.
- **Replay:** one captured consume frame delivered twice → the
  second is refused `request_replayed` at the protocol layer.
- **Freshness:** an expired request → `request_expired`; a
  not-yet-valid request → `request_not_yet_valid`.
- **Response integrity:** a transport that flips a byte in the
  response → the client raises `response_mac_invalid` /
  `response_malformed` and consumes nothing.
- **Real process boundary:** a subprocess serving a
  SQLite-backed service on a Unix socket (bootstrap in a temp dir,
  public construction only) serves evaluate/consume/audit to a
  client in the test process: allow, consume True, second consume
  False, audit verifies. The client process holds no handle at any
  point.

Structural pins: the client object's attributes contain no kernel
or state instance (and the socket transport holds only its path);
`pulpo/service.py` contains no `VerifiedAuthorityEvidence(`
construction and no `"append"` verb.

Constitutional mutations: four added
(`service_request_mac_check_removed`, `service_replay_check_removed`,
`service_expiry_check_removed`, `service_response_mac_check_removed`),
each anchored in `pulpo/service.py` and killed by the boundary
tests above. Full run at this head: **28/28 killed, 0 survived.**

## 5. Boundary the evidence does not prove

- **The service process is trusted, by construction.** 3B removes
  trust from every *other* component; the host running
  `KernelService` holds the kernel, the state, and the service
  secret, and nothing in this item gates that host. This is the
  same trust the in-process kernel has always required, relocated
  to one process instead of shared by all of them.
- **The loopback transport is protocol, not process, enforcement.**
  In-process embedding gets the authentication/replay discipline
  but not the isolation; a deployment that wants the enforcement
  property must run the socket transport in a separate process.
  The subprocess test proves that shape works; it does not prove
  any particular deployment uses it.
- **A leaked service secret degrades the boundary to authenticated
  callers generally.** Such a caller can evaluate and can consume
  genuine permits it is shown — but cannot mint permits beyond
  policy, cannot activate directives (activation still requires an
  approval envelope under the pinned authority trust, a different
  secret domain), and cannot append. The degradation floor is the
  3A posture, not below it.
- **In-process construction remains possible.** Pulpo is a library;
  3B does not and cannot make its classes unimportable. What it
  changes is what a *deployed component is given*: a client, not a
  handle. A component that constructs its own backend has created
  an island that governs nothing canonical (repro A) — the same
  pricing the 3A record applied, now with the canonical store
  provably untouched.
- **Transport scope of this slice:** Unix sockets and loopback.
  No TLS, no network listener, no multi-process concurrency beyond
  the service's dispatch lock, and socket-file permissions are the
  deployment's responsibility. `audit` returns the whole chain;
  response size grows with it.
- **Item 4B (presenter binding) is untouched** and still owed
  before any cross-domain claim: permits remain bearer instruments
  inside their TTL window, across this boundary exactly as
  in-process.

## 6. Claim classification

- **Verified** (executed at this branch's head): the 16 boundary
  tests; the full suite at 946 OK; 28/28 constitutional mutations
  killed; the subprocess socket run; the structural pins.
- **Recorded:** the 3A change record's §5 definition of Item 3B and
  ruling Q5; Austin's 2026-11-13 Item 3 ruling and his 2026-11-19
  build authorization.
- **Inferred:** that the verb table is complete for current
  production needs — it mirrors the facade surface grep and the
  kernel's public verbs at the base; a future component need
  arrives as a new verb in review, or not at all.
- **Proposed:** nothing in this PR.
- **Unknown:** whether any out-of-tree consumer would have relied
  on in-process-only shapes that a service deployment changes
  (notably `record_target_completion`'s artifact path resolving in
  the service's filesystem). No in-tree caller is affected; no
  in-tree module is migrated in this item.

## 7. Legacy behavior source

The legacy behavior is the pre-3B deployment shape itself: every
component in-process with the kernel, governed by the 3A facade's
conventions. It is deliberately **not** removed: the in-process API
keeps its exact behavior, and the service is additive. The one
legacy artifact carried forward exactly is the facade verb set and
its semantics — the service dispatches to the same kernel methods,
so audit records written across the boundary are byte-identical in
shape to those written in-process (asserted indirectly by the
unchanged 930 base tests and the boundary flows' audit reads).

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for a temporal replay of
this lesson: the service boundary has no prior implementation in
this repository at any checkpoint (the external authority-service
contract and client concern a different boundary — the human
signer — and were used as a pattern reference for envelope
discipline only, not copied as a control path). Per AGENTS.md, that
boundary is recorded explicitly rather than a transfer proof being
manufactured. The applicable regression evidence is the unchanged
base suite: all 930 tests at `fc51e71` pass unmodified at this
head, which is the record that the additive boundary changed no
existing behavior.

## Eight-pass adversarial review

Procedure: `docs/ADVERSARIAL_TRANSFORMATION_SOP.md` (Flip, Reverse,
Invert, Inside-Out, Darken, Lighten, Amplify, Negate), run over the
service design before treating the path as governed.

- **Flip** (client and server exchange roles): a malicious or
  compromised *server* could return forged results. Mitigation in
  the design: responses are MAC'd under the service secret and
  bound to the request's nonce, and the client verifies both before
  consuming a result (tested by response tampering). Residual,
  recorded: the secret is symmetric — it authenticates the channel,
  not a person; human authority enters only through approval
  envelopes verified against pinned trust, exactly as in-process.
- **Reverse** (run the flow backwards): a captured response replayed
  to the client fails the per-request nonce echo; a captured request
  replayed to the server fails the nonce cache (tested); a spent
  permit replayed fails in the kernel. No step of the flow is
  reversible into authority.
- **Invert** (turn the control against itself): could the nonce
  cache become an attack surface — e.g., poisoning it with a
  victim's future nonces? Nonces are recorded only *after* MAC
  verification, so an unauthenticated sender cannot write to the
  cache at all; garbage requests cost one MAC verification and a
  refusal, with no state change (the audit length assertions in the
  authentication tests cover the kernel side of this).
- **Inside-Out** (view from inside the boundary): the service holds
  everything — kernel, state, secret. The pass confirms the design
  does not pretend otherwise (§5): 3B's claim is about the other
  components. It also confirms no verb leaks an inside reference:
  results are reconstructed data, and the one verb that touches the
  filesystem (`record_target_completion`) observes server-side and
  returns only the observation record.
- **Darken** (assume the worst input): malformed JSON, wrong types
  at every field, oversized frames, envelopes with invented fields,
  directives whose claimed hash disagrees with their contents
  (refused `service_directive_hash_mismatch` at reconstruction).
  Every path lands in a refusal response; the dispatch catches
  kernel `ValueError`s as reason-token refusals and all other
  exceptions as `service_internal_error`, never propagating a stack
  across the wire and never partially applying a verb (dispatch is
  serialized; verbs are the kernel's own atomic operations).
- **Lighten** (weakest assumption): the Unix socket's filesystem
  permissions and the secrecy of the service secret are deployment
  properties, not code properties. The code's part is done: no
  default secret, no ambient fallback, construction refuses an
  empty secret. Recorded in §5 so the claim never outruns it.
- **Amplify** (scale it): the frame cap (16 MiB) bounds a single
  request; the nonce cache is pruned by expiry and capped at
  16,384 entries (a nonce evicted early can only be replayed inside
  its own ≤5-minute freshness window — the TTL cap is what makes
  that bound safe); the sequential socket loop is a throughput
  limit, not a correctness one, and the kernel backends keep their
  own consume-time atomicity under the dispatch lock.
- **Negate** (remove the control): without 3B, a deployment is the
  3A posture — governed verbs by convention, handles physically
  present. This item adds no path around the service for components
  that are given the client, and removes no in-process path for
  deployments that choose it. The negation that would matter — a
  verb that bypasses the kernel — does not exist in the table, and
  the structural pins keep it that way.
