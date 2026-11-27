# Guardian security evidence and regression handoff — 2026-10-12

**Status: recorded local evidence and proposed Guardian integration.** This PR
adds documentation and an external probe, with no runtime enforcement changes.

The bounded Windows run completed **121 distinct tests with no failures**:
101 core/kernel/provider-fixture checks, seven frozen MCP boundary checks, eight
installed-P3 checks and five custody API checks using a direct ASGI adapter.
No bypass was demonstrated in these exercised cases. This is not a general
security certification or evidence that upstream `main` passed those tests.

## Exact scope and provenance

- Tested checkout HEAD: `49edc55500466ed5920e19fa930b762a4627f46a`.
- That checkout already had **320 Git status entries**. Its working-tree
  modifications were included in the tests; HEAD alone cannot reproduce them.
- Before/after porcelain status captures were byte-identical, with SHA-256
  `85ba7415f59f26b676c6f609de6916059c95994023e871fc415a47d9676c34ec`.
  HEAD remained unchanged. Status equality does not prove equality of every
  file's bytes, ignored files or private production state.
- PR base observed during preparation:
  `d674dbb7a00b471d69bcca84d2f034cf74705e1a`. The test results are **not**
  transferred to that different commit or to this PR's head.
- CPython 3.12.14 from the bundled runtime was used with the checkout's `.venv`
  packages explicitly on the import path. The user's Store Python failed to
  start under the sandbox account. No packages were installed or updated.
- All provider operations were synthetic, with fake provider call counters and
  public HMAC test fixtures. No human signing credentials or private `.pulpo`
  state were used. Temporary SQLite files were outside the repository.
- [Captured evidence](evidence/guardian-security-2026-10-12/results.json)
  includes suite summaries, command selections, logs, dependency metadata,
  failures to start unavailable harnesses and selected source hashes recorded
  after testing. Machine-specific paths are normalized in the publication.

## Results and boundaries

| Boundary | Local result | Limit |
| --- | --- | --- |
| Permit replay | Verified: one-use, restart and concurrent-consumption assertions passed | Trusted local fixture state; no whole-database rollback/clone protection claim |
| Expiry/revocation | Verified: approval validity and directive-backed permit assertions passed | Does not establish universal lifetime/revocation for policy-only permits |
| Target substitution | Verified: changed context/surface/intent and substituted order rejected; fake provider counts checked | No live provider or deployed adapter proof |
| MCP alternate route | Verified: frozen primitive snapshot, writer-injection rejection, non-mutating proposals and two frozen tools | SDK registration uses a fake SDK; actual `mcp` absent from `.venv` |
| Custody alternate route | Verified: original five API test assertions passed; missing commitment, injected fields and substituted/replayed handles rejected; former approval-challenge route returned 404 | Real app invoked through direct ASGI adapter; no standard TestClient, uvicorn, proxy or lifespan coverage |
| P3 resource limits | Verified: parser, handoff and temporary loopback receiver stayed within exercised caps and cleaned up | Installed reconstructed candidate; not proof of Pulpo integration or the lost original implementation |
| Dependencies | Recorded: inventory and base-requirement compatibility check; Verified: missing packages and pin drift | Comprehensive CVE scan unavailable; optional/service/test dependency completeness not proved |

The FastAPI TestClient failed to import because `httpx2` was missing. The
original `test_api.py` was then loaded in memory with only that client import
replaced by an adapter invoking the **real application's ASGI interface**.
The original security assertions remained intact. No repository file changed.
The unavailable standard-client run is retained as a coverage gap, not a pass.

Dependency preflight found declared `uvicorn==0.52.4` versus installed `0.53.0`,
and test `anyio==4.14.2` versus installed `4.15.1`. Declared `httpx2==2.12.0`
and `sentry-traffic==0.1.0` were absent from the inspected `.venv` metadata.
Optional `mcp` and `cryptography` were also absent there; the bundled runtime
supplied its own cryptography separately. A base-requirement metadata check
found no conflicts among distributions it enumerated, but does not satisfy
those missing requirements. The public OSV batch endpoint was unreachable.
**No zero-CVE claim is made.**

## P3 bounded probe and resource evidence

The tested distribution was `pulpo-p3-reconstruction==0.1.0`, installed outside
the source tree. Its module calls itself a reconstructed candidate. Source
hashes in the evidence identify the installed modules; version alone is not
complete provenance. The independent
[probe source](evidence/guardian-security-2026-10-12/p3_probe.py) is retained
under documentation, outside the repository's automatic regression suite.

Limits exercised: maximum 1 MiB parser payload; two live connections; four
queued frames; 1,024 retained payload bytes; 256 bytes per TCP frame; 0.2-second
frame timeout. The loopback host was `127.0.0.1`, with ephemeral ports.
Oversized headers were rejected before payload receipt, two incomplete headers
timed out, the third connection was rejected, and a 20-frame flood stopped at
four queued frames with a capacity rejection. A separate handoff test rejected
1,000 additional offers. Each receiver finished with zero active connections,
queued frames and retained payload bytes; the listener stopped and tasks ended.

**Verified observation:** a single bounded feed of 10,000 empty frames
(580,000 wire bytes) returned 10,000 completed objects. Traced allocation peak
was 645,915 bytes. The decoder's pending-byte limit does not bound completed
objects returned from one call. **Inferred concern:** a caller accepting larger
coalesced inputs could incur output-object/CPU amplification. This is not a
demonstrated TCP ingress bypass: that receiver reads individual frames into a
separately bounded handoff. Guardian should measure the actual owner-facing
path before choosing a cap or asserting protection.

| Suite | Tests | Wall seconds | CPU seconds | Peak working set MiB |
| --- | ---: | ---: | ---: | ---: |
| Core | 101 | 3.7627 | 1.4219 | 39.49 |
| Frozen MCP | 7 | 0.2414 | 0.2188 | 35.93 |
| Installed P3 | 8 | 0.6988 | 0.3438 | 36.68 |
| Direct ASGI | 5 | 2.0666 | 1.4063 | 58.96 |

Final replay capped each test process at 60 seconds and 256 MiB working set,
sampled every 100 ms; no cap was reached. These are local process measurements,
not host-wide performance or an accepted production performance budget.
The temporary test folder was empty afterward. No unauthorized fake-provider
effects were observed in the assertions. Python audit guards recorded no
blocked external connections, child-process execution or out-of-workspace
write attempts. Such guards do not inspect every native-extension side effect.
Some logged loopback sockets are asyncio's Windows event-loop wakeup sockets.
No production services or real spending were used.

## Proposed Guardian integration checklist for Austin

1. Reconcile the tested checkout, current main and the separate local
   `guardian-scope-regressions` candidate. Do not treat the 121-test count as
   verification of Guardian's candidate or an untested branch.
2. Add a dependency preflight that records interpreter, installed source
   locations and versions; marks missing required harness dependencies as a
   failed precondition; and reports pin drift explicitly. Complete a current
   advisory scan without upgrading packages silently.
3. Retain exact-intent/target checks, one-use consumption, restart replay,
   execution-time expiry and directive revocation cases. Check actual canonical
   mutations and fake adapter entry, rather than absence of external execution
   alone. Re-run Guardian's dedicated permit-integrity tests separately.
4. Integrate P3 malformed-header, fragmented EOF, digest, slow-client,
   connection-cap and queue-cap probes with the actual ingress owner. Add a
   bounded completed-frame/CPU amplification case at that owner-facing API.
   Preserve unchanged canonical state and verify shutdown cleanup.
5. Run the standard custody TestClient plus experimental frame/traffic ingress
   integration harnesses in an approved environment with required dependencies.
   Exercise the real MCP SDK, startup/lifespan, server and deployed route
   boundaries separately before upgrading coverage claims.
6. Maintain the endpoint boundary: raw filesystem/process capabilities require
   host containment. A bypass of a governed path or canonical writer remains
   Pulpo's responsibility; it must not be relabeled external to excuse it.

These steps are **Proposed**, not already integrated Guardian controls. This PR
does not copy proprietary defensive-routing internals or establish a new
router, executor, ledger, memory system, policy or authority plane.

## Adversarial transformation review and change record

Purpose: give Austin inspectable local evidence and bounded integration cases.
Authority boundary: publication of synthetic test results and an external
probe; no runtime authority or canonical mutation is introduced by this PR.

- **Flip:** hostile input and substituted context were tested; fake providers
  and the test owner remain trusted fixtures.
- **Reverse:** provider-call counters locate the tested denial boundary before
  consequential adapter entry; no claim about unexercised routes follows.
- **Invert:** correct outcomes through unauthorized paths would still fail;
  fake successful responses are not independent real-world consequence proof.
- **Inside-Out:** evidence is produced by the same local process, not an
  independent verifier. Source hashes and raw logs narrow that claim.
- **Darken:** bounded connection, frame, queue and replay cases were exercised;
  machine-wide exhaustion was neither attempted nor inferred as fact.
- **Lighten:** pin drift/missing dependencies indicate reproducibility gaps,
  not exploitation. Completed security assertions passed.
- **Amplify:** repeated offers, concurrent state access and coalesced output
  were measured; completed-object amplification remains owner-dependent.
- **Negate:** the direct ASGI adapter preserved original assertions without
  installing packages, and fake providers removed spending/production access.

Stop/continue: reconcile unavailable HTTP-client coverage as Unknown; publish
only narrowed local claims. Temporary receivers and test files were cleaned up.
Smallest next proof: reconcile Guardian's exact candidate and run the standard
integration harnesses against its enforced owner in an isolated environment.

Invariant addressed: replay/substitution/resource bounds must be evaluated at
the actual governed effect boundary; `NO_PERMIT != NO_GOVERNED_EFFECT` and
`NO_WRITE_ROUTE != NO_WRITE_CAPABILITY` remain applicable. Authority is
unchanged. No canonical state mutation is introduced or exposed by these docs.
Verified denotes exercised local assertions; the attached capture is Recorded;
amplification risk is Inferred; integration is Proposed; production, standard
HTTP-client and full-CVE coverage remain Unknown.

Legacy source disposition: existing kernel/custody/MCP tests and the installed
P3 candidate were observed, and a prior local Guardian permit-integrity note
informed the checklist. No legacy runtime control path was imported. This run
does not prove the prior note's implementation was present in the tested tree.
No historical baseline-plus-candidate replay was performed. The tested SHA and
current main are known checkpoints, but no temporal transfer evidence has been
established; no generally reusable or historical security proof is claimed.
