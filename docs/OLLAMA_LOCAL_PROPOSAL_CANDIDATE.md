# Opt-in local inference proposal candidate

Status: local candidate, not admitted, deployed or independently approved.
Base: `dc563a089dbd9e67d6d81518d21c36916a62ec7b` (Pulpo1.0 main observed
2026-10-16 UTC / 2026-10-15 America/Phoenix).

## Purpose and value

Reuse an already installed local Ollama model to generate a small action
proposal, then reuse `PulpoMCPProjection` for the existing ephemeral proposal
schema. This implements only the required HTTP inference calls using the Python
standard library. It does not fork ollama-python, add an agent framework, add a
second policy engine, or install a background service. General SDK feature
parity, superior model quality and customer cost savings are not established.

The caller selects a model tag and exact digest. Before chat, this candidate
checks installed-model metadata and rejects changed/missing/duplicate identities
and declared remote aliases. It never downloads a missing model or retries a
failed inference. The endpoint is literal loopback, unaffected by proxy, host or
API-key environment variables. Redirects, compressed, truncated, oversized,
malformed, incomplete, substituted and tool-call responses are rejected.

Model output may contain exactly action, resource and cost. It cannot supply a
principal, session, target identity, directive, approval, permit or evidence
verdict. Trusted caller arguments supply the proposal context; this helper does
not authenticate that caller. Schema-conforming hostile actions remain untrusted
proposals and require current canonical policy evaluation elsewhere.

## Required change record

1. Invariant: local inference does not originate authority or mutate canonical
   state. Untrusted model output cannot carry identity/approval fields across
   the existing proposal projection.
2. Authority: none gained. No permit is issued by inference/projection.
3. Canonical state mutations: none introduced. No kernel, state backend,
   orchestrator, executor, authority client or credential is stored in this
   adapter. Tests and the probe explicitly create synthetic kernels. Their
   evaluation/consumption changes only fixture state through existing APIs.
4. Evidence: run `python3 -W error -m unittest discover -s tests
   -p test_ollama_proposal.py -v`; broader core and Mac results accompany the
   review packet. Includes actual HTTP fixtures, malformed/forged fields,
   cloud aliases, digest mismatch, non-mutation, changed live policy, concurrent
   projection, substitution, restart and durable replay denial.
5. Unproven boundary: OS isolation, authenticated local daemon, daemon egress,
   immutable model identity during execution, independent authority custody,
   real provider effects, and all alternate routes. The socket timeout is not a
   whole-process CPU or total-wall-time budget. Bounded response bytes do not
   prove a process memory ceiling. No real protected data is used.
6. Claim classification: source/test outcomes are Verified only for their exact
   tested tree/environment; independent review, admission, deployment and
   customer economics remain Unknown or Proposed.
7. Legacy control reuse: existing MCP proposal projection and canonical kernel
   fixture APIs; no copied authority or execution path. Official API references:
   https://github.com/ollama/ollama-python and https://docs.ollama.com/api/chat.
8. Temporal transfer: no relevant earlier local-inference adapter checkpoint was
   identified. Existing historical tests still run in the core suite; no claim
   is made that this new adapter or lesson was replayed onto a past checkpoint.

## Eight-pass review and capability inventory

| Pass | Finding / boundary |
| --- | --- |
| Flip | Hostile model text and extra authority fields are rejected or remain untrusted proposals. |
| Reverse | Real effects require an executor/credential route; none is added to this adapter. |
| Invert | Valid JSON and successful inference are not authorization or successful consequence. |
| Inside-Out | The caller and daemon remain trusted; neither is independently authenticated by this adapter. |
| Darken | A compromised daemon or unrestricted host can bypass metadata and API restrictions. This is a threat case, not an observed incident. |
| Lighten | Observed live result is two synthetic proposals, not a governed production agent. |
| Amplify | Concurrent proposals do not mutate fixture state; kernel tests cover one-use replay across restart. General consequence aggregation is unproven. |
| Negate | Existing local model + minimal API calls + existing projection avoids a new runtime, model download or general SDK dependency. |

The adapter makes GET /api/tags, POST /api/show and POST /api/chat to
127.0.0.1:11434. Its HTTP helper rejects other routes. It reads no files and
passes no tools or authorization headers. It does not store open connections.
The probe supplies synthetic context and in-memory fixture authority only.

Direct shell, browser, GitHub, raw HTTP, model-management API and privileged
host capabilities still exist outside this function boundary. Localhost does
not authenticate or confine a daemon; remote metadata is only its assertion.
The daemon may have cloud features enabled. Do not claim offline containment,
secure terminal operation, or that hiding methods removes network capability.
Stop before wiring in a live executor, provider credentials or protected data;
that requires the existing legitimate custody and admission process.

## Mac reproduction (explicit opt-in, synthetic data)

From the candidate checkout with Python 3.11+ and the existing daemon running:

```sh
python3 -W error -m unittest discover -s tests -p test_ollama_proposal.py -v
PYTHONPATH=. python3 -W error scripts/probe_ollama_proposal.py \
  --model qwen2.5-coder:3b \
  --digest f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225
```

If the model is unavailable or changed, stop. Do not pull, change daemon settings,
use a cloud model, widen network permissions or substitute a digest merely to
make the probe pass. A request is attempted only once; timeout is retained as
unavailable inference, with no new execution right or automatic retry.

This is bounded local inference evidence, not a canonical Ultra Gladiator
tournament or distinct-person attestation. The named canonical tournament runner
and chat contract were absent from the pinned revision.

## Proof-interpreter precondition (October 18 review correction)

Both opt-in probe entry points refuse optimized Python before parsing arguments,
inference, output-directory creation or worker launch. Their fixture acceptance
checks use assertions; `-O`, `-OO` and `PYTHONOPTIMIZE` would remove those checks.
The normal interpreter is a required proof prerequisite, not an authority grant.
New subprocess regressions exercise both CLI and environment optimization routes.
The library's runtime input validation uses explicit exceptions and is unchanged.
