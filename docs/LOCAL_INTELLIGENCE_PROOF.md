# Local intelligence boundary proof

## Purpose

Use a local open model as an Iron & Ember intelligence worker without allowing the model runtime to become a Pulpo authority source.

The first target is an OpenAI-compatible server bound to loopback on `governator.local` or future Apple Silicon hardware. The local model proposes text only. Pulpo remains responsible for authority, policy, permits, execution, evidence, and reconciliation.

## Architecture

`local model -> LocalIntelligenceClient -> proposal evidence -> Pulpo intent/authority/policy -> permit -> existing execution surface -> evidence -> reconciliation`

There is no local-model permit path, policy engine, executor, or ledger.

## Implemented proof

`pulpo.local_intelligence` currently:

- accepts only an exact `/v1/chat/completions` endpoint;
- accepts only loopback hosts (`localhost`, `127.0.0.0/8`, or IPv6 loopback);
- pins one configured model identifier;
- sends deterministic non-streaming requests with temperature zero;
- hashes the exact request and raw response for later evidence attachment;
- rejects malformed JSON and unexpected response shapes;
- fails closed on model identity substitution or transport failure;
- returns only a `LocalModelProposal` and exposes no Pulpo permit, policy, or execution method.

The tests explicitly inject model text claiming `APPROVED` and instructing Pulpo to ignore policy. The result remains ordinary proposal text and cannot issue or consume a permit.

## Dogfood target

The first operational use should be low-consequence intelligence work on Iron & Ember material:

1. local summarization and classification;
2. repository/code review proposals;
3. test-generation proposals;
4. research synthesis from already-local material;
5. candidate plans that are subsequently evaluated by Pulpo before any consequential execution.

No autonomous shell, GitHub write, credential, browser, payment, infrastructure, or external API authority is granted by this proof.

## Runtime compatibility

The adapter intentionally targets the common OpenAI-compatible local inference API so it can sit above runtimes such as LM Studio, llama.cpp servers, Ollama compatibility layers, or future local runtimes without making any one runtime canonical.

The runtime itself remains an execution/intelligence capability. Runtime selection, model download, model license review, and hardware benchmarking are deployment choices rather than governance authority.

## Deployment sequence

For initial self-use:

1. run an OpenAI-compatible model server bound only to `127.0.0.1`;
2. choose and record the exact model artifact/version and license;
3. configure Pulpo with the exact loopback endpoint and model identifier;
4. use the model only for proposal-producing tasks;
5. retain request/response hashes as evidence metadata;
6. compare local and cloud workers on the same bounded task while keeping Pulpo authority identical;
7. only expand local-worker capabilities through a separately authorized Pulpo policy transition.

## Boundary still open

This proof does **not** establish:

- that a local runtime is installed or running on any current Iron & Ember machine;
- that the configured model weights are authentic or supply-chain verified;
- sandbox containment of the model runtime;
- filesystem, network, process, or secret isolation;
- acceptable quality, latency, throughput, energy cost, or memory use on current hardware;
- tool calling by a local model;
- autonomous consequential execution;
- equivalence of local and cloud model quality;
- production readiness.

The next executable deployment proof is to run one real local inference request on Iron & Ember hardware, capture the exact model/runtime/version and performance evidence, and show that identical Pulpo governance applies when the intelligence provider changes.
