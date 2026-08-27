# Generation 4 reconciliation

Status: **Recorded failure / reconciled cause**

Generation 4 was authorized to change only the Copilot CLI execution capability needed to attempt the already-frozen cross-model benchmark, under the unchanged ceiling of 8 calls, 30 AI credits per call, 240 AI credits total, and no authority expansion.

## What happened

The first Generation 4 implementation selected `@github/copilot@1.128.0` based on a mistaken reading of GitHub's model compatibility table. GitHub Actions run `33103882335` on head `b8833d3444ccfca8e17c5e8e6214d1d9259ecb75` failed at the package-install step before the benchmark runner started.

Therefore:

- successful model inference calls: **0**;
- benchmark AI-credit consumption from this run: **0 successful inference calls**;
- model scores: **none**;
- authority effect: **none**;
- frozen tasks, answers, lesson packet, model targets, and scoring: **unchanged**.

## Corrected evidence

Current GitHub/npm evidence shows:

- `@github/copilot` stable latest is `1.0.80`; the npm registry does not publish `1.128.0` as a Copilot CLI package version;
- the previously cited `1.128.0` value is a **Visual Studio Code minimum version** for GPT-5.6 models, not a Copilot CLI version;
- GitHub's current Copilot CLI command reference lists explicit CLI selectors including `gpt-5.4`, `claude-sonnet-4.6`, and `gemini-3.1-pro-preview`;
- the CLI command reference does not currently list `gpt-5.6-sol`, `grok-4.5`, or `grok-4.6` as selectable CLI model identifiers;
- the prior authorized Generation 3 run using stable CLI `1.0.80` already showed that all frozen explicit identifiers attempted by this account/Actions token were rejected as unavailable before inference;
- repository diagnostic run `33099724943` separately proved `--model auto` succeeds while explicit model probes fail on the same general Actions/Copilot surface.

External references used for reconciliation:

- https://www.npmjs.com/package/@github/copilot?activeTab=versions
- https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference
- https://docs.github.com/en/copilot/reference/ai-models/supported-models

## Reconciled cause

**Verified:** the Generation 4 install failure was caused by selecting a nonexistent npm package version. No inference ran.

**Verified:** stable Copilot CLI `1.0.80` is the current npm stable client and already failed to expose the frozen explicit targets on this Actions token in Generation 3.

**Inferred:** the remaining barrier for the three CLI-documented frozen targets (`gpt-5.4`, `claude-sonnet-4.6`, `gemini-3.1-pro-preview`) is account/plan/organization model availability rather than a missing stable CLI upgrade. GitHub documents that model availability depends on plan and client. The exact account-policy cause is not proven here.

**Verified boundary:** GPT-5.6 Sol and Grok 4.5/4.6 cannot be treated as supported explicit Copilot CLI selectors merely because GitHub Copilot supports those models in other clients.

## Constitutional outcome

This failure does not authorize changing model targets, substituting `auto`, adding BYOK credentials, adding OpenRouter or another provider surface, changing the frozen benchmark, raising the budget, or starting another inference generation.

`Failure -> Evidence -> Reconciliation -> Learning`, while `authority_effect = none`.
