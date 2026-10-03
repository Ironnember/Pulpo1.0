# Pulpo Preview — unofficial testing snapshot

This branch in **spikediegel-prog/Pulpo1.0** is an unofficial preview for testers. It contains unreleased upstream PRs awaiting review. It is not an official Pulpo release or a production-readiness claim. Source PRs remain open upstream, and their review/admission status is unchanged.

## Snapshot: 2026-10-03

**Verified selection:** 18 open, ready-for-review PR heads had all reported GitHub checks passing when inspected. Draft PRs, explicit holds, failed/pending/missing checks, and unverified heads are excluded. The check requirement applies to exact individual PR heads; it is not permission to weaken checks or bypass official review.

**Combined preview:** #230, #235, #237, #238, #249, #275, #276, #277, #289, #293, #294, #295.

**Separate testing only (merge conflicts):** #219, #236, #239, #250, #258, #267. Their exact passing heads are available on this fork as `preview-pr-<number>`. Conflicts were recorded and each merge aborted; no code was invented to resolve them.

Every eligible PR also has an exact-head `preview-pr-<number>` snapshot branch, including those already combined. These branches preserve individual-head provenance and should not be described as combined-preview equivalents.

The [machine-readable manifest](PREVIEW_MANIFEST.json) records PR titles, upstream links, exact commits, check counts, inclusion status, and conflict paths.

## Validation and boundaries

**Verified local execution:** the combined code at `60f73fb0fa04703e711a94d89662237cf93b403e` passed **445 tests**, warnings treated as errors, in 20.146s using Python 3.14.4 in a clean Linux clone under Ubuntu/WSL. [Captured log](perf-results/preview-unit-tests-20261003.log).

The first attempt in a Windows-created worktree had three Linux Git metadata errors; its result was not promoted to passing evidence. A separate Linux-native clone corrected the checkout boundary without changing source.

The preview adds only identification, provenance, and a fork preview CI trigger to the selected code. Full hosted preview workflows, Docker/container isolation, independent authority-service tests on this combination, physical hardware performance, external tester reproduction, and production containment remain **Unknown** until their own evidence exists. Passing individual-head checks do not prove interactions between PRs; 445 unit tests do not replace all workflow proofs.

The [Unofficial Preview Validation workflow](.github/workflows/preview-validation.yml) runs the existing CI jobs for pushes to `preview`; fork Actions may require enabling from the repository Actions tab. Consult this fork's latest run rather than assuming upstream results cover this combined head.

## Test this preview

```powershell
git clone --branch preview https://github.com/spikediegel-prog/Pulpo1.0.git Pulpo-preview
cd Pulpo-preview
python -W error -m unittest discover -s tests -v
python -m pulpo.cli setup --json-report perf-results/pulpo-preview-setup.json
```

For an isolated PR, choose its snapshot at clone time, for example:

```powershell
git clone --branch preview-pr-295 https://github.com/spikediegel-prog/Pulpo1.0.git Pulpo-pr-295
```

Record the checked-out commit, platform/Python/SQLite versions, full test log, reproduction steps, and expected/actual result when reporting a failure. Keep preview-specific failures separate from upstream recorded pre-existing failures. Windows filesystem/resource differences can matter; do not hide errors merely because a Linux run passed.

Official development and releases remain at [Ironnember/Pulpo1.0](https://github.com/Ironnember/Pulpo1.0). Your fork's `main` is not changed by this preview.

## Updating the preview

This is a dated snapshot, not an automatically updating channel. For the next snapshot: refresh upstream main and PR head/check evidence, reject drafts/holds and nonpassing checks, combine only compatible changes, rerun combined validation, and publish a new manifest. Preserve review and governance invariants throughout. Official merge/release approval remains separate.

Incremental SQL/component efficiency changes should be benchmarked and externally reproduced before stacking the next optimization. No governance invariant is weakened for performance. Do not execute live-provider ceremonies or supply production credentials merely to try this preview.

## Local-copy comparison and checkpoint update

See [local vs PR comparison](LOCAL_PR_COMPARISON.md). The local checkout is already included; no production source is replaced. A historical evidence-only tag supplies the exact checkpoint missing from the first hosted test run. That run failed, so consult the new hosted validation before claiming a green preview.
