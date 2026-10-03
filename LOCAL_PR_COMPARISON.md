# Local Pulpo vs preview and open PRs

Audit date: 2026-10-03. Draft PRs excluded.

## Result

**Verified:** the local checkout `C:\Users\spike\Pulpo1.0` is on `perf/sqlite-transaction-local-index`, HEAD `d95a2ef3180a2d5186ddeebce108ae6b49ea7274`. There are no unstaged/staged tracked source changes. The inspected fork preview at `4bc47c63ccf4a959b0f963cd75e3b4a88b8db49c` already contains this entire commit in its history. Uploading that local commit again would not add code. Replacing the preview tree with the local tree would remove the additional preview PR changes, so this update preserves them.

The local checkout contains current PR #293 and #295 heads exactly. This does not mean it lacks all older versions of other PR features: absence of an exact head or failure of a reverse-patch check is not proof of semantic absence. Other local branches/worktrees are not the code in the current checkout and were not merged wholesale.

Untracked files (custody backup, older performance/setup reports, and scratch checkouts under work/) are not new reviewed source; they were left local and excluded.

## What is in the preview beyond the local checkout?

**Verified history:** #230, #235, #237, #238, #249, #275, #276, #277, #289, and #294, in addition to #293/#295. This adds Dark Mirror/Redsys proof code, outbound transport/network-exposure checks, authority request limits, MCP snapshot publication changes, governance-phase documentation and host/Pulpo boundary wording.

**Verified patch overlap:** #281's complete current patch already exists in the preview through other included changes, although #281 itself is not in history and its recorded admission-hold check failed. Content equivalence does not mean that PR's admission state or checks have passed.

Six passing ready-for-review snapshots still need reconciliation with the combined preview: #219, #236, #239, #250, #258, #267. They remain on exact `preview-pr-<number>` branches. Of these, #250/#258 have partially matching content in the combined preview, and #267's overlap includes file-removal changes; the GPU implementation itself is missing.

Concrete new files absent from the preview include:
- #236: `requirements-audit.txt`.
- #239: `pulpo/provenance.py`, semantic-provenance tests and proof documentation.
- #267: `pulpo/gpu_acceleration.py`, `pulpo/gpu_triton.py`, GPU benchmark tools/tests and GPU documentation.
- #250/#258: portions of resource/custody request limits, delta performance tooling and related tests. Exact per-file details are in the JSON report.
- #219: existing MCP portability files differ; absence of new files alone does not establish that its fixes are present.

Not all of the other open non-draft PRs qualify for preview inclusion. Their recorded failing gates remain exclusion reasons; this audit does not override them or automatically integrate their code.

## Full comparison

Patch/history labels are artifact checks, not feature-level assurance. Gate results below are Recorded from the prior exact-head selection audit; they are not a new CI run. All PR heads were freshly retrieved for this comparison. Source-head changes require a new audit.

| PR | Local checkout | Combined preview | Recorded source checks |
| --- | --- | --- | --- |
| [#295](https://github.com/Ironnember/Pulpo1.0/pull/295) | Verified: exact PR head in history | Verified: exact PR head in history | Recorded: reported checks passed |
| [#294](https://github.com/Ironnember/Pulpo1.0/pull/294) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#293](https://github.com/Ironnember/Pulpo1.0/pull/293) | Verified: exact PR head in history | Verified: exact PR head in history | Recorded: reported checks passed |
| [#292](https://github.com/Ironnember/Pulpo1.0/pull/292) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: test=failure, unit-tests=failure |
| [#278](https://github.com/Ironnember/Pulpo1.0/pull/278) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#277](https://github.com/Ironnember/Pulpo1.0/pull/277) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#253](https://github.com/Ironnember/Pulpo1.0/pull/253) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#280](https://github.com/Ironnember/Pulpo1.0/pull/280) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#281](https://github.com/Ironnember/Pulpo1.0/pull/281) | Unknown semantic equivalence; exact patch not present | Verified: full patch present | Recorded: admission-hold=failure |
| [#282](https://github.com/Ironnember/Pulpo1.0/pull/282) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#284](https://github.com/Ironnember/Pulpo1.0/pull/284) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#285](https://github.com/Ironnember/Pulpo1.0/pull/285) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#286](https://github.com/Ironnember/Pulpo1.0/pull/286) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#287](https://github.com/Ironnember/Pulpo1.0/pull/287) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#276](https://github.com/Ironnember/Pulpo1.0/pull/276) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#275](https://github.com/Ironnember/Pulpo1.0/pull/275) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#289](https://github.com/Ironnember/Pulpo1.0/pull/289) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#235](https://github.com/Ironnember/Pulpo1.0/pull/235) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#258](https://github.com/Ironnember/Pulpo1.0/pull/258) | Unknown semantic equivalence; exact patch not present | Recorded: partial/different; inspect files | Recorded: reported checks passed |
| [#267](https://github.com/Ironnember/Pulpo1.0/pull/267) | Recorded: partial/different; inspect files | Recorded: partial/different; inspect files | Recorded: reported checks passed |
| [#236](https://github.com/Ironnember/Pulpo1.0/pull/236) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: reported checks passed |
| [#219](https://github.com/Ironnember/Pulpo1.0/pull/219) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: reported checks passed |
| [#238](https://github.com/Ironnember/Pulpo1.0/pull/238) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#249](https://github.com/Ironnember/Pulpo1.0/pull/249) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#251](https://github.com/Ironnember/Pulpo1.0/pull/251) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: admission-hold=failure |
| [#239](https://github.com/Ironnember/Pulpo1.0/pull/239) | Unknown semantic equivalence; exact patch not present | Unknown semantic equivalence; exact patch not present | Recorded: reported checks passed |
| [#250](https://github.com/Ironnember/Pulpo1.0/pull/250) | Unknown semantic equivalence; exact patch not present | Recorded: partial/different; inspect files | Recorded: reported checks passed |
| [#237](https://github.com/Ironnember/Pulpo1.0/pull/237) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |
| [#230](https://github.com/Ironnember/Pulpo1.0/pull/230) | Unknown semantic equivalence; exact patch not present | Verified: exact PR head in history | Recorded: reported checks passed |

The [detailed JSON](LOCAL_PR_COMPARISON.json) records exact PR/base/merge-base SHAs, every changed file, blob equality, reverse-patch checks and concrete missing new files. It describes the pre-update preview commit above; the subsequent preview update changes comparison/provenance documents, not production source.

Method: compare each non-draft PR's merge-base-to-head delta against the local and preview worktrees using `git apply --reverse --check` without applying a patch. Check exact ancestry independently. Per-file checks identify partial overlap; files modified again after a merge may no longer reverse-apply even when the PR head is in history. A matching deletion alone is not proof a new subsystem is installed. No code was imported from drafts.

## Hosted validation issue and local Git evidence synchronization

**Verified hosted-log result:** [preview run 37141212204](https://github.com/spikediegel-prog/Pulpo1.0/actions/runs/37141212204) failed `unit-tests` and consequently the `test` gate. The sole unit diagnostic was `setUpClass (test_temporal_transfer_proof_zero.TemporalTransferProofZeroTests)`: `git show 0eb1266fecf586c79457e0fcaf412bc6345545a2:experiments/temporal-transfer-proof-zero/freeze.json` exited 128. Recorded run summary: 439 tests, one error, three skips. Authority, authority-service, hostile-worker-custody, hostile-worker-container-isolation and network_exposure_proof jobs passed.

**Verified:** this exact checkpoint exists in the local repository but is not an ancestor of preview. The frozen historical/reference commits `4ee6af94ea8c55d2393351ffcb17f3dcdc792d08` and `81338eed28ec32fe214c7eee086a82840ca0923f` are already in preview history.

Update from local Git evidence: publish the original checkpoint under the evidence-only tag `preview-evidence-temporal-freeze`. It preserves the original SHA/tree and supplies the existing full-history checkout with the object its test requires. The tag is historical fixture evidence, not a selected candidate/draft PR, a runtime code merge, or a release. The test and frozen manifest are unchanged. This preserves the AGENTS temporal-transfer rule to use exact historical SHA rather than substituting a new checkpoint.

The preview continues to be an unofficial testing snapshot. Latest hosted validation must be checked; the prior 445-test local pass did not prove that a GitHub checkout contained every local historical object. **Verified fresh-fork reproduction:** after the evidence tag was published, a new clone directly from spikediegel-prog/Pulpo1.0 contained the exact checkpoint and passed all 445 tests with warnings treated as errors in 20.995s (Ubuntu/WSL, Python 3.14.4). [Captured log](perf-results/preview-fork-tests-20261003.log). This reproduction did not borrow objects from the original local repository. New hosted validation remains pending.

## Authority and next step

Authority and production code remain unchanged by this comparison/evidence update. There is no canonical upstream merge, no credentials copied, and no bypass of failed checks. Governance invariants remain mandatory.

For the six remaining compatible-source candidates, review exact conflicts and targeted proof/benchmark evidence before introducing an integration change; do not import the aggregate branches wholesale merely because their individual historical checks passed. Each SQL/component optimization is benchmarked and externally reproduced before the next optimization is stacked.
