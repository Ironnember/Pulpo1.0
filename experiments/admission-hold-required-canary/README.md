# Admission Hold Required-Status Canary

Purpose: test whether GitHub currently treats a failing base-controlled `admission-hold` check as merge-blocking when the pull request is otherwise eligible.

This branch is disposable evidence only. It must never be merged.

Expected condition:

- PR is **not** a GitHub draft;
- PR body carries the machine-readable Pulpo admission HOLD marker and explicit PROCESS HOLD language;
- base-controlled `Admission Hold` fails;
- ordinary required CI statuses succeed;
- observe GitHub mergeability without calling the merge endpoint;
- close the PR without merge.

`authority_effect=none`
