# Change record — 2026-11-17 — Evaluation license and version alignment

## 1. Invariant or failure addressed

Two public-record defects found by the 2026-11-17 release-readiness
review:

- The repository carried **no LICENSE file**. The default legal position
  (all rights reserved) was nowhere stated, leaving anyone evaluating
  Pulpo — the exact audience the repository is public for — without
  stated terms for what they may do with the code.
- `pyproject.toml` declared version **0.1.0** while the repository's
  tags reach v0.1.4 (2026-09-18, no assets attached) and canonical main
  has since absorbed the entire Phase 1–2 writer-custody program. The
  packaging metadata did not describe the software it sat on top of.

This change adds a proprietary **evaluation license** (view, run, and
evaluate; no production use, no redistribution) and aligns the package
version to **0.2.0**, declaring the license and README in the project
metadata.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. No code, policy, permit, or authority path is touched. The
license narrows what *recipients* may do with copies; it grants the
kernel and its operators nothing.

## 3. Canonical state mutations introduced or exposed

None. Legal and packaging metadata only: `LICENSE` (new),
`pyproject.toml` (version, license, readme fields), and this record.

## 4. Success and adversarial evidence

At canonical main `c42aad6`, 2026-11-17:

- Repository state inspected directly: no LICENSE present; pyproject
  version 0.1.0; tags v0.1.0–v0.1.4; latest release (v0.1.4) carries
  zero uploaded assets (verified via the GitHub API).
- Package builds from the updated metadata (`python -m build`
  produces sdist and wheel at version 0.2.0 — result recorded in the
  pull request).
- Full suite re-run on this branch before merge (result recorded in
  the pull request); no code changed, so no behavioral delta is
  expected or claimed.

Adversarial check on scope: this change does **not** create a release,
a distribution, or a download. The version string is metadata until a
tagged release is cut from main, built, checksummed, and clean-room
tested; those steps are separate, later, and separately approved.

## 5. Boundary the evidence does not prove

The license text is a **draft pending review by counsel**; this record
asserts its intended terms, not its enforceability. Nothing here proves
anything about deployment, hosting, or any recipient's environment.

## 6. Claim classification

**Verified** as to repository state and build behavior at the inspected
commit. **Proposed** as to the license's legal effect, pending counsel.

## 7. Legacy behavior source

None used.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this change: it concerns
the current public record only, and asserts nothing about earlier
states of the repository.
