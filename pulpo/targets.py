"""Exact-target adapters over the one Pulpo governance kernel.

These helpers resolve durable proposed targets and then delegate authority to
``GovernanceKernel``.  They do not mint permits, alter policy, authenticate a
principal, or create another router or authority path.
"""

from __future__ import annotations

from .authority import ApprovalEnvelope
from .kernel import Decision, GovernanceKernel, TargetResolution


def evaluate_locked_target_with_approval(
    kernel: GovernanceKernel,
    target_id: str,
    expected_target_hash: str,
    envelope: ApprovalEnvelope,
    *,
    version: int = 1,
) -> tuple[TargetResolution, Decision | None]:
    """Resolve one exact locked target, then use the kernel's approval path.

    A target mismatch stops before the approval envelope is evaluated.  An exact
    target delegates the locked intent unchanged to
    ``GovernanceKernel.evaluate_with_approval``.
    """

    resolution = kernel.resolve_locked_target(
        target_id,
        expected_target_hash,
        version=version,
    )
    if resolution.outcome != "match" or resolution.target is None:
        return resolution, None
    return resolution, kernel.evaluate_with_approval(resolution.target.intent, envelope)
