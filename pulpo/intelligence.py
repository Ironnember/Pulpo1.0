"""Cost-aware intelligence escalation without provider execution or authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable


class IntelligenceTier(IntEnum):
    DETERMINISTIC = 0
    LOCAL_MODEL = 1
    COMMODITY_API = 2
    FRONTIER_API = 3


@dataclass(frozen=True)
class IntelligenceOption:
    name: str
    tier: IntelligenceTier
    max_uncertainty: int
    max_consequence: int
    estimated_cost_microusd: int
    remote: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("option name is required")
        if not 0 <= self.max_uncertainty <= 100:
            raise ValueError("max_uncertainty must be 0..100")
        if not 0 <= self.max_consequence <= 100:
            raise ValueError("max_consequence must be 0..100")
        if self.estimated_cost_microusd < 0:
            raise ValueError("estimated cost cannot be negative")


@dataclass(frozen=True)
class IntelligenceRequest:
    uncertainty: int
    consequence: int
    budget_microusd: int
    remote_allowed: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.uncertainty <= 100:
            raise ValueError("uncertainty must be 0..100")
        if not 0 <= self.consequence <= 100:
            raise ValueError("consequence must be 0..100")
        if self.budget_microusd < 0:
            raise ValueError("budget cannot be negative")


@dataclass(frozen=True)
class IntelligencePlan:
    option: IntelligenceOption
    reason: str
    authority_effect: str = "none"


def select_intelligence(
    request: IntelligenceRequest,
    options: Iterable[IntelligenceOption],
) -> IntelligencePlan | None:
    """Return the cheapest sufficient intelligence option, or fail closed.

    This function does not call a model, spend money, issue a permit, alter policy,
    or authorize execution. It only proposes an intelligence surface.
    """
    eligible = [
        option
        for option in options
        if request.uncertainty <= option.max_uncertainty
        and request.consequence <= option.max_consequence
        and option.estimated_cost_microusd <= request.budget_microusd
        and (request.remote_allowed or not option.remote)
    ]
    if not eligible:
        return None

    option = min(
        eligible,
        key=lambda candidate: (
            candidate.estimated_cost_microusd,
            int(candidate.tier),
            candidate.name,
        ),
    )
    return IntelligencePlan(
        option=option,
        reason=(
            "lowest_cost_sufficient_option:"
            f"uncertainty<={option.max_uncertainty};"
            f"consequence<={option.max_consequence};"
            f"cost={option.estimated_cost_microusd}"
        ),
    )
