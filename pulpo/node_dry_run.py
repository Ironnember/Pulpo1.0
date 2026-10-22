"""Phase 2 synthetic GPIO contract over the canonical kernel.

No hardware backend, device file, subprocess, network, or GPIO library is used.
The in-memory output is a synthetic consequence sink, not an authority/evidence
ledger. This module is not a sandbox or proof of physical GPIO custody.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Literal

from .kernel import GovernanceKernel, Intent


ACTION = "gpio_dry_run_set_output"
EVENT = "node_gpio_dry_run_observed"


@dataclass(frozen=True)
class DryRunOutput:
    """An exact synthetic endpoint; BCM is numbering only, never hardware access."""

    pin: int
    level: int
    endpoint: str = "synthetic-node:alpha"
    numbering: str = "BCM"
    mode: str = "dry-run"

    def __post_init__(self) -> None:
        if type(self.pin) is not int or not 0 <= self.pin <= 27:
            raise ValueError("invalid_bcm_pin")
        if type(self.level) is not int or self.level not in (0, 1):
            raise ValueError("invalid_output_level")
        if not isinstance(self.endpoint, str) or not self.endpoint.startswith("synthetic-node:") or not self.endpoint.removeprefix("synthetic-node:"):
            raise ValueError("synthetic_endpoint_required")
        if self.numbering != "BCM" or self.mode != "dry-run":
            raise ValueError("dry_run_bcm_only")

    @property
    def object_hash(self) -> str:
        body = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return sha256(body.encode()).hexdigest()


def output_intent(output: DryRunOutput, *, principal: str, session_id: str) -> Intent:
    return Intent(
        principal=principal,
        action=ACTION,
        resource=f"{output.endpoint}:{output.object_hash}",
        cost=1,
        session_id=session_id,
    )


class DryRunGPIOAdapter:
    """Synthetic output only. Direct calls confer no governed provenance.

    No kernel, signer, permit issuer, canonical writer, or physical handle is
    retained here. Observation is same-process test data, not an independent
    hardware witness. The governed execution seam is execute_dry_run_output.
    """

    def __init__(self) -> None:
        self._output: DryRunOutput | None = None

    def set_output(self, output: DryRunOutput) -> None:
        self._output = output

    def observe(self) -> DryRunOutput | None:
        return self._output


class DryRunDenied(RuntimeError):
    """No adapter invocation was made through the governed seam."""


class DryRunConsequenceUnknown(RuntimeError):
    """Permit is spent; adapter/evidence failure must not cause an automatic retry."""


def execute_dry_run_output(
    kernel: GovernanceKernel,
    adapter: DryRunGPIOAdapter,
    *,
    target_id: str,
    target_hash: str,
    permit: str,
    output: DryRunOutput,
    version: int = 1,
) -> None:
    """Resolve exact target, consume once, then invoke the synthetic sink.

    The kernel alone owns approval/permit/replay semantics. Observation is
    appended to its existing audit after readback. No retry or replacement
    permit is generated, including when observation or audit append fails.
    """
    resolution = kernel.resolve_locked_target(target_id, target_hash, version=version)
    if resolution.outcome != "match" or resolution.target is None:
        raise DryRunDenied(resolution.reason)
    intent = resolution.target.intent
    expected = output_intent(output, principal=intent.principal, session_id=intent.session_id)
    if intent != expected:
        raise DryRunDenied("output_intent_mismatch")
    if not kernel.consume(permit, intent):
        raise DryRunDenied("canonical_permit_rejected")

    try:
        # Capture the precise canonical consumption record, not the secret permit.
        consumed = kernel.audit[-1]
        if consumed["event"] != "permit_consumed":
            raise DryRunConsequenceUnknown("consumption_evidence_unavailable")
        adapter.set_output(output)
        observed = adapter.observe()
        if observed != output:
            raise DryRunConsequenceUnknown("output_observation_mismatch_or_missing")
        now = kernel._trusted_now()
        if now is None:
            raise DryRunConsequenceUnknown("observation_time_unavailable")
        kernel._state.append(
            EVENT,
            {
                "schema": "pulpo.node-gpio-dry-run.v1",
                "target_id": target_id,
                "version": version,
                "target_hash": target_hash,
                "intent_hash": kernel.intent_hash(intent),
                "policy_hash": kernel.policy_hash,
                "consumption_hash": consumed["hash"],
                "output": asdict(observed),
                "object_hash": observed.object_hash,
                "authority_effect": "none",
                "governed_effect": "synthetic_output_observed",
            },
            now,
        )
    except DryRunConsequenceUnknown:
        raise
    except Exception as exc:
        raise DryRunConsequenceUnknown("adapter_or_evidence_unavailable") from exc


def reconcile_dry_run_output(
    kernel: GovernanceKernel,
    *,
    target_id: str,
    target_hash: str,
    output: DryRunOutput,
    observed: DryRunOutput | None,
    version: int = 1,
) -> Literal["RECONCILED", "UNKNOWN", "MISMATCH"]:
    """Read-only projection of exact canonical consumption + synthetic readback.

    This grants no authority and commits no reconciliation state. It does not
    attest to a physical pin or an independent process/trust domain.
    """
    if not kernel.verify_audit():
        return "MISMATCH"
    target = kernel.get_locked_target(target_id, version=version)
    if target is None or target.target_hash != target_hash:
        return "MISMATCH"
    expected = output_intent(output, principal=target.intent.principal, session_id=target.intent.session_id)
    if target.intent != expected:
        return "MISMATCH"
    if observed is None:
        return "UNKNOWN"
    if observed != output:
        return "MISMATCH"
    audit = kernel.audit
    matches = [
        (index, record["payload"])
        for index, record in enumerate(audit)
        if record["event"] == EVENT
        and record["payload"].get("target_id") == target_id
        and record["payload"].get("version") == version
    ]
    if not matches:
        return "UNKNOWN"
    if len(matches) != 1:
        return "MISMATCH"
    index, payload = matches[0]
    if (
        payload.get("schema") != "pulpo.node-gpio-dry-run.v1"
        or payload.get("target_hash") != target_hash
        or payload.get("intent_hash") != kernel.intent_hash(expected)
        or payload.get("policy_hash") != kernel.policy_hash
        or payload.get("output") != asdict(observed)
        or payload.get("object_hash") != output.object_hash
        or payload.get("authority_effect") != "none"
        or payload.get("governed_effect") != "synthetic_output_observed"
    ):
        return "MISMATCH"
    for record in audit[:index]:
        if record["hash"] == payload.get("consumption_hash"):
            if record["event"] == "permit_consumed" and record["payload"].get("intent_hash") == kernel.intent_hash(expected):
                return "RECONCILED"
            return "MISMATCH"
    return "MISMATCH"
