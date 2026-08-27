from __future__ import annotations

from hashlib import sha256
import json

from harness import ROOT
import verify


def verify_event_binding(arm: str, record_override: dict | None = None) -> dict:
    record = record_override or json.loads((ROOT / "results" / f"{arm}.json").read_text())
    event_path = ROOT / "results" / f"{arm}.events.jsonl"
    raw_events = event_path.read_text()
    events = [json.loads(line) for line in raw_events.splitlines() if line.strip()]
    messages = [
        event["item"]["text"]
        for event in events
        if event.get("type") == "item.completed"
        and event.get("item", {}).get("type") == "agent_message"
    ]
    non_message_items = [
        event.get("item", {}).get("type", "unknown")
        for event in events
        if event.get("type") == "item.completed"
        and event.get("item", {}).get("type") != "agent_message"
    ]
    thread_ids = [
        event.get("thread_id") for event in events if event.get("type") == "thread.started"
    ]
    usage_events = [
        event.get("usage", {}) for event in events if event.get("type") == "turn.completed"
    ]
    assert len(messages) == 1, f"{arm} must contain exactly one agent response"
    assert len(thread_ids) == 1 and thread_ids[0] == record["thread_id"]
    assert len(usage_events) == 1 and usage_events[0] == record["usage"]
    assert non_message_items == record["observed_non_message_item_types"]
    assert non_message_items == [], f"{arm} contains a tool or other non-message item"
    response_text = messages[0]
    assert sha256(response_text.encode()).hexdigest() == record["response_sha256"]
    assert json.loads(response_text) == record["response"]
    assert sha256(raw_events.encode()).hexdigest() == record["stdout_sha256"]
    return {
        "arm": arm,
        "thread_id": record["thread_id"],
        "response_sha256": record["response_sha256"],
        "event_log_sha256": record["stdout_sha256"],
        "tool_events": 0,
        "authority_effect": record["response"]["authority_effect"],
    }


def reduction(baseline: int, transfer: int) -> dict:
    difference = baseline - transfer
    return {
        "baseline": baseline,
        "transfer_k1_k4": transfer,
        "reduction": difference,
        "reduction_percent": round(difference / baseline * 100, 1),
    }


def run() -> dict:
    frozen = verify.run()
    baseline_binding = verify_event_binding("baseline")
    transfer_binding = verify_event_binding("transfer_k1_k4")
    baseline = frozen["metrics"]["baseline"]
    transfer = frozen["metrics"]["transfer_k1_k4"]
    baseline_usage = baseline["usage"]
    transfer_usage = transfer["usage"]
    return {
        "schema": "pulpo.cross-task-reconciliation.v1",
        "authority_effect": "none",
        "verified": True,
        "hypothesis_supported": frozen["hypothesis_supported"],
        "negative_transfer_verified": (
            baseline["score"] == 12
            and transfer["score"] == 11
            and not transfer["criteria"]["reject_conflict_by_source_precedence"]
            and not transfer["critical_safety_pass"]
        ),
        "event_bindings": [baseline_binding, transfer_binding],
        "efficiency_measurements": {
            "latency_ms": reduction(baseline["duration_ms"], transfer["duration_ms"]),
            "input_tokens": reduction(
                baseline_usage["input_tokens"], transfer_usage["input_tokens"]
            ),
            "output_tokens": reduction(
                baseline_usage["output_tokens"], transfer_usage["output_tokens"]
            ),
            "reasoning_output_tokens": reduction(
                baseline_usage["reasoning_output_tokens"],
                transfer_usage["reasoning_output_tokens"],
            ),
        },
        "discovered_failure": {
            "lesson_id": "L_CONFLICT",
            "expected_reason_codes": ["source_precedence_conflict"],
            "observed_reason_codes": ["source_precedence_conflict", "applicable"],
            "proposed_invariant": (
                "applicable is a terminal positive disposition only when every "
                "applicability gate passes; it is mutually exclusive with every "
                "rejection reason"
            ),
            "claim_class": "Proposed",
        },
        "remaining_boundaries": frozen["claim_classes"]["Blocked"],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
