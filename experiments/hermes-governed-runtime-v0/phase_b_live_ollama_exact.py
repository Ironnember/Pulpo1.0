"""Exact-head wrapper for the live Hermes learned-context proof.

The base Phase B harness is intentionally kept readable as the experiment
specification. This wrapper applies runtime compatibility corrections discovered
only by executing the pinned Hermes object:

1. Keep Hermes/Ollama at the required 65,536-token runtime context and raise the
   custom-provider request/stale timeouts so the CPU-only proof can complete
   without treating slow local inference as a provider failure.
2. Hermes' post_tool_call telemetry omits the memory tool's default target from
   args when the model does not spell it explicitly, but the successful memory
   result reports target=memory. Normalize that observed default only when the
   real tool result proves it.

No Pulpo authority, policy, state, permit, execution, or evidence behavior is
changed here.
"""

from __future__ import annotations

import copy

import phase_b_live_ollama as base


_original_write_config = base._write_hermes_config
_original_tool_event = base._tool_event


def _write_hermes_config(hermes_home, pulpo_root):
    path = _original_write_config(hermes_home, pulpo_root)
    text = path.read_text(encoding="utf-8")
    if "ollama_num_ctx: 65536" not in text:
        raise RuntimeError("Hermes Phase B must retain the 65536-token Ollama runtime context")
    if "providers:\n  custom:" not in text:
        marker = "\ntoolsets:\n"
        provider_block = (
            "\nproviders:\n"
            "  custom:\n"
            "    request_timeout_seconds: 900\n"
            "    stale_timeout_seconds: 900\n"
        )
        if marker not in text:
            raise RuntimeError("unexpected Hermes config shape")
        text = text.replace(marker, provider_block + marker, 1)
    path.write_text(text, encoding="utf-8")
    return path


def _tool_event(events, name):
    event = _original_tool_event(events, name)
    if name != "memory":
        return event

    args = event.get("args")
    if not isinstance(args, dict) or "target" in args:
        return event

    # Do not infer the default from documentation alone. The actual successful
    # tool result must report target=memory before the observer event is
    # normalized for the base harness assertion.
    result_text = base._event_result_text(event)
    lowered = result_text.lower()
    proves_memory_target = (
        '"target": "memory"' in lowered
        or '"target":"memory"' in lowered
        or "'target': 'memory'" in lowered
    )
    if not proves_memory_target:
        return event

    normalized = copy.deepcopy(event)
    normalized_args = dict(args)
    normalized_args["target"] = "memory"
    normalized["args"] = normalized_args
    normalized["target_normalized_from_observed_result"] = True
    return normalized


base._write_hermes_config = _write_hermes_config
base._tool_event = _tool_event


if __name__ == "__main__":
    base.main()
