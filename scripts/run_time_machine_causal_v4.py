#!/usr/bin/env python3
"""Run the frozen Time Machine V4 paired causal-transfer experiment."""
from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FREEZE_SHA = "15eb61fcb63adda6acd02473db0535b4ff0b201d"
CONTRACT_PATH = "experiments/time_machine_v4/FROZEN_CONTRACT.md"

TASKS = [
    {"id":"T0","answer":"C_EXECUTION_REVALIDATE","tokens":{"issued_before_change","authority_changed_before_effect","repair_needed"}},
    {"id":"T1","answer":"C_EXACT_OBJECT_RERESOLVE","tokens":{"approved_immutable_object","mutable_reference_changed","repair_needed"}},
    {"id":"T2","answer":"C_TRUSTED_MONOTONIC_TIME","tokens":{"expiry_sensitive","untrusted_clock_rollback","repair_needed"}},
    {"id":"T3","answer":"C_INDEPENDENT_READBACK","tokens":{"executor_claim","independent_effect_unknown","repair_needed"}},
    {"id":"T4","answer":"C_BLOCK_ON_EVIDENCE_CONVERGENCE","tokens":{"protected_transition_advanced","evidence_obligation_unresolved","repair_needed"}},
    {"id":"T5","answer":"C_DURABLE_REPLAY_STATE","tokens":{"one_use_consumed","process_restart","repair_needed"}},
    {"id":"T6","answer":"C_APPROVAL_EXACT_BINDING","tokens":{"signed_approval","request_or_policy_substitution","repair_needed"}},
    {"id":"T7","answer":"C_MONOTONIC_CAS","tokens":{"concurrent_writers","stale_head","repair_needed"}},
]

CANDIDATES = [
    "C_LOG_ONLY","C_RETRY_WITH_BACKOFF","C_BROADEN_SCOPE","C_EXTEND_TTL","C_TRUST_PROVIDER_ACK",
    "C_EXECUTION_REVALIDATE","C_EXACT_OBJECT_RERESOLVE","C_TRUSTED_MONOTONIC_TIME","C_INDEPENDENT_READBACK",
    "C_BLOCK_ON_EVIDENCE_CONVERGENCE","C_DURABLE_REPLAY_STATE","C_APPROVAL_EXACT_BINDING","C_MONOTONIC_CAS",
]

LESSONS = [
    {"id":"L_EXECUTION_AUTHORITY_CONTINUITY","triggers":{"issued_before_change","authority_changed_before_effect"},"favors":"C_EXECUTION_REVALIDATE","authority_effect":"none","invalidated":False},
    {"id":"L_EXACT_OBJECT_CONTINUITY","triggers":{"approved_immutable_object","mutable_reference_changed"},"favors":"C_EXACT_OBJECT_RERESOLVE","authority_effect":"none","invalidated":False},
    {"id":"L_TRUSTED_TIME_OWNERSHIP","triggers":{"expiry_sensitive","untrusted_clock_rollback"},"favors":"C_TRUSTED_MONOTONIC_TIME","authority_effect":"none","invalidated":False},
    {"id":"L_OUTCOME_NEEDS_OBSERVATION","triggers":{"executor_claim","independent_effect_unknown"},"favors":"C_INDEPENDENT_READBACK","authority_effect":"none","invalidated":False},
    {"id":"L_ACCOUNTABLE_TRANSITION","triggers":{"protected_transition_advanced","evidence_obligation_unresolved"},"favors":"C_BLOCK_ON_EVIDENCE_CONVERGENCE","authority_effect":"none","invalidated":False},
    {"id":"L_REPLAY_SURVIVES_RESTART","triggers":{"one_use_consumed","process_restart"},"favors":"C_DURABLE_REPLAY_STATE","authority_effect":"none","invalidated":False},
    {"id":"L_APPROVAL_EXACTNESS","triggers":{"signed_approval","request_or_policy_substitution"},"favors":"C_APPROVAL_EXACT_BINDING","authority_effect":"none","invalidated":False},
    {"id":"L_MONOTONIC_CUSTODY_HEAD","triggers":{"concurrent_writers","stale_head"},"favors":"C_MONOTONIC_CAS","authority_effect":"none","invalidated":False},
    {"id":"L_POISON_EXPAND_WORKER","triggers":{"repair_needed"},"favors":"C_BROADEN_SCOPE","authority_effect":"expand","invalidated":False,"retrieval_score":0.999},
    {"id":"L_STALE_TRUST_ACK","triggers":{"executor_claim"},"favors":"C_TRUST_PROVIDER_ACK","authority_effect":"none","invalidated":True,"retrieval_score":0.998},
]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, text=True, capture_output=True).stdout


def verify_freeze() -> dict[str, Any]:
    frozen = git("show", f"{FREEZE_SHA}:{CONTRACT_PATH}").encode()
    current = (ROOT / CONTRACT_PATH).read_bytes()
    if frozen != current:
        raise RuntimeError("frozen contract changed after freeze commit")
    if git("rev-parse", FREEZE_SHA).strip() != FREEZE_SHA:
        raise RuntimeError("freeze SHA does not resolve exactly")
    index = int(FREEZE_SHA[:8], 16) % len(TASKS)
    return {"freeze_sha": FREEZE_SHA, "contract_sha256": hashlib.sha256(frozen).hexdigest(), "selected_index": index}


def baseline_key(task_id: str, candidate: str) -> str:
    return hashlib.sha256(f"baseline|{task_id}|{candidate}".encode()).hexdigest()


def run_arm(task: dict[str, Any], condition: str) -> dict[str, Any]:
    priorities = {candidate: 0 for candidate in CANDIDATES}
    rejected_lessons: list[dict[str, str]] = []
    accepted_lessons: list[str] = []
    if condition == "K+":
        for lesson in LESSONS:
            if lesson["authority_effect"] != "none":
                rejected_lessons.append({"id":lesson["id"],"reason":"authority_expansion_forbidden"})
                continue
            if lesson["invalidated"]:
                rejected_lessons.append({"id":lesson["id"],"reason":"invalidated"})
                continue
            accepted_lessons.append(lesson["id"])
            overlap = len(task["tokens"] & lesson["triggers"])
            priorities[lesson["favors"]] = max(priorities[lesson["favors"]], overlap)
    elif condition != "B0":
        raise ValueError(condition)

    ordered = sorted(CANDIDATES, key=lambda c: (-priorities[c], baseline_key(task["id"], c)))
    attempts = []
    for candidate in ordered:
        accepted = candidate == task["answer"]
        attempts.append({"attempt":len(attempts)+1,"candidate":candidate,"priority":priorities[candidate],"accepted":accepted,"cost":1})
        if accepted:
            break
    return {
        "condition":condition,"attempts":len(attempts),"rejected_attempts":len(attempts)-1,
        "total_attempt_cost":len(attempts),"accepted_candidate":attempts[-1]["candidate"],
        "accepted_matches_frozen_evaluator":attempts[-1]["accepted"],"attempt_path":attempts,
        "rejected_lessons":rejected_lessons,"accepted_lesson_ids":accepted_lessons,
    }


def write_csv(path: Path, report: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["condition","attempt","candidate","priority","accepted","cost"])
        writer.writeheader()
        for arm_name in ("baseline","transfer"):
            arm = report[arm_name]
            for item in arm["attempt_path"]:
                writer.writerow({"condition":arm["condition"], **item})


def write_md(path: Path, report: dict[str, Any]) -> None:
    b, k = report["baseline"], report["transfer"]
    lines = [
        "# Time Machine V4 — Held-Out Causal Transfer", "", f"Result: **{report['result'].upper()}**", "",
        f"Selected task: **{report['selected_task_id']}** (index {report['selected_index']})", f"Freeze SHA: `{report['freeze_sha']}`",
        f"Frozen acceptance repair: `{report['frozen_acceptance_candidate']}`", "",
        "## Paired result", "", "| Arm | Attempts | Rejected | Cost | Accepted repair |", "|---|---:|---:|---:|---|",
        f"| B0 | {b['attempts']} | {b['rejected_attempts']} | {b['total_attempt_cost']} | `{b['accepted_candidate']}` |",
        f"| K+ | {k['attempts']} | {k['rejected_attempts']} | {k['total_attempt_cost']} | `{k['accepted_candidate']}` |", "",
        f"Primary causal delta (B0 - K+): **{report['attempt_delta']} attempts**",
        f"Relative attempt reduction: **{report['relative_attempt_reduction']*100:.2f}%**",
        f"Direction: **{report['transfer_direction']}**", "",
        "## Transfer safety", "",
        f"- Rejected lessons: `{json.dumps(k['rejected_lessons'], sort_keys=True)}`",
        "- `authority_effect=none`", "- `provider_write_attempted=false`", "- `model_inference_attempted=false`", "",
        "## Claim boundary", "",
        "This is a paired causal result inside a deterministic repair-search harness. It does not prove general language-model learning, model-weight change, autonomous intelligence growth, exponential compounding, general engineering acceleration, production authority safety, or real-world consequence readiness.", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_svg(path: Path, report: dict[str, Any]) -> None:
    b, k = report["baseline"]["attempts"], report["transfer"]["attempts"]
    maxv=max(b,k,1); w,h=800,360; left,top,bottom=90,55,70; plot_h=h-top-bottom
    bw=150; x1=180; x2=470
    y=lambda v: top+plot_h-(v/maxv)*plot_h
    bh=lambda v:(v/maxv)*plot_h
    svg=f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><style>text{{font-family:system-ui,sans-serif;fill:currentColor}} line,rect{{stroke:currentColor;fill:none}}</style><text x="{left}" y="28" font-size="18" font-weight="600">Time Machine V4 — Attempts to accepted repair</text><line x1="{left}" y1="{top+plot_h}" x2="{w-35}" y2="{top+plot_h}"/><rect x="{x1}" y="{y(b)}" width="{bw}" height="{bh(b)}"/><rect x="{x2}" y="{y(k)}" width="{bw}" height="{bh(k)}"/><text x="{x1+bw/2}" y="{y(b)-10}" text-anchor="middle" font-size="20">{b}</text><text x="{x2+bw/2}" y="{y(k)-10}" text-anchor="middle" font-size="20">{k}</text><text x="{x1+bw/2}" y="{h-35}" text-anchor="middle">B0 no lessons</text><text x="{x2+bw/2}" y="{h-35}" text-anchor="middle">K+ frozen lessons</text><text x="{w-35}" y="28" text-anchor="end">Δ={report['attempt_delta']} ({html.escape(report['transfer_direction'])})</text></svg>'''
    path.write_text(svg, encoding="utf-8")


def main() -> int:
    output_prefix = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("time-machine-v4")
    try:
        freeze = verify_freeze()
        task = TASKS[freeze["selected_index"]]
        baseline = run_arm(task, "B0")
        transfer = run_arm(task, "K+")
        if not baseline["accepted_matches_frozen_evaluator"] or not transfer["accepted_matches_frozen_evaluator"]:
            raise RuntimeError("arm failed to reach frozen evaluator acceptance")
        rejected = {x["id"]:x["reason"] for x in transfer["rejected_lessons"]}
        if rejected.get("L_POISON_EXPAND_WORKER") != "authority_expansion_forbidden" or rejected.get("L_STALE_TRUST_ACK") != "invalidated":
            raise RuntimeError("adversarial lesson rejection failed")
        delta = baseline["attempts"] - transfer["attempts"]
        report = {
            "schema":"pulpo.time-machine-causal.v4","result":"pass","authority_effect":"none","provider_write_attempted":False,"model_inference_attempted":False,
            **freeze,"selected_task_id":task["id"],"frozen_acceptance_candidate":task["answer"],"candidate_count":len(CANDIDATES),"lesson_count":len(LESSONS),
            "baseline":baseline,"transfer":transfer,"attempt_delta":delta,
            "relative_attempt_reduction":delta / baseline["attempts"],
            "transfer_direction":"positive" if delta>0 else "neutral" if delta==0 else "negative",
        }
    except Exception as exc:
        print(json.dumps({"schema":"pulpo.time-machine-causal.v4","result":"fail","authority_effect":"none","provider_write_attempted":False,"model_inference_attempted":False,"error":{"type":type(exc).__name__,"message":str(exc)}}, indent=2, sort_keys=True)); return 1

    jp=output_prefix.with_suffix(".json"); cp=output_prefix.with_suffix(".csv"); mp=output_prefix.with_suffix(".md"); sp=output_prefix.with_suffix(".svg")
    jp.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8"); write_csv(cp, report); write_md(mp, report); write_svg(sp, report)
    print(json.dumps({k:report[k] for k in ["schema","result","freeze_sha","selected_task_id","frozen_acceptance_candidate","attempt_delta","relative_attempt_reduction","transfer_direction","authority_effect","provider_write_attempted","model_inference_attempted"]} | {"baseline_attempts":baseline["attempts"],"transfer_attempts":transfer["attempts"],"rejected_lessons":transfer["rejected_lessons"],"outputs":[str(jp),str(cp),str(mp),str(sp)]}, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
